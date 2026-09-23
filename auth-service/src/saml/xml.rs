//! Namespace-aware XML deserialization into the serde models of
//! [`saml::model`](crate::saml::model), over [`quick_xml`].
//!
//! quick-xml's serde deserializer matches elements and attributes by *local*
//! name and drops the prefix, so on its own an `<evil:Issuer>` would read as a
//! `<saml:Issuer>`. [`Document::parse`] therefore first rewrites the input, in
//! one [`NsReader`] pass, into a namespace-resolved form that the models are
//! then deserialized from:
//!
//! - Every element is renamed `alias.Local`, where `alias` names its resolved
//!   namespace URI (see [`NAMESPACES`]). An element in any other namespace, or in
//!   none, becomes `unknown.Local`, which no model names. So a model field
//!   `#[serde(rename = "saml.Issuer")]` matches by `(namespace-URI, local-name)`
//!   whatever prefix the sender chose, and never a same-named element from
//!   another namespace (no namespace-confusion attacks).
//! - Unprefixed attributes keep their name. Namespace declarations and prefixed
//!   attributes (`xml:lang`, `xsi:type`, ...) are dropped: no model reads them.
//! - Comments, processing instructions and the XML declaration are dropped, and
//!   CDATA becomes plain (escaped) text.
//! - Every element gets a [`INDEX_ATTRIBUTE`] attribute: its index in
//!   [`Document::elements`], so a model can point back at the source bytes of
//!   the element it was read from (see [`ElementRef`]). Input cannot forge it:
//!   an input attribute whose name contains a `.` is dropped like a prefixed one.
//!
//! The pass also rejects what the SAML messages never legitimately contain: a
//! DTD (so no custom entities), an undeclared namespace prefix, malformed or
//! multi-root XML, excessive nesting, and more than [`NODE_LIMIT`] elements.
//!
//! SECURITY (XML Signature Wrapping): comments are invisible here, and
//! exclusive-c14n (the only canonicalization the signature checks accept)
//! excludes them from the digest, so an element forged inside a comment is
//! invisible to both extraction and the signature. The models are all read from
//! one parse of the document, and signature verification is bound to the source
//! bytes of the very element a model was read from, via its [`ElementRef`].

use crate::saml::constants::{NS_DSIG, NS_MD, NS_SAML, NS_SAMLP, NS_SOAP, NS_XENC};
use quick_xml::{
    NsReader, XmlVersion,
    events::{BytesStart, Event},
    name::{PrefixDeclaration, ResolveResult},
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{fmt::Write as _, ops::Range};

/// The namespaces the models read, with the alias their elements are renamed
/// to (`saml:Issuer` becomes `saml.Issuer`, whatever the input prefix was).
const NAMESPACES: &[(&str, &str)] = &[
    (NS_SOAP, "soap"),
    (NS_SAMLP, "samlp"),
    (NS_SAML, "saml"),
    (NS_MD, "md"),
    (NS_DSIG, "ds"),
    (NS_XENC, "xenc"),
];

/// Alias for an element in a namespace outside [`NAMESPACES`] (or in none).
const UNKNOWN_ALIAS: &str = "unknown";

/// The attribute carrying an element's index in [`Document::elements`]; a model
/// reads it with `#[serde(rename = "@src.index")]`.
pub const INDEX_ATTRIBUTE: &str = "src.index";

/// Cap on the element count, bounding memory from an oversized document; a
/// legitimate SAML message has at most a few thousand elements.
const NODE_LIMIT: usize = 100_000;

/// Cap on element nesting. SAML messages nest a dozen levels deep; the cap keeps
/// a pathological document from exhausting the stack of the (recursive) serde
/// deserializer.
const DEPTH_LIMIT: usize = 256;

/// Opaque XML parse error (`Display`), convertible into `AuthError`.
#[derive(Debug)]
pub struct XmlError(String);

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XmlError {}

fn err(message: impl std::fmt::Display) -> XmlError {
    XmlError(message.to_string())
}

/// An element's expanded name: namespace URI (`None` for an element in no
/// namespace) plus local, unprefixed name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QName<'a> {
    pub namespace: Option<&'a str>,
    pub local_name: &'a str,
}

impl std::fmt::Display for QName<'_> {
    /// James Clark notation (`{namespace}local`), as used in the error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.namespace {
            Some(ns) => write!(f, "{{{ns}}}{}", self.local_name),
            None => f.write_str(self.local_name),
        }
    }
}

/// Attributes by local name, with their normalized values.
type Attributes = Vec<(String, String)>;

/// Namespace declarations: prefix (`None` for the default namespace) and URI.
type NamespaceDeclarations = Vec<(Option<String>, String)>;

/// One element of the parsed document, in document order.
#[derive(Debug)]
pub struct Element {
    namespace: Option<String>,
    local_name: String,
    parent: Option<usize>,
    /// Every non-namespace-declaration attribute by local name (so `xml:id`
    /// reads as `id`), value normalized per XML §3.3.3.
    attributes: Attributes,
    /// The `xmlns` / `xmlns:p` declarations on this element's own start tag.
    namespace_declarations: NamespaceDeclarations,
    /// Byte range in the source, opening `<` through the closing `>`.
    span: Range<usize>,
}

impl Element {
    pub fn qname(&self) -> QName<'_> {
        QName {
            namespace: self.namespace.as_deref(),
            local_name: &self.local_name,
        }
    }

    /// Whether this element is `(ns, local_name)`.
    pub fn is(&self, ns: &str, local_name: &str) -> bool {
        self.namespace.as_deref() == Some(ns) && self.local_name == local_name
    }

    pub fn parent(&self) -> Option<usize> {
        self.parent
    }

    /// The value of attribute `name` (matched by local name).
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The [`INDEX_ATTRIBUTE`] of a deserialized model: which element of the
/// [`Document`] it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ElementRef(usize);

impl ElementRef {
    /// Index of the element in [`Document::elements`].
    pub fn index(self) -> usize {
        self.0
    }
}

/// A parsed, namespace-resolved XML document borrowing its source.
pub struct Document<'a> {
    source: &'a str,
    /// The namespace-resolved rewrite the models are deserialized from.
    resolved: String,
    /// The document element, index 0 (so a document always has one).
    root: Element,
    /// Every other element in document order, index 1 onwards.
    rest: Vec<Element>,
}

impl<'a> Document<'a> {
    /// Parse `xml`, see the [module docs](self) for what is rejected.
    pub fn parse(xml: &'a str) -> Result<Self, XmlError> {
        let mut parser = Parser {
            reader: NsReader::from_str(xml),
            resolved: String::with_capacity(xml.len()),
            elements: Vec::new(),
            open: Vec::new(),
        };
        parser.run()?;
        let mut elements = parser.elements.into_iter();
        let root = elements.next().ok_or_else(|| err("no document element"))?;
        Ok(Self {
            source: xml,
            resolved: parser.resolved,
            root,
            rest: elements.collect(),
        })
    }

    /// Deserialize the document element into the model `T`.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, XmlError> {
        quick_xml::de::from_str(&self.resolved).map_err(err)
    }

    /// The document element.
    pub fn root(&self) -> &Element {
        &self.root
    }

    /// Every element, in document order (index 0 is the document element).
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        std::iter::once(&self.root).chain(&self.rest)
    }

    pub fn element(&self, r: ElementRef) -> Option<&Element> {
        match r.0 {
            0 => Some(&self.root),
            i => self.rest.get(i - 1),
        }
    }

    /// The elements strictly inside element `r`, in document order. A subtree
    /// is contiguous in document order, so these are the elements that follow
    /// `r` and start before it ends.
    pub fn descendants(&self, r: ElementRef) -> impl Iterator<Item = &Element> {
        let end = self.element(r).map_or(0, |e| e.span.end);
        // `rest` starts at index 1, so `rest[r..]` is everything after `r`.
        self.rest
            .get(r.0..)
            .unwrap_or_default()
            .iter()
            .take_while(move |e| e.span.start < end)
    }

    /// The raw source bytes of element `r`, exactly as they appear in the input.
    pub fn source(&self, r: ElementRef) -> Option<&'a str> {
        self.source.get(self.element(r)?.span.clone())
    }

    /// Element `r` as a standalone document: its raw source bytes when those
    /// parse on their own, else with the namespace declarations it inherits from
    /// its ancestors (e.g. a `soap:Envelope`) restored onto its start tag.
    ///
    /// Digest-preserving only because exclusive c14n is pinned: it emits a
    /// declaration only where the prefix is visibly utilized, so restoring the
    /// scope the signer canonicalized in gives the same canonical bytes.
    ///
    /// `None` if even the restored source does not parse, or a URI would need
    /// attribute escaping (fail closed rather than escape).
    pub fn standalone_source(&self, r: ElementRef) -> Option<String> {
        let raw = self.source(r)?;
        if Document::parse(raw).is_ok() {
            return Some(raw.to_owned());
        }
        let inherited = self.inherited_namespaces(r)?;
        if inherited
            .iter()
            .any(|(_, uri)| uri.contains(['"', '&', '<']))
        {
            return None;
        }

        // Insert after the element name, which ends at the first whitespace, `/`
        // or `>`: a fixed position in a known start tag, not a content search.
        let rest = raw.strip_prefix('<')?;
        let insert_at = 1 + rest.find(|c: char| c.is_whitespace() || c == '/' || c == '>')?;
        let declarations: String = inherited
            .iter()
            .map(|(prefix, uri)| match prefix {
                Some(p) => format!(r#" xmlns:{p}="{uri}""#),
                None => format!(r#" xmlns="{uri}""#),
            })
            .collect();
        // `get`, not `[..]`: `insert_at` comes from a `find` on this same string
        // so it is a character boundary, but fail closed rather than panic.
        let restored = format!(
            "{}{declarations}{}",
            raw.get(..insert_at)?,
            raw.get(insert_at..)?
        );
        Document::parse(&restored).ok()?;
        Some(restored)
    }

    /// The namespace declarations element `r` inherits: those in scope on its
    /// parent whose prefix `r` does not redeclare itself (nearest ancestor wins).
    fn inherited_namespaces(&self, r: ElementRef) -> Option<Vec<(Option<&str>, &str)>> {
        let element = self.element(r)?;
        let redeclared = |prefix: Option<&str>| {
            element
                .namespace_declarations
                .iter()
                .any(|(p, _)| p.as_deref() == prefix)
        };
        let mut inherited: Vec<(Option<&str>, &str)> = Vec::new();
        let mut ancestor = element.parent;
        while let Some(i) = ancestor {
            let a = self.element(ElementRef(i))?;
            for (prefix, uri) in &a.namespace_declarations {
                let prefix = prefix.as_deref();
                if !redeclared(prefix) && !inherited.iter().any(|(p, _)| *p == prefix) {
                    inherited.push((prefix, uri));
                }
            }
            ancestor = a.parent;
        }
        // An `xmlns=""` undeclaration only matters where it overrides something;
        // restoring it on a standalone element is a no-op, so leave it out.
        inherited.retain(|(prefix, uri)| prefix.is_some() || !uri.is_empty());
        Some(inherited)
    }
}

/// Parse `xml` and deserialize its document element into `T`.
pub fn from_str<T: DeserializeOwned>(xml: &str) -> Result<T, XmlError> {
    Document::parse(xml)?.deserialize()
}

/// `name` as a local name or prefix: non-empty and colon-free (an XML
/// Namespaces NCName).
///
/// SECURITY: quick-xml splits a name at its *first* colon, so `<foo:a:b>` has
/// local name `a:b`. Rewritten to `unknown.a:b`, serde would split it again and
/// read the element as `b`, so `<foo:a:saml.Issuer>` would match the
/// `saml.Issuer` field. A second colon is never valid, so it is refused.
fn ncname(name: &[u8]) -> Result<&str, XmlError> {
    let name = std::str::from_utf8(name).map_err(err)?;
    if name.is_empty() || name.contains(':') {
        return Err(err(format!("{name:?} is not a valid XML name")));
    }
    Ok(name)
}

/// The single [`NsReader`] pass behind [`Document::parse`].
struct Parser<'a> {
    reader: NsReader<&'a [u8]>,
    resolved: String,
    elements: Vec<Element>,
    /// The open elements: index into `elements` and resolved name.
    open: Vec<(usize, String)>,
}

impl Parser<'_> {
    fn run(&mut self) -> Result<(), XmlError> {
        loop {
            let start = self.position();
            let (ns, event) = self.reader.read_resolved_event().map_err(err)?;
            let namespace = match ns {
                ResolveResult::Bound(ns) => Some(
                    std::str::from_utf8(ns.into_inner())
                        .map_err(err)?
                        .to_owned(),
                ),
                ResolveResult::Unbound => None,
                ResolveResult::Unknown(prefix) => {
                    return Err(err(format!(
                        "undeclared namespace prefix {:?}",
                        String::from_utf8_lossy(&prefix)
                    )));
                }
            };
            match event {
                Event::Start(e) => self.start(&e, namespace, start, false)?,
                Event::Empty(e) => self.start(&e, namespace, start, true)?,
                Event::End(_) => {
                    let (index, name) = self.open.pop().ok_or_else(|| err("unmatched end tag"))?;
                    let end = self.position();
                    if let Some(element) = self.elements.get_mut(index) {
                        element.span.end = end;
                    }
                    write!(self.resolved, "</{name}>").map_err(err)?;
                }
                Event::Text(t) => {
                    // Raw copy: quick-xml splits entity references out into
                    // `GeneralRef` events, so this holds no `<` and no `&`.
                    let text = t.decode().map_err(err)?;
                    self.text(&text)?;
                }
                Event::CData(c) => {
                    let text = c.decode().map_err(err)?;
                    self.text(&quick_xml::escape::escape(text))?;
                }
                Event::GeneralRef(r) => {
                    let name = r.decode().map_err(err)?;
                    let known = match r.resolve_char_ref().map_err(err)? {
                        Some(_) => true,
                        None => quick_xml::escape::resolve_predefined_entity(&name).is_some(),
                    };
                    if !known {
                        return Err(err(format!("unknown entity reference &{name};")));
                    }
                    self.text(&format!("&{name};"))?;
                }
                Event::DocType(_) => return Err(err("a DTD is not allowed")),
                Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {}
                Event::Eof => break,
            }
        }
        if self.elements.is_empty() {
            return Err(err("no document element"));
        }
        if !self.open.is_empty() {
            return Err(err("unexpected end of document"));
        }
        Ok(())
    }

    fn position(&self) -> usize {
        // The input is a `&str` in memory, so its length fits in `usize`.
        usize::try_from(self.reader.buffer_position()).unwrap_or(usize::MAX)
    }

    /// Only whitespace may sit outside the document element.
    fn text(&mut self, text: &str) -> Result<(), XmlError> {
        if self.open.is_empty() {
            if text.trim().is_empty() {
                return Ok(());
            }
            return Err(err("text outside the document element"));
        }
        self.resolved.push_str(text);
        Ok(())
    }

    fn start(
        &mut self,
        e: &BytesStart<'_>,
        namespace: Option<String>,
        start: usize,
        empty: bool,
    ) -> Result<(), XmlError> {
        if self.open.is_empty() && !self.elements.is_empty() {
            return Err(err("more than one document element"));
        }
        if self.elements.len() >= NODE_LIMIT {
            return Err(err(format!("more than {NODE_LIMIT} elements")));
        }
        if self.open.len() >= DEPTH_LIMIT {
            return Err(err(format!("elements nested more than {DEPTH_LIMIT} deep")));
        }

        let local_name = ncname(e.local_name().into_inner())?.to_owned();
        let alias = namespace
            .as_deref()
            .and_then(|ns| NAMESPACES.iter().find(|(uri, _)| *uri == ns))
            .map_or(UNKNOWN_ALIAS, |(_, alias)| alias);
        let name = format!("{alias}.{local_name}");

        let index = self.elements.len();
        write!(self.resolved, r#"<{name} {INDEX_ATTRIBUTE}="{index}""#).map_err(err)?;

        let (attributes, namespace_declarations) = self.attributes(e)?;

        self.elements.push(Element {
            namespace,
            local_name,
            parent: self.open.last().map(|(i, _)| *i),
            attributes,
            namespace_declarations,
            span: start..self.position(),
        });
        if empty {
            self.resolved.push_str("/>");
        } else {
            self.resolved.push('>');
            self.open.push((index, name));
        }
        Ok(())
    }

    /// Write the unprefixed attributes of `e` onto the rewrite, and return all
    /// of its attributes (by local name) and namespace declarations for the
    /// [`Element`].
    fn attributes(
        &mut self,
        e: &BytesStart<'_>,
    ) -> Result<(Attributes, NamespaceDeclarations), XmlError> {
        let mut attributes = Vec::new();
        let mut namespace_declarations = Vec::new();
        for attr in e.attributes() {
            let attr = attr.map_err(err)?;
            let value = attr
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(err)?
                .into_owned();
            if let Some(binding) = attr.key.as_namespace_binding() {
                let prefix = match binding {
                    PrefixDeclaration::Default => None,
                    PrefixDeclaration::Named(p) => Some(ncname(p)?.to_owned()),
                };
                namespace_declarations.push((prefix, value));
                continue;
            }
            let (ns, local) = self.reader.resolver().resolve_attribute(attr.key);
            let local = ncname(local.into_inner())?;
            match ns {
                // Only an unprefixed, dot-free name reaches the rewrite, so the
                // input can never produce `INDEX_ATTRIBUTE` itself.
                ResolveResult::Unbound if !local.contains('.') => {
                    write!(
                        self.resolved,
                        r#" {local}="{}""#,
                        quick_xml::escape::escape(value.as_str())
                    )
                    .map_err(err)?;
                }
                ResolveResult::Unbound | ResolveResult::Bound(_) => {}
                ResolveResult::Unknown(prefix) => {
                    return Err(err(format!(
                        "undeclared namespace prefix {:?}",
                        String::from_utf8_lossy(&prefix)
                    )));
                }
            }
            attributes.push((local.to_owned(), value));
        }
        Ok((attributes, namespace_declarations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::constants::{NS_SAML, NS_SAMLP, NS_SOAP};

    #[derive(Debug, Deserialize)]
    struct Issuers {
        #[serde(rename = "saml.Issuer", default)]
        saml: Vec<String>,
        #[serde(rename = "samlp.Issuer", default)]
        samlp: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct Text {
        #[serde(rename = "@src.index")]
        element: ElementRef,
        #[serde(rename = "$text", default)]
        text: String,
    }

    #[test]
    fn elements_match_by_namespace_not_by_prefix() {
        // Two elements share the local name "Issuer" but live in different
        // namespaces, and a third uses an unusual prefix for the SAML namespace:
        // only the SAML-namespace ones read as `saml:Issuer`.
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}"><other:Issuer xmlns:other="urn:other">WRONG</other:Issuer><saml:Issuer>RIGHT</saml:Issuer><a:Issuer xmlns:a="{NS_SAML}">ALSO</a:Issuer><Issuer>NO-NS</Issuer></samlp:Response>"#
        );
        let issuers: Issuers = from_str(&xml).unwrap();
        assert_eq!(issuers.saml, ["RIGHT", "ALSO"]);
        assert!(issuers.samlp.is_empty());
    }

    #[test]
    fn a_name_with_a_second_colon_cannot_smuggle_a_known_name() {
        // quick-xml's serde takes everything after the *first* colon as the
        // local name, so `unknown.a:saml.Issuer` would read as `saml.Issuer`.
        // A QName has at most one colon (Namespaces in XML §4), so refuse it.
        for xml in [
            r#"<r xmlns:foo="urn:foo"><foo:a:saml.Issuer>FORGED</foo:a:saml.Issuer></r>"#
                .to_string(),
            format!(r#"<r xmlns:saml="{NS_SAML}" xmlns:foo="urn:foo" foo:a:b="x"/>"#),
        ] {
            assert!(Document::parse(&xml).is_err(), "{xml} must be rejected");
        }
    }

    #[test]
    fn default_namespace_applies_to_unprefixed_elements() {
        let xml = format!(
            r#"<Response xmlns="{NS_SAMLP}"><Issuer xmlns="{NS_SAML}">x</Issuer></Response>"#
        );
        let doc = Document::parse(&xml).unwrap();
        assert!(doc.root().is(NS_SAMLP, "Response"));
        let issuers: Issuers = doc.deserialize().unwrap();
        assert_eq!(issuers.saml, ["x"]);
    }

    #[test]
    fn text_is_unescaped_and_comments_are_invisible() {
        let xml = format!(
            r#"<r xmlns:saml="{NS_SAML}"><saml:Issuer>a &amp; b &lt;c&gt;<!--EVIL--><![CDATA[&d]]>&#65;</saml:Issuer></r>"#
        );
        let issuers: Issuers = from_str(&xml).unwrap();
        assert_eq!(issuers.saml, ["a & b <c>&dA"]);
    }

    #[test]
    fn a_text_field_rejects_element_children() {
        // SECURITY: `<saml:Issuer><x>urn:rd</x></saml:Issuer>` must not read as
        // `urn:rd`; a `String` field over an element with children is an error.
        let xml =
            format!(r#"<r xmlns:saml="{NS_SAML}"><saml:Issuer><x>urn:rd</x></saml:Issuer></r>"#);
        assert!(from_str::<Issuers>(&xml).is_err());
    }

    #[test]
    fn an_element_forged_in_a_comment_is_invisible() {
        let xml = format!(
            r#"<r xmlns:saml="{NS_SAML}"><!--<saml:Issuer>FORGED</saml:Issuer>--><saml:Issuer>GENUINE</saml:Issuer></r>"#
        );
        let issuers: Issuers = from_str(&xml).unwrap();
        assert_eq!(issuers.saml, ["GENUINE"]);
    }

    #[test]
    fn malformed_or_unsafe_documents_are_rejected() {
        for xml in [
            "",
            "   ",
            "not xml <<<",
            r#"<saml:Assertion>x</saml:Assertion>"#,
            r#"<r xmlns="urn:x"><a></r>"#,
            r#"<r xmlns="urn:x"/><r xmlns="urn:x"/>"#,
            r#"<r xmlns="urn:x">"#,
            r#"<r xmlns="urn:x"/>trailing"#,
            r#"<r xmlns="urn:x" a="1" a="2"/>"#,
            r#"<r xmlns="urn:x" p:a="1"/>"#,
            r#"<r xmlns="urn:x">&custom;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY e "x">]><r xmlns="urn:x">&e;</r>"#,
        ] {
            assert!(Document::parse(xml).is_err(), "{xml:?} must be rejected");
        }
    }

    #[test]
    fn excessive_nesting_is_rejected() {
        let deep = format!(
            "{}{}",
            "<a>".repeat(DEPTH_LIMIT + 1),
            "</a>".repeat(DEPTH_LIMIT + 1)
        );
        assert!(Document::parse(&deep).is_err());
    }

    #[test]
    fn recursion_up_to_the_depth_limit_does_not_exhaust_the_stack() {
        // `StatusCode` nests itself, so a hostile Status recurses the serde
        // deserializer as deep as the depth limit lets it.
        let depth = DEPTH_LIMIT - 2;
        let xml = format!(
            r#"<Status xmlns="{NS_SAMLP}">{}{}</Status>"#,
            r#"<StatusCode Value="x">"#.repeat(depth),
            "</StatusCode>".repeat(depth)
        );
        let status: crate::saml::model::Status = from_str(&xml).unwrap();
        assert_eq!(status.code(), Some("x"));
    }

    #[test]
    fn the_index_attribute_cannot_be_forged() {
        // An input attribute spelled like the injected one (with or without a
        // prefix) is dropped, so a model always points at its own element.
        let xml = format!(
            r#"<r xmlns:saml="{NS_SAML}" xmlns:src="urn:src"><saml:Issuer src.index="0" src:index="0">x</saml:Issuer></r>"#
        );
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "saml.Issuer")]
            issuer: Text,
        }
        let doc = Document::parse(&xml).unwrap();
        let r: R = doc.deserialize().unwrap();
        assert_eq!(r.issuer.element.index(), 1);
        assert!(doc.element(r.issuer.element).unwrap().is(NS_SAML, "Issuer"));
        assert_eq!(r.issuer.text, "x");
    }

    #[test]
    fn source_returns_exact_element_bytes() {
        let xml = r#"<root xmlns="urn:r"><a>x</a><enc xmlns="urn:e"><data>cipher</data></enc><e/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let sources: Vec<&str> = (0..doc.elements().count())
            .map(|i| doc.source(ElementRef(i)).unwrap())
            .collect();
        assert_eq!(
            sources,
            [
                xml,
                "<a>x</a>",
                r#"<enc xmlns="urn:e"><data>cipher</data></enc>"#,
                "<data>cipher</data>",
                "<e/>",
            ]
        );
    }

    #[test]
    fn attributes_are_read_by_local_name_and_normalized() {
        let xml = "<r xmlns=\"urn:x\" xml:id=\"i\" foo=\"a\tb\"/>";
        let doc = Document::parse(xml).unwrap();
        assert_eq!(doc.root().attribute("id"), Some("i"));
        assert_eq!(doc.root().attribute("foo"), Some("a b"));
        assert_eq!(doc.root().attribute("missing"), None);
    }

    #[test]
    fn inherited_namespaces_make_a_sliced_element_parse_standalone() {
        // samlp:/saml: are declared on the envelope, not on the sliced element.
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{NS_SOAP}" xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}"><soap:Body><samlp:ArtifactResponse ID="_a1"><saml:Issuer>urn:rd</saml:Issuer></samlp:ArtifactResponse></soap:Body></soap:Envelope>"#
        );
        let doc = Document::parse(&xml).unwrap();
        let art = ElementRef(2);
        assert!(doc.element(art).unwrap().is(NS_SAMLP, "ArtifactResponse"));

        // The raw slice has undeclared prefixes.
        let raw = doc.source(art).unwrap();
        assert!(
            Document::parse(raw).is_err(),
            "raw slice must not parse: {raw}"
        );

        // With the inherited declarations restored it parses, and is the same
        // element with the same content.
        let restored = doc.standalone_source(art).unwrap();
        let restored = Document::parse(&restored).expect("restored slice must parse");
        assert!(restored.root().is(NS_SAMLP, "ArtifactResponse"));
        assert_eq!(restored.root().attribute("ID"), Some("_a1"));
        let issuers: Issuers = restored.deserialize().unwrap();
        assert_eq!(issuers.saml, ["urn:rd"]);
    }

    #[test]
    fn self_contained_element_source_is_returned_unchanged() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{NS_SOAP}"><soap:Body><samlp:Response xmlns:samlp="{NS_SAMLP}" ID="_r1"/></soap:Body></soap:Envelope>"#
        );
        let doc = Document::parse(&xml).unwrap();
        let response = ElementRef(2);
        assert_eq!(
            doc.standalone_source(response).as_deref(),
            doc.source(response)
        );
    }
}
