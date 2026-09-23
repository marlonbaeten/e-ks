//! Shared validation context and checks for the SAML validators.

use crate::{
    saml::{
        constants::{CLOCK_SKEW_SECONDS, MESSAGE_FRESHNESS_SECONDS, STATUS_SUCCESS},
        model::Status,
        xml::Document,
    },
    types::EntityId,
};
use chrono::{DateTime, Duration, Utc};

/// Context threaded through every validation step: the parsed document (for the
/// source bytes of signed and encrypted elements), one wall-clock reference with
/// the eID §9.5 clock-skew allowance, and the error accumulator the checks push
/// their findings onto.
///
/// Mirrors the validators' contract: checks never abort, they record errors;
/// the caller treats the result as valid only when no error was recorded.
pub(super) struct Validator<'a, 'input> {
    pub doc: &'a Document<'input>,
    pub now: DateTime<Utc>,
    pub skew: Duration,
    pub errors: &'a mut Vec<String>,
}

impl<'a, 'input> Validator<'a, 'input> {
    pub fn new(doc: &'a Document<'input>, errors: &'a mut Vec<String>) -> Self {
        Self {
            doc,
            now: Utc::now(),
            skew: Duration::seconds(CLOCK_SKEW_SECONDS),
            errors,
        }
    }

    pub fn error(&mut self, message: String) {
        self.errors.push(message);
    }

    /// eID §7.6.1/§7.6.2/§7.6.3 (and SAML core): `@Version` MUST be exactly `2.0`.
    /// A missing or differing version fails closed rather than being ignored.
    pub fn check_version(&mut self, version: Option<&str>, label: &str) {
        match version {
            Some("2.0") => {}
            Some(v) => self.error(format!(
                "{label} has unsupported @Version {v:?} (MUST be 2.0)"
            )),
            None => self.error(format!("{label} is missing the required @Version")),
        }
    }

    /// eID §7.6.1/§7.6.2/§7.6.3.5 rule 1: the `<saml:Issuer>` MUST be the pinned
    /// RD EntityID, so an RD-signed envelope naming a different entity is
    /// rejected. `None` skips the check (tests). (An Issuer with element children
    /// never gets here: the model rejects it at parse time.)
    pub fn check_issuer(
        &mut self,
        issuer: Option<&str>,
        expected_issuer: Option<&EntityId>,
        label: &str,
    ) {
        let Some(expected) = expected_issuer else {
            return;
        };
        match issuer.map(str::trim) {
            Some(i) if expected == i => {}
            Some(i) => self.error(format!(
                "{label} Issuer mismatch: expected {expected}, got {i}"
            )),
            None => self.error(format!("{label} has no Issuer")),
        }
    }

    /// eID §7.6.1/§7.6.2: require a `Success` StatusCode, composing the
    /// second-level StatusCode and StatusMessage (§7.8) into the error so the actual
    /// reason is visible in logs. Returns the top-level status code for callers that
    /// branch on it.
    pub fn check_status_success(&mut self, status: Option<&Status>, label: &str) -> Option<String> {
        let status_code = status.and_then(Status::code);
        if status_code != Some(STATUS_SUCCESS) {
            self.error(format!(
                "{label} status: {} ({}) - {}",
                status_code.unwrap_or("unknown"),
                status
                    .and_then(Status::second_level_code)
                    .unwrap_or_default(),
                status
                    .and_then(|s| s.status_message.as_deref())
                    .unwrap_or_default()
            ));
        }
        status_code.map(str::to_owned)
    }

    /// Bound an `@IssueInstant`/`@AuthnInstant` on both sides: reject a value older
    /// than the message-freshness window (plus skew) and one further in the future
    /// than skew allows.
    ///
    /// eID §7.6.1/§7.6.2/§7.6.3 give `@IssueInstant` cardinality 1 on every message
    /// we receive and §7.6.3 the same for `@AuthnInstant`, so an absent or
    /// unparseable value fails closed rather than skipping the freshness bound.
    ///
    /// The spec sets no explicit freshness window (it bounds the Assertion only via
    /// `Conditions`), so [MESSAGE_FRESHNESS_SECONDS] is our own ceiling: the
    /// envelope types carry no `Conditions` at all, which would otherwise leave
    /// them unbounded in time. The future bound matters for the same reason:
    /// without it a far-future instant would never expire.
    pub fn check_freshness(&mut self, val: Option<&str>, label: &str) {
        let Some(s) = val else {
            self.error(format!("{label} is missing (required, cardinality 1)"));
            return;
        };
        let Ok(t) = s.parse::<DateTime<Utc>>() else {
            self.error(format!("{label} has an invalid timestamp: {s}"));
            return;
        };
        let max_age = Duration::seconds(MESSAGE_FRESHNESS_SECONDS);
        let Some(stale_after) = self.shifted(t, max_age + self.skew, label, s) else {
            return;
        };
        let Some(not_before) = self.shifted(t, -self.skew, label, s) else {
            return;
        };
        if stale_after < self.now {
            self.error(format!("{label} is stale: issued at {s}"));
        } else if not_before > self.now {
            self.error(format!("{label} is in the future: issued at {s}"));
        }
    }

    /// `t` shifted by `delta`, or `None` (with an error recorded) when the shift
    /// is not representable.
    ///
    /// chrono's `+`/`-` on a `DateTime` **panic** on overflow, and every instant
    /// the validators shift is a wire value: a timestamp near the edge of the
    /// representable range (chrono parses years up to +262142) would take the
    /// process down. An instant that cannot absorb a 30-second skew allowance is
    /// nonsense anyway, so it is rejected rather than reasoned about.
    fn shifted(
        &mut self,
        t: DateTime<Utc>,
        delta: Duration,
        label: &str,
        raw: &str,
    ) -> Option<DateTime<Utc>> {
        let shifted = t.checked_add_signed(delta);
        if shifted.is_none() {
            self.error(format!(
                "{label} timestamp is outside the usable range: {raw}"
            ));
        }
        shifted
    }

    /// eID §7.6.3 (cardinality 1): `Conditions/@NotBefore` is mandatory (stricter
    /// than SAML core, where it is optional). Reject a missing, unparseable, or
    /// not-yet-valid value.
    pub fn check_not_before(&mut self, val: Option<&str>, label: &str) {
        if let Some((t, s)) = self.parse_required_instant(val, "NotBefore", label)
            && let Some(not_before) = self.shifted(t, -self.skew, label, s)
            && not_before > self.now
        {
            self.error(format!("{label} not yet valid: NotBefore {s}"));
        }
    }

    /// eID §7.6.3 (cardinality 1) / §9.5: @NotOnOrAfter is mandatory, so a missing
    /// or unparseable value fails closed rather than silently skipping the
    /// freshness check (an assertion with no/garbage expiry must not be accepted).
    pub fn check_not_on_or_after(&mut self, val: Option<&str>, label: &str) {
        if let Some((t, s)) = self.parse_required_instant(val, "NotOnOrAfter", label)
            && let Some(expires_at) = self.shifted(t, self.skew, label, s)
            && expires_at < self.now
        {
            self.error(format!("{label} expired: {s}"));
        }
    }

    /// Parse a mandatory timestamp attribute, failing closed: a missing or
    /// unparseable value records an error and yields `None`. On success the parsed
    /// instant is returned together with the raw string (for error messages).
    fn parse_required_instant<'v>(
        &mut self,
        val: Option<&'v str>,
        attr: &str,
        label: &str,
    ) -> Option<(DateTime<Utc>, &'v str)> {
        let Some(s) = val else {
            self.error(format!("{label} is missing the required {attr}"));
            return None;
        };
        match s.parse::<DateTime<Utc>>() {
            Ok(t) => Some((t, s)),
            Err(_) => {
                self.error(format!("{label} has an invalid {attr} timestamp: {s}"));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::constants::NS_SAMLP;

    /// Run `check` with a [`Validator`] over a dummy document and return the
    /// recorded errors (the checks here never read the document).
    fn time_check_errors(check: impl FnOnce(&mut Validator)) -> Vec<String> {
        let doc = Document::parse(r#"<x xmlns="urn:x"/>"#).unwrap();
        let mut errors = Vec::new();
        check(&mut Validator::new(&doc, &mut errors));
        errors
    }

    // -- check_status_success --

    fn status(xml: &str) -> Status {
        crate::saml::xml::from_str(&format!(r#"<Status xmlns="{NS_SAMLP}">{xml}</Status>"#))
            .expect("test Status parses")
    }

    #[test]
    fn check_status_success_accepts_success() {
        let s = status(&format!(r#"<StatusCode Value="{STATUS_SUCCESS}"/>"#));
        let errors = time_check_errors(|v| {
            assert_eq!(
                v.check_status_success(Some(&s), "Test").as_deref(),
                Some(STATUS_SUCCESS)
            );
        });
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn check_status_success_reports_second_level_code_and_message() {
        let s = status(
            r#"<StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></StatusCode><StatusMessage>Authentication cancelled</StatusMessage>"#,
        );
        let errors = time_check_errors(|v| {
            v.check_status_success(Some(&s), "Test");
        });
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Responder"), "{errors:?}");
        assert!(errors[0].contains("AuthnFailed"), "{errors:?}");
        assert!(errors[0].contains("Authentication cancelled"), "{errors:?}");
    }

    #[test]
    fn check_status_success_rejects_a_missing_status() {
        let errors = time_check_errors(|v| {
            assert!(v.check_status_success(None, "Test").is_none());
        });
        assert!(errors[0].contains("unknown"), "{errors:?}");
    }

    // -- check_not_on_or_after --

    #[test]
    fn check_not_on_or_after_valid() {
        let future = (Utc::now() + Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let errors = time_check_errors(|v| v.check_not_on_or_after(Some(&future), "Test"));
        assert!(errors.is_empty());
    }

    #[test]
    fn check_not_on_or_after_expired() {
        let past = (Utc::now() - Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let errors = time_check_errors(|v| v.check_not_on_or_after(Some(&past), "Test"));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("expired"));
    }

    #[test]
    fn check_freshness_bounds_both_directions_and_requires_presence() {
        let at = |offset: Duration| {
            (Utc::now() + offset)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        };

        // A recent instant is fresh.
        let errors =
            time_check_errors(|v| v.check_freshness(Some(&at(-Duration::seconds(10))), "Msg"));
        assert!(errors.is_empty(), "fresh instant: {errors:?}");

        // eID cardinality 1: an absent instant fails closed.
        let errors = time_check_errors(|v| v.check_freshness(None, "Msg"));
        assert!(
            errors.iter().any(|e| e.contains("is missing")),
            "{errors:?}"
        );

        // Older than the freshness window plus skew is stale.
        let errors =
            time_check_errors(|v| v.check_freshness(Some(&at(-Duration::seconds(400))), "Msg"));
        assert!(errors.iter().any(|e| e.contains("stale")), "{errors:?}");

        // Further in the future than skew allows is rejected too: without this a
        // far-future instant would never age out.
        let errors = time_check_errors(|v| v.check_freshness(Some(&at(Duration::hours(1))), "Msg"));
        assert!(
            errors.iter().any(|e| e.contains("in the future")),
            "{errors:?}"
        );

        // Inside the skew allowance a slightly-future instant is still accepted.
        let errors =
            time_check_errors(|v| v.check_freshness(Some(&at(Duration::seconds(5))), "Msg"));
        assert!(errors.is_empty(), "within skew: {errors:?}");

        // An unparseable instant fails closed.
        let errors = time_check_errors(|v| v.check_freshness(Some("garbage"), "Msg"));
        assert!(errors.iter().any(|e| e.contains("invalid timestamp")));
    }

    #[test]
    fn check_not_before_requires_presence_and_rejects_future() {
        let at = |offset: Duration| {
            (Utc::now() + offset)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        };

        // eID §7.6.3 makes Conditions/@NotBefore mandatory.
        let errors = time_check_errors(|v| v.check_not_before(None, "Test"));
        assert!(
            errors.iter().any(|e| e.contains("missing the required")),
            "{errors:?}"
        );

        let errors =
            time_check_errors(|v| v.check_not_before(Some(&at(Duration::hours(1))), "Test"));
        assert!(
            errors.iter().any(|e| e.contains("not yet valid")),
            "{errors:?}"
        );

        let errors = time_check_errors(|v| v.check_not_before(Some("nonsense"), "Test"));
        assert!(errors.iter().any(|e| e.contains("invalid NotBefore")));

        let errors =
            time_check_errors(|v| v.check_not_before(Some(&at(-Duration::minutes(5))), "Test"));
        assert!(errors.is_empty(), "past NotBefore: {errors:?}");
    }

    #[test]
    fn check_not_on_or_after_missing_or_malformed_fails_closed() {
        // Absent @NotOnOrAfter is a mandatory-element violation, not "no check".
        let errors = time_check_errors(|v| v.check_not_on_or_after(None, "Test"));
        assert!(errors.iter().any(|e| e.contains("missing the required")));

        // An unparseable timestamp must also be rejected, not silently accepted.
        let errors =
            time_check_errors(|v| v.check_not_on_or_after(Some("not-a-timestamp"), "Test"));
        assert!(errors.iter().any(|e| e.contains("invalid NotOnOrAfter")));
    }

    /// The largest instant chrono can parse. Shifting it by the skew allowance
    /// overflows, and chrono's `+` panics on overflow, so every timestamp check
    /// must reject it instead of arithmetic-ing on it.
    const MAX_PARSEABLE_INSTANT: &str = "+262142-12-31T23:59:59Z";
    /// The smallest instant chrono can parse: the same hazard, subtracting skew.
    const MIN_PARSEABLE_INSTANT: &str = "-262143-01-01T00:00:00Z";

    #[test]
    fn timestamps_at_the_edge_of_the_range_are_rejected_not_panicked_on() {
        // A hostile `@IssueInstant` / `@NotBefore` / `@NotOnOrAfter` at the edge
        // of chrono's range must be refused, never take the process down.
        for raw in [MAX_PARSEABLE_INSTANT, MIN_PARSEABLE_INSTANT] {
            assert!(
                raw.parse::<DateTime<Utc>>().is_ok(),
                "{raw} must actually parse, or this test proves nothing"
            );

            let errors = time_check_errors(|v| v.check_freshness(Some(raw), "Test"));
            assert!(!errors.is_empty(), "freshness accepted {raw}");

            let errors = time_check_errors(|v| v.check_not_before(Some(raw), "Test"));
            assert!(!errors.is_empty(), "NotBefore accepted {raw}");

            let errors = time_check_errors(|v| v.check_not_on_or_after(Some(raw), "Test"));
            assert!(!errors.is_empty(), "NotOnOrAfter accepted {raw}");
        }
    }
}
