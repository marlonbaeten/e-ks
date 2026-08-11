# Bundling libxmlsec1 + libxml2 into the binary — findings

Goal: ship the `backend-xmlsec` build as a self-contained binary with **no
system libxmlsec1/libxml2 runtime dependency**, so it is as portable as the
pure-Rust `bergshamra` default. This documents what that actually takes, with
the spike results, so the tradeoff is a decision and not a guess.

## TL;DR

Bundling is **feasible but not a flag-flip**. There is no turnkey crate; the
only fully-clean route is a **vendored from-source build** of libxml2 + xmlsec
with XSLT and ICU disabled. A static link of the *distro* archives gets most of
the way (xmlsec1, xml2, ssl, crypto bundled) but cannot finish, because the
distro ships no `libxslt.a` and its `libxslt.so` drags `libxml2.so` back in.

Effort estimate: **moderate on Linux** (a from-source `build.rs`, ~days),
**high cross-platform** (Windows/macOS toolchains). For comparison, the default
`bergshamra` backend already is a zero-system-dep static binary for free.

## What the ecosystem gives you (verified 2026-08)

| Need | Turnkey crate? | Notes |
| --- | --- | --- |
| Vendored OpenSSL source + build | **yes** — `openssl-src` (92M dl) | crypto backend can be vendored cleanly |
| Vendored libxml2 source + build | **no** | no `libxml2-src`; `libxml` crate links system only |
| Vendored libxmlsec1 source + build | **no** | no `xmlsec1-src` of any kind |
| Build tooling | `cc`, `cmake`, `bindgen`, `pkg-config` | present and usable |

So OpenSSL vendors for free; **libxml2 and libxmlsec1 must be built from source
by our own `build.rs`** — that is the missing turnkey piece.

## Upstream build systems

- **libxml2**: CMake (modern) or autotools. `cmake` crate can drive a static
  build with `-DLIBXML2_WITH_ICU=OFF -DLIBXML2_WITH_HTTP=OFF … -DBUILD_SHARED_LIBS=OFF`.
- **libxmlsec1 1.2.x** (the current Debian/Ubuntu series, what this repo links):
  **autotools only** — `./configure --enable-static --without-libxslt --with-openssl=…`
  then `make`. No CMakeLists.txt in 1.2.x.
- **libxmlsec1 1.3.x**: adds CMake support. Moving to 1.3 would let one `cmake`
  crate invocation build it, which is why a source-build effort should target 1.3.

Static consumers also need `-DXMLSEC_STATIC -DLIBXML_STATIC` (mostly a Windows
symbol-visibility concern; a no-op on Linux ELF, which is why the spike links
without them).

## The distro-archive spike (in `build.rs`, `XMLSEC_MINI_SYS_STATIC=1`)

`build.rs` can statically link the archives Ubuntu ships. Result, verified by
`ldd` on the built test binary:

- **Bundled (gone from `ldd`)**: `libxmlsec1-openssl.a`, `libxmlsec1.a`,
  `libxml2.a`, `libssl.a`, `libcrypto.a`. The conformance suite passes.
- **Still dynamic**: `libxslt.so.1`, `libicuuc/​libicudata.so.74`, and — the
  blocker — **`libxml2.so.2` reappears**.

Two hard limits the spike exposed, both pointing at the same fix:

1. **No `libxslt.a`.** The distro ships only `libxslt.so`. libxmlsec1.a was built
   referencing libxslt, so xslt can't simply be dropped.
2. **`libxslt.so` depends on `libxml2.so`.** Linking xslt dynamically pulls the
   *shared* libxml2 back in beside the static `libxml2.a` we bundled — a
   duplicate-libxml2 in one process, which is both not-bundled and a latent
   symbol hazard.
3. Enumerating the transitive private chain (ICU, z, lzma, …) is manual: it comes
   from `pkg-config --static --libs`, but pkg-config refuses to *static*-link
   libraries in system dirs, so each layer is emitted by hand.

Net: the distro-archive path bundles the core but **cannot produce a clean
xml2-free binary**, because xslt has no archive and re-imports xml2.

## The clean route (recommended if bundling is pursued)

Vendor and build from source in `xmlsec-mini-sys/build.rs`:

1. `openssl-src` → static libcrypto/libssl (or reuse the app's existing OpenSSL).
2. Vendor **libxml2** source; `cmake` crate → static `libxml2.a`, `--without-icu`
   (removes the ICU pull), no http/ftp/python.
3. Vendor **libxmlsec1 1.3.x** source; `cmake` crate → static `libxmlsec1.a` +
   `libxmlsec1-openssl.a`, `--without-libxslt` (removes xslt entirely — eID uses
   no XSLT transforms, and disabling them is also a security win), pointed at the
   libxml2 and OpenSSL built above.
4. Emit the static link chain (no xslt, no ICU): `xmlsec1-openssl xmlsec1 xml2
   ssl crypto` + base `z lzma m dl pthread`.

With xslt and ICU compiled out, the `libxml2.so` re-import disappears and the
binary is genuinely self-contained on Linux. The FFI bindings and all Rust above
`xmlsec-mini-sys` stay byte-for-byte identical — this is a `build.rs`-only change.

## Recommendation

Given the pure-Rust `bergshamra` default already ships a zero-system-dependency
static binary, the xmlsec backend's value is **cross-checking against the
reference C implementation**, for which linking the system libxmlsec1 (current
default) is entirely adequate. Pursue the vendored static build only if xmlsec
must become a *shippable* backend; budget it as a Linux-first, 1.3.x-targeted
`build.rs` effort, and keep cross-platform out of scope until proven necessary.
