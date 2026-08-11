/* Headers for the minimal libxmlsec1 + libxml2 surface we bind.
 *
 * The OpenSSL crypto backend is selected via the -DXMLSEC_CRYPTO_OPENSSL flag
 * that `pkg-config --cflags xmlsec1-openssl` emits (build.rs forwards it to
 * bindgen), so the concrete `xmlSecOpenSSL*` functions below are declared. Only
 * the symbols allow-listed in build.rs are emitted into the Rust bindings. */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
