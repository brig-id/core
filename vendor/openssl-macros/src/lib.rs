// Patched for Rust 1.96: avoid round-tripping the function body through
// syn::ItemFn + quote!, which drops the `c` prefix from C string literals on
// that compiler version. Instead we inject the doc attributes as raw token
// text and re-emit the original item token stream unchanged.

use proc_macro::TokenStream;
use proc_macro2::Ident;
use syn::parse_macro_input;

#[proc_macro_attribute]
pub fn corresponds(attr: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(attr as Ident);
    let function = function.to_string();

    let line = format!(
        "This corresponds to [`{0}`](https://www.openssl.org/docs/manmaster/man3/{0}.html).",
        function
    );

    // Build the doc attributes as token text and parse them — no C string
    // literals appear here, so parsing is safe on all stable Rust versions.
    let doc_tokens: TokenStream = format!(
        r#"#[doc = ""] #[doc = {:?}] #[doc(alias = {:?})]"#,
        line, function
    )
    .parse()
    .expect("doc attribute tokens are always valid");

    // Chain the doc tokens with the original, unmodified item token stream.
    // The item is never deserialized through syn, so C string literals survive.
    doc_tokens.into_iter().chain(item).collect()
}
