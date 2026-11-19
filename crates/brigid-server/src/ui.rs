//! The interface, served by the server itself.
//!
//! A released server carries the built interface inside its executable
//! (`brigid-ui-embed`, from the edition's `build.rs`): no directory to install
//! next to it. A development build
//! carries none and reads the directory named by `server.ui_dist_dir`
//! instead. Both go through the same code, so what the tests and the
//! end-to-end suites see is what a released server does.
//!
//! - A page is a file: `/signup/` is `signup/index.html`. A path that names
//!   nothing answers `404`; there is no page that answers for all the others.
//! - Files whose name carries a hash of their content (`/build/`, `/assets/`)
//!   are cached for good; the others are checked again each time (`ETag`).
//! - Every response of the interface is served under the Content Security
//!   Policy made from the build's list of script hashes. Without that list
//!   there is no interface: never a weaker policy.

use std::{
    borrow::Cow,
    collections::HashMap,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use tower_http::set_header::SetResponseHeaderLayer;

/// The interface an executable carries: the table `brigid-ui-embed` writes
/// at build time, which the edition includes and hands over as it is.
#[derive(Clone, Copy)]
pub struct EmbeddedUi {
    /// Each file: its path, its bytes, and whether they are gzip.
    pub files: &'static [(&'static str, &'static [u8], bool)],
    /// The build's list of script hashes; `None` when nothing is embedded.
    pub csp_hashes: Option<&'static str>,
}

impl EmbeddedUi {
    /// An executable without an interface (a development build).
    pub const NONE: Self = Self {
        files: &[],
        csp_hashes: None,
    };
}

/// The list of script hashes of a build: read, never served.
const CSP_HASHES: &str = "csp-hashes.json";
/// The bundler's own report: not served.
const NOT_SERVED: &[&str] = &["q-manifest.json"];

/// Why a directory cannot be served as the interface.
#[derive(Debug)]
pub enum UiError {
    /// The directory or one of its files cannot be read.
    Unreadable(PathBuf, std::io::Error),
    /// No `index.html`: not a build of the interface.
    NoIndex(PathBuf),
    /// No usable `csp-hashes.json`: the pages would have no policy to be
    /// served under.
    NoPolicy(String),
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(path, e) => write!(f, "{} cannot be read: {e}", path.display()),
            Self::NoIndex(path) => write!(
                f,
                "{} has no index.html: it is not a build of the interface",
                path.display()
            ),
            Self::NoPolicy(why) => write!(
                f,
                "no Content Security Policy for the interface ({why}): build it again \
                 with `pnpm build`, which writes {CSP_HASHES}"
            ),
        }
    }
}

impl std::error::Error for UiError {}

struct File {
    content_type: &'static str,
    /// The file as it is, or gzip-compressed when `gzip`.
    bytes: Cow<'static, [u8]>,
    gzip: bool,
    /// `"<hash>"`: changes when the content does.
    etag: HeaderValue,
    /// Its name carries a hash of its content: it never changes.
    immutable: bool,
}

/// A build of the interface, ready to be served.
pub struct Ui {
    files: HashMap<String, File>,
    csp: HeaderValue,
}

impl Ui {
    /// The interface this executable carries, if it carries one.
    pub fn embedded(embedded: &EmbeddedUi) -> Option<Self> {
        let hashes = embedded.csp_hashes?;
        let csp = policy(hashes).expect("the embedded list of hashes was checked at build time");
        let files = embedded
            .files
            .iter()
            .map(|(path, bytes, gzip)| {
                ((*path).to_owned(), file(path, Cow::Borrowed(*bytes), *gzip))
            })
            .collect();
        Some(Self { files, csp })
    }

    /// The build in directory `dist`, read into memory once. The development
    /// option: a change on disk is seen at the next start.
    pub fn from_dir(dist: &Path) -> Result<Self, UiError> {
        let hashes = std::fs::read_to_string(dist.join(CSP_HASHES))
            .map_err(|e| UiError::NoPolicy(format!("{CSP_HASHES}: {e}")))?;
        let csp = policy(&hashes)?;
        let mut files = HashMap::new();
        read_dir(dist, dist, &mut files)?;
        if !files.contains_key("index.html") {
            return Err(UiError::NoIndex(dist.to_owned()));
        }
        Ok(Self { files, csp })
    }

    /// How many files it serves.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The Content Security Policy its responses are served under.
    pub fn csp(&self) -> &str {
        self.csp.to_str().unwrap_or_default()
    }

    /// Answers a request no route of the API took.
    fn respond(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Response {
        let Some(key) = file_key(path) else {
            return not_found();
        };
        let Some(file) = self.files.get(key.as_ref()) else {
            // A directory asked without its final slash: say where it is.
            if !path.ends_with('/') && self.files.contains_key(&format!("{key}/index.html")) {
                let to = match query {
                    Some(query) => format!("{path}/?{query}"),
                    None => format!("{path}/"),
                };
                return match HeaderValue::from_str(&to) {
                    Ok(to) => {
                        (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, to)]).into_response()
                    }
                    Err(_) => not_found(),
                };
            }
            return not_found();
        };
        if method != Method::GET && method != Method::HEAD {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, HeaderValue::from_static("GET, HEAD"))],
            )
                .into_response();
        }

        let mut response = Response::new(Body::empty());
        let h = response.headers_mut();
        h.insert(header::ETAG, file.etag.clone());
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if file.immutable {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        if headers
            .get(header::IF_NONE_MATCH)
            .is_some_and(|seen| seen == file.etag)
        {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            return response;
        }
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        let body: Cow<'_, [u8]> = if !file.gzip {
            Cow::Borrowed(&file.bytes)
        } else {
            h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
            if accepts_gzip(headers) {
                h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                Cow::Borrowed(&file.bytes)
            } else {
                // Rare (a client that takes no compression): unpacked for it.
                let mut plain = Vec::new();
                if flate2::read::GzDecoder::new(&file.bytes[..])
                    .read_to_end(&mut plain)
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                Cow::Owned(plain)
            }
        };
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        if method == Method::GET {
            *response.body_mut() = Body::from(body.into_owned());
        }
        response
    }
}

/// Serves `ui` for every request no route of `router` takes, then applies
/// the security headers to the whole router, routes and interface alike.
///
/// `brigid_api::build_router` sets the same headers on its own routes, with
/// a policy that loads nothing (they answer with JSON or a redirect).
/// `if_not_present` leaves those alone: only the interface's responses get
/// the interface's policy. Without an interface, unknown paths are `404`.
pub fn apply_ui(router: Router, ui: Option<Arc<Ui>>) -> Router {
    let csp = ui.as_ref().map_or_else(
        // No page is served: nothing may be loaded from a response.
        || HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        |ui| ui.csp.clone(),
    );
    let router = match ui {
        Some(ui) => router.fallback(move |request: Request<Body>| {
            let ui = Arc::clone(&ui);
            async move {
                ui.respond(
                    request.method(),
                    request.uri().path(),
                    request.uri().query(),
                    request.headers(),
                )
            }
        }),
        None => router,
    };
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            csp,
        ))
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "Not found\n",
    )
        .into_response()
}

/// The file a request path names: `/` and `/signup/` name an `index.html`.
/// `None` for a path that could name something outside the build.
fn file_key(path: &str) -> Option<Cow<'_, str>> {
    let path = path.strip_prefix('/')?;
    if path
        .split('/')
        .any(|part| part == ".." || part == "." || part.contains(['\\', '\0']))
        || path.contains("//")
        || path.starts_with('/')
    {
        return None;
    }
    Some(if path.is_empty() || path.ends_with('/') {
        Cow::Owned(format!("{path}index.html"))
    } else {
        Cow::Borrowed(path)
    })
}

/// Whether the client takes gzip: named in `Accept-Encoding`, and not
/// refused with `q=0`.
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| {
            let mut parts = coding.split(';').map(str::trim);
            matches!(parts.next(), Some("gzip" | "*"))
                && !parts.any(|p| {
                    matches!(
                        p.replace(' ', "").as_str(),
                        "q=0" | "q=0.0" | "q=0.00" | "q=0.000"
                    )
                })
        })
}

fn file(path: &str, bytes: Cow<'static, [u8]>, gzip: bool) -> File {
    File {
        content_type: content_type(path),
        etag: HeaderValue::from_str(&format!("\"{:016x}-{}\"", fnv1a(&bytes), bytes.len()))
            .expect("hexadecimal"),
        immutable: path.starts_with("build/") || path.starts_with("assets/"),
        bytes,
        gzip,
    }
}

/// FNV-1a, 64 bits: tells one content of a file from the next for the
/// browser's cache. Not a protection of anything.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The types the interface is made of. Anything else is sent as bytes to
/// save, which a browser does not run.
fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        "jpg" | "jpeg" => "image/jpeg",
        "avif" => "image/avif",
        "webp" => "image/webp",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn read_dir(root: &Path, dir: &Path, files: &mut HashMap<String, File>) -> Result<(), UiError> {
    let unreadable = |e| UiError::Unreadable(dir.to_owned(), e);
    for entry in std::fs::read_dir(dir).map_err(unreadable)? {
        let path = entry.map_err(unreadable)?.path();
        if path.is_dir() {
            read_dir(root, &path, files)?;
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let key = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if key == CSP_HASHES || NOT_SERVED.contains(&key.as_str()) {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| UiError::Unreadable(path.clone(), e))?;
        files.insert(key.clone(), file(&key, Cow::Owned(bytes), false));
    }
    Ok(())
}

/// The hashes the interface's build writes to `csp-hashes.json`: the
/// `'sha256-…'` source of each inline `<script>` and `<style>` it emitted.
#[derive(serde::Deserialize)]
struct CspHashes {
    script: Vec<String>,
    style: Vec<String>,
}

/// A CSP hash source as the manifest writes it: `'sha256-<base64>'`.
/// Anything else is dropped rather than injected into the header.
fn is_hash_source(s: &str) -> bool {
    s.strip_prefix("'sha256-")
        .and_then(|rest| rest.strip_suffix('\''))
        .is_some_and(|b64| {
            !b64.is_empty()
                && b64
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        })
}

/// The Content Security Policy of the interface, from its list of hashes.
///
/// Inline scripts and styles are allowed by hash only: an injected script
/// does not run. The policy names no origin but the server's own: the
/// interface loads nothing from anywhere else, and a build of it that tried
/// to would be stopped here. There is no `'unsafe-inline'`, in any case.
fn policy(manifest: &str) -> Result<HeaderValue, UiError> {
    let hashes: CspHashes = serde_json::from_str(manifest)
        .map_err(|e| UiError::NoPolicy(format!("{CSP_HASHES} is not readable: {e}")))?;
    let keep = |sources: Vec<String>| {
        sources
            .into_iter()
            .filter(|s| is_hash_source(s))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let (script, style) = (keep(hashes.script), keep(hashes.style));
    let join = |sources: &str| {
        if sources.is_empty() {
            "'self'".to_owned()
        } else {
            format!("'self' {sources}")
        }
    };
    HeaderValue::from_str(&format!(
        "default-src 'self'; \
         script-src {}; \
         style-src {}; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         object-src 'none'; \
         base-uri 'self'",
        join(&script),
        join(&style)
    ))
    .map_err(|_| UiError::NoPolicy("the policy is not a header value".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_make_the_policy_and_nothing_else_does() {
        let csp = policy(
            r#"{"script":["'sha256-AAAA'","'unsafe-eval'","x; script-src *"],"style":["'sha256-BB+/='"],"pages":[]}"#,
        )
        .unwrap();
        let csp = csp.to_str().unwrap();
        assert!(csp.contains("script-src 'self' 'sha256-AAAA';"), "{csp}");
        assert!(csp.contains("style-src 'self' 'sha256-BB+/=';"));
        assert!(!csp.contains("unsafe-eval"), "only hash sources are copied");
        assert!(!csp.contains("script-src *"));
    }

    /// The interface loads nothing from anywhere else, so the policy has no
    /// origin to allow: a scheme, a host, a wildcard or `'unsafe-inline'` in
    /// it is a regression.
    #[test]
    fn the_policy_names_no_origin_and_allows_no_inline_code() {
        for manifest in [
            r#"{"script":["'sha256-AAAA'"],"style":["'sha256-BBBB'"]}"#,
            r#"{"script":[],"style":[]}"#,
        ] {
            let csp = policy(manifest).unwrap();
            for part in csp
                .to_str()
                .unwrap()
                .split([' ', ';'])
                .filter(|p| !p.is_empty())
            {
                let allowed = part.ends_with("-src")
                    || part.ends_with("-ancestors")
                    || part.ends_with("-uri")
                    || part.ends_with("-action")
                    || matches!(part, "'self'" | "'none'" | "data:")
                    || part.starts_with("'sha256-");
                assert!(allowed, "unexpected source {part:?} in {csp:?}");
            }
        }
    }

    #[test]
    fn without_a_list_of_hashes_there_is_no_policy() {
        assert!(matches!(policy("not json"), Err(UiError::NoPolicy(_))));
        assert!(matches!(
            policy(r#"{"script":[]}"#),
            Err(UiError::NoPolicy(_))
        ));
    }

    #[test]
    fn a_path_names_a_file_of_the_build_or_nothing() {
        assert_eq!(file_key("/").as_deref(), Some("index.html"));
        assert_eq!(file_key("/signup/").as_deref(), Some("signup/index.html"));
        assert_eq!(file_key("/build/q-1.js").as_deref(), Some("build/q-1.js"));
        for outside in [
            "",
            "signup/",
            "/../etc/passwd",
            "/build/../../secret",
            "/a//b",
            "//evil.example/",
            "/a\\b",
            "/./index.html",
        ] {
            assert_eq!(file_key(outside), None, "{outside:?}");
        }
    }

    #[test]
    fn gzip_is_sent_to_those_who_take_it() {
        let with = |value: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(value));
            accepts_gzip(&h)
        };
        assert!(with("gzip, deflate, br"));
        assert!(with("br;q=1.0, gzip;q=0.8"));
        assert!(with("*"));
        assert!(!with("br"));
        assert!(!with("gzip;q=0, br"));
        assert!(!with("identity"));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }

    #[test]
    fn types_and_caching_follow_the_name() {
        let script = file("build/q-abc.js", Cow::Borrowed(b"x"), false);
        assert_eq!(script.content_type, "text/javascript; charset=utf-8");
        assert!(script.immutable);
        let page = file("signup/index.html", Cow::Borrowed(b"x"), false);
        assert_eq!(page.content_type, "text/html; charset=utf-8");
        assert!(!page.immutable);
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
        // The tag changes with the content.
        assert_ne!(
            file("a.txt", Cow::Borrowed(b"one"), false).etag,
            file("a.txt", Cow::Borrowed(b"two"), false).etag
        );
    }
}
