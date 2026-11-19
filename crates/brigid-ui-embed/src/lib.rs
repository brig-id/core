//! Embeds the built interface in a server's executable: called from the
//! `build.rs` of each edition (seedling, grove), which then includes the
//! generated table and hands it to `brigid_server::EmbeddedUi`:
//!
//! ```ignore
//! // build.rs
//! fn main() { brigid_ui_embed::embed_interface(); }
//! // src/main.rs
//! mod embedded { include!(concat!(env!("OUT_DIR"), "/embedded_ui.rs")); }
//! ```
//!
//! `BRIGID_UI_DIST` names the `dist` directory of a build of `brig-id/app`
//! (`pnpm build`). Its files are compiled into the binary, the text ones
//! compressed, with the list of script hashes its Content Security Policy is
//! made of.
//!
//! - **A release build requires it**, and requires the list of hashes: a
//!   released server is one executable, and never serves its pages under a
//!   weaker policy.
//! - A debug build without it embeds nothing: the server then serves the
//!   directory named by `server.ui_dist_dir`, or no interface at all.

use std::{
    env, fs,
    io::Write as _,
    path::{Path, PathBuf},
};

/// What the interface may weigh in the binary. It is fonts, two background
/// images and scripts: more than this is a mistake in its build.
const LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Files of the build that are not served: the bundler's own report.
const NOT_SERVED: &[&str] = &["q-manifest.json"];

/// The list of script hashes: read by the server, not served.
const CSP_HASHES: &str = "csp-hashes.json";

/// Extensions worth compressing. The rest (fonts, images) already is.
const TEXT: &[&str] = &["html", "js", "css", "json", "svg", "txt", "map"];

/// Writes `$OUT_DIR/embedded_ui.rs`: the files of the interface (`FILES`) and
/// its list of script hashes (`CSP_HASHES`). Panics, failing the build, when
/// the interface cannot be embedded.
pub fn embed_interface() {
    println!("cargo:rerun-if-env-changed=BRIGID_UI_DIST");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let release = env::var("PROFILE").as_deref() == Ok("release");
    let dist = env::var("BRIGID_UI_DIST").ok().filter(|d| !d.is_empty());

    let generated = match dist {
        Some(dist) => embed(Path::new(&dist), &out).unwrap_or_else(|problem| {
            panic!("the interface in BRIGID_UI_DIST={dist} cannot be embedded: {problem}")
        }),
        None if release => panic!(
            "a release build embeds the interface: set BRIGID_UI_DIST to the `dist` \
             directory of a build of brig-id/app (`pnpm build`)"
        ),
        None => "pub static FILES: &[(&str, &[u8], bool)] = &[];\n\
                 pub static CSP_HASHES: Option<&str> = None;\n"
            .to_owned(),
    };
    fs::write(out.join("embedded_ui.rs"), generated).expect("write the generated table");
}

/// Writes what is needed under `out` and returns the Rust source of the
/// table: for each file its path, its bytes, and whether they are gzip.
fn embed(dist: &Path, out: &Path) -> Result<String, String> {
    println!("cargo:rerun-if-changed={}", dist.display());
    let dist = dist
        .canonicalize()
        .map_err(|e| format!("not a directory that can be read ({e})"))?;
    let mut files = Vec::new();
    walk(&dist, &dist, &mut files)?;
    files.sort();
    if !files.iter().any(|(path, _)| path == "index.html") {
        return Err("no index.html: is this the `dist` of a build?".into());
    }
    let hashes = dist.join(CSP_HASHES);
    if !hashes.is_file() {
        return Err(format!(
            "no {CSP_HASHES}: the pages would have no Content Security Policy to be \
             served under (`pnpm build` writes it)"
        ));
    }

    let compressed = out.join("ui");
    fs::create_dir_all(&compressed).map_err(|e| e.to_string())?;
    let mut table = String::from("pub static FILES: &[(&str, &[u8], bool)] = &[\n");
    let mut total = 0;
    for (n, (path, source)) in files.iter().enumerate() {
        let bytes = fs::read(source).map_err(|e| format!("{path}: {e}"))?;
        let extension = path.rsplit('.').next().unwrap_or("");
        let (embedded, gzip) = if TEXT.contains(&extension) {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&bytes).map_err(|e| e.to_string())?;
            let packed = encoder.finish().map_err(|e| e.to_string())?;
            let target = compressed.join(format!("{n}.gz"));
            fs::write(&target, &packed).map_err(|e| e.to_string())?;
            total += packed.len();
            (target, true)
        } else {
            total += bytes.len();
            (source.clone(), false)
        };
        table.push_str(&format!(
            "    ({path:?}, include_bytes!({:?}), {gzip}),\n",
            embedded.display().to_string()
        ));
    }
    table.push_str("];\n");
    table.push_str(&format!(
        "pub static CSP_HASHES: Option<&str> = Some(include_str!({:?}));\n",
        hashes.display().to_string()
    ));
    if total > LIMIT_BYTES {
        return Err(format!(
            "it weighs {total} bytes in the binary, over the limit of {LIMIT_BYTES}"
        ));
    }
    println!(
        "cargo:warning=interface embedded: {} files, {} KiB",
        files.len(),
        total / 1024
    );
    Ok(table)
}

/// Every file under `dir` that the server serves, as its path from `root`
/// (with `/`) and its place on disk.
fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            walk(root, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if relative == CSP_HASHES || NOT_SERVED.contains(&relative.as_str()) {
            continue;
        }
        files.push((relative, path));
    }
    Ok(())
}
