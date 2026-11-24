//! Stamps the build's identity into the binary so every connection record can
//! name exactly what produced it. Comparing results across time is worthless
//! without it — and a build made from a dirty working tree has to say so, or
//! it quietly pollutes comparisons for months.
//!
//! Everything here is best-effort: a source tree with no git, or no git
//! binary, builds fine and simply records no commit.
//!
//! It also holds a release to its version: see `check_release_version`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_DIRTY");
    println!("cargo:rustc-env=SPORA_BUILD_TARGET={}", env("TARGET"));

    // A release pipeline that builds from an archive can supply these itself.
    if let Ok(commit) = std::env::var("SPORA_BUILD_COMMIT") {
        println!("cargo:rustc-env=SPORA_BUILD_COMMIT={commit}");
        let dirty = std::env::var("SPORA_BUILD_DIRTY").unwrap_or_else(|_| "0".into());
        println!("cargo:rustc-env=SPORA_BUILD_DIRTY={dirty}");
        return;
    }

    // The tag paths are for `check_release_version`: tagging a commit changes
    // neither `HEAD` nor the index, and the next build must see the tag.
    for path in [
        "../.git/HEAD",
        "../.git/index",
        "../.git/packed-refs",
        "../.git/refs/tags",
    ] {
        if std::path::Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    // `HEAD` and the index do not change for an unstaged edit. Watching only
    // those files lets Cargo reuse a cached `dirty=false` stamp even while a
    // tracked source file differs from the index — exactly the provenance lie
    // the field lab's artifact manifest is meant to catch. Enumerate tracked
    // workspace files so any such edit reruns this script. Paths from git are
    // repository-root relative; build.rs runs from `spora-core/`.
    if let Some(files) = git(&["ls-files"]) {
        for file in files.lines().filter(|line| !line.is_empty()) {
            println!("cargo:rerun-if-changed=../{file}");
        }
    }

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=SPORA_BUILD_COMMIT={commit}");

    // `--porcelain` prints one line per modified path; any output at all
    // means this build does not correspond to the commit above.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|out| !out.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=SPORA_BUILD_DIRTY={}", u8::from(dirty));

    // A tree with uncommitted changes is not the tagged release, and is
    // what the next version's first edit to Cargo.toml looks like.
    if !dirty {
        check_release_version();
    }
}

/// The version lives in one place, `[workspace.package]` in the workspace's
/// Cargo.toml, and a release is published under a tag, `v<version>`. Nothing
/// else keeps the two from drifting apart (the binaries of v0.3.3 called
/// themselves 0.1.0), so the build of a commit tagged `v1.2.3` fails unless
/// the version is 1.2.3.
///
/// Only a tagged commit is checked: between releases the version is that of
/// the last one, or already the next one's. A build that cannot ask git, or
/// sees no tags (a shallow clone), is not checked here, which is why the
/// release workflow also compares what its binaries report with its tag.
fn check_release_version() {
    // Tags of a repository this workspace is merely unpacked inside are
    // someone else's versions.
    if git(&["rev-parse", "--show-prefix"]).as_deref() != Some("spora-core/") {
        return;
    }
    let Some(tags) = git(&["tag", "--points-at", "HEAD", "--list", "v[0-9]*"]) else {
        return;
    };
    let version = env("CARGO_PKG_VERSION");
    let tags: Vec<&str> = tags.lines().filter(|tag| !tag.is_empty()).collect();
    if tags.is_empty()
        || tags
            .iter()
            .any(|tag| tag.strip_prefix('v') == Some(&version))
    {
        return;
    }
    let tags = tags.join(", ");
    // `cargo::error` fails the build with these lines alone; a non-zero exit
    // would bury them under this script's whole output.
    println!("cargo::error=this commit is tagged {tags}, but Cargo.toml says version {version}");
    println!(
        "cargo::error=a release's tag and its version must agree: set `version` under \
         `[workspace.package]` in the workspace's Cargo.toml to the release's, commit it \
         together with Cargo.lock, and tag that commit instead"
    );
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
