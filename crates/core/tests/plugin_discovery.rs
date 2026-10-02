//! plugin 候補探索の結合試験（TASK-109.1・PLUG-4・PLUG-11・REPAIR-12）。
//!
//! 加えて TASK-109.4（PLUG-4・`docs/design/crate-naming.md` 決定 3）として、plugin 追加の前後で
//! core のソース sha256 一覧とバイナリ sha256 が不変であることを検証する（`plug4_*`）。
//!
//! 公開 API のみを使い、一時ディレクトリを system / user の管理ディレクトリに見立てて走査結果を
//! 具体値で照合する。実ホストの `/usr/libexec` には触れず、3 OS で同じ試験が動く。

use std::fs;
use std::path::{Path, PathBuf};

use fandhe_container_core::plugin_discovery::{
    DiscoveryOptions, PathSearchPolicy, PluginCandidate, PluginDirKind, PluginFileKind,
    PluginRegistry, PluginSearchDir, RegistrationStatus, discover_candidates,
    discover_with_options, write_path_warnings,
};

/// テスト用の一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-discovery-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmp dir");
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn exe(name: &str) -> String {
    format!(
        "fandhe-container-plugin-{name}{}",
        std::env::consts::EXE_SUFFIX
    )
}

fn touch(dir: &Path, file: &str) {
    fs::write(dir.join(file), b"").expect("write file");
}

fn summary(c: &[PluginCandidate]) -> Vec<(String, PluginDirKind, PluginFileKind)> {
    c.iter()
        .map(|c| (c.name().to_owned(), c.origin(), c.file_kind()))
        .collect()
}

#[test]
fn plug11_scans_system_and_user_dirs_and_filters_by_name() {
    let tmp = Tmp::new("scan");
    let sys = tmp.0.join("system");
    let usr = tmp.0.join("user");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&usr).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&sys, &exe("cri"));
    touch(&usr, &exe("macos"));
    for d in [&sys, &usr] {
        touch(d, "README");
        touch(d, "other-tool");
        touch(d, "fandhe-container-plugin-");
        touch(d, &exe("UPPER"));
        fs::create_dir_all(d.join(exe("subdir"))).unwrap();
    }
    let dirs = [
        PluginSearchDir::new(PluginDirKind::User, usr.clone()),
        PluginSearchDir::new(PluginDirKind::System, sys.clone()),
    ];
    let got = discover_candidates(&dirs).expect("discover");
    assert_eq!(
        summary(&got),
        vec![
            (
                "cri".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            (
                "macos".to_owned(),
                PluginDirKind::User,
                PluginFileKind::File
            ),
        ]
    );
    assert_eq!(got[0].path(), sys.join(exe("cri")));
    assert_eq!(got[2].path(), usr.join(exe("macos")));
}

#[test]
fn plug11_missing_dirs_yield_empty_list() {
    let tmp = Tmp::new("missing");
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, tmp.0.join("nope-a")),
        PluginSearchDir::new(PluginDirKind::User, tmp.0.join("nope-b")),
    ];
    assert_eq!(discover_candidates(&dirs).expect("ok"), vec![]);

    let present = tmp.0.join("present");
    fs::create_dir_all(&present).unwrap();
    touch(&present, &exe("mcp"));
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, tmp.0.join("nope-c")),
        PluginSearchDir::new(PluginDirKind::User, present),
    ];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![("mcp".to_owned(), PluginDirKind::User, PluginFileKind::File)]
    );
}

#[test]
fn plug11_same_name_in_both_dirs_is_reported_twice() {
    let tmp = Tmp::new("dup");
    let sys = tmp.0.join("system");
    let usr = tmp.0.join("user");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&usr).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&usr, &exe("mcp"));
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, sys),
        PluginSearchDir::new(PluginDirKind::User, usr),
    ];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            ("mcp".to_owned(), PluginDirKind::User, PluginFileKind::File),
        ]
    );
}

#[cfg(unix)]
#[test]
fn plug11_symlink_is_reported_without_following() {
    let tmp = Tmp::new("symlink");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).unwrap();
    std::os::unix::fs::symlink(tmp.0.join("dangling-target"), sys.join(exe("link"))).unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, sys)];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![(
            "link".to_owned(),
            PluginDirKind::System,
            PluginFileKind::Symlink
        )]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn plug11_non_utf8_name_is_excluded() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = Tmp::new("nonutf8");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).unwrap();
    let mut raw = b"fandhe-container-plugin-".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe]);
    fs::write(sys.join(OsStr::from_bytes(&raw)), b"").unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, sys)];
    assert_eq!(discover_candidates(&dirs).expect("ok"), vec![]);
}

#[test]
fn plug11_search_path_that_is_a_file_is_an_error() {
    let tmp = Tmp::new("isfile");
    let file = tmp.0.join("not-a-dir");
    fs::write(&file, b"").unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, file)];
    let err = discover_candidates(&dirs).expect_err("must not swallow");
    #[cfg(target_os = "linux")]
    assert_eq!(err.code().as_str(), "INTERNAL");
    #[cfg(not(target_os = "linux"))]
    let _ = err;
}

/// PATH 探索の試験用に、管理ディレクトリ（mcp）と PATH 用ディレクトリ（cri・macos・命名規約外）を作る。
fn path_fixture(tag: &str) -> (Tmp, Vec<PluginSearchDir>, PathBuf) {
    let tmp = Tmp::new(tag);
    let sys = tmp.0.join("system");
    let pdir = tmp.0.join("pathdir");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&pdir).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&pdir, &exe("cri"));
    touch(&pdir, &exe("macos"));
    touch(&pdir, "README");
    touch(&pdir, "other-tool");
    let managed = vec![PluginSearchDir::new(PluginDirKind::System, sys)];
    (tmp, managed, pdir)
}

#[test]
fn plug11_path_search_disabled_by_default_finds_nothing_on_path() {
    let (_tmp, managed, pdir) = path_fixture("path-off");
    let value = std::env::join_paths([&pdir]).unwrap();
    let report =
        discover_with_options(&managed, Some(&value), &DiscoveryOptions::default()).unwrap();
    assert_eq!(
        summary(report.candidates()),
        vec![(
            "mcp".to_owned(),
            PluginDirKind::System,
            PluginFileKind::File
        )]
    );
    assert!(report.path_warnings().is_empty());
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    assert_eq!(out.len(), 0);
}

#[test]
fn plug11_path_search_opt_in_warns_once_per_candidate() {
    let (_tmp, managed, pdir) = path_fixture("path-on");
    let value = std::env::join_paths([&pdir]).unwrap();
    let opts = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
    let report = discover_with_options(&managed, Some(&value), &opts).unwrap();
    assert_eq!(
        summary(report.candidates()),
        vec![
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            ("cri".to_owned(), PluginDirKind::Path, PluginFileKind::File),
            (
                "macos".to_owned(),
                PluginDirKind::Path,
                PluginFileKind::File
            ),
        ]
    );
    assert_eq!(report.path_warnings().len(), 2);
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    let names: Vec<String> = lines
        .iter()
        .map(|l| {
            assert!(l.contains("not registered"));
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["level"], "warn");
            v["name"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(names, vec!["cri", "macos"]);
}

#[test]
fn plug11_path_search_skips_missing_and_duplicate_entries() {
    let (tmp, managed, pdir) = path_fixture("path-skip");
    let plain = tmp.0.join("plain-file");
    fs::write(&plain, b"").unwrap();
    let missing = tmp.0.join("missing");
    let value = std::env::join_paths([&missing, &pdir, &plain, &pdir]).unwrap();
    // cri のみを残して 1 件にする
    fs::remove_file(pdir.join(exe("macos"))).unwrap();
    let opts = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
    let report = discover_with_options(&managed, Some(&value), &opts).unwrap();
    let on_path: Vec<_> = report
        .candidates()
        .iter()
        .filter(|c| c.origin() == PluginDirKind::Path)
        .collect();
    assert_eq!(on_path.len(), 1);
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 1);
}

#[test]
fn plug11_existing_discover_candidates_never_touches_path() {
    let (_tmp, managed, _pdir) = path_fixture("path-legacy");
    let found = discover_candidates(&managed).unwrap();
    assert!(found.iter().all(|c| c.origin() != PluginDirKind::Path));
    assert_eq!(found.len(), 1);
}

// ---------------------------------------------------------------------------
// TASK-109.4: plugin 追加前後の core 不変性（PLUG-4・決定 3 の (1)(3)）
// ---------------------------------------------------------------------------

/// PLUG-4 の同一性比較用に使う最小の SHA-256（FIPS 180-4）。
///
/// 用途は「追加前後で同じ指紋か」の比較に限る。PLUG-11 の信頼性検証（TASK-122）には使わない。
/// workspace 依存に `sha2` が入ったら置き換え候補（依存追加は承認制のため本タスクでは自前実装）。
mod sha256 {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub struct Sha256 {
        state: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        total: u64,
    }

    impl Sha256 {
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0; 64],
                buf_len: 0,
                total: 0,
            }
        }

        fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
            let mut w = [0u32; 64];
            for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
                w[i] = u32::from_be_bytes(*chunk);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                *s = s.wrapping_add(v);
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.total += data.len() as u64;
            while !data.is_empty() {
                let n = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
                self.buf_len += n;
                data = &data[n..];
                if self.buf_len == 64 {
                    let block = self.buf;
                    Self::compress(&mut self.state, &block);
                    self.buf_len = 0;
                }
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.total.wrapping_mul(8);
            self.update(&[0x80]);
            while self.buf_len != 56 {
                self.update(&[0]);
            }
            self.update(&bit_len.to_be_bytes());
            let mut out = [0u8; 32];
            for (o, s) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
                *o = s.to_be_bytes();
            }
            out
        }
    }

    pub fn hex(digest: &[u8; 32]) -> String {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn hex_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex(&h.finalize())
    }

    /// ファイルを固定長バッファでストリーム読みして sha256 を返す（無制限確保をしない）。
    pub fn sha256_file(path: &Path) -> String {
        let mut f = File::open(path).expect("open file for sha256");
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).expect("read file for sha256");
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        hex(&h.finalize())
    }
}

/// 自前 SHA-256 が既知ベクタ（FIPS 180-4 / NIST の例）と一致することの確認。
#[test]
fn plug4_sha256_helper_matches_known_vectors() {
    assert_eq!(
        sha256::hex_of(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256::hex_of(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let two_block = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha256::hex_of(two_block),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // 分割 update でも同一結果になる
    let mut h = sha256::Sha256::new();
    for chunk in two_block.chunks(7) {
        h.update(chunk);
    }
    assert_eq!(sha256::hex(&h.finalize()), sha256::hex_of(two_block));
}

/// 走査するファイル件数の上限（超過は fail-closed で panic）。
const MAX_SOURCE_FILES: usize = 4096;

fn collect_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read source dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        // symlink は辿らない（走査範囲を core 配下に閉じる）
        let meta = fs::symlink_metadata(&path).expect("stat source entry");
        if meta.is_dir() {
            collect_files(&path, root, out);
        } else if meta.is_file() {
            assert!(out.len() < MAX_SOURCE_FILES, "too many source files");
            let rel: Vec<_> = path
                .strip_prefix(root)
                .expect("path under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push((rel.join("/"), sha256::sha256_file(&path)));
        }
    }
}

/// core crate のソース（`Cargo.toml` と `src/` 配下の全ファイル）の (相対パス, sha256) 一覧。
///
/// `tests/` はテスト自身であり core の成果物に入らないため対象外とする。
fn core_source_sha256_list() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = vec![(
        "Cargo.toml".to_owned(),
        sha256::sha256_file(&root.join("Cargo.toml")),
    )];
    collect_files(&root.join("src"), &root, &mut out);
    out.sort();
    out
}

/// core バイナリの代理指紋。
///
/// core は lib のみで bin target が無いため、core を静的リンクしたこのテスト実行ファイルを
/// 代理対象にする（PoC-13 の `core-harness` 比較と同形）。TASK-79 で CLI bin が入ったら、
/// `cargo build --locked` の成果物へ切り替える（REPAIR-3）。
fn core_binary_sha256() -> String {
    sha256::sha256_file(&std::env::current_exe().expect("current_exe"))
}

/// PLUG-4（TASK-109.4）: plugin を管理ディレクトリへ追加して発見・登録しても、core のソース
/// sha256 一覧とバイナリ（代理）sha256 は変わらない。決定 3 の (2) 依存木比較は本テストの対象外。
/// 現状は代理指紋（test 実行ファイル）の比較で保証が弱い。TASK-79 の CLI bin 導入時に
/// `cargo build --locked` 成果物の比較へ置き換える（REPAIR-3）。
#[test]
fn plug4_core_sha256_unchanged_after_plugin_add() {
    let tmp = Tmp::new("plug4");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, sys.clone())];

    let src_before = core_source_sha256_list();
    let bin_before = core_binary_sha256();
    assert!(discover_candidates(&dirs).unwrap().is_empty());

    // plugin 追加（ファイルは置くだけで実行しない）と発見・登録
    touch(&sys, &exe("sha256probe"));
    let found = discover_candidates(&dirs).unwrap();
    assert_eq!(found.len(), 1);
    let mut registry = PluginRegistry::new();
    for c in found {
        let outcome = registry.register(c).unwrap();
        assert_eq!(outcome.status(), RegistrationStatus::Registered);
    }
    assert_eq!(registry.len(), 1);
    assert!(registry.get("sha256probe").is_some());

    let src_after = core_source_sha256_list();
    let bin_after = core_binary_sha256();

    // 空振り防止
    for required in [
        "Cargo.toml",
        "src/lib.rs",
        "src/plugin_discovery.rs",
        "src/plugin_discovery/registry.rs",
    ] {
        assert!(
            src_before.iter().any(|(p, _)| p == required),
            "missing {required}"
        );
    }
    assert!(
        src_before
            .iter()
            .all(|(_, h)| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    assert_eq!(bin_before.len(), 64);

    assert_eq!(src_before, src_after, "core source sha256 list changed");
    assert_eq!(bin_before, bin_after, "core binary sha256 changed");
}
