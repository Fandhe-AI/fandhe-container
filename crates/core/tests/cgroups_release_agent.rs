//! cgroups v2 による `release_agent` 悪用手法の無効化確認（SEC-6・CORE-4・TASK-35・MS-2・#167）。
//!
//! # テスト記録（TASK-35 の成果物）
//! PoC-9 の脱出試験表 ESC-04（脱出クラス 2。期待値は「書き込み拒否、またはファイル自体が存在しない」）
//! のうち、本実装（`fandhe_container_core::cgroups`、TASK-32）で成立し得ないことを機械照合する。
//!
//! ## 構造的に無効化される根拠
//! - `release_agent`（ルート cgroup）と `notify_on_release` は cgroup v1 のインターフェースファイルで、
//!   cgroup v2 の cgroup ディレクトリには存在しない。v2 は「空になった」通知を `cgroup.events` の
//!   `populated` で行い、ホスト側でプログラムを起動する仕組みを持たない（カーネル文書
//!   `Documentation/admin-guide/cgroup-v2.rst` の `cgroup.events` と、v1 側の
//!   `Documentation/admin-guide/cgroup-v1/cgroups.rst` の release agent の節）。
//! - 既知の悪用例 CVE-2022-0492 は v1 の `release_agent` 書き込み経路（`kernel/cgroup/cgroup-v1.c`）の
//!   capability 検査欠如であり、v2 専用の本実装には該当するファイル自体が無い。
//! - 本実装は v1 / hybrid を fail-closed で拒否する（`parse_self_cgroup_v2` の hybrid 拒否と
//!   `verify_cgroup2` の magic 検査。crate 内ユニットテスト
//!   `core4_sec6_task32_1_parse_self_cgroup_v2_rejects_hybrid` が照合済み）。
//! - 多層防御として SEC-1 の `CAP_SYS_ADMIN` 既定拒否がコンテナ内からの v1 階層マウントも塞ぐが、
//!   それは本テストの範囲外（ここでは試験しない）。
//!
//! ## 3 層の構成
//! 1. 静的監査（3 OS・既定のテスト集合）: `crates/core/src` の実コード行が `release_agent` /
//!    `notify_on_release` を作成・参照しないこと。コメント行は対象外、行末コメントは除去しない（fail-closed）。
//! 2. Linux の実ホスト確認（既定のテスト集合・特権不要）: `/sys/fs/cgroup` が cgroup2 ならルートと自
//!    cgroup に当該ファイルが無いこと、そうでなければ `DelegatedCgroup::detect` が構造化エラーで拒否すること。
//!    ホスト状態に応じたテスト内分岐であり skip ではない（どの分岐も必ず assert する）。
//! 3. 委譲 cgroup 上の実機確認（`#[ignore]`）: 実際に作った cgroup に当該ファイルが無く、作成も拒否される
//!    こと。委譲された cgroup v2 サブツリーが必要で GitHub ホステッド runner では保証できないため既定の
//!    集合から分離している（CI 通過のための弱体化ではない）。
//!
//! # 実機前提テストの実行方法（層 3）
//! 自プロセスを cgroup 間で移動するため `cargo` を経由せず、ビルド済みバイナリを委譲スコープで直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroups_release_agent --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_release_agent-XXXX> --ignored
//! ```
//!
//! `--include-ignored` は非対応（`prepare` による自プロセスの移動が層 2 の `/proc/self/cgroup` 読み取りと
//! 競合するため）。本ファイルの ignored テストは 1 件に限る。

use std::fs;
use std::path::{Path, PathBuf};

/// 走査対象のトークン（cgroup v1 専用ファイル名）。
const FORBIDDEN_TOKENS: [&str; 2] = ["release_agent", "notify_on_release"];

/// 違反 1 件（行番号とトークン）。
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    token: &'static str,
}

/// 1 つのソース文字列から、コメント行以外でトークンを含む行を列挙する。
///
/// 行末コメントは除去しない。文字列リテラル中の `//` による見逃しを避け、判定を厳しい側に倒す。
fn scan_source(text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for token in FORBIDDEN_TOKENS {
            if line.contains(token) {
                out.push(Violation { line: i + 1, token });
            }
        }
    }
    out
}

/// `dir` 配下の `*.rs` を再帰的に集める。
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// SEC-6・TASK-35: cgroup 実装を含む `crates/core/src` が v1 専用ファイルを作成・参照しない。
#[test]
fn sec6_task35_core_src_has_no_release_agent_reference() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);
    files.sort();

    // 走査の空振り検出。cgroup 実装が対象に含まれていること。
    assert!(!files.is_empty(), "no source files scanned");
    for rel in [
        PathBuf::from("cgroups.rs"),
        Path::new("cgroups").join("cpu.rs"),
    ] {
        assert!(
            files
                .iter()
                .any(|f| f.strip_prefix(&src) == Ok(rel.as_path())),
            "{} was not scanned",
            rel.display()
        );
    }

    let mut violations = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        for v in scan_source(&text) {
            violations.push(format!("{}:{}:{}", f.display(), v.line, v.token));
        }
    }
    assert_eq!(violations, Vec::<String>::new());
}

/// SEC-6・TASK-35: 走査関数の陽性対照。コード行は検出し、コメント行は無視する。
#[test]
fn sec6_task35_scanner_detects_code_and_ignores_comments() {
    let sample = "let p = \"release_agent\";\n\
                  /// release_agent は v1 専用\n\
                  // notify_on_release\n\
                  //! release_agent\n\
                  let q = 1; // notify_on_release\n\
                  let ok = 2;\r\n";
    assert_eq!(
        scan_source(sample),
        vec![
            Violation {
                line: 1,
                token: "release_agent"
            },
            Violation {
                line: 5,
                token: "notify_on_release"
            },
        ]
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupName, CgroupStep, ContainerCgroup, DelegatedCgroup,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    /// カーネル応答の読み取り上限。
    const READ_LIMIT: u64 = 1024 * 1024;

    /// 上限付きで読む。上限を超える入力は途切れた内容を完全な入力として扱わないよう失敗させる。
    fn read_limited(path: &str) -> String {
        let f = fs::File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
        let mut s = String::new();
        // 1 バイト余分に読み、上限到達（切り詰め）を検出する。
        f.take(READ_LIMIT + 1)
            .read_to_string(&mut s)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            s.len() as u64 <= READ_LIMIT,
            "{path} exceeds the {READ_LIMIT} byte read limit"
        );
        s
    }

    /// `/proc/self/mountinfo` から `/sys/fs/cgroup` の fstype を返す（無ければ `None`）。
    fn cgroup_root_fstype(mountinfo: &str) -> Option<String> {
        let mut found = None;
        for line in mountinfo.lines() {
            let Some((head, tail)) = line.split_once(" - ") else {
                continue;
            };
            if head.split(' ').nth(4) == Some(CGROUP_ROOT) {
                // 後勝ち（上に重ねられたマウントが実効）。
                found = tail.split(' ').next().map(str::to_owned);
            }
        }
        found
    }

    fn assert_no_v1_files(dir: &Path) {
        for name in ["release_agent", "notify_on_release"] {
            let p = dir.join(name);
            match fs::symlink_metadata(&p) {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{}", p.display()),
                Ok(_) => panic!("{} must not exist on cgroup v2", p.display()),
            }
        }
    }

    /// 自 cgroup のディレクトリ（検証済み要素のみ join）。解決できなければ原因付きの `Err`。
    fn own_cgroup_dir() -> Result<PathBuf, String> {
        let text = read_limited("/proc/self/cgroup");
        let path = text
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or_else(|| "no cgroup v2 entry (`0::`) in /proc/self/cgroup".to_owned())?;
        let mut dir = PathBuf::from(CGROUP_ROOT);
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if comp == ".." || comp == "." || comp.contains('\0') {
                return Err(format!("unsafe component {comp:?} in cgroup path {path:?}"));
            }
            dir.push(comp);
        }
        if dir.is_dir() {
            Ok(dir)
        } else {
            Err(format!(
                "own cgroup directory {} (from {path:?}) is not visible",
                dir.display()
            ))
        }
    }

    /// SEC-6・CORE-4・TASK-35: 実ホストの cgroup 階層に応じ、v2 では v1 専用ファイルの不在を、
    /// それ以外では `detect` の fail-closed 拒否を照合する。
    #[test]
    fn sec6_task35_host_cgroup_has_no_release_agent_or_rejected() {
        let fstype = cgroup_root_fstype(&read_limited("/proc/self/mountinfo"));
        if fstype.as_deref() == Some("cgroup2") {
            let root = Path::new(CGROUP_ROOT);
            // 陽性対照: 実際の cgroup2 を見ている。
            assert!(root.join("cgroup.procs").exists());
            assert!(root.join("cgroup.controllers").exists());
            assert_no_v1_files(root);
            // 解決できない場合は黙って省略せず、原因付きで失敗させる（REPAIR-12）。
            let own = own_cgroup_dir().unwrap_or_else(|e| panic!("cannot resolve own cgroup: {e}"));
            assert!(own.join("cgroup.procs").exists(), "{}", own.display());
            assert_no_v1_files(&own);
        } else {
            let err = DelegatedCgroup::detect()
                .expect_err("v1/hybrid/unmounted cgroup must be rejected (CORE-4)");
            let pair = (err.code, err.step);
            let allowed = [
                (ErrorCode::FailedPrecondition, CgroupStep::ReadSelfCgroup),
                (ErrorCode::FailedPrecondition, CgroupStep::VerifyCgroup2),
                (ErrorCode::NotFound, CgroupStep::OpenRoot),
            ];
            assert!(allowed.contains(&pair), "unexpected rejection: {err:?}");
        }
    }

    /// 後始末（作成した子 cgroup の削除）を assert 失敗時にも走らせるためのガード。
    ///
    /// 成功経路では `finish` で削除結果を検証する。`finish` 前に drop された場合（assert 失敗等）も
    /// 削除を試み、失敗は標準エラーへ報告する（unwind 中でなければ panic する）。
    struct Cleanup<'a> {
        delegated: &'a DelegatedCgroup,
        child: Option<ContainerCgroup>,
    }

    impl Cleanup<'_> {
        /// 子 cgroup を削除し、結果を返す。
        fn finish(mut self) -> Result<(), String> {
            match self.child.take() {
                Some(child) => self
                    .delegated
                    .remove_child(&child)
                    .map_err(|e| format!("remove_child failed: {e:?}")),
                None => Ok(()),
            }
        }
    }

    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let Some(child) = self.child.take() else {
                return;
            };
            if let Err(e) = self.delegated.remove_child(&child) {
                eprintln!("cleanup: remove_child failed: {e:?}");
                if !std::thread::panicking() {
                    panic!("cleanup: remove_child failed: {e:?}");
                }
            }
        }
    }

    /// SEC-6・CORE-4・TASK-35: 委譲 cgroup 上で、親・退避リーフ・コンテナ用子 cgroup のいずれにも
    /// `release_agent` / `notify_on_release` が無く、作成も拒否されること。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sec6_task35_delegated_cgroup_has_no_release_agent() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from(CGROUP_ROOT).join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("t{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        // controller の有効化は v1 専用ファイルの不在確認に不要なので行わない
        // （委譲サブツリーに Memory / Cpu が委譲されていなくても試験できるようにする）。
        let (child, _proof) = delegated.prepare(&name).expect("prepare");
        let cleanup = Cleanup {
            delegated: &delegated,
            child: Some(child),
        };

        let child_dir = parent.join(name.as_str());
        for dir in [&parent, &parent.join("fc-runtime"), &child_dir] {
            // 陽性対照: 実際の cgroup ディレクトリである。
            assert!(dir.join("cgroup.procs").exists(), "{}", dir.display());
            assert_no_v1_files(dir);
        }

        // 作成試行: 拒否され、その後も存在しない。
        for file in ["release_agent", "notify_on_release"] {
            let target = child_dir.join(file);
            let res = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target);
            assert!(res.is_err(), "creating {} must fail", target.display());
            assert!(!target.exists(), "{}", target.display());
        }

        // 成功経路でも削除結果を検証する。
        cleanup.finish().expect("remove container cgroup");
        assert!(!child_dir.exists(), "{}", child_dir.display());
    }
}
