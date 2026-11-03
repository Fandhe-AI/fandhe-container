//! 本番の `create` の経路(`run_to` → `run_create` → `with_named_definition_held` → 本物の `create_with_options`)で、
//! 定義の照合から状態記録の作成までの間の `network rm` が防がれていることの結合試験
//! (#3550・NET-6・NET-9・CLI-1・REPAIR-5・REPAIR-12。設計は `docs/design/network-wiring.md` D10)。
//!
//! `src/commands/network.rs` の単体試験は `with_named_definition_held` を直接呼ぶため、`run_create` が保持を呼ばなくなる
//! 退行や、core の create が保持区間の外へ出る退行は検出できない。本試験は CLI の入口だけを使い、次を具体値で確かめる。
//!
//! 1. 成功した create の後の `network rm` は `FAILED_PRECONDITION`(終了コード 5)で拒否され、定義が残る。
//! 2. 保持区間の中で失敗した create は参照を残さず、その後の `network rm` は成功する。
//! 3. create と `network rm` を並行に繰り返しても、「create が成功したコンテナが参照するネットワークの定義が消えている」
//!    状態は作られない(窓が開いていれば間欠的に壊れる検出器。窓が無ければ決定的に成り立つ不変条件)。
//!
//! # 必要環境と分離(ci.md「実機前提テスト」)
//! 名前付きネットワークの create は pasta の解決(`--pasta-path` の検証。祖先まで root 所有の実体)を通る。GitHub ホステッド
//! runner の既定には passt が無いため、既定のテスト集合から `#[ignore]` で分離する。`pasta` が `/usr/bin/pasta` にある Linux の
//! 非 root で `cargo test -p fandhe-container-cli --test create_network_window -- --ignored` で実行する(CI への組み込みは
//! passt の導入承認後。PR 本文の対象外欄を参照)。

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use fandhe_container_cli::commands::run_to;

const PASTA: &str = "/usr/bin/pasta";
const IN_USE: &str = "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"network is in use by a container; delete the containers that use it first\"}\n";
const LS_N1: &str = "NAME\tMODE\tSUBNET\nn1\tpasta\t-\n";
const LS_EMPTY: &str = "NAME\tMODE\tSUBNET\n";

/// 結果(終了コード・標準出力・標準エラー)。
struct Out {
    code: u8,
    stdout: String,
    stderr: String,
}

fn cli(root: &Path, rest: &[&str]) -> Out {
    let mut v: Vec<OsString> = vec!["--root".into(), root.into()];
    v.extend(rest.iter().map(OsString::from));
    let mut out = Vec::new();
    let ex = run_to(v, &mut out);
    let mut err = Vec::new();
    ex.write_stderr(&mut err).expect("stderr");
    Out {
        code: ex.exit_code(),
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn create_on(root: &Path, bundle: &Path, id: &str, net: &str) -> Out {
    cli(
        root,
        &[
            "--pasta-path",
            PASTA,
            "create",
            "--network",
            net,
            "--bundle",
            bundle.to_str().expect("utf8"),
            id,
        ],
    )
}

fn make_bundle(dir: &Path, with_rootfs: bool) -> PathBuf {
    let bundle = dir.join(if with_rootfs { "ok" } else { "norootfs" });
    if with_rootfs {
        std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    } else {
        std::fs::create_dir_all(&bundle).expect("bundle");
    }
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    bundle
}

fn setup(tag: &str) -> (scratch_root::ScratchDir, PathBuf, PathBuf, PathBuf) {
    let scratch = scratch_root::ScratchDir::new(tag, std::time::Duration::from_secs(10));
    let tmp = scratch.path().join("t");
    std::fs::create_dir_all(&tmp).expect("tmp");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let root = tmp.join("state");
    let ok = make_bundle(&tmp, true);
    let bad = make_bundle(&tmp, false);
    let r = cli(&root, &["network", "create", "n1"]);
    assert_eq!(r.code, 0, "network create: {}", r.stderr);
    (scratch, root, ok, bad)
}

/// 1: 成功した create の後、`network rm` は FAILED_PRECONDITION(5)で拒否され、定義が残る。
#[test]
#[ignore = "requires a trusted pasta at /usr/bin/pasta (NET-9); see module doc"]
fn net6_net9_cli1_3550_rm_refused_after_production_create() {
    let (_s, root, ok, _bad) = setup("fc-cli-win1");
    let r = create_on(&root, &ok, "c1", "n1");
    assert_eq!(r.code, 0, "create: {}", r.stderr);
    let rm = cli(&root, &["network", "rm", "n1"]);
    assert_eq!((rm.code, rm.stderr.as_str()), (5, IN_USE));
    assert_eq!(cli(&root, &["network", "ls"]).stdout, LS_N1);
}

/// 2: 保持区間の中(core の create)で失敗した create は何も残さず、その後の `network rm` は成功する。
#[test]
#[ignore = "requires a trusted pasta at /usr/bin/pasta (NET-9); see module doc"]
fn net6_cli1_3550_failed_create_leaves_no_reference() {
    let (_s, root, _ok, bad) = setup("fc-cli-win2");
    let r = create_on(&root, &bad, "c2", "n1");
    assert_ne!(r.code, 0, "create must fail without a rootfs");
    let rm = cli(&root, &["network", "rm", "n1"]);
    assert_eq!(rm.code, 0, "rm after failed create: {}", rm.stderr);
    assert_eq!(cli(&root, &["network", "ls"]).stdout, LS_EMPTY);
}

/// 3: create と `network rm` の並行で、成功した create が参照する定義は消えない。
#[test]
#[ignore = "requires a trusted pasta at /usr/bin/pasta (NET-9); see module doc"]
fn net6_net9_cli1_3550_concurrent_create_and_rm_never_orphan_a_reference() {
    let (_s, root, ok, _bad) = setup("fc-cli-win3");
    let done = AtomicBool::new(false);
    let mut created = 0u32;
    std::thread::scope(|sc| {
        let rm_loop = sc.spawn(|| {
            let mut removed = false;
            while !done.load(Ordering::SeqCst) && !removed {
                removed = cli(&root, &["network", "rm", "n1"]).code == 0;
            }
            removed
        });
        for i in 0..8 {
            if create_on(&root, &ok, &format!("w{i}"), "n1").code == 0 {
                created += 1;
            }
        }
        done.store(true, Ordering::SeqCst);
        let removed = rm_loop.join().expect("rm thread");
        // 成功した create が 1 つでもあれば rm は成功してはならない(参照が残る)。
        assert!(
            !(removed && created > 0),
            "rm removed a network referenced by {created} created container(s)"
        );
    });
    let ls = cli(&root, &["network", "ls"]).stdout;
    assert!(
        ls == LS_N1 || (created == 0 && ls == LS_EMPTY),
        "unexpected ls {ls:?} (created={created})"
    );
}
