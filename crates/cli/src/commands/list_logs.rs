//! `list` / `logs` コマンド本体（Linux は plugin を介さず core の状態ストアを直接読む。TASK-79.3・CLI-1・MS-6）。
//!
//! `commands::run_to` が argv を解析した後に [`run_list`] / [`run_logs`] を呼ぶ。状態の読み出しは core の
//! `StateStore::list` / `get`（OCI-5）へ委ね、ID の文字種検証も core の型（`ContainerId`）を唯一の判定とする。
//! 状態ルートの解決・状態ストアの組み立ては `create_start::production_runtime` を共用する。
//!
//! # list の出力形式
//!
//! stdout へタブ区切りテキスト（LF 固定）を出す。1 行目は固定ヘッダ `ID\tSTATUS\tPID`、以降 1 レコード 1 行で
//! `<id>\t<status>\t<pid または ->`。並びは状態ストアが返す順（ID 昇順）、0 件はヘッダのみで終了コード 0。
//! 値は core が検証済みの ID（`[A-Za-z0-9._-]`）・固定語の状態（`creating/created/running/stopped`）・
//! 10 進の PID だけで、エスケープ不要。`bundle` や annotations は任意の UTF-8（タブ・改行・端末制御文字を含み得る）
//! ため出力しない（インジェクション回避。SEC-1）。
//!
//! # logs の判定表（fail-closed。実装済みを装わない。REPAIR-3）
//!
//! | 条件 | 結果 |
//! | ---- | ---- |
//! | ID の文字種違反 | 2（`INVALID_ARGUMENT`） |
//! | 状態ルートを開けない（非 Linux は plugin 解決の失敗） | core のコードどおり（非 Linux は候補なしで 5、他は 8 / 6） |
//! | 対象の状態レコードが無い | 3（`NOT_FOUND`） |
//! | 対象が存在する | 8（`UNIMPLEMENTED`。stdout には何も出さない） |
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - logs の内容読み出し: コンテナログのディレクトリ契約が未決で、書き手（supervisor への stdout / stderr 受け渡し。
//!   #1471・本番 launcher #1314）も未提供。読み出しの正規入口は supervisor 側にあり、`cli -> supervisor` の依存辺は
//!   `docs/architecture.md` に無い（crate 境界の設計変更を要する）。確定後に実装する（CLI-1）。
//! - list の JSON 出力・bundle 列: JSON を手組みしない（REPAIR-2）ため serde 系の配線か core の公開ライタが前提
//!   （TASK-95・TASK-98）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。非 Linux では状態ストアを開けず core 側が
//!   `Unimplemented` を返す（fail-closed）。

use std::io::Write;
use std::num::NonZeroU32;
use std::time::Instant;

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::{
    ContainerId, ErrorCode, GetStateRequest, ListStateRequest, MAX_PAGE_SIZE, StateRecord,
    StateStore, TraitError,
};

use super::CliExit;
use super::args::{GlobalArgs, ListArgs, LogsArgs};
use super::create_start::{OP_LOG_ENV, export_ops, production_runtime};

/// list の固定ヘッダ行（LF 終端）。
const LIST_HEADER: &str = "ID\tSTATUS\tPID\n";

/// 走査するページ数の上限（REPAIR-5）。不正なストア実装が `next_cursor` を返し続けても無期限に回らない。
const MAX_LIST_PAGES: u32 = 100_000;

/// 1 レコードを 1 行（LF 終端）で `out` へ追記する。PID が無ければ `-`。
fn format_record_line(record: &StateRecord, out: &mut String) {
    out.push_str(record.id().as_str());
    out.push('\t');
    out.push_str(record.status().state().as_str());
    out.push('\t');
    match record.status().pid() {
        Some(pid) => out.push_str(&pid.get().to_string()),
        None => out.push('-'),
    }
    out.push('\n');
}

fn stdout_error() -> TraitError {
    TraitError::new(ErrorCode::Internal, "failed to write to stdout")
}

/// 状態ストアの全レコードをヘッダ付きで `out` へ書く。ページごとに 1 回の `write_all` で書き、全件を溜めない。
fn list_containers(
    store: &dyn StateStore,
    out: &mut dyn Write,
    page_size: NonZeroU32,
) -> Result<(), TraitError> {
    out.write_all(LIST_HEADER.as_bytes())
        .map_err(|_| stdout_error())?;
    let mut req = ListStateRequest::new(page_size)?;
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        let mut buf = String::new();
        for record in page.records() {
            format_record_line(record, &mut buf);
        }
        if !buf.is_empty() {
            out.write_all(buf.as_bytes()).map_err(|_| stdout_error())?;
        }
        match page.next_cursor() {
            Some(cursor) => req = req.with_cursor(cursor.clone()),
            None => return Ok(()),
        }
    }
    Err(TraitError::new(
        ErrorCode::Internal,
        "state listing did not terminate",
    ))
}

/// 対象の状態レコードが存在することを確かめる（無ければ `NotFound`）。
fn container_exists(store: &dyn StateStore, id: &ContainerId) -> Result<(), TraitError> {
    store.get(&GetStateRequest::new(id.clone())).map(|_| ())
}

/// 計測へ成功・失敗を 1 回だけ記録する（core の list / get は記録しないため CLI 側で記録する。REPAIR-4）。
fn record_op(recorder: &OpRecorder, op_name: &str, ok: bool, started: Instant) {
    if let Ok(name) = OpName::new(op_name) {
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
}

/// 状態ストアを開く段階の失敗を終了値へ写す。コンテナ ID を参照していない段階の `NotFound` は
/// 状態ルート不在であり、コンテナ不在（`container not found`）と誤報しない。
///
/// 非 Linux では plugin 解決の失敗（`plugin_backend::BackendFailure`）を先に拾い、「未導入」と「信頼性検証の
/// 拒否」などを区別できる固定文言の識別子で出す（C1・TASK-79.4 追補）。照合は `plugin_backend` の固定文言表との
/// 完全一致のみで、一致時に出すのはその `&'static str` 定数だけ。core の `TraitError::message`
/// （`--root` 不正・発見の I/O エラー等を含む）は出力へ流さず、表に無い失敗は従来の汎用文言に落とす。
fn store_open_failure(e: &TraitError) -> CliExit {
    #[cfg(not(target_os = "linux"))]
    if let Some(kind) = super::plugin_backend::BackendFailure::classify(e) {
        return CliExit::Error(crate::error::CliError::new(kind.code(), kind.message()));
    }
    match e.code() {
        ErrorCode::NotFound => CliExit::state_root_not_found(),
        c => CliExit::failed(c),
    }
}

/// 本番入口の `list`。成功時は stdout に一覧を出す。
pub(super) fn run_list(global: &GlobalArgs, _args: &ListArgs, stdout: &mut dyn Write) -> CliExit {
    let started = Instant::now();
    let rt = match production_runtime(global, OpRecorder::new(), "list", started, || Ok(())) {
        Ok((rt, ())) => rt,
        // core 到達前の失敗は production_runtime が記録・出力済み。
        Err(e) => return store_open_failure(&e),
    };
    let page_size = NonZeroU32::new(MAX_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let result = list_containers(rt.store.as_ref(), stdout, page_size);
    record_op(&rt.recorder, "list", result.is_ok(), started);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(()) => CliExit::Success,
        // list はコンテナを参照しないため、NotFound はコンテナ不在ではない。
        Err(e) => store_open_failure(&e),
    }
}

/// 本番入口の `logs`。ログ内容の読み出しは未実装のため、対象が存在しても `UNIMPLEMENTED` で失敗する（REPAIR-3）。
pub(super) fn run_logs(global: &GlobalArgs, args: &LogsArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "logs", started, || {
        ContainerId::new(args.id.as_str())
    });
    let (rt, id) = match prepared {
        Ok(v) => v,
        Err(e) => return store_open_failure(&e),
    };
    // 計測は最終結果（未実装を含む）から 1 回だけ決める。存在確認が通っても未実装で終わるため Failure（REPAIR-4）。
    let exit = match container_exists(rt.store.as_ref(), &id) {
        Ok(()) => CliExit::unimplemented(),
        Err(e) => CliExit::failed(e.code()),
    };
    record_op(
        &rt.recorder,
        "logs",
        matches!(exit, CliExit::Success),
        started,
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{ContainerStatus, StateRevision};

    fn record(status: ContainerStatus) -> StateRecord {
        StateRecord::new(status, std::env::temp_dir(), StateRevision::from_raw(1)).expect("rec")
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    /// CLI-1: 1 行の形式（pid なし `-`・pid あり 10 進）。
    #[test]
    fn cli1_format_record_line() {
        let mut s = String::new();
        let pid = NonZeroU32::new(4242);
        format_record_line(&record(ContainerStatus::created(cid("a1"), None)), &mut s);
        format_record_line(&record(ContainerStatus::running(cid("b2"), pid)), &mut s);
        format_record_line(
            &record(ContainerStatus::stopped(cid("c3"), Some(0))),
            &mut s,
        );
        assert_eq!(s, "a1\tcreated\t-\nb2\trunning\t4242\nc3\tstopped\t-\n");
    }

    fn stderr_line(e: &CliExit) -> String {
        let mut buf = Vec::new();
        e.write_stderr(&mut buf).expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// CLI-1: ストアを開く段階の NotFound は状態ルート不在で、コンテナ不在と区別される。
    #[test]
    fn cli1_store_open_not_found_is_state_root() {
        let nf = TraitError::new(ErrorCode::NotFound, "x");
        let e = store_open_failure(&nf);
        assert_eq!(e.exit_code(), 3);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"NOT_FOUND\",\"message\":\"state root not found\"}\n"
        );
        let inv = TraitError::new(ErrorCode::InvalidArgument, "x");
        let e = store_open_failure(&inv);
        assert_eq!(e.exit_code(), 2);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid argument\"}\n"
        );
    }

    /// C1: 非 Linux の plugin 解決失敗は「未導入」と「検証未実装」で別の固定文言になる。
    /// 表に無い失敗（任意文言）は汎用文言のまま。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn c1_plugin_failures_have_distinct_identifiers_off_linux() {
        use super::super::plugin_backend::BackendFailure;
        let e = store_open_failure(&BackendFailure::NotInstalled.into_error());
        assert_eq!(e.exit_code(), 5);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"platform backend plugin is not installed\"}\n"
        );
        let e = store_open_failure(&BackendFailure::TrustUnsupported.into_error());
        assert_eq!(e.exit_code(), 8);
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin trust verification is not implemented on this platform\"}\n"
        );
        let e = store_open_failure(&TraitError::new(ErrorCode::FailedPrecondition, "detail"));
        assert_eq!(
            stderr_line(&e),
            "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"failed precondition\"}\n"
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use fandhe_container_core::oci_runtime::create;
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_core::traits::CreateRequest;

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-cli-ll-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// 書き込みに失敗する Write。
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn store(base: &TmpDir) -> FileStateStore {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            FileStateStore::open(root).expect("open")
        }

        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn create_all(base: &TmpDir, st: &FileStateStore, names: &[&str]) {
            let rec = OpRecorder::new();
            for n in names {
                let req = CreateRequest::new(ContainerId::new(*n).expect("id"), make_bundle(base))
                    .expect("req");
                create(st, &rec, &req).expect("create");
            }
        }

        fn listed(st: &FileStateStore, page: u32) -> String {
            let mut out = Vec::new();
            list_containers(st, &mut out, NonZeroU32::new(page).expect("nz")).expect("list");
            String::from_utf8(out).expect("utf8")
        }

        /// CLI-1: 0 件はヘッダのみ。
        #[test]
        fn cli1_list_empty_is_header_only() {
            let base = TmpDir::new("empty");
            let st = store(&base);
            assert_eq!(listed(&st, 2), "ID\tSTATUS\tPID\n");
        }

        /// CLI-1: 複数件は ID 昇順で、ページ境界（3 件 / ページサイズ 2、1 件ずつ）をまたいでも全件出る。
        #[test]
        fn cli1_list_spans_pages() {
            let base = TmpDir::new("pages");
            let st = store(&base);
            create_all(&base, &st, &["c3", "a1", "b2"]);
            let expect = "ID\tSTATUS\tPID\na1\tcreated\t-\nb2\tcreated\t-\nc3\tcreated\t-\n";
            assert_eq!(listed(&st, 2), expect);
            assert_eq!(listed(&st, 1), expect);
            assert_eq!(listed(&st, 1000), expect);
        }

        /// CLI-1: logs の存在確認。無ければ NotFound、あれば Ok。
        #[test]
        fn cli1_container_exists() {
            let base = TmpDir::new("exists");
            let st = store(&base);
            create_all(&base, &st, &["a1"]);
            let a1 = ContainerId::new("a1").expect("id");
            let nope = ContainerId::new("nope").expect("id");
            assert!(container_exists(&st, &a1).is_ok());
            let e = container_exists(&st, &nope).expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
        }

        /// 書き込み失敗は panic せず Internal になる。
        #[test]
        fn err2_list_write_failure_is_internal() {
            let base = TmpDir::new("wfail");
            let st = store(&base);
            let e = list_containers(&st, &mut FailingWriter, NonZeroU32::MIN).expect_err("io");
            assert_eq!(e.code(), ErrorCode::Internal);
        }
    }
}
