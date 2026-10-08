//! `create` / `start` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.1・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_create`] / [`run_start`] を呼ぶ。実処理は core の
//! `oci_runtime::create` / `oci_runtime::start`（OCI-4・OCI-5・TASK-29）へ委ね、入力の意味検証
//! （ID の文字種・bundle の絶対パス・rootfs の symlink 検査）も core の型と関数を唯一の判定とする。
//! `--bundle` 自体やその祖先が symlink でも create は受理し、渡されたパスのまま状態へ保存する
//! （canonicalize しない）。bundle までの経路の symlink は start が起動前に検査して拒否する（SEC-1）。
//! 依存（状態ストア・launcher・計測器）は [`Runtime`] で注入できるようにし、単体テストではフェイクを差せる。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - 本番の [`ProcessLauncher`] はリポジトリ内に存在しない。そのため本番入口の `start` は
//!   [`UnavailableLauncher`] により fail-closed で `UNIMPLEMENTED` を返す。将来は supervisor 経由の
//!   起動（TASK-157・TASK-37〜39・CORE-1）に差し替え、起動済みプロセスの監視・回収を supervisor へ引き渡す。
//!   失敗する `start` でも core は起動権の予約（Created → Running）と取り消し（Running → Created）を
//!   状態ストアへ書くため、状態は Created のままでも `state.json` の revision は進む（ファイルは不変ではない）。
//! - 計測（REPAIR-4）のファイル出力は Linux の x86_64 / aarch64 のみ（`op_log_file`）。本バイナリを
//!   setuid / setgid・file capability つきで導入しない前提で、権限分離（TASK-171・SUP-14）で見直す。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。ここでは core を呼ぶだけで、
//!   非 Linux では core 側が `Unimplemented` を返す（fail-closed）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, LifecycleOp, OciRuntimeError, ProcessLauncher, StartTimeouts,
    StartedContainer, create, start,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, ErrorCode, StartRequest, StateRecord, StateStore, TraitError,
};

use super::CliExit;
use super::args::{CreateArgs, GlobalArgs, StartArgs};

/// core の操作へ注入する依存の束。
pub(super) struct Runtime {
    pub(super) store: Box<dyn StateStore>,
    pub(super) launcher: Arc<dyn ProcessLauncher>,
    pub(super) recorder: OpRecorder,
    pub(super) timeouts: StartTimeouts,
}

/// 本番の launcher。プロセス起動の本番実装がまだ無いため、常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// core の `start` は launch 失敗時に予約を Created へ戻すため、状態は壊れない。将来仕様: supervisor 経由で
/// コンテナプロセスを起動する実装（TASK-157・TASK-37〜39・CORE-1）に置き換える。
struct UnavailableLauncher;

impl ProcessLauncher for UnavailableLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "process launcher is not available yet",
        ))
    }
}

/// 構築済みの要求で core の `create` を呼ぶ。
pub(super) fn create_container(
    rt: &Runtime,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    create(rt.store.as_ref(), &rt.recorder, req)
}

/// 構築済みの要求で core の `start` を呼ぶ。起動済みプロセスのハンドルは呼び出し元へ返す
/// （監視・回収は呼び出し元の責務。CORE-1）。
pub(super) fn start_container(
    rt: &Runtime,
    req: &StartRequest,
) -> Result<StartedContainer, OciRuntimeError> {
    start(
        rt.store.as_ref(),
        &rt.recorder,
        &rt.launcher,
        req,
        &rt.timeouts,
    )
}

/// ID の文字種と bundle の絶対パスを core の型で検証する（相対パスの解決・canonicalize はしない。SEC-1）。
fn build_create_request(args: &CreateArgs) -> Result<CreateRequest, TraitError> {
    let id = ContainerId::new(args.id.as_str())?;
    CreateRequest::new(id, args.bundle.clone())
}

fn build_start_request(args: &StartArgs) -> Result<StartRequest, TraitError> {
    Ok(StartRequest::new(ContainerId::new(args.id.as_str())?))
}

/// 要求を構築し、状態ルートを解決して本番の依存を組む。要求構築が先なので、不正な入力では状態ルートを作らない。
/// いずれかの失敗は core に到達していないため、ここで `op_name` の失敗として記録する（REPAIR-4）。
fn production_runtime<R>(
    global: &GlobalArgs,
    recorder: OpRecorder,
    op_name: &str,
    started: Instant,
    build: impl FnOnce() -> Result<R, TraitError>,
) -> Result<(Runtime, R), TraitError> {
    let prepared = build().and_then(|req| {
        let root = StateRoot::resolve(global.root.clone())?;
        let store = FileStateStore::open(root)?;
        Ok((req, store))
    });
    match prepared {
        Ok((req, store)) => Ok((
            Runtime {
                store: Box::new(store),
                launcher: Arc::new(UnavailableLauncher),
                recorder,
                timeouts: StartTimeouts::default(),
            },
            req,
        )),
        Err(e) => {
            record_pre_core_failure(&recorder, op_name, started);
            export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
            Err(e)
        }
    }
}

/// core に到達する前の失敗を操作名 `op_name` の失敗として記録する（REPAIR-4）。
/// core に到達した操作は core 自身が記録するため、ここで二重には記録しない。
fn record_pre_core_failure(recorder: &OpRecorder, op_name: &str, started: Instant) {
    if let Ok(name) = OpName::new(op_name) {
        let _ = recorder.record(&name, OpOutcome::Failure, started.elapsed());
    }
}

/// 計測（`OpRecorder`）の JSON Lines 出力先を指す環境変数（REPAIR-4）。
///
/// OCI の stdout 契約（create / start は成功時に何も出さない）と stderr の 1 行エラー JSON を保つため、
/// 計測は stdout / stderr へ混ぜず、この環境変数が指すファイルへ追記する。未設定なら出力しない。
pub(super) const OP_LOG_ENV: &str = "FANDHE_CONTAINER_OP_LOG";

/// 計測ログの出力先を安全に開く Linux（x86_64 / aarch64）実装（SEC-1・REPAIR-5）。
///
/// [`export_ops`] から [`open_op_log`] だけが呼ばれる。open フラグの値はアーキテクチャごとに異なるため
/// （`flags`）、値を確認済みの x86_64 / aarch64 に限って有効にする。それ以外のアーキテクチャ・OS は
/// 外側の `open_op_log` が常に `None` を返し、計測を出力しない（fail-closed。core の `sys` が対応外
/// アーキテクチャで `Unsupported` を返すのと同じ判断）。
///
/// 前提（SEC-1）: 本バイナリを setuid / setgid・file capability つきで導入しない。出力先は環境変数で
/// 指定でき、検査は「実効 UID から見て差し替えられない経路か」だけを見るため、呼び出し元より高い権限で
/// 動くと、呼び出し元が本来書けないファイルへ追記させられる。この前提が破られた実行のうち、実 / 実効の
/// UID・GID の食い違いとして観測できるものは [`unelevated_euid`] で検出して出力を拒否する
/// （file capability だけが付いた実行は UID・GID に現れないため検出できない）。
/// 権限分離の方式（TASK-171・SUP-14）が決まったら、この判定と出力先の扱いを見直す。
///
/// 将来仕様（REPAIR-3）: open フラグと fd 相対の open は、core に安全な公開 API を置いて再利用する形へ
/// 寄せる（現状は cli 側の複製。core の変更を伴うため本 module では行っていない）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod op_log_file {
    pub(super) use flags::O_NONBLOCK;
    use flags::{O_DIRECTORY, O_NOFOLLOW, O_PATH};

    /// x86_64 の open フラグ（asm-generic の値）。libc 非依存のため値を直書きし、固定値テストで照合する。
    /// 値が同じものも含め、アーキテクチャごとに個別定義する（他アーキテクチャの値を流用しない）。
    #[cfg(target_arch = "x86_64")]
    mod flags {
        /// 読み手のいない FIFO の open で無期限にブロックしないための O_NONBLOCK（REPAIR-5）。
        pub(in super::super) const O_NONBLOCK: i32 = 0o4000;
        /// ディレクトリ以外の open を失敗させる O_DIRECTORY。
        pub(super) const O_DIRECTORY: i32 = 0o200_000;
        /// 最終要素が symlink なら open を失敗させる O_NOFOLLOW。
        pub(super) const O_NOFOLLOW: i32 = 0o400_000;
        /// 副作用なく inode だけを固定する O_PATH。
        pub(super) const O_PATH: i32 = 0o10_000_000;
    }

    /// aarch64 の open フラグ。O_DIRECTORY / O_NOFOLLOW は arm64 が asm-generic の値を上書きしている。
    #[cfg(target_arch = "aarch64")]
    mod flags {
        /// 読み手のいない FIFO の open で無期限にブロックしないための O_NONBLOCK（REPAIR-5）。
        pub(in super::super) const O_NONBLOCK: i32 = 0o4000;
        /// ディレクトリ以外の open を失敗させる O_DIRECTORY。
        pub(super) const O_DIRECTORY: i32 = 0o40_000;
        /// 最終要素が symlink なら open を失敗させる O_NOFOLLOW。
        pub(super) const O_NOFOLLOW: i32 = 0o100_000;
        /// 副作用なく inode だけを固定する O_PATH。
        pub(super) const O_PATH: i32 = 0o10_000_000;
    }

    /// 新規作成する計測ログの mode（所有者のみ読み書き。umask に任せて group / other へ開かない）。
    const OP_LOG_CREATE_MODE: u32 = 0o600;

    /// `/proc/self/status` を読む上限バイト数（無制限確保の防止。実際は 2 KiB 前後）。
    const PROC_STATUS_MAX_BYTES: u64 = 64 * 1024;

    /// `/proc/<pid>/status` の本文から `key`（`Uid:` / `Gid:`）の 4 値（real・effective・saved・fs）を取り出す。
    /// 行が無い・複数ある・値が 4 個でない・10 進の `u32` でない場合は `None`。
    fn status_ids(status: &str, key: &str) -> Option<[u32; 4]> {
        let mut found = None;
        for line in status.lines() {
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            let mut fields = rest.split_ascii_whitespace();
            let mut ids = [0u32; 4];
            for slot in &mut ids {
                let field = fields.next()?;
                if !field.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                *slot = field.parse().ok()?;
            }
            if fields.next().is_some() {
                return None;
            }
            found = Some(ids);
        }
        found
    }

    /// `/proc/<pid>/status` の本文から、権限が持ち上がっていない実行の実効 UID を返す（SEC-1）。
    ///
    /// UID・GID それぞれの real・effective・saved・fs の 4 値がすべて一致するときだけ `Some(実効 UID)`。
    /// 食い違い（setuid / setgid で起動された・途中で切り替えた）や、形式を解釈できない場合は `None` で、
    /// 呼び出し側は計測を出力しない（fail-closed）。ファイル操作の権限は fs 値で決まるため、real と
    /// effective だけでなく 4 値すべての一致を求める。
    pub(super) fn unelevated_euid_from_status(status: &str) -> Option<u32> {
        let [ruid, euid, suid, fsuid] = status_ids(status, "Uid:")?;
        let [rgid, egid, sgid, fsgid] = status_ids(status, "Gid:")?;
        let same_uid = ruid == euid && euid == suid && suid == fsuid;
        let same_gid = rgid == egid && egid == sgid && sgid == fsgid;
        (same_uid && same_gid).then_some(euid)
    }

    /// 呼び出しプロセスの実効 UID を `/proc/self/status` から得る（unsafe・libc なし）。
    /// 読めない・上限超過・[`unelevated_euid_from_status`] が拒否した場合は `None`（計測を出力しない）。
    pub(super) fn unelevated_euid() -> Option<u32> {
        use std::io::Read;
        let f = std::fs::File::open("/proc/self/status").ok()?;
        let mut text = String::new();
        f.take(PROC_STATUS_MAX_BYTES + 1)
            .read_to_string(&mut text)
            .ok()?;
        if text.len() as u64 > PROC_STATUS_MAX_BYTES {
            return None;
        }
        unelevated_euid_from_status(&text)
    }

    /// 開いた fd に対する要素 `name` の `/proc/self/fd/<fd>/<name>` 経路を作る。
    /// この経路は親 fd が指すディレクトリ直下の 1 要素だけを解決するため、パス文字列の再解決で
    /// 親が差し替えられる競合（TOCTOU）が起きない。`openat` 相当を unsafe なしで実現する（SEC-1）。
    fn child_via_fd(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::path::PathBuf {
        use std::os::fd::AsRawFd;
        std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name)
    }

    /// 開いた fd のディレクトリが、他ユーザーに差し替えられない状態かを fd から検査する（SEC-1）。
    /// ディレクトリであり、所有者が root か自分で、group / other 書き込み可なら sticky bit を要する。
    fn dir_trusted(dir: &std::fs::File, euid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(m) = dir.metadata() else {
            return false;
        };
        let mode = m.mode();
        let writable_by_others = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        let owner_ok = m.uid() == 0 || m.uid() == euid;
        m.is_dir() && owner_ok && (!writable_by_others || sticky)
    }

    /// `dir` 直下の要素 `name` を O_NOFOLLOW でディレクトリとして開く（親 fd 経由。SEC-1）。
    fn open_dir_at(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY)
            .open(child_via_fd(dir, name))
    }

    /// symlink を辿る回数の上限（ループ・過大な展開の防止）。
    const MAX_SYMLINK_HOPS: u32 = 8;

    /// 解決待ちの経路要素。`..` は物理的な親（開いた fd のスタックの 1 つ手前）へ戻る。
    enum Step {
        Name(std::ffi::OsString),
        Parent,
    }

    /// 親ディレクトリを、ルートから 1 要素ずつディレクトリ fd で固定しながら開く（SEC-1）。
    ///
    /// 各要素は直前に開いた fd 経由で O_NOFOLLOW | O_DIRECTORY で開き、開いた fd ごとに所有者・権限を
    /// 検査する。パス全体を再解決しないため、検査と open の間に親を symlink へ差し替えられない。
    /// root 所有の symlink（システム標準の `/var/run` -> `../run` 等）のみ、その場で内容を読んで同じ
    /// 手順で辿る（root 所有のため一般ユーザーは差し替えられない）。`..` は検査済みディレクトリ fd の
    /// スタックを 1 つ戻して解決し、ルートより上へ出る経路は拒否する。
    pub(super) fn open_trusted_parent(
        parent: &std::path::Path,
        euid: u32,
    ) -> Option<std::fs::File> {
        use std::collections::VecDeque;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::Component;

        /// `path` の各要素を `queue` の先頭へ順序を保って積み、絶対パスだったかを返す。
        fn push_components(queue: &mut VecDeque<Step>, path: &std::path::Path) -> Option<bool> {
            let mut absolute = false;
            let mut steps = Vec::new();
            for c in path.components() {
                match c {
                    Component::RootDir => absolute = true,
                    Component::Normal(n) => steps.push(Step::Name(n.to_os_string())),
                    Component::ParentDir => steps.push(Step::Parent),
                    Component::CurDir => {}
                    Component::Prefix(_) => return None,
                }
            }
            for st in steps.into_iter().rev() {
                queue.push_front(st);
            }
            Some(absolute)
        }

        let abs = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(parent)
        };
        let open_root = || -> Option<std::fs::File> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY)
                .open("/")
                .ok()?;
            dir_trusted(&f, euid).then_some(f)
        };
        let mut queue = VecDeque::new();
        push_components(&mut queue, &abs)?;
        // 検査済みディレクトリ fd のスタック（先頭がルート、末尾が現在位置）。
        let mut stack = vec![open_root()?];
        let mut hops = 0;
        while let Some(step) = queue.pop_front() {
            let name = match step {
                Step::Parent => {
                    // ルートより上へは出ない（escape-above-root は拒否）。
                    if stack.len() <= 1 {
                        return None;
                    }
                    stack.pop();
                    continue;
                }
                Step::Name(n) => n,
            };
            let cur = stack.last()?;
            match open_dir_at(cur, &name) {
                Ok(next) => {
                    if !dir_trusted(&next, euid) {
                        return None;
                    }
                    stack.push(next);
                }
                Err(_) => {
                    // symlink だった場合のみ、root 所有に限って辿る。それ以外は拒否する。
                    let link = child_via_fd(cur, &name);
                    let m = std::fs::symlink_metadata(&link).ok()?;
                    if !m.file_type().is_symlink() || m.uid() != 0 {
                        return None;
                    }
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return None;
                    }
                    let target = std::fs::read_link(&link).ok()?;
                    if push_components(&mut queue, &target)? {
                        stack.truncate(1);
                    }
                }
            }
        }
        stack.pop()
    }

    /// 計測出力先を副作用なく固定して検証してから書き込み用に開く。通常ファイル以外は拒否する。
    ///
    /// 親ディレクトリをルートから fd で固定しながら開き（[`open_trusted_parent`]）、
    /// その親 fd 経由で最終要素を O_PATH | O_NOFOLLOW で固定する。O_PATH はデバイス・FIFO を開いても
    /// 副作用（`/dev/watchdog` の起動等）を起こさない。固定した fd で種別・ハードリンク数（1 のみ許可）・
    /// 所有者を検証した後に限り、`/proc/self/fd` 経由で同じ inode を追記用に開き直し、再度検証する。
    /// 未存在のときは O_EXCL（create_new）・mode 0600 で排他的に作成し、既存対象の検査を迂回させない
    /// （SEC-1・REPAIR-5）。実 / 実効の UID・GID が食い違う実行（[`unelevated_euid`]）では開かない。
    /// 排他作成が並行プロセスに負けた（AlreadyExists）ときは、既存対象として検証からやり直す
    /// （[`OP_LOG_OPEN_ATTEMPTS`] 回まで）。
    pub(super) fn open_op_log(path: &std::ffi::OsStr) -> Option<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let path = std::path::Path::new(path);
        let name = path.file_name()?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        let euid = unelevated_euid()?;
        let dir = open_trusted_parent(parent, euid)?;
        let target = child_via_fd(&dir, name);
        let verify = |f: &std::fs::File| -> bool {
            f.metadata()
                .map(|m| m.is_file() && m.nlink() == 1 && m.uid() == euid)
                .unwrap_or(false)
        };
        // 未存在 → 排他作成の間に別プロセスが同じファイルを作ると create_new は AlreadyExists で失敗する。
        // その場合に限り、既存対象として検証からやり直す（並行起動した CLI の計測を落とさない。REPAIR-4）。
        // やり直しは有限回で、ファイルの作成・削除を繰り返されても無期限には回らない（REPAIR-5）。
        for _ in 0..OP_LOG_OPEN_ATTEMPTS {
            let pinned = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_PATH | O_NOFOLLOW)
                .open(&target)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // 未存在: 排他的に作成する（既存・競合で現れた対象には O_EXCL で失敗する）。
                    match std::fs::OpenOptions::new()
                        .append(true)
                        .create_new(true)
                        .mode(OP_LOG_CREATE_MODE)
                        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
                        .open(&target)
                    {
                        Ok(f) => return verify(&f).then_some(f),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(_) => return None,
                    }
                }
                Err(_) => return None,
            };
            if !verify(&pinned) {
                return None;
            }
            let f = std::fs::OpenOptions::new()
                .append(true)
                .custom_flags(O_NONBLOCK)
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
                .ok()?;
            return verify(&f).then_some(f);
        }
        None
    }

    /// [`open_op_log`] が「固定 → 検証 → 開く」を試す回数の上限。2 回目以降は、未存在からの排他作成が
    /// 並行プロセスに負けたときだけ使う（REPAIR-5: 無期限に回らない）。
    const OP_LOG_OPEN_ATTEMPTS: u32 = 4;
}

/// 対応外の環境（macOS・Windows、および x86_64 / aarch64 以外の Linux）は計測のファイル出力を拒否する
/// （fail-closed。SEC-1・REPAIR-4）。macOS・Windows は実効 UID の取得と symlink / junction / reparse point の
/// 安全な検査が未実装、他アーキテクチャの Linux は open フラグの値が未確認のため。
/// 将来は各 OS の安全な open 実装を `sys` モジュールに追加して対応する。
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn open_op_log(_path: &std::ffi::OsStr) -> Option<std::fs::File> {
    None
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use op_log_file::open_op_log;

/// 1 回の計測出力（全 `op_stats` 行 + メタ行）の上限バイト数（REPAIR-4・REPAIR-5）。
///
/// 出力は型で有界である。行数は core の `MAX_TRACKED_OPS`（64）+ メタ 1 行まで、1 行は固定キー・
/// `OP_NAME_MAX_LEN`（64）バイト以下の操作名・整数値だけで 512 バイトに収まる。したがって通常は
/// 33 KiB 未満で、この上限は core 側の形式が変わったときに巨大な 1 回書き込みをしないための歯止め。
/// 超過した出力は書かずに捨てる（計測は best effort。操作の結果は変えない）。
const OP_LOG_MAX_BYTES: usize = 64 * 1024;

/// 割り込み（EINTR）で 1 バイトも書けなかった write をやり直す回数の上限（REPAIR-5）。
const OP_LOG_WRITE_ATTEMPTS: u32 = 4;

/// 計測スナップショット全体を 1 つのバッファへ組み立て、`w` へ **1 回の `write`** で書く（REPAIR-4）。
///
/// 複数の CLI プロセスが同じ計測ログへ並行に追記しても JSON 行が混ざらないようにするための入口。
/// core の `OpRecorder::export_json_lines` は行本体と改行を別々の `write_all` で書くため、ファイルへ
/// 直接渡すと「A の本体 → B の本体 → 改行」の順で 1 行に 2 つの JSON が並びうる。ここではメモリ上の
/// バッファへ書かせ、全行（LF 終端）を 1 回の write(2) にまとめる。`O_APPEND` で開いた通常ファイルへの
/// 1 回の write(2) は、追記位置の決定と書き込みを inode ロックの下で一括して行うため、他プロセスの
/// 追記と行の途中で混ざらない（行単位ではなく 1 回の出力全体が連続する）。プロセス間ロックは使わない
/// ため、ロック保持者を待って CLI が結果を返せなくなる経路も増えない（REPAIR-5）。
///
/// `write_all` は使わない。部分書き込みを残りの write で継ぎ足すと、その間に他プロセスの行が
/// 入りうるため、書けたバイト数が全体に満たなければ継ぎ足さずに失敗を返す（容量不足・
/// `RLIMIT_FSIZE` 等。このとき末尾に不完全な行が残りうる。読み手は解析できない行を捨てること）。
/// 1 バイトも書かれない EINTR だけは [`OP_LOG_WRITE_ATTEMPTS`] 回までやり直す。
/// 戻り値は書いたバイト数。[`OP_LOG_MAX_BYTES`] を超える出力は 1 バイトも書かずに失敗を返す。
fn write_ops_once(recorder: &OpRecorder, w: &mut dyn std::io::Write) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    let mut buf: Vec<u8> = Vec::new();
    recorder
        .export_json_lines(Some(&mut buf))
        .map_err(|_| Error::other("failed to encode op stats"))?;
    if buf.len() > OP_LOG_MAX_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "op stats output exceeds the size limit",
        ));
    }
    for _ in 0..OP_LOG_WRITE_ATTEMPTS {
        match w.write(&buf) {
            Ok(n) if n == buf.len() => return Ok(n),
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "op stats output was written partially",
                ));
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Interrupted,
        "op stats output was interrupted repeatedly",
    ))
}

/// 計測を `path` の通常ファイルへ追記する（best effort。失敗しても終了コード・エラー出力は変えない）。
///
/// open は O_NONBLOCK で行い、通常ファイル以外は拒否して書き込まない（REPAIR-5: 読み手のいない
/// FIFO 等で CLI が無期限にブロックしない）。書き込みは [`write_ops_once`] による 1 回の write で、
/// 同じファイルへ並行に追記する他の CLI プロセスと JSON 行が混ざらない（REPAIR-4）。
pub(super) fn export_ops(recorder: &OpRecorder, path: Option<&std::ffi::OsStr>) {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return;
    };
    let Some(mut f) = open_op_log(path) else {
        return;
    };
    let _ = write_ops_once(recorder, &mut f);
}

/// 本番入口の `create`。成功時は何も出さない（OCI の create 互換）。
///
/// 要求構築・状態ストア初期化の失敗も操作名 `create` の失敗として計測する（REPAIR-4）。
pub(super) fn run_create(global: &GlobalArgs, args: &CreateArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let result = production_runtime(global, recorder, "create", started, || {
        build_create_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Create, e))
    .and_then(|(rt, req)| {
        let r = create_container(&rt, &req);
        export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
        r
    });
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `start`。
pub(super) fn run_start(global: &GlobalArgs, args: &StartArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let prepared = production_runtime(global, recorder, "start", started, || {
        build_start_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let result = start_container(&rt, &req);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        // 本番 launcher（UnavailableLauncher）では到達しない。将来 launcher が差し替わっても、
        // 監視者へ引き渡せないまま CLI が終了して孤児プロセスを残さないよう、止めてから失敗を返す
        // （fail-closed）。supervisor への引き渡しは TASK-157。
        // 注意: この枝はプロセスを止めるだけで、core が Running（pid あり）へ進めた状態は戻さない。
        // TASK-157 で launcher を差し替えるときは、supervisor への引き渡しか、状態のロールバック
        // （停止の記録）のどちらかをここへ必ず入れること（入れないと、プロセスのいない Running が残る）。
        Ok(started) => {
            let (_record, process) = started.into_parts();
            let _ = process.terminate(rt.timeouts.terminate());
            CliExit::Runtime(OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Internal,
                "no supervisor is available to take over the started process",
            ))
        }
        Err(e) => CliExit::Runtime(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_args(bundle: &str, id: &str) -> CreateArgs {
        CreateArgs {
            bundle: PathBuf::from(bundle),
            id: id.to_string(),
        }
    }

    /// CLI-1・ERR-2: 相対 bundle は INVALID_ARGUMENT（終了コード 2・op=create）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_create_rejects_relative_bundle() {
        let e = build_create_request(&create_args("rel/b", "c1")).expect_err("relative");
        let e = OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.exit_code().get(), 2);
        assert_eq!(e.op(), LifecycleOp::Create);
    }

    /// CLI-1・ERR-2: 不正な ID 文字は INVALID_ARGUMENT。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_create_request(&CreateArgs {
                bundle: std::env::temp_dir(),
                id: id.to_string(),
            })
            .expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_start_request(&StartArgs { id: id.to_string() }).expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1: 正常な引数は core の要求型へ値をそのまま写す。
    #[test]
    fn cli1_build_create_request_keeps_values() {
        // OS ごとに絶対パスの形が違う（Windows は `/abs/b` を絶対と見なさない）ため temp_dir 由来にする。
        let bundle = std::env::temp_dir().join("abs-b");
        let req = build_create_request(&CreateArgs {
            bundle: bundle.clone(),
            id: "c1".to_string(),
        })
        .expect("ok");
        assert_eq!(req.id().as_str(), "c1");
        assert_eq!(req.bundle(), bundle.as_path());
    }

    /// REPAIR-4: 計測は指定ファイルへ JSON Lines で追記され、未指定なら何も書かない。
    /// Linux 以外は計測のファイル出力を拒否するため対象外（SEC-1）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair4_export_ops_appends_json_lines() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        export_ops(&rec, None);
        assert!(!path.exists());
        export_ops(&rec, Some(path.as_os_str()));
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"op_stats\""));
        assert!(lines[1].contains("\"op_stats_meta\""));
    }

    /// write の呼び出しごとの引数長を記録し、台本どおりの結果を返す出力先（台本が尽きたら全量を受理）。
    struct ScriptedSink {
        calls: Vec<usize>,
        data: Vec<u8>,
        script: std::collections::VecDeque<std::io::Result<usize>>,
    }

    impl ScriptedSink {
        fn new(script: Vec<std::io::Result<usize>>) -> Self {
            Self {
                calls: Vec::new(),
                data: Vec::new(),
                script: script.into(),
            }
        }
    }

    impl std::io::Write for ScriptedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls.push(buf.len());
            let n = match self.script.pop_front() {
                Some(r) => r?.min(buf.len()),
                None => buf.len(),
            };
            self.data.extend_from_slice(buf.get(..n).unwrap_or(buf));
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `name` を成功 1 件（1 ms）だけ記録した計測器。
    fn recorder_with(name: &str) -> OpRecorder {
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new(name).expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        rec
    }

    const CREATE_ONCE_LINES: &str = concat!(
        "{\"event\":\"op_stats\",\"op\":\"create\",\"success\":1,\"failure\":0,\"count\":1,",
        "\"min_us\":1000,\"mean_us\":1000,\"p95_us\":1000,\"max_us\":1000}\n",
        "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}\n",
    );

    /// REPAIR-4: 計測の全行（op_stats 行 + メタ行。各行 LF 終端）を 1 回の write で書く。
    /// 行本体と改行を別の write に分けない（並行追記で JSON 行が混ざらないための前提）。
    #[test]
    fn repair4_write_ops_once_emits_all_lines_in_single_write() {
        let mut sink = ScriptedSink::new(Vec::new());
        let n = write_ops_once(&recorder_with("create"), &mut sink).expect("write");
        assert_eq!(n, CREATE_ONCE_LINES.len());
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len()]);
        assert_eq!(
            String::from_utf8(sink.data).expect("utf8"),
            CREATE_ONCE_LINES
        );
    }

    /// REPAIR-4: 部分書き込みは残りを継ぎ足さず失敗にする（継ぎ足しの間に他プロセスの行が入るため）。
    #[test]
    fn repair4_write_ops_once_does_not_continue_partial_write() {
        let mut sink = ScriptedSink::new(vec![Ok(10)]);
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("partial");
        assert_eq!(e.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len()]);
        assert_eq!(sink.data.len(), 10);
    }

    /// REPAIR-4・REPAIR-5: 1 バイトも書けない EINTR は有限回だけやり直し、やり直しも全量 1 回の write。
    #[test]
    fn repair5_write_ops_once_retries_interrupted_bounded() {
        let interrupted = || Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        let mut sink = ScriptedSink::new(vec![interrupted()]);
        let n = write_ops_once(&recorder_with("create"), &mut sink).expect("write");
        assert_eq!(n, CREATE_ONCE_LINES.len());
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len(); 2]);
        assert_eq!(
            String::from_utf8(sink.data).expect("utf8"),
            CREATE_ONCE_LINES
        );

        let mut sink = ScriptedSink::new((0..8).map(|_| interrupted()).collect());
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("interrupted");
        assert_eq!(e.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(sink.calls.len(), 4);
        assert!(sink.data.is_empty());

        let mut sink = ScriptedSink::new(vec![Err(std::io::Error::other("disk"))]);
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("error");
        assert_eq!(e.kind(), std::io::ErrorKind::Other);
        assert_eq!(sink.calls.len(), 1);
    }

    /// REPAIR-4: 操作名の種類数が core の上限（64）でも 1 回の出力は上限（64 KiB）に収まり、1 回の write で出る。
    #[test]
    fn repair4_write_ops_once_fits_limit_at_max_tracked_ops() {
        use fandhe_container_core::observability::{MAX_TRACKED_OPS, OP_NAME_MAX_LEN};
        let rec = OpRecorder::new();
        for i in 0..MAX_TRACKED_OPS {
            let name = format!("{i:0>width$}", width = OP_NAME_MAX_LEN);
            rec.record(
                &OpName::new(name).expect("name"),
                OpOutcome::Failure,
                Duration::MAX,
            )
            .expect("record");
        }
        let mut sink = ScriptedSink::new(Vec::new());
        let n = write_ops_once(&rec, &mut sink).expect("write");
        assert_eq!(sink.calls, vec![n]);
        assert!(n <= OP_LOG_MAX_BYTES, "{n}");
        let text = String::from_utf8(sink.data).expect("utf8");
        assert_eq!(text.lines().count(), MAX_TRACKED_OPS + 1);
        assert!(text.lines().all(|l| l.len() <= 512), "line too long");
    }

    /// REPAIR-4: 複数スレッドが別々の fd で同じ計測ログへ並行に追記しても、JSON 行が混ざらない。
    /// 未存在からの同時作成でも出力を落とさず、各出力の 2 行（op_stats・メタ）は連続して並ぶ。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair4_export_ops_concurrent_appends_keep_lines_intact() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 50;
        let path =
            std::env::temp_dir().join(format!("fc-cli-oplog-concurrent-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let rec = recorder_with(&format!("op{t}"));
                    barrier.wait();
                    for _ in 0..ROUNDS {
                        export_ops(&rec, Some(path.as_os_str()));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        assert!(text.ends_with('\n'));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), THREADS * ROUNDS * 2);
        let meta = "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}";
        let mut per_thread = vec![0usize; THREADS];
        for pair in lines.chunks(2) {
            let t = (0..THREADS)
                .find(|t| {
                    pair.first().copied()
                        == Some(
                            format!(
                                "{{\"event\":\"op_stats\",\"op\":\"op{t}\",\"success\":1,\"failure\":0,\"count\":1,\"min_us\":1000,\"mean_us\":1000,\"p95_us\":1000,\"max_us\":1000}}"
                            )
                            .as_str(),
                        )
                })
                .unwrap_or_else(|| panic!("mixed or unknown line: {pair:?}"));
            assert_eq!(pair.get(1).copied(), Some(meta), "{pair:?}");
            if let Some(c) = per_thread.get_mut(t) {
                *c += 1;
            }
        }
        assert_eq!(per_thread, vec![ROUNDS; THREADS]);
    }

    /// REPAIR-5: 計測出力先が FIFO でも `export_ops` がブロックせず、何も書き込まない。
    /// 読み手がいない場合と、読み手が open しただけで読まない場合の両方を具体値で検証する。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair5_export_ops_rejects_fifo_without_blocking() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        use std::os::unix::fs::OpenOptionsExt;
        let rec = Arc::new(OpRecorder::new());
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let run = |path: std::path::PathBuf| {
            let (tx, rx) = std::sync::mpsc::channel();
            let rec = Arc::clone(&rec);
            std::thread::spawn(move || {
                export_ops(&rec, Some(path.as_os_str()));
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5))
                .expect("export_ops must not block on a FIFO");
        };
        let mkfifo = |name: &str| {
            let p =
                std::env::temp_dir().join(format!("fc-cli-oplog-{name}-{}", std::process::id()));
            let _ = std::fs::remove_file(&p);
            let st = std::process::Command::new("mkfifo")
                .arg(&p)
                .status()
                .expect("mkfifo");
            assert!(st.success());
            p
        };
        // 読み手なし。
        let p1 = mkfifo("noreader");
        run(p1.clone());
        let _ = std::fs::remove_file(&p1);
        // 読み手あり（open のみで読まない）。何も書かれていないこと。
        let p2 = mkfifo("idlereader");
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(op_log_file::O_NONBLOCK)
            .open(&p2)
            .expect("open reader");
        run(p2.clone());
        let mut buf = [0u8; 16];
        let n = match std::io::Read::read(&mut &reader, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(e) => panic!("read: {e}"),
        };
        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&p2);
    }

    /// SEC-1: 最終要素が symlink なら辿らず拒否し、リンク先は書き換えない。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_open_op_log_rejects_symlink_and_hardlink() {
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").expect("victim");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        assert!(open_op_log(link.as_os_str()).is_none());
        let hard = dir.join("hard");
        std::fs::hard_link(&victim, &hard).expect("hardlink");
        assert!(open_op_log(hard.as_os_str()).is_none());
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
        let fresh = dir.join("fresh");
        assert!(open_op_log(fresh.as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: 信頼できない（非 root 所有の）親 symlink は辿らず拒否し、リンク先へ書かない。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_open_op_log_rejects_parent_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-psym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = dir.join("linkdir");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(open_op_log(link.join("log").as_os_str()).is_none());
        assert!(!real.join("log").exists());
        assert!(open_op_log(real.join("log").as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: デバイスノードは O_PATH で固定して種別検査で拒否し、書き込み用に開かない。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_open_op_log_rejects_device_node() {
        assert!(open_op_log(std::ffi::OsStr::new("/dev/null")).is_none());
    }

    /// SEC-1: 親の `..` は検査済み fd のスタックで解決でき、ルートより上へ出る経路は拒否する。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_open_trusted_parent_resolves_parent_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-dd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let via_dotdot = real.join("..").join("real").join("log");
        assert!(open_op_log(via_dotdot.as_os_str()).is_some());
        assert!(real.join("log").is_file());
        let euid = op_log_file::unelevated_euid().expect("euid");
        let above_root = std::path::Path::new("/..");
        assert!(op_log_file::open_trusted_parent(above_root, euid).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: Linux 以外は計測のファイル出力を拒否し、ファイルを作らない（fail-closed）。
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    #[test]
    fn sec1_open_op_log_refused_on_unsupported_target() {
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-nl-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(open_op_log(path.as_os_str()).is_none());
        assert!(!path.exists());
    }

    /// REPAIR-4: 不正 ID（core 到達前の失敗）も操作名 create の失敗として 1 件計測される。
    #[test]
    fn repair4_pre_core_failure_is_recorded_once() {
        let rec = OpRecorder::new();
        record_pre_core_failure(&rec, "create", Instant::now());
        let snap = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("snap");
        assert_eq!(snap.failure(), 1);
        assert_eq!(snap.success(), 0);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use fandhe_container_core::traits::ContainerState;
        use std::num::NonZeroU32;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("fc-cli-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
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

        /// 有効な bundle（config.json と rootfs/）を作る。
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

        fn runtime(base: &TmpDir, launcher: Arc<dyn ProcessLauncher>) -> Runtime {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            Runtime {
                store: Box::new(FileStateStore::open(root).expect("open")),
                launcher,
                recorder: OpRecorder::new(),
                timeouts: StartTimeouts::default(),
            }
        }

        struct FakeProcess;

        impl LaunchedProcess for FakeProcess {
            fn pid(&self) -> NonZeroU32 {
                NonZeroU32::new(4242).expect("nonzero")
            }
            fn wait(
                &self,
                _timeout: Duration,
            ) -> Result<Option<fandhe_container_core::oci_runtime::ProcessExit>, TraitError>
            {
                Ok(None)
            }
            fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }

        struct FakeLauncher(AtomicUsize);

        impl ProcessLauncher for FakeLauncher {
            fn launch(
                &self,
                _spec: &LaunchSpec,
                _timeout: Duration,
            ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(FakeProcess))
            }
        }

        /// CLI-1・OCI-4: create は core を呼び、Created（pid なし）を記録する。同一 ID の再 create は ALREADY_EXISTS（4）。
        #[test]
        fn cli1_create_calls_core_and_rejects_duplicate() {
            let base = TmpDir::new("create");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            let args = CreateArgs {
                bundle: bundle.clone(),
                id: "c1".into(),
            };
            let rec =
                create_container(&rt, &build_create_request(&args).expect("req")).expect("create");
            assert_eq!(rec.status().state(), ContainerState::Created);
            assert_eq!(rec.status().pid(), None);
            let e =
                create_container(&rt, &build_create_request(&args).expect("req")).expect_err("dup");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(e.exit_code().get(), 4);
            assert_eq!(e.op(), LifecycleOp::Create);
        }

        /// ERR-2: 未 create の ID の start は NOT_FOUND（3）で launcher を呼ばない。
        #[test]
        fn err2_start_unknown_id_is_not_found() {
            let base = TmpDir::new("notfound");
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            let e = start_container(
                &rt,
                &build_start_request(&StartArgs { id: "nope".into() }).expect("req"),
            )
            .expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
        }

        /// CLI-1・CORE-1: create → start で Running・launcher の返した pid が記録され、ハンドルが呼び出し元へ渡る。
        #[test]
        fn cli1_start_calls_core_and_hands_over_process() {
            let base = TmpDir::new("start");
            let bundle = make_bundle(&base);
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            create_container(
                &rt,
                &build_create_request(&CreateArgs {
                    bundle,
                    id: "start-ok".into(),
                })
                .expect("req"),
            )
            .expect("create");
            let started = start_container(
                &rt,
                &build_start_request(&StartArgs {
                    id: "start-ok".into(),
                })
                .expect("req"),
            )
            .expect("start");
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_eq!(started.record().status().pid(), NonZeroU32::new(4242));
            assert_eq!(started.process().pid().get(), 4242);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
        }

        /// REPAIR-3: 本番 launcher では start が UNIMPLEMENTED（8）で、状態は Created に戻る。
        #[test]
        fn repair3_unavailable_launcher_keeps_created() {
            let base = TmpDir::new("unavail");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            create_container(
                &rt,
                &build_create_request(&CreateArgs {
                    bundle,
                    id: "unavail".into(),
                })
                .expect("req"),
            )
            .expect("create");
            let e = start_container(
                &rt,
                &build_start_request(&StartArgs {
                    id: "unavail".into(),
                })
                .expect("req"),
            )
            .expect_err("unimpl");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            let id = ContainerId::new("unavail").expect("id");
            let got = rt
                .store
                .get(&fandhe_container_core::traits::GetStateRequest::new(id))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Created);
        }
    }
}
