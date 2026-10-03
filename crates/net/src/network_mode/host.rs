//! host モード（ホスト netns 共有）の検証（NET-6・TASK-143.1・#326・MS-8。Linux のみ）。
//!
//! host モードは新しい netns を作らず、runtime が OCI `linux.namespaces` から `network` を外して
//! 起動することでホストの netns を引き継ぐ（PoC-15 と同じ方式）。runtime（core）側の接続は本 crate の
//! スコープ外で、本モジュールは「呼び出しスレッドが本当にホスト netns にいるか」と「あるプロセスの
//! 全スレッドがホスト netns に属するか」を nsfs inode の (dev, ino) 照合で確かめる。`setns(2)` は使わず
//! unsafe も追加しない。
//!
//! # 契約
//! - ホスト netns の基準は runtime が渡す信頼済み識別子（[`NsId`]）のみ。`/proc/1/ns/net` は基準に使わない
//!   （PID namespace 内では PID 1 がホストと別 netns になり得て、誤った基準で判定してしまうため）。
//!   runtime はホスト側で取得した参照（起動時に保持した netns の (dev, ino) 等）を渡す責務を持つ。
//!   rootless の host モードは NET-9・TASK-147 の領域で未対応
//! - 呼び出しスレッドが基準の netns 以外にいる場合は `FailedPrecondition`。setns による加入
//!   （runtime 自体がホスト以外の netns で動く構成）は未実装の将来仕様（REPAIR-3）
//! - netns はスレッド単位の属性で、`/proc/<pid>/ns/net` はそのうち 1 スレッド（`pid` 自身）しか示さない。
//!   [`HostNetns::verify_process`] は `/proc/<pid>/task/` の全スレッドを照合し、1 つでも別 netns なら
//!   `Other` を返す。判定は呼び出し時点のスナップショットで、列挙後に作られたスレッドや列挙後の
//!   `setns(2)` は対象外。想定する呼び出し元は、exec 直後の自分の子を検証する runtime
//! - procfs の `/proc/<pid>/task/` の列挙は、列挙中に対象の別スレッドが終了すると生存スレッドを
//!   1 つ取りこぼし得る（カーネルの readdir は終了したスレッドの位置で打ち切り、次の呼び出しを先頭からの
//!   件数で再開するため、詰まった分だけ飛ぶ）。スレッドの終了と並行して照合すると「全スレッド」の保証は
//!   弱まる。想定する呼び出し元（exec 直後の単一スレッドの子）では並行終了が起きないため影響しない
//! - [`HostNetns::verify_process`] は pid 再利用による TOCTOU が残る。呼び出し側は自分の子 pid に限って使う。
//!   `pid` は本プロセスから見える `/proc` の PID namespace での番号として解釈する
//! - エラーメッセージは固定の英語文で、パスや inode の中身を含めない

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::classify_errno;

/// netns の識別子（nsfs inode の dev, ino）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NsId {
    dev: u64,
    ino: u64,
}

impl NsId {
    /// (dev, ino) から作る。
    pub fn new(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }
    /// nsfs のデバイス番号。
    pub fn dev(&self) -> u64 {
        self.dev
    }
    /// nsfs の inode 番号。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// プロセスの netns がホスト netns と一致するかの判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostNetnsMembership {
    /// ホスト netns に属する。
    Member,
    /// 別の netns に属する。
    Other {
        /// 観測した netns の識別子。
        observed: NsId,
    },
}

/// 検証済みのホスト netns（呼び出しスレッドが属していることを `detect` が確認済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostNetns {
    id: NsId,
}

/// ns の magic link を stat した失敗時のメッセージ（固定文。パスを含めない）。
const STAT_NS_FAILED: &str = "failed to stat network namespace entry in /proc";

fn stat_ns(path: &Path) -> Result<NsId, NetError> {
    stat_ns_io(path).map_err(|e| proc_error(&e, STAT_NS_FAILED))
}

/// `stat_ns` の `io::Error` を保ったままの版。失敗理由で終了中スレッドを見分ける呼び出し元が使う。
fn stat_ns_io(path: &Path) -> io::Result<NsId> {
    // stat は ns の magic link を辿り nsfs inode の (dev, ino) を返す。
    let md = fs::metadata(path)?;
    Ok(NsId::new(md.dev(), md.ino()))
}

fn proc_error(e: &io::Error, message: &'static str) -> NetError {
    NetError::new(
        e.raw_os_error()
            .map_or(NetErrorCode::Internal, classify_errno),
        message,
    )
}

/// `/proc/<pid>/task/` を列挙し、生存中の各スレッドの (tid, netns 識別子) を返すイテレータを作る。
///
/// プロセス自体が無ければ `NotFound`。列挙中に終了したスレッド・終了処理中のスレッドは飛ばす
/// （`skip_exited_thread`）。数値でないエントリは procfs の想定外の形として `Internal`（fail-closed）。
/// 全件を `Vec` に集めないため件数上限は設けない。
fn task_netns_ids(
    pid: u32,
) -> Result<impl Iterator<Item = Result<(u32, NsId), NetError>>, NetError> {
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let entries = fs::read_dir(&task_dir)
        .map_err(|e| proc_error(&e, "failed to read thread list in /proc"))?;
    Ok(entries.filter_map(move |entry| task_netns_id(&task_dir, entry).transpose()))
}

/// `task_netns_ids` の 1 エントリ分。終了中・終了済みスレッドは `Ok(None)`。
fn task_netns_id(
    task_dir: &Path,
    entry: io::Result<fs::DirEntry>,
) -> Result<Option<(u32, NsId)>, NetError> {
    let entry = entry.map_err(|e| proc_error(&e, "failed to read thread list in /proc"))?;
    let tid = entry
        .file_name()
        .to_str()
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| {
            NetError::new(
                NetErrorCode::Internal,
                "unexpected entry in /proc thread list",
            )
        })?;
    let thread_dir: PathBuf = task_dir.join(tid.to_string());
    match stat_ns_io(&thread_dir.join("ns").join("net")) {
        Ok(id) => Ok(Some((tid, id))),
        Err(e) => {
            skip_exited_thread(&e, || fs::symlink_metadata(&thread_dir).map(|_| ())).map(|()| None)
        }
    }
}

/// スレッドの ns link の stat 失敗を「終了中・終了済みとして飛ばす（`Ok(())`）」か「エラー」かに分ける。
///
/// NET-6・TASK-143.1 の全スレッド照合（[`HostNetns::verify_process`]）から呼ばれる。`dir_probe` は
/// スレッドのディレクトリ（`/proc/<pid>/task/<tid>`）を stat する関数で、`PermissionDenied` のときだけ呼ぶ。
/// - ENOENT: 飛ばす。tid のディレクトリが既に消えた場合に加え、終了処理中のスレッドでも返る。
///   カーネルは `do_exit` で `exit_task_namespaces` により nsproxy を外してから、後の `release_task` で
///   pid を外して `/proc` のエントリを消すため、その間（ゾンビの間はずっと）はディレクトリが残ったまま
///   ns link が ENOENT になる。nsproxy を失ったスレッドはもうネットワーク操作ができないため、飛ばしても
///   照合は弱まらない
/// - EACCES・EPERM（`PermissionDenied`）: task 構造体を取れなくなった時点（pid が外れた後）でも返るが、権限不足と区別できないため
///   `dir_probe` でディレクトリの消失（NotFound）を確かめたときだけ飛ばし、残っていれば元のエラーを返す
///   （権限不足を黙って見逃さない）
/// - その他: 元のエラーを返す
///
/// 全スレッドが飛ばされた場合（全スレッドが終了中のプロセス・`CONFIG_NET_NS` の無いカーネル）は
/// `classify_membership` が 0 件として `NotFound` を返す（fail-closed）。
fn skip_exited_thread(
    e: &io::Error,
    dir_probe: impl FnOnce() -> io::Result<()>,
) -> Result<(), NetError> {
    let skip = match e.kind() {
        io::ErrorKind::NotFound => true,
        io::ErrorKind::PermissionDenied => {
            dir_probe().is_err_and(|gone| gone.kind() == io::ErrorKind::NotFound)
        }
        _ => false,
    };
    if skip {
        Ok(())
    } else {
        Err(proc_error(e, STAT_NS_FAILED))
    }
}

/// スレッドごとの netns 識別子の並びから所属を判定する純粋関数。
///
/// 1 つでも `host` と異なれば最初の不一致を `Other` として返す。全件一致なら `Member`。
/// 観測できたスレッドが 0 件なら `NotFound`（判定根拠が無いため fail-closed）。
fn classify_membership(
    host: NsId,
    ids: impl IntoIterator<Item = Result<NsId, NetError>>,
) -> Result<HostNetnsMembership, NetError> {
    let mut seen = false;
    for id in ids {
        let id = id?;
        if id != host {
            return Ok(HostNetnsMembership::Other { observed: id });
        }
        seen = true;
    }
    if seen {
        Ok(HostNetnsMembership::Member)
    } else {
        Err(NetError::new(
            NetErrorCode::NotFound,
            "process has no live threads",
        ))
    }
}

/// 呼び出しスレッドの netns が信頼済みホスト netns と一致することを確認する純粋関数。
///
/// 一致しなければ `FailedPrecondition`（fail-closed）。
pub fn classify_host_netns(thread: NsId, trusted_host: NsId) -> Result<NsId, NetError> {
    if thread == trusted_host {
        Ok(trusted_host)
    } else {
        Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "calling thread is not in the host network namespace",
        ))
    }
}

impl HostNetns {
    /// 呼び出しスレッドが、runtime の渡した信頼済みホスト netns `trusted_host` にいることを確認する。
    ///
    /// `trusted_host` は runtime がホスト側で取得した識別子で、`/proc/1/ns/net` からは導出しない
    /// （PID namespace 内で誤判定するため。NET-6）。netns はスレッド単位のため `/proc/thread-self` を参照する。
    pub fn detect(trusted_host: NsId) -> Result<Self, NetError> {
        let thread = stat_ns(Path::new("/proc/thread-self/ns/net"))?;
        Ok(Self {
            id: classify_host_netns(thread, trusted_host)?,
        })
    }

    /// ホスト netns の識別子。
    pub fn id(&self) -> NsId {
        self.id
    }

    /// `pid` のプロセスの全スレッドがホスト netns に属するかを返す。
    ///
    /// `/proc/<pid>/task/` の全スレッドを照合し、1 つでも別 netns なら `Other`（最初の不一致）。
    /// 呼び出し時点のスナップショットで、以後のスレッド生成・`setns(2)` は対象外。`pid` は
    /// 1..=`i32::MAX` のみ。pid 再利用の TOCTOU は残る（モジュール doc）。
    pub fn verify_process(&self, pid: u32) -> Result<HostNetnsMembership, NetError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "pid is out of range",
            ));
        }
        let ids = task_netns_ids(pid)?.map(|r| r.map(|(_, id)| id));
        classify_membership(self.id, ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自プロセスでスレッドを大量に終了させるテストと、自プロセスのスレッド列挙で特定 tid を探すテストを
    /// 直列化するロック。並行するスレッド終了で procfs の列挙が生存スレッドを取りこぼし得る（モジュール
    /// doc の契約）ため、同じプロセス内で並列実行すると後者が偽の失敗になる。
    static THREAD_CHURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 呼び出しスレッドの tid（`/proc/thread-self` は `<pid>/task/<tid>` を指す）。
    fn current_tid() -> Option<u32> {
        fs::read_link("/proc/thread-self").ok().and_then(|link| {
            link.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse::<u32>().ok())
        })
    }

    fn lock_thread_churn() -> std::sync::MutexGuard<'static, ()> {
        THREAD_CHURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// NET-6: 一致は Ok、不一致は FAILED_PRECONDITION。
    #[test]
    fn net6_classify_host_netns() {
        let a = NsId::new(4, 100);
        assert_eq!(classify_host_netns(a, a).unwrap(), a);
        let e = classify_host_netns(NsId::new(4, 101), a).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.code().as_str(), "FAILED_PRECONDITION");
        let e = classify_host_netns(NsId::new(5, 100), a).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-6: pid 範囲外は INVALID_ARGUMENT。
    #[test]
    fn net6_verify_process_rejects_bad_pid() {
        let h = HostNetns {
            id: NsId::new(1, 1),
        };
        for pid in [0u32, i32::MAX as u32 + 1, u32::MAX] {
            let e = h.verify_process(pid).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "pid {pid}");
        }
    }

    /// NET-6: 自プロセスの netns は非 root でも読め、同一 id なら Member、別 id なら Other。
    #[test]
    fn net6_verify_process_self() {
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let same = HostNetns { id: own };
        assert_eq!(
            same.verify_process(std::process::id()).unwrap(),
            HostNetnsMembership::Member
        );
        let other = HostNetns {
            id: NsId::new(own.dev(), own.ino() + 1),
        };
        assert_eq!(
            other.verify_process(std::process::id()).unwrap(),
            HostNetnsMembership::Other { observed: own }
        );
    }

    /// NET-6: 存在しない pid は NOT_FOUND。
    #[test]
    fn net6_verify_process_missing() {
        let h = HostNetns {
            id: NsId::new(1, 1),
        };
        // pid_max は 2^22 以下のため i32::MAX は存在しない。
        let e = h.verify_process(i32::MAX as u32).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
    }

    /// NET-6: 全スレッド一致のみ Member。1 つでも異なれば最初の不一致を Other、0 件は NOT_FOUND、
    /// 列挙エラーはそのまま返す（片方のスレッドだけ別 netns のプロセスを Member と誤判定しない）。
    #[test]
    fn net6_classify_membership_all_threads() {
        let h = NsId::new(4, 100);
        let o = NsId::new(4, 200);
        let p = NsId::new(4, 300);
        assert_eq!(
            classify_membership(h, [Ok(h), Ok(h)]).unwrap(),
            HostNetnsMembership::Member
        );
        assert_eq!(
            classify_membership(h, [Ok(h), Ok(o)]).unwrap(),
            HostNetnsMembership::Other { observed: o }
        );
        assert_eq!(
            classify_membership(h, [Ok(o), Ok(h)]).unwrap(),
            HostNetnsMembership::Other { observed: o }
        );
        assert_eq!(
            classify_membership(h, [Ok(h), Ok(p), Ok(o)]).unwrap(),
            HostNetnsMembership::Other { observed: p }
        );
        let e = classify_membership(h, []).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        let e = classify_membership(
            h,
            [
                Ok(h),
                Err(NetError::new(NetErrorCode::PermissionDenied, "denied")),
            ],
        )
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
    }

    /// NET-6: 複数スレッドの自プロセスでは、起こしたスレッドの tid がすべて列挙され、
    /// いずれも自スレッドと同じ netns で、verify_process は Member。
    ///
    /// libtest の他のワーカースレッドが並行して終了すると、procfs の列挙は生存スレッドを 1 つ取りこぼし得る
    /// （カーネルの `next_tid` は現在のスレッドが `pid_alive` でなくなると打ち切り、次の `getdents` は
    /// リーダーからの件数で再開する。モジュール doc の契約）。そのため列挙を最大 `PASSES` 回まで繰り返し、
    /// 起こしたスレッドとリーダーが揃った時点で止める。`Err` は再試行せず即座に失敗させ（終了中
    /// スレッドの誤エラーの回帰を隠さない）、揃わなかった途中の列挙も含めて全列挙の全件が自スレッドの
    /// netns であることを確かめる。
    #[test]
    fn net6_task_netns_ids_enumerates_all_threads() {
        const N: usize = 3;
        const PASSES: usize = 20;
        let _churn = lock_thread_churn();
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let pid = std::process::id();
        let barrier = std::sync::Barrier::new(N + 1);
        // 各スレッドは tid の取得に失敗しても必ず barrier に到達し、main も検証より先に barrier を
        // 抜けるため、失敗時にテストがハングしない（REPAIR-5）。
        let (tids, snapshots, membership) = std::thread::scope(|s| {
            let (tx, rx) = std::sync::mpsc::channel::<Option<u32>>();
            for _ in 0..N {
                let tx = tx.clone();
                let barrier = &barrier;
                s.spawn(move || {
                    let _ = tx.send(current_tid());
                    barrier.wait();
                });
            }
            drop(tx);
            let tids: Vec<Option<u32>> = rx.iter().take(N).collect();
            let expected: Vec<u32> = tids.iter().flatten().copied().chain([pid]).collect();
            let mut snapshots: Vec<Result<Vec<(u32, NsId)>, NetError>> = Vec::new();
            for _ in 0..PASSES {
                let snapshot: Result<Vec<(u32, NsId)>, NetError> =
                    task_netns_ids(pid).and_then(|it| it.collect());
                let retry = snapshot.as_ref().is_ok_and(|listed| {
                    !expected
                        .iter()
                        .all(|t| listed.iter().any(|(listed_tid, _)| listed_tid == t))
                });
                snapshots.push(snapshot);
                if !retry {
                    break;
                }
            }
            let membership = HostNetns { id: own }.verify_process(pid);
            barrier.wait();
            (tids, snapshots, membership)
        });
        assert_eq!(tids.len(), N);
        let snapshots: Vec<Vec<(u32, NsId)>> = snapshots.into_iter().map(|s| s.unwrap()).collect();
        for listed in &snapshots {
            assert!(listed.iter().all(|(_, id)| *id == own), "listed {listed:?}");
        }
        let listed = snapshots.last().expect("at least one enumeration");
        for tid in tids {
            let tid = tid.expect("thread tid from /proc/thread-self");
            assert_eq!(
                listed.iter().find(|(t, _)| *t == tid).map(|(_, id)| *id),
                Some(own),
                "tid {tid}"
            );
        }
        assert_eq!(
            listed.iter().find(|(t, _)| *t == pid).map(|(_, id)| *id),
            Some(own),
            "leader {pid}"
        );
        assert_eq!(membership.unwrap(), HostNetnsMembership::Member);
    }

    /// NET-6: ns link の stat 失敗の分類。ENOENT は終了中・終了済みとして飛ばし（ディレクトリは
    /// 確かめない）、`PermissionDenied` はディレクトリ消失時のみ飛ばす。それ以外・ディレクトリが
    /// 残る権限エラーは errno に応じたコードと固定文のエラー（権限不足を見逃さない）。
    #[test]
    fn net6_skip_exited_thread_classifies_stat_errors() {
        const ENOENT: i32 = 2;
        const EIO: i32 = 5;
        const EACCES: i32 = 13;
        let gone = || Err(io::Error::from_raw_os_error(ENOENT));
        let present = || Ok(());
        let unreachable_probe = || -> io::Result<()> { panic!("dir probe must not be called") };

        assert_eq!(
            skip_exited_thread(&io::Error::from_raw_os_error(ENOENT), unreachable_probe),
            Ok(())
        );
        assert_eq!(
            skip_exited_thread(&io::Error::from_raw_os_error(EACCES), gone),
            Ok(())
        );
        let e = skip_exited_thread(&io::Error::from_raw_os_error(EACCES), present).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.message(), STAT_NS_FAILED);
        // ディレクトリの確認自体が権限エラーでも、消失と確かめられないため元のエラーを返す。
        let e = skip_exited_thread(&io::Error::from_raw_os_error(EACCES), || {
            Err(io::Error::from_raw_os_error(EACCES))
        })
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        let e =
            skip_exited_thread(&io::Error::from_raw_os_error(EIO), unreachable_probe).unwrap_err();
        assert_eq!(e.code(), classify_errno(EIO));
        assert_eq!(e.message(), STAT_NS_FAILED);
    }

    /// `/proc/<pid>/stat` の状態文字（comm は空白・括弧を含み得るため最後の `)` の後ろを読む）。
    fn proc_state(pid: u32) -> Option<char> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(')')?;
        rest.trim_start().chars().next()
    }

    /// NET-6: 終了済み・未回収（ゾンビ）の子は nsproxy が外れ、`/proc/<pid>/task/<pid>` が残ったまま
    /// ns link が ENOENT になる（終了処理中スレッドと同じ状態を決定的に作る）。そのスレッドは飛ばされ、
    /// 生存スレッド 0 件として verify_process は「生存スレッド無し」の NOT_FOUND（fail-closed）を返す。
    #[test]
    fn net6_verify_process_zombie_has_no_live_threads() {
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        // ゾンビになるまで有界に待つ（REPAIR-5。最大 5 秒）。
        let mut state = None;
        for _ in 0..500 {
            state = proc_state(pid);
            if state == Some('Z') {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let task_dir_present = Path::new("/proc")
            .join(pid.to_string())
            .join("task")
            .join(pid.to_string())
            .exists();
        let listed: Result<Vec<(u32, NsId)>, NetError> =
            task_netns_ids(pid).and_then(|it| it.collect());
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let membership = HostNetns { id: own }.verify_process(pid);
        // 失敗時もゾンビを残さないよう、検証より先に回収する。
        let status = child.wait().expect("reap `true`");

        assert_eq!(state, Some('Z'));
        assert!(task_dir_present, "zombie thread directory must remain");
        assert_eq!(listed.unwrap(), Vec::<(u32, NsId)>::new());
        let e = membership.unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.message(), "process has no live threads");
        assert_eq!(status.code(), Some(0));
    }

    /// NET-6: スレッドの join 直後（カーネルではまだ `do_exit` の途中で、ディレクトリが残ったまま
    /// nsproxy が外れ得る）に自プロセスを照合しても Member のまま（CI run 37151011637 で
    /// libtest のワーカースレッド終了と競合して NOT_FOUND になった事象の再現）。
    ///
    /// 競合の発生は確率的なため本テストは再現の補助で、決定的な検証は
    /// `net6_verify_process_zombie_has_no_live_threads` が担う。待ち合わせを持たず有界に終わる。
    /// 列挙の取りこぼし（モジュール doc の契約）は本テストの判定を変えない: 列挙の先頭は常に生存中の
    /// スレッドグループリーダー（libtest のメインスレッド）で、同じ netns のスレッドが 1 件以上見えるため。
    #[test]
    fn net6_verify_process_self_while_threads_exit() {
        const ROUNDS: usize = 200;
        const THREADS: usize = 4;
        let _churn = lock_thread_churn();
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let host = HostNetns { id: own };
        let pid = std::process::id();
        let mut tids = Vec::with_capacity(ROUNDS * THREADS);
        for round in 0..ROUNDS {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| std::thread::spawn(current_tid))
                .collect();
            for h in handles {
                tids.extend(h.join().expect("worker thread"));
            }
            assert_eq!(
                host.verify_process(pid).unwrap(),
                HostNetnsMembership::Member,
                "round {round}"
            );
        }
        // join の後もカーネル側の終了処理は続くため、ロックを放す前に起こしたスレッドが `/proc` から
        // 消えるのを有界に待ち（最大 5 秒。REPAIR-5）、直列化した列挙テストへ終了を持ち越さない。
        // 待ちの打ち切りは本テストの判定に関係しないため失敗にしない。
        let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
        for _ in 0..500 {
            if tids.iter().all(|t| !task_dir.join(t.to_string()).exists()) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// NET-6: detect は渡された信頼済み基準とのみ照合する。自スレッドの id なら Ok、別 id なら
    /// FAILED_PRECONDITION（/proc/1 は参照しない）。
    #[test]
    fn net6_detect_uses_trusted_reference() {
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        assert_eq!(HostNetns::detect(own).unwrap().id(), own);
        let e = HostNetns::detect(NsId::new(own.dev(), own.ino() + 1)).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }
}
