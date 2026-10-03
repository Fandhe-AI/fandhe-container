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

fn stat_ns(path: &Path) -> Result<NsId, NetError> {
    // stat は ns の magic link を辿り nsfs inode の (dev, ino) を返す。
    let md = fs::metadata(path)
        .map_err(|e| proc_error(&e, "failed to stat network namespace entry in /proc"))?;
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
/// プロセス自体が無ければ `NotFound`。列挙中に終了したスレッドは飛ばす。数値でないエントリは
/// procfs の想定外の形として `Internal`（fail-closed）。全件を `Vec` に集めないため件数上限は設けない。
fn task_netns_ids(
    pid: u32,
) -> Result<impl Iterator<Item = Result<(u32, NsId), NetError>>, NetError> {
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let entries = fs::read_dir(&task_dir)
        .map_err(|e| proc_error(&e, "failed to read thread list in /proc"))?;
    Ok(entries.filter_map(move |entry| task_netns_id(&task_dir, entry).transpose()))
}

/// `task_netns_ids` の 1 エントリ分。終了済みスレッドは `Ok(None)`。
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
    match stat_ns(&thread_dir.join("ns").join("net")) {
        Ok(id) => Ok(Some((tid, id))),
        Err(e) => {
            // 終了済みスレッドの ns link はカーネルが ENOENT だけでなく EACCES も返し得る
            // （task 構造体の取得に失敗した時点で EACCES）。スレッドのディレクトリ自体が消えていれば
            // 終了と判断して飛ばし、残っていれば元のエラーを返す（権限不足を黙って見逃さない）。
            match fs::symlink_metadata(&thread_dir) {
                Err(gone) if gone.kind() == io::ErrorKind::NotFound => Ok(None),
                _ => Err(e),
            }
        }
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
    #[test]
    fn net6_task_netns_ids_enumerates_all_threads() {
        const N: usize = 3;
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let pid = std::process::id();
        let barrier = std::sync::Barrier::new(N + 1);
        // 各スレッドは tid の取得に失敗しても必ず barrier に到達し、main も検証より先に barrier を
        // 抜けるため、失敗時にテストがハングしない（REPAIR-5）。
        let (tids, listed, membership) = std::thread::scope(|s| {
            let (tx, rx) = std::sync::mpsc::channel::<Option<u32>>();
            for _ in 0..N {
                let tx = tx.clone();
                let barrier = &barrier;
                s.spawn(move || {
                    // `/proc/thread-self` は `<pid>/task/<tid>` を指す。
                    let tid = fs::read_link("/proc/thread-self").ok().and_then(|link| {
                        link.file_name()
                            .and_then(|n| n.to_str())
                            .and_then(|n| n.parse::<u32>().ok())
                    });
                    let _ = tx.send(tid);
                    barrier.wait();
                });
            }
            drop(tx);
            let tids: Vec<Option<u32>> = rx.iter().take(N).collect();
            let listed: Result<Vec<(u32, NsId)>, NetError> =
                task_netns_ids(pid).and_then(|it| it.collect());
            let membership = HostNetns { id: own }.verify_process(pid);
            barrier.wait();
            (tids, listed, membership)
        });
        let listed = listed.unwrap();
        assert_eq!(tids.len(), N);
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
        assert!(listed.iter().all(|(_, id)| *id == own));
        assert_eq!(membership.unwrap(), HostNetnsMembership::Member);
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
