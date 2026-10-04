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
//!   `Other` を返す。判定は列挙時点のスナップショットで、列挙後に作られたスレッドや列挙後の
//!   `setns(2)` は対象外。想定する呼び出し元は、exec 直後の自分の子を検証する runtime
//! - procfs の `/proc/<pid>/task/` の 1 回の列挙は、列挙中に対象の別スレッドが終了すると生存スレッドを
//!   1 つ取りこぼし得る（カーネルの readdir は、既に返したスレッドが `release_task` でスレッド一覧から
//!   外れると、次の `getdents` をスレッドグループリーダーからの件数で再開するため、詰まった分だけ飛ぶ）。
//!   そのため [`HostNetns::verify_process`] は列挙を繰り返し、生の tid 集合（ns link が ENOENT の終了中
//!   スレッドも含む）が 2 回連続で一致した時点で判定する（`scan_until_stable`）。取りこぼしの原因になった
//!   スレッドはその列挙に含まれ、一覧から外れているため次の列挙には現れない。よって 2 回連続の一致は、
//!   前の列挙に取りこぼしが無かったことを意味する（後の列挙が取りこぼしていても、その分は前の列挙で
//!   照合済み）。そのため各列挙の全エントリを照合し、どの列挙でも別 netns のスレッドが 1 つでもあれば
//!   即 `Other`。不一致の間は短い待ちを挟んで再列挙し、`MAX_PASSES` 回列挙しても一致しなければ判定不能
//!   として `FailedPrecondition`（fail-closed。待ちを含め有界）。
//!   残る穴は、列挙の間に同じ tid が同じプロセスの新しいスレッドへ再利用される場合（pid 空間の一巡を要する）のみ
//! - [`HostNetns::verify_process`] は pid 再利用による TOCTOU が残る。呼び出し側は自分の子 pid に限って使う。
//!   `pid` は本プロセスから見える `/proc` の PID namespace での番号として解釈する
//! - エラーメッセージは固定の英語文で、パスや inode の中身を含めない

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// 1 回の列挙で受け付けるスレッド数の上限（`scan_until_stable`）。
///
/// tid（`u32`）を列挙ごとに `Vec` へ集めて比べるため、確保量を 2 列挙分 × 4 バイト × 上限（512 KiB）に
/// 抑える。想定する対象（exec 直後の子）はこれより桁違いに少なく、超えた場合は `ResourceExhausted`。
const MAX_THREADS: usize = 1 << 16;

/// tid 集合が安定するまでの列挙回数の上限（`scan_until_stable`）。
///
/// 1 回の列挙はスレッド数に比例する stat で済み、列挙の間の待ち（`retry_backoff`）も合計約 27 ms に
/// 収まるため、スレッドの生成・終了が続いても有界に終わる（REPAIR-5）。
const MAX_PASSES: usize = 32;

/// 不一致の後に再列挙するまでの待ちの初期値（`retry_backoff`）。
const RETRY_BACKOFF_INITIAL: Duration = Duration::from_micros(50);

/// 不一致の後に再列挙するまでの待ちの上限（`retry_backoff`）。
const RETRY_BACKOFF_MAX: Duration = Duration::from_millis(1);

/// `retry` 回目（1 始まり）の不一致の後、再列挙までに待つ時間を返す純粋関数。
///
/// 50 µs から倍々に伸ばし 1 ms で頭打ちにする（50・100・200・400・800・1000・1000 …）。待たずに
/// 再列挙すると、スレッドの生成・終了が短時間に集中する間（終了処理の残り・スレッドプールの入れ替え）に
/// 列挙回数の上限を使い切って `FailedPrecondition` になりやすいため、揺れが収まる時間を与える。
/// 最初の 2 回の列挙の間は待たない（想定する呼び出し元〔exec 直後の子〕は 2 回で一致する）。
fn retry_backoff(retry: usize) -> Duration {
    let shift = u32::try_from(retry.saturating_sub(1)).unwrap_or(u32::MAX);
    RETRY_BACKOFF_INITIAL
        .checked_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .map_or(RETRY_BACKOFF_MAX, |d| d.min(RETRY_BACKOFF_MAX))
}

/// `/proc/<pid>/task/` を 1 回列挙し、各スレッドの (tid, netns 識別子) を返すイテレータを作る。
///
/// プロセス自体が無ければ `NotFound`。列挙中に終了したスレッド・終了処理中のスレッドは識別子を
/// `None` にして tid は残す（`skip_exited_thread`。tid 集合の安定判定に含めるため）。数値でない
/// エントリは procfs の想定外の形として `Internal`（fail-closed）。1 回の列挙は生存スレッドを取りこぼし
/// 得る（モジュール doc）ため、判定には `scan_until_stable` を通す。件数の上限は呼び出し側が検証する。
fn task_netns_ids(
    pid: u32,
) -> Result<impl Iterator<Item = Result<(u32, Option<NsId>), NetError>>, NetError> {
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let entries = fs::read_dir(&task_dir)
        .map_err(|e| proc_error(&e, "failed to read thread list in /proc"))?;
    Ok(entries.map(move |entry| task_netns_id(&task_dir, entry)))
}

/// `task_netns_ids` の 1 エントリ分。終了中・終了済みスレッドは識別子が `None`。
fn task_netns_id(
    task_dir: &Path,
    entry: io::Result<fs::DirEntry>,
) -> Result<(u32, Option<NsId>), NetError> {
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
        Ok(id) => Ok((tid, Some(id))),
        Err(e) => skip_exited_thread(&e, || fs::symlink_metadata(&thread_dir).map(|_| ()))
            .map(|()| (tid, None)),
    }
}

/// スレッドの ns link の stat 失敗を「終了中・終了済みとして飛ばす（`Ok(())`）」か「エラー」かに分ける。
///
/// NET-6・TASK-143.1 の全スレッド照合（[`HostNetns::verify_process`]）の列挙（`task_netns_id`）から呼ばれる。`dir_probe` は
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
/// 飛ばしたスレッドも tid は列挙に残し、tid 集合の安定判定に含める。全スレッドが飛ばされた場合
/// （全スレッドが終了中のプロセス・`CONFIG_NET_NS` の無いカーネル）は、`verify_process` が生存スレッド
/// 0 件として `NotFound` を返す（fail-closed）。
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

/// `scan_until_stable` の結果。
#[derive(Debug, PartialEq, Eq)]
enum TaskScan {
    /// どれかの列挙で `host` と異なる netns のスレッドを見つけた（列挙順で最初のもの）。
    Other(NsId),
    /// tid 集合が 2 回連続で一致し、その 2 回の列挙で観測した識別子はすべて `host`。
    Stable {
        /// 一致した tid 集合（昇順・重複なし）。
        tids: Vec<u32>,
        /// 後（直近）の列挙で ns link を stat できた（生存中の）スレッドがあったか。前の列挙で生存して
        /// いても、直近で全スレッドが終了中なら `false`（生存スレッド無しとして fail-closed にする）。
        live: bool,
    },
}

/// 列挙 `enumerate` を tid 集合が 2 回連続で一致するまで繰り返し、全スレッドの netns を `host` と照合する
/// （NET-6・TASK-143.1）。列挙と待ち（`pause`）を差し替えられる純粋関数で、副作用は引数経由のみ。
///
/// `verify_process` が `task_netns_ids` と `std::thread::sleep` を渡して呼ぶ。不一致の後は
/// `retry_backoff` の時間だけ `pause` してから再列挙する。1 回の procfs 列挙は並行するスレッド終了で生存
/// スレッドを取りこぼし得るが、2 回連続の一致は前の列挙に取りこぼしが無かったことを示す（モジュール
/// doc の契約）。判定は次のとおり。
/// - どの列挙でも、識別子が `host` と異なるエントリを見た時点で `Other`（列挙の途中でも打ち切る）
/// - 列挙またはエントリの `Err` は再試行せずそのまま返す（権限不足・プロセス消失を隠さない）
/// - 1 回の列挙が `MAX_THREADS` 件を超えたら `ResourceExhausted`（確保量の上限。coding-rust）
/// - `MAX_PASSES` 回列挙しても一致しなければ `FailedPrecondition`。スレッドの生成・終了が続いて
///   「現在の状態では判定できない」ことを表し、時間を置いた再試行で解消し得る点が `FailedPrecondition`
///   （EBUSY 相当。`netns` でも対象の状態が操作を妨げる場合に使う）の分類に合う。期限切れではないため
///   `Timeout` は使わない。`Member` とは扱わない（fail-closed）
fn scan_until_stable<I>(
    host: NsId,
    mut enumerate: impl FnMut() -> Result<I, NetError>,
    mut pause: impl FnMut(Duration),
) -> Result<TaskScan, NetError>
where
    I: IntoIterator<Item = Result<(u32, Option<NsId>), NetError>>,
{
    let mut prev: Option<Vec<u32>> = None;
    for pass in 0..MAX_PASSES {
        // pass 回目の列挙の前には pass - 1 回の不一致が起きている。
        if pass >= 2 {
            pause(retry_backoff(pass - 1));
        }
        let mut tids: Vec<u32> = Vec::new();
        let mut live = false;
        for entry in enumerate()? {
            let (tid, id) = entry?;
            if let Some(id) = id {
                if id != host {
                    return Ok(TaskScan::Other(id));
                }
                live = true;
            }
            if tids.len() >= MAX_THREADS {
                return Err(NetError::new(
                    NetErrorCode::ResourceExhausted,
                    "process has too many threads to verify",
                ));
            }
            tids.push(tid);
        }
        tids.sort_unstable();
        // procfs は同じ tid を 2 度返さない想定だが、比較を集合として扱うため防御的に重複を除く。
        tids.dedup();
        // 生存の有無は直近の列挙で判定する（前の列挙の生存は、その後に全スレッドが終了中になり得るため
        // 根拠にしない）。
        match prev {
            Some(prev_tids) if prev_tids == tids => return Ok(TaskScan::Stable { tids, live }),
            _ => prev = Some(tids),
        }
    }
    Err(NetError::new(
        NetErrorCode::FailedPrecondition,
        "thread list of process did not stabilize",
    ))
}

/// `scan_until_stable` の結果を `verify_process` の判定に写す純粋関数。
///
/// 生存スレッドを 1 つも観測できなかった安定結果は、判定根拠が無いため `NotFound`（fail-closed）。
fn membership_from_scan(scan: TaskScan) -> Result<HostNetnsMembership, NetError> {
    match scan {
        TaskScan::Other(observed) => Ok(HostNetnsMembership::Other { observed }),
        TaskScan::Stable { live: true, .. } => Ok(HostNetnsMembership::Member),
        TaskScan::Stable { live: false, .. } => Err(NetError::new(
            NetErrorCode::NotFound,
            "process has no live threads",
        )),
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
    /// `/proc/<pid>/task/` の全スレッドを、tid 集合が 2 回連続で一致するまで列挙し直して照合する
    /// （並行するスレッド終了による列挙の取りこぼしを塞ぐ。モジュール doc）。不一致の間は列挙の間に
    /// 短い待ち（合計で最大約 27 ms。`retry_backoff`）を挟むため、呼び出しスレッドをその分ブロックし得る。
    /// どの列挙でも 1 つでも別 netns なら `Other`（最初の不一致）。生存スレッドが 0 件なら `NotFound`、
    /// 一致しないまま列挙回数の上限に達したら `FailedPrecondition`、スレッド数が上限を超えたら
    /// `ResourceExhausted`（いずれも fail-closed）。列挙時点のスナップショットで、以後のスレッド生成・`setns(2)` は対象外。
    /// `pid` は 1..=`i32::MAX` のみ。pid 再利用の TOCTOU は残る（モジュール doc）。
    pub fn verify_process(&self, pid: u32) -> Result<HostNetnsMembership, NetError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "pid is out of range",
            ));
        }
        membership_from_scan(scan_until_stable(
            self.id,
            || task_netns_ids(pid),
            std::thread::sleep,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自プロセスでスレッドを大量に生成・終了させるテストと、自プロセスを列挙・照合するテストを直列化する
    /// ロック。取りこぼしは `scan_until_stable` の再列挙で塞がれるが、スレッドの生成・終了が続く間は
    /// tid 集合が一致しないまま列挙回数の上限に達し、契約どおり FAILED_PRECONDITION（fail-closed）になる。
    /// 別テストの都合で自プロセスが揺れて偽の失敗にならないよう、同じプロセス内で並列に走らせない。
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
        let _churn = lock_thread_churn();
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

    /// 毎回同じ列挙 `pass` を返す差し替え用の列挙で `scan_until_stable` を呼び、結果と列挙回数を返す。
    /// 列挙が変わらないため再列挙の待ちは起きない（起きたら失敗させる）。
    fn scan_fixed(
        host: NsId,
        pass: &[Result<(u32, Option<NsId>), NetError>],
    ) -> (Result<TaskScan, NetError>, usize) {
        let mut calls = 0usize;
        let scan = scan_until_stable(
            host,
            || {
                calls += 1;
                Ok::<_, NetError>(pass.to_vec())
            },
            |d| panic!("unexpected pause {d:?}"),
        );
        (scan, calls)
    }

    /// NET-6: 全スレッド一致のみ Member。1 つでも異なれば最初の不一致を Other、生存スレッド 0 件は
    /// NOT_FOUND、エントリのエラーはそのまま返す（片方のスレッドだけ別 netns のプロセスを Member と
    /// 誤判定しない）。列挙が変わらなければ 2 回目で一致して止まる。
    #[test]
    fn net6_scan_until_stable_all_threads() {
        let h = NsId::new(4, 100);
        let o = NsId::new(4, 200);
        let p = NsId::new(4, 300);
        let (scan, calls) = scan_fixed(h, &[Ok((10, Some(h))), Ok((11, Some(h)))]);
        assert_eq!(
            scan.unwrap(),
            TaskScan::Stable {
                tids: vec![10, 11],
                live: true
            }
        );
        assert_eq!(calls, 2);
        for (pass, observed) in [
            (vec![Ok((10, Some(h))), Ok((11, Some(o)))], o),
            (vec![Ok((10, Some(o))), Ok((11, Some(h)))], o),
            (
                vec![Ok((10, Some(h))), Ok((11, Some(p))), Ok((12, Some(o)))],
                p,
            ),
        ] {
            let (scan, calls) = scan_fixed(h, &pass);
            assert_eq!(scan.unwrap(), TaskScan::Other(observed), "{pass:?}");
            assert_eq!(calls, 1, "{pass:?}");
        }
        let (scan, calls) = scan_fixed(h, &[]);
        let scan = scan.unwrap();
        assert_eq!(
            scan,
            TaskScan::Stable {
                tids: vec![],
                live: false
            }
        );
        assert_eq!(calls, 2);
        let e = membership_from_scan(scan).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.message(), "process has no live threads");
        let (scan, calls) = scan_fixed(
            h,
            &[
                Ok((10, Some(h))),
                Err(NetError::new(NetErrorCode::PermissionDenied, "denied")),
            ],
        );
        assert_eq!(scan.unwrap_err().code(), NetErrorCode::PermissionDenied);
        assert_eq!(calls, 1);
    }

    /// NET-6: `scan_until_stable` の結果の写像。Other はそのまま、生存スレッドありの安定結果は Member、
    /// 無しは NOT_FOUND（fail-closed）。
    #[test]
    fn net6_membership_from_scan() {
        let o = NsId::new(4, 200);
        assert_eq!(
            membership_from_scan(TaskScan::Other(o)).unwrap(),
            HostNetnsMembership::Other { observed: o }
        );
        assert_eq!(
            membership_from_scan(TaskScan::Stable {
                tids: vec![10],
                live: true
            })
            .unwrap(),
            HostNetnsMembership::Member
        );
        let e = membership_from_scan(TaskScan::Stable {
            tids: vec![10],
            live: false,
        })
        .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
    }

    /// 差し替え用の列挙 `pass`（0 始まりの列挙回数から 1 回分の列挙を返す）で `scan_until_stable` を
    /// 呼び、結果・列挙回数・再列挙前の待ちの記録を返す（実際には待たない）。
    fn scan_scripted(
        host: NsId,
        pass: impl Fn(usize) -> Result<Vec<Result<(u32, Option<NsId>), NetError>>, NetError>,
    ) -> (Result<TaskScan, NetError>, usize, Vec<Duration>) {
        let mut calls = 0usize;
        let mut pauses = Vec::new();
        let scan = scan_until_stable(
            host,
            || {
                let r = pass(calls);
                calls += 1;
                r
            },
            |d| pauses.push(d),
        );
        (scan, calls, pauses)
    }

    /// NET-6: 再列挙前の待ちは 50 µs から倍々に伸び、1 ms で頭打ち（極端な回数でも溢れない）。
    #[test]
    fn net6_retry_backoff_schedule() {
        let us = Duration::from_micros;
        assert_eq!(retry_backoff(1), us(50));
        assert_eq!(retry_backoff(2), us(100));
        assert_eq!(retry_backoff(3), us(200));
        assert_eq!(retry_backoff(4), us(400));
        assert_eq!(retry_backoff(5), us(800));
        assert_eq!(retry_backoff(6), us(1000));
        assert_eq!(retry_backoff(30), us(1000));
        assert_eq!(retry_backoff(33), us(1000));
        assert_eq!(retry_backoff(usize::MAX), us(1000));
    }

    /// NET-6: tid 集合が前回と異なる間は再列挙し、2 回連続で一致した時点で止まる（取りこぼしのある
    /// 列挙で判定しない）。並び順の違いは同じ集合として扱う。
    #[test]
    fn net6_scan_until_stable_reenumerates_until_tids_match() {
        let h = NsId::new(4, 100);
        // 1 回目 {10,11,12}・2 回目 {10,11}（12 が終了）・3 回目 {10,11} で一致する。
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h))), Ok((11, Some(h))), Ok((12, Some(h)))],
                _ => vec![Ok((10, Some(h))), Ok((11, Some(h)))],
            })
        });
        assert_eq!(
            scan.unwrap(),
            TaskScan::Stable {
                tids: vec![10, 11],
                live: true
            }
        );
        assert_eq!(calls, 3);
        assert_eq!(pauses, vec![Duration::from_micros(50)]);
        // 1 回目で 11 を取りこぼし（{10,12}）、2 回目は {10,11,12}、3 回目で一致する。
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h))), Ok((12, Some(h)))],
                _ => vec![Ok((10, Some(h))), Ok((11, Some(h))), Ok((12, Some(h)))],
            })
        });
        assert_eq!(
            scan.unwrap(),
            TaskScan::Stable {
                tids: vec![10, 11, 12],
                live: true
            }
        );
        assert_eq!(calls, 3);
        assert_eq!(pauses, vec![Duration::from_micros(50)]);
        // 並び順だけが違う列挙は同じ集合として 2 回目で一致する。
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(if n % 2 == 0 {
                vec![Ok((11, Some(h))), Ok((10, Some(h)))]
            } else {
                vec![Ok((10, Some(h))), Ok((11, Some(h)))]
            })
        });
        assert_eq!(
            scan.unwrap(),
            TaskScan::Stable {
                tids: vec![10, 11],
                live: true
            }
        );
        assert_eq!(calls, 2);
        assert_eq!(pauses, Vec::<Duration>::new());
    }

    /// NET-6: tid 集合が毎回変わり続けると、`MAX_PASSES`（32）回で打ち切って判定不能の
    /// FAILED_PRECONDITION を返す（Member と扱わない。有界に終わる。REPAIR-5）。
    #[test]
    fn net6_scan_until_stable_gives_up_after_max_passes() {
        let h = NsId::new(4, 100);
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            let churn = if n % 2 == 0 { 11 } else { 12 };
            Ok(vec![Ok((10, Some(h))), Ok((churn, Some(h)))])
        });
        let e = scan.unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.code().as_str(), "FAILED_PRECONDITION");
        assert_eq!(e.message(), "thread list of process did not stabilize");
        assert_eq!(MAX_PASSES, 32);
        assert_eq!(calls, 32);
        // 3 回目以降の各列挙の前に 1 回ずつ（30 回）待ち、合計は 26.55 ms で有界。
        let expected: Vec<Duration> = (1..=30).map(retry_backoff).collect();
        assert_eq!(pauses, expected);
        assert_eq!(
            pauses.iter().sum::<Duration>(),
            Duration::from_micros(26_550)
        );
    }

    /// NET-6: 別 netns のスレッドは何回目の列挙で見えても即 Other（以後の列挙・同じ列挙の残りを読まない）。
    #[test]
    fn net6_scan_until_stable_detects_other_in_any_pass() {
        let h = NsId::new(4, 100);
        let o = NsId::new(4, 200);
        // 1 回目で 11 を取りこぼし、2 回目で別 netns の 11 が見える。
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h)))],
                _ => vec![Ok((10, Some(h))), Ok((11, Some(o)))],
            })
        });
        assert_eq!(scan.unwrap(), TaskScan::Other(o));
        assert_eq!(calls, 2);
        assert_eq!(pauses, Vec::<Duration>::new());
        // 1 回目で見えた後のエントリ（エラー）は読まない。
        let (scan, calls, pauses) = scan_scripted(h, |_| {
            Ok(vec![
                Ok((10, Some(o))),
                Err(NetError::new(NetErrorCode::Internal, "unreachable")),
            ])
        });
        assert_eq!(scan.unwrap(), TaskScan::Other(o));
        assert_eq!(calls, 1);
        assert_eq!(pauses, Vec::<Duration>::new());
    }

    /// NET-6: 終了中スレッド（識別子 None）も tid 集合に含めて比べる。生存中だった tid が終了中に
    /// 変わっても集合は同じで、生存の有無は直近の列挙で決まる（直近で全スレッドが終了中なら live でなく、
    /// verify_process は NOT_FOUND。前の列挙の生存を根拠に Member としない）。
    #[test]
    fn net6_scan_until_stable_counts_exiting_threads() {
        let h = NsId::new(4, 100);
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h))), Ok((11, None))],
                _ => vec![Ok((10, None)), Ok((11, None))],
            })
        });
        let scan = scan.unwrap();
        assert_eq!(
            scan,
            TaskScan::Stable {
                tids: vec![10, 11],
                live: false
            }
        );
        assert_eq!(calls, 2);
        assert_eq!(pauses, Vec::<Duration>::new());
        let e = membership_from_scan(scan).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.message(), "process has no live threads");
        // 終了中の 11 が一覧から外れると集合が変わるため再列挙する。
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h))), Ok((11, None))],
                _ => vec![Ok((10, Some(h)))],
            })
        });
        assert_eq!(
            scan.unwrap(),
            TaskScan::Stable {
                tids: vec![10],
                live: true
            }
        );
        assert_eq!(calls, 3);
        assert_eq!(pauses, vec![Duration::from_micros(50)]);
    }

    /// NET-6: 2 回目以降の列挙・エントリのエラーは再試行せずそのまま返す（プロセス消失・権限不足を隠さない）。
    #[test]
    fn net6_scan_until_stable_propagates_errors_in_later_pass() {
        let h = NsId::new(4, 100);
        let (scan, calls, pauses) = scan_scripted(h, |n| match n {
            0 => Ok(vec![Ok((10, Some(h))), Ok((11, Some(h)))]),
            _ => Err(NetError::new(NetErrorCode::NotFound, "gone")),
        });
        assert_eq!(scan.unwrap_err().code(), NetErrorCode::NotFound);
        assert_eq!(calls, 2);
        assert_eq!(pauses, Vec::<Duration>::new());
        let (scan, calls, pauses) = scan_scripted(h, |n| {
            Ok(match n {
                0 => vec![Ok((10, Some(h)))],
                _ => vec![
                    Ok((10, Some(h))),
                    Err(NetError::new(NetErrorCode::PermissionDenied, "denied")),
                ],
            })
        });
        assert_eq!(scan.unwrap_err().code(), NetErrorCode::PermissionDenied);
        assert_eq!(calls, 2);
        assert_eq!(pauses, Vec::<Duration>::new());
    }

    /// NET-6: 1 回の列挙の件数は `MAX_THREADS`（65536）件まで受け付け、超えたら確保前に
    /// RESOURCE_EXHAUSTED を返す（再列挙しない）。
    #[test]
    fn net6_scan_until_stable_limits_thread_count() {
        let h = NsId::new(4, 100);
        assert_eq!(MAX_THREADS, 65_536);
        let limit = u32::try_from(MAX_THREADS).unwrap();
        let mut calls = 0usize;
        let scan = scan_until_stable(
            h,
            || {
                calls += 1;
                Ok::<_, NetError>((0..limit).map(|t| Ok((t, Some(h)))))
            },
            |d| panic!("unexpected pause {d:?}"),
        );
        let TaskScan::Stable { tids, live } = scan.unwrap() else {
            panic!("all threads are in the host network namespace");
        };
        assert_eq!(
            (tids.len(), tids.first(), tids.last()),
            (MAX_THREADS, Some(&0), Some(&(limit - 1)))
        );
        assert!(live);
        assert_eq!(calls, 2);
        let mut calls = 0usize;
        let scan = scan_until_stable(
            h,
            || {
                calls += 1;
                Ok::<_, NetError>((0..=limit).map(|t| Ok((t, Some(h)))))
            },
            |d| panic!("unexpected pause {d:?}"),
        );
        let e = scan.unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "process has too many threads to verify");
        assert_eq!(calls, 1);
    }

    /// NET-6: 複数スレッドの自プロセスでは、起こしたスレッドの tid とリーダーが `scan_until_stable` の
    /// 安定した tid 集合にすべて含まれ、全スレッドが自スレッドと同じ netns で、verify_process は Member。
    ///
    /// libtest の他のワーカースレッドが並行して終了すると 1 回の procfs 列挙は生存スレッドを取りこぼし
    /// 得るが（モジュール doc の契約）、`scan_until_stable` が tid 集合の一致まで再列挙するため、テスト側では
    /// 再列挙しない（ライブラリの保証をそのまま検証する）。`Err` は即座に失敗させる（終了中スレッドの
    /// 誤エラーの回帰を隠さない）。
    #[test]
    fn net6_task_netns_ids_enumerates_all_threads() {
        const N: usize = 3;
        let _churn = lock_thread_churn();
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let pid = std::process::id();
        let barrier = std::sync::Barrier::new(N + 1);
        // 各スレッドは tid の取得に失敗しても必ず barrier に到達し、main も検証より先に barrier を
        // 抜けるため、失敗時にテストがハングしない（REPAIR-5）。
        let (tids, scan, membership) = std::thread::scope(|s| {
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
            let scan = scan_until_stable(own, || task_netns_ids(pid), std::thread::sleep);
            let membership = HostNetns { id: own }.verify_process(pid);
            barrier.wait();
            (tids, scan, membership)
        });
        assert_eq!(tids.len(), N);
        let TaskScan::Stable { tids: listed, live } = scan.unwrap() else {
            panic!("own threads must all be in the own network namespace");
        };
        assert!(live, "live threads must be observed");
        for tid in tids {
            let tid = tid.expect("thread tid from /proc/thread-self");
            assert!(
                listed.binary_search(&tid).is_ok(),
                "tid {tid} in {listed:?}"
            );
        }
        assert!(
            listed.binary_search(&pid).is_ok(),
            "leader {pid} in {listed:?}"
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
    /// ns link が ENOENT になる（終了処理中スレッドと同じ状態を決定的に作る）。そのスレッドは識別子
    /// 無し（tid は安定判定のため残す）で列挙され、生存スレッド 0 件として verify_process は「生存
    /// スレッド無し」の NOT_FOUND（fail-closed）を返す。
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
        let listed: Result<Vec<(u32, Option<NsId>)>, NetError> =
            task_netns_ids(pid).and_then(|it| it.collect());
        let own = stat_ns(Path::new("/proc/thread-self/ns/net")).unwrap();
        let membership = HostNetns { id: own }.verify_process(pid);
        // 失敗時もゾンビを残さないよう、検証より先に回収する。
        let status = child.wait().expect("reap `true`");

        assert_eq!(state, Some('Z'));
        assert!(task_dir_present, "zombie thread directory must remain");
        assert_eq!(listed.unwrap(), vec![(pid, None)]);
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
    /// 終了するスレッドで tid 集合が揺れても、`scan_until_stable` が一致するまで再列挙するため Member の
    /// まま（列挙の先頭は常に生存中のスレッドグループリーダー〔libtest のメインスレッド〕で、生存スレッド
    /// が 1 件以上見える）。
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
