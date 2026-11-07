//! exec の pty（擬似端末）の割り当て・resize・master の受け渡し（SUP-6・SEC-1・CRI-6・TASK-63.2・#3758）。
//!
//! # 役割・呼び出し文脈
//! CRI の Exec（`tty=true`）で、コンテナ内のコマンドへ slave を制御端末として付け、master を呼び出し側
//! （最終的には helper 経由で plugin-cri。#3759〜#3761）へ返すための型と手順を持つ。`unsafe` は持たず、
//! `crate::sys` の薄いラッパー（`open_rdwr_noctty_at`・`pty_unlock_and_index`・`set_window_size` 等）だけを使う。
//!
//! - [`ExecReady::allocate_pty`](super::ExecReady::allocate_pty)（`reapply.rs`）が、コマンドと同じ権利
//!   （capability 削減・NNP・Landlock・seccomp の再適用の **後**）で、照合済みの `/` の fd 起点にコンテナの
//!   devpts から `(PtyMaster, PtySlave)` を割り当てる。本モジュールの [`allocate_in_root`] が本体
//! - [`ChildStdio::from_pty_slave`](super::ChildStdio::from_pty_slave)（`process.rs`）が slave を fd 0〜2 と
//!   制御端末（`setsid` + `TIOCSCTTY`）に結ぶ
//! - [`ExecPtySender`]・[`ExecPtyReceiver`] が master を worker から親へ `SCM_RIGHTS` で渡す
//!   （[`spawn_exec_worker_with_listener_and_pty`](super::spawn_exec_worker_with_listener_and_pty)）
//!
//! # SEC-1 の契約
//! - pty はコンテナの devpts（独立した instance）からだけ割り当てる。ホストの devpts の pty・ホストの端末 fd は
//!   コンテナへ渡さない。本番の公開 API にホストの devpts で開く口を作らない（試験用の
//!   `open_host_pty_for_test` は `exec-test-support` feature の下だけ）
//! - コマンドが持つのは slave だけで、slave の fd から辿れるのは同じ pty だけ（`/proc/self/fd/0` の開き直しも
//!   同じ slave）。master はコマンドの fork 前に worker が親へ送って閉じるため、コマンドとその子孫は master を
//!   持たない
//! - 割り当てはコマンドと同じ権利（再適用の後）で行い、launch より広げない。fd はすべて `O_CLOEXEC`・
//!   `O_NOCTTY`（制御端末にするのは `TIOCSCTTY` だけ）。パスは 1 要素ずつ `O_NOFOLLOW` で辿り（`/dev/ptmx` の
//!   symlink は辿らない）、devpts の magic・文字デバイスの `rdev`・`st_dev` で検証する
//! - master の受け取り側は種別（5:2）と master であること（`TIOCGPTN` の成功。受け取り済みの master の unlock は冪等）を検証し、不一致は fd を閉じて
//!   拒否する（[`PtyMaster::from_received`]）
//! - `TIOCSTI` で入力を注入できるのは、コンテナ自身の pty の入力キューだけ（ホストの端末は届かない。
//!   `legacy_tiocsti` の前提 (2)(3) は維持される）
//!
//! # 未実装（REPAIR-3）
//! supervisor の `ExecStdio` への tty の追加と、受けた master を helper の channel へ返す結線は #3760・#3761、
//! plugin-cri の resize の転送は #3761 で実装済み、実コンテナ（Landlock・seccomp の下）での実機確認は #3762、
//! 完全版 Attach の init の pty は #3765 の範囲で、本モジュールは行わない。

use std::ffi::CStr;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::time::Instant;

use crate::exec::{ContainerChild, ExecError, IsolationStage};
use crate::sys;
use crate::traits::types::ErrorCode;

/// `/dev/ptmx` の文字デバイス番号（major 5・minor 2。devpts の `ptmx` ノードも同じ）。
const PTMX_MAJOR: u32 = 5;
const PTMX_MINOR: u32 = 2;
/// UNIX98 pty の slave の major（`UNIX98_PTY_SLAVE_MAJOR`）。index は繰り上げず minor にそのまま入れる。
const SLAVE_MAJOR: u32 = 136;
/// slave の index の上限（排他的。カーネルの minor は 20 bit で `NR_UNIX98_PTY_MAX` は `1 << 20`）。
const SLAVE_INDEX_LIMIT: u32 = 1 << 20;
/// 割り当てを受けた master を運ぶ 1 通の本文（seccomp listener の `L`・失敗通知の `E` と区別する）。
pub(crate) const TOKEN_PTY_MASTER: u8 = b'P';
/// 割り当ての段（`pts` の devpts の検証・`ptmx` と slave の open・unlock・サイズ設定）。
const STAGE: IsolationStage = IsolationStage::Exec;

/// 端末サイズ（行・列）。ピクセル寸法は常に 0（CRI の ResizeEvent に無い）。
///
/// CRI の ResizeEvent の `uint16` に合わせた型で、`TIOCSWINSZ` へそのまま渡せる。0 行・0 列も表現できる
/// （カーネルは 0 を受け付ける。呼び出し側が意味のない値を弾くかは #3761 で決める）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    rows: u16,
    cols: u16,
}

impl WindowSize {
    /// 行・列から作る。
    #[must_use]
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }

    /// 行数。
    #[must_use]
    pub const fn rows(self) -> u16 {
        self.rows
    }

    /// 列数。
    #[must_use]
    pub const fn cols(self) -> u16 {
        self.cols
    }
}

/// pty の master 側（呼び出し側が入出力と resize に使う）。
///
/// 構築できるのは [`ExecReady::allocate_pty`](super::ExecReady::allocate_pty) の結果、別プロセスから受け取った
/// fd の検証（[`PtyMaster::from_received`]）、試験用の入口だけ。fd は `O_CLOEXEC`。
#[derive(Debug)]
pub struct PtyMaster(OwnedFd);

impl PtyMaster {
    /// 端末サイズを `TIOCSWINSZ` で設定する（resize）。slave 側のフォアグラウンドのプロセスグループへ
    /// `SIGWINCH` が届く。失敗は段 `Exec` の `ExecError`。
    pub fn resize(&self, size: WindowSize) -> Result<(), ExecError> {
        sys::set_window_size(self.0.as_fd(), size.rows, size.cols)
            .map_err(|e| ExecError::from_sys(e, STAGE, "ioctl(TIOCSWINSZ)"))
    }

    /// 現在の端末サイズを `TIOCGWINSZ` で読む。
    pub fn window_size(&self) -> Result<WindowSize, ExecError> {
        sys::window_size(self.0.as_fd())
            .map(|(rows, cols)| WindowSize::new(rows, cols))
            .map_err(|e| ExecError::from_sys(e, STAGE, "ioctl(TIOCGWINSZ)"))
    }

    /// fd の借用。
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// 所有権を fd として取り出す（helper の channel へ `SCM_RIGHTS` で渡す等）。
    #[must_use]
    pub fn into_owned_fd(self) -> OwnedFd {
        self.0
    }

    /// 別プロセスから受け取った fd を master として検証して包む。
    ///
    /// 文字デバイス `5:2`（`ptmx`）であり、かつ `TIOCGPTN` が成功する（slave の fd では `ENOTTY`）ことを
    /// 確かめる。不一致は `InvalidArgument` で拒否し、fd は drop で閉じる（fail-closed。SEC-1）。
    pub fn from_received(fd: OwnedFd) -> Result<Self, ExecError> {
        let meta = fstat(fd.as_fd(), "fstat(received pty master)")?;
        if !meta.file_type().is_char_device() || meta.rdev() != sys::makedev(PTMX_MAJOR, PTMX_MINOR)
        {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                STAGE,
                "the received fd is not a pty master",
            ));
        }
        sys::pty_unlock_and_index(fd.as_fd()).map_err(|_| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                STAGE,
                "the received fd is not a pty master",
            )
        })?;
        Ok(Self(fd))
    }
}

/// pty の slave 側（コマンドの標準入出力と制御端末になる）。
///
/// 公開コンストラクタを持たず、[`ExecReady::allocate_pty`](super::ExecReady::allocate_pty) の結果と試験用の入口
/// だけから得る。fd は `O_CLOEXEC`・`O_NOCTTY`。
#[derive(Debug)]
pub struct PtySlave(OwnedFd);

impl PtySlave {
    /// 端末サイズを読む（試験と診断用）。
    pub fn window_size(&self) -> Result<WindowSize, ExecError> {
        sys::window_size(self.0.as_fd())
            .map(|(rows, cols)| WindowSize::new(rows, cols))
            .map_err(|e| ExecError::from_sys(e, STAGE, "ioctl(TIOCGWINSZ)"))
    }

    /// fd の複製（`ChildStdio::from_pty_slave` が fd 0〜2 の 3 本を作る）。
    pub(crate) fn try_clone_fd(&self) -> Result<OwnedFd, ExecError> {
        self.0.try_clone().map_err(|e| {
            ExecError::from_io(&e, IsolationStage::Spawn, "dup(pty slave for exec stdio)")
        })
    }
}

fn fstat(fd: BorrowedFd<'_>, what: &str) -> Result<std::fs::Metadata, ExecError> {
    let dup = fd
        .try_clone_to_owned()
        .map_err(|e| ExecError::from_io(&e, STAGE, what))?;
    std::fs::File::from(dup)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, what))
}

fn precondition(message: &'static str) -> ExecError {
    ExecError::new(ErrorCode::FailedPrecondition, STAGE, message)
}

/// 照合済みの `/`（`root`）起点に、コンテナの devpts から pty を割り当てる（本体。手順は doc 冒頭の契約）。
///
/// 1. `dev` → `pts` を 1 要素ずつ `O_PATH|O_NOFOLLOW|O_DIRECTORY` で辿る（symlink は辿らない）
/// 2. `pts` が devpts（`DEVPTS_MAGIC`）であることを確かめる
/// 3. `pts/ptmx` を開き、文字デバイス `5:2` かつ `pts` と同じ `st_dev` であることを確かめる
/// 4. unlock して番号 N を得る（`TIOCSPTLCK`・`TIOCGPTN`）
/// 5. `pts/N` を開き、文字デバイスで `st_dev` が `pts` と同じ・`rdev` が N の UNIX98 slave の番号と一致することを確かめる
/// 6. master に初期サイズを設定する
///
/// 途中で失敗したら開いた fd はすべて drop で閉じる。`TIOCGPTPEER` は `may_open`（デバイス cgroup）を通らない
/// ため使わず、パスで開く（`sys::pty_unlock_and_index` の方針と同じ）。
pub(crate) fn allocate_in_root(
    root: BorrowedFd<'_>,
    size: WindowSize,
) -> Result<(PtyMaster, PtySlave), ExecError> {
    let open_dir = |parent: BorrowedFd<'_>, name: &CStr, what: &str| {
        sys::open_dir_path_nofollow(Some(parent), name)
            .map_err(|e| ExecError::from_sys(e, STAGE, what))
    };
    let dev = open_dir(root, c"dev", "openat(/dev)")?;
    let pts = open_dir(dev.as_fd(), c"pts", "openat(/dev/pts)")?;
    if sys::fs_type(pts.as_fd()).map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(/dev/pts)"))?
        != sys::DEVPTS_MAGIC
    {
        return Err(precondition("the container /dev/pts is not a devpts mount"));
    }
    let pts_dev = fstat(pts.as_fd(), "fstat(/dev/pts)")?.dev();

    let master = sys::open_rdwr_noctty_at(pts.as_fd(), c"ptmx")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/dev/pts/ptmx)"))?;
    let meta = fstat(master.as_fd(), "fstat(/dev/pts/ptmx)")?;
    if !meta.file_type().is_char_device()
        || meta.rdev() != sys::makedev(PTMX_MAJOR, PTMX_MINOR)
        || meta.dev() != pts_dev
    {
        return Err(precondition(
            "the container /dev/pts/ptmx is not the devpts ptmx node",
        ));
    }
    let index = sys::pty_unlock_and_index(master.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "unlock the pty slave"))?;
    let name = std::ffi::CString::new(index.to_string())
        .map_err(|_| ExecError::new(ErrorCode::Internal, STAGE, "invalid pty slave index"))?;
    let slave = sys::open_rdwr_noctty_at(pts.as_fd(), &name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/dev/pts/N)"))?;
    let meta = fstat(slave.as_fd(), "fstat(/dev/pts/N)")?;
    let expected = slave_rdev(index)
        .ok_or_else(|| precondition("the pty slave index is out of the UNIX98 range"))?;
    if !meta.file_type().is_char_device() || meta.rdev() != expected || meta.dev() != pts_dev {
        return Err(precondition(
            "the container /dev/pts/N is not the pty slave of the allocated master",
        ));
    }
    let master = PtyMaster(master);
    master.resize(size)?;
    Ok((master, PtySlave(slave)))
}

/// UNIX98 slave の番号 `index` のデバイス番号（major 136・minor は index そのまま）。範囲外は `None`。
fn slave_rdev(index: u32) -> Option<u64> {
    (index < SLAVE_INDEX_LIMIT).then(|| sys::makedev(SLAVE_MAJOR, index))
}

/// 試験専用: ホストの `/dev/ptmx`（devtmpfs）から pty を割り当てる。コンテナの devpts ではないため本番では使わない。
///
/// ホストの devpts の `pts/ptmx` は通常 mode 000 で非 root は開けないため、`/dev/ptmx` を使う。`slave` は
/// `/dev/pts/N` を開いて `rdev` を検証する。`exec-test-support` feature の下だけに存在する。
#[cfg(any(test, feature = "exec-test-support"))]
#[doc(hidden)]
pub fn open_host_pty_for_test(size: WindowSize) -> Result<(PtyMaster, PtySlave), ExecError> {
    let dev = sys::open_dir_path_nofollow(None, c"/dev")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/dev)"))?;
    // ホストによっては `/dev/ptmx` が `pts/ptmx` への symlink のため、試験専用の入口では symlink を辿って開き、
    // 開いた実体が文字デバイス `5:2` であることを fstat で検証する（本番の `allocate_in_root` は `O_NOFOLLOW`
    // のまま。#3758）。
    let master: OwnedFd = {
        use std::os::unix::fs::OpenOptionsExt as _;
        // `O_NOCTTY`（Linux の x86_64・aarch64 とも 0o400）で制御端末を取得しない。`O_CLOEXEC` は std が付ける。
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0o400)
            .open("/dev/ptmx")
            .map_err(|e| {
                ExecError::new(
                    ErrorCode::Internal,
                    STAGE,
                    format!("open(/dev/ptmx) failed: {e}"),
                )
            })?;
        OwnedFd::from(file)
    };
    let meta = fstat(master.as_fd(), "fstat(/dev/ptmx)")?;
    if !meta.file_type().is_char_device() || meta.rdev() != sys::makedev(PTMX_MAJOR, PTMX_MINOR) {
        return Err(precondition("the host /dev/ptmx is not the ptmx node"));
    }
    let index = sys::pty_unlock_and_index(master.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "unlock the pty slave"))?;
    let pts = sys::open_dir_path_nofollow(Some(dev.as_fd()), c"pts")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/dev/pts)"))?;
    let name = std::ffi::CString::new(index.to_string())
        .map_err(|_| ExecError::new(ErrorCode::Internal, STAGE, "invalid pty slave index"))?;
    let slave = sys::open_rdwr_noctty_at(pts.as_fd(), &name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/dev/pts/N)"))?;
    let master = PtyMaster(master);
    master.resize(size)?;
    Ok((master, PtySlave(slave)))
}

/// worker 側の master の送信口（[`spawn_exec_worker_with_listener_and_pty`](super::spawn_exec_worker_with_listener_and_pty)
/// が worker へ渡す）。構築できるのは core だけで、`Clone` を持たない。
#[derive(Debug)]
pub struct ExecPtySender(OwnedFd);

impl ExecPtySender {
    pub(crate) fn new(child_end: OwnedFd) -> Self {
        Self(child_end)
    }

    /// `master` を親へ送り、手元の master を閉じる（ACK は待たない。`SOCK_SEQPACKET` の送信は buffer に積まれるだけで
    /// 相互待ちにならない）。コマンドの fork より **前** に呼ぶこと（コマンドの子へ master を継承させない。SEC-1）。
    pub fn hand_over(self, master: PtyMaster) -> Result<(), ExecError> {
        sys::seccomp_notify::send_fd_with_token(self.0.as_fd(), TOKEN_PTY_MASTER, master.0.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "send of the pty master"))?;
        drop(master);
        Ok(())
    }

    /// 試験専用: pty の master ではない fd（`/dev/null` 等）を送る（受信側の拒否の照合）。
    #[cfg(feature = "exec-test-support")]
    #[doc(hidden)]
    pub fn hand_over_non_pty_for_test(self, fd: BorrowedFd<'_>) -> Result<(), ExecError> {
        sys::seccomp_notify::send_fd_with_token(self.0.as_fd(), TOKEN_PTY_MASTER, fd)
            .map_err(|e| ExecError::from_sys(e, STAGE, "send of the pty master"))
    }
}

/// 親側の master の受信口。worker の fork の前に作った socketpair の親の端を所有する。
#[derive(Debug)]
pub struct ExecPtyReceiver(OwnedFd);

/// [`ExecPtyReceiver::receive`] の結果。
#[derive(Debug)]
#[non_exhaustive]
pub enum PtyReceipt {
    /// 検証済みの master を受け取った。
    Received(PtyMaster),
    /// 何も届かないまま worker 側が閉じた（tty を割り当てる前に worker が終わった通常の経路）。
    SenderClosed,
    /// 検証の不一致・切り詰め・送信元の不一致・fd 本数の不一致・master でない fd。受け取った fd はすべて閉じた。
    Rejected(ExecError),
    /// 期限までに届かなかった（`Timeout`）。
    TimedOut(ExecError),
}

impl ExecPtyReceiver {
    pub(crate) fn new(parent_end: OwnedFd) -> Self {
        Self(parent_end)
    }

    /// 親の端の fd 番号（worker が継承した複製を閉じるために使う）。
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }

    /// master を期限つきで受信・検証する（REPAIR-5）。`worker` は送信元の pid の照合に使う。
    ///
    /// 検証: 切り詰めなし・本文がちょうど `TOKEN_PTY_MASTER` の 1 バイト・fd がちょうど 1 本・
    /// `SCM_CREDENTIALS` の pid が worker・close-on-exec・[`PtyMaster::from_received`]。呼び出し順の契約:
    /// 親は seccomp listener を受けた後、worker の終了を待つ **前** に呼ぶ。
    pub fn receive(self, worker: &ContainerChild, deadline: Instant) -> PtyReceipt {
        use crate::exec::seccomp_listener::wait_readable;
        let fail = |code, message: &'static str| {
            PtyReceipt::Rejected(ExecError::new(code, STAGE, message))
        };
        loop {
            match wait_readable(self.0.as_fd(), deadline) {
                Ok(true) => {}
                Ok(false) => {
                    return PtyReceipt::TimedOut(ExecError::new(
                        ErrorCode::Timeout,
                        STAGE,
                        "the pty master was not delivered in time",
                    ));
                }
                Err(e) => {
                    return PtyReceipt::Rejected(ExecError::from_sys(
                        e,
                        STAGE,
                        "wait for the pty master",
                    ));
                }
            }
            match sys::seccomp_notify::recv_fd_with_creds(self.0.as_fd()) {
                Err(sys::SysError::Os(e)) if e == sys::EAGAIN => {}
                Err(e) => {
                    return PtyReceipt::Rejected(ExecError::from_sys(
                        e,
                        STAGE,
                        "receive of the pty master",
                    ));
                }
                Ok(received) => return classify(received, worker.pid(), fail),
            }
        }
    }
}

/// 受信した 1 通の分類（受け取った fd は不採用なら drop で閉じる）。
fn classify(
    received: sys::seccomp_notify::ReceivedFd,
    expected_pid: u32,
    fail: impl Fn(ErrorCode, &'static str) -> PtyReceipt,
) -> PtyReceipt {
    let sys::seccomp_notify::ReceivedFd {
        payload,
        mut fds,
        creds,
        truncated,
    } = received;
    if payload.is_empty() && fds.is_empty() {
        return PtyReceipt::SenderClosed;
    }
    if truncated {
        return fail(ErrorCode::Internal, "the pty message was truncated");
    }
    if payload.as_slice() != [TOKEN_PTY_MASTER] {
        return fail(
            ErrorCode::Internal,
            "the pty message had an unexpected payload",
        );
    }
    if fds.len() != 1 {
        return fail(
            ErrorCode::Internal,
            "the pty message did not carry exactly one fd",
        );
    }
    let Some(creds) = creds else {
        return fail(
            ErrorCode::Internal,
            "the pty message carried no sender credentials",
        );
    };
    if u32::try_from(creds.pid).ok() != Some(expected_pid) {
        return fail(
            ErrorCode::Internal,
            "the pty message came from an unexpected process",
        );
    }
    let Some(fd) = fds.pop() else {
        return fail(
            ErrorCode::Internal,
            "the pty message did not carry exactly one fd",
        );
    };
    match sys::seccomp_notify::fd_is_cloexec(fd.as_fd()) {
        Ok(true) => {}
        _ => {
            return fail(
                ErrorCode::Internal,
                "the received pty master is not close-on-exec",
            );
        }
    }
    match PtyMaster::from_received(fd) {
        Ok(master) => PtyReceipt::Received(master),
        Err(e) => PtyReceipt::Rejected(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-6・SEC-1（#3758）: UNIX98 slave の番号は major 136 固定・minor は index そのままで、範囲外は拒否する。
    #[test]
    fn sup6_3758_slave_rdev_follows_unix98_numbering() {
        assert_eq!(slave_rdev(0), Some(sys::makedev(136, 0)));
        assert_eq!(slave_rdev(255), Some(sys::makedev(136, 255)));
        assert_eq!(slave_rdev(256), Some(sys::makedev(136, 256)));
        assert_eq!(slave_rdev(2048), Some(sys::makedev(136, 2048)));
        assert_eq!(
            slave_rdev((1 << 20) - 1),
            Some(sys::makedev(136, (1 << 20) - 1))
        );
        assert_eq!(slave_rdev(1 << 20), None);
    }

    /// SEC-1（#3758）: master でない fd（通常ファイル・`/dev/null`）は `from_received` が `InvalidArgument` で拒否する。
    #[test]
    fn sec1_3758_from_received_rejects_non_master() {
        for path in ["/proc/self/status", "/dev/null"] {
            let fd = OwnedFd::from(std::fs::File::open(path).unwrap());
            let err = PtyMaster::from_received(fd).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{path}");
        }
    }

    /// SEC-1（#3758）: devpts でないディレクトリを根にした割り当ては `FailedPrecondition` で拒否する。
    #[test]
    fn sec1_3758_allocate_in_root_rejects_non_devpts_pts() {
        let dir = std::env::temp_dir().join(format!("fandhe-pty-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dev/pts")).unwrap();
        let root = sys::open_dir_path_nofollow(
            None,
            &std::ffi::CString::new(dir.to_str().unwrap()).unwrap(),
        )
        .unwrap();
        let result = allocate_in_root(root.as_fd(), WindowSize::new(24, 80));
        let _ = std::fs::remove_dir_all(&dir);
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// SEC-1（#3758）: `dev` が無い根は `NotFound` 系の失敗になり、割り当てない。
    #[test]
    fn sec1_3758_allocate_in_root_without_dev_fails() {
        let dir = std::env::temp_dir().join(format!("fandhe-pty-nodev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = sys::open_dir_path_nofollow(
            None,
            &std::ffi::CString::new(dir.to_str().unwrap()).unwrap(),
        )
        .unwrap();
        let result = allocate_in_root(root.as_fd(), WindowSize::new(24, 80));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err());
    }

    /// SUP-6（#3758）: `WindowSize` の getter。
    #[test]
    fn sup6_3758_window_size_getters() {
        let s = WindowSize::new(37, 91);
        assert_eq!((s.rows(), s.cols()), (37, 91));
    }
}
