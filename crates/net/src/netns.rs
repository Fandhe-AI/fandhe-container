//! コンテナ用 network namespace の作成と pin（TASK-139.2.1・#847・NET-1・MS-8）。
//!
//! `crate::network::attach_container` が「veth の peer 側を入れる netns」を用意するための下請けで、
//! PoC-15 `netsetup` の `netns-create` に相当する。後続の runtime が名前（pin パス）でこの netns へ
//! join でき、ネットワーク削除（TASK-139.4）が同じパスから解放できるよう、netns をファイルへ
//! bind マウントして固定（pin）する。`ip netns add` と同じ方式。
//!
//! # 方式
//!
//! 呼び出しスレッドの netns は変えない。専用の使い捨て OS スレッドを 1 本起こし、そのスレッドだけが
//! `unshare(CLONE_NEWNET)` → `/proc/thread-self/ns/net` を open → pin 先ファイルへ bind マウント、を行って
//! 終了する。`CLONE_NEWNET` は `CLONE_NEWUSER` と違いマルチスレッドのプロセスでも合法で、影響は
//! 呼び出したスレッドだけに閉じる。元の netns へ戻る必要が生じないので `setns` は使わない。
//! 同じスレッドで、その netns に束縛された `NETLINK_ROUTE` ソケットの fd も開いて返す（netlink ソケットは
//! 作成時の netns に束縛されるため、コンテナ netns の中の address / route を操作する手段はこれだけ。
//! `setns` を使わないので `unsafe` も増えない。TASK-139.3・#316）。bind 以降は呼び出し側スレッドが行う。
//! 結果（ns ファイルの fd とソケット fd）は `Mutex` + `Condvar` の受け渡し口で返し、待ちは期限つき（REPAIR-5）。
//! 期限切れ後に完了したスレッドは、自分で pin のアンマウントとファイル削除を行って回収する
//! （受け渡し口が `Abandoned` に切り替わっていることを完了時にロック下で確認する）。
//!
//! # 安全性の設計（P0。パストラバーサル・symlink・マウント伝播）
//!
//! - pin 先は「呼び出し側が渡す絶対パスのディレクトリ」直下の、検証済み `EndpointId`（`/` を含まず
//!   `.` 始まりでない）をファイル名にした通常ファイル。`Path::join` のみで組み立てる
//! - ディレクトリは symlink でない・group / other に書き込み不可・実効 UID の所有、のすべてを満たさない
//!   場合は拒否する（fail-closed）。検査したディレクトリは開いた fd で固定し、pin ファイルの作成・伝播検査・
//!   後始末は `/proc/self/fd/<dirfd>/<名前>` 経由で同じ実体に対して行う（検査後に祖先のパスが差し替えられても、
//!   検査していない場所には作用しない）。ディレクトリより上位の経路の検証は呼び出し側の責務
//! - pin 先ファイルは `create_new`（`O_EXCL`）で作る。既存物（他者のファイル・symlink）は上書きも
//!   削除もしない。bind マウントの対象は、作成直後に保持した fd の `/proc/self/fd/<n>` で指定し、
//!   作成から mount までの間のパス差し替えを塞ぐ
//! - fd は `O_CLOEXEC`（std 既定）で、コンテナプロセスへ漏れない
//!
//! - 置き場ディレクトリを含むマウントの伝播が `shared` なら拒否する（fail-closed）。`shared` のまま
//!   bind マウントすると peer の mount namespace へ pin が伝播し、unpin 後も別 namespace が保持して
//!   netns が生き残りうるため。呼び出し側は置き場を private（または slave）なマウントにしておく
//!   （例: `mount --bind DIR DIR && mount --make-private DIR`）。`ip netns add` のように置き場を
//!   `MS_SHARED` の自己 bind にする処理は行わない。判定は `/proc/self/mountinfo` から行い、
//!   判定できなければ拒否する
//! - 解除（`unpin`）が失敗したら `ContainerNetns` を呼び出し側へ返す（再試行可能）
//! - 解除（`unpin_path`）は、本プロセスが作成して未解除の pin（プロセス内の所有記録 `PINS` と照合できる
//!   もの）だけを対象にする。記録の無いファイル・マウントは形が pin と同じでも削除・アンマウントしない
//!   （fail-closed）。作成プロセスの終了後・再起動後の残置 pin の清掃は、永続的な所有記録と照合する設計
//!   （TASK-139.4）で扱い、それまでは本 API からは解除できない
//!
//! # 権限
//!
//! `unshare(CLONE_NEWNET)` と `mount` / `umount2` に `CAP_SYS_ADMIN` が必要。本 crate は権限を上げない。

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
use crate::instrument::NetOpRecorder;
use crate::netlink_route::{NetlinkRouteSocket, classify_errno};
use crate::network::{EndpointId, NetnsFailure, ResourceState, UnpinFailure};
use crate::sys::{self, SysError};

/// `ns` ファイルの絶対パス。`unshare` したスレッド自身の netns を指す。
const THREAD_NS_PATH: &CStr = c"/proc/thread-self/ns/net";

/// pin 済みのコンテナ用 netns。
///
/// `fd` を保持している間と pin のマウントが残っている間、netns は生き続ける。`fd` は
/// `LinkSet::move_to_netns`（`IFLA_NET_NS_FD`）の移動先指定に使う。解放は
/// `crate::network` のロールバック、または将来のネットワーク削除（TASK-139.4）が `unpin` で行う。
#[derive(Debug)]
pub struct ContainerNetns {
    fd: OwnedFd,
    pin: PathBuf,
    /// この netns に束縛された route ソケット。接続処理の終わりに [`release_route_socket`]
    /// で閉じる（コンテナごとに fd を常駐させない。CORE-9）。
    route: Option<NetlinkRouteSocket>,
}

impl ContainerNetns {
    /// netns を指す ns ファイルの fd（借用）。
    pub fn fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.fd.as_fd()
    }

    /// pin 先のパス（runtime が join に使う）。
    pub fn pin_path(&self) -> &Path {
        &self.pin
    }

    /// netns の中で動く route ソケット（接続処理の途中だけ存在する）。解放済みなら `None`。
    pub(crate) fn route_socket(&self) -> Option<&NetlinkRouteSocket> {
        self.route.as_ref()
    }

    /// route ソケットを閉じる（接続処理の成功時に呼ぶ。pin と ns の fd は保持したまま）。
    pub(crate) fn release_route_socket(&mut self) {
        self.route = None;
    }
}

fn sys_error(call: &str, e: SysError) -> NetError {
    match e {
        SysError::Os(errno) => NetError::new(
            classify_errno(errno),
            format!("{call} failed: errno {errno}"),
        ),
        SysError::Unsupported => NetError::new(
            NetErrorCode::Unimplemented,
            format!("{call}: unsupported architecture"),
        ),
        SysError::BadSenderAddress | SysError::BadLocalAddress => {
            NetError::new(NetErrorCode::Internal, format!("{call}: unexpected error"))
        }
    }
}

fn io_error(call: &str, e: &io::Error) -> NetError {
    match e.raw_os_error() {
        Some(errno) => NetError::new(
            classify_errno(errno),
            format!("{call} failed: errno {errno}"),
        ),
        None => NetError::new(NetErrorCode::Internal, format!("{call} failed")),
    }
}

/// netns 置き場ディレクトリの属性検査（OS 呼び出しを含まない純粋関数。単体テスト用に分離）。
///
/// - `is_dir`: `symlink_metadata` の結果がディレクトリ（symlink はディレクトリ扱いにならない）
/// - `mode`: `st_mode`。group / other 書き込み可なら拒否
/// - `owner` / `euid`: 所有者が実効 UID でなければ拒否
fn check_base_dir_attrs(is_dir: bool, mode: u32, owner: u32, euid: u32) -> Result<(), NetError> {
    if !is_dir {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must be a real directory (not a symlink)",
        ));
    }
    if mode & 0o022 != 0 {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must not be group or other writable",
        ));
    }
    if owner != euid {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must be owned by the effective user",
        ));
    }
    Ok(())
}

fn check_base_dir(base: &Path) -> Result<(), NetError> {
    if !base.is_absolute() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns directory must be an absolute path",
        ));
    }
    let meta = fs::symlink_metadata(base).map_err(|e| io_error("stat netns directory", &e))?;
    check_base_dir_attrs(
        meta.file_type().is_dir(),
        meta.mode(),
        meta.uid(),
        sys::effective_uid(),
    )
}

/// 使い捨てスレッドの本体。`unshare` → ns を open → 保持中の fd 経由で pin 先へ bind マウント。
/// bind マウントが最後の副作用なので、`Err` のときは pin のマウントは作られていない。
fn unshare_and_pin(target: &CStr) -> Result<(OwnedFd, FileId, OwnedFd), NetError> {
    // 影響は当スレッドの netns だけ。このスレッドは戻り値を返したら終了する。
    sys::unshare_net().map_err(|e| sys_error("unshare", e))?;
    // 新 netns に束縛された route ソケットを、bind マウント（最後の副作用）より前に開く。
    // 失敗しても pin のマウントは作られていない。
    let sock = sys::open_route_socket().map_err(|e| sys_error("socket", e))?;
    let ns = File::open("/proc/thread-self/ns/net").map_err(|e| io_error("open thread ns", &e))?;
    // pin のマウント越しに見える inode は netns 自身のものになる。所有証明用に控える（`PINS`）。
    let ns_id = ns
        .metadata()
        .map(|m| file_id(&m))
        .map_err(|e| io_error("stat thread ns", &e))?;
    sys::bind_mount(THREAD_NS_PATH, target).map_err(|e| sys_error("mount", e))?;
    Ok((OwnedFd::from(ns), ns_id, sock))
}

/// `/proc/self/mountinfo` の `mountpoint` 欄（8 進エスケープ `\040` 等）を元のバイト列へ戻す。
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'\\'
            && let Some(oct) = b.get(i + 1..i + 4)
            && oct.iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let v = oct
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `mountinfo` の内容から `dir`（正規化済みの絶対パス）を含むマウントを探し、その伝播が `shared` なら
/// 拒否する（OS 呼び出しを含まない純粋関数。単体テスト用に分離）。最長一致のマウントポイントを採り、
/// 同長なら後の行（重ねマウントの最上位）を採る。見つからなければ拒否する（fail-closed）。
fn check_propagation(mountinfo: &str, dir: &Path) -> Result<(), NetError> {
    let target = dir.as_os_str().as_bytes();
    let mut best: Option<(usize, bool)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let Some(mp_field) = fields.get(4) else {
            continue;
        };
        let mp = unescape_mountinfo(mp_field);
        let contains = target == mp.as_slice()
            || mp == b"/"
            || (target.starts_with(&mp) && target.get(mp.len()) == Some(&b'/'));
        if !contains {
            continue;
        }
        let shared = fields
            .iter()
            .skip(6)
            .take_while(|f| **f != "-")
            .any(|f| f.starts_with("shared:"));
        if best.is_none_or(|(len, _)| mp.len() >= len) {
            best = Some((mp.len(), shared));
        }
    }
    match best {
        Some((_, false)) => Ok(()),
        Some((_, true)) => Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must not be on a shared mount (make it private first)",
        )),
        None => Err(NetError::new(
            NetErrorCode::Internal,
            "mount of netns directory not found in mountinfo",
        )),
    }
}

/// 固定済みの置き場ディレクトリ（`PinDir::real`。開いた fd から得た実際の位置）の伝播を検査する。
fn check_dir_propagation(dir: &PinDir) -> Result<(), NetError> {
    let raw = fs::read("/proc/self/mountinfo").map_err(|e| io_error("read mountinfo", &e))?;
    check_propagation(&String::from_utf8_lossy(&raw), &dir.real)
}

/// 作った pin ファイルを消す（消せたら `PINS` の記録も外す）。失敗は `Present`（残っていると分かる）で報告する。
///
/// 削除の直前にパスの実体が作成時の `fid` であることを照合し、別の実体へ差し替わっていれば消さない
/// （`Unknown`。作成した pin の所在が分からないため）。記録の無いものを消さない点は `unpin_path` と同じ。
fn remove_pin_file(pin: &Path, fid: FileId) -> Option<ResourceState> {
    match fs::symlink_metadata(pin) {
        Ok(m) if file_id(&m) == fid => {}
        Ok(_) => return Some(ResourceState::Unknown),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            forget_pin(fid);
            return None;
        }
        Err(_) => return Some(ResourceState::Present),
    }
    match fs::remove_file(pin) {
        Ok(()) => {
            forget_pin(fid);
            None
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            forget_pin(fid);
            None
        }
        Err(_) => Some(ResourceState::Present),
    }
}

/// `base` 直下に `id` 名の pin を作り、新しい netns をそこへ固定する。
///
/// 成功時は `ContainerNetns`（fd と pin パス）を返す。失敗時は自分が作ったファイルだけを片付け、
/// 時間切れ等で mount の有無が不明なら削除せず `leftover = Some(Unknown)` で報告する。`timeout` は
/// 使い捨てスレッドの完了待ちの期限（REPAIR-5）。時間切れ後もスレッドは裏で完走しうる。
///
/// 置き場ディレクトリは検査時に開いた fd で固定し（[`open_pin_dir`]）、pin ファイルの作成・伝播検査・
/// 失敗時や時間切れ後の後始末はすべて `/proc/self/fd/<dirfd>/<名前>` 経由で同じ実体に対して行う。
/// 検査後に `base` やその祖先が差し替えられても、検査していない場所に pin を作ったり消したりしない。
pub(crate) fn create_pinned(
    base: &Path,
    id: &EndpointId,
    timeout: Duration,
    recorder: &Arc<dyn NetOpRecorder>,
) -> Result<ContainerNetns, NetnsFailure> {
    let fail = |error: NetError, leftover: Option<ResourceState>| NetnsFailure { error, leftover };
    let dir = Arc::new(open_pin_dir(base).map_err(|e| fail(e, None))?);
    let name = std::ffi::OsStr::new(id.as_str());
    // 呼び出し側へ返す pin パス（runtime の join・`unpin_path` に使う名前）。
    let pin = base.join(name);
    // 本関数内の操作に使う、固定したディレクトリ経由のパス。
    let via = dir.entry(name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&via)
        .map_err(|e| fail(io_error("create netns pin file", &e), None))?;
    // 作成した実体の識別子を記録する。`unpin_path` が「本モジュールが作った pin」だけを対象にする根拠で、
    // 以降の失敗時の削除（`remove_pin_file`）も、この識別子と一致する実体だけを消す。
    let fid = match file.metadata() {
        Ok(m) => file_id(&m),
        Err(e) => {
            // 識別子を取れないので照合つきの削除ができない。消さずに残置として報告する（fail-closed）。
            return Err(fail(
                io_error("stat netns pin file", &e),
                Some(ResourceState::Present),
            ));
        }
    };
    register_pin(fid);
    // 作成時の mode は umask で削られうる（例: umask 0777 → 0000）。`check_pin_file_attrs` が要求する
    // 厳密な 0o400 にするため、保持した fd（fchmod）で明示設定する。パスは再解決しない。
    if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o400)) {
        return Err(fail(
            io_error("chmod netns pin file", &e),
            remove_pin_file(&via, fid),
        ));
    }
    let target = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| {
        fail(
            NetError::new(NetErrorCode::Internal, "invalid pin target"),
            remove_pin_file(&via, fid),
        )
    })?;

    // 伝播検査は pin ファイルの作成後に行う（既存物への `AlreadyExists` を先に返すため）。
    // 拒否したら自分が作ったファイルだけ消す。
    if let Err(e) = check_dir_propagation(&dir) {
        return Err(fail(e, remove_pin_file(&via, fid)));
    }
    let via_c = CString::new(via.as_os_str().as_bytes()).map_err(|_| {
        fail(
            NetError::new(NetErrorCode::InvalidArgument, "netns path contains NUL"),
            remove_pin_file(&via, fid),
        )
    })?;

    let handoff: Arc<Handoff> = Arc::new((Mutex::new(Slot::Pending), Condvar::new()));
    let worker_handoff = Arc::clone(&handoff);
    let worker_via = via.clone();
    // ワーカーが後始末を担う間も `/proc/self/fd/<dirfd>` を有効に保つ。
    let worker_dir = Arc::clone(&dir);
    // 時間切れ後もワーカーが完走するまで `unpin_path` を拒否させる（unlink との競合防止）。
    let inflight = InflightGuard::new(fid);
    let spawned = thread::Builder::new()
        .name("fandhe-netns".to_owned())
        .spawn(move || {
            // `file` を握ったまま mount することで、`/proc/self/fd/<n>` が差し替え不能な対象を指す。
            let _hold = file;
            let _dir = worker_dir;
            let inflight = inflight;
            let result = unshare_and_pin(&target).map(|(fd, ns_id, sock)| {
                set_pin_ns(fid, ns_id);
                (fd, sock)
            });
            let (lock, cv) = &*worker_handoff;
            let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*slot, Slot::Abandoned) {
                // 呼び出し側は期限切れで見切り済み。完了した副作用はこのスレッドが回収する。
                drop(slot);
                reclaim_abandoned(&via_c, &worker_via, fid, result.is_ok());
                drop(inflight);
            } else {
                drop(inflight);
                *slot = Slot::Done(result);
                cv.notify_one();
            }
        });
    if spawned.is_err() {
        return Err(fail(
            NetError::new(
                NetErrorCode::ResourceExhausted,
                "failed to spawn netns thread",
            ),
            remove_pin_file(&via, fid),
        ));
    }

    let (lock, cv) = &*handoff;
    let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut guard, _) = cv
        .wait_timeout_while(guard, timeout, |s| matches!(s, Slot::Pending))
        .unwrap_or_else(PoisonError::into_inner);
    // 未完了なら、ロックを握ったまま `Abandoned` にして回収をスレッドへ引き継ぐ（完了との競合を防ぐ）。
    match std::mem::replace(&mut *guard, Slot::Abandoned) {
        Slot::Done(Ok((fd, sock))) => {
            // bind 以降は呼び出し側スレッドで行う（bind は socket 作成時の netns を引き継ぐ）。
            match NetlinkRouteSocket::from_unbound_route_fd(sock, Arc::clone(recorder)) {
                Ok(route) => Ok(ContainerNetns {
                    fd,
                    pin,
                    route: Some(route),
                }),
                Err(error) => {
                    // pin は mount 済み。ハンドルを作れないので、ここで pin を解除して片付ける。
                    drop(fd);
                    drop(guard);
                    let leftover = match unpin_path(&pin) {
                        Ok(()) => None,
                        Err(_) => Some(ResourceState::Present),
                    };
                    Err(fail(error, leftover))
                }
            }
        }
        Slot::Done(Err(error)) => Err(fail(error, remove_pin_file(&via, fid))),
        Slot::Pending => Err(fail(
            NetError::new(NetErrorCode::Timeout, "timed out creating netns"),
            Some(ResourceState::Unknown),
        )),
        Slot::Abandoned => Err(fail(
            NetError::new(NetErrorCode::Internal, "netns handoff in unexpected state"),
            Some(ResourceState::Unknown),
        )),
    }
}

/// 使い捨てスレッドから呼び出し側への結果の受け渡し状態。
enum Slot {
    /// スレッドが未完了。
    Pending,
    /// スレッドが完了し、結果を置いた。
    Done(Result<(OwnedFd, OwnedFd), NetError>),
    /// 呼び出し側が期限切れで見切った。以後の後始末は完了時のスレッドが担う。
    Abandoned,
}

type Handoff = (Mutex<Slot>, Condvar);

/// 見切られた後に完了したスレッドが、自分の副作用を戻す。`mounted` なら pin をアンマウントし、
/// アンマウントできた（またはマウントが無かった）場合だけ自分が `create_new` で作った pin ファイルを
/// 削除する。アンマウントに失敗したら pin ファイルを残す（呼び出し側へ報告済みの pin パスから
/// `unpin_path` で再試行できるようにするため。ファイルを消すとマウントが名前を失ってリークする）。
/// 失敗しても報告先は無い（時間切れ時点で `Unknown` を返済み）。
///
/// `via_c` / `via` は固定した置き場ディレクトリ経由のパス（`/proc/self/fd/<dirfd>/<名前>`）。呼び出し側の
/// ワーカーがディレクトリの fd を保持している間だけ有効。
fn reclaim_abandoned(via_c: &CStr, via: &Path, fid: FileId, mounted: bool) {
    if mounted && sys::unmount_detach(via_c).is_err() {
        return;
    }
    let _ = remove_pin_file(via, fid);
}

/// pin を外す（`umount2(MNT_DETACH)` → ファイル削除）。fd を drop し参照が尽きれば、カーネルが
/// netns と中に残った peer veth を破棄する。ロールバックと、将来のネットワーク削除（TASK-139.4）が共用する。
///
/// 失敗時は `ns`（fd と pin パス）を [`UnpinFailure`] に入れて返し、呼び出し側が再試行できる。
/// 再試行しても、アンマウント済みやファイル削除済みの途中状態から続行できる。検証は [`unpin_path`] と同じ。
pub(crate) fn unpin(ns: ContainerNetns) -> Result<(), UnpinFailure<ContainerNetns>> {
    match unpin_path(&ns.pin) {
        Ok(()) => Ok(()),
        Err(error) => Err(UnpinFailure { error, netns: ns }),
    }
}

/// pin パスだけから netns の pin を解除する（`ContainerNetns` を手放した後の再試行用）。
///
/// ロールバックで `unpin` が失敗するとハンドルは破棄され、マウントとファイルだけが残る。接続失敗の
/// 報告（`AttachRollbackReport::leftover`）に載った pin パスを、同じプロセス内でここへ渡すと、アンマウントと
/// ファイル削除をやり直せる（所有記録は解除に成功するまで残る）。すでに消えている（`ENOENT`）場合は
/// 成功扱い（冪等）。
///
/// 任意ファイルの削除・他者の pin の解除を防ぐため（P0）、次のすべてを満たす pin だけを対象にする（fail-closed）。
/// - 絶対パスで、親ディレクトリが置き場の検証（symlink でない・group / other 書き込み不可・実効 UID 所有）に通る。
///   親ディレクトリは開いた fd で固定し、以降の操作は `/proc/self/fd/<dirfd>/<名前>` 経由で行う
///   （検査後に親のパスが差し替えられても、検査した同じディレクトリに対してだけ作用する）
/// - 本プロセスの `create_pinned` が作って未解除の pin であること。作成時に控えた「pin ファイルの (dev, ino)」
///   （未マウント時）または「固定した netns の (dev, ino)」（nsfs マウント中）に現在の実体が一致すること
///   （操作の直前に stat し直して照合）。記録が無い pin（作成プロセスの終了後・再起動後の残置）は、
///   マウントの有無に関わらず umount・削除の前に `FailedPrecondition` で拒否する。形（mode `0o400`・
///   サイズ 0・実効 UID 所有の通常ファイル）だけでは本モジュールが作った pin と証明できず、任意の空ファイルの
///   削除や同一 UID の別プロセスの netns の破棄につながるため。プロセスをまたぐ清掃は、永続的な所有記録と
///   照合する設計（TASK-139.4）で扱う
/// - `/proc/self/mountinfo` 上で、pin がマウントされていないか、`nsfs` としてマウントされている
/// - アンマウント後の実体が、作成時の pin ファイル（上記 inode）かつ本モジュールが作った形
///   （実効 UID 所有・mode `0o400`・サイズ 0 の通常ファイル）
/// - `create_pinned` の時間切れ後も裏で動作中のワーカーが居る pin ではない（ワーカーが完了するまで
///   `FailedPrecondition` で拒否する。unlink が先行すると、ワーカーが unlink 済み inode へ bind マウントして
///   名前の無い netns マウントがリークするため。完了後に再試行すれば、回収済みか解除できる）
///
/// 残る隙間: 親ディレクトリ内の最終要素の差し替えは、同ディレクトリへ書ける実効 UID 本人（検証で他者の
/// 書き込みは排除済み）にしかできず、stat から umount / unlink までの数命令の間に限られる。
pub fn unpin_path(pin: &Path) -> Result<(), NetError> {
    if !pin.is_absolute() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns pin path must be absolute",
        ));
    }
    let (Some(parent), Some(name)) = (pin.parent(), pin.file_name()) else {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns pin path must name a file",
        ));
    };
    match fs::symlink_metadata(pin) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error("stat netns pin", &e)),
    }
    let dir = open_pin_dir(parent)?;
    let via = dir.entry(name);
    let real = dir.real.join(name);
    let euid = sys::effective_uid();

    let current = match fs::symlink_metadata(&via) {
        Ok(m) if m.file_type().is_file() => file_id(&m),
        Ok(_) => {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "netns pin path is not a regular file",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error("stat netns pin", &e)),
    };
    // 本プロセスの記録（所有の証明）を引く。nsfs マウントの解除は記録がある場合に限る（下記）。
    let record = lookup_pin(current);
    // 動作中ワーカーの pin は、どの経路のパスで指定されても実体（作成時の識別子）で判定して拒否する。
    if inflight_contains(current) || record.is_some_and(|r| inflight_contains(r.file)) {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns pin creation is still in progress; retry later",
        ));
    }
    let raw = fs::read("/proc/self/mountinfo").map_err(|e| io_error("read mountinfo", &e))?;
    // アンマウント後に現れるべき pin ファイルの識別子。
    let expected_file: Option<FileId> = match pin_mount_state(&String::from_utf8_lossy(&raw), &real)
    {
        PinMount::None => {
            // 記録の無いファイルは、形（実効 UID 所有・0o400・空）が pin と同じでも削除しない（fail-closed）。
            // 形だけでは本モジュールが作った pin と証明できず、呼び出し側が指定した任意の空ファイルを
            // 消しうるため。記録が netns 側（`r.ns`）とだけ一致する場合（マウントが無いのに nsfs の inode が
            // 見える）も、作成した状態ではないので拒否する。
            let Some(r) = record else {
                return Err(not_our_pin());
            };
            if r.file != current {
                return Err(not_our_pin());
            }
            Some(current)
        }
        PinMount::Nsfs => {
            // 所有を証明できない nsfs マウントは umount 前に拒否する（fail-closed）。umount すると
            // 後続の検査で拒否しても名前空間は既に切り離されており、同一 UID の別プロセスの pin を
            // 破棄しうる。作成プロセス終了後の清掃は永続状態による所有照合（TASK-139.4）で行う。
            let Some(r) = record else {
                return Err(not_our_pin());
            };
            if Some(current) != r.ns {
                return Err(not_our_pin());
            }
            let c_via = CString::new(via.as_os_str().as_bytes()).map_err(|_| {
                NetError::new(NetErrorCode::InvalidArgument, "netns path contains NUL")
            })?;
            // 直前に再照合する（stat からの間に別の実体へ差し替わっていれば解除しない）。
            match fs::symlink_metadata(&via) {
                Ok(m) if file_id(&m) == current => {}
                Ok(_) => return Err(not_our_pin()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    forget_pin(r.file);
                    return Ok(());
                }
                Err(e) => return Err(io_error("stat netns pin", &e)),
            }
            match sys::unmount_detach(&c_via) {
                Ok(()) => {}
                // 並行して外れた場合。実体の検査は下で行う。
                Err(SysError::Os(e)) if e == sys::EINVAL || e == sys::ENOENT => {}
                Err(e) => return Err(sys_error("umount", e)),
            }
            Some(r.file)
        }
        PinMount::Other => {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "netns pin path is mounted but not as a netns",
            ));
        }
    };
    // アンマウント後の実体が作成時の pin ファイルであることを再検査する（重ねマウントが残っていれば
    // nsfs の inode になり、差し替えられていれば別 inode になり、いずれも拒否される）。
    let final_id = match fs::symlink_metadata(&via) {
        Ok(m) => {
            let id = file_id(&m);
            match expected_file {
                Some(e) if id != e => return Err(not_our_pin()),
                _ => {}
            }
            check_pin_file_attrs(m.file_type().is_file(), m.mode(), m.uid(), m.len(), euid)?;
            id
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(r) = record {
                forget_pin(r.file);
            }
            return Ok(());
        }
        Err(e) => return Err(io_error("stat netns pin", &e)),
    };
    match fs::remove_file(&via) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error("remove netns pin file", &e)),
    }
    if let Some(r) = record {
        forget_pin(r.file);
    }
    forget_pin(final_id);
    Ok(())
}

fn not_our_pin() -> NetError {
    NetError::new(
        NetErrorCode::FailedPrecondition,
        "path is not a netns pin created by this process",
    )
}

/// ファイルの識別子 (st_dev, st_ino)。
type FileId = (u64, u64);

fn file_id(m: &fs::Metadata) -> FileId {
    (m.dev(), m.ino())
}

/// `create_pinned` が作った pin の記録。`file` は pin ファイル自身、`ns` はマウント後に見える netns の識別子。
#[derive(Clone, Copy)]
struct PinRecord {
    file: FileId,
    ns: Option<FileId>,
}

/// 本プロセスが作成して未解除の pin。`unpin_path` が所有の証明に使う（形の検査だけでは足りないため）。
static PINS: Mutex<Vec<PinRecord>> = Mutex::new(Vec::new());

fn register_pin(file: FileId) {
    let mut v = PINS.lock().unwrap_or_else(PoisonError::into_inner);
    v.retain(|r| r.file != file);
    v.push(PinRecord { file, ns: None });
}

fn set_pin_ns(file: FileId, ns: FileId) {
    let mut v = PINS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(r) = v.iter_mut().find(|r| r.file == file) {
        r.ns = Some(ns);
    }
}

fn forget_pin(file: FileId) {
    PINS.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|r| r.file != file);
}

fn lookup_pin(id: FileId) -> Option<PinRecord> {
    PINS.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .find(|r| r.file == id || r.ns == Some(id))
        .copied()
}

/// 開いて固定した pin 置き場ディレクトリ。
struct PinDir {
    /// 開いたままにして `/proc/self/fd/<n>` を有効に保つ。
    file: File,
    /// 開いた時点の正規パス（mountinfo 照合用）。
    real: PathBuf,
}

impl PinDir {
    /// 固定したディレクトリ配下の `name` を指すパス。親のパスが後で差し替えられても同じディレクトリを指す。
    fn entry(&self, name: &std::ffi::OsStr) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd())).join(name)
    }
}

/// 親ディレクトリを検査して開く。パスの検査（symlink でない・書き込み権限・所有者）と、開いた fd の
/// 実体（同じ dev / ino）を突き合わせ、検査と使用の間の差し替えを塞ぐ。
fn open_pin_dir(parent: &Path) -> Result<PinDir, NetError> {
    check_base_dir(parent)?;
    let file = File::open(parent).map_err(|e| io_error("open netns directory", &e))?;
    let opened = file
        .metadata()
        .map_err(|e| io_error("stat netns directory", &e))?;
    let named = fs::symlink_metadata(parent).map_err(|e| io_error("stat netns directory", &e))?;
    if file_id(&opened) != file_id(&named) {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory changed while being opened",
        ));
    }
    check_base_dir_attrs(
        opened.file_type().is_dir(),
        opened.mode(),
        opened.uid(),
        sys::effective_uid(),
    )?;
    let real = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|e| io_error("resolve netns directory", &e))?;
    Ok(PinDir { file, real })
}
/// pin ファイルの実体検査（OS 呼び出しを含まない純粋関数）。`create_pinned` が作る形
/// （通常ファイル・実効 UID 所有・mode `0o400`・空）だけを許す。
fn check_pin_file_attrs(
    is_file: bool,
    mode: u32,
    owner: u32,
    len: u64,
    euid: u32,
) -> Result<(), NetError> {
    if is_file && mode & 0o7777 == 0o400 && owner == euid && len == 0 {
        Ok(())
    } else {
        Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "path is not a netns pin created by this crate",
        ))
    }
}

/// `mountinfo` 上での pin パスのマウント状態。
#[derive(Debug, PartialEq, Eq)]
enum PinMount {
    /// マウントされていない。
    None,
    /// 最上位のマウントが `nsfs`（netns の bind マウント）。
    Nsfs,
    /// 最上位のマウントが `nsfs` 以外。
    Other,
}

/// `mountinfo` から `pin`（正規化済みの絶対パス）をマウントポイントとする最上位（最後の行）のマウントを探す。
fn pin_mount_state(mountinfo: &str, pin: &Path) -> PinMount {
    let target = pin.as_os_str().as_bytes();
    let mut state = PinMount::None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let Some(mp_field) = fields.get(4) else {
            continue;
        };
        if unescape_mountinfo(mp_field) != target {
            continue;
        }
        let fstype = fields
            .iter()
            .position(|f| *f == "-")
            .and_then(|i| fields.get(i + 1));
        state = if fstype == Some(&"nsfs") {
            PinMount::Nsfs
        } else {
            PinMount::Other
        };
    }
    state
}

/// `create_pinned` の使い捨てスレッドが動作中の pin ファイルの識別子 (dev, ino)（時間切れ後も含む）。
/// `unpin_path` が動作中のワーカーと競合して unlink しないよう参照する。パスではなく実体で持つのは、
/// 同じ pin を別の経路のパス（祖先の symlink 等）で指定されても取りこぼさないため。
static INFLIGHT: Mutex<Vec<FileId>> = Mutex::new(Vec::new());

fn inflight_contains(file: FileId) -> bool {
    INFLIGHT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&file)
}

/// 動作中ワーカーの登録。drop で登録を外す（スレッド起動失敗でクロージャが破棄された場合も外れる）。
struct InflightGuard(FileId);

impl InflightGuard {
    fn new(file: FileId) -> Self {
        INFLIGHT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(file);
        Self(file)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut v = INFLIGHT.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = v.iter().position(|p| *p == self.0) {
            v.swap_remove(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_recorder() -> Arc<dyn NetOpRecorder> {
        Arc::new(crate::instrument::NoopNetOpRecorder)
    }

    /// NET-1・TASK-139.2.1: 置き場ディレクトリ検査の具体的な合否。
    #[test]
    fn net1_base_dir_attr_checks() {
        assert!(check_base_dir_attrs(true, 0o040_755, 1000, 1000).is_ok());
        assert!(check_base_dir_attrs(true, 0o040_700, 0, 0).is_ok());
        for (is_dir, mode, owner, what) in [
            (false, 0o040_755, 1000, "not a real directory"),
            (true, 0o040_775, 1000, "group writable"),
            (true, 0o040_757, 1000, "other writable"),
            (true, 0o040_755, 1001, "other owner"),
        ] {
            let e = check_base_dir_attrs(is_dir, mode, owner, 1000).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{what}");
        }
    }

    /// NET-1: `unpin_path` は相対パスを拒否し、存在しない pin は成功（冪等）、ディレクトリは拒否する。
    #[test]
    fn net1_unpin_path_guards_and_idempotence() {
        let e = unpin_path(Path::new("relative/pin")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let missing = std::env::temp_dir().join("fandhe-net-unpin-missing-pin-xyz");
        assert!(unpin_path(&missing).is_ok());
        let e = unpin_path(&std::env::temp_dir()).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-1: 通常ファイル（pin でないもの）は未マウントでも削除しない（P0: 任意ファイル削除の防止）。
    #[test]
    fn net1_unpin_path_keeps_foreign_regular_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("foreign");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let f = dir.join("precious");
        fs::write(&f, b"data").unwrap();
        let e = unpin_path(&f).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(fs::read(&f).unwrap(), b"data");
        // 置き場として不適切（group / other 書き込み可）なディレクトリ配下は、形が pin でも拒否する。
        let pin = dir.join("pinlike");
        fs::write(&pin, b"").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let e = unpin_path(&pin).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(pin.exists());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&f).unwrap();
        fs::remove_file(&pin).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 本 crate が作る形の空の pin ファイル（未マウントの残骸）は解除できる。
    #[test]
    fn net1_unpin_path_removes_leftover_pin_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("leftover");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("web-1");
        make_registered_pin(&pin);
        unpin_path(&pin).unwrap();
        assert!(!pin.exists());
        fs::remove_dir(&dir).unwrap();
    }

    /// 本モジュールが作った形の空ファイルを作り、`create_pinned` と同様に所有記録へ登録する。
    fn make_registered_pin(pin: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(pin, b"").unwrap();
        fs::set_permissions(pin, fs::Permissions::from_mode(0o400)).unwrap();
        register_pin(file_id(&fs::symlink_metadata(pin).unwrap()));
    }

    /// NET-1・P0: 形（0400・空・実効 UID 所有の通常ファイル）が pin と異なるファイルは、記録が無くても消さない。
    #[test]
    fn net1_unpin_path_keeps_non_pin_shaped_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("shaped");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("not-a-pin");
        fs::write(&pin, b"data").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
        let e = unpin_path(&pin).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(pin.exists());
        fs::remove_file(&pin).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1・P0: 所有記録の無いファイルは、置き場検証と形の検査（実効 UID 所有・0o400・空の通常ファイル）を
    /// 通っても削除しない（作成プロセスの終了後の残置を含む。プロセスをまたぐ清掃は TASK-139.4）。
    #[test]
    fn net1_unpin_path_rejects_pin_shaped_file_without_record() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("norecord");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("web-1");
        fs::write(&pin, b"").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o400)).unwrap();
        let e = unpin_path(&pin).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "path is not a netns pin created by this process"
        );
        assert!(pin.exists());
        // 同じ実体を記録した後なら解除できる（拒否の理由が記録の有無だけであることの確認）。
        register_pin(file_id(&fs::symlink_metadata(&pin).unwrap()));
        unpin_path(&pin).unwrap();
        assert!(!pin.exists());
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1・P0: 記録済みの pin の名前へ、記録の無い同じ形のファイルが差し替わったら削除しない。
    #[test]
    fn net1_unpin_path_rejects_unrecorded_replacement() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("replaced");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("web-1");
        make_registered_pin(&pin);
        let recorded = file_id(&fs::symlink_metadata(&pin).unwrap());
        // 旧ファイルを別名で残し（inode 番号の再利用を防ぐ）、記録の無い同形ファイルを被せる。
        let kept = dir.join("kept");
        fs::rename(&pin, &kept).unwrap();
        fs::write(&pin, b"").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o400)).unwrap();
        let e = unpin_path(&pin).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(pin.exists());
        forget_pin(recorded);
        fs::remove_file(&pin).unwrap();
        fs::remove_file(&kept).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 作成時の識別子と異なる実体へ差し替わった pin ファイルは、失敗時の後始末でも削除しない。
    #[test]
    fn net1_remove_pin_file_checks_identity() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("rmid");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("web-1");
        make_registered_pin(&pin);
        let fid = file_id(&fs::symlink_metadata(&pin).unwrap());
        let kept = dir.join("kept");
        fs::rename(&pin, &kept).unwrap();
        fs::write(&pin, b"other").unwrap();
        assert_eq!(remove_pin_file(&pin, fid), Some(ResourceState::Unknown));
        assert_eq!(fs::read(&pin).unwrap(), b"other");
        // 元の実体に戻せば消せ、記録も外れる。
        fs::remove_file(&pin).unwrap();
        fs::rename(&kept, &pin).unwrap();
        assert_eq!(remove_pin_file(&pin, fid), None);
        assert!(!pin.exists());
        assert!(lookup_pin(fid).is_none());
        // 既に無ければ成功扱い（冪等）。
        assert_eq!(remove_pin_file(&pin, fid), None);
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 別 inode に差し替わった pin は、現在の実体の記録で判定する（記録が無ければ拒否）。
    #[test]
    fn net1_unpin_path_judges_swapped_file_by_current_inode() {
        let dir = scratch_dir("swapped");
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let pin = dir.join("web-1");
        make_registered_pin(&pin);
        let recorded = file_id(&fs::symlink_metadata(&pin).unwrap());
        // 同じ inode 番号が再利用されないよう、旧ファイルを残したまま別ファイルを rename で被せる。
        let other = dir.join("other");
        make_registered_pin(&other);
        let other_id = file_id(&fs::symlink_metadata(&other).unwrap());
        fs::rename(&other, &pin).unwrap();
        // 差し替え後の実体は別の記録（other_id）を持つが、記録された本来の pin（recorded）ではない。
        // 記録は他にも残っている状態でも、現在の実体の記録と照合して扱う。
        forget_pin(recorded);
        unpin_path(&pin).unwrap();
        assert!(!pin.exists());
        forget_pin(other_id);
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 動作中ワーカーの pin は unlink せず拒否する（ワーカー完了後は通常どおり扱える）。
    #[test]
    fn net1_unpin_path_rejects_inflight_pin() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("inflight");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = dir.join("web-1");
        make_registered_pin(&pin);
        let guard = InflightGuard::new(file_id(&fs::symlink_metadata(&pin).unwrap()));
        let e = unpin_path(&pin).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(pin.exists());
        drop(guard);
        unpin_path(&pin).unwrap();
        assert!(!pin.exists());
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: pin ファイル実体検査の具体的な合否。
    #[test]
    fn net1_pin_file_attr_checks() {
        assert!(check_pin_file_attrs(true, 0o100_400, 1000, 0, 1000).is_ok());
        for (is_file, mode, owner, len, what) in [
            (false, 0o040_400, 1000, 0, "not a file"),
            (true, 0o100_444, 1000, 0, "nsfs-like mode"),
            (true, 0o100_400, 0, 0, "other owner"),
            (true, 0o100_400, 1000, 4, "non-empty"),
        ] {
            let e = check_pin_file_attrs(is_file, mode, owner, len, 1000).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{what}");
        }
    }

    /// NET-1: mountinfo 上の pin のマウント状態（最上位の fstype で判定）。
    #[test]
    fn net1_pin_mount_state_from_mountinfo() {
        let info = "\
50 30 0:4 net:[4026531992] /run/ns/a rw shared:9 - nsfs nsfs rw
51 30 0:30 / /run/ns/b rw - tmpfs tmpfs rw
52 30 0:4 net:[4026531993] /run/ns/c rw - nsfs nsfs rw
53 30 0:30 / /run/ns/c rw - tmpfs tmpfs rw
";
        let st = |p: &str| pin_mount_state(info, Path::new(p));
        assert_eq!(st("/run/ns/a"), PinMount::Nsfs);
        assert_eq!(st("/run/ns/b"), PinMount::Other);
        assert_eq!(st("/run/ns/c"), PinMount::Other);
        assert_eq!(st("/run/ns/d"), PinMount::None);
    }
    /// NET-1: 相対パスは受け付けない。
    #[test]
    fn net1_relative_base_dir_is_rejected() {
        let e = check_base_dir(Path::new("relative/dir")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 22 0:25 / /run rw,nosuid shared:2 - tmpfs tmpfs rw
41 30 0:40 / /run/priv rw master:3 - tmpfs tmpfs rw
42 30 0:41 / /run/with\\040space rw - tmpfs tmpfs rw
43 41 0:42 / /run/priv/slave rw shared:7 master:3 - tmpfs tmpfs rw
";

    /// NET-1: 置き場を含むマウントの伝播判定（最長一致・shared 拒否・private / slave 許可）。
    #[test]
    fn net1_propagation_check_uses_longest_mount() {
        let code = |p: &str| check_propagation(MOUNTINFO, Path::new(p)).map_err(|e| e.code());
        assert_eq!(code("/run/netns"), Err(NetErrorCode::FailedPrecondition));
        assert_eq!(code("/var/lib/x"), Err(NetErrorCode::FailedPrecondition));
        assert_eq!(code("/run/priv"), Ok(()));
        assert_eq!(code("/run/priv/d"), Ok(()));
        assert_eq!(code("/run/with space/d"), Ok(()));
        assert_eq!(
            code("/run/priv/slave/d"),
            Err(NetErrorCode::FailedPrecondition)
        );
        // 前方一致だけでは別マウントとみなさない（`/run/privx` は `/run` に属する）。
        assert_eq!(code("/run/privx"), Err(NetErrorCode::FailedPrecondition));
    }

    /// NET-1: mountinfo に該当マウントが無ければ拒否する（fail-closed）。
    #[test]
    fn net1_propagation_check_rejects_unknown_mount() {
        let e = check_propagation("", Path::new("/run/x")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
    }

    /// 8 進エスケープの復号。
    #[test]
    fn mountinfo_octal_unescape() {
        assert_eq!(unescape_mountinfo("/a\\040b\\134c"), b"/a b\\c");
        assert_eq!(unescape_mountinfo("/plain"), b"/plain");
        assert_eq!(unescape_mountinfo("/x\\4"), b"/x\\4");
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-netns-test-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    /// NET-1: symlink の置き場ディレクトリは実体が正当でも拒否する。
    #[test]
    fn net1_symlinked_base_dir_is_rejected() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let real = scratch_dir("real");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = real.with_extension("link");
        symlink(&real, &link).unwrap();
        let e = check_base_dir(&link).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(check_base_dir(&real).is_ok());
        fs::remove_file(&link).unwrap();
        fs::remove_dir(&real).unwrap();
    }

    /// NET-1: `create_pinned` は置き場を fd で固定する前の検査（`open_pin_dir`）で、symlink の置き場を
    /// 拒否し、リンク先の実ディレクトリには何も作らない（mount へ進まない権限不要の経路）。
    #[test]
    fn net1_create_pinned_rejects_symlinked_base_without_side_effects() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let real = scratch_dir("cp-real");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = real.with_extension("link");
        symlink(&real, &link).unwrap();
        let id = EndpointId::new("web-1").unwrap();
        let f = create_pinned(&link, &id, Duration::from_secs(1), &noop_recorder()).unwrap_err();
        assert_eq!(f.error.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(f.leftover, None);
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
        fs::remove_file(&link).unwrap();
        fs::remove_dir(&real).unwrap();
    }

    /// NET-1: group / other 書き込み可の実ディレクトリは拒否する。
    #[test]
    fn net1_world_writable_base_dir_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("ww");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let e = check_base_dir(&dir).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 既存の pin 先（他者のファイルの可能性）は上書きも削除もせず AlreadyExists で拒否する。
    /// 権限不要で検証できる経路（`create_new` の段階で失敗し、mount には進まない）。
    #[test]
    fn net1_existing_pin_file_is_kept() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exists");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let id = EndpointId::new("web-1").unwrap();
        let pin = dir.join("web-1");
        fs::write(&pin, b"keep").unwrap();
        let f = create_pinned(&dir, &id, Duration::from_secs(1), &noop_recorder()).unwrap_err();
        assert_eq!(f.error.code(), NetErrorCode::AlreadyExists);
        assert_eq!(f.leftover, None);
        assert_eq!(fs::read(&pin).unwrap(), b"keep");
        fs::remove_file(&pin).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}
