//! 複数スレッドのプロセスから制御チャネルの拒否と seccomp の拒否を期限付きで永続化する中継（Linux。SEC-4・REPAIR-5・SUP-1・SEC-1・#2058）。
//!
//! # 役割
//!
//! [`FileAuditSink`] は主経路のファイル I/O を fork した使い捨ての子で実行するため、呼び出しプロセスが
//! 複数スレッドだと主経路を試行できず（`isolation_unavailable`）、`CAP_AUDIT_WRITE` の無い非特権起動では代替経路
//! （カーネル監査）も失敗して拒否が残らない。supervisor の制御チャネルのサーバスレッドは監視スレッドと並行して
//! 動くため常にこの状態になる。本中継は、**スレッドを作る前の単一スレッドの時点で** 監査専用の子プロセス
//! （helper）を 1 つ fork して常駐させ、以後の `record` を socketpair 越しに helper へ渡す。helper は単一スレッドの
//! ままなので、持たせた [`FileAuditSink`] の隔離（主経路 → 代替経路 → 失敗通知）がそのまま働く。
//!
//! # 契約
//!
//! - 構築（[`ControlAuditRelay::spawn`]）は呼び出しプロセスが単一スレッドのときだけ成功する（`FailedPrecondition`）。
//!   制御チャネルの listener を bind する前に呼ぶこと（helper は fd 3 以上を閉じるため listener を持たない）
//! - 段（`AuditRecord::stage`。#3121）は枠が運ばない。段つきの記録を通すと段は落ちる（現行の配線では段つきの
//!   pre-pivot の記録は単一スレッドの launch が sink へ直接書き、中継を通らない。REPAIR-3）。落ちることは試験
//!   `sec4_err4_3209_stage_is_dropped_by_relay_frame` が固定する（枠が段の有無でバイト同一・復号後は段なし）。
//!   段つきを拒否せず落とすのは、記録そのものを失わないため（記録の成否で拒否は覆らない。fail-closed）
//! - 運べるのは [`AuditEvent::PluginPeer`]（#2484。plugin-cri の peer 認証の拒否。socket のパスは mount と同じ枠で運ぶ）・
//!   [`AuditEvent::ControlPeer`]・[`AuditEvent::Seccomp`]・[`AuditEvent::ExitSignal`]（#2236。launcher の
//!   回収点が出す補助の `exit_signal`）・理由なしの [`AuditEvent::Mount`]（#2481。supervisor の `start` が作業スレッドで
//!   出す bind・sysfs の拒否。パスは生バイトで運ぶ）・閉じた表（`MOUNT_REASONS`）の理由つきの `Mount`（#2623。start の
//!   作業スレッドが出す rootfs の固定の検証後の差し替えの 2 理由）の記録だけ（他の層と、表に無い理由の `Mount` は
//!   `InvalidArgument`。理由トークンは静的文字列の開いた語彙で、復号側が閉じた表へ戻せるものだけを運ぶ。それ以外の
//!   理由つきの記録は単一スレッドの launch が `FileAuditSink` へ直接出す）。時刻・PID・
//!   コンテナ ID・理由トークン（seccomp は種別トークンと syscall 番号・arch）を固定の枠で送り、helper が [`AuditRecord`] を
//!   組み直す（生のバイト列を記録として扱わない。REPAIR-2）。seccomp の記録は supervisor の seccomp 通知ループ
//!   （`record_seccomp_denial_for` 経由。SEC-4・REPAIR-5・#2025）が書く
//! - `record` は helper の応答を [`RECORD_WAIT_LIMIT`] まで待つ（helper の sink の最悪待ち時間と同じ）。応答が無ければ
//!   helper を SIGKILL して以後の `record` を `Unavailable` で拒否する（ずれた応答を次の要求へ取り違えない。fail-closed）。
//!   拒否の判定自体は呼び出し側で既に確定しており、本中継の失敗は判定を覆さない
//! - 親が終了すると socketpair が EOF になり helper も終了する。drop でも SIGKILL して回収を試みる
//!
//! # 未実装（REPAIR-3）
//!
//! helper が死んだ後の再起動はしない（以後 `Unavailable`。呼び出し側が構造化ログへ縮退する）。

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::sys;
use crate::traits::{ContainerId, ErrorCode, TraitError};

use super::{
    AUDIT_PATH_MAX_BYTES, AuditEvent, AuditPath, AuditPid, AuditRecord, AuditSignal, AuditSink,
    AuditSyscallArch, AuditSyscallNr, AuditTimestamp, ControlPeerRejection, FileAuditSink,
    PluginPeerRejection, RECORD_WAIT_LIMIT,
};

/// 枠の固定部: 理由 1・秒 8・ナノ秒 4・PID 4・コンテナ ID 長 1。
const FIXED_LEN: usize = 1 + 8 + 4 + 4 + 1;
/// helper の応答: 永続化できた。
const ACK_OK: u8 = 1;
/// helper の応答: 主経路・代替経路とも失敗した。
const ACK_FAIL: u8 = 0;
/// helper が fd 3 以上を閉じられなかったときの終了コード。
const CLOSE_FDS_FAILED_EXIT: i32 = 3;
/// 回収待ちの上限（drop 時）。
const REAP_WAIT: Duration = Duration::from_secs(1);

/// seccomp の記録を示す先頭バイト（`REJECTIONS` の添字と重ならない値）。コンテナ ID の後に syscall 番号（u32）と arch（u32）が付く。
const TAG_SECCOMP: u8 = 0x80;
/// 記録先の確認要求を示す先頭バイト（本体は固定部だけ。何も書かず、helper の sink が保存先を開けるかだけを確かめる）。
const TAG_PROBE: u8 = 0x81;
/// 終了シグナル（`AuditEvent::ExitSignal`。#2236）の記録を示す先頭バイト。コンテナ ID の後に signal（u8）と target_pid（u32）が付く。
const TAG_EXIT_SIGNAL: u8 = 0x82;
/// exit_signal の枠だけが持つ追加部（signal 1・target_pid 4）。
const EXIT_SIGNAL_EXTRA_LEN: usize = 1 + 4;
/// seccomp の枠だけが持つ追加部（番号 4・arch 4）。
const SECCOMP_EXTRA_LEN: usize = 8;
/// mount（理由なし。#2481）の記録を示す先頭バイト。コンテナ ID の後に追加部（path_present 1・path_len 2・original_len 8）、
/// さらに可変長のパス本体 `path_len` バイトが付く。
const TAG_MOUNT: u8 = 0x83;
/// mount の枠の固定の追加部の長さ（path_present 1・path_len 2・original_len 8）。パス本体はこの後ろに続く。
const MOUNT_EXTRA_LEN: usize = 1 + 2 + 8;

/// plugin の peer 認証の拒否（`AuditEvent::PluginPeer`。#2484）の記録を示す先頭バイト。コンテナ ID（常に空）の後に
/// 理由の添字（`PLUGIN_PEER_REJECTIONS` の位置 1）と mount と同じ追加部（`MountHeader`）、可変長のパス本体が付く。
const TAG_PLUGIN_PEER: u8 = 0x84;
/// plugin_peer の枠の固定の追加部の長さ（理由の添字 1 ＋ `MOUNT_EXTRA_LEN`）。
const PLUGIN_PEER_EXTRA_LEN: usize = 1 + MOUNT_EXTRA_LEN;

/// 理由つきの mount（`AuditEvent::Mount { reason: Some(_) }`。#2623）の記録を示す先頭バイト。コンテナ ID の後に
/// 理由の添字（`MOUNT_REASONS` の位置 1）と mount と同じ追加部（`MountHeader`）、可変長のパス本体が付く。
const TAG_MOUNT_REASON: u8 = 0x85;
/// 理由つき mount の枠の固定の追加部の長さ（理由の添字 1 ＋ `MOUNT_EXTRA_LEN`）。
const MOUNT_REASON_EXTRA_LEN: usize = 1 + MOUNT_EXTRA_LEN;

/// 理由つき mount で運べる理由（枠の添字）の閉じた表。start の作業スレッド（複数スレッド）が出す
/// rootfs の固定（`RootfsDir::pin`）の検証後の差し替えの 2 理由だけ（SEC-4・SEC-1・#2623）。
/// 理由トークンは静的文字列の開いた語彙のため、復号側はこの表から静的トークンを引き直す。
/// 増やすときは表と試験を同時に更新する。
const MOUNT_REASONS: [crate::exec::ViolationReason; 2] = [
    crate::exec::ViolationReason::PathSymlinkOrNotDirectory,
    crate::exec::ViolationReason::PathMissing,
];

/// plugin_peer で運べる拒否理由（枠の添字）。`Unknown` も運ぶ（落とさず記録する）。
const PLUGIN_PEER_REJECTIONS: [PluginPeerRejection; 5] = [
    PluginPeerRejection::PeerUidMismatch,
    PluginPeerRejection::PeerUidUnavailable,
    PluginPeerRejection::PeerPidMismatch,
    PluginPeerRejection::PeerPidUnavailable,
    PluginPeerRejection::Unknown,
];

/// pasta の検証拒否（`AuditEvent::PastaVerify`。SEC-4・NET-9・PLUG-11・#3330）の記録を示す先頭バイト。コンテナ ID の後に
/// 理由の添字（`PASTA_VERIFY_REJECTIONS` の位置 1）が付く。supervisor の start が、構築済みの relay 経由で期限つきに配送する。
const TAG_PASTA_VERIFY: u8 = 0x86;
/// pasta_verify の枠だけが持つ追加部の長さ（理由の添字 1）。
const PASTA_VERIFY_EXTRA_LEN: usize = 1;

/// pasta_verify で運べる拒否理由（枠の添字）。
const PASTA_VERIFY_REJECTIONS: [super::PastaVerifyRejection; 2] = [
    super::PastaVerifyRejection::RecordChanged,
    super::PastaVerifyRejection::PermissionDenied,
];

/// 先頭バイトから、コンテナ ID の後ろに続く追加部の長さを返す（`serve` の読み取り量を 1 か所で決める）。
const fn extra_len(tag: u8) -> usize {
    match tag {
        TAG_SECCOMP => SECCOMP_EXTRA_LEN,
        TAG_EXIT_SIGNAL => EXIT_SIGNAL_EXTRA_LEN,
        TAG_MOUNT => MOUNT_EXTRA_LEN,
        TAG_PLUGIN_PEER => PLUGIN_PEER_EXTRA_LEN,
        TAG_MOUNT_REASON => MOUNT_REASON_EXTRA_LEN,
        TAG_PASTA_VERIFY => PASTA_VERIFY_EXTRA_LEN,
        _ => 0,
    }
}

/// 運べる拒否理由（枠の先頭バイトが添字）。
const REJECTIONS: [ControlPeerRejection; 2] = [
    ControlPeerRejection::PeerUidMismatch,
    ControlPeerRejection::PeerCredentialsUnavailable,
];

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

/// 記録を枠へ符号化する。`ControlPeer` 以外・長すぎるコンテナ ID は拒否する。
fn encode(record: &AuditRecord) -> Result<Vec<u8>, TraitError> {
    let (tag, extra, exit_signal) = match record.event() {
        AuditEvent::Mount { path, reason: None } => {
            return encode_mount(record, path.as_ref());
        }
        AuditEvent::Mount {
            path,
            reason: Some(reason),
        } => {
            return encode_mount_reason(record, path.as_ref(), reason.as_str());
        }
        AuditEvent::PluginPeer { path, reason } => {
            return encode_plugin_peer(record, path, reason.as_str());
        }
        AuditEvent::ControlPeer { reason } => {
            let Some(tag) = REJECTIONS
                .iter()
                .position(|r| r.as_str() == reason.as_str())
                .and_then(|i| u8::try_from(i).ok())
            else {
                return Err(err(
                    ErrorCode::InvalidArgument,
                    "the audit relay does not know this rejection reason",
                ));
            };
            (tag, None, None)
        }
        AuditEvent::PastaVerify { reason } => {
            let Some(index) = PASTA_VERIFY_REJECTIONS
                .iter()
                .position(|r| r.as_str() == reason.as_str())
                .and_then(|i| u8::try_from(i).ok())
            else {
                return Err(err(
                    ErrorCode::InvalidArgument,
                    "the audit relay does not know this pasta rejection reason",
                ));
            };
            let mut frame = Vec::with_capacity(FIXED_LEN + 1 + PASTA_VERIFY_EXTRA_LEN);
            push_head(&mut frame, TAG_PASTA_VERIFY, record)?;
            frame.push(index);
            return Ok(frame);
        }
        AuditEvent::Seccomp { syscall, arch } => {
            (TAG_SECCOMP, Some((syscall.get(), arch.get())), None)
        }
        AuditEvent::ExitSignal { signal, target_pid } => (
            TAG_EXIT_SIGNAL,
            None,
            Some((signal.get(), target_pid.get())),
        ),
        _ => {
            return Err(err(
                ErrorCode::InvalidArgument,
                "the audit relay only carries control channel, plugin peer, pasta verify, seccomp, exit signal and mount records",
            ));
        }
    };
    let id = record.container_id().map_or("", ContainerId::as_str);
    let Ok(id_len) = u8::try_from(id.len()) else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the container id is too long for the audit relay",
        ));
    };
    let at = record.timestamp().as_unix_duration();
    let mut frame = Vec::with_capacity(FIXED_LEN + id.len());
    frame.push(tag);
    frame.extend_from_slice(&at.as_secs().to_be_bytes());
    frame.extend_from_slice(&at.subsec_nanos().to_be_bytes());
    frame.extend_from_slice(&record.pid().get().to_be_bytes());
    frame.push(id_len);
    frame.extend_from_slice(id.as_bytes());
    if let Some((nr, arch)) = extra {
        frame.extend_from_slice(&nr.to_be_bytes());
        frame.extend_from_slice(&arch.to_be_bytes());
    }
    if let Some((signal, target_pid)) = exit_signal {
        frame.push(signal);
        frame.extend_from_slice(&target_pid.to_be_bytes());
    }
    Ok(frame)
}

/// 共通の固定部（先頭バイト・時刻・PID・コンテナ ID）を `frame` へ積む。ID が長すぎれば拒否する。
fn push_head(frame: &mut Vec<u8>, tag: u8, record: &AuditRecord) -> Result<(), TraitError> {
    let id = record.container_id().map_or("", ContainerId::as_str);
    let Ok(id_len) = u8::try_from(id.len()) else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the container id is too long for the audit relay",
        ));
    };
    let at = record.timestamp().as_unix_duration();
    frame.push(tag);
    frame.extend_from_slice(&at.as_secs().to_be_bytes());
    frame.extend_from_slice(&at.subsec_nanos().to_be_bytes());
    frame.extend_from_slice(&record.pid().get().to_be_bytes());
    frame.push(id_len);
    frame.extend_from_slice(id.as_bytes());
    Ok(())
}

/// mount（理由なし。#2481）の枠の固定長の追加部（present 1・path_len 2・original_len 8）。
/// 符号化・復号・`serve` の本体読み取り量の決定をこの型へ集約し、生のバイト列を手で組まない（REPAIR-2）。
/// 値は [`MountHeader::parse`] / [`MountHeader::for_path`] を通ったものだけが持つ（保持長 ≤ 上限、
/// 存在フラグと長さ・元の長さの整合を満たす）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountHeader {
    present: bool,
    path_len: u16,
    original_len: u64,
}

impl MountHeader {
    /// パス（無ければ `None`）から追加部とパス本体のバイト列を作る。保持長は [`AUDIT_PATH_MAX_BYTES`] 以下
    /// （`AuditPath` の不変条件）なので `u16` に収まる。
    fn for_path(path: Option<&AuditPath>) -> Result<(Self, &[u8]), TraitError> {
        let (bytes, original_len) = match path {
            Some(p) => (p.as_path().as_os_str().as_bytes(), p.original_len()),
            None => (&[][..], 0),
        };
        let too_long = || err(ErrorCode::InvalidArgument, "the audit path is too long");
        if bytes.len() > AUDIT_PATH_MAX_BYTES {
            return Err(too_long());
        }
        let header = Self {
            present: path.is_some(),
            path_len: u16::try_from(bytes.len()).map_err(|_| too_long())?,
            original_len: u64::try_from(original_len).map_err(|_| too_long())?,
        };
        Ok((header, bytes))
    }

    /// 追加部を固定長のバイト列へ符号化する。
    fn to_bytes(self) -> [u8; MOUNT_EXTRA_LEN] {
        let mut out = [0u8; MOUNT_EXTRA_LEN];
        out[0] = u8::from(self.present);
        out[1..3].copy_from_slice(&self.path_len.to_be_bytes());
        out[3..].copy_from_slice(&self.original_len.to_be_bytes());
        out
    }

    /// 追加部を復号する。長さが `MOUNT_EXTRA_LEN` でない・存在フラグ不正・上限超過・
    /// 切り詰めの有無と `original_len` の矛盾は `None`。
    fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; MOUNT_EXTRA_LEN] = bytes.try_into().ok()?;
        let present = match bytes[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let path_len = u16::from_be_bytes([bytes[1], bytes[2]]);
        let original_len = u64::from_be_bytes(bytes[3..].try_into().ok()?);
        let kept = usize::from(path_len);
        if kept > AUDIT_PATH_MAX_BYTES {
            return None;
        }
        let original = usize::try_from(original_len).ok()?;
        let consistent = if present {
            original >= kept && (original > AUDIT_PATH_MAX_BYTES || original == kept)
        } else {
            kept == 0 && original == 0
        };
        consistent.then_some(Self {
            present,
            path_len,
            original_len,
        })
    }

    /// 追加部の後ろに続くパス本体の長さ（`serve` の読み取り量。検証済みで上限以下）。
    fn body_len(self) -> usize {
        usize::from(self.path_len)
    }

    /// パス本体から `AuditPath` を組み直す。本体の長さが `body_len` と一致しなければ `None`。
    fn into_path(self, body: &[u8]) -> Option<Option<AuditPath>> {
        if body.len() != self.body_len() {
            return None;
        }
        if !self.present {
            return Some(None);
        }
        Some(Some(AuditPath {
            path: PathBuf::from(OsStr::from_bytes(body)),
            original_len: usize::try_from(self.original_len).ok()?,
        }))
    }
}

/// 理由なしの `Mount` を枠へ符号化する（#2481）。パスは生バイトのまま運ぶ。
fn encode_mount(record: &AuditRecord, path: Option<&AuditPath>) -> Result<Vec<u8>, TraitError> {
    let (header, bytes) = MountHeader::for_path(path)?;
    let mut frame = Vec::with_capacity(FIXED_LEN + MOUNT_EXTRA_LEN + bytes.len());
    push_head(&mut frame, TAG_MOUNT, record)?;
    frame.extend_from_slice(&header.to_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

/// 理由つきの `Mount`（#2623）を枠へ符号化する。理由は閉じた表 `MOUNT_REASONS` の添字で運び、表に無いトークンは拒否する。
fn encode_mount_reason(
    record: &AuditRecord,
    path: Option<&AuditPath>,
    reason: &str,
) -> Result<Vec<u8>, TraitError> {
    let Some(index) = MOUNT_REASONS
        .iter()
        .position(|r| r.as_str() == reason)
        .and_then(|i| u8::try_from(i).ok())
    else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the audit relay does not carry mount records with this reason",
        ));
    };
    let (header, bytes) = MountHeader::for_path(path)?;
    let mut frame = Vec::with_capacity(FIXED_LEN + MOUNT_REASON_EXTRA_LEN + bytes.len());
    push_head(&mut frame, TAG_MOUNT_REASON, record)?;
    frame.push(index);
    frame.extend_from_slice(&header.to_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

/// `PluginPeer`（#2484）を枠へ符号化する。理由は閉じた表の添字で運び、表に無いトークンは拒否する。
fn encode_plugin_peer(
    record: &AuditRecord,
    path: &AuditPath,
    reason: &str,
) -> Result<Vec<u8>, TraitError> {
    let Some(index) = PLUGIN_PEER_REJECTIONS
        .iter()
        .position(|r| r.as_str() == reason)
        .and_then(|i| u8::try_from(i).ok())
    else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the audit relay does not know this rejection reason",
        ));
    };
    let (header, bytes) = MountHeader::for_path(Some(path))?;
    let mut frame = Vec::with_capacity(FIXED_LEN + PLUGIN_PEER_EXTRA_LEN + bytes.len());
    push_head(&mut frame, TAG_PLUGIN_PEER, record)?;
    frame.push(index);
    frame.extend_from_slice(&header.to_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

/// `rest`（ID の後ろ）から plugin_peer の記録の ID と事象を組み直す。壊れた枠・パスなしは `None`。
fn decode_plugin_peer(rest: &[u8], id_len: usize) -> Option<(&[u8], AuditEvent)> {
    let (id, after) = rest.split_at_checked(id_len)?;
    let rejection = PLUGIN_PEER_REJECTIONS.get(usize::from(*after.first()?))?;
    let header = MountHeader::parse(after.get(1..PLUGIN_PEER_EXTRA_LEN)?)?;
    let path = header.into_path(after.get(PLUGIN_PEER_EXTRA_LEN..)?)??;
    Some((
        id,
        AuditEvent::PluginPeer {
            path,
            reason: super::AuditReason::new(rejection.as_str()),
        },
    ))
}

/// `rest`（ID の後ろ）から理由つき mount の記録の ID と事象を組み直す。理由は表の静的トークンから作り、
/// 枠のバイト列から文字列を作らない。壊れた枠・範囲外の添字は `None`。
fn decode_mount_reason(rest: &[u8], id_len: usize) -> Option<(&[u8], AuditEvent)> {
    let (id, after) = rest.split_at_checked(id_len)?;
    let reason = MOUNT_REASONS.get(usize::from(*after.first()?))?;
    let header = MountHeader::parse(after.get(1..MOUNT_REASON_EXTRA_LEN)?)?;
    let path = header.into_path(after.get(MOUNT_REASON_EXTRA_LEN..)?)?;
    Some((
        id,
        AuditEvent::Mount {
            path,
            reason: Some(super::AuditReason::new(reason.as_str())),
        },
    ))
}

/// `rest`（ID の後ろ）から mount の記録の ID と事象を組み直す。壊れた枠は `None`。
fn decode_mount(rest: &[u8], id_len: usize) -> Option<(&[u8], AuditEvent)> {
    let (id, after) = rest.split_at_checked(id_len)?;
    let header = MountHeader::parse(after.get(..MOUNT_EXTRA_LEN)?)?;
    let path = header.into_path(after.get(MOUNT_EXTRA_LEN..)?)?;
    Some((id, AuditEvent::Mount { path, reason: None }))
}

/// 枠から記録を組み直す。壊れた枠は `None`（記録を捏造しない）。
fn decode(frame: &[u8]) -> Option<AuditRecord> {
    let tag = *frame.first()?;
    let secs = u64::from_be_bytes(frame.get(1..9)?.try_into().ok()?);
    let nanos = u32::from_be_bytes(frame.get(9..13)?.try_into().ok()?);
    let pid = u32::from_be_bytes(frame.get(13..17)?.try_into().ok()?);
    let id_len = usize::from(*frame.get(17)?);
    let rest = frame.get(FIXED_LEN..)?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    let (id, event) = if tag == TAG_MOUNT {
        decode_mount(rest, id_len)?
    } else if tag == TAG_MOUNT_REASON {
        decode_mount_reason(rest, id_len)?
    } else if tag == TAG_PLUGIN_PEER {
        decode_plugin_peer(rest, id_len)?
    } else if tag == TAG_PASTA_VERIFY {
        if rest.len() != id_len.checked_add(PASTA_VERIFY_EXTRA_LEN)? {
            return None;
        }
        let (id, extra) = rest.split_at(id_len);
        let rejection = PASTA_VERIFY_REJECTIONS.get(usize::from(*extra.first()?))?;
        (id, rejection.audit_event())
    } else if tag == TAG_SECCOMP {
        // 長さは厳密に一致させる（余りも不足も壊れた枠）。
        if rest.len() != id_len.checked_add(SECCOMP_EXTRA_LEN)? {
            return None;
        }
        let (id, extra) = rest.split_at(id_len);
        let nr = u32::from_be_bytes(extra.get(0..4)?.try_into().ok()?);
        let arch = u32::from_be_bytes(extra.get(4..8)?.try_into().ok()?);
        (
            id,
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::from_seccomp_data_nr(nr.cast_signed()),
                arch: AuditSyscallArch::from_raw(arch),
            },
        )
    } else if tag == TAG_EXIT_SIGNAL {
        if rest.len() != id_len.checked_add(EXIT_SIGNAL_EXTRA_LEN)? {
            return None;
        }
        let (id, extra) = rest.split_at(id_len);
        let signal = AuditSignal::new(i32::from(*extra.first()?)).ok()?;
        let target = u32::from_be_bytes(extra.get(1..5)?.try_into().ok()?);
        let target_pid = AuditPid::new(i32::try_from(target).ok()?).ok()?;
        (id, AuditEvent::ExitSignal { signal, target_pid })
    } else {
        if rest.len() != id_len {
            return None;
        }
        (rest, REJECTIONS.get(usize::from(tag))?.audit_event())
    };
    let at = AuditTimestamp::from_unix_duration(Duration::new(secs, nanos));
    let pid = AuditPid::new(i32::try_from(pid).ok()?).ok()?;
    let mut record = AuditRecord::new(at, pid, event);
    if !id.is_empty() {
        record = record.with_container_id(ContainerId::new(std::str::from_utf8(id).ok()?).ok()?);
    }
    Some(record)
}

/// helper の本体。枠を読んで `sink` に記録し、結果を 1 バイトで返す。EOF（親の終了）で終わる。
fn serve(mut stream: UnixStream, sink: &FileAuditSink) -> i32 {
    loop {
        let mut head = [0u8; FIXED_LEN];
        if stream.read_exact(&mut head).is_err() {
            return 0;
        }
        let id_len = usize::from(head.last().copied().unwrap_or(0));
        let extra = head.first().copied().map_or(0, extra_len);
        let mut frame = head.to_vec();
        frame.resize(FIXED_LEN + id_len + extra, 0);
        if let Some(body) = frame.get_mut(FIXED_LEN..)
            && stream.read_exact(body).is_err()
        {
            return 1;
        }
        let header_offset = match head.first() {
            Some(&TAG_MOUNT) => Some(0),
            // plugin_peer は追加部の先頭に理由の添字 1 バイトがあり、MountHeader はその後ろ。
            Some(&TAG_PLUGIN_PEER | &TAG_MOUNT_REASON) => Some(1),
            _ => None,
        };
        if let Some(offset) = header_offset {
            // 可変長のパス本体。長さは型で検証してから確保する（壊れた枠はストリームを読み進められないので
            // helper を終え、親は応答待ちの期限で Unavailable になる。fail-closed。DoS 対策）。
            let Some(header) = frame
                .get(FIXED_LEN + id_len + offset..)
                .and_then(MountHeader::parse)
            else {
                return 1;
            };
            let start = frame.len();
            frame.resize(start + header.body_len(), 0);
            if let Some(body) = frame.get_mut(start..)
                && stream.read_exact(body).is_err()
            {
                return 1;
            }
        }
        let ok = if head.first() == Some(&TAG_PROBE) {
            id_len == 0 && sink.probe_primary().is_ok()
        } else {
            decode(&frame).is_some_and(|r| sink.record(&r).is_ok())
        };
        if stream
            .write_all(&[if ok { ACK_OK } else { ACK_FAIL }])
            .is_err()
        {
            return 1;
        }
    }
}

/// fd 0〜2 が閉じていても helper の `close_range(3, ..)` と衝突しないよう、fd を 3 以上へ移す。
fn dup_high(stream: UnixStream) -> Option<UnixStream> {
    let fd: OwnedFd = stream.into();
    sys::dup_fd_at_least(fd.as_fd(), 3)
        .ok()
        .map(UnixStream::from)
}

struct State {
    stream: UnixStream,
    broken: bool,
}

/// 単一スレッドの時点で fork した監査専用 helper へ制御チャネルの拒否を渡す [`AuditSink`]。
pub struct ControlAuditRelay {
    state: Mutex<State>,
    pid: u32,
    pidfd: Option<OwnedFd>,
}

impl std::fmt::Debug for ControlAuditRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlAuditRelay").finish_non_exhaustive()
    }
}

impl ControlAuditRelay {
    /// `sink` を持つ helper を fork する。呼び出しプロセスが複数スレッドなら `FailedPrecondition`。
    /// fork 直後に未回収の自分の子と確認できなければ `Unavailable`（pid を保持しない）。
    ///
    /// 呼び出し元: supervisor の `start`（制御チャネルの `install` の前、スレッドを作る前）。
    pub fn spawn(sink: FileAuditSink) -> Result<Self, TraitError> {
        let unavailable = || err(ErrorCode::Unavailable, "failed to start the audit relay");
        let (parent, child) = UnixStream::pair().map_err(|_| unavailable())?;
        let parent = dup_high(parent).ok_or_else(unavailable)?;
        let child = dup_high(child).ok_or_else(unavailable)?;
        let forked = sys::fork_single_threaded_no_flush(
            || {
                if sys::close_fds_from_except(3, child.as_fd()).is_err() {
                    return CLOSE_FDS_FAILED_EXIT;
                }
                serve(child, &sink)
            },
            2,
        );
        let pid = match forked {
            Ok(pid) => pid,
            Err(sys::SysError::MultiThreaded) => {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "the audit relay must be started before any thread is created",
                ));
            }
            Err(_) => return Err(unavailable()),
        };
        // 回収前に開く（以後 pid が再利用されても元の子を指す）。
        // 開いた後に未回収の自分の子だと確かめる。SIGCHLD が SIG_IGN／SA_NOCLDWAIT だと fork から
        // pidfd_open までの間に自動回収・PID 再利用が起き得る。確認できなければ helper は既に終了して
        // いる（または自分の子でない）ため、pidfd も数値 pid も保持せず起動失敗にする（どの経路でも
        // 送信・wait しない。fail-closed。回収済みなので回収の後始末は不要。SUP-1・SEC-4・CORE-1）。
        let pidfd = sys::pidfd_open(pid).ok();
        if !is_unreaped_own_child(sys::wait_pid_nohang(pid)) {
            return Err(unavailable());
        }
        Ok(Self {
            state: Mutex::new(State {
                stream: parent,
                broken: false,
            }),
            pid,
            pidfd,
        })
    }

    /// helper の PID。呼び出し元（supervisor）が cgroup の退避で自プロセスと一緒に移す対象として宣言する
    /// （`DelegatedCgroup::with_companions`。helper が委譲 cgroup に残ると退避が拒否される。CORE-3・SUP-1）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// helper を SIGKILL する。どの経路でも、未回収の自分の子と確認できた場合だけ送る
    /// （pidfd があればそれへ、無ければ pid へ。確認できなければ送らない。SUP-1・SEC-4）。
    fn kill_helper(&self) {
        kill_if_unreaped(sys::wait_pid_nohang(self.pid), || match &self.pidfd {
            Some(fd) => sys::pidfd_send_signal(fd.as_fd(), sys::Signal::Kill),
            None => sys::kill_pid(self.pid, sys::Signal::Kill),
        });
    }
}

/// `wait_pid_nohang` の結果が「自分の未回収の子（まだ終わっていない）」を示すか。
/// `ECHILD`（自動回収済み・他人の PID）やその他のエラー、回収済みは false（fail-closed）。
fn is_unreaped_own_child(polled: Result<Option<i32>, sys::SysError>) -> bool {
    matches!(polled, Ok(None))
}

/// 未回収の自分の子と確認できた場合だけ `send` を呼ぶ。呼んだら true。
fn kill_if_unreaped<E>(
    polled: Result<Option<i32>, sys::SysError>,
    send: impl FnOnce() -> Result<(), E>,
) -> bool {
    if !is_unreaped_own_child(polled) {
        return false;
    }
    let _ = send();
    true
}

impl ControlAuditRelay {
    /// helper に記録先（`@audit.log`）を開けるかを期限つきで確かめさせる。記録は 1 件も書かない（SEC-4・REPAIR-5・#2027）。
    ///
    /// 呼び出し元: supervisor の `start`（記録経路を前提に起動してよいかの確認。失敗なら起動を拒否する）。応答が無ければ
    /// [`AuditSink::record`] と同じく helper を SIGKILL して `Timeout`、開けなければ `Internal` を返す。
    pub fn probe(&self) -> Result<(), TraitError> {
        let mut frame = vec![0u8; FIXED_LEN];
        if let Some(tag) = frame.first_mut() {
            *tag = TAG_PROBE;
        }
        self.exchange(&frame)
    }

    /// 枠を helper へ送り、応答を [`RECORD_WAIT_LIMIT`] まで待つ。
    fn exchange(&self, frame: &[u8]) -> Result<(), TraitError> {
        self.exchange_until(frame, None)
    }

    /// [`Self::exchange`] を絶対期限 `deadline`(あれば)へ絞った版(REPAIR-5・SEC-4)。
    ///
    /// ロック取得も期限内で打ち切り(別の記録が helper の応答待ちで保持している間は `try_lock` を
    /// 短い間隔で試す)、取得後に残り時間を再計算する。残りが無ければ送信せず `Timeout`。
    /// 期限なしのときは従来どおり無期限にロックを待ち、応答待ちは [`RECORD_WAIT_LIMIT`] まで。
    fn exchange_until(&self, frame: &[u8], deadline: Option<Instant>) -> Result<(), TraitError> {
        let timed_out = || {
            err(
                ErrorCode::Timeout,
                "the audit record was not delivered within the deadline",
            )
        };
        let mut state = match deadline {
            None => match self.state.lock() {
                Ok(g) => g,
                Err(_) => return Err(err(ErrorCode::Internal, "the audit relay lock is poisoned")),
            },
            Some(d) => loop {
                match self.state.try_lock() {
                    Ok(g) => break g,
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(err(ErrorCode::Internal, "the audit relay lock is poisoned"));
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        let left = d.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return Err(timed_out());
                        }
                        std::thread::sleep(left.min(Duration::from_millis(1)));
                    }
                }
            },
        };
        let limit = match deadline {
            None => RECORD_WAIT_LIMIT,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(timed_out());
                }
                left.min(RECORD_WAIT_LIMIT)
            }
        };
        let limit = limit.max(Duration::from_millis(1));
        if state.broken {
            return Err(err(
                ErrorCode::Unavailable,
                "the audit relay is unavailable",
            ));
        }
        let answer_by = Instant::now() + limit;
        let mut ack = [0u8; 1];
        let sent = state.stream.set_write_timeout(Some(limit)).is_ok()
            && state.stream.write_all(frame).is_ok();
        let remaining = answer_by
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        let answered = sent
            && state.stream.set_read_timeout(Some(remaining)).is_ok()
            && state.stream.read_exact(&mut ack).is_ok();
        if !answered {
            state.broken = true;
            drop(state);
            self.kill_helper();
            return Err(err(
                ErrorCode::Timeout,
                "the audit relay did not answer in time",
            ));
        }
        if ack == [ACK_OK] {
            Ok(())
        } else {
            Err(err(
                ErrorCode::Internal,
                "the audit record was not persisted",
            ))
        }
    }
}

impl AuditSink for ControlAuditRelay {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let frame = encode(record)?;
        self.exchange(&frame)
    }

    fn record_until(&self, record: &AuditRecord, deadline: Instant) -> Result<(), TraitError> {
        if Instant::now() >= deadline {
            return Err(err(
                ErrorCode::Timeout,
                "the audit record was not delivered within the deadline",
            ));
        }
        let frame = encode(record)?;
        self.exchange_until(&frame, Some(deadline))
    }
}

impl Drop for ControlAuditRelay {
    fn drop(&mut self) {
        self.kill_helper();
        let end = Instant::now() + REAP_WAIT;
        while Instant::now() < end {
            if !matches!(sys::wait_pid_nohang(self.pid), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-5・SEC-4: 別の記録がロックを保持している間に短い絶対期限で呼んでも、期限 + 許容差以内に
    /// `Timeout` で戻り、helper へは何も送らない(取得後の再計算と、ロック取得自体の期限打ち切り)。
    #[test]
    fn repair5_sec4_record_until_gives_up_lock_wait_at_deadline() {
        let (parent, mut peer) = UnixStream::pair().unwrap();
        // 非実在の pid(自分の子ではないため Drop の kill は確認で止まる)。
        let relay = std::sync::Arc::new(ControlAuditRelay {
            state: Mutex::new(State {
                stream: parent,
                broken: false,
            }),
            pid: 0x3fff_fff0,
            pidfd: None,
        });
        let holder = std::sync::Arc::clone(&relay);
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let _g = holder.state.lock().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let record = sample(ControlPeerRejection::PeerUidMismatch, None);
        let budget = Duration::from_millis(100);
        let start = Instant::now();
        let e = relay.record_until(&record, start + budget).unwrap_err();
        let took = start.elapsed();
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert!(took >= budget, "{took:?}");
        assert!(took < budget + Duration::from_millis(300), "{took:?}");
        release_tx.send(()).unwrap();
        t.join().unwrap();
        // 何も送っていない(読み出しは即座に WouldBlock/EOF 相当)。
        peer.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 1];
        assert!(peer.read(&mut buf).is_err());
        // 期限切れなら、ロックが空いていても送信しない。
        let e = relay
            .record_until(&record, Instant::now() - Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert!(peer.read(&mut buf).is_err());
    }

    /// SUP-1・SEC-4・CORE-1: 確認できない場合は送信 0 回（pidfd・pid どちらの送信手段でも同じ）。
    #[test]
    fn kill_if_unreaped_unverified_sends_zero_times() {
        let mut sent = 0;
        let r = kill_if_unreaped(Err(sys::SysError::Os(10)), || {
            sent += 1;
            Ok::<(), ()>(())
        });
        assert_eq!((r, sent), (false, 0));
    }

    /// SUP-1・SEC-4: 未回収と確認できない場合（ECHILD・他エラー・回収済み）は送信しない。
    #[test]
    fn kill_if_unreaped_sends_only_for_unreaped_child() {
        let mut sent = 0;
        assert!(kill_if_unreaped(Ok(None), || {
            sent += 1;
            Ok::<(), ()>(())
        }));
        assert_eq!(sent, 1);
        for polled in [
            Ok(Some(0)),
            Err(sys::SysError::Os(10)),
            Err(sys::SysError::Os(22)),
        ] {
            assert!(!kill_if_unreaped(polled, || {
                sent += 1;
                Ok::<(), ()>(())
            }));
        }
        assert_eq!(sent, 1);
    }

    fn sample(rejection: ControlPeerRejection, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            rejection.audit_event(),
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// SEC-4・SUP-1: 枠の往復で時刻・PID・理由・コンテナ ID が一致する。
    #[test]
    fn sec4_frame_round_trips_every_field() {
        for rejection in REJECTIONS {
            for id in [None, Some("web-1")] {
                let rec = sample(rejection, id);
                let back = decode(&encode(&rec).unwrap()).unwrap();
                assert_eq!(back.timestamp(), rec.timestamp());
                assert_eq!(back.pid(), rec.pid());
                assert_eq!(back.container_id(), rec.container_id());
                assert_eq!(
                    encode(&back).unwrap(),
                    encode(&rec).unwrap(),
                    "reason token must survive"
                );
            }
        }
    }

    /// SEC-4: まだ運ばない層（Landlock・PluginTrust・AuditCoverageDegraded）は拒否する。
    #[test]
    fn sec4_other_layers_are_rejected() {
        for event in [
            AuditEvent::Landlock {
                path: AuditPath::new("/x"),
                syscall: None,
            },
            AuditEvent::AuditCoverageDegraded {
                seccomp_kill: None,
                landlock: None,
            },
        ] {
            let rec = AuditRecord::new(
                AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
                AuditPid::new(1).unwrap(),
                event,
            );
            assert_eq!(encode(&rec).unwrap_err().code(), ErrorCode::InvalidArgument);
        }
    }

    fn mount_sample(path: Option<AuditPath>, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 3)),
            AuditPid::new(99).unwrap(),
            AuditEvent::Mount { path, reason: None },
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// REPAIR-2・#2481: `MountHeader` は固定長で往復し、長さ違い・存在フラグ不正・上限超過・矛盾は拒否する。
    #[test]
    fn repair2_2481_mount_header_is_fixed_length_and_validated() {
        let abc = AuditPath::new("/abc");
        let (h, body) = MountHeader::for_path(Some(&abc)).unwrap();
        assert_eq!(body, b"/abc");
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), MOUNT_EXTRA_LEN);
        assert_eq!(MountHeader::parse(&bytes), Some(h));
        assert_eq!(h.body_len(), 4);
        assert!(MountHeader::parse(&bytes[..MOUNT_EXTRA_LEN - 1]).is_none());
        let mut bad = bytes;
        bad[0] = 2;
        assert!(MountHeader::parse(&bad).is_none());
        let mut over = bytes;
        over[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(MountHeader::parse(&over).is_none());
        assert!(h.into_path(b"/ab").is_none());
        let (none, _) = MountHeader::for_path(None).unwrap();
        assert_eq!(none.into_path(b""), Some(None));
    }

    /// SEC-4・#2481: mount（理由なし）の枠はパスのバイト列・切り詰め・元の長さ・ID が往復で一致する。
    #[test]
    fn sec4_2481_mount_frame_round_trips() {
        let non_utf8 = AuditPath::new(OsStr::from_bytes(&[b'/', 0xff, 0xfe, b'\n', b'a']));
        let long = AuditPath::new(&"a".repeat(AUDIT_PATH_MAX_BYTES + 10));
        let exact = AuditPath::new(&"b".repeat(AUDIT_PATH_MAX_BYTES));
        for path in [
            None,
            Some(AuditPath::new("/etc/shadow")),
            Some(AuditPath::new("")),
            Some(non_utf8),
            Some(long),
            Some(exact),
        ] {
            for id in [None, Some("web-1")] {
                let rec = mount_sample(path.clone(), id);
                let frame = encode(&rec).unwrap();
                assert_eq!(extra_len(frame[0]), MOUNT_EXTRA_LEN);
                let back = decode(&frame).unwrap();
                assert_eq!(back.event(), rec.event());
                assert_eq!(back.pid(), rec.pid());
                assert_eq!(back.timestamp(), rec.timestamp());
                assert_eq!(back.container_id(), rec.container_id());
            }
        }
        let long = AuditPath::new(&"a".repeat(AUDIT_PATH_MAX_BYTES + 10));
        let back = decode(&encode(&mount_sample(Some(long), None)).unwrap()).unwrap();
        let AuditEvent::Mount { path: Some(p), .. } = back.event() else {
            panic!("mount with a path");
        };
        assert!(p.is_truncated());
        assert_eq!(p.original_len(), AUDIT_PATH_MAX_BYTES + 10);
    }

    /// REPAIR-2・#2481: mount の壊れた枠（本体の不足・余り・長さ上限超過・存在フラグ不正・元の長さの矛盾）は記録にしない。
    #[test]
    fn repair2_2481_malformed_mount_frames_are_not_decoded() {
        let good = encode(&mount_sample(Some(AuditPath::new("/abc")), Some("ab"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let at = FIXED_LEN + 2;
        let mut huge = good.clone();
        huge[at + 1..at + 3].copy_from_slice(&5000u16.to_be_bytes());
        assert!(decode(&huge).is_none());
        let mut bad_present = good.clone();
        bad_present[at] = 2;
        assert!(decode(&bad_present).is_none());
        let mut shorter_original = good.clone();
        shorter_original[at + 3..at + 11].copy_from_slice(&3u64.to_be_bytes());
        assert!(decode(&shorter_original).is_none());
        let mut bigger_original = good.clone();
        bigger_original[at + 3..at + 11].copy_from_slice(&9u64.to_be_bytes());
        assert!(decode(&bigger_original).is_none());
        let none = encode(&mount_sample(None, None)).unwrap();
        assert!(decode(&none).is_some());
        let mut none_with_len = none;
        none_with_len[FIXED_LEN + 1..FIXED_LEN + 3].copy_from_slice(&1u16.to_be_bytes());
        none_with_len.push(b'x');
        assert!(decode(&none_with_len).is_none());
    }

    fn reason_sample(
        path: Option<AuditPath>,
        reason: &'static str,
        id: Option<&str>,
    ) -> AuditRecord {
        let mut rec = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(5, 6)),
            AuditPid::new(7).unwrap(),
            AuditEvent::Mount {
                path,
                reason: Some(super::super::AuditReason::new(reason)),
            },
        );
        if let Some(id) = id {
            rec = rec.with_container_id(ContainerId::new(id).unwrap());
        }
        rec
    }

    /// SEC-4・#2623: 閉じた表の理由つき mount は枠を往復し、理由・ID・PID が一致する。
    #[test]
    fn sec4_2623_mount_with_closed_reason_round_trips() {
        for r in MOUNT_REASONS {
            for path in [None, Some(AuditPath::new("/a/b"))] {
                let rec = reason_sample(path.clone(), r.as_str(), Some("c1"));
                let frame = encode(&rec).unwrap();
                assert_eq!(frame[0], TAG_MOUNT_REASON);
                assert_eq!(extra_len(frame[0]), MOUNT_REASON_EXTRA_LEN);
                let back = decode(&frame).unwrap();
                assert_eq!(back.container_id().unwrap().as_str(), "c1");
                assert_eq!(back.pid().get(), 7);
                match back.event() {
                    AuditEvent::Mount {
                        path: p,
                        reason: Some(reason),
                    } => {
                        assert_eq!(reason.as_str(), r.as_str());
                        assert_eq!(
                            p.as_ref().map(AuditPath::as_path),
                            path.as_ref().map(AuditPath::as_path)
                        );
                    }
                    other => panic!("unexpected event: {other:?}"),
                }
            }
        }
    }

    /// SEC-4・#2623: 表に無い理由の mount は運ばない（静的トークンを復号側で戻せない）。
    #[test]
    fn sec4_2623_mount_with_reason_outside_table_is_rejected() {
        for reason in ["x", "rootfs_is_host_root", "path_not_absolute"] {
            let rec = reason_sample(None, reason, None);
            assert_eq!(encode(&rec).unwrap_err().code(), ErrorCode::InvalidArgument);
        }
    }

    /// REPAIR-2・#2623: 範囲外の添字・長さの食い違いは復号しない（記録を捏造しない）。
    #[test]
    fn repair2_2623_malformed_mount_reason_frames_are_not_decoded() {
        let rec = reason_sample(None, MOUNT_REASONS[0].as_str(), Some("c1"));
        let frame = encode(&rec).unwrap();
        let idx_at = FIXED_LEN + 2;
        let mut bad_index = frame.clone();
        bad_index[idx_at] = u8::try_from(MOUNT_REASONS.len()).unwrap();
        assert!(decode(&bad_index).is_none());
        let mut extra = frame.clone();
        extra.push(b'x');
        assert!(decode(&extra).is_none());
        assert!(decode(&frame[..frame.len() - 1]).is_none());
        assert!(decode(&frame).is_some());
    }

    /// 表の一貫性: 各理由は exec worker の写像でパスなしの理由つき Mount になる（start の記録と同じ写像）。
    #[test]
    fn sec4_2623_reason_table_matches_exec_worker_mapping() {
        for r in MOUNT_REASONS {
            match r.exec_worker_audit_event() {
                Some(AuditEvent::Mount {
                    path: None,
                    reason: Some(x),
                }) => assert_eq!(x.as_str(), r.as_str()),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    fn seccomp_sample(nr: i32, arch: u32, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 7)),
            AuditPid::new(77).unwrap(),
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::from_seccomp_data_nr(nr),
                arch: AuditSyscallArch::from_raw(arch),
            },
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// SEC-4・#2025: seccomp の枠は番号・arch・PID・コンテナ ID が往復で一致する（負の番号のビット列も保つ）。
    #[test]
    fn sec4_2025_seccomp_frame_round_trips() {
        for (nr, arch, id) in [
            (312, 0xC000_003E, Some("web-1")),
            (272, 0xC000_00B7, None),
            (-1, 0xDEAD_BEEF, Some("a")),
        ] {
            let rec = seccomp_sample(nr, arch, id);
            let frame = encode(&rec).unwrap();
            assert_eq!(
                frame.len(),
                FIXED_LEN + id.map_or(0, str::len) + SECCOMP_EXTRA_LEN
            );
            let back = decode(&frame).unwrap();
            assert_eq!(
                back.syscall().map(AuditSyscallNr::get),
                Some(nr.cast_unsigned())
            );
            assert_eq!(back.seccomp_arch().map(AuditSyscallArch::get), Some(arch));
            assert_eq!(back.pid(), rec.pid());
            assert_eq!(back.timestamp(), rec.timestamp());
            assert_eq!(back.container_id(), rec.container_id());
        }
    }

    /// REPAIR-2・#2025: seccomp の壊れた枠（追加部の不足・余り・ID 長の不一致）は記録にしない。
    #[test]
    fn repair2_2025_malformed_seccomp_frames_are_not_decoded() {
        let good = encode(&seccomp_sample(312, 0xC000_003E, Some("ab"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let mut wrong_len = good;
        wrong_len[17] = 3;
        assert!(decode(&wrong_len).is_none());
    }

    /// REPAIR-2: 壊れた枠（短い・未知の理由・不正な時刻・PID 0）は記録にしない。
    #[test]
    fn repair2_malformed_frames_are_not_decoded() {
        let good = encode(&sample(ControlPeerRejection::PeerUidMismatch, Some("a"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        assert!(decode(&[]).is_none());
        let mut bad_tag = good.clone();
        bad_tag[0] = 9;
        assert!(decode(&bad_tag).is_none());
        let mut bad_nanos = good.clone();
        bad_nanos[9..13].copy_from_slice(&1_000_000_000u32.to_be_bytes());
        assert!(decode(&bad_nanos).is_none());
        let mut zero_pid = good;
        zero_pid[13..17].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode(&zero_pid).is_none());
    }

    /// SEC-4・ERR-4・REPAIR-3・#3209: 段つきの記録を中継の枠へ通すと段は落ちる（枠は段の有無でバイト同一で、
    /// 復号後の記録は段なし・他の値は一致）。拒否ではなく落とすのは、記録そのものを失わないため。
    #[test]
    fn sec4_err4_3209_stage_is_dropped_by_relay_frame() {
        use super::super::AuditStage;
        use crate::exec::IsolationStage;
        let stage = AuditStage::from(IsolationStage::MountBinds);
        let mut records = vec![
            sample(ControlPeerRejection::PeerUidMismatch, Some("c1")),
            exit_signal_sample(31, 4321, Some("c1")),
            mount_sample(Some(AuditPath::new("/a/b")), Some("c1")),
            plugin_peer_sample(PLUGIN_PEER_REJECTIONS[0], "/run/p/cri.sock"),
            reason_sample(None, MOUNT_REASONS[0].as_str(), Some("c1")),
            reason_sample(
                Some(AuditPath::new("/a")),
                MOUNT_REASONS[1].as_str(),
                Some("c1"),
            ),
            seccomp_sample(165, 0xC000_003E, Some("c1")),
        ];
        assert_eq!(records.len(), 7);
        for plain in records.drain(..) {
            let staged = plain.clone().with_stage(stage);
            assert_eq!(staged.stage(), Some(stage));
            let frame = encode(&staged).unwrap();
            assert_eq!(
                frame,
                encode(&plain).unwrap(),
                "frame must not carry the stage"
            );
            let back = decode(&frame).unwrap();
            assert_eq!(back.stage(), None);
            assert_eq!(back.event(), plain.event());
            assert_eq!(back.timestamp(), plain.timestamp());
            assert_eq!(back.pid(), plain.pid());
            assert_eq!(back.container_id(), plain.container_id());
        }
    }

    fn exit_signal_sample(signal: i32, target: i32, id: Option<&str>) -> AuditRecord {
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 9)),
            AuditPid::new(55).unwrap(),
            AuditEvent::ExitSignal {
                signal: AuditSignal::new(signal).unwrap(),
                target_pid: AuditPid::new(target).unwrap(),
            },
        );
        match id {
            Some(id) => r.with_container_id(ContainerId::new(id).unwrap()),
            None => r,
        }
    }

    /// SEC-4・NET-9・PLUG-11・#3330: pasta_verify の枠は理由・コンテナ ID・PID・時刻が往復で一致し、
    /// 壊れた枠(不足・余り・未知の理由の添字)は記録にしない。
    #[test]
    fn sec4_3330_pasta_verify_frame_round_trips() {
        for (rejection, token) in [
            (
                super::super::PastaVerifyRejection::RecordChanged,
                "pasta_record_changed",
            ),
            (
                super::super::PastaVerifyRejection::PermissionDenied,
                "pasta_permission_denied",
            ),
        ] {
            let rec = AuditRecord::new(
                AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 7)),
                AuditPid::new(77).unwrap(),
                rejection.audit_event(),
            )
            .with_container_id(ContainerId::new("web-1").unwrap());
            let frame = encode(&rec).unwrap();
            assert_eq!(frame.len(), FIXED_LEN + 5 + PASTA_VERIFY_EXTRA_LEN);
            assert_eq!(extra_len(frame[0]), PASTA_VERIFY_EXTRA_LEN);
            let back = decode(&frame).unwrap();
            assert_eq!(
                back.reason().map(super::super::AuditReason::as_str),
                Some(token)
            );
            assert_eq!(back.pid(), rec.pid());
            assert_eq!(back.timestamp(), rec.timestamp());
            assert_eq!(back.container_id(), rec.container_id());
            assert!(decode(&frame[..frame.len() - 1]).is_none());
            let mut longer = frame.clone();
            longer.push(0);
            assert!(decode(&longer).is_none());
            let mut unknown = frame.clone();
            *unknown.last_mut().unwrap() = 2;
            assert!(decode(&unknown).is_none());
        }
    }

    /// SEC-4・ESC-06・#2236: exit_signal の枠は signal・target_pid・PID・時刻・コンテナ ID が往復で一致する。
    #[test]
    fn sec4_2236_exit_signal_frame_round_trips() {
        for (signal, target, id) in [
            (31, 4321, Some("web-1")),
            (1, 1, None),
            (64, i32::MAX, Some("a")),
        ] {
            let rec = exit_signal_sample(signal, target, id);
            let frame = encode(&rec).unwrap();
            assert_eq!(
                frame.len(),
                FIXED_LEN + id.map_or(0, str::len) + EXIT_SIGNAL_EXTRA_LEN
            );
            assert_eq!(extra_len(frame[0]), EXIT_SIGNAL_EXTRA_LEN);
            let back = decode(&frame).unwrap();
            assert_eq!(back.exit_signal().map(AuditSignal::get), Some(signal as u8));
            assert_eq!(back.target_pid().map(AuditPid::get), Some(target as u32));
            assert_eq!(back.pid(), rec.pid());
            assert_eq!(back.timestamp(), rec.timestamp());
            assert_eq!(back.container_id(), rec.container_id());
        }
    }

    /// REPAIR-2・#2236: exit_signal の壊れた枠（不足・余り・signal 0 / 65・target_pid 0・ID 長の不一致）は記録にしない。
    #[test]
    fn repair2_2236_malformed_exit_signal_frames_are_not_decoded() {
        let good = encode(&exit_signal_sample(31, 4321, Some("ab"))).unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let sig_at = FIXED_LEN + 2;
        for bad in [0u8, 65, 255] {
            let mut f = good.clone();
            f[sig_at] = bad;
            assert!(decode(&f).is_none(), "signal {bad}");
        }
        let mut zero_target = good.clone();
        zero_target[sig_at + 1..sig_at + 5].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode(&zero_target).is_none());
        let mut huge_target = good.clone();
        huge_target[sig_at + 1..sig_at + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&huge_target).is_none());
        let mut wrong_len = good;
        wrong_len[17] = 3;
        assert!(decode(&wrong_len).is_none());
    }

    fn plugin_peer_sample(rejection: PluginPeerRejection, path: &str) -> AuditRecord {
        AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            rejection.audit_event(std::path::Path::new(path)),
        )
    }

    /// SEC-4・PLUG-12・#2484: plugin_peer の枠は理由 5 種・パス（切り詰めと元の長さを含む）が往復で一致する。
    #[test]
    fn sec4_2484_plugin_peer_frame_round_trips() {
        let long = format!("/{}", "a".repeat(AUDIT_PATH_MAX_BYTES + 10));
        for rejection in PLUGIN_PEER_REJECTIONS {
            for path in ["/run/p/cri.sock", long.as_str()] {
                let rec = plugin_peer_sample(rejection, path);
                let frame = encode(&rec).unwrap();
                assert_eq!(frame[0], TAG_PLUGIN_PEER);
                assert_eq!(extra_len(frame[0]), PLUGIN_PEER_EXTRA_LEN);
                let back = decode(&frame).unwrap();
                assert_eq!(back.event(), rec.event());
                assert_eq!(back.pid(), rec.pid());
                assert_eq!(back.timestamp(), rec.timestamp());
                assert_eq!(back.container_id(), None);
                assert_eq!(back.reason().unwrap().as_str(), rejection.as_str());
            }
        }
        let back =
            decode(&encode(&plugin_peer_sample(PluginPeerRejection::Unknown, &long)).unwrap())
                .unwrap();
        let AuditEvent::PluginPeer { path, .. } = back.event() else {
            panic!("plugin_peer");
        };
        assert!(path.is_truncated());
        assert_eq!(path.original_len(), AUDIT_PATH_MAX_BYTES + 11);
    }

    /// REPAIR-2・#2484: plugin_peer の壊れた枠（未知の理由添字・パスなし・本体の不足と余り）は記録にしない。
    #[test]
    fn repair2_2484_malformed_plugin_peer_frames_are_not_decoded() {
        let good = encode(&plugin_peer_sample(
            PluginPeerRejection::PeerUidMismatch,
            "/s.sock",
        ))
        .unwrap();
        assert!(decode(&good).is_some());
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        let mut bad_reason = good.clone();
        bad_reason[FIXED_LEN] = 5;
        assert!(decode(&bad_reason).is_none());
        let mut absent = good;
        absent[FIXED_LEN + 1] = 0;
        assert!(decode(&absent).is_none());
    }
}
