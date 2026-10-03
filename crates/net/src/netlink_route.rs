//! `NETLINK_ROUTE` 側の入口モジュール（TASK-136・NET-11・MS-8）。
//!
//! ファミリ非依存の nlmsghdr / rtattr コーデック（`crate::netlink`。TASK-136.1・#298）を再公開し、
//! Linux では `NETLINK_ROUTE` ソケットの open / bind / send / recv（[`NetlinkRouteSocket`]。
//! TASK-136.2.1・#843）を提供する。各操作の成功 / 失敗と所要時間は `crate::instrument` の
//! `NetOpRecorder` へ渡す（REPAIR-4）。
//!
//! さらに要求 1 件の往復として、seq 採番（`SeqAllocator`）・`NLMSG_ERROR` の復号
//! （[`decode_nlmsgerr`]）・seq 一致の ACK / エラー判定・全体期限つきの応答待ち
//! （`NetlinkRouteSocket::request`。Linux のみ。TASK-136.2.2・#844・REPAIR-5）を提供する。
//! bridge・veth の作成メッセージ（`RTM_NEWLINK`。[`LinkCreate`]。TASK-136.3.1・#845）も組み立てる。
//! link 作成・設定の送信ラッパー（`NetlinkRouteSocket::create_link` / `set_link`。`RTM_SETLINK` の
//! netns 移動・up は [`LinkSet`]。TASK-136.3.2・#846）も提供する。address / route 操作（`addr_route` モジュール。
//! `AddressSpec`・`RouteSpec`・`add_address`・`add_route`。TASK-136.4・#301）も本層の上に載る。
//! 自ソケットの `nl_pid` を bind 直後に `getsockname` で取得し（[`NetlinkRouteSocket::local_pid`]）、
//! `request` は応答の `nlmsg_pid` が自ソケットと一致しないメッセージを破棄する（#1313。多層防御）。
//! 実機前提の結合テスト（`tests/link_netns_privileged.rs`・`tests/netlink_route_addr_route.rs`。
//! TASK-136.5・#302）と既定集合からの分離方式は `AGENTS.md`「実機前提テスト」節を参照。
//!
//! # 拡張 ACK（NET-11・REPAIR-4）
//!
//! route ソケットは open 時に `NETLINK_EXT_ACK` と `NETLINK_CAP_ACK` を有効にする（どちらも失敗したら
//! 無視して従来どおり errno だけで動く）。`CAP_ACK` を使う理由は、既定ではエラー応答が要求全体を写して
//! 返すため、上限（1 MiB）近い要求が失敗すると応答が受信上限を超えて破棄され、本当の errno が
//! `Timeout` に化けるのを避けるため。`NLMSGERR_ATTR_OFFS` は要求先頭からのオフセットで、要求は
//! 呼び出し側が持っているので写しがなくても失う情報はない。
//! 拡張 ACK の文字列はカーネル由来の外部入力として長さを制限し、印字可能な ASCII 以外を除いて
//! エラーの `message` に載せる（[`decode_nlmsgerr_with_flags`]）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - netfilter ソケット（`NETLINK_NETFILTER`）での拡張 ACK の有効化・解釈。拡張 ACK は route ソケットだけで
//!   有効にする（`nftables_batch` が受け取るバイト列を変えないため）
//! - 拡張 ACK のうち `NLMSGERR_ATTR_COOKIE`・`POLICY`・`MISS_TYPE` / `MISS_NEST` の解釈（読み飛ばす）
//! - dump 中断（`NLM_F_DUMP_INTR`）の自動再試行（検出して `FailedPrecondition` で返すのみ）、複数スレッドでの seq 別の待機者振り分け（往復は 1 件ずつ直列化する）
//! - link の down・削除・属性変更の送信ラッパー。address / route の未実装範囲は `addr_route` の doc を参照

use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{NetError, NetErrorCode};

pub use crate::netlink::*;

mod addr_route;
pub use addr_route::*;
mod link;
pub use link::*;

/// 要求の `nlmsg_seq` を採番する（NET-11・TASK-136.2.2）。
///
/// 1 始まりで加算し、0 は飛ばす（0 はカーネル発の非要求メッセージの seq のため、要求に使うと
/// 応答と取り違える）。`u32` を一周したら 1 へ戻る。ソケットごとに 1 つ持てば足りる
/// （port ID がソケットごとに一意で、応答は送信元ソケットにだけ届く）。
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct SeqAllocator(AtomicU32);

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl SeqAllocator {
    /// 次の採番が 1 になる採番器を作る。
    pub(crate) fn new() -> Self {
        Self(AtomicU32::new(1))
    }

    /// 次の seq（非 0）を返す。
    pub(crate) fn next(&self) -> u32 {
        loop {
            let v = self.0.fetch_add(1, Ordering::Relaxed);
            if v != 0 {
                return v;
            }
        }
    }

    #[cfg(test)]
    fn starting_at(first: u32) -> Self {
        Self(AtomicU32::new(first))
    }
}

/// 拡張 ACK の文字列（`NLMSGERR_ATTR_MSG`）の最大バイト数。カーネルの書式つきメッセージは
/// `NETLINK_MAX_FMTMSG_LEN`（80）で静的メッセージも短いため、それより余裕のある値で打ち切る。
const MAX_EXT_ACK_MESSAGE_LEN: usize = 128;

/// `NLMSG_ERROR` ペイロード（`struct nlmsgerr`）の復号結果（NET-11・ERR-1）。
///
/// `errno == 0` は ACK、それ以外はカーネルが返した失敗（正の errno）。拡張 ACK
/// （`NETLINK_EXT_ACK`。[`decode_nlmsgerr_with_flags`]）が付いていれば、失敗理由の文字列と
/// 問題の属性のオフセットも持つ。フィールドは非公開でアクセサ経由にする。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlAck {
    errno: i32,
    request_seq: Option<u32>,
    ext_message: Option<String>,
    ext_offset: Option<u32>,
}

impl NlAck {
    /// 正の errno（0 は ACK）。
    pub fn errno(&self) -> i32 {
        self.errno
    }

    /// ACK（成功応答）か。
    pub fn is_ack(&self) -> bool {
        self.errno == 0
    }

    /// ペイロードに埋め込まれた元要求ヘッダの `nlmsg_seq`。`NETLINK_CAP_ACK` 等で切り詰められて
    /// いれば `None`。
    pub fn request_seq(&self) -> Option<u32> {
        self.request_seq
    }

    /// 拡張 ACK の失敗理由（サニタイズ済み。ASCII の印字可能文字のみ・最大 128 バイト + `...`）。
    pub fn ext_message(&self) -> Option<&str> {
        self.ext_message.as_deref()
    }

    /// 拡張 ACK の、問題のある属性の元要求先頭からのオフセット。
    pub fn ext_offset(&self) -> Option<u32> {
        self.ext_offset
    }

    /// 失敗時の `NetError` の `message`（英語）。拡張 ACK がなければ従来と同一の
    /// `netlink request failed: errno N`。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn failure_message(&self) -> String {
        let mut m = format!("netlink request failed: errno {}", self.errno);
        if let Some(text) = &self.ext_message {
            m.push_str(": ");
            m.push_str(text);
        }
        if let Some(off) = self.ext_offset {
            m.push_str(&format!(" (at offset {off})"));
        }
        m
    }
}

/// `NLMSG_ERROR` メッセージのペイロードを復号する（拡張 ACK は解釈しない。
/// [`decode_nlmsgerr_with_flags`] に `flags = 0` を渡すのと同じ）。
pub fn decode_nlmsgerr(payload: &[u8]) -> Result<NlAck, NetError> {
    decode_nlmsgerr_with_flags(0, payload)
}

/// `NLMSG_ERROR` メッセージのペイロードを復号する（カーネル応答は外部入力として検証する）。
///
/// 先頭 4 バイトの `error`（ホストバイトオーダーの `i32`）が 0 なら ACK、負なら `-errno` の失敗。
/// 4 バイト未満・正値・`i32::MIN` はプロトコル違反として `DataLoss`。後続の元要求ヘッダ
/// （16 バイト）が揃っていれば、その `nlmsg_seq` を `request_seq` に返す。
///
/// `flags` は受信した nlmsghdr の `nlmsg_flags`。`NLM_F_ACK_TLVS` が立っていれば、ペイロード末尾の
/// 拡張 ACK 属性から `NLMSGERR_ATTR_MSG`（文字列）と `NLMSGERR_ATTR_OFFS`（オフセット）を取り出す。
/// `NLM_F_CAPPED` ならペイロードは 20 バイト（error + 元ヘッダ）で終わり、そうでなければ元要求の
/// 全体（4 バイト境界に切り上げ）の後ろから属性が始まる。拡張部分は診断情報なので best effort で、
/// 壊れていれば全体を捨てて errno だけを返す（エラー判定は変えない。REPAIR-2）。
/// `NLM_F_CAPPED` / `NLM_F_ACK_TLVS` は他のフラグと同じビットなので、呼び出し側は
/// `NLMSG_ERROR` のメッセージにだけ渡すこと。COOKIE・POLICY・MISS_* は未解釈（REPAIR-3）。
pub fn decode_nlmsgerr_with_flags(flags: u16, payload: &[u8]) -> Result<NlAck, NetError> {
    let bad = |msg: &str| NetError::new(NetErrorCode::DataLoss, msg.to_string());
    let head: [u8; 4] = payload
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("nlmsgerr payload shorter than 4 bytes"))?;
    let raw = i32::from_ne_bytes(head);
    let errno = if raw == 0 {
        0
    } else if raw < 0 {
        raw.checked_neg()
            .ok_or_else(|| bad("nlmsgerr error value out of range"))?
    } else {
        return Err(bad("nlmsgerr carries a positive error value"));
    };
    // 元要求ヘッダは payload[4..20]。nlmsg_seq はその先頭から 8..12 バイト目（payload[12..16]）。
    // ヘッダ 16 バイトが揃っていない（切り詰められた）場合は None。
    // 5..=19 バイトは「ACK の 4 バイトでも、元要求ヘッダまで揃った形でもない」中途半端な長さで、
    // 切り詰めと区別できない破損なので DataLoss とする。
    if payload.len() > 4 && payload.len() < 4 + NLMSG_HEADER_LEN {
        return Err(bad("nlmsgerr payload has a partial original header"));
    }
    let request_seq = if payload.len() >= 4 + NLMSG_HEADER_LEN {
        payload
            .get(12..16)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_ne_bytes)
    } else {
        None
    };
    let (ext_message, ext_offset) = if flags & NLM_F_ACK_TLVS != 0 {
        decode_ext_ack(flags, payload).unwrap_or((None, None))
    } else {
        (None, None)
    };
    Ok(NlAck {
        errno,
        request_seq,
        ext_message,
        ext_offset,
    })
}

/// 拡張 ACK の属性領域を解釈する。領域の位置が決まらない・属性が壊れている場合は `None`
/// （呼び出し側が拡張部分全体を捨てる）。
fn decode_ext_ack(flags: u16, payload: &[u8]) -> Option<(Option<String>, Option<u32>)> {
    let start = if flags & NLM_F_CAPPED != 0 {
        4 + NLMSG_HEADER_LEN
    } else {
        // 元要求の nlmsg_len（payload[4..8]）は外部入力。範囲と桁あふれを検証してから使う。
        let orig_len =
            usize::try_from(u32::from_ne_bytes(payload.get(4..8)?.try_into().ok()?)).ok()?;
        if orig_len < NLMSG_HEADER_LEN {
            return None;
        }
        let aligned = orig_len.checked_add(ALIGN_TO - 1)? & !(ALIGN_TO - 1);
        4usize.checked_add(aligned)?
    };
    let tlvs = payload.get(start..)?;
    let mut message = None;
    let mut offset = None;
    for attr in AttrIter::new(tlvs) {
        let attr = attr.ok()?;
        match attr.attr_type() {
            NLMSGERR_ATTR_MSG if message.is_none() => {
                message = sanitize_ext_ack_message(attr.payload());
            }
            NLMSGERR_ATTR_OFFS if offset.is_none() => {
                offset = <[u8; 4]>::try_from(attr.payload())
                    .ok()
                    .map(u32::from_ne_bytes);
            }
            _ => {}
        }
    }
    Some((message, offset))
}

/// カーネル由来の文字列を `message` に載せられる形にする（ログ注入・表示の乱れ・巨大化の防止）。
///
/// 最初の NUL で切り、128 バイトを超える分は捨てて末尾に `...` を付ける。ASCII の印字可能文字
/// （0x20..=0x7E）以外は 1 バイトにつき `?` に置き換える。空白だけ・空なら `None`。
fn sanitize_ext_ack_message(raw: &[u8]) -> Option<String> {
    let text = raw.split(|&b| b == 0).next().unwrap_or_default();
    let truncated = text.len() > MAX_EXT_ACK_MESSAGE_LEN;
    let mut out: String = text
        .iter()
        .take(MAX_EXT_ACK_MESSAGE_LEN)
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '?'
            }
        })
        .collect();
    if out.trim().is_empty() {
        return None;
    }
    if truncated {
        out.push_str("...");
    }
    Some(out)
}

#[cfg(target_os = "linux")]
pub use socket::{
    MAX_RECV_DATAGRAM_LEN, MAX_REPLY_BYTES, MAX_REPLY_MESSAGES, NetlinkReply, NetlinkReplyMessage,
    NetlinkRouteSocket, RECV_BUFFER_LEN,
};

#[cfg(target_os = "linux")]
pub(crate) use socket::{RequestGate, classify_errno};

#[cfg(target_os = "linux")]
mod socket {
    use std::fmt;
    use std::num::NonZeroU32;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::sync::{Arc, Condvar, Mutex, PoisonError};
    use std::time::Duration;

    use super::{SeqAllocator, decode_nlmsgerr_with_flags};
    use crate::error::{NetError, NetErrorCode};
    use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};
    use crate::netlink::{
        ALIGN_TO, MAX_MESSAGE_LEN, NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_MATCH, NLM_F_REQUEST,
        NLM_F_ROOT, NLMSG_DONE, NLMSG_ERROR, NLMSG_HEADER_LEN, NLMSG_NOOP, NLMSG_OVERRUN,
        NlMsgBuilder, NlMsgHeader, NlMsgIter,
    };
    use crate::netlink_route::{LinkCreate, LinkSet};
    use crate::nftables_batch::{MAX_BATCH_LEN, NftBatchBytes};
    use crate::sys::{self, Deadline, Readiness, RecvMeta, SysError};

    /// 受信バッファの通常の長さ（バイト）。これ以下のデータグラムはこの長さのバッファで受ける
    /// （カーネルは dump 応答の 1 データグラムを受信側のバッファ長に合わせて詰めるため、小さく
    /// しすぎない）。これを超えるデータグラムは実長に合わせて [`MAX_RECV_DATAGRAM_LEN`] まで広げる。
    pub const RECV_BUFFER_LEN: usize = 32 * 1024;

    /// 受信する 1 データグラムの上限長（バイト）。コーデックの `MAX_MESSAGE_LEN` と同じ 1 MiB。
    /// カーネルが申告した実長をこの値で検証してから確保するため、無制限には確保しない。
    pub const MAX_RECV_DATAGRAM_LEN: usize = MAX_MESSAGE_LEN as usize;

    const _: () = assert!(RECV_BUFFER_LEN <= MAX_RECV_DATAGRAM_LEN);

    /// 1 回の往復で収集する応答ペイロードの合計上限（バイト）。無制限の確保（DoS）を防ぐ暫定値で、
    /// spec に根拠値はない（REPAIR-3。実運用の dump 規模が分かった時点で見直す）。
    pub const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;

    /// 1 回の往復で収集する応答メッセージ件数の上限。ペイロードが空のメッセージが続いても
    /// `Vec` が増え続けないようにする暫定値（REPAIR-3。根拠値は spec にない）。
    pub const MAX_REPLY_MESSAGES: usize = 262_144;

    /// 往復の応答に含まれる 1 メッセージ（ACK / DONE / NOOP を除く）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NetlinkReplyMessage {
        msg_type: u16,
        flags: u16,
        payload: Vec<u8>,
    }

    impl NetlinkReplyMessage {
        /// `nlmsg_type`（`RTM_NEWLINK` 等）。
        pub fn msg_type(&self) -> u16 {
            self.msg_type
        }

        /// `nlmsg_flags`。
        pub fn flags(&self) -> u16 {
            self.flags
        }

        /// ヘッダを除いたペイロード（ファミリ固有ヘッダ + 属性）。
        pub fn payload(&self) -> &[u8] {
            &self.payload
        }
    }

    /// 成功した往復の結果（NET-11）。ACK のみの操作では `messages` は空。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NetlinkReply {
        seq: u32,
        messages: Vec<NetlinkReplyMessage>,
    }

    impl NetlinkReply {
        /// この往復で採番して送った `nlmsg_seq`（応答の seq と一致済み）。
        pub fn seq(&self) -> u32 {
            self.seq
        }

        /// ACK / DONE を除く応答メッセージ（到着順）。
        pub fn messages(&self) -> &[NetlinkReplyMessage] {
            &self.messages
        }
    }

    /// 同一ソケット上の往復を 1 件ずつに直列化する門（REPAIR-5）。
    ///
    /// 往復が並行すると互いの応答を seq 不一致として破棄し合うため必要。順番待ちも往復全体の
    /// [`Deadline`] に含め、無期限には待たない。
    #[derive(Debug, Default)]
    pub(crate) struct RequestGate {
        busy: Mutex<bool>,
        released: Condvar,
    }

    /// [`RequestGate`] の保持中を表す。Drop で解放して次の待機者を起こす。
    pub(crate) struct GateGuard<'a>(&'a RequestGate);

    impl RequestGate {
        pub(crate) fn acquire(
            &self,
            deadline: &Deadline,
            total: Duration,
        ) -> Result<GateGuard<'_>, NetError> {
            let mut busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                let remaining = deadline.remaining();
                // 門が空いていても期限切れなら取得しない（期限後に要求を送らない）。
                if remaining.is_zero() {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        format!(
                            "netlink request not started within {} ms (gate wait)",
                            total.as_millis()
                        ),
                    ));
                }
                if !*busy {
                    break;
                }
                // 巨大な timeout で内部の期限計算があふれないよう 1 回の待機を区切り、残り時間で再計算する。
                let (g, _) = self
                    .released
                    .wait_timeout(busy, remaining.min(Duration::from_secs(3600)))
                    .unwrap_or_else(PoisonError::into_inner);
                busy = g;
            }
            *busy = true;
            Ok(GateGuard(self))
        }
    }

    impl Drop for GateGuard<'_> {
        fn drop(&mut self) {
            *self.0.busy.lock().unwrap_or_else(PoisonError::into_inner) = false;
            self.0.released.notify_one();
        }
    }

    /// bind 済みの `NETLINK_ROUTE` ソケット（NET-11）。
    ///
    /// 未 bind の状態を表現できない（[`open`](Self::open) が open と bind をまとめて行う）。
    /// `nl_pid` はカーネル採番・マルチキャスト購読なし。fd は `SOCK_CLOEXEC` で、Drop で閉じる。
    /// 通常は [`request`](Self::request)（seq 採番・ACK / エラー判定・全体期限つきの往復。#844）を
    /// 使う。生の `send` / `recv` は `NlMsgBuilder` で組んだバイト列の送受信だけを行い、seq 照合は
    /// しない。採番された自ソケットの `nl_pid` は [`local_pid`](Self::local_pid) で取得できる（#1313）。
    ///
    /// `Send + Sync` で、`&self` のまま複数スレッドから呼べる。`request` は内部で 1 件ずつに直列化
    /// する。`request` の最中に別スレッドが生の `recv` を呼ぶと応答を横取りしうるため、同じ
    /// ソケットで `request` と生の `recv` を併用しないこと。
    ///
    /// open / send / recv は 1 回ごとに結果と所要時間を [`NetOpRecorder`] へ渡す（REPAIR-4）。
    pub struct NetlinkRouteSocket {
        fd: OwnedFd,
        /// 「先頭データグラムの長さ確認 → 取り出し」を 1 つの読み手にまとめるためのロック。
        /// 保持するのは待たない syscall（`MSG_DONTWAIT`）の間だけで、`poll` の待機中は保持しない。
        recv_lock: Mutex<()>,
        recorder: Arc<dyn NetOpRecorder>,
        /// `request` の seq 採番器（ソケット単位）。
        seq: SeqAllocator,
        /// bind 後に `getsockname` で得たカーネル採番の `nl_pid`（0 は open 失敗にするため非 0 型）。
        local_pid: NonZeroU32,
        /// `request` の直列化。
        gate: RequestGate,
        /// open 時に有効にできた ACK オプション（拡張 ACK。NET-11）。
        ack_options: AckOptions,
    }

    /// open 時に有効にできた ACK オプション。失敗しても open は成功し、その項目が `false` になる。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct AckOptions {
        /// `NETLINK_EXT_ACK`（失敗理由・オフセットの TLV を受け取る）。
        pub ext_ack: bool,
        /// `NETLINK_CAP_ACK`（エラー応答が元要求の本体を写さない）。
        pub cap_ack: bool,
    }

    /// [`enable_ack_options`] が設定するオプションの種別。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum AckOpt {
        ExtAck,
        CapAck,
    }

    /// 拡張 ACK 関連のソケットオプションを有効にする。診断情報のためのオプションなので、
    /// 失敗（古いカーネル等）は無視して `false` を記録するだけで、エラーにしない。
    /// `set` を差し替えられるのは失敗経路を実カーネルなしで試すため。
    pub(crate) fn enable_ack_options(
        fd: BorrowedFd<'_>,
        set: impl Fn(BorrowedFd<'_>, AckOpt) -> Result<(), SysError>,
    ) -> AckOptions {
        AckOptions {
            ext_ack: set(fd, AckOpt::ExtAck).is_ok(),
            cap_ack: set(fd, AckOpt::CapAck).is_ok(),
        }
    }

    fn set_ack_opt(fd: BorrowedFd<'_>, opt: AckOpt) -> Result<(), SysError> {
        match opt {
            AckOpt::ExtAck => sys::enable_ext_ack(fd),
            AckOpt::CapAck => sys::enable_cap_ack(fd),
        }
    }

    impl fmt::Debug for NetlinkRouteSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("NetlinkRouteSocket")
                .field("fd", &self.fd.as_raw_fd())
                .field("ack_options", &self.ack_options)
                .finish_non_exhaustive()
        }
    }

    /// 待たない 1 回の受信の結果。
    #[derive(Debug)]
    enum TryRecv {
        /// 1 データグラムを取り出した（`buf` は確保したバッファ全体。有効長は `meta.len`）。
        Datagram { buf: Vec<u8>, meta: RecvMeta },
        /// 先頭データグラムが上限長を超えていたため、確保せずに破棄した。
        Oversized { len: usize },
    }

    /// 先頭データグラムの実長を確認し、`max_len` 以下なら `max(実長, min_buf)` のバッファを確保して
    /// 取り出す。超えていれば確保せずにキューから破棄する（残すと以後の受信が進まないため）。
    ///
    /// カーネルの申告長（外部入力）を上限検証してから確保に使う。呼び出し側が `recv_lock` を保持して
    /// いる前提で、長さ確認と取り出しの間に同じソケットの別の読み手は割り込まない。
    fn try_recv_datagram(
        fd: BorrowedFd<'_>,
        min_buf: usize,
        max_len: usize,
    ) -> Result<TryRecv, SysError> {
        let len = sys::peek_datagram_len(fd)?;
        if len > max_len {
            let mut discard = [0u8; 1];
            sys::recv_from(fd, &mut discard)?;
            return Ok(TryRecv::Oversized { len });
        }
        let mut buf = vec![0u8; len.max(min_buf)];
        let meta = sys::recv_from(fd, &mut buf)?;
        Ok(TryRecv::Datagram { buf, meta })
    }

    impl NetlinkRouteSocket {
        /// ソケットを開いて bind する（計測結果は記録しない。記録するなら
        /// [`open_with_recorder`](Self::open_with_recorder)）。
        pub fn open() -> Result<Self, NetError> {
            Self::open_with_recorder(Arc::new(NoopNetOpRecorder))
        }

        /// ソケットを開いて bind し、以後の open / send / recv の結果と所要時間を `recorder` へ渡す
        /// （REPAIR-4）。open 自体の成否もここで 1 件記録する。
        pub fn open_with_recorder(recorder: Arc<dyn NetOpRecorder>) -> Result<Self, NetError> {
            Self::open_protocol(recorder, sys::open_route_socket, true)
        }

        /// `NETLINK_NETFILTER` ソケットとして開いて bind する（nf_tables のバッチ送信用。
        /// `crate::nftables_batch::NetlinkNetfilterSocket` だけが使う。TASK-137.3・#306）。
        ///
        /// 型名は route だが、送受信・期限・計装の機構はプロトコルに依存しないため再利用している。
        /// `request` などの rtnetlink 固有の往復（dump / DONE の終端規則）は netfilter 側へ公開しない。
        /// 共通コアの切り出しは後続の整理課題（REPAIR-3）。
        pub(crate) fn open_netfilter_with_recorder(
            recorder: Arc<dyn NetOpRecorder>,
        ) -> Result<Self, NetError> {
            Self::open_protocol(recorder, sys::open_netfilter_socket, false)
        }

        /// カーネルが採番した自ソケットの port ID（`nl_pid`）。このソケット宛ての応答の
        /// `nlmsg_pid` はこれと一致する。生の `recv` では照合しないため、必要な呼び出し側が使う。
        pub fn local_pid(&self) -> NonZeroU32 {
            self.local_pid
        }

        /// 計装の記録先（`NetlinkNetfilterSocket` が往復全体を記録するために共有する）。
        pub(crate) fn recorder(&self) -> &Arc<dyn NetOpRecorder> {
            &self.recorder
        }

        /// 有効にできた ACK オプション（netfilter ソケットは常に両方 `false`）。
        #[cfg(test)]
        pub(crate) fn ack_options(&self) -> AckOptions {
            self.ack_options
        }

        /// open（`socket` + `bind`）の共通部。`open_fd` が protocol ごとのソケット作成を担う。
        /// `ack_opts` が真なら拡張 ACK を有効にする（route 用。netfilter は `nftables_batch` の
        /// 応答バイト列を変えないため無効のまま）。
        fn open_protocol(
            recorder: Arc<dyn NetOpRecorder>,
            open_fd: fn() -> Result<OwnedFd, SysError>,
            ack_opts: bool,
        ) -> Result<Self, NetError> {
            let (fd, local_pid) = record_net_op(recorder.as_ref(), NetOpKind::NetlinkOpen, || {
                let fd = open_fd().map_err(|e| map_sys_error("socket", e))?;
                sys::bind_kernel_assigned(fd.as_fd()).map_err(|e| map_sys_error("bind", e))?;
                let raw =
                    sys::local_nl_pid(fd.as_fd()).map_err(|e| map_sys_error("getsockname", e))?;
                let local_pid = nonzero_local_pid(raw)?;
                Ok::<_, NetError>((fd, local_pid))
            })?;
            let ack_options = if ack_opts {
                enable_ack_options(fd.as_fd(), set_ack_opt)
            } else {
                AckOptions {
                    ext_ack: false,
                    cap_ack: false,
                }
            };
            Ok(Self {
                fd,
                local_pid,
                recv_lock: Mutex::new(()),
                recorder,
                seq: SeqAllocator::new(),
                gate: RequestGate::default(),
                ack_options,
            })
        }

        /// 要求 1 件を送り、seq が一致する ACK / 応答が揃うまで待つ（NET-11・TASK-136.2.2）。
        ///
        /// `NLM_F_REQUEST | NLM_F_ACK` を `flags` に足し、seq は本メソッドが採番する（呼び出し側は
        /// 指定できない）。`build` で `msg_type` に続くファミリ固有ヘッダ・属性を組む。`timeout` は
        /// 順番待ち・送信・応答待ちを通した全体の期限で、超えれば `Timeout`（REPAIR-5）。
        ///
        /// 判定: seq 一致の `NLMSG_ERROR` が errno 0 なら成功、非 0 なら errno を分類した構造化エラー
        /// （ERR-1）。`NLMSG_DONE`（dump の終端）でも成功。seq 不一致のメッセージ（以前に時間切れした
        /// 要求の遅延応答等）は破棄する。`nlmsg_pid` が自ソケットの `nl_pid` と異なるメッセージも
        /// 破棄する（#1313）: 自分宛てでない `NLMSG_ERROR`（seq がたまたま一致するもの・なりすまし・
        /// 将来のマルチキャスト通知）で要求の成否を決めさせず、また構造化エラーにして往復を
        /// 中断すると他宛てトラフィックの混入で可用性を損なうため、seq 不一致と同じく読み飛ばす。
        /// 破棄し続けても全体期限で `Timeout` になる（REPAIR-5）。`Timeout` / `DataLoss` で戻った場合、カーネル側で操作が適用
        /// 済みかは不明なので、呼び出し側が状態を再照会すること。
        pub fn request(
            &self,
            msg_type: u16,
            flags: u16,
            timeout: Duration,
            build: impl FnOnce(&mut NlMsgBuilder) -> Result<(), NetError>,
        ) -> Result<NetlinkReply, NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::NetlinkRequest, || {
                let deadline = Deadline::after(timeout);
                let _turn = self.gate.acquire(&deadline, timeout)?;
                let seq = self.seq.next();
                let dump = is_dump_request(msg_type, flags);
                let mut builder =
                    NlMsgBuilder::new(msg_type, flags | NLM_F_REQUEST | NLM_F_ACK, seq, 0);
                build(&mut builder)?;
                let message = builder.finish()?;
                // build に時間がかかって期限が切れた場合、要求をカーネルへ送らない。
                if deadline.remaining().is_zero() {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        format!(
                            "netlink request seq {seq} not sent: deadline of {} ms passed",
                            timeout.as_millis()
                        ),
                    ));
                }
                self.send(&message)?;
                await_reply_for(seq, dump, self.local_pid, &deadline, timeout, |t| {
                    self.recv(t)
                })
            })
        }

        /// link 作成要求（`RTM_NEWLINK`）を送り ACK を待つ（NET-11・TASK-136.3.2）。`NetOpKind::LinkCreate`
        /// として記録する（内側の request / send / recv も個別に記録）。`timeout` は全体の期限
        /// （推奨 5〜10 秒）。`Timeout` / `DataLoss` ではカーネル側で作成済みか不明なため、状態を再照会すること。
        /// 同名が既にあれば `AlreadyExists`、権限不足は `PermissionDenied`。
        pub fn create_link(
            &self,
            req: &LinkCreate,
            timeout: Duration,
        ) -> Result<NetlinkReply, NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::LinkCreate, || {
                self.request(req.msg_type(), req.flags(), timeout, |b| req.encode(b))
            })
        }

        /// link 設定要求（`RTM_SETLINK`: netns 移動・up）を送り ACK を待つ（NET-11・TASK-136.3.2）。
        /// `NetOpKind::LinkSet` として記録する。対象が自 netns に無ければ `NotFound`（netns 移動後の
        /// デバイスは移動先 netns のソケットから操作する）。`Timeout` / `DataLoss` では適用済みか不明。
        pub fn set_link(
            &self,
            req: &LinkSet<'_>,
            timeout: Duration,
        ) -> Result<NetlinkReply, NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::LinkSet, || {
                self.request(req.msg_type(), req.flags(), timeout, |b| req.encode(b))
            })
        }

        /// `message`（`NlMsgBuilder` で組んだ 1 メッセージ）をそのままカーネルへ送る。
        ///
        /// 空・`NLMSG_HEADER_LEN` 未満・`MAX_MESSAGE_LEN` 超、および「アラインした `nlmsg_len` が実長と一致しない（複数メッセージ連結を含む）・末尾パディング（0〜3 バイト）が 0 でない」入力は `InvalidArgument`。部分送信は `DataLoss`。
        pub fn send(&self, message: &[u8]) -> Result<(), NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::NetlinkSend, || {
                self.send_unrecorded(message)
            })
        }

        /// 閉じた nf_tables バッチ（連結された複数メッセージ）を 1 データグラムとして送る
        /// （TASK-137.3・#306。`NetOpKind::NetlinkSend` として記録）。
        ///
        /// [`send`](Self::send) の単一メッセージ検証は通さない。`NftBatchBytes` は非公開フィールドで
        /// `NftBatch::finish` だけが作れ、BEGIN・本体・END の framing は型で保証されるため（REPAIR-2）、
        /// ここでは長さの上限だけ確認する。部分送信は `DataLoss`。送信が `EMSGSIZE`（ソケットの
        /// `SO_SNDBUF` 超過）なら `ResourceExhausted`。
        pub(crate) fn send_batch_bytes(&self, batch: &NftBatchBytes) -> Result<(), NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::NetlinkSend, || {
                let bytes = batch.bytes();
                if bytes.len() > MAX_BATCH_LEN {
                    return Err(NetError::new(
                        NetErrorCode::InvalidArgument,
                        format!(
                            "nf_tables batch length {} exceeds {}",
                            bytes.len(),
                            MAX_BATCH_LEN
                        ),
                    ));
                }
                let sent = sys::send_to_kernel(self.fd.as_fd(), bytes)
                    .map_err(|e| map_sys_error("sendto", e))?;
                if sent != bytes.len() {
                    return Err(NetError::new(
                        NetErrorCode::DataLoss,
                        format!("partial netlink send: {} of {} bytes", sent, bytes.len()),
                    ));
                }
                Ok(())
            })
        }

        /// [`send`](Self::send) の本体（検証と送信）。
        fn send_unrecorded(&self, message: &[u8]) -> Result<(), NetError> {
            if message.len() < NLMSG_HEADER_LEN || message.len() > MAX_MESSAGE_LEN as usize {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    format!(
                        "netlink message length {} is outside {}..={}",
                        message.len(),
                        NLMSG_HEADER_LEN,
                        MAX_MESSAGE_LEN
                    ),
                ));
            }
            // 単一メッセージの契約を型ではなく送信前検証で保証する（REPAIR-2）。
            // 復号できない・nlmsg_len が実長と不一致（短い=複数メッセージ連結、長い=切り詰め）は渡さない。
            let header = NlMsgHeader::decode(message).map_err(|e| {
                NetError::new(NetErrorCode::InvalidArgument, e.message().to_string())
            })?;
            // NlMsgBuilder::finish は nlmsg_len に末尾パディングを含めず、バイト列は 4 バイト境界まで 0 埋めする。
            // よって実長は nlmsg_len を 4 バイトへアラインした値と一致し、nlmsg_len 以降（0〜3 バイト）は 0 でなければならない。
            let msg_len = header.len() as usize;
            let aligned_len = msg_len.saturating_add(ALIGN_TO - 1) & !(ALIGN_TO - 1);
            let padding_is_zero = message
                .get(msg_len..)
                .is_some_and(|pad| pad.iter().all(|&b| b == 0));
            if aligned_len != message.len() || !padding_is_zero {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    format!(
                        "nlmsg_len {} does not match buffer length {} (single message with zero padding required)",
                        msg_len,
                        message.len()
                    ),
                ));
            }
            let sent = sys::send_to_kernel(self.fd.as_fd(), message)
                .map_err(|e| map_sys_error("sendto", e))?;
            if sent != message.len() {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    format!("partial netlink send: {} of {} bytes", sent, message.len()),
                ));
            }
            Ok(())
        }

        /// 最大 `timeout` 待って 1 データグラムを受信し、受信長に切り詰めたバイト列を返す。
        ///
        /// `timeout` は呼び出し全体の期限（REPAIR-5）。開始時刻（単調時計）からの残り時間を毎回
        /// 計算し直すため、次のどの場合も「残り時間だけ待ち直す」動作になり、期限より早く
        /// `Timeout` を返さず、期限を超えても待たない:
        /// - 同じソケットを共有する別スレッドが、`poll` の後に先にデータグラムを読んだ（`EAGAIN`）
        /// - シグナルで `poll` / `recvfrom` が中断された（`EINTR`）
        /// - `timeout` が 1 回の `poll` に渡せる上限（`i32::MAX` ms）を超える
        ///
        /// `timeout` が 0 なら待たず、すでに届いているデータグラムだけを返す。期限内に届かなければ
        /// `Timeout`。
        ///
        /// 受信長はカーネルが申告した実長に合わせる。[`RECV_BUFFER_LEN`] を超えるデータグラムも
        /// [`MAX_RECV_DATAGRAM_LEN`] までは欠落なく受信し、それを超えるものは確保せずに破棄して
        /// `DataLoss` を返す。カーネル以外の送信元も `DataLoss`（そのデータグラムは破棄済み）。
        /// 返したバイト列の解釈は呼び出し側が `NlMsgIter` で行う。
        pub fn recv(&self, timeout: Duration) -> Result<Vec<u8>, NetError> {
            record_net_op(self.recorder.as_ref(), NetOpKind::NetlinkRecv, || {
                self.recv_with(timeout, |fd| {
                    try_recv_datagram(fd, RECV_BUFFER_LEN, MAX_RECV_DATAGRAM_LEN)
                })
            })
        }

        /// [`recv`](Self::recv) の本体。`try_recv` は待たない 1 回の受信（本番は
        /// [`try_recv_datagram`]）で、`recv_lock` を保持した状態で呼ばれる。単体試験が「`poll` の後に
        /// 別の読み手が先に取った」競合や小さい上限長を決定的に再現するための差し替え点。
        fn recv_with(
            &self,
            timeout: Duration,
            mut try_recv: impl FnMut(BorrowedFd<'_>) -> Result<TryRecv, SysError>,
        ) -> Result<Vec<u8>, NetError> {
            let deadline = Deadline::after(timeout);
            let timed_out = || {
                NetError::new(
                    NetErrorCode::Timeout,
                    format!("no netlink message within {} ms", timeout.as_millis()),
                )
            };
            let (mut buf, meta) = loop {
                let readiness = sys::wait_readable(self.fd.as_fd(), &deadline)
                    .map_err(|e| map_sys_error("poll", e))?;
                if readiness == Readiness::TimedOut {
                    return Err(timed_out());
                }
                let attempt = {
                    // 待たない syscall の間だけ保持する。保護対象のデータを持たないため、他スレッドの
                    // panic による poison は無視して続行する。
                    let _guard = self
                        .recv_lock
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    try_recv(self.fd.as_fd())
                };
                match attempt {
                    Ok(TryRecv::Datagram { buf, meta }) => break (buf, meta),
                    Ok(TryRecv::Oversized { len }) => {
                        return Err(NetError::new(
                            NetErrorCode::DataLoss,
                            format!(
                                "dropped netlink datagram of {len} bytes exceeding the limit of {MAX_RECV_DATAGRAM_LEN} bytes"
                            ),
                        ));
                    }
                    // 別スレッドが先に読んだ（EAGAIN）・シグナルで中断された（EINTR）。失敗にせず、
                    // 残り時間があれば待ち直す。回数ではなく全体期限で打ち切る（REPAIR-5）。
                    Err(SysError::Os(errno @ (sys::EAGAIN | sys::EINTR))) => {
                        // POLLIN なしの例外状態（POLLERR 等）で保留中の errno も取り出せなかった場合、
                        // 待ち直しても poll が即座に戻り続ける。期限までの空回りを避けてエラーにする。
                        if readiness == Readiness::Exceptional {
                            return Err(NetError::new(
                                NetErrorCode::Internal,
                                format!(
                                    "netlink socket reported an error condition without data (recvfrom errno {errno})"
                                ),
                            ));
                        }
                        if deadline.remaining().is_zero() {
                            return Err(timed_out());
                        }
                    }
                    Err(e) => return Err(map_sys_error("recvfrom", e)),
                }
            };
            if meta.truncated {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    format!(
                        "netlink datagram of {} bytes exceeds receive buffer of {} bytes",
                        meta.len,
                        buf.len()
                    ),
                ));
            }
            if meta.sender_pid != 0 {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    "dropped netlink datagram from a non-kernel sender",
                ));
            }
            buf.truncate(meta.len);
            Ok(buf)
        }
    }

    #[cfg(test)]
    const TEST_LOCAL_PID: NonZeroU32 = match NonZeroU32::new(0x4242) {
        Some(p) => p,
        None => panic!("nonzero"),
    };

    /// seq `seq` の応答が確定する（ACK・エラー・DONE）まで `recv` で受信して判定する（NET-11・REPAIR-5）。
    ///
    /// `deadline` は往復全体で 1 つ（`total` は文言用の元の timeout）。各 `recv` には残り時間を渡し、
    /// 受信のたびに期限を張り直さない。`recv` は本番では `NetlinkRouteSocket::recv`、単体試験では
    /// 決定的な偽物。
    #[cfg(test)]
    fn await_reply(
        seq: u32,
        deadline: &Deadline,
        total: Duration,
        recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
    ) -> Result<NetlinkReply, NetError> {
        await_reply_for(seq, false, TEST_LOCAL_PID, deadline, total, recv)
    }

    /// [`await_reply`] の本体。応答の終端はカーネルの送出順に合わせて次のとおり判定する。
    ///
    /// - 非 dump（doit）: seq 一致の `NLMSG_ERROR`（ACK / errno）で終端する。カーネルは
    ///   `netlink_rcv_skb`（net/netlink/af_netlink.c）で doit の呼び出しが戻ってから `netlink_ack` を
    ///   送り、doit の応答（GET の 1 件・`NLM_F_ECHO` の通知等）は doit の中で同期的に
    ///   `nlmsg_unicast` 済みのため、受信キュー（FIFO）上で ACK は同じ seq の最後のデータグラムになる。
    ///   ACK より前のデータグラムの応答はすべて `messages` に集め終えている。
    /// - dump（[`is_dump_request`]）: `NLMSG_DONE` で終端する（DONE は非 dump でも終端として扱う）。
    ///   開始に成功した dump では `netlink_dump_start` が `-EINTR` を返し、`netlink_rcv_skb` は ACK を
    ///   送らない。開始に失敗すれば errno 付きの `NLMSG_ERROR` が届く。errno 0 の ACK が届いても完了させない。
    /// - 終端と同じデータグラムで終端より後ろにある同じ seq のメッセージ（NOOP を除く）は、上記の
    ///   送出順に反するため `DataLoss`。終端より後のデータグラムは読まず、次の往復が seq 不一致として破棄する。
    ///
    /// `NLM_F_DUMP_INTR`（`nl_dump_check_consistent` だけが立てる）のついた応答は不完全なので
    /// `FailedPrecondition`（再試行可能）で返す。
    fn await_reply_for(
        seq: u32,
        dump: bool,
        local_pid: NonZeroU32,
        deadline: &Deadline,
        total: Duration,
        recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
    ) -> Result<NetlinkReply, NetError> {
        // 応答の解釈中に期限を過ぎた場合は、errno・DONE エラー・DUMP_INTR 等のどのエラーでも
        // Timeout に統一する（全体期限の契約。REPAIR-5）。
        await_reply_inner(seq, dump, local_pid, deadline, total, recv).map_err(|e| {
            if e.code() != NetErrorCode::Timeout && deadline.remaining().is_zero() {
                NetError::new(
                    NetErrorCode::Timeout,
                    format!(
                        "no reply for netlink request seq {seq} within {} ms",
                        total.as_millis()
                    ),
                )
            } else {
                e
            }
        })
    }

    /// [`await_reply_for`] の本体（期限後のエラー正規化は呼び出し側で行う）。
    fn await_reply_inner(
        seq: u32,
        dump: bool,
        local_pid: NonZeroU32,
        deadline: &Deadline,
        total: Duration,
        mut recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
    ) -> Result<NetlinkReply, NetError> {
        let timed_out = || {
            NetError::new(
                NetErrorCode::Timeout,
                format!(
                    "no reply for netlink request seq {seq} within {} ms",
                    total.as_millis()
                ),
            )
        };
        let data_loss = |msg: String| NetError::new(NetErrorCode::DataLoss, msg);
        let mut messages = Vec::new();
        let mut collected = 0usize;
        let interrupted = || {
            NetError::new(
                NetErrorCode::FailedPrecondition,
                format!("netlink dump for seq {seq} was interrupted (NLM_F_DUMP_INTR); retry"),
            )
        };
        // 期限後に届いた ACK / DONE を成功として返さない（全体期限の契約。REPAIR-5）。
        let finish = |messages: Vec<NetlinkReplyMessage>| {
            if deadline.remaining().is_zero() {
                Err(timed_out())
            } else {
                Ok(NetlinkReply { seq, messages })
            }
        };
        loop {
            let data = match recv(deadline.remaining()) {
                Err(e) if e.code() == NetErrorCode::Timeout => return Err(timed_out()),
                other => other?,
            };
            // 終端（ACK・DONE）を見つけても即returnせず、データグラム全体を検証してから確定する。
            // 同じデータグラムの後続に不正フレームや予期しないメッセージがあれば見逃さない（NET-11）。
            let mut terminal = false;
            for item in NlMsgIter::new(&data) {
                let msg = item?;
                let h = msg.header();
                // 以前に時間切れした要求の遅延応答が残りうるため、不一致はエラーにせず破棄する。
                // 宛先 `nlmsg_pid` が自ソケットでないメッセージ（他宛て・なりすまし）も同様に破棄する
                // （#1313）。この判定が終端後の検査より前にあるため、終端後に届いた他宛てメッセージは
                // `DataLoss` にならず黙って破棄される。
                if h.seq() != seq || h.pid() != local_pid.get() {
                    continue;
                }
                if terminal && h.msg_type() != NLMSG_NOOP {
                    return Err(data_loss(format!(
                        "unexpected netlink message (type {}) after the terminal reply for seq {seq}",
                        h.msg_type()
                    )));
                }
                // DUMP_INTR は dump の応答にしか立たないため、dump 判定によらず検査する。
                if h.flags() & NLM_F_DUMP_INTR != 0 {
                    return Err(interrupted());
                }
                match h.msg_type() {
                    NLMSG_ERROR => {
                        let ack = decode_nlmsgerr_with_flags(h.flags(), msg.payload())?;
                        if ack.request_seq().is_some_and(|s| s != seq) {
                            return Err(data_loss(format!(
                                "nlmsgerr for seq {seq} embeds a different request seq"
                            )));
                        }
                        if ack.is_ack() {
                            if !dump {
                                terminal = true;
                            }
                            continue;
                        }
                        return Err(NetError::new(
                            classify_errno(ack.errno()),
                            ack.failure_message(),
                        ));
                    }
                    NLMSG_DONE => {
                        let errno = decode_done_errno(msg.payload())?;
                        if errno == 0 {
                            terminal = true;
                            continue;
                        }
                        return Err(NetError::new(
                            classify_errno(errno),
                            format!("netlink dump failed: errno {errno}"),
                        ));
                    }
                    NLMSG_NOOP => {}
                    NLMSG_OVERRUN => {
                        return Err(data_loss(format!("netlink overrun for seq {seq}")));
                    }
                    other => {
                        // ヘッダ分も加算し、空ペイロードのメッセージでも総量が増えるようにする。
                        collected = collected
                            .saturating_add(msg.payload().len())
                            .saturating_add(NLMSG_HEADER_LEN);
                        if collected > MAX_REPLY_BYTES || messages.len() >= MAX_REPLY_MESSAGES {
                            return Err(NetError::new(
                                NetErrorCode::ResourceExhausted,
                                format!(
                                    "netlink reply for seq {seq} exceeds {MAX_REPLY_BYTES} bytes or {MAX_REPLY_MESSAGES} messages"
                                ),
                            ));
                        }
                        messages.push(NetlinkReplyMessage {
                            msg_type: other,
                            flags: h.flags(),
                            payload: msg.payload().to_vec(),
                        });
                    }
                }
            }
            if terminal {
                return finish(messages);
            }
            if deadline.remaining().is_zero() {
                return Err(timed_out());
            }
        }
    }

    /// 要求が dump か。カーネルの判定（`rtnetlink_rcv_msg` の
    /// `kind == RTNL_KIND_GET && (nlmsg_flags & NLM_F_DUMP)`）と一致させる。
    ///
    /// - GET 系（`RTM_BASE`＝16 以上で `msg_type & 3 == 2`）だけを対象にする。`NLM_F_ROOT`・
    ///   `NLM_F_MATCH` は NEW 系の `NLM_F_REPLACE`・`NLM_F_EXCL` と同じビットのため、NEW 要求を dump と
    ///   誤判定すると来ない DONE を待ち続けて時間切れになる
    /// - カーネルは `NLM_F_ROOT`・`NLM_F_MATCH` のどちらか一方でも dump として扱う（両方揃いを要求すると、
    ///   片方だけの GET で ACK が来ないまま DONE で終わる応答を非 dump として扱い、判定がずれる）
    fn is_dump_request(msg_type: u16, flags: u16) -> bool {
        const RTM_BASE: u16 = 16;
        msg_type >= RTM_BASE && msg_type & 3 == 2 && flags & (NLM_F_ROOT | NLM_F_MATCH) != 0
    }

    /// `NLMSG_DONE` のペイロードから dump の errno（正値。0 は成功）を取り出す（カーネル応答は外部入力）。
    ///
    /// DONE のペイロードは `struct nlmsgerr` ではなく `int` 1 個（`netlink_dump_done` の
    /// `dump_done_errno`）で、`NLM_F_ACK_TLVS` 時はその後ろに属性が続く。よって先頭 4 バイトだけを
    /// 読み、元要求ヘッダの長さ検査（[`decode_nlmsgerr`]）は適用しない。空ペイロードは成功として
    /// 受理する。1〜3 バイト・正値・`i32::MIN` は `DataLoss`。
    fn decode_done_errno(payload: &[u8]) -> Result<i32, NetError> {
        let bad = |msg: &str| NetError::new(NetErrorCode::DataLoss, msg.to_string());
        if payload.is_empty() {
            return Ok(0);
        }
        let head: [u8; 4] = payload
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("NLMSG_DONE payload shorter than 4 bytes"))?;
        match i32::from_ne_bytes(head) {
            0 => Ok(0),
            raw if raw < 0 => raw
                .checked_neg()
                .ok_or_else(|| bad("NLMSG_DONE error value out of range")),
            _ => Err(bad("NLMSG_DONE carries a positive error value")),
        }
    }

    /// `getsockname` が返した `nl_pid` を非 0 型にする。カーネルは bind 後に 0 を割り当てないため、
    /// 0 は異常として open の失敗にする（fail-closed。#1313）。
    fn nonzero_local_pid(raw: u32) -> Result<NonZeroU32, NetError> {
        NonZeroU32::new(raw).ok_or_else(|| {
            NetError::new(
                NetErrorCode::Internal,
                "getsockname: kernel assigned netlink port id 0",
            )
        })
    }

    /// errno を `NetErrorCode` へ写す（メッセージは英語で syscall 名と errno 数値のみ）。
    fn map_sys_error(call: &str, e: SysError) -> NetError {
        match e {
            SysError::Unsupported => NetError::new(
                NetErrorCode::Unimplemented,
                format!("{call}: unsupported architecture"),
            ),
            SysError::Os(errno) => NetError::new(
                classify_errno(errno),
                format!("{call} failed: errno {errno}"),
            ),
            SysError::BadSenderAddress => NetError::new(
                NetErrorCode::DataLoss,
                format!("{call}: dropped datagram whose sender is not a netlink address"),
            ),
            SysError::BadLocalAddress => NetError::new(
                NetErrorCode::Internal,
                format!("{call}: local address is not a netlink address"),
            ),
        }
    }

    pub(crate) fn classify_errno(errno: i32) -> NetErrorCode {
        match errno {
            sys::EPERM | sys::EACCES => NetErrorCode::PermissionDenied,
            sys::EAFNOSUPPORT | sys::EPROTONOSUPPORT | sys::EOPNOTSUPP => {
                NetErrorCode::Unimplemented
            }
            sys::ENOENT | sys::ENODEV => NetErrorCode::NotFound,
            sys::EEXIST => NetErrorCode::AlreadyExists,
            sys::EBUSY => NetErrorCode::FailedPrecondition,
            sys::EINVAL => NetErrorCode::InvalidArgument,
            sys::ENOBUFS
            | sys::ENOMEM
            | sys::EMFILE
            | sys::ENFILE
            | sys::EAGAIN
            | sys::EMSGSIZE => NetErrorCode::ResourceExhausted,
            _ => NetErrorCode::Internal,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::netlink_route::{IfName, LinkRef, RTM_GETLINK, RTM_NEWLINK};

        /// NET-11: errno 写像の具体値。
        #[test]
        fn errno_mapping() {
            assert_eq!(classify_errno(1), NetErrorCode::PermissionDenied);
            assert_eq!(classify_errno(13), NetErrorCode::PermissionDenied);
            assert_eq!(classify_errno(93), NetErrorCode::Unimplemented);
            assert_eq!(classify_errno(97), NetErrorCode::Unimplemented);
            assert_eq!(classify_errno(105), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(24), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(11), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(2), NetErrorCode::NotFound);
            assert_eq!(classify_errno(19), NetErrorCode::NotFound);
            assert_eq!(classify_errno(17), NetErrorCode::AlreadyExists);
            assert_eq!(classify_errno(16), NetErrorCode::FailedPrecondition);
            assert_eq!(classify_errno(22), NetErrorCode::InvalidArgument);
            assert_eq!(classify_errno(95), NetErrorCode::Unimplemented);
            assert_eq!(classify_errno(90), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(5), NetErrorCode::Internal);
            let e = map_sys_error("socket", SysError::Os(1));
            assert_eq!(e.to_string(), "PERMISSION_DENIED: socket failed: errno 1");
            let e = map_sys_error("recvfrom", SysError::BadSenderAddress);
            assert_eq!(
                e.to_string(),
                "DATA_LOSS: recvfrom: dropped datagram whose sender is not a netlink address"
            );
            let e = map_sys_error("poll", SysError::Unsupported);
            assert_eq!(
                e.to_string(),
                "UNIMPLEMENTED: poll: unsupported architecture"
            );
        }

        /// lo（ifindex 1）1 件だけを問い合わせる非 dump の RTM_GETLINK。非特権で成立し、カーネルは
        /// RTM_NEWLINK 1 件を 1 データグラムで返す（NLM_F_ACK なしのため ACK は返らない）。
        fn getlink_lo(seq: u32) -> Vec<u8> {
            use crate::netlink::{NLM_F_REQUEST, NlMsgBuilder};
            let mut b = NlMsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST, seq, 0);
            // struct ifinfomsg: family(1) pad(1) type(2) index(i32) flags(4) change(4)。
            let mut ifi = [0u8; 16];
            ifi[4..8].copy_from_slice(&1i32.to_ne_bytes());
            b.put_fixed(&ifi).expect("ifinfomsg");
            b.finish().expect("finish")
        }

        /// NET-11・#1313: 実カーネルの応答ヘッダの `nlmsg_pid` は `local_pid()` と一致し、非 0 である。
        #[test]
        fn reply_pid_matches_local_pid() {
            let s = NetlinkRouteSocket::open().expect("open");
            assert_ne!(s.local_pid().get(), 0);
            s.send(&getlink_lo(7)).expect("send");
            let data = s.recv(Duration::from_secs(5)).expect("recv");
            let h = NlMsgIter::new(&data)
                .next()
                .expect("one message")
                .expect("valid")
                .header();
            assert_eq!(h.pid(), s.local_pid().get());
        }

        /// 本番と同じ上限での待たない 1 回の受信。
        fn real_try_recv(fd: BorrowedFd<'_>) -> Result<TryRecv, SysError> {
            try_recv_datagram(fd, RECV_BUFFER_LEN, MAX_RECV_DATAGRAM_LEN)
        }

        /// 受信 1 データグラムの先頭メッセージの (type, seq)。
        fn first_type_and_seq(data: &[u8]) -> (u16, u32) {
            let h = NlMsgHeader::decode(data).expect("header");
            (h.msg_type(), h.seq())
        }

        /// NET-11・REPAIR-5: `poll` 通過後に別の読み手が先にデータグラムを読んでも（`recvfrom` が
        /// EAGAIN）、`Timeout` で失敗せず、期限内に届いた次の応答を受信する。
        ///
        /// 競合の再現: seq=1 の応答が届いて `poll` が通過した直後、1 回目の `try_recv` の中で
        /// 「別の読み手」がその応答を読み取り、続けて seq=2 の要求を送ってから EAGAIN を返す。
        #[test]
        fn recv_keeps_waiting_after_another_reader_wins_the_race() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(1)).expect("send 1");
            let mut calls = 0u32;
            let mut stolen = None;
            let started = std::time::Instant::now();
            let data = s
                .recv_with(Duration::from_secs(5), |fd| {
                    calls += 1;
                    if calls == 1 {
                        let TryRecv::Datagram { buf, meta } =
                            real_try_recv(fd).expect("other reader takes it")
                        else {
                            panic!("unexpected oversized datagram");
                        };
                        stolen = Some(first_type_and_seq(buf.get(..meta.len).expect("len")));
                        s.send(&getlink_lo(2)).expect("send 2");
                        return Err(SysError::Os(sys::EAGAIN));
                    }
                    real_try_recv(fd)
                })
                .expect("recv must continue until the next datagram");
            assert_eq!(stolen, Some((RTM_NEWLINK, 1)));
            assert_eq!(first_type_and_seq(&data), (RTM_NEWLINK, 2));
            assert_eq!(calls, 2);
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: `recvfrom` が EINTR で中断されても同じ扱いで、残り時間内に待ち直して
        /// 同じデータグラムを受信する（回数上限で `Internal` にしない）。
        #[test]
        fn recv_retries_after_eintr_within_the_deadline() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(7)).expect("send");
            let mut calls = 0u32;
            let data = s
                .recv_with(Duration::from_secs(5), |fd| {
                    calls += 1;
                    if calls <= 20 {
                        return Err(SysError::Os(sys::EINTR));
                    }
                    real_try_recv(fd)
                })
                .expect("recv");
            assert_eq!(first_type_and_seq(&data), (RTM_NEWLINK, 7));
            assert_eq!(calls, 21);
        }

        /// NET-11・REPAIR-5: 先に読まれたあと次の応答が来なければ、残り時間を待ち切ってから
        /// `Timeout` を返す（即座には返さず、期限を超えても待たない）。
        #[test]
        fn recv_times_out_at_the_deadline_after_losing_the_race() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(3)).expect("send");
            let mut calls = 0u32;
            let started = std::time::Instant::now();
            let e = s
                .recv_with(Duration::from_millis(300), |fd| {
                    calls += 1;
                    real_try_recv(fd).expect("other reader takes it");
                    Err(SysError::Os(sys::EAGAIN))
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(e.to_string(), "TIMEOUT: no netlink message within 300 ms");
            assert_eq!(calls, 1);
            assert!(started.elapsed() >= Duration::from_millis(300));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: 読み続けても毎回先を越される場合でも、期限を過ぎたら `Timeout` で止まる
        /// （受信競合が続いても無期限に回らない）。
        #[test]
        fn recv_stops_at_the_deadline_under_repeated_races() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(4)).expect("send");
            let started = std::time::Instant::now();
            // データグラムを読まずに EAGAIN を返し続ける（poll は毎回 Readable で即座に戻る）。
            let e = s
                .recv_with(Duration::from_millis(200), |_| {
                    Err(SysError::Os(sys::EAGAIN))
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() >= Duration::from_millis(200));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: timeout 0 は待たず、届いていなければ直ちに `Timeout`。
        #[test]
        fn recv_with_zero_timeout_does_not_wait() {
            let s = NetlinkRouteSocket::open().expect("open");
            let started = std::time::Instant::now();
            let e = s.recv(Duration::ZERO).expect_err("timeout");
            assert_eq!(e.to_string(), "TIMEOUT: no netlink message within 0 ms");
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11: 送信前の入力検証（カーネルへ渡さない）。
        #[test]
        fn send_rejects_bad_lengths() {
            let s = NetlinkRouteSocket::open().expect("open");
            for len in [0usize, 15, MAX_MESSAGE_LEN as usize + 1] {
                let e = s.send(&vec![0u8; len]).expect_err("must reject");
                assert_eq!(e.code(), NetErrorCode::InvalidArgument, "len {len}");
            }
        }

        /// NET-11・REPAIR-2: nlmsg_len と実長の不一致・複数メッセージ連結は送信前に拒否する。
        #[test]
        fn send_rejects_mismatched_header_len() {
            use crate::netlink::NlMsgBuilder;
            let s = NetlinkRouteSocket::open().expect("open");
            let one = NlMsgBuilder::new(18, crate::netlink::NLM_F_REQUEST, 1, 0)
                .finish()
                .expect("finish");
            assert_eq!(one.len(), NLMSG_HEADER_LEN);
            // 2 メッセージ連結（先頭の nlmsg_len は 16 のまま実長 32）。
            let mut two = one.clone();
            two.extend_from_slice(&one);
            let e = s.send(&two).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            // ヘッダ長が実長より大きい。
            let mut long_hdr = one.clone();
            long_hdr[0..4].copy_from_slice(&32u32.to_ne_bytes());
            let e = s.send(&long_hdr).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            // ヘッダ長が 16 未満。
            let mut short_hdr = one;
            short_hdr[0..4].copy_from_slice(&8u32.to_ne_bytes());
            let e = s.send(&short_hdr).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }

        /// NET-11・REPAIR-2: 末尾パディングを含む NlMsgBuilder の出力は受理し、非 0 パディング・過剰パディングは拒否する。
        #[test]
        fn send_accepts_padded_builder_output() {
            use crate::netlink::NlMsgBuilder;
            let s = NetlinkRouteSocket::open().expect("open");
            let mut b = NlMsgBuilder::new(18, crate::netlink::NLM_F_REQUEST, 1, 0);
            b.put_fixed(&[1]).expect("fixed");
            let msg = b.finish().expect("finish");
            assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().expect("len")), 17);
            assert_eq!(msg.len(), 20);
            // 受理（カーネル応答の成否は問わず、InvalidArgument でないこと）。
            if let Err(e) = s.send(&msg) {
                assert_ne!(e.code(), NetErrorCode::InvalidArgument);
            }
            let mut dirty = msg.clone();
            dirty[19] = 1;
            let e = s.send(&dirty).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let mut over = msg.clone();
            over.extend_from_slice(&[0u8; 4]);
            let e = s.send(&over).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let e = s.send(&msg[..17]).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }

        /// NET-11: 通常のバッファ長を超えるデータグラムも、実長に合わせたバッファで欠落なく受信する
        /// （上限長までは `DataLoss` にしない）。通常のバッファ長を 16 バイトへ縮めて再現し、
        /// 既定のバッファ長での受信結果と全バイトが一致することを照合する。
        #[test]
        fn recv_grows_buffer_to_the_datagram_length() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(5)).expect("send");
            let expected = s.recv(Duration::from_secs(5)).expect("recv");
            assert!(expected.len() > 16, "reply is {} bytes", expected.len());
            assert_eq!(first_type_and_seq(&expected), (RTM_NEWLINK, 5));

            s.send(&getlink_lo(5)).expect("send");
            let grown = s
                .recv_with(Duration::from_secs(5), |fd| {
                    try_recv_datagram(fd, 16, MAX_RECV_DATAGRAM_LEN)
                })
                .expect("recv with a 16-byte normal buffer");
            assert_eq!(grown.len(), expected.len());
            assert_eq!(first_type_and_seq(&grown), (RTM_NEWLINK, 5));
            let h = NlMsgHeader::decode(&grown).expect("header");
            assert_eq!(h.len() as usize, grown.len());
        }

        /// NET-11: 上限長を超えるデータグラムは確保せずに破棄して `DataLoss` を返し、キューに残さない
        /// （次の受信は次のデータグラムへ進む）。上限長を 64 バイトへ縮めて再現する。
        #[test]
        fn recv_drops_datagram_above_the_limit() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(6)).expect("send 6");
            let e = s
                .recv_with(Duration::from_secs(5), |fd| try_recv_datagram(fd, 16, 64))
                .expect_err("oversized");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
            assert!(
                e.to_string()
                    .starts_with("DATA_LOSS: dropped netlink datagram of "),
                "{e}"
            );
            // 破棄済みなので、待たない受信では何も残っていない。
            let e = s.recv(Duration::ZERO).expect_err("queue is empty");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            s.send(&getlink_lo(8)).expect("send 8");
            let next = s.recv(Duration::from_secs(5)).expect("recv");
            assert_eq!(first_type_and_seq(&next), (RTM_NEWLINK, 8));
        }

        /// 実効 capability に `CAP_NET_ADMIN`（bit 12）があるか（`/proc/self/status` の `CapEff`）。
        fn has_cap_net_admin() -> bool {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_owned()))
                })
                .and_then(|v| u64::from_str_radix(&v, 16).ok())
                .is_some_and(|caps| caps & (1 << 12) != 0)
        }

        /// NET-11・TASK-136.3.2: 存在しない名前への up は失敗し、LinkSet と request が 1 件ずつ失敗として
        /// 記録される。カーネルは権限検査が先に来るため、`CAP_NET_ADMIN` が無ければ `PermissionDenied`
        /// （fail-closed）、あれば `NotFound`（ENODEV）になる。
        #[test]
        fn net11_set_link_on_missing_device_fails_and_is_recorded() {
            use crate::instrument::NetOpOutcome;
            use crate::instrument::testing::Collect;
            let collect = Arc::new(Collect::default());
            let s = NetlinkRouteSocket::open_with_recorder(collect.clone()).expect("open");
            let req = LinkSet::up(LinkRef::Name(IfName::new("fcn-absent0").expect("name")));
            let e = s
                .set_link(&req, Duration::from_secs(5))
                .expect_err("absent device");
            let want = if has_cap_net_admin() {
                NetErrorCode::NotFound
            } else {
                NetErrorCode::PermissionDenied
            };
            assert_eq!(e.code(), want);
            let kinds = collect.kinds();
            let n = |k| {
                kinds
                    .iter()
                    .filter(|x| **x == (k, NetOpOutcome::Failure))
                    .count()
            };
            assert_eq!(n(NetOpKind::LinkSet), 1);
            assert_eq!(n(NetOpKind::NetlinkRequest), 1);
        }

        /// REPAIR-4・NET-11: open / send / recv は成功・失敗のどちらでも 1 回につき 1 件、種別と
        /// 結果と所要時間を記録先へ渡す。
        #[test]
        fn repair4_socket_operations_are_recorded() {
            use crate::instrument::testing::Collect;
            use crate::instrument::{NetOpOutcome, NetOpSample};
            let collect = Arc::new(Collect::default());
            let s = NetlinkRouteSocket::open_with_recorder(collect.clone()).expect("open");
            s.send(&getlink_lo(9)).expect("send");
            let data = s.recv(Duration::from_secs(5)).expect("recv");
            assert_eq!(first_type_and_seq(&data), (RTM_NEWLINK, 9));
            let e = s.send(&[0u8; 3]).expect_err("invalid");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let e = s.recv(Duration::from_millis(100)).expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(
                collect.kinds(),
                vec![
                    (NetOpKind::NetlinkOpen, NetOpOutcome::Success),
                    (NetOpKind::NetlinkSend, NetOpOutcome::Success),
                    (NetOpKind::NetlinkRecv, NetOpOutcome::Success),
                    (NetOpKind::NetlinkSend, NetOpOutcome::Failure),
                    (NetOpKind::NetlinkRecv, NetOpOutcome::Failure),
                ]
            );
            // 時間切れの recv のレイテンシは、待った時間（100 ms 以上）を含む。
            let timed_out = collect.items().last().map(NetOpSample::latency);
            assert!(
                timed_out >= Some(Duration::from_millis(100)),
                "{timed_out:?}"
            );
            assert!(timed_out < Some(Duration::from_secs(5)), "{timed_out:?}");
        }

        // ---- request / await_reply（NET-11・TASK-136.2.2・REPAIR-5）----

        /// 偽の応答データグラム: `NLMSG_ERROR`（errno は正値で渡し、負にして格納。`inner_seq` は
        /// 埋め込む元要求ヘッダの seq）。
        fn err_dgram(seq: u32, errno: i32, inner_seq: u32) -> Vec<u8> {
            let mut b = NlMsgBuilder::new(NLMSG_ERROR, 0, seq, TEST_LOCAL_PID.get());
            let mut p = Vec::new();
            p.extend_from_slice(&(-errno).to_ne_bytes());
            p.extend_from_slice(&[0u8; 8]);
            p.extend_from_slice(&inner_seq.to_ne_bytes());
            p.extend_from_slice(&[0u8; 4]);
            b.put_fixed(&p).expect("payload");
            b.finish().expect("finish")
        }

        fn plain_dgram(msg_type: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
            let mut b = NlMsgBuilder::new(msg_type, 0, seq, TEST_LOCAL_PID.get());
            b.put_fixed(payload).expect("payload");
            b.finish().expect("finish")
        }

        /// 偽 recv を順に返し、尽きたら Timeout を返す。
        fn script(mut items: Vec<Vec<u8>>) -> impl FnMut(Duration) -> Result<Vec<u8>, NetError> {
            items.reverse();
            move |_| {
                items
                    .pop()
                    .ok_or_else(|| NetError::new(NetErrorCode::Timeout, "none"))
            }
        }

        fn run(
            seq: u32,
            total: Duration,
            recv: impl FnMut(Duration) -> Result<Vec<u8>, NetError>,
        ) -> Result<NetlinkReply, NetError> {
            await_reply(seq, &Deadline::after(total), total, recv)
        }

        /// NET-11: seq 一致の ACK は成功、応答メッセージが無ければ空。
        #[test]
        fn matching_ack_succeeds() {
            let r = run(5, Duration::from_secs(5), script(vec![err_dgram(5, 0, 5)])).expect("ack");
            assert_eq!(r.seq(), 5);
            assert!(r.messages().is_empty());
        }

        /// REPAIR-5: 期限後に届いた ACK は成功にせず Timeout。
        #[test]
        fn late_ack_after_deadline_is_timeout() {
            let total = Duration::from_millis(30);
            let deadline = Deadline::after(total);
            let mut once = Some(err_dgram(5, 0, 5));
            let e = await_reply(5, &deadline, total, |_| {
                std::thread::sleep(Duration::from_millis(80));
                Ok(once.take().expect("one"))
            })
            .expect_err("late");
            assert_eq!(e.code(), NetErrorCode::Timeout);
        }

        /// REPAIR-5: 期限後に届いた errno エラー応答も別エラーではなく Timeout に統一する。
        #[test]
        fn late_errno_after_deadline_is_timeout() {
            let total = Duration::from_millis(30);
            let deadline = Deadline::after(total);
            // errno 17（EEXIST）の正しいエラー応答。期限内なら AlreadyExists になる値を使う。
            let mut once = Some(err_dgram(5, 17, 5));
            let e = await_reply(5, &deadline, total, |_| {
                std::thread::sleep(Duration::from_millis(80));
                Ok(once.take().expect("one"))
            })
            .expect_err("late");
            assert_eq!(e.code(), NetErrorCode::Timeout);
        }

        /// NET-11: dump 判定はカーネル（`rtnetlink_rcv_msg`）と同じく GET 系に限り、`NLM_F_ROOT`・
        /// `NLM_F_MATCH` のどちらか一方でも dump。NEW 要求の REPLACE|EXCL（同ビット）は dump ではない。
        #[test]
        fn dump_detection_matches_the_kernel() {
            // RTM_NEWADDR = 20（&3 == 0）、RTM_GETADDR = 22（&3 == 2）、NLMSG_DONE = 3（RTM_BASE 未満）。
            let f = NLM_F_ROOT | NLM_F_MATCH;
            assert!(!is_dump_request(20, f));
            assert!(!is_dump_request(20, NLM_F_ROOT));
            assert!(is_dump_request(22, f));
            assert!(is_dump_request(22, NLM_F_ROOT));
            assert!(is_dump_request(22, NLM_F_MATCH));
            assert!(!is_dump_request(22, 0));
            assert!(!is_dump_request(NLMSG_DONE, f));
        }

        /// NET-11: seq 不一致の ACK は破棄して待ち続け、一致したものを採用する。
        #[test]
        fn mismatched_seq_is_discarded_then_match_succeeds() {
            let r = run(
                6,
                Duration::from_secs(5),
                script(vec![err_dgram(5, 0, 5), err_dgram(6, 0, 6)]),
            )
            .expect("ack");
            assert_eq!(r.seq(), 6);
        }

        /// NET-11・REPAIR-5: seq 不一致だけなら成功扱いにせず Timeout。
        #[test]
        fn only_mismatched_seq_times_out() {
            let e = run(6, Duration::from_secs(5), script(vec![err_dgram(5, 0, 5)]))
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(
                e.to_string(),
                "TIMEOUT: no reply for netlink request seq 6 within 5000 ms"
            );
        }

        /// NET-11・ERR-1: errno 17 は構造化エラー（ALREADY_EXISTS）。
        #[test]
        fn nonzero_errno_is_structured_error() {
            let e = run(3, Duration::from_secs(5), script(vec![err_dgram(3, 17, 3)]))
                .expect_err("eexist");
            assert_eq!(e.code(), NetErrorCode::AlreadyExists);
            assert_eq!(
                e.to_string(),
                "ALREADY_EXISTS: netlink request failed: errno 17"
            );
            let e = run(3, Duration::from_secs(5), script(vec![err_dgram(3, 1, 3)]))
                .expect_err("eperm");
            assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        }

        /// 拡張 ACK 付きの `NLMSG_ERROR`（capped。MSG と OFFS を持つ）。
        fn ext_err_dgram(seq: u32, errno: i32, msg: &[u8], offs: u32) -> Vec<u8> {
            let mut b = NlMsgBuilder::new(
                NLMSG_ERROR,
                crate::netlink::NLM_F_CAPPED | crate::netlink::NLM_F_ACK_TLVS,
                seq,
                TEST_LOCAL_PID.get(),
            );
            let mut p = Vec::new();
            p.extend_from_slice(&(-errno).to_ne_bytes());
            p.extend_from_slice(&[0u8; 8]);
            p.extend_from_slice(&seq.to_ne_bytes());
            p.extend_from_slice(&[0u8; 4]);
            let mut text = msg.to_vec();
            text.push(0);
            p.extend_from_slice(&((4 + text.len()) as u16).to_ne_bytes());
            p.extend_from_slice(&crate::netlink::NLMSGERR_ATTR_MSG.to_ne_bytes());
            p.extend_from_slice(&text);
            while !p.len().is_multiple_of(4) {
                p.push(0);
            }
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&crate::netlink::NLMSGERR_ATTR_OFFS.to_ne_bytes());
            p.extend_from_slice(&offs.to_ne_bytes());
            b.put_fixed(&p).expect("payload");
            b.finish().expect("finish")
        }

        /// NET-11・REPAIR-4: 拡張 ACK の文字列とオフセットがエラーの message に入る。
        #[test]
        fn ext_ack_message_is_in_error() {
            let dg = ext_err_dgram(3, 22, b"Unknown device type", 36);
            let e = run(3, Duration::from_secs(5), script(vec![dg])).expect_err("einval");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(
                e.to_string(),
                "INVALID_ARGUMENT: netlink request failed: errno 22: Unknown device type (at offset 36)"
            );
        }

        /// NET-11: ACK オプションの設定に失敗しても open 相当は成功扱い（両方 false）。片方だけの失敗も反映。
        #[test]
        fn enable_ack_options_ignores_failures() {
            use std::os::fd::AsFd as _;
            let fd = sys::open_route_socket().expect("open");
            let all_fail = enable_ack_options(fd.as_fd(), |_, _| Err(SysError::Os(92)));
            assert_eq!(
                all_fail,
                AckOptions {
                    ext_ack: false,
                    cap_ack: false
                }
            );
            let only_cap = enable_ack_options(fd.as_fd(), |_, o| match o {
                AckOpt::ExtAck => Err(SysError::Os(92)),
                AckOpt::CapAck => Ok(()),
            });
            assert_eq!(
                only_cap,
                AckOptions {
                    ext_ack: false,
                    cap_ack: true
                }
            );
        }

        /// NET-11: 実カーネルでは route ソケットだけ拡張 ACK が有効（Linux 4.12 以降前提）。
        #[test]
        fn route_socket_enables_ack_options_netfilter_does_not() {
            let route = NetlinkRouteSocket::open().expect("route");
            assert_eq!(
                route.ack_options(),
                AckOptions {
                    ext_ack: true,
                    cap_ack: true
                }
            );
            let nf = NetlinkRouteSocket::open_netfilter_with_recorder(Arc::new(NoopNetOpRecorder))
                .expect("netfilter");
            assert_eq!(
                nf.ack_options(),
                AckOptions {
                    ext_ack: false,
                    cap_ack: false
                }
            );
        }

        /// NET-11: 埋め込まれた元要求 seq が外側と食い違えば DataLoss。
        #[test]
        fn embedded_seq_mismatch_is_data_loss() {
            let e = run(3, Duration::from_secs(5), script(vec![err_dgram(3, 0, 4)]))
                .expect_err("data loss");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }

        /// NET-11: 応答メッセージを収集し、NLMSG_DONE で終端する。NOOP は無視する。
        #[test]
        fn collects_messages_until_done() {
            let mut dg = plain_dgram(16, 8, &[1, 2, 3, 4]);
            dg.extend(plain_dgram(NLMSG_NOOP, 8, &[]));
            dg.extend(plain_dgram(16, 8, &[5, 6, 7, 8]));
            let r = run(
                8,
                Duration::from_secs(5),
                script(vec![dg, plain_dgram(NLMSG_DONE, 8, &[0, 0, 0, 0])]),
            )
            .expect("done");
            let got: Vec<(u16, &[u8])> = r
                .messages()
                .iter()
                .map(|m| (m.msg_type(), m.payload()))
                .collect();
            assert_eq!(
                got,
                vec![(16, &[1u8, 2, 3, 4][..]), (16, &[5u8, 6, 7, 8][..])]
            );
        }

        /// NET-11: NLMSG_DONE のペイロードが負の errno なら、部分結果を返さずエラーにする。
        #[test]
        fn done_with_errno_is_error() {
            let payload = (-2i32).to_ne_bytes();
            let e = run(
                8,
                Duration::from_secs(5),
                script(vec![plain_dgram(NLMSG_DONE, 8, &payload)]),
            )
            .expect_err("dump failed");
            assert_eq!(e.code(), NetErrorCode::NotFound);
        }

        /// NET-11: NLMSG_DONE が空ペイロードなら成功。
        #[test]
        fn done_with_empty_payload_is_ok() {
            run(
                8,
                Duration::from_secs(5),
                script(vec![plain_dgram(NLMSG_DONE, 8, &[])]),
            )
            .expect("done");
        }

        /// NET-11: NLMSG_OVERRUN は DataLoss。
        #[test]
        fn overrun_is_data_loss() {
            let e = run(
                2,
                Duration::from_secs(5),
                script(vec![plain_dgram(NLMSG_OVERRUN, 2, &[0; 4])]),
            )
            .expect_err("overrun");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }

        /// NET-11: 壊れた応答（nlmsg_len 不整合）は DataLoss。
        #[test]
        fn malformed_reply_is_data_loss() {
            let e = run(2, Duration::from_secs(5), script(vec![vec![0xff; 20]]))
                .expect_err("malformed");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }

        /// 他宛て（`nlmsg_pid` 不一致）の固定バイト列。seq=5・pid=0x9999・errno 引数つきの `NLMSG_ERROR`。
        fn foreign_err_bytes(errno: i32) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&36u32.to_ne_bytes()); // nlmsg_len
            b.extend_from_slice(&NLMSG_ERROR.to_ne_bytes()); // nlmsg_type
            b.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
            b.extend_from_slice(&5u32.to_ne_bytes()); // nlmsg_seq
            b.extend_from_slice(&0x9999u32.to_ne_bytes()); // nlmsg_pid（他宛て）
            b.extend_from_slice(&(-errno).to_ne_bytes());
            b.extend_from_slice(&[0u8; 16]); // 元要求ヘッダ（seq 5 を後で埋める）
            b.get_mut(28..32)
                .expect("seq slot")
                .copy_from_slice(&5u32.to_ne_bytes());
            b
        }

        /// NET-11・#1313: pid 不一致の ACK は破棄され、続く自分宛て ACK で成功する。
        #[test]
        fn foreign_pid_ack_is_discarded_then_own_ack_succeeds() {
            let items = vec![foreign_err_bytes(0), err_dgram(5, 0, 5)];
            let r = run(5, Duration::from_secs(5), script(items)).expect("own ack");
            assert_eq!(r.seq(), 5);
        }

        /// NET-11・#1313: pid 不一致の errno はエラーとして伝播しない。
        #[test]
        fn foreign_pid_error_is_not_propagated() {
            let items = vec![foreign_err_bytes(17), err_dgram(5, 0, 5)];
            let r = run(5, Duration::from_secs(5), script(items)).expect("own ack");
            assert_eq!(r.seq(), 5);
        }

        /// NET-11・REPAIR-5・#1313: 他宛ての応答しか来なければ Timeout になる。
        #[test]
        fn only_foreign_pid_replies_time_out() {
            let items = vec![foreign_err_bytes(0), foreign_err_bytes(0)];
            let e = run(5, Duration::from_secs(5), script(items)).expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
        }

        /// NET-11・#1313: 終端と同じデータグラムの後ろにある他宛てメッセージは DataLoss にならない。
        #[test]
        fn foreign_pid_message_after_terminal_is_ignored() {
            let mut d = err_dgram(5, 0, 5);
            d.extend_from_slice(&foreign_err_bytes(0));
            let r = run(5, Duration::from_secs(5), script(vec![d])).expect("ok");
            assert_eq!(r.seq(), 5);
        }

        /// NET-11・#1313: dump は他宛ての DONE では終端せず、自分宛ての DONE で終端する。
        #[test]
        fn dump_ignores_foreign_pid_done() {
            let mut foreign = NlMsgBuilder::new(NLMSG_DONE, 0, 4, 0x9999);
            foreign.put_fixed(&[0u8; 4]).expect("payload");
            let items = vec![
                foreign.finish().expect("finish"),
                plain_dgram(16, 4, b"aaaa"),
                plain_dgram(NLMSG_DONE, 4, &[0u8; 4]),
            ];
            let r = await_reply_for(
                4,
                true,
                TEST_LOCAL_PID,
                &Deadline::after(Duration::from_secs(5)),
                Duration::from_secs(5),
                script(items),
            )
            .expect("ok");
            assert_eq!(r.messages().len(), 1);
        }

        /// NET-11・#1313: pid 0 は open 失敗（Internal）、非 0 はそのまま通る。
        #[test]
        fn nonzero_local_pid_rejects_zero() {
            let e = nonzero_local_pid(0).expect_err("zero");
            assert_eq!(e.code(), NetErrorCode::Internal);
            assert!(e.message().contains("port id 0"), "{}", e.message());
            assert_eq!(nonzero_local_pid(7).expect("ok").get(), 7);
        }

        /// NET-11・#1313: `BadLocalAddress` の写像。
        #[test]
        fn bad_local_address_maps_to_internal() {
            let e = map_sys_error("getsockname", SysError::BadLocalAddress);
            assert_eq!(e.code(), NetErrorCode::Internal);
            assert_eq!(
                e.message(),
                "getsockname: local address is not a netlink address"
            );
        }

        /// NET-11: dump では ACK が DONE より先に届いても完了せず、DONE までの応答を集める。
        #[test]
        fn dump_ack_before_done_keeps_collecting() {
            let items = vec![
                plain_dgram(16, 4, b"aaaa"),
                err_dgram(4, 0, 4),
                plain_dgram(16, 4, b"bbbb"),
                plain_dgram(NLMSG_DONE, 4, &[]),
            ];
            let r = await_reply_for(
                4,
                true,
                TEST_LOCAL_PID,
                &Deadline::after(Duration::from_secs(5)),
                Duration::from_secs(5),
                script(items),
            )
            .expect("ok");
            assert_eq!(r.messages().len(), 2);
        }

        /// NET-11: ACK と同じデータグラムで ACK の後ろに同じ seq の応答があれば、送出順に反するため DataLoss。
        #[test]
        fn trailing_message_after_ack_is_data_loss() {
            let mut dg = err_dgram(7, 0, 7);
            dg.extend(plain_dgram(16, 7, &[1, 2, 3, 4]));
            let r = run(7, Duration::from_secs(1), script(vec![dg]));
            assert_eq!(r.unwrap_err().code(), NetErrorCode::DataLoss);
        }

        /// NET-11: 終端の後ろの不正フレームも見逃さず DataLoss。
        #[test]
        fn malformed_frame_after_ack_is_error() {
            let mut dg = err_dgram(7, 0, 7);
            dg.extend([0xff, 0, 0, 0, 1]);
            let e = run(7, Duration::from_secs(1), script(vec![dg])).expect_err("malformed");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }

        /// NET-11: 非 dump では ACK より前の複数データグラムの応答をすべて到着順に集めてから、ACK で
        /// 終端する（カーネルは doit の応答を送り終えてから ACK を送る）。ACK の後のデータグラムは
        /// 読まない（次の往復が seq 不一致として破棄する）。
        #[test]
        fn non_dump_collects_replies_before_ack() {
            let mut queue = vec![
                plain_dgram(16, 9, b"aaaa"),
                plain_dgram(20, 9, b"bbbbbbbb"),
                err_dgram(9, 0, 9),
                plain_dgram(16, 10, b"next"),
            ];
            queue.reverse();
            let mut recvs = 0usize;
            let r = run(9, Duration::from_secs(5), |_| {
                recvs += 1;
                queue
                    .pop()
                    .ok_or_else(|| NetError::new(NetErrorCode::Timeout, "none"))
            })
            .expect("ack");
            let got: Vec<(u16, &[u8])> = r
                .messages()
                .iter()
                .map(|m| (m.msg_type(), m.payload()))
                .collect();
            assert_eq!(got, vec![(16, &b"aaaa"[..]), (20, &b"bbbbbbbb"[..])]);
            assert_eq!(recvs, 3);
            assert_eq!(queue, vec![plain_dgram(16, 10, b"next")]);
        }

        /// NET-11: dump の開始に失敗した errno 付き NLMSG_ERROR は、dump でもエラーで終端する。
        #[test]
        fn dump_start_failure_is_error() {
            let e = await_reply_for(
                4,
                true,
                TEST_LOCAL_PID,
                &Deadline::after(Duration::from_secs(5)),
                Duration::from_secs(5),
                script(vec![err_dgram(4, 95, 4)]),
            )
            .expect_err("eopnotsupp");
            assert_eq!(e.code(), NetErrorCode::Unimplemented);
            assert_eq!(
                e.to_string(),
                "UNIMPLEMENTED: netlink request failed: errno 95"
            );
        }

        /// NET-11: NLM_F_DUMP_INTR の dump は FailedPrecondition（再試行可能）。
        #[test]
        fn dump_intr_is_retryable_error() {
            let mut b = NlMsgBuilder::new(16, NLM_F_DUMP_INTR, 4, TEST_LOCAL_PID.get());
            b.put_fixed(b"aaaa").expect("payload");
            let items = vec![b.finish().expect("finish")];
            let e = await_reply_for(
                4,
                true,
                TEST_LOCAL_PID,
                &Deadline::after(Duration::from_secs(5)),
                Duration::from_secs(5),
                script(items),
            )
            .expect_err("intr");
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        }

        /// NET-11: DUMP_INTR は dump 判定によらず検出する（DONE 側に立っても成功にしない）。
        #[test]
        fn dump_intr_on_done_is_detected_without_dump_flag() {
            let mut b = NlMsgBuilder::new(NLMSG_DONE, NLM_F_DUMP_INTR, 4, TEST_LOCAL_PID.get());
            b.put_fixed(&[0u8; 4]).expect("payload");
            let e = run(
                4,
                Duration::from_secs(5),
                script(vec![b.finish().expect("finish")]),
            )
            .expect_err("intr");
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
            assert_eq!(
                e.to_string(),
                "FAILED_PRECONDITION: netlink dump for seq 4 was interrupted (NLM_F_DUMP_INTR); retry"
            );
        }

        /// NET-11: NLMSG_DONE のペイロードは先頭の int だけを読む（extended ACK の属性が続いても
        /// nlmsgerr の元要求ヘッダ検査で DataLoss にしない）。不正値は DataLoss。
        #[test]
        fn done_payload_is_a_leading_int() {
            assert_eq!(decode_done_errno(&[]).expect("empty"), 0);
            assert_eq!(decode_done_errno(&0i32.to_ne_bytes()).expect("zero"), 0);
            assert_eq!(
                decode_done_errno(&(-2i32).to_ne_bytes()).expect("enoent"),
                2
            );
            let mut with_tlv = (-22i32).to_ne_bytes().to_vec();
            with_tlv.extend_from_slice(&[8, 0, 1, 0, b'e', b'r', b'r', 0]);
            assert_eq!(decode_done_errno(&with_tlv).expect("tlv"), 22);
            for bad in [
                vec![0u8; 3],
                1i32.to_ne_bytes().to_vec(),
                i32::MIN.to_ne_bytes().to_vec(),
            ] {
                assert_eq!(
                    decode_done_errno(&bad).expect_err("bad").code(),
                    NetErrorCode::DataLoss
                );
            }
        }

        /// REPAIR-3: 空ペイロードのメッセージでも件数上限で打ち切る。
        #[test]
        fn empty_payload_messages_are_bounded() {
            let dgram = plain_dgram(16, 4, &[]);
            let e = run(4, Duration::from_secs(30), |_| Ok(dgram.clone())).expect_err("exhausted");
            assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        }

        /// REPAIR-5: 期限切れ後は門が空いていても取得できない。
        #[test]
        fn repair5_expired_deadline_does_not_acquire_gate() {
            let gate = RequestGate::default();
            let e = gate
                .acquire(&Deadline::after(Duration::ZERO), Duration::ZERO)
                .err()
                .expect("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
        }

        /// REPAIR-5: build 中に期限が切れたら送信しない。
        #[test]
        fn repair5_expired_during_build_is_not_sent() {
            let s = NetlinkRouteSocket::open().expect("open");
            let e = s
                .request(RTM_GETLINK, 0, Duration::from_millis(50), |b| {
                    std::thread::sleep(Duration::from_millis(100));
                    b.put_fixed(&[0u8; 16])
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
        }

        /// NET-11: 収集上限（合計 16 MiB）を超えると ResourceExhausted。
        #[test]
        fn reply_collection_is_bounded() {
            let big = vec![0u8; 512 * 1024];
            let items: Vec<Vec<u8>> = (0..40).map(|_| plain_dgram(16, 4, &big)).collect();
            let e = run(4, Duration::from_secs(30), script(items)).expect_err("exhausted");
            assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        }

        /// REPAIR-5: seq 不一致の応答が流れ続けても、往復全体の期限で Timeout になる
        /// （受信のたびに期限が延びない）。
        #[test]
        fn repair5_total_deadline_bounds_endless_mismatches() {
            let started = std::time::Instant::now();
            let e = run(9, Duration::from_millis(200), |_| {
                std::thread::sleep(Duration::from_millis(20));
                Ok(err_dgram(1, 0, 1))
            })
            .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() >= Duration::from_millis(200));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// REPAIR-5: timeout 0 は待たずに Timeout（届いていない応答は待たない）。
        #[test]
        fn repair5_zero_timeout_does_not_wait() {
            let s = NetlinkRouteSocket::open().expect("open");
            let started = std::time::Instant::now();
            let e = await_reply(1, &Deadline::after(Duration::ZERO), Duration::ZERO, |t| {
                s.recv(t)
            })
            .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: 実ソケットで何も来なければ全体期限で Timeout。
        #[test]
        fn await_reply_times_out_on_silent_socket() {
            let s = NetlinkRouteSocket::open().expect("open");
            let total = Duration::from_millis(200);
            let started = std::time::Instant::now();
            let e =
                await_reply(1, &Deadline::after(total), total, |t| s.recv(t)).expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() >= Duration::from_millis(200));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// REPAIR-5: 別の往復が飛んでいる間の順番待ちも自分の timeout で打ち切る。
        #[test]
        fn repair5_waiting_for_the_gate_is_bounded() {
            let s = NetlinkRouteSocket::open().expect("open");
            let _busy = s
                .gate
                .acquire(
                    &Deadline::after(Duration::from_secs(30)),
                    Duration::from_secs(30),
                )
                .expect("gate");
            let started = std::time::Instant::now();
            let e = s
                .request(RTM_GETLINK, 0, Duration::from_millis(150), |b| {
                    b.put_fixed(&[0u8; 16])
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-4: 実カーネル往復。lo の GETLINK が RTM_NEWLINK 1 件で成功し、seq は
        /// 往復ごとに +1。build の失敗は送信せずに伝播する。
        #[test]
        fn request_roundtrip_against_kernel() {
            use crate::instrument::NetOpOutcome;
            use crate::instrument::testing::Collect;
            let collect = Arc::new(Collect::default());
            let s = NetlinkRouteSocket::open_with_recorder(collect.clone()).expect("open");
            let lo = |b: &mut NlMsgBuilder| {
                let mut ifi = [0u8; 16];
                ifi[4..8].copy_from_slice(&1i32.to_ne_bytes());
                b.put_fixed(&ifi)
            };
            let r1 = s
                .request(RTM_GETLINK, 0, Duration::from_secs(5), lo)
                .expect("request 1");
            assert_eq!(r1.seq(), 1);
            assert_eq!(r1.messages().len(), 1);
            assert_eq!(
                r1.messages().first().map(|m| m.msg_type()),
                Some(RTM_NEWLINK)
            );
            let r2 = s
                .request(RTM_GETLINK, 0, Duration::from_secs(5), lo)
                .expect("request 2");
            assert_eq!(r2.seq(), 2);
            let e = s
                .request(RTM_GETLINK, 0, Duration::from_secs(5), |_| {
                    Err(NetError::new(NetErrorCode::InvalidArgument, "bad"))
                })
                .expect_err("build failure");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let kinds = collect.kinds();
            assert_eq!(
                kinds
                    .iter()
                    .filter(|k| k.0 == NetOpKind::NetlinkRequest)
                    .count(),
                3
            );
            assert_eq!(
                kinds
                    .iter()
                    .filter(|k| k.0 == NetOpKind::NetlinkSend)
                    .count(),
                2
            );
            assert_eq!(
                kinds.last(),
                Some(&(NetOpKind::NetlinkRequest, NetOpOutcome::Failure))
            );
        }

        /// NET-11: 複数スレッドから `&self` で共有できる（`Send + Sync`）。
        #[test]
        fn socket_is_send_and_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<NetlinkRouteSocket>();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-11: seq は 1 から増え、u32 を一周したら 0 を飛ばして 1 へ戻る。
    #[test]
    fn seq_allocator_skips_zero() {
        let a = SeqAllocator::new();
        assert_eq!((a.next(), a.next(), a.next()), (1, 2, 3));
        let w = SeqAllocator::starting_at(u32::MAX);
        assert_eq!((w.next(), w.next(), w.next()), (u32::MAX, 1, 2));
    }

    fn payload(error: i32, inner_seq: Option<u32>) -> Vec<u8> {
        let mut v = error.to_ne_bytes().to_vec();
        if let Some(s) = inner_seq {
            v.extend_from_slice(&[0u8; 8]);
            v.extend_from_slice(&s.to_ne_bytes());
            v.extend_from_slice(&[0u8; 4]);
        }
        v
    }

    /// NET-11・ERR-1: nlmsgerr の復号（ACK・errno・元要求 seq の有無）。
    #[test]
    fn decode_nlmsgerr_values() {
        let ack = decode_nlmsgerr(&payload(0, Some(7))).expect("ack");
        assert_eq!(
            (ack.errno(), ack.is_ack(), ack.request_seq()),
            (0, true, Some(7))
        );
        let e = decode_nlmsgerr(&payload(-17, Some(9))).expect("errno");
        assert_eq!(
            (e.errno(), e.is_ack(), e.request_seq()),
            (17, false, Some(9))
        );
        let short = decode_nlmsgerr(&payload(-2, None)).expect("no header");
        assert_eq!((short.errno(), short.request_seq()), (2, None));
        // 5..=19 バイト（元ヘッダが中途半端）は DataLoss。
        let mut cut = payload(-2, Some(5));
        cut.truncate(4 + 12);
        assert_eq!(
            decode_nlmsgerr(&cut).expect_err("partial").code(),
            NetErrorCode::DataLoss
        );
    }

    /// NET-11: 不正なペイロードは DataLoss（3 バイト・正値・i32::MIN・空）。
    #[test]
    fn decode_nlmsgerr_rejects_malformed() {
        for bad in [
            vec![0u8; 3],
            payload(1, None),
            payload(i32::MIN, None),
            Vec::new(),
        ] {
            let e = decode_nlmsgerr(&bad).expect_err("malformed");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
        }
    }

    // --- 拡張 ACK（NET-11・REPAIR-2・REPAIR-4） ---

    fn tlv(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut v = ((4 + data.len()) as u16).to_ne_bytes().to_vec();
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(data);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    /// capped: error + 元ヘッダ 16 バイト + TLV。
    fn capped(error: i32, seq: u32, tlvs: &[u8]) -> Vec<u8> {
        let mut v = payload(error, Some(seq));
        v.extend_from_slice(tlvs);
        v
    }

    const CAPPED_TLVS: u16 = NLM_F_CAPPED | NLM_F_ACK_TLVS;

    #[test]
    fn ext_ack_capped_message() {
        let p = capped(-22, 7, &tlv(NLMSGERR_ATTR_MSG, b"Unknown device type\0"));
        let a = decode_nlmsgerr_with_flags(CAPPED_TLVS, &p).expect("ok");
        assert_eq!(a.errno(), 22);
        assert_eq!(a.request_seq(), Some(7));
        assert_eq!(a.ext_message(), Some("Unknown device type"));
        assert_eq!(a.ext_offset(), None);
        assert_eq!(
            a.failure_message(),
            "netlink request failed: errno 22: Unknown device type"
        );
    }

    #[test]
    fn ext_ack_capped_message_and_offset() {
        let mut t = tlv(NLMSGERR_ATTR_MSG, b"Unknown device type\0");
        t.extend(tlv(NLMSGERR_ATTR_OFFS, &36u32.to_ne_bytes()));
        let a = decode_nlmsgerr_with_flags(CAPPED_TLVS, &capped(-22, 7, &t)).expect("ok");
        assert_eq!(a.ext_offset(), Some(36));
        assert_eq!(
            a.failure_message(),
            "netlink request failed: errno 22: Unknown device type (at offset 36)"
        );
        let only_off = tlv(NLMSGERR_ATTR_OFFS, &8u32.to_ne_bytes());
        let a = decode_nlmsgerr_with_flags(CAPPED_TLVS, &capped(-22, 7, &only_off)).expect("ok");
        assert_eq!(
            a.failure_message(),
            "netlink request failed: errno 22 (at offset 8)"
        );
    }

    #[test]
    fn ext_ack_uncapped_message() {
        // 元ヘッダの nlmsg_len = 21（本体 5 バイト）。本体はパディング込み 8 バイト写される。
        let mut p = payload(-22, Some(7));
        p.get_mut(4..8)
            .expect("len field")
            .copy_from_slice(&21u32.to_ne_bytes());
        p.extend_from_slice(&[0xAA; 8]);
        p.extend(tlv(NLMSGERR_ATTR_MSG, b"bad attr\0"));
        let a = decode_nlmsgerr_with_flags(NLM_F_ACK_TLVS, &p).expect("ok");
        assert_eq!(a.ext_message(), Some("bad attr"));
    }

    #[test]
    fn ext_ack_on_success_ack() {
        let p = capped(0, 5, &tlv(NLMSGERR_ATTR_MSG, b"warning\0"));
        let a = decode_nlmsgerr_with_flags(CAPPED_TLVS, &p).expect("ok");
        assert!(a.is_ack());
        assert_eq!(a.ext_message(), Some("warning"));
    }

    /// REPAIR-2: 壊れた TLV・範囲外の長さは拡張部分だけ捨てて errno は返す。
    #[test]
    fn ext_ack_broken_tlvs_are_ignored() {
        let mut long_rta = 200u16.to_ne_bytes().to_vec();
        long_rta.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
        long_rta.extend_from_slice(b"abc\0");
        let mut small_rta = 2u16.to_ne_bytes().to_vec();
        small_rta.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
        let cases: Vec<(u16, Vec<u8>)> = vec![
            (CAPPED_TLVS, capped(-22, 7, &long_rta)),
            (CAPPED_TLVS, capped(-22, 7, &small_rta)),
            (CAPPED_TLVS, capped(-22, 7, &[1, 2, 3])),
            // uncapped: 元の nlmsg_len が 16 未満・payload 超え・桁あふれ寸前
            (NLM_F_ACK_TLVS, payload(-22, Some(7))),
            (NLM_F_ACK_TLVS, {
                let mut p = payload(-22, Some(7));
                p.get_mut(4..8)
                    .expect("len")
                    .copy_from_slice(&1000u32.to_ne_bytes());
                p
            }),
            (NLM_F_ACK_TLVS, {
                let mut p = payload(-22, Some(7));
                p.get_mut(4..8)
                    .expect("len")
                    .copy_from_slice(&u32::MAX.to_ne_bytes());
                p
            }),
        ];
        for (flags, p) in cases {
            let a = decode_nlmsgerr_with_flags(flags, &p).expect("errno survives");
            assert_eq!((a.errno(), a.request_seq()), (22, Some(7)));
            assert_eq!((a.ext_message(), a.ext_offset()), (None, None));
        }
    }

    #[test]
    fn ext_ack_bad_offset_length_is_ignored() {
        for len in [2usize, 8] {
            let mut t = tlv(NLMSGERR_ATTR_MSG, b"hi\0");
            t.extend(tlv(NLMSGERR_ATTR_OFFS, &vec![0u8; len]));
            let a = decode_nlmsgerr_with_flags(CAPPED_TLVS, &capped(-22, 7, &t)).expect("ok");
            assert_eq!((a.ext_message(), a.ext_offset()), (Some("hi"), None));
        }
    }

    #[test]
    fn sanitize_rules() {
        let long = vec![b'a'; 200];
        assert_eq!(
            sanitize_ext_ack_message(&long),
            Some(format!("{}...", "a".repeat(128)))
        );
        assert_eq!(sanitize_ext_ack_message(b"tail"), Some("tail".to_string()));
        assert_eq!(
            sanitize_ext_ack_message(b"bad\nline\x1b[31m\xff"),
            Some("bad?line?[31m?".to_string())
        );
        assert_eq!(sanitize_ext_ack_message(b"ab\0cd"), Some("ab".to_string()));
        assert_eq!(sanitize_ext_ack_message(b""), None);
        assert_eq!(sanitize_ext_ack_message(b"   \0x"), None);
    }

    /// AC3: flags なしなら TLV が続いても解釈せず、従来の結果と同じ。
    #[test]
    fn ext_ack_ignored_without_flag() {
        let p = capped(-22, 7, &tlv(NLMSGERR_ATTR_MSG, b"x\0"));
        let a = decode_nlmsgerr_with_flags(0, &p).expect("ok");
        assert_eq!((a.ext_message(), a.ext_offset()), (None, None));
        assert_eq!(decode_nlmsgerr(&p).expect("ok"), a);
        assert_eq!(a.failure_message(), "netlink request failed: errno 22");
    }

    /// REPAIR-2: 任意バイト列とフラグの組でも panic しない。
    #[test]
    fn ext_ack_no_panic_on_arbitrary_bytes() {
        for flags in [0, NLM_F_CAPPED, NLM_F_ACK_TLVS, CAPPED_TLVS] {
            for n in 0..64usize {
                let buf: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
                let _ = decode_nlmsgerr_with_flags(flags, &buf);
                let ff = vec![0xFFu8; n];
                let _ = decode_nlmsgerr_with_flags(flags, &ff);
            }
        }
    }
}
