//! nf_tables バッチの ACK / エラー判定と構造化エラー（TASK-137.3・NET-11・REPAIR-2・REPAIR-5・MS-8・#306）。
//!
//! `NetlinkNetfilterSocket::send_batch`（同 crate の `socket`。Linux のみ）が受信した
//! データグラムを [`NftBatchAckCollector`] へ渡し、バッチ内の本体メッセージごとの ACK / `NLMSG_ERROR` を
//! 集める。ソケット I/O を持たない純粋な状態機械なので、判定ロジックは scripted なデータグラムで
//! 単体テストする。errno の分類に Linux 値（`netlink_route::classify_errno`）を使うため、
//! 本モジュールも Linux でのみビルドされる。
//!
//! # カーネルの挙動（`net/netfilter/nfnetlink.c`）と判定規則
//!
//! - バッチは all-or-nothing。本体にエラーがあっても処理は止まらず、全エラーを積んだうえでバッチ全体を
//!   abort し、ACK / エラー列を送信順に配送する。よって他の本体の errno 0 の ACK は「適用済み」を意味せず、
//!   1 件でも失敗があれば [`NftBatchOutcome::Aborted`]（何も適用されていない）になる
//! - 権限不足（`CAP_NET_ADMIN` なし）の `-EPERM` や `-ENOMEM`・commit の失敗はバッチ先頭（BEGIN）の seq に
//!   対して返る。BEGIN / END の非 0 errno は [`NftBatchPosition::Begin`] / [`NftBatchPosition::End`] として
//!   記録し、バッチ全体の失敗なので本体の判定が揃っていなくても「判定済み」（[`Progress::Decided`]）にする。
//!   ただし即座には確定せず、本体の失敗と同じく同期点まで読み、同じデータグラムの後続や別データグラムの
//!   失敗も `failures()` に集める（失敗の全件返却。NET-11）
//! - BEGIN / END への errno 0 の ACK は許容して無視する（カーネル版数で返る場合がある）
//! - 判定済みの条件は「本体の全 seq に判定が揃う」または「BEGIN / END が失敗した」。END は `NLM_F_ACK` を
//!   持たず成功時は無応答のため待てないが、失敗（非 0 errno）が別データグラムで届き得る。そこで判定後に
//!   同期点（nf_tables の `NFT_MSG_GETGEN` + `NLM_F_ACK` の別要求）を送り、その応答が届くまで読む
//!   （`socket::drain_until_barrier`）。応答は FIFO のため、同期点への応答より前の応答はすべて `feed` 済みに
//!   なり、[`NftBatchAckCollector::conclude`] で最終判定する。時間の経過で「終わり」と推定しない
//! - 同期点への応答は `NFT_MSG_NEWGEN`（同じ seq）→ errno 0 の `NLMSG_ERROR` の順に届く
//!   （`nf_tables_getgen` が NEWGEN を unicast してから 0 を返し、`netlink_rcv_skb` が ACK を積む）。
//!   NEWGEN を受けずに届いた errno 0 の ACK は GETGEN が実行された証拠にならないので `DataLoss`、
//!   同期点の seq を持つそれ以外の type も `DataLoss` にする（カーネル応答の境界検査）
//! - 同期点の NEWGEN は外部入力として nfgenmsg を echo と同じ粒度で照合する（#3039・NET-3・SEC-1）。
//!   ペイロードは 4 バイト以上、version は `NFNETLINK_V0`、family は `NFPROTO_UNSPEC` でなければ `DataLoss`
//!   （`nf_tables_fill_gen_info` が `nfnl_msg_put(..., AF_UNSPEC, NFNETLINK_V0, ...)` で固定するため。根拠の版と
//!   行は下の「stable・distro との差」）。`res_id`（世代番号）・flags・属性（`NFTA_GEN_ID` 等。世代番号は
//!   未使用。REPAIR-3）は見ない。同じ seq の 2 通目の NEWGEN と同期点の ACK / エラー後の NEWGEN も `DataLoss`
//!   （`nf_tables_getgen` は NEWGEN を 1 通だけ unicast してから ACK が積まれる）。拒否は `Unknown`（上位は
//!   quarantine 側）
//! - 同期点が非 0 errno で拒否された場合（権限不足のバッチでは同期点も `EPERM`）も、その応答はバッチより後に
//!   処理された要求への応答なので読み切りの印になる。失敗を集めていれば `Aborted`、なければ適用状態を
//!   確認できないので `Unknown` にする
//!
//! # NEWRULE の echo 応答（ルールハンドルの取得。NET-3・CRI-2・SEC-1・#2839・#2905）
//!
//! `NLM_F_ECHO` 付きで積んだ NEWRULE（`NftBatchBytes::body_echo` が真の本体）には、ACK とは別に
//! 追加したルールそのものが NEWRULE メッセージとして送り元へ返り（echo。`nlmsg_seq` は要求の seq）、
//! ペイロードの `NFTA_RULE_HANDLE`（`__be64`）にカーネルが採番したハンドルが入る。
//!
//! ## 到着順と送信条件（一次情報。Linux v6.12 = commit `adc218676eef25575469234709c2d87185ca223a`）
//!
//! URL は `https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/<path>#L<行>`。
//!
//! - 到着順は **echo → 各 ACK → 同期点の応答**。`net/netfilter/nfnetlink.c` の `nfnetlink_rcv_batch` は
//!   BEGIN / 本体の ACK・エラーを `err_list` に積むだけで（L430-433・L535-559。L537-540 のコメント
//!   「Errors are delivered once the full batch has been processed」）、`ss->commit`（L574）の後、最後の
//!   `nfnl_err_deliver`（L603）で送る。echo は `net/netfilter/nf_tables_api.c` の `nf_tables_commit`
//!   （L10300〜。`nf_tables_rule_notify` の呼び出しは L10465 / L10475）が作り、末尾の `nft_commit_notify`
//!   （L10173-10207・呼び出し L10623）が `nfnetlink_send`（nfnetlink.c L176-182）→ `nlmsg_notify`
//!   （`net/netlink/af_netlink.c` L2564〜）で要求元へ unicast する。同じソケットの受信キュー（FIFO）に
//!   入るため、成功したバッチでは echo（本体の順。複数件が 1 データグラムにまとまることがある）→ ACK の順
//!   になる。それでも本実装は **両方の順を受理する**（判定の決め手は「同期点までに要求した echo が揃う
//!   こと」で順序に依存しない。順序を厳格にしても安全性は増えず、別版のカーネルの差で `Unknown` になる
//!   危険だけが増えるため）。
//! - 送信条件: `nft_ctx_init`（nf_tables_api.c L130-148）が要求の `NLM_F_ECHO` を `ctx->report`
//!   （L146。`include/net/netlink.h` L916-919 の `nlmsg_report`）に写し、`nf_tables_rule_notify`
//!   （L3513-3554）は `NLM_F_ECHO` 付きなら必ず通知を作る（L3523-3525）。echo の flags は
//!   `NLM_F_APPEND` / `NLM_F_CREATE` / `NLM_F_EXCL` だけで `NLM_F_REQUEST` は付かない（L3537-3540）。
//!   `nf_tables_fill_rule_info`（L3454〜）の nfgenmsg は `family = ctx->family`・`res_id = nft_base_seq(net)`
//!   （L3467-3468。**世代番号で 0 ではない**。version は `NFNETLINK_V0` 固定）で、`NFTA_RULE_TABLE` /
//!   `NFTA_RULE_CHAIN`（NUL 込みの文字列。L3472・L3474）・`NFTA_RULE_HANDLE`（L3476）、条件つきで POSITION / EXPRESSIONS / USERDATA が続く。
//! - echo が届かない場合: (1) 通知用 skb の確保・組み立ての失敗は `nfnetlink_set_err`（L3553）だが、
//!   `do_one_set_err`（af_netlink.c L1561〜。飛ばす根拠は L1566-1567 の `sk == p->exclude_sk` と L1572 の
//!   `nlk->portid == p->portid`）は要求元のソケットを飛ばすため要求元には何の知らせも無く echo
//!   が欠ける、(2) 受信キューのあふれは `nlmsg_unicast`（`MSG_DONTWAIT`）の `netlink_overrun`
//!   （af_netlink.c L350-360）で要求元に `ENOBUFS`（`socket` が `ResourceExhausted`・`Unknown` にする）、
//!   (3) バッチの失敗（本体のエラー・commit の失敗）は abort で echo が出ない（`-EAGAIN` の replay では
//!   最後の 1 回分だけ届く。nfnetlink.c L567-572 の `NFNL_BATCH_REPLAY` と L575-577 の commit の `-EAGAIN`）。(1) が黙って起きるため、「同期点までに要求した echo が
//!   揃わなければ `Unknown`」が必須の守りになる。
//! - BEGIN には `NLM_F_ECHO` を付けない前提: commit 後の `nf_tables_gen_notify(NEWGEN)`（L10624）は BEGIN
//!   の `NLM_F_ECHO` を見るため、付けると BEGIN の seq に NEWGEN が届き `DataLoss` になる。
//!
//! ## 検証の規則
//!
//! echo と ACK はどちらも同期点（GETGEN）への応答より前に届くため、読み切り判定は変えない。echo は外部入力
//! として次を fail-closed（`DataLoss`・`Unknown`）にする: echo を要求していない本体への NEWRULE・同じ本体
//! への重複・nfgenmsg より短いペイロード・BEGIN / END の seq への NEWRULE・**nfgenmsg の family、
//! `NFTA_RULE_TABLE`、`NFTA_RULE_CHAIN` が要求（`NftBatch::push_with` が積んだバイト列から取った期待値。
//! `RuleEchoExpect`）とバイト単位で一致しないもの**（欠落・重複・ネスト・NUL の不正を含む。seq が合っていても
//! 別のルールのハンドルを採ると、後の DELRULE が別のルールを消しうるため。SEC-1）・ハンドル属性の
//! 欠落 / 重複 / 8 バイト以外 / 0（`NftRuleHandle::from_rule_attrs`）。加えて nfgenmsg の version が `NFNETLINK_V0`
//! 以外のもの（v6.12・v5.15 とも `nf_tables_fill_rule_info` は `nfnl_msg_put(..., NFNETLINK_V0, ...)` で 0 に
//! 固定するため、0 以外は解釈の前提が崩れた応答。#2970）も拒否する。比べるのは version・family の各 1 バイトと
//! 2 つの名前だけで、`res_id`（世代番号）・flags・他の属性は見ない。エラーメッセージに名前や受信バイト列は
//! 載せない。echo を要求した本体のハンドルが同期点までに揃わない場合と、失敗を集めたのに echo を受けていた
//! （矛盾する応答）場合も `Unknown`（コミット済みかもしれないがハンドルが不明。上位は quarantine に倒す）。
//!
//! ## v5.15 との差（一次情報。Linux v5.15 = commit `8bb7eca972ad531c9b149c0a51ab43a417385813`。#2970・REPAIR-3）
//!
//! 同じ: `nft_ctx_init` の `ctx->report = nlmsg_report(nlh)`（L142）・`nf_tables_fill_rule_info` の
//! `nfnl_msg_put(..., NFNETLINK_V0, nft_base_seq(net))`（L2884-2885）・`nft_commit_notify`（L8432〜。呼び出し L8750）
//! → `nf_tables_gen_notify(NEWGEN)`（L8751）の順・`ss->commit`（nfnetlink.c L562）→ `nfnl_err_deliver`（L590）。
//! よって echo の送信条件・到着順（echo → ACK → 同期点）・echo の version（0）は変わらず、version の照合は
//! v5.15 でも正常な echo を拒否しない。
//!
//! 差: v5.15 の `nfnetlink_rcv_batch` は本体の `NLM_F_ACK`（L525）にしか errno 0 を積まず、v6.12 の BEGIN の ACK
//! （L430-433）と END の ACK（L581-584）は無い。本実装は BEGIN / END に `NLM_F_ACK` を付けず errno 0 の ACK の到着を
//! 判定に使わないので影響しない。
//!
//! ## stable・distro との差（#3039・NET-3・SEC-1・REPAIR-3）
//!
//! 同期点の NEWGEN（`nf_tables_fill_gen_info`）と echo（`nf_tables_fill_rule_info`）の形を、次の 6 版で
//! `net/netfilter/nf_tables_api.c` / `nfnetlink.c` の一次情報から確かめた。どの版も NEWGEN は
//! `nfnl_msg_put(skb, portid, seq, event, 0, AF_UNSPEC, NFNETLINK_V0, <世代番号>)`（family 0・version 0・
//! res_id = 世代番号）で、`nf_tables_getgen` が NEWGEN を 1 通 unicast してから戻り、echo の送信条件
//! （`ctx->report`・`NLM_F_ECHO`）・到着順（echo → ACK → 同期点）・echo の version 0・属性の並びも同じ。
//!
//! | 版（commit） | `nf_tables_fill_gen_info` / `nfnl_msg_put` | `nf_tables_getgen` の unicast |
//! | --- | --- | --- |
//! | upstream v5.15（`8bb7eca972ad531c9b149c0a51ab43a417385813`） | L7825 / L7833-7834 | L7927 |
//! | upstream v6.12（`adc218676eef25575469234709c2d87185ca223a`） | L9218 / L9226-9227 | L9320 |
//! | stable v5.15.223（`792fbe1537d8daeca9bd1917e84078b5432aadc2`） | L8502 / L8510-8511 | L8604 |
//! | Ubuntu jammy `Ubuntu-5.15.0-203.213`（`b14aab7b783edc43be8c9f766561087b04fdfcba`。5.15.223 相当） | L8552 / L8560-8561 | L8654 |
//! | stable v6.12.114（`85d82e0d7c2dfd3e75d34f35b7ebbf41f45c9c4e`） | L9294 / L9301-9302 | L9395 |
//! | Ubuntu noble `Ubuntu-6.8.0-149.149`（`6dcf89bf9d1650d117680189bf4bbb596af7ab84`。6.8.12 相当） | L9097 / L9104-9105 | L9198 |
//!
//! 版による差は 2 つだけで、どちらも本実装の判定に影響しない。(a) BEGIN / END への errno 0 の ACK は v6.12 系にだけ
//! あり、5.15 系と Ubuntu 6.8 には無い（判定に使わない）。(b) `res_id` を作る関数が v5.15 系の `nft_base_seq()` と
//! v6.12.114・Ubuntu 6.8 の `nft_base_seq_be16()` で違う（意味は同じで、`res_id` は照合しない）。
//!
//! 未確認: Debian・RHEL 系などほかの distro、Ubuntu 24.04 の HWE（6.8 より新しい版）、6.1.y・6.6.y の stable、
//! 各 distro の今後のパッチ。実カーネルでの観測は #1626（人間担当）。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! extended ACK（`NETLINK_EXT_ACK`）の解釈と、`NFTA_GEN_ID` による楽観的並行制御は未実装。

use std::fmt;
use std::time::Duration;

use super::NftBatchOutcome;
use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLMSG_ERROR, NLMSG_NOOP, NlMsgIter};
use crate::netlink_route::{classify_errno, decode_nlmsgerr};
use crate::nftables_batch::{
    NFGENMSG_LEN, NFNETLINK_V0, NFNL_SUBSYS_NFTABLES, NFPROTO_UNSPEC, NfGenMsg, NftBatchBytes,
    RuleEchoExpect, nfnl_msg_type,
};
use crate::nftables_rules::{NFT_MSG_NEWRULE, NftRuleHandle, rule_table_chain_attrs};

/// nf_tables の世代番号の照会（`linux/netfilter/nf_tables.h` の `NFT_MSG_GETGEN`）。同期点に使う。
pub(crate) const NFT_MSG_GETGEN: u8 = 16;
/// `NFT_MSG_GETGEN` への応答（`NFT_MSG_NEWGEN`）。
pub(crate) const NFT_MSG_NEWGEN: u8 = 15;
/// 同期点への応答 `NFT_MSG_NEWGEN` の `nlmsg_type`（0x0A0F）。
const NEWGEN_TYPE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWGEN);
/// `NLM_F_ECHO` に対する応答 `NFT_MSG_NEWRULE` の `nlmsg_type`（0x0A06）。
const NEWRULE_TYPE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE);

/// 失敗したメッセージのバッチ内位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NftBatchPosition {
    /// `NFNL_MSG_BATCH_BEGIN`（権限不足などバッチ全体の失敗）。
    Begin,
    /// 本体メッセージ。`index` は `NftBatchBytes::body_seqs` の何番目か（0 始まり）。
    Body {
        /// 積んだ順の添字。
        index: usize,
    },
    /// `NFNL_MSG_BATCH_END`。
    End,
}

impl fmt::Display for NftBatchPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Begin => f.write_str("begin"),
            Self::Body { index } => write!(f, "body[{index}]"),
            Self::End => f.write_str("end"),
        }
    }
}

/// カーネルが失敗を返した 1 メッセージ（どのメッセージが何で失敗したか。NET-11）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftMessageFailure {
    position: NftBatchPosition,
    seq: u32,
    errno: i32,
    code: NetErrorCode,
}

impl NftMessageFailure {
    /// バッチ内の位置。
    pub fn position(&self) -> NftBatchPosition {
        self.position
    }

    /// 失敗したメッセージの `nlmsg_seq`。
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// カーネルが返した正の errno。
    pub fn errno(&self) -> i32 {
        self.errno
    }

    /// errno を分類した機械可読なコード（ERR-1）。
    pub fn code(&self) -> NetErrorCode {
        self.code
    }
}

/// バッチ送信の構造化エラー（`code` / `message` に加え、失敗メッセージの一覧と適用状態を持つ）。
///
/// `message` は英語で、件数・添字・seq・errno の数値だけを載せる（テーブル名や受信バイト列は載せない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftBatchError {
    error: NetError,
    outcome: NftBatchOutcome,
    failures: Vec<NftMessageFailure>,
}

impl NftBatchError {
    /// 送信前の失敗（空バッチ・期限切れ・組み立て失敗・送信拒否）。
    pub(crate) fn not_sent(error: NetError) -> Self {
        Self {
            error,
            outcome: NftBatchOutcome::NotSent,
            failures: Vec::new(),
        }
    }

    /// 送信後に適用されたか不明な失敗（部分送信など。失敗一覧は空）。
    pub(crate) fn unknown_outcome(error: NetError) -> Self {
        Self {
            error,
            outcome: NftBatchOutcome::Unknown,
            failures: Vec::new(),
        }
    }

    /// 機械可読な分類。`Aborted` ではカーネルが返した先頭の失敗の分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }

    /// バッチが適用されたか。
    pub fn outcome(&self) -> NftBatchOutcome {
        self.outcome
    }

    /// 失敗したメッセージの一覧（Begin・本体の添字順・End の順）。
    pub fn failures(&self) -> &[NftMessageFailure] {
        &self.failures
    }
}

impl fmt::Display for NftBatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for NftBatchError {}

impl From<NftBatchError> for NetError {
    fn from(e: NftBatchError) -> Self {
        e.error
    }
}

/// 全メッセージが成功した結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftBatchAck {
    begin_seq: u32,
    end_seq: u32,
    body_seqs: Vec<u32>,
    /// 本体ごとの echo で得たルールハンドル（`body_seqs` と同じ添字。echo 未要求は `None`）。
    rule_handles: Vec<Option<NftRuleHandle>>,
}

impl NftBatchAck {
    /// BEGIN の seq。
    pub fn begin_seq(&self) -> u32 {
        self.begin_seq
    }

    /// END の seq。
    pub fn end_seq(&self) -> u32 {
        self.end_seq
    }

    /// ACK を確認した本体メッセージの seq（積んだ順）。
    pub fn body_seqs(&self) -> &[u32] {
        &self.body_seqs
    }

    /// `index` 番目の本体の echo 応答から得たルールハンドル。echo を要求していない本体・範囲外は `None`
    /// （echo を要求した本体のハンドルが欠けた結果は成功にならない）。
    pub fn rule_handle(&self, index: usize) -> Option<NftRuleHandle> {
        self.rule_handles.get(index).copied().flatten()
    }
}

/// [`NftBatchAckCollector::feed`] の経過。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// 判定が揃っていない。次のデータグラムを待つ。
    Pending,
    /// 本体の全 seq の判定が揃った、または BEGIN / END が失敗した。成功・失敗はまだ確定せず、
    /// 同期点への応答まで読んでから [`NftBatchAckCollector::conclude`] で確定する。
    Decided,
}

/// 1 バッチ分の応答を集めて判定する状態機械。
///
/// 前提: ソケットが seq をバッチごとに一意に採番する（`[begin_seq..=end_seq]` の外の seq は以前に
/// 時間切れしたバッチの遅延応答として破棄できる）。マルチキャスト購読はなく、カーネル発の
/// 非要求メッセージは来ない。
#[derive(Debug)]
pub(crate) struct NftBatchAckCollector {
    begin_seq: u32,
    end_seq: u32,
    body_seqs: Vec<u32>,
    /// 本体ごとの判定済みフラグ（`body_seqs` と同じ添字）。
    seen: Vec<bool>,
    pending: usize,
    /// 本体ごとの echo 要求（`NftBatchBytes::body_echo`）と、受理した echo のルールハンドル。
    echo_expected: Vec<Option<RuleEchoExpect>>,
    rule_handles: Vec<Option<NftRuleHandle>>,
    failures: Vec<NftMessageFailure>,
    /// BEGIN / END の非 0 errno を受けたか（本体の判定を待たずに判定済みにする）。
    marker_failed: bool,
    /// 判定後に送る同期点（`NFT_MSG_GETGEN` + `NLM_F_ACK`）の seq と、その応答 NEWGEN を受けたか。
    barrier_seq: Option<u32>,
    barrier_gen_seen: bool,
    /// 同期点への `NLMSG_ERROR` の errno（`Some(0)` は成功の ACK）。`Some` になれば読み切りの印。
    barrier_reply: Option<i32>,
}

fn data_loss(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

impl NftBatchAckCollector {
    /// 閉じたバッチの seq 構成から作る。保持する件数は `NftBatch` の長さ上限で有界。
    pub(crate) fn new(batch: &NftBatchBytes) -> Self {
        let body_seqs = batch.body_seqs().to_vec();
        Self {
            begin_seq: batch.begin_seq(),
            end_seq: batch.end_seq(),
            seen: vec![false; body_seqs.len()],
            pending: body_seqs.len(),
            echo_expected: (0..body_seqs.len())
                .map(|i| batch.body_echo_expect(i).cloned())
                .collect(),
            rule_handles: vec![None; body_seqs.len()],
            body_seqs,
            failures: Vec::new(),
            marker_failed: false,
            barrier_seq: None,
            barrier_gen_seen: false,
            barrier_reply: None,
        }
    }

    /// 同期点の seq を登録する。カーネルは送信ごとに全応答を積み終えてから戻り、応答は FIFO で届くため、
    /// 後続の同期点への応答が届けば、それより前（END の失敗を含む）の応答はすべて `feed` 済みになる。
    pub(crate) fn set_barrier(&mut self, seq: u32) {
        self.barrier_seq = Some(seq);
        self.barrier_gen_seen = false;
        self.barrier_reply = None;
    }

    /// 同期点への応答（`NLMSG_ERROR`。成功・失敗を問わない）を受け、読み切りが完了したか。
    pub(crate) fn barrier_reached(&self) -> bool {
        self.barrier_reply.is_some()
    }

    /// 同期点への応答の errno（未着は `None`、成功の ACK は `Some(0)`）。判定は `conclude` が行うため試験用。
    #[cfg(test)]
    pub(crate) fn barrier_reply(&self) -> Option<i32> {
        self.barrier_reply
    }

    /// `seq` が指すバッチ内の位置。範囲外（遅延応答）は `None`。
    fn locate(&self, seq: u32) -> Option<NftBatchPosition> {
        if seq == self.begin_seq {
            return Some(NftBatchPosition::Begin);
        }
        if seq == self.end_seq {
            return Some(NftBatchPosition::End);
        }
        let index = usize::try_from(seq.wrapping_sub(self.begin_seq))
            .ok()?
            .checked_sub(1)?;
        (self.body_seqs.get(index) == Some(&seq)).then_some(NftBatchPosition::Body { index })
    }

    fn record(&mut self, position: NftBatchPosition, seq: u32, errno: i32) {
        self.failures.push(NftMessageFailure {
            position,
            seq,
            errno,
            code: classify_errno(errno),
        });
    }

    /// 受信した 1 データグラム（外部入力）を判定する。
    pub(crate) fn feed(&mut self, datagram: &[u8]) -> Result<Progress, NftBatchError> {
        for item in NlMsgIter::new(datagram) {
            let msg = item.map_err(|e| self.unknown(data_loss(e.message().to_string())))?;
            let h = msg.header();
            if self.barrier_seq == Some(h.seq()) {
                self.feed_barrier(h.msg_type(), h.seq(), msg.payload())?;
                continue;
            }
            let Some(position) = self.locate(h.seq()) else {
                // 以前に時間切れしたバッチの遅延応答。
                continue;
            };
            if h.msg_type() == NLMSG_NOOP {
                continue;
            }
            if h.msg_type() == NEWRULE_TYPE {
                self.feed_rule_echo(position, h.seq(), &msg)?;
                continue;
            }
            if h.msg_type() != NLMSG_ERROR {
                return Err(self.unknown(data_loss(format!(
                    "unexpected netlink message type {} for batch seq {}",
                    h.msg_type(),
                    h.seq()
                ))));
            }
            let ack = decode_nlmsgerr(msg.payload()).map_err(|e| self.unknown(e))?;
            if ack.request_seq().is_some_and(|s| s != h.seq()) {
                return Err(self.unknown(data_loss(format!(
                    "nlmsgerr for batch seq {} embeds a different request seq",
                    h.seq()
                ))));
            }
            let errno = ack.errno();
            match position {
                NftBatchPosition::Begin | NftBatchPosition::End => {
                    if errno != 0 {
                        if self.failures.iter().any(|f| f.position == position) {
                            return Err(self.unknown(data_loss(format!(
                                "duplicate verdict for batch seq {}",
                                h.seq()
                            ))));
                        }
                        // バッチ全体の失敗。本体の判定を待たずに判定済みにするが、後続の失敗も集めるため
                        // ここでは確定しない（同期点まで読む）。
                        self.record(position, h.seq(), errno);
                        self.marker_failed = true;
                    }
                }
                NftBatchPosition::Body { index } => {
                    let Some(seen) = self.seen.get_mut(index) else {
                        continue;
                    };
                    if *seen {
                        return Err(self.unknown(data_loss(format!(
                            "duplicate verdict for batch seq {}",
                            h.seq()
                        ))));
                    }
                    *seen = true;
                    self.pending = self.pending.saturating_sub(1);
                    if errno != 0 {
                        self.record(position, h.seq(), errno);
                    }
                }
            }
        }
        if self.pending > 0 && !self.marker_failed {
            return Ok(Progress::Pending);
        }
        Ok(Progress::Decided)
    }

    /// 同期点への応答まで読んだ後の最終判定（NET-11）。
    ///
    /// - 同期点への応答が未着: 読み切れていないので `Internal`（`Unknown`。呼び出し側の誤用の防御）
    /// - 失敗を 1 件以上集めた: 全件を並べて `Aborted`（同期点への応答の errno によらない）
    /// - 同期点が非 0 errno: 適用状態を確認できないので `Unknown`
    /// - 本体の判定が欠けている: `Internal`（`Unknown`。判定済みの条件から起こらない防御）
    /// - それ以外: 全本体が errno 0 で成功
    pub(crate) fn conclude(&self) -> Result<NftBatchAck, NftBatchError> {
        let Some(errno) = self.barrier_reply else {
            return Err(self.unknown(NetError::new(
                NetErrorCode::Internal,
                "nf_tables batch verdict concluded before the sync reply",
            )));
        };
        if !self.failures.is_empty() {
            // 失敗を集めたバッチはカーネルが abort しており echo は出ないはず。受けていたら矛盾する応答で、
            // 適用状態を断定できない。
            if self.rule_handles.iter().any(Option::is_some) {
                return Err(self.unknown(data_loss(
                    "rule echo received for a batch the kernel rejected",
                )));
            }
            return Err(self.aborted());
        }
        if errno != 0 {
            return Err(self.unknown(NetError::new(
                classify_errno(errno),
                format!("sync request failed with errno {errno}"),
            )));
        }
        if self.pending > 0 {
            return Err(self.unknown(NetError::new(
                NetErrorCode::Internal,
                format!(
                    "nf_tables batch concluded with {} of {} body verdicts missing",
                    self.pending,
                    self.body_seqs.len()
                ),
            )));
        }
        let missing = self
            .echo_expected
            .iter()
            .zip(&self.rule_handles)
            .filter(|(want, got)| want.is_some() && got.is_none())
            .count();
        if missing > 0 {
            return Err(self.unknown(data_loss(format!(
                "{missing} requested rule echo(es) missing at the sync reply"
            ))));
        }
        Ok(NftBatchAck {
            begin_seq: self.begin_seq,
            end_seq: self.end_seq,
            body_seqs: self.body_seqs.clone(),
            rule_handles: self.rule_handles.clone(),
        })
    }

    /// echo を要求した NEWRULE への応答（echo）1 件からルールハンドルを取り出して記録する。
    /// 検証の規則はモジュール doc「NEWRULE の echo 応答」。
    fn feed_rule_echo(
        &mut self,
        position: NftBatchPosition,
        seq: u32,
        msg: &crate::netlink::NlMsg<'_>,
    ) -> Result<(), NftBatchError> {
        let NftBatchPosition::Body { index } = position else {
            return Err(self.unknown(data_loss(format!("rule echo for non-body batch seq {seq}"))));
        };
        let Some(expect) = self.echo_expected.get(index).and_then(Option::as_ref) else {
            return Err(self.unknown(data_loss(format!(
                "unrequested rule echo for batch seq {seq}"
            ))));
        };
        if self.rule_handles.get(index).copied().flatten().is_some() {
            return Err(self.unknown(data_loss(format!(
                "duplicate rule echo for batch seq {seq}"
            ))));
        }
        let nfg = NfGenMsg::decode(msg.payload()).map_err(|e| self.unknown(e))?;
        // 応答の中身が要求と同じルールのものかを、family・テーブル名・チェイン名で照合する（SEC-1・#2905）。
        // seq が合っていても別のルールのハンドルを採ると、後の DELRULE が別のルールを消しうる。
        // メッセージには名前の値や受信バイト列を載せない。version は NFNETLINK_V0 と照合し（#2970）、
        // res_id（世代番号）は比べない。
        let family_ok = nfg.family() == expect.family();
        let attrs = msg.attrs(NFGENMSG_LEN).map_err(|e| self.unknown(e))?;
        let identity = rule_table_chain_attrs(attrs);
        let rejected = match &identity {
            _ if nfg.version() != NFNETLINK_V0 => Some("nfnetlink version"),
            _ if !family_ok => Some("family"),
            Err(_) => Some("table or chain attribute"),
            Ok((t, _)) if t.as_slice() != expect.table() => Some("table"),
            Ok((_, c)) if c.as_slice() != expect.chain() => Some("chain"),
            Ok(_) => None,
        };
        if let Some(what) = rejected {
            return Err(self.unknown(data_loss(format!(
                "rule echo for batch seq {seq} does not match the requested {what}"
            ))));
        }
        let attrs = msg.attrs(NFGENMSG_LEN).map_err(|e| self.unknown(e))?;
        let handle = NftRuleHandle::from_rule_attrs(attrs).map_err(|e| self.unknown(e))?;
        if let Some(slot) = self.rule_handles.get_mut(index) {
            *slot = Some(handle);
        }
        Ok(())
    }

    /// 同期点の seq を持つ 1 メッセージを判定する（応答は NEWGEN → errno 0 の ACK の順）。
    ///
    /// NEWGEN は nfgenmsg の version が `NFNETLINK_V0`・family が `NFPROTO_UNSPEC` であることを照合し、
    /// 重複や ACK / エラー後の到着とあわせて `DataLoss` / `Unknown` で拒否する（#3039・NET-3・SEC-1）。
    ///
    /// errno 0 の ACK は、先に NEWGEN を受けていた場合だけ同期点の完了とする。GETGEN の応答を積めなかった
    /// 場合は `nf_tables_getgen` がエラーを返し ACK が非 0 errno になるため、NEWGEN なしの errno 0 は
    /// 想定外の応答として扱う。非 0 errno は読み切りの印として記録し、判定は [`Self::conclude`] に委ねる。
    fn feed_barrier(
        &mut self,
        msg_type: u16,
        seq: u32,
        payload: &[u8],
    ) -> Result<(), NftBatchError> {
        match msg_type {
            NEWGEN_TYPE => {
                // 2 通目の NEWGEN と、同期点の ACK / エラーの後の NEWGEN は順序が崩れた応答（#3039）。
                if self.barrier_gen_seen || self.barrier_reply.is_some() {
                    return Err(self.unknown(data_loss(format!(
                        "duplicate or late generation reply for sync seq {seq}"
                    ))));
                }
                // nfgenmsg は echo と同じ粒度で照合する（version 0・family 0。res_id・属性は見ない。#3039）。
                let nfg = NfGenMsg::decode(payload).map_err(|e| self.unknown(e))?;
                if nfg.version() != NFNETLINK_V0 {
                    return Err(self.unknown(data_loss(format!(
                        "sync generation reply for seq {seq} has unexpected nfnetlink version"
                    ))));
                }
                if nfg.family() != NFPROTO_UNSPEC {
                    return Err(self.unknown(data_loss(format!(
                        "sync generation reply for seq {seq} has unexpected family"
                    ))));
                }
                self.barrier_gen_seen = true;
                Ok(())
            }
            NLMSG_NOOP => Ok(()),
            NLMSG_ERROR => {
                let ack = decode_nlmsgerr(payload).map_err(|e| self.unknown(e))?;
                if ack.request_seq().is_some_and(|s| s != seq) {
                    return Err(self.unknown(data_loss(format!(
                        "sync ack for seq {seq} embeds a different request seq"
                    ))));
                }
                if ack.errno() == 0 && !self.barrier_gen_seen {
                    return Err(self.unknown(data_loss(format!(
                        "sync ack for seq {seq} arrived without a generation reply"
                    ))));
                }
                self.barrier_reply = Some(ack.errno());
                Ok(())
            }
            other => Err(self.unknown(data_loss(format!(
                "unexpected netlink message type {other} for sync seq {seq}"
            )))),
        }
    }

    fn sorted_failures(&self) -> Vec<NftMessageFailure> {
        let mut v = self.failures.clone();
        v.sort_by_key(|f| f.position);
        v
    }

    /// カーネルが失敗を返した場合のエラー（outcome は `Aborted`）。
    pub(crate) fn aborted(&self) -> NftBatchError {
        let failures = self.sorted_failures();
        let (code, message) = match failures.first() {
            Some(first) => (
                first.code,
                format!(
                    "nf_tables batch rejected: {} message failure(s), first at {} (seq {}, errno {})",
                    failures.len(),
                    first.position,
                    first.seq,
                    first.errno
                ),
            ),
            None => (
                NetErrorCode::Internal,
                "nf_tables batch rejected".to_string(),
            ),
        };
        NftBatchError {
            error: NetError::new(code, message),
            outcome: NftBatchOutcome::Aborted,
            failures,
        }
    }

    /// 適用されたか不明なエラー（outcome は `Unknown`）。これまでに集めた失敗を添える。
    pub(crate) fn unknown(&self, error: NetError) -> NftBatchError {
        NftBatchError {
            error,
            outcome: NftBatchOutcome::Unknown,
            failures: self.sorted_failures(),
        }
    }

    /// 期限内に判定が揃わなかった場合のエラー（`Timeout`・`Unknown`。REPAIR-5）。
    pub(crate) fn timeout_error(&self, total: Duration) -> NftBatchError {
        let received = self.body_seqs.len().saturating_sub(self.pending);
        self.unknown(NetError::new(
            NetErrorCode::Timeout,
            format!(
                "no complete reply for nf_tables batch (seq {}..={}) within {} ms; {} of {} body verdicts received",
                self.begin_seq,
                self.end_seq,
                total.as_millis(),
                received,
                self.body_seqs.len()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NLM_F_ACK, NLM_F_ECHO, NLM_F_REQUEST, NlMsgBuilder};
    use crate::nftables_batch::{
        NFNL_SUBSYS_NFTABLES, NFPROTO_INET, NFPROTO_IPV4, NfGenMsg, NftBatch, nfnl_msg_type,
    };

    const NEWTABLE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, 0);

    fn push_body(b: &mut NftBatch) {
        b.push_with(|seq| {
            let mut m = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
            NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut m)?;
            Ok(m)
        })
        .expect("push");
    }

    /// 本体 `n` 件・begin_seq 100 のバッチ（begin=100, 本体=101.., end=101+n）。
    fn batch(n: usize) -> NftBatchBytes {
        let mut b = NftBatch::new(100).expect("new");
        for _ in 0..n {
            push_body(&mut b);
        }
        b.finish().expect("finish")
    }

    /// `NLMSG_ERROR` のデータグラム（errno は正値で渡す。`inner_seq` は埋め込む元ヘッダの seq）。
    fn err_dgram(seq: u32, errno: i32, inner_seq: u32) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(NLMSG_ERROR, 0, seq, 0);
        let mut p = Vec::new();
        p.extend_from_slice(&(-errno).to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&inner_seq.to_ne_bytes());
        p.extend_from_slice(&[0u8; 4]);
        b.put_fixed(&p).expect("payload");
        b.finish().expect("finish")
    }

    fn ok(seq: u32) -> Vec<u8> {
        err_dgram(seq, 0, seq)
    }

    /// 同期点 `seq` を登録し、NEWGEN → errno `errno` の応答を与えて読み切りを完了させる。
    fn reach_barrier(c: &mut NftBatchAckCollector, seq: u32, errno: i32) {
        c.set_barrier(seq);
        c.feed(&cat(&[newgen(seq), err_dgram(seq, errno, seq)]))
            .expect("barrier reply");
        assert_eq!(c.barrier_reply(), Some(errno));
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn fail(index: usize, seq: u32, errno: i32) -> NftMessageFailure {
        NftMessageFailure {
            position: NftBatchPosition::Body { index },
            seq,
            errno,
            code: classify_errno(errno),
        }
    }

    /// NET-11: 本体 3 件すべて errno 0 なら成功で seq と件数を返す。
    #[test]
    fn net11_all_acks_succeed() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let p = c.feed(&cat(&[ok(101), ok(102), ok(103)])).expect("feed");
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 105, 0);
        assert_eq!(
            c.conclude(),
            Ok(NftBatchAck {
                begin_seq: 100,
                end_seq: 104,
                body_seqs: vec![101, 102, 103],
                rule_handles: vec![None, None, None],
            })
        );
    }

    /// NET-11: 応答が複数データグラムに分かれても、揃うまで Pending。
    #[test]
    fn net11_verdicts_across_datagrams() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Pending);
        assert_eq!(c.feed(&ok(102)).expect("feed"), Progress::Decided);
    }

    /// NET-11: 3 件中 index 1 が EEXIST。失敗メッセージを特定し outcome は Aborted。
    #[test]
    fn net11_partial_failure_identifies_message() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let p = c
            .feed(&cat(&[ok(101), err_dgram(102, 17, 102), ok(103)]))
            .expect("decided");
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 105, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.failures(), &[fail(1, 102, 17)][..]);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(
            e.message(),
            "nf_tables batch rejected: 1 message failure(s), first at body[1] (seq 102, errno 17)"
        );
    }

    /// NET-11: 複数の失敗は添字順にすべて並び、先頭の分類が code になる。
    #[test]
    fn net11_multiple_failures_are_all_listed() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        let p = c
            .feed(&cat(&[
                err_dgram(103, 22, 103),
                err_dgram(101, 2, 101),
                ok(102),
            ]))
            .expect("decided");
        assert_eq!(p, Progress::Decided);
        let e = c.aborted();
        assert_eq!(e.failures(), &[fail(0, 101, 2), fail(2, 103, 22)][..]);
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: 失敗を含んで判定が揃っても即確定せず、後続データグラムの失敗も `aborted` に含まれる。
    #[test]
    fn net11_failure_in_later_datagram_is_collected_after_failed() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&err_dgram(101, 17, 101)).expect("pending"),
            Progress::Pending
        );
        assert_eq!(c.feed(&ok(102)).expect("decided"), Progress::Decided);
        // 判定済みの後に届く END の失敗も記録し、同期点まで読んでから確定する（先の失敗も保持する）。
        assert_eq!(
            c.feed(&err_dgram(103, 12, 103)).expect("end failure"),
            Progress::Decided
        );
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![
                (NftBatchPosition::Body { index: 0 }, 101, 17),
                (NftBatchPosition::End, 103, 12)
            ]
        );
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: BEGIN への EPERM はバッチ全体の失敗で、本体の判定を待たずに判定済みになる。権限不足では
    /// 同期点も EPERM で拒否されるが、読み切りの印として扱い Aborted で確定する。
    #[test]
    fn net11_begin_eperm_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&err_dgram(100, 1, 100)).expect("eperm"),
            Progress::Decided
        );
        c.set_barrier(104);
        c.feed(&err_dgram(104, 1, 104)).expect("sync eperm");
        assert!(c.barrier_reached());
        let e = c.conclude().expect_err("aborted");
        assert_eq!(
            e.failures(),
            &[NftMessageFailure {
                position: NftBatchPosition::Begin,
                seq: 100,
                errno: 1,
                code: NetErrorCode::PermissionDenied,
            }][..]
        );
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-11: END への非 0 errno も位置 End として記録し、本体の判定を待たずに判定済みになる。
    #[test]
    fn net11_end_error_is_batch_level() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(
            c.feed(&err_dgram(102, 12, 102)).expect("end failure"),
            Progress::Decided
        );
        let e = c.aborted();
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.errno(), f.code()))
                .collect::<Vec<_>>(),
            vec![(NftBatchPosition::End, 12, NetErrorCode::ResourceExhausted)]
        );
    }

    /// NET-11: BEGIN / END への errno 0 の ACK は無視する（DataLoss にしない）。
    #[test]
    fn marker_ack_is_tolerated() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let p = c.feed(&cat(&[ok(100), ok(101), ok(102)])).expect("feed");
        assert_eq!(p, Progress::Decided);
        reach_barrier(&mut c, 103, 0);
        assert!(c.conclude().is_ok());
    }

    /// NET-11: 範囲外の seq（以前のバッチの遅延応答）は破棄して続行する。
    #[test]
    fn net11_stale_seq_is_discarded() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(
            c.feed(&cat(&[err_dgram(50, 17, 50), ok(99), ok(105)]))
                .expect("feed"),
            Progress::Pending
        );
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Decided);
    }

    /// NET-11: 同じ本体 seq への 2 回目の判定は DataLoss / Unknown。
    #[test]
    fn duplicate_verdict_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        let e = c.feed(&cat(&[ok(101), ok(101)])).expect_err("dup");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 埋め込まれた元要求の seq がヘッダと食い違えば DataLoss。
    #[test]
    fn embedded_seq_mismatch_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c.feed(&err_dgram(101, 0, 999)).expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 範囲内の seq を持つ NLMSG_ERROR 以外（NOOP を除く）は DataLoss。
    #[test]
    fn unexpected_message_type_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let noop = NlMsgBuilder::new(NLMSG_NOOP, 0, 101, 0)
            .finish()
            .expect("finish");
        assert_eq!(c.feed(&noop).expect("noop"), Progress::Pending);
        let mut b = NlMsgBuilder::new(NEWTABLE, 0, 101, 0);
        b.put_fixed(&[0u8; 4]).expect("payload");
        let e = c.feed(&b.finish().expect("finish")).expect_err("type");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// NET-11: 壊れたフレームは DataLoss / Unknown（panic しない）。
    #[test]
    fn malformed_frame_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c.feed(&[1, 2, 3, 4, 5]).expect_err("malformed");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
    }

    /// REPAIR-5: 時間切れエラーは Timeout / Unknown で、集めた件数と失敗を添える。
    #[test]
    fn repair5_timeout_error_reports_progress() {
        let mut c = NftBatchAckCollector::new(&batch(3));
        c.feed(&cat(&[err_dgram(101, 17, 101), ok(102)]))
            .expect("pending");
        let e = c.timeout_error(Duration::from_millis(1500));
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.failures(), &[fail(0, 101, 17)][..]);
        assert_eq!(
            e.message(),
            "no complete reply for nf_tables batch (seq 100..=104) within 1500 ms; 2 of 3 body verdicts received"
        );
    }

    /// NET-11: NftBatchError は NetError へ変換でき、Display に入力名を含まない。
    #[test]
    fn batch_error_converts_to_net_error() {
        let e = NftBatchError::not_sent(NetError::new(NetErrorCode::InvalidArgument, "empty"));
        assert_eq!(e.outcome(), NftBatchOutcome::NotSent);
        assert!(e.failures().is_empty());
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: empty");
        let n: NetError = e.into();
        assert_eq!(n.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-11: seq が u32 を一周するバッチでも位置を特定できる。
    #[test]
    fn locate_handles_seq_wraparound() {
        let mut b = NftBatch::new(u32::MAX - 1).expect("new");
        for _ in 0..3 {
            push_body(&mut b);
        }
        let bytes = b.finish().expect("finish");
        assert_eq!(bytes.body_seqs(), &[u32::MAX, 0, 1][..]);
        let c = NftBatchAckCollector::new(&bytes);
        assert_eq!(c.locate(u32::MAX - 1), Some(NftBatchPosition::Begin));
        assert_eq!(c.locate(0), Some(NftBatchPosition::Body { index: 1 }));
        assert_eq!(c.locate(2), Some(NftBatchPosition::End));
        assert_eq!(c.locate(3), None);
    }

    /// 同期点への応答 `NFT_MSG_NEWGEN`（type 0x0A0F。属性は省略）。
    fn newgen(seq: u32) -> Vec<u8> {
        newgen_with(seq, &[0, 0, 0x01, 0x02])
    }

    /// nfgenmsg の生バイトを指定できる NEWGEN（family, version, res_id の順）。
    fn newgen_with(seq: u32, nfgenmsg: &[u8]) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0x0A0F, 0, seq, 0);
        b.put_fixed(nfgenmsg).expect("nfgenmsg");
        b.finish().expect("finish")
    }

    /// NET-3・SEC-1・#3039: 同期点の NEWGEN の nfgenmsg が想定外なら DataLoss / Unknown で拒否する。
    #[test]
    fn net3_sec1_newgen_nfgenmsg_mismatch_is_data_loss() {
        let cases: [(&[u8], &str); 3] = [
            (
                &[0, 1, 0, 0],
                "sync generation reply for seq 103 has unexpected nfnetlink version",
            ),
            (
                &[1, 0, 0, 0],
                "sync generation reply for seq 103 has unexpected family",
            ),
            (&[0, 0, 0], "payload too short for nfgenmsg: 3 bytes"),
        ];
        for (nfg, msg) in cases {
            let mut c = NftBatchAckCollector::new(&batch(1));
            assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Decided);
            c.set_barrier(103);
            let e = c.feed(&newgen_with(103, nfg)).expect_err("nfgenmsg");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
            assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
            assert_eq!(e.message(), msg);
            assert!(!c.barrier_reached());
        }
    }

    /// NET-3・SEC-1・#3039: 同じ seq の 2 通目の NEWGEN と、ACK の後の NEWGEN は拒否する。
    #[test]
    fn net3_sec1_duplicate_or_late_newgen_is_data_loss() {
        let want = "duplicate or late generation reply for sync seq 103";
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        c.feed(&newgen(103)).expect("first");
        let e = c.feed(&newgen(103)).expect_err("dup");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.message(), want);

        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        c.feed(&newgen(103)).expect("first");
        c.feed(&ok(103)).expect("ack");
        let e = c.feed(&newgen(103)).expect_err("late");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.message(), want);
    }

    /// NET-11: 同期点の応答は NEWGEN（0x0A0F）→ errno 0 の ACK の順で完了する。NEWGEN だけでは未完了。
    #[test]
    fn net11_barrier_completes_after_newgen_then_ack() {
        assert_eq!(NEWGEN_TYPE, 0x0A0F);
        let mut c = NftBatchAckCollector::new(&batch(1));
        assert_eq!(c.feed(&ok(101)).expect("feed"), Progress::Decided);
        c.set_barrier(103);
        assert_eq!(c.feed(&newgen(103)).expect("newgen"), Progress::Decided);
        assert!(!c.barrier_reached());
        assert_eq!(c.feed(&ok(103)).expect("ack"), Progress::Decided);
        assert_eq!(c.barrier_reply(), Some(0));
        assert_eq!(c.conclude().expect("ok").body_seqs(), &[101][..]);
    }

    /// NET-11: NEWGEN を受けずに届いた同期点の errno 0 の ACK は DataLoss / Unknown（完了にしない）。
    #[test]
    fn net11_barrier_ack_without_newgen_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let e = c.feed(&ok(103)).expect_err("no newgen");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(
            e.message(),
            "sync ack for seq 103 arrived without a generation reply"
        );
        assert!(!c.barrier_reached());
    }

    /// NET-11: 同期点の seq を持つ NEWGEN・NOOP・NLMSG_ERROR 以外の type は DataLoss / Unknown。
    #[test]
    fn net11_unexpected_type_for_barrier_seq_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let noop = NlMsgBuilder::new(NLMSG_NOOP, 0, 103, 0)
            .finish()
            .expect("finish");
        assert_eq!(c.feed(&noop).expect("noop"), Progress::Pending);
        let mut b = NlMsgBuilder::new(NEWTABLE, 0, 103, 0);
        b.put_fixed(&[0u8; 4]).expect("payload");
        let e = c.feed(&b.finish().expect("finish")).expect_err("type");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(
            e.message(),
            "unexpected netlink message type 2560 for sync seq 103"
        );
        assert!(!c.barrier_reached());
    }

    /// NET-11: 失敗のないバッチで同期点が EPERM で拒否されたら成功にせず PermissionDenied / Unknown。
    #[test]
    fn net11_barrier_errno_is_unknown() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&ok(101)).expect("body");
        reach_barrier(&mut c, 103, 1);
        let e = c.conclude().expect_err("eperm");
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.message(), "sync request failed with errno 1");
    }

    /// NET-11: END の失敗の後に同じデータグラムで届く本体の失敗も集める（END で打ち切らない）。
    #[test]
    fn net11_end_failure_does_not_stop_collecting_same_datagram() {
        let mut c = NftBatchAckCollector::new(&batch(2));
        assert_eq!(
            c.feed(&cat(&[
                err_dgram(103, 12, 103),
                err_dgram(102, 17, 102),
                ok(101)
            ]))
            .expect("decided"),
            Progress::Decided
        );
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(
            e.failures()
                .iter()
                .map(|f| (f.position(), f.seq(), f.errno()))
                .collect::<Vec<_>>(),
            vec![
                (NftBatchPosition::Body { index: 1 }, 102, 17),
                (NftBatchPosition::End, 103, 12)
            ]
        );
        assert_eq!(
            e.message(),
            "nf_tables batch rejected: 2 message failure(s), first at body[1] (seq 102, errno 17)"
        );
    }

    /// NET-11: 同じ BEGIN / END への 2 回目の失敗は DataLoss / Unknown（集めた失敗は添える）。
    #[test]
    fn net11_duplicate_marker_failure_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        let e = c
            .feed(&cat(&[err_dgram(100, 1, 100), err_dgram(100, 1, 100)]))
            .expect_err("dup");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.message(), "duplicate verdict for batch seq 100");
        assert_eq!(e.failures().len(), 1);
    }

    /// NET-11: 同期点への応答が未着のまま conclude しても成功にせず Internal / Unknown。
    #[test]
    fn net11_conclude_before_sync_reply_is_unknown() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&ok(101)).expect("body");
        let e = c.conclude().expect_err("not reached");
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        c.set_barrier(103);
        c.feed(&newgen(103)).expect("newgen");
        let e = c.conclude().expect_err("newgen only");
        assert_eq!(e.code(), NetErrorCode::Internal);
    }

    /// NET-11: 失敗を集めた後の同期点の拒否は読み切りの印として扱い、Aborted で確定する。
    #[test]
    fn net11_barrier_errno_after_failure_is_aborted() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.feed(&err_dgram(101, 17, 101)).expect("body failure");
        reach_barrier(&mut c, 103, 12);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(e.failures(), &[fail(0, 101, 17)][..]);
    }

    /// NET-11: 同期点 ACK が別の要求 seq を埋め込んでいれば成功にせず DataLoss（Unknown）にする。
    #[test]
    fn net11_barrier_ack_with_mismatched_inner_seq_is_data_loss() {
        let mut c = NftBatchAckCollector::new(&batch(1));
        c.set_barrier(103);
        let e = c.feed(&err_dgram(103, 0, 999)).expect_err("mismatch");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert!(!c.barrier_reached());
    }

    // ---- NEWRULE の echo 応答（NET-3・CRI-2・REPAIR-2・#2839） ----

    /// 本体 2 件（index 0 = 101: echo 要求あり、index 1 = 102: echo 要求なし）のバッチ。begin = 100。
    fn echo_batch(echo: [bool; 2]) -> NftBatchBytes {
        let mut b = NftBatch::new(100).expect("new");
        for want in echo {
            b.push_with(|seq| {
                let (ty, flags) = if want {
                    (NEWRULE_TYPE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO)
                } else {
                    (NEWTABLE, NLM_F_REQUEST | NLM_F_ACK)
                };
                let mut m = NlMsgBuilder::new(ty, flags, seq, 0);
                NfGenMsg::new(NFPROTO_IPV4, 0).put_into(&mut m)?;
                if want {
                    // 要求のテーブル名・チェイン名（echo の照合の期待値になる。SEC-1・#2905）。
                    m.put_attr(1, b"t\0")?;
                    m.put_attr(2, b"c\0")?;
                }
                Ok(m)
            })
            .expect("push");
        }
        b.finish().expect("finish")
    }

    /// echo 応答（NEWRULE。nfgenmsg + TABLE + CHAIN + HANDLE）。`handle` は属性の生バイト列。
    fn rule_echo_raw(seq: u32, handle: Option<&[u8]>) -> Vec<u8> {
        rule_echo_with(seq, NFPROTO_IPV4, Some(b"t\0"), Some(b"c\0"), handle)
    }

    /// echo 応答の family・テーブル名・チェイン名を指定して組み立てる（`None` は属性を出さない）。
    /// res_id は実カーネルと同様に非 0（世代番号）にする。
    fn rule_echo_with(
        seq: u32,
        family: u8,
        table: Option<&[u8]>,
        chain: Option<&[u8]>,
        handle: Option<&[u8]>,
    ) -> Vec<u8> {
        rule_echo_versioned(seq, 0, family, table, chain, handle)
    }

    /// `rule_echo_with` に nfgenmsg の version を指定できる版（res_id は 0x0102）。
    fn rule_echo_versioned(
        seq: u32,
        version: u8,
        family: u8,
        table: Option<&[u8]>,
        chain: Option<&[u8]>,
        handle: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(NEWRULE_TYPE, 0, seq, 0);
        b.put_fixed(&[family, version, 0x01, 0x02]).expect("nfg");
        if let Some(t) = table {
            b.put_attr(1, t).expect("table");
        }
        if let Some(c) = chain {
            b.put_attr(2, c).expect("chain");
        }
        if let Some(h) = handle {
            b.put_attr(3, h).expect("handle");
        }
        b.finish().expect("finish")
    }

    fn rule_echo(seq: u32, handle: u64) -> Vec<u8> {
        rule_echo_raw(seq, Some(&handle.to_be_bytes()))
    }

    fn handle(n: u64) -> Option<NftRuleHandle> {
        Some(NftRuleHandle::new(n).expect("handle"))
    }

    /// NET-3: echo → ACK の順でも、ACK → echo の順でも、同じハンドルが得られる。
    #[test]
    fn net3_echo_handle_is_collected_in_either_order() {
        for dgrams in [
            cat(&[rule_echo(101, 2), ok(101), ok(102)]),
            cat(&[ok(101), ok(102), rule_echo(101, 2)]),
        ] {
            let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
            c.feed(&dgrams).expect("feed");
            reach_barrier(&mut c, 104, 0);
            let ack = c.conclude().expect("ack");
            assert_eq!(ack.rule_handle(0), handle(2));
            assert_eq!(ack.rule_handle(1), None);
            assert_eq!(ack.rule_handle(2), None);
        }
    }

    /// NET-3: 複数の echo を 1 データグラムにまとめても、別データグラムに分けても受け付ける。
    #[test]
    fn net3_multiple_echoes_collected() {
        let mut c = NftBatchAckCollector::new(&echo_batch([true, true]));
        c.feed(&cat(&[rule_echo(101, 2), rule_echo(102, 3)]))
            .expect("echoes");
        c.feed(&cat(&[ok(101), ok(102)])).expect("acks");
        reach_barrier(&mut c, 104, 0);
        let ack = c.conclude().expect("ack");
        assert_eq!(
            (ack.rule_handle(0), ack.rule_handle(1)),
            (handle(2), handle(3))
        );
    }

    /// NET-3: echo の欠落は成功にせず Unknown（DataLoss）にする。
    #[test]
    fn net3_missing_echo_is_unknown() {
        let mut c = NftBatchAckCollector::new(&echo_batch([true, true]));
        c.feed(&cat(&[rule_echo(101, 2), ok(101), ok(102)]))
            .expect("feed");
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("missing");
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.code(), NetErrorCode::DataLoss);
    }

    /// NET-3: echo の重複・要求していない本体への echo・BEGIN / END の seq への echo は DataLoss。
    #[test]
    fn net3_duplicate_or_unrequested_echo_is_data_loss() {
        for (dgrams, desc) in [
            (cat(&[rule_echo(101, 2), rule_echo(101, 3)]), "duplicate"),
            (rule_echo(102, 2), "unrequested"),
            (rule_echo(100, 2), "begin"),
            (rule_echo(103, 2), "end"),
        ] {
            let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
            let e = c.feed(&dgrams).expect_err(desc);
            assert_eq!(e.code(), NetErrorCode::DataLoss, "{desc}");
            assert_eq!(e.outcome(), NftBatchOutcome::Unknown, "{desc}");
        }
    }

    /// NET-3・REPAIR-2: 不正なハンドル属性（欠落・0・7 バイト・9 バイト・重複）と短いペイロードは DataLoss。
    #[test]
    fn net3_malformed_echo_is_data_loss() {
        let mut dup = NlMsgBuilder::new(NEWRULE_TYPE, 0, 101, 0);
        NfGenMsg::new(NFPROTO_IPV4, 0)
            .put_into(&mut dup)
            .expect("nfg");
        dup.put_attr(3, &2u64.to_be_bytes()).expect("h1");
        dup.put_attr(3, &3u64.to_be_bytes()).expect("h2");
        let mut short = NlMsgBuilder::new(NEWRULE_TYPE, 0, 101, 0);
        short.put_fixed(&[2, 0]).expect("short");
        for dgram in [
            rule_echo_raw(101, None),
            rule_echo(101, 0),
            rule_echo_raw(101, Some(&[0, 0, 0, 0, 0, 0, 2])),
            rule_echo_raw(101, Some(&[0, 0, 0, 0, 0, 0, 0, 0, 2])),
            dup.finish().expect("dup"),
            short.finish().expect("short"),
        ] {
            let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
            let e = c.feed(&dgram).expect_err("malformed");
            assert_eq!(e.code(), NetErrorCode::DataLoss);
            assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        }
    }

    /// NET-3: echo を受けたのに失敗が集まった（矛盾する応答）場合は Aborted と断定せず Unknown にする。
    /// echo を受けていない失敗は従来どおり Aborted。
    #[test]
    fn net3_echo_with_failure_is_unknown_but_plain_failure_is_aborted() {
        let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
        c.feed(&cat(&[rule_echo(101, 2), ok(101), err_dgram(102, 17, 102)]))
            .expect("feed");
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("contradiction");
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        assert_eq!(e.code(), NetErrorCode::DataLoss);

        let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
        c.feed(&cat(&[err_dgram(101, 17, 101), ok(102)]))
            .expect("feed");
        reach_barrier(&mut c, 104, 0);
        let e = c.conclude().expect_err("aborted");
        assert_eq!(e.outcome(), NftBatchOutcome::Aborted);
    }

    /// NET-3・SEC-1・#2970: echo の nfgenmsg の version が NFNETLINK_V0 以外なら、
    /// seq が合っていても DataLoss・Unknown とし、ハンドルを記録しない。
    #[test]
    fn net3_sec1_echo_version_mismatch_is_data_loss() {
        let h = 2u64.to_be_bytes();
        for version in [1u8, 0xFF] {
            let dgram = rule_echo_versioned(
                101,
                version,
                NFPROTO_IPV4,
                Some(b"t\0"),
                Some(b"c\0"),
                Some(&h),
            );
            let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
            let e = c.feed(&dgram).expect_err("version");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "version {version}");
            assert_eq!(e.outcome(), NftBatchOutcome::Unknown, "version {version}");
            assert!(e.message().contains("nfnetlink version"), "{}", e.message());
            assert_eq!(c.rule_handles[0], None, "version {version}");
        }
    }

    /// NET-3・SEC-1・#2905: echo の family・テーブル名・チェイン名が要求（IPv4・`t`・`c`）と違えば、
    /// seq が合っていても DataLoss・Unknown とし、ハンドルを記録しない。
    #[test]
    fn net3_sec1_echo_identity_mismatch_is_data_loss() {
        let h = 2u64.to_be_bytes();
        let ok_t: Option<&[u8]> = Some(b"t\0");
        let ok_c: Option<&[u8]> = Some(b"c\0");
        let mut nested = NlMsgBuilder::new(NEWRULE_TYPE, 0, 101, 0);
        NfGenMsg::new(NFPROTO_IPV4, 0)
            .put_into(&mut nested)
            .expect("nfg");
        nested
            .put_nested(1, |b| b.put_attr(1, b"t\0"))
            .expect("nested table");
        nested.put_attr(2, b"c\0").expect("chain");
        nested.put_attr(3, &h).expect("handle");
        let mut dup_t = NlMsgBuilder::new(NEWRULE_TYPE, 0, 101, 0);
        NfGenMsg::new(NFPROTO_IPV4, 0)
            .put_into(&mut dup_t)
            .expect("nfg");
        for _ in 0..2 {
            dup_t.put_attr(1, b"t\0").expect("table");
        }
        dup_t.put_attr(2, b"c\0").expect("chain");
        dup_t.put_attr(3, &h).expect("handle");
        let mut dup_c = NlMsgBuilder::new(NEWRULE_TYPE, 0, 101, 0);
        NfGenMsg::new(NFPROTO_IPV4, 0)
            .put_into(&mut dup_c)
            .expect("nfg");
        dup_c.put_attr(1, b"t\0").expect("table");
        for _ in 0..2 {
            dup_c.put_attr(2, b"c\0").expect("chain");
        }
        dup_c.put_attr(3, &h).expect("handle");
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "table x",
                rule_echo_with(101, NFPROTO_IPV4, Some(b"x\0"), ok_c, Some(&h)),
            ),
            (
                "chain d",
                rule_echo_with(101, NFPROTO_IPV4, ok_t, Some(b"d\0"), Some(&h)),
            ),
            (
                "family inet",
                rule_echo_with(101, NFPROTO_INET, ok_t, ok_c, Some(&h)),
            ),
            (
                "table without NUL",
                rule_echo_with(101, NFPROTO_IPV4, Some(b"t"), ok_c, Some(&h)),
            ),
            (
                "table with inner NUL",
                rule_echo_with(101, NFPROTO_IPV4, Some(b"t\0x\0"), ok_c, Some(&h)),
            ),
            (
                "table missing",
                rule_echo_with(101, NFPROTO_IPV4, None, ok_c, Some(&h)),
            ),
            (
                "chain missing",
                rule_echo_with(101, NFPROTO_IPV4, ok_t, None, Some(&h)),
            ),
            ("table nested", nested.finish().expect("nested")),
            ("table duplicated", dup_t.finish().expect("dup_t")),
            ("chain duplicated", dup_c.finish().expect("dup_c")),
        ];
        for (desc, dgram) in cases {
            let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
            let e = c.feed(&dgram).expect_err(desc);
            assert_eq!(e.code(), NetErrorCode::DataLoss, "{desc}");
            assert_eq!(e.outcome(), NftBatchOutcome::Unknown, "{desc}");
            assert_eq!(c.rule_handles[0], None, "{desc}");
        }
    }

    /// NET-3・SEC-1: seq が合っていても、別のルール（別チェイン）の echo を取り違えて採らない。
    #[test]
    fn net3_sec1_swapped_chain_echo_is_rejected() {
        let mut b = NftBatch::new(100).expect("new");
        for chain in [&b"c\0"[..], &b"d\0"[..]] {
            b.push_with(|seq| {
                let mut m =
                    NlMsgBuilder::new(NEWRULE_TYPE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO, seq, 0);
                NfGenMsg::new(NFPROTO_IPV4, 0).put_into(&mut m)?;
                m.put_attr(1, b"t\0")?;
                m.put_attr(2, chain)?;
                Ok(m)
            })
            .expect("push");
        }
        let batch = b.finish().expect("finish");
        let h = 2u64.to_be_bytes();
        let mut c = NftBatchAckCollector::new(&batch);
        let e = c
            .feed(&rule_echo_with(
                101,
                NFPROTO_IPV4,
                Some(b"t\0"),
                Some(b"d\0"),
                Some(&h),
            ))
            .expect_err("swapped");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.outcome(), NftBatchOutcome::Unknown);
        let mut c = NftBatchAckCollector::new(&batch);
        c.feed(&rule_echo_with(
            102,
            NFPROTO_IPV4,
            Some(b"t\0"),
            Some(b"d\0"),
            Some(&h),
        ))
        .expect("matching echo");
        assert_eq!(c.rule_handles[1], handle(2));
    }

    /// NET-3・#2905: 実カーネルの echo の形（res_id は世代番号で非 0・flags は CREATE|APPEND・
    /// POSITION とネストした EXPRESSIONS つき）は受理する。
    #[test]
    fn net3_echo_with_nonzero_res_id_and_extra_attrs_is_accepted() {
        let mut b = NlMsgBuilder::new(
            NEWRULE_TYPE,
            crate::netlink::NLM_F_CREATE | crate::netlink::NLM_F_APPEND,
            101,
            0,
        );
        NfGenMsg::new(NFPROTO_IPV4, 0x0102)
            .put_into(&mut b)
            .expect("nfg");
        b.put_attr(1, b"t\0").expect("table");
        b.put_attr(2, b"c\0").expect("chain");
        b.put_attr(3, &2u64.to_be_bytes()).expect("handle");
        b.put_attr(7, &1u64.to_be_bytes()).expect("position");
        b.put_nested(4, |n| n.put_attr(1, b"x")).expect("exprs");
        let mut c = NftBatchAckCollector::new(&echo_batch([true, false]));
        c.feed(&b.finish().expect("finish")).expect("accepted");
        assert_eq!(c.rule_handles[0], handle(2));
    }
}

/// ACK 判定が使う nf_tables のメッセージ種別の `libc` 照合（NET-1・MVM-4・REPAIR-12。#3102。方式は
/// `docs/design/ffi-libc-check.md`）。宣言と同じく Linux の試験ビルド限定。
#[cfg(all(test, target_os = "linux"))]
mod libc_abi {
    use core::ffi::c_int;

    const _: () = {
        libc_const_eq!(NFT_MSG_NEWGEN, u8, c_int);
        libc_const_eq!(NFT_MSG_GETGEN, u8, c_int);
    };
}
