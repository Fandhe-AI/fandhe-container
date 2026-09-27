//! `NetworkPlugin` 拡張点トレイト（TASK-4.3・CRI-7・PLUG-1・MS-0）。
//!
//! ネットワーク設定の制御面（bridge・veth・netns・ポート公開・DNAT の作成/削除）を
//! 抽象化する拡張点。データパス（パケット転送そのもの）ではなく制御面の RPC なので、
//! plugin 境界を越えるコストは許容範囲になる（PoC-13）。トレイト定義は本 crate（core）に
//! 置くが、実装は本 crate には置かず、別プロセス plugin（`fandhe-container-plugin-net` 等。
//! TASK-114）が担う。core 側の proxy（G8・TASK-107/114）が UDS＋長さ接頭辞フレームの
//! RPC へ変換し、`Box<dyn NetworkPlugin>` として呼び出し側へ渡す（PLUG-1）。
//!
//! # netsetup（PoC-15）粒度との対応
//!
//! CRI-7 の 2026-09-23 追記により、メソッド分割は PoC-15 の `netsetup` の操作粒度
//! （`net-create`・`netns-create`・`veth-attach`・`publish-port`・`net-delete`）に
//! そのまま対応づけられることが実機で確認されている。
//!
//! | netsetup（PoC-15） | メソッド | 単位 | 主な責務 | CRI 対応 |
//! | ------------------ | -------- | ---- | -------- | -------- |
//! | `net-create` | [`NetworkPlugin::create_network`] | ネットワーク | bridge・専用 nft テーブル（masquerade）・DNS ヘルパー | `SetUpPod` 相当 |
//! | `netns-create` | [`NetworkPlugin::create_netns`] | コンテナ | 専用 netns の作成（lo の up を含む）。所属ネットワークを受け取り `net-delete` の追跡対象に加える | `SetUpPod` の一部 |
//! | `veth-attach` | [`NetworkPlugin::attach`] | コンテナ | veth ペアの作成、bridge / netns への接続、アドレス・default route の設定 | `SetUpPod` の一部 |
//! | `publish-port` | [`NetworkPlugin::publish_port`] | コンテナ | ポート公開（nft DNAT） | PortMapping |
//! | `net-delete` | [`NetworkPlugin::delete_network`] | ネットワーク | bridge・nft テーブル・関連 netns の一括削除 | `TearDownPod` 相当 |
//!
//! [`NetworkPlugin::detach`] は PoC-15 の `netsetup` には対応する操作粒度がない
//! （PoC-15 はネットワーク単位の一括削除のみを実証した）。CNI の `DEL`・CRI の
//! `StopPodSandbox`/`RemovePodSandbox` 相当のコンテナ単位の後始末として本トレイトが
//! 独自に定義する。ポート公開（DNAT）→ veth → netns を逆順に解放し、
//! [`NetworkPlugin::attach`] 前（netns のみ作成済み）でも呼び出せる。
//!
//! 分割の理由: ネットワーク単位とコンテナ単位のライフサイクルが異なるため、
//! 単一メソッドに畳み込まずライフサイクル単位ごとに分ける。PoC-15 の実機実証で、
//! この粒度でロールバックと冪等性の境界が引けることを確認している（CRI-7 追記）。
//! DNS ヘルパーの起動・終了と `/etc/resolv.conf` の設定は `create_network` /
//! `delete_network`（`SetUpPod` / `TearDownPod` 相当）に含まれ、DNS レジストリの更新は
//! コンテナのライフサイクルイベント（`ContainerRuntime` 側の create/delete）にフックする
//! 設計である。関連ビヘイビア: NET-1〜NET-5（bridge・veth・nft・DNS ヘルパー）。
//! NET-11（netlink / nftables の自前実装）は plugin 実装側の関心事であり、本トレイトは
//! 実装方式（netlink 直叩き・nft コマンド呼び出し等）に依存しない。
//!
//! # 未対応（スコープ外。#19・TASK-4.h1 と後続タスクへ引き継ぐ）
//!
//! - NET-6 の host / none モード（netsetup の操作を経由しない経路の扱いは #19 で確定する）
//! - DNS ヘルパーのライフサイクルとレジストリ更新の詳細（NET-5・NET-7）、
//!   `--add-host` / `--dns`（NET-12）、rootless ネットワーク（NET-9・検討中）、
//!   ホスト側 bind IP の指定
//! - 実装（TASK-114・G7 の net crate）と proxy（G8・TASK-107/114）
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない（REPAIR-3）。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use super::types::{ContainerId, ErrorCode, TraitError};

/// ネットワーク設定の制御面（bridge・veth・netns・ポート公開）を抽象化する拡張点。
///
/// # 契約
/// 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）。
/// 2. 相手の応答を待つ処理（plugin RPC）は無期限に待たず、上限時間を超えたら
///    [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の決定は
///    proxy 実装（G8・TASK-107/114）の責務であり、本トレイトは契約のみを定める。
/// 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn NetworkPlugin>` として複数スレッド
///    から共有できることを前提にしてよい。
/// 4. 本 crate（core）にはこのトレイトの実装を置かない。実装は plugin 側にある
///    （PLUG-1・TASK-114）。「実装済みを装わない」という REPAIR-3 の方針に基づく。
/// 5. plugin の信頼境界（UDS の所有者・権限検証、別 UID からの接続切断等。
///    PLUG-11・PLUG-12）はこのトレイトの外側、境界機構（`fandhe-container-plugin`）の
///    責務であり、`NetworkPlugin` の呼び出し側はそれらが検証済みであることを
///    前提にしてよい。
/// 6. **部分失敗時のロールバック**: [`Self::create_network`]・[`Self::create_netns`]・
///    [`Self::attach`]・[`Self::publish_port`] が途中で失敗した場合、実装は作成済みの
///    リソース（bridge・veth・nft テーブル・netns・DNAT ルール）を逆順に削除してから
///    `Err` を返す（PoC-15 の 2026-09-24 修正に準拠）。[`Self::create_netns`] は netns
///    作成後に lo の up を行うため、lo 設定が失敗した場合は作成済みの netns 自体を
///    削除してから `Err` を返す。[`Self::publish_port`] は DNAT ルール追加後に失敗
///    した場合、追加済みのルールを撤回してから `Err` を返す。撤回にも失敗した場合は
///    [`ErrorCode::Internal`] を返し、`message` に残存資源を含める（fail-closed。
///    呼び出し側はポート公開が残っている可能性があるものとして扱う）。ロールバックせず
///    netns を残したまま `Err` を返すと、同じコンテナへの再試行が
///    [`ErrorCode::AlreadyExists`]（契約 7）により恒久的に失敗するため、ロールバックは
///    再試行可能性の前提でもある。
/// 7. **二重作成の拒否**: 同名のネットワークや同じコンテナの netns が既にあれば
///    [`ErrorCode::AlreadyExists`] を返す。前回の残骸を黙って再利用しない。
/// 8. **前提違反**: 存在しないネットワークへの [`Self::create_netns`] / [`Self::attach`] /
///    [`Self::publish_port`] / [`Self::detach`]、netns 未作成のコンテナへの
///    [`Self::attach`]、netns が未作成、または既に [`Self::detach`] 済みのコンテナへの
///    [`Self::detach`]、未 attach のコンテナへの [`Self::publish_port`] は
///    [`ErrorCode::NotFound`] を返す。加えて [`Self::attach`]・
///    [`Self::detach`] は、対象コンテナの netns が [`Self::create_netns`] で
///    紐付けられたネットワーク（`CreateNetnsRequest::network`）と `req.network()` が
///    一致しない場合、[`ErrorCode::FailedPrecondition`] を返す（異なるネットワークへの
///    越境接続・越境解放を拒否し、[`Self::delete_network`] の追跡対象と実際の接続先の
///    食い違いを防ぐ）。同様に [`Self::publish_port`] は、対象コンテナが
///    [`Self::attach`] された際のネットワーク（`AttachRequest::network`）と
///    `req.network()` が一致しない場合、[`ErrorCode::FailedPrecondition`] を返す
///    （別ネットワークに属するコンテナ ID を渡して越境 DNAT を設定させないため）。
/// 9. **削除・解放はベストエフォートで続行**: [`Self::delete_network`]・[`Self::detach`]
///    は個々の削除・解放に失敗しても残りを続け、1 件でも失敗があれば `Err`
///    （[`ErrorCode::Internal`]。`message` に残存資源を含める。契約 6 の
///    [`Self::publish_port`] と同じ fail-closed の表現）を返す（PoC-15 の `net-delete`
///    に準拠。[`Self::detach`] も同じパターンを踏襲する）。
/// 10. **静的アドレスの検証**: [`Self::attach`] の `AttachRequest::address`
///     （[`AttachRequest::with_address`] 経由）が指定されている場合、実装は次を検証する。
///     (a) 指定アドレスが `req.network()` の [`Self::create_network`] 時のサブネット
///     （`CreateNetworkRequest::subnet`）に含まれること。含まれない、またはそのサブネットの
///     ネットワークアドレス・ブロードキャストアドレス等のホスト割り当てに使えない予約
///     アドレスであれば [`ErrorCode::InvalidArgument`] を返す。(b) 同一ネットワーク内の
///     他コンテナが既にそのアドレスを使用中であれば [`ErrorCode::AlreadyExists`] を返す。
///     アドレス未指定の場合は実装が動的に割り当てる（[`AttachRequest::with_address`] の
///     doc のとおり）。
/// 11. **ホストポートの二重公開の拒否**: [`Self::publish_port`] は、同じホスト側ポート
///     番号とプロトコルの組が、ネットワーク・コンテナに関わらず既に公開済みであれば
///     [`ErrorCode::AlreadyExists`] を返す。ホスト bind IP の指定はスコープ外（#19）の
///     ままであるため、判定キーは `(host_port, protocol)` のみとする。[`Self::detach`]
///     または [`Self::delete_network`] で解放されたポートは再公開できる。
///
/// メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。
/// dyn 互換（object safety）を保ち、async ランタイムへの依存を追加しない
/// （依存最小方針。dependency-policy.md）。
pub trait NetworkPlugin: Send + Sync {
    /// ネットワーク（bridge・専用 nft テーブル・DNS ヘルパー）を作成する。
    ///
    /// netsetup の `net-create` に対応し、CRI の `SetUpPod` 相当。前提: 同名の
    /// ネットワークが存在しないこと。存在する場合は [`ErrorCode::AlreadyExists`] を
    /// 返す（契約 7）。途中で失敗した場合は作成済みリソースを逆順に削除する（契約 6）。
    /// 対応: NET-1〜NET-3。
    fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError>;

    /// コンテナ専用の netns を作成する（lo の up を含む）。
    ///
    /// netsetup の `netns-create` に対応し、`SetUpPod` の一部。前提: `req.network()` が
    /// [`Self::create_network`] 済みであること（未作成なら [`ErrorCode::NotFound`]。
    /// 作成済みネットワークにのみ netns を紐付けることで、[`Self::delete_network`] が
    /// 存在しないネットワーク名を回収対象として追跡する事態や、孤立した netns が
    /// 残る事態を防ぐ）。加えて、同じコンテナの netns が既に存在しないこと。
    /// 存在する場合は [`ErrorCode::AlreadyExists`] を返す（契約 7）。`req.network()` が
    /// 指すネットワークに属するものとして実装側が追跡し、[`Self::delete_network`] の
    /// 削除対象に含める（`attach` 未実施でも回収できるようにするため）。lo の up に
    /// 失敗した場合は作成済みの netns を削除してから `Err` を返す（契約 6）。
    /// 対応: NET-1。
    fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError>;

    /// veth ペアを作成し、bridge / netns へ接続してアドレス・default route を設定する。
    ///
    /// netsetup の `veth-attach` に対応し、`SetUpPod` の一部。前提: `req.network()` が
    /// [`Self::create_network`] 済みであること（未作成なら [`ErrorCode::NotFound`]）、
    /// 対象コンテナの netns が [`Self::create_netns`] 済みであること（未作成なら、
    /// `create_network` 未作成時と同じ扱いとして [`ErrorCode::NotFound`]）。さらに、
    /// その netns が [`Self::create_netns`] 呼び出し時に紐付けられたネットワーク
    /// （`CreateNetnsRequest::network`）が `req.network()` と一致すること（不一致なら
    /// [`ErrorCode::FailedPrecondition`]）。異なるネットワークに属する netns への接続を
    /// 許すと、実際の接続先ネットワークと [`Self::delete_network`] が追跡する削除対象
    /// ネットワークが食い違い、分離・後始末の契約が崩れるため。`req.address()` で
    /// 静的アドレスが指定されている場合はサブネット内・非予約・未使用であることを
    /// 検証する（契約 10。範囲外・予約アドレスは [`ErrorCode::InvalidArgument`]、
    /// 他コンテナが使用中なら [`ErrorCode::AlreadyExists`]）。途中で失敗した場合は
    /// 作成済みリソースを逆順に削除する（契約 6）。対応: NET-1・NET-2。
    fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError>;

    /// コンテナのポートをホスト側へ公開する（nft DNAT）。
    ///
    /// netsetup の `publish-port` に対応する。前提: `req.network()` が
    /// [`Self::create_network`] 済みで、対象コンテナが [`Self::attach`] 済みであること
    /// （いずれも未作成なら [`ErrorCode::NotFound`]）。加えて、対象コンテナが
    /// [`Self::attach`] された際のネットワーク（`AttachRequest::network`）が
    /// `req.network()` と一致すること（不一致なら [`ErrorCode::FailedPrecondition`]）。
    /// 一致を要求しないと、別ネットワークに属するコンテナ ID を渡されても実装が
    /// そのアドレスへ DNAT を設定でき、ネットワーク間の分離と [`Self::delete_network`]
    /// が追跡する削除対象の食い違いを招く（[`Self::attach`] の契約 8 と同じ理由）。
    /// 宛先は生の IP アドレスではなく [`ContainerId`] で指定し、実装（plugin 側）が
    /// attach 済みのアドレスへ解決する。これは PoC-15 との差分であり、ネットワーク外の
    /// 任意ホストへ DNAT させる経路をトレイト境界で作らないための設計である
    /// （#19 で確認する）。加えて、同じホスト側ポートとプロトコルの組がネットワーク・
    /// コンテナに関わらず既に公開済みであれば [`ErrorCode::AlreadyExists`] を返す
    /// （契約 11。ホスト bind IP の指定はスコープ外〔#19〕のため判定キーは
    /// `(host_port, protocol)` のみ）。[`Self::detach`] / [`Self::delete_network`] で
    /// 解放されたポートは再公開できる。DNAT ルール追加後に失敗した場合は追加済みの
    /// ルールを撤回してから `Err` を返し、撤回にも失敗すれば [`ErrorCode::Internal`] を
    /// 返す（契約 6）。対応: NET-4。
    fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError>;

    /// コンテナのネットワーク接続を解放する（ポート公開 → veth → netns の逆順）。
    ///
    /// CNI の `DEL`・CRI の `StopPodSandbox` / `RemovePodSandbox` 相当のコンテナ単位の
    /// 後始末 API（PoC-15 の `netsetup` には対応する操作粒度がなく、本トレイトが独自に
    /// 定義する）。[`Self::attach`] 前（netns のみ作成済み）でも呼び出せる。前提:
    /// `req.network()` が [`Self::create_network`] 済みであること（未作成なら
    /// [`ErrorCode::NotFound`]）。対象コンテナの netns が存在すること（未作成、または
    /// 既に detach 済みなら [`ErrorCode::NotFound`]）。その netns が [`Self::create_netns`]
    /// 呼び出し時に紐付けられたネットワークが `req.network()` と一致すること（不一致
    /// なら [`ErrorCode::FailedPrecondition`]。[`Self::attach`] の契約 8 と同じ理由）。
    /// 対象コンテナに [`Self::publish_port`] 済みのポート公開があれば、veth・netns を
    /// 解放する前にそれらをまとめて解放する。個々の解放に失敗しても残りの解放を続け、
    /// 1 件でも失敗があれば `Err`（[`ErrorCode::Internal`]。`message` に残存資源を含める。
    /// 契約 9）を返す。二重の呼び出しは、1 回目で netns が解放済みになるため 2 回目が
    /// [`ErrorCode::NotFound`] になる。[`Self::delete_network`] との関係:
    /// `delete_network` はネットワーク単位で残存する netns をまとめて回収するため、
    /// `detach` 済みのコンテナは `delete_network` の削除対象から自然に外れ、二重削除に
    /// ならない。対応: NET-1・NET-2・NET-4。
    fn detach(&self, req: &DetachRequest) -> Result<DetachResponse, TraitError>;

    /// ネットワーク（bridge・nft テーブル・関連 netns）を一括削除する。
    ///
    /// netsetup の `net-delete` に対応し、CRI の `TearDownPod` 相当。削除対象の netns
    /// 一覧は呼び出し側から受け取らず、そのネットワークに [`Self::create_netns`]（`req.network()`
    /// で紐付け）・[`Self::attach`] のいずれかで関連付けたものを実装（plugin 側）が追跡して
    /// 決める（上限のない `Vec` を境界へ持ち込まないため）。`attach` 前に失敗した netns も
    /// `create_netns` の時点で追跡対象に入っているため回収できる。[`Self::detach`] 済みの
    /// コンテナは実装側の追跡対象から既に外れているため、削除対象に含まれない
    /// （二重削除の防止）。個々の削除に失敗しても残りの削除を続け、1 件でも失敗があれば
    /// `Err` を返す（契約 9）。対応: NET-3・NET-5。
    fn delete_network(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError>;
}

/// ネットワーク名・netns 名の許容文字数の上限（暫定値）。
///
/// plugin はインターフェース名の制約（`IFNAMSIZ` 由来。PoC-17 で bridge の接頭辞込みで
/// 8 文字が `ERANGE` になった事例）により、さらに厳しい上限を [`ErrorCode::InvalidArgument`]
/// で課してよい。この値の確定は人間のアーキテクチャレビュー（#19・TASK-4.h1）で行う。
const IDENTIFIER_MAX_LEN: usize = 64;

/// [`NetworkName`]・[`NetnsName`] に共通する検証本体。
///
/// bridge・nft テーブル・netns の名前として実装側が使うため、パス区切り文字・NUL・
/// 非 ASCII・制御文字・空白を型のレベルで排除する（PoC-15 で名前が nft スクリプトや
/// インターフェース名へ埋め込まれていたため、境界の型の時点で制限する。security.md）。
/// `kind` はエラーメッセージに出す名詞（"network name" / "netns name"）。
///
/// 拒否条件（いずれかに該当すると [`ErrorCode::InvalidArgument`]）:
/// - 空文字列
/// - 長さが `IDENTIFIER_MAX_LEN`（64 バイト）を超える
/// - 先頭が ASCII 英数字でない
/// - 2 文字目以降に `[A-Za-z0-9-]` 以外の文字を含む
fn validate_identifier(value: &str, kind: &str) -> Result<(), TraitError> {
    if value.is_empty() {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must not be empty"),
        ));
    }
    if value.len() > IDENTIFIER_MAX_LEN {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must be at most {IDENTIFIER_MAX_LEN} bytes"),
        ));
    }
    let mut bytes = value.bytes();
    // `is_empty()` チェック済みのため `next()` は必ず `Some` を返す。
    let first = bytes.next().unwrap_or(b'\0');
    if !first.is_ascii_alphanumeric() {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must start with an ASCII alphanumeric character"),
        ));
    }
    if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must match [A-Za-z0-9][A-Za-z0-9-]*"),
        ));
    }
    Ok(())
}

/// 検証済みのネットワーク名。
///
/// 生成は [`NetworkName::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// 入力文字列を検証してネットワーク名を作る（検証条件は [`validate_identifier`]）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        validate_identifier(&value, "network name")?;
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for NetworkName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for NetworkName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// 検証済みの netns 識別子。
///
/// netns の実体（パス・fd）は本トレイトの型に含めない（下記 [`NetnsStatus`] の doc）。
/// この型は plugin が [`ContainerId`] から導出し応答する netns の「名前」のみを表し、
/// [`NetworkName`] と同じ文字集合・長さ制約を [`validate_identifier`] で共有する。
/// 生成は [`NetnsName::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetnsName(String);

impl NetnsName {
    /// 入力文字列を検証して netns 名を作る（検証条件は [`validate_identifier`]）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        validate_identifier(&value, "netns name")?;
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for NetnsName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for NetnsName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// IPv4 / IPv6 アドレスと prefix 長の組（CIDR 表記）。
///
/// prefix 長はアドレスファミリごとの上限（IPv4: 32・IPv6: 128）を超えられない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// アドレスと prefix 長から CIDR を作る。
    ///
    /// `prefix_len` がアドレスファミリの上限（IPv4: 32・IPv6: 128）を超える場合は
    /// [`ErrorCode::InvalidArgument`] を返す。
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, TraitError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("prefix length must be at most {max} for this address family"),
            ));
        }
        Ok(Self { addr, prefix_len })
    }

    /// アドレスを返す。
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// prefix 長を返す。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// このサブネットに `addr` が含まれるかどうかを判定する（NET-1・契約 10 の
    /// 「サブネット内」検証で使う）。アドレスファミリが異なる場合は常に `false` を
    /// 返す（IPv4 サブネットは IPv6 アドレスを含み得ないため）。
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(base), IpAddr::V4(target)) => {
                let mask = v4_prefix_mask(self.prefix_len);
                (u32::from(base) & mask) == (u32::from(target) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(target)) => {
                let mask = v6_prefix_mask(self.prefix_len);
                (u128::from(base) & mask) == (u128::from(target) & mask)
            }
            _ => false,
        }
    }

    /// このサブネットのネットワークアドレス（ホスト部がすべて 0）を返す
    /// （NET-1・契約 10 の予約アドレス検証で使う）。
    pub fn network_address(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(base) => IpAddr::V4(Ipv4Addr::from(
                u32::from(base) & v4_prefix_mask(self.prefix_len),
            )),
            IpAddr::V6(base) => IpAddr::V6(Ipv6Addr::from(
                u128::from(base) & v6_prefix_mask(self.prefix_len),
            )),
        }
    }

    /// このサブネットのブロードキャストアドレス（ホスト部がすべて 1）を返す
    /// （NET-1・契約 10 の予約アドレス検証で使う）。IPv6 にはブロードキャストの概念が
    /// ないため常に `None`。IPv4 でもホスト部が存在しない `/32` はネットワーク
    /// アドレスとブロードキャストアドレスを区別できないため `None` を返す。
    pub fn broadcast_address(&self) -> Option<IpAddr> {
        match self.addr {
            IpAddr::V4(base) if self.prefix_len < 32 => {
                let mask = v4_prefix_mask(self.prefix_len);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from(base) | !mask)))
            }
            _ => None,
        }
    }
}

/// `prefix_len`（0..=32）に対応する IPv4 のサブネットマスクをビット表現で返す。
///
/// `prefix_len == 0` はホスト部のみ（マスク全 0）を意味し、シフト量 32 は
/// Rust の整数シフトで許容されない（オーバーフロー panic）ため専用に分岐する。
/// `IpCidr::new` が範囲（0..=32）を検証済みであることを前提とする内部ヘルパー。
fn v4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

/// `prefix_len`（0..=128）に対応する IPv6 のサブネットマスクをビット表現で返す。
/// 分岐の理由は [`v4_prefix_mask`] と同じ（シフト量 128 の回避）。
fn v6_prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// ポート公開のトランスポートプロトコル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
    /// TCP。
    Tcp,
    /// UDP。
    Udp,
}

impl Protocol {
    /// プロトコル名を小文字文字列で返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// [`NetworkPlugin::create_network`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CreateNetworkRequest {
    name: NetworkName,
    subnet: IpCidr,
}

impl CreateNetworkRequest {
    /// ネットワーク名と bridge 側のアドレス・prefix（サブネット）から要求を作る。
    pub fn new(name: NetworkName, subnet: IpCidr) -> Self {
        Self { name, subnet }
    }

    /// ネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// bridge 側のサブネット（アドレス・prefix）を返す。
    pub fn subnet(&self) -> IpCidr {
        self.subnet
    }
}

/// [`NetworkPlugin::create_network`] の応答。
///
/// 将来の拡張（DNS ヘルパーのアドレス等）に備えて構造体にする（coding-rust.md）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetworkStatus {
    name: NetworkName,
    subnet: IpCidr,
}

impl NetworkStatus {
    /// ネットワーク名とサブネットから状態を作る。
    pub fn new(name: NetworkName, subnet: IpCidr) -> Self {
        Self { name, subnet }
    }

    /// ネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// bridge 側のサブネット（アドレス・prefix）を返す。
    pub fn subnet(&self) -> IpCidr {
        self.subnet
    }
}

/// [`NetworkPlugin::create_netns`] の要求。
///
/// `network` は、この netns がどのネットワークに属するかを実装（plugin 側）へ伝える。
/// [`Self::network`] 経由の `attach` 前に本呼び出しが失敗しても、実装はこの時点で
/// 受け取ったネットワーク名に紐付けて netns を追跡でき、その後の
/// [`NetworkPlugin::delete_network`] が `attach` 未実施の netns も含めて回収できる
/// （残存孤児 netns の防止）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CreateNetnsRequest {
    network: NetworkName,
    container: ContainerId,
}

impl CreateNetnsRequest {
    /// 所属先ネットワーク名と対象コンテナの ID から要求を作る。netns の名前は検証済みの
    /// [`ContainerId`] から実装側が導出する（パストラバーサル対策。security.md）。
    pub fn new(network: NetworkName, container: ContainerId) -> Self {
        Self { network, container }
    }

    /// 所属先ネットワーク名を返す。実装（plugin 側）はこれを使って
    /// [`NetworkPlugin::delete_network`] の追跡対象にこの netns を含める。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }
}

/// [`NetworkPlugin::create_netns`] の応答。
///
/// 保持するのは対象コンテナの ID と、実装（plugin 側）が [`ContainerId`] から
/// 導出して報告する検証済みの netns 名（[`NetnsName`]）のみである。netns の実体
/// （パス・fd）の解決と、それに対する配下性・種別・TOCTOU の検証は本トレイトの型に
/// 含めない。それらは untrusted な plugin 応答を受け取る境界機構
/// （`fandhe-container-plugin`。PLUG-11・PLUG-12）と runtime 側の実装（TASK-114）の
/// 責務であり、本 crate（core）のトレイト定義には実装を置かない（契約 4）。
/// runtime が netns の fd をどう受け取るか（UDS 越しの fd 受け渡し等）は
/// 人間のアーキテクチャレビュー（#19・TASK-4.h1）でシグネチャとあわせて決める
/// （REPAIR-3: 実装済みを装わない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetnsStatus {
    container: ContainerId,
    name: NetnsName,
}

impl NetnsStatus {
    /// 対象コンテナの ID と検証済みの netns 名から応答を作る。
    ///
    /// 両引数はすでに検証済みの型（[`ContainerId`]・[`NetnsName`]）であるため、
    /// この関数自体は失敗しない。
    pub fn new(container: ContainerId, name: NetnsName) -> Self {
        Self { container, name }
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// netns 名を返す。
    pub fn name(&self) -> &NetnsName {
        &self.name
    }
}

/// [`NetworkPlugin::attach`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttachRequest {
    network: NetworkName,
    container: ContainerId,
    address: Option<IpCidr>,
}

impl AttachRequest {
    /// 接続先ネットワークと対象コンテナから要求を作る（アドレスは未指定）。
    pub fn new(network: NetworkName, container: ContainerId) -> Self {
        Self {
            network,
            container,
            address: None,
        }
    }

    /// 静的 IPAM（NET-1）で使う固定アドレスを指定するビルダ。
    ///
    /// 指定しない場合、実装（plugin 側）が動的に IPAM を行う。指定した場合、
    /// [`NetworkPlugin::attach`] の実装は対象ネットワークのサブネット内・非予約・
    /// 未使用であることを検証する（トレイト doc の契約 10）。
    pub fn with_address(mut self, address: IpCidr) -> Self {
        self.address = Some(address);
        self
    }

    /// 接続先ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// 指定された固定アドレス（未指定なら `None`）を返す。
    pub fn address(&self) -> Option<IpCidr> {
        self.address
    }
}

/// [`NetworkPlugin::attach`] の応答。実際に割り当てられたアドレスとゲートウェイを返す。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AttachResponse {
    network: NetworkName,
    container: ContainerId,
    address: IpCidr,
    gateway: Option<IpAddr>,
}

impl AttachResponse {
    /// 接続先ネットワーク・対象コンテナ・割り当てアドレス・ゲートウェイから応答を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        address: IpCidr,
        gateway: Option<IpAddr>,
    ) -> Self {
        Self {
            network,
            container,
            address,
            gateway,
        }
    }

    /// 接続先ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// 実際に割り当てられたアドレス（CIDR）を返す。
    pub fn address(&self) -> IpCidr {
        self.address
    }

    /// default route のゲートウェイ（判明していれば）を返す。
    pub fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
}

/// [`NetworkPlugin::publish_port`] の要求。
///
/// 宛先は生の IP アドレスではなく [`ContainerId`] で指定する。実装（plugin 側）が
/// [`NetworkPlugin::attach`] 済みのアドレスへ解決する（トレイト doc の契約参照）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PublishPortRequest {
    network: NetworkName,
    container: ContainerId,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
    protocol: Protocol,
}

impl PublishPortRequest {
    /// ネットワーク名・対象コンテナ・ホスト側ポート・コンテナ側ポート・プロトコルから
    /// 要求を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        host_port: NonZeroU16,
        container_port: NonZeroU16,
        protocol: Protocol,
    ) -> Self {
        Self {
            network,
            container,
            host_port,
            container_port,
            protocol,
        }
    }

    /// 対象ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 宛先コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// ホスト側の公開ポートを返す。
    pub fn host_port(&self) -> NonZeroU16 {
        self.host_port
    }

    /// コンテナ側の待受ポートを返す。
    pub fn container_port(&self) -> NonZeroU16 {
        self.container_port
    }

    /// トランスポートプロトコルを返す。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// [`NetworkPlugin::publish_port`] の応答。要求と同じ内容を実施結果として返す。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PortMapping {
    network: NetworkName,
    container: ContainerId,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
    protocol: Protocol,
}

impl PortMapping {
    /// ネットワーク名・対象コンテナ・ホスト側ポート・コンテナ側ポート・プロトコルから
    /// マッピング結果を作る。
    pub fn new(
        network: NetworkName,
        container: ContainerId,
        host_port: NonZeroU16,
        container_port: NonZeroU16,
        protocol: Protocol,
    ) -> Self {
        Self {
            network,
            container,
            host_port,
            container_port,
            protocol,
        }
    }

    /// 対象ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 宛先コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }

    /// ホスト側の公開ポートを返す。
    pub fn host_port(&self) -> NonZeroU16 {
        self.host_port
    }

    /// コンテナ側の待受ポートを返す。
    pub fn container_port(&self) -> NonZeroU16 {
        self.container_port
    }

    /// トランスポートプロトコルを返す。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// [`NetworkPlugin::detach`] の要求。
///
/// コンテナのネットワーク接続（ポート公開・veth・netns）を解放する対象を指定する。
/// 解放するリソースの一覧はここでは受け取らない。[`Self::network`]・[`Self::container`]
/// から実装（plugin 側）が追跡済みの資源（`create_netns`・`attach`・`publish_port` で
/// 紐付けたもの）を特定する（上限のない `Vec` を境界へ持ち込まない設計は
/// [`DeleteNetworkRequest`] と同じ）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DetachRequest {
    network: NetworkName,
    container: ContainerId,
}

impl DetachRequest {
    /// 対象ネットワークとコンテナから要求を作る。
    pub fn new(network: NetworkName, container: ContainerId) -> Self {
        Self { network, container }
    }

    /// 対象ネットワーク名を返す。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 対象コンテナの ID を返す。
    pub fn container(&self) -> &ContainerId {
        &self.container
    }
}

/// [`NetworkPlugin::detach`] の応答。当面は空だが、将来の拡張（解放した資源の種別等）
/// に備えて構造体にする（[`DeleteNetworkResponse`] と同じ形）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DetachResponse {}

impl DetachResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

/// [`NetworkPlugin::delete_network`] の要求。
///
/// 削除対象の netns 一覧はここでは受け取らない。そのネットワークで作成・接続した
/// netns は実装（plugin 側）が追跡して決める（上限のない `Vec` を境界へ持ち込まない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DeleteNetworkRequest {
    name: NetworkName,
}

impl DeleteNetworkRequest {
    /// 削除対象のネットワーク名から要求を作る。
    pub fn new(name: NetworkName) -> Self {
        Self { name }
    }

    /// 削除対象のネットワーク名を返す。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }
}

/// [`NetworkPlugin::delete_network`] の応答。当面は空だが、将来の拡張
/// （解放した資源の情報等）に備えて構造体にする（[`super::container_runtime::DeleteResponse`]
/// と同じ形）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteNetworkResponse {}

impl DeleteNetworkResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// [`StubNetworkPlugin::create_netns`] が netns 名を決定的に導出するための
    /// 変換規則（テスト用スタブ限定。P1 修正）。
    ///
    /// 実際の plugin 実装が netns 名を `ContainerId` からどう導出するかは
    /// 人間のアーキテクチャレビュー（#19・TASK-4.h1）で確定する未確定事項であり、
    /// ここでの規則はスタブの契約テストを通すためだけの仮のものである
    /// （REPAIR-3: 実装済みを装わない）。`ContainerId` が許すが [`NetnsName`] では
    /// 許可されない文字（`.`・`_`）を `-` に置換し、`"netns-"` 接頭辞を付ける。
    /// 置換後の文字はすべて `[A-Za-z0-9-]`（`ContainerId` の文字集合の部分集合）に
    /// 限られ、接頭辞が英字で始まるため、結果が [`IDENTIFIER_MAX_LEN`] に収まる
    /// 限り [`NetnsName::new`] の検証には理論上常に通る。長さを切り詰めると
    /// 異なる `ContainerId` が同じ `NetnsName` に衝突しうるため切り詰めは行わず、
    /// 収まらない場合は [`ErrorCode::InvalidArgument`] を返す（`ContainerId` は
    /// 検証済みの外部入力であり、この経路は `panic` させない。coding-rust.md）。
    fn derive_netns_name(container: &ContainerId) -> Result<NetnsName, TraitError> {
        const PREFIX: &str = "netns-";
        let sanitized: String = container
            .as_str()
            .chars()
            .map(|c| if c == '.' || c == '_' { '-' } else { c })
            .collect();
        let available = IDENTIFIER_MAX_LEN.saturating_sub(PREFIX.len());
        if sanitized.len() > available {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "container id is too long to derive a netns name \
                     (stub rule allows at most {available} bytes after sanitization)"
                ),
            ));
        }
        NetnsName::new(format!("{PREFIX}{sanitized}"))
    }

    /// [`StubNetworkPlugin::attach`] が静的アドレス（`AttachRequest::address`）を
    /// 検証するための述語（トレイト doc の契約 10）。
    ///
    /// `address.addr()` が `subnet` に含まれない場合、または `subnet` のネットワーク
    /// アドレス・ブロードキャストアドレスと一致する場合に
    /// [`ErrorCode::InvalidArgument`] を返す。使用中かどうか（契約 10 の (b)）は
    /// 呼び出し側（`attach`）が `assigned_addresses` を見て別途判定する。
    fn validate_static_address(subnet: IpCidr, address: IpCidr) -> Result<(), TraitError> {
        let ip = address.addr();
        if !subnet.contains(ip) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("address {ip} is outside the network's subnet {subnet}"),
            ));
        }
        if ip == subnet.network_address() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("address {ip} is the network address of the subnet {subnet}"),
            ));
        }
        if subnet.broadcast_address() == Some(ip) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("address {ip} is the broadcast address of the subnet {subnet}"),
            ));
        }
        Ok(())
    }

    /// テスト専用の契約検証スタブ実装（dyn 互換性・契約 6〜11 の失敗条件を確認するため
    /// のみに使う）。トレイト doc の契約 4「本 crate にはこのトレイトの実装を置かない」
    /// は本番実装を core に置かないという方針であり、`#[cfg(test)]` 配下のみに存在する
    /// 契約チェック用スタブはその対象外である。
    ///
    /// ネットワーク作成状況・netns の所属ネットワーク・attach 済みネットワークを状態と
    /// して保持し、トレイト doc の契約 6〜9・各メソッド doc が定める前提違反を実際に
    /// 検出する。
    struct StubNetworkPlugin {
        /// ネットワーク名 → 作成時のサブネット。契約 10（静的アドレス検証）で
        /// `req.network()` のサブネットを参照するために `IpCidr` も保持する。
        networks: Mutex<HashMap<NetworkName, IpCidr>>,
        netns: Mutex<HashMap<ContainerId, NetworkName>>,
        /// 導出済みの netns 名 → 所有コンテナ（P2 修正）。`derive_netns_name` の
        /// 仮規則は異なる `ContainerId`（例: `a.b` と `a_b`）を同じ `NetnsName` に
        /// 変換しうるため、`create_netns` はこのマップで衝突を検出して拒否する。
        netns_names: Mutex<HashMap<NetnsName, ContainerId>>,
        attached: Mutex<HashMap<ContainerId, NetworkName>>,
        /// コンテナごとに公開済みのポート（[`NetworkPlugin::detach`] が解放対象を
        /// 追跡し、[`NetworkPlugin::publish_port`] が積む）。契約 11（ホストポートの
        /// 二重公開の拒否）の判定もこのマップを全件走査して行う（別途フラットな
        /// `(host_port, protocol)` 集合を持たず、`detach`/`delete_network` による
        /// 解放と自動的に整合させるため）。
        published: Mutex<HashMap<ContainerId, Vec<PortMapping>>>,
        /// ネットワーク名 → （割り当て済みアドレス → コンテナ ID）。契約 10 の
        /// 「同一ネットワーク内の他コンテナが使用中」判定に使う。
        assigned_addresses: Mutex<HashMap<NetworkName, HashMap<IpAddr, ContainerId>>>,
        /// ネットワーク本体の削除（`networks` からの除去）だけを失敗させる
        /// （契約 9。配下の netns・attach・公開ポートの回収は成功する前提）。
        fail_delete: AtomicBool,
        /// DNAT ルール追加後の失敗を注入する（契約 6）。
        fail_publish_port: AtomicBool,
        /// `fail_publish_port` が立っている間、追加済みルールの撤回自体も
        /// 失敗させるかどうか。`false`（既定）なら撤回は成功する。
        fail_publish_port_rollback: AtomicBool,
        /// netns の解放だけを失敗させる（契約 9。公開ポート・attach の解放は
        /// 成功する前提）。
        fail_detach: AtomicBool,
    }

    impl StubNetworkPlugin {
        fn new() -> Self {
            Self {
                networks: Mutex::new(HashMap::new()),
                netns: Mutex::new(HashMap::new()),
                netns_names: Mutex::new(HashMap::new()),
                attached: Mutex::new(HashMap::new()),
                published: Mutex::new(HashMap::new()),
                assigned_addresses: Mutex::new(HashMap::new()),
                fail_delete: AtomicBool::new(false),
                fail_publish_port: AtomicBool::new(false),
                fail_publish_port_rollback: AtomicBool::new(false),
                fail_detach: AtomicBool::new(false),
            }
        }

        /// [`NetworkPlugin::delete_network`] の次回呼び出しを契約 9 の
        /// 「1 件でも失敗があれば `Err`」経路へ強制するためのスイッチ。ネットワーク
        /// 本体の削除のみを失敗させ、配下の netns・attach・公開ポートは回収済みの
        /// ままにする（残存資源はネットワークエントリ自体になる）。
        fn set_fail_delete(&self, fail: bool) {
            self.fail_delete.store(fail, Ordering::SeqCst);
        }

        /// [`NetworkPlugin::publish_port`] の次回呼び出しを契約 6 の
        /// 「DNAT ルール追加後に失敗する」経路へ強制するためのスイッチ。撤回が
        /// 成功するか失敗するかは [`Self::set_fail_publish_port_rollback`] で選ぶ。
        fn set_fail_publish_port(&self, fail: bool) {
            self.fail_publish_port.store(fail, Ordering::SeqCst);
        }

        /// [`Self::set_fail_publish_port`] で失敗を注入している間、追加済み DNAT
        /// ルールの撤回自体も失敗させるかどうかを切り替える。`true` にすると
        /// 契約 6 の「撤回にも失敗した場合」経路（残存資源あり）を再現し、
        /// `false`（既定）なら撤回に成功する経路（残存資源なし）を再現する。
        fn set_fail_publish_port_rollback(&self, fail: bool) {
            self.fail_publish_port_rollback
                .store(fail, Ordering::SeqCst);
        }

        /// [`NetworkPlugin::detach`] の次回呼び出しを契約 9 の
        /// 「1 件でも失敗があれば `Err`」経路へ強制するためのスイッチ。netns の
        /// 解放のみを失敗させ、公開ポート・attach の解放は成功させる（残存資源は
        /// netns 自体になる）。
        fn set_fail_detach(&self, fail: bool) {
            self.fail_detach.store(fail, Ordering::SeqCst);
        }
    }

    impl NetworkPlugin for StubNetworkPlugin {
        fn create_network(&self, req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
            let mut networks = self.networks.lock().expect("lock networks");
            if networks.contains_key(req.name()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "network already exists",
                ));
            }
            networks.insert(req.name().clone(), req.subnet());
            Ok(NetworkStatus::new(req.name().clone(), req.subnet()))
        }

        fn create_netns(&self, req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains_key(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let mut netns = self.netns.lock().expect("lock netns");
            if netns.contains_key(req.container()) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "netns already exists for this container",
                ));
            }
            // P1 修正: 名前の導出を `netns.insert` より前に行う。導出（外部入力である
            // `ContainerId` からの変換）が失敗しても追跡状態を汚さないようにするため
            // （旧実装は insert 後に `.expect` しており、59 バイト以上の
            // `ContainerId` や `.`・`_` を含む `ContainerId` で panic し、かつ
            // netns が「作成済み」として残る不整合を招いていた）。
            let name = derive_netns_name(req.container())?;
            // P2 修正: `derive_netns_name`（スタブ限定の仮規則）は `a.b` と `a_b` の
            // ように異なる `ContainerId` を同じ `NetnsName` に変換しうる。導出名が
            // 他コンテナの netns 名と衝突する場合は、いずれの状態（`netns`・
            // `netns_names`）も変更する前に `AlreadyExists` で拒否する。
            let mut netns_names = self.netns_names.lock().expect("lock netns_names");
            if netns_names.contains_key(&name) {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "derived netns name collides with an existing netns (stub-only rule)",
                ));
            }
            netns_names.insert(name.clone(), req.container().clone());
            netns.insert(req.container().clone(), req.network().clone());
            Ok(NetnsStatus::new(req.container().clone(), name))
        }

        fn attach(&self, req: &AttachRequest) -> Result<AttachResponse, TraitError> {
            let subnet = *self
                .networks
                .lock()
                .expect("lock networks")
                .get(req.network())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "network not found"))?;
            let netns = self.netns.lock().expect("lock netns");
            let bound_network = netns
                .get(req.container())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "netns not created"))?;
            if bound_network != req.network() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "netns is bound to a different network",
                ));
            }
            // 契約 10: 静的アドレス（`with_address` 経由）はサブネット内・非予約・
            // 未使用であることを検証してから記録する。未指定なら実装が動的に
            // 割り当てる（このスタブでは固定のサンプルアドレスで代替する）。
            let address = match req.address() {
                Some(address) => {
                    validate_static_address(subnet, address)?;
                    let mut assigned = self
                        .assigned_addresses
                        .lock()
                        .expect("lock assigned_addresses");
                    let network_addrs = assigned.entry(req.network().clone()).or_default();
                    if let Some(existing) = network_addrs.get(&address.addr())
                        && existing != req.container()
                    {
                        return Err(TraitError::new(
                            ErrorCode::AlreadyExists,
                            "address is already in use by another container on this network",
                        ));
                    }
                    network_addrs.insert(address.addr(), req.container().clone());
                    address
                }
                None => IpCidr::new(sample_attach_addr(), 24).expect("valid cidr"),
            };
            self.attached
                .lock()
                .expect("lock attached")
                .insert(req.container().clone(), req.network().clone());
            Ok(AttachResponse::new(
                req.network().clone(),
                req.container().clone(),
                address,
                Some(sample_gateway()),
            ))
        }

        fn publish_port(&self, req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains_key(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let attached = self.attached.lock().expect("lock attached");
            let bound_network = attached
                .get(req.container())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "container not attached"))?;
            if bound_network != req.network() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is attached to a different network",
                ));
            }
            drop(attached);
            // 契約 11: 同じホスト側ポートとプロトコルの組がネットワーク・コンテナに
            // 関わらず既に公開済みなら拒否する。フラットな `(host_port, protocol)`
            // 集合を別途持たず `published` を全件走査するのは、`detach` /
            // `delete_network` による解放（`published` からの削除）と自動的に
            // 整合させ、二重管理による状態不整合を避けるため。
            if self
                .published
                .lock()
                .expect("lock published")
                .values()
                .flatten()
                .any(|existing| {
                    existing.host_port() == req.host_port() && existing.protocol() == req.protocol()
                })
            {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "host port is already published",
                ));
            }
            let mapping = PortMapping::new(
                req.network().clone(),
                req.container().clone(),
                req.host_port(),
                req.container_port(),
                req.protocol(),
            );
            // 契約 6: DNAT ルール追加後に失敗した場合は追加済みのルールを撤回してから
            // `Err` を返し、撤回にも失敗すれば `Internal` を返して message に残存資源を
            // 含める。このスタブは `set_fail_publish_port` が立っている間、まず
            // ルール相当の状態（`published`）を実際に積んでから撤回を試みることで、
            // 「追加後に失敗する」契約 6 の経路を忠実に模擬する（旧実装はルールを
            // 一切積まなかったため、撤回対象の状態そのものが存在しなかった）。
            if self.fail_publish_port.load(Ordering::SeqCst) {
                self.published
                    .lock()
                    .expect("lock published")
                    .entry(req.container().clone())
                    .or_default()
                    .push(mapping.clone());
                if self.fail_publish_port_rollback.load(Ordering::SeqCst) {
                    // 撤回にも失敗: 資源を残したまま Err を返し、message に残存資源を
                    // 含める（契約 6 の後段）。
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        format!(
                            "failed to add DNAT rule and rollback also failed; \
                             residual rule host_port={} container_port={} protocol={}",
                            mapping.host_port(),
                            mapping.container_port(),
                            mapping.protocol().as_str()
                        ),
                    ));
                }
                // 撤回に成功: 直前に積んだルールを取り除き、追加前の状態へ戻してから
                // `Err` を返す（契約 6 の前段。エラーコードは doc がこの分岐に固有の
                // コードを定めていないため、契約 9 の削除失敗と同じ `Internal` を
                // 代表値として用いる）。
                let mut published = self.published.lock().expect("lock published");
                if let Some(list) = published.get_mut(req.container()) {
                    list.pop();
                    if list.is_empty() {
                        published.remove(req.container());
                    }
                }
                drop(published);
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to add DNAT rule; rolled back successfully",
                ));
            }
            // `detach` が解放対象として追跡できるよう、公開済みポートを積んでおく。
            self.published
                .lock()
                .expect("lock published")
                .entry(req.container().clone())
                .or_default()
                .push(mapping.clone());
            Ok(mapping)
        }

        fn detach(&self, req: &DetachRequest) -> Result<DetachResponse, TraitError> {
            if !self
                .networks
                .lock()
                .expect("lock networks")
                .contains_key(req.network())
            {
                return Err(TraitError::new(ErrorCode::NotFound, "network not found"));
            }
            let mut netns = self.netns.lock().expect("lock netns");
            let bound_network = netns
                .get(req.container())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "netns not found"))?
                .clone();
            if bound_network != *req.network() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "netns is bound to a different network",
                ));
            }
            // 契約 9: ポート公開 → veth（attached）→ netns の逆順にベストエフォートで
            // 解放する。公開ポート・attach の解放は常に成功させ、netns の解放だけを
            // `fail_detach` で失敗させられるようにする。個々の解放に失敗しても残りの
            // 解放は続け（ここでは既に完了済み）、1 件でも失敗があれば `Internal` を
            // 返して message に残存資源を含める。netns エントリは解放に失敗した場合
            // 追跡状態に残し（残存資源）、次回の呼び出しで再試行できるようにする。
            self.published
                .lock()
                .expect("lock published")
                .remove(req.container());
            self.attached
                .lock()
                .expect("lock attached")
                .remove(req.container());
            // 契約 10 の割り当て済みアドレス台帳も、attach の解放にあわせて回収する
            // （このコンテナが占有していたアドレスを他コンテナが再利用できるようにする）。
            if let Some(addrs) = self
                .assigned_addresses
                .lock()
                .expect("lock assigned_addresses")
                .get_mut(req.network())
            {
                addrs.retain(|_, container| container != req.container());
            }
            if self.fail_detach.load(Ordering::SeqCst) {
                drop(netns);
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to release one or more tracked resources: residual netns",
                ));
            }
            netns.remove(req.container());
            drop(netns);
            // P2 修正: netns 本体を解放したら、衝突検出用の逆引き（`netns_names`）
            // からも同じ名前を取り除く。`derive_netns_name` は決定的なので、
            // 作成時と同じ入力から同じ名前を再計算できる。
            if let Ok(name) = derive_netns_name(req.container()) {
                self.netns_names
                    .lock()
                    .expect("lock netns_names")
                    .remove(&name);
            }
            Ok(DetachResponse::new())
        }

        fn delete_network(
            &self,
            req: &DeleteNetworkRequest,
        ) -> Result<DeleteNetworkResponse, TraitError> {
            // トレイト doc（delete_network）: 「そのネットワークに create_netns（紐付け）・
            // attach のいずれかで関連付けたもの」を削除対象として回収する。ネットワーク名の
            // 一致で netns を洗い出し、紐づく attach・公開済みポートもまとめて削除する
            // （他ネットワークの資源には触れない）。この回収はネットワーク本体の削除に
            // 先立って行い、契約 9 の「個々の削除に失敗しても残りの削除を続ける」を
            // 体現する（配下資源の回収は常に成功する前提とし、続くネットワーク本体の
            // 削除だけを `fail_delete` で失敗させられるようにする）。
            let name = req.name().clone();
            let mut netns = self.netns.lock().expect("lock netns");
            let mut netns_names = self.netns_names.lock().expect("lock netns_names");
            let mut attached = self.attached.lock().expect("lock attached");
            let mut published = self.published.lock().expect("lock published");
            let containers: Vec<ContainerId> = netns
                .iter()
                .filter(|(_, bound_network)| **bound_network == name)
                .map(|(container, _)| container.clone())
                .collect();
            for container in containers {
                // P2 修正: netns_names（衝突検出用の逆引き）も netns 本体と一緒に
                // 回収する（`derive_netns_name` は決定的なので再計算できる）。
                if let Ok(derived) = derive_netns_name(&container) {
                    netns_names.remove(&derived);
                }
                netns.remove(&container);
                attached.remove(&container);
                published.remove(&container);
            }
            drop(netns);
            drop(netns_names);
            drop(attached);
            drop(published);
            // 契約 10 の割り当て済みアドレス台帳もネットワーク単位で回収する
            // （配下資源の回収と同じく常に成功する前提）。
            self.assigned_addresses
                .lock()
                .expect("lock assigned_addresses")
                .remove(&name);
            // 契約 9: ネットワーク本体（bridge・nft テーブル相当）の削除に失敗した場合、
            // 配下資源は既に回収済みのため、残存資源は `networks` のエントリ自体になる。
            // message にその旨を含め、`networks` からは除去せずに `Err` を返す
            // （呼び出し側が同じネットワーク名で削除を再試行できるようにするため）。
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    format!(
                        "failed to delete one or more tracked resources: residual network {name}"
                    ),
                ));
            }
            self.networks.lock().expect("lock networks").remove(&name);
            Ok(DeleteNetworkResponse::new())
        }
    }

    fn sample_network_name() -> NetworkName {
        NetworkName::new("front-end").expect("valid network name")
    }

    fn other_network_name() -> NetworkName {
        NetworkName::new("back-end").expect("valid network name")
    }

    fn sample_container_id() -> ContainerId {
        ContainerId::new("sample-container").expect("valid id")
    }

    /// [`other_network_name`] に属するコンテナ用の 2 つ目の ID
    /// （`delete_network` がネットワーク単位でのみ回収することを確認するため）。
    fn other_container_id() -> ContainerId {
        ContainerId::new("other-container").expect("valid id")
    }

    fn sample_subnet() -> IpCidr {
        IpCidr::new(IpAddr::from([10, 250, 11, 1]), 24).expect("valid cidr")
    }

    fn sample_attach_addr() -> IpAddr {
        IpAddr::from([10, 250, 11, 2])
    }

    fn sample_gateway() -> IpAddr {
        IpAddr::from([10, 250, 11, 1])
    }

    /// CRI-7: `NetworkPlugin` は dyn 互換で、`Box`/`Arc` に収めて 6 メソッドを順に呼べる。
    #[test]
    fn cri7_network_plugin_is_dyn_compatible() {
        let boxed: Box<dyn NetworkPlugin> = Box::new(StubNetworkPlugin::new());
        let net_req = CreateNetworkRequest::new(sample_network_name(), sample_subnet());
        let net_status = boxed.create_network(&net_req).expect("create succeeds");
        assert_eq!(net_status.subnet().to_string(), "10.250.11.1/24");

        let netns_status = boxed
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("network is created so create_netns succeeds");
        assert_eq!(netns_status.container(), &sample_container_id());
        assert_eq!(netns_status.name().as_str(), "netns-sample-container");

        let attach_resp = boxed
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach succeeds");
        assert_eq!(attach_resp.address().to_string(), "10.250.11.2/24");

        let mapping = boxed
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("publish_port succeeds");
        assert_eq!(mapping.protocol().as_str(), "tcp");

        let detach_resp = boxed
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("detach succeeds");
        assert_eq!(detach_resp, DetachResponse::new());

        let shared: Arc<dyn NetworkPlugin> = Arc::new(StubNetworkPlugin::new());
        let delete_resp = shared
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect("delete_network succeeds");
        assert_eq!(delete_resp, DeleteNetworkResponse::new());
    }

    /// PLUG-1: 実装のエラーコードが ERR-1 の機械可読文字列（`code().as_str()`）へ
    /// そのまま伝播する（二重の `create_network` は `ALREADY_EXISTS`）。
    #[test]
    fn plug1_network_plugin_error_propagates_code() {
        let plugin = StubNetworkPlugin::new();
        let req = CreateNetworkRequest::new(sample_network_name(), sample_subnet());
        assert!(plugin.create_network(&req).is_ok());
        let err = plugin
            .create_network(&req)
            .expect_err("second create must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// NET-1: 受理されるネットワーク名の例（英数字始まり・ハイフン・境界長）。
    #[test]
    fn net1_network_name_accepts_valid_values() {
        assert_eq!(NetworkName::new("n1").expect("valid").as_str(), "n1");
        assert_eq!(
            NetworkName::new("front-end").expect("valid").as_str(),
            "front-end"
        );
        let max_len = "a".repeat(64);
        assert!(NetworkName::new(max_len).is_ok());
    }

    /// NET-1: 拒否されるネットワーク名の例（空・記号先頭・区切り文字・NUL・非 ASCII・長さ超過）。
    #[test]
    fn net1_network_name_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            "-a".to_string(),
            "a_b".to_string(),
            "a.b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
            "a\0b".to_string(),
            "é".to_string(),
            "a".repeat(65),
        ];
        for case in cases {
            let err = NetworkName::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// NET-1: `TryFrom<&str>` / `TryFrom<String>` が `new` と同じ検証結果を返す。
    #[test]
    fn net1_network_name_try_from_matches_new() {
        let name = NetworkName::try_from("front-end").expect("valid");
        assert_eq!(name.as_str(), "front-end");

        let name = NetworkName::try_from("front-end".to_string()).expect("valid");
        assert_eq!(name.as_str(), "front-end");

        let err = NetworkName::try_from("-a").expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// CRI-7: 受理される netns 名の例（[`NetworkName`] と同じ文字集合・境界長）。
    #[test]
    fn cri7_netns_name_accepts_valid_values() {
        assert_eq!(NetnsName::new("n1").expect("valid").as_str(), "n1");
        assert_eq!(
            NetnsName::new("netns-sample").expect("valid").as_str(),
            "netns-sample"
        );
        let max_len = "a".repeat(64);
        assert!(NetnsName::new(max_len).is_ok());
    }

    /// CRI-7: 拒否される netns 名の例（[`NetworkName`] と同じ検証を共有する）。
    #[test]
    fn cri7_netns_name_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            "-a".to_string(),
            "a_b".to_string(),
            "a.b".to_string(),
            "a/b".to_string(),
            "a\0b".to_string(),
            "a".repeat(65),
        ];
        for case in cases {
            let err = NetnsName::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// CRI-7: `TryFrom<&str>` / `TryFrom<String>` が `NetnsName::new` と同じ検証結果を返す。
    #[test]
    fn cri7_netns_name_try_from_matches_new() {
        let name = NetnsName::try_from("netns-a").expect("valid");
        assert_eq!(name.as_str(), "netns-a");

        let name = NetnsName::try_from("netns-a".to_string()).expect("valid");
        assert_eq!(name.as_str(), "netns-a");

        let err = NetnsName::try_from("-a").expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// CRI-7: `NetnsStatus` は識別子のみを保持する値型で、同一入力から作った 2 つの
    /// インスタンスが `Eq` で等しく、コンテナ ID・netns 名を具体値で参照できる。
    #[test]
    fn cri7_netns_status_holds_container_and_name() {
        let container = sample_container_id();
        let name = NetnsName::new("netns-sample").expect("valid");
        let status = NetnsStatus::new(container.clone(), name.clone());
        assert_eq!(status.container(), &container);
        assert_eq!(status.name(), &name);
        assert_eq!(status.clone(), NetnsStatus::new(container, name));
    }

    /// NET-1: `IpCidr::new` はアドレスファミリごとの prefix 上限を検証し、
    /// `Display` が "10.250.11.1/24" 形式になる。
    #[test]
    fn net1_ip_cidr_validates_prefix_by_family() {
        let v4 = IpAddr::from([10, 250, 11, 1]);
        assert!(IpCidr::new(v4, 0).is_ok());
        assert!(IpCidr::new(v4, 32).is_ok());
        let err = IpCidr::new(v4, 33).expect_err("v4 prefix must be <= 32");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let v6 = IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]);
        assert!(IpCidr::new(v6, 128).is_ok());
        let err = IpCidr::new(v6, 129).expect_err("v6 prefix must be <= 128");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let cidr = IpCidr::new(v4, 24).expect("valid cidr");
        assert_eq!(cidr.to_string(), "10.250.11.1/24");
    }

    /// 契約 10: `IpCidr::contains` は IPv4 サブネット内外を判定し、アドレス
    /// ファミリが異なれば常に `false` を返す。
    #[test]
    fn net1_ip_cidr_contains_ipv4() {
        let subnet = IpCidr::new(IpAddr::from([10, 250, 11, 0]), 24).expect("valid cidr");
        assert!(subnet.contains(IpAddr::from([10, 250, 11, 1])));
        assert!(subnet.contains(IpAddr::from([10, 250, 11, 254])));
        assert!(!subnet.contains(IpAddr::from([10, 250, 12, 1])));
        // アドレスファミリ不一致は常に false。
        assert!(!subnet.contains(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])));
    }

    /// 契約 10: `IpCidr::contains` は IPv6 サブネット内外を判定する。
    #[test]
    fn net1_ip_cidr_contains_ipv6() {
        let subnet = IpCidr::new(IpAddr::from([0x2001u16, 0x0db8, 0, 0, 0, 0, 0, 0]), 32)
            .expect("valid cidr");
        assert!(subnet.contains(IpAddr::from([0x2001u16, 0x0db8, 0, 0, 0, 0, 0, 1])));
        assert!(!subnet.contains(IpAddr::from([0x2001u16, 0x0db9, 0, 0, 0, 0, 0, 1])));
    }

    /// 契約 10: prefix 長 0（境界値）は同一アドレスファミリの任意のアドレスを含む。
    #[test]
    fn net1_ip_cidr_contains_prefix_zero_matches_any_same_family_address() {
        let v4_any = IpCidr::new(IpAddr::from([0, 0, 0, 0]), 0).expect("valid cidr");
        assert!(v4_any.contains(IpAddr::from([255, 255, 255, 255])));
        assert!(v4_any.contains(IpAddr::from([1, 2, 3, 4])));

        let v6_any = IpCidr::new(IpAddr::from([0u16; 8]), 0).expect("valid cidr");
        assert!(v6_any.contains(IpAddr::from([0xffffu16; 8])));
    }

    /// 契約 10: prefix 長が最大値（境界値。v4: 32・v6: 128）はホスト経路として
    /// 完全一致するアドレスのみを含む。
    #[test]
    fn net1_ip_cidr_contains_max_prefix_matches_exact_address_only() {
        let v4_host = IpCidr::new(IpAddr::from([10, 0, 0, 1]), 32).expect("valid cidr");
        assert!(v4_host.contains(IpAddr::from([10, 0, 0, 1])));
        assert!(!v4_host.contains(IpAddr::from([10, 0, 0, 2])));

        let v6_host =
            IpCidr::new(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 128).expect("valid cidr");
        assert!(v6_host.contains(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])));
        assert!(!v6_host.contains(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 2])));
    }

    /// 契約 10: IPv4 サブネットのネットワークアドレス・ブロードキャストアドレスが
    /// 具体値どおりになる（`10.250.11.0/24` → `.0` と `.255`）。
    #[test]
    fn net1_ip_cidr_network_and_broadcast_addresses_ipv4() {
        let subnet = IpCidr::new(IpAddr::from([10, 250, 11, 1]), 24).expect("valid cidr");
        assert_eq!(subnet.network_address(), IpAddr::from([10, 250, 11, 0]));
        assert_eq!(
            subnet.broadcast_address(),
            Some(IpAddr::from([10, 250, 11, 255]))
        );
    }

    /// 契約 10: IPv6 にはブロードキャストの概念がなく常に `None`。IPv4 の `/32`
    /// もネットワークアドレスとブロードキャストアドレスを区別できないため `None`。
    #[test]
    fn net1_ip_cidr_broadcast_address_is_none_for_ipv6_and_slash32() {
        let v6 = IpCidr::new(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 64).expect("valid cidr");
        assert_eq!(v6.broadcast_address(), None);

        let v4_host = IpCidr::new(IpAddr::from([10, 0, 0, 1]), 32).expect("valid cidr");
        assert_eq!(v4_host.broadcast_address(), None);
    }

    /// NET-4: `Protocol::as_str` が全バリアントで小文字文字列を返す。
    #[test]
    fn net1_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
    }

    /// `CreateNetnsRequest` は所属先ネットワーク名を保持し、`network()` で参照できる
    /// （`delete_network` の追跡対象決定に使うため）。
    #[test]
    fn cri7_create_netns_request_returns_network() {
        let req = CreateNetnsRequest::new(sample_network_name(), sample_container_id());
        assert_eq!(req.network(), &sample_network_name());
        assert_eq!(req.container(), &sample_container_id());
    }

    /// NET-1: `AttachRequest` は `new` 直後に `address()` が `None`、
    /// `with_address` の後は `Some`（具体値で一致）になる。
    #[test]
    fn net1_attach_request_address_is_optional() {
        let req = AttachRequest::new(sample_network_name(), sample_container_id());
        assert_eq!(req.address(), None);

        let addr = IpCidr::new(sample_attach_addr(), 24).expect("valid cidr");
        let req = req.with_address(addr);
        assert_eq!(req.address(), Some(addr));
    }

    /// 契約 8: 存在しないネットワークへの `create_netns` は `NotFound`。
    #[test]
    fn net1_create_netns_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 7: 同じコンテナの netns を二重に作成すると `AlreadyExists`。
    #[test]
    fn net1_create_netns_duplicate_container_is_already_exists() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let req = CreateNetnsRequest::new(sample_network_name(), sample_container_id());
        plugin.create_netns(&req).expect("first create succeeds");
        let err = plugin
            .create_netns(&req)
            .expect_err("second create for same container must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// P1 修正: `derive_netns_name` は `.`・`_` を含む有効な `ContainerId` を
    /// panic せず決定的に変換する（旧実装は `netns.insert` 後に `.expect` しており、
    /// この入力で panic していた）。
    #[test]
    fn net1_derive_netns_name_replaces_dots_and_underscores() {
        let container = ContainerId::new("web.1_test").expect("valid container id");
        let name = derive_netns_name(&container).expect("derivation must not fail");
        assert_eq!(name.as_str(), "netns-web-1-test");
    }

    /// P1 修正: `derive_netns_name` は `IDENTIFIER_MAX_LEN`（64 バイト）を超える長さの
    /// `ContainerId` でも panic せず、`InvalidArgument` を返す（切り詰めによる
    /// 異なる `ContainerId` 間の衝突を避けるため。旧実装は境界検証なしに文字列連結
    /// するだけだったため、59 バイト以上の `ContainerId` で `NetnsName::new` の
    /// 長さ検証に落ちて `.expect` が panic していた）。
    #[test]
    fn net1_derive_netns_name_rejects_long_container_id() {
        let long_id = "a".repeat(200);
        let container = ContainerId::new(long_id).expect("valid container id");
        let err = derive_netns_name(&container)
            .expect_err("a container id that does not fit must be rejected, not truncated");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// P1 修正: `create_netns` は `.`・`_` を含む `ContainerId` では panic せず `Ok` を
    /// 返し、`NetnsStatus::name()` が導出規則どおりの具体値になる（名前導出は
    /// `netns.insert` より前に行われるため、導出に成功した場合のみ状態が変化する
    /// 契約が保たれる）。長すぎる `ContainerId` では名前導出が `Err` を返し、
    /// その場合 `netns` に一切エントリが残らないこと（insert 前に弾かれたこと）も
    /// あわせて確認する。
    #[test]
    fn net1_create_netns_does_not_panic_for_dotted_or_long_container_id() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");

        let dotted = ContainerId::new("web.1_test").expect("valid container id");
        let status = plugin
            .create_netns(&CreateNetnsRequest::new(sample_network_name(), dotted))
            .expect("create_netns must not panic for a valid ContainerId with '.' and '_'");
        assert_eq!(status.name().as_str(), "netns-web-1-test");

        let long_id = ContainerId::new("a".repeat(200)).expect("valid container id");
        let err = plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                long_id.clone(),
            ))
            .expect_err("create_netns must not panic; it must reject a name that does not fit");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
        // 導出は insert より前に行われるため、失敗した場合は netns に一切
        // 記録が残らない（P1 修正の核心: 旧実装は insert 済みのまま panic していた）。
        assert_eq!(plugin.netns.lock().expect("lock netns").get(&long_id), None);
    }

    /// P2 修正: `derive_netns_name`（スタブ限定の仮規則）は `a.b` と `a_b` のように
    /// 異なる `ContainerId` を同じ `NetnsName` に変換しうる。`create_netns` は
    /// 導出名が既存の netns 名と衝突する場合、insert 前に `AlreadyExists` で拒否し、
    /// 追跡状態（`netns`）を汚さないことを確認する。
    #[test]
    fn net1_create_netns_rejects_colliding_derived_name() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");

        let dot_id = ContainerId::new("a.b").expect("valid container id");
        let status = plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                dot_id.clone(),
            ))
            .expect("first container acquires the derived name");
        assert_eq!(status.name().as_str(), "netns-a-b");

        let underscore_id = ContainerId::new("a_b").expect("valid container id");
        let err = plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                underscore_id.clone(),
            ))
            .expect_err("a colliding derived name must be rejected");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
        // insert 前に拒否されるため、衝突した側のコンテナは netns に記録されない。
        assert_eq!(
            plugin.netns.lock().expect("lock netns").get(&underscore_id),
            None
        );
        // 衝突していない最初のコンテナの記録はそのまま残る。
        assert_eq!(
            plugin.netns.lock().expect("lock netns").get(&dot_id),
            Some(&sample_network_name())
        );
    }

    /// 契約 8: 存在しないネットワークへの `attach` は `NotFound`。
    #[test]
    fn net1_attach_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: netns 未作成のコンテナへの `attach` は、`create_network` 未作成時と
    /// 同じ扱いで `NotFound`（メソッド doc の記述を契約一覧に合わせて統一）。
    #[test]
    fn net1_attach_without_netns_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let err = plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns was never created for this container");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: netns が別ネットワークに紐付いている場合の `attach` は
    /// `FailedPrecondition`（越境接続の拒否）。
    #[test]
    fn net2_attach_netns_bound_to_other_network_is_failed_precondition() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns bound to front-end");
        let err = plugin
            .attach(&AttachRequest::new(
                other_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns is bound to a different network");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// 契約 10: サブネット内・非予約・未使用の静的アドレスを指定した `attach` は
    /// 成功し、指定どおりのアドレスが `AttachResponse` に反映される。
    #[test]
    fn net1_attach_with_valid_static_address_succeeds() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        let address = IpCidr::new(IpAddr::from([10, 250, 11, 42]), 24).expect("valid cidr");
        let resp = plugin
            .attach(
                &AttachRequest::new(sample_network_name(), sample_container_id())
                    .with_address(address),
            )
            .expect("valid static address must be accepted");
        assert_eq!(resp.address(), address);
    }

    /// 契約 10 (a): サブネット外の静的アドレスを指定した `attach` は
    /// `InvalidArgument`。
    #[test]
    fn net1_attach_with_static_address_outside_subnet_is_invalid_argument() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        let outside = IpCidr::new(IpAddr::from([10, 250, 12, 42]), 24).expect("valid cidr");
        let err = plugin
            .attach(
                &AttachRequest::new(sample_network_name(), sample_container_id())
                    .with_address(outside),
            )
            .expect_err("address outside the subnet must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// 契約 10 (a): サブネットのネットワークアドレス・ブロードキャストアドレスを
    /// 指定した `attach` は `InvalidArgument`（予約アドレス）。
    #[test]
    fn net1_attach_with_reserved_static_address_is_invalid_argument() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");

        let network_addr = IpCidr::new(IpAddr::from([10, 250, 11, 0]), 24).expect("valid cidr");
        let err = plugin
            .attach(
                &AttachRequest::new(sample_network_name(), sample_container_id())
                    .with_address(network_addr),
            )
            .expect_err("the network address itself must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        let broadcast_addr = IpCidr::new(IpAddr::from([10, 250, 11, 255]), 24).expect("valid cidr");
        let err = plugin
            .attach(
                &AttachRequest::new(sample_network_name(), sample_container_id())
                    .with_address(broadcast_addr),
            )
            .expect_err("the broadcast address must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }

    /// 契約 10 (b): 同一ネットワーク内の他コンテナが使用中の静的アドレスを指定した
    /// `attach` は `AlreadyExists`。`detach` で解放されれば再利用できることも
    /// あわせて確認する。
    #[test]
    fn net1_attach_with_static_address_in_use_by_other_container_is_already_exists() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns for first container");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                other_container_id(),
            ))
            .expect("create netns for second container");

        let address = IpCidr::new(IpAddr::from([10, 250, 11, 42]), 24).expect("valid cidr");
        plugin
            .attach(
                &AttachRequest::new(sample_network_name(), sample_container_id())
                    .with_address(address),
            )
            .expect("first container acquires the address");

        let err = plugin
            .attach(
                &AttachRequest::new(sample_network_name(), other_container_id())
                    .with_address(address),
            )
            .expect_err("a different container must not reuse the same address");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");

        // 解放（detach）すれば別コンテナが同じアドレスを取得できる。
        plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("detach releases the address");
        plugin
            .attach(
                &AttachRequest::new(sample_network_name(), other_container_id())
                    .with_address(address),
            )
            .expect("the address can be reused once released by detach");
    }

    /// 契約 8: 存在しないネットワークへの `publish_port` は `NotFound`。
    #[test]
    fn net4_publish_port_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: 未 attach のコンテナへの `publish_port` は `NotFound`。
    #[test]
    fn net4_publish_port_without_attach_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("container was never attached");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: attach 済みのネットワークと異なるネットワークを指定した `publish_port` は
    /// `FailedPrecondition`（越境 DNAT の拒否）。
    #[test]
    fn net4_publish_port_attached_to_other_network_is_failed_precondition() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach to front-end");
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                other_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("container is attached to a different network");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// 契約 11: 同じホストポート・プロトコルの組は、ネットワーク・コンテナが異なって
    /// いても二重公開を拒否される（`AlreadyExists`）。
    #[test]
    fn net4_publish_port_duplicate_host_port_is_already_exists() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns for first container");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach first container");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                other_network_name(),
                other_container_id(),
            ))
            .expect("create netns for second container");
        plugin
            .attach(&AttachRequest::new(
                other_network_name(),
                other_container_id(),
            ))
            .expect("attach second container");

        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("first publish_port succeeds");

        // 別ネットワーク・別コンテナでも、同じ host_port・プロトコルの組は拒否される。
        let err = plugin
            .publish_port(&PublishPortRequest::new(
                other_network_name(),
                other_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(81).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("the same host port and protocol must not be published twice");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");

        // プロトコルが異なれば同じ host_port を公開できる（判定キーは
        // (host_port, protocol) のため）。
        plugin
            .publish_port(&PublishPortRequest::new(
                other_network_name(),
                other_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(81).expect("nonzero"),
                Protocol::Udp,
            ))
            .expect("a different protocol on the same host port must be allowed");
    }

    /// 契約 11: `detach` で解放されたホストポートは再公開できる。
    #[test]
    fn net4_publish_port_reusable_after_detach() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("first publish_port succeeds");

        plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("detach releases the published port");

        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("recreate netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("re-attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("the host port must be reusable once released by detach");
    }

    /// 契約 11: `delete_network` で解放されたホストポートは再公開できる。
    #[test]
    fn net4_publish_port_reusable_after_delete_network() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("first publish_port succeeds");

        plugin
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect("delete_network releases the published port");

        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("recreate network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("recreate netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("re-attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("the host port must be reusable once released by delete_network");
    }

    /// 契約 9: `delete_network` はネットワーク本体の削除に失敗すれば `Internal` を
    /// 返し、message に残存資源（ネットワーク名）を含める。配下の netns は
    /// ベストエフォートの回収が先に成功しているため削除済みのままだが、
    /// ネットワーク自体は `networks` に残り、同名での再作成が `AlreadyExists` に
    /// なることで残存を確認できる（P1 修正: 旧実装は失敗注入時に状態を一切
    /// 変更しておらず、契約 9 が要求する「残存資源」を再現できていなかった）。
    #[test]
    fn net3_delete_network_partial_failure_leaves_network_residual() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin.set_fail_delete(true);

        let err = plugin
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect_err("a partial failure must surface as Err");
        assert_eq!(err.code().as_str(), "INTERNAL");
        assert!(
            err.message().contains("residual network"),
            "message must name the residual resource: {}",
            err.message()
        );

        // 配下の netns はベストエフォートの回収で既に削除済み（残存資源ではない）。
        assert_eq!(
            plugin
                .netns
                .lock()
                .expect("lock netns")
                .get(&sample_container_id()),
            None
        );
        // ネットワーク本体は削除に失敗したため `networks` に残っている
        // （残存資源）。同名の再作成が `AlreadyExists` になることでも確認できる。
        let err = plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect_err("the network entry itself must still be tracked as residual");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");

        // 失敗注入を解除して再試行すると、残存していたネットワークも削除できる。
        plugin.set_fail_delete(false);
        plugin
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect("retry succeeds once the failure is no longer injected");
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("network can be recreated once fully deleted");
    }

    /// `delete_network` のメソッド doc「そのネットワークに create_netns（紐付け）・
    /// attach のいずれかで関連付けたものを実装（plugin 側）が追跡して決める」を検証する。
    /// 削除後は同名ネットワーク・同コンテナの再作成が Ok になり（残骸が残らない）、
    /// 別ネットワークに属する netns/attach/公開ポートは削除対象に含まれず残る
    /// （ネットワーク単位でのみ回収する）。
    #[test]
    fn net3_delete_network_reclaims_netns_and_allows_recreate() {
        let plugin = StubNetworkPlugin::new();

        // 削除対象のネットワーク（front-end）側の資源一式。
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns bound to front-end");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach to front-end");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("publish_port on front-end");

        // 削除対象ではない別ネットワーク（back-end）側の資源一式。回収されないことを
        // 確認する対照群。
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                other_network_name(),
                other_container_id(),
            ))
            .expect("create netns bound to back-end");

        plugin
            .delete_network(&DeleteNetworkRequest::new(sample_network_name()))
            .expect("delete_network reclaims front-end resources");

        // 回収済み: 同名ネットワーク・同コンテナの再作成が Ok になる
        // （AlreadyExists が返らない = 残骸が残っていない）。
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("front-end network can be recreated after delete_network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("netns for the same container can be recreated after delete_network");

        // 対照群: 別ネットワーク（back-end）の netns は削除対象に含まれないため、
        // 同コンテナでの再作成は AlreadyExists のまま（＝資源が残っている証拠）。
        let err = plugin
            .create_netns(&CreateNetnsRequest::new(
                other_network_name(),
                other_container_id(),
            ))
            .expect_err("back-end's netns must be untouched by delete_network of front-end");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
    }

    /// 契約 6 の後段: `publish_port` は DNAT ルール追加後に失敗し、撤回にも失敗した
    /// 場合、`Internal` を返し message に残存資源（ホスト側・コンテナ側ポート）を
    /// 含める。実際に `published` へルールが積まれた状態のまま残ることを具体値で
    /// 検証する（P1 修正: 旧実装はルールを一切積まなかったため、撤回対象の状態も
    /// 残存資源も再現できていなかった）。
    #[test]
    fn net4_publish_port_partial_failure_rollback_fails_leaves_residual() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin.set_fail_publish_port(true);
        plugin.set_fail_publish_port_rollback(true);

        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("DNAT rule addition and its rollback both fail");
        assert_eq!(err.code().as_str(), "INTERNAL");
        assert!(
            err.message().contains("host_port=8080") && err.message().contains("container_port=80"),
            "message must name the residual rule: {}",
            err.message()
        );

        let published = plugin.published.lock().expect("lock published");
        let residual = published
            .get(&sample_container_id())
            .expect("the failed-to-roll-back rule must remain tracked");
        assert_eq!(residual.len(), 1);
        assert_eq!(
            *residual
                .first()
                .expect("residual.len() == 1 was just asserted"),
            PortMapping::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            )
        );
    }

    /// 契約 6 の前段: `publish_port` は DNAT ルール追加後に失敗しても、撤回に成功
    /// すれば追加前の状態（`published` にエントリなし）へ戻したうえで `Err` を返す。
    /// エラーコードは doc がこの分岐に固有のコードを定めていないため、契約 9 の
    /// 削除失敗と同じ `Internal` を代表値として用いる（このスタブの選択であり、
    /// 新しい契約を追加するものではない）。
    #[test]
    fn net4_publish_port_partial_failure_rollback_succeeds_clears_residual() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin.set_fail_publish_port(true);
        // set_fail_publish_port_rollback は既定で false（撤回は成功する）。

        let err = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect_err("DNAT rule addition fails but rollback succeeds");
        assert_eq!(err.code().as_str(), "INTERNAL");
        assert!(
            err.message().contains("rolled back successfully"),
            "message must indicate the rollback outcome: {}",
            err.message()
        );

        // 撤回成功: 追加前の状態（エントリなし）へ戻っている。
        assert_eq!(
            plugin
                .published
                .lock()
                .expect("lock published")
                .get(&sample_container_id()),
            None
        );

        // 失敗注入を解除して再試行すると、通常どおり公開できる。
        plugin.set_fail_publish_port(false);
        let mapping = plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("retry succeeds once the failure is no longer injected");
        assert_eq!(mapping.host_port().get(), 8080);
    }

    /// 契約 9: `detach` はポート公開・veth（attach）・netns をまとめて解放し、
    /// 解放後は同じコンテナに対して `create_netns` をやり直せる（netns が実際に
    /// 追跡対象から外れたことの確認）。
    #[test]
    fn net1_detach_releases_netns_and_attachment() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        let resp = plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("detach succeeds");
        assert_eq!(resp, DetachResponse::new());
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("netns was released so it can be recreated");
    }

    /// 契約 8: netns が既に解放済み（未作成を含む）のコンテナへの 2 回目の `detach` は
    /// `NotFound`。
    #[test]
    fn net1_detach_twice_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("first detach succeeds");
        let err = plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns was already released");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: 存在しないネットワークへの `detach` は `NotFound`。
    #[test]
    fn net1_detach_without_network_is_not_found() {
        let plugin = StubNetworkPlugin::new();
        let err = plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("network was never created");
        assert_eq!(err.code().as_str(), "NOT_FOUND");
    }

    /// 契約 8: netns が別ネットワークに紐付いている場合の `detach` は
    /// `FailedPrecondition`（越境解放の拒否）。
    #[test]
    fn net2_detach_other_network_is_failed_precondition() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create front-end network");
        plugin
            .create_network(&CreateNetworkRequest::new(
                other_network_name(),
                IpCidr::new(IpAddr::from([10, 250, 12, 1]), 24).expect("valid cidr"),
            ))
            .expect("create back-end network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns bound to front-end");
        let err = plugin
            .detach(&DetachRequest::new(
                other_network_name(),
                sample_container_id(),
            ))
            .expect_err("netns is bound to a different network");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// 契約 6・9: `detach` は解放対象に公開済みポートを含める（`publish_port` が
    /// 積んだ追跡状態が `detach` 後に消える）。
    #[test]
    fn net4_detach_removes_published_ports() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("publish_port succeeds");
        assert_eq!(
            plugin
                .published
                .lock()
                .expect("lock published")
                .get(&sample_container_id())
                .map(Vec::len),
            Some(1)
        );

        plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("detach succeeds");
        assert_eq!(
            plugin
                .published
                .lock()
                .expect("lock published")
                .get(&sample_container_id()),
            None
        );
    }

    /// 契約 9: `detach` は netns の解放に失敗すれば `Internal` を返し、message に
    /// 残存資源（netns）を含める。公開ポート・attach の解放はベストエフォートで
    /// 先に成功しているため削除済みのままだが、netns だけが追跡状態に残る
    /// （P1 修正: 旧実装は失敗注入前に netns も含めてすべて削除していたため、
    /// 契約 9 が要求する「残存資源」を再現できていなかった）。失敗注入を解除すると
    /// 同じ要求で再試行でき、残っていた netns も最終的に解放される。
    #[test]
    fn net3_detach_partial_failure_leaves_netns_residual() {
        let plugin = StubNetworkPlugin::new();
        plugin
            .create_network(&CreateNetworkRequest::new(
                sample_network_name(),
                sample_subnet(),
            ))
            .expect("create network");
        plugin
            .create_netns(&CreateNetnsRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("create netns");
        plugin
            .attach(&AttachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("attach");
        plugin
            .publish_port(&PublishPortRequest::new(
                sample_network_name(),
                sample_container_id(),
                NonZeroU16::new(8080).expect("nonzero"),
                NonZeroU16::new(80).expect("nonzero"),
                Protocol::Tcp,
            ))
            .expect("publish_port succeeds");
        plugin.set_fail_detach(true);

        let err = plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect_err("a partial failure must surface as Err");
        assert_eq!(err.code().as_str(), "INTERNAL");
        assert!(
            err.message().contains("residual netns"),
            "message must name the residual resource: {}",
            err.message()
        );

        // ベストエフォートで先に解放される公開ポート・attach は既に消えている。
        assert_eq!(
            plugin
                .published
                .lock()
                .expect("lock published")
                .get(&sample_container_id()),
            None
        );
        assert_eq!(
            plugin
                .attached
                .lock()
                .expect("lock attached")
                .get(&sample_container_id()),
            None
        );
        // netns だけが残存資源として追跡され続ける。
        assert_eq!(
            plugin
                .netns
                .lock()
                .expect("lock netns")
                .get(&sample_container_id()),
            Some(&sample_network_name())
        );

        // 失敗注入を解除して再試行すると、残っていた netns も解放される。
        plugin.set_fail_detach(false);
        plugin
            .detach(&DetachRequest::new(
                sample_network_name(),
                sample_container_id(),
            ))
            .expect("retry succeeds once the failure is no longer injected");
        assert_eq!(
            plugin
                .netns
                .lock()
                .expect("lock netns")
                .get(&sample_container_id()),
            None
        );
    }
}
