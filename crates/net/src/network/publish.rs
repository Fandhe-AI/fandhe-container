//! コンテナのポート公開指定（検証済みの型）と DNAT ルールの expr 列（TASK-139.3・#316・NET-1・MS-8）。
//!
//! 呼び出し元は `crate::network::ContainerAttachSpec::with_port_publishes`（外部入力である CLI / TOML /
//! CRI 由来の公開指定を型へ落とす境界）と `crate::network::attach_container`（接続の最後に
//! ネットワーク専用 nft テーブルの `prerouting` / `output` へ投入）。ルールの形は PoC-15 と
//! TASK-138.3 / 138.4 の実機試験で実証済みのものを踏襲する。
//!
//! # ルールの形
//!
//! `ip daddr == host_addr && ip protocol == {6|17} && th dport == host_port` →
//! `dnat to container_addr:container_port`。dport だけでは照合しない。`prerouting` は bridge から
//! 出ていく転送通信も通るため、dport のみだとコンテナ発の外部宛て通信を横取りしてしまう。
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - `host_addr` は明示された非 loopback の unicast アドレスに限る。`0.0.0.0/8`（`0.0.0.0` の全アドレス公開は
//!   意図しない外部公開につながる）・`127.0.0.0/8`（loopback 宛ては `route_localnet` が必要）・
//!   `224.0.0.0/4`（multicast）・`240.0.0.0/4`（予約済み・broadcast を含む）は拒否する
//! - 同一 host アドレス・ポートの競合（コンテナ間・ネットワーク間）は [`PortRegistry`] で投入前に検出して
//!   拒否する（nft は同一ルールの重複を拒否しないため、後から入れたルールが機能しない）。レジストリは
//!   呼び出し側が所有し、複数ネットワークで 1 つを共有する。デーモンレス構成で別プロセスが公開した受け口とも
//!   競合を検出するには [`PortRegistry::with_shared_file`] を使う（排他ロック付きの共有ファイル。既定の
//!   [`PortRegistry::new`] はプロセス内のみ）。共有ファイルは開いた fd を検証し（通常ファイル・実効 UID 所有・
//!   `0o077` なし・symlink 非追従）、一時ファイル＋fsync＋rename で原子的に更新する。空・不完全な内容・
//!   同じ受け口の重複行・書き込み側が出さない値（ポート 0・公開先範囲外のアドレス・CR）は予約ゼロ件ではなく
//!   破損として拒否する。サイズ上限（1 MiB）は読み込み・書き込みの両方で同じ検査を通し、上限を超える
//!   予約は書き込む前に `ResourceExhausted` で拒否する（書いたファイルを次回読めなくならないため）。ロックは置き換えない `<path>.lock` に掛ける。再起動後の予約表の組み直しは `network::recorded::rebuild_port_registry_recorded`
//!   （メンバー記録の公開の行から登録する。NET-3・REPAIR-4・#3362）。孤児エントリの回収は未実装で担当 Issue 未確定（REPAIR-3）
//! - 状態ルートをまたぐ衝突は、公開の前にカーネルの全 `fandhe_net_*` テーブルの DNAT を dump して照合する
//!   （`crate::network::listener_dump`。NET-3・#3063。`PortRegistry::reserve` の前に呼ぶ多層防御）。未実装範囲として、
//!   照会から投入までを排他する共有ロックと、投入後の再 dump による事後確認が残る（照会から投入までの間に別の
//!   状態ルートが割り込むと二重に投入できる窓がある。REPAIR-3。D11 の全体はまだ満たしていない。#3191）
//! - IPv4 のみ（静的 IPAM が IPv4 のみのため）。公開の個別解除は
//!   `network::unpublish_container_port`（NEWRULE の echo 応答のハンドル指定。NET-3・#2839）。プロセス再起動後は
//!   `network::recorded` がメンバー記録に永続化したハンドルから復元して個別に解除する（#3068）。記録の無い公開と
//!   ネットワーク削除時はテーブルごと解放する（`PortRegistry::release_network`。TASK-139.4）

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{EndpointId, NetworkName};
use crate::error::{NetError, NetErrorCode};
use crate::nftables_rules::{
    NftCmp, NftDataValue, NftImmediate, NftNat, NftPayload, NftRegister, NftRuleExprs,
};

/// 1 コンテナあたりの公開指定の上限（バッチ長の上限 1 MiB に対して十分小さい値）。
pub const MAX_PORT_PUBLISHES: usize = 64;

// 呼び出し元（`network.rs` の Linux 限定 `publish_ports`）以外の OS では未使用になる。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const IPPROTO_TCP: u8 = 6;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const IPPROTO_UDP: u8 = 17;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 公開先として許可する IPv4 アドレスか。`0.0.0.0/8`（"this network"・未指定を含む）・`127.0.0.0/8`
/// （loopback）・`224.0.0.0/4`（multicast）・`240.0.0.0/4`（予約済み。`255.255.255.255` の broadcast を含む）
/// を拒否する。いずれも host のローカルアドレスにならず、DNAT ルールが意図せず他の通信に一致する
/// （または一致しない）ため。それ以外は許可する（`169.254.0.0/16` や TEST-NET も unicast として扱う）。
fn is_publishable_unicast(addr: Ipv4Addr) -> bool {
    let first = addr.octets()[0];
    !(first == 0 || first == 127 || first >= 224)
}

/// 公開するトランスポートプロトコル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortProtocol {
    /// TCP（IP プロトコル番号 6）。
    Tcp,
    /// UDP（IP プロトコル番号 17）。
    Udp,
}

impl PortProtocol {
    /// IP ヘッダーのプロトコル番号。
    // Linux 限定の呼び出し元のみが使う。他 OS の非 test ビルドでは未使用（単体テストは全 OS で使う）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

/// ポート公開 1 件（host の `host_addr:host_port` 宛ての通信をコンテナの `container_port` へ DNAT する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortPublish {
    protocol: PortProtocol,
    host_addr: Ipv4Addr,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
}

impl PortPublish {
    /// 検証して作る。ポート 0、および `host_addr` が公開先として許可する範囲（モジュール doc「契約」）の
    /// 外なら `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(
        protocol: PortProtocol,
        host_addr: Ipv4Addr,
        host_port: u16,
        container_port: u16,
    ) -> Result<Self, NetError> {
        if !is_publishable_unicast(host_addr) {
            return Err(invalid(
                "host address must be an explicit unicast non-loopback address",
            ));
        }
        let host_port = NonZeroU16::new(host_port).ok_or_else(|| invalid("host port is zero"))?;
        let container_port =
            NonZeroU16::new(container_port).ok_or_else(|| invalid("container port is zero"))?;
        Ok(Self {
            protocol,
            host_addr,
            host_port,
            container_port,
        })
    }

    /// プロトコル。
    pub fn protocol(&self) -> PortProtocol {
        self.protocol
    }

    /// 公開する host 側のアドレス。
    pub fn host_addr(&self) -> Ipv4Addr {
        self.host_addr
    }

    /// 公開する host 側のポート。
    pub fn host_port(&self) -> u16 {
        self.host_port.get()
    }

    /// 転送先のコンテナ側ポート。
    pub fn container_port(&self) -> u16 {
        self.container_port.get()
    }

    /// 同じ host 側の受け口（プロトコル・アドレス・ポート）かどうか。重複検出に使う。
    pub(crate) fn same_listener(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.host_addr == other.host_addr
            && self.host_port == other.host_port
    }

    /// `container` 宛ての DNAT ルールの expr 列を組み立てる（モジュール doc「ルールの形」）。
    // Linux 限定の `publish_ports` のみが使う。他 OS の非 test ビルドでは未使用。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn dnat_rule_exprs(&self, container: Ipv4Addr) -> Result<NftRuleExprs, NetError> {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let mut exprs = NftRuleExprs::new();
        exprs.push(NftPayload::ipv4_daddr(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&self.host_addr.octets())?)?.to_expr()?)?;
        exprs.push(NftPayload::ipv4_protocol(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&[self.protocol.number()])?)?.to_expr()?)?;
        exprs.push(NftPayload::transport_dport(r1)?.to_expr()?)?;
        exprs.push(
            NftCmp::eq(r1, NftDataValue::new(&self.host_port.get().to_be_bytes())?)?.to_expr()?,
        )?;
        exprs.push(NftImmediate::ipv4_addr(r1, container)?.to_expr()?)?;
        exprs.push(NftImmediate::port(r2, self.container_port.get())?.to_expr()?)?;
        exprs.push(NftNat::dnat_ipv4(r1, Some(r2))?.to_expr()?)?;
        Ok(exprs)
    }
}

/// 受け口の持ち主（ネットワークとエンドポイント）。
type ListenerOwner = (NetworkName, EndpointId);

/// 公開済みの受け口（プロトコル・host アドレス・host ポート）の予約表（NET-1・TASK-139.3・#316）。
///
/// `attach_container` が DNAT ルールを投入する前に受け口を予約し、既に誰かが公開している受け口なら
/// 接続を失敗させる。nft は同一ルールの重複を拒否せず、先に入ったルールが優先されて後のコンテナの公開が
/// 機能しないため。コンテナ間・ネットワーク間の競合を検出できるよう、呼び出し側が全ネットワークで 1 つを
/// 共有する。状態は呼び出し側が所有するメモリ上の値（常駐デーモンを持たない。CORE-1）で、それ自体は永続化しない。
/// 再起動後は `network::recorded::rebuild_port_registry_recorded` がメンバー記録の公開の行から組み直す
/// （組み直しが不完全な間は新規の予約を拒否する。NET-3・REPAIR-4・#3362）。
///
/// # プロセス間の共有
///
/// [`PortRegistry::with_shared_file`] で作ると、予約の都度、共有ファイルを排他ロックして最新の内容を
/// 読み直し、競合検査と書き戻しを同じロックの中で行う。デーモンレス構成で別プロセスから接続した
/// コンテナとも競合を検出できる。ロックの待ちには期限を設ける（REPAIR-5）。ファイルは所有者のみ
/// 読み書き可（0600）で作り、symlink・通常ファイル以外・過大なファイル・壊れた内容は fail-closed で拒否する。
///
/// 組み直しの「不完全」の印は共有ファイルに載せず、プロセスごとに持つ。共有ファイルを使うプロセスも、最初の
/// `reserve` の前に自分で `rebuild_port_registry_recorded` を呼ぶこと。`reserve` の製品の呼び出し元は、直前に
/// カーネル dump の照合（`ensure_no_listener_conflict`）を通すこと（NET-3・REPAIR-4・#3433）。
///
/// 結線する側（#3074 の supervisor・#3075 の plugin-cri）は [`PortRegistry::awaiting_rebuild`] または
/// [`PortRegistry::with_shared_file_awaiting_rebuild`] で作る。この「組み直し待ち」の予約表は、
/// `rebuild_port_registry_recorded`（Linux 限定）を 1 回通るまで、受け口を伴う `reserve` を
/// `FailedPrecondition` で断る（#3477。状態での拒否。型での拒否・既定の変更・共有ファイルへの印の記録は採らない。
/// 判断は `docs/design/network-wiring.md`「Issue #3477 の実装メモ」）。`new()`・`with_shared_file()` は待ち状態にしない。
/// 非 Linux には組み直しの関数が無いため、待ち状態の予約表は受け口を伴う予約を通さない（net の DNAT 公開は Linux 限定）。
/// 待ち状態の構築口はまだどの製品経路にも結線していない（REPAIR-3。結線は #3074・#3075）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortRegistry {
    owners: HashMap<ListenerKey, ListenerOwner>,
    /// プロセス間で共有する予約ファイル（`None` ならプロセス内のみ）。
    shared: Option<PathBuf>,
    /// 記録からの組み直しが不完全だった印。立っている間、受け口を伴う `reserve` は `FailedPrecondition` で拒否する
    /// （予約が足りないまま新規公開を通すと二重投入になりうるため。fail-closed。NET-3・REPAIR-4・#3362）。
    /// 解放系（`release*`）は止めない。呼び出し側のメモリ上の値で、他プロセスへは伝えない。各プロセスが自分で
    /// 組み直す契約（#3433。同じ記録から同じ判定に至る）。
    incomplete: bool,
    /// 組み直す前の待ち状態（#3477）。立っている間、受け口を伴う `reserve` は `FailedPrecondition`。
    /// `mark_incomplete` / `clear_incomplete`（組み直しの完了時に必ず呼ばれる）で解ける。既定は `false`。
    awaiting_rebuild: bool,
}

/// [`PortRegistry::adopt`] の結果（記録からの組み直しの件数。#3362）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AdoptOutcome {
    /// 新たに登録した受け口。
    pub(crate) registered: usize,
    /// 同じ持ち主で既に予約済みだった受け口。
    pub(crate) already_held: usize,
    /// 別の持ち主が持っていたため登録しなかった受け口。
    pub(crate) conflicts: usize,
}

type ListenerKey = (PortProtocol, Ipv4Addr, u16);

/// 共有ファイルの最大サイズ（無制限の読み込みを防ぐ）。読み込み・書き込みの両方が
/// [`check_shared_len`] で同じ上限を検査する。名前が最大長（64 バイト）の行は 151 バイトなので、
/// 最悪でも約 6,900 件の受け口を保持できる。
const MAX_SHARED_FILE_BYTES: u64 = 1024 * 1024;
/// 共有ファイルのロック待ちの期限。
const SHARED_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 共有ファイルの先頭行（形式の版）。
const SHARED_HEADER: &str = "fandhe-portreg v1\n";
/// 共有ファイルの終端マーカー。無ければ書き込み途中として拒否する。
const SHARED_FOOTER: &str = "end\n";

fn shared_err(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::Internal, msg)
}

/// 共有ファイルの内容長 `len` がサイズ上限内か検査する。[`parse_shared`]（読み込み前後）と
/// [`encode_shared`]（書き込み前）が共有し、上限超過はどちらも `ResourceExhausted` を返す。
fn check_shared_len(len: u64) -> Result<(), NetError> {
    if len > MAX_SHARED_FILE_BYTES {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "shared port registry exceeds the size limit",
        ));
    }
    Ok(())
}

/// `path` の末尾へ `suffix` を足したパス（ロックファイル・一時ファイル用）。
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// 開いた fd の属性を検証する（TOCTOU を避けるため、パスではなく開いた後の fd を検査する）。
///
/// 通常ファイルで、実効 UID 所有、グループ・その他に権限が無い（`0o077` が 0）ことを要求する。
/// さらに `path` を symlink を追わずに引き直した dev / ino が fd と一致することを要求し、
/// 最後の要素が symlink（や差し替えられたファイル）なら拒否する。検査後は fd だけを使うので、
/// 以降のパス差し替えは影響しない。
fn verify_opened(file: &File, path: &Path) -> Result<(), NetError> {
    let meta = file
        .metadata()
        .map_err(|_| shared_err("failed to stat shared port registry"))?;
    if !meta.file_type().is_file() {
        return Err(shared_err("shared port registry is not a regular file"));
    }
    let via_path = std::fs::symlink_metadata(path)
        .map_err(|_| shared_err("failed to stat shared port registry"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Err(shared_err("shared port registry permissions are too open"));
        }
        #[cfg(target_os = "linux")]
        if meta.uid() != crate::sys::effective_uid() {
            return Err(shared_err("shared port registry has an unexpected owner"));
        }
        if via_path.dev() != meta.dev() || via_path.ino() != meta.ino() {
            return Err(shared_err("shared port registry path was replaced"));
        }
    }
    #[cfg(not(unix))]
    if !via_path.file_type().is_file() {
        return Err(shared_err("shared port registry is not a regular file"));
    }
    Ok(())
}

/// ファイルを開く。`create` なら無いときだけ排他作成する（`create_new` = O_EXCL。symlink を追わない）。
/// 既存なら通常 open のうえ [`verify_opened`] で fd を検証する。`create` でなく無ければ `None`。
fn open_verified(path: &Path, create: bool) -> Result<Option<File>, NetError> {
    let open_err = || shared_err("failed to open shared port registry");
    if create {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(path) {
            Ok(f) => return Ok(Some(f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(open_err()),
        }
    }
    match OpenOptions::new().read(true).write(create).open(path) {
        Ok(f) => {
            verify_opened(&f, path)?;
            Ok(Some(f))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(_) => Err(open_err()),
    }
}

/// 共有ファイルのロックファイル（`<path>.lock`）を開いて排他ロックする（期限付き）。
///
/// データファイルは原子的な rename で置き換えるため inode が変わる。ロックはデータファイルではなく
/// 置き換えない専用ロックファイルに掛ける。返す `File` を保持している間がロック区間。
fn open_locked(path: &Path) -> Result<File, NetError> {
    let lock_path = with_suffix(path, ".lock");
    let file = open_verified(&lock_path, true)?
        .ok_or_else(|| shared_err("failed to open shared port registry"))?;
    let deadline = Instant::now() + SHARED_LOCK_TIMEOUT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out locking shared port registry",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(shared_err("failed to lock shared port registry"));
            }
        }
    }
}

/// 共有ファイルを読む。ファイルが無ければ予約ゼロ件（初回）。空ファイルや不完全な内容は
/// 予約ゼロ件として扱わず破損として拒否する（fail-closed。書き込みは原子的 rename のため、
/// 正常系では空ファイルは現れない）。[`encode_shared`] が出さない内容（同じ受け口の重複行・
/// ポート 0・公開先範囲外のアドレス・行末の CR）も破損とする。重複を上書きで受理すると先の所有者が
/// 失われ、`release` が残すべき予約を外し得るため。サイズ上限超過は `ResourceExhausted`。
/// 呼び出しは [`open_locked`] のロック区間内で行うこと。
fn parse_shared(path: &Path) -> Result<HashMap<ListenerKey, ListenerOwner>, NetError> {
    let Some(mut file) = open_verified(path, false)? else {
        return Ok(HashMap::new());
    };
    let meta = file
        .metadata()
        .map_err(|_| shared_err("failed to stat shared port registry"))?;
    check_shared_len(meta.len())?;
    let mut text = String::new();
    // stat 後に伸びた場合も上限超過として検出できるよう、上限 + 1 バイトまで読んで同じ検査を通す。
    (&mut file)
        .take(MAX_SHARED_FILE_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|_| shared_err("failed to read shared port registry"))?;
    check_shared_len(text.len() as u64)?;
    let corrupt = || shared_err("shared port registry is corrupt");
    // 先頭行がヘッダ、末尾行が終端マーカー。切り詰められた内容・空ファイルはここで弾く。
    let body = text
        .strip_prefix(SHARED_HEADER)
        .and_then(|t| t.strip_suffix(SHARED_FOOTER))
        .ok_or_else(corrupt)?;
    let mut map = HashMap::new();
    // `lines()` は行末の CR を黙って除くため使わない（CR は最後の欄に残り、ID の検証で弾かれる）。
    for line in body.split_terminator('\n') {
        let mut f = line.split(' ');
        let (Some(proto), Some(addr), Some(port), Some(net), Some(ep), None) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            return Err(corrupt());
        };
        let proto = match proto {
            "tcp" => PortProtocol::Tcp,
            "udp" => PortProtocol::Udp,
            _ => return Err(corrupt()),
        };
        // 受け口は `PortPublish::new` と同じ規則（公開先範囲・ポート非 0）を満たすこと。
        let addr: Ipv4Addr = addr.parse().map_err(|_| corrupt())?;
        if !is_publishable_unicast(addr) {
            return Err(corrupt());
        }
        let port = port
            .parse::<u16>()
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(corrupt)?;
        let owner = (
            NetworkName::new(net).map_err(|_| corrupt())?,
            EndpointId::new(ep).map_err(|_| corrupt())?,
        );
        // 解析後のキーで照合するので、`080` と `80` のような表記違いの重複も検出する。
        if map.insert((proto, addr, port.get()), owner).is_some() {
            return Err(corrupt());
        }
    }
    Ok(map)
}

/// 予約表を共有ファイルの内容へ符号化する（行はソート済み）。長さが上限を超えれば
/// [`check_shared_len`] の `ResourceExhausted`（[`parse_shared`] と同じ検査）。
fn encode_shared(map: &HashMap<ListenerKey, ListenerOwner>) -> Result<String, NetError> {
    let mut lines: Vec<String> = map
        .iter()
        .map(|((proto, addr, port), (n, e))| {
            let proto = match proto {
                PortProtocol::Tcp => "tcp",
                PortProtocol::Udp => "udp",
            };
            format!("{proto} {addr} {port} {} {}\n", n.as_str(), e.as_str())
        })
        .collect();
    lines.sort();
    let body = format!("{SHARED_HEADER}{}{SHARED_FOOTER}", lines.concat());
    check_shared_len(body.len() as u64)?;
    Ok(body)
}

/// 共有ファイルを原子的に置き換える（一時ファイルへ書いて fsync → rename → 親ディレクトリ fsync）。
/// 途中で失敗・クラッシュしても元のファイルは無傷で残る。[`open_locked`] のロック区間内で呼ぶこと。
/// サイズ上限は一時ファイルに触れる前に [`encode_shared`] で検査する（超過時はファイル操作をしない）。
fn write_shared(path: &Path, map: &HashMap<ListenerKey, ListenerOwner>) -> Result<(), NetError> {
    let body = encode_shared(map)?;
    let werr = || shared_err("failed to write shared port registry");
    let tmp = with_suffix(path, ".tmp");
    // 前回の残骸があれば消す（symlink なら link 自体が消えるだけ）。ロック区間内なので競合しない。
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(werr()),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp).map_err(|_| werr())?;
        f.write_all(body.as_bytes()).map_err(|_| werr())?;
        f.sync_all().map_err(|_| werr())?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|_| werr())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    // rename の永続化（ベストエフォート。rename 済みなので失敗しても内容は新旧どちらかで完全）。
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Ok(d) = File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

impl PortRegistry {
    /// 空の予約表。
    pub fn new() -> Self {
        Self::default()
    }

    /// プロセス間で共有する予約ファイル `path` を使う予約表（構造体 doc「プロセス間の共有」）。
    /// ファイルが無ければ最初の予約時に作る。親ディレクトリは呼び出し側が所有者のみ書き込み可で用意すること。
    pub fn with_shared_file(path: PathBuf) -> Self {
        Self {
            owners: HashMap::new(),
            shared: Some(path),
            incomplete: false,
            awaiting_rebuild: false,
        }
    }

    /// 組み直し待ちの空の予約表（構造体 doc。#3477）。`rebuild_port_registry_recorded` を通すまで、
    /// 受け口を伴う `reserve` は `FailedPrecondition`。再起動後に記録から組み直す呼び出し元が使う。
    pub fn awaiting_rebuild() -> Self {
        Self {
            awaiting_rebuild: true,
            ..Self::default()
        }
    }

    /// [`PortRegistry::with_shared_file`] の組み直し待ち版（#3477）。共有ファイル上で他のプロセスが
    /// 組み直し済みでも、このプロセスが自分で組み直すまで待ちは解けない。
    pub fn with_shared_file_awaiting_rebuild(path: PathBuf) -> Self {
        Self {
            awaiting_rebuild: true,
            ..Self::with_shared_file(path)
        }
    }

    /// 組み直す前の待ち状態で、受け口を伴う新規の予約を拒否しているか（診断用。#3477）。
    pub fn is_awaiting_rebuild(&self) -> bool {
        self.awaiting_rebuild
    }

    /// 予約済みの受け口の件数（共有ファイル使用時は、このプロセスが最後に読み書きした時点の件数）。
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// 予約が 1 件も無いか。
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// 組み直しが不完全で、受け口を伴う新規の予約を拒否している状態か（診断用）。
    pub fn is_incomplete(&self) -> bool {
        self.incomplete
    }

    /// 組み直しが不完全だった印を立てる（`rebuild_port_registry_recorded` が使う）。
    // 呼び出し元は Linux 限定の `network::recorded`。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn mark_incomplete(&mut self) {
        self.incomplete = true;
        self.awaiting_rebuild = false;
    }

    /// 組み直しが完全に成功したので印を外す。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn clear_incomplete(&mut self) {
        self.incomplete = false;
        self.awaiting_rebuild = false;
    }

    /// 記録から読んだ公開 `entries` を予約として登録する（再起動後の組み直し。NET-3・REPAIR-4・#3362）。
    ///
    /// 同じ持ち主の既存の予約は `already_held`（冪等）、別の持ち主の予約は `conflicts`（登録せず元の持ち主のまま）。
    /// `entries` 内の同じ受け口も同じ規則で扱う。`entries` の件数は記録の上限（ネットワーク数 × メンバー数 ×
    /// `MAX_PORT_PUBLISHES`）で有界。`reserve` のコンテナ単位の上限はここでは課さない（記録は復号時に 1 メンバー
    /// `MAX_PORT_PUBLISHES` 件以下を保証済みで、超えた endpoint は以後の `reserve` が止まるだけで安全側）。
    /// 共有ファイル使用時はロックの下で 1 回だけ読み直して合併し、追加があるときだけ 1 回書く
    /// （サイズ上限超過は書かずに `ResourceExhausted`。ロック待ちの期限は `Timeout`）。失敗時は予約を増やさない。
    // 呼び出し元は Linux 限定の `network::recorded`。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn adopt(
        &mut self,
        entries: &[(NetworkName, EndpointId, PortPublish)],
    ) -> Result<AdoptOutcome, NetError> {
        let _lock = match &self.shared {
            Some(path) => {
                let lock = open_locked(path)?;
                self.owners = parse_shared(path)?;
                Some(lock)
            }
            None => None,
        };
        let mut next = self.owners.clone();
        let mut out = AdoptOutcome::default();
        for (network, endpoint, p) in entries {
            match next.get(&Self::key(p)) {
                Some((n, e)) if n == network && e == endpoint => out.already_held += 1,
                Some(_) => out.conflicts += 1,
                None => {
                    next.insert(Self::key(p), (network.clone(), endpoint.clone()));
                    out.registered += 1;
                }
            }
        }
        if out.registered > 0
            && let Some(path) = &self.shared
        {
            write_shared(path, &next)?;
        }
        self.owners = next;
        Ok(out)
    }

    fn key(p: &PortPublish) -> (PortProtocol, Ipv4Addr, u16) {
        (p.protocol, p.host_addr, p.host_port.get())
    }

    /// `owner` として `ports` の受け口をすべて予約する。1 件でも既に予約済み（同じ持ち主を含む）なら
    /// 何も予約せず `AlreadyExists`（all-or-nothing）。`ports` 内の重複も `AlreadyExists`。
    /// 共有ファイル使用時は、予約後の内容がサイズ上限を超えるなら書き込まず `ResourceExhausted`、
    /// 破損は `Internal`、ロック待ちの期限切れは `Timeout`（いずれも予約は増えない）。`ports` が空なら常に `Ok`。
    /// 組み直しが不完全な印（[`PortRegistry::is_incomplete`]）がある間、受け口を伴う予約は `FailedPrecondition`。
    /// 組み直し待ち（[`PortRegistry::is_awaiting_rebuild`]）の間も同じく `FailedPrecondition`（#3477）。
    /// 製品の呼び出し元は直前にカーネル dump の照合を通すこと（受け口不明の保持の防御はそれに依る。#3433）。
    pub(crate) fn reserve(
        &mut self,
        network: &NetworkName,
        endpoint: &EndpointId,
        ports: &[PortPublish],
    ) -> Result<(), NetError> {
        let conflict = || {
            NetError::new(
                NetErrorCode::AlreadyExists,
                "port listener is already published",
            )
        };
        if ports.is_empty() {
            // 公開なしの attach では共有予約表に触れない（ロック・解析の失敗で接続を落とさない）。
            return Ok(());
        }
        // 組み直す前の待ち状態なら断る（共有ファイルのロックより前。何も変えず、ファイルも作らない。NET-3・#3477）。
        if self.awaiting_rebuild {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "port registry has not been rebuilt from records",
            ));
        }
        // 組み直しが不完全なら新規の予約を断る（共有ファイルのロックより前。何も変えない。NET-3・#3362）。
        if self.incomplete {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "port registry is incomplete; rebuild from records failed",
            ));
        }
        // 共有ファイルは排他ロックの中で最新を読み直し、検査と書き戻しを同じロックで行う。
        let _lock = match &self.shared {
            Some(path) => {
                let lock = open_locked(path)?;
                self.owners = parse_shared(path)?;
                Some(lock)
            }
            None => None,
        };
        for (i, p) in ports.iter().enumerate() {
            if self.owners.contains_key(&Self::key(p))
                || ports.iter().skip(i + 1).any(|q| p.same_listener(q))
            {
                return Err(conflict());
            }
        }
        // コンテナ単位の上限（MAX_PORT_PUBLISHES）は既存の予約（attach 時の公開分・結果不明の予約を含む）と
        // 今回の件数の合計で検査する。予約・DNAT 投入の前に拒否する（繰り返し公開による無制限増加の防止）。
        let held = self
            .owners
            .values()
            .filter(|(n, e)| n == network && e == endpoint)
            .count();
        if held.saturating_add(ports.len()) > MAX_PORT_PUBLISHES {
            return Err(NetError::new(
                NetErrorCode::ResourceExhausted,
                "too many published ports for the container",
            ));
        }
        let mut next = self.owners.clone();
        for p in ports {
            next.insert(Self::key(p), (network.clone(), endpoint.clone()));
        }
        if let Some(path) = &self.shared {
            write_shared(path, &next)?;
        }
        self.owners = next;
        Ok(())
    }

    /// `endpoint`（`network` 内）が持つ予約をすべて解放し、解放した件数を返す。
    ///
    /// 共有ファイルのロック・読み込み・書き込みに失敗した場合は `Err` を返し、予約は残る（fail-closed。
    /// 呼び出し側は残った予約を報告して再試行できる）。
    ///
    /// DNAT ルールが残っている可能性がある間（結果不明のバッチ）は呼ばないこと。ネットワークの
    /// テーブルを削除して消えたことを確認した後に呼ぶ（ネットワーク削除では `release_network` を使う）。
    pub fn release(
        &mut self,
        network: &NetworkName,
        endpoint: &EndpointId,
    ) -> Result<usize, NetError> {
        let keep = |_: &ListenerKey, (n, e): &mut ListenerOwner| !(n == network && e == endpoint);
        if let Some(path) = &self.shared {
            // 共有ファイルから先に外す。失敗時は予約を残してエラーを返す。
            let _lock = open_locked(path)?;
            let mut map = parse_shared(path)?;
            let before = map.len();
            map.retain(keep);
            write_shared(path, &map)?;
            let released = before - map.len();
            self.owners = map;
            return Ok(released);
        }
        let before = self.owners.len();
        self.owners.retain(keep);
        Ok(before - self.owners.len())
    }

    /// `endpoint`（`network` 内）が持つ予約のうち、`ports` の受け口だけを解放し、解放した件数を返す。
    ///
    /// attach 後の追加公開（`publish_container_ports`）が確定的に失敗したとき、今回の予約だけを戻すために使う。
    /// 同じ endpoint が先に公開した受け口は残す。失敗時の扱い（予約を残して `Err`）は [`PortRegistry::release`]
    /// と同じで、DNAT ルールが残っている可能性がある間（結果不明のバッチ）は呼ばないこと。
    pub(crate) fn release_listeners(
        &mut self,
        network: &NetworkName,
        endpoint: &EndpointId,
        ports: &[PortPublish],
    ) -> Result<usize, NetError> {
        let keys: Vec<_> = ports.iter().map(Self::key).collect();
        let keep = |k: &ListenerKey, (n, e): &mut ListenerOwner| {
            !(n == network && e == endpoint && keys.contains(k))
        };
        if let Some(path) = &self.shared {
            let _lock = open_locked(path)?;
            let mut map = parse_shared(path)?;
            let before = map.len();
            map.retain(keep);
            write_shared(path, &map)?;
            let released = before - map.len();
            self.owners = map;
            return Ok(released);
        }
        let before = self.owners.len();
        self.owners.retain(keep);
        Ok(before - self.owners.len())
    }

    /// `endpoint`（`network` 内）が持つ予約の件数を返す（予約は変えない。コンテナ単体の切り離し NET-1・NET-3・#3062）。
    ///
    /// 結果不明のまま記録した公開（ハンドルが無い）の予約が残っていないかの確認に使う。共有ファイル使用時は
    /// ロックして最新を読み直す。ロック・解析の失敗は `Err`（呼び出し側は予約が残るものとして fail-closed に扱う）。
    // 呼び出し元の `detach_container_with` は OS 非依存だが、実機の呼び出しは Linux 限定。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn held_by(
        &mut self,
        network: &NetworkName,
        endpoint: &EndpointId,
    ) -> Result<usize, NetError> {
        let _lock = match &self.shared {
            Some(path) => {
                let lock = open_locked(path)?;
                self.owners = parse_shared(path)?;
                Some(lock)
            }
            None => None,
        };
        Ok(self
            .owners
            .values()
            .filter(|(n, e)| n == network && e == endpoint)
            .count())
    }

    /// `network` の予約をすべて解放し、解放した件数を返す（ネットワーク削除用。TASK-139.4・NET-1）。
    ///
    /// 結果が不明なバッチで quarantine 中の endpoint の予約も含む。手順・失敗時の扱い（予約を残して `Err`）は
    /// [`PortRegistry::release`] と同じで、専用 nft テーブルの削除を確認した後にだけ呼ぶこと。
    pub fn release_network(&mut self, network: &NetworkName) -> Result<usize, NetError> {
        let keep = |_: &ListenerKey, (n, _): &mut ListenerOwner| n != network;
        if let Some(path) = &self.shared {
            let _lock = open_locked(path)?;
            let mut map = parse_shared(path)?;
            let before = map.len();
            map.retain(keep);
            write_shared(path, &map)?;
            let released = before - map.len();
            self.owners = map;
            return Ok(released);
        }
        let before = self.owners.len();
        self.owners.retain(keep);
        Ok(before - self.owners.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables_rules::NatType;

    fn a(x: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(x)
    }

    /// NET-4・NET-1: 同じ endpoint への繰り返し予約でも、累積が MAX_PORT_PUBLISHES を超えたら
    /// 何も増やさず `ResourceExhausted` で拒否する。
    #[test]
    fn net4_reserve_rejects_cumulative_over_limit() {
        let net = NetworkName::new("web").unwrap();
        let ep = EndpointId::new("c1").unwrap();
        let mk = |range: std::ops::Range<u16>| -> Vec<PortPublish> {
            range
                .map(|i| {
                    PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 10_000 + i, 80).unwrap()
                })
                .collect()
        };
        let mut reg = PortRegistry::new();
        reg.reserve(&net, &ep, &mk(0..MAX_PORT_PUBLISHES as u16 - 1))
            .unwrap();
        let err = reg.reserve(&net, &ep, &mk(1000..1002)).unwrap_err();
        assert_eq!(err.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(reg.len(), MAX_PORT_PUBLISHES - 1);
        reg.reserve(&net, &ep, &mk(1000..1001)).unwrap();
        assert_eq!(reg.len(), MAX_PORT_PUBLISHES);
    }

    /// NET-1・NET-4: `release_listeners` は指定した受け口だけを外し、同じ endpoint の他の予約を残す。
    #[test]
    fn net4_release_listeners_releases_only_given_ports() {
        let net = NetworkName::new("web").unwrap();
        let ep = EndpointId::new("c1").unwrap();
        let p1 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8080, 80).unwrap();
        let p2 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8081, 81).unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&net, &ep, std::slice::from_ref(&p1)).unwrap();
        reg.reserve(&net, &ep, std::slice::from_ref(&p2)).unwrap();
        assert_eq!(reg.release_listeners(&net, &ep, &[p2]).unwrap(), 1);
        assert_eq!(reg.len(), 1);
        // p1 は残っているので再予約は衝突し、p2 は再予約できる。
        assert!(reg.reserve(&net, &ep, std::slice::from_ref(&p1)).is_err());
        reg.reserve(&net, &ep, &[p2]).unwrap();
    }

    /// NET-1・TASK-139.3: 非 loopback の unicast は受理し、未指定・loopback・broadcast・multicast・
    /// ポート 0 は `InvalidArgument`。
    #[test]
    fn net1_port_publish_validation() {
        let ok = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8080, 80).unwrap();
        assert_eq!(ok.host_addr(), a([192, 0, 2, 10]));
        assert_eq!(ok.host_port(), 8080);
        assert_eq!(ok.container_port(), 80);
        for bad in [
            a([0, 0, 0, 0]),
            a([0, 0, 0, 1]),
            a([0, 255, 255, 255]),
            a([240, 0, 0, 1]),
            a([254, 255, 255, 255]),
            a([127, 0, 0, 1]),
            a([127, 255, 255, 254]),
            a([255, 255, 255, 255]),
            a([224, 0, 0, 1]),
        ] {
            let e = PortPublish::new(PortProtocol::Udp, bad, 8080, 80).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
        for (hp, cp) in [(0, 80), (8080, 0)] {
            let e = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), hp, cp).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    /// NET-1・TASK-139.3: expr 列の具体値（daddr・プロトコル番号・dport の big endian・転送先・nat 種別）。
    #[test]
    fn net1_dnat_exprs_have_expected_values() {
        for (proto, num) in [(PortProtocol::Tcp, 6u8), (PortProtocol::Udp, 17u8)] {
            let p = PortPublish::new(proto, a([192, 0, 2, 10]), 0x1f90, 80).unwrap();
            let exprs = p.dnat_rule_exprs(a([10, 89, 0, 2])).unwrap();
            let e = exprs.exprs();
            assert_eq!(e.len(), 9);
            let names: Vec<&str> = e.iter().map(|x| x.name().as_str()).collect();
            assert_eq!(
                names,
                [
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "immediate",
                    "immediate",
                    "nat"
                ]
            );
            assert_eq!(
                NftCmp::from_expr(&e[1]).unwrap().data().as_bytes(),
                [192, 0, 2, 10]
            );
            assert_eq!(NftCmp::from_expr(&e[3]).unwrap().data().as_bytes(), [num]);
            assert_eq!(
                NftCmp::from_expr(&e[5]).unwrap().data().as_bytes(),
                [0x1f, 0x90]
            );
            let nat = NftNat::from_expr(&e[8]).unwrap();
            assert_eq!(nat.nat_type(), NatType::Dnat);
        }
    }

    /// NET-1・TASK-139.3: 受け口の同一判定はプロトコル・アドレス・ポートの 3 つ組。
    #[test]
    fn net1_same_listener_compares_triple() {
        let t = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let u = PortPublish::new(PortProtocol::Udp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let t2 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 8080).unwrap();
        assert!(t.same_listener(&t2));
        assert!(!t.same_listener(&u));
    }

    /// NET-1・TASK-139.3: 受け口の予約は all-or-nothing で、別コンテナ・別ネットワークとの競合を拒否し、
    /// 解放後は再予約できる。
    #[test]
    fn net1_port_registry_detects_conflicts() {
        let web = NetworkName::new("web").unwrap();
        let db = NetworkName::new("db").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let p81 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 81, 80).unwrap();
        let udp80 = PortPublish::new(PortProtocol::Udp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let mut r = PortRegistry::new();
        r.reserve(&web, &c1, &[p80]).unwrap();
        // 同じネットワークの別コンテナ。p81 も予約されない（all-or-nothing）。
        let e = r.reserve(&web, &c2, &[p81, p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r.len(), 1);
        // 別ネットワークでも競合する。プロトコルが違えば別の受け口。
        assert_eq!(
            r.reserve(&db, &c2, &[p80]).unwrap_err().code(),
            NetErrorCode::AlreadyExists
        );
        r.reserve(&db, &c2, &[udp80]).unwrap();
        assert_eq!(r.len(), 2);
        // 指定内の重複。
        let e = r.reserve(&db, &c1, &[p81, p81]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r.release(&web, &c1).unwrap(), 1);
        r.reserve(&db, &c2, &[p80]).unwrap();
        assert_eq!(r.len(), 2);
    }

    /// NET-1・TASK-139.4: `release_network` は指定ネットワークの予約だけをまとめて外す（プロセス内・共有ファイル）。
    #[test]
    fn net1_release_network_releases_only_that_network() {
        let web = NetworkName::new("web").unwrap();
        let db = NetworkName::new("db").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let p81 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 81, 80).unwrap();
        let p82 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 82, 80).unwrap();

        let mut r = PortRegistry::new();
        r.reserve(&web, &c1, &[p80]).unwrap();
        r.reserve(&web, &c2, &[p81]).unwrap();
        r.reserve(&db, &c1, &[p82]).unwrap();
        assert_eq!(r.release_network(&web).unwrap(), 2);
        assert_eq!(r.len(), 1);
        assert_eq!(r.release_network(&web).unwrap(), 0);

        let dir = shared_dir("release-network");
        let path = dir.join("ports.reg");
        let mut s1 = PortRegistry::with_shared_file(path.clone());
        let mut s2 = PortRegistry::with_shared_file(path.clone());
        s1.reserve(&web, &c1, &[p80]).unwrap();
        s1.reserve(&db, &c1, &[p82]).unwrap();
        assert_eq!(s1.release_network(&web).unwrap(), 1);
        // 他方のインスタンスから、解放済みの受け口を予約でき、他ネットワークの予約は残る。
        s2.reserve(&db, &c2, &[p80]).unwrap();
        assert_eq!(
            s2.reserve(&web, &c2, &[p82]).unwrap_err().code(),
            NetErrorCode::AlreadyExists
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-1・NET-3・#3062: `held_by` は持ち主ごとの件数を返し、予約を変えない。共有ファイルでは別
    /// インスタンスの予約も読み直して数え、壊れた内容は `Err`。
    #[test]
    fn net1_held_by_counts_owner_reservations() {
        let web = NetworkName::new("web").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let mk = |p: u16| PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), p, 80).unwrap();
        let mut r = PortRegistry::new();
        r.reserve(&web, &c1, &[mk(8080), mk(8081)]).unwrap();
        r.reserve(&web, &c2, &[mk(8082)]).unwrap();
        assert_eq!(r.held_by(&web, &c1).unwrap(), 2);
        assert_eq!(r.held_by(&web, &c2).unwrap(), 1);
        assert_eq!(r.held_by(&NetworkName::new("db").unwrap(), &c1).unwrap(), 0);
        assert_eq!(r.len(), 3);

        let dir = shared_dir("held-by");
        let path = dir.join("ports.reg");
        let mut s1 = PortRegistry::with_shared_file(path.clone());
        let mut s2 = PortRegistry::with_shared_file(path.clone());
        s1.reserve(&web, &c1, &[mk(9000), mk(9001)]).unwrap();
        assert_eq!(s2.held_by(&web, &c1).unwrap(), 2);
        assert_eq!(s2.held_by(&web, &c2).unwrap(), 0);
        write_private(&path, "fandhe-portreg v1\nbroken\nend\n");
        assert_eq!(
            s2.held_by(&web, &c1).unwrap_err().code(),
            NetErrorCode::Internal
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-1・REPAIR-12(#3375): 前回の残骸（古い `ports.reg` と余計なディレクトリ）が同じ名前に残っていても
    /// `test_root_at` が空に作り直し、共有ファイルの試験が古い予約を読まず、drop で消える。
    #[test]
    fn net1_repair12_test_root_clears_stale_residue() {
        let p = std::env::temp_dir().join(format!(
            "fc-portreg-stale-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(p.join("sub")).unwrap();
        std::fs::write(
            p.join("ports.reg"),
            "fandhe-portreg v1\ntcp 192.0.2.10 80 web c9\n",
        )
        .unwrap();
        {
            let root = crate::test_root::test_root_at(p.clone());
            assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
            assert!(!root.join("ports.reg").exists());
            // 元の失敗（排他作成）と同じ作成が通る。
            std::fs::create_dir(root.join("sub")).unwrap();
        }
        assert!(!p.exists());
    }

    /// NET-1・TASK-139.3: 共有ファイルの予約は別インスタンス（別プロセス相当）との競合を検出し、
    /// 解放は他方から見える。壊れた内容は fail-closed。
    #[test]
    fn net1_shared_registry_detects_cross_instance_conflicts() {
        // 残骸の上で進めないよう、連番つき・作成前削除・Drop 後始末の補助を使う（REPAIR-12・#3375）。
        let dir = crate::test_root::test_root("fc-portreg", "xinst");
        let path = dir.join("ports.reg");
        let _ = std::fs::remove_file(&path);
        let web = NetworkName::new("web").unwrap();
        let (c1, c2) = (
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
        );
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let mut r1 = PortRegistry::with_shared_file(path.clone());
        let mut r2 = PortRegistry::with_shared_file(path.clone());
        r1.reserve(&web, &c1, &[p80]).unwrap();
        let e = r2.reserve(&web, &c2, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(r1.release(&web, &c1).unwrap(), 1);
        r2.reserve(&web, &c2, &[p80]).unwrap();
        assert_eq!(r2.len(), 1);
        std::fs::write(&path, "garbage\n").unwrap();
        let e = r1.reserve(&web, &c1, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
        // 空ファイル（切り詰め）・終端マーカー欠落は予約ゼロ件として受理せず拒否する。
        std::fs::write(&path, "").unwrap();
        let e = r1.reserve(&web, &c1, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
        std::fs::write(&path, "fandhe-portreg v1\ntcp 192.0.2.10 80 web c2\n").unwrap();
        let e = r1.reserve(&web, &c1, &[p80]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
        // 壊れた共有ファイルでも、公開なしの予約は共有表に触れず成功する。
        r1.reserve(&web, &c1, &[]).unwrap();
        // 解放は失敗を Err で返し、呼び出し側が検知できる（予約は残る）。
        assert_eq!(
            r1.release(&web, &c1).unwrap_err().code(),
            NetErrorCode::Internal
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 共有ファイルのテスト用の一時ディレクトリ（テストごとに別名。並列実行で衝突させない）。
    fn shared_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fc-portreg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 所有者のみ読み書き可（0600）で `text` を書く（[`verify_opened`] の権限検査を通し、内容の検査に
    /// 届かせるため）。
    fn write_private(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// 共有ファイルの行 1 つ分（`tcp 192.0.2.10 <5 桁のポート> <net> <ep>\n`）の固定部分の長さ。
    const LINE_FIXED: usize = "tcp 192.0.2.10 10000  \n".len();

    /// 符号化後の長さがちょうど `total` バイトになる予約表を作る。各行は 25〜151 バイトで、
    /// ポート（10000 から連番）で受け口を一意にする。
    fn map_with_encoded_len(total: usize) -> HashMap<ListenerKey, ListenerOwner> {
        let line = |len: usize| {
            let s = len - LINE_FIXED;
            let net = s.saturating_sub(1).min(64);
            (net, s - net)
        };
        let max_line = LINE_FIXED + 128;
        let mut remaining = total - SHARED_HEADER.len() - SHARED_FOOTER.len();
        let mut lens = Vec::new();
        while remaining > max_line * 2 {
            lens.push(max_line);
            remaining -= max_line;
        }
        lens.push(remaining / 2);
        lens.push(remaining - remaining / 2);
        let mut map = HashMap::new();
        for (i, len) in lens.into_iter().enumerate() {
            let (n, e) = line(len);
            let port = 10000 + u16::try_from(i).unwrap();
            map.insert(
                (PortProtocol::Tcp, a([192, 0, 2, 10]), port),
                (
                    NetworkName::new(&"n".repeat(n)).unwrap(),
                    EndpointId::new(&"e".repeat(e)).unwrap(),
                ),
            );
        }
        map
    }

    /// NET-1・TASK-139.3: サイズ上限の検査は上限ちょうど（1 MiB = 1,048,576 バイト）を受理し、
    /// 1 バイト超過を `ResourceExhausted` で拒否する（読み込み・書き込みで共有する関数）。
    #[test]
    fn net1_shared_len_limit_is_exact() {
        assert_eq!(MAX_SHARED_FILE_BYTES, 1_048_576);
        check_shared_len(1_048_576).unwrap();
        assert_eq!(
            check_shared_len(1_048_577).unwrap_err().code(),
            NetErrorCode::ResourceExhausted
        );
    }

    /// NET-1・TASK-139.3: 上限ちょうどの予約表は書けて同じ内容で読み直せる。1 バイト超過は書き込む前に
    /// `ResourceExhausted` で拒否し、既存のファイルは変わらず一時ファイルも残らない。読み込み側も
    /// 上限超過のファイルを同じ `ResourceExhausted` で拒否する。
    #[test]
    fn net1_shared_registry_enforces_size_limit_on_write_and_read() {
        let dir = shared_dir("size");
        let path = dir.join("ports.reg");
        let exact = map_with_encoded_len(1_048_576);
        assert_eq!(encode_shared(&exact).unwrap().len(), 1_048_576);
        write_shared(&path, &exact).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1_048_576);
        assert_eq!(parse_shared(&path).unwrap(), exact);

        let over = map_with_encoded_len(1_048_577);
        assert_eq!(
            encode_shared(&over).unwrap_err().code(),
            NetErrorCode::ResourceExhausted
        );
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            write_shared(&path, &over).unwrap_err().code(),
            NetErrorCode::ResourceExhausted
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!with_suffix(&path, ".tmp").exists());

        // 上限ちょうどの内容に 1 行（25 バイト）足したファイルは、内容が正しくても読み込みで拒否する。
        let mut text = String::from_utf8(before).unwrap();
        let tail = text.len() - SHARED_FOOTER.len();
        text.insert_str(tail, "udp 192.0.2.10 10000 n e\n");
        assert_eq!(text.len(), 1_048_601);
        write_private(&path, &text);
        assert_eq!(
            parse_shared(&path).unwrap_err().code(),
            NetErrorCode::ResourceExhausted
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-1・TASK-139.3: 上限ちょうどの共有ファイルに予約を足すと `ResourceExhausted` で失敗し、
    /// ファイル・件数とも変わらない（公開 API の `reserve` 経由）。
    #[test]
    fn net1_shared_registry_reserve_rejects_over_limit() {
        let dir = shared_dir("reserve-limit");
        let path = dir.join("ports.reg");
        let exact = map_with_encoded_len(1_048_576);
        write_shared(&path, &exact).unwrap();
        let before = std::fs::read(&path).unwrap();
        let web = NetworkName::new("web").unwrap();
        let c1 = EndpointId::new("c1").unwrap();
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let mut r = PortRegistry::with_shared_file(path.clone());
        assert_eq!(
            r.reserve(&web, &c1, &[p80]).unwrap_err().code(),
            NetErrorCode::ResourceExhausted
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(r.len(), exact.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-1・TASK-139.3: 同じ受け口の重複行（持ち主違い・同じ持ち主・`080` と `80` の表記違い）、
    /// 書き込み側が出さない値（ポート 0・loopback・行末の CR）は破損として `Internal` で拒否し、
    /// `release` もファイルを書き換えない。
    #[test]
    fn net1_shared_registry_rejects_duplicate_and_foreign_lines() {
        let dir = shared_dir("dup");
        let path = dir.join("ports.reg");
        let web = NetworkName::new("web").unwrap();
        let c1 = EndpointId::new("c1").unwrap();
        let p81 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 81, 80).unwrap();
        for body in [
            "tcp 192.0.2.10 80 web c1\ntcp 192.0.2.10 80 web c2\n",
            "tcp 192.0.2.10 80 web c1\ntcp 192.0.2.10 80 web c1\n",
            "tcp 192.0.2.10 80 web c1\ntcp 192.0.2.10 080 db c2\n",
            "tcp 192.0.2.10 0 web c1\n",
            "tcp 127.0.0.1 80 web c1\n",
            "tcp 192.0.2.10 80 web c1\r\n",
        ] {
            let text = format!("fandhe-portreg v1\n{body}end\n");
            write_private(&path, &text);
            let e = parse_shared(&path).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::Internal, "{body:?}");
            assert_eq!(e.message(), "shared port registry is corrupt", "{body:?}");
            let mut r = PortRegistry::with_shared_file(path.clone());
            assert_eq!(
                r.reserve(&web, &c1, &[p81]).unwrap_err().code(),
                NetErrorCode::Internal
            );
            assert_eq!(
                r.release(&web, &c1).unwrap_err().code(),
                NetErrorCode::Internal
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
        // 重複の無い 2 行は受理する（対照）。
        write_private(
            &path,
            "fandhe-portreg v1\ntcp 192.0.2.10 80 web c1\nudp 192.0.2.10 80 web c2\nend\n",
        );
        assert_eq!(parse_shared(&path).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-1・TASK-139.3: 共有ファイルが symlink・緩い権限なら拒否し、公開なしの attach は書き直さない。
    #[cfg(unix)]
    #[test]
    fn net1_shared_registry_rejects_unsafe_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-portreg-unsafe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let web = NetworkName::new("web").unwrap();
        let c1 = EndpointId::new("c1").unwrap();
        let p80 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();

        // データファイルが symlink。
        let target = dir.join("target");
        std::fs::write(&target, "fandhe-portreg v1\nend\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.reg");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut r = PortRegistry::with_shared_file(link);
        assert_eq!(
            r.reserve(&web, &c1, &[p80]).unwrap_err().code(),
            NetErrorCode::Internal
        );

        // 権限が緩い。
        let loose = dir.join("loose.reg");
        std::fs::write(&loose, "fandhe-portreg v1\nend\n").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut r = PortRegistry::with_shared_file(loose);
        assert_eq!(
            r.reserve(&web, &c1, &[p80]).unwrap_err().code(),
            NetErrorCode::Internal
        );

        // 公開なしの attach は共有ファイルを作らない・書き換えない。
        let none = dir.join("none.reg");
        let mut r = PortRegistry::with_shared_file(none.clone());
        r.reserve(&web, &c1, &[]).unwrap();
        assert!(!none.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn adopt_fixture() -> (NetworkName, EndpointId, EndpointId, PortPublish) {
        (
            NetworkName::new("web").unwrap(),
            EndpointId::new("c1").unwrap(),
            EndpointId::new("c2").unwrap(),
            PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8080, 80).unwrap(),
        )
    }

    /// NET-3・REPAIR-4・#3362: `adopt` は 1 件登録し、同じ持ち主での再実行は `already_held`（冪等）。
    #[test]
    fn net3_3362_adopt_registers_and_is_idempotent() {
        let (web, c1, _c2, p) = adopt_fixture();
        let mut reg = PortRegistry::new();
        let out = reg.adopt(&[(web.clone(), c1.clone(), p)]).unwrap();
        assert_eq!(
            out,
            AdoptOutcome {
                registered: 1,
                already_held: 0,
                conflicts: 0
            }
        );
        assert_eq!(reg.len(), 1);
        let again = reg.adopt(&[(web, c1, p)]).unwrap();
        assert_eq!(
            again,
            AdoptOutcome {
                registered: 0,
                already_held: 1,
                conflicts: 0
            }
        );
        assert_eq!(reg.len(), 1);
    }

    /// NET-3・#3362: 別の持ち主の受け口は `conflicts` で、持ち主は元のまま（元の持ち主の `release` で 1 件解放される）。
    #[test]
    fn net3_3362_adopt_keeps_first_owner_on_conflict() {
        let (web, c1, c2, p) = adopt_fixture();
        let mut reg = PortRegistry::new();
        reg.adopt(&[(web.clone(), c1.clone(), p)]).unwrap();
        let out = reg.adopt(&[(web.clone(), c2.clone(), p)]).unwrap();
        assert_eq!(out.conflicts, 1);
        assert_eq!(out.registered, 0);
        assert_eq!(reg.release(&web, &c2).unwrap(), 0);
        assert_eq!(reg.release(&web, &c1).unwrap(), 1);
        assert!(reg.is_empty());
    }

    /// NET-3・REPAIR-4・#3362: 印が立つと受け口を伴う `reserve` は `FailedPrecondition` で何も変えず、
    /// 空の `reserve` と解放は止まらない。印を外すと再び通る。
    #[test]
    fn net3_3362_incomplete_mark_fails_closed_for_reserve_only() {
        let (web, c1, c2, p) = adopt_fixture();
        let p2 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8081, 80).unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&web, &c1, &[p]).unwrap();
        reg.mark_incomplete();
        assert!(reg.is_incomplete());
        let e = reg.reserve(&web, &c2, &[p2]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(reg.len(), 1);
        reg.reserve(&web, &c2, &[]).unwrap();
        assert_eq!(reg.release(&web, &c1).unwrap(), 1);
        reg.clear_incomplete();
        reg.reserve(&web, &c2, &[p2]).unwrap();
        assert_eq!(reg.len(), 1);
    }

    /// NET-3・REPAIR-4・#3477: 組み直し待ちの予約表は受け口を伴う `reserve` を断り、空の `reserve` と解放は通す。
    /// 既定（`new()`）は待ち状態にしない。
    #[test]
    fn net3_3477_awaiting_rebuild_rejects_reserve_with_ports() {
        let (web, c1, c2, p) = adopt_fixture();
        let mut reg = PortRegistry::awaiting_rebuild();
        assert!(reg.is_awaiting_rebuild());
        assert!(!reg.is_incomplete());
        let e = reg.reserve(&web, &c1, &[p]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "port registry has not been rebuilt from records"
        );
        assert_eq!(reg.len(), 0);
        reg.reserve(&web, &c2, &[]).unwrap();
        assert_eq!(reg.release(&web, &c1).unwrap(), 0);
        let mut plain = PortRegistry::new();
        assert!(!plain.is_awaiting_rebuild());
        plain.reserve(&web, &c1, &[p]).unwrap();
        assert_eq!(plain.len(), 1);
    }

    /// NET-3・#3477: 共有ファイル版の待ち状態は、ロックより前に断るので共有ファイルもロックファイルも作らない。
    #[test]
    fn net3_3477_awaiting_shared_file_rejects_before_touching_file() {
        let (web, c1, _c2, p) = adopt_fixture();
        let dir = shared_dir("awaiting-shared");
        let path = dir.join("ports.reg");
        let mut reg = PortRegistry::with_shared_file_awaiting_rebuild(path.clone());
        let e = reg.reserve(&web, &c1, &[p]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(!path.exists());
        let mut lock = path.clone().into_os_string();
        lock.push(".lock");
        assert!(!std::path::Path::new(&lock).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NET-3・#3362: 共有ファイルでは `adopt` の登録が別インスタンスの `reserve` に見える（同じ受け口は `AlreadyExists`）。
    #[test]
    fn net3_3362_adopt_is_visible_through_shared_file() {
        let (web, c1, c2, p) = adopt_fixture();
        let dir = shared_dir("adopt-shared");
        let path = dir.join("ports.reg");
        let mut r1 = PortRegistry::with_shared_file(path.clone());
        let mut r2 = PortRegistry::with_shared_file(path);
        assert_eq!(r1.adopt(&[(web.clone(), c1, p)]).unwrap().registered, 1);
        assert_eq!(
            r2.reserve(&web, &c2, &[p]).unwrap_err().code(),
            NetErrorCode::AlreadyExists
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// nft の cmp データとしてカーネルへ渡る L4 プロトコル番号の `libc` 照合（NET-1・NET-3・MVM-4・REPAIR-12。#3102。
/// 方式は `docs/design/ffi-libc-check.md`）。宣言と同じく Linux の試験ビルド限定。
#[cfg(all(test, target_os = "linux"))]
mod libc_abi {
    use core::ffi::c_int;

    const _: () = {
        libc_const_eq!(IPPROTO_TCP, u8, c_int);
        libc_const_eq!(IPPROTO_UDP, u8, c_int);
    };
}
