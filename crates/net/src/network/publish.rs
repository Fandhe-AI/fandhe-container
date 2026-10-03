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
//!   予約は書き込む前に `ResourceExhausted` で拒否する（書いたファイルを次回読めなくならないため）。ロックは置き換えない `<path>.lock` に掛ける。再起動後の復元と孤児エントリの回収は TASK-139.4 以降（REPAIR-3）
//! - IPv4 のみ（静的 IPAM が IPv4 のみのため）。公開の個別解除はルールハンドルの取得経路が無く未対応
//!   （ネットワーク削除時にテーブルごと解放する。TASK-139.4）

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
/// 共有する。状態は呼び出し側が所有するメモリ上の値（常駐デーモンを持たない。CORE-1）で、永続化は
/// TASK-139.4 以降（REPAIR-3）。
///
/// # プロセス間の共有
///
/// [`PortRegistry::with_shared_file`] で作ると、予約の都度、共有ファイルを排他ロックして最新の内容を
/// 読み直し、競合検査と書き戻しを同じロックの中で行う。デーモンレス構成で別プロセスから接続した
/// コンテナとも競合を検出できる。ロックの待ちには期限を設ける（REPAIR-5）。ファイルは所有者のみ
/// 読み書き可（0600）で作り、symlink・通常ファイル以外・過大なファイル・壊れた内容は fail-closed で拒否する。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortRegistry {
    owners: HashMap<ListenerKey, ListenerOwner>,
    /// プロセス間で共有する予約ファイル（`None` ならプロセス内のみ）。
    shared: Option<PathBuf>,
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
        }
    }

    /// 予約済みの受け口の件数（共有ファイル使用時は、このプロセスが最後に読み書きした時点の件数）。
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// 予約が 1 件も無いか。
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    fn key(p: &PortPublish) -> (PortProtocol, Ipv4Addr, u16) {
        (p.protocol, p.host_addr, p.host_port.get())
    }

    /// `owner` として `ports` の受け口をすべて予約する。1 件でも既に予約済み（同じ持ち主を含む）なら
    /// 何も予約せず `AlreadyExists`（all-or-nothing）。`ports` 内の重複も `AlreadyExists`。
    /// 共有ファイル使用時は、予約後の内容がサイズ上限を超えるなら書き込まず `ResourceExhausted`、
    /// 破損は `Internal`、ロック待ちの期限切れは `Timeout`（いずれも予約は増えない）。
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
    /// テーブルを削除して消えたことを確認した後（TASK-139.4）に呼ぶ。
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables_rules::NatType;

    fn a(x: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(x)
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

    /// NET-1・TASK-139.3: 共有ファイルの予約は別インスタンス（別プロセス相当）との競合を検出し、
    /// 解放は他方から見える。壊れた内容は fail-closed。
    #[test]
    fn net1_shared_registry_detects_cross_instance_conflicts() {
        let dir = std::env::temp_dir().join(format!("fc-portreg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
}
