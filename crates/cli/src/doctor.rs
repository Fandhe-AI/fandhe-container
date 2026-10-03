//! `doctor`: Docker 併存時のネットワーク到達性リスクの判定材料を集める読み取り専用の診断
//! （TASK-148.1・NET-10・MS-8・根拠 PoC-15 の発見事項 1）。
//!
//! Docker と同一ホストで自前ネットワーク（NET-1）を併存させると、`br_netfilter` がロードされ、
//! かつ Docker が iptables の `FORWARD` チェインを `policy drop` にしている環境では、bridge 経由の
//! 転送が Docker のチェインで落とされ外部到達性が損なわれる可能性がある。本モジュールは次の 2 つの
//! 事実を取得し（`FORWARD` policy はホストの `ip filter FORWARD` チェインの値であり、Docker が設定した
//! 値かどうかは照会だけでは判別できない。NET-10）、[`evaluate`] が 2 条件の組み合わせ判定・警告文・
//! `DOCKER-USER` 案内・終了コード・JSON Lines 出力（TASK-148.2）を担う。サブコマンド配線・出力先の選択・
//! `process::exit` は TASK-79 の範囲で未実装である。
//!
//! # 確認方法
//!
//! - `br_netfilter`: `/proc/sys/net/bridge/bridge-nf-call-iptables` の存在で判定する。このディレクトリは
//!   `br_netfilter` の初期化時に作られるため、モジュール版と組み込み版の両方で使える。
//!   `/sys/module/br_netfilter` は組み込み版では当てにならないため判定には使わない。ファイルの値
//!   （`0` / `1`）は bridge 通過パケットを iptables に渡すかどうかとして返し、`1` のときだけリスク条件を成立とする（`0` は不成立）。
//! - `FORWARD` チェインの policy: nf_tables に対する `NFT_MSG_GETCHAIN` の読み取り照会
//!   （`ip filter FORWARD`）。外部コマンド（`iptables` / `nft`）は起動しない（NET-11・フルスクラッチ方針）。
//!   nfnetlink は `CAP_NET_ADMIN` を要するため、非特権では [`ForwardPolicyState::PermissionDenied`] になる。
//!
//! # 判定不能の扱い（fail-closed）
//!
//! 「accept」と「答えが出なかった」を取り違えないよう、取得できなかった場合は独立した値で返す。
//! `bridge-nf-call-iptables` の `NotFound` も、`/proc/self/mountinfo` 上で `/proc/sys/net` を含むマウントが
//! procfs（fstype `proc`）であり、かつ `/proc/sys/net` がディレクトリと確認できた場合に限り未ロードとし、
//! procfs 未マウント・通常ディレクトリ・mountinfo を読めない等で確認できなければ `Unknown` とする。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! IPv6（`ip6 filter FORWARD`）、Docker の nftables ネイティブバックエンドのテーブル、iptables-legacy の
//! policy の実取得（x_tables の getsockopt）、`DOCKER-USER` チェインの照会は未実装。legacy 環境は
//! [`ForwardPolicyState::NotFoundInNftables`] の補助情報で示すに留める。

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::nftables_batch::{ChainInfo, ChainPolicy, NfInetHook};

/// sysctl・`/proc` の読み取り上限（バイト）。想定値は 1 文字なので小さく抑える。
const MAX_PROC_READ: u64 = 4096;

/// `/proc/self/mountinfo` の読み取り上限（バイト）。1 行は概ね数百バイトなので、コンテナを多数抱える
/// ホストのマウント数（数万）でも収まる値にする。超過時は読み切れないため判定不能とする（fail-closed）。
const MAX_MOUNTINFO_READ: u64 = 4 * 1024 * 1024;

/// `/proc` 配下で br_netfilter の有無を示すパス（root からの相対）。
const BR_NF_CALL_IPTABLES: &str = "proc/sys/net/bridge/bridge-nf-call-iptables";

/// procfs 自体が参照できることの確認に使うパス（root からの相対）。
///
/// procfs が未マウントだと `BR_NF_CALL_IPTABLES` も `NotFound` になり、未ロードと区別できないため、
/// procfs 上で常に存在する `/proc/sys/net` を先に確認する。
const PROC_SYS_NET: &str = "proc/sys/net";

/// 自プロセスから見たマウント一覧（root からの相対）。パスの存在だけでは procfs 上か分からないため、
/// `/proc/sys/net` を含むマウントの fstype をここから確認する（NET-10）。
const PROC_SELF_MOUNTINFO: &str = "proc/self/mountinfo";

/// `/proc/net`（root からの相対。procfs 上では `self/net` への symlink）。`IP_TABLES_NAMES` 不在を
/// 「filter なし」と断定する前に procfs 上であることを確認する対象（NET-10）。
const PROC_NET: &str = "proc/net";

/// iptables-legacy が使うテーブル名の一覧（root からの相対）。
const IP_TABLES_NAMES: &str = "proc/net/ip_tables_names";

/// 取得に失敗した理由（ERR 系に揃えた機械可読な `code` と英語の `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorProbeError {
    /// 機械可読なコード（例: `PERMISSION_DENIED`）。
    pub code: String,
    /// 人間向けの説明（英語。入力値・ホスト固有の情報は載せない）。
    pub message: String,
}

impl DoctorProbeError {
    fn from_net(e: &NetError) -> Self {
        Self {
            code: e.code().as_str().to_string(),
            message: e.message().to_string(),
        }
    }

    fn from_io(e: &std::io::Error) -> Self {
        let code = match e.kind() {
            ErrorKind::PermissionDenied => NetErrorCode::PermissionDenied,
            ErrorKind::NotFound => NetErrorCode::NotFound,
            _ => NetErrorCode::Internal,
        };
        Self {
            code: code.as_str().to_string(),
            message: "failed to read a procfs entry".to_string(),
        }
    }
}

/// `br_netfilter` のロード状態。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrNetfilterState {
    /// ロード済み。`call_iptables` は `bridge-nf-call-iptables` の値（`0` / `1` 以外は `None`）。
    Loaded {
        /// bridge を通るパケットを iptables に渡すか。
        call_iptables: Option<bool>,
    },
    /// 未ロード（sysctl が存在しない）。
    NotLoaded,
    /// 存在の判定ができなかった（権限エラー等）。
    Unknown {
        /// 失敗理由。
        reason: DoctorProbeError,
    },
    /// Linux 以外では対象外。
    Unsupported,
}

/// `br_netfilter` のロード状態を読む probe。root は既定 `/` 固定で、利用者入力のパスは受け取らない。
#[derive(Debug, Clone)]
pub struct BrNetfilterProbe {
    root: PathBuf,
}

impl Default for BrNetfilterProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl BrNetfilterProbe {
    /// ホストの `/` を対象にする。
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// テスト用に root を差し替える（利用者入力からは呼ばない）。
    #[cfg(all(test, target_os = "linux"))]
    fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// ロード状態を判定する。
    pub fn probe(&self) -> BrNetfilterState {
        if !cfg!(target_os = "linux") {
            return BrNetfilterState::Unsupported;
        }
        match read_limited(&self.root.join(BR_NF_CALL_IPTABLES), MAX_PROC_READ) {
            Ok(text) => BrNetfilterState::Loaded {
                call_iptables: match text.trim() {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
            },
            // NotFound は procfs が参照可能と確認できた場合に限り未ロードとする
            // （未マウントの procfs を未ロードと誤判定しない fail-closed。NET-10）。
            Err(e) if e.kind() == ErrorKind::NotFound => {
                match confirm_procfs(&self.root, PROC_SYS_NET) {
                    Ok(()) => BrNetfilterState::NotLoaded,
                    Err(reason) => BrNetfilterState::Unknown { reason },
                }
            }
            Err(e) => BrNetfilterState::Unknown {
                reason: DoctorProbeError::from_io(&e),
            },
        }
    }
}

/// `root` からの相対パス `dir`（`proc/` 配下のディレクトリ）が procfs 上にあることを確認する。
/// procfs 配下のファイルの `NotFound` を「存在しない」と断定してよいかの前提（NET-10）。
///
/// パスの存在だけでは procfs 上と保証できない（通常のディレクトリが残っている環境がありうる）ため、
/// `/proc/self/mountinfo` で `dir` を含むマウントの fstype が `proc` であり、かつ `dir` がディレクトリで
/// あることを確かめる。mountinfo を読めない・上限超過・該当マウントが無い・fstype が `proc` でない・
/// `dir` が無い場合は確認できないとして理由を返す（呼び出し側は判定不能として扱う。fail-closed）。
fn confirm_procfs(root: &Path, dir: &str) -> Result<(), DoctorProbeError> {
    let not_confirmed = || DoctorProbeError {
        code: NetErrorCode::Internal.as_str().to_string(),
        message: "procfs mount could not be confirmed".to_string(),
    };
    let mountinfo = read_limited(&root.join(PROC_SELF_MOUNTINFO), MAX_MOUNTINFO_READ)
        .map_err(|e| DoctorProbeError::from_io(&e))?;
    // mountinfo のマウントポイントは自プロセスの root からの絶対パスで書かれている。
    if mount_fstype(&mountinfo, &Path::new("/").join(dir)).as_deref() != Some("proc") {
        return Err(not_confirmed());
    }
    match std::fs::metadata(root.join(dir)) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(not_confirmed()),
        Err(e) => Err(DoctorProbeError::from_io(&e)),
    }
}

/// `mountinfo` 上で `path` を含むマウントの fstype（net の mountinfo 解析を再利用する）。
#[cfg(target_os = "linux")]
fn mount_fstype(mountinfo: &str, path: &Path) -> Option<String> {
    fandhe_container_net::netns::covering_mount_fstype(mountinfo, path)
}

/// Linux 以外では mountinfo が無いため常に確認できない（`probe` は先に `Unsupported` を返すので到達しない）。
#[cfg(not(target_os = "linux"))]
fn mount_fstype(_mountinfo: &str, _path: &Path) -> Option<String> {
    None
}

/// `limit` バイト以内のファイルを文字列として読む（無制限読み取りを避ける）。
///
/// 上限を超えるファイルは途中で切れた内容を返さず `InvalidData` で失敗させる（切れた内容から
/// 「行が無い」と誤断定しない fail-closed。呼び出し側は判定不能として扱う）。
fn read_limited(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut buf = Vec::new();
    // 上限 + 1 バイトまで読み、超過分が読めたら EOF に達していない（読み切れていない）と判定する。
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "file exceeds read limit",
        ));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// ホストの `ip filter FORWARD` チェイン policy の取得結果。
///
/// 値はホスト上のチェインの状態で、Docker が設定したものかどうかは照会だけでは判別できない
/// （Docker 起因かの判定は別の根拠で行う。NET-10 の診断材料）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardPolicyState {
    /// base chain の policy を取得できた。
    Policy(ChainPolicy),
    /// nftables 側の policy は accept だが、legacy iptables の filter テーブルが併存しうる（存在する、または
    /// 読み取れず不明）ため、legacy 側の FORWARD policy が DROP の可能性を否定できない状態。legacy の
    /// filter テーブルが無いと確認できた場合は [`ForwardPolicyState::Policy`] になる（NET-10・fail-closed）。
    AcceptLegacyUnruledOut {
        /// legacy iptables の filter テーブルが存在するか。`None` は判定不能（`NotFoundInNftables` と同義）。
        legacy_iptables_filter: Option<bool>,
    },
    /// チェインはあるが policy 属性を持たない（base chain でない）。
    NotBaseChain,
    /// nftables に `ip filter FORWARD` が無い。iptables-legacy 環境では正常で、`legacy_iptables_filter` は
    /// `/proc/net/ip_tables_names` に `filter` があるか（policy 自体は未取得。モジュール doc の未実装範囲）。
    NotFoundInNftables {
        /// legacy iptables の filter テーブルが存在するか。`None` は権限不足等で読み取れず判定不能
        /// （不存在の `Some(false)` と区別する。fail-closed）。ファイル自体が無い場合は、`/proc/net` が
        /// procfs 上と確認できれば `Some(false)`・確認できなければ `None`。
        legacy_iptables_filter: Option<bool>,
    },
    /// 権限不足。nfnetlink の照会には `CAP_NET_ADMIN` が必要。
    PermissionDenied,
    /// タイムアウト・応答の不整合など、判定できなかった。
    Unknown {
        /// 失敗理由。
        reason: DoctorProbeError,
    },
    /// Linux 以外では対象外。
    Unsupported,
}

/// `FORWARD` チェイン policy の取得元。テストで差し替えられるよう境界にしている。
pub trait ForwardPolicySource {
    /// `ip filter FORWARD` のチェイン情報を読み取り専用で取得する。
    fn forward_policy(&self) -> Result<ChainInfo, NetError>;
}

/// netlink（`NFT_MSG_GETCHAIN`）で取得する Linux の実装。
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct NftForwardPolicySource;

/// netlink 往復の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
const NFT_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(target_os = "linux")]
impl ForwardPolicySource for NftForwardPolicySource {
    fn forward_policy(&self) -> Result<ChainInfo, NetError> {
        use fandhe_container_net::nftables_batch::{
            ChainGet, NetlinkNetfilterSocket, NftFamily, NftName,
        };
        let socket = NetlinkNetfilterSocket::open()?;
        let req = ChainGet::new(
            NftFamily::Ipv4,
            NftName::new("filter")?,
            NftName::new("FORWARD")?,
        );
        socket.chain_info(&req, NFT_QUERY_TIMEOUT)
    }
}

/// `FORWARD` policy を取得して [`ForwardPolicyState`] にまとめる。`root` は legacy 補助判定の読み取り元。
pub fn probe_forward_policy(source: &dyn ForwardPolicySource, root: &Path) -> ForwardPolicyState {
    if !cfg!(target_os = "linux") {
        return ForwardPolicyState::Unsupported;
    }
    match source.forward_policy() {
        Ok(info) => match info.policy() {
            // 同名でも別 hook の base chain の policy を転送経路のものとして返さない
            // （hook が forward と確認できなければ判定不能。fail-closed。NET-10）。
            Some(_) if info.hook() != Some(NfInetHook::Forward.value()) => {
                ForwardPolicyState::Unknown {
                    reason: DoctorProbeError {
                        code: NetErrorCode::DataLoss.as_str().to_string(),
                        message: "FORWARD chain is not hooked to the forward hook".to_string(),
                    },
                }
            }
            // nftables 側が accept でも、併存する legacy iptables の FORWARD policy が DROP の
            // ホストを無リスクと誤判定しない。legacy の filter テーブルが無いと確認できた場合のみ
            // accept を確定させる（fail-closed。NET-10）。
            Some(ChainPolicy::Accept) => match has_legacy_filter(root) {
                Some(false) => ForwardPolicyState::Policy(ChainPolicy::Accept),
                legacy_iptables_filter => ForwardPolicyState::AcceptLegacyUnruledOut {
                    legacy_iptables_filter,
                },
            },
            Some(p) => ForwardPolicyState::Policy(p),
            None => ForwardPolicyState::NotBaseChain,
        },
        Err(e) => match e.code() {
            NetErrorCode::NotFound => ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: has_legacy_filter(root),
            },
            NetErrorCode::PermissionDenied => ForwardPolicyState::PermissionDenied,
            // Linux 上の照会未実装は OS 対象外ではなく判定不能（成功終了に見せない。fail-closed）。
            // 対象外 OS は関数冒頭で `Unsupported` を返している。
            _ => ForwardPolicyState::Unknown {
                reason: DoctorProbeError::from_net(&e),
            },
        },
    }
}

/// `/proc/net/ip_tables_names` に `filter` 行があるか。ファイル不在（ip_tables 未ロード）は `/proc/net` が
/// procfs 上と確認できた場合に限り `Some(false)`。procfs と確認できない場合・権限不足などその他の
/// 読み取り失敗は不存在と断定できないため `None`（判定不能。fail-closed）。
fn has_legacy_filter(root: &Path) -> Option<bool> {
    match read_limited(&root.join(IP_TABLES_NAMES), MAX_PROC_READ) {
        Ok(t) => Some(t.lines().any(|l| l.trim() == "filter")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            confirm_procfs(root, PROC_NET).is_ok().then_some(false)
        }
        Err(_) => None,
    }
}

/// 2 つの probe の結果。組み合わせ判定・表示は [`evaluate`]（TASK-148.2）が担う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFindings {
    /// `br_netfilter` のロード状態。
    pub br_netfilter: BrNetfilterState,
    /// ホストの `ip filter FORWARD` チェイン policy（Docker 設定かは別途判定。NET-10）。
    pub forward_policy: ForwardPolicyState,
}

/// 2 つの probe を実行して結果をそのまま保持する。
pub fn collect(probe: &BrNetfilterProbe, source: &dyn ForwardPolicySource) -> DoctorFindings {
    DoctorFindings {
        br_netfilter: probe.probe(),
        forward_policy: probe_forward_policy(source, &probe.root),
    }
}

/// 1 つの条件の判定結果（3 値＋対象外）。「満たさない」と「判定できない」を取り違えない（fail-closed。NET-10）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionState {
    /// 条件を満たす。
    Met,
    /// 条件を満たさないと確定した。
    NotMet,
    /// 判定できなかった（権限不足・照会失敗等）。
    Unknown,
    /// 対象外の OS。
    NotApplicable,
}

/// 2 条件を組み合わせた診断の結論（NET-10・TASK-148.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorOutcome {
    /// どちらかが満たされないと確定し、リスクなし。
    NoRisk,
    /// 2 条件がともに成立し、リスク警告を出す。
    RiskDetected,
    /// 少なくとも一方が判定不能で、リスクの有無を確定できない。
    Inconclusive,
    /// Linux 以外では対象外。
    NotApplicable,
}

/// `doctor` の終了ステータス。
///
/// spec に警告用の値の定義がないため本タスクで定めた（`net` の DNS ヘルパーの 1=実行時失敗・2=引数エラーに揃える）。
/// `Fatal` / `Usage` は TASK-79 の配線側が使う予約値で、本モジュールの評価（[`DoctorReport::exit_status`]）は返さない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorExitStatus {
    /// 0: 問題なし、または対象外。
    Ok,
    /// 1: 致命的エラー（ERR-1。予約）。
    Fatal,
    /// 2: 引数エラー（予約）。
    Usage,
    /// 3: リスク警告（致命的エラーとは別の値）。
    Warning,
    /// 4: 判定不能。
    Inconclusive,
}

impl DoctorExitStatus {
    /// プロセス終了コードの値。
    pub fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Fatal => 1,
            Self::Usage => 2,
            Self::Warning => 3,
            Self::Inconclusive => 4,
        }
    }
}

/// 診断の重大度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorSeverity {
    /// リスク警告。
    Warning,
    /// 情報通知（判定不能など）。
    Notice,
}

impl DoctorSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Notice => "notice",
        }
    }
}

/// 機械可読な 1 件の診断（`code` は ERR 系に揃えた英大文字スネーク、`message` は英語）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorDiagnostic {
    /// 重大度。
    pub severity: DoctorSeverity,
    /// 機械可読なコード（`BRIDGE_FORWARD_DROP_RISK` / `DIAGNOSIS_INCONCLUSIVE`）。
    pub code: &'static str,
    /// 人間向けの説明（英語。ホスト固有の情報を載せない）。
    pub message: String,
    /// 対処の案内（`DOCKER-USER` チェインでの許可方法など）。doctor 自身は設定を変更しない。
    pub remediation: Vec<String>,
}

/// 評価結果。表示（[`DoctorReport::write_json_lines`]）と終了コード（[`DoctorReport::exit_status`]）の元になる。
///
/// CLI への配線（サブコマンド・stdout / stderr の選択・`process::exit`）は TASK-79 の範囲。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// 結論。
    pub outcome: DoctorOutcome,
    /// 診断（`NoRisk` / `NotApplicable` では空）。
    pub diagnostics: Vec<DoctorDiagnostic>,
    /// 判定の元になった事実。
    pub findings: DoctorFindings,
}

fn br_netfilter_condition(s: &BrNetfilterState) -> ConditionState {
    match s {
        // bridge-nf-call-iptables=1 のときだけ bridge 通過パケットが iptables に渡り、リスクが成立する。
        // 0 は現時点では渡されないため不成立（将来 sysctl が変わりうることは現在の診断結果と分ける）。
        // 0 / 1 以外で読めない値は判定不能にする。
        BrNetfilterState::Loaded {
            call_iptables: Some(true),
        } => ConditionState::Met,
        BrNetfilterState::Loaded {
            call_iptables: Some(false),
        } => ConditionState::NotMet,
        BrNetfilterState::Loaded {
            call_iptables: None,
        } => ConditionState::Unknown,
        BrNetfilterState::NotLoaded => ConditionState::NotMet,
        BrNetfilterState::Unknown { .. } => ConditionState::Unknown,
        BrNetfilterState::Unsupported => ConditionState::NotApplicable,
    }
}

fn forward_drop_condition(s: &ForwardPolicyState) -> ConditionState {
    match s {
        ForwardPolicyState::Policy(ChainPolicy::Drop) => ConditionState::Met,
        ForwardPolicyState::Policy(ChainPolicy::Accept) => ConditionState::NotMet,
        // legacy iptables の併存を否定できない accept は無リスクと断定しない。
        ForwardPolicyState::AcceptLegacyUnruledOut { .. } => ConditionState::Unknown,
        // 未知のカーネル値は fail-closed で判定不能にする。
        ForwardPolicyState::Policy(ChainPolicy::Other(_)) => ConditionState::Unknown,
        // nftables 側の FORWARD は policy を持たないだけで、legacy iptables の filter テーブルが
        // 併存して policy が DROP の場合がありうる。legacy 側を確認できないため判定不能にする
        // （fail-closed。NET-10）。
        ForwardPolicyState::NotBaseChain => ConditionState::Unknown,
        ForwardPolicyState::NotFoundInNftables {
            legacy_iptables_filter: Some(false),
        } => ConditionState::NotMet,
        // legacy の policy は未取得のため判定できない。
        ForwardPolicyState::NotFoundInNftables {
            legacy_iptables_filter: Some(true) | None,
        } => ConditionState::Unknown,
        ForwardPolicyState::PermissionDenied => ConditionState::Unknown,
        ForwardPolicyState::Unknown { .. } => ConditionState::Unknown,
        ForwardPolicyState::Unsupported => ConditionState::NotApplicable,
    }
}

/// 2 条件を組み合わせて診断結果を作る純粋関数（NET-10・TASK-148.2）。
///
/// 評価順: 対象外 → どちらか NotMet でリスクなし → 両方 Met で警告 → それ以外は判定不能。
/// 非 root では GETCHAIN が `PermissionDenied` になるため、判定不能を「問題なし」にせず別通知で知らせる。
pub fn evaluate(findings: &DoctorFindings) -> DoctorReport {
    let a = br_netfilter_condition(&findings.br_netfilter);
    let b = forward_drop_condition(&findings.forward_policy);
    use ConditionState::{Met, NotApplicable, NotMet};
    let outcome = if a == NotApplicable || b == NotApplicable {
        DoctorOutcome::NotApplicable
    } else if a == NotMet || b == NotMet {
        DoctorOutcome::NoRisk
    } else if a == Met && b == Met {
        DoctorOutcome::RiskDetected
    } else {
        DoctorOutcome::Inconclusive
    };
    let diagnostics = match outcome {
        DoctorOutcome::RiskDetected => vec![DoctorDiagnostic {
            severity: DoctorSeverity::Warning,
            code: "BRIDGE_FORWARD_DROP_RISK",
            message: "br_netfilter is loaded and the host \"ip filter FORWARD\" chain policy is drop \
                      (as Docker sets when it manages iptables); bridged traffic of fandhe-container \
                      networks may be dropped and external reachability may be lost"
                .to_string(),
            remediation: vec![
                "First check which iptables backend is in use (\"iptables --version\" shows nf_tables or \
                 legacy) and whether the DOCKER-USER chain exists (\"iptables -S DOCKER-USER\"); \
                 DOCKER-USER exists only while Docker is running with iptables management enabled"
                    .to_string(),
                "If it exists, consider adding narrowly scoped rules to the DOCKER-USER chain for the \
                 fandhe-container bridge (<bridge>), restricted by source, destination and protocol, \
                 instead of accepting all forwarded traffic of the bridge, which would bypass \
                 existing traffic restrictions"
                    .to_string(),
                "fandhe-container doctor does not modify firewall rules; apply the rules above yourself"
                    .to_string(),
            ],
        }],
        DoctorOutcome::Inconclusive => vec![inconclusive_diagnostic(findings, a, b)],
        DoctorOutcome::NoRisk | DoctorOutcome::NotApplicable => Vec::new(),
    };
    DoctorReport {
        outcome,
        diagnostics,
        findings: findings.clone(),
    }
}

fn inconclusive_diagnostic(
    findings: &DoctorFindings,
    a: ConditionState,
    b: ConditionState,
) -> DoctorDiagnostic {
    let mut reasons: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();
    if a == ConditionState::Unknown {
        // 原因別に診断コードと案内を分ける。値が読めている場合や権限以外の失敗では
        // 権限での再実行を案内しない（誤誘導の防止）。
        let (code, advice) = match &findings.br_netfilter {
            BrNetfilterState::Unknown { reason } if reason.code == "PERMISSION_DENIED" => (
                "PERMISSION_DENIED",
                "Re-run as a user that can read /proc/sys/net (e.g. root)",
            ),
            BrNetfilterState::Unknown { reason } => (
                reason.code.as_str(),
                "Check the probe error code above; the br_netfilter state could not be read",
            ),
            BrNetfilterState::Loaded { .. } => (
                "UNRECOGNIZED_BRIDGE_NF_VALUE",
                "bridge-nf-call-iptables has a value other than 0 or 1; check it with \"sysctl net.bridge.bridge-nf-call-iptables\" (running as root does not help)",
            ),
            _ => (
                "BR_NETFILTER_UNAVAILABLE",
                "Check the br_netfilter state manually with \"lsmod | grep br_netfilter\"",
            ),
        };
        reasons.push(format!(
            "br_netfilter state could not be determined ({code})"
        ));
        remediation.push(advice.to_string());
    }
    if b == ConditionState::Unknown {
        // 原因別に診断コードと案内を分ける。権限不足以外は root で再実行しても解消しないため、
        // CAP_NET_ADMIN の案内を出さない（誤誘導の防止）。
        let (code, advice) = match &findings.forward_policy {
            ForwardPolicyState::PermissionDenied => (
                "PERMISSION_DENIED",
                "Re-run with CAP_NET_ADMIN (e.g. as root) to read the FORWARD chain policy",
            ),
            ForwardPolicyState::Unknown { reason } => (
                reason.code.as_str(),
                "Check the probe error code above; the FORWARD chain policy could not be read",
            ),
            ForwardPolicyState::AcceptLegacyUnruledOut { .. } => (
                "LEGACY_IPTABLES_POLICY_UNREAD",
                "The nftables FORWARD policy is accept, but a legacy iptables FORWARD policy cannot be ruled out; check it with \"iptables -S FORWARD\" (running as root does not help)",
            ),
            ForwardPolicyState::NotBaseChain => (
                "FORWARD_CHAIN_NOT_BASE",
                "The nftables FORWARD chain has no policy, so a legacy iptables FORWARD policy cannot be ruled out; check it with \"iptables -S FORWARD\" (running as root does not help)",
            ),
            ForwardPolicyState::Policy(_) => (
                "UNRECOGNIZED_POLICY",
                "The kernel reported an unrecognized FORWARD policy value; check it with \"nft list chain ip filter FORWARD\"",
            ),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: Some(true),
            } => (
                "LEGACY_IPTABLES_POLICY_UNREAD",
                "Legacy iptables filter table exists but its FORWARD policy is not read by this version; check it with \"iptables -S FORWARD\" (running as root does not help)",
            ),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: None,
            } => (
                "LEGACY_IPTABLES_STATE_UNKNOWN",
                "Whether a legacy iptables filter table exists could not be determined; check it with \"iptables -S FORWARD\" (running as root does not help)",
            ),
            _ => (
                "FORWARD_POLICY_UNAVAILABLE",
                "Check the FORWARD chain policy manually with \"iptables -S FORWARD\"",
            ),
        };
        reasons.push(format!("forward policy could not be determined ({code})"));
        remediation.push(advice.to_string());
    }
    DoctorDiagnostic {
        severity: DoctorSeverity::Notice,
        code: "DIAGNOSIS_INCONCLUSIVE",
        message: reasons.join("; "),
        remediation,
    }
}

impl DoctorReport {
    /// 結論に対応する終了ステータス。
    pub fn exit_status(&self) -> DoctorExitStatus {
        match self.outcome {
            DoctorOutcome::NoRisk | DoctorOutcome::NotApplicable => DoctorExitStatus::Ok,
            DoctorOutcome::RiskDetected => DoctorExitStatus::Warning,
            DoctorOutcome::Inconclusive => DoctorExitStatus::Inconclusive,
        }
    }

    /// 診断を 1 件 1 行の JSON Lines で書き出す（ERR-4 の構造化形式に寄せる）。出力先は TASK-79 が決める。
    pub fn write_json_lines(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        let br = br_netfilter_token(&self.findings.br_netfilter);
        let fw = forward_policy_token(&self.findings.forward_policy);
        for d in &self.diagnostics {
            let rem: Vec<String> = d
                .remediation
                .iter()
                .map(|r| format!("\"{}\"", json_escape(r)))
                .collect();
            writeln!(
                w,
                "{{\"severity\":\"{}\",\"code\":\"{}\",\"message\":\"{}\",\"remediation\":[{}],\"br_netfilter\":\"{}\",\"forward_policy\":\"{}\"}}",
                d.severity.as_str(),
                json_escape(d.code),
                json_escape(&d.message),
                rem.join(","),
                json_escape(&br),
                json_escape(&fw),
            )?;
        }
        Ok(())
    }
}

fn br_netfilter_token(s: &BrNetfilterState) -> String {
    match s {
        BrNetfilterState::Loaded {
            call_iptables: Some(true),
        } => "loaded(call_iptables=1)".to_string(),
        BrNetfilterState::Loaded {
            call_iptables: Some(false),
        } => "loaded(call_iptables=0)".to_string(),
        BrNetfilterState::Loaded {
            call_iptables: None,
        } => "loaded".to_string(),
        BrNetfilterState::NotLoaded => "not_loaded".to_string(),
        BrNetfilterState::Unknown { reason } => format!("unknown({})", reason.code),
        BrNetfilterState::Unsupported => "unsupported".to_string(),
    }
}

fn forward_policy_token(s: &ForwardPolicyState) -> String {
    match s {
        ForwardPolicyState::Policy(ChainPolicy::Drop) => "policy(drop)".to_string(),
        ForwardPolicyState::Policy(ChainPolicy::Accept) => "policy(accept)".to_string(),
        ForwardPolicyState::Policy(ChainPolicy::Other(n)) => format!("policy(other={n})"),
        ForwardPolicyState::AcceptLegacyUnruledOut { .. } => {
            "policy(accept,legacy_unruled_out)".to_string()
        }
        ForwardPolicyState::NotBaseChain => "not_base_chain".to_string(),
        ForwardPolicyState::NotFoundInNftables { .. } => "not_found_in_nftables".to_string(),
        ForwardPolicyState::PermissionDenied => "permission_denied".to_string(),
        ForwardPolicyState::Unknown { reason } => format!("unknown({})", reason.code),
        ForwardPolicyState::Unsupported => "unsupported".to_string(),
    }
}

/// JSON 文字列リテラルの内側用エスケープ。cli は plugin crate に依存しないため共有せずローカルに持つ
/// （同種の実装: `crates/plugin/src/lifecycle/resident.rs`）。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 評価層（`evaluate`）のテスト。実機に依存しない純粋関数のため全 OS で実行される
/// （Linux 限定の実機プローブテストは後続の `tests` モジュール）。
#[cfg(test)]
mod eval_tests {
    use super::*;

    fn loaded() -> BrNetfilterState {
        BrNetfilterState::Loaded {
            call_iptables: Some(true),
        }
    }
    fn err() -> DoctorProbeError {
        DoctorProbeError {
            code: "INTERNAL".to_string(),
            message: "x".to_string(),
        }
    }
    fn f(b: BrNetfilterState, p: ForwardPolicyState) -> DoctorFindings {
        DoctorFindings {
            br_netfilter: b,
            forward_policy: p,
        }
    }

    #[test]
    fn net10_condition_table_br_netfilter() {
        use ConditionState::*;
        for (c, want) in [(Some(true), Met), (Some(false), NotMet), (None, Unknown)] {
            assert_eq!(
                br_netfilter_condition(&BrNetfilterState::Loaded { call_iptables: c }),
                want
            );
        }
        assert_eq!(br_netfilter_condition(&BrNetfilterState::NotLoaded), NotMet);
        assert_eq!(
            br_netfilter_condition(&BrNetfilterState::Unknown { reason: err() }),
            Unknown
        );
        assert_eq!(
            br_netfilter_condition(&BrNetfilterState::Unsupported),
            NotApplicable
        );
    }

    #[test]
    fn net10_condition_table_forward_policy() {
        use ConditionState::*;
        let nf = |l| ForwardPolicyState::NotFoundInNftables {
            legacy_iptables_filter: l,
        };
        let acc = |l| ForwardPolicyState::AcceptLegacyUnruledOut {
            legacy_iptables_filter: l,
        };
        let cases = [
            (acc(Some(true)), Unknown),
            (acc(None), Unknown),
            (ForwardPolicyState::Policy(ChainPolicy::Drop), Met),
            (ForwardPolicyState::Policy(ChainPolicy::Accept), NotMet),
            (ForwardPolicyState::Policy(ChainPolicy::Other(7)), Unknown),
            (ForwardPolicyState::NotBaseChain, Unknown),
            (nf(Some(false)), NotMet),
            (nf(Some(true)), Unknown),
            (nf(None), Unknown),
            (ForwardPolicyState::PermissionDenied, Unknown),
            (ForwardPolicyState::Unknown { reason: err() }, Unknown),
            (ForwardPolicyState::Unsupported, NotApplicable),
        ];
        for (s, want) in cases {
            assert_eq!(forward_drop_condition(&s), want, "{s:?}");
        }
    }

    #[test]
    fn net10_warning_only_when_both_met() {
        let brs = [
            loaded(),
            BrNetfilterState::NotLoaded,
            BrNetfilterState::Unknown { reason: err() },
            BrNetfilterState::Unsupported,
        ];
        let fws = [
            ForwardPolicyState::Policy(ChainPolicy::Drop),
            ForwardPolicyState::Policy(ChainPolicy::Accept),
            ForwardPolicyState::Policy(ChainPolicy::Other(7)),
            ForwardPolicyState::NotBaseChain,
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: None,
            },
            ForwardPolicyState::PermissionDenied,
            ForwardPolicyState::Unsupported,
        ];
        for b in &brs {
            for p in &fws {
                let r = evaluate(&f(b.clone(), p.clone()));
                let warns = r
                    .diagnostics
                    .iter()
                    .filter(|d| d.code == "BRIDGE_FORWARD_DROP_RISK")
                    .count();
                let both = *b == loaded() && *p == ForwardPolicyState::Policy(ChainPolicy::Drop);
                assert_eq!(warns, usize::from(both), "{b:?} x {p:?}");
                assert_eq!(r.outcome == DoctorOutcome::RiskDetected, both);
            }
        }
    }

    #[test]
    fn net10_outcome_mapping() {
        let o = |b, p| evaluate(&f(b, p)).outcome;
        // nftables が accept でも legacy 併存を否定できなければ無リスクにしない。
        assert_eq!(
            o(
                loaded(),
                ForwardPolicyState::AcceptLegacyUnruledOut {
                    legacy_iptables_filter: Some(true)
                }
            ),
            DoctorOutcome::Inconclusive
        );
        assert_eq!(
            o(
                BrNetfilterState::NotLoaded,
                ForwardPolicyState::PermissionDenied
            ),
            DoctorOutcome::NoRisk
        );
        assert_eq!(
            o(loaded(), ForwardPolicyState::PermissionDenied),
            DoctorOutcome::Inconclusive
        );
        assert_eq!(
            o(
                BrNetfilterState::Unknown { reason: err() },
                ForwardPolicyState::Policy(ChainPolicy::Accept)
            ),
            DoctorOutcome::NoRisk
        );
        assert_eq!(
            o(
                BrNetfilterState::Unsupported,
                ForwardPolicyState::Policy(ChainPolicy::Drop)
            ),
            DoctorOutcome::NotApplicable
        );
    }

    fn risk() -> DoctorReport {
        evaluate(&f(loaded(), ForwardPolicyState::Policy(ChainPolicy::Drop)))
    }

    #[test]
    fn net10_call_iptables_zero_is_no_risk() {
        let r = evaluate(&f(
            BrNetfilterState::Loaded {
                call_iptables: Some(false),
            },
            ForwardPolicyState::Policy(ChainPolicy::Drop),
        ));
        assert_eq!(r.outcome, DoctorOutcome::NoRisk);
        assert!(r.diagnostics.is_empty());
    }

    #[test]
    fn net10_remediation_checks_first_and_has_no_blanket_accept() {
        let r = risk();
        let rem = &r.diagnostics[0].remediation;
        assert!(
            rem[0].contains("iptables --version") && rem[0].contains("iptables -S DOCKER-USER")
        );
        assert!(rem.iter().all(|x| !x.contains("-j ACCEPT")));
    }

    #[test]
    fn net10_warning_mentions_docker_user() {
        let r = risk();
        let d = &r.diagnostics[0];
        assert_eq!(d.severity, DoctorSeverity::Warning);
        assert!(d.message.contains("drop") && d.message.contains("br_netfilter"));
        assert!(
            d.remediation
                .iter()
                .any(|x| x.contains("DOCKER-USER") && x.contains("<bridge>"))
        );
    }

    #[test]
    fn net10_exit_codes_distinguish_warning_from_fatal() {
        assert_eq!(DoctorExitStatus::Ok.code(), 0);
        assert_eq!(DoctorExitStatus::Fatal.code(), 1);
        assert_eq!(DoctorExitStatus::Usage.code(), 2);
        assert_eq!(DoctorExitStatus::Warning.code(), 3);
        assert_eq!(DoctorExitStatus::Inconclusive.code(), 4);
        assert_ne!(
            DoctorExitStatus::Warning.code(),
            DoctorExitStatus::Fatal.code()
        );
        assert_ne!(
            DoctorExitStatus::Inconclusive.code(),
            DoctorExitStatus::Fatal.code()
        );
        assert_eq!(risk().exit_status(), DoctorExitStatus::Warning);
        let ok = evaluate(&f(
            BrNetfilterState::NotLoaded,
            ForwardPolicyState::PermissionDenied,
        ));
        assert_eq!(ok.exit_status(), DoctorExitStatus::Ok);
        let inc = evaluate(&f(loaded(), ForwardPolicyState::PermissionDenied));
        assert_eq!(inc.exit_status(), DoctorExitStatus::Inconclusive);
    }

    #[test]
    fn net10_inconclusive_notice_is_not_warning() {
        let r = evaluate(&f(loaded(), ForwardPolicyState::PermissionDenied));
        let d = &r.diagnostics[0];
        assert_eq!(d.severity, DoctorSeverity::Notice);
        assert_eq!(d.code, "DIAGNOSIS_INCONCLUSIVE");
        assert_eq!(
            d.message,
            "forward policy could not be determined (PERMISSION_DENIED)"
        );
        assert!(d.remediation[0].contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn net10_json_lines_rendering() {
        let r = evaluate(&f(loaded(), ForwardPolicyState::PermissionDenied));
        let mut buf = Vec::new();
        r.write_json_lines(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "{\"severity\":\"notice\",\"code\":\"DIAGNOSIS_INCONCLUSIVE\",\"message\":\"forward policy could not be determined (PERMISSION_DENIED)\",\"remediation\":[\"Re-run with CAP_NET_ADMIN (e.g. as root) to read the FORWARD chain policy\"],\"br_netfilter\":\"loaded(call_iptables=1)\",\"forward_policy\":\"permission_denied\"}\n"
        );
        let mut buf = Vec::new();
        risk().write_json_lines(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.lines().count(), 1);
        assert!(s.ends_with("\"forward_policy\":\"policy(drop)\"}\n"));
        let mut buf = Vec::new();
        evaluate(&f(
            BrNetfilterState::NotLoaded,
            ForwardPolicyState::PermissionDenied,
        ))
        .write_json_lines(&mut buf)
        .unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn net10_inconclusive_legacy_codes_are_distinct() {
        for (legacy, code) in [
            (Some(true), "LEGACY_IPTABLES_POLICY_UNREAD"),
            (None, "LEGACY_IPTABLES_STATE_UNKNOWN"),
        ] {
            let r = evaluate(&f(
                loaded(),
                ForwardPolicyState::NotFoundInNftables {
                    legacy_iptables_filter: legacy,
                },
            ));
            let d = &r.diagnostics[0];
            assert_eq!(d.code, "DIAGNOSIS_INCONCLUSIVE");
            assert!(d.message.contains(code), "{}", d.message);
            assert!(!d.remediation[0].contains("CAP_NET_ADMIN"));
        }
    }

    #[test]
    fn net10_not_base_chain_is_inconclusive_not_no_risk() {
        let r = evaluate(&f(loaded(), ForwardPolicyState::NotBaseChain));
        assert_eq!(r.outcome, DoctorOutcome::Inconclusive);
        assert_eq!(r.exit_status(), DoctorExitStatus::Inconclusive);
        let d = &r.diagnostics[0];
        assert!(
            d.message.contains("FORWARD_CHAIN_NOT_BASE"),
            "{}",
            d.message
        );
        assert!(!d.remediation[0].contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn net10_inconclusive_br_netfilter_codes_by_cause() {
        let fw = ForwardPolicyState::Policy(ChainPolicy::Drop);
        let perm = DoctorProbeError {
            code: "PERMISSION_DENIED".to_string(),
            message: "x".to_string(),
        };
        let cases = [
            (
                BrNetfilterState::Unknown { reason: perm },
                "PERMISSION_DENIED",
                true,
            ),
            (
                BrNetfilterState::Unknown { reason: err() },
                "INTERNAL",
                false,
            ),
            (
                BrNetfilterState::Loaded {
                    call_iptables: None,
                },
                "UNRECOGNIZED_BRIDGE_NF_VALUE",
                false,
            ),
        ];
        for (b, code, root_hint) in cases {
            let r = evaluate(&f(b, fw.clone()));
            let d = &r.diagnostics[0];
            assert!(d.message.contains(code), "{}", d.message);
            assert_eq!(d.remediation[0].contains("Re-run as a user"), root_hint);
        }
    }

    #[test]
    fn net10_json_escape() {
        assert_eq!(json_escape("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// プロセス ID と連番で一意な一時 root（Drop で削除）。
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("fandhe-doctor-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }

        fn write(&self, rel: &str, body: &str) {
            let f = self.0.join(rel);
            std::fs::create_dir_all(f.parent().expect("parent")).expect("mkdir");
            std::fs::write(f, body).expect("write");
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Mock(Result<Vec<u8>, NetErrorCode>);

    impl ForwardPolicySource for Mock {
        fn forward_policy(&self) -> Result<ChainInfo, NetError> {
            match &self.0 {
                Ok(p) => ChainInfo::decode(p),
                Err(c) => Err(NetError::new(*c, "mock")),
            }
        }
    }

    fn reply(policy: Option<u32>) -> Vec<u8> {
        reply_with_hook(policy, Some(2))
    }

    /// `hook` は `NFTA_HOOK_HOOKNUM`（`None` は hook 属性なし）。
    fn reply_with_hook(policy: Option<u32>, hook: Option<u32>) -> Vec<u8> {
        let mut p = vec![2u8, 0, 0, 0];
        if let Some(h) = hook {
            p.extend_from_slice(&12u16.to_ne_bytes());
            p.extend_from_slice(&(4u16 | 0x8000).to_ne_bytes());
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&1u16.to_ne_bytes());
            p.extend_from_slice(&h.to_be_bytes());
        }
        if let Some(v) = policy {
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&5u16.to_ne_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        p
    }

    /// `/proc` に procfs がマウントされた mountinfo（`/` は ext4）。
    const MOUNTINFO_PROCFS: &str = "\
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
24 22 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw
";

    /// procfs が参照できる環境を模した root（`/proc/sys/net`・`/proc/net` が存在し、mountinfo 上で
    /// `/proc` が procfs）。
    fn procfs_root() -> TempRoot {
        let t = TempRoot::new();
        std::fs::create_dir_all(t.0.join(PROC_SYS_NET)).expect("mkdir");
        std::fs::create_dir_all(t.0.join(PROC_NET)).expect("mkdir");
        t.write(PROC_SELF_MOUNTINFO, MOUNTINFO_PROCFS);
        t
    }

    fn br(value: Option<&str>) -> BrNetfilterState {
        let t = procfs_root();
        if let Some(v) = value {
            t.write(BR_NF_CALL_IPTABLES, v);
        }
        BrNetfilterProbe::with_root(t.0.clone()).probe()
    }

    /// NET-10: ファイルありは Loaded、値に応じて call_iptables が決まる。
    #[test]
    fn net10_br_netfilter_loaded() {
        let loaded = |c| BrNetfilterState::Loaded { call_iptables: c };
        assert_eq!(br(Some("1\n")), loaded(Some(true)));
        assert_eq!(br(Some("0\n")), loaded(Some(false)));
        assert_eq!(br(Some("x")), loaded(None));
    }

    /// NET-10: ファイル無しは NotLoaded。
    #[test]
    fn net10_br_netfilter_not_loaded() {
        assert_eq!(br(None), BrNetfilterState::NotLoaded);
    }

    /// NET-10: procfs を参照できない（`/proc/sys/net` が無い）場合は NotLoaded でなく Unknown。
    #[test]
    fn net10_br_netfilter_procfs_unavailable_is_unknown() {
        let t = TempRoot::new();
        let st = BrNetfilterProbe::with_root(t.0.clone()).probe();
        assert!(matches!(st, BrNetfilterState::Unknown { .. }), "{st:?}");
    }

    /// NET-10: `/proc/sys/net` が通常ディレクトリで procfs と確認できない場合は NotLoaded でなく Unknown。
    #[test]
    fn net10_br_netfilter_plain_directory_is_unknown() {
        let t = TempRoot::new();
        std::fs::create_dir_all(t.0.join(PROC_SYS_NET)).expect("mkdir");
        let st = BrNetfilterProbe::with_root(t.0.clone()).probe();
        // mountinfo が無い（procfs 上でない）ので NotFound の読み取り失敗として判定不能。
        assert_eq!(
            st,
            BrNetfilterState::Unknown {
                reason: DoctorProbeError {
                    code: "NOT_FOUND".to_string(),
                    message: "failed to read a procfs entry".to_string(),
                }
            }
        );
    }

    /// NET-10: mountinfo 上で `/proc/sys/net` を含むマウントが procfs でなければ、ディレクトリと mountinfo が
    /// 揃っていても NotLoaded と断定せず Unknown。
    #[test]
    fn net10_br_netfilter_non_procfs_mount_is_unknown() {
        let not_confirmed = BrNetfilterState::Unknown {
            reason: DoctorProbeError {
                code: "INTERNAL".to_string(),
                message: "procfs mount could not be confirmed".to_string(),
            },
        };
        let probe = |mountinfo: &str| {
            let t = TempRoot::new();
            std::fs::create_dir_all(t.0.join(PROC_SYS_NET)).expect("mkdir");
            t.write(PROC_SELF_MOUNTINFO, mountinfo);
            BrNetfilterProbe::with_root(t.0.clone()).probe()
        };
        // `/proc` が通常のディレクトリ（`/` の ext4 上）。
        assert_eq!(
            probe("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"),
            not_confirmed
        );
        // `/proc` は procfs だが `/proc/sys` に tmpfs が重ねられている。
        assert_eq!(
            probe(&format!(
                "{MOUNTINFO_PROCFS}30 24 0:30 / /proc/sys rw - tmpfs tmpfs rw\n"
            )),
            not_confirmed
        );
        // 該当マウントが無い（空の mountinfo）。
        assert_eq!(probe(""), not_confirmed);
        // 上限を超えて読み切れない mountinfo（procfs の行が上限より後ろにある）。
        let mut big =
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n".repeat(MAX_MOUNTINFO_READ as usize / 30 + 1);
        big.push_str(MOUNTINFO_PROCFS);
        assert_eq!(
            probe(&big),
            BrNetfilterState::Unknown {
                reason: DoctorProbeError {
                    code: "INTERNAL".to_string(),
                    message: "failed to read a procfs entry".to_string(),
                }
            }
        );
    }

    /// NET-10: mountinfo 上は procfs でも `/proc/sys/net` が無ければ（net sysctl 不在）Unknown。
    #[test]
    fn net10_br_netfilter_missing_proc_sys_net_is_unknown() {
        let t = TempRoot::new();
        t.write(PROC_SELF_MOUNTINFO, MOUNTINFO_PROCFS);
        let st = BrNetfilterProbe::with_root(t.0.clone()).probe();
        assert_eq!(
            st,
            BrNetfilterState::Unknown {
                reason: DoctorProbeError {
                    code: "NOT_FOUND".to_string(),
                    message: "failed to read a procfs entry".to_string(),
                }
            }
        );
    }

    /// NET-10: policy の取得結果が各状態に対応する。
    #[test]
    fn net10_forward_policy_states() {
        let t = TempRoot::new();
        let st = |m: Mock| probe_forward_policy(&m, &t.0);
        assert_eq!(
            st(Mock(Ok(reply(Some(0))))),
            ForwardPolicyState::Policy(ChainPolicy::Drop)
        );
        // accept は legacy の filter テーブル不在を確認できた場合のみ確定する。
        assert_eq!(
            st(Mock(Ok(reply(Some(1))))),
            ForwardPolicyState::AcceptLegacyUnruledOut {
                legacy_iptables_filter: None
            }
        );
        assert_eq!(
            probe_forward_policy(&Mock(Ok(reply(Some(1)))), &procfs_root().0),
            ForwardPolicyState::Policy(ChainPolicy::Accept)
        );
        // Linux 上の Unimplemented は対象外ではなく判定不能。
        assert!(matches!(
            st(Mock(Err(NetErrorCode::Unimplemented))),
            ForwardPolicyState::Unknown { .. }
        ));
        assert_eq!(st(Mock(Ok(reply(None)))), ForwardPolicyState::NotBaseChain);
        // 別 hook（prerouting）・hook 属性なしの base chain は転送経路の policy として返さない。
        for hook in [Some(0), None] {
            assert!(
                matches!(
                    st(Mock(Ok(reply_with_hook(Some(0), hook)))),
                    ForwardPolicyState::Unknown { .. }
                ),
                "hook={hook:?}"
            );
        }
        assert_eq!(
            st(Mock(Err(NetErrorCode::PermissionDenied))),
            ForwardPolicyState::PermissionDenied
        );
        // nftables に無く、procfs と確認できない root の ip_tables_names 不在は判定不能（None）。
        assert_eq!(
            st(Mock(Err(NetErrorCode::NotFound))),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: None
            }
        );
        // procfs 上と確認できれば ip_tables_names 不在は「filter なし」（Some(false)）。
        let procfs = procfs_root();
        assert_eq!(
            probe_forward_policy(&Mock(Err(NetErrorCode::NotFound)), &procfs.0),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: Some(false)
            }
        );
        assert_eq!(
            st(Mock(Err(NetErrorCode::Timeout))),
            ForwardPolicyState::Unknown {
                reason: DoctorProbeError {
                    code: "TIMEOUT".to_string(),
                    message: "mock".to_string()
                }
            }
        );
    }

    /// NET-10: 読み取り上限を超える ip_tables_names は「filter なし」と断定せず None（判定不能）。
    #[test]
    fn net10_legacy_filter_oversized_is_unknown() {
        let root = TempRoot::new();
        // filter 行は上限より後ろにある。
        let mut text = "nat\n".repeat(MAX_PROC_READ as usize / 4 + 1);
        text.push_str("filter\n");
        root.write(IP_TABLES_NAMES, &text);
        assert_eq!(has_legacy_filter(&root.0), None);
        let r = read_limited(&root.0.join(IP_TABLES_NAMES), MAX_PROC_READ).unwrap_err();
        assert_eq!(r.kind(), ErrorKind::InvalidData);
        // ちょうど上限の内容は読み切れるので判定できる（filter 行なし）。
        let exact = TempRoot::new();
        exact.write(IP_TABLES_NAMES, &"n".repeat(MAX_PROC_READ as usize));
        assert_eq!(has_legacy_filter(&exact.0), Some(false));
    }

    /// NET-10: legacy iptables の filter テーブルの有無が補助情報に反映される。
    #[test]
    fn net10_legacy_filter_detection() {
        let with = TempRoot::new();
        with.write(IP_TABLES_NAMES, "nat\nfilter\n");
        let without = TempRoot::new();
        without.write(IP_TABLES_NAMES, "nat\n");
        let nf = Mock(Err(NetErrorCode::NotFound));
        assert_eq!(
            probe_forward_policy(&nf, &with.0),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: Some(true)
            }
        );
        assert_eq!(
            probe_forward_policy(&nf, &without.0),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: Some(false)
            }
        );
        // ファイル不在でも、`/proc/net` を含むマウントが procfs でなければ不存在と断定せず None。
        let plain = TempRoot::new();
        std::fs::create_dir_all(plain.0.join(PROC_NET)).expect("mkdir");
        plain.write(PROC_SELF_MOUNTINFO, "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n");
        assert_eq!(
            probe_forward_policy(&nf, &plain.0),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: None
            }
        );
        // 読み取り失敗（ここでは filter がディレクトリ）は不存在と区別して None。
        let unreadable = TempRoot::new();
        unreadable.write(&format!("{IP_TABLES_NAMES}/x"), "");
        assert_eq!(
            probe_forward_policy(&nf, &unreadable.0),
            ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: None
            }
        );
    }

    /// NET-10: collect は 2 つの probe の結果をそのまま保持する。
    #[test]
    fn net10_collect_keeps_both_results() {
        let t = TempRoot::new();
        t.write(BR_NF_CALL_IPTABLES, "1\n");
        let probe = BrNetfilterProbe::with_root(t.0.clone());
        let f = collect(&probe, &Mock(Ok(reply(Some(0)))));
        assert_eq!(
            f,
            DoctorFindings {
                br_netfilter: BrNetfilterState::Loaded {
                    call_iptables: Some(true)
                },
                forward_policy: ForwardPolicyState::Policy(ChainPolicy::Drop),
            }
        );
    }
}

/// Linux 以外では probe が Unsupported を返す（CLI-1: OS 固有処理の局所化）。
#[cfg(all(test, not(target_os = "linux")))]
mod tests_off_linux {
    use super::*;

    /// NET-10: Linux 以外は Unsupported。
    #[test]
    fn net10_br_netfilter_unsupported_off_linux() {
        assert_eq!(
            BrNetfilterProbe::new().probe(),
            BrNetfilterState::Unsupported
        );
    }

    /// NET-10・TASK-148.2: 実 probe の Unsupported は対象外・終了コード 0。
    #[test]
    fn net10_evaluate_unsupported_off_linux() {
        let findings = DoctorFindings {
            br_netfilter: BrNetfilterState::Unsupported,
            forward_policy: ForwardPolicyState::Unsupported,
        };
        let r = evaluate(&findings);
        assert_eq!(r.outcome, DoctorOutcome::NotApplicable);
        assert_eq!(r.exit_status().code(), 0);
    }
}
