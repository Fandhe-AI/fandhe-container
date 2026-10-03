//! `doctor`: Docker 併存時のネットワーク到達性リスクの判定材料を集める読み取り専用の診断
//! （TASK-148.1・NET-10・MS-8・根拠 PoC-15 の発見事項 1）。
//!
//! Docker と同一ホストで自前ネットワーク（NET-1）を併存させると、`br_netfilter` がロードされ、
//! かつ Docker が iptables の `FORWARD` チェインを `policy drop` にしている環境では、bridge 経由の
//! 転送が Docker のチェインで落とされ外部到達性が損なわれる可能性がある。本モジュールは次の 2 つの
//! 事実を取得するだけで、2 条件の組み合わせ判定・警告文・DOCKER-USER 案内・終了コード・サブコマンド配線は
//! 後続の TASK-148.2（#344）と TASK-79 の範囲である（[`DoctorFindings`] を渡す）。
//!
//! # 確認方法
//!
//! - `br_netfilter`: `/proc/sys/net/bridge/bridge-nf-call-iptables` の存在で判定する。このディレクトリは
//!   `br_netfilter` の初期化時に作られるため、モジュール版と組み込み版の両方で使える。
//!   `/sys/module/br_netfilter` は組み込み版では当てにならないため判定には使わない。ファイルの値
//!   （`0` / `1`）は bridge 通過パケットを iptables に渡すかどうかとして併せて返す。
//! - `FORWARD` チェインの policy: nf_tables に対する `NFT_MSG_GETCHAIN` の読み取り照会
//!   （`ip filter FORWARD`）。外部コマンド（`iptables` / `nft`）は起動しない（NET-11・フルスクラッチ方針）。
//!   nfnetlink は `CAP_NET_ADMIN` を要するため、非特権では [`ForwardPolicyState::PermissionDenied`] になる。
//!
//! # 判定不能の扱い（fail-closed）
//!
//! 「accept」と「答えが出なかった」を取り違えないよう、取得できなかった場合は独立した値で返す。
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
use fandhe_container_net::nftables_batch::{ChainInfo, ChainPolicy};

/// sysctl・`/proc` の読み取り上限（バイト）。想定値は 1 文字なので小さく抑える。
const MAX_PROC_READ: u64 = 4096;

/// `/proc` 配下で br_netfilter の有無を示すパス（root からの相対）。
const BR_NF_CALL_IPTABLES: &str = "proc/sys/net/bridge/bridge-nf-call-iptables";

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
        match read_limited(&self.root.join(BR_NF_CALL_IPTABLES)) {
            Ok(text) => BrNetfilterState::Loaded {
                call_iptables: match text.trim() {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                },
            },
            Err(e) if e.kind() == ErrorKind::NotFound => BrNetfilterState::NotLoaded,
            Err(e) => BrNetfilterState::Unknown {
                reason: DoctorProbeError::from_io(&e),
            },
        }
    }
}

/// 先頭 [`MAX_PROC_READ`] バイトだけを文字列として読む（無制限読み取りを避ける）。
fn read_limited(path: &Path) -> std::io::Result<String> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(MAX_PROC_READ)
        .read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Docker の `FORWARD` チェイン policy の取得結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardPolicyState {
    /// base chain の policy を取得できた。
    Policy(ChainPolicy),
    /// チェインはあるが policy 属性を持たない（base chain でない）。
    NotBaseChain,
    /// nftables に `ip filter FORWARD` が無い。iptables-legacy 環境では正常で、`legacy_iptables_filter` は
    /// `/proc/net/ip_tables_names` に `filter` があるか（policy 自体は未取得。モジュール doc の未実装範囲）。
    NotFoundInNftables {
        /// legacy iptables の filter テーブルが存在するか。`None` は権限不足等で読み取れず判定不能
        /// （不存在の `Some(false)` と区別する。fail-closed）。ファイル自体が無い場合は `Some(false)`。
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
            Some(p) => ForwardPolicyState::Policy(p),
            None => ForwardPolicyState::NotBaseChain,
        },
        Err(e) => match e.code() {
            NetErrorCode::NotFound => ForwardPolicyState::NotFoundInNftables {
                legacy_iptables_filter: has_legacy_filter(root),
            },
            NetErrorCode::PermissionDenied => ForwardPolicyState::PermissionDenied,
            NetErrorCode::Unimplemented => ForwardPolicyState::Unsupported,
            _ => ForwardPolicyState::Unknown {
                reason: DoctorProbeError::from_net(&e),
            },
        },
    }
}

/// `/proc/net/ip_tables_names` に `filter` 行があるか。ファイル不在（ip_tables 未ロード）は `Some(false)`、
/// 権限不足などその他の読み取り失敗は不存在と断定できないため `None`（判定不能）。
fn has_legacy_filter(root: &Path) -> Option<bool> {
    match read_limited(&root.join(IP_TABLES_NAMES)) {
        Ok(t) => Some(t.lines().any(|l| l.trim() == "filter")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

/// 2 つの probe の結果。組み合わせ判定・表示は TASK-148.2（#344）が担う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFindings {
    /// `br_netfilter` のロード状態。
    pub br_netfilter: BrNetfilterState,
    /// Docker の `FORWARD` チェイン policy。
    pub forward_policy: ForwardPolicyState,
}

/// 2 つの probe を実行して結果をそのまま保持する。
pub fn collect(probe: &BrNetfilterProbe, source: &dyn ForwardPolicySource) -> DoctorFindings {
    DoctorFindings {
        br_netfilter: probe.probe(),
        forward_policy: probe_forward_policy(source, &probe.root),
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
        let mut p = vec![2u8, 0, 0, 0];
        if let Some(v) = policy {
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&5u16.to_ne_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        p
    }

    fn br(value: Option<&str>) -> BrNetfilterState {
        let t = TempRoot::new();
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

    /// NET-10: policy の取得結果が各状態に対応する。
    #[test]
    fn net10_forward_policy_states() {
        let t = TempRoot::new();
        let st = |m: Mock| probe_forward_policy(&m, &t.0);
        assert_eq!(
            st(Mock(Ok(reply(Some(0))))),
            ForwardPolicyState::Policy(ChainPolicy::Drop)
        );
        assert_eq!(
            st(Mock(Ok(reply(Some(1))))),
            ForwardPolicyState::Policy(ChainPolicy::Accept)
        );
        assert_eq!(st(Mock(Ok(reply(None)))), ForwardPolicyState::NotBaseChain);
        assert_eq!(
            st(Mock(Err(NetErrorCode::PermissionDenied))),
            ForwardPolicyState::PermissionDenied
        );
        assert_eq!(
            st(Mock(Err(NetErrorCode::NotFound))),
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
}
