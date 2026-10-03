//! `--add-host` / `--dns` の利用者入力（hostname・IP）を副作用の前に検証する純粋関数群
//! （NET-12・TASK-185.1・#335・ERR-1・MS-8）。
//!
//! CLI / stack が `--add-host` / `--dns` を受け取った直後に呼ばれ、`/etc/hosts` 追記・`resolv.conf`
//! 書き換え・DNS ヘルパー設定変更の前に不正値をコンテナ作成前に拒否する。後続の `/etc/hosts` 追記
//! （TASK-185.2・#345）・上流転送（TASK-185.3・#346）・host/none の `--dns` 反映（TASK-185.4・#347）・
//! 軽量運用の `--dns` 直接書き込み（TASK-146.2・#336）から再利用される。
//!
//! `--add-host <hostname>:<ip>` は最初の `:` で 2 分割する（[`AddHostEntry::parse`]。残り全体を IP とするため
//! `::1` 等の IPv6 表記をそのまま渡せる）。検証済みエントリはコンテナの hosts ファイルへ追記できる
//! （[`apply_add_hosts`]。TASK-185.2・#345）。追記先は「管理ルート（コンテナ状態ディレクトリ）」と
//! そこからの相対パスで指定し、ルート配下の既存の通常ファイルに限る（`/etc/hosts` のような管理外の
//! ファイルは絶対パス・`..`・symlink・管理ルート内の bind mount 経由のいずれでも指せない）。
//! ネットワークモード（bridge / host / none）を引数に取らないため全モードで同じ処理になる。hosts ファイルの
//! 生成・コンテナへの bind mount は runtime / core 側の責務で、本モジュールは既存の通常ファイルへ追記するだけ
//! （無ければ作らず `NOT_FOUND`）。
//! 追記は Linux 限定（子モジュール `hosts_file`。他 OS は `UNIMPLEMENTED`）。管理ルートから
//! `openat(O_NOFOLLOW)` で 1 要素ずつ辿って開いた fd だけを検証・追記に使い（パスを再解決しない）、
//! symlink（途中ディレクトリを含む）・ハードリンク（nlink != 1）・他ユーザー所有・管理ルートと別のマウント上の
//! ファイル（fd の `mnt_id` で照合）を拒否する。書き込み失敗時は同じロック下で書き込み前の長さへ戻し、
//! 巻き戻しにも失敗した場合は不完全な行が残りうるため `DATA_LOSS` で通常の失敗と区別して返す。
//!
//! host/none の `--dns` 反映と none の loopback 制限は子モジュール `resolv_conf`（TASK-185.4・#347）。
//! 上流転送（TASK-185.3）は未実装（REPAIR-3）。エラーの `message` は固定の英語文字列で、
//! 入力値を載せない（ログ・ファイルへの行注入を防ぐ）。`dns_helper::DnsName`（小文字化・末尾ドット除去）
//! とは意味論が異なり、ここでは入力をそのまま保持し、末尾ドット（空ラベル）は拒否する。

#[cfg(target_os = "linux")]
mod hosts_file;
pub mod resolv_conf;

use std::net::IpAddr;
use std::path::Path;

use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};

/// hostname 全体の最大バイト長（RFC 1123）。
const MAX_HOSTNAME_LEN: usize = 253;
/// ラベルの最大バイト長（RFC 1123）。
const MAX_LABEL_LEN: usize = 63;
/// IPv6 の最長テキスト表記（IPv4 射影を含む）のバイト長。
const MAX_IP_TEXT_LEN: usize = 45;
/// `--add-host` 1 件の最大バイト長（hostname + `:` + IP）。分割前に検査する。
const MAX_ADD_HOST_LEN: usize = MAX_HOSTNAME_LEN + 1 + MAX_IP_TEXT_LEN;
/// `--add-host` の最大件数。spec（NET-12）に件数規定は無く、無制限確保を避けるための実装上限。
pub const MAX_ADD_HOST_ENTRIES: usize = 256;

/// 入力検証の違反理由（機械可読）。`NetError`（`INVALID_ARGUMENT`）へ変換できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InputViolation {
    /// 改行・制御文字・空白を含む（hostname・IP 共通）。
    ControlOrWhitespace,
    /// hostname が空。
    EmptyHostname,
    /// hostname の総長が 253 バイトを超える。
    HostnameTooLong,
    /// ラベル長が 0（空ラベル・末尾ドット）または 63 を超える。
    LabelLength,
    /// ラベルの先頭または末尾がハイフン。
    LabelHyphenEdge,
    /// ASCII 英数字・ハイフン・区切りの `.` 以外の文字を含む。
    InvalidHostnameChar,
    /// IPv4 / IPv6 のいずれとしても解釈できない。
    NotIpAddress,
    /// `--add-host` の値に `<hostname>:<ip>` の区切り `:` が無い。
    MissingHostIpSeparator,
    /// `--add-host` の 1 件が長すぎる（hostname + `:` + IP の上限超過）。
    AddHostTooLong,
    /// `--add-host` の件数が上限（[`MAX_ADD_HOST_ENTRIES`]）を超える。
    TooManyAddHosts,
    /// none モードで loopback 以外の `--dns` を指定した。
    NotLoopbackForNoneMode,
}

impl InputViolation {
    /// 違反理由の機械可読な識別子。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControlOrWhitespace => "CONTROL_OR_WHITESPACE",
            Self::EmptyHostname => "EMPTY_HOSTNAME",
            Self::HostnameTooLong => "HOSTNAME_TOO_LONG",
            Self::LabelLength => "LABEL_LENGTH",
            Self::LabelHyphenEdge => "LABEL_HYPHEN_EDGE",
            Self::InvalidHostnameChar => "INVALID_HOSTNAME_CHAR",
            Self::NotIpAddress => "NOT_IP_ADDRESS",
            Self::MissingHostIpSeparator => "MISSING_SEPARATOR",
            Self::AddHostTooLong => "ADD_HOST_TOO_LONG",
            Self::TooManyAddHosts => "TOO_MANY_ADD_HOSTS",
            Self::NotLoopbackForNoneMode => "NOT_LOOPBACK_FOR_NONE_MODE",
        }
    }

    /// 固定の英語メッセージ（入力値を含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::ControlOrWhitespace => "invalid input: contains control character or whitespace",
            Self::EmptyHostname => "invalid hostname: empty",
            Self::HostnameTooLong => "invalid hostname: exceeds 253 characters",
            Self::LabelLength => "invalid hostname: label must be 1 to 63 characters",
            Self::LabelHyphenEdge => "invalid hostname: label must not start or end with hyphen",
            Self::InvalidHostnameChar => {
                "invalid hostname: only ASCII letters, digits, hyphens and dots are allowed"
            }
            Self::NotIpAddress => "invalid IP address: not a valid IPv4 or IPv6 address",
            Self::MissingHostIpSeparator => "invalid add-host: expected <hostname>:<ip>",
            Self::AddHostTooLong => "invalid add-host: entry is too long",
            Self::TooManyAddHosts => "invalid add-host: too many entries",
            Self::NotLoopbackForNoneMode => {
                "invalid --dns for none network mode: only loopback addresses (127.0.0.0/8, ::1) are allowed"
            }
        }
    }
}

impl From<InputViolation> for NetError {
    fn from(v: InputViolation) -> Self {
        NetError::new(NetErrorCode::InvalidArgument, v.message())
    }
}

/// 改行・制御文字・空白を含むか（`trim` による暗黙補正はしない）。
fn has_control_or_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// RFC 1123 で検証済みのホスト名（`--add-host` の hostname 部）。
///
/// 入力をそのまま保持する（小文字化・末尾ドット除去はしない）。全数字のラベルは RFC 1123 上有効のため
/// `"123"` のような値も受理する。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostName(String);

impl HostName {
    /// hostname を検証して返す。総長 1〜253、各ラベル 1〜63 文字の ASCII 英数字・ハイフン
    /// （先頭・末尾ハイフン不可）。違反は `INVALID_ARGUMENT` の `NetError`（NET-12）。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        Self::validate(s)?;
        Ok(Self(s.to_owned()))
    }

    fn validate(s: &str) -> Result<(), InputViolation> {
        if has_control_or_whitespace(s) {
            return Err(InputViolation::ControlOrWhitespace);
        }
        if s.is_empty() {
            return Err(InputViolation::EmptyHostname);
        }
        if s.len() > MAX_HOSTNAME_LEN {
            return Err(InputViolation::HostnameTooLong);
        }
        for label in s.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(InputViolation::LabelLength);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(InputViolation::InvalidHostnameChar);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(InputViolation::LabelHyphenEdge);
            }
        }
        Ok(())
    }

    /// 検証済み hostname を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `--add-host` の IP 部・`--dns` の値を IPv4 / IPv6 として検証する（NET-12）。
///
/// std のパーサに従い fail-closed: 先頭ゼロのオクテット（`010.0.0.1`）・ゾーン ID（`fe80::1%eth0`）・
/// 角括弧（`[::1]`）・CIDR（`1.2.3.4/24`）は拒否し、IPv4 射影（`::ffff:192.0.2.1`）は受理する。
/// アドレス種別（loopback 等）の制限は行わない（none モードの loopback 制限は `resolv_conf` が行う。TASK-185.4）。
pub fn parse_ip_addr(s: &str) -> Result<IpAddr, NetError> {
    if has_control_or_whitespace(s) {
        return Err(InputViolation::ControlOrWhitespace.into());
    }
    s.parse::<IpAddr>()
        .map_err(|_| InputViolation::NotIpAddress.into())
}

/// 検証済みの `--add-host` 1 件（hostname と IP）。不正値を表現できない型で、hosts ファイルへ書く行は
/// この型からのみ描画する（行注入を型で防ぐ。NET-12）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddHostEntry {
    host: HostName,
    ip: IpAddr,
}

impl AddHostEntry {
    /// `<hostname>:<ip>` を最初の `:` で 2 分割して検証する。左が hostname、残り全体が IP
    /// （hostname は `:` を含まないため `host:::1` は (`host`, `::1`)）。違反は `INVALID_ARGUMENT`（NET-12）。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        if s.len() > MAX_ADD_HOST_LEN {
            return Err(InputViolation::AddHostTooLong.into());
        }
        let (host, ip) = s
            .split_once(':')
            .ok_or(InputViolation::MissingHostIpSeparator)?;
        Ok(Self {
            host: HostName::parse(host)?,
            ip: parse_ip_addr(ip)?,
        })
    }

    /// 検証済み hostname。
    pub fn host(&self) -> &HostName {
        &self.host
    }

    /// 検証済み IP。
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// 複数の `--add-host` 値を全件検証して返す。1 件でも不正、または件数が上限超過なら `Err`（副作用なし）。
pub fn parse_add_hosts<'a, I>(raw: I) -> Result<Vec<AddHostEntry>, NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for s in raw {
        if out.len() >= MAX_ADD_HOST_ENTRIES {
            return Err(InputViolation::TooManyAddHosts.into());
        }
        out.push(AddHostEntry::parse(s)?);
    }
    Ok(out)
}

/// hosts ファイル形式の行（`<ip>\t<hostname>\n`）へ描画する。IP は `IpAddr` の正規化表記になる。
pub fn render_hosts_lines(entries: &[AddHostEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!("{}\t{}\n", e.ip, e.host.as_str()));
    }
    out
}

/// 検証済みエントリをコンテナの hosts ファイルへ追記する（NET-12・TASK-185.2）。
///
/// `managed_root` は管理ルート（コンテナ状態ディレクトリ）で、symlink を含まない絶対パスで渡す（正規化せず、
/// 管理ルート自身・祖先が symlink なら `FAILED_PRECONDITION`）。`hosts_rel` はその配下の hosts ファイルへの
/// 相対パスで、ネットワークモードに依存しない。ルート外（絶対パス・`..`・symlink・管理ルート内の
/// bind mount 経由）は指せない。既存の通常ファイルにのみ追記し（無ければ `NOT_FOUND` で作成しない）、
/// tmp + rename は使わない（bind mount 済みファイルの inode を保つため）。境界の守り方・ロック・巻き戻しは
/// Linux 限定の `hosts_file` モジュールに置く。`entries` が空なら何も開かない。
///
/// 呼び出し側の前提:
/// - `hosts_rel` の途中ディレクトリと hosts ファイルは、コンテナ・他ユーザーが書き込めないディレクトリ
///   配下に置くこと（書き込めると symlink 以外の手段で中身を入れ替えられ、本関数の検査の前提が崩れる）。
///
/// Linux 以外では `UNIMPLEMENTED` を返す（fail-closed）。symlink を辿らない `openat` と fd の `mnt_id`
/// 照合を持たない OS でパス検査だけの追記をすると、検査と open の間の差し替えで管理外のファイルへ
/// 書けてしまうため。macOS / Windows のコンテナは Linux VM 側で hosts を扱う。
pub fn append_add_hosts(
    managed_root: &Path,
    hosts_rel: &Path,
    entries: &[AddHostEntry],
) -> Result<(), NetError> {
    if entries.is_empty() {
        return Ok(());
    }
    // 公開 API 単体でも件数を上限検証する（parse_add_hosts を経由しない呼び出しでの無制限確保を防ぐ）。
    if entries.len() > MAX_ADD_HOST_ENTRIES {
        return Err(InputViolation::TooManyAddHosts.into());
    }
    #[cfg(target_os = "linux")]
    {
        hosts_file::append_lines(managed_root, hosts_rel, &render_hosts_lines(entries))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (managed_root, hosts_rel);
        Err(NetError::new(
            NetErrorCode::Unimplemented,
            "appending to hosts file is only supported on Linux",
        ))
    }
}

/// `--add-host` の生値を全件検証してから hosts ファイルへ追記する入口（NET-12・TASK-185.2）。
///
/// 検証が全件通るまでファイルを開かないため、検証失敗時に hosts ファイルは変更されない。
/// 計測しない呼び出し口で、成否・所要時間を記録するには [`apply_add_hosts_with_recorder`] を使う。
pub fn apply_add_hosts<'a, I>(managed_root: &Path, hosts_rel: &Path, raw: I) -> Result<(), NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    apply_add_hosts_with_recorder(managed_root, hosts_rel, raw, &NoopNetOpRecorder)
}

/// [`apply_add_hosts`] に計装を付けた入口（REPAIR-4）。検証から追記・fsync までの成否と所要時間を
/// `NetOpKind::AddHostsApply` として `recorder` へ渡す（入力値・パスは記録しない）。
pub fn apply_add_hosts_with_recorder<'a, I>(
    managed_root: &Path,
    hosts_rel: &Path,
    raw: I,
    recorder: &dyn NetOpRecorder,
) -> Result<(), NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    record_net_op(recorder, NetOpKind::AddHostsApply, || {
        let entries = parse_add_hosts(raw)?;
        append_add_hosts(managed_root, hosts_rel, &entries)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_err(s: &str) -> NetError {
        HostName::parse(s).expect_err(s)
    }

    fn assert_violation(e: &NetError, v: InputViolation) {
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), v.message());
    }

    /// NET-12: 正常な hostname は入力のまま受理する。
    #[test]
    fn accepts_valid_hostnames() {
        for s in [
            "localhost",
            "my-host",
            "a.example.com",
            "Web01.Example",
            "123",
        ] {
            assert_eq!(HostName::parse(s).unwrap().as_str(), s);
        }
    }

    /// NET-12・R1: 空 hostname。
    #[test]
    fn rejects_empty_hostname() {
        assert_violation(&host_err(""), InputViolation::EmptyHostname);
    }

    /// NET-12・R2: ラベル長・総長の境界値。
    #[test]
    fn label_and_total_length_boundaries() {
        assert!(HostName::parse(&"a".repeat(63)).is_ok());
        assert_violation(&host_err(&"a".repeat(64)), InputViolation::LabelLength);

        let total253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(total253.len(), 253);
        assert!(HostName::parse(&total253).is_ok());
        let total254 = format!("{total253}d");
        assert_eq!(total254.len(), 254);
        assert_violation(&host_err(&total254), InputViolation::HostnameTooLong);
    }

    /// NET-12・R2: ハイフン端・空ラベル・文字種。
    #[test]
    fn rejects_bad_labels() {
        for s in ["-a.b", "a-.b", "a.-b"] {
            assert_violation(&host_err(s), InputViolation::LabelHyphenEdge);
        }
        for s in ["a..b", "a.", ".a"] {
            assert_violation(&host_err(s), InputViolation::LabelLength);
        }
        for s in ["a_b", "例え.jp"] {
            assert_violation(&host_err(s), InputViolation::InvalidHostnameChar);
        }
    }

    /// NET-12・R3: IP の受理（値も照合）。
    #[test]
    fn accepts_ip_addresses() {
        assert_eq!(parse_ip_addr("192.0.2.1").unwrap().to_string(), "192.0.2.1");
        assert_eq!(parse_ip_addr("::1").unwrap().to_string(), "::1");
        assert_eq!(
            parse_ip_addr("2001:db8::1").unwrap().to_string(),
            "2001:db8::1"
        );
        assert!(parse_ip_addr("::ffff:192.0.2.1").unwrap().is_ipv6());
    }

    /// NET-12・R3: IPv4 / IPv6 として解釈できない値。
    #[test]
    fn rejects_non_ip() {
        for s in [
            "",
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4/24",
            "[::1]",
            "fe80::1%eth0",
            "010.0.0.1",
            "example.com",
        ] {
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::NotIpAddress);
        }
    }

    /// NET-12・R4: 制御文字・空白は hostname・IP の両方で最優先で拒否する。
    #[test]
    fn rejects_control_and_whitespace() {
        let bad = [
            "a\nb",
            "a\rb",
            "a\tb",
            "a\0b",
            "a\x7fb",
            "a\u{85}b",
            "a\u{a0}b",
            "a\u{3000}b",
            " a",
            "a ",
            "my host",
        ];
        for s in bad {
            assert_violation(&host_err(s), InputViolation::ControlOrWhitespace);
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::ControlOrWhitespace);
        }
        for s in [" 192.0.2.1", "192.0.2.1 ", "192.0.2.1\n"] {
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::ControlOrWhitespace);
        }
        assert_violation(
            &host_err("a\n1.2.3.4 evil"),
            InputViolation::ControlOrWhitespace,
        );
    }

    /// NET-12・R5・ERR-1: 理由の識別子・メッセージ・NetError 変換の具体値。
    #[test]
    fn violation_strings_and_net_error() {
        let table = [
            (InputViolation::ControlOrWhitespace, "CONTROL_OR_WHITESPACE"),
            (InputViolation::EmptyHostname, "EMPTY_HOSTNAME"),
            (InputViolation::HostnameTooLong, "HOSTNAME_TOO_LONG"),
            (InputViolation::LabelLength, "LABEL_LENGTH"),
            (InputViolation::LabelHyphenEdge, "LABEL_HYPHEN_EDGE"),
            (InputViolation::InvalidHostnameChar, "INVALID_HOSTNAME_CHAR"),
            (InputViolation::NotIpAddress, "NOT_IP_ADDRESS"),
            (InputViolation::MissingHostIpSeparator, "MISSING_SEPARATOR"),
            (InputViolation::AddHostTooLong, "ADD_HOST_TOO_LONG"),
            (InputViolation::TooManyAddHosts, "TOO_MANY_ADD_HOSTS"),
            (
                InputViolation::NotLoopbackForNoneMode,
                "NOT_LOOPBACK_FOR_NONE_MODE",
            ),
        ];
        for (v, s) in table {
            assert_eq!(v.as_str(), s);
        }
        let e: NetError = InputViolation::EmptyHostname.into();
        assert_eq!(e.code().as_str(), "INVALID_ARGUMENT");
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: invalid hostname: empty");
    }

    /// NET-12: エラーメッセージに入力値を載せない（ログ注入防止）。
    #[test]
    fn message_does_not_echo_input() {
        let e = host_err("evil\ninjected");
        assert!(!e.message().contains("evil"));
        let e = parse_ip_addr("evil\ninjected").unwrap_err();
        assert!(!e.message().contains("evil"));
    }

    fn entry_err(s: &str) -> NetError {
        AddHostEntry::parse(s).expect_err(s)
    }

    /// NET-12: 最初の `:` で分割し、残り全体を IP とする（IPv6 を含む）。
    #[test]
    fn add_host_splits_on_first_colon() {
        for (raw, host, ip) in [
            ("host:192.0.2.1", "host", "192.0.2.1"),
            ("host:::1", "host", "::1"),
            ("host:2001:db8::1", "host", "2001:db8::1"),
            (
                "a.example:::ffff:192.0.2.1",
                "a.example",
                "::ffff:192.0.2.1",
            ),
        ] {
            let e = AddHostEntry::parse(raw).unwrap();
            assert_eq!(e.host().as_str(), host);
            assert_eq!(e.ip().to_string(), ip);
        }
    }

    /// NET-12・ERR-1: 分割・検証の拒否（INVALID_ARGUMENT と理由を具体値で照合）。
    #[test]
    fn add_host_rejects_bad_entries() {
        for (raw, v) in [
            ("host:", InputViolation::NotIpAddress),
            (":1.2.3.4", InputViolation::EmptyHostname),
            ("host", InputViolation::MissingHostIpSeparator),
            ("", InputViolation::MissingHostIpSeparator),
            ("host:fe80::1%eth0", InputViolation::NotIpAddress),
            ("host:[::1]", InputViolation::NotIpAddress),
            ("host:host-gateway", InputViolation::NotIpAddress),
            ("bad host:1.2.3.4", InputViolation::ControlOrWhitespace),
            (
                "a\n1.2.3.4 evil:1.2.3.4",
                InputViolation::ControlOrWhitespace,
            ),
            ("host:1.2.3.4\n", InputViolation::ControlOrWhitespace),
        ] {
            assert_violation(&entry_err(raw), v);
        }
        let long = format!("{}:1.2.3.4", "a".repeat(MAX_ADD_HOST_LEN));
        assert_violation(&entry_err(&long), InputViolation::AddHostTooLong);
    }

    /// NET-12: 複数件は順序どおり、1 件でも不正なら全体が Err、件数は上限ちょうどまで。
    #[test]
    fn parse_add_hosts_all_or_nothing_and_limit() {
        let v = parse_add_hosts(["web:192.0.2.1", "db:2001:db8::1"]).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].host().as_str(), "web");
        assert_eq!(v[1].ip().to_string(), "2001:db8::1");
        assert_violation(
            &parse_add_hosts(["web:192.0.2.1", "bad host:192.0.2.2"]).unwrap_err(),
            InputViolation::ControlOrWhitespace,
        );
        let ok = vec!["h:192.0.2.1"; MAX_ADD_HOST_ENTRIES];
        assert_eq!(parse_add_hosts(ok.iter().copied()).unwrap().len(), 256);
        let over = vec!["h:192.0.2.1"; MAX_ADD_HOST_ENTRIES + 1];
        assert_violation(
            &parse_add_hosts(over.iter().copied()).unwrap_err(),
            InputViolation::TooManyAddHosts,
        );
    }

    /// NET-12: hosts 行の描画（タブ区切り・IPv6 正規化表記）。
    #[test]
    fn render_lines_exact_bytes() {
        let v = parse_add_hosts(["web:192.0.2.1", "db:2001:DB8:0:0:0:0:0:1"]).unwrap();
        assert_eq!(render_hosts_lines(&v), "192.0.2.1\tweb\n2001:db8::1\tdb\n");
        assert_eq!(render_hosts_lines(&[]), "");
    }

    /// NET-12: append_add_hosts 単体でも件数上限を検証する（ファイルに触れる前に拒否するため、
    /// 管理ルートが存在しなくても `INVALID_ARGUMENT`）。
    #[test]
    fn append_rejects_too_many_entries() {
        let one = AddHostEntry::parse("h:192.0.2.1").unwrap();
        let entries = vec![one; MAX_ADD_HOST_ENTRIES + 1];
        let root = std::env::temp_dir().join("fc-addhost-nonexistent-root");
        let e = append_add_hosts(&root, Path::new("hosts"), &entries).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), "invalid add-host: too many entries");
    }

    /// NET-12・TASK-185.2: Linux 以外では追記せず `UNIMPLEMENTED`（fail-closed）。空エントリは何もせず成功。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn append_is_unimplemented_outside_linux() {
        let root = std::env::temp_dir().join(format!("fc-addhost-nl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let hosts = root.join("hosts");
        std::fs::write(&hosts, "orig\n").unwrap();
        let e = apply_add_hosts(&root, Path::new("hosts"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "appending to hosts file is only supported on Linux"
        );
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "orig\n");
        assert_eq!(
            apply_add_hosts(&root, Path::new("hosts"), std::iter::empty()),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
