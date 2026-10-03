//! `--add-host` / `--dns` の利用者入力（hostname・IP）を副作用の前に検証する純粋関数群
//! （NET-12・TASK-185.1・#335・ERR-1・MS-8）。
//!
//! CLI / stack が `--add-host` / `--dns` を受け取った直後に呼ばれ、`/etc/hosts` 追記・`resolv.conf`
//! 書き換え・DNS ヘルパー設定変更の前に不正値をコンテナ作成前に拒否する。後続の `/etc/hosts` 追記
//! （TASK-185.2・#345）・上流転送（TASK-185.3・#346）・host/none の `--dns` 反映（TASK-185.4・#347）・
//! 軽量運用の `--dns` 直接書き込み（TASK-146.2・#336）から再利用される。
//!
//! 本モジュール本体は検証のみ。host/none の `--dns` 反映と none の loopback 制限は子モジュール
//! `resolv_conf`（TASK-185.4・#347）。`<hostname>:<ip>` の分割パース・`/etc/hosts` 追記・上流転送は
//! 未実装（TASK-185.2・185.3。REPAIR-3）。エラーの `message` は固定の英語文字列で、
//! 入力値を載せない（ログ・ファイルへの行注入を防ぐ）。`dns_helper::DnsName`（小文字化・末尾ドット除去）
//! とは意味論が異なり、ここでは入力をそのまま保持し、末尾ドット（空ラベル）は拒否する。

pub mod resolv_conf;

use std::net::IpAddr;

use crate::error::{NetError, NetErrorCode};

/// hostname 全体の最大バイト長（RFC 1123）。
const MAX_HOSTNAME_LEN: usize = 253;
/// ラベルの最大バイト長（RFC 1123）。
const MAX_LABEL_LEN: usize = 63;

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
}
