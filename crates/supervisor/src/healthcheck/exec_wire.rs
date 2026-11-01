//! healthcheck の exec 専用 helper が supervisor へ返す結果行（`FCHX1`。SUP-4・SUP-6・REPAIR-2・#2441）。
//!
//! 役割: helper（`healthcheck::exec_helper`。`/proc/self/exe healthcheck-exec`）の fd 2 に書く 1 行の符号化と、
//! supervisor 側のアダプタ（`healthcheck::exec_probe`）による復号を 1 か所に置く。生の文字列を手で組まないよう、
//! 行は [`HealthExecLine`] 型からしか作れず、復号は許可リスト（固定語彙）でのみ受ける（untrusted な入力。
//! 未知の語・範囲外・矛盾は拒否し、`Healthy` へ倒さない = fail-closed）。
//!
//! # 形式（`\n` 終端・最大 [`LINE_MAX`] バイト・単一スペース区切り・語数ちょうど）
//!
//! | 形 | 意味 |
//! | --- | --- |
//! | `FCHX1 exited <0-255> <healthy\|unhealthy> <audit> <exit_audit>` | コマンドが起動し、終了コードで終わった |
//! | `FCHX1 signaled <1-64> unhealthy <audit> <exit_audit>` | コマンドが起動し、シグナルで終わった |
//! | `FCHX1 not_started <step\|-> <CODE> <0\|1> <audit>` | コマンドが起動していない（`SetupFailed`）。`<0\|1>` は分離違反か |
//! | `FCHX1 failed <CODE> <audit>` | exec の通しが拒否・失敗した（`Timeout` を含む） |
//! | `FCHX1 stale` | helper の前提検査の不一致（記録が Running でない・pid や所有者の不一致）。exec も監査もしていない |
//! | `FCHX1 invalid` | helper の引数の検証失敗 |
//!
//! `<audit>` / `<exit_audit>` は監査記録の結果（[`AuditToken`]）。`<CODE>` は ERR-1 の `ErrorCode::as_str`、
//! `<step>` は `ExecChildStep::as_str`。コマンドの出力・パス・errno の文字列は運ばない。

use fandhe_container_core::audit_log::AuditDelivery;
use fandhe_container_core::exec::ExecChildStep;
use fandhe_container_core::traits::ErrorCode;

/// 結果行の識別子（版つき）。
pub const WIRE_TAG: &str = "FCHX1";

/// exec 子 cgroup の作成通知行の識別子（`FCHC1 <exec 子 cgroup 名>\n`）。結果行（[`WIRE_TAG`]）とは別で、
/// helper が排他作成に成功した直後に fd 2 へ 1 回だけ書く。supervisor はこの通知を受けた cgroup だけを
/// 停止する（pid から名前を推定しない。SUP-4・SUP-6・REPAIR-5・#2441）。
pub const CGROUP_TAG: &str = "FCHC1";

/// 作成通知行を組む（`FCHC1 <name>\n`。名前は検証済みの [`ExecCgroupName`]）。
pub fn encode_cgroup_created(name: &fandhe_container_core::exec::ExecCgroupName) -> Vec<u8> {
    format!("{CGROUP_TAG} {}\n", name.as_str()).into_bytes()
}

/// 結果行の最大バイト数（改行を含まない）。
pub const LINE_MAX: usize = 256;

/// 監査記録の結果の写像（`AuditDelivery` は non_exhaustive のため、未知の値は [`Self::Unknown`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditToken {
    /// 記録の対象外（拒否ではない）。
    Na,
    /// sink が 1 件受理した。
    Recorded,
    /// sink が記録に失敗した。
    SinkFailed,
    /// レコードを組み立てられなかった。
    Unavailable,
    /// 上記以外（将来の variant）。
    Unknown,
}

impl AuditToken {
    /// `AuditDelivery` から写す。
    pub fn from_delivery(delivery: &AuditDelivery) -> Self {
        match delivery {
            AuditDelivery::NotApplicable => Self::Na,
            AuditDelivery::Recorded => Self::Recorded,
            AuditDelivery::SinkFailed(_) => Self::SinkFailed,
            AuditDelivery::RecordUnavailable(_) => Self::Unavailable,
            _ => Self::Unknown,
        }
    }

    /// ワイヤー上のトークン。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Na => "na",
            Self::Recorded => "recorded",
            Self::SinkFailed => "sink_failed",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        [
            Self::Na,
            Self::Recorded,
            Self::SinkFailed,
            Self::Unavailable,
            Self::Unknown,
        ]
        .into_iter()
        .find(|t| t.as_str() == token)
    }
}

/// helper が返す結果行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthExecLine {
    /// コマンドが起動し、終了コードで終わった。`healthy` は helper が `health_from_exec_exit` で判定した結果。
    Exited {
        /// 終了コード（0〜255）。
        code: u8,
        /// 0 のとき真。
        healthy: bool,
        /// `execve` 前の拒否の記録（コマンドが起動したので通常は `Na`）。
        audit: AuditToken,
        /// 補助の `exit_signal` 記録。
        exit_audit: AuditToken,
    },
    /// コマンドが起動し、シグナルで終わった（常に不健全）。
    Signaled {
        /// シグナル番号（1〜64）。
        signal: u8,
        /// `execve` 前の拒否の記録。
        audit: AuditToken,
        /// 補助の `exit_signal` 記録（SIGSYS のとき）。
        exit_audit: AuditToken,
    },
    /// コマンドが起動していない（`ExecExit::SetupFailed`）。
    NotStarted {
        /// 失敗した段（届かなければ `None`）。
        step: Option<ExecChildStep>,
        /// 失敗の分類。
        code: ErrorCode,
        /// 分離違反による拒否だったか。
        violation: bool,
        /// 違反の監査記録の結果。
        audit: AuditToken,
    },
    /// exec の通しが拒否・失敗した（`Timeout` を含む）。
    Failed {
        /// 失敗の分類。
        code: ErrorCode,
        /// 拒否の監査記録の結果。
        audit: AuditToken,
    },
    /// helper の前提検査の不一致（exec していない）。
    Stale,
    /// helper の引数の検証失敗。
    Invalid,
}

/// 復号の失敗（理由は固定語彙。入力の中身は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// 長さの上限超過・空・非 UTF-8・識別子違い。
    Malformed,
    /// 語数・語彙・値の範囲が許可リストに合わない。
    Rejected,
    /// 値同士が矛盾する（`exited 0 unhealthy` 等）。
    Contradiction,
}

impl HealthExecLine {
    /// 改行つきの 1 行に符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let body = match *self {
            Self::Exited {
                code,
                healthy,
                audit,
                exit_audit,
            } => format!(
                "{WIRE_TAG} exited {code} {} {} {}",
                if healthy { "healthy" } else { "unhealthy" },
                audit.as_str(),
                exit_audit.as_str()
            ),
            Self::Signaled {
                signal,
                audit,
                exit_audit,
            } => format!(
                "{WIRE_TAG} signaled {signal} unhealthy {} {}",
                audit.as_str(),
                exit_audit.as_str()
            ),
            Self::NotStarted {
                step,
                code,
                violation,
                audit,
            } => format!(
                "{WIRE_TAG} not_started {} {} {} {}",
                step.map_or("-", ExecChildStep::as_str),
                code.as_str(),
                u8::from(violation),
                audit.as_str()
            ),
            Self::Failed { code, audit } => {
                format!("{WIRE_TAG} failed {} {}", code.as_str(), audit.as_str())
            }
            Self::Stale => format!("{WIRE_TAG} stale"),
            Self::Invalid => format!("{WIRE_TAG} invalid"),
        };
        let mut bytes = body.into_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// 改行を除いた 1 行を復号する。許可リストに無い入力はすべて拒否する（fail-closed）。
    pub fn decode(line: &[u8]) -> Result<Self, WireError> {
        if line.is_empty() || line.len() > LINE_MAX {
            return Err(WireError::Malformed);
        }
        let text = std::str::from_utf8(line).map_err(|_| WireError::Malformed)?;
        let words: Vec<&str> = text.split(' ').collect();
        if words.first().copied() != Some(WIRE_TAG) {
            return Err(WireError::Malformed);
        }
        let audit_of = |w: Option<&&str>| {
            w.and_then(|t| AuditToken::parse(t))
                .ok_or(WireError::Rejected)
        };
        match words.as_slice() {
            [_, "exited", code, health, audit, exit_audit] => {
                let code: u8 = parse_decimal(code, 0, 255)?;
                let healthy = match *health {
                    "healthy" => true,
                    "unhealthy" => false,
                    _ => return Err(WireError::Rejected),
                };
                if healthy != (code == 0) {
                    return Err(WireError::Contradiction);
                }
                Ok(Self::Exited {
                    code,
                    healthy,
                    audit: audit_of(Some(audit))?,
                    exit_audit: audit_of(Some(exit_audit))?,
                })
            }
            [_, "signaled", signal, health, audit, exit_audit] => {
                let signal: u8 = parse_decimal(signal, 1, 64)?;
                if *health != "unhealthy" {
                    return Err(WireError::Contradiction);
                }
                Ok(Self::Signaled {
                    signal,
                    audit: audit_of(Some(audit))?,
                    exit_audit: audit_of(Some(exit_audit))?,
                })
            }
            [_, "not_started", step, code, violation, audit] => {
                let step = match *step {
                    "-" => None,
                    token => Some(ExecChildStep::from_token(token).ok_or(WireError::Rejected)?),
                };
                let violation = match *violation {
                    "0" => false,
                    "1" => true,
                    _ => return Err(WireError::Rejected),
                };
                Ok(Self::NotStarted {
                    step,
                    code: ErrorCode::from_name(code).ok_or(WireError::Rejected)?,
                    violation,
                    audit: audit_of(Some(audit))?,
                })
            }
            [_, "failed", code, audit] => Ok(Self::Failed {
                code: ErrorCode::from_name(code).ok_or(WireError::Rejected)?,
                audit: audit_of(Some(audit))?,
            }),
            [_, "stale"] => Ok(Self::Stale),
            [_, "invalid"] => Ok(Self::Invalid),
            _ => Err(WireError::Rejected),
        }
    }
}

/// 10 進の非負整数だけを受ける（符号・空白・先頭 0 の揺れ・範囲外は拒否）。
fn parse_decimal(text: &str, min: u8, max: u8) -> Result<u8, WireError> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(WireError::Rejected);
    }
    let value: u8 = text.parse().map_err(|_| WireError::Rejected)?;
    if value < min || value > max {
        return Err(WireError::Rejected);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(line: HealthExecLine) {
        let bytes = line.encode();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let body = bytes.get(..bytes.len() - 1).unwrap();
        assert!(body.len() <= LINE_MAX);
        assert_eq!(HealthExecLine::decode(body), Ok(line));
    }

    /// SUP-4・REPAIR-2（#2441）: 全形が往復する。
    #[test]
    fn sup4_2441_every_form_roundtrips() {
        roundtrip(HealthExecLine::Exited {
            code: 0,
            healthy: true,
            audit: AuditToken::Na,
            exit_audit: AuditToken::Na,
        });
        roundtrip(HealthExecLine::Exited {
            code: 3,
            healthy: false,
            audit: AuditToken::Na,
            exit_audit: AuditToken::Recorded,
        });
        roundtrip(HealthExecLine::Signaled {
            signal: 31,
            audit: AuditToken::Na,
            exit_audit: AuditToken::SinkFailed,
        });
        roundtrip(HealthExecLine::NotStarted {
            step: Some(ExecChildStep::OpenEntrypoint),
            code: ErrorCode::NotFound,
            violation: false,
            audit: AuditToken::Na,
        });
        roundtrip(HealthExecLine::NotStarted {
            step: None,
            code: ErrorCode::Internal,
            violation: true,
            audit: AuditToken::Recorded,
        });
        roundtrip(HealthExecLine::Failed {
            code: ErrorCode::Timeout,
            audit: AuditToken::Unavailable,
        });
        roundtrip(HealthExecLine::Stale);
        roundtrip(HealthExecLine::Invalid);
    }

    /// SUP-4・SUP-6（#2441）: 具体的な符号化結果を固定する。
    #[test]
    fn sup4_2441_concrete_encodings() {
        let line = HealthExecLine::Exited {
            code: 3,
            healthy: false,
            audit: AuditToken::Na,
            exit_audit: AuditToken::Na,
        };
        assert_eq!(line.encode(), b"FCHX1 exited 3 unhealthy na na\n".to_vec());
        assert_eq!(
            HealthExecLine::Failed {
                code: ErrorCode::Timeout,
                audit: AuditToken::Na
            }
            .encode(),
            b"FCHX1 failed TIMEOUT na\n".to_vec()
        );
    }

    /// REPAIR-2・SEC-1（#2441）: 長さ超過・未知の語・語数違い・範囲外・正規形でない数・矛盾はすべて拒否する。
    #[test]
    fn sup4_2441_rejects_malformed_and_contradictory_lines() {
        let reject = |text: &str, expected: WireError| {
            assert_eq!(
                HealthExecLine::decode(text.as_bytes()),
                Err(expected),
                "{text}"
            );
        };
        reject("", WireError::Malformed);
        reject("FCHX2 stale", WireError::Malformed);
        reject("garbage", WireError::Malformed);
        reject("FCHX1", WireError::Rejected);
        reject("FCHX1 stale extra", WireError::Rejected);
        reject("FCHX1  stale", WireError::Rejected);
        reject("FCHX1 exited 3 unhealthy na", WireError::Rejected);
        reject("FCHX1 exited 256 unhealthy na na", WireError::Rejected);
        reject("FCHX1 exited 03 unhealthy na na", WireError::Rejected);
        reject("FCHX1 exited +3 unhealthy na na", WireError::Rejected);
        reject("FCHX1 exited 3 broken na na", WireError::Rejected);
        reject("FCHX1 exited 0 unhealthy na na", WireError::Contradiction);
        reject("FCHX1 exited 3 healthy na na", WireError::Contradiction);
        reject("FCHX1 signaled 0 unhealthy na na", WireError::Rejected);
        reject("FCHX1 signaled 65 unhealthy na na", WireError::Rejected);
        reject("FCHX1 signaled 9 healthy na na", WireError::Contradiction);
        reject("FCHX1 exited 0 healthy na bogus", WireError::Rejected);
        reject("FCHX1 failed NOPE na", WireError::Rejected);
        reject(
            "FCHX1 not_started no_such_step INTERNAL 0 na",
            WireError::Rejected,
        );
        reject("FCHX1 not_started - INTERNAL 2 na", WireError::Rejected);
        let long = format!("FCHX1 stale{}", " ".repeat(LINE_MAX));
        reject(&long, WireError::Malformed);
        assert_eq!(
            HealthExecLine::decode(&[b'F', 0xff, 0xfe]),
            Err(WireError::Malformed)
        );
    }

    /// REPAIR-2（#2441）: 未知の `AuditDelivery` は `unknown` へ、既知は固定語彙へ写る。
    #[test]
    fn sup4_2441_audit_token_mapping() {
        assert_eq!(
            AuditToken::from_delivery(&AuditDelivery::NotApplicable),
            AuditToken::Na
        );
        assert_eq!(
            AuditToken::from_delivery(&AuditDelivery::Recorded),
            AuditToken::Recorded
        );
        assert_eq!(AuditToken::Unknown.as_str(), "unknown");
    }
}
