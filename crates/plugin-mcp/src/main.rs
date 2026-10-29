//! バイナリ `fandhe-container-plugin-mcp` の入口（MCP サーバー plugin の参照実装。MCP-1・MCP-2。TASK-118・MS-4）。
//!
//! TASK-118.1（#464）で独立バイナリとしてビルドできるようにした雛形。MCP クライアントが stdio で
//! 起動するか、core が PLUG-4 の発見機構で起動するかは未確定のため、stdout は JSON-RPC の応答経路
//! として予約し何も書かない。診断は stderr に 1 行 JSON（`code` / `message`、英語）で出す。
//!
//! 起動形態は 2 つ（引数はどちらも受け付けない）。
//! - stdio（既定）: 環境変数 `FANDHE_CONTAINER_PLUGIN_SOCKET`（`PLUGIN_SOCKET_ENV`）が未設定なら、stdin の
//!   JSON-RPC 2.0（改行区切り）を EOF まで処理し、応答を stdout へ書く（`initialize` / `tools/list` /
//!   `tools/call`。TASK-118.2・118.3。処理本体は lib の `server`）。
//! - UDS: 同環境変数が設定済みなら、core（またはそれを模したハーネス）が bind 済みの UDS へ
//!   `UdsStream::connect`（server の peer UID 検証つき。PLUG-12）で接続し、同じ JSON-RPC 処理を
//!   その上で行う（TASK-118.4・#467。処理本体は lib の `uds`）。stdin / stdout は使わず stdout へ何も書かない。
//!   接続方向は plugin-macos / plugin-windows と同じ（core が bind、plugin が connect）。別 UID の
//!   listener には 1 バイトも送らず `PERMISSION_DENIED`・終了コード 3 で fail-closed する。
//!
//! 診断は stderr のみ。終了コード: 正常（stdin の EOF・相手の切断）は 0、読み込み失敗・書き込み失敗・
//! 受信/送信の期限超過は 1（`UNAVAILABLE` / `DEADLINE_EXCEEDED`）、引数あり・socket パスの不正
//! （空・相対・`..` 含み）は 2（`INVALID_ARGUMENT`）、UDS への接続失敗は 3（plugin-macos / -windows と同じ値で、
//! core 側 proxy が同じ規則で扱えるようにする）。引数・環境変数の値・socket パスは出力へ埋め込まない。
//! peer 認証の拒否イベントは、socket パスを除いた構造化 1 行（`PathlessPeerAuthObserver`）にして
//! 接続失敗の診断の直前に stderr へ出す（SEC-4。永続的な監査ログへの配線は core 側との結線で未実装（結線は別 issue で行う。#1869 で設計した plugin-backend-wiring.md 4.9 では入口の対象外で、追跡 issue は未起票。起票の要否は #3417 のコメントでユーザーに諮った）。REPAIR-3）。
//! `list_containers` の状態ルート解決では core が `XDG_RUNTIME_DIR` を読む。
//!
//! 未実装（REPAIR-3。TASK-118 の後続 sub で扱う）: `start_container` の本番起動（supervisor 起動の
//! adapter。#1718 待ちで、現状は `UNIMPLEMENTED` を `isError` で返す）、core 側 proxy との結線・UDS 上のフレーミングの確定（別 issue で行う。#1869 で設計した plugin-backend-wiring.md 4.9 では入口の対象外で、追跡 issue は未起票。起票の要否は #3417 のコメントでユーザーに諮った。現状は改行区切りの暫定契約）。

use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_plugin::{
    PLUGIN_SOCKET_ENV, PeerAuthObserver, PeerAuthRejection, PluginError, UdsStream,
};
use fandhe_container_plugin_mcp::server::ServeError;

const READ_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from stdin\"}";
const WRITE_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}";
const READ_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from stdin\"}";
const WRITE_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to stdout\"}";
const ENCODE_FAILED_JSON: &str =
    "{\"code\":\"INTERNAL\",\"message\":\"failed to encode response\"}";
const SPAWN_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to spawn worker thread\"}";
const INVALID_ARGUMENT_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}";
const INVALID_SOCKET_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid socket path\"}";
const UDS_READ_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from socket\"}";
const UDS_WRITE_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to socket\"}";
const UDS_READ_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from socket\"}";
const UDS_WRITE_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to socket\"}";

/// UDS 接続失敗の終了コード（plugin-macos / -windows と同じ値）。
const EXIT_CONNECT_FAILED: u8 = 3;
/// UDS 接続の期限（core の起動期限より短くする。REPAIR-5）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// stderr へ 1 行書く。読まれない stderr で止まらないよう期限付きで書き、結果は無視する（REPAIR-5）。
fn stderr_line(line: &str) {
    fandhe_container_plugin_mcp::server::write_diagnostic(line);
}

/// 引数ありの拒否（終了コード 2）。引数の値は診断へ埋め込まない（MCP-1・REPAIR-12）。
fn reject_args() -> ExitCode {
    stderr_line(INVALID_ARGUMENT_JSON);
    ExitCode::from(2)
}

/// 環境変数の socket パスを検証する。空・相対・`..` を含むものは拒否する（外部入力。PLUG-12）。
/// `sun_path` 長・NUL・配置ディレクトリの検証は `UdsStream::connect` / core の bind 側の責務。
fn validate_socket_path(raw: &std::ffi::OsStr) -> Option<PathBuf> {
    let path = Path::new(raw);
    let ok = !raw.is_empty()
        && path.is_absolute()
        && !path.components().any(|c| c == Component::ParentDir);
    ok.then(|| path.to_path_buf())
}

/// 接続失敗の診断 1 行。code は ERR-1 名、message は固定文言のみ（パス・環境変数値を含めない）。
fn connect_failed_json(e: &PluginError) -> String {
    serde_json::json!({"code": e.code().as_str(), "message": e.message()}).to_string()
}

/// 処理結果を診断と終了コードへ写す。`uds` は入出力元が socket か（診断文言の違い）。
fn exit_for(result: Result<(), ServeError>, uds: bool) -> ExitCode {
    let json = match result {
        Ok(()) => return ExitCode::SUCCESS,
        Err(ServeError::Read(_)) if uds => UDS_READ_FAILED_JSON,
        Err(ServeError::Read(_)) => READ_FAILED_JSON,
        Err(ServeError::Write(_)) if uds => UDS_WRITE_FAILED_JSON,
        Err(ServeError::Write(_)) => WRITE_FAILED_JSON,
        Err(ServeError::ReadTimeout) if uds => UDS_READ_TIMEOUT_JSON,
        Err(ServeError::ReadTimeout) => READ_TIMEOUT_JSON,
        Err(ServeError::WriteTimeout) if uds => UDS_WRITE_TIMEOUT_JSON,
        Err(ServeError::WriteTimeout) => WRITE_TIMEOUT_JSON,
        Err(ServeError::Spawn(_)) => SPAWN_FAILED_JSON,
        Err(ServeError::Encode) => ENCODE_FAILED_JSON,
    };
    stderr_line(json);
    ExitCode::from(1)
}

/// 1 回の接続で保持する拒否イベントの最大件数（有界メモリ。超過分は捨てず件数で集約する。SEC-4）。
const MAX_REJECTION_LINES: usize = 8;

/// peer 認証の拒否イベントを socket パス抜きの 1 行 JSON としてメモリへ積む受け手（PLUG-12・SEC-4）。
/// `PeerAuthRejection::to_json_line` は socket パスを含むため使わず、パス以外の項目だけを写す。
/// I/O はせず、接続失敗後に `drain` で回収して stderr へ書く（REPAIR-5）。
#[derive(Default)]
struct PathlessPeerAuthObserver {
    lines: Vec<String>,
    coalesced: u64,
}

impl PeerAuthObserver for PathlessPeerAuthObserver {
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>) {
        if self.lines.len() >= MAX_REJECTION_LINES {
            self.coalesced = self.coalesced.saturating_add(1);
            return;
        }
        let mut line = serde_json::json!({
            "event": "plugin_peer_auth",
            "op": event.op.as_str(),
            "outcome": "error",
            "reason": event.reason.as_str(),
            "code": event.code.as_str(),
            "expected_uid": event.expected_uid,
        });
        // 正式な plugin_peer_auth イベントと揃え、取得できない peer_uid はキーごと省略する。
        if let (Some(uid), Some(obj)) = (event.peer_uid, line.as_object_mut()) {
            obj.insert("peer_uid".to_owned(), serde_json::json!(uid));
        }
        self.lines.push(line.to_string());
    }
}

impl PathlessPeerAuthObserver {
    /// 積んだ行を届いた順に返す。集約があれば末尾に件数行を足す。
    fn drain(&mut self) -> Vec<String> {
        let mut out = std::mem::take(&mut self.lines);
        if self.coalesced > 0 {
            out.push(
                serde_json::json!({
                    "event": "plugin_peer_auth",
                    "outcome": "error",
                    "reason": "peer_auth_rejections_coalesced",
                    "count": self.coalesced,
                })
                .to_string(),
            );
            self.coalesced = 0;
        }
        out
    }
}

/// UDS モード。接続は peer 認証つき `UdsStream::connect` のみ（PLUG-12）。
fn run_uds(raw: &std::ffi::OsStr) -> ExitCode {
    let Some(path) = validate_socket_path(raw) else {
        stderr_line(INVALID_SOCKET_JSON);
        return ExitCode::from(2);
    };
    // 拒否イベントはパスを除いた形で回収し、失敗時に stderr へ出す（上の doc。SEC-4）。
    let mut observer = PathlessPeerAuthObserver::default();
    match UdsStream::connect(&path, CONNECT_TIMEOUT, &mut observer) {
        Ok(stream) => exit_for(fandhe_container_plugin_mcp::uds::serve_uds(stream), true),
        Err(e) => {
            for line in observer.drain() {
                stderr_line(&line);
            }
            stderr_line(&connect_failed_json(&e));
            ExitCode::from(EXIT_CONNECT_FAILED)
        }
    }
}

fn main() -> ExitCode {
    use fandhe_container_plugin_mcp::server::serve;
    if std::env::args_os().nth(1).is_some() {
        return reject_args();
    }
    if let Some(raw) = std::env::var_os(PLUGIN_SOCKET_ENV) {
        return run_uds(&raw);
    }
    // 読み書きは serve 内の専用スレッドで行うため、'static な Stdin / Stdout を渡す（REPAIR-5）。
    exit_for(
        serve(std::io::BufReader::new(std::io::stdin()), std::io::stdout()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP-1・REPAIR-12: 診断 JSON は固定の具体値。
    #[test]
    fn diagnostics_are_fixed_json() {
        assert_eq!(
            INVALID_SOCKET_JSON,
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid socket path\"}"
        );
        assert_eq!(
            INVALID_ARGUMENT_JSON,
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}"
        );
        assert_eq!(
            READ_FAILED_JSON,
            "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from stdin\"}"
        );
        assert_eq!(
            READ_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from stdin\"}"
        );
        assert_eq!(
            WRITE_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to stdout\"}"
        );
        assert_eq!(
            UDS_READ_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from socket\"}"
        );
        assert_eq!(
            UDS_WRITE_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to socket\"}"
        );
        assert_eq!(
            ENCODE_FAILED_JSON,
            "{\"code\":\"INTERNAL\",\"message\":\"failed to encode response\"}"
        );
        assert_eq!(
            WRITE_FAILED_JSON,
            "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}"
        );
    }

    /// SEC-4: 集約行は固定の具体値で、通常行の後ろに 1 行足される。
    #[test]
    fn pathless_observer_drain_appends_coalesced_line() {
        let mut o = PathlessPeerAuthObserver {
            lines: vec!["{\"event\":\"plugin_peer_auth\"}".to_string()],
            coalesced: 2,
        };
        let lines = o.drain();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[1],
            "{\"count\":2,\"event\":\"plugin_peer_auth\",\"outcome\":\"error\",\"reason\":\"peer_auth_rejections_coalesced\"}"
        );
        assert!(o.drain().is_empty());
    }

    /// PLUG-12: socket パスは空・相対・`..` 含みを拒否し、絶対パスのみ通す。
    #[test]
    fn socket_path_validation() {
        use std::ffi::OsStr;
        assert_eq!(validate_socket_path(OsStr::new("")), None);
        assert_eq!(validate_socket_path(OsStr::new("rel/p.sock")), None);
        assert_eq!(validate_socket_path(OsStr::new("/a/../b.sock")), None);
        #[cfg(unix)]
        assert_eq!(
            validate_socket_path(OsStr::new("/a/b.sock")),
            Some(PathBuf::from("/a/b.sock"))
        );
    }
}
