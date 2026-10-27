//! macOS VM 実機試験（`vm_boot`・`vm_cold_start`）が共有するゲストマーカーの検証（MAC-1・TASK-64.6・TASK-70 準備）。
//!
//! 役割: ブートマーカーと起動完了マーカーの決定・重複拒否・出現順の判定を 1 か所に置き、2 つの試験で
//! 必須性・空文字拒否・順序の規則がずれるのを防ぐ。呼び出し元は `tests/vm_boot.rs` と
//! `tests/vm_cold_start.rs`（どちらも `#[path]` で取り込む）。std だけで書き、cfg は付けない。
//! 片方の試験だけが使う関数には、その関数にだけ理由付きで `allow(dead_code)` を付ける。

/// ブートマーカーを決める。未指定は既定値、空文字列は拒否する。
///
/// 空マーカーは `contains` が常に true になり、ゲストが何も出力しなくても起動確認を通過してしまうため（MAC-1）。
pub fn resolve_boot_marker(raw: Option<String>) -> Result<String, String> {
    match raw {
        None => Ok("Linux version".to_string()),
        Some(m) if m.is_empty() => {
            Err("boot marker must not be empty (it would match any console output)".to_string())
        }
        Some(m) => Ok(m),
    }
}

/// 起動完了マーカーを決める。既定値は無く、未指定・空文字列は拒否する。
///
/// `Linux version` のような起動初期のマーカーだけでは、直後にゲストが停止しても成功してしまう。
/// ゲスト資産が起動完了後にだけ出力する文字列を呼び出し側に必ず指定させる（MAC-1）。
pub fn resolve_ready_marker(raw: Option<String>) -> Result<String, String> {
    match raw {
        None => Err("FANDHE_CONTAINER_MACOS_VM_READY_MARKER is required".to_string()),
        Some(m) if m.is_empty() => Err("ready marker must not be empty".to_string()),
        Some(m) => Ok(m),
    }
}

/// ブートマーカーと起動完了マーカーの重複を拒否する。
///
/// 一致・包含関係にあると起動初期の出力だけで両方が成立し、起動完了前にゲストが停止しても通ってしまう（MAC-1）。
pub fn validate_marker_pair(boot: &str, ready: &str) -> Result<(), String> {
    if boot.contains(ready) || ready.contains(boot) {
        return Err(format!(
            "boot marker {boot:?} and ready marker {ready:?} must not be equal or contain one another"
        ));
    }
    Ok(())
}

/// ブートマーカーの出現より後に起動完了マーカーが現れたかを返す。
///
/// 起動完了マーカーはブートマーカー末尾以降だけを探索し、順序（ブート後に起動完了）を保証する（MAC-1）。
#[allow(
    dead_code,
    reason = "vm_boot だけが使う。vm_cold_start は走査器（MarkerScanner）で同じ順序規則を実装する"
)]
pub fn markers_observed_in_order(text: &str, boot: &str, ready: &str) -> bool {
    text.find(boot)
        .and_then(|pos| text.get(pos + boot.len()..))
        .is_some_and(|rest| rest.contains(ready))
}
