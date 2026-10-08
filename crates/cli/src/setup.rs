//! `setup` サブコマンド: OS 固有設定の処理を日常操作コマンドから切り離して置く場所（TASK-80.1・CLI-2・MS-6）。
//!
//! CLI-2 は「OS 固有の設定（WSL2 有効化・Virtualization.framework の entitlement 等）はセットアップ時にのみ要求され、
//! 日常操作コマンドには現れない」ことを求める。OS 固有設定に関するステップ定義と OS 分岐は本 module に局所化し、
//! `commands::run_to` の `Command::Setup` の腕からだけ [`run`] を呼ぶ（日常操作コマンドからは到達しない）。
//!
//! 現状は要求ステップの提示までで、OS 設定の検出・適用は行わない（実装済みを装わない。REPAIR-3）。
//! - cli は platform-* へ依存できない（CLI-1・PLUG-4・`make check-cli-backend-deps`）ため、検出・適用は将来 plugin 境界経由になる。
//! - WSL2 有効化・Developer Mode は管理者権限を要し、macOS の entitlement はビルド / 署名時の属性で実行時には付与できない。
//!   CLI からの昇格・シェル / 外部コマンド起動・設定ファイル / レジストリの変更は行わない。
//!
//! 将来仕様: ステップの検出・適用（Windows は WIN-1・WIN-2・WIN-4・WIN-5、macOS は MAC-1〔Virtualization.framework 経路〕。plugin 経由。TASK-114・TASK-125。本タスクは TASK-80.1・MS-6・CLI-2）。
//! 日常操作コマンドの実行パスから OS 固有設定を除く整理は TASK-80.2、分離の単体テストは TASK-80.3。

use std::io::Write;

use fandhe_container_core::traits::ErrorCode;

use crate::commands::CliExit;

/// `setup` が要求する OS 固有ステップ（閉じた列挙。外部入力からは構築しない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Windows: WSL2 の有効化（管理者権限が必要。WIN-1・WIN-5）。
    Wsl2Enable,
    /// Windows: Developer Mode の有効化（管理者権限が必要。WIN-4・WIN-5）。
    DeveloperMode,
    /// Windows: `.wslconfig` の `virtiofs=true`（管理者権限は不要。WIN-2・WIN-5）。
    WslconfigVirtiofs,
    /// macOS: `com.apple.security.virtualization` entitlement とコード署名（CLI-2・MAC-1。spec は entitlement の具体値を定義せず、Virtualization.framework 利用の前提として扱う）。
    VirtualizationEntitlement,
    /// macOS: macOS 13 以上であること（CLI-2・MAC-1。spec は最小 macOS 版数を定義していないため、13 以上は本実装の暫定要件で、版数が確定した時点で spec 側の更新をユーザーへ報告する）。
    MacosMinVersion,
}

impl SetupStep {
    /// 機械可読な固定 ID（出力の `step` フィールド）。
    pub fn id(self) -> &'static str {
        match self {
            SetupStep::Wsl2Enable => "wsl2-enable",
            SetupStep::DeveloperMode => "developer-mode",
            SetupStep::WslconfigVirtiofs => "wslconfig-virtiofs",
            SetupStep::VirtualizationEntitlement => "virtualization-entitlement",
            SetupStep::MacosMinVersion => "macos-min-version",
        }
    }

    /// 管理者権限（昇格）を要するか。
    pub fn requires_admin(self) -> bool {
        matches!(self, SetupStep::Wsl2Enable | SetupStep::DeveloperMode)
    }
}

/// `setup` の対象 OS 区分。OS 分岐を引数に出し、3 OS の表を全 OS のビルドでテストできるようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupPlatform {
    Linux,
    Macos,
    Windows,
    Other,
}

/// 実行中のホストの区分（`cfg!(target_os)` による分岐はここだけ）。
pub fn host_platform() -> SetupPlatform {
    if cfg!(target_os = "linux") {
        SetupPlatform::Linux
    } else if cfg!(target_os = "macos") {
        SetupPlatform::Macos
    } else if cfg!(target_os = "windows") {
        SetupPlatform::Windows
    } else {
        SetupPlatform::Other
    }
}

/// 区分ごとに要求されるステップ（Linux と未対応 OS は空）。
pub fn required_steps(platform: SetupPlatform) -> &'static [SetupStep] {
    match platform {
        SetupPlatform::Windows => &[
            SetupStep::Wsl2Enable,
            SetupStep::DeveloperMode,
            SetupStep::WslconfigVirtiofs,
        ],
        SetupPlatform::Macos => &[
            SetupStep::VirtualizationEntitlement,
            SetupStep::MacosMinVersion,
        ],
        SetupPlatform::Linux | SetupPlatform::Other => &[],
    }
}

/// ステップ 1 件の出力行（固定文言のみの JSON。LF 終端）。値は定数由来で引用符等を含まない（テストで固定）。
fn step_line(step: SetupStep) -> String {
    format!(
        "{{\"step\":\"{}\",\"requires_admin\":{},\"status\":\"manual\"}}\n",
        step.id(),
        step.requires_admin()
    )
}

/// 区分を指定して `setup` を実行する（テスト用の入口）。
///
/// - Linux: 要求ステップなしで成功（出力なし）。
/// - macOS / Windows: 要求ステップを 1 行ずつ stdout へ出し、自動適用が未実装のため `UNIMPLEMENTED`（8）で失敗する。
/// - その他 OS: 対応外のため `UNIMPLEMENTED`（8）。
pub fn run_for(platform: SetupPlatform, stdout: &mut dyn Write) -> CliExit {
    if platform == SetupPlatform::Other {
        return CliExit::Failed(ErrorCode::Unimplemented);
    }
    let steps = required_steps(platform);
    for step in steps {
        // 1 行を 1 回の write_all で書く（行の途中へ他の出力が入らないようにする）。
        if stdout.write_all(step_line(*step).as_bytes()).is_err() {
            return CliExit::Failed(ErrorCode::Internal);
        }
    }
    if steps.is_empty() {
        CliExit::Success
    } else {
        CliExit::Failed(ErrorCode::Unimplemented)
    }
}

/// 本番入口。`commands::run_to` の `Command::Setup` からのみ呼ばれる。
pub fn run(stdout: &mut dyn Write) -> CliExit {
    run_for(host_platform(), stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out_of(platform: SetupPlatform) -> (u8, String) {
        let mut buf = Vec::new();
        let r = run_for(platform, &mut buf);
        (r.exit_code(), String::from_utf8(buf).expect("utf8"))
    }

    /// CLI-2: Linux は OS 固有の要求ステップを持たない。
    #[test]
    fn cli2_required_steps_linux_is_empty() {
        assert_eq!(required_steps(SetupPlatform::Linux), &[]);
        assert_eq!(required_steps(SetupPlatform::Other), &[]);
    }

    /// CLI-2: Windows のステップ（WIN-1・WIN-2・WIN-4・WIN-5）。
    #[test]
    fn cli2_required_steps_windows() {
        let got: Vec<(&str, bool)> = required_steps(SetupPlatform::Windows)
            .iter()
            .map(|s| (s.id(), s.requires_admin()))
            .collect();
        assert_eq!(
            got,
            [
                ("wsl2-enable", true),
                ("developer-mode", true),
                ("wslconfig-virtiofs", false)
            ]
        );
    }

    /// CLI-2: macOS のステップ（MAC-1）。
    #[test]
    fn cli2_required_steps_macos() {
        let got: Vec<(&str, bool)> = required_steps(SetupPlatform::Macos)
            .iter()
            .map(|s| (s.id(), s.requires_admin()))
            .collect();
        assert_eq!(
            got,
            [
                ("virtualization-entitlement", false),
                ("macos-min-version", false)
            ]
        );
    }

    /// CLI-2: 出力行は JSON 安全な固定文言で、1 行 1 ステップ・LF 終端。
    #[test]
    fn cli2_step_lines_are_json_safe() {
        for p in [SetupPlatform::Windows, SetupPlatform::Macos] {
            for s in required_steps(p) {
                assert!(
                    s.id()
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "{}",
                    s.id()
                );
                let line = step_line(*s);
                assert!(line.ends_with('\n'));
                assert_eq!(line.matches('\n').count(), 1);
            }
        }
        assert_eq!(
            step_line(SetupStep::Wsl2Enable),
            "{\"step\":\"wsl2-enable\",\"requires_admin\":true,\"status\":\"manual\"}\n"
        );
    }

    /// CLI-2・REPAIR-3: 区分ごとの出力と終了コード。要求ステップが残る OS では成功を返さない。
    #[test]
    fn cli2_run_output_per_platform() {
        assert_eq!(out_of(SetupPlatform::Linux), (0, String::new()));
        assert_eq!(out_of(SetupPlatform::Other), (8, String::new()));
        let mac = concat!(
            "{\"step\":\"virtualization-entitlement\",\"requires_admin\":false,\"status\":\"manual\"}\n",
            "{\"step\":\"macos-min-version\",\"requires_admin\":false,\"status\":\"manual\"}\n"
        );
        assert_eq!(out_of(SetupPlatform::Macos), (8, mac.to_owned()));
        let (code, text) = out_of(SetupPlatform::Windows);
        assert_eq!(code, 8);
        assert_eq!(text.lines().count(), 3);
    }

    /// stdout 書き込み失敗は panic せず INTERNAL（1）で失敗する。
    #[test]
    fn cli2_run_stdout_failure_is_internal() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("x"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(run_for(SetupPlatform::Windows, &mut Broken).exit_code(), 1);
    }
}
