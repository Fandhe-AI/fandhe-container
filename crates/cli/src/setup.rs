//! `setup` サブコマンド: OS 固有設定の処理を日常操作コマンドから切り離して置く場所（TASK-80.1・CLI-2・MS-6）。
//!
//! CLI-2 は「OS 固有の設定（WSL2 有効化・Virtualization.framework の entitlement 等）はセットアップ時にのみ要求され、
//! 日常操作コマンドには現れない」ことを求める。OS 固有設定に関するステップ定義と OS 分岐は本 module に局所化し、
//! `commands::run_to` の `Command::Setup` の腕からだけ [`run`] を呼ぶ（日常操作コマンドからは到達しない）。
//!
//! Linux は rootful のときだけ要る特権ランチャーのインストール手順をステップ `privileged-launcher-install` として 1 行表示して 0 で終わる
//! （表示が完成形。#1454 の決定・SUP-14・CORE-6。rootless の既定では不要）。CLI は `setcap`・`chmod`・sudo・インストールスクリプトの
//! 実行をせず、本 module は外部コマンドを起動しない（単体テスト `cli2_setup_does_not_spawn_processes` で照合）。
//! 表示する使い方と `scripts/install-privileged-launcher.sh` の食い違いは単体テスト `sup14_launcher_install_instructions_match_script_usage` が検出する。
//!
//! 終了コードの規則: 条件なし（どの構成でも要る）のステップが残れば `UNIMPLEMENTED`（8）、条件つき（[`SetupCondition`]）のステップだけなら 0。
//!
//! macOS / Windows も Linux と同じ形式の `instructions`（手順の固定文言。表示のみ）つきでステップを提示し、
//! OS 設定の検出・適用は行わない（TASK-125 の範囲。実装済みを装わない。REPAIR-3・#2452・CLI-1）。
//! Windows の文言は `docs/setup/windows.md` と食い違わない（単体テスト `win5_instructions_match_windows_setup_doc` で照合）。
//! macOS の文言は `docs/setup/macos.md` と食い違わない（単体テスト `mac1_cli2_instructions_match_macos_setup_doc` で照合。#2602）。
//! - cli は platform-* へ依存できない（CLI-1・PLUG-4・`make check-cli-backend-deps`）ため、検出・適用は将来 plugin 境界経由になる。
//! - WSL2 有効化・Developer Mode は管理者権限を要し、macOS の entitlement はビルド / 署名時の属性で実行時には付与できない。
//!   CLI からの昇格・シェル / 外部コマンド起動・設定ファイル / レジストリの変更は行わない。
//!
//! 将来仕様: ステップの検出・適用（Windows は WIN-1・WIN-2・WIN-4・WIN-5、macOS は MAC-1〔Virtualization.framework 経路〕。plugin 経由。#1869 の設計〔docs/design/plugin-backend-wiring.md。承認と実装 issue の起票は #2232〕・TASK-125。本タスクは TASK-80.1・MS-6・CLI-2）。
//! 日常操作コマンドからの切り離しは TASK-80.2 で確立済み（参照点は `commands::run_setup` のみ）。分離の単体テストは `tests::cli2_daily_commands_do_not_request_os_setup`（TASK-80.3）。

use std::io::Write;

use fandhe_container_core::traits::ErrorCode;

use crate::commands::CliExit;
use crate::json::json_escape_into;

/// 特権ランチャーのインストール手順の固定文言（sudo は案内しない。root で直接実行する。#1454）。
/// 引数は `scripts/install-privileged-launcher.sh` の使い方（#2137 の sha256 3 引数を含む）に合わせる。
const LAUNCHER_INSTALL_INSTRUCTIONS: &str = "rootful only; rootless (default) needs no install. As root, run scripts/install-privileged-launcher.sh --launcher <file> --launcher-sha256 <hex> --supervisor <file> --supervisor-sha256 <hex> --cli <file> --cli-sha256 <hex> [--dest-dir <absolute path>] (default dest-dir /usr/local/libexec/fandhe-container). fandhe-container does not run it. See docs/setup/linux.md";

/// Windows: WSL2 有効化の手順の固定文言（`docs/setup/windows.md`「WSL2 の有効化」と同じコマンド。WIN-1・WIN-5・#2452）。
const WSL2_ENABLE_INSTRUCTIONS: &str = "Requires administrator. In an elevated PowerShell, run wsl --install and reboot (or enable the Virtual Machine Platform and Windows Subsystem for Linux features, reboot, and run wsl --set-default-version 2). Then install a WSL2 distribution and confirm that wsl -l -v shows VERSION 2 and that wsl --version succeeds. fandhe-container does not run these. See docs/setup/windows.md";

/// Windows: Developer Mode の手順の固定文言（`docs/setup/windows.md`「Developer Mode の有効化」。WIN-4・WIN-5・#2452）。
const DEVELOPER_MODE_INSTRUCTIONS: &str = "Requires administrator. Turn on Developer Mode in Settings > System > For developers (Windows 11) or Settings > Update & Security > For developers (Windows 10); it is needed to create symbolic links and widens the local attack surface. fandhe-container does not change it. See docs/setup/windows.md";

/// Windows: `.wslconfig` の virtiofs の手順の固定文言（`docs/setup/windows.md`「`.wslconfig` で virtiofs を有効化」。WIN-2・WIN-5・#2452）。
const WSLCONFIG_VIRTIOFS_INSTRUCTIONS: &str = "No administrator needed. In %UserProfile%\\.wslconfig, add virtiofs=true under [wsl2] (put comments on their own lines), then run wsl --shutdown so the setting takes effect. fandhe-container does not edit .wslconfig. See docs/setup/windows.md";

/// macOS: entitlement と署名の手順の固定文言（`fandhe-container-plugin-macos` の前提。MAC-1・#2452）。
/// `docs/setup/macos.md`「entitlement とコード署名」と同じ手順（#2602）。
const VIRTUALIZATION_ENTITLEMENT_INSTRUCTIONS: &str = "The macOS backend plugin fandhe-container-plugin-macos must be code-signed with the com.apple.security.virtualization entitlement (ad-hoc signing is accepted), e.g. codesign --sign - --force --entitlements <plist granting com.apple.security.virtualization> <path to fandhe-container-plugin-macos>. fandhe-container does not sign binaries. See docs/setup/macos.md";

/// macOS: 最低版数の手順の固定文言（13 以上は `MacosMinVersion` の暫定要件。spec 未定義。`docs/setup/macos.md`「macOS の版」と同じ。MAC-1・#2452・#2602）。
const MACOS_MIN_VERSION_INSTRUCTIONS: &str = "Requires macOS 13 or later (provisional minimum for Virtualization.framework). Check with sw_vers -productVersion. fandhe-container does not check or upgrade macOS. See docs/setup/macos.md";

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
    /// Linux の rootful だけ: `scripts/install-privileged-launcher.sh` を root で実行する手順の表示（CLI は実行しない。
    /// #1721・#1722・SUP-14・CORE-6・CLI-2・#1454）。
    PrivilegedLauncherInstall,
}

/// ステップが要る構成の条件（閉じた列挙）。条件つきのステップは、その構成でなければ不要なので終了コードを失敗にしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCondition {
    /// rootful で使うときだけ要る（CORE-6 の既定は rootless）。
    Rootful,
}

impl SetupCondition {
    /// 機械可読な固定 ID（出力の `condition` フィールド）。
    pub fn id(self) -> &'static str {
        match self {
            SetupCondition::Rootful => "rootful",
        }
    }
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
            SetupStep::PrivilegedLauncherInstall => "privileged-launcher-install",
        }
    }

    /// ステップが要る構成の条件。`None` はどの構成でも要る（未適用なら `run_for` は失敗を返す）。
    pub fn condition(self) -> Option<SetupCondition> {
        match self {
            SetupStep::Wsl2Enable
            | SetupStep::DeveloperMode
            | SetupStep::WslconfigVirtiofs
            | SetupStep::VirtualizationEntitlement
            | SetupStep::MacosMinVersion => None,
            SetupStep::PrivilegedLauncherInstall => Some(SetupCondition::Rootful),
        }
    }

    /// 手順の固定文言（出力の `instructions` フィールド。英語・外部入力を含まない。表示のみで CLI は実行しない）。
    /// 現状は全ステップが `Some`。手順の無いステップを足せるよう `Option` を保つ。
    pub fn instructions(self) -> Option<&'static str> {
        match self {
            SetupStep::Wsl2Enable => Some(WSL2_ENABLE_INSTRUCTIONS),
            SetupStep::DeveloperMode => Some(DEVELOPER_MODE_INSTRUCTIONS),
            SetupStep::WslconfigVirtiofs => Some(WSLCONFIG_VIRTIOFS_INSTRUCTIONS),
            SetupStep::VirtualizationEntitlement => Some(VIRTUALIZATION_ENTITLEMENT_INSTRUCTIONS),
            SetupStep::MacosMinVersion => Some(MACOS_MIN_VERSION_INSTRUCTIONS),
            SetupStep::PrivilegedLauncherInstall => Some(LAUNCHER_INSTALL_INSTRUCTIONS),
        }
    }

    /// 管理者権限（昇格）を要するか。
    pub fn requires_admin(self) -> bool {
        matches!(
            self,
            SetupStep::Wsl2Enable | SetupStep::DeveloperMode | SetupStep::PrivilegedLauncherInstall
        )
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
fn host_platform() -> SetupPlatform {
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

/// 区分ごとに要求されるステップ（未対応 OS は空）。
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
        SetupPlatform::Linux => &[SetupStep::PrivilegedLauncherInstall],
        SetupPlatform::Other => &[],
    }
}

/// ステップ 1 件の出力行（固定スキーマの JSON。LF 終端）。手組みの `format!` を使わず、cli の
/// `json` モジュールのエスケープを通して組み立てる（将来ステップ ID に可変値が入っても注入しない。
/// REPAIR-2・CLI-2）。
fn step_line(step: SetupStep) -> String {
    let mut line = String::with_capacity(512);
    line.push_str("{\"step\":\"");
    json_escape_into(&mut line, step.id());
    line.push_str("\",\"requires_admin\":");
    line.push_str(if step.requires_admin() {
        "true"
    } else {
        "false"
    });
    line.push_str(",\"status\":\"manual\"");
    if let Some(c) = step.condition() {
        line.push_str(",\"condition\":\"");
        json_escape_into(&mut line, c.id());
        line.push('"');
    }
    if let Some(text) = step.instructions() {
        line.push_str(",\"instructions\":\"");
        json_escape_into(&mut line, text);
        line.push('"');
    }
    line.push_str("}\n");
    line
}

/// 区分を指定して `setup` を実行する（テスト用の入口）。
///
/// - Linux: rootful のときだけ要る手順を 1 行出して成功（表示が完成形。#1454・SUP-14）。
/// - macOS / Windows: 要求ステップを 1 行ずつ stdout へ出し、自動適用が未実装のため `UNIMPLEMENTED`（8）で失敗する。
/// - その他 OS: 対応外のため `UNIMPLEMENTED`（8）。
pub fn run_for(platform: SetupPlatform, stdout: &mut dyn Write) -> CliExit {
    if platform == SetupPlatform::Other {
        return CliExit::failed(ErrorCode::Unimplemented);
    }
    let steps = required_steps(platform);
    for step in steps {
        // 1 行を 1 つのバッファで `write_all` する（断片ごとの write を避ける。他プロセスとの不可分性は保証しない）。
        if stdout.write_all(step_line(*step).as_bytes()).is_err() {
            return CliExit::failed(ErrorCode::Internal);
        }
    }
    // 条件なしのステップが残る（どの構成でも要るのに自動適用が無い）ときだけ失敗にする。
    if steps.iter().any(|s| s.condition().is_none()) {
        CliExit::failed(ErrorCode::Unimplemented)
    } else {
        CliExit::Success
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

    /// 期待する Linux の出力行（具体値）。
    const LINUX_LINE: &str = "{\"step\":\"privileged-launcher-install\",\"requires_admin\":true,\"status\":\"manual\",\"condition\":\"rootful\",\"instructions\":\"rootful only; rootless (default) needs no install. As root, run scripts/install-privileged-launcher.sh --launcher <file> --launcher-sha256 <hex> --supervisor <file> --supervisor-sha256 <hex> --cli <file> --cli-sha256 <hex> [--dest-dir <absolute path>] (default dest-dir /usr/local/libexec/fandhe-container). fandhe-container does not run it. See docs/setup/linux.md\"}\n";

    /// CLI-2・SUP-14・CORE-6: Linux は rootful だけ要る特権ランチャーのインストール手順を返し、未対応 OS は空。
    #[test]
    fn cli2_sup14_required_steps_linux_is_launcher_install() {
        let got: Vec<(&str, bool, Option<&str>)> = required_steps(SetupPlatform::Linux)
            .iter()
            .map(|s| (s.id(), s.requires_admin(), s.condition().map(|c| c.id())))
            .collect();
        assert_eq!(
            got,
            [("privileged-launcher-install", true, Some("rootful"))]
        );
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
        for p in [
            SetupPlatform::Windows,
            SetupPlatform::Macos,
            SetupPlatform::Linux,
        ] {
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
            test_line("wsl2-enable", true, WSL2_ENABLE_INSTRUCTIONS)
        );
        assert_eq!(step_line(SetupStep::PrivilegedLauncherInstall), LINUX_LINE);
    }

    /// CLI-2・REPAIR-3: 区分ごとの出力と終了コード。要求ステップが残る OS では成功を返さない。
    #[test]
    fn cli2_run_output_per_platform() {
        assert_eq!(out_of(SetupPlatform::Linux), (0, LINUX_LINE.to_owned()));
        assert_eq!(out_of(SetupPlatform::Other), (8, String::new()));
        let mac = [
            test_line(
                "virtualization-entitlement",
                false,
                VIRTUALIZATION_ENTITLEMENT_INSTRUCTIONS,
            ),
            test_line("macos-min-version", false, MACOS_MIN_VERSION_INSTRUCTIONS),
        ]
        .concat();
        assert_eq!(out_of(SetupPlatform::Macos), (8, mac));
        let win = [
            test_line("wsl2-enable", true, WSL2_ENABLE_INSTRUCTIONS),
            test_line("developer-mode", true, DEVELOPER_MODE_INSTRUCTIONS),
            test_line("wslconfig-virtiofs", false, WSLCONFIG_VIRTIOFS_INSTRUCTIONS),
        ]
        .concat();
        assert_eq!(out_of(SetupPlatform::Windows), (8, win));
        // 文言の具体値（定数からの組み立てとの循環照合を避ける）。JSON では `\` が `\\` になる。
        assert!(step_line(SetupStep::WslconfigVirtiofs).contains(
            r"No administrator needed. In %UserProfile%\\.wslconfig, add virtiofs=true under [wsl2]"
        ));
        assert!(step_line(SetupStep::MacosMinVersion).contains("Requires macOS 13 or later"));
    }

    /// 期待する出力行を組み立てる（文言中の `\` だけを JSON 用に 2 重化する）。
    fn test_line(id: &str, admin: bool, text: &str) -> String {
        format!(
            "{{\"step\":\"{id}\",\"requires_admin\":{admin},\"status\":\"manual\",\"instructions\":\"{}\"}}\n",
            text.replace('\\', "\\\\")
        )
    }

    /// CLI-1・CLI-2・#2452: 全 OS 区分の全ステップが、非空・ASCII 印字可能・単一行の手順文言を持つ。
    #[test]
    fn cli1_cli2_every_step_has_instructions() {
        for p in [
            SetupPlatform::Windows,
            SetupPlatform::Macos,
            SetupPlatform::Linux,
        ] {
            for s in required_steps(p) {
                let t = s.instructions().unwrap_or_else(|| panic!("{}", s.id()));
                assert!(!t.is_empty());
                assert!(t.chars().all(|c| c == ' ' || c.is_ascii_graphic()), "{t}");
                assert!(t.contains("fandhe-container does not"), "{t}");
            }
        }
    }

    /// WIN-5・REPAIR-12・#2452: Windows の文言のコマンド・設定値が `docs/setup/windows.md` にも載っている。
    #[test]
    fn win5_instructions_match_windows_setup_doc() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/setup/windows.md"),
        )
        .expect("windows.md");
        let all = [
            WSL2_ENABLE_INSTRUCTIONS,
            DEVELOPER_MODE_INSTRUCTIONS,
            WSLCONFIG_VIRTIOFS_INSTRUCTIONS,
        ]
        .join(" ");
        for needle in [
            "wsl --install",
            "wsl --set-default-version 2",
            "wsl -l -v",
            "wsl --version",
            "virtiofs=true",
            "[wsl2]",
            "wsl --shutdown",
            ".wslconfig",
        ] {
            assert!(all.contains(needle), "instructions: {needle}");
            assert!(doc.contains(needle), "doc: {needle}");
        }
        for id in ["wsl2-enable", "developer-mode", "wslconfig-virtiofs"] {
            assert!(doc.contains(&format!("`{id}`")), "doc id: {id}");
        }
    }

    /// MAC-1・CLI-2・REPAIR-12・#2602: macOS の文言のコマンド・値が `docs/setup/macos.md` にも載り、両文言が文書へのリンクで終わる。
    #[test]
    fn mac1_cli2_instructions_match_macos_setup_doc() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/setup/macos.md"),
        )
        .expect("macos.md");
        let all = [
            VIRTUALIZATION_ENTITLEMENT_INSTRUCTIONS,
            MACOS_MIN_VERSION_INSTRUCTIONS,
        ]
        .join(" ");
        for needle in [
            "com.apple.security.virtualization",
            "codesign --sign - --force --entitlements",
            "fandhe-container-plugin-macos",
            "sw_vers -productVersion",
            "macOS 13",
        ] {
            assert!(all.contains(needle), "instructions: {needle}");
            assert!(doc.contains(needle), "doc: {needle}");
        }
        for id in ["virtualization-entitlement", "macos-min-version"] {
            assert!(doc.contains(&format!("`{id}`")), "doc id: {id}");
        }
        for t in [
            VIRTUALIZATION_ENTITLEMENT_INSTRUCTIONS,
            MACOS_MIN_VERSION_INSTRUCTIONS,
        ] {
            assert!(t.ends_with(" See docs/setup/macos.md"), "{t}");
        }
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

    // ---- 日常操作コマンドからの分離（TASK-80.3・CLI-2）----
    //
    // 参照方向は setup -> commands のみ（commands 側のテストは setup の型を import しない。TASK-80.2 の規則）。

    use crate::commands::{Command, CommandKind, run_to};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 補助キーワード（小文字化して部分一致）。OS 固有設定の手掛かりとなる語。
    const AUX_MARKERS: [&str; 5] = ["wsl", "developer mode", "entitlement", "virtiofs", "setup"];

    /// 一時ディレクトリ（プロセス ID + 連番。unix は 0700。Drop で削除）。
    /// 空のイメージストアに対する `system df` の出力（固定 9 行。値はすべて 0）。
    const SYSTEM_DF_EMPTY: &str = "KEY\tVALUE\nimages.count\t0\nimages.bytes\t0\nimages.reclaimable_bytes\t0\nimages.missing_blobs\t0\ncache.blob_count\t0\ncache.bytes\t0\ncache.unregistered_count\t0\ncache.unregistered_bytes\t0\ncache.foreign_entries\t0\n";

    /// Linux では `ScratchDir`（systemd-tmpfiles の aging 走査と BundleLock の flock の競合を避ける。
    /// #3141・CORE-5・REPAIR-12）の子に作る。他 OS は `temp_dir()` 直下（flock を取る経路が無い）。
    struct TmpDir(
        PathBuf,
        #[cfg(target_os = "linux")]
        #[allow(dead_code)]
        crate::scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
        // 非 Linux は残骸を消して作った実体（Drop で後始末。REPAIR-12・#3435）。
        #[cfg(not(target_os = "linux"))]
        #[allow(dead_code)]
        crate::test_root::TestRoot,
    );

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            #[cfg(target_os = "linux")]
            let scratch = crate::scratch_root::ScratchDir::new(
                "fc-cli-setup",
                std::time::Duration::from_secs(10),
            );
            #[cfg(target_os = "linux")]
            let p = scratch.path().join(format!("{tag}-{n}"));
            #[cfg(not(target_os = "linux"))]
            let p =
                std::env::temp_dir().join(format!("fc-cli-setup-{tag}-{}-{n}", std::process::id()));
            // Linux は ScratchDir が作成前の削除を担う。他 OS は残骸・PID 再利用との衝突を避けるため
            // 作成前に削除する（REPAIR-12・#3435）。
            #[cfg(target_os = "linux")]
            {
                std::fs::create_dir_all(&p).expect("mkdir");
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
                Self(p, scratch)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let root = crate::test_root::test_root_at(p.clone());
                Self(p, root)
            }
        }
    }

    /// 最小の OCI bundle を作る（Linux の create が受理する形。他 OS では中身は読まれない）。
    fn make_bundle(base: &Path) -> PathBuf {
        let b = base.join("bundle");
        std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
        std::fs::write(
            b.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .expect("config");
        b
    }

    /// `text` に含まれる OS 固有設定要求のマーカーを返す。
    ///
    /// マーカーは setup 自身の出力形式（`step_line` の接頭辞）と全ステップ ID から導出し、
    /// `SetupStep` の追加に自動追随させる。
    fn setup_markers_in(text: &str) -> Vec<String> {
        let line = step_line(SetupStep::Wsl2Enable);
        let prefix = line.split(':').next().unwrap_or("").to_owned() + ":";
        let mut needles: Vec<String> = vec![prefix];
        for p in [
            SetupPlatform::Windows,
            SetupPlatform::Macos,
            SetupPlatform::Linux,
        ] {
            needles.extend(required_steps(p).iter().map(|s| s.id().to_owned()));
        }
        needles.extend(AUX_MARKERS.iter().map(|s| (*s).to_owned()));
        let lower = text.to_lowercase();
        needles
            .into_iter()
            .filter(|n| lower.contains(&n.to_lowercase()))
            .collect()
    }

    /// `--root` を前置して `run_to` を呼び、(終了コード, stdout, stderr) を返す。
    fn invoke(root: &Path, argv: &[&str]) -> (u8, String, String) {
        let mut full: Vec<OsString> = vec![OsString::from("--root"), root.into()];
        full.extend(argv.iter().map(OsString::from));
        let mut out = Vec::new();
        let r = run_to(full, &mut out);
        let mut err = Vec::new();
        r.write_stderr(&mut err).expect("stderr");
        (
            r.exit_code(),
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    /// CLI-2・TASK-80.3: setup を一度も実行していなくても、日常操作 6 コマンドの出力に
    /// OS 固有設定の要求（setup のステップ行・WSL2 / entitlement 等の語）は現れない。
    ///
    /// 非 Linux では plugin 候補なしの fail-closed（FAILED_PRECONDITION=5）、Linux では実経路の終了コードで照合する。
    #[test]
    fn cli2_daily_commands_do_not_request_os_setup() {
        let linux = cfg!(target_os = "linux");
        let base = TmpDir::new("daily");
        let root = base.0.join("state");
        let bundle = make_bundle(&base.0);
        let b = bundle.to_str().expect("utf8");
        // image / system 用のイメージストア root（空。blobs/sha256 だけ作る）。
        let images = base.0.join("images");
        std::fs::create_dir_all(images.join("blobs").join("sha256")).expect("images");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&images, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        let ir = images.to_str().expect("utf8").to_owned();
        if linux {
            let (c, _, e) = invoke(&root, &["create", "--bundle", b, "d1"]);
            assert_eq!((c, e.as_str()), (0, ""));
        }

        let mut seen = Vec::new();
        for command in Command::ALL {
            if command.kind() != CommandKind::Daily {
                continue;
            }
            // ワイルドカードなし: コマンド追加時に argv / 期待値の定義漏れをコンパイルエラーにする。
            let (argv, exit, stdout): (Vec<&str>, u8, &str) = match command {
                Command::Create => (
                    vec!["create", "--bundle", b, "c1"],
                    if linux { 0 } else { 5 },
                    "",
                ),
                // Linux の start は supervisor の bin を CLI の隣から探す。テスト実行ファイルの隣には無いため FAILED_PRECONDITION（5）
                // （非 Linux は plugin 解決の失敗の 5。いずれも OS 固有設定を要求しない。#1718）。
                Command::Start => (vec!["start", "c1"], 5, ""),
                Command::Stop => (vec!["stop", "c1"], 5, ""),
                Command::Kill => (vec!["kill", "c1"], 5, ""),
                Command::Delete => (vec!["delete", "d1"], if linux { 0 } else { 5 }, ""),
                Command::List => (
                    vec!["list"],
                    if linux { 0 } else { 5 },
                    if linux {
                        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
                    } else {
                        ""
                    },
                ),
                Command::Logs => (vec!["logs", "c1"], if linux { 0 } else { 5 }, ""),
                // 不在 ID の inspect は Linux で NOT_FOUND(3)、非 Linux は plugin 解決の失敗(5)。出力は無い。
                Command::Inspect => (vec!["inspect", "none"], if linux { 3 } else { 5 }, ""),
                // state も inspect と同じ(不在 ID は Linux で NOT_FOUND(3)、非 Linux は plugin 解決の失敗(5)。#1903)。
                Command::State => (vec!["state", "none"], if linux { 3 } else { 5 }, ""),
                Command::Image => (
                    vec!["image", "ls", "--image-root", &ir],
                    if linux { 0 } else { 5 },
                    if linux {
                        "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n"
                    } else {
                        ""
                    },
                ),
                Command::System => (
                    vec!["system", "df", "--image-root", &ir],
                    if linux { 0 } else { 5 },
                    if linux { SYSTEM_DF_EMPTY } else { "" },
                ),
                // network は Linux 以外では状態ルートも作らず UNIMPLEMENTED(8。#3066・NET-6)。
                Command::Network => (
                    vec!["network", "ls"],
                    if linux { 0 } else { 8 },
                    if linux { "NAME\tMODE\tSUBNET\n" } else { "" },
                ),
                Command::Setup | Command::Doctor => continue,
            };
            let (code, out, err) = invoke(&root, &argv);
            assert_eq!(out, stdout, "{}", command.as_str());
            assert_eq!(code, exit, "{}: {err}", command.as_str());
            assert_eq!(
                setup_markers_in(&out),
                Vec::<String>::new(),
                "stdout of {}",
                command.as_str()
            );
            assert_eq!(
                setup_markers_in(&err),
                Vec::<String>::new(),
                "stderr of {}: {err}",
                command.as_str()
            );
            seen.push(command.as_str());
        }
        assert_eq!(
            seen,
            [
                "create", "start", "stop", "kill", "delete", "list", "logs", "inspect", "state",
                "image", "system", "network"
            ]
        );
        // 日常操作は OS 固有設定を要求しないが、plugin 拒否の監査記録先（`<状態ルート>/@audit.log`。SEC-4）を
        // 作る際に `FileStateStore::open` が状態ルートを 0700 で作る。macOS は FileStateStore 対応済み（OCI-5）で作り、
        // Windows は未対応（Unimplemented。fail-closed）で何も作らない。
        if cfg!(target_os = "macos") {
            assert!(root.is_dir(), "state root must be created on macOS");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&root)
                    .expect("metadata")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o700);
            }
        } else if !linux {
            assert!(!root.exists(), "state root must not be created on Windows");
        }
    }

    /// CLI-2・TASK-80.3: 検出器が空虚でないこと（setup 自身の出力はマーカーとして検出される）。
    #[test]
    fn cli2_setup_marker_detection_is_not_vacuous() {
        let (_, win) = out_of(SetupPlatform::Windows);
        assert_eq!(
            setup_markers_in(&win),
            [
                "{\"step\":",
                "wsl2-enable",
                "developer-mode",
                "wslconfig-virtiofs",
                "wsl",
                "developer mode",
                "virtiofs",
                "setup"
            ]
        );
        assert!(setup_markers_in(&win).contains(&"wsl2-enable".to_owned()));
        let (_, mac) = out_of(SetupPlatform::Macos);
        assert!(setup_markers_in(&mac).contains(&"virtualization-entitlement".to_owned()));
        assert!(setup_markers_in(&mac).contains(&"entitlement".to_owned()));
        assert!(
            setup_markers_in(&step_line(SetupStep::Wsl2Enable)).contains(&"{\"step\":".to_owned())
        );
        let (_, linux) = out_of(SetupPlatform::Linux);
        assert!(setup_markers_in(&linux).contains(&"privileged-launcher-install".to_owned()));
        assert!(setup_markers_in(&linux).contains(&"{\"step\":".to_owned()));
        assert_eq!(setup_markers_in("created c1"), Vec::<String>::new());
    }

    /// CLI-2・SUP-14: 本 module の本番コードは外部コマンドを起動しない（setcap・chmod・スクリプト実行をしない）。
    #[test]
    fn cli2_setup_does_not_spawn_processes() {
        let src = include_str!("setup.rs");
        let marker = ["#[cfg(", "test)]"].concat();
        let prod = src.split(marker.as_str()).next().expect("split");
        assert!(prod.len() < src.len(), "test boundary not found");
        let banned = [
            ["process", "::Command"].concat(),
            ["Command", "::new"].concat(),
            [".spa", "wn("].concat(),
            ["set", "cap"].concat(),
        ];
        for token in &banned {
            // doc コメントは「setcap を実行しない」と述べるため、コメント行以外のコードだけを見る。
            let hit = prod
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains(token.as_str()));
            assert!(!hit, "banned token {token}");
        }
    }

    /// SUP-14・REPAIR-12: 表示する使い方の引数がインストールスクリプトの実際の引数と食い違わない。
    #[test]
    fn sup14_launcher_install_instructions_match_script_usage() {
        let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("install-privileged-launcher.sh");
        let script = std::fs::read_to_string(&script_path).expect("read script");
        let text = SetupStep::PrivilegedLauncherInstall
            .instructions()
            .expect("instructions");
        let mut opts: Vec<&str> = text
            .split_whitespace()
            .map(|w| w.trim_start_matches('['))
            .filter(|w| w.starts_with("--"))
            .collect();
        opts.sort_unstable();
        assert_eq!(
            opts,
            [
                "--cli",
                "--cli-sha256",
                "--dest-dir",
                "--launcher",
                "--launcher-sha256",
                "--supervisor",
                "--supervisor-sha256"
            ]
        );
        for o in &opts {
            assert!(script.contains(&format!("    {o}) ")), "script lacks {o}");
        }
        assert!(script.contains("DEFAULT_DEST_DIR=\"/usr/local/libexec/fandhe-container\""));
        assert!(text.contains("default dest-dir /usr/local/libexec/fandhe-container"));
    }
}
