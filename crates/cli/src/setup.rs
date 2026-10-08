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
//! 日常操作コマンドからの切り離しは TASK-80.2 で確立済み（参照点は `commands::run_setup` のみ）。分離の単体テストは `tests::cli2_daily_commands_do_not_request_os_setup`（TASK-80.3）。

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
        return CliExit::failed(ErrorCode::Unimplemented);
    }
    let steps = required_steps(platform);
    for step in steps {
        // 1 行を 1 回の write_all で書く（行の途中へ他の出力が入らないようにする）。
        if stdout.write_all(step_line(*step).as_bytes()).is_err() {
            return CliExit::failed(ErrorCode::Internal);
        }
    }
    if steps.is_empty() {
        CliExit::Success
    } else {
        CliExit::failed(ErrorCode::Unimplemented)
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
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fc-cli-setup-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("mkdir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
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
        for p in [SetupPlatform::Windows, SetupPlatform::Macos] {
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
                Command::Start => (vec!["start", "c1"], if linux { 8 } else { 5 }, ""),
                Command::Stop => (vec!["stop", "c1"], 5, ""),
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
                Command::Logs => (vec!["logs", "c1"], if linux { 8 } else { 5 }, ""),
                Command::Setup => continue,
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
        assert_eq!(seen, ["create", "start", "stop", "delete", "list", "logs"]);
        if !linux {
            assert!(!root.exists(), "state root must not be created off Linux");
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
                "virtiofs"
            ]
        );
        assert!(setup_markers_in(&win).contains(&"wsl2-enable".to_owned()));
        let (_, mac) = out_of(SetupPlatform::Macos);
        assert!(setup_markers_in(&mac).contains(&"virtualization-entitlement".to_owned()));
        assert!(setup_markers_in(&mac).contains(&"entitlement".to_owned()));
        assert!(
            setup_markers_in(&step_line(SetupStep::Wsl2Enable)).contains(&"{\"step\":".to_owned())
        );
        assert_eq!(setup_markers_in("created c1"), Vec::<String>::new());
    }
}
