//! WSL2 検出の結合試験（`tests/wsl2_detect.rs`。TASK-67.3・WIN-1・REPAIR-5・REPAIR-12）と virtiofs 共有
//! マウントの結合試験（`tests/wsl2_mount.rs`。TASK-67.4・WIN-2）が `wsl.exe` の代わりに起動する偽の実行ファイル。
//!
//! これはテスト専用の道具であり、本物の `wsl.exe` の出力を保証するものではない（REPAIR-3。出力例は
//! 解析器のユニットテストと同じく模したもので、実機での確認は TASK-67.6・#377）。専用 feature
//! `wsl2-test-support` でのみビルドされ、リリース成果物には入らない。
//!
//! # 振る舞いの選び方
//!
//! 被試験側は固定の引数（`--version` / `-l -v`）と環境変数 `WSL_UTF8=1` しか渡さないため、振る舞い
//! （モード）は実行ファイル名 `fake_wsl-<mode>`（Windows は `.exe` 付き）から決める。結合試験は本 bin を
//! モードごとの名前でリンク（またはコピー）して渡す。
//!
//! - 引数が `--version` / `-l -v` 以外、または `WSL_UTF8` が `1` でなければ終了コード 64 / 65
//!   （被試験側が引数・環境変数を正しく渡していることの確認）
//! - 未知のモードは終了コード 2
//!
//! | モード | `--version` | `-l -v` |
//! | ---- | ---- | ---- |
//! | `ok` | 英語のバージョン（0） | 英語の一覧（0） |
//! | `utf16` | UTF-16LE（BOM 付き）のバージョン（0） | UTF-16LE（BOM 付き）の日本語の一覧（0） |
//! | `nodistro` | 英語のバージョン（0） | 0 件の案内文と `WSL_E_DEFAULT_DISTRO_NOT_FOUND`（1） |
//! | `v1only` | 英語のバージョン（0） | WSL1 のディストリのみ（0） |
//! | `disabled` | `WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED`（1） | 同左（1） |
//! | `denied` | `E_ACCESSDENIED`（1） | 同左（1） |
//! | `garbage` | 未知の形式（0） | 未知の形式（0） |
//! | `hang` | 60 秒眠る | 60 秒眠る |
//! | `flood` | 128 KiB を出力（0） | 同左（0） |
//!
//! # マウント系モード（`mount_ok` / `mount_9p` / `mount_launch` / `mount_unset`）
//!
//! `--version` / `-l -v` は `ok` と同じ。加えて `--distribution Ubuntu --user root --exec <コマンド>` を受け付け、
//! ゲストのマウント表を実行ファイルと同じ場所の `<実行ファイル名>.state`（行ごとに `ID<TAB>マウント先<TAB>
//! オプション<TAB>fstype`）に保持して、呼び出しをまたいで状態を持つ。状態ファイルが無ければ `/`（ID 1・ext4）
//! だけの表から始める。結合試験はモードごとに別の状態ファイルを使い、開始時に削除して初期化する。
//!
//! | コマンド | 振る舞い |
//! | ---- | ---- |
//! | `cat /proc/self/mountinfo` | マウント表を mountinfo 形式で出力（0） |
//! | `sh -c <検証込み mount スクリプト> sh <ホスト> <名前> <オプション> <nonce>` | `/mnt/fandhe/<名前>` に新しい ID でマウントを積み、その ID を出力する（`mount_9p` は fstype `9p`、他は `virtiofs`。0） |
//! | `sh -c <ID 照合付き umount スクリプト> sh <マウント先> <ID> <nonce>` | 最上位の ID が一致すれば外す（0）、不一致は 203 |
//!
//! スクリプト本文はゲストのシェルで解釈せず、`mount -t drvfs` / `umount "$1"` を含むかだけを確かめる
//! （本文の振る舞いはユニットテストの模擬ゲストと実機確認 TASK-67.6・#377 の担当）。

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

const EN_VERSION: &str = "WSL version: 2.1.5.0\r\nKernel version: 5.15.146.1-2\r\nWSLg version: 1.0.60\r\nWindows version: 10.0.22631.3296\r\n";
const EN_LIST: &str = "  NAME              STATE           VERSION\r\n* Ubuntu            Running         2\r\n  docker-desktop    Stopped         2\r\n  Legacy            Stopped         1\r\n";
const JA_LIST: &str =
    "  名前      状態      バージョン\r\n* Ubuntu    実行中    2\r\n  Debian    停止      2\r\n";
const V1_LIST: &str = "  NAME      STATE      VERSION\r\n* Legacy    Running    1\r\n";
const NO_DISTRO: &str = "Windows Subsystem for Linux has no installed distributions.\r\nUse 'wsl.exe --list --online' to list available distributions\r\nand 'wsl.exe --install <Distro>' to install.\r\nError code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n";
const DISABLED: &str = "The Windows Subsystem for Linux optional component is not enabled.\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n";
const DENIED: &str = "Access is denied.\r\nError code: Wsl/Service/E_ACCESSDENIED\r\n";

/// 呼び出された引数の種類。
enum Call {
    Version,
    List,
    /// `--distribution Ubuntu --user root --exec` に続くゲスト内コマンド（マウント系モードのみ受け付ける）。
    Exec(Vec<String>),
}

/// マウント表の 1 行（ID・マウント先・オプション・fstype）。
type MountRow = (u32, String, String, String);

fn state_path() -> Option<std::path::PathBuf> {
    Some(std::env::current_exe().ok()?.with_extension("state"))
}

fn load_state() -> Option<Vec<MountRow>> {
    let path = state_path()?;
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Some(vec![(1, "/".into(), "rw".into(), "ext4".into())]);
    };
    text.lines()
        .map(|l| {
            let mut f = l.split('\t');
            Some((
                f.next()?.parse().ok()?,
                f.next()?.to_string(),
                f.next()?.to_string(),
                f.next()?.to_string(),
            ))
        })
        .collect()
}

fn save_state(rows: &[MountRow]) -> Option<()> {
    let text: String = rows
        .iter()
        .map(|(id, p, o, t)| format!("{id}\t{p}\t{o}\t{t}\n"))
        .collect();
    std::fs::write(state_path()?, text).ok()
}

/// マウント系モードのゲスト内コマンドを模擬する。
fn guest_exec(mode: &str, cmd: &[&str]) -> ExitCode {
    let Some(mut rows) = load_state() else {
        return ExitCode::from(3);
    };
    match cmd {
        ["cat", "/proc/self/mountinfo"] => {
            let text: String = rows
                .iter()
                .enumerate()
                .map(|(i, (id, p, o, t))| format!("{id} 1 0:{i} / {p} {o} - {t} src rw\n"))
                .collect();
            emit(text.as_bytes(), 0)
        }
        ["sh", "-c", script, "sh", _host, name, opts, _nonce]
            if script.contains("mount -t drvfs") =>
        {
            let id = rows.iter().map(|r| r.0).max().unwrap_or(0).max(99) + 1;
            let base = if opts.split(',').any(|o| o == "ro") {
                "ro"
            } else {
                "rw"
            };
            let fstype = if mode == "mount_9p" { "9p" } else { "virtiofs" };
            rows.push((
                id,
                format!("/mnt/fandhe/{name}"),
                format!("{base},nosuid,nodev"),
                fstype.to_string(),
            ));
            if save_state(&rows).is_none() {
                return ExitCode::from(3);
            }
            // 本物のスクリプトと同じく、自分のマウント ID（mount 前後の差分）を標準出力へ書く。
            emit(format!("{id}\n").as_bytes(), 0)
        }
        ["sh", "-c", script, "sh", target, id, _nonce] if script.contains("umount \"$1\"") => {
            let top = rows.iter().rposition(|r| r.1 == *target);
            match top {
                Some(i) if rows.get(i).is_some_and(|r| r.0.to_string() == *id) => {
                    rows.remove(i);
                    save_state(&rows).map_or(ExitCode::from(3), |()| ExitCode::SUCCESS)
                }
                _ => ExitCode::from(203),
            }
        }
        _ => ExitCode::from(64),
    }
}

fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// 実行ファイル名 `fake_wsl-<mode>` からモードを取り出す。
fn mode() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let stem = exe.file_stem()?.to_str()?;
    stem.strip_prefix("fake_wsl-").map(str::to_string)
}

fn emit(bytes: &[u8], code: u8) -> ExitCode {
    let mut out = std::io::stdout().lock();
    if out.write_all(bytes).and_then(|()| out.flush()).is_err() {
        return ExitCode::from(3);
    }
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let call = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => Call::Version,
        ["-l", "-v"] => Call::List,
        [
            "--distribution",
            "Ubuntu",
            "--user",
            "root",
            "--exec",
            rest @ ..,
        ] if !rest.is_empty() => Call::Exec(rest.iter().map(|s| (*s).to_string()).collect()),
        _ => return ExitCode::from(64),
    };
    if std::env::var("WSL_UTF8").as_deref() != Ok("1") {
        return ExitCode::from(65);
    }
    let Some(mode) = mode() else {
        return ExitCode::from(2);
    };
    let mount_mode = matches!(
        mode.as_str(),
        "mount_ok" | "mount_9p" | "mount_launch" | "mount_unset"
    );
    match (mode.as_str(), call) {
        (_, Call::Exec(cmd)) if mount_mode => {
            let cmd: Vec<&str> = cmd.iter().map(String::as_str).collect();
            guest_exec(&mode, &cmd)
        }
        (_, Call::Exec(_)) => ExitCode::from(64),
        (_, Call::Version) if mount_mode => emit(EN_VERSION.as_bytes(), 0),
        (_, Call::List) if mount_mode => emit(EN_LIST.as_bytes(), 0),
        ("ok" | "nodistro" | "v1only", Call::Version) => emit(EN_VERSION.as_bytes(), 0),
        ("ok", Call::List) => emit(EN_LIST.as_bytes(), 0),
        ("utf16", Call::Version) => emit(&utf16le_with_bom(EN_VERSION), 0),
        ("utf16", Call::List) => emit(&utf16le_with_bom(JA_LIST), 0),
        ("nodistro", Call::List) => emit(NO_DISTRO.as_bytes(), 1),
        ("v1only", Call::List) => emit(V1_LIST.as_bytes(), 0),
        ("disabled", _) => emit(DISABLED.as_bytes(), 1),
        ("denied", _) => emit(DENIED.as_bytes(), 1),
        ("garbage", _) => emit(b"hello from an unknown tool\n", 0),
        ("hang", _) => {
            std::thread::sleep(Duration::from_secs(60));
            ExitCode::SUCCESS
        }
        ("flood", _) => emit(&vec![b'x'; 128 * 1024], 0),
        _ => ExitCode::from(2),
    }
}
