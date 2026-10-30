//! `create` の `--pasta-path` / `--pasta-path-search` の判定・解決・検証（NET-9・CLI-1・PLUG-11・SEC-4・#3199）。
//!
//! # 役割と呼び出し文脈
//!
//! `create_start::run_create` が `production_runtime` へ渡す `build` クロージャの中で、`--network` の形式検証
//! （`create_network::check_network_options`）の後・`UNIMPLEMENTED` の拒否（`reject_not_wired`）の前に
//! [`resolve_for_create`] を呼ぶ。状態ルートの作成より前に拒否するため（D2）。結果の [`PastaRecord`] は
//! `create_options::document_of` が起動オプション文書 `FCOPT1` の kind `pasta` へ書き、supervisor が起動時に
//! 辿り直して照合する（`docs/design/rootless-network.md` 12.4・12.5・12.14）。
//!
//! # 判定表（`decide`）
//!
//! | `--network` | インストール | フラグ | 結果 |
//! | ----------- | ------------ | ------ | ---- |
//! | ユーザー定義名でない | 問わない | あり | `InvalidArgument`（効かない指定を黙って受けない） |
//! | ユーザー定義名でない | 問わない | なし | 何もしない（従来どおり） |
//! | ユーザー定義名 | Linux 以外 | あり | `Unimplemented`（net の固定文言。CLI-1） |
//! | ユーザー定義名 | Linux 以外 | なし | 何もしない（後段の `UNIMPLEMENTED` に任せる） |
//! | ユーザー定義名 | rootful（euid 0 または信頼できる隣のランチャー） | あり | `InvalidArgument`（rootful は pasta を使わない。D13） |
//! | ユーザー定義名 | rootful | なし | 何もしない（後段の `UNIMPLEMENTED`） |
//! | ユーザー定義名 | 隣のランチャーが信頼できない | 問わない | `FailedPrecondition`（直接経路へ落とさない。SUP-14） |
//! | ユーザー定義名 | rootless | なし | `FailedPrecondition`（`pasta path is not configured`。既定のパスは持たない） |
//! | ユーザー定義名 | rootless | あり | 解決して検証する |
//!
//! インストールの種別（`current_exe` と隣のランチャーの stat）は、フラグがあるか `--network` がユーザー定義名の
//! ときだけ求める（それ以外の `create` には足さない）。種別は `start` と同じ `classify_launcher_beside` で決める。
//!
//! # 解決と検証
//!
//! `--pasta-path` は net の `verify_pasta_binary`、`--pasta-path-search` は `search_pasta_in_path`（CLI 自身の `PATH`）で
//! 解決・検証する（所有者・権限・祖先の symlink・版の検査は net が担う。CLI は規則を二重に持たない）。`PATH` 探索で採った
//! パスは警告 1 行を stderr へ出す（12.5。パスは無害化して上限を置く）。net のエラーはコードを保って写す
//! （`NetErrorCode` を `Internal` に潰さない）。メッセージは固定の英文で、パス・入力値を含めない。
//!
//! # 将来仕様・残余（REPAIR-3）
//!
//! - `--network` のユーザー定義名は #3329 まで最終的に `UNIMPLEMENTED` で拒否されるため、本番の `create` が `pasta` の記録を
//!   書くのは #3329 で行う。記録の消費（起動時の再検証・pasta の起動）は supervisor 側で #1940 により実装済み。
//! - SEC-4 の監査（作成時の `PermissionDenied`）は記録先が状態ストアを開いた後にしか作れず、D2（状態ルートを作る前の拒否）と
//!   両立しないため、本段では記録しない（設計判断。#3330 の範囲でも対象外）。起動時の識別の不一致と権限違反の監査は supervisor の start が #3330 で実装済み。

use std::ffi::OsStr;

use fandhe_container_core::oci_runtime::OCI_ERROR_MESSAGE_MAX_BYTES;
use fandhe_container_core::sanitize::sanitize_display_bounded;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::pasta::binary::{PastaBinary, search_pasta_in_path, verify_pasta_binary};
use fandhe_container_net::pasta::record::PastaRecord;

use super::args::{GlobalArgs, PastaSource};
use super::stop_delete::{WARNING_WRITE_TIMEOUT, emit_warning_bounded, write_warning_to_stderr};
use crate::json::json_escape;

/// rootless のユーザー定義ネットワークなのにどちらのフラグも無い（既定のパスは持たない。12.4）。
pub(super) const MSG_NOT_CONFIGURED: &str = "pasta path is not configured";
/// `create` 以外のサブコマンドに pasta のフラグがある。
pub(super) const MSG_FLAG_NOT_CREATE: &str =
    "--pasta-path and --pasta-path-search apply only to the create command";
/// `create` でも効かない指定（ユーザー定義名でない・rootful）。
const MSG_NOT_APPLICABLE: &str = "--pasta-path and --pasta-path-search apply only to a user-defined network on a rootless install";
/// 隣のランチャーが信頼できない（`start` と同じ文言。直接経路へ落とさない。SUP-14）。
const MSG_UNTRUSTED_LAUNCHER: &str = "privileged launcher is not a trusted executable (must be a regular file owned by root or the current user, not writable by group or others)";
/// CLI 自身の実行ファイルの場所を決められない。
#[cfg(target_os = "linux")]
const MSG_EXE_UNRESOLVABLE: &str = "failed to locate the CLI executable";
/// `PATH` 探索の警告の `code`・`message`（固定）。
const WARN_CODE: &str = "PASTA_PATH_CANDIDATE";
const WARN_MESSAGE: &str = "pasta was taken from PATH because --pasta-path-search was given; verify it is the intended binary";

/// インストールの種別（`decide` の入力）。
// 種別の作り手 `detect_install` は OS ごとに一部の variant しか作らない(判定表の試験は全件を使う)。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InstallKind {
    /// 隣にランチャーが無い（rootless）。
    Rootless,
    /// euid 0 または信頼できる隣のランチャーがある（rootful）。
    Rootful,
    /// 隣のランチャーが在るが信頼できない。
    UntrustedLauncher,
    /// Linux 以外（Linux のビルドでは `detect_install` が作らず、判定表の試験だけが使う）。
    NonLinux,
}

fn terr(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

/// 判定表（モジュール doc）。解決が要るときだけ `Some(source)` を返す。
pub(super) fn decide(
    pasta: Option<&PastaSource>,
    named_network: bool,
    install: InstallKind,
) -> Result<Option<&PastaSource>, TraitError> {
    if !named_network {
        return match pasta {
            Some(_) => Err(terr(ErrorCode::InvalidArgument, MSG_NOT_APPLICABLE)),
            None => Ok(None),
        };
    }
    match (install, pasta) {
        (InstallKind::NonLinux, Some(_)) => Err(terr(
            ErrorCode::Unimplemented,
            fandhe_container_net::pasta::binary::MSG_UNSUPPORTED_OS,
        )),
        (InstallKind::NonLinux, None) => Ok(None),
        (InstallKind::Rootful, Some(_)) => {
            Err(terr(ErrorCode::InvalidArgument, MSG_NOT_APPLICABLE))
        }
        (InstallKind::Rootful, None) => Ok(None),
        (InstallKind::UntrustedLauncher, _) => {
            Err(terr(ErrorCode::FailedPrecondition, MSG_UNTRUSTED_LAUNCHER))
        }
        (InstallKind::Rootless, Some(source)) => Ok(Some(source)),
        (InstallKind::Rootless, None) => {
            Err(terr(ErrorCode::FailedPrecondition, MSG_NOT_CONFIGURED))
        }
    }
}

/// net のエラーをコードを保ったまま写す（実体は supervisor の `net_error`。cli と plugin-cri で共有。REPAIR-1）。
use fandhe_container_supervisor::net_error::net_error_to_trait_keeping_code as net_error_to_trait;

/// `PATH` 探索の警告 1 行（JSON。`path` は無害化して上限を置く。12.5・PLUG-11）。
pub(super) fn path_warning_line(bin: &PastaBinary) -> String {
    warning_line_for(bin.path())
}

/// [`path_warning_line`] の本体（`PastaBinary` を作れない試験のためにパスで受ける）。
fn warning_line_for(path: &std::path::Path) -> String {
    let path = sanitize_display_bounded(&path.to_string_lossy(), OCI_ERROR_MESSAGE_MAX_BYTES);
    format!(
        "{{\"level\":\"warn\",\"code\":\"{WARN_CODE}\",\"message\":\"{WARN_MESSAGE}\",\"path\":\"{}\"}}",
        json_escape(path.as_str())
    )
}

/// 指定から pasta を解決・検証する。`PATH` 探索なら警告の行も返す（出力は呼び出し側）。
pub(super) fn resolve_source(
    source: &PastaSource,
    path_env: Option<&OsStr>,
) -> Result<(PastaBinary, Option<String>), TraitError> {
    match source {
        PastaSource::Path(p) => verify_pasta_binary(p)
            .map(|b| (b, None))
            .map_err(|e| net_error_to_trait(&e)),
        PastaSource::PathSearch => search_pasta_in_path(path_env)
            .map(|(b, _warning)| {
                let line = path_warning_line(&b);
                (b, Some(line))
            })
            .map_err(|e| net_error_to_trait(&e)),
    }
}

#[cfg(target_os = "linux")]
fn detect_install() -> Result<InstallKind, TraitError> {
    use fandhe_container_supervisor::control::listener::effective_uid;
    use fandhe_container_supervisor::start_client::{LauncherPresence, classify_launcher_beside};
    let euid = effective_uid()?;
    if euid == 0 {
        return Ok(InstallKind::Rootful);
    }
    let exe = std::env::current_exe()
        .map_err(|_| terr(ErrorCode::FailedPrecondition, MSG_EXE_UNRESOLVABLE))?;
    match classify_launcher_beside(&exe, euid) {
        Ok(LauncherPresence::Absent) => Ok(InstallKind::Rootless),
        Ok(LauncherPresence::Trusted(_)) => Ok(InstallKind::Rootful),
        Ok(_) => Ok(InstallKind::UntrustedLauncher),
        Err(_) => Err(terr(ErrorCode::FailedPrecondition, MSG_EXE_UNRESOLVABLE)),
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_install() -> Result<InstallKind, TraitError> {
    Ok(InstallKind::NonLinux)
}

/// `create` で pasta の指定を判定し、必要なら解決・検証した記録を返す（モジュール doc）。
///
/// フラグも無くユーザー定義名でもない `create` では何も調べない（`current_exe` も stat も足さない）。
pub(super) fn resolve_for_create(
    global: &GlobalArgs,
    named_network: bool,
) -> Result<Option<PastaRecord>, TraitError> {
    if global.pasta.is_none() && !named_network {
        return Ok(None);
    }
    // ユーザー定義名でなければインストールの種別は結果を変えない（フラグありは InvalidArgument）。
    let install = if named_network {
        detect_install()?
    } else {
        InstallKind::Rootless
    };
    let Some(source) = decide(global.pasta.as_ref(), named_network, install)? else {
        return Ok(None);
    };
    let (bin, warning) = resolve_source(source, std::env::var_os("PATH").as_deref())?;
    if let Some(line) = warning {
        emit_warning_bounded(line, write_warning_to_stderr, WARNING_WRITE_TIMEOUT);
    }
    Ok(Some(bin.record()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use std::path::PathBuf;

    fn path_src() -> PastaSource {
        PastaSource::Path(PathBuf::from("/usr/bin/pasta"))
    }

    fn outcome(
        pasta: Option<&PastaSource>,
        named: bool,
        install: InstallKind,
    ) -> Result<bool, (ErrorCode, String)> {
        decide(pasta, named, install)
            .map(|r| r.is_some())
            .map_err(|e| (e.code(), e.message().to_owned()))
    }

    /// NET-9・CLI-1(#3199): 判定表の全件。
    #[test]
    fn net9_cli1_pasta_decide_table() {
        use ErrorCode as C;
        use InstallKind as I;
        let src = path_src();
        let search = PastaSource::PathSearch;
        let na = MSG_NOT_APPLICABLE.to_owned();
        for i in [I::Rootless, I::Rootful, I::UntrustedLauncher, I::NonLinux] {
            assert_eq!(outcome(None, false, i), Ok(false), "{i:?}");
            for s in [&src, &search] {
                assert_eq!(
                    outcome(Some(s), false, i),
                    Err((C::InvalidArgument, na.clone())),
                    "{i:?}"
                );
            }
        }
        assert_eq!(
            outcome(Some(&src), true, I::NonLinux),
            Err((
                C::Unimplemented,
                "pasta is only supported on Linux".to_owned()
            ))
        );
        assert_eq!(outcome(None, true, I::NonLinux), Ok(false));
        assert_eq!(
            outcome(Some(&search), true, I::Rootful),
            Err((C::InvalidArgument, na))
        );
        assert_eq!(outcome(None, true, I::Rootful), Ok(false));
        for s in [None, Some(&src)] {
            assert_eq!(
                outcome(s, true, I::UntrustedLauncher),
                Err((C::FailedPrecondition, MSG_UNTRUSTED_LAUNCHER.to_owned()))
            );
        }
        assert_eq!(
            outcome(None, true, I::Rootless),
            Err((
                C::FailedPrecondition,
                "pasta path is not configured".to_owned()
            ))
        );
        assert_eq!(outcome(Some(&src), true, I::Rootless), Ok(true));
        assert_eq!(outcome(Some(&search), true, I::Rootless), Ok(true));
    }

    /// NET-9(#3199): net のコードを潰さずに写す。
    #[test]
    fn net9_pasta_net_error_mapping() {
        let cases = [
            (NetErrorCode::NotFound, ErrorCode::NotFound),
            (NetErrorCode::PermissionDenied, ErrorCode::PermissionDenied),
            (
                NetErrorCode::FailedPrecondition,
                ErrorCode::FailedPrecondition,
            ),
            (NetErrorCode::Timeout, ErrorCode::Timeout),
            (NetErrorCode::InvalidArgument, ErrorCode::InvalidArgument),
            (NetErrorCode::Internal, ErrorCode::Internal),
        ];
        for (n, t) in cases {
            let e = net_error_to_trait(&NetError::new(n, "fixed"));
            assert_eq!((e.code(), e.message()), (t, "fixed"));
        }
    }

    /// NET-9・PLUG-11(#3199): 解決の失敗は net のコードと固定文言のまま届く。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_plug11_resolve_source_failures_keep_codes() {
        let e = resolve_source(&PastaSource::Path("relative/pasta".into()), None)
            .map(|_| ())
            .expect_err("relative");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let e = resolve_source(&PastaSource::PathSearch, Some(OsStr::new("")))
            .map(|_| ())
            .expect_err("empty PATH");
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::NotFound, "pasta was not found in PATH")
        );
        let e = resolve_source(&PastaSource::Path("/nonexistent-dir/pasta".into()), None)
            .map(|_| ())
            .expect_err("missing");
        assert_eq!(e.code(), ErrorCode::NotFound);
    }

    /// PLUG-11(#3199): 警告は固定の code / message と無害化したパスの 1 行 JSON。
    #[test]
    fn plug11_pasta_path_warning_line_shape() {
        let line = warning_line_for(std::path::Path::new("/a\"b\\c\u{7}\n/pasta"));
        assert_eq!(
            line,
            format!(
                "{{\"level\":\"warn\",\"code\":\"PASTA_PATH_CANDIDATE\",\"message\":\"{WARN_MESSAGE}\",\"path\":\"/a\\\"b\\\\c  /pasta\"}}"
            )
        );
        assert!(!line.contains('\n'));
        let long = format!("/{}", "x".repeat(OCI_ERROR_MESSAGE_MAX_BYTES * 2));
        assert!(
            warning_line_for(std::path::Path::new(&long)).len() < OCI_ERROR_MESSAGE_MAX_BYTES + 400
        );
    }
}
