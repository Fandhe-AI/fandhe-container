//! `create` / `start` / `stop` / `delete` / `list` / `logs` / `exec` / `image` / `system` の argv 解析（TASK-79.2.1・TASK-79.2.2・TASK-79.3・CLI-1・MS-6）。
//!
//! `commands::run` が先頭のグローバルオプション（`--root`・`--plugin-path-search`。順不同）とサブコマンド名の後ろを渡して呼ぶ純粋関数群。
//! ファイルシステムにも環境にも触れず、値の意味検証（絶対パス・ID の文字種）は core の型
//! （`ContainerId`・`CreateRequest`・`StateRoot`）に委ねる（検査の二重実装を避ける。SEC-1）。
//! 構文は runc 互換: `fandhe-container [--root <dir>] create [--image-root <dir> --image <sha256:digest|name[:tag]>] --bundle <dir> <id>` / `... start <id>` / `... stop <id>` / `... delete [--force] [--image-root <dir>] <id>` / `... list` / `... logs [--follow] [--tail <N>] [--stream <stdout|stderr>] [--escape] <id>`。
//! `exec`（SUP-6・#2626）は `... exec [--env KEY=VALUE]... [--timeout <秒>] <id> <path> [<arg>...]`（オプションは `<id>` の前だけ）。
//! イメージ管理（#2221）は `image ls --image-root <dir>` / `image rm [--force] --image-root <dir> <ref>` / `image tag --image-root <dir> <source> <target>` / `system df --image-root <dir>`（`--image-root` は必須の絶対パス）。
//! 解析失敗の理由は呼び出し元で固定文言に落とし、引数値を出力へ埋め込まない（インジェクション回避）。

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use fandhe_container_supervisor::container_options::env::EnvVar;

/// グローバルオプション（サブコマンドより前）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct GlobalArgs {
    /// `--root`（状態ルートの上書き）。未指定は core の既定解決。
    pub(super) root: Option<PathBuf>,
    /// `--plugin-path-search`（macOS / Windows の plugin 発見で `PATH` 探索を opt-in する。PLUG-11）。
    ///
    /// 3 OS で同一構文を受理する（CLI-1）が、Linux は plugin を介さず core を直接呼ぶため効果はない。
    pub(super) plugin_path_search: bool,
}

/// `create` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CreateArgs {
    pub(super) bundle: PathBuf,
    pub(super) id: String,
    /// `--image-root` と `--image` の組（どちらも指定したときだけ `Some`。OCI-7・#2315）。
    pub(super) image: Option<CreateImageArgs>,
}

/// `create` のイメージ指定。意味検証（digest・タグ参照の形式、ストア root の存在）は呼び出し元が core / oci の型に委ねる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CreateImageArgs {
    /// イメージストアの root（絶対パス）。
    pub(super) image_root: PathBuf,
    /// 使うイメージの指定（未検証の文字列。manifest digest かタグ参照。判別は `image_refs::classify_create_image`）。
    pub(super) reference: String,
}

/// `start` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StartArgs {
    pub(super) id: String,
}

/// `stop` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StopArgs {
    pub(super) id: String,
}

/// `delete` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeleteArgs {
    pub(super) id: String,
    /// `--force`（core の `DeleteRequest::with_force` へ素通しする。生存中コンテナへは core が拒否する）。
    pub(super) force: bool,
    /// `--image-root`（イメージ参照を解除するストアの root。絶対パス。省略時は解除しない。OCI-7・#2315）。
    pub(super) image_root: Option<PathBuf>,
}

/// `exec` の既定の全体期限（秒。pidfd の受け渡しから終了待ちまで。REPAIR-5・SUP-6・#2626）。
pub(super) const EXEC_DEFAULT_TIMEOUT_SECS: u64 = 60;

/// `exec --timeout` に指定できる秒数の上限（超える値は使い方エラー。無制限に長い期限を受けない。REPAIR-5・#2626）。
pub(super) const EXEC_MAX_TIMEOUT_SECS: u64 = 3600;

/// `exec` の引数（SUP-6・CLI-1・#2626）。
///
/// 非 Linux の `exec` は plugin 解決の拒否に到達するだけでフィールドを読まないため、dead_code を許す
/// （3 OS で同じ構文を受理する。CLI-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) struct ExecArgs {
    pub(super) id: String,
    /// `--env KEY=VALUE`（その exec に対して明示した環境変数。指定順で後勝ち。ホスト環境は継承しない）。
    pub(super) env: Vec<EnvVar>,
    /// `--timeout <秒>`（準備から終了待ちまでの全体の期限。`1..=EXEC_MAX_TIMEOUT_SECS`）。
    pub(super) timeout: Duration,
    /// コンテナ内の実行ファイルの絶対パス（絶対パスの検証は supervisor の `ExecRequest::new` が行う。PATH 探索はしない）。
    pub(super) path: String,
    /// `argv[0]` を除く引数（argv は `[path, args...]`）。
    pub(super) args: Vec<String>,
}

/// `list` の引数（現状オプションなし。将来のオプション追加に備えて構造体にしておく。TASK-79.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListArgs;

/// `setup` の引数（オプションなし。TASK-80.1・CLI-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupArgs;

/// `doctor` の引数（オプションなし。#2133）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DoctorArgs;

/// `logs --tail` に指定できる件数の上限（supervisor の `MAX_TAIL_RECORDS` と同じ値。範囲外は使い方エラー。
/// 値の確定はオーナー確認待ち。args は OS 非依存の純粋関数群のため、定数は別に持ち、等しいことを試験で照合する）。
pub(super) const MAX_LOGS_TAIL: u32 = 1_000_000;

/// `logs --stream` の値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogStreamArg {
    Stdout,
    Stderr,
}

/// `logs` の引数（CLI-1・SUP-7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LogsArgs {
    pub(super) id: String,
    /// `--follow`（追記を期限まで追う）。
    pub(super) follow: bool,
    /// `--tail <N>`（絞り込み後の末尾 N レコード。`0..=MAX_LOGS_TAIL`）。
    pub(super) tail: Option<u32>,
    /// `--stream <stdout|stderr>`。
    pub(super) stream: Option<LogStreamArg>,
    /// `--escape`（本体の制御文字を `cat -v` と同じ表で表示用に変換）。
    pub(super) escape: bool,
}

/// `image` サブコマンドの引数（#2221・CLI-1・OCI-7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ImageArgs {
    /// `image ls --image-root <dir>`。
    Ls(ImageLsArgs),
    /// `image rm [--force] --image-root <dir> <ref>`。
    Rm(ImageRmArgs),
    /// `image tag --image-root <dir> <source> <target>`（#2316）。
    Tag(ImageTagArgs),
}

/// `image tag` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageTagArgs {
    /// イメージストアの root（絶対パス）。
    pub(super) image_root: PathBuf,
    /// 付け元（既存タグまたは manifest digest。未検証の文字列。意味検証は `image` モジュールが oci に委ねる）。
    pub(super) source: String,
    /// 付けるタグ（未検証の文字列。タグ参照だけを受ける検証は `image` モジュールが行う）。
    pub(super) target: String,
}

/// `image ls` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageLsArgs {
    /// イメージストアの root（絶対パス）。
    pub(super) image_root: PathBuf,
}

/// `image rm` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageRmArgs {
    /// イメージストアの root（絶対パス）。
    pub(super) image_root: PathBuf,
    /// `--force`（停止中のコンテナだけが参照するイメージを untag だけで通す。OCI-7）。
    pub(super) force: bool,
    /// 対象のイメージ参照（未検証の文字列。意味検証は oci の `ImageReference::parse` に委ねる）。
    pub(super) reference: String,
}

/// `system` サブコマンドの引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SystemArgs {
    /// `system df --image-root <dir>`。
    Df(SystemDfArgs),
}

/// `system df` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SystemDfArgs {
    /// イメージストアの root（絶対パス）。
    pub(super) image_root: PathBuf,
}

/// 解析失敗（使い方エラー）。理由は呼び出し元で固定文言に写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UsageError;

/// 先頭のグローバルオプションを読み、残り（サブコマンド名以降）を返す。
///
/// 現状のグローバルオプションは `--root <dir>` のみ。重複・値欠落は使い方エラー。
pub(super) fn parse_global(args: Vec<OsString>) -> Result<(GlobalArgs, Vec<OsString>), UsageError> {
    let mut global = GlobalArgs::default();
    let mut it = args.into_iter().peekable();
    loop {
        if it.peek().is_some_and(|a| a == "--root") {
            it.next();
            let value = it.next().ok_or(UsageError)?;
            if global.root.is_some() {
                return Err(UsageError);
            }
            global.root = Some(PathBuf::from(value));
        } else if it.peek().is_some_and(|a| a == "--plugin-path-search") {
            it.next();
            if global.plugin_path_search {
                return Err(UsageError);
            }
            global.plugin_path_search = true;
        } else {
            break;
        }
    }
    Ok((global, it.collect()))
}

/// `create [--image-root <abs> --image <sha256:digest|name[:tag]>] --bundle <dir> <id>` を解析する
/// （`--bundle` は必須・順不同・`--` 以降は位置引数。`--image-root` と `--image` は両方そろったときだけ受け、各 1 回まで）。
pub(super) fn parse_create(args: Vec<OsString>) -> Result<CreateArgs, UsageError> {
    let mut bundle: Option<PathBuf> = None;
    let mut image_root: Option<PathBuf> = None;
    let mut reference: Option<String> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--bundle" {
            let value = it.next().ok_or(UsageError)?;
            if bundle.is_some() {
                return Err(UsageError);
            }
            bundle = Some(PathBuf::from(value));
        } else if a == "--image-root" {
            let value = it.next().ok_or(UsageError)?;
            if image_root.is_some() {
                return Err(UsageError);
            }
            image_root = Some(PathBuf::from(value));
        } else if a == "--image" {
            let value = it.next().ok_or(UsageError)?;
            if reference.is_some() {
                return Err(UsageError);
            }
            reference = Some(value.into_string().map_err(|_| UsageError)?);
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    let id = single_id(positional)?;
    let image = match (image_root, reference) {
        (None, None) => None,
        (Some(image_root), Some(reference)) => {
            // 相対パスは作業ディレクトリ依存で 3 OS の挙動がぶれるため拒否する（`parse_image_options` と同じ）。
            if !image_root.is_absolute() {
                return Err(UsageError);
            }
            Some(CreateImageArgs {
                image_root,
                reference,
            })
        }
        _ => return Err(UsageError),
    };
    Ok(CreateArgs {
        bundle: bundle.ok_or(UsageError)?,
        id,
        image,
    })
}

/// `start <id>` を解析する。
pub(super) fn parse_start(args: Vec<OsString>) -> Result<StartArgs, UsageError> {
    Ok(StartArgs {
        id: single_positional(args)?,
    })
}

/// `stop <id>` を解析する（オプションは受け付けない）。
pub(super) fn parse_stop(args: Vec<OsString>) -> Result<StopArgs, UsageError> {
    Ok(StopArgs {
        id: single_positional(args)?,
    })
}

/// `exec [--env KEY=VALUE]... [--timeout <秒>] [--] <id> <path> [<arg>...]` を解析する（SUP-6・CLI-1・#2626）。
///
/// オプションは `<id>` より前だけで受ける（`<id>` の後ろはすべてコマンドの引数で、`-l` のようなオプション風の語も
/// そのまま渡す。docker exec と同じ）。`--env` は何回でも、`--timeout` は 1 回まで。`--env` の値は `EnvVar::parse` で検証する
/// （値なしの `KEY` によるホスト環境の継承・NUL・空のキーは使い方エラー）。`--timeout` は `1..=EXEC_MAX_TIMEOUT_SECS` の
/// 10 進整数。`<path>` は必須（空でないこと以外の検証は supervisor の `ExecRequest::new`）。
pub(super) fn parse_exec(args: Vec<OsString>) -> Result<ExecArgs, UsageError> {
    let mut env: Vec<EnvVar> = Vec::new();
    let mut timeout: Option<Duration> = None;
    let mut it = args.into_iter();
    let id = loop {
        let a = it.next().ok_or(UsageError)?;
        if a == "--" {
            break it.next().ok_or(UsageError)?;
        } else if a == "--env" {
            let value = it
                .next()
                .ok_or(UsageError)?
                .into_string()
                .map_err(|_| UsageError)?;
            env.push(EnvVar::parse(&value).map_err(|_| UsageError)?);
        } else if a == "--timeout" {
            let value = it
                .next()
                .ok_or(UsageError)?
                .into_string()
                .map_err(|_| UsageError)?;
            if timeout.is_some() {
                return Err(UsageError);
            }
            let secs: u64 = value.parse().map_err(|_| UsageError)?;
            if !(1..=EXEC_MAX_TIMEOUT_SECS).contains(&secs) {
                return Err(UsageError);
            }
            timeout = Some(Duration::from_secs(secs));
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            break a;
        }
    };
    let id = id.into_string().map_err(|_| UsageError)?;
    let path = it
        .next()
        .ok_or(UsageError)?
        .into_string()
        .map_err(|_| UsageError)?;
    if path.is_empty() {
        return Err(UsageError);
    }
    let rest = it
        .map(|a| a.into_string().map_err(|_| UsageError))
        .collect::<Result<Vec<String>, UsageError>>()?;
    Ok(ExecArgs {
        id,
        env,
        timeout: timeout.unwrap_or(Duration::from_secs(EXEC_DEFAULT_TIMEOUT_SECS)),
        path,
        args: rest,
    })
}

/// `delete [--force] [--image-root <abs>] <id>` を解析する（各オプションは 1 回だけ・順不同・`--` 以降は位置引数）。
pub(super) fn parse_delete(args: Vec<OsString>) -> Result<DeleteArgs, UsageError> {
    let mut force = false;
    let mut image_root: Option<PathBuf> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--force" {
            if force {
                return Err(UsageError);
            }
            force = true;
        } else if a == "--image-root" {
            let value = it.next().ok_or(UsageError)?;
            if image_root.is_some() {
                return Err(UsageError);
            }
            image_root = Some(PathBuf::from(value));
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    if image_root.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err(UsageError);
    }
    Ok(DeleteArgs {
        id: single_id(positional)?,
        force,
        image_root,
    })
}

/// `list` を解析する（位置引数・オプションとも受け付けない。`--` 単独のみ許容）。
pub(super) fn parse_list(args: Vec<OsString>) -> Result<ListArgs, UsageError> {
    let mut it = args.into_iter();
    match it.next() {
        None => Ok(ListArgs),
        Some(a) if a == "--" && it.next().is_none() => Ok(ListArgs),
        Some(_) => Err(UsageError),
    }
}

/// `setup` を解析する（位置引数・オプションとも受け付けない。`--` 単独のみ許容）。
pub(super) fn parse_setup(args: Vec<OsString>) -> Result<SetupArgs, UsageError> {
    let mut it = args.into_iter();
    match it.next() {
        None => Ok(SetupArgs),
        Some(a) if a == "--" && it.next().is_none() => Ok(SetupArgs),
        Some(_) => Err(UsageError),
    }
}

/// `doctor` を解析する（位置引数・オプションとも受け付けない。`--` 単独のみ許容）。
pub(super) fn parse_doctor(args: Vec<OsString>) -> Result<DoctorArgs, UsageError> {
    let mut it = args.into_iter();
    match it.next() {
        None => Ok(DoctorArgs),
        Some(a) if a == "--" && it.next().is_none() => Ok(DoctorArgs),
        Some(_) => Err(UsageError),
    }
}

/// `logs [--follow] [--tail <N>] [--stream <stdout|stderr>] [--escape] [--] <id>` を解析する。
/// オプションは順不同で各 1 回まで（重複は使い方エラー）。長い形だけを受け、`-f` / `-n` は使い方エラー。
/// `--tail` の値は 10 進数字だけ（符号・空白・`all` は拒否）で `0..=MAX_LOGS_TAIL`。
pub(super) fn parse_logs(args: Vec<OsString>) -> Result<LogsArgs, UsageError> {
    let mut follow = false;
    let mut tail: Option<u32> = None;
    let mut stream: Option<LogStreamArg> = None;
    let mut escape = false;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--follow" {
            if follow {
                return Err(UsageError);
            }
            follow = true;
        } else if a == "--escape" {
            if escape {
                return Err(UsageError);
            }
            escape = true;
        } else if a == "--tail" {
            let value = it.next().ok_or(UsageError)?;
            if tail.is_some() {
                return Err(UsageError);
            }
            tail = Some(parse_tail_count(&value)?);
        } else if a == "--stream" {
            let value = it.next().ok_or(UsageError)?;
            if stream.is_some() {
                return Err(UsageError);
            }
            stream = Some(if value == "stdout" {
                LogStreamArg::Stdout
            } else if value == "stderr" {
                LogStreamArg::Stderr
            } else {
                return Err(UsageError);
            });
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    Ok(LogsArgs {
        id: single_id(positional)?,
        follow,
        tail,
        stream,
        escape,
    })
}

/// `--tail` の値（10 進数字だけ・`0..=MAX_LOGS_TAIL`）。
fn parse_tail_count(value: &OsString) -> Result<u32, UsageError> {
    let s = value.to_str().ok_or(UsageError)?;
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError);
    }
    let n: u32 = s.parse().map_err(|_| UsageError)?;
    if n > MAX_LOGS_TAIL {
        return Err(UsageError);
    }
    Ok(n)
}

/// `image <ls|rm|tag> ...` を解析する（サブコマンド無し・未知は使い方エラー）。
pub(super) fn parse_image(args: Vec<OsString>) -> Result<ImageArgs, UsageError> {
    let mut it = args.into_iter();
    let sub = it.next().ok_or(UsageError)?;
    let rest: Vec<OsString> = it.collect();
    if sub == "ls" {
        let (image_root, _, positional) = parse_image_options(rest, false)?;
        if !positional.is_empty() {
            return Err(UsageError);
        }
        Ok(ImageArgs::Ls(ImageLsArgs { image_root }))
    } else if sub == "rm" {
        let (image_root, force, positional) = parse_image_options(rest, true)?;
        Ok(ImageArgs::Rm(ImageRmArgs {
            image_root,
            force,
            reference: single_id(positional)?,
        }))
    } else if sub == "tag" {
        let (image_root, _, positional) = parse_image_options(rest, false)?;
        let (source, target) = two_positionals(positional)?;
        Ok(ImageArgs::Tag(ImageTagArgs {
            image_root,
            source,
            target,
        }))
    } else {
        Err(UsageError)
    }
}

/// `system df --image-root <dir>` を解析する。
pub(super) fn parse_system(args: Vec<OsString>) -> Result<SystemArgs, UsageError> {
    let mut it = args.into_iter();
    let sub = it.next().ok_or(UsageError)?;
    if sub != "df" {
        return Err(UsageError);
    }
    let (image_root, _, positional) = parse_image_options(it.collect(), false)?;
    if !positional.is_empty() {
        return Err(UsageError);
    }
    Ok(SystemArgs::Df(SystemDfArgs { image_root }))
}

/// image 系サブコマンド共通のオプション解析。`--image-root <dir>`（必須・1 回・絶対パスのみ）と、
/// `allow_force` のときの `--force`（1 回）を読み、残りの位置引数を返す。`--` 以降は位置引数。
/// 値の意味検証（存在・ディレクトリか）は oci の `ImageStore::open` に委ね、ここでは作らない・辿らない。
fn parse_image_options(
    args: Vec<OsString>,
    allow_force: bool,
) -> Result<(PathBuf, bool, Vec<OsString>), UsageError> {
    let mut image_root: Option<PathBuf> = None;
    let mut force = false;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--image-root" {
            let value = it.next().ok_or(UsageError)?;
            if image_root.is_some() {
                return Err(UsageError);
            }
            image_root = Some(PathBuf::from(value));
        } else if allow_force && a == "--force" {
            if force {
                return Err(UsageError);
            }
            force = true;
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    let image_root = image_root.ok_or(UsageError)?;
    // 相対パスは作業ディレクトリ依存で 3 OS の挙動がぶれるため、使い方エラーとして拒否する。
    if !image_root.is_absolute() {
        return Err(UsageError);
    }
    Ok((image_root, force, positional))
}

/// オプションを持たないコマンドの位置引数 1 個を取り出す（`--` 以降は位置引数、`-` 始まりは拒否）。
fn single_positional(args: Vec<OsString>) -> Result<String, UsageError> {
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    single_id(positional)
}

/// `-` で始まる UTF-8 引数はオプションとして扱う（未知オプションを ID と取り違えない）。
/// 非 UTF-8 は位置引数として残り、`single_id` で拒否される。
fn is_option_like(a: &OsString) -> bool {
    a.to_str().is_some_and(|s| s.starts_with('-'))
}

/// 位置引数がちょうど 1 個の UTF-8 文字列であることを確かめる。
fn single_id(mut positional: Vec<OsString>) -> Result<String, UsageError> {
    if positional.len() != 1 {
        return Err(UsageError);
    }
    positional
        .pop()
        .and_then(|v| v.into_string().ok())
        .ok_or(UsageError)
}

/// 位置引数がちょうど 2 個の UTF-8 文字列であることを確かめる（`image tag <source> <target>`）。
fn two_positionals(positional: Vec<OsString>) -> Result<(String, String), UsageError> {
    let [a, b]: [OsString; 2] = positional.try_into().map_err(|_| UsageError)?;
    Ok((
        a.into_string().map_err(|_| UsageError)?,
        b.into_string().map_err(|_| UsageError)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    /// CLI-1: グローバル `--root` は先頭のみ読み、残りを返す。
    #[test]
    fn cli1_parse_global_root() {
        let (g, rest) = parse_global(v(&["--root", "/r", "start", "a"])).expect("ok");
        assert_eq!(g.root, Some(PathBuf::from("/r")));
        assert_eq!(rest, v(&["start", "a"]));
        let (g, rest) = parse_global(v(&["start"])).expect("ok");
        assert_eq!(g.root, None);
        assert_eq!(rest, v(&["start"]));
    }

    /// CLI-1: `--root` の値欠落・重複は使い方エラー。
    #[test]
    fn cli1_parse_global_rejects_missing_and_duplicate() {
        assert_eq!(parse_global(v(&["--root"])), Err(UsageError));
        assert_eq!(
            parse_global(v(&["--root", "/a", "--root", "/b", "start"])),
            Err(UsageError)
        );
    }

    /// PLUG-11・CLI-1: `--plugin-path-search` は `--root` と順不同で受理し、重複は使い方エラー。
    #[test]
    fn plug11_parse_global_plugin_path_search() {
        let (g, rest) =
            parse_global(v(&["--plugin-path-search", "--root", "/r", "list"])).expect("ok");
        assert!(g.plugin_path_search);
        assert_eq!(g.root, Some(PathBuf::from("/r")));
        assert_eq!(rest, v(&["list"]));
        let (g, _) =
            parse_global(v(&["--root", "/r", "--plugin-path-search", "list"])).expect("ok");
        assert!(g.plugin_path_search);
        let (g, _) = parse_global(v(&["list"])).expect("ok");
        assert!(!g.plugin_path_search);
        assert_eq!(
            parse_global(v(&["--plugin-path-search", "--plugin-path-search", "list"])),
            Err(UsageError)
        );
    }

    /// OCI-7・CLI-1: create の `--image-root` と `--image` は両方そろったときだけ受け、順不同・各 1 回。
    #[test]
    fn oci7_parse_create_image_options() {
        let root = std::env::temp_dir();
        let r = root.to_str().unwrap();
        let d = format!("sha256:{}", "a".repeat(64));
        let expect = Ok(CreateArgs {
            bundle: PathBuf::from("/b"),
            id: "c1".into(),
            image: Some(CreateImageArgs {
                image_root: root.clone(),
                reference: d.clone(),
            }),
        });
        assert_eq!(
            parse_create(v(&[
                "--image-root",
                r,
                "--image",
                &d,
                "--bundle",
                "/b",
                "c1"
            ])),
            expect
        );
        assert_eq!(
            parse_create(v(&[
                "--bundle",
                "/b",
                "--image",
                &d,
                "--image-root",
                r,
                "--",
                "c1"
            ])),
            expect
        );
        for bad in [
            v(&["--bundle", "/b", "--image", &d, "c1"]),
            v(&["--bundle", "/b", "--image-root", r, "c1"]),
            v(&["--bundle", "/b", "--image-root", "rel", "--image", &d, "c1"]),
            v(&[
                "--bundle",
                "/b",
                "--image-root",
                "/i",
                "--image-root",
                "/i",
                "--image",
                &d,
                "c1",
            ]),
            v(&[
                "--bundle",
                "/b",
                "--image-root",
                "/i",
                "--image",
                &d,
                "--image",
                &d,
                "c1",
            ]),
            v(&["--bundle", "/b", "--image-root", "/i", "--image"]),
            v(&["--bundle", "/b", "--", "--image", "c1"]),
        ] {
            assert_eq!(parse_create(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// OCI-7・CLI-1: delete の `--image-root` は任意・絶対パスのみ・1 回まで。
    #[test]
    fn oci7_parse_delete_image_root() {
        let root = std::env::temp_dir();
        let r = root.to_str().unwrap();
        assert_eq!(
            parse_delete(v(&["--image-root", r, "--force", "c1"])),
            Ok(DeleteArgs {
                id: "c1".into(),
                force: true,
                image_root: Some(root.clone()),
            })
        );
        for bad in [
            v(&["--image-root", "rel", "c1"]),
            v(&["--image-root", "/a", "--image-root", "/b", "c1"]),
            v(&["--image-root"]),
        ] {
            assert_eq!(parse_delete(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// CLI-1: create の正常系（順不同・`--` 以降は位置引数）。
    #[test]
    fn cli1_parse_create_ok() {
        let expect = CreateArgs {
            bundle: PathBuf::from("/b"),
            id: "c1".into(),
            image: None,
        };
        assert_eq!(
            parse_create(v(&["--bundle", "/b", "c1"])),
            Ok(expect.clone())
        );
        assert_eq!(
            parse_create(v(&["c1", "--bundle", "/b"])),
            Ok(expect.clone())
        );
        assert_eq!(parse_create(v(&["--bundle", "/b", "--", "c1"])), Ok(expect));
        assert_eq!(
            parse_create(v(&["--bundle", "/b", "--", "-x"])).map(|a| a.id),
            Ok("-x".to_string())
        );
    }

    /// CLI-1: create の異常系（bundle 欠落・値欠落・重複・未知オプション・位置引数の過不足）。
    #[test]
    fn cli1_parse_create_rejects_invalid() {
        for a in [
            v(&["c1"]),
            v(&["--bundle"]),
            v(&["--bundle", "/b"]),
            v(&["--bundle", "/a", "--bundle", "/b", "c1"]),
            v(&["--bundle", "/b", "--unknown", "c1"]),
            v(&["--bundle", "/b", "c1", "c2"]),
            v(&[]),
        ] {
            assert_eq!(parse_create(a), Err(UsageError));
        }
    }

    /// CLI-1: start の正常系と異常系。
    #[test]
    fn cli1_parse_start() {
        assert_eq!(parse_start(v(&["c1"])), Ok(StartArgs { id: "c1".into() }));
        assert_eq!(
            parse_start(v(&["--", "-c"])),
            Ok(StartArgs { id: "-c".into() })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--all", "a"]), v(&["-a"])] {
            assert_eq!(parse_start(a), Err(UsageError));
        }
    }

    /// CLI-1: 非 UTF-8 の ID は使い方エラー。
    #[cfg(unix)]
    #[test]
    fn cli1_parse_start_rejects_non_utf8_id() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            parse_start(vec![OsString::from_vec(vec![0x66, 0xff])]),
            Err(UsageError)
        );
    }

    /// CLI-1: stop は位置引数 1 個のみ。
    #[test]
    fn cli1_parse_stop() {
        assert_eq!(parse_stop(v(&["c1"])), Ok(StopArgs { id: "c1".into() }));
        assert_eq!(
            parse_stop(v(&["--", "-c"])),
            Ok(StopArgs { id: "-c".into() })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--force", "a"]), v(&["-a"])] {
            assert_eq!(parse_stop(a), Err(UsageError));
        }
    }

    /// CLI-1: delete の正常系（`--force` は前後どちらでも・`--` 以降は位置引数）。
    #[test]
    fn cli1_parse_delete_ok() {
        let plain = DeleteArgs {
            id: "c1".into(),
            force: false,
            image_root: None,
        };
        let forced = DeleteArgs {
            id: "c1".into(),
            force: true,
            image_root: None,
        };
        assert_eq!(parse_delete(v(&["c1"])), Ok(plain));
        assert_eq!(parse_delete(v(&["--force", "c1"])), Ok(forced.clone()));
        assert_eq!(parse_delete(v(&["c1", "--force"])), Ok(forced));
        assert_eq!(
            parse_delete(v(&["--force", "--", "-x"])),
            Ok(DeleteArgs {
                id: "-x".into(),
                force: true,
                image_root: None
            })
        );
    }

    /// CLI-1: delete の異常系（空・2 個・未知オプション・`--force` 重複・短縮形）。
    #[test]
    fn cli1_parse_delete_rejects_invalid() {
        for a in [
            v(&[]),
            v(&["a", "b"]),
            v(&["--x", "a"]),
            v(&["-f", "a"]),
            v(&["--force", "--force", "a"]),
            v(&["--force"]),
        ] {
            assert_eq!(parse_delete(a), Err(UsageError));
        }
    }

    /// CLI-1: 非 UTF-8 の ID は stop / delete でも使い方エラー。
    #[cfg(unix)]
    #[test]
    fn cli1_parse_stop_delete_reject_non_utf8_id() {
        use std::os::unix::ffi::OsStringExt;
        let bad = || vec![OsString::from_vec(vec![0x66, 0xff])];
        assert_eq!(parse_stop(bad()), Err(UsageError));
        assert_eq!(parse_delete(bad()), Err(UsageError));
    }

    /// CLI-1: list は引数なし（または `--` のみ）だけ受理する。
    #[test]
    fn cli1_parse_list() {
        assert_eq!(parse_list(v(&[])), Ok(ListArgs));
        assert_eq!(parse_list(v(&["--"])), Ok(ListArgs));
        for a in [v(&["x"]), v(&["--all"]), v(&["--", "x"]), v(&["-a"])] {
            assert_eq!(parse_list(a), Err(UsageError));
        }
    }

    /// CLI-1: doctor は引数なし（または `--` のみ）だけ受理する。
    #[test]
    fn cli1_parse_doctor() {
        assert_eq!(parse_doctor(v(&[])), Ok(DoctorArgs));
        assert_eq!(parse_doctor(v(&["--"])), Ok(DoctorArgs));
        for a in [v(&["x"]), v(&["--x"]), v(&["--", "x"])] {
            assert_eq!(parse_doctor(a), Err(UsageError));
        }
    }

    /// CLI-2: setup は引数なし（または `--` のみ）だけ受理する。
    #[test]
    fn cli2_parse_setup() {
        assert_eq!(parse_setup(v(&[])), Ok(SetupArgs));
        assert_eq!(parse_setup(v(&["--"])), Ok(SetupArgs));
        for a in [v(&["x"]), v(&["--all"]), v(&["--", "x"])] {
            assert_eq!(parse_setup(a), Err(UsageError));
        }
    }

    fn logs_plain(id: &str) -> LogsArgs {
        LogsArgs {
            id: id.into(),
            follow: false,
            tail: None,
            stream: None,
            escape: false,
        }
    }

    /// CLI-1: logs は位置引数 1 個のみ（オプションなし）。
    #[test]
    fn cli1_parse_logs() {
        assert_eq!(parse_logs(v(&["c1"])), Ok(logs_plain("c1")));
        assert_eq!(parse_logs(v(&["--", "-c"])), Ok(logs_plain("-c")));
        for a in [v(&[]), v(&["a", "b"]), v(&["--x", "a"]), v(&["-f", "a"])] {
            assert_eq!(parse_logs(a.clone()), Err(UsageError), "{a:?}");
        }
    }

    /// CLI-1・SUP-7: logs のオプション（順不同・各 1 回まで・長い形だけ）。
    #[test]
    fn cli1_parse_logs_options() {
        assert_eq!(
            parse_logs(v(&[
                "--follow", "--tail", "5", "--stream", "stderr", "--escape", "c1"
            ])),
            Ok(LogsArgs {
                id: "c1".into(),
                follow: true,
                tail: Some(5),
                stream: Some(LogStreamArg::Stderr),
                escape: true,
            })
        );
        assert_eq!(
            parse_logs(v(&["c1", "--escape", "--tail", "0"])),
            Ok(LogsArgs {
                tail: Some(0),
                escape: true,
                ..logs_plain("c1")
            })
        );
        assert_eq!(
            parse_logs(v(&["--stream", "stdout", "--", "--follow"])),
            Ok(LogsArgs {
                stream: Some(LogStreamArg::Stdout),
                ..logs_plain("--follow")
            })
        );
        assert_eq!(
            parse_logs(v(&["--tail", "1000000", "c1"])).map(|a| a.tail),
            Ok(Some(1_000_000))
        );
        for bad in [
            v(&["--tail"]),
            v(&["--tail", "c1"]),
            v(&["--tail", "x", "c1"]),
            v(&["--tail", "-1", "c1"]),
            v(&["--tail", "+5", "c1"]),
            v(&["--tail", " 5", "c1"]),
            v(&["--tail", "all", "c1"]),
            v(&["--tail", "", "c1"]),
            v(&["--tail", "1000001", "c1"]),
            v(&["--tail", "99999999999", "c1"]),
            v(&["--tail=5", "c1"]),
            v(&["--tail", "1", "--tail", "2", "c1"]),
            v(&["--stream", "bogus", "c1"]),
            v(&["--stream"]),
            v(&["--stream", "stdout", "--stream", "stderr", "c1"]),
            v(&["--follow", "--follow", "c1"]),
            v(&["--escape", "--escape", "c1"]),
            v(&["-f", "c1"]),
            v(&["-n", "1", "c1"]),
            v(&["--follow"]),
        ] {
            assert_eq!(parse_logs(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// CLI-1: `--tail` の上限は supervisor の定数と同じ。
    #[test]
    fn cli1_logs_tail_limit_matches_supervisor() {
        assert_eq!(
            MAX_LOGS_TAIL,
            fandhe_container_supervisor::logs::MAX_TAIL_RECORDS
        );
    }

    /// CLI-1: 非 UTF-8 の ID は logs でも使い方エラー。
    #[cfg(unix)]
    #[test]
    fn cli1_parse_logs_rejects_non_utf8_id() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            parse_logs(vec![OsString::from_vec(vec![0x66, 0xff])]),
            Err(UsageError)
        );
    }

    /// CLI-1・OCI-7: image ls / system df の正常系と異常系。
    #[test]
    fn cli1_oci7_parse_image_ls_and_system_df() {
        let root = std::env::temp_dir();
        let r = root.to_str().expect("utf8").to_owned();
        assert_eq!(
            parse_image(v(&["ls", "--image-root", &r])),
            Ok(ImageArgs::Ls(ImageLsArgs {
                image_root: root.clone()
            }))
        );
        assert_eq!(
            parse_system(v(&["df", "--image-root", &r])),
            Ok(SystemArgs::Df(SystemDfArgs {
                image_root: root.clone()
            }))
        );
        for bad in [
            v(&[]),
            v(&["bogus"]),
            v(&["ls"]),
            v(&["ls", "--image-root"]),
            v(&["ls", "--image-root", "rel/dir"]),
            v(&["ls", "--image-root", &r, "extra"]),
            v(&["ls", "--image-root", &r, "--image-root", &r]),
            v(&["ls", "--force", "--image-root", &r]),
            v(&["ls", "--bogus", "--image-root", &r]),
        ] {
            assert_eq!(parse_image(bad.clone()), Err(UsageError), "{bad:?}");
        }
        for bad in [
            v(&[]),
            v(&["bogus"]),
            v(&["df"]),
            v(&["df", "--image-root", &r, "extra"]),
        ] {
            assert_eq!(parse_system(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// CLI-1・OCI-7: image rm の構文（--force は 1 回・順不同・`--` 以降は位置引数・参照は 1 個）。
    #[test]
    fn cli1_oci7_parse_image_rm() {
        let root = std::env::temp_dir();
        let r = root.to_str().expect("utf8").to_owned();
        let expect = |force: bool| {
            Ok(ImageArgs::Rm(ImageRmArgs {
                image_root: root.clone(),
                force,
                reference: "busybox:latest".into(),
            }))
        };
        assert_eq!(
            parse_image(v(&["rm", "--image-root", &r, "busybox:latest"])),
            expect(false)
        );
        assert_eq!(
            parse_image(v(&["rm", "--force", "busybox:latest", "--image-root", &r])),
            expect(true)
        );
        assert_eq!(
            parse_image(v(&["rm", "--image-root", &r, "--", "busybox:latest"])),
            expect(false)
        );
        for bad in [
            v(&["rm", "--image-root", &r]),
            v(&["rm", "--image-root", &r, "a", "b"]),
            v(&["rm", "--force", "--force", "--image-root", &r, "x"]),
            v(&["rm", "--bogus", "--image-root", &r, "x"]),
            v(&["rm", "x"]),
        ] {
            assert_eq!(parse_image(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// CLI-1・OCI-7: image tag の構文（順不同・`--` 以降は位置引数・位置引数はちょうど 2 個・--force は不可）。
    #[test]
    fn cli1_oci7_parse_image_tag() {
        let root = std::env::temp_dir();
        let r = root.to_str().expect("utf8").to_owned();
        let expect = Ok(ImageArgs::Tag(ImageTagArgs {
            image_root: root.clone(),
            source: "busybox".into(),
            target: "busybox:v2".into(),
        }));
        assert_eq!(
            parse_image(v(&["tag", "--image-root", &r, "busybox", "busybox:v2"])),
            expect
        );
        assert_eq!(
            parse_image(v(&["tag", "busybox", "busybox:v2", "--image-root", &r])),
            expect
        );
        assert_eq!(
            parse_image(v(&[
                "tag",
                "--image-root",
                &r,
                "--",
                "busybox",
                "busybox:v2"
            ])),
            expect
        );
        for bad in [
            v(&["tag", "--image-root", &r, "a"]),
            v(&["tag", "--image-root", &r, "a", "b", "c"]),
            v(&["tag", "--force", "--image-root", &r, "a", "b"]),
            v(&["tag", "a", "b"]),
            v(&["tag", "--image-root", "rel/dir", "a", "b"]),
            v(&["tag", "--image-root", &r, "--image-root", &r, "a", "b"]),
            v(&["tag", "--bogus", "--image-root", &r, "a", "b"]),
        ] {
            assert_eq!(parse_image(bad.clone()), Err(UsageError), "{bad:?}");
        }
    }

    /// SUP-6・CLI-1・#2626: `exec` はオプション（`--env`・`--timeout`）を `<id>` の前に受け、`<id>` の後ろは
    /// オプション風の語を含めてすべてコマンドの引数として保つ。
    #[test]
    fn sup6_parse_exec_options_and_command() {
        let a = parse_exec(v(&["c1", "/bin/echo", "hi", "-n", "--env"])).expect("ok");
        assert_eq!(a.id, "c1");
        assert_eq!(a.path, "/bin/echo");
        assert_eq!(a.args, vec!["hi", "-n", "--env"]);
        assert!(a.env.is_empty());
        assert_eq!(a.timeout, Duration::from_secs(EXEC_DEFAULT_TIMEOUT_SECS));

        let a = parse_exec(v(&[
            "--env",
            "A=1",
            "--timeout",
            "30",
            "--env",
            "B=",
            "c1",
            "/bin/true",
        ]))
        .expect("ok");
        let env: Vec<(&str, &str)> = a.env.iter().map(|e| (e.key(), e.value())).collect();
        assert_eq!(env, vec![("A", "1"), ("B", "")]);
        assert_eq!(a.timeout, Duration::from_secs(30));
        assert!(a.args.is_empty());

        // `--` の後ろは `<id>` から始まる位置引数（`-` で始まる ID も `--` なら受ける。ID の文字種は core が検証する）。
        let a = parse_exec(v(&["--", "-x", "/bin/true"])).expect("ok");
        assert_eq!((a.id.as_str(), a.path.as_str()), ("-x", "/bin/true"));
    }

    /// SUP-6・CLI-1・#2626: `exec` の使い方エラー（id・path 欠落、未知オプション、値なしの `--env`、
    /// `--timeout` の 0・上限超・重複・非数値）。
    #[test]
    fn sup6_parse_exec_rejections() {
        for bad in [
            v(&[]),
            v(&["c1"]),
            v(&["c1", ""]),
            v(&["--bogus", "c1", "/bin/true"]),
            v(&["--env"]),
            v(&["--env", "KEY", "c1", "/bin/true"]),
            v(&["--env", "=v", "c1", "/bin/true"]),
            v(&["--timeout"]),
            v(&["--timeout", "0", "c1", "/bin/true"]),
            v(&["--timeout", "3601", "c1", "/bin/true"]),
            v(&["--timeout", "-1", "c1", "/bin/true"]),
            v(&["--timeout", "x", "c1", "/bin/true"]),
            v(&["--timeout", "5", "--timeout", "6", "c1", "/bin/true"]),
            v(&["--"]),
        ] {
            assert_eq!(parse_exec(bad.clone()), Err(UsageError), "{bad:?}");
        }
        // 上限ちょうどは受ける。
        let a = parse_exec(v(&["--timeout", "3600", "c1", "/bin/true"])).expect("ok");
        assert_eq!(a.timeout, Duration::from_secs(EXEC_MAX_TIMEOUT_SECS));
    }

    /// CLI-1: 非 UTF-8 の位置引数は image tag で使い方エラー。
    #[cfg(unix)]
    #[test]
    fn cli1_parse_image_tag_rejects_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let root = std::env::temp_dir();
        let bad = vec![
            OsString::from("tag"),
            OsString::from("--image-root"),
            root.into_os_string(),
            OsString::from("a"),
            OsString::from_vec(vec![0x62, 0xff]),
        ];
        assert_eq!(parse_image(bad), Err(UsageError));
    }
}
