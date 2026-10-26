//! `create` / `start` / `stop` / `delete` / `list` / `logs` / `inspect` / `image` / `system` の argv 解析（TASK-79.2.1・TASK-79.2.2・TASK-79.3・CLI-1・MS-6）。
//!
//! `commands::run` が先頭のグローバルオプション（`--root`・`--plugin-path-search`。順不同）とサブコマンド名の後ろを渡して呼ぶ純粋関数群。
//! ファイルシステムにも環境にも触れず、値の意味検証（絶対パス・ID の文字種）は core の型
//! （`ContainerId`・`CreateRequest`・`StateRoot`）に委ねる（検査の二重実装を避ける。SEC-1）。
//! 構文は runc 互換: `fandhe-container [--root <dir>] create [--image-root <dir> --image <sha256:digest|name[:tag]>] --bundle <dir> <id>` / `... start [--audit-policy <best-effort|strict>] <id>` / `... stop [--signal <名前|番号>] <id>` / `... inspect <id>` / `... delete [--force] [--image-root <dir>] <id>` / `... list` / `... logs [--follow] [--tail <N>] [--stream <stdout|stderr>] [--escape] <id>`。
//! イメージ管理（#2221）は `image ls --image-root <dir>` / `image rm [--force] --image-root <dir> <ref>` / `image tag --image-root <dir> <source> <target>` / `system df --image-root <dir>`（`--image-root` は必須の絶対パス）。
//! 解析失敗の理由は呼び出し元で固定文言に落とし、引数値を出力へ埋め込まない（インジェクション回避）。

use std::ffi::OsString;
use std::path::PathBuf;

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
    /// `--ulimit`・`--env`・`--env-file`・`--label`・`--ipc`・`--shm-size`・`--tmpfs`・`--cap-drop`(未検証の文字列。意味検証は `create_options`。
    /// SUP-12・CLI-1・#2713)。
    pub(super) options: CreateOptionArgs,
}

/// `create` の起動オプションの指定(argv の生の値。件数の上限だけをここで見て、形式の検証は `create_options` が既存の
/// パーサで行う。SUP-12・SEC-1・#2713)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct CreateOptionArgs {
    /// `--ulimit <name>=<soft>[:<hard>]`(最大 [`MAX_CREATE_ULIMITS`] 件)。
    pub(super) ulimits: Vec<String>,
    /// `--env` / `-e` `<KEY=VALUE>`(最大 `ENV_MAX_ENTRIES` 件)。
    pub(super) env: Vec<String>,
    /// `--env-file <path>`(最大 [`MAX_CREATE_ENV_FILES`] 件。CLI が非特権のまま読む)。
    pub(super) env_files: Vec<PathBuf>,
    /// `--label <key>[=<value>]`(最大 `ANNOTATIONS_MAX_ENTRIES` − 1 件。世代の注釈の分を空ける)。
    pub(super) labels: Vec<String>,
    /// `--ipc <private|shareable|host>`(1 回まで)。
    pub(super) ipc: Option<String>,
    /// `--shm-size <size>`(1 回まで)。
    pub(super) shm_size: Option<String>,
    /// `--tmpfs <dest>[:<opts>]`(最大 `TMPFS_MAX_MOUNTS` 件)。
    pub(super) tmpfs: Vec<String>,
    /// `--cap-drop <CAP>`(最大 core の `MAX_DROP_NAMES` 件。`ALL` を含む。CLI-1・SEC-1・#2775)。
    pub(super) cap_drop: Vec<String>,
}

/// `create --ulimit` の最大件数(rlimit の種別数と同じ 16)。
pub(super) const MAX_CREATE_ULIMITS: usize = 16;
/// `create --env-file` の最大件数。
pub(super) const MAX_CREATE_ENV_FILES: usize = 64;

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
    /// `--audit-policy` の生の値(未検証。語彙の検証は `create_start` が core の `AuditCoveragePolicy` に委ねる。SEC-4・#2761)。
    pub(super) audit_policy: Option<String>,
}

/// `stop` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StopArgs {
    pub(super) id: String,
    /// `--signal <名前|番号>` の生の値(未検証。Docker 表記の解釈は `stop_delete` が core の `Signal::parse_notation` に
    /// 委ねる。未指定は SIGTERM。CLI-1・ERR-1・#2775)。
    pub(super) signal: Option<String>,
}

/// `inspect` の引数(CLI-1・SUP-11・#2775)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InspectArgs {
    pub(super) id: String,
}

/// `delete` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeleteArgs {
    pub(super) id: String,
    /// `--force`（core の `DeleteRequest::with_force` へ素通しする。生存中コンテナへは core が拒否する）。
    pub(super) force: bool,
    /// `--image-root`（イメージ参照を解除するストアの root。絶対パス。省略時は create 時に状態記録へ残した root を使い、
    /// 指定が記録と食い違えば拒否する。記録の無いコンテナでは解除しない。OCI-7・#2315・#2499）。
    pub(super) image_root: Option<PathBuf>,
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
    let mut options = CreateOptionArgs::default();
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if let Some(kind) = repeatable_option(&a) {
            let value = it.next().ok_or(UsageError)?;
            push_option(&mut options, kind, value)?;
        } else if a == "--ipc" || a == "--shm-size" {
            let value = it.next().ok_or(UsageError)?;
            let slot = if a == "--ipc" {
                &mut options.ipc
            } else {
                &mut options.shm_size
            };
            if slot.is_some() {
                return Err(UsageError);
            }
            *slot = Some(value.into_string().map_err(|_| UsageError)?);
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
        options,
    })
}

/// 繰り返せる `create` のオプションの種類。
#[derive(Clone, Copy)]
enum RepeatableOption {
    Ulimit,
    Env,
    EnvFile,
    Label,
    Tmpfs,
    CapDrop,
}

fn repeatable_option(a: &OsString) -> Option<RepeatableOption> {
    if a == "--ulimit" {
        Some(RepeatableOption::Ulimit)
    } else if a == "--env" || a == "-e" {
        Some(RepeatableOption::Env)
    } else if a == "--env-file" {
        Some(RepeatableOption::EnvFile)
    } else if a == "--label" {
        Some(RepeatableOption::Label)
    } else if a == "--tmpfs" {
        Some(RepeatableOption::Tmpfs)
    } else if a == "--cap-drop" {
        Some(RepeatableOption::CapDrop)
    } else {
        None
    }
}

/// 値を種類ごとの列へ足す。件数が上限を超えたら使い方エラー(確保の前に止める。値の形式はここでは見ない)。
fn push_option(
    options: &mut CreateOptionArgs,
    kind: RepeatableOption,
    value: OsString,
) -> Result<(), UsageError> {
    use fandhe_container_core::capabilities::MAX_DROP_NAMES;
    use fandhe_container_core::tmpfs::TMPFS_MAX_MOUNTS;
    use fandhe_container_core::traits::ANNOTATIONS_MAX_ENTRIES;
    use fandhe_container_supervisor::container_options::env::ENV_MAX_ENTRIES;
    fn text(value: OsString) -> Result<String, UsageError> {
        value.into_string().map_err(|_| UsageError)
    }
    match kind {
        RepeatableOption::Ulimit => {
            if options.ulimits.len() >= MAX_CREATE_ULIMITS {
                return Err(UsageError);
            }
            options.ulimits.push(text(value)?);
        }
        RepeatableOption::Env => {
            if options.env.len() >= ENV_MAX_ENTRIES {
                return Err(UsageError);
            }
            options.env.push(text(value)?);
        }
        RepeatableOption::EnvFile => {
            if options.env_files.len() >= MAX_CREATE_ENV_FILES {
                return Err(UsageError);
            }
            options.env_files.push(PathBuf::from(value));
        }
        RepeatableOption::Label => {
            // 作成世代の注釈(CLI が足す 1 件)の分を確保する(#2713)。
            if options.labels.len() >= ANNOTATIONS_MAX_ENTRIES - 1 {
                return Err(UsageError);
            }
            options.labels.push(text(value)?);
        }
        RepeatableOption::Tmpfs => {
            if options.tmpfs.len() >= TMPFS_MAX_MOUNTS {
                return Err(UsageError);
            }
            options.tmpfs.push(text(value)?);
        }
        RepeatableOption::CapDrop => {
            if options.cap_drop.len() >= MAX_DROP_NAMES {
                return Err(UsageError);
            }
            options.cap_drop.push(text(value)?);
        }
    }
    Ok(())
}

/// `start [--audit-policy <値>] <id>` を解析する(オプションは 1 回だけ・順不同・`--` 以降は位置引数。SEC-4・#2761)。
/// 値の意味の検証はここでは行わない(core の型に委ねる)。
pub(super) fn parse_start(args: Vec<OsString>) -> Result<StartArgs, UsageError> {
    let mut audit_policy: Option<String> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--audit-policy" {
            let value = it.next().ok_or(UsageError)?;
            if audit_policy.is_some() {
                return Err(UsageError);
            }
            audit_policy = Some(value.into_string().map_err(|_| UsageError)?);
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    Ok(StartArgs {
        id: single_id(positional)?,
        audit_policy,
    })
}

/// `stop [--signal <名前|番号>] <id>` を解析する(`--signal` は 1 回まで・`--` 以降は位置引数)。
/// Docker の `-s` は受けない(`logs -f` と同じく長い形だけ。D06)。値の意味はここでは見ない(core の型に委ねる)。
pub(super) fn parse_stop(args: Vec<OsString>) -> Result<StopArgs, UsageError> {
    let mut signal: Option<String> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--signal" {
            let value = it.next().ok_or(UsageError)?;
            if signal.is_some() {
                return Err(UsageError);
            }
            signal = Some(value.into_string().map_err(|_| UsageError)?);
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    Ok(StopArgs {
        id: single_id(positional)?,
        signal,
    })
}

/// `inspect <id>` を解析する(オプションは受け付けない)。
pub(super) fn parse_inspect(args: Vec<OsString>) -> Result<InspectArgs, UsageError> {
    Ok(InspectArgs {
        id: single_positional(args)?,
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
            options: CreateOptionArgs::default(),
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

    /// SUP-12・CLI-1(#2713): create の起動オプションは生の文字列のまま集め、繰り返しは指定順に保つ。
    #[test]
    fn sup12_parse_create_collects_options() {
        let got = parse_create(v(&[
            "--ulimit",
            "nofile=1024:2048",
            "--ulimit",
            "nproc=64",
            "-e",
            "A=1",
            "--env",
            "B=2",
            "--env-file",
            "/e.env",
            "--label",
            "tier=web",
            "--ipc",
            "private",
            "--shm-size",
            "128m",
            "--tmpfs",
            "/run:rw",
            "--bundle",
            "/b",
            "c1",
        ]))
        .expect("parsed");
        assert_eq!(
            got.options,
            CreateOptionArgs {
                ulimits: vec!["nofile=1024:2048".into(), "nproc=64".into()],
                env: vec!["A=1".into(), "B=2".into()],
                env_files: vec![PathBuf::from("/e.env")],
                labels: vec!["tier=web".into()],
                ipc: Some("private".into()),
                shm_size: Some("128m".into()),
                tmpfs: vec!["/run:rw".into()],
                cap_drop: Vec::new(),
            }
        );
    }

    /// SUP-12・SEC-1(#2713): `--ipc` / `--shm-size` の重複、値の欠落、繰り返しの件数超過は使い方エラー。
    #[test]
    fn sup12_parse_create_rejects_bad_options() {
        for bad in [
            v(&["--ipc", "host", "--ipc", "private", "--bundle", "/b", "c1"]),
            v(&[
                "--shm-size",
                "1m",
                "--shm-size",
                "2m",
                "--bundle",
                "/b",
                "c1",
            ]),
            v(&["--bundle", "/b", "c1", "--ulimit"]),
            v(&["--bundle", "/b", "c1", "--env"]),
        ] {
            assert_eq!(parse_create(bad), Err(UsageError));
        }
        let mut many = vec![];
        for _ in 0..=MAX_CREATE_ULIMITS {
            many.extend(v(&["--ulimit", "nofile=1"]));
        }
        many.extend(v(&["--bundle", "/b", "c1"]));
        assert_eq!(parse_create(many), Err(UsageError));
        let mut files = vec![];
        for _ in 0..=MAX_CREATE_ENV_FILES {
            files.extend(v(&["--env-file", "/e"]));
        }
        files.extend(v(&["--bundle", "/b", "c1"]));
        assert_eq!(parse_create(files), Err(UsageError));
    }

    /// CLI-1: create の正常系（順不同・`--` 以降は位置引数）。
    #[test]
    fn cli1_parse_create_ok() {
        let expect = CreateArgs {
            options: CreateOptionArgs::default(),
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
        assert_eq!(
            parse_start(v(&["c1"])),
            Ok(StartArgs {
                id: "c1".into(),
                audit_policy: None
            })
        );
        assert_eq!(
            parse_start(v(&["--", "-c"])),
            Ok(StartArgs {
                id: "-c".into(),
                audit_policy: None
            })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--all", "a"]), v(&["-a"])] {
            assert_eq!(parse_start(a), Err(UsageError));
        }
    }

    /// SEC-4・#2761: `--audit-policy` は値つきで 1 回だけ・順不同。生の値をそのまま保持する。
    #[test]
    fn sec4_cli1_parse_start_audit_policy() {
        let ok = |id: &str, p: &str| {
            Ok(StartArgs {
                id: id.into(),
                audit_policy: Some(p.into()),
            })
        };
        assert_eq!(
            parse_start(v(&["--audit-policy", "strict", "c1"])),
            ok("c1", "strict")
        );
        assert_eq!(
            parse_start(v(&["c1", "--audit-policy", "best-effort"])),
            ok("c1", "best-effort")
        );
        assert_eq!(
            parse_start(v(&["--audit-policy", "x", "--", "-c"])),
            ok("-c", "x")
        );
        for a in [
            v(&["--audit-policy"]),
            v(&["--audit-policy", "strict"]),
            v(&["--audit-policy", "strict", "--audit-policy", "strict", "c1"]),
            v(&["--audit-policy", "strict", "a", "b"]),
        ] {
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
        assert_eq!(
            parse_stop(v(&["c1"])),
            Ok(StopArgs {
                id: "c1".into(),
                signal: None
            })
        );
        assert_eq!(
            parse_stop(v(&["--", "-c"])),
            Ok(StopArgs {
                id: "-c".into(),
                signal: None
            })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--force", "a"]), v(&["-a"])] {
            assert_eq!(parse_stop(a), Err(UsageError));
        }
    }

    /// CLI-1・#2775: `stop --signal` は前後どちらでも受け、値の欠落・重複・`-s` は使い方エラー。値の意味は見ない。
    #[test]
    fn cli1_parse_stop_signal() {
        let want = Ok(StopArgs {
            id: "c1".into(),
            signal: Some("SIGKILL".into()),
        });
        assert_eq!(parse_stop(v(&["--signal", "SIGKILL", "c1"])), want);
        assert_eq!(parse_stop(v(&["c1", "--signal", "SIGKILL"])), want);
        assert_eq!(
            parse_stop(v(&["--signal", "BOGUS", "c1"])).map(|a| a.signal),
            Ok(Some("BOGUS".into()))
        );
        for a in [
            v(&["--signal"]),
            v(&["c1", "--signal"]),
            v(&["--signal", "9", "--signal", "15", "c1"]),
            v(&["-s", "9", "c1"]),
            v(&["--signal", "9"]),
        ] {
            assert_eq!(parse_stop(a), Err(UsageError));
        }
    }

    /// CLI-1・#2775: `inspect` は ID をちょうど 1 つ受け、オプション・余分な引数は使い方エラー。
    #[test]
    fn cli1_parse_inspect() {
        assert_eq!(
            parse_inspect(v(&["c1"])),
            Ok(InspectArgs { id: "c1".into() })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--format", "a"]), v(&["-a"])] {
            assert_eq!(parse_inspect(a), Err(UsageError));
        }
    }

    /// CLI-1・#2775: `create --cap-drop` は繰り返し指定でき、値の欠落と件数超過は使い方エラー。値の意味は見ない。
    #[test]
    fn cli1_parse_create_cap_drop() {
        let a = parse_create(v(&[
            "--bundle",
            "/b",
            "--cap-drop",
            "ALL",
            "--cap-drop",
            "chown",
            "c1",
        ]))
        .expect("parse");
        assert_eq!(a.options.cap_drop, vec!["ALL".to_string(), "chown".into()]);
        assert_eq!(
            parse_create(v(&["--bundle", "/b", "c1", "--cap-drop"])),
            Err(UsageError)
        );
        let mut many = vec!["--bundle", "/b"];
        for _ in 0..=fandhe_container_core::capabilities::MAX_DROP_NAMES {
            many.extend(["--cap-drop", "chown"]);
        }
        many.push("c1");
        assert_eq!(parse_create(v(&many)), Err(UsageError));
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
