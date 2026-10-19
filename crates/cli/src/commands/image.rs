//! `image ls` / `system df` / `image rm` コマンド本体（oci の管理 API への配線。#2221・CLI-1・OCI-7・TASK-183）。
//!
//! `commands::run_to` が argv を解析した後に [`run_image`] / [`run_system`] を呼ぶ。実処理は
//! `fandhe-container-oci` の `image_management`（`ImageStore`・`ReferenceTable::list_images`・`disk_usage`・
//! `plan_image_rm_with`・`execute_image_rm`）へ委ね、CLI は引数の解析・出力の整形・エラーの写像だけを担う。
//! イメージの参照解釈は oci の `ImageReference::parse`（docker.io の正規化・`library/` と `latest` の補完を含む）を唯一の判定とする。
//!
//! # 構文
//!
//! `image ls --image-root <abs>` / `system df --image-root <abs>` / `image rm [--force] --image-root <abs> <ref>`。
//! イメージストアの root は必須オプション `--image-root`（絶対パス）で受ける。既定位置は未決のため発明しない（下記「未実装」）。
//! root は作らない（`ImageStore::open` が存在するディレクトリ・非 symlink であることだけを見る）。
//!
//! # 出力形式（stdout・タブ区切り・LF 固定）
//!
//! 値はすべて oci が検証済みの newtype（host・repository・tag・digest は `[A-Za-z0-9._:/@-]`）と 10 進整数だけで、
//! タブ・改行・制御文字を含み得ないためエスケープ不要。argv の値は出力へ埋め込まない。JSON は手組みしない（REPAIR-2）。
//!
//! - `image ls`: 固定ヘッダ `REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING`、1 行 1 エントリ（タグ昇順 → タグなし digest 昇順は oci の順序）。
//!   タグなしは `REPOSITORY` と `TAG` が `-`。`MISSING` は欠損 blob 数。0 件はヘッダのみ。
//! - `system df`: 固定ヘッダ `KEY\tVALUE` に続く固定順 9 行（`images.*` 4 行・`cache.*` 5 行）。
//! - `image rm`: `untagged\t<ref>`・`deleted\t<manifest>`・`deleted-blob\t<digest>` を 1 行 1 事実で出す。
//!   blob の削除に失敗したもの（`undeleted_blobs`）があれば `undeleted-blob\t<digest>` を出したうえで `INTERNAL`（1）で失敗する
//!   （参照テーブルは更新済みのため `Ok` で成功と見せない。REPAIR-4）。
//!
//! # エラー写像（ERR-1・ERR-2）
//!
//! oci の `OciErrorCode` を core の `ErrorCode` へ同名で写す（`DataLoss`・`ResourceExhausted`・`Internal` は `INTERNAL`）。
//! `message` は本 module の固定文言表のみで、oci の `OciError::message`（コンテナ ID を含みうる）は出力へ流さない。
//!
//! # `image rm` の排他手順
//!
//! oci の契約（ガードを保持したまま `StateStore` の操作を取らない・状態のスナップショットはガード取得前に読む）を守る。
//! 1. ガードを取り `--force` なしで判定する。参照が無い・`UntagOnly`/`Delete` ならそのまま実行して終わる。
//! 2. 使用中で `--force` なしなら拒否する。`--force` ありなら**ガードを手放して**状態ストアを読み、
//!    停止中のコンテナの集合を作る（読めなければそのエラーで終了。fail-closed）。
//! 3. 再びガードを取り、スナップショット付きで判定し直す。スナップショット後に起動したコンテナは実行中扱いで拒否される。
//!
//! # 未実装・前提（実装済みを装わない。REPAIR-3）
//!
//! - 参照テーブルのディスク永続化と読み込みは oci 側で未実装（#851・#854・#2315）。CLI は空の参照テーブルでしかストアを開けないため、
//!   現状は `image ls` が常にヘッダのみ、`system df` の images 側が 0 件（キャッシュ側は実ファイルを全件「未登録」として数える）、
//!   `image rm` が常に `NOT_FOUND` になる。永続化が入ったら `ImageStore::with_table` へ読み込み結果を渡す配線を足す。
//! - `--image-root` 省略時の既定位置（Linux の root / rootless、macOS / Windows の置き場。MAC-4・WIN-1）は未決。
//! - macOS / Windows ではイメージキャッシュの置き場（ゲスト VM 内かホストか）が未決のため、ローカルの oci を呼ばず
//!   他コマンドと同じ plugin 解決の失敗（`list_logs::store_open_failure`）で fail-closed に失敗する。
//! - `system df` の containers・staging・展開後サイズは oci が未計測のため出さない（#2222）。
//! - `image tag` / `image prune` の CLI 配線、oci の `OciOpRecorder` と CLI 計測の橋渡しは範囲外。

use std::io::Write;
use std::num::NonZeroU32;
use std::time::Instant;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::traits::{
    ContainerState, ErrorCode, ListStateRequest, MAX_PAGE_SIZE, StateStore, TraitError,
};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    ContainerRefId, DiskUsage, ImageList, ImageRmKind, ImageRmOptions, ImageRmOutcome, ImageRmPlan,
    ImageRmTarget, ImageStore, StoppedContainers, TagKey,
};
use fandhe_container_oci::reference::{Digest, ImageReference, Reference};

use super::CliExit;
use super::args::{GlobalArgs, ImageArgs, SystemArgs};
use super::create_start::{OP_LOG_ENV, export_ops, open_store};
use super::list_logs::{MAX_LIST_PAGES, record_op, store_open_failure};
use crate::error::CliError;

/// `image ls` の固定ヘッダ行（LF 終端）。
const IMAGE_LS_HEADER: &str = "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n";
/// `system df` の固定ヘッダ行（LF 終端）。
const SYSTEM_DF_HEADER: &str = "KEY\tVALUE\n";

const MSG_ROOT_NOT_FOUND: &str = "image store root not found";
const MSG_ROOT_NOT_DIRECTORY: &str = "image store root is not a directory";
const MSG_LOCKED: &str = "image store is locked by another operation";
const MSG_IMAGE_NOT_FOUND: &str = "image not found";
const MSG_IN_USE: &str = "image is in use by a container";
const MSG_IN_USE_HINT: &str =
    "image is in use by a container; use --force to untag images used only by stopped containers";
const MSG_UNDELETED: &str = "image record removed but some blob files could not be deleted";
const MSG_BLOB_DIR: &str = "image store blob directory is invalid";
const MSG_SCAN_LIMIT: &str = "image store scan limit exceeded";

/// 失敗が出た段階。同じ `OciErrorCode` でも段階で意味が違う（`NotFound` はストア root の不在か対象イメージの不在か）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// `ImageStore::open`（root の検証）。
    Open,
    /// `ImageStore::lock`（排他区間の取得）。
    Lock,
    /// ls / df の読み取り。
    Read,
    /// `image rm` の判定・実行。
    Remove,
}

/// oci の分類を core の `ErrorCode` へ写す。`OciErrorCode` は `#[non_exhaustive]` ではないが、将来の追加に備え未知は `Internal`。
fn map_code(code: OciErrorCode) -> ErrorCode {
    match code {
        OciErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        OciErrorCode::NotFound => ErrorCode::NotFound,
        OciErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        OciErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        OciErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        OciErrorCode::Timeout => ErrorCode::Timeout,
        OciErrorCode::Unimplemented => ErrorCode::Unimplemented,
        OciErrorCode::Unavailable => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    }
}

/// 段階つきの固定文言表。oci の `message` は使わない（argv・パス・コンテナ ID を出力へ埋め込まない）。
fn failure_message(code: OciErrorCode, stage: Stage) -> &'static str {
    match (stage, code) {
        (Stage::Open, OciErrorCode::NotFound) => MSG_ROOT_NOT_FOUND,
        (Stage::Open, OciErrorCode::FailedPrecondition) => MSG_ROOT_NOT_DIRECTORY,
        (Stage::Lock, OciErrorCode::Timeout) => MSG_LOCKED,
        (Stage::Remove, OciErrorCode::NotFound) => MSG_IMAGE_NOT_FOUND,
        (Stage::Read | Stage::Remove, OciErrorCode::FailedPrecondition) => MSG_BLOB_DIR,
        (Stage::Read | Stage::Remove, OciErrorCode::ResourceExhausted) => MSG_SCAN_LIMIT,
        (_, OciErrorCode::InvalidArgument) => "invalid argument",
        (_, OciErrorCode::AlreadyExists) => "already exists",
        (_, OciErrorCode::FailedPrecondition) => "failed precondition",
        (_, OciErrorCode::PermissionDenied) => "permission denied",
        (_, OciErrorCode::Timeout) => "operation timed out",
        (_, OciErrorCode::Unimplemented) => "not implemented on this platform",
        (_, OciErrorCode::Unavailable) => "unavailable",
        _ => "operation failed",
    }
}

fn oci_failure(e: &OciError, stage: Stage) -> CliExit {
    CliExit::Error(CliError::new(
        map_code(e.code()),
        failure_message(e.code(), stage),
    ))
}

fn stdout_failure() -> CliExit {
    CliExit::failed(ErrorCode::Internal)
}

/// 1 回の `write_all` にまとめて stdout へ書く（`list` と同じ）。
fn write_out(out: &mut dyn Write, text: &str) -> Result<(), CliExit> {
    out.write_all(text.as_bytes()).map_err(|_| stdout_failure())
}

/// `image ls` の表を作る。
fn format_image_ls(list: &ImageList) -> String {
    let mut s = String::from(IMAGE_LS_HEADER);
    for e in &list.entries {
        match &e.tag {
            Some(t) => {
                s.push_str(&format!("{}/{}\t{}", t.host, t.repository, t.tag));
            }
            None => s.push_str("-\t-"),
        }
        s.push_str(&format!(
            "\t{}\t{}\t{}\n",
            e.digest,
            e.size_bytes,
            e.missing_blobs.len()
        ));
    }
    s
}

/// `system df` の表を作る（固定順 9 行）。
fn format_system_df(du: &DiskUsage) -> String {
    let mut s = String::from(SYSTEM_DF_HEADER);
    let rows: [(&str, String); 9] = [
        ("images.count", du.images.count.to_string()),
        ("images.bytes", du.images.bytes.to_string()),
        (
            "images.reclaimable_bytes",
            du.images.reclaimable_bytes.to_string(),
        ),
        ("images.missing_blobs", du.images.missing_blobs.to_string()),
        ("cache.blob_count", du.cache.blob_count.to_string()),
        ("cache.bytes", du.cache.bytes.to_string()),
        (
            "cache.unregistered_count",
            du.cache.unregistered_count.to_string(),
        ),
        (
            "cache.unregistered_bytes",
            du.cache.unregistered_bytes.to_string(),
        ),
        (
            "cache.foreign_entries",
            du.cache.foreign_entries.to_string(),
        ),
    ];
    for (k, v) in rows {
        s.push_str(k);
        s.push('\t');
        s.push_str(&v);
        s.push('\n');
    }
    s
}

/// `image rm` の結果を 1 行 1 事実で整形する。
fn format_rm_outcome(o: &ImageRmOutcome) -> String {
    let mut s = String::new();
    for t in &o.untagged {
        s.push_str(&format!("untagged\t{t}\n"));
    }
    if o.kind == ImageRmKind::Deleted {
        s.push_str(&format!("deleted\t{}\n", o.manifest));
    }
    for d in &o.deleted_blobs {
        s.push_str(&format!("deleted-blob\t{d}\n"));
    }
    for d in &o.undeleted_blobs {
        s.push_str(&format!("undeleted-blob\t{d}\n"));
    }
    s
}

/// `<ref>` を `image rm` の対象へ変換する。純 digest（`sha256:<hex>`）を先に試し、それ以外は oci の参照解析に委ねる。
/// `name@digest` は digest 優先（oci の正規化規則）。
fn parse_target(input: &str) -> Result<ImageRmTarget, OciError> {
    if let Ok(d) = Digest::parse(input) {
        return Ok(ImageRmTarget::Manifest(d));
    }
    let r = ImageReference::parse(input)?;
    Ok(match r.reference() {
        Reference::Tag(t) => ImageRmTarget::Tag(TagKey::new(
            r.registry().clone(),
            r.repository().clone(),
            t.clone(),
        )),
        Reference::Digest(d) => ImageRmTarget::Manifest(d.clone()),
    })
}

/// `image ls` の実処理（ストアは呼び出し側が開く）。
fn run_image_ls_with(store: &ImageStore, out: &mut dyn Write) -> CliExit {
    let list = match store.lock() {
        Ok(g) => g.list_images(store.root()),
        Err(e) => return oci_failure(&e, Stage::Lock),
    };
    match list {
        Ok(l) => match write_out(out, &format_image_ls(&l)) {
            Ok(()) => CliExit::Success,
            Err(e) => e,
        },
        Err(e) => oci_failure(&e, Stage::Read),
    }
}

/// `system df` の実処理。
fn run_system_df_with(store: &ImageStore, out: &mut dyn Write) -> CliExit {
    let usage = match store.lock() {
        Ok(g) => g.disk_usage(store.root()),
        Err(e) => return oci_failure(&e, Stage::Lock),
    };
    match usage {
        Ok(u) => match write_out(out, &format_system_df(&u)) {
            Ok(()) => CliExit::Success,
            Err(e) => e,
        },
        Err(e) => oci_failure(&e, Stage::Read),
    }
}

/// `image rm` の実処理。`snapshot` は `--force` で使用中のときだけ、**ガードを手放した状態で**呼ばれる。
fn run_image_rm_with(
    store: &ImageStore,
    target: &ImageRmTarget,
    force: bool,
    snapshot: &dyn Fn() -> Result<StoppedContainers, CliExit>,
    out: &mut dyn Write,
) -> CliExit {
    let opts = if force {
        ImageRmOptions::force()
    } else {
        ImageRmOptions::default()
    };
    let none = StoppedContainers::new();
    // 1 回目: スナップショット無し（全コンテナ実行中扱い）で判定する。
    let first = {
        let mut guard = match store.lock() {
            Ok(g) => g,
            Err(e) => return oci_failure(&e, Stage::Lock),
        };
        match guard.plan_image_rm_with(target, &opts, &none) {
            Err(e) => return oci_failure(&e, Stage::Remove),
            Ok(ImageRmPlan::Refuse(_)) => None,
            Ok(_) => Some(guard.execute_image_rm(store.root(), target, &opts, &none)),
        }
    };
    let result = match first {
        Some(r) => r,
        None if !force => return in_use(false),
        None => {
            // ガードは手放し済み。状態ストアはガードの外で読む（oci の排他の契約）。
            let stopped = match snapshot() {
                Ok(s) => s,
                Err(e) => return e,
            };
            let mut guard = match store.lock() {
                Ok(g) => g,
                Err(e) => return oci_failure(&e, Stage::Lock),
            };
            match guard.plan_image_rm_with(target, &opts, &stopped) {
                Err(e) => return oci_failure(&e, Stage::Remove),
                Ok(ImageRmPlan::Refuse(_)) => return in_use(true),
                Ok(_) => guard.execute_image_rm(store.root(), target, &opts, &stopped),
            }
        }
    };
    let outcome = match result {
        Ok(o) => o,
        Err(e) => return oci_failure(&e, Stage::Remove),
    };
    if let Err(e) = write_out(out, &format_rm_outcome(&outcome)) {
        return e;
    }
    if outcome.undeleted_blobs.is_empty() {
        CliExit::Success
    } else {
        CliExit::Error(CliError::new(ErrorCode::Internal, MSG_UNDELETED))
    }
}

/// 使用中の拒否。`--force` を付けていなければ回復手段を添える。
fn in_use(forced: bool) -> CliExit {
    let msg = if forced { MSG_IN_USE } else { MSG_IN_USE_HINT };
    CliExit::Error(CliError::new(ErrorCode::FailedPrecondition, msg))
}

/// 状態ストアから停止中のコンテナの集合を作る。ページ数に上限を置き（REPAIR-5）、読めなければ fail-closed で失敗する。
fn stopped_snapshot(global: &GlobalArgs) -> Result<StoppedContainers, CliExit> {
    let store = open_store(global).map_err(|e| store_open_failure(&e))?;
    snapshot_from(&store).map_err(|e| CliExit::failed(e.code()))
}

fn snapshot_from(store: &dyn StateStore) -> Result<StoppedContainers, TraitError> {
    let page_size = NonZeroU32::new(MAX_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let mut req = ListStateRequest::new(page_size)?;
    let mut stopped = StoppedContainers::new();
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        for record in page.records() {
            if record.status().state() == ContainerState::Stopped
                && let Ok(id) = ContainerRefId::new(record.id().as_str())
            {
                stopped.insert(id);
            }
        }
        match page.next_cursor() {
            Some(cursor) => req = req.with_cursor(cursor.clone()),
            None => return Ok(stopped),
        }
    }
    Err(TraitError::new(
        ErrorCode::Internal,
        "state listing did not terminate",
    ))
}

/// 計測へ成功・失敗を 1 回記録して出力する（REPAIR-4）。
fn with_ops(op_name: &str, f: impl FnOnce() -> CliExit) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let exit = f();
    record_op(
        &recorder,
        op_name,
        matches!(exit, CliExit::Success),
        started,
    );
    export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    exit
}

/// 非 Linux は他コマンドと同じ plugin 解決の失敗で fail-closed に終える（moduleの doc「未実装」）。
/// Linux では `None`。定数の分岐にして、非 Linux でも以降の関数が未使用にならないようにする。
fn non_linux_failure(global: &GlobalArgs) -> Option<CliExit> {
    if cfg!(target_os = "linux") {
        return None;
    }
    // 非 Linux の `open_store` は plugin 解決の失敗（TraitError）を返すだけで、状態ルートには触れない。
    Some(match open_store(global) {
        Err(e) => store_open_failure(&e),
        // 到達しない（非 Linux の open_store は常に Err）。到達しても実行はせず fail-closed。
        Ok(_) => CliExit::failed(ErrorCode::FailedPrecondition),
    })
}

fn open_image_store(root: &std::path::Path) -> Result<ImageStore, CliExit> {
    ImageStore::open(root).map_err(|e| oci_failure(&e, Stage::Open))
}

/// 本番入口の `image`。
pub(super) fn run_image(global: &GlobalArgs, args: &ImageArgs, stdout: &mut dyn Write) -> CliExit {
    if let Some(e) = non_linux_failure(global) {
        return e;
    }
    match args {
        ImageArgs::Ls(a) => with_ops("image_ls", || match open_image_store(&a.image_root) {
            Ok(store) => run_image_ls_with(&store, stdout),
            Err(e) => e,
        }),
        ImageArgs::Rm(a) => with_ops("image_rm", || {
            let target = match parse_target(&a.reference) {
                Ok(t) => t,
                Err(e) => return oci_failure(&e, Stage::Remove),
            };
            match open_image_store(&a.image_root) {
                Ok(store) => run_image_rm_with(
                    &store,
                    &target,
                    a.force,
                    &|| stopped_snapshot(global),
                    stdout,
                ),
                Err(e) => e,
            }
        }),
    }
}

/// 本番入口の `system`。
pub(super) fn run_system(
    global: &GlobalArgs,
    args: &SystemArgs,
    stdout: &mut dyn Write,
) -> CliExit {
    if let Some(e) = non_linux_failure(global) {
        return e;
    }
    match args {
        SystemArgs::Df(a) => with_ops("system_df", || match open_image_store(&a.image_root) {
            Ok(store) => run_system_df_with(&store, stdout),
            Err(e) => e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_oci::image_management::{ManifestComposition, ReferenceTable};
    use fandhe_container_oci::reference::{RegistryHost, Repository, Tag};
    use std::cell::Cell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 試験用の一時ディレクトリ（drop で削除）。
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-cli-image-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
            Tmp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn put_blob(&self, c: char, len: usize) {
            let hex: String = std::iter::repeat_n(c, 64).collect();
            std::fs::write(
                self.0.join("blobs").join("sha256").join(hex),
                vec![b'x'; len],
            )
            .expect("write");
        }
        fn has_blob(&self, c: char) -> bool {
            let hex: String = std::iter::repeat_n(c, 64).collect();
            self.0.join("blobs").join("sha256").join(hex).exists()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dg(c: char) -> Digest {
        Digest::parse(&format!(
            "sha256:{}",
            std::iter::repeat_n(c, 64).collect::<String>()
        ))
        .expect("digest")
    }

    fn key(repo: &str, tag: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry-1.docker.io").expect("host"),
            Repository::parse(repo).expect("repo"),
            Tag::parse(tag).expect("tag"),
        )
    }

    /// manifest(config=`c`, layers=`l`) を登録する。
    fn add_manifest(t: &mut ReferenceTable, m: char, c: char, l: &[char]) {
        let layers = l.iter().map(|x| dg(*x)).collect();
        t.register_manifest(
            dg(m),
            ManifestComposition::new(dg(c), layers).expect("comp"),
        )
        .expect("register");
    }

    fn out_of(f: impl FnOnce(&mut Vec<u8>) -> CliExit) -> (CliExit, String) {
        let mut buf = Vec::new();
        let e = f(&mut buf);
        (e, String::from_utf8(buf).expect("utf8"))
    }

    fn stderr_of(e: &CliExit) -> String {
        let mut b = Vec::new();
        e.write_stderr(&mut b).expect("write");
        String::from_utf8(b).expect("utf8")
    }

    fn no_snapshot() -> Result<StoppedContainers, CliExit> {
        panic!("snapshot must not be read");
    }

    /// CLI-1・OCI-7: 空ストアの image ls はヘッダのみで 0。
    #[test]
    fn cli1_oci7_image_ls_empty_is_header_only() {
        let tmp = Tmp::new();
        let store = ImageStore::open(tmp.path()).expect("open");
        let (e, out) = out_of(|o| run_image_ls_with(&store, o));
        assert_eq!(e.exit_code(), 0);
        assert_eq!(out, "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n");
    }

    /// CLI-1・OCI-7: タグつき 2 行とタグなし 1 行・欠損 blob を具体値で照合する。
    #[test]
    fn cli1_oci7_image_ls_lists_tagged_and_dangling_rows() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 10);
        tmp.put_blob('b', 20);
        tmp.put_blob('c', 5);
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &['b']);
        add_manifest(&mut t, '2', 'a', &['c', 'd']); // d は欠損
        add_manifest(&mut t, '3', 'c', &[]);
        t.register_tag(key("library/busybox", "latest"), &dg('1'))
            .expect("tag");
        t.register_tag(key("library/busybox", "1.36"), &dg('2'))
            .expect("tag");
        let store = ImageStore::with_table(tmp.path(), t).expect("open");
        let (e, out) = out_of(|o| run_image_ls_with(&store, o));
        assert_eq!(e.exit_code(), 0);
        let h1 = "1".repeat(64);
        let h2 = "2".repeat(64);
        let h3 = "3".repeat(64);
        let expect = format!(
            "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n\
             registry-1.docker.io/library/busybox\t1.36\tsha256:{h2}\t15\t1\n\
             registry-1.docker.io/library/busybox\tlatest\tsha256:{h1}\t30\t0\n\
             -\t-\tsha256:{h3}\t5\t0\n"
        );
        assert_eq!(out, expect);
    }

    /// CLI-1・OCI-7: system df の 9 行を具体値で照合する（共有レイヤーは二重計上しない・未登録 blob は別集計）。
    #[test]
    fn cli1_oci7_system_df_fixed_nine_rows() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 10);
        tmp.put_blob('b', 20);
        tmp.put_blob('e', 7); // 未登録
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &['b']);
        add_manifest(&mut t, '2', 'a', &['b']);
        t.register_tag(key("library/x", "t1"), &dg('1'))
            .expect("tag");
        let store = ImageStore::with_table(tmp.path(), t).expect("open");
        let (e, out) = out_of(|o| run_system_df_with(&store, o));
        assert_eq!(e.exit_code(), 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], "KEY\tVALUE");
        let keys: Vec<&str> = lines[1..]
            .iter()
            .map(|l| l.split('\t').next().expect("key"))
            .collect();
        assert_eq!(
            keys,
            [
                "images.count",
                "images.bytes",
                "images.reclaimable_bytes",
                "images.missing_blobs",
                "cache.blob_count",
                "cache.bytes",
                "cache.unregistered_count",
                "cache.unregistered_bytes",
                "cache.foreign_entries"
            ]
        );
        assert!(out.contains("images.count\t2\n"));
        assert!(out.contains("images.bytes\t30\n"));
        assert!(out.contains("cache.blob_count\t3\n"));
        assert!(out.contains("cache.bytes\t37\n"));
        assert!(out.contains("cache.unregistered_count\t1\n"));
        assert!(out.contains("cache.unregistered_bytes\t7\n"));
    }

    fn rm_store(tmp: &Tmp, containers: &[&str]) -> ImageStore {
        // manifest 1: config a + layer b（共有しない）、タグ latest 1 件。
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &['b']);
        t.register_tag(key("library/busybox", "latest"), &dg('1'))
            .expect("tag");
        for c in containers {
            t.register_container(ContainerRefId::new(c).expect("cid"), &dg('1'))
                .expect("container");
        }
        ImageStore::with_table(tmp.path(), t).expect("open")
    }

    fn target(s: &str) -> ImageRmTarget {
        parse_target(s).expect("target")
    }

    /// OCI-7: タグが 2 件あるイメージのタグ指定は untag だけで blob を残す。
    #[test]
    fn cli1_oci7_image_rm_tag_with_two_tags_untags_only() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &['b']);
        t.register_tag(key("library/busybox", "latest"), &dg('1'))
            .expect("tag");
        t.register_tag(key("library/busybox", "v1"), &dg('1'))
            .expect("tag");
        let store = ImageStore::with_table(tmp.path(), t).expect("open");
        let (e, out) =
            out_of(|o| run_image_rm_with(&store, &target("busybox:v1"), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 0);
        assert_eq!(out, "untagged\tregistry-1.docker.io/library/busybox:v1\n");
        assert!(tmp.has_blob('a') && tmp.has_blob('b'));
    }

    /// OCI-7: 最後のタグの削除は完全削除（manifest と blob の実ファイルが消える）。
    #[test]
    fn cli1_oci7_image_rm_last_tag_deletes_blobs() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &[]);
        let (e, out) =
            out_of(|o| run_image_rm_with(&store, &target("busybox"), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 0);
        let h1 = "1".repeat(64);
        assert!(out.starts_with("untagged\tregistry-1.docker.io/library/busybox:latest\n"));
        assert!(out.contains(&format!("deleted\tsha256:{h1}\n")));
        assert!(out.contains(&format!("deleted-blob\tsha256:{}\n", "a".repeat(64))));
        assert!(out.contains(&format!("deleted-blob\tsha256:{}\n", "b".repeat(64))));
        assert!(!tmp.has_blob('a') && !tmp.has_blob('b'));
    }

    /// OCI-7: digest 指定の完全削除。
    #[test]
    fn cli1_oci7_image_rm_by_digest() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &[]);
        let d = format!("sha256:{}", "1".repeat(64));
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target(&d), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 0);
        assert!(out.contains("deleted\t"));
        assert!(!tmp.has_blob('a'));
    }

    /// OCI-7: コンテナ参照ありで --force なしは 5。文言は固定でコンテナ ID を含まない。ファイルは不変。
    #[test]
    fn cli1_oci7_image_rm_in_use_refuses_without_leaking_container_id() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &["secret-container-id"]);
        let (e, out) =
            out_of(|o| run_image_rm_with(&store, &target("busybox"), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 5);
        assert_eq!(e.code(), Some("FAILED_PRECONDITION"));
        assert_eq!(out, "");
        let err = stderr_of(&e);
        assert!(err.contains(MSG_IN_USE_HINT));
        assert!(!err.contains("secret-container-id"));
        assert!(tmp.has_blob('a') && tmp.has_blob('b'));
    }

    /// OCI-7: --force かつスナップショットで停止中なら untag だけで blob を残す。
    #[test]
    fn cli1_oci7_image_rm_force_stopped_untags_only() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &["c1"]);
        let called = Cell::new(0u32);
        let snap = || {
            called.set(called.get() + 1);
            Ok(StoppedContainers::from_iter([
                ContainerRefId::new("c1").expect("id")
            ]))
        };
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target("busybox"), true, &snap, o));
        assert_eq!(e.exit_code(), 0);
        assert_eq!(
            out,
            "untagged\tregistry-1.docker.io/library/busybox:latest\n"
        );
        assert_eq!(called.get(), 1);
        assert!(tmp.has_blob('a') && tmp.has_blob('b'));
    }

    /// OCI-7: --force でもスナップショットに無い（実行中扱い）コンテナは拒否する。
    #[test]
    fn cli1_oci7_image_rm_force_running_is_refused() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        let store = rm_store(&tmp, &["c1"]);
        let snap = || Ok(StoppedContainers::new());
        let (e, _) = out_of(|o| run_image_rm_with(&store, &target("busybox"), true, &snap, o));
        assert_eq!(e.exit_code(), 5);
        assert!(stderr_of(&e).contains(MSG_IN_USE));
        assert!(!stderr_of(&e).contains("--force"));
    }

    /// OCI-7・REPAIR-5: --force でスナップショット取得が失敗したらそのエラーで終わり、何も変えない（fail-closed）。
    #[test]
    fn cli1_oci7_image_rm_force_snapshot_failure_is_fail_closed() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &["c1"]);
        let snap = || Err(CliExit::failed(ErrorCode::Unavailable));
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target("busybox"), true, &snap, o));
        assert_eq!(
            e.exit_code(),
            CliExit::failed(ErrorCode::Unavailable).exit_code()
        );
        assert_eq!(out, "");
        assert!(tmp.has_blob('a') && tmp.has_blob('b'));
        // タグが残っている（同じ対象をもう一度判定できる）。
        let (e2, _) =
            out_of(|o| run_image_rm_with(&store, &target("busybox"), false, &no_snapshot, o));
        assert_eq!(e2.exit_code(), 5);
    }

    /// OCI-7: 未知の参照は 3、不正な参照は parse_target の段階で失敗する。
    #[test]
    fn cli1_oci7_image_rm_unknown_and_invalid_reference() {
        let tmp = Tmp::new();
        let store = rm_store(&tmp, &[]);
        let (e, _) =
            out_of(|o| run_image_rm_with(&store, &target("nope:1"), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 3);
        assert_eq!(e.code(), Some("NOT_FOUND"));
        assert!(stderr_of(&e).contains(MSG_IMAGE_NOT_FOUND));
        let bad = parse_target("bad ref!").expect_err("invalid");
        assert_eq!(bad.code(), OciErrorCode::InvalidArgument);
    }

    /// CLI-1・OCI-7: root の不在は 3、通常ファイルは 5、blobs が symlink なら ls は 5。
    #[test]
    fn cli1_oci7_store_root_failures() {
        let tmp = Tmp::new();
        let missing = tmp.path().join("missing");
        let e = open_image_store(&missing).expect_err("missing");
        assert_eq!(e.exit_code(), 3);
        assert!(stderr_of(&e).contains(MSG_ROOT_NOT_FOUND));
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        let e = open_image_store(&file).expect_err("file");
        assert_eq!(e.exit_code(), 5);
        assert!(stderr_of(&e).contains(MSG_ROOT_NOT_DIRECTORY));
        #[cfg(unix)]
        {
            let root2 = Tmp::new();
            std::fs::remove_dir_all(root2.path().join("blobs")).expect("rm");
            std::os::unix::fs::symlink(tmp.path(), root2.path().join("blobs")).expect("symlink");
            let store = ImageStore::open(root2.path()).expect("open");
            let (e, out) = out_of(|o| run_image_ls_with(&store, o));
            assert_eq!(e.exit_code(), 5);
            assert_eq!(out, "");
        }
    }

    /// OCI-7: 純 digest・名前@digest・タグ参照の変換。
    #[test]
    fn cli1_oci7_parse_target_forms() {
        let h = "a".repeat(64);
        assert_eq!(
            parse_target(&format!("sha256:{h}")).expect("digest"),
            ImageRmTarget::Manifest(dg('a'))
        );
        assert_eq!(
            parse_target(&format!("busybox@sha256:{h}")).expect("name@digest"),
            ImageRmTarget::Manifest(dg('a'))
        );
        assert_eq!(
            parse_target("busybox").expect("tag"),
            ImageRmTarget::Tag(key("library/busybox", "latest"))
        );
    }

    /// OCI-7: undeleted_blobs が非空のときは INTERNAL で失敗する（整形は undeleted-blob 行を含む）。
    /// `ImageRmOutcome` は構築できないため、権限で削除を失敗させて実際に発生させる。
    #[cfg(unix)]
    #[test]
    fn cli1_oci7_image_rm_undeleted_blob_is_internal_failure() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &[]);
        let dir = tmp.path().join("blobs").join("sha256");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        // root（権限検査が効かない）では削除が成功してしまうため、効かない環境では検証を飛ばさず期待を切り替える。
        let writable_anyway = std::fs::write(dir.join("probe"), b"").is_ok();
        let (e, out) =
            out_of(|o| run_image_rm_with(&store, &target("busybox"), false, &no_snapshot, o));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        if writable_anyway {
            assert_eq!(e.exit_code(), 0);
        } else {
            assert_eq!(e.exit_code(), 1);
            assert_eq!(e.code(), Some("INTERNAL"));
            assert!(out.contains("undeleted-blob\tsha256:"));
            assert!(stderr_of(&e).contains(MSG_UNDELETED));
        }
    }

    /// 固定文言は引用符・バックスラッシュ・制御文字を含まない（JSON を壊さない）。
    #[test]
    fn err1_fixed_messages_are_json_safe() {
        for m in [
            MSG_ROOT_NOT_FOUND,
            MSG_ROOT_NOT_DIRECTORY,
            MSG_LOCKED,
            MSG_IMAGE_NOT_FOUND,
            MSG_IN_USE,
            MSG_IN_USE_HINT,
            MSG_UNDELETED,
            MSG_BLOB_DIR,
            MSG_SCAN_LIMIT,
        ] {
            assert!(
                !m.contains(['"', '\\']) && !m.chars().any(char::is_control),
                "{m}"
            );
        }
        let codes = [
            OciErrorCode::InvalidArgument,
            OciErrorCode::NotFound,
            OciErrorCode::AlreadyExists,
            OciErrorCode::FailedPrecondition,
            OciErrorCode::PermissionDenied,
            OciErrorCode::Timeout,
            OciErrorCode::Unimplemented,
            OciErrorCode::Unavailable,
            OciErrorCode::DataLoss,
            OciErrorCode::ResourceExhausted,
            OciErrorCode::Internal,
        ];
        for c in codes {
            for s in [Stage::Open, Stage::Lock, Stage::Read, Stage::Remove] {
                let m = failure_message(c, s);
                assert!(
                    !m.contains(['"', '\\']) && !m.chars().any(char::is_control),
                    "{m}"
                );
            }
        }
        assert_eq!(map_code(OciErrorCode::DataLoss), ErrorCode::Internal);
        assert_eq!(
            map_code(OciErrorCode::ResourceExhausted),
            ErrorCode::Internal
        );
        assert_eq!(map_code(OciErrorCode::NotFound), ErrorCode::NotFound);
    }
}
