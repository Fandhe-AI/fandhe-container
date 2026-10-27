//! `image ls` / `system df` / `image rm` / `image tag` コマンド本体（oci の管理 API への配線。#2221・#2316・CLI-1・OCI-7・TASK-183）。
//!
//! `commands::run_to` が argv を解析した後に [`run_image`] / [`run_system`] を呼ぶ。実処理は
//! `fandhe-container-oci` の `image_management`（`ImageStore`・`ReferenceTable::list_images`・`disk_usage`・
//! `plan_image_rm_with`・`execute_image_rm`・`ImageStore::tag_image`）へ委ね、CLI は引数の解析・出力の整形・エラーの写像だけを担う。
//! イメージの参照解釈は、digest に見える入力（`sha256:` / `sha384:` / `sha512:` で始まり `/` も `@` も含まない）を
//! `image_refs::is_bare_digest_form` で先に判別し（`create --image` と共有。OCI-7・#2600）、それ以外を oci の
//! `ImageReference::parse`（docker.io の正規化・`library/` と `latest` の補完を含む）に委ねる。digest に見えて
//! `sha256:<小文字 hex 64 桁>` でない入力（大文字 hex・`sha512:`・長さ違い）はタグと誤読せず `INVALID_ARGUMENT`
//! （`MSG_BAD_DIGEST`）で拒否する。repository 名が `sha256` のイメージは `docker.io/library/sha256:<tag>` と書く。
//!
//! `name@digest` は `create --image` と違い受ける（digest 優先。#2221・#2316 以来の契約）。rm / tag は manifest digest 自体を
//! 対象にする管理操作で、name は構文検証だけ通して捨て、digest 部は `Digest::parse` で厳格に検証するため、操作の範囲は
//! 素の digest を渡した場合と同じで広がらない。
//!
//! ## `name@digest` を受け続ける判断（#2659・OCI-7・CLI-1・TASK-183。pull の配線 #2539・#2800 の後の再判断）
//!
//! 現時点の決定は (a) 受け続ける（挙動を変えない）。理由は次のとおり。
//!
//! - 配線の後も在庫は manifest ごとの repository を持たない。repository を持つのはタグ（`TagKey`）だけで、digest 指定で
//!   pull した manifest には名前が残らない。このため「name と在庫の repository の一致を要求する」(b) は、正確には実装できない。
//!   実装できる形は「その manifest に付いたタグの host / repository と照合する」だけで、タグの無い manifest では常に不一致になり (c) と同じになる。
//! - (b) を正しく実装するには、在庫のスキーマへ manifest ごとの repository を記録する必要がある（oci の永続化形式の変更）。
//! - (c)（`create --image` と同じ拒否）は既存契約（#2221・#2316）の破壊になる。
//!
//! (b)・(c) への切り替えはオーナーの判断待ちで、見直しの契機は「在庫が manifest ごとの repository を持ったとき」
//! または「オーナーが (b)・(c) を選んだとき」。残余リスク: 食い違う name を黙って捨てるため、別 repository のタグごと
//! 削除・タグ付けしうる（素の digest でも同じ範囲）。この決定は `cli1_oci7_image_rm_name_at_digest_*` などの試験で固定している。
//!
//! # 構文
//!
//! `image ls --image-root <abs>` / `system df --image-root <abs>` / `image rm [--force] --image-root <abs> <ref>` / `image tag --image-root <abs> <source> <target>`。
//! イメージストアの root は必須オプション `--image-root`（絶対パス）で受ける。既定位置は未決のため発明しない（下記「未実装」）。
//! root は作らない（`ImageStore::open` が存在するディレクトリ・非 symlink・所有者・書き込み権限・祖先を検査する。#2381）。
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
//! - `image tag`（#2316）: `tagged\t<tag>\t<manifest>`（新規）・`retagged\t<tag>\t<付け替え前>\t<付け替え後>`（付け替え）・
//!   `unchanged\t<tag>\t<manifest>`（同じ付け先への再付与）を 1 行で出す。いずれも終了コード 0。`source` は既存タグまたは
//!   manifest digest、`target` はタグ参照のみ（digest は `INVALID_ARGUMENT`）。タグ件数が oci の `MAX_TAG_REFS` を超える
//!   新規タグは oci が `ResourceExhausted` で拒否し、`RESOURCE_EXHAUSTED`（10）と固定文言
//!   （`MSG_TAG_LIMIT`）で返す（#2609 で core に `ErrorCode::ResourceExhausted` を追加済み）。
//!
//! # エラー写像（ERR-1・ERR-2）
//!
//! oci の `OciErrorCode` を core の `ErrorCode` へ同名で写す（`DataLoss`・`Internal` は `INTERNAL`、`ResourceExhausted` は `RESOURCE_EXHAUSTED`）。
//! `message` は本 module の固定文言表のみで、oci の `OciError::message`（コンテナ ID を含みうる）は出力へ流さない。
//!
//! # `image rm` の排他手順
//!
//! oci の契約（ガードを保持したまま `StateStore` の操作を取らない・状態のスナップショットはガード取得前に読む）を守る。
//! 1. ガードを取り `--force` なしで判定する。参照が無い・`UntagOnly`/`Delete` ならそのまま実行して終わる。
//!    使用中の拒否なら、**ガードを手放して**拒否に載った参照を照合・回収し（`ref_reconcile`。create ゲートの排他の下。#2495）、
//!    もう一度同じ判定をする（照合できなければ何も外さず拒否のまま）。
//! 2. 使用中で `--force` なしなら拒否する。`--force` ありなら**ガードを手放して**状態ストアを読み、
//!    停止中のコンテナの集合を作る（読めなければそのエラーで終了。fail-closed）。
//! 3. 再びガードを取り、スナップショット付きで判定し直す。スナップショット後に起動したコンテナは実行中扱いで拒否される。
//!
//! # 未実装・前提（実装済みを装わない。REPAIR-3）
//!
//! - コンテナ参照（`@container-refs.json`）は永続化済み（#2341・#2352）で、manifest の在庫・タグ・リース（`@image-inventory.json`）も
//!   oci 側で永続化済み（#2380。`ImageStore::lock` が排他取得のたびに読み直すので、CLI 側の配線は要らない）。在庫を埋める経路は cri の
//!   `OciImagePuller::pull`（`PullImage`）に配線済み（#2539）。CLI に `pull` サブコマンドは無く、同じ root を `--image-root` に渡せば
//!   その在庫が見える。本番の `PullImage` へは plugin-cri の ImageService（#2592）から届く。pull していない root の在庫は
//!   空のため、その root では `image ls` がヘッダのみ、`system df` の images 側が 0 件（キャッシュ側は実ファイルを全件「未登録」として数える）、
//!   `image rm` と `image tag` が `NOT_FOUND` になる（在庫が入れば `image tag` のタグはプロセスをまたいで残る）。create / delete の `--image-root`〔`image_refs`・#2315〕も同じ在庫を使う。
//! - `--image-root` の経路では `recover_stale_pulls`（残った pull の回収 GC）を呼ばない。CLI は pull を持たず短命のため、同じ root を使う plugin-cri の起動時に回収される（#2819・OCI-7）。
//! - `--image-root` 省略時の既定位置（Linux の root / rootless、macOS / Windows の置き場。MAC-4・WIN-1）は未決。
//! - macOS / Windows ではイメージキャッシュの置き場（ゲスト VM 内かホストか）が未決のため、ローカルの oci を呼ばず
//!   他コマンドと同じ plugin 解決の失敗（`list_logs::store_open_failure`）で fail-closed に失敗する。
//! - `system df` の containers・staging・展開後サイズは oci が未計測のため出さない（#2222）。
//! - `image prune` の CLI 配線（配線時は `image rm` と同じく `ref_reconcile::reconcile_in_use` を呼ぶ）は範囲外。
//! - oci の `OciOpRecorder` は `oci_recorder::CliOciRecorder` で CLI の `OpRecorder` へ橋渡しし、`image ls` / `image rm` / `image tag` / `system df` の
//!   `ImageStore` に付ける（`oci.*` の名前で記録。#2968・REPAIR-4・OCI-1）。CLI に pull・展開の経路は無いため、それらの計装は経路が入った時点で同じアダプタを渡す。

use std::io::Write;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::traits::{
    ContainerState, ErrorCode, ListStateRequest, MAX_PAGE_SIZE, StateStore, TraitError,
};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    ContainerRefId, DiskUsage, ImageList, ImageRmKind, ImageRmOptions, ImageRmOutcome, ImageRmPlan,
    ImageRmTarget, ImageStore, ImageTagChange, ImageTagOutcome, ImageTagSource, StoppedContainers,
    TagKey,
};
use fandhe_container_oci::instrument::OciOpRecorder;
use fandhe_container_oci::reference::{Digest, ImageReference, Reference};

use super::CliExit;
use super::args::{GlobalArgs, ImageArgs, SystemArgs};
use super::create_start::{OP_LOG_ENV, export_ops, open_store};
use super::image_refs::{is_bare_digest_form, legacy_scope, ref_key, state_scope};
use super::list_logs::{MAX_LIST_PAGES, record_op, store_open_failure};
use super::oci_recorder::CliOciRecorder;
use super::ref_reconcile::reconcile_for_image_rm;
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
const MSG_TAG_LIMIT: &str = "image tag limit exceeded";
const MSG_REF_LIMIT: &str = "container reference limit exceeded";
pub(super) const MSG_TAG_NOT_FOUND: &str = "image tag not found";
/// digest に見えるが `sha256:<小文字 hex 64 桁>` でない入力の固定文言（core の `ImageManifestDigest::new` と同一。試験で照合）。
const MSG_BAD_DIGEST: &str = "manifest digest must be sha256:<64 lowercase hex>";
const MSG_TAG_TARGET: &str = "target must be a tag reference";

/// 失敗が出た段階。同じ `OciErrorCode` でも段階で意味が違う（`NotFound` はストア root の不在か対象イメージの不在か）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    /// `ImageStore::open`（root の検証）。
    Open,
    /// `ImageStore::lock`（排他区間の取得）。
    Lock,
    /// ls / df の読み取り。
    Read,
    /// `image rm` の判定・実行。
    Remove,
    /// `image tag` の解決・登録（排他の取得失敗も含む）。
    Tag,
    /// create / delete のコンテナ参照の登録・解除（`image_refs::StoreImageRefs`。#2315・OCI-7）。
    Refs,
    /// create の `--image` のタグ参照の解決（`image_refs::resolve_create_image`。#2496・OCI-7・CLI-1）。
    Resolve,
}

/// oci の分類を core の `ErrorCode` へ写す。`OciErrorCode` も `#[non_exhaustive]` で `_` 腕が要り、
/// `DataLoss`（core に対応が無い）と未知は `Internal` に畳む。全件の対応は試験が `OciErrorCode::ALL` から照合する。
pub(super) fn map_code(code: OciErrorCode) -> ErrorCode {
    match code {
        OciErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        OciErrorCode::NotFound => ErrorCode::NotFound,
        OciErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        OciErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
        OciErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        OciErrorCode::Timeout => ErrorCode::Timeout,
        OciErrorCode::Unimplemented => ErrorCode::Unimplemented,
        OciErrorCode::Unavailable => ErrorCode::Unavailable,
        OciErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    }
}

/// 段階つきの固定文言表。oci の `message` は使わない（argv・パス・コンテナ ID を出力へ埋め込まない）。
pub(super) fn failure_message(code: OciErrorCode, stage: Stage) -> &'static str {
    match (stage, code) {
        (Stage::Open, OciErrorCode::NotFound) => MSG_ROOT_NOT_FOUND,
        (Stage::Open, OciErrorCode::FailedPrecondition) => MSG_ROOT_NOT_DIRECTORY,
        (Stage::Lock, OciErrorCode::Timeout) => MSG_LOCKED,
        (Stage::Remove | Stage::Tag, OciErrorCode::NotFound) => MSG_IMAGE_NOT_FOUND,
        // `ImageStore::tag_image` の Timeout は排他の取得失敗だけ。
        (Stage::Tag, OciErrorCode::Timeout) => MSG_LOCKED,
        (Stage::Tag, OciErrorCode::ResourceExhausted) => MSG_TAG_LIMIT,
        // 参照の登録先は `register_container_ref` の NotFound（manifest が在庫に無い）が主。
        (Stage::Resolve, OciErrorCode::NotFound) => MSG_TAG_NOT_FOUND,
        (Stage::Resolve, OciErrorCode::Timeout) => MSG_LOCKED,
        (Stage::Refs, OciErrorCode::NotFound) => MSG_IMAGE_NOT_FOUND,
        (Stage::Refs, OciErrorCode::Timeout) => MSG_LOCKED,
        (Stage::Refs, OciErrorCode::ResourceExhausted) => MSG_REF_LIMIT,
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

/// oci の失敗を、固定文言つきの core の `TraitError` へ写す（create / delete の配線用。`OciError::message` は流さない）。
pub(super) fn trait_failure(e: &OciError, stage: Stage) -> TraitError {
    TraitError::new(map_code(e.code()), failure_message(e.code(), stage))
}

/// create / delete の `--image-root` を開く。core に入る前に呼び、失敗は固定文言の `TraitError`（`Stage::Open`）にする。
pub(super) fn open_image_store_for_lifecycle(
    root: &std::path::Path,
) -> Result<ImageStore, TraitError> {
    ImageStore::open(root).map_err(|e| trait_failure(&e, Stage::Open))
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

/// 解析済みのイメージ参照（タグ参照か manifest digest か）。`image rm` の対象と `image tag` の source/target が共有する。
enum ParsedRef {
    Tag(TagKey),
    Digest(Digest),
}

/// digest に見える入力は `Digest::parse` だけで決め（失敗は `MSG_BAD_DIGEST`。タグへ流さない）、それ以外は oci の参照解析に委ねる。
/// `name@digest` は digest 優先（oci の正規化規則。module doc）。
fn parse_ref(input: &str, stage: Stage) -> Result<ParsedRef, CliExit> {
    if is_bare_digest_form(input) {
        return Digest::parse(input).map(ParsedRef::Digest).map_err(|_| {
            CliExit::Error(CliError::new(ErrorCode::InvalidArgument, MSG_BAD_DIGEST))
        });
    }
    let r = ImageReference::parse(input).map_err(|e| oci_failure(&e, stage))?;
    Ok(match r.reference() {
        Reference::Tag(t) => ParsedRef::Tag(TagKey::new(
            r.registry().clone(),
            r.repository().clone(),
            t.clone(),
        )),
        Reference::Digest(d) => ParsedRef::Digest(d.clone()),
    })
}

/// `<ref>` を `image rm` の対象へ変換する。
fn parse_target(input: &str) -> Result<ImageRmTarget, CliExit> {
    Ok(match parse_ref(input, Stage::Remove)? {
        ParsedRef::Tag(k) => ImageRmTarget::Tag(k),
        ParsedRef::Digest(d) => ImageRmTarget::Manifest(d),
    })
}

/// `image tag` の付け元（既存タグまたは manifest digest）へ変換する。
fn parse_tag_source(input: &str) -> Result<ImageTagSource, CliExit> {
    Ok(match parse_ref(input, Stage::Tag)? {
        ParsedRef::Tag(k) => ImageTagSource::Tag(k),
        ParsedRef::Digest(d) => ImageTagSource::Manifest(d),
    })
}

/// `image tag` の付けるタグへ変換する。正しい digest 指定（`name@digest` を含む）は `MSG_TAG_TARGET`、
/// digest に見える不正な入力は `MSG_BAD_DIGEST`（いずれも `INVALID_ARGUMENT`）。
fn parse_tag_target(input: &str) -> Result<TagKey, CliExit> {
    match parse_ref(input, Stage::Tag)? {
        ParsedRef::Tag(k) => Ok(k),
        ParsedRef::Digest(_) => Err(CliExit::Error(CliError::new(
            ErrorCode::InvalidArgument,
            MSG_TAG_TARGET,
        ))),
    }
}

/// `image tag` の結果を 1 行で整形する。未知の区分は `None`（成功を装わず呼び出し側が失敗させる）。
fn format_tag_outcome(o: &ImageTagOutcome) -> Option<String> {
    Some(match &o.change {
        ImageTagChange::Added => format!("tagged\t{}\t{}\n", o.tag, o.manifest),
        ImageTagChange::Moved { from } => {
            format!("retagged\t{}\t{}\t{}\n", o.tag, from, o.manifest)
        }
        ImageTagChange::Unchanged => format!("unchanged\t{}\t{}\n", o.tag, o.manifest),
        _ => return None,
    })
}

/// `image tag` の実処理。解決・存在確認・登録は oci の排他区間（`ImageStore::tag_image`）で 1 回に行う。
fn run_image_tag_with(
    store: &ImageStore,
    source: &ImageTagSource,
    target: TagKey,
    out: &mut dyn Write,
) -> CliExit {
    let outcome = match store.tag_image(source, target) {
        Ok(o) => o,
        Err(e) => return oci_failure(&e, Stage::Tag),
    };
    let Some(text) = format_tag_outcome(&outcome) else {
        return CliExit::failed(ErrorCode::Internal);
    };
    match write_out(out, &text) {
        Ok(()) => CliExit::Success,
        Err(e) => e,
    }
}

/// `image ls` の実処理（ストアは呼び出し側が開く。計装なし。試験用）。
#[cfg(test)]
fn run_image_ls_with(store: &ImageStore, out: &mut dyn Write) -> CliExit {
    run_image_ls_recorded(
        store,
        &fandhe_container_oci::instrument::NoopOciOpRecorder,
        out,
    )
}

/// 計装つきの `image ls`。`list_images_with` へ記録先を渡す（ストアの記録先はロック取得だけに効くため。#2968）。
fn run_image_ls_recorded(
    store: &ImageStore,
    recorder: &dyn OciOpRecorder,
    out: &mut dyn Write,
) -> CliExit {
    let list = match store.lock() {
        Ok(g) => g.list_images_with(recorder, store.root()),
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

/// `system df` の実処理（計装なし。試験用）。
#[cfg(test)]
fn run_system_df_with(store: &ImageStore, out: &mut dyn Write) -> CliExit {
    run_system_df_recorded(
        store,
        &fandhe_container_oci::instrument::NoopOciOpRecorder,
        out,
    )
}

/// 計装つきの `system df`（#2968）。
fn run_system_df_recorded(
    store: &ImageStore,
    recorder: &dyn OciOpRecorder,
    out: &mut dyn Write,
) -> CliExit {
    let usage = match store.lock() {
        Ok(g) => g.disk_usage_with(recorder, store.root()),
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

/// `image rm` の実処理（参照の照合なし）。`run_image_rm_reclaiming` の `reclaim` を何もしない形にしたもの（試験用）。
#[cfg(test)]
fn run_image_rm_with(
    store: &ImageStore,
    target: &ImageRmTarget,
    force: bool,
    snapshot: &dyn Fn() -> Result<StoppedContainers, CliExit>,
    out: &mut dyn Write,
) -> CliExit {
    run_image_rm_reclaiming(store, target, force, snapshot, &|_| {}, out)
}

/// `image rm` の実処理。`snapshot` は `--force` で使用中のときだけ、**ガードを手放した状態で**呼ばれる。
///
/// 1 回目の判定が使用中で拒否したら、**ガードを手放した状態で** `reclaim`（拒否に載った参照の照合と回収。契機 B・#2495）を
/// 呼び、判定をやり直す。照合に失敗・保留しても従来どおりの拒否に進む（残す側に誤る）。
#[cfg(test)]
fn run_image_rm_reclaiming(
    store: &ImageStore,
    target: &ImageRmTarget,
    force: bool,
    snapshot: &dyn Fn() -> Result<StoppedContainers, CliExit>,
    reclaim: &dyn Fn(&[ContainerRefId]),
    out: &mut dyn Write,
) -> CliExit {
    run_image_rm_recorded(
        store,
        &fandhe_container_oci::instrument::NoopOciOpRecorder,
        target,
        force,
        snapshot,
        reclaim,
        out,
    )
}

/// 計装つきの `image rm`（`execute_image_rm_with` へ記録先を渡す。#2968）。
fn run_image_rm_recorded(
    store: &ImageStore,
    recorder: &dyn OciOpRecorder,
    target: &ImageRmTarget,
    force: bool,
    snapshot: &dyn Fn() -> Result<StoppedContainers, CliExit>,
    reclaim: &dyn Fn(&[ContainerRefId]),
    out: &mut dyn Write,
) -> CliExit {
    let opts = if force {
        ImageRmOptions::force()
    } else {
        ImageRmOptions::default()
    };
    let none = StoppedContainers::new();
    // 1 回目: スナップショット無し（全コンテナ実行中扱い）で判定する。
    // `Err(containers)` は使用中の拒否（拒否に載った参照の全件）。
    let attempt = || -> Result<Result<_, Vec<ContainerRefId>>, CliExit> {
        let mut guard = match store.lock() {
            Ok(g) => g,
            Err(e) => return Err(oci_failure(&e, Stage::Lock)),
        };
        match guard.plan_image_rm_with(target, &opts, &none) {
            Err(e) => Err(oci_failure(&e, Stage::Remove)),
            Ok(ImageRmPlan::Refuse(u)) => Ok(Err(u.containers)),
            Ok(_) => Ok(Ok(guard.execute_image_rm_with(
                recorder,
                store.root(),
                target,
                &opts,
                &none,
            ))),
        }
    };
    let first = match attempt() {
        Err(e) => return e,
        Ok(Ok(r)) => Some(r),
        Ok(Err(containers)) => {
            // ガードは手放し済み。照合は状態ストアとゲートを使うため、ガードの外で呼ぶ（ロック順序）。
            reclaim(&containers);
            match attempt() {
                Err(e) => return e,
                Ok(Ok(r)) => Some(r),
                Ok(Err(_)) => None,
            }
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
                Ok(_) => {
                    guard.execute_image_rm_with(recorder, store.root(), target, &opts, &stopped)
                }
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
    // 参照キーは create / delete と同じ状態ルートの scope を含める（含めないと `plan_image_rm_with` の完全一致で
    // 停止中と判定されず `image rm --force` が拒否される。OCI-7）。
    let scope = state_scope(&store).map_err(|e| CliExit::failed(e.code()))?;
    // 旧版の scope（`--root` の字面から決めたもの）のキーで残った参照も停止中として扱う（#2499・OCI-7）。
    let legacy = legacy_scope(global.root.clone(), &scope);
    let scopes: Vec<&str> = std::iter::once(scope.as_str())
        .chain(legacy.as_deref())
        .collect();
    snapshot_from(&store, &scopes).map_err(|e| CliExit::failed(e.code()))
}

fn snapshot_from(store: &dyn StateStore, scopes: &[&str]) -> Result<StoppedContainers, TraitError> {
    let page_size = NonZeroU32::new(MAX_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let mut req = ListStateRequest::new(page_size)?;
    let mut stopped = StoppedContainers::new();
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        for record in page.records() {
            if record.status().state() == ContainerState::Stopped {
                for scope in scopes {
                    if let Ok(id) = ContainerRefId::new(&ref_key(scope, record.id().as_str())) {
                        stopped.insert(id);
                    }
                }
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
///
/// closure には記録器の共有ハンドルを渡す。イメージストアを開く入口（`open_image_store_recorded`）へ渡すと、
/// oci 内の操作が同じ記録器へ `oci.*` の名前で入る（`oci_recorder`。REPAIR-4・OCI-1・#2968）。
fn with_ops(op_name: &str, f: impl FnOnce(&Arc<OpRecorder>) -> CliExit) -> CliExit {
    let started = Instant::now();
    let recorder = Arc::new(OpRecorder::new());
    let exit = f(&recorder);
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

/// `open_image_store` に oci の計装（`OciOpRecorder`）を `recorder` へ橋渡しして付ける（#2968）。
fn open_image_store_recorded(
    root: &std::path::Path,
    recorder: &Arc<OpRecorder>,
) -> Result<ImageStore, CliExit> {
    open_image_store(root)
        .map(|s| s.with_recorder(Arc::new(CliOciRecorder::new(Arc::clone(recorder)))))
}

/// 本番入口の `image`。
pub(super) fn run_image(global: &GlobalArgs, args: &ImageArgs, stdout: &mut dyn Write) -> CliExit {
    if let Some(e) = non_linux_failure(global) {
        return e;
    }
    match args {
        ImageArgs::Ls(a) => with_ops("image_ls", |rec| {
            match open_image_store_recorded(&a.image_root, rec) {
                Ok(store) => {
                    run_image_ls_recorded(&store, &CliOciRecorder::new(Arc::clone(rec)), stdout)
                }
                Err(e) => e,
            }
        }),
        ImageArgs::Rm(a) => with_ops("image_rm", |rec| {
            let target = match parse_target(&a.reference) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match open_image_store_recorded(&a.image_root, rec) {
                Ok(store) => run_image_rm_recorded(
                    &store,
                    &CliOciRecorder::new(Arc::clone(rec)),
                    &target,
                    a.force,
                    &|| stopped_snapshot(global),
                    &|candidates| reconcile_for_image_rm(global, &store, candidates),
                    stdout,
                ),
                Err(e) => e,
            }
        }),
        ImageArgs::Tag(a) => with_ops("image_tag", |rec| {
            let source = match parse_tag_source(&a.source) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let target = match parse_tag_target(&a.target) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match open_image_store_recorded(&a.image_root, rec) {
                Ok(store) => run_image_tag_with(&store, &source, target, stdout),
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
        SystemArgs::Df(a) => with_ops("system_df", |rec| {
            match open_image_store_recorded(&a.image_root, rec) {
                Ok(store) => {
                    run_system_df_recorded(&store, &CliOciRecorder::new(Arc::clone(rec)), stdout)
                }
                Err(e) => e,
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-1・ERR-1: `OciErrorCode::ALL` の全件を照合する。`Internal` へ畳まれるのは
    /// `Internal` と `DataLoss` だけで、それ以外は同名の core の code に写る。
    #[test]
    fn err1_map_code_covers_all_oci_codes() {
        let mut folded = Vec::new();
        for oc in OciErrorCode::ALL {
            let mapped = map_code(oc);
            if mapped == ErrorCode::Internal {
                folded.push(oc);
            } else {
                assert_eq!(mapped.as_str(), oc.as_str(), "{oc:?}");
            }
        }
        assert_eq!(folded, [OciErrorCode::DataLoss, OciErrorCode::Internal]);
    }
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
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

    /// OCI-7・#2659: `name@digest` は name が一致しても digest で解決し、素の digest と同じ出力で削除する。
    #[test]
    fn cli1_oci7_image_rm_name_at_digest_matching_name_deletes_by_digest() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &[]);
        let d = format!("busybox@sha256:{}", "1".repeat(64));
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target(&d), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 0);
        let h1 = "1".repeat(64);
        assert!(out.starts_with("untagged\tregistry-1.docker.io/library/busybox:latest\n"));
        assert!(out.contains(&format!("deleted\tsha256:{h1}\n")));
        assert!(out.contains(&format!("deleted-blob\tsha256:{}\n", "a".repeat(64))));
        assert!(out.contains(&format!("deleted-blob\tsha256:{}\n", "b".repeat(64))));
        assert!(!tmp.has_blob('a') && !tmp.has_blob('b'));
    }

    /// OCI-7・#2659: name が食い違っても digest 優先で削除する（(a) の残余リスクを固定。切り替え時は意図した試験の変更になる）。
    #[test]
    fn cli1_oci7_image_rm_name_at_digest_mismatched_name_is_digest_first() {
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let store = rm_store(&tmp, &[]);
        let d = format!("nginx@sha256:{}", "1".repeat(64));
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target(&d), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 0);
        assert!(out.starts_with("untagged\tregistry-1.docker.io/library/busybox:latest\n"));
        assert!(out.contains(&format!("deleted\tsha256:{}\n", "1".repeat(64))));
        assert!(!tmp.has_blob('a') && !tmp.has_blob('b'));
    }

    /// OCI-7・#2659: 在庫に無い digest の `name@digest` は INVALID_ARGUMENT ではなく 3 / NOT_FOUND。
    #[test]
    fn cli1_oci7_image_rm_name_at_unknown_digest_is_not_found() {
        let tmp = Tmp::new();
        let store = rm_store(&tmp, &[]);
        let d = format!("nginx@sha256:{}", "9".repeat(64));
        let (e, out) = out_of(|o| run_image_rm_with(&store, &target(&d), false, &no_snapshot, o));
        assert_eq!(e.exit_code(), 3);
        assert_eq!(e.code(), Some("NOT_FOUND"));
        assert!(stderr_of(&e).contains(MSG_IMAGE_NOT_FOUND));
        assert_eq!(out, "");
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

    /// OCI-7・#2495: 状態の無い参照だけが残った manifest の `image rm` は、拒否の前に照合・回収されて成功する。
    /// 他の状態ルートの参照は回収されず、従来どおり拒否される。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_image_rm_reclaims_stale_ref_then_deletes() {
        use super::super::ref_reconcile::reconcile_in_use;
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        let scope = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        let state_tmp = Tmp::new();
        let state = FileStateStore::open(
            StateRoot::from_override(state_tmp.path().join("state")).expect("root"),
        )
        .expect("state");
        let reclaim = |store: &ImageStore, c: &[ContainerRefId]| {
            reconcile_in_use(store, &state, scope, c);
        };

        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let key = super::ref_key(scope, "c1");
        let store = rm_store(&tmp, &[key.as_str()]);
        let (e, out) = out_of(|o| {
            run_image_rm_reclaiming(
                &store,
                &target("busybox"),
                false,
                &no_snapshot,
                &|c| reclaim(&store, c),
                o,
            )
        });
        assert_eq!(e.exit_code(), 0);
        assert!(out.contains("deleted\tsha256:"), "{out}");
        assert!(!tmp.has_blob('a') && !tmp.has_blob('b'));

        let tmp2 = Tmp::new();
        tmp2.put_blob('a', 1);
        tmp2.put_blob('b', 1);
        let foreign = super::ref_key(other, "c1");
        let store2 = rm_store(&tmp2, &[foreign.as_str()]);
        let (e, out) = out_of(|o| {
            run_image_rm_reclaiming(
                &store2,
                &target("busybox"),
                false,
                &no_snapshot,
                &|c| reclaim(&store2, c),
                o,
            )
        });
        assert_eq!(e.exit_code(), 5);
        assert_eq!(e.code(), Some("FAILED_PRECONDITION"));
        assert_eq!(out, "");
        assert!(tmp2.has_blob('a') && tmp2.has_blob('b'));
    }

    /// OCI-7: アダプタが scope つきで登録した参照（長い ID を含む）は、同じ参照キーの停止中スナップショットで
    /// 停止後の `image rm --force` が通る。
    #[test]
    fn oci7_image_rm_force_stopped_with_scoped_ref_keys() {
        let scope = "0123456789abcdef0123456789abcdef";
        let long = "a".repeat(255);
        let keys = [super::ref_key(scope, "c1"), super::ref_key(scope, &long)];
        let tmp = Tmp::new();
        tmp.put_blob('a', 1);
        tmp.put_blob('b', 1);
        let names: Vec<&str> = keys.iter().map(String::as_str).collect();
        let store = rm_store(&tmp, &names);
        let snap = || {
            Ok(StoppedContainers::from_iter(
                keys.iter().map(|k| ContainerRefId::new(k).expect("id")),
            ))
        };
        let (e, _) = out_of(|o| run_image_rm_with(&store, &target("busybox"), true, &snap, o));
        assert_eq!(e.exit_code(), 0);
        // 接頭辞なしの ID で登録した停止中は一致せず拒否される（キー表現の不一致の再発検出）。
        let tmp2 = Tmp::new();
        let store2 = rm_store(&tmp2, &names);
        let bare = || {
            Ok(StoppedContainers::from_iter([
                ContainerRefId::new("c1").expect("id")
            ]))
        };
        let (e, _) = out_of(|o| run_image_rm_with(&store2, &target("busybox"), true, &bare, o));
        assert_ne!(e.exit_code(), 0);
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
        assert_eq!(bad.exit_code(), 2);
        assert_eq!(bad.code(), Some("INVALID_ARGUMENT"));
        assert!(stderr_of(&bad).contains("invalid argument"));
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

    /// REPAIR-4・OCI-1: 記録付きで開いたストアの `image ls` / `system df` が `oci.*` の操作を記録器へ入れる。
    #[test]
    fn repair4_recorded_store_feeds_oci_ops_into_recorder() {
        let tmp = Tmp::new();
        let rec = Arc::new(OpRecorder::new());
        let store = open_image_store_recorded(tmp.path(), &rec).expect("open");
        let bridge = CliOciRecorder::new(Arc::clone(&rec));
        let (e, _) = out_of(|o| run_image_ls_recorded(&store, &bridge, o));
        assert_eq!(e.exit_code(), 0);
        let (e, _) = out_of(|o| run_system_df_recorded(&store, &bridge, o));
        assert_eq!(e.exit_code(), 0);
        let get = |n: &str| {
            let name = fandhe_container_core::observability::OpName::new(n).expect("name");
            rec.snapshot_op(&name).map(|s| (s.success(), s.failure()))
        };
        assert_eq!(get("oci.image.list"), Some((1, 0)));
        assert_eq!(get("oci.image.df"), Some((1, 0)));
        assert_eq!(get("oci.store.lock"), Some((2, 0)));
    }

    /// CLI-1・OCI-7・SEC-1（#2547）: root が group / other に書き込めれば PERMISSION_DENIED（6）、0700 と 0755 は受理。
    #[cfg(unix)]
    #[test]
    fn cli1_oci7_sec1_store_root_mode_checks() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = Tmp::new();
        let chmod = |m: u32| {
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(m)).expect("chmod")
        };
        chmod(0o757);
        let e = open_image_store(tmp.path()).expect_err("0757");
        assert_eq!(e.exit_code(), 6);
        let err = stderr_of(&e);
        assert!(err.contains("PERMISSION_DENIED"), "{err}");
        assert!(err.contains("permission denied"), "{err}");
        for mode in [0o700, 0o755] {
            chmod(mode);
            let store = open_image_store(tmp.path()).expect("accepted");
            let (e, out) = out_of(|o| run_image_ls_with(&store, o));
            assert_eq!(e.exit_code(), 0, "mode {mode:o}");
            assert_eq!(out, "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n");
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

    fn tag_store(tmp: &Tmp, tags: &[(&str, char)]) -> ImageStore {
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &[]);
        add_manifest(&mut t, '2', 'b', &[]);
        for (name, m) in tags {
            t.register_tag(key("library/busybox", name), &dg(*m))
                .expect("tag");
        }
        ImageStore::with_table(tmp.path(), t).expect("open")
    }

    fn run_tag(store: &ImageStore, source: &str, target: &str) -> (CliExit, String) {
        let source = parse_tag_source(source).expect("source");
        let target = parse_tag_target(target).expect("target");
        out_of(|o| run_image_tag_with(store, &source, target, o))
    }

    /// CLI-1・OCI-7: タグ source で新規タグを付けると tagged 行を出して 0。
    #[test]
    fn cli1_oci7_image_tag_added_by_tag_source() {
        let tmp = Tmp::new();
        let store = tag_store(&tmp, &[("latest", '1')]);
        let (e, out) = run_tag(&store, "busybox:latest", "busybox:v2");
        assert_eq!(e.exit_code(), 0);
        assert_eq!(
            out,
            format!(
                "tagged\tregistry-1.docker.io/library/busybox:v2\tsha256:{}\n",
                "1".repeat(64)
            )
        );
        let g = store.lock().expect("lock");
        assert_eq!(g.tags().count(), 2);
    }

    /// CLI-1・OCI-7: digest source でも tagged 行になる。
    #[test]
    fn cli1_oci7_image_tag_by_digest_source() {
        let tmp = Tmp::new();
        let store = tag_store(&tmp, &[]);
        let (e, out) = run_tag(&store, &format!("sha256:{}", "1".repeat(64)), "busybox:v1");
        assert_eq!(e.exit_code(), 0);
        assert_eq!(
            out,
            format!(
                "tagged\tregistry-1.docker.io/library/busybox:v1\tsha256:{}\n",
                "1".repeat(64)
            )
        );
    }

    /// CLI-1・OCI-7・#2659: tag の source が `name@digest` なら name の一致・不一致によらず digest で解決する。
    #[test]
    fn cli1_oci7_image_tag_name_at_digest_source_match_and_mismatch() {
        let h = "1".repeat(64);
        let want = format!("tagged\tregistry-1.docker.io/library/busybox:v1\tsha256:{h}\n");
        for name in ["busybox", "nginx"] {
            let tmp = Tmp::new();
            let store = tag_store(&tmp, &[]);
            let (e, out) = run_tag(&store, &format!("{name}@sha256:{h}"), "busybox:v1");
            assert_eq!(e.exit_code(), 0, "{name}");
            assert_eq!(out, want, "{name}");
        }
    }

    /// CLI-1・OCI-7: 別 manifest を指すタグの付け替えは retagged 行（付け替え前 → 後）。
    #[test]
    fn cli1_oci7_image_tag_retag_reports_from_and_to() {
        let tmp = Tmp::new();
        let store = tag_store(&tmp, &[("latest", '1'), ("v2", '2')]);
        let (e, out) = run_tag(&store, "busybox:latest", "busybox:v2");
        assert_eq!(e.exit_code(), 0);
        assert_eq!(
            out,
            format!(
                "retagged\tregistry-1.docker.io/library/busybox:v2\tsha256:{}\tsha256:{}\n",
                "2".repeat(64),
                "1".repeat(64)
            )
        );
        let g = store.lock().expect("lock");
        assert_eq!(g.manifest_references(&dg('1')).tags.len(), 2);
    }

    /// CLI-1・OCI-7: 同じ付け先への再付与は unchanged 行で 0。
    #[test]
    fn cli1_oci7_image_tag_unchanged() {
        let tmp = Tmp::new();
        let store = tag_store(&tmp, &[("latest", '1'), ("v2", '1')]);
        let (e, out) = run_tag(&store, "busybox:latest", "busybox:v2");
        assert_eq!(e.exit_code(), 0);
        assert_eq!(
            out,
            format!(
                "unchanged\tregistry-1.docker.io/library/busybox:v2\tsha256:{}\n",
                "1".repeat(64)
            )
        );
    }

    /// CLI-1・OCI-7・ERR-1: 存在しない source は 3 / NOT_FOUND で、stdout は空・テーブル不変・argv を出力しない。
    #[test]
    fn cli1_oci7_image_tag_unknown_source_is_not_found() {
        let tmp = Tmp::new();
        let store = tag_store(&tmp, &[("latest", '1')]);
        let (e, out) = run_tag(&store, "nope", "busybox:v2");
        assert_eq!(e.exit_code(), 3);
        assert_eq!(e.code(), Some("NOT_FOUND"));
        assert_eq!(out, "");
        let err = stderr_of(&e);
        assert!(err.contains(MSG_IMAGE_NOT_FOUND), "{err}");
        assert!(!err.contains("nope"), "{err}");
        assert_eq!(store.lock().expect("lock").tags().count(), 1);
    }

    /// OCI-7・CLI-1（#2600）: digest に見える不正な入力はタグと誤読せず、rm / tag の 3 入口とも 2 / INVALID_ARGUMENT。
    #[test]
    fn cli1_oci7_parse_ref_digest_like_inputs() {
        let bad_digest = [
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}F", "a".repeat(63)),
            format!("sha512:{}", "a".repeat(128)),
            format!("sha384:{}", "a".repeat(96)),
            format!("sha256:{}", "a".repeat(63)),
        ];
        for t in &bad_digest {
            for e in [
                parse_target(t).expect_err("rm"),
                parse_tag_source(t).expect_err("src"),
                parse_tag_target(t).expect_err("dst"),
            ] {
                assert_eq!(e.exit_code(), 2, "{t}");
                assert_eq!(e.code(), Some("INVALID_ARGUMENT"), "{t}");
                let err = stderr_of(&e);
                assert!(err.contains(MSG_BAD_DIGEST), "{err}");
                assert!(!err.contains(t.as_str()), "{err}");
            }
        }
        let a = "a".repeat(64);
        assert_eq!(
            parse_target(&format!("sha256:{a}")).expect("digest"),
            ImageRmTarget::Manifest(dg('a'))
        );
        assert_eq!(
            parse_tag_source(&format!("sha256:{a}")).expect("digest"),
            ImageTagSource::Manifest(dg('a'))
        );
        let e = parse_tag_target(&format!("sha256:{a}")).expect_err("digest target");
        assert!(stderr_of(&e).contains(MSG_TAG_TARGET));
        let e = parse_tag_target(&format!("busybox@sha256:{a}")).expect_err("name@digest");
        assert!(stderr_of(&e).contains(MSG_TAG_TARGET));
        // name@大文字 hex は従来どおり固定の汎用文言。
        let e = parse_target(&format!("busybox@sha256:{}", "A".repeat(64))).expect_err("bad");
        assert_eq!(e.exit_code(), 2);
        assert!(stderr_of(&e).contains("invalid argument"));
        // タグ参照は変わらない（repository 名が sha256 のイメージは / を含めて書く）。
        assert_eq!(
            parse_target("busybox:v2").expect("tag"),
            ImageRmTarget::Tag(key("library/busybox", "v2"))
        );
        assert_eq!(
            parse_target("docker.io/library/sha256:v1").expect("tag"),
            ImageRmTarget::Tag(key("library/sha256", "v1"))
        );
        assert_eq!(
            parse_tag_target("busybox:v2").expect("tag"),
            key("library/busybox", "v2")
        );
    }

    /// OCI-7: 固定文言は core の `ImageManifestDigest::new` と同一。
    #[test]
    fn oci7_bad_digest_message_matches_core() {
        let e = fandhe_container_core::oci_runtime::ImageManifestDigest::new(&format!(
            "sha256:{}",
            "A".repeat(64)
        ))
        .expect_err("bad");
        assert_eq!(e.message(), MSG_BAD_DIGEST);
    }

    /// CLI-1・OCI-7: digest を target にすると 2 / INVALID_ARGUMENT（name@digest も同じ）。
    #[test]
    fn cli1_oci7_image_tag_digest_target_is_invalid_argument() {
        let h = "1".repeat(64);
        for t in [format!("sha256:{h}"), format!("busybox@sha256:{h}")] {
            let e = parse_tag_target(&t).expect_err("digest target");
            assert_eq!(e.exit_code(), 2, "{t}");
            assert_eq!(e.code(), Some("INVALID_ARGUMENT"), "{t}");
            assert!(stderr_of(&e).contains(MSG_TAG_TARGET));
        }
        let e = parse_tag_target("UPPER CASE").expect_err("invalid");
        assert_eq!(e.exit_code(), 2);
        assert_eq!(
            parse_tag_target("busybox:v2").expect("tag"),
            key("library/busybox", "v2")
        );
    }

    /// CLI-1・OCI-7: タグ件数が上限なら新規タグは 10 / RESOURCE_EXHAUSTED と固定文言、付け替えは成功する。
    #[test]
    fn cli1_oci7_image_tag_limit_is_resource_exhausted_with_fixed_message() {
        use fandhe_container_oci::image_management::MAX_TAG_REFS;
        let tmp = Tmp::new();
        let mut t = ReferenceTable::new();
        add_manifest(&mut t, '1', 'a', &[]);
        add_manifest(&mut t, '2', 'b', &[]);
        for i in 0..MAX_TAG_REFS {
            t.register_tag(key("library/busybox", &format!("t{i}")), &dg('1'))
                .expect("tag");
        }
        let store = ImageStore::with_table(tmp.path(), t).expect("open");
        let (e, out) = run_tag(&store, "busybox:t0", "busybox:brand-new");
        assert_eq!(e.exit_code(), 10);
        assert_eq!(e.code(), Some("RESOURCE_EXHAUSTED"));
        assert!(stderr_of(&e).contains(MSG_TAG_LIMIT));
        assert_eq!(out, "");
        let (e, out) = run_tag(&store, &format!("sha256:{}", "2".repeat(64)), "busybox:t1");
        assert_eq!(e.exit_code(), 0);
        assert!(out.starts_with("retagged\t"), "{out}");
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
            MSG_TAG_LIMIT,
            MSG_TAG_TARGET,
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
            for s in [
                Stage::Open,
                Stage::Lock,
                Stage::Read,
                Stage::Remove,
                Stage::Tag,
                Stage::Refs,
            ] {
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
            ErrorCode::ResourceExhausted
        );
        assert_eq!(map_code(OciErrorCode::NotFound), ErrorCode::NotFound);
    }
}
