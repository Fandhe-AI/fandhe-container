//! OCI Runtime の `create`（コンテナ状態の初期化。TASK-29.2・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! bundle の `config.json` を検証し、プロセスを一切起動しないまま [`StateStore`] へ
//! 「created・pid なし」の状態を 1 件作る。将来の plugin 側 `ContainerRuntime::create` 実装・CLI・
//! TASK-29.3（start）が呼び出し元になる。`ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、
//! 本関数はトレイト実装ではなく `StateStore` を依存注入で受け取る自由関数とした。ファイルベースの
//! `StateStore` の既定実装は `crate::state_store::FileStateStore`（TASK-31.1・OCI-5）。
//!
//! # fail-closed の判断（config.rs が本タスクへ委ねた判断の結果）
//!
//! 1. [`OciConfig::unapplied_fields`] が空でない config は [`ErrorCode::Unimplemented`] で拒否する。
//!    capabilities・seccomp 等を黙って無視すると、指定より弱い分離で起動する経路になる
//!    （SEC-1・CORE-5）。個別フィールドの許可は、それを実際に適用する後続タスクが
//!    パーサ側で解釈済みに移すことで行う。`linux.resources` の memory / cpu / pids / blockIO（weight・throttle）
//!    は #2019 で解釈済みに移り、cgroup v2 の範囲外の値は Linux では create の時点で `InvalidArgument` で
//!    拒否する（`cgroups::ResourceLimitPlan`）。それ以外の resources の項目は未適用として拒否する。
//!    `linux.cgroupsPath` は [`check_cgroups_path`] が拒否する（値は配置に使わない方針。#2010）。
//! 2. `process` を持たない config は拒否する。start で起動できない config を created にしない。
//! 3. `root.path` は `..` 要素と、bundle 配下の全パス要素（中間要素を含む）の symlink・Windows junction（reparse point）を拒否し、
//!    存在するディレクトリであることを確認する。bundle 内の link 経由で bundle 外を rootfs に
//!    できないようにするため（SEC-1）。bundle 外を指す絶対パスの `root.path` は設定作成者の
//!    明示指定として受け入れ、末尾要素のみ検査する。
//!
//! すべての検証は [`StateStore::create`] の前に済ませるため、失敗時にストアへ何も書かれず
//! 後始末は不要である。エラーメッセージは固定文言と静的なフィールドパスのみで、config の値や
//! OS 依存の I/O エラー文字列を含めない。
//!
//! # イメージつき create のレイヤー展開（#2342・OCI-7）
//!
//! 展開器つきの [`create_with_image`] は、bundle の検証の「間」で展開する:
//! 参照登録 → config 検証 → 既存状態の確認 → 展開先の排他作成 → 展開 → 展開先を `root.path` へ公開 → bundle 検証
//! （`check_rootfs` を含む全検証）→ 状態作成 → 確定。
//!
//! - 展開の前に config を検証するのは、不正な config で大きな展開をしないため。`root.path` も config から決まる
//! - rootfs の実在・種類の検査は展開の後の実体に対して行う（start の TOCTOU 再検証と同じ規則）
//! - 参照の登録を展開より前に置くのは OCI-7 の順序（未登録のレイヤーを使わない）。展開中、登録した参照が
//!   GC から blob を守るので、展開器はイメージストアの排他を展開の全体で保持しなくてよい
//!
//! 失敗時の後始末は、公開前と公開後で分ける。rootfs を削除するのは公開前（展開・公開の失敗）だけで、公開後
//! （bundle 検証・`root.path` の書き換わり・状態作成の失敗）は rootfs を常に保持し、解除するのは参照だけである
//! （状態作成の `AlreadyExists` / `InvalidArgument` では参照を解除し、`Internal`・`Timeout` 等の書き込みの
//! 有無が曖昧な失敗では参照も残す）。公開後の rootfs は使用中かを確定できないため、状態一覧による使用中判定も
//! 行わず消さない。公開後の失敗の後に同じ bundle で再試行すると、残った rootfs により `AlreadyExists` になる。
//! Linux は展開先を `root.path` ではなく非公開の名前（同じ親の下）に作り、固定した親の fd からの fd 相対の操作だけで
//! 作成・公開（`renameat2(RENAME_NOREPLACE)`）・後始末を行い、展開器へは rootfs の fd を指す `/proc/self/fd/N` を渡す
//! （bundle 内の中間要素を差し替えられても bundle 外へ書かない・消さない。SEC-1）。展開中は `root.path` が無いので、
//! 並行する通常の create が未完成の rootfs で成功することはなく、展開の失敗は非公開の展開先だけを消す。
//! 公開後の失敗では rootfs を消さずに残す（create 間の排他が未実装のため。REPAIR-3）。Linux 以外は
//! 展開先を固定できないため、展開開始前（作成の前）に `Unimplemented` で拒否し、何も作らない（fail-closed）。
//! create の途中でプロセスが落ちて残った展開途中の木（非公開の名前）は、持ち主のいない（OS ロックが取れる）
//! ものだけを次の create の時点と `reap_stale_unpacks` が回収する（#2379・OCI-7。`image_rootfs` のモジュール doc）。
//! 公開済みで状態の無い rootfs（公開後・状態作成前のクラッシュ、delete の後始末の失敗、状態の喪失）は、
//! 展開先を作る前に孤児と確かめられたときだけ回収する（印 v2・`flock`・状態の全件照合。確かめられなければ
//! `AlreadyExists` で止まる fail-closed。利用者のデータを消さない。#2540・`image_rootfs` のモジュール doc）。
//! 公開した rootfs を状態作成まで保持するのは、生きている create を孤児と区別するため。公開した rootfs は状態レコードに記録し
//! （`StateRecord::image_rootfs`）、delete が状態削除の成功後に消す（所有・タイミング・失敗時の扱いは
//! `docs/design/image-rootfs-lifetime.md`。OCI-7・OCI-5・#2378）。delete は bundle 自体は消さない。
//! 展開器なしの [`create_with_image`] は従来どおり、bundle の rootfs が展開済みの前提で動く。
//!
//! # スコープ外
//!
//! - プロセス起動（TASK-29.3 start）・namespace 分離・mount 適用（bind は start と本番 launcher が適用する〔#1915〕。bind 以外の種類は未対応）
//! - mounts の rootfs 内 symlink 解決（mount を適用する側の担当）
//! - 本番のレイヤー展開器（oci の展開を呼ぶアダプタ。未実装。REPAIR-3）。[`create_with_image`] は
//!   [`ImageRootfsUnpacker`] を受けて展開の位置・展開先の作成・後始末だけを担う（下記）
//! - OCI-7 の参照テーブル登録は [`create_with_image`] が担う（TASK-183.8.1）。bundle を直に指定する
//!   [`create`] は参照を登録しない
//! - ファイルベースの状態保存（TASK-31・OCI-5）
//! - create 後に bundle の `config.json` が書き換えられる TOCTOU は、start（TASK-29.3）が
//!   [`validate_bundle`] で再検証して対処する（ダイジェスト保持は `StateRecord` の拡張を要するため採らない）

use std::io;
use std::path::{Component, Path, PathBuf};

use super::cgroup_requirement::check_cgroups_path;
use super::config::{OciConfig, OciConfigError, load_config};
use super::error::{LifecycleOp, OciRuntimeError};
use super::image_refs::{ContainerImage, ImageRefRegistration};
use super::image_rootfs::{
    CreatedRootfs, ImageRootfsPrivilege, ImageRootfsUnpacker, prepare_rootfs_target_with,
    reap_published_orphan, record_staging_reclamation, state_root_scope,
};
use super::launch::BundleLock;
use super::mount_destination::audit_mount_config_error;
use super::resources::LinuxResourceLimits;
use crate::audit_log::AuditSink;
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerId, ContainerStatus, CreateRequest, CreateStateRequest, ErrorCode, GetStateRequest,
    ImageRootfsOwnership, ImageRootfsRecord, StateRecord, StateStore, TraitError,
};

/// bundle 直下の設定ファイル名（OCI Runtime Spec）。
const CONFIG_FILE_NAME: &str = "config.json";

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const CREATE_OP_NAME: &str = "create";

/// 参照登録・登録の巻き戻しの操作名（REPAIR-4）。
const IMAGE_REF_REGISTER_OP_NAME: &str = "image_ref_register";
const IMAGE_REF_ROLLBACK_OP_NAME: &str = "image_ref_rollback";
const IMAGE_REF_BIND_OP_NAME: &str = "image_ref_bind";

/// レイヤー展開と、失敗時の展開途中 rootfs の削除の操作名（REPAIR-4・#2342）。
const IMAGE_ROOTFS_UNPACK_OP_NAME: &str = "image_rootfs_unpack";
const IMAGE_ROOTFS_CLEANUP_OP_NAME: &str = "image_rootfs_cleanup";

/// `config.json` を検証し、プロセス未起動の「created」状態を `store` に作る。
///
/// 戻り値の [`StateRecord`] は state が `Created`・pid なしで、revision は後続の start が
/// `UpdateStateRequest` に使う。同じ ID が既にある場合は [`StateStore::create`] の
/// [`ErrorCode::AlreadyExists`] をそのまま返す。
///
/// 成功・失敗の件数と所要時間は `recorder` へ操作名 `create` で記録する（全終了経路。REPAIR-4）。
///
/// 失敗は [`OciRuntimeError`]（`op` = create・内部エラーと同一の `code`・非ゼロの
/// [`OciRuntimeError::exit_code`]）で返す。標準エラーへの書き出しと終了は呼び出し元（CLI・plugin）の
/// 責務（ERR-2・TASK-96.2）。
pub fn create(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    create_impl(store, recorder, req, None)
}

/// [`create`] に、`mounts[].destination` の拒否の監査記録を足したもの（SEC-4・OCI-4・#2480）。
///
/// config のパースが `mounts[].destination` を拒否したとき（宛先の遡り・rootfs 全体・相対 `..` 等）、
/// [`audit_mount_config_error`] で mount 層の拒否として `sink` に 1 件記録する。本番の create（CLI の
/// `create`）はこちらを呼び、`sink` は状態ルートの `@audit.log` への `FileAuditSink` を渡す。
///
/// - 記録の成否で拒否を覆さない。返す `code`・`message`・終了コードは [`create`] とバイト単位で同じ（fail-closed）
/// - 記録は `path` なし。config の入力値・ホストのパスは載せない
/// - 記録の `container_id` は要求された ID。拒否は `AlreadyExists` の判定より前に起きるため、
///   同じ ID の既存コンテナとは対応しない場合がある（start の記録と同じ意味）
/// - destination 以外の拒否は記録しない
/// - plugin-cri の `CoreLifecycleRuntime::create` も本関数を呼ぶ（#2594）。ただしマルチスレッドでは
///   `FileAuditSink` の fork 隔離が使えないため、plugin-cri は単一スレッドの間に作った `ControlAuditRelay`
///   を `sink` として渡す
pub fn create_audited(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &CreateRequest,
    sink: &dyn AuditSink,
) -> Result<StateRecord, OciRuntimeError> {
    create_impl(
        store,
        recorder,
        req,
        Some(ConfigAudit { id: req.id(), sink }),
    )
}

fn create_impl(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &CreateRequest,
    audit: Option<ConfigAudit<'_>>,
) -> Result<StateRecord, OciRuntimeError> {
    // 変換は最上位 1 か所のみ。内部関数は `TraitError` のまま（波及最小）。
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
    let name = OpName::new(CREATE_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || create_inner(store, req, audit).map_err(to_err))
}

/// create の config 検証で、`mounts[].destination` の拒否を記録するための配線（#2480・SEC-4・OCI-4）。
///
/// `create_audited` / `create_with_image_audited` に加え、start の再検証（`load_resource_limits_audited` と
/// start の `build_spec`。TOCTOU で書き換えられた destination の拒否。#2594）が作る。
#[derive(Clone, Copy)]
pub(super) struct ConfigAudit<'a> {
    pub(super) id: &'a ContainerId,
    pub(super) sink: &'a dyn AuditSink,
}

fn create_inner(
    store: &dyn StateStore,
    req: &CreateRequest,
    audit: Option<ConfigAudit<'_>>,
) -> Result<StateRecord, TraitError> {
    // delete が core の作った rootfs を消している間の create を排他する（検証より前に取る。OCI-7・#2378）。
    let _guard = lock_for_create(req.bundle())?;
    validate_bundle_audited(req.bundle(), audit)?;
    create_state(store, req, None)
}

/// delete が rootfs の後始末を終えるまで保持する bundle の所有ロックを、create 側が取る（#2378・OCI-7）。
///
/// delete は core が作った rootfs の削除が済むまでこのロックを保持する。その間に同じ bundle を採用する create が
/// 状態を作ると、新しいコンテナの rootfs を旧 delete が消すため、ロック保持中の create は `FailedPrecondition`
/// で拒否する。
///
/// ロックは bundle が指す実体に取る（[`BundleLock::acquire_resolved`]。bundle の祖先が symlink でも、実体の
/// 絶対パスで同じ bundle を指す delete と排他する）。Linux でそれでもロックを取れないときは、状態を作らずに
/// 拒否する（fail-closed）。排他なしで進むと、delete が保持中でも create が成功し、旧 delete が新しい
/// コンテナの rootfs を消しうるため。ただし bundle の検証で拒否される bundle（不在・config 不正等）は、
/// 従来どおり検証のエラー（コードと文言）を返す。Linux 以外はロックが未実装（`Unimplemented`）のため排他せず
/// 進む（Linux 以外は core が rootfs を作らず、delete も rootfs を消さない）。
fn lock_for_create(bundle: &Path) -> Result<Option<BundleLock>, TraitError> {
    match BundleLock::acquire_resolved(bundle) {
        Ok(lock) => Ok(Some(lock)),
        Err(e) if e.code() == ErrorCode::FailedPrecondition => Err(e),
        Err(_) if !cfg!(target_os = "linux") => Ok(None),
        Err(e) => {
            validate_bundle(bundle)?;
            Err(e)
        }
    }
}

/// 状態を作る。`image_rootfs` は core が作って公開した rootfs の記録（展開器つきの create だけが渡す。
/// 利用者が用意した rootfs には付けず、delete は触れない。OCI-7・#2378）。
fn create_state(
    store: &dyn StateStore,
    req: &CreateRequest,
    image_rootfs: Option<ImageRootfsRecord>,
) -> Result<StateRecord, TraitError> {
    let status = ContainerStatus::created(req.id().clone(), None);
    let mut state_req = CreateStateRequest::new(status, req.bundle().to_path_buf())?
        .with_annotations(req.annotations().clone());
    if let Some(r) = image_rootfs {
        state_req = state_req.with_image_rootfs(r);
    }
    store.create(&state_req)
}

/// [`create`] に、OCI-7 のイメージ参照の登録を前置したもの（TASK-183.8.1・OCI-7）。
///
/// 処理順は「参照登録 → rootfs の使用（bundle の検証。展開器があればレイヤー展開を挟む。モジュール doc 参照）→
/// `StateStore` の状態作成」。
/// 参照を最初に登録するのは、GC（`image rm` / `image prune`）が使用中のレイヤーを消す窓を作らないため。
/// 既存の [`create`] の挙動は変えない。
///
/// - `register` が [`ImageRefRegistration::AlreadyRegistered`] を返したら [`ErrorCode::AlreadyExists`] で拒否し、
///   後始末はしない。自分が足した参照ではなく、並行する同じ ID の create の参照を外すと、そちらが
///   参照なしで作られうるため
/// - `register` のエラーはそのまま返し、状態は書かない（fail-closed）
/// - bundle の検証が失敗したら参照を外す。`StateStore::create` が [`ErrorCode::AlreadyExists`] /
///   [`ErrorCode::InvalidArgument`] で失敗したときも外す（状態が書かれていないと断定できるため）。
///   `Internal`・`Timeout` 等の書き込みの有無が曖昧な失敗では参照を残す。残る方向はデータを余分に
///   持つだけで安全側であり、起動時の照合（#854）が回収する
/// - 後始末の失敗は元のエラーを優先して返し、操作名 `image_ref_rollback` で `recorder` に記録する（REPAIR-4）
///
/// 成功・失敗は操作名 `create` で記録する。登録は `image_ref_register` で記録する。
pub fn create_with_image(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    create_with_image_impl(store, recorder, image, req, None)
}

/// [`create_with_image`] に、[`create_audited`] と同じ `mounts[].destination` 拒否の監査記録を足したもの
/// （SEC-4・OCI-4・#2480）。展開器の有無にかかわらず、拒否 1 回につき 1 件記録する。
pub fn create_with_image_audited(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    req: &CreateRequest,
    sink: &dyn AuditSink,
) -> Result<StateRecord, OciRuntimeError> {
    create_with_image_impl(
        store,
        recorder,
        image,
        req,
        Some(ConfigAudit { id: req.id(), sink }),
    )
}

fn create_with_image_impl(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    req: &CreateRequest,
    audit: Option<ConfigAudit<'_>>,
) -> Result<StateRecord, OciRuntimeError> {
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
    let name = OpName::new(CREATE_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || {
        create_with_image_inner(store, recorder, image, req, audit).map_err(to_err)
    })
}

fn create_with_image_inner(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    req: &CreateRequest,
    audit: Option<ConfigAudit<'_>>,
) -> Result<StateRecord, TraitError> {
    let register_name = OpName::new(IMAGE_REF_REGISTER_OP_NAME)?;
    let registration = recorder.record_op(&register_name, || {
        image.refs().register(req.id(), image.manifest())
    })?;
    match registration {
        ImageRefRegistration::Registered => {}
        ImageRefRegistration::AlreadyRegistered => {
            return Err(TraitError::new(
                ErrorCode::AlreadyExists,
                "container id already holds an image reference",
            ));
        }
    }
    // OCI-7: 参照登録の後・状態作成の前。展開器があれば、検証を展開の前後に分けて展開する。
    // 展開器なしは、検証より前に bundle のロックを取り状態作成まで保持する（検証の後に delete が rootfs を消して
    // 完了する隙を作らない。通常の `create` と同じ順。OCI-7・SEC-1）。展開器ありは展開後・状態作成の前に取る。
    let mut early_guard: Option<Option<BundleLock>> = None;
    // 公開済みの rootfs は、状態を作り終えるまで保持する。木の `flock` を状態作成まで残し、公開後・状態作成前の
    // 生きている create を、孤児の回収（`reap_published_orphan`）が「持ち主あり」と見分けられるようにする
    // （`flock` は inode に掛かり、公開の改名の後も残る。#2540・OCI-7）。
    let mut held_rootfs: Option<CreatedRootfs> = None;
    let image_rootfs = match image.unpacker() {
        None => {
            match lock_for_create(req.bundle()) {
                Ok(g) => early_guard = Some(g),
                Err(e) => {
                    rollback_image_ref(recorder, image, req);
                    return Err(e);
                }
            }
            if let Err(e) = validate_bundle_audited(req.bundle(), audit) {
                rollback_image_ref(recorder, image, req);
                return Err(e);
            }
            None
        }
        Some(unpacker) => match unpack_rootfs(store, recorder, image, unpacker, req, audit) {
            // 公開済みの rootfs を状態へ記録する（delete が消す印）。記録を作れない失敗は公開後の失敗と同じ扱い
            // （rootfs は残し、参照だけ外す）。
            Ok(created) => match created.record() {
                Ok(record) => {
                    held_rootfs = Some(created);
                    // subuid 所有の木は、delete が userns の中で消すよう記録に残す（SEC-5・#2540）。
                    Some(match image.rootfs_privilege().ownership() {
                        ImageRootfsOwnership::SubordinateIds => record.with_subordinate_ownership(),
                        _ => record,
                    })
                }
                Err(e) => {
                    rollback_image_ref(recorder, image, req);
                    return Err(e);
                }
            },
            Err(e) => {
                // 公開前の失敗では rootfs は unpack_rootfs が消した後（公開後の失敗はここへ来ない）。残るのは未確定の参照だけ。
                rollback_image_ref(recorder, image, req);
                return Err(e);
            }
        },
    };
    // 状態を作る間も delete の rootfs 後始末と排他する。ロックを取れなければ公開済みの rootfs は残し、参照だけ外す。
    let guard = match early_guard {
        Some(g) => g,
        None => match lock_for_create(req.bundle()) {
            Ok(g) => g,
            Err(e) => {
                rollback_image_ref(recorder, image, req);
                return Err(e);
            }
        },
    };
    let created_state = create_state(store, req, image_rootfs);
    drop(guard);
    drop(held_rootfs);
    match created_state {
        Ok(record) => {
            // 参照を状態作成まで済んだものとして確定する。delete は確定済みの参照だけを外すので、状態作成前に止まった
            // create の参照を、既存の別の状態の delete が巻き込んで外す競合を防げる。失敗しても状態は
            // 作成済みなので成功を返す（参照は未結合のまま残り、delete は外さない。余分に持つだけの安全側。
            // 起動時の照合〔#854〕が回収する）。記録は `image_ref_bind`。
            if let Ok(name) = OpName::new(IMAGE_REF_BIND_OP_NAME)
                && let Ok(generation) = recorder.record_op(&name, || image.refs().bind(req.id()))
            {
                // 状態作成から確定までの間に並行する delete が状態を消していると、delete は未確定の参照を
                // 読めず外さない。確定した参照は他の create が同じ ID を登録できないので（`register` が
                // AlreadyRegistered を返す）、確定後に状態が無ければそれは自分が作った状態が消えたことを
                // 意味する。自分の世代だけを外す（再作成された別の参照を巻き込まない）。
                let gone = matches!(
                    store.get(&GetStateRequest::new(req.id().clone())),
                    Err(ref e) if e.code() == ErrorCode::NotFound
                );
                if gone && let Ok(name) = OpName::new(IMAGE_REF_ROLLBACK_OP_NAME) {
                    let _ =
                        recorder.record_op(&name, || image.refs().release_if(req.id(), generation));
                }
            }
            Ok(record)
        }
        Err(e) => {
            // 状態が書かれていないと断定できる失敗だけ参照を外す。
            if matches!(
                e.code(),
                ErrorCode::AlreadyExists | ErrorCode::InvalidArgument
            ) {
                // 公開済みの rootfs は使用中かを確定できないため消さずに残し、解除するのは参照だけ
                // （`unpack_rootfs` の注記）。残った rootfs は #854 の起動時照合・手動で回収する。
                rollback_image_ref(recorder, image, req);
            }
            Err(e)
        }
    }
}

/// 展開器ありの create の「config 検証 → 展開先の作成 → 展開 → bundle 検証」（#2342・OCI-7）。
///
/// 検証を展開の前後に分ける理由: config の検証（不正な config で展開しない・`root.path` を知る）は展開の
/// 前に、rootfs の実在・種類の検査（`check_rootfs`）は展開の後の実体に対して行う。後者は start の TOCTOU
/// 再検証と同じ規則を create でも成り立たせる。公開前の失敗では作った rootfs をここで消し、公開後は消さない（参照の解除は呼び出し元）。
fn unpack_rootfs(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    unpacker: &dyn ImageRootfsUnpacker,
    req: &CreateRequest,
    audit: Option<ConfigAudit<'_>>,
) -> Result<CreatedRootfs, TraitError> {
    let config = validate_config(req.bundle(), audit)?;
    // 展開の無駄を避ける事前確認。最終判定は `StateStore::create`。
    if store.get(&GetStateRequest::new(req.id().clone())).is_ok() {
        return Err(TraitError::new(
            ErrorCode::AlreadyExists,
            "container state already exists",
        ));
    }
    // 公開済みで状態の無い rootfs（公開後・状態作成前のクラッシュ、delete の後始末の失敗、状態の喪失）が
    // あれば、孤児と確かめられたときだけ先に回収する。確かめられなければ残し、下の作成が `AlreadyExists`
    // で拒否する（利用者のデータへ展開しない。#2540・OCI-7）。
    let privilege = image.rootfs_privilege();
    let _ = reap_published_orphan(
        store,
        recorder,
        req.bundle(),
        config.root().path(),
        privilege,
    );
    // Linux は非公開の名前で展開し、成功後に最終の名前へ公開する（展開中は `root.path` が存在せず、
    // 並行する別の create は rootfs を使用中として成功できない。展開途中の失敗の後始末は他から参照されない
    // 非公開の rootfs だけを消す）。Linux 以外は作成の前に Unimplemented で拒否する。
    // 回収の実処理は計測区間で包み、後続の作成が失敗しても結果と所要時間を記録する（REPAIR-4）。
    let mut created =
        prepare_rootfs_target_with(req.bundle(), config.root().path(), privilege, &|reap| {
            let started = std::time::Instant::now();
            let reclamation = reap();
            record_staging_reclamation(recorder, &reclamation, started.elapsed());
            reclamation
        })?;
    let unpack_name = OpName::new(IMAGE_ROOTFS_UNPACK_OP_NAME)?;
    // 展開器へは固定した rootfs を指す経路を渡す（作成後の bundle 内の差し替えで bundle 外へ書かせない。SEC-1）。
    let unpack_path = created.unpack_path();
    let unpacked = recorder.record_op(&unpack_name, || {
        unpacker.unpack(image.manifest(), &unpack_path)
    });
    if let Err(e) = unpacked {
        remove_created_rootfs(recorder, created, privilege);
        return Err(e);
    }
    // 公開前に所有トークンの印を書く（delete が作成世代を照合する。OCI-7・#2378）。失敗は公開前なので消す。
    // 印には状態ルートの識別子も載せる（孤児の回収が別の状態ルートの木を消さないため。OCI-5・#2635）。
    if let Err(e) = created.seal_with(state_root_scope(store).as_deref(), privilege) {
        remove_created_rootfs(recorder, created, privilege);
        return Err(e);
    }
    if let Err(e) = created.publish_with(privilege) {
        // 改名前の失敗だけ非公開の木を消す。改名後の検証失敗は公開済みで、並行する create が使いうるため
        // 残す（OCI-7 の使用中 rootfs の保持。#854 の起動時照合・手動で回収する）。
        if !created.is_published() {
            remove_created_rootfs(recorder, created, privilege);
        }
        return Err(e);
    }
    // 公開後の失敗では rootfs を消さずに残す（OCI-7 の使用中 rootfs の保持）。公開済みの名前は並行する通常の
    // create が検証して自分のものとして成功しうるが、bundle の別表記・別 bundle からの同一 rootfs の参照を
    // 確実に見分ける手段と、通常の create と共有する排他が無いため、「未使用の確認 → 削除」は使用中の
    // rootfs を壊しうる。残る木は #854 の起動時照合・手動で回収する（余分に持つだけの安全側。REPAIR-3）。
    match validate_bundle_audited(req.bundle(), audit) {
        // 文字列の一致に加え、解決した実体が展開した実体（保持中の fd の dev・ino）であることを確認する
        // （展開中に bundle の途中の要素を別名へ移して新しい同名の rootfs を用意する差し替えを拒否する）。
        Ok((_, rootfs))
            if same_dir_path(&rootfs, created.path()) && created.is_unpacked_at(&rootfs) =>
        {
            Ok(created)
        }
        Ok(_) => Err(invalid("root.path changed while unpacking")),
        Err(e) => Err(e),
    }
}

/// 2 つの経路が同じディレクトリを指すかを、`.`・`//`・末尾の `/` を除いた要素列で比べる。
///
/// `check_rootfs` は `bundle.join(root.path)` をそのまま返すため、`./rootfs`・`rootfs/` のような等価な
/// 書き方の `root.path` も `prepare_rootfs_target` の正規化済みの経路と同じものとして扱う。
fn same_dir_path(a: &Path, b: &Path) -> bool {
    let normal = |p: &Path| -> Vec<std::ffi::OsString> {
        p.components()
            .filter(|c| !matches!(c, Component::CurDir))
            .map(|c| c.as_os_str().to_os_string())
            .collect()
    };
    normal(a) == normal(b)
}

/// 作った rootfs を消す。失敗は握りつぶさず `image_rootfs_cleanup` として記録し、元のエラーを優先させる。
fn remove_created_rootfs(
    recorder: &OpRecorder,
    created: CreatedRootfs,
    privilege: &ImageRootfsPrivilege,
) {
    if let Ok(name) = OpName::new(IMAGE_ROOTFS_CLEANUP_OP_NAME) {
        let _ = recorder.record_op(&name, || created.remove_with(privilege));
    }
}

/// 登録した参照を外す。失敗は握りつぶさず `image_ref_rollback` として記録し、元のエラーを優先させる。
fn rollback_image_ref(recorder: &OpRecorder, image: ContainerImage<'_>, req: &CreateRequest) {
    if let Ok(name) = OpName::new(IMAGE_REF_ROLLBACK_OP_NAME) {
        let _ = recorder.record_op(&name, || image.refs().release(req.id()));
    }
}

/// bundle の `config.json` を読み込み、起動可能な設定であることを検証する。
///
/// create（本モジュール）と start（`start.rs`。create 後の書き換え = TOCTOU の再検証）が同一の
/// 検証を共有するための入口。戻り値は検証済みの設定と、検査済みの rootfs の絶対パス。
/// 検証内容はモジュール doc の「fail-closed の判断」を参照。
pub(super) fn validate_bundle(bundle: &Path) -> Result<(OciConfig, PathBuf), TraitError> {
    validate_bundle_audited(bundle, None)
}

/// [`validate_bundle`] に、`mounts[].destination` 拒否の監査記録（`audit` が `Some` のときだけ）を足したもの。
/// create の経路（#2480）と start の再検証の経路（#2594）が `Some` を渡す。
pub(super) fn validate_bundle_audited(
    bundle: &Path,
    audit: Option<ConfigAudit<'_>>,
) -> Result<(OciConfig, PathBuf), TraitError> {
    let config = validate_config(bundle, audit)?;
    let rootfs = check_rootfs(bundle, config.root().path())?;
    Ok((config, rootfs))
}

/// `validate_bundle` のうち rootfs の実在に依らない部分（config の読み込みと各種検証）。
///
/// イメージつき create は、展開の前にこれだけを済ませる（不正な config で展開しない。#2342）。
///
/// `audit` があれば、`mounts[].destination` の拒否をここで mount 層の監査へ記録する。`OciConfigError` の
/// field 情報は `TraitError` へ変換すると落ちるため、変換の直前がフックできる唯一の点（#2480・SEC-4・OCI-4）。
/// 返すエラーの内容は `audit` の有無で変わらない。
fn validate_config(bundle: &Path, audit: Option<ConfigAudit<'_>>) -> Result<OciConfig, TraitError> {
    let config = load_config(&bundle.join(CONFIG_FILE_NAME)).map_err(|e| match audit {
        // 記録の成否（delivery）は拒否に影響させない。失敗の通知は sink 側の責務。
        Some(a) => config_error(audit_mount_config_error(e, Some(a.id), a.sink).error),
        None => config_error(e),
    })?;
    reject_unapplied(&config)?;
    check_cgroups_path(&config)?;
    check_resource_ranges(&config)?;
    if config.process().is_none() {
        return Err(invalid("config.json: process is required"));
    }
    Ok(config)
}

/// `linux.resources` が cgroup v2 の値として表せる範囲か確かめる（Linux のみ。範囲外は `InvalidArgument`）。
///
/// 変換は `cgroups::ResourceLimitPlan` と共有し、start が書く値と同じ規則で create の時点に拒否する。
/// メッセージは固定文言で、値を含めない（ERR-1）。他 OS は cgroup を持たず start も拒否されるため何もしない。
#[cfg(target_os = "linux")]
fn check_resource_ranges(config: &OciConfig) -> Result<(), TraitError> {
    if let Some(limits) = config.linux_resources() {
        crate::cgroups::ResourceLimitPlan::try_from(limits).map_err(|e| {
            TraitError::new(
                e.code,
                format!(
                    "{CONFIG_FILE_NAME}: linux.resources has a value outside the cgroup v2 range"
                ),
            )
        })?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_resource_ranges(_config: &OciConfig) -> Result<(), TraitError> {
    Ok(())
}

/// bundle の `config.json` を検証して `linux.resources`（解釈済みの項目）を返す（#2019）。
///
/// supervisor の start 経路（`ProductionStartDeps::prepare_cgroup`）が、cgroup の連鎖で制限ファイルへ書く値を
/// 取り出すために呼ぶ。検証は create / start と同一（`validate_bundle`）で、`linux.resources` が無ければ
/// `None`。launcher は fork の前に、この値と `oci_runtime::start` が読む config の値の一致を確かめる
/// （手順 5 と手順 8 の間の書き換え対策）。
pub fn load_resource_limits(bundle: &Path) -> Result<Option<LinuxResourceLimits>, TraitError> {
    let (config, _rootfs) = validate_bundle(bundle)?;
    Ok(config.linux_resources().cloned())
}

/// [`load_resource_limits`] に、`mounts[].destination` 拒否の監査記録（SEC-4・OCI-4・#2594）を足したもの。
///
/// supervisor の start 手順 5（`prepare_cgroup`）が、create 後に書き換えられた destination（TOCTOU）を
/// 最初に拒否する点で呼ぶ。拒否は mount 層・`path` なしで `sink` に 1 件記録する。返すエラーは
/// [`load_resource_limits`] とバイト単位で同じ（記録の成否で拒否を覆さない。fail-closed）。
pub fn load_resource_limits_audited(
    bundle: &Path,
    id: &ContainerId,
    sink: &dyn AuditSink,
) -> Result<Option<LinuxResourceLimits>, TraitError> {
    let (config, _rootfs) = validate_bundle_audited(bundle, Some(ConfigAudit { id, sink }))?;
    Ok(config.linux_resources().cloned())
}

fn invalid(message: &str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

/// パーサのエラーを、値を含まない固定文言のまま `TraitError` に写す。
fn config_error(err: OciConfigError) -> TraitError {
    TraitError::new(err.code(), format!("{CONFIG_FILE_NAME}: {}", err.message()))
}

/// 未解釈の指定（`UnappliedField`）を 1 つでも含む config を拒否する（SEC-1・CORE-5）。
fn reject_unapplied(config: &OciConfig) -> Result<(), TraitError> {
    let fields = config.unapplied_fields();
    if fields.is_empty() {
        return Ok(());
    }
    let list: Vec<&'static str> = fields.iter().map(|f| f.as_str()).collect();
    Err(TraitError::new(
        ErrorCode::Unimplemented,
        format!("unsupported config fields: {}", list.join(", ")),
    ))
}

/// `root.path` が bundle 配下に収まり（bundle 外の絶対指定は拒否）、bundle 配下の全要素が
/// symlink でない存在するディレクトリであることを確認する。
pub(super) fn check_rootfs(bundle: &Path, root_path: &Path) -> Result<PathBuf, TraitError> {
    // 展開中の非公開の木（予約名）を通常の create が rootfs として採用しない（OCI-7）。
    if super::image_rootfs::has_staging_component(root_path) {
        return Err(invalid("root.path must not use a reserved staging name"));
    }
    // bundle 自体が展開途中の木（またはその配下）でも採用しない。`root.path` を `.` にすれば root.path
    // の検査を素通りできるため、bundle の表記と実体（symlink 解決後）の両方を見る（OCI-7）。
    let resolved_bundle = std::fs::canonicalize(bundle).ok();
    if super::image_rootfs::has_staging_component(bundle)
        || resolved_bundle
            .as_deref()
            .is_some_and(super::image_rootfs::has_staging_component)
    {
        return Err(invalid("bundle must not use a reserved staging name"));
    }
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid("root.path must not contain '..'"));
    }
    let rootfs: PathBuf = bundle.join(root_path);
    // 絶対指定の `root.path` は bundle を置き換える。ホストの `/` を rootfs にできないようにする（SEC-1。
    // `exec::prepare_rootfs` の `RootfsIsHostRoot` と同じ境界を起動前にも守る）。
    if !rootfs
        .components()
        .any(|c| matches!(c, Component::Normal(_)))
    {
        return Err(invalid("rootfs must not be the filesystem root"));
    }
    // bundle 配下の相対部分を要素ごとに検査する。bundle 自体（親が symlink でもよい）は対象外。
    // bundle 外を指す絶対指定は、ホスト上の任意ディレクトリを rootfs にできてしまうため拒否する（SEC-1）。
    let mut checked = match rootfs.strip_prefix(bundle) {
        Ok(rel) => {
            let mut current = bundle.to_path_buf();
            let mut last = None;
            for c in rel.components() {
                if let Component::Normal(part) = c {
                    current.push(part);
                    let meta = inspect(&current)?;
                    if is_link_like(&meta) {
                        return Err(invalid("rootfs must not contain a symlink"));
                    }
                    last = Some(meta);
                }
            }
            last
        }
        Err(_) => return Err(invalid("rootfs must be inside the bundle")),
    };
    if checked.is_none() {
        // bundle 自身（相対部分が空）。
        let meta = inspect(&rootfs)?;
        if is_link_like(&meta) {
            return Err(invalid("rootfs must not be a symlink"));
        }
        checked = Some(meta);
    }
    match checked {
        Some(meta) if meta.is_dir() => Ok(rootfs),
        _ => Err(invalid("rootfs is not a directory")),
    }
}

/// symlink に加え、Windows のディレクトリ junction 等の reparse point もリンクとして扱う（SEC-1）。
///
/// junction は `FileType::is_symlink()` が false を返すため、属性の `FILE_ATTRIBUTE_REPARSE_POINT`
/// で検出する。他 OS では symlink 判定のみ。
pub(super) fn is_link_like(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

pub(super) fn inspect(path: &Path) -> Result<std::fs::Metadata, TraitError> {
    std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
            TraitError::new(ErrorCode::NotFound, "rootfs directory not found")
        }
        io::ErrorKind::PermissionDenied => {
            TraitError::new(ErrorCode::PermissionDenied, "cannot access rootfs")
        }
        _ => TraitError::new(ErrorCode::Internal, "failed to inspect rootfs"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{
        ContainerId, ContainerState, DeleteStateRequest, DeleteStateResponse, GetStateRequest,
        ListStateRequest, StateList, StateRevision, UpdateStateRequest,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// テスト専用のインメモリ `StateStore`（`traits::state_store` のスタブは非公開のため別に持つ）。
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
    }

    impl MemStateStore {
        fn new() -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
            }
        }

        fn len(&self) -> usize {
            self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let revision = StateRevision::from_raw(records.len() as u64 + 1);
            let mut record =
                StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
            if let Some(a) = req.annotations() {
                record = record.with_annotations(a.clone());
            }
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }

        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            Ok(StateList::new(records.values().cloned().collect(), None))
        }

        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .remove(req.id())
                .map(|_| DeleteStateResponse::new())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }
    }

    /// テストごとに一意な bundle ディレクトリ（終了時に削除）。
    ///
    /// bundle は `ScratchDir` の子にする（親は Linux で共有 flock を持ち、`BundleLock` の排他 flock が失敗するため）。
    /// pid だけの名前を先に消す旧方式の置き換え（#3434・REPAIR-12）。
    struct Bundle {
        dir: PathBuf,
        _scratch: crate::scratch_root::ScratchDir,
    }

    impl Bundle {
        fn new(name: &str) -> Self {
            let (scratch, dir) =
                crate::test_support::scratch_child(&format!("fandhe-oci-create-{name}"), "bundle");
            Self {
                dir,
                _scratch: scratch,
            }
        }

        fn write_config(&self, v: &Value) {
            std::fs::write(
                self.dir.join("config.json"),
                serde_json::to_vec(v).expect("serialize"),
            )
            .expect("write config");
        }

        fn request(&self, id: &str) -> CreateRequest {
            CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
                .expect("absolute bundle")
        }
    }

    fn valid_config() -> Value {
        json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/true"],
                "cwd": "/"
            }
        })
    }

    /// REPAIR-12・#3434: 旧方式の pid だけの名前の残骸（FIFO の `config.json`）があっても `Bundle::new` は別名の
    /// bundle を作り、設定の書き込みと rootfs の検査が成功する。残骸に触れず、drop は自分のパスだけを消す。
    #[cfg(unix)]
    #[test]
    fn repair12_3434_bundle_ignores_legacy_pid_residue() {
        let residue = crate::test_support::LegacyResidue::new(
            &format!("fandhe-oci-create-legacy3434-{}", std::process::id()),
            "config.json",
        );
        let b = ready_bundle("legacy3434");
        assert_ne!(b.dir, residue.dir());
        assert!(
            std::fs::metadata(b.dir.join("config.json"))
                .unwrap()
                .is_file()
        );
        assert!(check_rootfs(&b.dir, Path::new("rootfs")).is_ok());
        residue.assert_untouched();
        let path = b.dir.clone();
        drop(b);
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        residue.assert_untouched();
    }

    fn ready_bundle(name: &str) -> Bundle {
        let b = Bundle::new(name);
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        b
    }

    /// SEC-4・OCI-4（#2594）: `load_resource_limits_audited` は destination 拒否を mount 層・`path` なしで
    /// 1 件記録し、返すエラーは `load_resource_limits` と同じ。destination 以外の拒否は記録しない。
    #[test]
    fn sec4_load_resource_limits_audited_records_destination_rejection() {
        use crate::audit_log::{AuditEvent, mount::tests::VecSink};
        for (i, dest) in ["/../..", "/", "run/../../.."].into_iter().enumerate() {
            let b = ready_bundle(&format!("lrl-dest-{i}"));
            let mut cfg = valid_config();
            cfg["mounts"] = json!([{
                "destination": dest, "type": "bind", "source": "/srv/x", "options": ["bind", "rw"]
            }]);
            b.write_config(&cfg);
            let id = ContainerId::new("c1").expect("id");
            let sink = VecSink::new(false);
            let err = load_resource_limits_audited(&b.dir, &id, &sink).expect_err("must fail");
            let plain = load_resource_limits(&b.dir).expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{dest}");
            assert_eq!(err.code(), plain.code());
            assert_eq!(err.message(), plain.message());
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{dest}");
            assert_eq!(recs[0].container_id(), Some(&id));
            assert!(matches!(
                recs[0].event(),
                AuditEvent::Mount {
                    path: None,
                    reason: None
                }
            ));
            // 記録に失敗しても拒否は同じ（fail-closed）。
            let bad = VecSink::new(true);
            let err2 = load_resource_limits_audited(&b.dir, &id, &bad).expect_err("must fail");
            assert_eq!(err2.message(), plain.message());
        }
        // destination 以外の拒否（process 欠落）は記録しない。
        let b = ready_bundle("lrl-noproc");
        let mut cfg = valid_config();
        cfg.as_object_mut().expect("object").remove("process");
        b.write_config(&cfg);
        let sink = VecSink::new(false);
        let id = ContainerId::new("c1").expect("id");
        assert!(load_resource_limits_audited(&b.dir, &id, &sink).is_err());
        assert!(sink.snapshot().is_empty());
    }

    /// OCI-4: 正しい bundle で created・pid なしの状態が作られ、ストアからも同じ値が取れる。
    #[test]
    fn oci4_create_initializes_created_state_without_process() {
        let b = ready_bundle("ok");
        let store = MemStateStore::new();
        let req = b.request("c1");
        let record = create(&store, &OpRecorder::new(), &req).expect("create succeeds");
        assert_eq!(record.status().state(), ContainerState::Created);
        assert_eq!(record.status().pid(), None);
        assert_eq!(record.status().exit_code(), None);
        assert_eq!(record.bundle(), req.bundle());
        let got = store
            .get(&GetStateRequest::new(req.id().clone()))
            .expect("stored");
        assert_eq!(got, record);
    }

    /// SUP-12・CLI-1（#2713）: `CreateRequest::with_annotations` の label が状態記録へ具体値で残る。
    #[test]
    fn sup12_create_records_annotations_from_request() {
        let b = ready_bundle("annotations");
        let store = MemStateStore::new();
        let annotations = crate::traits::Annotations::new([
            ("com.example.tier".to_owned(), "web".to_owned()),
            ("owner".to_owned(), String::new()),
        ])
        .expect("annotations");
        let req = b.request("c1").with_annotations(annotations);
        let record = create(&store, &OpRecorder::new(), &req).expect("create succeeds");
        assert_eq!(record.annotations().get("com.example.tier"), Some("web"));
        assert_eq!(record.annotations().get("owner"), Some(""));
        assert_eq!(record.annotations().get("missing"), None);
    }

    /// OCI-4: 構文エラーの config.json は InvalidArgument で、ストアに何も残らない。
    #[test]
    fn oci4_create_rejects_malformed_config() {
        let b = Bundle::new("malformed");
        std::fs::write(b.dir.join("config.json"), b"{ not json").expect("write");
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(store.len(), 0);
    }

    /// OCI-4: config.json が無い bundle は NotFound。
    #[test]
    fn oci4_create_rejects_missing_config() {
        let b = Bundle::new("noconfig");
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(store.len(), 0);
    }

    /// OCI-4: process 無しの config は created にしない。
    #[test]
    fn oci4_create_rejects_missing_process() {
        let b = ready_bundle("noproc");
        let mut cfg = valid_config();
        cfg.as_object_mut().expect("obj").remove("process");
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "config.json: process is required");
        assert_eq!(store.len(), 0);
    }

    /// SEC-1・CORE-5: 未解釈の指定（seccomp・capabilities）を含む config は Unimplemented で拒否する。
    #[test]
    fn sec1_create_rejects_unapplied_fields() {
        let b = ready_bundle("unapplied");
        let mut cfg = valid_config();
        cfg["linux"] = json!({"seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}});
        cfg["process"]["capabilities"] = json!({"bounding": ["CAP_SYS_ADMIN"]});
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert!(err.message().contains("linux.seccomp"), "{}", err.message());
        assert!(
            err.message().contains("process.capabilities"),
            "{}",
            err.message()
        );
        assert_eq!(store.len(), 0);
    }

    /// OCI-4: rootfs 不在は NotFound、通常ファイルは InvalidArgument。
    #[test]
    fn oci4_create_rejects_missing_or_non_dir_rootfs() {
        let b = Bundle::new("rootfs");
        b.write_config(&valid_config());
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("missing");
        assert_eq!(err.code(), ErrorCode::NotFound);
        std::fs::write(b.dir.join("rootfs"), b"x").expect("file");
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("not a dir");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(store.len(), 0);
    }

    /// SEC-1: `root.path` の `..` 要素は bundle 外への脱出として拒否する。
    #[test]
    fn oci4_create_rejects_parent_dir_in_root_path() {
        let b = ready_bundle("dotdot");
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("../x");
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(store.len(), 0);
    }

    /// SEC-1: rootfs が symlink の場合は拒否する（Windows は symlink 作成が権限依存のため Unix のみ）。
    #[cfg(unix)]
    #[test]
    fn oci4_create_rejects_symlink_rootfs() {
        let b = Bundle::new("symlink");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("real")).expect("real");
        std::os::unix::fs::symlink(b.dir.join("real"), b.dir.join("rootfs")).expect("symlink");
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(store.len(), 0);
    }

    /// CORE-2: 同じ ID の 2 回目の create は AlreadyExists で、件数は 1 のまま。
    #[test]
    fn core2_create_twice_returns_already_exists() {
        let b = ready_bundle("twice");
        let store = MemStateStore::new();
        create(&store, &OpRecorder::new(), &b.request("c1")).expect("first");
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("second");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(store.len(), 1);
    }

    /// SEC-1: bundle 外を指す絶対 `root.path` は実在ディレクトリでも拒否する。
    #[test]
    fn sec1_create_rejects_absolute_root_path_outside_bundle() {
        let b = Bundle::new("abs-out");
        let outside = std::env::temp_dir();
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!(outside.to_str().expect("utf8"));
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "rootfs must be inside the bundle");
        assert_eq!(store.len(), 0);
    }

    /// OCI-4: bundle 配下を指す絶対 `root.path` は成功する。
    #[test]
    fn oci4_create_accepts_absolute_root_path() {
        let b = Bundle::new("abs");
        let abs = b.dir.join("elsewhere");
        std::fs::create_dir(&abs).expect("dir");
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!(abs.to_str().expect("utf8"));
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let record = create(&store, &OpRecorder::new(), &b.request("c1")).expect("create succeeds");
        assert_eq!(record.status().state(), ContainerState::Created);
    }

    /// SEC-1: 中間要素が symlink で bundle 外を指す root.path を拒否する。
    #[cfg(unix)]
    #[test]
    fn sec1_create_rejects_intermediate_symlink_rootfs() {
        let b = Bundle::new("midlink");
        let outside = Bundle::new("midlink-outside");
        std::fs::create_dir(outside.dir.join("rootfs")).expect("outside rootfs");
        std::os::unix::fs::symlink(&outside.dir, b.dir.join("link")).expect("symlink");
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("link/rootfs");
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(store.len(), 0);
    }

    /// REPAIR-4: 成功・失敗の両経路で件数とレイテンシが 1 件ずつ記録される。
    #[test]
    fn repair4_create_records_success_and_failure() {
        let b = ready_bundle("rec");
        let store = MemStateStore::new();
        let rec = OpRecorder::new();
        create(&store, &rec, &b.request("c1")).expect("first");
        create(&store, &rec, &b.request("c1")).expect_err("dup");
        let stats = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("recorded");
        assert_eq!(stats.success(), 1);
        assert_eq!(stats.failure(), 1);
        assert!(stats.latency().is_some());
    }

    /// ERR-2・TASK-96.2: ID 重複の失敗が op = create・同一 code・終了コード 4・構造化 1 行で得られる。
    #[test]
    fn err2_create_failure_is_wired_to_oci_runtime_error() {
        let b = ready_bundle("err2-dup");
        let store = MemStateStore::new();
        let rec = OpRecorder::new();
        create(&store, &rec, &b.request("c1")).expect("first");
        let err = create(&store, &rec, &b.request("c1")).expect_err("dup");
        assert_eq!(err.op(), LifecycleOp::Create);
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(err.exit_code().get(), 4);
        let mut out = Vec::new();
        err.write_json_line(&mut out).expect("write");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            format!(
                "{{\"op\":\"create\",\"code\":\"ALREADY_EXISTS\",\"message\":{}}}\n",
                serde_json::to_string(err.message()).expect("json")
            )
        );
    }

    /// ERR-2・TASK-96.2: config.json 不在（検証段階の失敗）が NOT_FOUND・終了コード 3 になり、失敗が計数される。
    #[test]
    fn err2_create_missing_config_is_not_found() {
        let b = Bundle::new("err2-noconfig");
        let store = MemStateStore::new();
        let rec = OpRecorder::new();
        let err = create(&store, &rec, &b.request("c1")).expect_err("no config");
        assert_eq!(err.op(), LifecycleOp::Create);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.exit_code().get(), 3);
        let stats = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("recorded");
        assert_eq!(stats.failure(), 1);
    }

    // ---- OCI-7 イメージ参照の登録（TASK-183.8.1）----

    use crate::oci_runtime::{
        ContainerImageRefs, ImageManifestDigest, ImageRefRegistration, ImageRefRelease,
    };
    use std::sync::Arc;

    const MANIFEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type Log = Arc<Mutex<Vec<&'static str>>>;

    fn push(log: &Log, entry: &'static str) {
        log.lock().unwrap_or_else(|e| e.into_inner()).push(entry);
    }

    fn log_of(log: &Log) -> Vec<&'static str> {
        log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 呼び出し順を記録するテスト用 `StateStore`（`create` の結果を差し替えられる）。
    struct LoggingStore {
        inner: MemStateStore,
        log: Log,
        create_error: Option<ErrorCode>,
        /// 状態作成の直後に並行する delete が状態を消した状況を再現する。
        delete_after_create: bool,
        /// `create_error` で失敗させる前に、同じ ID・bundle の状態を先に作る（並行する通常の create の成功を再現）。
        concurrent_create_wins: bool,
    }

    impl StateStore for LoggingStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            push(&self.log, "store.create");
            if let Some(code) = self.create_error {
                if self.concurrent_create_wins {
                    self.inner.create(req)?;
                }
                return Err(TraitError::new(code, "injected"));
            }
            let record = self.inner.create(req)?;
            if self.delete_after_create {
                self.inner.delete(&DeleteStateRequest::new(
                    req.id().clone(),
                    record.revision(),
                ))?;
            }
            Ok(record)
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            self.inner.update(req)
        }
        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.inner.get(req)
        }
        fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
            self.inner.list(req)
        }
        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            self.inner.delete(req)
        }
    }

    /// 呼び出し順を記録するテスト用 `ContainerImageRefs`。`register` は bundle の rootfs を作れる。
    struct LoggingRefs {
        log: Log,
        register_result: Result<ImageRefRegistration, TraitError>,
        create_rootfs_in: Option<PathBuf>,
    }

    impl ContainerImageRefs for LoggingRefs {
        fn register(
            &self,
            _id: &ContainerId,
            _manifest: &ImageManifestDigest,
        ) -> Result<ImageRefRegistration, TraitError> {
            push(&self.log, "refs.register");
            if let Some(bundle) = &self.create_rootfs_in {
                std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
            }
            self.register_result.clone()
        }
        fn release(&self, _id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
            push(&self.log, "refs.release");
            Ok(ImageRefRelease::Released)
        }
        fn bind(
            &self,
            _id: &ContainerId,
        ) -> Result<crate::oci_runtime::ImageRefGeneration, TraitError> {
            push(&self.log, "refs.bind");
            Ok(crate::oci_runtime::ImageRefGeneration::from_raw(1))
        }
        fn registration(
            &self,
            _id: &ContainerId,
        ) -> Result<Option<crate::oci_runtime::ImageRefGeneration>, TraitError> {
            Ok(None)
        }
        fn release_if(
            &self,
            _id: &ContainerId,
            _expected: crate::oci_runtime::ImageRefGeneration,
        ) -> Result<ImageRefRelease, TraitError> {
            push(&self.log, "refs.release_if");
            Ok(ImageRefRelease::NotRegistered)
        }
    }

    fn fixture(
        create_error: Option<ErrorCode>,
        register_result: Result<ImageRefRegistration, TraitError>,
        rootfs_by_register: Option<&Bundle>,
    ) -> (LoggingStore, LoggingRefs, Log) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let store = LoggingStore {
            inner: MemStateStore::new(),
            log: Arc::clone(&log),
            create_error,
            delete_after_create: false,
            concurrent_create_wins: false,
        };
        let refs = LoggingRefs {
            log: Arc::clone(&log),
            register_result,
            create_rootfs_in: rootfs_by_register.map(|b| b.dir.clone()),
        };
        (store, refs, log)
    }

    fn run_with_image(
        store: &LoggingStore,
        refs: &LoggingRefs,
        rec: &OpRecorder,
        b: &Bundle,
    ) -> Result<StateRecord, OciRuntimeError> {
        let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
        create_with_image(
            store,
            rec,
            ContainerImage::new(refs, &manifest),
            &b.request("c1"),
        )
    }

    /// OCI-7: 参照登録 → rootfs の使用 → 状態作成の順。登録が rootfs を作る替え玉で、登録が先であることを観測する。
    #[test]
    fn oci7_create_registers_before_rootfs_use_and_state_create() {
        let b = Bundle::new("oci7-order");
        b.write_config(&valid_config());
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), Some(&b));
        let record = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect("create");
        assert_eq!(record.status().state(), ContainerState::Created);
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "store.create", "refs.bind"]
        );
    }

    /// OCI-7: 登録が失敗したら状態は作らず、エラーはそのまま返る。
    #[test]
    fn oci7_create_register_failure_writes_no_state() {
        let b = ready_bundle("oci7-regfail");
        let (store, refs, log) =
            fixture(None, Err(TraitError::new(ErrorCode::Timeout, "lock")), None);
        let err = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(log_of(&log), vec!["refs.register"]);
        assert_eq!(store.inner.len(), 0);
    }

    /// OCI-7: 既に登録済みの ID は AlreadyExists で拒否し、他者の参照を外さない。
    #[test]
    fn oci7_create_already_registered_is_rejected_without_rollback() {
        let b = ready_bundle("oci7-already");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::AlreadyRegistered), None);
        let err = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect_err("reject");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(log_of(&log), vec!["refs.register"]);
    }

    /// OCI-7: bundle の検証失敗では参照を外し、状態は作らない。
    #[test]
    fn oci7_create_rolls_back_on_bundle_validation_failure() {
        let b = Bundle::new("oci7-badbundle");
        b.write_config(&valid_config());
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let err = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect_err("no rootfs");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// OCI-7・SEC-1（#2378）: 展開器なしの create も bundle の検証より前にロックを取る。delete が保持中なら、
    /// rootfs が無い bundle でも検証（`NotFound`）へ進まず `FailedPrecondition` で拒否し、参照を外して状態は作らない
    /// （検証の後にロックを取ると、その隙に delete が rootfs を消して完了し、rootfs の無い状態を作れてしまう）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_create_without_unpacker_locks_before_validation() {
        let b = Bundle::new("oci7-lock-first");
        b.write_config(&valid_config());
        let _held = BundleLock::acquire(&b.dir).expect("hold the bundle lock");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let err = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect_err("locked");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
        assert_eq!(store.inner.len(), 0);
    }

    /// OCI-7: 状態作成が AlreadyExists で失敗したら参照を外す。
    #[test]
    fn oci7_create_rolls_back_on_state_already_exists() {
        let b = ready_bundle("oci7-stateexists");
        let (store, refs, log) = fixture(
            Some(ErrorCode::AlreadyExists),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let err = run_with_image(&store, &refs, &OpRecorder::new(), &b).expect_err("exists");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "store.create", "refs.release"]
        );
    }

    /// OCI-7: 書き込みの有無が曖昧な状態作成の失敗（Internal）では参照を残す（安全側）。
    #[test]
    fn oci7_create_keeps_ref_on_ambiguous_state_error() {
        let b = ready_bundle("oci7-ambiguous");
        let (store, refs, log) = fixture(
            Some(ErrorCode::Internal),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let rec = OpRecorder::new();
        let err = run_with_image(&store, &refs, &rec, &b).expect_err("internal");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(log_of(&log), vec!["refs.register", "store.create"]);
        let stats = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("recorded");
        assert_eq!(stats.failure(), 1);
    }

    /// OCI-7: 状態作成と確定の間に並行する delete が状態を消していたら、確定した自分の世代の参照を外す。
    #[test]
    fn oci7_create_releases_bound_ref_when_state_vanished_before_bind() {
        let b = ready_bundle("oci7-vanish");
        let (mut store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        store.delete_after_create = true;
        run_with_image(&store, &refs, &OpRecorder::new(), &b).expect("create");
        assert_eq!(
            log_of(&log),
            vec![
                "refs.register",
                "store.create",
                "refs.bind",
                "refs.release_if"
            ]
        );
    }
    // ---- OCI-7 レイヤー展開の位置と後始末（#2342）----

    use crate::oci_runtime::{ImageRootfsUnpacked, ImageRootfsUnpacker};

    #[derive(Clone, Copy, PartialEq)]
    #[cfg_attr(not(unix), allow(dead_code))]
    enum UnpackMode {
        Ok,
        /// 書いてから失敗する。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        FailAfterWrite,
        /// 読み取り専用のディレクトリを作って成功する。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        ReadOnlyDir,
    }

    struct LoggingUnpacker {
        log: Log,
        mode: UnpackMode,
        /// 展開の途中で config の `root.path` を書き換える（bundle, 新しい config）。
        rewrite_config: Option<(PathBuf, Value)>,
        /// 展開中に最終の `root.path` が見えるかを観測する経路。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        probe: Option<PathBuf>,
        observed_visible: Mutex<Option<bool>>,
        /// 展開中に（他者として）最終の `root.path` を作り、中に印を置く。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        create_final: Option<PathBuf>,
        observed: Mutex<Vec<String>>,
    }

    impl LoggingUnpacker {
        fn new(log: &Log, mode: UnpackMode) -> Self {
            Self {
                log: Arc::clone(log),
                mode,
                rewrite_config: None,
                probe: None,
                observed_visible: Mutex::new(None),
                create_final: None,
                observed: Mutex::new(Vec::new()),
            }
        }
    }

    impl ImageRootfsUnpacker for LoggingUnpacker {
        fn unpack(
            &self,
            _manifest: &ImageManifestDigest,
            rootfs: &Path,
        ) -> Result<ImageRootfsUnpacked, TraitError> {
            push(&self.log, "unpack");
            let empty = std::fs::read_dir(rootfs).expect("rootfs exists").count() == 0;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                std::fs::metadata(rootfs)
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o700;
            self.observed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("empty={empty} mode={mode:o}"));
            if let Some(probe) = &self.probe {
                *self
                    .observed_visible
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(probe.exists());
            }
            if let Some(path) = &self.create_final {
                std::fs::create_dir(path).expect("final");
                std::fs::write(path.join("others"), b"x").expect("others");
            }
            if let Some((bundle, cfg)) = &self.rewrite_config {
                std::fs::write(
                    bundle.join("config.json"),
                    serde_json::to_vec(cfg).expect("ser"),
                )
                .expect("rewrite");
            }
            match self.mode {
                UnpackMode::Ok => Ok(ImageRootfsUnpacked::default()),
                UnpackMode::FailAfterWrite => {
                    std::fs::write(rootfs.join("f"), b"x").expect("f");
                    std::fs::create_dir(rootfs.join("d")).expect("d");
                    std::fs::write(rootfs.join("d").join("g"), b"y").expect("g");
                    Err(TraitError::new(ErrorCode::Internal, "unpack failed"))
                }
                UnpackMode::ReadOnlyDir => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let d = rootfs.join("ro");
                        std::fs::create_dir(&d).expect("ro");
                        std::fs::write(d.join("f"), b"x").expect("f");
                        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555))
                            .expect("chmod");
                    }
                    Ok(ImageRootfsUnpacked::default())
                }
            }
        }
    }

    fn run_unpacking(
        store: &LoggingStore,
        refs: &LoggingRefs,
        unpacker: &LoggingUnpacker,
        rec: &OpRecorder,
        b: &Bundle,
    ) -> Result<StateRecord, OciRuntimeError> {
        let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
        create_with_image(
            store,
            rec,
            ContainerImage::new(refs, &manifest).with_unpacker(unpacker),
            &b.request("c1"),
        )
    }

    fn config_bundle(name: &str) -> Bundle {
        let b = Bundle::new(name);
        b.write_config(&valid_config());
        b
    }

    #[cfg(unix)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn count_of(rec: &OpRecorder, op: &str) -> (u64, u64) {
        rec.snapshot_op(&OpName::new(op).expect("name"))
            .map(|s| (s.success(), s.failure()))
            .unwrap_or((0, 0))
    }

    /// OCI-7: 順序は 登録 → 展開 → 状態作成 → 確定。展開器は空の 0700 の rootfs を受け取る。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_runs_between_register_and_state_create() {
        let b = config_bundle("unpack-order");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect("create");
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "unpack", "store.create", "refs.bind"]
        );
        assert_eq!(
            *unpacker.observed.lock().expect("lock"),
            vec!["empty=true mode=700".to_string()]
        );
        assert!(b.dir.join("rootfs").is_dir());
    }

    /// OCI-7: 展開の途中の失敗で rootfs を消し、参照を外す。元のエラーが返る。
    // Linux 以外は rootfs の同一性を保証できず後始末を拒否する（image_rootfs.rs）ため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_failure_removes_rootfs_and_releases_ref() {
        let b = config_bundle("unpack-fail");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::FailAfterWrite);
        let rec = OpRecorder::new();
        let err = run_unpacking(&store, &refs, &unpacker, &rec, &b).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(!b.dir.join("rootfs").exists());
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "unpack", "refs.release"]
        );
        assert_eq!(store.inner.len(), 0);
        assert_eq!(count_of(&rec, "image_rootfs_unpack"), (0, 1));
        assert_eq!(count_of(&rec, "image_rootfs_cleanup"), (1, 0));
    }

    /// OCI-7: rootfs が既に存在する場合は展開せず AlreadyExists。既存の中身は残り、参照は外れる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_refuses_existing_rootfs() {
        let b = config_bundle("unpack-exists");
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        std::fs::write(b.dir.join("rootfs").join("keep"), b"x").expect("keep");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert!(b.dir.join("rootfs").join("keep").exists());
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// OCI-7: 不正な config（process なし）では展開せず rootfs も作らない。参照は外れる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_skipped_for_invalid_config() {
        let b = Bundle::new("unpack-badcfg");
        let mut cfg = valid_config();
        cfg.as_object_mut().expect("obj").remove("process");
        b.write_config(&cfg);
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(!b.dir.join("rootfs").exists());
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// OCI-7: 同じ ID の状態が既にあれば展開せず AlreadyExists。参照は外れる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_skipped_when_state_exists() {
        let b = config_bundle("unpack-stateexists");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        create_state(&store.inner, &b.request("c1"), None).expect("pre-existing");
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert!(!b.dir.join("rootfs").exists());
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// OCI-7: 展開の後に状態作成が AlreadyExists になったら rootfs を消し、参照を外す。
    // Linux 以外は rootfs の同一性を保証できず後始末を拒否する（image_rootfs.rs）ため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_state_already_exists_cleans_up() {
        let b = config_bundle("unpack-createexists");
        let (store, refs, log) = fixture(
            Some(ErrorCode::AlreadyExists),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        // 公開済みの rootfs は使用中かを確定できないため残し、参照だけ外す。
        assert!(b.dir.join("rootfs").is_dir());
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "unpack", "store.create", "refs.release"]
        );
    }

    /// OCI-7: 読み取り専用のディレクトリを含む展開物も、権限を補正して消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_cleanup_handles_read_only_dirs() {
        let b = config_bundle("unpack-ro");
        let (store, refs, log) = fixture(
            Some(ErrorCode::AlreadyExists),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::ReadOnlyDir);
        run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        // 公開後の失敗では使用中かを確定できないため残す（読み取り専用ディレクトリの削除は image_rootfs の単体試験）。
        assert!(b.dir.join("rootfs").is_dir());
    }

    /// OCI-7: 曖昧な状態作成の失敗（Internal）では rootfs も参照も残す。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_keeps_rootfs_and_ref_on_ambiguous_state_error() {
        let b = config_bundle("unpack-ambiguous");
        let (store, refs, log) = fixture(
            Some(ErrorCode::Internal),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(b.dir.join("rootfs").is_dir());
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "unpack", "store.create"]
        );
    }

    /// OCI-7: `root.path` が bundle 自身（`.`）なら展開せず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_rejects_bundle_itself_as_rootfs() {
        let b = Bundle::new("unpack-dot");
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!(".");
        b.write_config(&cfg);
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// SEC-1: `root.path` の中間要素が symlink なら拒否し、bundle 外に何も作らない。
    #[cfg(target_os = "linux")]
    #[cfg(unix)]
    #[test]
    fn oci7_unpack_rejects_symlink_in_root_path() {
        let b = Bundle::new("unpack-symlink");
        let outside = Bundle::new("unpack-symlink-out");
        std::os::unix::fs::symlink(&outside.dir, b.dir.join("link")).expect("symlink");
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("link/rootfs");
        b.write_config(&cfg);
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_dir(&outside.dir).expect("read").count(), 0);
        assert_eq!(log_of(&log), vec!["refs.register", "refs.release"]);
    }

    /// OCI-7・SEC-1: Linux では展開中の rootfs は最終の `root.path` に無く（並行する別の create から見えない）、
    /// 成功後に公開される。展開器へは bundle 配下の経路ではなく固定した fd の経路が渡る。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_runs_in_private_staging_and_publishes_after() {
        let b = config_bundle("unpack-staging");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let mut unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        unpacker.probe = Some(b.dir.join("rootfs"));
        run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect("create");
        assert_eq!(
            unpacker.observed_visible.lock().expect("lock").clone(),
            Some(false)
        );
        assert!(b.dir.join("rootfs").is_dir());
    }

    /// OCI-7: 展開の失敗では非公開の展開先だけを消し、最終の `root.path` に作られた他者の rootfs は触らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_failure_does_not_touch_rootfs_published_by_others() {
        let b = config_bundle("unpack-others");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let mut unpacker = LoggingUnpacker::new(&log, UnpackMode::FailAfterWrite);
        unpacker.create_final = Some(b.dir.join("rootfs"));
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(b.dir.join("rootfs").join("others").exists());
    }

    /// OCI-7・SEC-1: Linux 以外は展開先を固定できないため、作成も展開もせず Unimplemented で拒否する。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_unpack_is_refused_without_creating_rootfs_on_non_linux() {
        let b = config_bundle("unpack-non-linux");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert!(!b.dir.join("rootfs").exists());
    }

    /// OCI-7: 同じ bundle を指す別 ID の状態があるとき、公開後の失敗でも rootfs を消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_keeps_rootfs_used_by_other_id_with_same_bundle() {
        let b = config_bundle("unpack-other-id");
        let (store, refs, log) = fixture(
            Some(ErrorCode::InvalidArgument),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        let other = CreateStateRequest::new(
            ContainerStatus::created(crate::traits::ContainerId::new("other").expect("id"), None),
            b.dir.clone(),
        )
        .expect("req");
        store.inner.create(&other).expect("other state");
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(b.dir.join("rootfs").is_dir());
    }

    /// OCI-7: 展開の間に `root.path` が書き換わったら拒否し、参照を外し rootfs は残す。
    // Linux 以外は rootfs の同一性を保証できず後始末を拒否する（image_rootfs.rs）ため Linux 限定。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_rejects_root_path_changed_while_unpacking() {
        let b = config_bundle("unpack-rewrite");
        let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("other");
        std::fs::create_dir(b.dir.join("other")).expect("other");
        let mut unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        unpacker.rewrite_config = Some((b.dir.clone(), cfg));
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        // 公開済みの rootfs は使用中かを確定できないため残す。
        assert!(b.dir.join("rootfs").is_dir());
        assert!(b.dir.join("other").is_dir());
        assert_eq!(
            log_of(&log),
            vec!["refs.register", "unpack", "refs.release"]
        );
    }

    /// OCI-7: 展開の間に同じ ID・bundle の通常の create が成功していたら、使用中の rootfs は消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_keeps_rootfs_used_by_concurrent_create() {
        let b = config_bundle("unpack-concurrent");
        let (mut store, refs, log) = fixture(
            Some(ErrorCode::AlreadyExists),
            Ok(ImageRefRegistration::Registered),
            None,
        );
        store.concurrent_create_wins = true;
        let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
        let err = run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b).expect_err("x");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert!(b.dir.join("rootfs").is_dir());
    }

    /// OCI-7: `root.path` の等価な書き方（`./rootfs`・`rootfs/`・`a//b`）でも、展開した木を消さず成功する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_unpack_accepts_equivalent_root_path_spellings() {
        for (i, spelling) in ["./rootfs", "rootfs/", "a//b", "./a/./b/"]
            .iter()
            .enumerate()
        {
            let b = Bundle::new(&format!("unpack-spelling-{i}"));
            std::fs::create_dir_all(b.dir.join("a")).expect("a");
            let mut cfg = valid_config();
            cfg["root"]["path"] = json!(spelling);
            b.write_config(&cfg);
            let (store, refs, log) = fixture(None, Ok(ImageRefRegistration::Registered), None);
            let unpacker = LoggingUnpacker::new(&log, UnpackMode::Ok);
            run_unpacking(&store, &refs, &unpacker, &OpRecorder::new(), &b)
                .unwrap_or_else(|e| panic!("{spelling}: {e:?}"));
            let expected = if spelling.contains('a') {
                "a/b"
            } else {
                "rootfs"
            };
            assert!(b.dir.join(expected).is_dir(), "{spelling}");
        }
    }

    /// OCI-7: 展開途中の `.fandhe-unpack-*` を bundle に指定し `root.path` を `.` にしても拒否する。
    /// symlink 経由の別表記でも、実体が予約名なら拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_check_rootfs_rejects_staging_dir_as_bundle() {
        // 排他作成の `ScratchDir` の子を使う（#3434・REPAIR-12）。
        let (_scratch, base) = crate::test_support::scratch_child("fandhe-oci7-bundle", "d");
        let staging = base.join(".fandhe-unpack-1-0");
        std::fs::create_dir_all(staging.join("sub")).expect("dirs");
        for root in [".", "sub"] {
            let e = check_rootfs(&staging, Path::new(root)).expect_err("staging bundle");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{root}");
        }
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&staging, &alias).expect("symlink");
        let e = check_rootfs(&alias, Path::new(".")).expect_err("alias of staging");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let ok = base.join("bundle");
        std::fs::create_dir_all(&ok).expect("ok");
        assert!(check_rootfs(&ok, Path::new(".")).is_ok());
    }
}
