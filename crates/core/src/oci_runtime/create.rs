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
//!    capabilities・seccomp・resources 等を黙って無視すると、指定より弱い分離で起動する経路になる
//!    （SEC-1・CORE-5）。個別フィールドの許可は、それを実際に適用する後続タスクが
//!    パーサ側で解釈済みに移すことで行う。
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
//! # スコープ外
//!
//! - プロセス起動（TASK-29.3 start）・namespace 分離・mount 適用（bind は start と本番 launcher が適用する〔#1915〕。bind 以外の種類は未対応）
//! - mounts の rootfs 内 symlink 解決（mount を適用する側の担当）
//! - レイヤー展開（bundle は展開済みの前提。[`create_with_image`] の rootfs 検査の位置が将来の差し込み点）
//! - OCI-7 の参照テーブル登録は [`create_with_image`] が担う（TASK-183.8.1）。bundle を直に指定する
//!   [`create`] は参照を登録しない
//! - ファイルベースの状態保存（TASK-31・OCI-5）
//! - create 後に bundle の `config.json` が書き換えられる TOCTOU は、start（TASK-29.3）が
//!   [`validate_bundle`] で再検証して対処する（ダイジェスト保持は `StateRecord` の拡張を要するため採らない）

use std::io;
use std::path::{Component, Path, PathBuf};

use super::config::{OciConfig, OciConfigError, load_config};
use super::error::{LifecycleOp, OciRuntimeError};
use super::image_refs::{ContainerImage, ImageRefRegistration};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerStatus, CreateRequest, CreateStateRequest, ErrorCode, StateRecord, StateStore,
    TraitError,
};

/// bundle 直下の設定ファイル名（OCI Runtime Spec）。
const CONFIG_FILE_NAME: &str = "config.json";

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const CREATE_OP_NAME: &str = "create";

/// 参照登録・登録の巻き戻しの操作名（REPAIR-4）。
const IMAGE_REF_REGISTER_OP_NAME: &str = "image_ref_register";
const IMAGE_REF_ROLLBACK_OP_NAME: &str = "image_ref_rollback";
const IMAGE_REF_BIND_OP_NAME: &str = "image_ref_bind";

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
    // 変換は最上位 1 か所のみ。内部関数は `TraitError` のまま（波及最小）。
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
    let name = OpName::new(CREATE_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || create_inner(store, req).map_err(to_err))
}

fn create_inner(store: &dyn StateStore, req: &CreateRequest) -> Result<StateRecord, TraitError> {
    validate_bundle(req.bundle())?;
    create_state(store, req)
}

fn create_state(store: &dyn StateStore, req: &CreateRequest) -> Result<StateRecord, TraitError> {
    let status = ContainerStatus::created(req.id().clone(), None);
    let state_req = CreateStateRequest::new(status, req.bundle().to_path_buf())?;
    store.create(&state_req)
}

/// [`create`] に、OCI-7 のイメージ参照の登録を前置したもの（TASK-183.8.1・OCI-7）。
///
/// 処理順は「参照登録 → rootfs の使用（bundle の検証。将来のレイヤー展開もここ）→ `StateStore` の状態作成」。
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
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
    let name = OpName::new(CREATE_OP_NAME).map_err(to_err)?;
    recorder.record_op(&name, || {
        create_with_image_inner(store, recorder, image, req).map_err(to_err)
    })
}

fn create_with_image_inner(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    image: ContainerImage<'_>,
    req: &CreateRequest,
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
    // OCI-7: 参照登録の後・状態作成の前。将来のレイヤー展開（未実装）はこの検証の前後に入る。
    if let Err(e) = validate_bundle(req.bundle()) {
        rollback_image_ref(recorder, image, req);
        return Err(e);
    }
    match create_state(store, req) {
        Ok(record) => {
            // 参照を作成した状態に結び付ける。delete は結び付いた参照だけを外すので、状態作成前に止まった
            // create の参照を、既存の別の状態の delete が巻き込んで外す競合を防げる。失敗しても状態は
            // 作成済みなので成功を返す（参照は未結合のまま残り、delete は外さない。余分に持つだけの安全側。
            // 起動時の照合〔#854〕が回収する）。記録は `image_ref_bind`。
            if let Ok(name) = OpName::new(IMAGE_REF_BIND_OP_NAME) {
                let _ =
                    recorder.record_op(&name, || image.refs().bind(req.id(), record.revision()));
            }
            Ok(record)
        }
        Err(e) => {
            // 状態が書かれていないと断定できる失敗だけ参照を外す。
            if matches!(
                e.code(),
                ErrorCode::AlreadyExists | ErrorCode::InvalidArgument
            ) {
                rollback_image_ref(recorder, image, req);
            }
            Err(e)
        }
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
    let config = load_config(&bundle.join(CONFIG_FILE_NAME)).map_err(config_error)?;
    reject_unapplied(&config)?;
    if config.process().is_none() {
        return Err(invalid("config.json: process is required"));
    }
    let rootfs = check_rootfs(bundle, config.root().path())?;
    Ok((config, rootfs))
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
fn is_link_like(meta: &std::fs::Metadata) -> bool {
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

fn inspect(path: &Path) -> Result<std::fs::Metadata, TraitError> {
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
            let record =
                StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
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
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// テストごとに一意な bundle ディレクトリ（終了時に削除）。
    struct Bundle {
        dir: PathBuf,
    }

    impl Bundle {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-oci-create-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create bundle dir");
            Self { dir }
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

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
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

    fn ready_bundle(name: &str) -> Bundle {
        let b = Bundle::new(name);
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        b
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
    }

    impl StateStore for LoggingStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            push(&self.log, "store.create");
            if let Some(code) = self.create_error {
                return Err(TraitError::new(code, "injected"));
            }
            self.inner.create(req)
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
        fn bind(&self, _id: &ContainerId, _revision: StateRevision) -> Result<(), TraitError> {
            push(&self.log, "refs.bind");
            Ok(())
        }
        fn registration(
            &self,
            _id: &ContainerId,
            _revision: StateRevision,
        ) -> Result<Option<crate::oci_runtime::ImageRefGeneration>, TraitError> {
            Ok(None)
        }
        fn release_if(
            &self,
            _id: &ContainerId,
            _expected: crate::oci_runtime::ImageRefGeneration,
        ) -> Result<ImageRefRelease, TraitError> {
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
}
