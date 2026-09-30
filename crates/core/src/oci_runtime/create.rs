//! OCI Runtime の `create`（コンテナ状態の初期化。TASK-29.2・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! bundle の `config.json` を検証し、プロセスを一切起動しないまま [`StateStore`] へ
//! 「created・pid なし」の状態を 1 件作る。将来の plugin 側 `ContainerRuntime::create` 実装・CLI・
//! TASK-29.3（start）が呼び出し元になる。`ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、
//! 本関数はトレイト実装ではなく `StateStore` を依存注入で受け取る自由関数とした。ファイルベースの
//! `StateStore` 既定実装は TASK-31（OCI-5）の担当でまだ存在しない。
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
//! - プロセス起動（TASK-29.3 start）・namespace 分離・mount 適用
//! - mounts の rootfs 内 symlink 解決（mount を適用する側の担当）
//! - OCI-7 の参照テーブル登録（TASK-183 が TASK-29 完了後に組み込む）
//! - ファイルベースの状態保存（TASK-31・OCI-5）
//! - create 後に bundle の `config.json` が書き換えられる TOCTOU は、start（TASK-29.3）が
//!   [`validate_bundle`] で再検証して対処する（ダイジェスト保持は `StateRecord` の拡張を要するため採らない）

use std::io;
use std::path::{Component, Path, PathBuf};

use super::config::{OciConfig, OciConfigError, load_config};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerStatus, CreateRequest, CreateStateRequest, ErrorCode, StateRecord, StateStore,
    TraitError,
};

/// bundle 直下の設定ファイル名（OCI Runtime Spec）。
const CONFIG_FILE_NAME: &str = "config.json";

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const CREATE_OP_NAME: &str = "create";

/// `config.json` を検証し、プロセス未起動の「created」状態を `store` に作る。
///
/// 戻り値の [`StateRecord`] は state が `Created`・pid なしで、revision は後続の start が
/// `UpdateStateRequest` に使う。同じ ID が既にある場合は [`StateStore::create`] の
/// [`ErrorCode::AlreadyExists`] をそのまま返す。
///
/// 成功・失敗の件数と所要時間は `recorder` へ操作名 `create` で記録する（全終了経路。REPAIR-4）。
pub fn create(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &CreateRequest,
) -> Result<StateRecord, TraitError> {
    let name = OpName::new(CREATE_OP_NAME)?;
    recorder.record_op(&name, || create_inner(store, req))
}

fn create_inner(store: &dyn StateStore, req: &CreateRequest) -> Result<StateRecord, TraitError> {
    validate_bundle(req.bundle())?;

    let status = ContainerStatus::created(req.id().clone(), None);
    let state_req = CreateStateRequest::new(status, req.bundle().to_path_buf())?;
    store.create(&state_req)
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

/// `root.path` が bundle 外へ字句的に出ず、bundle 配下の全要素が symlink でない
/// 存在するディレクトリであることを確認する。
fn check_rootfs(bundle: &Path, root_path: &Path) -> Result<PathBuf, TraitError> {
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid("root.path must not contain '..'"));
    }
    let rootfs: PathBuf = bundle.join(root_path);
    // bundle 配下の相対部分を要素ごとに検査する。bundle 自体（親が symlink でもよい）は対象外。
    // bundle 外の絶対パスは相対部分が取れないため、末尾要素のみ検査する。
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
        Err(_) => None,
    };
    if checked.is_none() {
        // bundle 自身、または bundle 外の絶対パス。
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

    /// OCI-4: `root.path` が絶対パスでも成功する。
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
}
