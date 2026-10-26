//! `create` / `start` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.1・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_create`] / [`run_start`] を呼ぶ。`create` の実処理は core の
//! `oci_runtime::create`（OCI-4・TASK-29）へ委ね、入力の意味検証（ID の文字種・bundle の絶対パス）も
//! core の型と関数を唯一の判定とする。`start` は core を呼ばず、supervisor の bin を起動して結果の 1 行を
//! 期限付きで受け取る（`supervisor_start` module。#1718・#1314 の配置 1-A）。CLI は `start` で状態を書かない。
//! `--bundle` 自体やその祖先が symlink でも create は受理し、渡されたパスのまま状態へ保存する
//! （canonicalize しない）。bundle までの経路の symlink は supervisor 側の start が起動前に検査して拒否する（SEC-1）。
//! 依存（状態ストア・計測器）は [`Runtime`] で注入できるようにし、単体テストではフェイクを差せる。
//!
//! `create` は config の `mounts[].destination` の拒否を、状態ルートの `@audit.log` へ mount 層で記録する
//! （core の `create_audited` / `create_with_image_audited`。SEC-4・OCI-4・#2480。Linux のみ。非 Linux は
//! `open_store` が先に失敗するため到達しない）。
//!
//! `create` は core を呼ぶ前に、同じ ID の前のインスタンスが残したコンテナログを best effort で回収する
//! （`reclaim_stale_container_log`。`delete` の待ちを超えて残った分。#2698・SUP-7・CLI-1）。本体は plugin-cri の
//! `CreateContainer` と共有する supervisor の `logs::reclaim_stale_container_logs`（#2760）。ID を再利用しない
//! CRI 側の残りは plugin-cri の起動時の走査で回収し、それでも残るものは手動で消す（`docs/setup/container-log-recovery.md`）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - `--image-root <abs> --image <sha256:digest|name[:tag]>` つきの `create` は core の `create_with_image` を呼び、イメージ参照（OCI-7）を
//!   `image_refs::StoreImageRefs` で登録・確定する（#2315）。レイヤーの展開はしない（本番の展開器は #2377。bundle の rootfs は展開済みの前提）。
//!   manifest の在庫は永続化済み（#2380）だが、本番で在庫を埋める経路（pull → `ImageStore` の配線）が未実装のため、`register` は
//!   常に `NOT_FOUND` になり、本番ではイメージつき create はその配線まで成功しない。
//!   `--image` の判別規則（digest かタグ参照か）と解決・付け替えの扱いは `image_refs` module の doc（#2496）。
//!   core 呼び出しの前に同じ参照キーの残骸（状態の無い参照）を回収し（契機 A）、呼び出し全体を create ゲートの共有で包む
//!   （`ref_reconcile`・`docs/design/container-ref-reconcile.md`。#2495）。
//! - 本番入口の `start` は、状態ストアで ID の存在を確かめた後、CLI の実体と同じディレクトリの
//!   `fandhe-container-supervisor` を起動して結果を受け取る（`supervisor_start` module の doc に契約・期限・
//!   未実装範囲を書く）。supervisor が core の本番 launcher（#1715・#1819）で起動し、Running の記録は supervisor が行う
//!   （rootless のみ。実機での通し確認は未実施で #2062）。CLI は状態を書かないので、失敗しても `state.json` は変わらない
//!   （プロセスのいない Running を CLI は残さない。#1541）。実体の隣に特権ランチャーがあれば rootful のインストールとしてランチャー経由で起動する（#2442。uid 0 の起動は `UNIMPLEMENTED`）。
//! - 計測（REPAIR-4）のファイル出力は core の `open_flags` が対応するアーキテクチャの Linux のみ（`op_log_file`。対応外は出力しない）。本バイナリを
//!   setuid / setgid・file capability つきで導入しない前提で、権限分離（TASK-171・SUP-14）で見直す。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4。`plugin_backend` module）。非 Linux では
//!   `production_runtime` が状態ストアの代わりに plugin の発見・信頼性検証を試み、現状は必ず fail-closed で
//!   失敗する（起動と RPC は #1869 の設計〔docs/design/plugin-backend-wiring.md。承認待ち・実装 issue は未起票〕・TASK-125）。

use std::time::Instant;

use fandhe_container_core::audit_log::{AuditCoveragePolicy, AuditSink, FileAuditSink};
use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    ContainerImage, ImageManifestDigest, LifecycleOp, OciRuntimeError, create_audited,
    create_with_image_audited,
};
use fandhe_container_core::state_store::FileStateStore;
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, StartRequest, StateRecord, StateStore, TraitError,
};

use super::CliExit;
use super::args::{CreateArgs, GlobalArgs, StartArgs};
use super::create_options;
use super::image::{Stage, open_image_store_for_lifecycle, trait_failure};
use super::image_refs::{
    StoreImageRefs, attach_image_root, classify_create_image, legacy_scope, resolve_create_image,
    state_scope,
};
use super::ref_reconcile::reclaim_stale_ref_recorded;
use super::stop_delete::{
    WARNING_WRITE_TIMEOUT, emit_warning_bounded, options_removal_warning, write_warning_to_stderr,
};
use fandhe_container_oci::image_management::{ContainerCreatePass, ImageStore};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store as options_store;

/// core の操作へ注入する依存の束（`start` は core を呼ばないため、状態ストアの存在確認と計測にだけ使う）。
pub(super) struct Runtime {
    pub(super) store: Box<dyn StateStore>,
    pub(super) recorder: OpRecorder,
    /// create の `mounts[].destination` 拒否の記録先（本番は状態ルートの `@audit.log`。SEC-4・OCI-4・#2480）。
    /// start / stop / delete は使わない。
    pub(super) audit: Box<dyn AuditSink>,
}

/// 構築済みの要求で core の `create` を呼ぶ。
pub(super) fn create_container(
    rt: &Runtime,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    create_audited(rt.store.as_ref(), &rt.recorder, req, rt.audit.as_ref())
}

/// イメージつき create の入力（検証済みの manifest digest と、開いたイメージストア）。
pub(super) struct CreateImage {
    pub(super) store: ImageStore,
    pub(super) manifest: ImageManifestDigest,
    /// 参照キーの接頭辞（状態ルートごと。`image_refs::state_scope`。別の状態ルートの同名 ID と混ざらないようにする）。
    pub(super) scope: String,
    /// 旧版の scope（`--root` の字面から決めたもの。新 scope と同じなら `None`）。残骸の回収だけに使う（#2499・OCI-7）。
    pub(super) legacy_scope: Option<String>,
}

/// 状態ストアを開く前の段階のイメージつき create の入力（`scope` が未確定）。
///
/// 参照キーの接頭辞 `scope` は「開いた状態ストアの `host_state_root()`」から求める（`--root` の表記ゆれ・祖先の
/// symlink を畳んだ正規パスにするため。#2499 P2-2）。ストアを開く前の `build_create` はこの型を返し、
/// `run_create` がストアを開いた後に [`PendingImage::bind`] で [`CreateImage`] にする。
pub(super) struct PendingImage {
    pub(super) store: ImageStore,
    pub(super) manifest: ImageManifestDigest,
    /// グローバル引数の `--root`（旧 scope の算出用）。
    pub(super) root_override: Option<std::path::PathBuf>,
}

impl PendingImage {
    /// 開いた状態ストアから scope を求めて [`CreateImage`] にする。ストアが状態ルートを示せなければ失敗する。
    pub(super) fn bind(self, state: &dyn StateStore) -> Result<CreateImage, TraitError> {
        let scope = state_scope(state)?;
        Ok(CreateImage {
            legacy_scope: legacy_scope(self.root_override, &scope),
            scope,
            store: self.store,
            manifest: self.manifest,
        })
    }
}

/// 構築済みの要求で core の `create_with_image` を呼ぶ（OCI-7・#2315）。
///
/// 参照の登録・確定・失敗時の巻き戻しは core が行う。展開器は付けない（本番の展開器は #2377 で、
/// bundle の rootfs は展開済みの前提）。`_pass`（create ゲートの共有）を要求し、未確定参照の回収側が
/// 進行中の create を見分けられない呼び出しを型で防ぐ（#2495）。
pub(super) fn create_container_with_image(
    rt: &Runtime,
    image: &CreateImage,
    req: &CreateRequest,
    _pass: &ContainerCreatePass<'_>,
) -> Result<StateRecord, OciRuntimeError> {
    let refs = StoreImageRefs::new(&image.store, &image.scope);
    create_with_image_audited(
        rt.store.as_ref(),
        &rt.recorder,
        ContainerImage::new(&refs, &image.manifest),
        req,
        rt.audit.as_ref(),
    )
}

/// イメージつき create の本番の流れ（契機 A。`ref_reconcile` の doc・#2495）。
///
/// 1. 同じ参照キーの残骸（状態の無い参照）を回収する（失敗・保留でも続行。判定は core の `register` に任せる）
/// 2. create ゲートの共有を取る（取れなければ状態を作る前に失敗。fail-closed）
/// 3. 共有を保持したまま core の `create_with_image` を呼ぶ
pub(super) fn create_container_with_image_reclaiming(
    rt: &Runtime,
    image: &CreateImage,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    // create 時のイメージストア root を状態記録へ残す。`--image-root` を省いた delete が、この記録から参照を解除する
    // （#2499・OCI-7・CLI-1）。状態を作る前に付けるので、状態の作成と同時に原子的に永続化される。
    let started = Instant::now();
    let req = &match attach_image_root(req, &image.store) {
        Ok(r) => r,
        Err(e) => {
            record_pre_core_failure(&rt.recorder, "create", started);
            return Err(OciRuntimeError::from_trait_error(LifecycleOp::Create, e));
        }
    };
    reclaim_stale_ref_recorded(
        &image.store,
        rt.store.as_ref(),
        &rt.recorder,
        &image.scope,
        req.id(),
    );
    // 旧版の scope（`--root` の字面から決めたもの）で残った同じ ID の残骸も回収する（#2499・OCI-7）。
    if let Some(legacy) = &image.legacy_scope {
        reclaim_stale_ref_recorded(
            &image.store,
            rt.store.as_ref(),
            &rt.recorder,
            legacy,
            req.id(),
        );
    }
    let gate_started = Instant::now();
    let pass = image.store.enter_container_create().map_err(|e| {
        // ゲート取得の失敗は core に到達せず core 側の計測に載らないため、ここで create の失敗として記録する（REPAIR-4）。
        record_pre_core_failure(&rt.recorder, "create", gate_started);
        OciRuntimeError::from_trait_error(LifecycleOp::Create, trait_failure(&e, Stage::Refs))
    })?;
    create_container_with_image(rt, image, req, &pass)
}

/// create の要求と、`--image-root` / `--image` があればその検証済みの入力を作る。
///
/// digest の形式は core の `ImageManifestDigest::new` を唯一の判定とし、ストア root は oci の
/// `ImageStore::open` に検証させる。いずれの失敗も core に入る前（状態ルートを作る前）に固定文言で返す。
fn build_create(
    global: &GlobalArgs,
    args: &CreateArgs,
) -> Result<(CreateRequest, Option<PendingImage>), TraitError> {
    let req = build_create_request(args)?;
    let image = match &args.image {
        None => None,
        Some(i) => {
            // 構文の判別はストアを開く前に行う（不正な入力は存在しない root でも INVALID_ARGUMENT。OCI-7・CLI-1）。
            let classified = classify_create_image(&i.reference)?;
            // 非 Linux はローカルストアを開かず、バックエンド（plugin）解決の拒否へそのまま渡す（OCI-7・CLI-1）。
            require_local_backend(global)?;
            let store = open_image_store_for_lifecycle(&i.image_root)?;
            let manifest = resolve_create_image(&store, classified)?;
            Some(PendingImage {
                store,
                manifest,
                root_override: global.root.clone(),
            })
        }
    };
    Ok((req, image))
}

/// ID の文字種と bundle の絶対パスを core の型で検証する（相対パスの解決・canonicalize はしない。SEC-1）。
fn build_create_request(args: &CreateArgs) -> Result<CreateRequest, TraitError> {
    let id = ContainerId::new(args.id.as_str())?;
    // `--label` は検証して状態記録の annotations へ直接書く(supervisor を通らない。#2713)。
    let annotations = create_options::labels_of(&args.options)?;
    Ok(CreateRequest::new(id, args.bundle.clone())?.with_annotations(annotations))
}

fn build_start_request(args: &StartArgs) -> Result<StartRequest, TraitError> {
    Ok(StartRequest::new(ContainerId::new(args.id.as_str())?))
}

/// `start --audit-policy` の値を core の固定語彙で検証する(未指定は `None` で、supervisor の既定が効く。SEC-4・#2761)。
/// 不正な値は `INVALID_ARGUMENT`(入力値は文言に入らない)。
fn build_audit_policy(args: &StartArgs) -> Result<Option<AuditCoveragePolicy>, TraitError> {
    args.audit_policy
        .as_deref()
        .map(str::parse::<AuditCoveragePolicy>)
        .transpose()
}

/// 要求を構築し、状態ルートを解決して本番の依存を組む。要求構築が先なので、不正な入力では状態ルートを作らない。
/// いずれかの失敗は core に到達していないため、ここで `op_name` の失敗として記録する（REPAIR-4）。
/// stop / delete（`stop_delete` module）からも呼ばれる。
pub(super) fn production_runtime<R>(
    global: &GlobalArgs,
    recorder: OpRecorder,
    op_name: &str,
    started: Instant,
    build: impl FnOnce() -> Result<R, TraitError>,
) -> Result<(Runtime, R), TraitError> {
    let prepared = build().and_then(|req| Ok((req, open_store(global)?)));
    match prepared {
        Ok((req, store)) => Ok((
            Runtime {
                // 同じ状態ルートの `@audit.log` へ記録する（open 済みの store から作り、二度は開かない）。
                audit: Box::new(FileAuditSink::in_state_store(&store)),
                store: Box::new(store),
                recorder,
            },
            req,
        )),
        Err(e) => {
            record_pre_core_failure(&recorder, op_name, started);
            export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
            Err(e)
        }
    }
}

/// ローカルの画像ストアを開く前の関門。Linux は何もせず、非 Linux は plugin 発見機構の拒否（`open_store` と同じ）を返す。
/// `--image-root` が無いホストでも NOT_FOUND でなく plugin 解決の拒否に到達させるため（OCI-7・CLI-1）。
#[cfg(target_os = "linux")]
pub(super) fn require_local_backend(_global: &GlobalArgs) -> Result<(), TraitError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn require_local_backend(global: &GlobalArgs) -> Result<(), TraitError> {
    Err(super::plugin_backend::unavailable(global))
}

/// 状態ストアを開く。Linux は core を直接使い、非 Linux は plugin 発見機構経由（TASK-79.4・PLUG-4）で
/// 解決を試みて、現状は必ず失敗する（`plugin_backend` の未実装範囲を参照。REPAIR-3）。
/// これは OS 別のバックエンド振り分けであり OS 固有設定（CLI-2）ではない。setup module は参照しない。
///
/// 状態ルートが無ければ親の下に 0700 で作る副作用がある（core の `FileStateStore::open`）。これは
/// create / start / stop / delete / list / logs の 6 コマンドで共通で、親は作らない（#1607 E2。理由は
/// `list_logs` の module doc）。`list_logs` の破損診断（`find_corrupted`）からも同じ解決で再度呼ばれる。
#[cfg(target_os = "linux")]
pub(super) fn open_store(global: &GlobalArgs) -> Result<FileStateStore, TraitError> {
    use fandhe_container_core::state_store::StateRoot;
    let root = StateRoot::resolve(global.root.clone())?;
    FileStateStore::open(root)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_store(global: &GlobalArgs) -> Result<FileStateStore, TraitError> {
    Err(super::plugin_backend::unavailable(global))
}

/// core に到達する前の失敗を操作名 `op_name` の失敗として記録する（REPAIR-4）。
/// core に到達した操作は core 自身が記録するため、ここで二重には記録しない。
pub(super) fn record_pre_core_failure(recorder: &OpRecorder, op_name: &str, started: Instant) {
    if let Ok(name) = OpName::new(op_name) {
        let _ = recorder.record(&name, OpOutcome::Failure, started.elapsed());
    }
}

/// 計測（`OpRecorder`）の JSON Lines 出力先を指す環境変数（REPAIR-4）。
///
/// OCI の stdout 契約（create / start は成功時に何も出さない）と stderr の 1 行エラー JSON を保つため、
/// 計測は stdout / stderr へ混ぜず、この環境変数が指すファイルへ追記する。未設定なら出力しない。
pub(super) const OP_LOG_ENV: &str = "FANDHE_CONTAINER_OP_LOG";

/// 計測ログの出力先を安全に開く Linux 実装（SEC-1・REPAIR-5）。
///
/// [`export_ops`] から [`open_op_log`] だけが呼ばれる。open フラグの値はアーキテクチャごとに異なるため、
/// 値は core の `open_flags::NofollowOpenFlags` から得る（SSOT は core の `sys`）。対応外アーキテクチャでは
/// `NofollowOpenFlags::current()` が `None` を返し、`open_op_log` は何も開かず `None` を返す。非 Linux は
/// 外側の `open_op_log` が常に `None` を返す（いずれも計測を出力しない fail-closed）。
///
/// 前提（SEC-1）: 本バイナリを setuid / setgid・file capability つきで導入しない。出力先は環境変数で
/// 指定でき、検査は「実効 UID から見て差し替えられない経路か」だけを見るため、呼び出し元より高い権限で
/// 動くと、呼び出し元が本来書けないファイルへ追記させられる。この前提が破られた実行のうち、実 / 実効の
/// UID・GID の食い違いとして観測できるものは [`unelevated_euid`] で検出して出力を拒否する
/// （file capability だけが付いた実行は UID・GID に現れないため検出できない）。
/// 権限分離の方式（TASK-171・SUP-14）が決まったら、この判定と出力先の扱いを見直す。
///
/// open フラグは core が SSOT（#1540）。fd 相対の open 処理は意味（既存ファイルの権限の扱い等）が
/// core の監査ログと異なるため、引き続き cli 側に持つ。
#[cfg(target_os = "linux")]
mod op_log_file {
    use fandhe_container_core::open_flags::NofollowOpenFlags;

    /// 新規作成する計測ログの mode（所有者のみ読み書き。umask に任せて group / other へ開かない）。
    const OP_LOG_CREATE_MODE: u32 = 0o600;

    /// `/proc/self/status` を読む上限バイト数（無制限確保の防止。実際は 2 KiB 前後）。
    const PROC_STATUS_MAX_BYTES: u64 = 64 * 1024;

    /// `/proc/<pid>/status` の本文から `key`（`Uid:` / `Gid:`）の 4 値（real・effective・saved・fs）を取り出す。
    /// 行が無い・複数ある・値が 4 個でない・10 進の `u32` でない場合は `None`。
    fn status_ids(status: &str, key: &str) -> Option<[u32; 4]> {
        let mut found = None;
        for line in status.lines() {
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            let mut fields = rest.split_ascii_whitespace();
            let mut ids = [0u32; 4];
            for slot in &mut ids {
                let field = fields.next()?;
                if !field.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                *slot = field.parse().ok()?;
            }
            if fields.next().is_some() {
                return None;
            }
            found = Some(ids);
        }
        found
    }

    /// `/proc/<pid>/status` の本文から、権限が持ち上がっていない実行の実効 UID を返す（SEC-1）。
    ///
    /// UID・GID それぞれの real・effective・saved・fs の 4 値がすべて一致するときだけ `Some(実効 UID)`。
    /// 食い違い（setuid / setgid で起動された・途中で切り替えた）や、形式を解釈できない場合は `None` で、
    /// 呼び出し側は計測を出力しない（fail-closed）。ファイル操作の権限は fs 値で決まるため、real と
    /// effective だけでなく 4 値すべての一致を求める。
    pub(super) fn unelevated_euid_from_status(status: &str) -> Option<u32> {
        let [ruid, euid, suid, fsuid] = status_ids(status, "Uid:")?;
        let [rgid, egid, sgid, fsgid] = status_ids(status, "Gid:")?;
        let same_uid = ruid == euid && euid == suid && suid == fsuid;
        let same_gid = rgid == egid && egid == sgid && sgid == fsgid;
        (same_uid && same_gid).then_some(euid)
    }

    /// 呼び出しプロセスの実効 UID を `/proc/self/status` から得る（unsafe・libc なし）。
    /// 読めない・上限超過・[`unelevated_euid_from_status`] が拒否した場合は `None`（計測を出力しない）。
    pub(super) fn unelevated_euid() -> Option<u32> {
        use std::io::Read;
        let f = std::fs::File::open("/proc/self/status").ok()?;
        let mut text = String::new();
        f.take(PROC_STATUS_MAX_BYTES + 1)
            .read_to_string(&mut text)
            .ok()?;
        if text.len() as u64 > PROC_STATUS_MAX_BYTES {
            return None;
        }
        unelevated_euid_from_status(&text)
    }

    /// 開いた fd に対する要素 `name` の `/proc/self/fd/<fd>/<name>` 経路を作る。
    /// この経路は親 fd が指すディレクトリ直下の 1 要素だけを解決するため、パス文字列の再解決で
    /// 親が差し替えられる競合（TOCTOU）が起きない。`openat` 相当を unsafe なしで実現する（SEC-1）。
    fn child_via_fd(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::path::PathBuf {
        use std::os::fd::AsRawFd;
        std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name)
    }

    /// 開いた fd のディレクトリが、他ユーザーに差し替えられない状態かを fd から検査する（SEC-1）。
    /// ディレクトリであり、所有者が root か自分で、group / other 書き込み可なら sticky bit を要する。
    fn dir_trusted(dir: &std::fs::File, euid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(m) = dir.metadata() else {
            return false;
        };
        let mode = m.mode();
        let writable_by_others = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        let owner_ok = m.uid() == 0 || m.uid() == euid;
        m.is_dir() && owner_ok && (!writable_by_others || sticky)
    }

    /// `dir` 直下の要素 `name` を O_NOFOLLOW でディレクトリとして開く（親 fd 経由。SEC-1）。
    fn open_dir_at(
        dir: &std::fs::File,
        name: &std::ffi::OsStr,
        flags: NofollowOpenFlags,
    ) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags.directory_nofollow_nonblock())
            .open(child_via_fd(dir, name))
    }

    /// symlink を辿る回数の上限（ループ・過大な展開の防止）。
    const MAX_SYMLINK_HOPS: u32 = 8;

    /// 解決待ちの経路要素。`..` は物理的な親（開いた fd のスタックの 1 つ手前）へ戻る。
    enum Step {
        Name(std::ffi::OsString),
        Parent,
    }

    /// 親ディレクトリを、ルートから 1 要素ずつディレクトリ fd で固定しながら開く（SEC-1）。
    ///
    /// 各要素は直前に開いた fd 経由で O_NOFOLLOW | O_DIRECTORY で開き、開いた fd ごとに所有者・権限を
    /// 検査する。パス全体を再解決しないため、検査と open の間に親を symlink へ差し替えられない。
    /// root 所有の symlink（システム標準の `/var/run` -> `../run` 等）のみ、その場で内容を読んで同じ
    /// 手順で辿る（root 所有のため一般ユーザーは差し替えられない）。`..` は検査済みディレクトリ fd の
    /// スタックを 1 つ戻して解決し、ルートより上へ出る経路は拒否する。
    pub(super) fn open_trusted_parent(
        parent: &std::path::Path,
        euid: u32,
        flags: NofollowOpenFlags,
    ) -> Option<std::fs::File> {
        use std::collections::VecDeque;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::Component;

        /// `path` の各要素を `queue` の先頭へ順序を保って積み、絶対パスだったかを返す。
        fn push_components(queue: &mut VecDeque<Step>, path: &std::path::Path) -> Option<bool> {
            let mut absolute = false;
            let mut steps = Vec::new();
            for c in path.components() {
                match c {
                    Component::RootDir => absolute = true,
                    Component::Normal(n) => steps.push(Step::Name(n.to_os_string())),
                    Component::ParentDir => steps.push(Step::Parent),
                    Component::CurDir => {}
                    Component::Prefix(_) => return None,
                }
            }
            for st in steps.into_iter().rev() {
                queue.push_front(st);
            }
            Some(absolute)
        }

        let abs = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(parent)
        };
        let open_root = || -> Option<std::fs::File> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(flags.directory_nofollow_nonblock())
                .open("/")
                .ok()?;
            dir_trusted(&f, euid).then_some(f)
        };
        let mut queue = VecDeque::new();
        push_components(&mut queue, &abs)?;
        // 検査済みディレクトリ fd のスタック（先頭がルート、末尾が現在位置）。
        let mut stack = vec![open_root()?];
        let mut hops = 0;
        while let Some(step) = queue.pop_front() {
            let name = match step {
                Step::Parent => {
                    // ルートより上へは出ない（escape-above-root は拒否）。
                    if stack.len() <= 1 {
                        return None;
                    }
                    stack.pop();
                    continue;
                }
                Step::Name(n) => n,
            };
            let cur = stack.last()?;
            match open_dir_at(cur, &name, flags) {
                Ok(next) => {
                    if !dir_trusted(&next, euid) {
                        return None;
                    }
                    stack.push(next);
                }
                Err(_) => {
                    // symlink だった場合のみ、root 所有に限って辿る。それ以外は拒否する。
                    let link = child_via_fd(cur, &name);
                    let m = std::fs::symlink_metadata(&link).ok()?;
                    if !m.file_type().is_symlink() || m.uid() != 0 {
                        return None;
                    }
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return None;
                    }
                    let target = std::fs::read_link(&link).ok()?;
                    if push_components(&mut queue, &target)? {
                        stack.truncate(1);
                    }
                }
            }
        }
        stack.pop()
    }

    /// 計測出力先を副作用なく固定して検証してから書き込み用に開く。通常ファイル以外は拒否する。
    ///
    /// 親ディレクトリをルートから fd で固定しながら開き（[`open_trusted_parent`]）、
    /// その親 fd 経由で最終要素を O_PATH | O_NOFOLLOW で固定する。O_PATH はデバイス・FIFO を開いても
    /// 副作用（`/dev/watchdog` の起動等）を起こさない。固定した fd で種別・ハードリンク数（1 のみ許可）・
    /// 所有者を検証した後に限り、`/proc/self/fd` 経由で同じ inode を追記用に開き直し、再度検証する。
    /// 未存在のときは O_EXCL（create_new）・mode 0600 で排他的に作成し、既存対象の検査を迂回させない
    /// （SEC-1・REPAIR-5）。実 / 実効の UID・GID が食い違う実行（[`unelevated_euid`]）では開かない。
    /// 排他作成が並行プロセスに負けた（AlreadyExists）ときは、既存対象として検証からやり直す
    /// （[`OP_LOG_OPEN_ATTEMPTS`] 回まで）。
    pub(super) fn open_op_log(path: &std::ffi::OsStr) -> Option<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let path = std::path::Path::new(path);
        let name = path.file_name()?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        let flags = NofollowOpenFlags::current()?;
        let euid = unelevated_euid()?;
        let dir = open_trusted_parent(parent, euid, flags)?;
        let target = child_via_fd(&dir, name);
        let verify = |f: &std::fs::File| -> bool {
            f.metadata()
                .map(|m| m.is_file() && m.nlink() == 1 && m.uid() == euid)
                .unwrap_or(false)
        };
        // 未存在 → 排他作成の間に別プロセスが同じファイルを作ると create_new は AlreadyExists で失敗する。
        // その場合に限り、既存対象として検証からやり直す（並行起動した CLI の計測を落とさない。REPAIR-4）。
        // やり直しは有限回で、ファイルの作成・削除を繰り返されても無期限には回らない（REPAIR-5）。
        for _ in 0..OP_LOG_OPEN_ATTEMPTS {
            let pinned = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(flags.path_nofollow())
                .open(&target)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // 未存在: 排他的に作成する（既存・競合で現れた対象には O_EXCL で失敗する）。
                    match std::fs::OpenOptions::new()
                        .append(true)
                        .create_new(true)
                        .mode(OP_LOG_CREATE_MODE)
                        .custom_flags(flags.file_nofollow_nonblock())
                        .open(&target)
                    {
                        Ok(f) => return verify(&f).then_some(f),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(_) => return None,
                    }
                }
                Err(_) => return None,
            };
            if !verify(&pinned) {
                return None;
            }
            let f = std::fs::OpenOptions::new()
                .append(true)
                .custom_flags(flags.nonblock())
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
                .ok()?;
            return verify(&f).then_some(f);
        }
        None
    }

    /// [`open_op_log`] が「固定 → 検証 → 開く」を試す回数の上限。2 回目以降は、未存在からの排他作成が
    /// 並行プロセスに負けたときだけ使う（REPAIR-5: 無期限に回らない）。
    const OP_LOG_OPEN_ATTEMPTS: u32 = 4;
}

/// 対応外の環境（macOS・Windows）は計測のファイル出力を拒否する
/// （fail-closed。SEC-1・REPAIR-4）。macOS・Windows は実効 UID の取得と symlink / junction / reparse point の
/// 安全な検査が未実装のため。x86_64 / aarch64 以外の Linux は core の `NofollowOpenFlags::current()` が
/// `None` を返すことで `op_log_file` 内部で拒否される。
/// 将来は各 OS の安全な open 実装を `sys` モジュールに追加して対応する。
#[cfg(not(target_os = "linux"))]
fn open_op_log(_path: &std::ffi::OsStr) -> Option<std::fs::File> {
    None
}

#[cfg(target_os = "linux")]
use op_log_file::open_op_log;

/// 1 回の計測出力（全 `op_stats` 行 + メタ行）の上限バイト数（REPAIR-4・REPAIR-5）。
///
/// 出力は型で有界である。行数は core の `MAX_TRACKED_OPS`（64）+ メタ 1 行まで、1 行は固定キー・
/// `OP_NAME_MAX_LEN`（64）バイト以下の操作名・整数値だけで 512 バイトに収まる。したがって通常は
/// 33 KiB 未満で、この上限は core 側の形式が変わったときに巨大な 1 回書き込みをしないための歯止め。
/// 超過した出力は書かずに捨てる（計測は best effort。操作の結果は変えない）。
const OP_LOG_MAX_BYTES: usize = 64 * 1024;

/// 割り込み（EINTR）で 1 バイトも書けなかった write をやり直す回数の上限（REPAIR-5）。
const OP_LOG_WRITE_ATTEMPTS: u32 = 4;

/// 計測スナップショット全体を 1 つのバッファへ組み立て、`w` へ **1 回の `write`** で書く（REPAIR-4）。
///
/// 複数の CLI プロセスが同じ計測ログへ並行に追記しても JSON 行が混ざらないようにするための入口。
/// core の `OpRecorder::export_json_lines` は行本体と改行を別々の `write_all` で書くため、ファイルへ
/// 直接渡すと「A の本体 → B の本体 → 改行」の順で 1 行に 2 つの JSON が並びうる。ここではメモリ上の
/// バッファへ書かせ、全行（LF 終端）を 1 回の write(2) にまとめる。`O_APPEND` で開いた通常ファイルへの
/// 1 回の write(2) は、追記位置の決定と書き込みを inode ロックの下で一括して行うため、他プロセスの
/// 追記と行の途中で混ざらない（行単位ではなく 1 回の出力全体が連続する）。プロセス間ロックは使わない
/// ため、ロック保持者を待って CLI が結果を返せなくなる経路も増えない（REPAIR-5）。
///
/// `write_all` は使わない。部分書き込みを残りの write で継ぎ足すと、その間に他プロセスの行が
/// 入りうるため、書けたバイト数が全体に満たなければ継ぎ足さずに失敗を返す（容量不足・
/// `RLIMIT_FSIZE` 等。このとき末尾に不完全な行が残りうる。読み手は解析できない行を捨てること）。
/// 1 バイトも書かれない EINTR だけは [`OP_LOG_WRITE_ATTEMPTS`] 回までやり直す。
/// 戻り値は書いたバイト数。[`OP_LOG_MAX_BYTES`] を超える出力は 1 バイトも書かずに失敗を返す。
fn write_ops_once(recorder: &OpRecorder, w: &mut dyn std::io::Write) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    let mut buf: Vec<u8> = Vec::new();
    recorder
        .export_json_lines(Some(&mut buf))
        .map_err(|_| Error::other("failed to encode op stats"))?;
    if buf.len() > OP_LOG_MAX_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "op stats output exceeds the size limit",
        ));
    }
    for _ in 0..OP_LOG_WRITE_ATTEMPTS {
        match w.write(&buf) {
            Ok(n) if n == buf.len() => return Ok(n),
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "op stats output was written partially",
                ));
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Interrupted,
        "op stats output was interrupted repeatedly",
    ))
}

/// 計測を `path` の通常ファイルへ追記する（best effort。失敗しても終了コード・エラー出力は変えない）。
///
/// open は O_NONBLOCK で行い、通常ファイル以外は拒否して書き込まない（REPAIR-5: 読み手のいない
/// FIFO 等で CLI が無期限にブロックしない）。書き込みは [`write_ops_once`] による 1 回の write で、
/// 同じファイルへ並行に追記する他の CLI プロセスと JSON 行が混ざらない（REPAIR-4）。
pub(super) fn export_ops(recorder: &OpRecorder, path: Option<&std::ffi::OsStr>) {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return;
    };
    let Some(mut f) = open_op_log(path) else {
        return;
    };
    let _ = write_ops_once(recorder, &mut f);
}

/// 起動オプション文書の I/O(ロック取得・書き込み・巻き戻し)を作業スレッドで待つ上限(REPAIR-5)。
const OPTIONS_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// ID 単位のロックの取得を待つ上限(`OPTIONS_IO_TIMEOUT` より短くし、期限切れを作業スレッド側でも検知する)。
const OPTIONS_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(8);

/// 書いた起動オプション文書と、create の間保持する ID 単位のロック(#2713・SUP-12)。
struct PreparedOptions {
    lock: options_store::OptionsLock,
    root: std::path::PathBuf,
    /// 書かなかった(指定が空・既存の状態がある)ときは `None`。
    written: Option<options_store::WrittenOptions>,
}

fn options_timeout() -> TraitError {
    TraitError::new(
        fandhe_container_core::traits::ErrorCode::Timeout,
        "container options file I/O did not finish within the deadline",
    )
}

/// 起動オプション文書を書く前の整理と書き込み(#2713・SUP-12)。ロックと書いた文書の識別(巻き戻し用)を返す。
///
/// ID 単位のロック(`options_store::acquire_lock`)を取り、core の create が終わるまで保持する。同じ ID の並行 `create` /
/// `delete` が、状態の不在確認と文書の掃除・書き込みの間に割り込んで他方の文書を消すのを防ぐ。
/// ロック取得・掃除・書き込み(fsync を含む)は作業スレッドで期限つきに待つ(REPAIR-5。応答しない FUSE・ネットワーク FS
/// で create が止まらない)。期限切れの作業スレッドは CLI の終了で消え、後から文書が残っても状態が無いので次の create /
/// delete が掃除する(別の世代の文書は、掃除がロックと状態の不在確認の下で行われるため消えない)。
///
/// - 同じ ID の状態が既にある(または確認できない)なら `ALREADY_EXISTS` で拒否する(既存コンテナの文書は触らない)
/// - 状態が無いのに文書が残っている(前のコンテナの残骸)なら先に消す。指定が空でもこの掃除は行う
/// - 指定が空なら書かない(文書が無ければ supervisor は既定値で動く)
/// - 状態ルートを持たない backend(非 Linux の plugin 経路)で指定があれば `UNIMPLEMENTED`(黙って捨てない)
fn prepare_options_file(
    rt: &Runtime,
    id: &ContainerId,
    document: &ContainerOptionsDocument,
) -> Result<Option<PreparedOptions>, TraitError> {
    let Some(root) = rt.store.host_state_root() else {
        if document.is_empty() {
            return Ok(None);
        }
        return Err(TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "container options are not supported by this backend",
        ));
    };
    let root = root.to_path_buf();
    let job_root = root.clone();
    let id = id.clone();
    let document = document.clone();
    let prepared = fandhe_container_supervisor::supervisor_log::run_bounded(
        move || -> Result<_, TraitError> {
            let lock = options_store::acquire_lock(&job_root, &id, OPTIONS_LOCK_WAIT)?;
            // 同じ ID の状態が既にある(または確認できない)なら拒否する。ここで見送って core の create に任せると、
            // 確認の後に並行 delete が状態を消したとき、世代注釈つきの新しい記録に対応する文書が無い(または前の世代の
            // 文書が残る)状態で create が成功してしまう(SUP-12・SEC-1・#2713)。
            if !super::stop_delete::id_is_still_deleted(&job_root, &id) {
                return Err(TraitError::new(
                    fandhe_container_core::traits::ErrorCode::AlreadyExists,
                    "the container already exists or its state cannot be checked",
                ));
            }
            options_store::remove(&job_root, &id)?;
            if document.is_empty() {
                return Ok((lock, None));
            }
            let written = options_store::write_new(&job_root, &id, &document)?;
            Ok((lock, Some(written)))
        },
        OPTIONS_IO_TIMEOUT,
    )
    .unwrap_or_else(|| Err(options_timeout()))?;
    let (lock, written) = prepared;
    Ok(Some(PreparedOptions {
        lock,
        root,
        written,
    }))
}

/// 空でない文書に作成世代を付け、同じ値を `req` の annotations(`GENERATION_ANNOTATION`)にも足す(#2713・SEC-1)。
///
/// 文書が空、または状態ルートを持たない backend(文書を書かない経路)では何も変えない。利用者の label が予約キーを
/// 持っていても、ここで足す値が後勝ちで置き換える。
fn bind_generation(
    rt: &Runtime,
    req: &CreateRequest,
    document: &ContainerOptionsDocument,
) -> Result<(CreateRequest, ContainerOptionsDocument), TraitError> {
    if document.is_empty() || rt.store.host_state_root().is_none() {
        return Ok((req.clone(), document.clone()));
    }
    let generation = options_store::new_generation()?;
    let entries = req
        .annotations()
        .iter()
        .filter(|(k, _)| *k != options_store::GENERATION_ANNOTATION)
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .chain(std::iter::once((
            options_store::GENERATION_ANNOTATION.to_owned(),
            generation.clone(),
        )));
    let annotations = fandhe_container_core::traits::Annotations::new(entries)?;
    Ok((
        req.clone().with_annotations(annotations),
        document.clone().with_generation(generation)?,
    ))
}

/// create が失敗したときの巻き戻し。自分が作った inode だけを消し、ロックファイルも消す(期限つき)。
fn rollback_options(prepared: PreparedOptions, id: &ContainerId) -> Result<(), TraitError> {
    let PreparedOptions {
        lock,
        root,
        written,
    } = prepared;
    let id = id.clone();
    fandhe_container_supervisor::supervisor_log::run_bounded(
        move || -> Result<(), TraitError> {
            let result = match &written {
                Some(w) => options_store::remove_if_same(&root, &id, w),
                None => Ok(()),
            };
            lock.remove_lock_file();
            result
        },
        OPTIONS_IO_TIMEOUT,
    )
    .unwrap_or_else(|| Err(options_timeout()))
}

/// 起動オプション文書を core の create の前に書き、create が失敗したら自分が作った inode だけを消す(#2713・SUP-12)。
///
/// 文書の準備に失敗したら core の create に入らない(オプションを黙って落とした状態を作らない。fail-closed)。
/// core に到達しないので、この失敗は create の失敗として 1 回だけ計測する(REPAIR-4)。
/// 巻き戻しの失敗は警告 1 行だけ出し、create の元のエラーを返す。
fn create_with_options(
    rt: &Runtime,
    req: &CreateRequest,
    image: Option<&CreateImage>,
    document: &ContainerOptionsDocument,
) -> Result<StateRecord, OciRuntimeError> {
    let started = Instant::now();
    // 文書を書くときは、作成世代を文書と状態記録の annotations の両方へ同じ値で入れる(supervisor が照合し、同じ ID の
    // 前のコンテナの残骸を適用しない。#2713・SEC-1)。
    let (req, document) = match bind_generation(rt, req, document) {
        Ok(pair) => pair,
        Err(e) => {
            record_pre_core_failure(&rt.recorder, "create", started);
            return Err(OciRuntimeError::from_trait_error(LifecycleOp::Create, e));
        }
    };
    let (req, document) = (&req, &document);
    let prepared = match prepare_options_file(rt, req.id(), document) {
        Ok(p) => p,
        Err(e) => {
            record_pre_core_failure(&rt.recorder, "create", started);
            return Err(OciRuntimeError::from_trait_error(LifecycleOp::Create, e));
        }
    };
    let r = match image {
        Some(image) => create_container_with_image_reclaiming(rt, image, req),
        None => create_container(rt, req),
    };
    if let Some(prepared) = prepared
        && r.is_err()
        && let Err(e) = rollback_options(prepared, req.id())
    {
        emit_warning_bounded(
            options_removal_warning(&e),
            write_warning_to_stderr,
            WARNING_WRITE_TIMEOUT,
        );
    }
    r
}
/// 本番入口の `create`。成功時は何も出さない（OCI の create 互換）。
///
/// 要求構築・状態ストア初期化の失敗も操作名 `create` の失敗として計測する（REPAIR-4）。
pub(super) fn run_create(global: &GlobalArgs, args: &CreateArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let result = production_runtime(global, recorder, "create", started, || {
        let (req, image) = build_create(global, args)?;
        // 起動オプション(ulimit・env 等)の意味検証と `--env-file` の読み取りは core に入る前に行う(#2713)。
        let document = create_options::document_of(&args.options)?;
        Ok((req, image, document))
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Create, e))
    .and_then(|(rt, (req, pending, document))| {
        // 参照キーの scope は開いた状態ストアから求める（表記ゆれを畳んだ正規パス。#2499）。
        let image = match pending.map(|p| p.bind(rt.store.as_ref())).transpose() {
            Ok(i) => i,
            Err(e) => {
                record_pre_core_failure(&rt.recorder, "create", started);
                export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
                return Err(OciRuntimeError::from_trait_error(LifecycleOp::Create, e));
            }
        };
        let r = match reclaim_stale_container_log(rt.store.as_ref(), req.id(), &rt.recorder) {
            // 回収の期限切れは core を呼ばずに create の失敗として計測する（REPAIR-4）。
            Err(e) => {
                if let Ok(name) = OpName::new("create") {
                    let _ = rt
                        .recorder
                        .record(&name, OpOutcome::Failure, started.elapsed());
                }
                Err(e)
            }
            Ok(()) => create_with_options(&rt, &req, image.as_ref(), &document),
        };
        export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
        r
    });
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 同じ ID の前のインスタンスが残したコンテナログを、core の create の前に回収する（#2698・SUP-7・CLI-1・REPAIR-4）。
///
/// `delete` はコンテナログの sink 閉鎖を最大 10 秒しか待たないため、supervisor の terminate がそれを超えるとログが残る。
/// 残りは同じ ID の `create` で消す（そうしないと新しいインスタンスの sink が既存の `<id>.log` を世代へ退避し、
/// 古い出力が新しい世代に混ざる）。待たずに 1 回だけ試す（create を遅らせない。上限は
/// `CONTAINER_LOG_REMOVE_TIMEOUT`）。古い supervisor がまだ sink を持つ（ロックが取れない）ときは何も消さない。
/// 回収が期限切れ（`Timeout`。I/O 停止等で作業スレッドが残り得る）のときは、残った作業スレッドを抱えたまま
/// 後続の監査記録（`FileAuditSink` は単一スレッド前提の fork を要する。SEC-4）へ進まないよう、core を呼ばずに
/// `TIMEOUT` で create を失敗させる（fail-closed。分離違反の監査記録を失わない）。作業スレッドは CLI の終了で消え、
/// guard は削除直前にロック保持中で評価されるため、後から別インスタンスのログを消すことはない。
/// guard は `stop_delete::id_is_still_deleted`（ロック保持中に状態の不在を確認）で、同じ ID が既にあるときは消さず、
/// 続く core の create が `ALREADY_EXISTS` を返す。best effort で create の成否・stderr は変えない。
/// 観測は op 名 `container_log_reclaim`（1 件以上消した Success、エラーの Failure）。0 件は記録しない。
fn reclaim_stale_container_log(
    store: &dyn StateStore,
    id: &fandhe_container_core::traits::ContainerId,
    recorder: &OpRecorder,
) -> Result<(), OciRuntimeError> {
    use fandhe_container_supervisor::logs::{StaleLogReclaim, reclaim_stale_container_logs};
    let Some(root) = store.host_state_root() else {
        return Ok(());
    };
    let started = Instant::now();
    let guard_root = root.to_path_buf();
    let guard_id = id.clone();
    // 回収の本体は plugin-cri の `CreateContainer` と共有する（#2760・REPAIR-1）。ここは計上と期限切れの写像だけを持つ。
    let (outcome, timed_out) = match reclaim_stale_container_logs(root, id, move || {
        super::stop_delete::id_is_still_deleted(&guard_root, &guard_id)
    }) {
        StaleLogReclaim::Removed(_) => (OpOutcome::Success, false),
        StaleLogReclaim::Nothing => return Ok(()),
        StaleLogReclaim::Failed(_) => (OpOutcome::Failure, false),
        StaleLogReclaim::TimedOut => (OpOutcome::Failure, true),
    };
    if let Ok(name) = OpName::new("container_log_reclaim") {
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
    reclaim_timeout_result(timed_out)
}

/// 回収の期限切れを create の失敗へ写す（残った作業スレッドを抱えたまま監査記録へ進まない。SEC-4・#2698）。
fn reclaim_timeout_result(timed_out: bool) -> Result<(), OciRuntimeError> {
    if timed_out {
        return Err(OciRuntimeError::new(
            LifecycleOp::Create,
            fandhe_container_core::traits::ErrorCode::Timeout,
            "stale container log reclaim did not finish within the deadline",
        ));
    }
    Ok(())
}

/// 本番入口の `start`。成功時は何も出さない（OCI の start 互換）。
///
/// 要求を構築して状態ストアで ID の存在を確かめ（不在は `NOT_FOUND`。spawn しない）、ストアを閉じてから
/// supervisor を起動する（`supervisor_start::start_via_supervisor`）。状態の正否の判定（Created か等）は
/// supervisor の手順に任せ、CLI は二重に持たない。core の `start` はこのプロセスで呼ばれなくなったため、
/// 計測（REPAIR-4）は CLI が操作名 `start` の成功・失敗と経過時間を 1 回記録する。
pub(super) fn run_start(global: &GlobalArgs, args: &StartArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let prepared = production_runtime(global, recorder, "start", started, || {
        Ok((build_start_request(args)?, build_audit_policy(args)?))
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e));
    let (rt, (req, audit_policy)) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let Runtime {
        store, recorder, ..
    } = rt;
    let result =
        ensure_exists(store, &req).and_then(|()| launch_supervisor(global, &req, audit_policy));
    record_start_outcome(&recorder, started, result.is_ok());
    export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(()) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 対象の状態レコードが存在することを読み取りだけで確かめる。`store` はここで閉じ、spawn の前に手放す。
fn ensure_exists(store: Box<dyn StateStore>, req: &StartRequest) -> Result<(), OciRuntimeError> {
    use fandhe_container_core::traits::GetStateRequest;
    store
        .get(&GetStateRequest::new(req.id().clone()))
        .map(|_| ())
        .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e))
}

/// 状態ルートの絶対パスを解決し、supervisor を起動して結果を受け取る。
#[cfg(target_os = "linux")]
fn launch_supervisor(
    global: &GlobalArgs,
    req: &StartRequest,
    audit_policy: Option<AuditCoveragePolicy>,
) -> Result<(), OciRuntimeError> {
    use fandhe_container_core::state_store::StateRoot;
    let root = StateRoot::resolve(global.root.clone())
        .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e))?;
    super::supervisor_start::start_via_supervisor(root.path(), req.id(), audit_policy)
        .map(|_pid| ())
}

/// 非 Linux は `production_runtime` が状態ストアを開く段階（plugin 解決）で必ず失敗するため到達しない。
#[cfg(not(target_os = "linux"))]
fn launch_supervisor(
    _global: &GlobalArgs,
    _req: &StartRequest,
    _audit_policy: Option<AuditCoveragePolicy>,
) -> Result<(), OciRuntimeError> {
    Err(OciRuntimeError::new(
        LifecycleOp::Start,
        fandhe_container_core::traits::ErrorCode::Unimplemented,
        "start is not implemented on this platform",
    ))
}

/// 操作名 `start` の成功・失敗と経過時間を記録する（REPAIR-4）。
fn record_start_outcome(recorder: &OpRecorder, started: Instant, ok: bool) {
    if let Ok(name) = OpName::new("start") {
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::super::args::CreateOptionArgs;
    use super::*;
    use fandhe_container_core::traits::ErrorCode;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::path::PathBuf;
    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    use std::time::Duration;

    fn create_args(bundle: &str, id: &str) -> CreateArgs {
        CreateArgs {
            options: CreateOptionArgs::default(),
            bundle: PathBuf::from(bundle),
            id: id.to_string(),
            image: None,
        }
    }

    /// CLI-1・ERR-2: 相対 bundle は INVALID_ARGUMENT（終了コード 2・op=create）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_create_rejects_relative_bundle() {
        let e = build_create_request(&create_args("rel/b", "c1")).expect_err("relative");
        let e = OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.exit_code().get(), 2);
        assert_eq!(e.op(), LifecycleOp::Create);
    }

    /// CLI-1・ERR-2: 不正な ID 文字は INVALID_ARGUMENT。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_create_request(&CreateArgs {
                options: CreateOptionArgs::default(),
                bundle: std::env::temp_dir(),
                id: id.to_string(),
                image: None,
            })
            .expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_start_request(&StartArgs {
                id: id.to_string(),
                audit_policy: None,
            })
            .expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1: 正常な引数は core の要求型へ値をそのまま写す。
    #[test]
    fn cli1_build_create_request_keeps_values() {
        // OS ごとに絶対パスの形が違う（Windows は `/abs/b` を絶対と見なさない）ため temp_dir 由来にする。
        let bundle = std::env::temp_dir().join("abs-b");
        let req = build_create_request(&CreateArgs {
            options: CreateOptionArgs::default(),
            bundle: bundle.clone(),
            id: "c1".to_string(),
            image: None,
        })
        .expect("ok");
        assert_eq!(req.id().as_str(), "c1");
        assert_eq!(req.bundle(), bundle.as_path());
    }

    /// REPAIR-4: 計測は指定ファイルへ JSON Lines で追記され、未指定なら何も書かない。
    /// Linux 以外は計測のファイル出力を拒否するため対象外（SEC-1）。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_export_ops_appends_json_lines() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        export_ops(&rec, None);
        assert!(!path.exists());
        export_ops(&rec, Some(path.as_os_str()));
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"op_stats\""));
        assert!(lines[1].contains("\"op_stats_meta\""));
    }

    /// write の呼び出しごとの引数長を記録し、台本どおりの結果を返す出力先（台本が尽きたら全量を受理）。
    struct ScriptedSink {
        calls: Vec<usize>,
        data: Vec<u8>,
        script: std::collections::VecDeque<std::io::Result<usize>>,
    }

    impl ScriptedSink {
        fn new(script: Vec<std::io::Result<usize>>) -> Self {
            Self {
                calls: Vec::new(),
                data: Vec::new(),
                script: script.into(),
            }
        }
    }

    impl std::io::Write for ScriptedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls.push(buf.len());
            let n = match self.script.pop_front() {
                Some(r) => r?.min(buf.len()),
                None => buf.len(),
            };
            self.data.extend_from_slice(buf.get(..n).unwrap_or(buf));
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `name` を成功 1 件（1 ms）だけ記録した計測器。
    fn recorder_with(name: &str) -> OpRecorder {
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new(name).expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        rec
    }

    const CREATE_ONCE_LINES: &str = concat!(
        "{\"event\":\"op_stats\",\"op\":\"create\",\"success\":1,\"failure\":0,\"count\":1,",
        "\"min_us\":1000,\"mean_us\":1000,\"p95_us\":1000,\"max_us\":1000}\n",
        "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}\n",
    );

    /// REPAIR-4: 計測の全行（op_stats 行 + メタ行。各行 LF 終端）を 1 回の write で書く。
    /// 行本体と改行を別の write に分けない（並行追記で JSON 行が混ざらないための前提）。
    #[test]
    fn repair4_write_ops_once_emits_all_lines_in_single_write() {
        let mut sink = ScriptedSink::new(Vec::new());
        let n = write_ops_once(&recorder_with("create"), &mut sink).expect("write");
        assert_eq!(n, CREATE_ONCE_LINES.len());
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len()]);
        assert_eq!(
            String::from_utf8(sink.data).expect("utf8"),
            CREATE_ONCE_LINES
        );
    }

    /// REPAIR-4: 部分書き込みは残りを継ぎ足さず失敗にする（継ぎ足しの間に他プロセスの行が入るため）。
    #[test]
    fn repair4_write_ops_once_does_not_continue_partial_write() {
        let mut sink = ScriptedSink::new(vec![Ok(10)]);
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("partial");
        assert_eq!(e.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len()]);
        assert_eq!(sink.data.len(), 10);
    }

    /// REPAIR-4・REPAIR-5: 1 バイトも書けない EINTR は有限回だけやり直し、やり直しも全量 1 回の write。
    #[test]
    fn repair5_write_ops_once_retries_interrupted_bounded() {
        let interrupted = || Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        let mut sink = ScriptedSink::new(vec![interrupted()]);
        let n = write_ops_once(&recorder_with("create"), &mut sink).expect("write");
        assert_eq!(n, CREATE_ONCE_LINES.len());
        assert_eq!(sink.calls, vec![CREATE_ONCE_LINES.len(); 2]);
        assert_eq!(
            String::from_utf8(sink.data).expect("utf8"),
            CREATE_ONCE_LINES
        );

        let mut sink = ScriptedSink::new((0..8).map(|_| interrupted()).collect());
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("interrupted");
        assert_eq!(e.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(sink.calls.len(), 4);
        assert!(sink.data.is_empty());

        let mut sink = ScriptedSink::new(vec![Err(std::io::Error::other("disk"))]);
        let e = write_ops_once(&recorder_with("create"), &mut sink).expect_err("error");
        assert_eq!(e.kind(), std::io::ErrorKind::Other);
        assert_eq!(sink.calls.len(), 1);
    }

    /// REPAIR-4: 操作名の種類数が core の上限（64）でも 1 回の出力は上限（64 KiB）に収まり、1 回の write で出る。
    #[test]
    fn repair4_write_ops_once_fits_limit_at_max_tracked_ops() {
        use fandhe_container_core::observability::{MAX_TRACKED_OPS, OP_NAME_MAX_LEN};
        let rec = OpRecorder::new();
        for i in 0..MAX_TRACKED_OPS {
            let name = format!("{i:0>width$}", width = OP_NAME_MAX_LEN);
            rec.record(
                &OpName::new(name).expect("name"),
                OpOutcome::Failure,
                Duration::MAX,
            )
            .expect("record");
        }
        let mut sink = ScriptedSink::new(Vec::new());
        let n = write_ops_once(&rec, &mut sink).expect("write");
        assert_eq!(sink.calls, vec![n]);
        assert!(n <= OP_LOG_MAX_BYTES, "{n}");
        let text = String::from_utf8(sink.data).expect("utf8");
        assert_eq!(text.lines().count(), MAX_TRACKED_OPS + 1);
        assert!(text.lines().all(|l| l.len() <= 512), "line too long");
    }

    /// REPAIR-4: 複数スレッドが別々の fd で同じ計測ログへ並行に追記しても、JSON 行が混ざらない。
    /// 未存在からの同時作成でも出力を落とさず、各出力の 2 行（op_stats・メタ）は連続して並ぶ。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair4_export_ops_concurrent_appends_keep_lines_intact() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 50;
        let path =
            std::env::temp_dir().join(format!("fc-cli-oplog-concurrent-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let rec = recorder_with(&format!("op{t}"));
                    barrier.wait();
                    for _ in 0..ROUNDS {
                        export_ops(&rec, Some(path.as_os_str()));
                    }
                    let _ = tx.send(());
                });
                rx
            })
            .collect();
        // 各スレッドの完了は有限期限で待つ（REPAIR-5。panic で送信側が落ちた場合も即座に失敗する）。
        for rx in handles {
            rx.recv_timeout(Duration::from_secs(30))
                .expect("export_ops threads must finish within 30s");
        }
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        assert!(text.ends_with('\n'));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), THREADS * ROUNDS * 2);
        let meta = "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}";
        let mut per_thread = vec![0usize; THREADS];
        for pair in lines.chunks(2) {
            let t = (0..THREADS)
                .find(|t| {
                    pair.first().copied()
                        == Some(
                            format!(
                                "{{\"event\":\"op_stats\",\"op\":\"op{t}\",\"success\":1,\"failure\":0,\"count\":1,\"min_us\":1000,\"mean_us\":1000,\"p95_us\":1000,\"max_us\":1000}}"
                            )
                            .as_str(),
                        )
                })
                .unwrap_or_else(|| panic!("mixed or unknown line: {pair:?}"));
            assert_eq!(pair.get(1).copied(), Some(meta), "{pair:?}");
            if let Some(c) = per_thread.get_mut(t) {
                *c += 1;
            }
        }
        assert_eq!(per_thread, vec![ROUNDS; THREADS]);
    }

    /// REPAIR-5: 計測出力先が FIFO でも `export_ops` がブロックせず、何も書き込まない。
    /// 読み手がいない場合と、読み手が open しただけで読まない場合の両方を具体値で検証する。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn repair5_export_ops_rejects_fifo_without_blocking() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        use std::os::unix::fs::OpenOptionsExt;
        let rec = Arc::new(OpRecorder::new());
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let run = |path: std::path::PathBuf| {
            let (tx, rx) = std::sync::mpsc::channel();
            let rec = Arc::clone(&rec);
            std::thread::spawn(move || {
                export_ops(&rec, Some(path.as_os_str()));
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5))
                .expect("export_ops must not block on a FIFO");
        };
        let mkfifo = |name: &str| {
            let p =
                std::env::temp_dir().join(format!("fc-cli-oplog-{name}-{}", std::process::id()));
            let _ = std::fs::remove_file(&p);
            // 子プロセスの終了は有限期限で待ち、超過時は kill して回収も期限つきで行う（REPAIR-5）。
            let mut child = std::process::Command::new("mkfifo")
                .arg(&p)
                .stdin(std::process::Stdio::null())
                .spawn()
                .expect("mkfifo");
            let poll = |child: &mut std::process::Child, limit: Duration| {
                let deadline = Instant::now() + limit;
                loop {
                    match child.try_wait().expect("poll mkfifo") {
                        Some(st) => return Some(st),
                        None if Instant::now() >= deadline => return None,
                        None => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            };
            let Some(st) = poll(&mut child, Duration::from_secs(10)) else {
                let _ = child.kill();
                let _ = poll(&mut child, Duration::from_secs(5));
                panic!("mkfifo did not exit within 10s");
            };
            assert!(st.success());
            p
        };
        // 読み手なし。
        let p1 = mkfifo("noreader");
        run(p1.clone());
        let _ = std::fs::remove_file(&p1);
        // 読み手あり（open のみで読まない）。何も書かれていないこと。
        let p2 = mkfifo("idlereader");
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                fandhe_container_core::open_flags::NofollowOpenFlags::current()
                    .expect("supported arch")
                    .nonblock(),
            )
            .open(&p2)
            .expect("open reader");
        run(p2.clone());
        let mut buf = [0u8; 16];
        let n = match std::io::Read::read(&mut &reader, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(e) => panic!("read: {e}"),
        };
        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&p2);
    }

    /// SEC-1: 最終要素が symlink なら辿らず拒否し、リンク先は書き換えない。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn sec1_open_op_log_rejects_symlink_and_hardlink() {
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").expect("victim");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        assert!(open_op_log(link.as_os_str()).is_none());
        let hard = dir.join("hard");
        std::fs::hard_link(&victim, &hard).expect("hardlink");
        assert!(open_op_log(hard.as_os_str()).is_none());
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
        let fresh = dir.join("fresh");
        assert!(open_op_log(fresh.as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: 信頼できない（非 root 所有の）親 symlink は辿らず拒否し、リンク先へ書かない。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn sec1_open_op_log_rejects_parent_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-psym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = dir.join("linkdir");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(open_op_log(link.join("log").as_os_str()).is_none());
        assert!(!real.join("log").exists());
        assert!(open_op_log(real.join("log").as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: デバイスノードは O_PATH で固定して種別検査で拒否し、書き込み用に開かない。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn sec1_open_op_log_rejects_device_node() {
        assert!(open_op_log(std::ffi::OsStr::new("/dev/null")).is_none());
    }

    /// SEC-1: 親の `..` は検査済み fd のスタックで解決でき、ルートより上へ出る経路は拒否する。
    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn sec1_open_trusted_parent_resolves_parent_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-dd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let via_dotdot = real.join("..").join("real").join("log");
        assert!(open_op_log(via_dotdot.as_os_str()).is_some());
        assert!(real.join("log").is_file());
        let euid = op_log_file::unelevated_euid().expect("euid");
        let above_root = std::path::Path::new("/..");
        let flags = fandhe_container_core::open_flags::NofollowOpenFlags::current().expect("flags");
        assert!(op_log_file::open_trusted_parent(above_root, euid, flags).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    mod op_log_file_tests {
        use super::super::op_log_file::{
            open_op_log, unelevated_euid, unelevated_euid_from_status,
        };

        /// `/proc/<pid>/status` を模した本文（前後に実物と同じ並びの行を置く）。
        fn status(uid: &str, gid: &str) -> String {
            format!(
                "Name:\tfandhe-container\nUmask:\t0022\nState:\tR (running)\nPid:\t42\n\
                 Uid:\t{uid}\nGid:\t{gid}\nFDSize:\t64\nGroups:\t1000 \n"
            )
        }

        /// SEC-1: real・effective・saved・fs の UID / GID がすべて一致する実行だけ実効 UID を返す。
        #[test]
        fn sec1_unelevated_euid_accepts_matching_ids() {
            let s = status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000");
            assert_eq!(unelevated_euid_from_status(&s), Some(1000));
            let s = status("0\t0\t0\t0", "0\t0\t0\t0");
            assert_eq!(unelevated_euid_from_status(&s), Some(0));
            let s = status("1000\t1000\t1000\t1000", "100\t100\t100\t100");
            assert_eq!(unelevated_euid_from_status(&s), Some(1000));
        }

        /// SEC-1: setuid / setgid 相当（real と effective の不一致）や saved・fs の不一致は拒否する。
        #[test]
        fn sec1_unelevated_euid_rejects_mismatched_ids() {
            let same = "1000\t1000\t1000\t1000";
            for uid in [
                "1000\t0\t0\t0",
                "1000\t0\t1000\t1000",
                "1000\t1000\t0\t1000",
                "1000\t1000\t1000\t0",
                "0\t1000\t1000\t1000",
            ] {
                assert_eq!(
                    unelevated_euid_from_status(&status(uid, same)),
                    None,
                    "{uid:?}"
                );
            }
            for gid in [
                "1000\t0\t0\t0",
                "1000\t0\t1000\t1000",
                "1000\t1000\t0\t1000",
                "1000\t1000\t1000\t0",
            ] {
                assert_eq!(
                    unelevated_euid_from_status(&status(same, gid)),
                    None,
                    "{gid:?}"
                );
            }
        }

        /// SEC-1: 形式を解釈できない status は拒否する（行の欠落・重複・個数違い・非数値・範囲外）。
        #[test]
        fn sec1_unelevated_euid_rejects_malformed_status() {
            let same = "1000\t1000\t1000\t1000";
            for bad in [
                "",
                "1000",
                "1000\t1000\t1000",
                "1000\t1000\t1000\t1000\t1000",
                "1000\t1000\t1000\tx",
                "+1000\t+1000\t+1000\t+1000",
                "-1\t-1\t-1\t-1",
                "4294967296\t4294967296\t4294967296\t4294967296",
            ] {
                assert_eq!(
                    unelevated_euid_from_status(&status(bad, same)),
                    None,
                    "{bad:?}"
                );
                assert_eq!(
                    unelevated_euid_from_status(&status(same, bad)),
                    None,
                    "{bad:?}"
                );
            }
            assert_eq!(unelevated_euid_from_status(""), None);
            assert_eq!(unelevated_euid_from_status("Name:\tx\n"), None);
            let no_gid = format!("Uid:\t{same}\n");
            assert_eq!(unelevated_euid_from_status(&no_gid), None);
            let no_uid = format!("Gid:\t{same}\n");
            assert_eq!(unelevated_euid_from_status(&no_uid), None);
            let dup = format!("Uid:\t{same}\nUid:\t{same}\nGid:\t{same}\n");
            assert_eq!(unelevated_euid_from_status(&dup), None);
            // 行頭以外に現れる `Uid:` は拾わない（プロセス名に紛れ込ませても判定を変えられない）。
            let in_name = format!("Name:\tUid:\t0\t0\t0\t0\nUid:\t{same}\nGid:\t{same}\n");
            assert_eq!(unelevated_euid_from_status(&in_name), Some(1000));
        }

        /// SEC-1: テストプロセス自身（setuid ではない）の実効 UID は `/proc/self` の所有者と一致する。
        #[test]
        fn sec1_unelevated_euid_reads_own_status() {
            use std::os::unix::fs::MetadataExt;
            let owner = std::fs::metadata("/proc/self").expect("stat").uid();
            assert_eq!(unelevated_euid(), Some(owner));
        }

        /// SEC-1: open フラグはアーキテクチャごとの固定値（Linux の UAPI ヘッダの値）。
        #[test]
        fn sec1_open_flags_have_fixed_values_per_arch() {
            use fandhe_container_core::open_flags::NofollowOpenFlags;
            let f = NofollowOpenFlags::current().expect("supported arch");
            // [nonblock, directory|nofollow|nonblock, path|nofollow, file nofollow|nonblock]
            #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
            let want = [0o4000, 0o604_000, 0o10_400_000, 0o404_000];
            #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
            let want = [0o4000, 0o144_000, 0o10_100_000, 0o104_000];
            assert_eq!(
                [
                    f.nonblock(),
                    f.directory_nofollow_nonblock(),
                    f.path_nofollow(),
                    f.file_nofollow_nonblock()
                ],
                want
            );
        }

        /// SEC-1: 新規作成する計測ログは mode 0600（group / other へ開かない）。既存ファイルの mode は変えない。
        #[test]
        fn sec1_open_op_log_creates_file_with_mode_0600() {
            use std::os::unix::fs::PermissionsExt;
            let dir =
                std::env::temp_dir().join(format!("fc-cli-oplog-mode-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            let mode = |p: &std::path::Path| {
                std::fs::metadata(p).expect("stat").permissions().mode() & 0o7777
            };
            let fresh = dir.join("fresh");
            drop(open_op_log(fresh.as_os_str()).expect("create"));
            assert_eq!(mode(&fresh), 0o600);
            let existing = dir.join("existing");
            std::fs::write(&existing, "").expect("write");
            std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o640))
                .expect("chmod");
            drop(open_op_log(existing.as_os_str()).expect("open"));
            assert_eq!(mode(&existing), 0o640);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// SEC-1: 対応外の OS・アーキテクチャは計測のファイル出力を拒否し、ファイルを作らない（fail-closed）。
    #[cfg(not(all(
        target_os = "linux",
        all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    #[test]
    fn sec1_open_op_log_refused_on_unsupported_target() {
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-nl-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(open_op_log(path.as_os_str()).is_none());
        assert!(!path.exists());
    }

    /// REPAIR-4: 不正 ID（core 到達前の失敗）も操作名 create の失敗として 1 件計測される。
    #[test]
    fn repair4_pre_core_failure_is_recorded_once() {
        let rec = OpRecorder::new();
        record_pre_core_failure(&rec, "create", Instant::now());
        let snap = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("snap");
        assert_eq!(snap.failure(), 1);
        assert_eq!(snap.success(), 0);
    }

    const IMG_DIGEST: &str =
        "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

    fn test_global() -> GlobalArgs {
        GlobalArgs {
            root: Some(std::env::temp_dir().join("fc-cli-state-root")),
            plugin_path_search: false,
        }
    }

    fn image_args(root: PathBuf, manifest: &str) -> CreateArgs {
        CreateArgs {
            options: CreateOptionArgs::default(),
            bundle: std::env::temp_dir(),
            id: "c1".into(),
            image: Some(crate::commands::args::CreateImageArgs {
                image_root: root,
                reference: manifest.into(),
            }),
        }
    }

    /// OCI-7・SEC-1: 不正な digest（大文字・短い・sha512・空）は INVALID_ARGUMENT で、ストアを開く前に拒否される。
    #[test]
    fn oci7_build_create_rejects_malformed_digest() {
        let upper = format!("sha256:{}", "A".repeat(64));
        let short = &IMG_DIGEST[..IMG_DIGEST.len() - 1];
        let sha512 = IMG_DIGEST.replace("sha256", "sha512");
        for bad in [upper.as_str(), short, sha512.as_str(), ""] {
            // root が存在しなくても digest の拒否が先に起きる（INVALID_ARGUMENT であって NOT_FOUND ではない）。
            let args = image_args(std::env::temp_dir().join("fc-cli-no-such-image-root"), bad);
            let e = build_create(&test_global(), &args)
                .err()
                .expect("must fail");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }

    /// OCI-7・CLI-1: 非 Linux ではタグ参照でもローカルストアを開かず、plugin 解決の拒否に到達する（#2496）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn oci7_build_create_non_linux_tag_ref_reaches_plugin_refusal() {
        let root = std::env::temp_dir().join("fc-cli-no-such-image-root-4");
        let e = build_create(&test_global(), &image_args(root, "alpine:3.19"))
            .err()
            .expect("must fail");
        assert_ne!(e.message(), "image store root not found");
        assert_ne!(e.message(), "image tag not found");
    }

    /// OCI-7・CLI-1: 非 Linux は存在しない `--image-root` でも NOT_FOUND にならず、plugin 解決の拒否に到達する。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn oci7_build_create_non_linux_skips_local_store() {
        let root = std::env::temp_dir().join("fc-cli-no-such-image-root-3");
        let e = build_create(&test_global(), &image_args(root, IMG_DIGEST))
            .err()
            .expect("must fail");
        assert_ne!(e.message(), "image store root not found");
    }

    /// OCI-7: 存在しない `--image-root` は NOT_FOUND と固定文言で、パスを含まない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_build_create_missing_image_root_is_fixed_not_found() {
        let root = std::env::temp_dir().join("fc-cli-no-such-image-root-2");
        let e = build_create(&test_global(), &image_args(root.clone(), IMG_DIGEST))
            .err()
            .expect("must fail");
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert_eq!(e.message(), "image store root not found");
        assert!(!e.message().contains(root.to_string_lossy().as_ref()));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use fandhe_container_core::traits::ContainerState;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("fc-cli-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
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

        /// 有効な bundle（config.json と rootfs/）を作る。
        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn runtime(base: &TmpDir) -> Runtime {
            let root =
                fandhe_container_core::state_store::StateRoot::from_override(base.0.join("state"))
                    .expect("root");
            let store = FileStateStore::open(root).expect("open");
            Runtime {
                audit: Box::new(FileAuditSink::in_state_store(&store)),
                store: Box::new(store),
                recorder: OpRecorder::new(),
            }
        }

        /// CLI-1・OCI-4: create は core を呼び、Created（pid なし）を記録する。同一 ID の再 create は ALREADY_EXISTS（4）。
        #[test]
        fn cli1_create_calls_core_and_rejects_duplicate() {
            let base = TmpDir::new("create");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let args = CreateArgs {
                options: CreateOptionArgs::default(),
                bundle: bundle.clone(),
                id: "c1".into(),
                image: None,
            };
            let rec =
                create_container(&rt, &build_create_request(&args).expect("req")).expect("create");
            assert_eq!(rec.status().state(), ContainerState::Created);
            assert_eq!(rec.status().pid(), None);
            let e =
                create_container(&rt, &build_create_request(&args).expect("req")).expect_err("dup");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(e.exit_code().get(), 4);
            assert_eq!(e.op(), LifecycleOp::Create);
        }

        fn options_args(bundle: &Path, id: &str) -> CreateArgs {
            CreateArgs {
                options: CreateOptionArgs {
                    ulimits: vec!["nofile=1024:2048".into()],
                    env: vec!["A=1".into()],
                    labels: vec!["tier=web".into()],
                    ..CreateOptionArgs::default()
                },
                bundle: bundle.to_path_buf(),
                id: id.into(),
                image: None,
            }
        }

        /// SUP-12・CLI-1・SEC-1(#2713): create は label を状態記録へ書き、起動オプション文書を 0600 で
        /// 状態ルート配下へ書く。同じ ID の再 create は `ALREADY_EXISTS` で、既存の文書は壊れない。
        #[test]
        fn sup12_create_writes_options_document_and_labels() {
            use std::os::unix::fs::MetadataExt as _;
            let base = TmpDir::new("opts");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let args = options_args(&bundle, "c1");
            let req = build_create_request(&args).expect("req");
            let doc = create_options::document_of(&args.options).expect("doc");
            let rec = create_with_options(&rt, &req, None, &doc).expect("create");
            assert_eq!(rec.annotations().get("tier"), Some("web"));
            let root = rt.store.host_state_root().expect("root").to_path_buf();
            let id = ContainerId::new("c1").expect("id");
            let path = options_store::options_path(&root, &id);
            assert_eq!(
                std::fs::metadata(&path).expect("meta").mode() & 0o777,
                0o600
            );
            // 文書と状態記録の annotations は同じ作成世代を持つ(supervisor が照合する。#2713・SEC-1)。
            let written = options_store::read(&root, &id)
                .expect("read")
                .expect("document");
            let generation = rec
                .annotations()
                .get(options_store::GENERATION_ANNOTATION)
                .expect("generation annotation");
            assert_eq!(generation.len(), 32);
            assert_eq!(written.generation(), Some(generation));
            assert_eq!(written.env(), doc.env());
            let before = std::fs::read(&path).expect("bytes");
            let e = create_with_options(&rt, &req, None, &doc).expect_err("dup");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(std::fs::read(&path).expect("bytes"), before);
        }

        /// SUP-12・CLI-1(#2713): core の create が失敗したら、書いた文書を残さない。
        #[test]
        fn sup12_create_failure_rolls_back_options_document() {
            let base = TmpDir::new("optsfail");
            let missing = base.0.join("no-such-bundle");
            let rt = runtime(&base);
            let args = options_args(&missing, "c1");
            let req = build_create_request(&args).expect("req");
            let doc = create_options::document_of(&args.options).expect("doc");
            let e = create_with_options(&rt, &req, None, &doc).expect_err("must fail");
            assert_eq!(e.code(), ErrorCode::NotFound);
            let root = rt.store.host_state_root().expect("root").to_path_buf();
            let path = options_store::options_path(&root, req.id());
            assert!(!path.exists(), "the document must be rolled back");
        }

        /// SUP-12・REPAIR-4(#2713): 文書の準備が失敗したら core に入らず、失敗を 1 回だけ計測し、状態を作らない。
        #[test]
        fn repair4_options_prepare_failure_is_recorded_once_and_creates_no_state() {
            let base = TmpDir::new("optsprep");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let root = rt.store.host_state_root().expect("root").to_path_buf();
            // 文書ディレクトリの位置に通常ファイルを置いて、準備(ディレクトリの検証)を失敗させる。
            std::fs::write(options_store::options_dir(&root), b"x").expect("blocker");
            let args = options_args(&bundle, "c1");
            let req = build_create_request(&args).expect("req");
            let doc = create_options::document_of(&args.options).expect("doc");
            create_with_options(&rt, &req, None, &doc).expect_err("must fail");
            let name = OpName::new("create").expect("name");
            let stats = rt.recorder.snapshot_op(&name).expect("recorded");
            assert_eq!((stats.success(), stats.failure()), (0, 1));
            assert!(
                rt.store
                    .get(&fandhe_container_core::traits::GetStateRequest::new(
                        req.id().clone()
                    ))
                    .is_err(),
                "core create must not have run"
            );
        }

        /// SUP-12(#2713): 指定が空でも、状態の無い残骸の文書は create が掃除する(前のコンテナの設定が効かない)。
        #[test]
        fn sup12_create_clears_stale_options_document() {
            let base = TmpDir::new("optsstale");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let root = rt.store.host_state_root().expect("root").to_path_buf();
            let id = ContainerId::new("c1").expect("id");
            let stale = create_options::document_of(&CreateOptionArgs {
                env: vec!["OLD=1".into()],
                ..CreateOptionArgs::default()
            })
            .expect("doc");
            options_store::write_new(&root, &id, &stale).expect("stale");
            let args = CreateArgs {
                options: CreateOptionArgs::default(),
                bundle,
                id: "c1".into(),
                image: None,
            };
            let req = build_create_request(&args).expect("req");
            let doc = create_options::document_of(&args.options).expect("doc");
            create_with_options(&rt, &req, None, &doc).expect("create");
            assert!(!options_store::options_path(&root, &id).exists());
        }

        const IMG_DIGEST_2: &str =
            "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

        fn seed_images(base: &TmpDir, tags: &[(&str, &str)]) -> PathBuf {
            use fandhe_container_oci::image_management::{ImageTagSource, ManifestComposition};
            use fandhe_container_oci::reference::{Digest, ImageReference, Reference};
            let root = base.0.join("images");
            std::fs::create_dir_all(&root).expect("mkdir");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            let store = ImageStore::open(&root).expect("store");
            let cfg = Digest::parse(&format!("sha256:{}", "c".repeat(64))).expect("cfg");
            for m in [IMG_DIGEST, IMG_DIGEST_2] {
                store
                    .lock()
                    .expect("lock")
                    .register_manifest(
                        Digest::parse(m).expect("d"),
                        ManifestComposition::new(cfg.clone(), vec![]).expect("comp"),
                    )
                    .expect("reg");
            }
            for (name, m) in tags {
                let r = ImageReference::parse(name).expect("ref");
                let Reference::Tag(t) = r.reference() else {
                    panic!("tag expected")
                };
                store
                    .tag_image(
                        &ImageTagSource::Manifest(Digest::parse(m).expect("d")),
                        fandhe_container_oci::image_management::TagKey::new(
                            r.registry().clone(),
                            r.repository().clone(),
                            t.clone(),
                        ),
                    )
                    .expect("tag");
            }
            root
        }

        /// OCI-7・CLI-1: 存在しないタグは NOT_FOUND と固定文言で、入力もパスも含まない（#2496）。
        #[test]
        fn oci7_build_create_unknown_tag_is_not_found() {
            let base = TmpDir::new("tag-nf");
            let root = seed_images(&base, &[("registry.example/lib/app:v1", IMG_DIGEST)]);
            let e = build_create(
                &test_global(),
                &image_args(root.clone(), "registry.example/lib/app:v2"),
            )
            .err()
            .expect("must fail");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.message(), "image tag not found");
            assert!(!e.message().contains(root.to_string_lossy().as_ref()));
        }

        /// OCI-7・CLI-1: タグを解決したあとに付け替えられても、create は解決した digest で参照を登録する（#2496）。
        #[test]
        fn oci7_create_with_tag_registers_resolved_digest_despite_retag() {
            use fandhe_container_oci::image_management::{ImageTagSource, TagKey};
            use fandhe_container_oci::reference::Digest;
            let base = TmpDir::new("tag-retag");
            let bundle = make_bundle(&base);
            let tag = "registry.example/lib/app:v1";
            let root = seed_images(&base, &[(tag, IMG_DIGEST)]);
            let mut global = test_global();
            global.root = Some(base.0.join("state"));
            let (_req, image) =
                build_create(&global, &image_args(root.clone(), tag)).expect("build");
            let pending = image.expect("image");
            assert_eq!(pending.manifest.as_str(), IMG_DIGEST);
            // 解決のあとに別のストアのインスタンスで付け替える。
            let other = ImageStore::open(&root).expect("other");
            let key: TagKey =
                match crate::commands::image_refs::classify_create_image(tag).expect("c") {
                    crate::commands::image_refs::CreateImageRef::Tag(k) => k,
                    _ => panic!("tag expected"),
                };
            let out = other
                .tag_image(
                    &ImageTagSource::Manifest(Digest::parse(IMG_DIGEST_2).expect("d")),
                    key,
                )
                .expect("retag");
            assert!(matches!(
                out.change,
                fandhe_container_oci::image_management::ImageTagChange::Moved { .. }
            ));
            let rt = runtime(&base);
            let image = pending.bind(rt.store.as_ref()).expect("bind");
            let req = build_create_request(&CreateArgs {
                options: CreateOptionArgs::default(),
                bundle,
                id: "c1".into(),
                image: None,
            })
            .expect("req");
            create_container_with_image_reclaiming(&rt, &image, &req).expect("create");
            let guard = image.store.lock().expect("lock");
            let m1 = guard.manifest_references(&Digest::parse(IMG_DIGEST).expect("d"));
            let m2 = guard.manifest_references(&Digest::parse(IMG_DIGEST_2).expect("d"));
            assert_eq!(m1.containers.len(), 1);
            assert!(m1.containers[0].as_str().ends_with(".c1"));
            assert!(m2.containers.is_empty());
            let moved: Vec<String> = guard
                .tags()
                .map(|(k, d)| format!("{k}={}", d.as_str()))
                .collect();
            assert_eq!(
                moved,
                vec![format!("registry.example/lib/app:v1={IMG_DIGEST_2}")]
            );
        }

        fn gate_test_image(base: &TmpDir) -> CreateImage {
            let root = base.0.join("images");
            std::fs::create_dir_all(&root).expect("mkdir");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            CreateImage {
                store: ImageStore::open(&root).expect("store"),
                manifest: ImageManifestDigest::new(IMG_DIGEST).expect("digest"),
                scope: "scope".into(),
                legacy_scope: None,
            }
        }

        /// REPAIR-4・OCI-7: create ゲートの共有取得が Timeout になっても create の失敗が 1 件記録される。
        #[test]
        fn repair4_create_gate_timeout_is_recorded_as_create_failure() {
            let base = TmpDir::new("gate-timeout");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let image = gate_test_image(&base);
            let holder = ImageStore::open(&base.0.join("images")).expect("holder");
            let _q = holder
                .quiesce_container_creates()
                .expect("q")
                .expect("some");
            let req = build_create_request(&CreateArgs {
                options: CreateOptionArgs::default(),
                bundle,
                id: "c1".into(),
                image: None,
            })
            .expect("req");
            let e = create_container_with_image_reclaiming(&rt, &image, &req).expect_err("timeout");
            assert_eq!(e.op(), LifecycleOp::Create);
            let snap = rt
                .recorder
                .snapshot_op(&OpName::new("create").expect("name"))
                .expect("snap");
            assert_eq!(snap.failure(), 1);
            assert_eq!(snap.success(), 0);
        }

        /// REPAIR-4・OCI-7: ゲートファイルを開けない場合（ディレクトリで置換）も create の失敗が 1 件記録される。
        #[test]
        fn repair4_create_gate_open_failure_is_recorded_as_create_failure() {
            let base = TmpDir::new("gate-open");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let image = gate_test_image(&base);
            std::fs::create_dir(
                base.0.join("images").join(
                    fandhe_container_oci::image_management::IMAGE_STORE_CREATE_GATE_FILE_NAME,
                ),
            )
            .expect("gate dir");
            let req = build_create_request(&CreateArgs {
                options: CreateOptionArgs::default(),
                bundle,
                id: "c1".into(),
                image: None,
            })
            .expect("req");
            let e = create_container_with_image_reclaiming(&rt, &image, &req).expect_err("open");
            assert_eq!(e.op(), LifecycleOp::Create);
            let snap = rt
                .recorder
                .snapshot_op(&OpName::new("create").expect("name"))
                .expect("snap");
            assert_eq!(snap.failure(), 1);
            assert_eq!(snap.success(), 0);
        }

        /// ERR-2: 未 create の ID の start は NOT_FOUND（3）で、supervisor を起動する前に返る。
        #[test]
        fn err2_start_unknown_id_is_not_found() {
            let base = TmpDir::new("notfound");
            let rt = runtime(&base);
            let e = ensure_exists(
                rt.store,
                &build_start_request(&StartArgs {
                    id: "nope".into(),
                    audit_policy: None,
                })
                .expect("req"),
            )
            .expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(e.op(), LifecycleOp::Start);
        }

        /// ERR-2: 作成済みの ID は存在確認を通り、状態は書き換わらない。
        #[test]
        fn cli1_start_existing_id_passes_existence_check() {
            let base = TmpDir::new("exists");
            let bundle = make_bundle(&base);
            let rt = runtime(&base);
            let rec = create_container(
                &rt,
                &build_create_request(&CreateArgs {
                    options: CreateOptionArgs::default(),
                    bundle,
                    id: "c1".into(),
                    image: None,
                })
                .expect("req"),
            )
            .expect("create");
            let req = build_start_request(&StartArgs {
                id: "c1".into(),
                audit_policy: None,
            })
            .expect("req");
            ensure_exists(rt.store, &req).expect("exists");
            let root =
                fandhe_container_core::state_store::StateRoot::from_override(base.0.join("state"))
                    .expect("root");
            let store = FileStateStore::open(root).expect("open");
            let got = store
                .get(&fandhe_container_core::traits::GetStateRequest::new(
                    req.id().clone(),
                ))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Created);
            assert_eq!(got.revision(), rec.revision());
        }

        /// REPAIR-4: start の成功・失敗は操作名 `start` で 1 件ずつ計測される。
        #[test]
        fn repair4_start_outcome_is_recorded() {
            let rec = OpRecorder::new();
            record_start_outcome(&rec, Instant::now(), false);
            record_start_outcome(&rec, Instant::now(), true);
            let snap = rec
                .snapshot_op(&OpName::new("start").expect("name"))
                .expect("snap");
            assert_eq!((snap.success(), snap.failure()), (1, 1));
        }
    }
}
/// 同じ ID の create 前の残りログ回収（#2698・SUP-7・CLI-1・REPAIR-4）の試験。ディレクトリ 0700 を前提にするため Linux のみ。
#[cfg(all(test, target_os = "linux"))]
mod reclaim_tests {
    use super::*;
    use fandhe_container_core::state_store::StateRoot;
    use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest};
    use fandhe_container_supervisor::logs::{RotatingFileSink, container_log_rotation_config};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-cli-rc-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }
        fn root(&self) -> PathBuf {
            self.0.join("state")
        }
        fn store(&self) -> FileStateStore {
            FileStateStore::open(StateRoot::from_override(self.root()).expect("root"))
                .expect("open")
        }
        /// ロックファイルを除いたログファイルの数（ロックは guard が false でも片付く）。
        fn names(&self) -> usize {
            std::fs::read_dir(self.root().join("@container-logs"))
                .map(|d| {
                    d.filter(|e| {
                        !e.as_ref()
                            .expect("e")
                            .file_name()
                            .to_string_lossy()
                            .ends_with(".lock")
                    })
                    .count()
                })
                .unwrap_or(0)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn open_sink(t: &Tmp, name: &str) -> RotatingFileSink {
        let dir = t.root().join("@container-logs");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        RotatingFileSink::open(&dir, &id(name), container_log_rotation_config()).expect("sink")
    }

    fn stats(rec: &OpRecorder) -> Option<(u64, u64)> {
        let n = OpName::new("container_log_reclaim").expect("name");
        rec.snapshot_op(&n).map(|s| (s.success(), s.failure()))
    }

    /// 残ったログ（sink は閉じ済み）は消え、Success が 1 件記録される。0 件のときは何も記録しない。
    #[test]
    fn sup7_cli1_create_reclaims_leftover_logs_for_same_id() {
        let t = Tmp::new("leftover");
        let st = t.store();
        let rec = OpRecorder::new();
        reclaim_stale_container_log(&st, &id("a1"), &rec).expect("ok");
        assert_eq!(stats(&rec), None);
        drop(open_sink(&t, "a1"));
        assert!(t.names() > 0);
        reclaim_stale_container_log(&st, &id("a1"), &rec).expect("ok");
        assert_eq!(t.names(), 0);
        assert_eq!(stats(&rec), Some((1, 0)));
    }

    /// 同じ ID の状態が既にあるときは消さず、何も記録しない（続く core の create が ALREADY_EXISTS を返す）。
    #[test]
    fn sup7_cli1_create_reclaim_keeps_logs_when_state_present() {
        let t = Tmp::new("present");
        let st = t.store();
        drop(open_sink(&t, "p1"));
        let bundle = t.0.join("bundle");
        std::fs::create_dir_all(&bundle).expect("bundle");
        let req =
            CreateStateRequest::new(ContainerStatus::created(id("p1"), None), bundle).expect("req");
        st.create(&req).expect("create");
        let before = t.names();
        let rec = OpRecorder::new();
        reclaim_stale_container_log(&st, &id("p1"), &rec).expect("ok");
        assert_eq!(t.names(), before);
        assert_eq!(stats(&rec), None);
    }

    /// 回収が期限切れなら create は core を呼ばず TIMEOUT で失敗する（SEC-4・SUP-7・#2698）。
    #[test]
    fn sup7_cli1_create_reclaim_timeout_fails_create_before_core() {
        assert!(reclaim_timeout_result(false).is_ok());
        let e = reclaim_timeout_result(true).expect_err("timeout");
        assert_eq!(e.code(), fandhe_container_core::traits::ErrorCode::Timeout);
    }

    /// 古い supervisor の sink が生きている（ロック保持）ときは消さず、Failure が 1 件記録される。
    #[test]
    fn sup7_cli1_create_reclaim_records_failure_when_sink_alive() {
        let t = Tmp::new("alive");
        let st = t.store();
        let _sink = open_sink(&t, "l1");
        let before = t.names();
        let rec = OpRecorder::new();
        reclaim_stale_container_log(&st, &id("l1"), &rec).expect("ok");
        assert_eq!(t.names(), before);
        assert_eq!(stats(&rec), Some((0, 1)));
    }
}
