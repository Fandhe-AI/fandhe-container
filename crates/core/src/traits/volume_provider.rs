//! `VolumeProvider` 拡張点トレイト（TASK-4.4・CRI-7・PLUG-1・D-14・MS-0）。
//!
//! ## core 側に実装を置く理由（PLUG-1・D-14）
//!
//! `ContainerRuntime`・`NetworkPlugin` は別プロセス plugin（UDS 境界）に実装を置き、
//! `StateStore` は core に既定実装を持ちつつ plugin で差し替え可能にする。これに対して
//! `VolumeProvider` は、トレイト定義・実装ともに本 crate（core）側に固定し、差し替え用の
//! plugin 境界を持たない。理由は、このトレイトがデータパス（ファイル I/O）に直結するため
//! である。plugin 境界（別プロセス＋UDS の RPC 往復）をデータパスに置くと、io crate が
//! 提供するバッチ write-back・フラッシュバリア（IO-1・IO-2）による I/O 改善を IPC の
//! オーバーヘッドが侵食してしまう（D-14「plugin 境界をデータパスに置かない」）。
//!
//! 具体的な見積もりは PoC-13（机上見積もり）による。PoC-2 の batch 比で、境界を
//! gRPC にした場合は 17.62%、UDS＋長さ接頭辞フレームにした場合でも 3.71% の劣化になる。
//! この劣化を避けるため、`VolumeProvider` はデータパスと同一プロセス（core）で動作する
//! ボリュームのライフサイクル（create/remove/inspect）とコンテナへの接続
//! （attach/detach）だけを抽象化する。read/write/flush 等のデータプレーン操作は本トレイト
//! に載せず、io crate の共有プロトコル（IO-1 のバッチ write-back、IO-2 の FLUSH バリア）を
//! 呼び出し側が直接使う。ACK・FLUSH ACK の保証範囲（IO-1・IO-2）は実装側が満たす契約として
//! 参照するのみで、本トレイト自身はそれを保証しない。
//!
//! ## REPAIR-3（実装済みを装わない）
//!
//! 本 crate には現時点で `VolumeProvider` の core 側実装がない。実装を担当する TASK は
//! `05-tasks.md` に明示されておらず、将来の I/O 層統合（io crate との結線）で実装する。
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない。

use std::fmt;
use std::path::PathBuf;

use super::types::{ContainerId, ErrorCode, TraitError};

/// [`VolumeName`] の許容バイト数の上限（[`super::types::ContainerId`] と同じ
/// NAME_MAX 相当の基準に合わせる。ボリューム管理領域のパス要素として使うため）。
const VOLUME_NAME_MAX_LEN: usize = 255;

/// ゲスト内マウント先パス（[`GuestPath`]）の許容バイト数の上限（PATH_MAX 相当）。
const GUEST_PATH_MAX_LEN: usize = 4096;

/// ボリューム操作（create/remove/inspect/attach/detach）とコンテナへの接続を抽象化する
/// 拡張点。データプレーン（read/write/flush）は持たない（io crate の責務）。
///
/// # 契約
/// 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）。
/// 2. 相手の応答を待つ処理（下位ストレージ I/O 等）は無期限に待たず、上限時間を超えたら
///    [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の決定は実装側の責務であり、
///    本トレイトは契約のみを定める。
/// 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn VolumeProvider>` として複数スレッドから
///    共有できることを前提にしてよい。
/// 4. 他の 3 トレイトと異なり、`VolumeProvider` は plugin 境界を持たない（モジュール doc の
///    「core 側に実装を置く理由」を参照）。plugin 経由でデータパスへ到達する経路を作らない。
///
/// メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。dyn 互換
/// （object safety）を保ち、async ランタイムへの依存を追加しない（依存最小方針）。
///
/// パスの大文字小文字非区別・260 文字超・Unicode 正規化の差（IO-5）の吸収は実装側の責務で
/// あり、本トレイトが要求する型（[`VolumeName`]・[`GuestPath`]）は文字集合・長さ・
/// トラバーサル要素の形式検証のみを行う。
pub trait VolumeProvider: Send + Sync {
    /// 新しいボリュームを作る。
    ///
    /// 前提: 同名のボリュームが存在しないこと。存在する場合は [`ErrorCode::AlreadyExists`]
    /// を返す。
    fn create(&self, req: &VolumeCreateRequest) -> Result<VolumeInfo, TraitError>;

    /// ボリュームを削除する。
    ///
    /// 前提: 対象ボリュームが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// いずれかのコンテナから attach 中であり、かつ [`VolumeRemoveRequest::force`] が false
    /// の場合は [`ErrorCode::FailedPrecondition`] を返す。
    fn remove(&self, req: &VolumeRemoveRequest) -> Result<VolumeRemoveResponse, TraitError>;

    /// ボリュームの情報を照会する。
    ///
    /// 前提: 対象ボリュームが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    fn inspect(&self, req: &VolumeInspectRequest) -> Result<VolumeInfo, TraitError>;

    /// ボリュームをコンテナのゲスト内パスへ接続する。
    ///
    /// 前提: 対象ボリュームが作成済みであること。存在しなければ [`ErrorCode::NotFound`] を
    /// 返す。同一コンテナ・同一 [`GuestPath`] への二重 attach は [`ErrorCode::AlreadyExists`]
    /// を返す。
    fn attach(&self, req: &VolumeAttachRequest) -> Result<VolumeAttachment, TraitError>;

    /// ボリュームをコンテナから切り離す。
    ///
    /// 前提: 対象の attach が存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    fn detach(&self, req: &VolumeDetachRequest) -> Result<VolumeDetachResponse, TraitError>;
}

/// 検証済みのボリューム名。
///
/// provider が管理するボリューム領域のパス要素（管理ディレクトリ名等）になるため、
/// [`super::types::ContainerId`] と同じ規則（`[A-Za-z0-9._-]` のみ、空・`.`・`..` を拒否、
/// 255 バイト以下）で検証し、パストラバーサルを型のレベルで排除する。`ContainerId` とは
/// 意味が異なるため、別名にはせず独立した型として定義する。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumeName(String);

impl VolumeName {
    /// 入力文字列を検証してボリューム名を作る。
    ///
    /// 拒否条件（いずれかに該当すると `ErrorCode::InvalidArgument`）:
    /// - 空文字列、`.`、`..`
    /// - 長さが `VOLUME_NAME_MAX_LEN`（255 バイト）を超える
    /// - `[A-Za-z0-9._-]` 以外の文字を含む（`/`・`\`・NUL・空白・非 ASCII を含む）
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() || value == "." || value == ".." {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "volume name must not be empty, \".\", or \"..\"",
            ));
        }
        if value.len() > VOLUME_NAME_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("volume name must be at most {VOLUME_NAME_MAX_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "volume name must match [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for VolumeName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for VolumeName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// コンテナ内（ゲスト Linux 内）のマウント先を表す検証済み絶対パス。
///
/// `PathBuf` ではなく `String` を保持する。コンテナ本体はホスト OS（macOS / Windows /
/// Linux）が何であってもゲストの Linux 内で動作する前提のため（OCI-5 の (4)。
/// [`super::container_runtime::Signal`] が Linux のシグナル番号をそのまま使う理由と同じ）、
/// マウント先パスは常に POSIX 形式（`/` 区切り・先頭 `/`）で表現する必要がある。Windows
/// ホストで `std::path::Path::is_absolute()` を使うと `/data` は絶対パスと判定されず、
/// 3 OS CI が壊れる。coding-rust.md が定める「パスは `PathBuf` で組み立てる」原則の例外
/// として、ゲスト内パスに限りここで `String` ベースの検証済み型を用いる。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuestPath(String);

impl GuestPath {
    /// 入力文字列を検証してゲスト内パスを作る。
    ///
    /// 拒否条件（いずれかに該当すると `ErrorCode::InvalidArgument`）:
    /// - `/` で始まらない（絶対パスでない）
    /// - NUL バイトを含む
    /// - `..` 要素を含む（パストラバーサル）
    /// - 長さが `GUEST_PATH_MAX_LEN`（4096 バイト）を超える
    ///
    /// symlink の解決や rootfs 配下であることの最終確認は実装側（将来）の責務であり、
    /// ここでは形式検証のみを行う（実装済みを装わない。REPAIR-3）。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if !value.starts_with('/') {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "guest path must be absolute (start with \"/\")",
            ));
        }
        if value.contains('\0') {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "guest path must not contain a NUL byte",
            ));
        }
        if value.split('/').any(|segment| segment == "..") {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "guest path must not contain a \"..\" segment",
            ));
        }
        if value.len() > GUEST_PATH_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("guest path must be at most {GUEST_PATH_MAX_LEN} bytes"),
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for GuestPath {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for GuestPath {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// ボリュームの接続元（provider 管理のボリューム、またはホストの絶対パスの bind マウント）。
///
/// フィールドを直接公開せず、[`VolumeSource::named`]・[`VolumeSource::bind`] を通してのみ
/// 作れるようにすることで、`Bind` の相対パスといった未検証の値の混入を防ぐ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VolumeSource {
    /// provider が管理する名前付きボリューム（例: io-share ドライバ）。
    Named(VolumeName),
    /// ホストの絶対パスを直接マウントする bind マウント。
    Bind(PathBuf),
}

impl VolumeSource {
    /// 名前付きボリュームを指す接続元を作る。
    pub fn named(name: VolumeName) -> Self {
        Self::Named(name)
    }

    /// ホストの絶対パスを指す bind マウントの接続元を作る。
    ///
    /// `path` が絶対パスでない場合は [`ErrorCode::InvalidArgument`] を返す（fail-closed。
    /// [`super::container_runtime::CreateRequest::new`] が bundle パスに課す制約と同じ理由で、
    /// 相対パスは plugin プロセスとの作業ディレクトリの違いにより解決先が曖昧になる）。
    pub fn bind(path: PathBuf) -> Result<Self, TraitError> {
        if !path.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bind mount host path must be absolute",
            ));
        }
        Ok(Self::Bind(path))
    }
}

/// ボリュームのアクセスモード。既定値は持たず、呼び出し側に明示させる（最小権限。
/// [`super::container_runtime::StopRequest`] が `grace` を必須にするのと同じ方針）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessMode {
    /// 読み取り専用でマウントする。
    ReadOnly,
    /// 読み書き可能でマウントする。
    ReadWrite,
}

/// [`VolumeProvider::create`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VolumeCreateRequest {
    name: VolumeName,
}

impl VolumeCreateRequest {
    /// ボリューム名から要求を作る。
    pub fn new(name: VolumeName) -> Self {
        Self { name }
    }

    /// 対象ボリューム名を返す。
    pub fn name(&self) -> &VolumeName {
        &self.name
    }
}

/// [`VolumeProvider::remove`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VolumeRemoveRequest {
    name: VolumeName,
    force: bool,
}

impl VolumeRemoveRequest {
    /// ボリューム名から要求を作る（`force` は既定で false）。
    pub fn new(name: VolumeName) -> Self {
        Self { name, force: false }
    }

    /// `force` を指定したビルダ。true の場合、attach 中でも切り離してから削除する。
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// 対象ボリューム名を返す。
    pub fn name(&self) -> &VolumeName {
        &self.name
    }

    /// 強制削除が指定されているかを返す。
    pub fn force(&self) -> bool {
        self.force
    }
}

/// [`VolumeProvider::inspect`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VolumeInspectRequest {
    name: VolumeName,
}

impl VolumeInspectRequest {
    /// ボリューム名から要求を作る。
    pub fn new(name: VolumeName) -> Self {
        Self { name }
    }

    /// 対象ボリューム名を返す。
    pub fn name(&self) -> &VolumeName {
        &self.name
    }
}

/// [`VolumeProvider::attach`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeAttachRequest {
    container_id: ContainerId,
    source: VolumeSource,
    destination: GuestPath,
    access_mode: AccessMode,
}

impl VolumeAttachRequest {
    /// 対象コンテナ・接続元・ゲスト内マウント先・アクセスモードから要求を作る
    /// （いずれも必須引数とし、既定値を持たせない）。
    pub fn new(
        container_id: ContainerId,
        source: VolumeSource,
        destination: GuestPath,
        access_mode: AccessMode,
    ) -> Self {
        Self {
            container_id,
            source,
            destination,
            access_mode,
        }
    }

    /// 対象コンテナの ID を返す。
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// 接続元を返す。
    pub fn source(&self) -> &VolumeSource {
        &self.source
    }

    /// ゲスト内マウント先を返す。
    pub fn destination(&self) -> &GuestPath {
        &self.destination
    }

    /// アクセスモードを返す。
    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }
}

/// [`VolumeProvider::detach`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VolumeDetachRequest {
    container_id: ContainerId,
    destination: GuestPath,
}

impl VolumeDetachRequest {
    /// 対象コンテナとゲスト内マウント先から要求を作る。
    pub fn new(container_id: ContainerId, destination: GuestPath) -> Self {
        Self {
            container_id,
            destination,
        }
    }

    /// 対象コンテナの ID を返す。
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// ゲスト内マウント先を返す。
    pub fn destination(&self) -> &GuestPath {
        &self.destination
    }
}

/// ボリュームの情報。真偽値やフラットな文字列ではなく、将来の拡張（サイズ・ドライバ種別等）
/// に備えて構造化された型にする（coding-rust.md）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VolumeInfo {
    name: VolumeName,
}

impl VolumeInfo {
    /// ボリューム名から情報を作る。
    pub fn new(name: VolumeName) -> Self {
        Self { name }
    }

    /// ボリューム名を返す。
    pub fn name(&self) -> &VolumeName {
        &self.name
    }
}

/// [`VolumeProvider::attach`] の応答。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeAttachment {
    container_id: ContainerId,
    destination: GuestPath,
    access_mode: AccessMode,
}

impl VolumeAttachment {
    /// 接続先コンテナ・ゲスト内マウント先・アクセスモードから応答を作る。
    pub fn new(container_id: ContainerId, destination: GuestPath, access_mode: AccessMode) -> Self {
        Self {
            container_id,
            destination,
            access_mode,
        }
    }

    /// 接続先コンテナの ID を返す。
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    /// ゲスト内マウント先を返す。
    pub fn destination(&self) -> &GuestPath {
        &self.destination
    }

    /// アクセスモードを返す。
    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }
}

/// [`VolumeProvider::remove`] の応答。当面は空だが、将来の拡張（解放した資源の情報等）に
/// 備えて構造体にする。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeRemoveResponse {}

impl VolumeRemoveResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

/// [`VolumeProvider::detach`] の応答。当面は空だが、将来の拡張に備えて構造体にする。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeDetachResponse {}

impl VolumeDetachResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// テスト用のスタブ実装。dyn 互換性と各メソッドの戻り値を確認するためのみに使う。
    struct StubVolumeProvider;

    impl VolumeProvider for StubVolumeProvider {
        fn create(&self, req: &VolumeCreateRequest) -> Result<VolumeInfo, TraitError> {
            Ok(VolumeInfo::new(req.name().clone()))
        }

        fn remove(&self, req: &VolumeRemoveRequest) -> Result<VolumeRemoveResponse, TraitError> {
            if !req.force() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "volume is still attached",
                ));
            }
            Ok(VolumeRemoveResponse::new())
        }

        fn inspect(&self, req: &VolumeInspectRequest) -> Result<VolumeInfo, TraitError> {
            Ok(VolumeInfo::new(req.name().clone()))
        }

        fn attach(&self, req: &VolumeAttachRequest) -> Result<VolumeAttachment, TraitError> {
            Ok(VolumeAttachment::new(
                req.container_id().clone(),
                req.destination().clone(),
                req.access_mode(),
            ))
        }

        fn detach(&self, req: &VolumeDetachRequest) -> Result<VolumeDetachResponse, TraitError> {
            let _ = req;
            Ok(VolumeDetachResponse::new())
        }
    }

    fn sample_container_id() -> ContainerId {
        ContainerId::new("sample-container").expect("valid id")
    }

    fn sample_volume_name() -> VolumeName {
        VolumeName::new("sample-volume").expect("valid name")
    }

    #[cfg(unix)]
    fn sample_host_path() -> PathBuf {
        PathBuf::from("/srv/x")
    }

    #[cfg(windows)]
    fn sample_host_path() -> PathBuf {
        PathBuf::from(r"C:\x")
    }

    /// PLUG-1: `VolumeProvider` は dyn 互換で、`Box`/`Arc` に収めて
    /// create → attach → detach → remove の一連を呼べる。戻り値は具体値で確認する。
    #[test]
    fn plug1_volume_provider_is_dyn_compatible() {
        let boxed: Box<dyn VolumeProvider> = Box::new(StubVolumeProvider);
        let name = sample_volume_name();
        let info = boxed
            .create(&VolumeCreateRequest::new(name.clone()))
            .expect("create succeeds");
        assert_eq!(info.name().as_str(), "sample-volume");

        let shared: Arc<dyn VolumeProvider> = Arc::new(StubVolumeProvider);
        let destination = GuestPath::new("/data").expect("valid guest path");
        let attach_req = VolumeAttachRequest::new(
            sample_container_id(),
            VolumeSource::named(name.clone()),
            destination.clone(),
            AccessMode::ReadWrite,
        );
        let attachment = shared.attach(&attach_req).expect("attach succeeds");
        assert_eq!(attachment.container_id().as_str(), "sample-container");
        assert_eq!(attachment.destination().as_str(), "/data");
        assert_eq!(attachment.access_mode(), AccessMode::ReadWrite);

        let detach_req = VolumeDetachRequest::new(sample_container_id(), destination);
        assert_eq!(
            shared.detach(&detach_req).expect("detach succeeds"),
            VolumeDetachResponse::new()
        );

        let removed = shared
            .remove(&VolumeRemoveRequest::new(name).with_force(true))
            .expect("force remove succeeds");
        assert_eq!(removed, VolumeRemoveResponse::new());
    }

    /// CRI-7: 受理される VolumeName の例（英数字・区切り記号・境界長）。
    #[test]
    fn cri7_volume_name_accepts_valid_values() {
        assert_eq!(VolumeName::new("abc").unwrap().as_str(), "abc");
        assert_eq!(VolumeName::new("a-b_c.1").unwrap().as_str(), "a-b_c.1");
        let max_len = "a".repeat(255);
        assert!(VolumeName::new(max_len).is_ok());
    }

    /// CRI-7: 拒否される VolumeName の例（空・トラバーサル・区切り文字・空白・NUL・
    /// 非 ASCII・長さ超過）。
    #[test]
    fn cri7_volume_name_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            ".".to_string(),
            "..".to_string(),
            "a/b".to_string(),
            "a\\b".to_string(),
            "a b".to_string(),
            "a\0b".to_string(),
            "é".to_string(),
            "a".repeat(256),
        ];
        for case in cases {
            let err = VolumeName::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// IO-5: GuestPath は絶対パスのみを受理し、相対パス・トラバーサル・NUL・長さ超過を
    /// 拒否する。OS 分岐を持たず、3 OS すべてで同じ結果になることを確認する対象。
    #[test]
    fn cri7_guest_path_validation() {
        assert_eq!(GuestPath::new("/data").unwrap().as_str(), "/data");
        assert_eq!(GuestPath::new("/a/b.c").unwrap().as_str(), "/a/b.c");
        let max_len = format!("/{}", "a".repeat(GUEST_PATH_MAX_LEN - 1));
        assert_eq!(max_len.len(), GUEST_PATH_MAX_LEN);
        assert!(GuestPath::new(max_len).is_ok());

        let cases: Vec<String> = vec![
            "data".to_string(),
            String::new(),
            "/a/../b".to_string(),
            "/..".to_string(),
            "/a\0b".to_string(),
            format!("/{}", "a".repeat(GUEST_PATH_MAX_LEN)),
        ];
        for case in cases {
            let err = GuestPath::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// PLUG-1: `VolumeSource::bind` は相対パスを拒否し、ホストの絶対パスは受理する。
    #[test]
    fn cri7_volume_source_bind_rejects_relative_host_path() {
        let err = VolumeSource::bind(PathBuf::from("relative"))
            .expect_err("relative path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        assert!(VolumeSource::bind(sample_host_path()).is_ok());
    }

    /// CRI-7: `remove` が使用中判定で `FAILED_PRECONDITION` を返す。
    #[test]
    fn cri7_volume_remove_in_use_returns_failed_precondition() {
        let provider = StubVolumeProvider;
        let err = provider
            .remove(&VolumeRemoveRequest::new(sample_volume_name()))
            .expect_err("must fail without force");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
    }

    /// CRI-7: `VolumeName` の `TryFrom<&str>`/`TryFrom<String>` は `new` と同じ検証結果を返す。
    #[test]
    fn cri7_volume_name_try_from_matches_new() {
        let name = VolumeName::try_from("abc").expect("valid name");
        assert_eq!(name.as_str(), "abc");

        let err = VolumeName::try_from("a/b".to_string()).expect_err("must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");
    }
}
