//! fandhe-container-oci: OCI イメージ管理（pull・キャッシュ・`image ls`/`rm`/`tag`）。
//!
//! 実装済み: レジストリクライアント基盤（TASK-51.1・OCI-1・#400）。構造化エラー型（`error`。ERR-1）、
//! イメージ参照の検証と正規化（`reference`）、接続先 URL の組み立てと TLS 設定済み HTTP `Agent` の構築
//! （`registry`・`tls`）。
//!
//! 実装済み: 匿名トークン取得（TASK-51.2・OCI-1・MS-4・#401。`auth` と `RegistryClient::authenticate_anonymous`）。
//! トークンのキャッシュ・再取得は未実装。
//!
//! 実装済み: Basic 認証（TASK-54.1・OCI-3・MS-4・#416。`auth::BasicCredentials` と
//! `RegistryClient::authenticate_basic`。`RegistryAuth::Basic` を manifest / blob 取得へ渡せる）。
//! 資格情報つき Bearer トークン交換 `authenticate_bearer`（TASK-54.2・OCI-3・#417）も持つ。OAuth2 の POST フローは未実装。
//!
//! 実装済み: チャレンジに応じて Basic / Bearer を自動選択する統一入口 `RegistryClient::authenticate`
//! （TASK-54.3・OCI-3・MS-4・#418）。認証 → manifest → blob の一連の pull が通る。
//!
//! 実装済み: manifest の取得・パースと platform 解決（TASK-51.3・OCI-1・MS-4・#402。`manifest` と
//! `RegistryClient::fetch_manifest`）。取得した manifest は本文 digest 未検証（突合は未実装）。
//!
//! 実装済み: blob のストリーミング取得（TASK-51.4・OCI-1・MS-4・#403。`RegistryClient::fetch_blob`。
//! サイズ上限・`Content-Length` 検証・CDN リダイレクトの手動追従）。取得した blob は `fetch_blob` 自体では digest 未検証。
//!
//! 実装済み: 取得済み blob の sha256 digest 検証（TASK-52.1・OCI-1・MS-4・#405。`layer::verify_blob_digest`）。
//! `fetch_blob` への組み込みと manifest 本文の digest 突合は未実装。
//!
//! 実装済み: レイヤー blob の gzip 展開（TASK-52.2・OCI-1・MS-4・#407。`layer::decompress_layer_to_writer`・
//! `layer::GzipLayerReader`）。展開後サイズの上限を必須引数とし、超過で中断する（decompression bomb 対策）。
//! 展開後 tar の diff_id 検証は未実装。
//!
//! 実装済み: レイヤー tar のルート配下への安全な展開（TASK-52.3・OCI-1・MS-4・#409。`layer::extract`）。
//! パス検証、ルートに閉じ込めた symlink 解決、hardlink の制限、エントリ数・累積サイズの上限を持つ。
//! 展開先 FS が別表記（大文字小文字・Unicode 正規化）を既存の実体へ解決する名前は、変更操作の前に
//! `AlreadyExists` で拒否する（IO-5）。
//! 複数レイヤーは `layer::extract::extract_layers` / `extract_layer_blobs` で下位から同一ルートへ重ねて展開する
//! （TASK-52.4・OCI-1・#410）。
//! whiteout（`.wh.<name>`）と不透明ディレクトリ（`.wh..wh..opq`）は展開パイプラインへ統合済みで、上位レイヤーが
//! 下位レイヤーの実体だけを消す（レイヤーごとに収集・適用・展開の 3 パスで、tar 内の並び順に依らない。既存パスは
//! image-spec の「Changeset over existing files」に従い置き換える。TASK-53.1〜53.3・OCI-1・OCI-2・#412〜#414。
//! `whiteout`・`layer::extract`）。
//! 未実装: ディレクトリ fd 起点の解決（TOCTOU 対策）、uid / gid 写像（SEC-5）、通常ファイルの
//! setuid / setgid / sticky の保持（所有者の写像が入るまで落とし、件数を結果に返す。SEC-5）、綴りの畳み込みによる
//! 名前衝突の検出（展開先 FS が区別する別表記は衝突として扱わない。IO-5）。
//!
//! 未実装（スタブではなく後続 issue の担当）: キャッシュ・`image ls`/`rm`/`tag`（TASK-52〜55・TASK-183〜184）。`RegistryClient` の通信は匿名トークン取得・
//! manifest 取得・blob 取得のみ。
//! 実装済み: ローカルイメージ管理の参照テーブルのデータ構造と登録・解除・カウント API（TASK-183.1・OCI-7・MS-4・#472。
//! `image_management`）。排他・永続化・GC・`image ls`/`rm`/`tag`/`prune` の CLI 経路は未実装。
//! PLUG-1 区分は core（crate-naming.md）。

pub mod auth;
pub mod error;
pub mod image_management;
pub mod instrument;
pub mod layer;
pub mod manifest;
pub mod reference;
pub mod registry;
mod tls;
mod whiteout;
