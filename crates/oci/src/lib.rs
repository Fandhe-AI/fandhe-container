//! fandhe-container-oci: OCI イメージ管理（pull・キャッシュ・`image ls`/`rm`/`tag`）。
//!
//! 実装済み: レジストリクライアント基盤（TASK-51.1・OCI-1・#400）。構造化エラー型（`error`。ERR-1）、
//! イメージ参照の検証と正規化（`reference`）、接続先 URL の組み立てと TLS 設定済み HTTP `Agent` の構築
//! （`registry`・`tls`）。
//!
//! 実装済み: 匿名トークン取得（TASK-51.2・OCI-1・MS-4・#401。`auth` と `RegistryClient::authenticate_anonymous`）。
//! 資格情報つき認証（OCI-3）とトークンのキャッシュ・再取得は未実装。
//!
//! 実装済み: manifest の取得・パースと platform 解決（TASK-51.3・OCI-1・MS-4・#402。`manifest` と
//! `RegistryClient::fetch_manifest`）。取得した manifest は digest 未検証（#405）。
//!
//! 未実装（スタブではなく後続 issue の担当）: blob のストリーミング取得と上限検証（#403）、digest 検証（#405）、
//! キャッシュ・`image ls`/`rm`/`tag`（TASK-52〜55・TASK-183〜184）。`RegistryClient` の通信は匿名トークン取得と
//! manifest 取得のみ。
//! PLUG-1 区分は core（crate-naming.md）。

pub mod auth;
pub mod error;
pub mod instrument;
pub mod manifest;
pub mod reference;
pub mod registry;
mod tls;
