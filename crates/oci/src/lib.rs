//! fandhe-container-oci: OCI イメージ管理（pull・キャッシュ・`image ls`/`rm`/`tag`）。
//!
//! 実装済み: レジストリクライアント基盤（TASK-51.1・OCI-1・#400）。構造化エラー型（`error`。ERR-1）、
//! イメージ参照の検証と正規化（`reference`）、接続先 URL の組み立てと TLS 設定済み HTTP `Agent` の構築
//! （`registry`・`tls`）。
//!
//! 未実装（スタブではなく後続 issue の担当）: トークン取得と `WWW-Authenticate` 解析（#401）、manifest の
//! 取得とパース（#402）、blob のストリーミング取得と上限検証（#403）、digest 検証（#405）、キャッシュ・
//! `image ls`/`rm`/`tag`（TASK-52〜55・TASK-183〜184）。`RegistryClient` はまだ通信する公開メソッドを持たない。
//! PLUG-1 区分は core（crate-naming.md）。

pub mod error;
pub mod reference;
pub mod registry;
mod tls;
