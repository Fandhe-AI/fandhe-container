//! ゲスト相対パスの構文規則を 1 か所に集めた検証済み newtype [`GuestPath`]
//! （IO-5・REPAIR-2・IO-1。`docs/design/io-protocol.md` の F5・#3159）。
//!
//! # 役割
//! 「ゲスト相対パス」（`/` 区切りの UTF-8 文字列）の構文検証をこの型の
//! [`GuestPath::parse`] だけに置く。検証を通らない値は作れないため、受け取る側は
//! 再検証せずに済む（REPAIR-2）。OS に依存しない純関数で、`std::path::Path` も
//! ファイルシステムも使わない。
//!
//! # 呼び出し文脈
//! 現状の利用者は [`crate::guest_files::GuestFileCreator::create_file`]。ワイヤー
//! ペイロードの復号（`payload::decode_create`。#3161 で実装済み）は長さと UTF-8 だけを
//! 見て、構文検証（本型の `parse`）は呼ばず呼び出し側に委ねる。同じ関数で検証する予定なのは
//! `PipelineClient::create`（#3162）とサーバーのディスパッチ時の Nack（`INVALID_ARGUMENT`。
//! #3163）で、本モジュールはその土台である（どちらも未実装。REPAIR-3）。
//!
//! # 検証の層の分担
//! 復号時は長さと UTF-8 だけ、構文は本型、IO-5 の大文字小文字衝突とホストパス長
//! （260 文字）は `GuestFileCreator` 側が担う。なお `fandhe-container-core` の
//! `traits::volume_provider::GuestPath`（コンテナ内の絶対パス）とは別物である。

use std::fmt;

use crate::error::{IoError, IoErrorCode};

/// ゲスト相対パス全体のバイト長の上限（Linux の PATH_MAX 相当）。暫定値で、校正は
/// TASK-88（F5・#1886。IO-5・REPAIR-2）。
pub const MAX_GUEST_PATH_BYTES: usize = 4096;

/// ゲスト相対パスのコンポーネント数の上限。暫定値で、校正は TASK-88
/// （F5・#1886。IO-5・REPAIR-2）。
pub const MAX_GUEST_PATH_COMPONENTS: usize = 256;

/// 1 コンポーネントのバイト長（UTF-8）の上限（主要ファイルシステムの NAME_MAX）。
/// 暫定値で、校正は TASK-88（F5・#1886。IO-5・REPAIR-2）。
pub const MAX_GUEST_NAME_BYTES: usize = 255;

/// [`GuestPath::parse`] が拒否した規則（規則ごとに 1 変種）。後続のサーバーが文字列を
/// 照合せずに Nack の reason へ写せるよう列挙型にする（#3163）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuestPathError {
    /// 空文字列。
    Empty,
    /// 全体が [`MAX_GUEST_PATH_BYTES`] を超える。
    TooLong,
    /// NUL を含む。
    ContainsNul,
    /// 先頭が `/`（絶対パス）。
    Absolute,
    /// コンポーネント数が [`MAX_GUEST_PATH_COMPONENTS`] を超える。
    TooManyComponents,
    /// 空のコンポーネント（`a//b`・末尾の `/`）。
    EmptyComponent,
    /// `.` または `..` のコンポーネント。
    DotComponent,
    /// コンポーネントに `\` または `:` を含む（Windows の区切り・ドライブ・ADS）。
    ForbiddenChar,
    /// コンポーネントが [`MAX_GUEST_NAME_BYTES`] を超える。
    NameTooLong,
}

impl GuestPathError {
    /// 固定の英語メッセージ（入力パスは含めない。F10）。
    fn message(self) -> &'static str {
        match self {
            Self::Empty => "guest path is empty",
            Self::TooLong => "guest path is too long",
            Self::ContainsNul | Self::ForbiddenChar => {
                "guest path component must not contain '\\', ':' or NUL"
            }
            Self::Absolute => "guest path must be relative (must not start with '/')",
            Self::TooManyComponents => "guest path has too many components",
            Self::EmptyComponent | Self::DotComponent => {
                "guest path component must be a single normal name"
            }
            Self::NameTooLong => "guest path component is too long",
        }
    }
}

impl fmt::Display for GuestPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for GuestPathError {}

impl From<GuestPathError> for IoError {
    fn from(err: GuestPathError) -> Self {
        IoError::new(IoErrorCode::InvalidArgument, err.message())
    }
}

/// 構文検証済みのゲスト相対パス（モジュール doc 参照）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuestPath(String);

impl GuestPath {
    /// `path` を検証して作る。上限（長さ → 件数 → 名前長）はアロケーションの前に
    /// 見る。通ったときだけ 4096 バイト以下の `String` を確保する。
    pub fn parse(path: &str) -> Result<Self, GuestPathError> {
        if path.len() > MAX_GUEST_PATH_BYTES {
            return Err(GuestPathError::TooLong);
        }
        if path.is_empty() {
            return Err(GuestPathError::Empty);
        }
        if path.contains('\0') {
            return Err(GuestPathError::ContainsNul);
        }
        if path.starts_with('/') {
            return Err(GuestPathError::Absolute);
        }
        let mut count = 0usize;
        for component in path.split('/') {
            count = count.saturating_add(1);
            if count > MAX_GUEST_PATH_COMPONENTS {
                return Err(GuestPathError::TooManyComponents);
            }
            if component.is_empty() {
                return Err(GuestPathError::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(GuestPathError::DotComponent);
            }
            if component.contains(['\\', ':']) {
                return Err(GuestPathError::ForbiddenChar);
            }
            if component.len() > MAX_GUEST_NAME_BYTES {
                return Err(GuestPathError::NameTooLong);
            }
        }
        Ok(Self(path.to_owned()))
    }

    /// 検証済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `/` で区切ったコンポーネント（すべて非空の通常名）。
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl AsRef<str> for GuestPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(p: &str) -> Vec<String> {
        GuestPath::parse(p)
            .expect("accepted")
            .components()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn io5_repair2_parse_accepts_normal_relative_paths() {
        for p in ["a", "a/b/c.txt", "日本語/ファイル", ".hidden", "...", "a b"] {
            let g = GuestPath::parse(p).expect("accepted");
            assert_eq!(g.as_str(), p);
        }
        assert_eq!(comps("a/b/c.txt"), ["a", "b", "c.txt"]);
        assert_eq!(comps("日本語/ファイル"), ["日本語", "ファイル"]);
    }

    #[test]
    fn io5_repair2_parse_rejects_each_syntax_rule() {
        let cases = [
            ("", GuestPathError::Empty),
            ("/abs", GuestPathError::Absolute),
            ("a//b", GuestPathError::EmptyComponent),
            ("a/", GuestPathError::EmptyComponent),
            (".", GuestPathError::DotComponent),
            ("..", GuestPathError::DotComponent),
            ("a/./b", GuestPathError::DotComponent),
            ("a/../b", GuestPathError::DotComponent),
            ("a\\b", GuestPathError::ForbiddenChar),
            ("C:x", GuestPathError::ForbiddenChar),
            ("a:b", GuestPathError::ForbiddenChar),
            ("a\0b", GuestPathError::ContainsNul),
        ];
        for (input, want) in cases {
            assert_eq!(GuestPath::parse(input), Err(want), "input {input:?}");
        }
    }

    #[test]
    fn io5_repair2_path_length_boundary() {
        // 255 バイト名 15 個 + 254 バイト名 + "y"（17 コンポーネント・区切り 16）で 4096 バイト。
        let mut names = vec!["n".repeat(MAX_GUEST_NAME_BYTES); 15];
        names.push("m".repeat(254));
        names.push("y".to_owned());
        let exact = names.join("/");
        assert_eq!(exact.len(), MAX_GUEST_PATH_BYTES);
        assert!(GuestPath::parse(&exact).is_ok());
        let over = format!("{exact}y");
        assert_eq!(over.len(), MAX_GUEST_PATH_BYTES + 1);
        assert_eq!(GuestPath::parse(&over), Err(GuestPathError::TooLong));
        let single = "x".repeat(MAX_GUEST_PATH_BYTES);
        assert_eq!(GuestPath::parse(&single), Err(GuestPathError::NameTooLong));
    }

    #[test]
    fn io5_repair2_component_count_boundary() {
        let ok = vec!["a"; MAX_GUEST_PATH_COMPONENTS].join("/");
        assert!(GuestPath::parse(&ok).is_ok());
        let bad = vec!["a"; MAX_GUEST_PATH_COMPONENTS + 1].join("/");
        assert_eq!(
            GuestPath::parse(&bad),
            Err(GuestPathError::TooManyComponents)
        );
    }

    #[test]
    fn io5_repair2_name_length_boundary() {
        assert!(GuestPath::parse(&"a".repeat(255)).is_ok());
        assert!(GuestPath::parse(&"あ".repeat(85)).is_ok()); // 255 バイト
        assert_eq!(
            GuestPath::parse(&"a".repeat(256)),
            Err(GuestPathError::NameTooLong)
        );
        // 86 文字（255 未満）でも 258 バイトで超過。
        assert_eq!(
            GuestPath::parse(&"あ".repeat(86)),
            Err(GuestPathError::NameTooLong)
        );
    }

    #[test]
    fn io5_repair2_accepted_components_are_single_normal_on_host() {
        use std::path::{Component, Path};
        for p in ["a/b/c.txt", "日本語/ファイル", ".hidden/...", "a b/c"] {
            for c in GuestPath::parse(p).expect("accepted").components() {
                let mut parts = Path::new(c).components();
                assert!(
                    matches!(
                        (parts.next(), parts.next()),
                        (Some(Component::Normal(_)), None)
                    ),
                    "component {c:?}"
                );
            }
        }
    }

    #[test]
    fn repair2_guest_path_error_maps_to_invalid_argument() {
        let all = [
            GuestPathError::Empty,
            GuestPathError::TooLong,
            GuestPathError::ContainsNul,
            GuestPathError::Absolute,
            GuestPathError::TooManyComponents,
            GuestPathError::EmptyComponent,
            GuestPathError::DotComponent,
            GuestPathError::ForbiddenChar,
            GuestPathError::NameTooLong,
        ];
        for e in all {
            let io: IoError = e.into();
            assert_eq!(io.code(), IoErrorCode::InvalidArgument);
            assert_eq!(io.message(), e.to_string());
        }
        let io: IoError = GuestPath::parse("secret-marker/../x").unwrap_err().into();
        assert!(!io.message().contains("secret-marker"));
    }

    #[test]
    fn io1_repair2_guest_path_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GuestPath>();
    }
}
