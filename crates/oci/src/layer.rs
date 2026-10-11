//! 取得済み blob の sha256 digest 検証（TASK-52.1・OCI-1・MS-4・#405）。
//!
//! `RegistryClient::fetch_blob`（TASK-51.4）が保存した blob はサイズ検証のみで、本文のハッシュは
//! descriptor の digest と未突合である。このモジュールはファイルを固定長バッファで読んで sha256 を計算し、
//! 参照 digest と完全一致しなければ `DataLoss` で拒否する（fail-closed。ソフトウェアとデータの完全性）。
//!
//! 呼び出し契約: layer 展開（TASK-52.x）やキャッシュ公開の前に、呼び出し側が本検証を通すこと。
//! 検証対象は呼び出し側が管理するステージング領域のファイルとし、パスはエラー文言に載せない。
//! 未実装（後続 issue）: `fetch_blob` 内への組み込み、manifest 本文の digest 突合、展開・キャッシュ格納。

use std::fmt::Write as _;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::error::{OciError, OciErrorCode};
use crate::reference::Digest;
use crate::registry::FetchedBlob;

/// 読み込みバッファ長（メモリ使用量を入力サイズに依存させない）。
const HASH_BUF_LEN: usize = 64 * 1024;

/// digest 検証に成功した blob（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedBlob {
    /// 本文から計算し、参照 digest と一致を確認した digest。
    pub digest: Digest,
    /// 読み取ったバイト数。
    pub size: u64,
}

/// `path` の blob の sha256 を計算し `expected` と比較する（OCI-1）。
///
/// `max_bytes` は読み取り上限で、呼び出し側は `descriptor.size` または `RegistryClientConfig::max_blob_bytes`
/// を渡す。超過は `ResourceExhausted`、不一致は `DataLoss`、通常ファイル以外は `InvalidArgument`。
pub fn verify_blob_digest(
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    let file = File::open(path).map_err(map_io_error)?;
    // 同一ハンドルで種別を確認する（FIFO 等で読みがブロックするのを避ける）。
    let meta = file.metadata().map_err(map_io_error)?;
    if !meta.is_file() {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "blob path is not a regular file",
        ));
    }
    let (hex, size) = sha256_hex_of_reader(file, max_bytes)?;
    let actual = format!("sha256:{hex}");
    if actual != expected.as_str() {
        return Err(OciError::new(
            OciErrorCode::DataLoss,
            "blob digest does not match the descriptor",
        ));
    }
    Ok(VerifiedBlob {
        digest: Digest::parse(&actual)?,
        size,
    })
}

/// `fetch_blob` の戻り値を、要求した digest に対して検証する薄いラッパー。
pub fn verify_fetched_blob(blob: &FetchedBlob, max_bytes: u64) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest(&blob.path, &blob.digest, max_bytes)
}

/// Reader を EOF まで読み、小文字 hex の sha256 と読み取りバイト数を返す。
fn sha256_hex_of_reader<R: Read>(mut r: R, max_bytes: u64) -> Result<(String, u64), OciError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io_error(e)),
        };
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "blob exceeds the size limit while hashing",
            ));
        }
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        // String への write は失敗しない。
        let _ = write!(hex, "{b:02x}");
    }
    Ok((hex, total))
}

/// I/O エラーを構造化エラーへ写す（パス・OS メッセージは載せない）。
fn map_io_error(e: std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::NotFound => OciError::new(OciErrorCode::NotFound, "blob file not found"),
        ErrorKind::PermissionDenied => {
            OciError::new(OciErrorCode::PermissionDenied, "blob file is not readable")
        }
        _ => OciError::new(OciErrorCode::Internal, "failed to read blob file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    const EMPTY: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MSG: &str = "blob digest does not match the descriptor";

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-oci-layer-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn digest_of(data: &[u8]) -> Digest {
        let (hex, _) = sha256_hex_of_reader(data, u64::MAX).unwrap();
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    /// OCI-1: 既知ベクタで一致する。
    #[test]
    fn oci1_known_vectors_match() {
        let d = tmp_dir("known");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 10).unwrap();
        assert_eq!(v.digest.as_str(), ABC);
        assert_eq!(v.size, 3);
        std::fs::write(&p, b"").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(EMPTY).unwrap(), 10).unwrap();
        assert_eq!(v.size, 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: 改ざん（書き換え・追記・切り詰め）は DataLoss。
    #[test]
    fn oci1_tampered_blob_is_rejected() {
        let d = tmp_dir("tamper");
        let p = d.join("b");
        let original = b"hello blob".to_vec();
        let expected = digest_of(&original);
        let mut flipped = original.clone();
        flipped[0] ^= 1;
        let mut appended = original.clone();
        appended.push(0);
        let truncated = original[..original.len() - 1].to_vec();
        for data in [flipped, appended, truncated] {
            std::fs::write(&p, &data).unwrap();
            let e = verify_blob_digest(&p, &expected, 1024).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss);
            assert_eq!(e.code().as_str(), "DATA_LOSS");
            assert_eq!(e.message(), MSG);
        }
        std::fs::write(&p, &original).unwrap();
        assert!(verify_blob_digest(&p, &expected, 1024).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: チャンク境界をまたぐ入力でも一貫する。
    #[test]
    fn oci1_multi_chunk_inputs() {
        let d = tmp_dir("chunks");
        let p = d.join("b");
        for len in [HASH_BUF_LEN, HASH_BUF_LEN + 1, HASH_BUF_LEN * 2] {
            let data = vec![0xa5u8; len];
            std::fs::write(&p, &data).unwrap();
            let v = verify_blob_digest(&p, &digest_of(&data), u64::MAX).unwrap();
            assert_eq!(v.size, len as u64);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_size_limit_exceeded() {
        let d = tmp_dir("limit");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let e = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 2).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 3).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_missing_and_directory_paths() {
        let d = tmp_dir("paths");
        let e = verify_blob_digest(&d.join("none"), &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        // ディレクトリは OS により open 自体が失敗するか通常ファイルでないとして拒否される。
        let e = verify_blob_digest(&d, &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert!(matches!(
            e.code(),
            OciErrorCode::InvalidArgument | OciErrorCode::PermissionDenied | OciErrorCode::Internal
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    struct Flaky {
        step: u8,
    }
    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.step += 1;
            match self.step {
                1 => Err(io::Error::from(ErrorKind::Interrupted)),
                2 => {
                    buf[..3].copy_from_slice(b"abc");
                    Ok(3)
                }
                _ => Ok(0),
            }
        }
    }

    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn oci1_interrupted_is_retried_and_other_errors_propagate() {
        let (hex, n) = sha256_hex_of_reader(Flaky { step: 0 }, 10).unwrap();
        assert_eq!(format!("sha256:{hex}"), ABC);
        assert_eq!(n, 3);
        let e = sha256_hex_of_reader(Broken, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Internal);
    }

    #[test]
    fn oci1_verify_fetched_blob() {
        let d = tmp_dir("fetched");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let mut blob = FetchedBlob {
            path: p.clone(),
            size: 3,
            digest: Digest::parse(ABC).unwrap(),
        };
        assert_eq!(verify_fetched_blob(&blob, 10).unwrap().size, 3);
        blob.digest = Digest::parse(EMPTY).unwrap();
        let e = verify_fetched_blob(&blob, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
