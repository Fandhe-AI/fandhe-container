//! `create --unpack` の試験が使う、本物の pull 経路で作る多層イメージの fixture（OCI-7・OCI-1・OCI-2・#2377）。
//!
//! 外部依存を足さないため、tar は最小の ustar ヘッダを自前で組む（通常ファイルとディレクトリだけ。圧縮なし）。
//! イメージは oci の公開 API（`begin_pull` → `open_staged_blob` → `commit` → `verify_staged_blob` → `publish`）で
//! 在庫へ公開するので、layers の mediaType も本番の cri の pull と同じ形で載る。
//! cli の in-crate 試験（`image_unpack/tests.rs`）と結合試験（`binary_entry.rs`）が `#[path]` で共有する。
//!
//! 共有先ごとに使う項目が違う（Linux 専用の試験だけが使う項目は `cfg(target_os = "linux")` で限定する。REPAIR-12）。

use std::io::Write as _;

use fandhe_container_oci::image_management::{
    ImageStore, ManifestComposition, PullId, PullPublishRequest,
};
use fandhe_container_oci::reference::Digest;

/// 非圧縮 tar のレイヤーの mediaType。
pub const MEDIA_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// tar の 1 エントリ。
pub enum Entry<'a> {
    /// 通常ファイル（パス・内容）。`.wh.<name>` の名前で whiteout になる。
    File(&'a str, &'a [u8]),
    /// ディレクトリ（パス）。
    // Dir を作るのは Linux 専用の `three_layer_tars` だけ（macOS 向けの lib test では未構築になる）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Dir(&'a str),
}

fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    field[..width].copy_from_slice(text.as_bytes());
    field[width] = 0;
}

fn header(name: &str, size: u64, typeflag: u8, mode: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], mode);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(text.as_bytes());
    h
}

/// 非圧縮の ustar tar を作る。
pub fn tar_of(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        match e {
            Entry::File(name, data) => {
                out.extend_from_slice(&header(name, data.len() as u64, b'0', 0o644));
                out.extend_from_slice(data);
                out.resize(out.len().div_ceil(512) * 512, 0);
            }
            Entry::Dir(name) => {
                let dir = format!("{}/", name.trim_end_matches('/'));
                out.extend_from_slice(&header(&dir, 0, b'5', 0o755));
            }
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// 公開済みのイメージ。
// `config`・`layers` は `#[path]` の共有先の一部（結合試験 `binary_entry.rs`）が読まない。
#[allow(dead_code)]
pub struct SeededImage {
    pub manifest: Digest,
    pub config: Digest,
    pub layers: Vec<Digest>,
}

/// `tars`（各レイヤーの非圧縮 tar。下位から順）を持つイメージを本物の pull 経路で公開する。
///
/// - `corrupt_diff_id`: そのレイヤーの config の `diff_id` を別の値にする（展開中の diff_id 突合の失敗を再現する）
/// - `record_media_types`: false なら mediaType を在庫へ載せない（v1 の在庫・旧経路の登録を再現する）
pub fn seed_image(
    store: &ImageStore,
    pull_id: &str,
    tars: &[Vec<u8>],
    corrupt_diff_id: Option<usize>,
    record_media_types: bool,
) -> SeededImage {
    let diff_ids: Vec<String> = tars
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if corrupt_diff_id == Some(i) {
                Digest::sha256_of(b"not the layer").as_str().to_owned()
            } else {
                Digest::sha256_of(t).as_str().to_owned()
            }
        })
        .collect();
    let ids: Vec<String> = diff_ids.iter().map(|d| format!("\"{d}\"")).collect();
    let config = format!(
        r#"{{"rootfs":{{"type":"layers","diff_ids":[{}]}}}}"#,
        ids.join(",")
    )
    .into_bytes();
    let config_digest = Digest::sha256_of(&config);
    let mut session = store
        .begin_pull(PullId::new(pull_id).expect("pull id"))
        .expect("begin pull");
    let mut stage = |digest: &Digest, bytes: &[u8]| {
        let mut w = session.open_staged_blob(digest).expect("writer");
        w.write_all(bytes).expect("write");
        w.commit().expect("commit");
        session.verify_staged_blob(digest, 1 << 24).expect("verify");
    };
    stage(&config_digest, &config);
    let layers: Vec<Digest> = tars.iter().map(|t| Digest::sha256_of(t)).collect();
    for (d, t) in layers.iter().zip(tars) {
        stage(d, t);
    }
    let mut composition =
        ManifestComposition::new(config_digest.clone(), layers.clone()).expect("composition");
    if record_media_types {
        composition = composition
            .with_layer_media_types(vec![MEDIA_TAR.to_owned(); tars.len()])
            .expect("media types");
    }
    let manifest = Digest::sha256_of(format!("manifest-{pull_id}").as_bytes());
    session
        .publish(PullPublishRequest::new(manifest.clone(), composition))
        .expect("publish");
    SeededImage {
        manifest,
        config: config_digest,
        layers,
    }
}

/// 3 層の標準イメージの tar。下位の `etc/os` を 2 層目が上書きし、3 層目が `old/gone.txt` を whiteout で消す。
#[cfg(target_os = "linux")]
pub fn three_layer_tars() -> Vec<Vec<u8>> {
    vec![
        tar_of(&[
            Entry::Dir("etc"),
            Entry::File("etc/os", b"base"),
            Entry::Dir("old"),
            Entry::File("old/gone.txt", b"gone"),
            Entry::File("old/keep.txt", b"keep"),
        ]),
        tar_of(&[
            Entry::File("etc/os", b"upper"),
            Entry::File("app.txt", b"app"),
        ]),
        tar_of(&[Entry::File("old/.wh.gone.txt", b"")]),
    ]
}
