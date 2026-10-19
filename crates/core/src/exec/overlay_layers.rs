//! mountinfo の overlayfs の super_options から、層（`lowerdir`・`upperdir`・`workdir`）のパスを取り出す純関数
//! （SEC-1・OCI-4・SEC-5・TASK-29 追補・#2166）。
//!
//! # 役割と呼び出し文脈
//!
//! bind mount の元が overlayfs 上にあると、overlay は別の superblock なので、inode の照合も mountinfo の
//! `(dev, path)` の照合も、その下層・上層・workdir の実体が状態ルートや rootfs と同じでも検出できない。
//! 適用の段（`super::bind_mounts` の `check_overlay_layers`）は、付け替えた木の mountinfo のうち fstype が
//! `overlay` の行から本モジュールで層のパスを取り出し、各層を `/` から `O_NOFOLLOW` で辿って inode の照合にかける。
//! 本モジュールは文字列の解析だけを担い、ファイルシステムには触れない。
//!
//! # 入力の書式（Linux v7.0 の一次情報。#2166）
//!
//! - 出力側: `fs/overlayfs/params.c:1049`（`ovl_show_options`）が `seq_show_option` で
//!   `lowerdir`（`:` 区切りの 1 本の値。`:1065`）・`lowerdir+`・`datadir+`（1 オプションが 1 層。`:1072`/`:1074`）・
//!   `upperdir`・`workdir`（`:1077`/`:1078`）を出す。`lowerdir` と `lowerdir+`/`datadir+` は併用しない（`:1060` のコメント）。
//! - エスケープ: `include/linux/seq_file.h:264`（`seq_show_option`）は、名前を `",= \t\n\\"`、値を `", \t\n\\"` について
//!   `seq_escape` する（8 進 3 桁の `\ooo`）。値の `:` はエスケープされない。そのため、`,` は常にオプションの区切りで、
//!   名前に `:` や `,` を含む層はカーネル側が `\:`（保存済みの文字列）として持ち、`\134:` の形で現れうる。
//! - 上限: `OVL_MAX_STACK` は `fs/overlayfs/params.h:20` で 500。
//!
//! # 解析の規則（fail-closed）
//!
//! 1. super_options を `,` で分ける。名前が上の 5 つ以外のオプションは無視する。
//! 2. 値の 8 進エスケープ（`\ooo`、値が 0o377 以下）を戻す。それ以外の `\` の使い方は `Err`。
//! 3. 戻した値に対し、`lowerdir` は区切りでない `:` で分ける（`::` の data-only 層の区切りも受ける）。
//!    戻した結果に残る `\:`・`\\`・`\,`・`\=` は 1 文字に戻す。それ以外の `\` は `Err`（バックスラッシュを含む層名は拒否する）。
//! 4. UTF-8 でない・NUL を含む・空の要素・層が 1 つも無い・層の数や長さが上限超過は `Err`。
//!
//! # 未対応・残余（REPAIR-3）
//!
//! 入れ子の overlay（層そのものが overlay の上にある）の再帰的な解析はしない。呼び出し側が拒否で代える。

/// 1 マウントで受ける lower 層の最大数（カーネルの `OVL_MAX_STACK`。`fs/overlayfs/params.h:20`）。
pub(super) const OVERLAY_MAX_LOWER_LAYERS: usize = 500;
/// 1 層のパスの最大バイト数（`PATH_MAX`）。
pub(super) const OVERLAY_MAX_LAYER_PATH_BYTES: usize = 4096;

/// [`overlay_layer_paths`] の失敗理由（呼び出し側は理由に関わらず fail-closed で拒否する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverlayParseError {
    /// 解釈できないエスケープ（`\` の後ろが 8 進 3 桁でも `: \ , =` でもない・末尾の `\`・0o377 超）。
    InvalidEscape,
    /// UTF-8 でない、または NUL を含む。
    InvalidBytes,
    /// 空の層の要素。
    EmptyEntry,
    /// lower 層が 1 つも無い。
    NoLayers,
    /// lower 層の数が [`OVERLAY_MAX_LOWER_LAYERS`] を超える。
    TooManyLayers,
    /// 1 層のパスが [`OVERLAY_MAX_LAYER_PATH_BYTES`] を超える。
    PathTooLong,
}

/// 8 進 3 桁のエスケープ（mountinfo の `seq_escape`）を戻す。他の `\` の使い方は `InvalidEscape`。
/// 戻した `\`（`\134`）は後段の規則 3 で再び解釈されるため、バイト列のまま返す。
fn decode_octal(raw: &str) -> Result<Vec<u8>, OverlayParseError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        let digits = bytes
            .get(i + 1..i + 4)
            .ok_or(OverlayParseError::InvalidEscape)?;
        let mut value: u32 = 0;
        for d in digits {
            if !(b'0'..=b'7').contains(d) {
                return Err(OverlayParseError::InvalidEscape);
            }
            value = value * 8 + u32::from(d - b'0');
        }
        out.push(u8::try_from(value).map_err(|_| OverlayParseError::InvalidEscape)?);
        i += 4;
    }
    Ok(out)
}

/// 戻した値を、区切りでない `:` で分ける（`split_colons` が偽なら分けず 1 要素）。`\X`（`X` は `: \ , =`）は 1 文字に戻す。
fn split_and_unescape(
    decoded: &[u8],
    split_colons: bool,
) -> Result<Vec<Vec<u8>>, OverlayParseError> {
    let mut parts = vec![Vec::new()];
    let mut i = 0;
    while let Some(&b) = decoded.get(i) {
        match b {
            b'\\' => {
                let next = decoded
                    .get(i + 1)
                    .copied()
                    .filter(|c| matches!(c, b':' | b'\\' | b',' | b'='))
                    .ok_or(OverlayParseError::InvalidEscape)?;
                if let Some(last) = parts.last_mut() {
                    last.push(next);
                }
                i += 2;
            }
            b':' if split_colons => {
                parts.push(Vec::new());
                i += 1;
            }
            _ => {
                if let Some(last) = parts.last_mut() {
                    last.push(b);
                }
                i += 1;
            }
        }
    }
    Ok(parts)
}

/// 空の要素を検証する。`lowerdir` の `::`（data-only 層との境界）が作る、両隣が空でない 1 個の空要素だけを捨てる。
fn drop_data_only_separators(parts: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, OverlayParseError> {
    let last = parts.len().saturating_sub(1);
    let mut out = Vec::with_capacity(parts.len());
    for (idx, part) in parts.iter().enumerate() {
        if !part.is_empty() {
            out.push(part.clone());
            continue;
        }
        let prev_ok = idx > 0 && parts.get(idx - 1).is_some_and(|p| !p.is_empty());
        let next_ok = idx < last && parts.get(idx + 1).is_some_and(|p| !p.is_empty());
        if !(prev_ok && next_ok) {
            return Err(OverlayParseError::EmptyEntry);
        }
    }
    Ok(out)
}

fn into_path(bytes: Vec<u8>) -> Result<String, OverlayParseError> {
    if bytes.len() > OVERLAY_MAX_LAYER_PATH_BYTES {
        return Err(OverlayParseError::PathTooLong);
    }
    if bytes.contains(&0) {
        return Err(OverlayParseError::InvalidBytes);
    }
    String::from_utf8(bytes).map_err(|_| OverlayParseError::InvalidBytes)
}

/// fstype が `overlay` の行の super_options から、層のパス（lower・upper・workdir の順）を返す。
///
/// 返すパスは相対パスのこともある（カーネルは文字列のまま記録する）。解決は呼び出し側が行う。
/// 全体として lower 層が 1 つも無い場合は `NoLayers`（壊れた入力・想定外の書式。fail-closed）。
pub(super) fn overlay_layer_paths(super_options: &str) -> Result<Vec<String>, OverlayParseError> {
    let mut lower: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for opt in super_options.split(',') {
        let Some((key, value)) = opt.split_once('=') else {
            continue;
        };
        let is_lowerdir = key == "lowerdir";
        let is_single_lower = matches!(key, "lowerdir+" | "datadir+");
        let is_other = matches!(key, "upperdir" | "workdir");
        if !(is_lowerdir || is_single_lower || is_other) {
            continue;
        }
        let decoded = decode_octal(value)?;
        let mut parts = split_and_unescape(&decoded, is_lowerdir)?;
        if is_lowerdir {
            parts = drop_data_only_separators(parts)?;
        }
        for part in parts {
            if part.is_empty() {
                return Err(OverlayParseError::EmptyEntry);
            }
            let path = into_path(part)?;
            if is_other {
                others.push(path);
            } else {
                lower.push(path);
                if lower.len() > OVERLAY_MAX_LOWER_LAYERS {
                    return Err(OverlayParseError::TooManyLayers);
                }
            }
        }
    }
    if lower.is_empty() {
        return Err(OverlayParseError::NoLayers);
    }
    lower.extend(others);
    Ok(lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(s: &str) -> Vec<String> {
        overlay_layer_paths(s).unwrap_or_else(|e| panic!("{s:?}: {e:?}"))
    }

    /// SEC-1・#2166: 通常の書式（lowerdir の `:` 区切り・upperdir・workdir）と無関係なオプションの無視。
    #[test]
    fn sec1_2166_parses_plain_layers_and_ignores_other_options() {
        assert_eq!(
            paths(
                "rw,lowerdir=/a:/b,upperdir=/u,workdir=/w,redirect_dir=off,metacopy=on,index=off"
            ),
            ["/a", "/b", "/u", "/w"]
        );
    }

    /// SEC-1・#2166: `lowerdir+`・`datadir+` は 1 オプション 1 層で `:` では分けない。
    #[test]
    fn sec1_2166_parses_lowerdir_plus_and_datadir_plus() {
        assert_eq!(
            paths("rw,lowerdir+=/a,lowerdir+=/b:c,datadir+=/d"),
            ["/a", "/b:c", "/d"]
        );
    }

    /// SEC-1・#2166: 8 進エスケープ（空白・`,`・`:`）と、戻した `\` が後段で `\:` として働く形。
    #[test]
    fn sec1_2166_decodes_octal_and_colon_escapes() {
        assert_eq!(paths("lowerdir=/a\\040b:/c\\054d"), ["/a b", "/c,d"]);
        assert_eq!(paths("lowerdir=/x\\134:y:/z"), ["/x:y", "/z"]);
        assert_eq!(paths("lowerdir=/x\\134\\134y"), ["/x\\y"]);
        assert_eq!(
            paths("lowerdir=/a,upperdir=/u\\072v,workdir=/w"),
            ["/a", "/u:v", "/w"]
        );
    }

    /// SEC-1・#2166: data-only 層（`::`）は層として照合する。
    #[test]
    fn sec1_2166_data_only_layers_are_included() {
        assert_eq!(paths("lowerdir=/a::/d"), ["/a", "/d"]);
        assert_eq!(paths("lowerdir=/a::/d::/e"), ["/a", "/d", "/e"]);
    }

    /// SEC-1・#2166: 不正なエスケープ・空の要素・NUL・UTF-8 でない値・層が無い入力は `Err`（panic しない）。
    #[test]
    fn sec1_2166_malformed_input_is_rejected_without_panic() {
        let err = |s: &str| overlay_layer_paths(s).expect_err(s);
        assert_eq!(err("lowerdir=/a\\x"), OverlayParseError::InvalidEscape);
        assert_eq!(err("lowerdir=/a\\9"), OverlayParseError::InvalidEscape);
        assert_eq!(err("lowerdir=/a\\"), OverlayParseError::InvalidEscape);
        assert_eq!(err("lowerdir=/a\\04"), OverlayParseError::InvalidEscape);
        assert_eq!(err("lowerdir=/a\\400"), OverlayParseError::InvalidEscape);
        // 戻したバックスラッシュの後ろが規則外。
        assert_eq!(err("lowerdir=/a\\134b"), OverlayParseError::InvalidEscape);
        assert_eq!(err("lowerdir=/a:"), OverlayParseError::EmptyEntry);
        assert_eq!(err("lowerdir=:/a"), OverlayParseError::EmptyEntry);
        assert_eq!(err("lowerdir=/a:::/b"), OverlayParseError::EmptyEntry);
        assert_eq!(
            err("lowerdir=/a,upperdir=,workdir=/w"),
            OverlayParseError::EmptyEntry
        );
        assert_eq!(err("lowerdir="), OverlayParseError::EmptyEntry);
        assert_eq!(err("lowerdir=/a\\000b"), OverlayParseError::InvalidBytes);
        assert_eq!(err("lowerdir=/a\\377"), OverlayParseError::InvalidBytes);
        assert_eq!(
            err("rw,upperdir=/u,workdir=/w"),
            OverlayParseError::NoLayers
        );
        assert_eq!(err(""), OverlayParseError::NoLayers);
        assert_eq!(err("lowerdir"), OverlayParseError::NoLayers);
    }

    /// SEC-1・#2166: 層の数と 1 層の長さの上限（境界値）。
    #[test]
    fn sec1_2166_limits_are_enforced_at_the_boundary() {
        let many = |n: usize| {
            let layers: Vec<String> = (0..n).map(|i| format!("/l{i}")).collect();
            format!("lowerdir={}", layers.join(":"))
        };
        assert_eq!(
            paths(&many(OVERLAY_MAX_LOWER_LAYERS)).len(),
            OVERLAY_MAX_LOWER_LAYERS
        );
        assert_eq!(
            overlay_layer_paths(&many(OVERLAY_MAX_LOWER_LAYERS + 1)),
            Err(OverlayParseError::TooManyLayers)
        );
        let long = |n: usize| format!("lowerdir=/{}", "a".repeat(n - 1));
        assert_eq!(paths(&long(OVERLAY_MAX_LAYER_PATH_BYTES)).len(), 1);
        assert_eq!(
            overlay_layer_paths(&long(OVERLAY_MAX_LAYER_PATH_BYTES + 1)),
            Err(OverlayParseError::PathTooLong)
        );
    }

    /// SEC-1・#2166: 境界値の並びで panic しない（任意の入力に対する堅牢性）。
    #[test]
    fn sec1_2166_odd_inputs_do_not_panic() {
        for s in [
            "lowerdir=\\",
            "lowerdir=\\0",
            "lowerdir=\\00",
            "lowerdir=,,,",
            ",,,",
            "=",
            "lowerdir==",
            "lowerdir+=",
            "datadir+=\\134",
            "workdir=\\134:",
            "lowerdir=\u{3042}:\u{3044}",
            "lowerdir=::",
            "lowerdir=\\134",
            "lowerdir=\\134,upperdir=\\134",
        ] {
            let _ = overlay_layer_paths(s);
        }
    }
}
