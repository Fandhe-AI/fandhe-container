//! 特権ランチャーの昇格手段（file capability / setuid root）の読み取り専用の診断（#2599・SUP-14・CORE-6）。
//!
//! CLI の `doctor` が `start` と同じ規則で解決したランチャー（[`crate::start_client::classify_launcher_beside`]
//! が返す `TrustedLauncher`）に対し、必要な `security.capability` が付いているか、または xattr 非対応環境の代替である
//! setuid root になっているかを判定する。属性は一切変更せず、外部コマンド（`getcap` 等）も起動しない。
//!
//! # 構成
//! - [`decode_vfs_cap`]: `security.capability` のバイト列（外部入力として扱う）の復号。純関数・全 OS で試験できる
//! - [`assess_elevation`]: 所有者・mode・xattr の読み取り結果から診断を決める。純関数
//! - `read_launcher_file_caps`（Linux のみ）: `sys` の `lgetxattr` ラッパーで xattr を読む
//!
//! # 範囲外（実装済みを装わない。REPAIR-3）
//! - ランチャー・supervisor の hash / 署名の照合（`docs/design/privilege-separation.md` 12 章の未確認事項のまま。PLUG-11）
//! - `nosuid` マウント上のランチャーの検出（setuid と file capability が効かない。ランチャーが実行時に fail-closed で拒否する）
//! - LSM（AppArmor 等）下の挙動
//! - 診断と `start` の実行の間の差し替え（TOCTOU）。診断にすぎず、昇格の可否は実行時にランチャーの
//!   `privilege::elevate` が検証する
//!
//! # 値の出典
//! `security.capability` の配置はカーネルの `include/uapi/linux/capability.h`（`VFS_CAP_*`）による。
//! `magic_etc`（LE u32）= リビジョン（上位 8 bit）| フラグ（下位 24 bit。bit 0 が effective）、続いて
//! `{permitted, inheritable}`（LE u32）の組が 2 組（v2 は計 20 バイト）、v3 はさらに `rootid`（LE u32。計 24 バイト）。

use crate::privilege::launcher_file_capability_mask;

/// `magic_etc` のリビジョン部のマスク。
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
/// `magic_etc` の effective フラグ。
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
/// 64 bit 形式（2 語）の最初のリビジョン。20 バイト。
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
/// v2 に `rootid` を足したリビジョン。24 バイト。
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
/// v2 の大きさ。
const VFS_CAP_LEN_V2: usize = 20;
/// v3 の大きさ。
const VFS_CAP_LEN_V3: usize = 24;
/// setuid ビット。
const S_ISUID: u32 = 0o4000;

/// 復号した file capability。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCaps {
    /// permitted のビット列（bit n が capability 番号 n）。
    pub permitted: u64,
    /// inheritable のビット列。
    pub inheritable: u64,
    /// effective フラグ（exec 時に permitted が effective に載る）。
    pub effective: bool,
    /// v3 の `rootid`（v2 は 0）。0 以外は init の user namespace では効かない。
    pub root_id: u32,
}

/// [`decode_vfs_cap`] の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VfsCapDecodeError {
    /// 長さが無い・合わない、または未対応のリビジョン（v1 を含む）。
    Malformed,
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(chunk))
}

/// `security.capability` の生のバイト列を復号する（外部入力として長さ・リビジョンを検証する）。
///
/// v2（20 バイト）と v3（24 バイト）だけを受ける。それ以外は [`VfsCapDecodeError::Malformed`]。
pub fn decode_vfs_cap(bytes: &[u8]) -> Result<FileCaps, VfsCapDecodeError> {
    let bad = VfsCapDecodeError::Malformed;
    let magic = le_u32(bytes, 0).ok_or(bad)?;
    let revision = magic & VFS_CAP_REVISION_MASK;
    let expected_len = match revision {
        VFS_CAP_REVISION_2 => VFS_CAP_LEN_V2,
        VFS_CAP_REVISION_3 => VFS_CAP_LEN_V3,
        _ => return Err(bad),
    };
    if bytes.len() != expected_len {
        return Err(bad);
    }
    let p0 = le_u32(bytes, 4).ok_or(bad)?;
    let i0 = le_u32(bytes, 8).ok_or(bad)?;
    let p1 = le_u32(bytes, 12).ok_or(bad)?;
    let i1 = le_u32(bytes, 16).ok_or(bad)?;
    let root_id = if revision == VFS_CAP_REVISION_3 {
        le_u32(bytes, 20).ok_or(bad)?
    } else {
        0
    };
    Ok(FileCaps {
        permitted: u64::from(p0) | (u64::from(p1) << 32),
        inheritable: u64::from(i0) | (u64::from(i1) << 32),
        effective: magic & VFS_CAP_FLAGS_EFFECTIVE != 0,
        root_id,
    })
}

/// `security.capability` の読み取り結果（errno は値を持たず分類だけ残す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XattrRead {
    /// 読めた（生のバイト列）。
    Present(Vec<u8>),
    /// xattr が付いていない（`ENODATA`）。
    NoData,
    /// ファイルシステムが xattr に非対応（`EOPNOTSUPP`）。
    Unsupported,
    /// 値が 24 バイトを超える（`ERANGE`）。
    TooLarge,
    /// その他の失敗（診断できない）。
    Error,
}

/// ランチャーの昇格手段の診断結果（機械可読。doctor の `state` に写す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElevationAssessment {
    /// setuid root（xattr 非対応環境の代替方式。`PrivilegeMethod::SetuidRoot`）。
    SetuidRoot,
    /// setuid root だが、併存する file capability が期待集合を満たさない（不足・effective 無し・名前空間付き・壊れ）。
    ///
    /// file capability が在ると setuid root の全権付与は効かず取得 capability がファイル側の集合に制限される
    /// （capabilities(7)）。このとき `privilege::plan_reduction` が UID 縮退条件で `start` を拒否するため、昇格できない。
    SetuidRootRestrictedByFileCaps,
    /// file capability が期待集合ちょうどで effective 付き。
    FileCapabilitiesOk,
    /// 期待集合を含み effective 付きだが、超過のビットがある（`elevate` が縮退するため `start` は通る）。
    FileCapabilitiesExcess,
    /// permitted が期待集合を含まない。
    FileCapabilitiesInsufficient,
    /// permitted は足りるが effective フラグが無い。
    FileCapabilitiesNotEffective,
    /// v3 の `rootid` が 0 以外（init の user namespace では効かない）。
    FileCapabilitiesNamespaced,
    /// バイト列が壊れている（長さ・リビジョン不正、24 バイト超を含む）。
    FileCapabilitiesMalformed,
    /// 昇格手段が無い（file capability が無く、setuid root でもない）。
    NoElevation,
    /// 読み取りに失敗し判定できない。
    Inconclusive,
}

/// 実体の所有者 `owner_uid`・`mode` と xattr の読み取り結果から、昇格手段を判定する（純関数）。
///
/// setuid root（setuid ビットかつ所有者 uid 0）は代替方式として先に採る。`launcher` bin は real が非 root で effective が
/// 0 のとき `SetuidRoot` を選ぶ（`launcher::select_method`）ため、xattr の有無に関わらず成立する。
pub fn assess_elevation(owner_uid: u32, mode: u32, xattr: &XattrRead) -> ElevationAssessment {
    if mode & S_ISUID != 0 && owner_uid == 0 {
        // 併存する file capability があるとそちらが優先されるため、期待集合を満たすかを評価する（fail-closed）。
        return match xattr {
            XattrRead::NoData | XattrRead::Unsupported => ElevationAssessment::SetuidRoot,
            XattrRead::Error => ElevationAssessment::Inconclusive,
            _ => match assess_file_caps(xattr) {
                ElevationAssessment::FileCapabilitiesOk
                | ElevationAssessment::FileCapabilitiesExcess => ElevationAssessment::SetuidRoot,
                _ => ElevationAssessment::SetuidRootRestrictedByFileCaps,
            },
        };
    }
    assess_file_caps(xattr)
}

/// file capability だけの判定（setuid root の分岐を含まない）。
fn assess_file_caps(xattr: &XattrRead) -> ElevationAssessment {
    let bytes = match xattr {
        XattrRead::Present(b) => b,
        XattrRead::NoData | XattrRead::Unsupported => return ElevationAssessment::NoElevation,
        XattrRead::TooLarge => return ElevationAssessment::FileCapabilitiesMalformed,
        XattrRead::Error => return ElevationAssessment::Inconclusive,
    };
    let Ok(caps) = decode_vfs_cap(bytes) else {
        return ElevationAssessment::FileCapabilitiesMalformed;
    };
    if caps.root_id != 0 {
        return ElevationAssessment::FileCapabilitiesNamespaced;
    }
    let want = launcher_file_capability_mask();
    if caps.permitted & want != want {
        return ElevationAssessment::FileCapabilitiesInsufficient;
    }
    if !caps.effective {
        return ElevationAssessment::FileCapabilitiesNotEffective;
    }
    if caps.permitted != want {
        return ElevationAssessment::FileCapabilitiesExcess;
    }
    ElevationAssessment::FileCapabilitiesOk
}

/// `path`（symlink 解決済みの実体）の `security.capability` を読む（読み取り専用）。
///
/// `doctor` が `classify_launcher_beside` の `Trusted` の `path` に対して呼ぶ。
#[cfg(target_os = "linux")]
pub fn read_launcher_file_caps(path: &std::path::Path) -> XattrRead {
    match crate::sys::read_security_capability(path) {
        Ok(bytes) => XattrRead::Present(bytes),
        Err(e) => match e.raw_os_error() {
            Some(crate::sys::ENODATA) => XattrRead::NoData,
            Some(crate::sys::EOPNOTSUPP) => XattrRead::Unsupported,
            Some(crate::sys::ERANGE) => XattrRead::TooLarge,
            _ => XattrRead::Error,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: u64 = 0x0000_0000_2820_1162;

    fn v2(magic_flags: u32, perm: u64, inh: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(VFS_CAP_REVISION_2 | magic_flags).to_le_bytes());
        v.extend_from_slice(&(perm as u32).to_le_bytes());
        v.extend_from_slice(&(inh as u32).to_le_bytes());
        v.extend_from_slice(&((perm >> 32) as u32).to_le_bytes());
        v.extend_from_slice(&((inh >> 32) as u32).to_le_bytes());
        v
    }

    fn v3(magic_flags: u32, perm: u64, root_id: u32) -> Vec<u8> {
        let mut v = v2(magic_flags, perm, 0);
        v[0..4].copy_from_slice(&(VFS_CAP_REVISION_3 | magic_flags).to_le_bytes());
        v.extend_from_slice(&root_id.to_le_bytes());
        v
    }

    /// SUP-14・#2599: v2 のバイト列を具体値で復号する（setcap の `+ep` 相当）。
    #[test]
    fn sup14_decode_v2_exact_bytes() {
        let bytes = [
            0x01, 0x00, 0x00, 0x02, // magic_etc = REVISION_2 | EFFECTIVE
            0x62, 0x11, 0x20, 0x28, // permitted[0] = 0x28201162
            0x00, 0x00, 0x00, 0x00, // inheritable[0]
            0x00, 0x00, 0x00, 0x00, // permitted[1]
            0x00, 0x00, 0x00, 0x00, // inheritable[1]
        ];
        assert_eq!(
            decode_vfs_cap(&bytes),
            Ok(FileCaps {
                permitted: MASK,
                inheritable: 0,
                effective: true,
                root_id: 0
            })
        );
    }

    /// SUP-14・#2599: v3 の rootid、effective 無し、不正な長さ・リビジョンの扱い。
    #[test]
    fn sup14_decode_v3_and_malformed() {
        let c = decode_vfs_cap(&v3(1, MASK, 0)).expect("v3");
        assert_eq!((c.permitted, c.effective, c.root_id), (MASK, true, 0));
        let c = decode_vfs_cap(&v3(1, MASK, 1000)).expect("v3 rootid");
        assert_eq!(c.root_id, 1000);
        let c = decode_vfs_cap(&v2(0, MASK, 0)).expect("v2 no effective");
        assert!(!c.effective);
        let good = v2(1, MASK, 0);
        for len in [0usize, 4, 12, 19] {
            assert_eq!(
                decode_vfs_cap(&good[..len]),
                Err(VfsCapDecodeError::Malformed),
                "len {len}"
            );
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(decode_vfs_cap(&long), Err(VfsCapDecodeError::Malformed));
        // v3 の宣言で長さが 20 のもの、v2 の宣言で長さが 24 のもの。
        let mut lie = good.clone();
        lie[0..4].copy_from_slice(&(VFS_CAP_REVISION_3 | 1).to_le_bytes());
        assert_eq!(decode_vfs_cap(&lie), Err(VfsCapDecodeError::Malformed));
        let mut lie = v3(1, MASK, 0);
        lie[0..4].copy_from_slice(&(VFS_CAP_REVISION_2 | 1).to_le_bytes());
        assert_eq!(decode_vfs_cap(&lie), Err(VfsCapDecodeError::Malformed));
        for rev in [0x0100_0000u32, 0x0400_0000, 0] {
            let mut b = good.clone();
            b[0..4].copy_from_slice(&rev.to_le_bytes());
            assert_eq!(decode_vfs_cap(&b), Err(VfsCapDecodeError::Malformed));
        }
    }

    /// SUP-14・#2599: 昇格手段の判定の全分岐。
    #[test]
    fn sup14_assess_elevation_all_branches() {
        use ElevationAssessment as A;
        let plain = 0o100_755;
        let present = |b: Vec<u8>| XattrRead::Present(b);
        assert_eq!(
            assess_elevation(0, plain, &present(v2(1, MASK, 0))),
            A::FileCapabilitiesOk
        );
        assert_eq!(
            assess_elevation(0, plain, &present(v3(1, MASK, 0))),
            A::FileCapabilitiesOk
        );
        assert_eq!(
            assess_elevation(0, plain, &present(v2(1, MASK | (1 << 16), 0))),
            A::FileCapabilitiesExcess
        );
        assert_eq!(
            assess_elevation(0, plain, &present(v2(1, MASK & !(1 << 6), 0))),
            A::FileCapabilitiesInsufficient
        );
        assert_eq!(
            assess_elevation(0, plain, &present(v2(0, MASK, 0))),
            A::FileCapabilitiesNotEffective
        );
        assert_eq!(
            assess_elevation(0, plain, &present(v3(1, MASK, 5))),
            A::FileCapabilitiesNamespaced
        );
        assert_eq!(
            assess_elevation(0, plain, &present(vec![1, 2, 3])),
            A::FileCapabilitiesMalformed
        );
        assert_eq!(
            assess_elevation(0, plain, &XattrRead::TooLarge),
            A::FileCapabilitiesMalformed
        );
        assert_eq!(
            assess_elevation(0, plain, &XattrRead::NoData),
            A::NoElevation
        );
        assert_eq!(
            assess_elevation(0, plain, &XattrRead::Unsupported),
            A::NoElevation
        );
        assert_eq!(
            assess_elevation(0, plain, &XattrRead::Error),
            A::Inconclusive
        );
        // setuid root は xattr の有無に関わらず代替方式として成立する。所有者が root でない setuid は昇格にならない。
        assert_eq!(
            assess_elevation(0, 0o104_755, &XattrRead::NoData),
            A::SetuidRoot
        );
        // setuid root でも不足の file capability が併存すれば昇格できない（start が UID 縮退で拒否される）。
        for bad in [
            v2(1, MASK & !(1 << 6), 0),
            v2(0, MASK, 0),
            v3(1, MASK, 5),
            vec![1, 2, 3],
        ] {
            assert_eq!(
                assess_elevation(0, 0o104_755, &present(bad)),
                A::SetuidRootRestrictedByFileCaps
            );
        }
        assert_eq!(
            assess_elevation(0, 0o104_755, &XattrRead::TooLarge),
            A::SetuidRootRestrictedByFileCaps
        );
        assert_eq!(
            assess_elevation(0, 0o104_755, &present(v2(1, MASK, 0))),
            A::SetuidRoot
        );
        assert_eq!(
            assess_elevation(0, 0o104_755, &XattrRead::Error),
            A::Inconclusive
        );
        assert_eq!(
            assess_elevation(1000, 0o104_755, &XattrRead::NoData),
            A::NoElevation
        );
    }

    /// SUP-14・#2599: 期待集合は install スクリプトの `LAUNCHER_CAPS` と同期している。
    #[test]
    fn sup14_expected_caps_match_install_script() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/install-privileged-launcher.sh");
        let text = std::fs::read_to_string(script).expect("read install script");
        let line = text
            .lines()
            .find_map(|l| l.strip_prefix("LAUNCHER_CAPS=\""))
            .and_then(|l| l.strip_suffix("+ep\""))
            .expect("LAUNCHER_CAPS line");
        let mut from_script: Vec<String> = line.split(',').map(str::to_owned).collect();
        from_script.sort();
        let mut expected: Vec<String> = crate::privilege::launcher_file_capabilities()
            .iter()
            .map(|c| c.as_str().to_ascii_lowercase())
            .collect();
        expected.sort();
        assert_eq!(from_script, expected);
    }

    /// SUP-14・#2599: 実ファイルの読み取り。setcap していない一時ファイルは xattr 無し（または非対応 FS）になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup14_read_launcher_file_caps_on_plain_file() {
        let dir = std::env::temp_dir().join(format!("fc-launcher-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let f = dir.join("plain");
        std::fs::write(&f, b"x").expect("write");
        let got = read_launcher_file_caps(&f);
        let missing = read_launcher_file_caps(&dir.join("absent"));
        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert!(
            matches!(got, XattrRead::NoData | XattrRead::Unsupported),
            "{got:?}"
        );
        assert_eq!(missing, XattrRead::Error);
    }
}
