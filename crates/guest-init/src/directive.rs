//! カーネルコマンドラインの virtiofs mount 指示の復号（MAC-1・TASK-65.3）。
//!
//! `/proc/cmdline` は untrusted として扱い、ホスト側 `guest_mount::parse_directives` と同じ規則で
//! 検証する。加えて多重防御として tag の重複と mount point の重なりも拒否する（ホストは型で生成しないため
//! 通常は起こらない）。呼び出し元は [`crate::process::process_directives`]。

/// 指示トークンのキー（`=` まで）。
pub const DIRECTIVE_KEY: &str = "fandhe.virtiofs=";
/// ゲスト内 mount point の固定基底。
pub const GUEST_MOUNT_BASE: &str = "/mnt/fandhe";
/// 指示の最大件数。
pub const MAX_VIRTIOFS_SHARES: usize = 8;
/// tag の最大バイト数。
pub const MAX_VIRTIOFS_TAG_BYTES: usize = 35;
/// mount point 全体の最大バイト数。
pub const MAX_GUEST_MOUNT_POINT_BYTES: usize = 128;
/// mount point の 1 要素の最大バイト数。
pub const MAX_GUEST_MOUNT_ELEMENT_BYTES: usize = 64;
/// mount point の基底以降の最大要素数。
pub const MAX_GUEST_MOUNT_DEPTH: usize = 4;

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// virtiofs の共有タグ。1〜35 バイトの ASCII 英数字と `.` `_` `-` のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag(String);

impl Tag {
    /// 検証して生成する。不正なら `None`。
    pub fn try_new(s: &str) -> Option<Self> {
        let ok = !s.is_empty() && s.len() <= MAX_VIRTIOFS_TAG_BYTES && s.bytes().all(is_name_byte);
        ok.then(|| Self(s.to_string()))
    }

    /// タグ文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `/mnt/fandhe` 配下の検証済み mount point。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint(String);

impl MountPoint {
    /// 基底配下・長さ・深さ・要素の文字種を検証して生成する。不正なら `None`。
    pub fn try_new(path: &str) -> Option<Self> {
        if path.len() > MAX_GUEST_MOUNT_POINT_BYTES {
            return None;
        }
        let rest = path.strip_prefix(GUEST_MOUNT_BASE)?.strip_prefix('/')?;
        for (depth, el) in rest.split('/').enumerate() {
            let bad = depth >= MAX_GUEST_MOUNT_DEPTH
                || el.is_empty()
                || el == "."
                || el == ".."
                || el.len() > MAX_GUEST_MOUNT_ELEMENT_BYTES
                || !el.bytes().all(is_name_byte);
            if bad {
                return None;
            }
        }
        Some(Self(path.to_string()))
    }

    /// 検証済みのパス文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 基底以降の要素（検証済みのため空・`.`・`..` を含まない）。
    pub fn elements(&self) -> impl Iterator<Item = &str> {
        self.0
            .strip_prefix(GUEST_MOUNT_BASE)
            .and_then(|r| r.strip_prefix('/'))
            .into_iter()
            .flat_map(|r| r.split('/'))
    }

    /// 同一または一方が他方の配下か（要素単位・大文字小文字非区別。fail-closed）。
    pub fn overlaps(&self, other: &MountPoint) -> bool {
        self.0
            .split('/')
            .zip(other.0.split('/'))
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

/// アクセス権。`ro` は必ず `MS_RDONLY` に写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// 読み取り専用。
    ReadOnly,
    /// 読み書き。
    ReadWrite,
}

/// 復号済みの mount 指示 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// 共有タグ（mount の source にもなる）。
    pub tag: Tag,
    /// ゲスト内の mount point。
    pub mount_point: MountPoint,
    /// アクセス権。
    pub access: Access,
}

/// 復号失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// 件数が [`MAX_VIRTIOFS_SHARES`] を超えた。
    TooMany,
    /// 書式不正（`index` は指示トークンの通し番号）。
    Malformed {
        /// 指示トークンの通し番号。
        index: usize,
    },
    /// tag の重複（多重防御）。
    DuplicateTag {
        /// 後から現れた指示の通し番号。
        index: usize,
    },
    /// mount point の重なり（多重防御）。
    OverlappingMountPoint {
        /// 後から現れた指示の通し番号。
        index: usize,
    },
}

fn directive_bodies(cmdline: &str) -> impl Iterator<Item = &str> {
    // /proc/cmdline は末尾に改行を持つため、空白類で区切る。
    cmdline
        .split_ascii_whitespace()
        .filter_map(|t| t.strip_prefix(DIRECTIVE_KEY))
}

/// コマンドラインの指示を全件復号する。全件成功か全件失敗のどちらかで、他のトークンは無視する。
pub fn decode_all(cmdline: &str) -> Result<Vec<Directive>, DecodeError> {
    let mut out: Vec<Directive> = Vec::new();
    for body in directive_bodies(cmdline) {
        let index = out.len();
        if index >= MAX_VIRTIOFS_SHARES {
            return Err(DecodeError::TooMany);
        }
        let bad = DecodeError::Malformed { index };
        let mut parts = body.split(':');
        let (Some(tag), Some(mp), Some(mode), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad);
        };
        let access = match mode {
            "ro" => Access::ReadOnly,
            "rw" => Access::ReadWrite,
            _ => return Err(bad),
        };
        let tag = Tag::try_new(tag).ok_or(bad)?;
        let mount_point = MountPoint::try_new(mp).ok_or(bad)?;
        if out
            .iter()
            .any(|d| d.tag.as_str().eq_ignore_ascii_case(tag.as_str()))
        {
            return Err(DecodeError::DuplicateTag { index });
        }
        if out.iter().any(|d| d.mount_point.overlaps(&mount_point)) {
            return Err(DecodeError::OverlappingMountPoint { index });
        }
        out.push(Directive {
            tag,
            mount_point,
            access,
        });
    }
    Ok(out)
}

/// 復号に失敗したとき、エラーを報告できる tag を集める。
///
/// 先頭から [`MAX_VIRTIOFS_SHARES`] 件までのトークンについて、最初の `:` より前が有効な tag のものだけを
/// 重複なし（大文字小文字非区別）で返す。復元できないトークンは報告行にできないため含めない
/// （ホストはタイムアウトで失敗させる。fail-closed）。
pub fn recoverable_tags(cmdline: &str) -> Vec<Tag> {
    let mut out: Vec<Tag> = Vec::new();
    for body in directive_bodies(cmdline).take(MAX_VIRTIOFS_SHARES) {
        let first = body.split(':').next().unwrap_or("");
        if let Some(tag) = Tag::try_new(first)
            && !out
                .iter()
                .any(|t| t.as_str().eq_ignore_ascii_case(tag.as_str()))
        {
            out.push(tag);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac1_decodes_two_directives_ignoring_other_tokens() {
        let cmd = "console=hvc0 fandhe.virtiofs=a:/mnt/fandhe/a:ro quiet fandhe.virtiofs=b:/mnt/fandhe/x/y:rw\n";
        let d = decode_all(cmd).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].tag.as_str(), "a");
        assert_eq!(d[0].mount_point.as_str(), "/mnt/fandhe/a");
        assert_eq!(d[0].access, Access::ReadOnly);
        assert_eq!(d[1].access, Access::ReadWrite);
        assert_eq!(
            d[1].mount_point.elements().collect::<Vec<_>>(),
            vec!["x", "y"]
        );
    }

    #[test]
    fn mac1_no_directives_is_empty_ok() {
        assert_eq!(decode_all("console=hvc0 quiet\n").unwrap(), vec![]);
    }

    #[test]
    fn mac1_rejects_malformed_forms() {
        for (cmd, index) in [
            ("fandhe.virtiofs=a:/mnt/fandhe/a", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/a:ro:x", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/a:RO", 0),
            ("fandhe.virtiofs=:/mnt/fandhe/a:ro", 0),
            ("fandhe.virtiofs=a b:/mnt/fandhe/a:ro", 0),
            ("fandhe.virtiofs=a:/etc:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/../etc:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/./a:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe//a:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/a/:ro", 0),
            ("fandhe.virtiofs=a:/mnt/fandhe/a/b/c/d/e:ro", 0),
            (
                "fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/proc:rw",
                1,
            ),
        ] {
            assert_eq!(
                decode_all(cmd),
                Err(DecodeError::Malformed { index }),
                "{cmd}"
            );
        }
    }

    #[test]
    fn mac1_limits_on_lengths() {
        let tag35 = "t".repeat(35);
        assert!(decode_all(&format!("fandhe.virtiofs={tag35}:/mnt/fandhe/a:ro")).is_ok());
        let tag36 = "t".repeat(36);
        assert!(decode_all(&format!("fandhe.virtiofs={tag36}:/mnt/fandhe/a:ro")).is_err());
        let el64 = "e".repeat(64);
        assert!(MountPoint::try_new(&format!("/mnt/fandhe/{el64}")).is_some());
        let el65 = "e".repeat(65);
        assert!(MountPoint::try_new(&format!("/mnt/fandhe/{el65}")).is_none());
        // 全体 128 バイト超（要素は 64 以下）。
        let long = format!(
            "/mnt/fandhe/{}/{}/{}",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40)
        );
        assert!(long.len() > 128);
        assert!(MountPoint::try_new(&long).is_none());
    }

    #[test]
    fn mac1_too_many_directives() {
        let nine: Vec<String> = (0..9)
            .map(|i| format!("fandhe.virtiofs=t{i}:/mnt/fandhe/m{i}:ro"))
            .collect();
        assert_eq!(decode_all(&nine.join(" ")), Err(DecodeError::TooMany));
        assert_eq!(decode_all(&nine[..8].join(" ")).unwrap().len(), 8);
    }

    #[test]
    fn mac1_rejects_duplicate_tag_and_overlap() {
        assert_eq!(
            decode_all("fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=A:/mnt/fandhe/b:ro"),
            Err(DecodeError::DuplicateTag { index: 1 })
        );
        assert_eq!(
            decode_all("fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/a/b:ro"),
            Err(DecodeError::OverlappingMountPoint { index: 1 })
        );
        assert_eq!(
            decode_all("fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/A:ro"),
            Err(DecodeError::OverlappingMountPoint { index: 1 })
        );
        // 兄弟は重ならない（文字列の接頭辞が同じでも要素が違う）。
        assert!(
            decode_all("fandhe.virtiofs=a:/mnt/fandhe/a:ro fandhe.virtiofs=b:/mnt/fandhe/ab:ro")
                .is_ok()
        );
    }

    #[test]
    fn mac1_recoverable_tags_dedupe_and_skip_invalid() {
        let cmd =
            "fandhe.virtiofs=a:bad fandhe.virtiofs=A:x:y fandhe.virtiofs=!:x fandhe.virtiofs=b";
        let tags: Vec<_> = recoverable_tags(cmd)
            .iter()
            .map(|t| t.as_str().to_string())
            .collect();
        assert_eq!(tags, vec!["a", "b"]);
    }

    #[test]
    fn mac1_recoverable_tags_limited_to_max_shares() {
        let nine: Vec<String> = (0..9).map(|i| format!("fandhe.virtiofs=t{i}:x")).collect();
        assert_eq!(recoverable_tags(&nine.join(" ")).len(), 8);
    }
}
