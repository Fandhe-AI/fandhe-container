//! bind mount の元がファイルシステム内で保護対象（状態ストアのルート）に到達するかを、mountinfo の実体で判定する。
//!
//! `canonicalize` は bind mount の別名を解決しないため、`major:minor` と FS 内パスの組で照合する（SEC-1・OCI-4・#1915）。
//! 判定は start の段（検査）と bind mount の適用の段（`exec::mount_binds`。固定した元に対して毎回）の両方が使う。
//! 呼び出し側は、パス解決と同じ mount namespace の mountinfo（`/proc/thread-self/mountinfo`）を渡すこと。

/// mountinfo の 1 行（必要なフィールドだけ。`major:minor`・FS 内の root・マウントポイント）。
pub(crate) struct MountRow {
    pub(crate) dev: String,
    pub(crate) root: String,
    pub(crate) point: String,
}

/// ファイルシステム内の実体（`major:minor` と FS 内パス）。bind mount の別名は同じ値になる（SEC-1）。
pub(crate) struct FsIdentity {
    pub(crate) dev: String,
    pub(crate) path: String,
}

/// mountinfo の `\040` 形式（8 進 3 桁）のエスケープを戻す。
fn unescape_mountinfo(field: &str) -> Option<String> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            let digits = bytes.get(i + 1..i + 4)?;
            let mut v: u32 = 0;
            for d in digits {
                if !(b'0'..=b'7').contains(d) {
                    return None;
                }
                v = v * 8 + u32::from(d - b'0');
            }
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `/proc/self/mountinfo` を行ごとに解釈する。解釈できない行があれば `None`（fail-closed）。
pub(crate) fn parse_mountinfo(info: &str) -> Option<Vec<MountRow>> {
    info.lines()
        .map(|line| {
            let mut f = line.split(' ');
            let dev = f.nth(2)?.to_owned();
            let root = unescape_mountinfo(f.next()?)?;
            let point = unescape_mountinfo(f.next()?)?;
            Some(MountRow { dev, root, point })
        })
        .collect()
}

fn under(base: &str, path: &str) -> Option<String> {
    if base == "/" {
        return Some(path.to_owned());
    }
    let rest = path.strip_prefix(base)?;
    (rest.is_empty() || rest.starts_with('/')).then(|| rest.to_owned())
}

fn join_fs_path(root: &str, rest: &str) -> String {
    let root = root.trim_end_matches('/');
    let joined = format!("{root}{rest}");
    if joined.is_empty() {
        "/".to_owned()
    } else {
        joined
    }
}

/// 正規化済みの絶対パスを含むマウント（マウントポイントが最長一致・同点は後勝ち）から、FS 内の実体を求める。
pub(crate) fn fs_identity(mounts: &[MountRow], real: &str) -> Option<FsIdentity> {
    let mut best: Option<(&MountRow, String)> = None;
    for m in mounts {
        if let Some(rest) = under(&m.point, real)
            && best
                .as_ref()
                .is_none_or(|(b, _)| m.point.len() >= b.point.len())
        {
            best = Some((m, rest));
        }
    }
    let (m, rest) = best?;
    Some(FsIdentity {
        dev: m.dev.clone(),
        path: join_fs_path(&m.root, &rest),
    })
}

fn identity_overlaps(a: &FsIdentity, b: &FsIdentity) -> bool {
    a.dev == b.dev && path_overlaps(&a.path, &b.path)
}

/// 同一・祖先・子孫のいずれかか。`/` は全パスの祖先として扱う（`injected_files::overlaps` は `/` を
/// 親にしないため、`mount --bind / /mnt/root` のような全体 bind を取りこぼす。SEC-1）。
fn path_overlaps(a: &str, b: &str) -> bool {
    a == "/" || b == "/" || crate::injected_files::overlaps(a, b)
}

/// 元（`canonicalize` 済み）が状態ルートの実体と、同一・祖先・子孫のいずれかで重なるかを判定する。
/// 元の配下に載った別マウント（再帰 bind で一緒に公開されるもの）の実体も照合する（SEC-1）。
pub(crate) fn source_reaches(mounts: &[MountRow], src_real: &str, state: &FsIdentity) -> bool {
    if fs_identity(mounts, src_real).is_some_and(|id| identity_overlaps(&id, state)) {
        return true;
    }
    mounts.iter().any(|m| {
        m.point != src_real
            && under(src_real, &m.point).is_some()
            && identity_overlaps(
                &FsIdentity {
                    dev: m.dev.clone(),
                    path: m.root.clone(),
                },
                state,
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-1（#1915）: bind mount による状態ルートの別名を、mountinfo の実体で検出する。
    #[test]
    fn sec1_source_reaches_state_through_bind_alias() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 /srv/state /state rw - ext4 /dev/sda1 rw\n\
                    30 10 8:1 /other /mnt/other\\040dir rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, "/state").expect("state");
        assert_eq!(state.path, "/srv/state");
        // 別名（/srv/state）・祖先（/srv）・子孫は拒否、無関係は許可。
        assert!(source_reaches(&mounts, "/srv/state", &state));
        assert!(source_reaches(&mounts, "/srv", &state));
        assert!(source_reaches(&mounts, "/srv/state/sub", &state));
        assert!(source_reaches(&mounts, "/", &state));
        assert!(!source_reaches(&mounts, "/srv/data", &state));
        assert!(!source_reaches(&mounts, "/mnt/other dir", &state));
    }

    /// SEC-1（#1915）: 再帰 bind で一緒に公開される配下マウントが状態ルートの実体なら拒否する。
    #[test]
    fn sec1_source_with_nested_mount_of_state_is_rejected() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:2 /st /state rw - ext4 /dev/sdb1 rw\n\
                    30 10 8:2 /st /pub/inner rw - ext4 /dev/sdb1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, "/state").expect("state");
        assert!(source_reaches(&mounts, "/pub", &state));
        assert!(!source_reaches(&mounts, "/unrelated", &state));
    }

    #[test]
    fn parse_mountinfo_rejects_malformed_line() {
        assert!(parse_mountinfo("garbage").is_none());
    }

    /// SEC-1（#1915）: 全体 bind（root が `/`）が状態ルートを含むときも到達と判定する（`/` を祖先として扱う）。
    #[test]
    fn sec1_whole_host_bind_reaches_state() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 / /mnt/root rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, "/mnt/root/srv/state").expect("state");
        assert_eq!(state.path, "/srv/state");
        // 元が `/` の全体 bind（FS 内パス `/`）は状態ルートの祖先。
        let whole = FsIdentity {
            dev: "8:1".to_owned(),
            path: "/".to_owned(),
        };
        assert!(identity_overlaps(&whole, &state));
        assert!(source_reaches(&mounts, "/mnt/root", &state));
        assert!(source_reaches(&mounts, "/mnt/root/srv", &state));
        assert!(!source_reaches(&mounts, "/mnt/root/other", &state));
        // 別デバイスの `/` は無関係。
        let other = FsIdentity {
            dev: "8:2".to_owned(),
            path: "/".to_owned(),
        };
        assert!(!identity_overlaps(&other, &state));
    }
}
