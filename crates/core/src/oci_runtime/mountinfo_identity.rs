//! bind mount の元がファイルシステム内で保護対象（状態ストアのルート）に到達するかを、mountinfo の実体で判定する。
//!
//! `canonicalize` は bind mount の別名を解決しないため、`major:minor` と FS 内パスの組で照合する（SEC-1・OCI-4・#1915）。
//! 元の属するマウントは、パスの最長一致ではなく fd の `mnt_id`（fdinfo）で特定する。親への overmount で覆われた
//! マウントがパス上は残るため、パスの最長一致は実際に参照するマウントと食い違い得る。
//! 判定は start の段（検査）と bind mount の適用の段（`exec::mount_binds`。固定した元に対して毎回）の両方が使う。
//! 呼び出し側は、パス解決と同じ mount namespace の mountinfo（`/proc/thread-self/mountinfo`）を渡すこと。
//!
//! mountinfo の読み取りは [`read_mountinfo_bounded`] が上限つきで行い、解析は [`parse_mountinfo`] が行数を制限する
//! （無制限確保による DoS を防ぐ）。

use std::collections::HashMap;
use std::io::Read as _;

/// mountinfo として読むバイト数の上限（超過は拒否）。実機の mountinfo は通常数十 KiB 以下。
pub(crate) const MOUNTINFO_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// mountinfo として解釈する行数の上限（超過は拒否）。
pub(crate) const MOUNTINFO_MAX_LINES: usize = 16 * 1024;

/// [`read_mountinfo_bounded`] の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountinfoReadError {
    /// 読めない（存在しない・権限・UTF-8 でない）。
    Unreadable,
    /// [`MOUNTINFO_MAX_BYTES`] を超える。
    TooLarge,
}

/// `path`（`/proc/thread-self/mountinfo` 等）を [`MOUNTINFO_MAX_BYTES`] までだけ読む。超過は `TooLarge`（fail-closed）。
pub(crate) fn read_mountinfo_bounded(path: &str) -> Result<String, MountinfoReadError> {
    let file = std::fs::File::open(path).map_err(|_| MountinfoReadError::Unreadable)?;
    let mut text = String::new();
    // 上限 + 1 バイトまで読み、超えたら拒否する（確保量は上限で頭打ち）。
    file.take(MOUNTINFO_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| MountinfoReadError::Unreadable)?;
    if u64::try_from(text.len()).map_or(true, |n| n > MOUNTINFO_MAX_BYTES) {
        return Err(MountinfoReadError::TooLarge);
    }
    Ok(text)
}

/// `/proc/<...>/fdinfo/<fd>` の `mnt_id:` 行（fd が属するマウントの ID）を取り出す。
#[cfg(target_os = "linux")]
pub(crate) fn parse_fdinfo_mnt_id(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `path` を `O_PATH` で開いた fd の属するマウント ID（`/proc/thread-self/fdinfo/N`）。start の段が使う。
/// `O_PATH` はブロックしないため、検査と open の間に FIFO 等へ差し替えられても停止しない（REPAIR-5）。
/// 種別は開いた同じ fd の `fstat` で見て、ディレクトリと通常ファイル以外は `None`（適用の段が種別で拒否する）。
#[cfg(target_os = "linux")]
pub(crate) fn path_mount_id(path: &str) -> Option<u64> {
    use std::os::fd::AsFd as _;
    use std::os::fd::AsRawFd as _;
    let c = std::ffi::CString::new(path).ok()?;
    // 絶対パスのため dirfd は解決に影響しない（`/` の fd を渡す）。
    let root = crate::sys::open_dir_path_nofollow(None, c"/").ok()?;
    let fd = crate::sys::open_path_follow_at(root.as_fd(), &c).ok()?;
    let meta = std::fs::File::from(fd.as_fd().try_clone_to_owned().ok()?)
        .metadata()
        .ok()?;
    if !meta.is_dir() && !meta.is_file() {
        return None;
    }
    let fdinfo =
        std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    parse_fdinfo_mnt_id(&fdinfo)
}

/// Linux 以外では `/proc` と `crate::sys` が無いため特定できない（bind mount は Linux 限定。呼び出し側は fail-closed にする）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn path_mount_id(_path: &str) -> Option<u64> {
    None
}

/// mountinfo の 1 行（必要なフィールドだけ。マウント ID・親 ID・`major:minor`・FS 内の root・マウントポイント）。
pub(crate) struct MountRow {
    pub(crate) id: u64,
    pub(crate) parent: u64,
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

/// `/proc/self/mountinfo` を行ごとに解釈する。解釈できない行・[`MOUNTINFO_MAX_LINES`] を超える行数は
/// `None`（fail-closed）。
pub(crate) fn parse_mountinfo(info: &str) -> Option<Vec<MountRow>> {
    if info.lines().nth(MOUNTINFO_MAX_LINES).is_some() {
        return None;
    }
    info.lines()
        .map(|line| {
            let mut f = line.split(' ');
            let id = f.next()?.parse().ok()?;
            let parent = f.next()?.parse().ok()?;
            let dev = f.next()?.to_owned();
            let root = unescape_mountinfo(f.next()?)?;
            let point = unescape_mountinfo(f.next()?)?;
            Some(MountRow {
                id,
                parent,
                dev,
                root,
                point,
            })
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

/// マウント ID `mnt_id` のマウントを基準に、正規化済みの絶対パス `real` の FS 内の実体を求める。
/// `mnt_id` の行が一意に無い・`real` がそのマウントポイント配下でない場合は `None`（fail-closed）。
pub(crate) fn fs_identity(mounts: &[MountRow], mnt_id: u64, real: &str) -> Option<FsIdentity> {
    let mut rows = mounts.iter().filter(|m| m.id == mnt_id);
    let m = rows.next()?;
    if rows.next().is_some() {
        return None;
    }
    let rest = under(&m.point, real)?;
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

/// 元（マウント ID `src_mnt_id`・正規化済みパス `src_real`）が状態ルートの実体と、同一・祖先・子孫のいずれかで
/// 重なるかを判定する。`recursive`（rbind）のときだけ、元のマウントの子孫マウントのうち元の配下に載るもの
/// （一緒に公開される。覆い隠されたものも保守的に含める）の実体も照合する（SEC-1）。
/// 元の位置を特定できない場合は `None`（呼び出し側が fail-closed にする）。
pub(crate) fn source_reaches(
    mounts: &[MountRow],
    src_mnt_id: u64,
    src_real: &str,
    recursive: bool,
    state: &FsIdentity,
) -> Option<bool> {
    reaches_by(
        mounts,
        src_mnt_id,
        src_real,
        recursive,
        state,
        identity_overlaps,
    )
}

/// `candidate` が `target` と同じデバイスで、同一または祖先のパスか（`target` を含むか）。
fn identity_contains(candidate: &FsIdentity, target: &FsIdentity) -> bool {
    candidate.dev == target.dev && under(&candidate.path, &target.path).is_some()
}

/// [`source_reaches`] の包含版。元（`recursive` なら公開される子孫マウントを含む）のいずれかが `target` の
/// 同一・祖先の実体であれば `Some(true)`（`target` の子孫だけを指す元は含まない）。rootfs・bundle のように、
/// 配下の別の実体を元にすることは許す一方で、それ自体を別名経由で公開させない保護対象に使う（SEC-1）。
pub(crate) fn source_contains(
    mounts: &[MountRow],
    src_mnt_id: u64,
    src_real: &str,
    recursive: bool,
    target: &FsIdentity,
) -> Option<bool> {
    reaches_by(
        mounts,
        src_mnt_id,
        src_real,
        recursive,
        target,
        identity_contains,
    )
}

/// 元の実体と（`recursive` のとき）公開される子孫マウントの実体のいずれかが `hit(元側, protected)` を満たすか。
fn reaches_by(
    mounts: &[MountRow],
    src_mnt_id: u64,
    src_real: &str,
    recursive: bool,
    state: &FsIdentity,
    hit: fn(&FsIdentity, &FsIdentity) -> bool,
) -> Option<bool> {
    let top = fs_identity(mounts, src_mnt_id, src_real)?;
    if hit(&top, state) {
        return Some(true);
    }
    if !recursive {
        return Some(false);
    }
    // 親子関係で子孫を辿る（各行は高々 1 回訪れるため行数に比例）。
    let mut children: HashMap<u64, Vec<&MountRow>> = HashMap::new();
    for m in mounts {
        children.entry(m.parent).or_default().push(m);
    }
    let mut seen = std::collections::HashSet::from([src_mnt_id]);
    let mut stack = vec![src_mnt_id];
    while let Some(id) = stack.pop() {
        for child in children.get(&id).into_iter().flatten() {
            if !seen.insert(child.id) {
                continue;
            }
            // 元の配下に載らない子（元がサブディレクトリのとき）は公開されない。
            if under(src_real, &child.point).is_none() {
                continue;
            }
            let id = FsIdentity {
                dev: child.dev.clone(),
                path: child.root.clone(),
            };
            if hit(&id, state) {
                return Some(true);
            }
            stack.push(child.id);
        }
    }
    Some(false)
}

/// 元（マウント ID `src_mnt_id`・パス `src_real`）が公開するマウントの `major:minor` の集合を返す。
/// 元のマウント自身に加え、`recursive`（rbind）のときは元の配下に載る子孫マウントのデバイスも含む
/// （子マウントが別 FS のとき、その FS 上のハードリンクも一緒に公開されるため。SEC-1・#1915）。
/// 元の位置を特定できない場合は `None`（呼び出し側が fail-closed にする）。
#[cfg(target_os = "linux")]
pub(crate) fn exposed_devs(
    mounts: &[MountRow],
    src_mnt_id: u64,
    src_real: &str,
    recursive: bool,
) -> Option<std::collections::HashSet<String>> {
    let top = fs_identity(mounts, src_mnt_id, src_real)?;
    let mut devs = std::collections::HashSet::from([top.dev]);
    if !recursive {
        return Some(devs);
    }
    let mut children: HashMap<u64, Vec<&MountRow>> = HashMap::new();
    for m in mounts {
        children.entry(m.parent).or_default().push(m);
    }
    let mut seen = std::collections::HashSet::from([src_mnt_id]);
    let mut stack = vec![src_mnt_id];
    while let Some(id) = stack.pop() {
        for child in children.get(&id).into_iter().flatten() {
            if !seen.insert(child.id) || under(src_real, &child.point).is_none() {
                continue;
            }
            devs.insert(child.dev.clone());
            stack.push(child.id);
        }
    }
    Some(devs)
}

/// `state_root`（正規化済みの絶対パス）の配下に載るマウントの実体（状態ルート自身のマウントは含まない）。
/// 状態ルート配下の子 bind mount 経由でも状態ファイルを公開させないため、保護対象に加える（SEC-1・#1915）。
/// 覆い隠されたマウントも保守的に含める。各要素は FS 内の実体と、ホスト側のマウントポイント（走査・枝刈りに使う）。
pub(crate) fn mounts_under(mounts: &[MountRow], state_root: &str) -> Vec<(FsIdentity, String)> {
    mounts
        .iter()
        .filter(|m| m.point != state_root && under(state_root, &m.point).is_some())
        .map(|m| {
            (
                FsIdentity {
                    dev: m.dev.clone(),
                    path: m.root.clone(),
                },
                m.point.clone(),
            )
        })
        .collect()
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
        let state = fs_identity(&mounts, 20, "/state").expect("state");
        assert_eq!(state.path, "/srv/state");
        // 別名（/srv/state）・祖先（/srv）・子孫は拒否、無関係は許可。
        assert_eq!(
            source_reaches(&mounts, 10, "/srv/state", true, &state),
            Some(true)
        );
        assert_eq!(
            source_reaches(&mounts, 10, "/srv", true, &state),
            Some(true)
        );
        assert_eq!(
            source_reaches(&mounts, 10, "/srv/state/sub", true, &state),
            Some(true)
        );
        assert_eq!(source_reaches(&mounts, 10, "/", true, &state), Some(true));
        assert_eq!(
            source_reaches(&mounts, 10, "/srv/data", true, &state),
            Some(false)
        );
        assert_eq!(
            source_reaches(&mounts, 30, "/mnt/other dir", true, &state),
            Some(false)
        );
    }

    /// SEC-1（#1915）: 再帰 bind で一緒に公開される配下マウントが状態ルートの実体なら拒否する。
    /// 非再帰 bind は配下のマウントを公開しないため拒否しない（誤拒否の回避。P1）。
    #[test]
    fn sec1_nested_mount_of_state_is_rejected_only_when_recursive() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:2 /st /state rw - ext4 /dev/sdb1 rw\n\
                    30 10 8:2 /st /pub/inner rw - ext4 /dev/sdb1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, 20, "/state").expect("state");
        assert_eq!(
            source_reaches(&mounts, 10, "/pub", true, &state),
            Some(true)
        );
        assert_eq!(
            source_reaches(&mounts, 10, "/pub", false, &state),
            Some(false)
        );
        assert_eq!(
            source_reaches(&mounts, 10, "/unrelated", true, &state),
            Some(false)
        );
    }

    /// SEC-1（#1915）: 親への overmount で覆われた子マウントが残っていても、元は fd の mnt_id で特定する。
    /// `/pub` に別のマウント（id 40）が載り、状態ルートの実体を持つ `/pub/inner`（id 30）が覆われている。
    /// 元 `/pub/x`（id 40）は覆われた行ではなく id 40 の実体で判定する（最長一致なら 30 を選んでしまう）。
    #[test]
    fn sec1_overmounted_child_does_not_hide_actual_mount() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:2 /st /state rw - ext4 /dev/sdb1 rw\n\
                    30 10 8:2 /st /pub/inner rw - ext4 /dev/sdb1 rw\n\
                    40 10 8:3 / /pub rw - ext4 /dev/sdc1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, 20, "/state").expect("state");
        // id 40 の中の `/pub/inner/y` は 8:3 の `/inner/y`（状態ルートではない）。
        let id = fs_identity(&mounts, 40, "/pub/inner/y").expect("id");
        assert_eq!((id.dev.as_str(), id.path.as_str()), ("8:3", "/inner/y"));
        assert_eq!(
            source_reaches(&mounts, 40, "/pub/inner/y", true, &state),
            Some(false)
        );
        // 元のマウント ID が mountinfo に無い・パスがそのマウントの外なら位置を特定できない。
        assert_eq!(source_reaches(&mounts, 99, "/pub", true, &state), None);
        assert_eq!(
            source_reaches(&mounts, 40, "/elsewhere", true, &state),
            None
        );
    }

    #[test]
    fn parse_mountinfo_rejects_malformed_line() {
        assert!(parse_mountinfo("garbage").is_none());
    }

    /// 行数の上限（[`MOUNTINFO_MAX_LINES`]）を超える入力は解釈せず拒否する。
    #[test]
    fn parse_mountinfo_rejects_too_many_lines() {
        let line = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let ok = line.repeat(MOUNTINFO_MAX_LINES);
        assert_eq!(
            parse_mountinfo(&ok).map(|v| v.len()),
            Some(MOUNTINFO_MAX_LINES)
        );
        let over = line.repeat(MOUNTINFO_MAX_LINES + 1);
        assert!(parse_mountinfo(&over).is_none());
    }

    /// バイト数の上限を超えるファイルは `TooLarge`、上限ちょうどは読める。
    #[test]
    fn read_mountinfo_bounded_enforces_byte_limit() {
        let dir = std::env::temp_dir().join(format!("fandhe-mi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("mountinfo");
        let at_cap = usize::try_from(MOUNTINFO_MAX_BYTES).expect("cap");
        std::fs::write(&path, "a".repeat(at_cap)).expect("write");
        let p = path.to_str().expect("utf8");
        assert_eq!(read_mountinfo_bounded(p).map(|t| t.len()), Ok(at_cap));
        std::fs::write(&path, "a".repeat(at_cap + 1)).expect("write");
        assert_eq!(read_mountinfo_bounded(p), Err(MountinfoReadError::TooLarge));
        assert_eq!(
            read_mountinfo_bounded(dir.join("none").to_str().expect("utf8")),
            Err(MountinfoReadError::Unreadable)
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// REPAIR-5（#1915）: `path_mount_id` は FIFO を開かず（ブロックせず）`None` を返す。通常ファイルは特定できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_path_mount_id_does_not_block_on_fifo() {
        let dir = std::env::temp_dir().join(format!("fandhe-mi-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fifo = dir.join("f");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let file = dir.join("r");
        std::fs::write(&file, b"x").expect("write");
        assert_eq!(path_mount_id(fifo.to_str().expect("utf8")), None);
        assert!(path_mount_id(file.to_str().expect("utf8")).is_some());
        assert!(path_mount_id(dir.to_str().expect("utf8")).is_some());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// SEC-1（#1915）: 再帰 bind の公開範囲のデバイスに子マウントも含み、rbind でなければ含まない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_exposed_devs_includes_child_mounts_only_for_rbind() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:2 / /data rw - ext4 /dev/sda2 rw\n\
                    30 10 8:3 / /other rw - ext4 /dev/sda3 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let r = exposed_devs(&mounts, 10, "/", true).expect("rbind");
        assert_eq!(r.len(), 3);
        let n = exposed_devs(&mounts, 10, "/", false).expect("bind");
        assert_eq!(n, std::collections::HashSet::from(["8:1".to_owned()]));
        let sub = exposed_devs(&mounts, 10, "/etc", true).expect("sub");
        assert_eq!(sub, std::collections::HashSet::from(["8:1".to_owned()]));
    }

    /// SEC-1（#1915）: 状態ルート配下のマウントの実体を列挙する（状態ルート自身は除く）。
    #[test]
    fn sec1_mounts_under_lists_child_mounts_of_state_root() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 /srv/state /state rw - ext4 /dev/sda1 rw\n\
                    30 20 8:2 /container-state /state/c1 rw - ext4 /dev/sda2 rw\n\
                    40 10 8:3 / /statex rw - ext4 /dev/sda3 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let v = mounts_under(&mounts, "/state");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0.dev, "8:2");
        assert_eq!(v[0].0.path, "/container-state");
        assert_eq!(v[0].1, "/state/c1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_fdinfo_mnt_id_reads_the_field() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t012\nmnt_id:\t42\n"),
            Some(42)
        );
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\n"), None);
    }

    /// SEC-1（#1915）: 全体 bind（root が `/`）が状態ルートを含むときも到達と判定する（`/` を祖先として扱う）。
    #[test]
    fn sec1_whole_host_bind_reaches_state() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 / /mnt/root rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let state = fs_identity(&mounts, 20, "/mnt/root/srv/state").expect("state");
        assert_eq!(state.path, "/srv/state");
        // 元が `/` の全体 bind（FS 内パス `/`）は状態ルートの祖先。
        let whole = FsIdentity {
            dev: "8:1".to_owned(),
            path: "/".to_owned(),
        };
        assert!(identity_overlaps(&whole, &state));
        assert_eq!(
            source_reaches(&mounts, 20, "/mnt/root", true, &state),
            Some(true)
        );
        assert_eq!(
            source_reaches(&mounts, 20, "/mnt/root/srv", true, &state),
            Some(true)
        );
        assert_eq!(
            source_reaches(&mounts, 20, "/mnt/root/other", true, &state),
            Some(false)
        );
        // 別デバイスの `/` は無関係。
        let other = FsIdentity {
            dev: "8:2".to_owned(),
            path: "/".to_owned(),
        };
        assert!(!identity_overlaps(&other, &state));
    }
}
