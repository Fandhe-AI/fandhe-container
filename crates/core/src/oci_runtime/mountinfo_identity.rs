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
//!
//! # mountinfo のパス文字列による行選択の点検（#2823・SEC-1・CORE-2・NET-1）
//!
//! 同じパスに別のマウントが重なる・祖先の overmount で隠れるマウントがあると、mount point や root の文字列で
//! 行を選ぶ判定は取り違える（crates/net の `unpin_in_dir` は #2764 で fd の `mnt_id` 照合へ変更済み）。
//! crates/core の箇所ごとの判定は次のとおり。
//!
//! | 箇所 | 判定 |
//! | ---- | ---- |
//! | `fs_identity`・`reaches_by`・`exposed_devs`・`mounts_under` の降り方 | 変更不要。`mnt_id` で行を引き、配下は parent ID で降りる。文字列は引いた後の絞り込みか、隠れた行も含める保守側のみ |
//! | `exec` の `mount_is_shared_in`・`mount_is_read_only_in`、`masked_paths`・`inject`・`devices`・`tmpfs` の before / after 照合 | 変更不要。`mnt_id` のみで判定 |
//! | `exec/bind_mounts` の `subtree_members`・`check_bind_subtree_with`・overlay 層・`fresh_state_identity` | 変更不要。ID・parent ID・dev で引く |
//! | `exec/rootfs` の `check_no_submounts`・`bind_lineage_ok`・pivot 後の検査 | 変更不要。ID の親子関係 |
//! | `landlock/apply`・`image_rootfs`・`start` の状態ルート / rootfs / bundle | 変更不要。fd の `mnt_id` で照合 |
//! | `exec/sysfs::check_sysfs_tree`・`exec/path_masks::check_subtree_read_only`（部分木の事後検証） | 変更済み。配下を前方一致で集めると隠れた行まで数え誤拒否していたため、top の `mnt_id` から parent ID で降りる |
//! | `start::build_protected_roots`（状態ルートの子マウントのハードリンク走査） | 変更済み。隠れた子を見えているマウントの中身に帰属させ、走査の枝刈りで同じ FS の一部を走査し損ねうるため、start の時点で point を fd で辿った `mnt_id` と子の ID を照合し、見えていない子は「リンクあり」に固定して枝刈りから外す |
//! | `sys.rs` 試験の devpts 実機試験 | 変更済み。返された fd の `mnt_id` で行を引く |
//! | `sys.rs` 試験の `is_mount_point`・`mount_options_of`、`sealed_copy` 試験の `/proc` 検索、`bind_mounts` 試験の `point == merged` | 据え置き。自作の一時マウントを引く実機前提の試験で、重なりの有無で意味が変わらない |
//!
//! 残余: 子マウントの可視判定は start の時点のトポロジーに基づく。restart までの間に構成が変わった場合は、従来の
//! 走査根・枝刈りと同じく start の時点の値を使う。別 crate（platform-macos・platform-windows）の
//! 独自のパス照合は本点検の範囲外。cli の `doctor` は #2909 で点検済み（`crates/cli/src/doctor.rs` のモジュール doc 参照）。

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

/// fdinfo として読むバイト数の上限（超過は拒否）。`O_PATH` の fd の fdinfo は数十バイトで、crates/net の
/// `MAX_FDINFO_READ` と同じ値にそろえる。landlock の旧上限（4096 での黙った切り捨て）はこの拒否に統一した（#2762）。
#[cfg(target_os = "linux")]
pub(crate) const FDINFO_MAX_BYTES: u64 = 64 * 1024;

/// fdinfo の `mnt_id` の読み取り・解析の失敗。呼び出し側が自分の段・エラー型へ写す（REPAIR-1・CORE-2・#2762）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum FdinfoMountIdError {
    /// 読めない（open・read の失敗、または UTF-8 でない）。
    Read(std::io::Error),
    /// [`FDINFO_MAX_BYTES`] を超える。
    TooLarge,
    /// 行頭が `mnt_id:` の行が無い。
    Missing,
    /// 行頭が `mnt_id:` の行が 2 つ以上ある（値が同じでも拒否する。fail-closed）。
    Duplicate,
    /// 値が `u64` として解釈できない（空・非数値・負数・桁あふれ）。
    Invalid,
}

/// fdinfo の本文から行頭が `mnt_id:` の行の値（fd が属するマウントの ID）を取り出す純関数。
/// 重複行は拒否する（`setns::parse_fdinfo_pid` と同じ。カーネルは 1 行しか出さない）。
/// 呼び出しは [`read_fd_mnt_id`] 経由が基本で、crates/core で fdinfo の `mnt_id` を解析する唯一の実装（REPAIR-1）。
/// crates/net・crates/gpu に同じ規則の別実装がある（依存方向のため共有しない。判断は
/// `docs/design/fdinfo-mnt-id-parsing.md`・#3140）。規則を変えるときは `testdata/fdinfo_mnt_id_cases.txt` と
/// 3 か所を同じ PR で直す（一致は 3 crate の `*_fdinfo_mnt_id_shared_cases` 試験が機械照合する）。
#[cfg(target_os = "linux")]
pub(crate) fn parse_fdinfo_mnt_id(fdinfo: &str) -> Result<u64, FdinfoMountIdError> {
    let mut found: Option<&str> = None;
    for value in fdinfo.lines().filter_map(|l| l.strip_prefix("mnt_id:")) {
        if found.replace(value).is_some() {
            return Err(FdinfoMountIdError::Duplicate);
        }
    }
    let value = found.ok_or(FdinfoMountIdError::Missing)?;
    value
        .trim()
        .parse()
        .map_err(|_| FdinfoMountIdError::Invalid)
}

/// `r` を [`FDINFO_MAX_BYTES`] までだけ読む。超過は `TooLarge`（fail-closed）。
#[cfg(target_os = "linux")]
fn read_fdinfo_bounded(r: impl std::io::Read) -> Result<String, FdinfoMountIdError> {
    let mut text = String::new();
    // 上限 + 1 バイトまで読み、超えたら拒否する（確保量は上限で頭打ち）。
    r.take(FDINFO_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(FdinfoMountIdError::Read)?;
    if u64::try_from(text.len()).map_or(true, |n| n > FDINFO_MAX_BYTES) {
        return Err(FdinfoMountIdError::TooLarge);
    }
    Ok(text)
}

/// `fd` の属するマウント ID を `/proc/thread-self/fdinfo/<fd>` から上限つきで読む。
/// `/proc/self` ではなく `thread-self` を使う（`establish` 後の別スレッドでは `/proc/self` が別の mount namespace を
/// 指し得るため）。exec・bind mount・landlock・image rootfs の各段が使う（REPAIR-1・CORE-2・#2762）。
#[cfg(target_os = "linux")]
pub(crate) fn read_fd_mnt_id(fd: std::os::fd::BorrowedFd<'_>) -> Result<u64, FdinfoMountIdError> {
    use std::os::fd::AsRawFd as _;
    let file = std::fs::File::open(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(FdinfoMountIdError::Read)?;
    parse_fdinfo_mnt_id(&read_fdinfo_bounded(file)?)
}

/// `path` を `O_PATH` で開いた fd の属するマウント ID（`/proc/thread-self/fdinfo/N`）。start の段が使う。
/// `O_PATH` はブロックしないため、検査と open の間に FIFO 等へ差し替えられても停止しない（REPAIR-5）。
/// 種別は開いた同じ fd の `fstat` で見て、ディレクトリと通常ファイル以外は `None`（適用の段が種別で拒否する）。
#[cfg(target_os = "linux")]
pub(crate) fn path_mount_id(path: &str) -> Option<u64> {
    use std::os::fd::AsFd as _;
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
    read_fd_mnt_id(fd.as_fd()).ok()
}

/// Linux 以外では `/proc` と `crate::sys` が無いため特定できない（bind mount は Linux 限定。呼び出し側は fail-closed にする）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn path_mount_id(_path: &str) -> Option<u64> {
    None
}

/// 鎖の長さの上限（適用の段の `MAX_ANCESTORS` と同じ。無制限の確保を避ける）。
#[cfg(target_os = "linux")]
const DIR_CHAIN_MAX: usize = 4096;

/// 絶対パス `path` のディレクトリを `/` から 1 要素ずつ `O_NOFOLLOW` で辿り、`(st_dev, st_ino)` の鎖を返す
/// （先頭が `path` 自身、末尾が `/`）。start の段が状態ルートの実体を固定するために使い、適用の段（restart を含む毎回）が
/// 元との同一・祖先・子孫の照合に使う（SEC-1・SEC-4・#2066）。mountinfo の文字列に依存せず、start の後に状態ルートや
/// 祖先が改名されても inode は変わらないため照合できる。
/// symlink・ディレクトリでない要素・絶対パスでない・[`DIR_CHAIN_MAX`] 段超は `None`（呼び出し側が fail-closed にする）。
#[cfg(target_os = "linux")]
pub(crate) fn dir_identity_chain(path: &str) -> Option<Vec<(u64, u64)>> {
    walk_dir_chain(path).map(|(chain, _leaf)| chain)
}

/// [`dir_identity_chain`] と同じ辿り方で鎖を作り、辿った末端の fd の属するマウント ID（fdinfo の `mnt_id`）も返す。
/// overlayfs の層が別の overlay の上にあるか（入れ子。mountinfo の fstype で判定する）を適用の段が見るために使う
/// （SEC-1・#2166）。末端の fd を固定したまま `mnt_id` を読むため、辿り直しによる差し替えの余地が無い。
#[cfg(target_os = "linux")]
pub(crate) fn dir_identity_chain_with_mnt_id(path: &str) -> Option<(Vec<(u64, u64)>, u64)> {
    use std::os::fd::AsFd as _;
    let (chain, leaf) = walk_dir_chain(path)?;
    Some((chain, read_fd_mnt_id(leaf.as_fd()).ok()?))
}

/// `dir_identity_chain` の本体。鎖と末端のディレクトリの fd を返す。
#[cfg(target_os = "linux")]
fn walk_dir_chain(path: &str) -> Option<(Vec<(u64, u64)>, std::os::fd::OwnedFd)> {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;
    if !path.starts_with('/') {
        return None;
    }
    let id = |fd: &std::os::fd::OwnedFd| -> Option<(u64, u64)> {
        let meta = std::fs::File::from(fd.try_clone().ok()?).metadata().ok()?;
        meta.is_dir().then(|| (meta.dev(), meta.ino()))
    };
    let mut cur = crate::sys::open_dir_path_nofollow(None, c"/").ok()?;
    let mut chain = vec![id(&cur)?];
    for name in path.split('/').filter(|e| !e.is_empty()) {
        if chain.len() >= DIR_CHAIN_MAX {
            return None;
        }
        let c = std::ffi::CString::new(name).ok()?;
        cur = crate::sys::open_dir_path_nofollow(Some(cur.as_fd()), &c).ok()?;
        chain.push(id(&cur)?);
    }
    chain.reverse();
    Some((chain, cur))
}

/// Linux 以外では `crate::sys` が無いため固定できない（bind mount は Linux 限定。呼び出し側は fail-closed にする）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn dir_identity_chain(_path: &str) -> Option<Vec<(u64, u64)>> {
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
#[derive(Clone)]
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
/// 覆い隠されたマウントも保守的に含める。各要素は FS 内の実体と、ホスト側のマウントポイント（走査・枝刈りに使う）と mount ID
/// （そのマウントが見えているかの fd 照合に使う。#2823）。
pub(crate) fn mounts_under(
    mounts: &[MountRow],
    state_root: &str,
) -> Vec<(FsIdentity, String, u64)> {
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
                m.id,
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
        assert_eq!(v[0].2, 30);
    }

    /// SEC-1・CORE-2（#2823）: 祖先の overmount で隠れた子も、mount ID つきで保守的に含める（見えているかは呼び出し側が fd で判定）。
    #[test]
    fn sec1_2823_mounts_under_includes_hidden_children_with_ids() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    20 10 8:1 /srv/state /state rw - ext4 /dev/sda1 rw\n\
                    30 20 8:3 / /state/x/y rw - ext4 /dev/sda3 rw\n\
                    35 20 8:1 /srv/state/x /state/x rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(info).expect("parse");
        let v = mounts_under(&mounts, "/state");
        let got: Vec<(&str, &str, u64)> = v
            .iter()
            .map(|(i, p, id)| (i.dev.as_str(), p.as_str(), *id))
            .collect();
        assert_eq!(
            got,
            vec![("8:3", "/state/x/y", 30), ("8:1", "/state/x", 35)]
        );
    }

    /// REPAIR-1・SEC-1・#3140: 共有 fixture（`testdata/fdinfo_mnt_id_cases.txt`）の全事例で、解析結果が期待と完全一致する。net・gpu の同名の照合試験と同じ fixture を読む。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair1_fdinfo_mnt_id_shared_cases() {
        use std::io::Cursor;
        const CASES: &str = include_str!("../../testdata/fdinfo_mnt_id_cases.txt");

        fn hex(s: &str) -> Vec<u8> {
            if s == "-" {
                return Vec::new();
            }
            assert!(s.len().is_multiple_of(2), "odd hex: {s}");
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect()
        }

        let classify = |bytes: &[u8]| -> String {
            match read_fdinfo_bounded(Cursor::new(bytes)).and_then(|t| parse_fdinfo_mnt_id(&t)) {
                Ok(n) => format!("ok:{n}"),
                Err(FdinfoMountIdError::Read(_)) => "read".into(),
                Err(FdinfoMountIdError::TooLarge) => "too_large".into(),
                Err(FdinfoMountIdError::Missing) => "missing".into(),
                Err(FdinfoMountIdError::Duplicate) => "duplicate".into(),
                Err(FdinfoMountIdError::Invalid) => "invalid".into(),
            }
        };
        let mut max_bytes = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0usize;
        for line in CASES
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f[0] == "max_bytes" {
                max_bytes = Some(f[1].parse::<u64>().expect("max_bytes"));
                continue;
            }
            let bytes = hex(f[1]);
            let shared = f[2];
            let over = f
                .get(3)
                .map(|o| o.strip_prefix("net=").expect("net= prefix"));
            let want = shared;
            let _ = over;
            let got = classify(&bytes);
            assert_eq!(
                got,
                want,
                "case {}: input {:?}",
                f[0],
                String::from_utf8_lossy(&bytes)
            );
            seen.insert(shared.split(':').next().unwrap().to_string());
            count += 1;
        }
        assert!(count >= 16, "fixture is too small: {count}");
        for k in ["ok", "missing", "duplicate", "invalid", "read"] {
            assert!(seen.contains(k), "fixture has no {k} case");
        }
        let max = max_bytes.expect("max_bytes line");
        assert_eq!(max, FDINFO_MAX_BYTES, "limit constant differs from fixture");
        let n = usize::try_from(max).unwrap();
        assert_eq!(classify(&vec![b'a'; n]), "missing");
        assert_eq!(classify(&vec![b'a'; n + 1]), "too_large");
    }

    /// REPAIR-1・CORE-2（#2762）: fdinfo の `mnt_id` 解析の正常系と、欠落・重複・非数値・上限超えの拒否。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair1_parse_fdinfo_mnt_id_cases() {
        let ok = |s: &str| parse_fdinfo_mnt_id(s).unwrap();
        assert_eq!(ok("pos:\t0\nflags:\t012600000\nmnt_id:\t52\nino:\t1\n"), 52);
        // 行頭が `mnt_id:` でない行は対象にならない。
        assert_eq!(ok("fanotify mnt_id:\t9\nmnt_id:\t7\n"), 7);
        assert_eq!(ok("mnt_id:\t18446744073709551615\n"), u64::MAX);
        assert!(matches!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t0\n"),
            Err(FdinfoMountIdError::Missing)
        ));
        assert!(matches!(
            parse_fdinfo_mnt_id(""),
            Err(FdinfoMountIdError::Missing)
        ));
        assert!(matches!(
            parse_fdinfo_mnt_id("mnt_id:\t52\nmnt_id:\t53\n"),
            Err(FdinfoMountIdError::Duplicate)
        ));
        assert!(matches!(
            parse_fdinfo_mnt_id("mnt_id:\t52\nmnt_id:\t52\n"),
            Err(FdinfoMountIdError::Duplicate)
        ));
        for bad in [
            "mnt_id:\tx\n",
            "mnt_id:\t-1\n",
            "mnt_id:\t\n",
            "mnt_id:\t18446744073709551616\n",
        ] {
            assert!(
                matches!(parse_fdinfo_mnt_id(bad), Err(FdinfoMountIdError::Invalid)),
                "{bad:?}"
            );
        }
    }

    /// REPAIR-1・REPAIR-5（#2762）: 読み取りの上限ちょうどは通り、1 バイト超えは `TooLarge`。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair1_read_fdinfo_bounded_limit() {
        let n = usize::try_from(FDINFO_MAX_BYTES).unwrap();
        let at = read_fdinfo_bounded(std::io::Cursor::new(vec![b'a'; n])).unwrap();
        assert_eq!(at.len(), n);
        assert!(matches!(
            read_fdinfo_bounded(std::io::Cursor::new(vec![b'a'; n + 1])),
            Err(FdinfoMountIdError::TooLarge)
        ));
    }

    /// REPAIR-1・CORE-2（#2762）: 実 fd の `mnt_id` が `/proc/thread-self/mountinfo` にちょうど 1 行ある。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair1_read_fd_mnt_id_matches_mountinfo() {
        use std::os::fd::AsFd as _;
        let f = std::fs::File::open("/").unwrap();
        let id = read_fd_mnt_id(f.as_fd()).unwrap();
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").unwrap();
        let n = info
            .lines()
            .filter(|l| l.split(' ').next().and_then(|v| v.parse::<u64>().ok()) == Some(id))
            .count();
        assert_eq!(n, 1);
    }

    /// SEC-1（#2066）: 鎖は自身が先頭・`/` が末尾で、各要素は実ディレクトリの (dev, ino)。symlink・存在しない・相対は `None`。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_dir_identity_chain_runs_from_leaf_to_root() {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = crate::test_support::TestTempDir::new("dir-chain").expect("temp dir");
        let leaf = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&leaf).expect("a/b");
        let id = |p: &std::path::Path| {
            let m = std::fs::metadata(p).expect("metadata");
            (m.dev(), m.ino())
        };
        let chain = dir_identity_chain(leaf.to_str().expect("utf8")).expect("chain");
        assert_eq!(chain.first(), Some(&id(&leaf)));
        assert_eq!(chain.get(1), Some(&id(&tmp.path().join("a"))));
        assert_eq!(chain.get(2), Some(&id(tmp.path())));
        assert_eq!(chain.last(), Some(&id(std::path::Path::new("/"))));
        std::os::unix::fs::symlink(&leaf, tmp.path().join("link")).expect("symlink");
        assert_eq!(
            dir_identity_chain(tmp.path().join("link").to_str().expect("utf8")),
            None
        );
        assert_eq!(
            dir_identity_chain(tmp.path().join("nope").to_str().expect("utf8")),
            None
        );
        assert_eq!(dir_identity_chain("relative/path"), None);
    }

    /// SEC-1・#2166: 鎖と末端の `mnt_id` を一度に返す。鎖は [`dir_identity_chain`] と同じで、`mnt_id` は `path_mount_id` と一致する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_2166_dir_identity_chain_with_mnt_id_matches_plain_chain() {
        let tmp = crate::test_support::TestTempDir::new("dir-chain-mnt").expect("temp dir");
        let leaf = tmp.path().join("a");
        std::fs::create_dir_all(&leaf).expect("a");
        let path = leaf.to_str().expect("utf8");
        let (chain, mnt_id) = dir_identity_chain_with_mnt_id(path).expect("chain");
        assert_eq!(Some(chain), dir_identity_chain(path));
        assert_eq!(Some(mnt_id), path_mount_id(path));
        assert_eq!(dir_identity_chain_with_mnt_id("relative/path"), None);
        assert_eq!(
            dir_identity_chain_with_mnt_id(tmp.path().join("nope").to_str().expect("utf8")),
            None
        );
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
