//! secrets / configs 注入の検証済み仕様型（SUP-12・TASK-169.4.2・SEC-1・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `container_options`（Docker 互換の指定モデル）が secrets / configs を解析して本モジュールの
//! 型へ変換し、`crate::exec` の `inject_files`（Linux 限定・`mount_tmpfs` の後・`pivot_root` の前）が
//! 「親ディレクトリごとの専用 tmpfs を作る → 内容を書く → read-only へ再マウントする」で実際に注入する。
//! 本モジュールは OS 非依存の純粋な型だけを持つ（[`crate::tmpfs`] と同じ位置づけ）。
//!
//! # 契約
//!
//! - **内容は表に出さない**: [`InjectedContent`] の `Debug` は長さだけを出す。本モジュールのエラー message は
//!   固定の英語文言で、利用者が渡したパス・内容を含めない（A4: 内容がログ・エラーへ出ない）
//! - **上限は確保前に検証**: 1 件のサイズ（[`INJECTED_FILE_MAX_BYTES`]）・件数（[`INJECTED_MAX_FILES`]）・
//!   合計サイズ（[`INJECTED_MAX_TOTAL_BYTES`]）・パス長・深さ・ファイル名長を上限検証する（無制限確保の防止）
//! - **マウント先**: [`MountDestination`]（字句正規化・`..` 拒否）で検証し、親ディレクトリが `/` になる指定
//!   （rootfs 直下）・`/proc` 配下・`/dev` そのものは拒否する。親ディレクトリごとに専用 tmpfs を 1 つ作る
//!   ため、異なる注入ディレクトリが入れ子になる指定と、利用者指定の tmpfs（`/dev/shm` を含む）との重なりは
//!   拒否する（どちらかが他方を覆い隠すため。[`InjectedFileSet::check_against_tmpfs`]）
//! - **モード**: `0o777` 以下のみ（setuid / setgid / sticky は拒否）。既定は `0o444`
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! launcher・CLI・stack（TOML）からの配線、uid / gid 指定、単一ファイルの bind 注入（既存ディレクトリへ
//! 1 ファイルだけ見せる）、利用者 tmpfs の配下への注入、環境変数由来の内容。

use crate::oci_runtime::{CONFIG_MAX_PATH_BYTES, MountDestination};
use crate::tmpfs::{TMPFS_MAX_DESTINATION_DEPTH, TmpfsMountSet};
use crate::traits::types::{ErrorCode, TraitError};

/// 注入ファイル 1 件の内容サイズの上限（512 KiB。Docker の secret の上限 500 KiB に合わせた値）。
pub const INJECTED_FILE_MAX_BYTES: usize = 512 * 1024;

/// 1 コンテナあたりの注入ファイル件数の上限。
pub const INJECTED_MAX_FILES: usize = 64;

/// 1 コンテナあたりの注入ファイルの合計サイズの上限（4 MiB。tmpfs はメモリに課金されるため抑える）。
pub const INJECTED_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// ファイル名（最終要素）の長さの上限（バイト。多くのファイルシステムの `NAME_MAX`）。
pub const INJECTED_FILE_NAME_MAX_BYTES: usize = 255;

/// 注入用 tmpfs のサイズを切り上げる単位（ページサイズ 4K / 16K / 64K のいずれでも表示が変わらない）。
pub const INJECTED_TMPFS_SIZE_UNIT: u64 = 64 * 1024;

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

/// 注入するファイルの内容。`Debug` は長さだけを出し、内容を表に出さない。
#[derive(Clone, PartialEq, Eq)]
pub struct InjectedContent(Vec<u8>);

impl InjectedContent {
    /// 内容から作る。[`INJECTED_FILE_MAX_BYTES`] 超は拒否する（空は許す）。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, TraitError> {
        if bytes.len() > INJECTED_FILE_MAX_BYTES {
            return Err(invalid("injected file content is too large"));
        }
        Ok(Self(bytes))
    }

    /// 内容のバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 内容のバイト数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for InjectedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InjectedContent(<redacted {} bytes>)", self.0.len())
    }
}

/// 注入ファイルのモード（`0o777` 以下）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectedFileMode(u32);

impl InjectedFileMode {
    /// 既定の `0444`（Docker の secret / config の既定と同じ）。
    pub const DEFAULT: Self = Self(0o444);

    /// モードから作る。`0o777` 超（setuid / setgid / sticky を含む）は拒否する。
    pub fn new(mode: u32) -> Result<Self, TraitError> {
        if mode > 0o777 {
            return Err(invalid("injected file mode must not exceed 0777"));
        }
        Ok(Self(mode))
    }

    /// モード値。
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// 検証済みの注入ファイル 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InjectedFileSpec {
    destination: MountDestination,
    parent: String,
    file_name: String,
    content: InjectedContent,
    mode: InjectedFileMode,
}

impl InjectedFileSpec {
    /// 注入ファイルを作る。`destination` は外部入力として扱い、正規化の確保より前に長さと要素数を検証する。
    pub fn new(
        destination: &str,
        content: InjectedContent,
        mode: InjectedFileMode,
    ) -> Result<Self, TraitError> {
        if destination.len() > CONFIG_MAX_PATH_BYTES {
            return Err(invalid("injected file destination is too long"));
        }
        let depth = destination
            .split('/')
            .filter(|e| !e.is_empty() && *e != ".")
            .count();
        if depth > TMPFS_MAX_DESTINATION_DEPTH {
            return Err(invalid("injected file destination is too deep"));
        }
        let destination = MountDestination::parse(destination)
            .map_err(|_| invalid("invalid injected file destination"))?;
        let (parent, name) = destination
            .as_str()
            .rsplit_once('/')
            .map(|(p, n)| (p.to_owned(), n.to_owned()))
            .ok_or_else(|| invalid("invalid injected file destination"))?;
        // 親が rootfs 直下（空文字 = `/`）になる指定は、rootfs 全体を覆う tmpfs になるため拒否する。
        if parent.is_empty() {
            return Err(invalid(
                "injected file must be placed in a directory below the root",
            ));
        }
        if name.len() > INJECTED_FILE_NAME_MAX_BYTES {
            return Err(invalid("injected file name is too long"));
        }
        Ok(Self {
            destination,
            parent,
            file_name: name,
            content,
            mode,
        })
    }

    /// コンテナ内のマウント先（ファイルのパス。正規化済み）。
    pub fn destination(&self) -> &MountDestination {
        &self.destination
    }

    /// 親ディレクトリ（`/` 始まり・正規化済み）。専用 tmpfs のマウント先になる。
    pub fn parent(&self) -> &str {
        &self.parent
    }

    /// ファイル名（最終要素）。
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// 内容。
    pub fn content(&self) -> &InjectedContent {
        &self.content
    }

    /// モード。
    pub fn mode(&self) -> InjectedFileMode {
        self.mode
    }
}

/// 親ディレクトリごとにまとめた注入ファイル（[`InjectedFileSet::groups`] の要素）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InjectedGroup<'a> {
    /// 専用 tmpfs のマウント先（親ディレクトリ）。
    pub directory: &'a str,
    /// このディレクトリへ置くファイル（指定順）。
    pub files: Vec<&'a InjectedFileSpec>,
    /// tmpfs の `size`（内容合計を [`INJECTED_TMPFS_SIZE_UNIT`] の倍数へ切り上げ。最小 1 単位）。
    pub tmpfs_size: u64,
}

/// `a` と `b` が同一または祖先・子孫の関係か（要素単位。`/a/b` と `/a/bc` は関係なし）。
fn overlaps(a: &str, b: &str) -> bool {
    let within = |child: &str, parent: &str| {
        child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    a == b || within(a, b) || within(b, a)
}

/// 検証済みの注入ファイル集合（指定順）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InjectedFileSet {
    files: Vec<InjectedFileSpec>,
    total_bytes: usize,
}

impl InjectedFileSet {
    /// 空の集合。
    pub fn new() -> Self {
        Self::default()
    }

    /// ファイルを追加する。件数・合計サイズの超過、重複、予約先、注入ディレクトリ同士の入れ子は拒否する。
    pub fn push(&mut self, spec: InjectedFileSpec) -> Result<(), TraitError> {
        // 件数・サイズは他の検証（走査）より先に確かめる。
        if self.files.len() >= INJECTED_MAX_FILES {
            return Err(invalid("too many injected files"));
        }
        if self.total_bytes.saturating_add(spec.content.len()) > INJECTED_MAX_TOTAL_BYTES {
            return Err(invalid("total size of injected files is too large"));
        }
        let parent = spec.parent();
        if parent == "/proc" || parent.starts_with("/proc/") {
            return Err(invalid(
                "injected files must not be placed on /proc or below",
            ));
        }
        if parent == "/dev" {
            return Err(invalid("injected files must not be placed on /dev itself"));
        }
        for e in &self.files {
            if e.destination == spec.destination {
                return Err(invalid("duplicate injected file destination"));
            }
            if e.parent != spec.parent
                && (overlaps(&e.parent, &spec.parent)
                    || overlaps(e.destination.as_str(), &spec.parent)
                    || overlaps(spec.destination.as_str(), &e.parent))
            {
                return Err(invalid("injected file directories must not overlap"));
            }
        }
        self.total_bytes += spec.content.len();
        self.files.push(spec);
        Ok(())
    }

    /// 指定順のファイル一覧。
    pub fn files(&self) -> &[InjectedFileSpec] {
        &self.files
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// 利用者指定の tmpfs（`/dev/shm` を含む）と注入ディレクトリが同一・祖先・子孫なら拒否する。
    pub fn check_against_tmpfs(&self, tmpfs: &TmpfsMountSet) -> Result<(), TraitError> {
        for f in &self.files {
            for t in tmpfs.mounts() {
                if overlaps(f.parent(), t.destination.as_str()) {
                    return Err(invalid("injected file directory overlaps a tmpfs mount"));
                }
            }
        }
        Ok(())
    }

    /// 親ディレクトリごとにまとめた一覧（初出順。ファイルは指定順）。
    pub fn groups(&self) -> Vec<InjectedGroup<'_>> {
        let mut groups: Vec<InjectedGroup<'_>> = Vec::new();
        for f in &self.files {
            match groups.iter_mut().find(|g| g.directory == f.parent()) {
                Some(g) => g.files.push(f),
                None => groups.push(InjectedGroup {
                    directory: f.parent(),
                    files: vec![f],
                    tmpfs_size: 0,
                }),
            }
        }
        for g in &mut groups {
            // tmpfs はファイルごとにページ単位で容量を課金するため、内容サイズの合計ではなく
            // 各ファイルを単位（64 KiB。4K / 16K / 64K ページのいずれでも足りる）へ切り上げて合算する。
            // inode・dentry は size= に課金されないため、メタデータ分の余裕は要らない。
            let total: u64 = g
                .files
                .iter()
                .map(|f| {
                    (f.content.len() as u64)
                        .div_ceil(INJECTED_TMPFS_SIZE_UNIT)
                        .saturating_mul(INJECTED_TMPFS_SIZE_UNIT)
                })
                .fold(0u64, u64::saturating_add);
            g.tmpfs_size = total.max(INJECTED_TMPFS_SIZE_UNIT);
        }
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tmpfs::TmpfsMountSpec;

    const SENTINEL: &[u8] = b"SENTINEL-DUMMY-VALUE";

    fn content(b: &[u8]) -> InjectedContent {
        InjectedContent::from_bytes(b.to_vec()).expect("content")
    }

    fn spec(dest: &str, size: usize) -> InjectedFileSpec {
        InjectedFileSpec::new(dest, content(&vec![b'x'; size]), InjectedFileMode::DEFAULT)
            .expect("spec")
    }

    fn err_of<T: std::fmt::Debug>(r: Result<T, TraitError>) -> (ErrorCode, String) {
        let e = r.expect_err("must be rejected");
        (e.code(), e.message().to_owned())
    }

    fn invalid_msg(m: &str) -> (ErrorCode, String) {
        (ErrorCode::InvalidArgument, m.to_owned())
    }

    /// SUP-12・TASK-169.4.2: 内容は 512 KiB まで。Debug は長さだけで内容を出さない。
    #[test]
    fn sup12_task169_4_2_content_bounds_and_redacted_debug() {
        assert_eq!(INJECTED_FILE_MAX_BYTES, 524_288);
        assert!(InjectedContent::from_bytes(vec![0; INJECTED_FILE_MAX_BYTES]).is_ok());
        assert!(
            InjectedContent::from_bytes(Vec::new())
                .expect("empty")
                .is_empty()
        );
        assert_eq!(
            err_of(InjectedContent::from_bytes(vec![
                0;
                INJECTED_FILE_MAX_BYTES + 1
            ])),
            invalid_msg("injected file content is too large")
        );
        let c = content(SENTINEL);
        assert_eq!(format!("{c:?}"), "InjectedContent(<redacted 20 bytes>)");
        let s =
            InjectedFileSpec::new("/run/secrets/a", c, InjectedFileMode::DEFAULT).expect("spec");
        assert!(!format!("{s:?}").contains("SENTINEL"));
    }

    /// SUP-12・TASK-169.4.2: モードは 0777 以下のみ。既定は 0444。
    #[test]
    fn sup12_task169_4_2_mode_bounds() {
        assert_eq!(InjectedFileMode::DEFAULT.bits(), 0o444);
        assert_eq!(InjectedFileMode::new(0o777).expect("max").bits(), 0o777);
        for bad in [0o1000, 0o2000, 0o4000, 0o4444] {
            assert_eq!(
                err_of(InjectedFileMode::new(bad)),
                invalid_msg("injected file mode must not exceed 0777")
            );
        }
    }

    /// SUP-12・TASK-169.4.2: 正規化・親ディレクトリ・ファイル名・各種拒否。
    #[test]
    fn sup12_task169_4_2_destination_is_normalized_and_validated() {
        let s = spec("run//secrets/./db_password", 1);
        assert_eq!(s.destination().as_str(), "/run/secrets/db_password");
        assert_eq!((s.parent(), s.file_name()), ("/run/secrets", "db_password"));
        let mk = |d: &str| InjectedFileSpec::new(d, content(b""), InjectedFileMode::DEFAULT);
        for bad in ["/a/../b", "", "/", "/a\\b", "/a\0b"] {
            assert_eq!(
                err_of(mk(bad)),
                invalid_msg("invalid injected file destination"),
                "{bad:?}"
            );
        }
        assert_eq!(
            err_of(mk("/file")),
            invalid_msg("injected file must be placed in a directory below the root")
        );
        let long_name = format!("/d/{}", "n".repeat(INJECTED_FILE_NAME_MAX_BYTES + 1));
        assert_eq!(
            err_of(mk(&long_name)),
            invalid_msg("injected file name is too long")
        );
        assert!(mk(&format!("/d/{}", "n".repeat(INJECTED_FILE_NAME_MAX_BYTES))).is_ok());
        let long = "/".repeat(CONFIG_MAX_PATH_BYTES) + "a";
        assert_eq!(
            err_of(mk(&long)),
            invalid_msg("injected file destination is too long")
        );
        assert!(mk(&"/d".repeat(TMPFS_MAX_DESTINATION_DEPTH)).is_ok());
        assert_eq!(
            err_of(mk(&"/d".repeat(TMPFS_MAX_DESTINATION_DEPTH + 1))),
            invalid_msg("injected file destination is too deep")
        );
    }

    /// SUP-12・TASK-169.4.2: 件数・合計サイズ・重複・予約先・入れ子の拒否。
    #[test]
    fn sup12_task169_4_2_set_rejects_overflow_duplicates_and_overlaps() {
        let mut set = InjectedFileSet::new();
        set.push(spec("/run/secrets/a", 1)).expect("a");
        set.push(spec("/run/secrets/b", 1)).expect("b same dir");
        assert_eq!(
            err_of(set.push(spec("/run/secrets/a/", 1))),
            invalid_msg("duplicate injected file destination")
        );
        assert_eq!(
            err_of(set.push(spec("/proc/x/y", 1))),
            invalid_msg("injected files must not be placed on /proc or below")
        );
        assert_eq!(
            err_of(set.push(spec("/dev/x", 1))),
            invalid_msg("injected files must not be placed on /dev itself")
        );
        // 別の注入ディレクトリの内側・外側、ファイルが他ディレクトリそのものになる指定は拒否する。
        for bad in ["/run/secrets/sub/c", "/run/c", "/run/secrets/a/c"] {
            assert_eq!(
                err_of(set.push(spec(bad, 1))),
                invalid_msg("injected file directories must not overlap"),
                "{bad}"
            );
        }
        // 前方一致するだけの兄弟ディレクトリは入れ子ではない。
        set.push(spec("/run/secrets2/c", 1)).expect("sibling");
        assert_eq!(set.files().len(), 3);

        let mut total = InjectedFileSet::new();
        for i in 0..8 {
            total
                .push(spec(&format!("/d{i}/f"), INJECTED_FILE_MAX_BYTES))
                .expect("within total");
        }
        assert_eq!(
            err_of(total.push(spec("/d9/f", 1))),
            invalid_msg("total size of injected files is too large")
        );

        let mut full = InjectedFileSet::new();
        for i in 0..INJECTED_MAX_FILES {
            full.push(spec(&format!("/m/f{i}"), 0))
                .expect("within limit");
        }
        assert_eq!(
            err_of(full.push(spec("/m/extra", 0))),
            invalid_msg("too many injected files")
        );
    }

    /// SUP-12・TASK-169.4.2: 利用者 tmpfs（`/dev/shm` を含む）との重なりを拒否する。
    #[test]
    fn sup12_task169_4_2_check_against_tmpfs() {
        let mut set = InjectedFileSet::new();
        set.push(spec("/run/secrets/a", 1)).expect("a");
        let tmpfs = |dests: &[&str]| {
            let mut t = TmpfsMountSet::new();
            for d in dests {
                t.push(TmpfsMountSpec::new(d, None).expect("spec"))
                    .expect("push");
            }
            t
        };
        assert_eq!(
            set.check_against_tmpfs(&tmpfs(&["/dev/shm", "/scratch"])),
            Ok(())
        );
        let overlap = invalid_msg("injected file directory overlaps a tmpfs mount");
        for dest in ["/run", "/run/secrets", "/run/secrets/x"] {
            assert_eq!(
                err_of(set.check_against_tmpfs(&tmpfs(&[dest]))),
                overlap,
                "{dest}"
            );
        }
    }

    /// SUP-12・TASK-169.4.2: ディレクトリごとのグループ化と tmpfs サイズ（64 KiB 単位の切り上げ）。
    #[test]
    fn sup12_task169_4_2_groups_and_sizes() {
        let mut set = InjectedFileSet::new();
        set.push(spec("/run/secrets/a", 10)).expect("a");
        set.push(spec("/etc/app/c", 65_536)).expect("c");
        set.push(spec("/run/secrets/b", 0)).expect("b");
        set.push(spec("/etc/app/d", 1)).expect("d");
        let groups = set.groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].directory, "/run/secrets");
        assert_eq!(
            groups[0]
                .files
                .iter()
                .map(|f| f.file_name())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(groups[0].tmpfs_size, 65_536);
        assert_eq!(groups[1].directory, "/etc/app");
        assert_eq!(groups[1].tmpfs_size, 131_072);
        // 小さいファイルが多くてもファイルごとに 1 単位ずつ課金される。
        let mut many = InjectedFileSet::new();
        for i in 0..64 {
            many.push(spec(&format!("/run/secrets/f{i}"), 1))
                .expect("f");
        }
        assert_eq!(many.groups()[0].tmpfs_size, 64 * 65_536);
        let empty = InjectedFileSet::new();
        assert!(empty.groups().is_empty() && empty.is_empty());
    }

    /// SUP-12・TASK-169.4.2: どのエラー message にも内容・入力値が現れない。
    #[test]
    fn sup12_task169_4_2_errors_never_contain_content_or_input() {
        let secret_path = "/run/SENTINEL-PATH/../x";
        let errs = [
            InjectedFileSpec::new(secret_path, content(SENTINEL), InjectedFileMode::DEFAULT)
                .expect_err("dotdot"),
            InjectedContent::from_bytes(vec![b'S'; INJECTED_FILE_MAX_BYTES + 1])
                .expect_err("large"),
        ];
        for e in errs {
            assert!(!e.message().contains("SENTINEL"), "{}", e.message());
        }
    }
}
