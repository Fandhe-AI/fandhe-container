//! 試験用の virtiofs symlink・ハードリンク観測モード（MAC-1・SEC-4・REPAIR-3・TASK-65.1 追補・#1877・#1374）。
//!
//! `AGENTS.md`「virtiofs の symlink・ハードリンク挙動の手動確認」の観測（ゲストからの `readlink`・`cat`・
//! `stat`・`ln`）を、シェルもコマンドも無い initrd（#362）の中から行うために、init が hvc0 へ出す行を作る。
//! ホストの結合試験 `platform-macos/tests/virtiofs_link.rs`（macOS 実機）が読む。行の形・名前空間の SSOT は
//! ホスト側 `guest_link_probe` で、`tests/contract.rs` が往復を照合する。呼び出し元は `init::run`
//! （ready の後に 1 回）。**判定はしない**: 観測結果の解釈と #1374 への記録は人間、拒否範囲を緩めるかは
//! オーナーの判断で、本モジュールは事実を 1 行 1 観測で出すだけ。
//!
//! # 起動条件（本番の起動では走らない）
//!
//! 予約キー `fandhe.guest-test=virtiofs-link` がちょうど 1 個あること（[`crate::probe::decode_test_mode`]。
//! 利用者のコマンドラインでは `reject_reserved_keys` により注入できない）と、共有ごとの mount 成功
//! （tag・mount point・access の完全一致）の AND。成立しない共有には FS 操作をせず `op=mount result=missing`
//! を 1 行だけ出し、最後に必ず `done` を出す（ホストが期限切れを待たず理由の分かる形で終えるため）。
//!
//! # 出力（v1。1 行 1 観測・正常時は観測 18 行 + 終端 done）
//!
//! 行頭 `fandhe-guest-test: virtiofs-link v1 ` の後に `share=<ro|rw> name=<固定名> op=<op> result=<結果>`
//! を続ける。結果は `ok`（`value=<文字列>` または `kind=<file|dir|symlink|other> nlink=<n> size=<n>` が付く
//! ことがある）・`error errno=<n>`・`not-regular kind=<k>`（read の前の stat が通常ファイルでなかった）・
//! `unprintable`（制御文字・非 UTF-8・行の上限超過。値は切り詰めて出さない）・`missing`。
//!
//! - `ro`（ReadOnly・`/mnt/fandhe/ro`）: `inside_link`・`abs_inside_link`・`dangling_inside_link` の各々に
//!   `readlink` → `lstat` → `stat` → `read`（12 行）。
//! - `rw`（ReadWrite・`/mnt/fandhe/rw`）: `src` の `create`（`create_new`・固定 1 行・`sync_all`）→ `sym` の
//!   `symlink`（`sym -> src`。FUSE_SYMLINK）→ `hard` の `link`（`hard` ← `src`。FUSE_LINK）→ `sym` の
//!   `readlink`・`lstat` → `hard` の `lstat`（6 行）。
//!
//! # 観測できないもの
//!
//! 共有範囲外を指す symlink（絶対パス・`..` 経由・範囲外への dangling）と既存のハードリンク（`nlink > 1`）は、
//! ホストの `VmConfigSpec::check_share_conflicts` が起動前に拒否するため fixture に入れられず、観測できない。
//! また正常ゲストの観測は拒否を維持する判断の補強にしかならず、侵害ゲストが nodeid へ直接 FUSE 要求を送る
//! 脅威は観測できない。
//!
//! # 安全性
//!
//! 共有の内容は untrusted。read は 65 バイトまで、行は 256 バイトまでで、行は検証済みの型（[`LinkValue`]・
//! [`LinkLine`]）でしか作れない（REPAIR-2）。書き込みは `rw` の mount の中の固定名 `src`・`sym`・`hard` だけで、
//! 名前は定数のため共有から読んだ名前を経路に使わない。`src` は `create_new`（`O_EXCL`）で開き、symlink・link は
//! 既存のエントリを上書きしない（`EEXIST`）。read の前に stat（追従）で通常ファイルを確認し、FIFO・デバイスを
//! open しない（PID 1 の停止を防ぐ）。stat から open までの差し替えの窓は、PID 1 しか動かない前提で許容する
//! （`probe` と同じ。lib.rs「未実装」）。FS 操作の期限（REPAIR-5）はホストの
//! `FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS` が担う（PID 1 にスレッドを足さない）。

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::directive::Access;
use crate::probe::TestMode;
use crate::process::ProcessOutcome;
use crate::report::Errno;

/// link 行の名前空間（行頭固定。末尾に空白 1 つ）。ホストの `guest_link_probe::LINK_NAMESPACE` と同値。
pub const LINK_NAMESPACE: &str = "fandhe-guest-test: virtiofs-link ";
/// link 行 v1 の接頭辞。ホストの `guest_link_probe::LINK_PREFIX` と同値。
pub const LINK_PREFIX: &str = "fandhe-guest-test: virtiofs-link v1 ";
/// 1 行の最大バイト数（改行を除く）。ホストの `guest_link_probe::MAX_LINK_LINE_BYTES` と同値。
pub const MAX_LINK_LINE_BYTES: usize = 256;
/// read の 1 行の上限（改行を除く。実際には 1 バイト多く読んで超過を検出する）。ホストの `MAX_LINK_READ_BYTES` と同値。
pub const MAX_LINK_READ_BYTES: usize = 64;
/// 読み取り専用の共有のタグ。ホストの `guest_link_probe::RO_TAG` と同値。
pub const RO_TAG: &str = "ro";
/// 読み取り専用の共有のゲスト内 mount point。ホストの `guest_link_probe::RO_MOUNT` と同値。
pub const RO_MOUNT: &str = "/mnt/fandhe/ro";
/// 読み書きできる共有のタグ。ホストの `guest_link_probe::RW_TAG` と同値。
pub const RW_TAG: &str = "rw";
/// 読み書きできる共有のゲスト内 mount point。ホストの `guest_link_probe::RW_MOUNT` と同値。
pub const RW_MOUNT: &str = "/mnt/fandhe/rw";
/// `ro` で観測するリンクの名前（この順）。ホストの `guest_link_probe::RO_LINK_NAMES` と同値。
pub const RO_LINK_NAMES: [&str; 3] = ["inside_link", "abs_inside_link", "dangling_inside_link"];
/// `rw` に作る通常ファイル。ホストの `guest_link_probe::RW_SRC_NAME` と同値。
pub const RW_SRC_NAME: &str = "src";
/// `rw` に作る symlink（`sym -> src`）。ホストの `guest_link_probe::RW_SYM_NAME` と同値。
pub const RW_SYM_NAME: &str = "sym";
/// `rw` に作るハードリンク（`hard` ← `src`）。ホストの `guest_link_probe::RW_HARD_NAME` と同値。
pub const RW_HARD_NAME: &str = "hard";
/// `src` に書く 1 行。ホストの `guest_link_probe::RW_SRC_LINE` と同値。
pub const RW_SRC_LINE: &str = "fandhe-virtiofs-link-v1";

/// 観測する共有。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Share {
    Ro,
    Rw,
}

impl Share {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ro => "ro",
            Self::Rw => "rw",
        }
    }
}

/// 観測の操作種別（行の `op=` の固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkOp {
    Readlink,
    Lstat,
    Stat,
    Read,
    Create,
    Symlink,
    Link,
    Mount,
}

impl LinkOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Readlink => "readlink",
            Self::Lstat => "lstat",
            Self::Stat => "stat",
            Self::Read => "read",
            Self::Create => "create",
            Self::Symlink => "symlink",
            Self::Link => "link",
            Self::Mount => "mount",
        }
    }
}

/// ファイル種別（行の `kind=` の固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

impl Kind {
    fn of(ft: fs::FileType) -> Self {
        if ft.is_file() {
            Self::File
        } else if ft.is_dir() {
            Self::Dir
        } else if ft.is_symlink() {
            Self::Symlink
        } else {
            Self::Other
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

/// 共有から読んだ文字列（readlink の値・read の 1 行）。制御文字を含む値は作れない。
///
/// 共有の内容は untrusted のため、コンソールへ偽の行や端末制御を注入できない形に限る（REPAIR-2）。
/// 空は許す（空ファイルの read）。行全体の上限は [`LinkLine`] が検査する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkValue(String);

impl LinkValue {
    /// 検証して生成する。制御文字を含めば `None`。
    pub fn try_new(s: &str) -> Option<Self> {
        (!s.chars().any(char::is_control)).then(|| Self(s.to_string()))
    }
}

/// 1 観測の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Ok,
    Value(LinkValue),
    Stat { kind: Kind, nlink: u64, size: u64 },
    Error(Errno),
    NotRegular(Kind),
    Unprintable,
    Missing,
}

/// 出力する 1 行（改行を含まない、検証済みの文字列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLine(String);

impl LinkLine {
    fn observation(share: Share, name: Option<&str>, op: LinkOp, outcome: &Outcome) -> Self {
        let render = |outcome: &Outcome| {
            let name = name.map_or_else(String::new, |n| format!("name={n} "));
            let result = match outcome {
                Outcome::Ok => "result=ok".to_string(),
                Outcome::Value(v) => format!("result=ok value={}", v.0),
                Outcome::Stat { kind, nlink, size } => {
                    format!("result=ok kind={} nlink={nlink} size={size}", kind.as_str())
                }
                Outcome::Error(e) => format!("result=error errno={}", e.get()),
                Outcome::NotRegular(k) => format!("result=not-regular kind={}", k.as_str()),
                Outcome::Unprintable => "result=unprintable".to_string(),
                Outcome::Missing => "result=missing".to_string(),
            };
            format!(
                "{LINK_PREFIX}share={} {name}op={} {result}",
                share.as_str(),
                op.as_str()
            )
        };
        let line = render(outcome);
        // 上限を超える行は切り詰めず、値の代わりに `unprintable` として出す。
        if line.len() <= MAX_LINK_LINE_BYTES {
            Self(line)
        } else {
            Self(render(&Outcome::Unprintable))
        }
    }

    fn done() -> Self {
        Self(format!("{LINK_PREFIX}done"))
    }

    /// 行の文字列（改行を含まない）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// 1 つの共有の実行計画。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePlan {
    /// mount 済みで、実際に観測する。
    Run,
    /// mount が成立していない。FS に触れず `op=mount result=missing` を出す。
    Missing,
}

/// 観測の実行計画（共有ごとに独立）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPlan {
    /// `ro` 共有の計画。
    pub ro: SharePlan,
    /// `rw` 共有の計画。
    pub rw: SharePlan,
}

/// 起動条件（キーと共有ごとの mount 成功の AND）から計画を決める。`None` なら何も出さない。
pub fn link_plan(mode: TestMode, outcome: &ProcessOutcome) -> Option<LinkPlan> {
    if mode != TestMode::VirtiofsLink {
        return None;
    }
    let mounted = |tag: &str, mount: &str, access: Access| {
        let ok = outcome.mounted_directives.iter().any(|d| {
            d.tag.as_str() == tag && d.mount_point.as_str() == mount && d.access == access
        });
        if ok {
            SharePlan::Run
        } else {
            SharePlan::Missing
        }
    };
    Some(LinkPlan {
        ro: mounted(RO_TAG, RO_MOUNT, Access::ReadOnly),
        rw: mounted(RW_TAG, RW_MOUNT, Access::ReadWrite),
    })
}

/// 計画に従って観測行を `emit` へ渡す（最後に done）。`ro_root`・`rw_root` は各共有の mount point。
pub fn run_virtiofs_link(
    plan: LinkPlan,
    ro_root: &Path,
    rw_root: &Path,
    emit: &mut dyn FnMut(LinkLine),
) {
    match plan.ro {
        SharePlan::Missing => emit(LinkLine::observation(
            Share::Ro,
            None,
            LinkOp::Mount,
            &Outcome::Missing,
        )),
        SharePlan::Run => observe_ro(ro_root, emit),
    }
    match plan.rw {
        SharePlan::Missing => emit(LinkLine::observation(
            Share::Rw,
            None,
            LinkOp::Mount,
            &Outcome::Missing,
        )),
        SharePlan::Run => observe_rw(rw_root, emit),
    }
    emit(LinkLine::done());
}

fn errno_outcome(e: &std::io::Error) -> Outcome {
    Outcome::Error(Errno::from_io(e))
}

fn stat_outcome(r: std::io::Result<fs::Metadata>) -> Outcome {
    match r {
        Ok(md) => Outcome::Stat {
            kind: Kind::of(md.file_type()),
            nlink: nlink_of(&md),
            size: md.len(),
        },
        Err(e) => errno_outcome(&e),
    }
}

#[cfg(unix)]
fn nlink_of(md: &fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::nlink(md)
}

// ゲストは Linux のため、unix 以外（ホストでの単体テスト用ビルド）では観測値を使わない。
#[cfg(not(unix))]
fn nlink_of(_md: &fs::Metadata) -> u64 {
    1
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn make_symlink(_target: &str, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

fn readlink_outcome(path: &Path) -> Outcome {
    match fs::read_link(path) {
        Ok(target) => target
            .to_str()
            .and_then(LinkValue::try_new)
            .map_or(Outcome::Unprintable, Outcome::Value),
        Err(e) => errno_outcome(&e),
    }
}

/// 通常ファイルの先頭 1 行を上限つきで読む。stat（追従）で通常ファイルでなければ open しない。
fn read_outcome(path: &Path) -> Outcome {
    match fs::metadata(path) {
        Err(e) => return errno_outcome(&e),
        Ok(md) if !md.is_file() => return Outcome::NotRegular(Kind::of(md.file_type())),
        Ok(_) => {}
    }
    let mut buf = Vec::new();
    let read =
        File::open(path).and_then(|f| f.take(MAX_LINK_READ_BYTES as u64 + 1).read_to_end(&mut buf));
    if let Err(e) = read {
        return errno_outcome(&e);
    }
    let line = match buf.iter().position(|b| *b == b'\n') {
        Some(i) => buf.get(..i),
        None if buf.len() <= MAX_LINK_READ_BYTES => Some(buf.as_slice()),
        None => None,
    };
    line.map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(LinkValue::try_new)
        .map_or(Outcome::Unprintable, Outcome::Value)
}

fn observe_ro(root: &Path, emit: &mut dyn FnMut(LinkLine)) {
    for name in RO_LINK_NAMES {
        let path = root.join(name);
        let mut put = |op, o: Outcome| emit(LinkLine::observation(Share::Ro, Some(name), op, &o));
        put(LinkOp::Readlink, readlink_outcome(&path));
        put(LinkOp::Lstat, stat_outcome(fs::symlink_metadata(&path)));
        put(LinkOp::Stat, stat_outcome(fs::metadata(&path)));
        put(LinkOp::Read, read_outcome(&path));
    }
}

/// `src` を `create_new` で作り 1 行を書いて `sync_all` する。既存のファイル・symlink は辿らず拒否する。
fn create_src(path: &Path) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(format!("{RW_SRC_LINE}\n").as_bytes())?;
    f.sync_all()
}

fn unit_outcome(r: std::io::Result<()>) -> Outcome {
    r.map_or_else(|e| errno_outcome(&e), |()| Outcome::Ok)
}

fn observe_rw(root: &Path, emit: &mut dyn FnMut(LinkLine)) {
    let src = root.join(RW_SRC_NAME);
    let sym = root.join(RW_SYM_NAME);
    let hard = root.join(RW_HARD_NAME);
    let mut put = |name, op, o: Outcome| emit(LinkLine::observation(Share::Rw, Some(name), op, &o));
    put(RW_SRC_NAME, LinkOp::Create, unit_outcome(create_src(&src)));
    put(
        RW_SYM_NAME,
        LinkOp::Symlink,
        unit_outcome(make_symlink(RW_SRC_NAME, &sym)),
    );
    put(
        RW_HARD_NAME,
        LinkOp::Link,
        unit_outcome(fs::hard_link(&src, &hard)),
    );
    put(RW_SYM_NAME, LinkOp::Readlink, readlink_outcome(&sym));
    put(
        RW_SYM_NAME,
        LinkOp::Lstat,
        stat_outcome(fs::symlink_metadata(&sym)),
    );
    put(
        RW_HARD_NAME,
        LinkOp::Lstat,
        stat_outcome(fs::symlink_metadata(&hard)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive::{Directive, MountPoint, Tag};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// テストごとの一時ディレクトリ（Drop で削除）。実体パスへ正規化する（macOS の `/var` 対策）。
    struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);
    impl Tmp {
        fn new() -> Self {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("fandhe-guest-link-{}-{n}", std::process::id()));
            // 残骸・PID 再利用との衝突を避けるため作成前に削除する（REPAIR-12・#3435）。
            let root = crate::test_root::test_root_at(p.clone());
            Self(fs::canonicalize(&p).unwrap(), root)
        }
        fn dir(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::create_dir_all(&p).unwrap();
            p
        }
    }
    const P: &str = "fandhe-guest-test: virtiofs-link v1 ";

    #[cfg(unix)]
    fn run(plan: LinkPlan, ro: &Path, rw: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        run_virtiofs_link(plan, ro, rw, &mut |l| lines.push(l.as_str().to_string()));
        lines
    }

    const RUN: LinkPlan = LinkPlan {
        ro: SharePlan::Run,
        rw: SharePlan::Run,
    };

    #[cfg(unix)]
    fn ro_fixture(ro: &Path) {
        fs::write(ro.join("inside.txt"), "inside\n").unwrap();
        std::os::unix::fs::symlink("inside.txt", ro.join("inside_link")).unwrap();
        std::os::unix::fs::symlink(ro.join("inside.txt"), ro.join("abs_inside_link")).unwrap();
        std::os::unix::fs::symlink(ro.join("missing"), ro.join("dangling_inside_link")).unwrap();
    }

    /// MAC-1・SEC-4・#1877: 正常系の 19 行が完全一致し、rw にリンクが作られる。
    #[cfg(unix)]
    #[test]
    fn mac1_sec4_link_probe_run_emits_exact_lines() {
        let t = Tmp::new();
        let (ro, rw) = (t.dir("ro"), t.dir("rw"));
        ro_fixture(&ro);
        let abs = ro.join("inside.txt");
        let abs = abs.to_str().unwrap();
        let missing = ro.join("missing");
        let missing = missing.to_str().unwrap();
        let sz = |p: &Path| fs::symlink_metadata(p).unwrap().len();
        let (s_in, s_abs, s_dang) = (
            sz(&ro.join("inside_link")),
            sz(&ro.join("abs_inside_link")),
            sz(&ro.join("dangling_inside_link")),
        );
        let lines = run(RUN, &ro, &rw);
        let want = vec![
            format!("{P}share=ro name=inside_link op=readlink result=ok value=inside.txt"),
            format!(
                "{P}share=ro name=inside_link op=lstat result=ok kind=symlink nlink=1 size={s_in}"
            ),
            format!("{P}share=ro name=inside_link op=stat result=ok kind=file nlink=1 size=7"),
            format!("{P}share=ro name=inside_link op=read result=ok value=inside"),
            format!("{P}share=ro name=abs_inside_link op=readlink result=ok value={abs}"),
            format!(
                "{P}share=ro name=abs_inside_link op=lstat result=ok kind=symlink nlink=1 size={s_abs}"
            ),
            format!("{P}share=ro name=abs_inside_link op=stat result=ok kind=file nlink=1 size=7"),
            format!("{P}share=ro name=abs_inside_link op=read result=ok value=inside"),
            format!("{P}share=ro name=dangling_inside_link op=readlink result=ok value={missing}"),
            format!(
                "{P}share=ro name=dangling_inside_link op=lstat result=ok kind=symlink nlink=1 size={s_dang}"
            ),
            format!("{P}share=ro name=dangling_inside_link op=stat result=error errno=2"),
            format!("{P}share=ro name=dangling_inside_link op=read result=error errno=2"),
            format!("{P}share=rw name=src op=create result=ok"),
            format!("{P}share=rw name=sym op=symlink result=ok"),
            format!("{P}share=rw name=hard op=link result=ok"),
            format!("{P}share=rw name=sym op=readlink result=ok value=src"),
            format!("{P}share=rw name=sym op=lstat result=ok kind=symlink nlink=1 size=3"),
            format!("{P}share=rw name=hard op=lstat result=ok kind=file nlink=2 size=24"),
            format!("{P}done"),
        ];
        assert_eq!(lines, want);
        assert_eq!(
            fs::read(rw.join("src")).unwrap(),
            b"fandhe-virtiofs-link-v1\n"
        );
        assert_eq!(fs::read_link(rw.join("sym")).unwrap(), Path::new("src"));
        assert_eq!(
            fs::read(rw.join("hard")).unwrap(),
            b"fandhe-virtiofs-link-v1\n"
        );
    }

    /// MAC-1・SEC-4・#1877: mount 不成立の共有には FS 操作をせず `mount result=missing` と done だけを出す。
    #[cfg(unix)]
    #[test]
    fn mac1_sec4_link_probe_missing_share_never_touches_fs() {
        let t = Tmp::new();
        let (ro, rw) = (t.dir("ro"), t.dir("rw"));
        ro_fixture(&ro);
        let plan = LinkPlan {
            ro: SharePlan::Missing,
            rw: SharePlan::Run,
        };
        let lines = run(plan, &ro, &rw);
        assert_eq!(lines.len(), 8);
        assert_eq!(lines[0], format!("{P}share=ro op=mount result=missing"));
        assert_eq!(
            lines[1],
            format!("{P}share=rw name=src op=create result=ok")
        );
        assert_eq!(lines[7], format!("{P}done"));
        let t = Tmp::new();
        let (ro, rw) = (t.dir("ro"), t.dir("rw"));
        ro_fixture(&ro);
        let plan = LinkPlan {
            ro: SharePlan::Run,
            rw: SharePlan::Missing,
        };
        let lines = run(plan, &ro, &rw);
        assert_eq!(lines.len(), 14);
        assert_eq!(lines[12], format!("{P}share=rw op=mount result=missing"));
        assert_eq!(lines[13], format!("{P}done"));
        assert_eq!(fs::read_dir(&rw).unwrap().count(), 0);
        let both = LinkPlan {
            ro: SharePlan::Missing,
            rw: SharePlan::Missing,
        };
        assert_eq!(
            run(both, &ro, &rw),
            vec![
                format!("{P}share=ro op=mount result=missing"),
                format!("{P}share=rw op=mount result=missing"),
                format!("{P}done"),
            ]
        );
        assert_eq!(fs::read_dir(&rw).unwrap().count(), 0);
    }

    /// MAC-1・SEC-4・#1877: rw に既存のエントリがあれば EEXIST で拒否し、内容・リンク先を書き換えない。
    #[cfg(unix)]
    #[test]
    fn mac1_sec4_link_probe_never_overwrites_existing_entries() {
        let t = Tmp::new();
        let (ro, rw) = (t.dir("ro"), t.dir("rw"));
        let outside = t.0.join("outside.txt");
        fs::write(&outside, "keep").unwrap();
        fs::write(rw.join("sym"), "old-sym").unwrap();
        fs::write(rw.join("hard"), "old-hard").unwrap();
        // src が symlink でも辿らない（create_new は O_EXCL）。
        std::os::unix::fs::symlink(&outside, rw.join("src")).unwrap();
        let lines = run(
            LinkPlan {
                ro: SharePlan::Missing,
                rw: SharePlan::Run,
            },
            &ro,
            &rw,
        );
        assert_eq!(
            lines[1],
            format!("{P}share=rw name=src op=create result=error errno=17")
        );
        assert_eq!(
            lines[2],
            format!("{P}share=rw name=sym op=symlink result=error errno=17")
        );
        assert_eq!(
            lines[3],
            format!("{P}share=rw name=hard op=link result=error errno=17")
        );
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        assert_eq!(fs::read(rw.join("sym")).unwrap(), b"old-sym");
        assert_eq!(fs::read(rw.join("hard")).unwrap(), b"old-hard");
    }

    fn read_line_of(bytes: &[u8]) -> String {
        let t = Tmp::new();
        let p = t.0.join("f");
        fs::write(&p, bytes).unwrap();
        LinkLine::observation(Share::Ro, Some("n"), LinkOp::Read, &read_outcome(&p))
            .as_str()
            .to_string()
    }

    /// MAC-1・SEC-4・#1877: read は 64 バイトまで受理し、超過・制御文字・非 UTF-8 は `unprintable`、CRLF は除く。
    #[test]
    fn mac1_sec4_link_probe_read_limits() {
        let head = format!("{P}share=ro name=n op=read ");
        let ok64 = "a".repeat(64);
        assert_eq!(
            read_line_of(ok64.as_bytes()),
            format!("{head}result=ok value={ok64}")
        );
        assert_eq!(
            read_line_of(format!("{ok64}\nrest").as_bytes()),
            format!("{head}result=ok value={ok64}")
        );
        assert_eq!(
            read_line_of("a".repeat(65).as_bytes()),
            format!("{head}result=unprintable")
        );
        assert_eq!(
            read_line_of(format!("{}\nx", "a".repeat(65)).as_bytes()),
            format!("{head}result=unprintable")
        );
        assert_eq!(
            read_line_of(b"v1\r\nx"),
            format!("{head}result=ok value=v1")
        );
        assert_eq!(read_line_of(b""), format!("{head}result=ok value="));
        for bad in [&b"a\x1b[2Jb\n"[..], &[0xff, b'\n'][..]] {
            assert_eq!(read_line_of(bad), format!("{head}result=unprintable"));
        }
    }

    /// MAC-1・SEC-4・#1877: 通常ファイルでないもの（ディレクトリ）は open せず `not-regular` にする。
    #[test]
    fn mac1_sec4_link_probe_read_skips_non_regular() {
        let t = Tmp::new();
        let d = t.dir("d");
        assert_eq!(read_outcome(&d), Outcome::NotRegular(Kind::Dir));
        assert_eq!(
            LinkLine::observation(Share::Ro, Some("n"), LinkOp::Read, &read_outcome(&d)).as_str(),
            format!("{P}share=ro name=n op=read result=not-regular kind=dir")
        );
    }

    /// MAC-1・SEC-4・#1877: 行はちょうど 256 バイトなら値つきで、257 バイトなら `unprintable` にする。
    #[test]
    fn mac1_sec4_link_line_boundary_is_256_bytes() {
        let head = format!("{P}share=ro name=n op=readlink result=ok value=");
        let fit = "a".repeat(MAX_LINK_LINE_BYTES - head.len());
        let line = LinkLine::observation(
            Share::Ro,
            Some("n"),
            LinkOp::Readlink,
            &Outcome::Value(LinkValue::try_new(&fit).unwrap()),
        );
        assert_eq!(line.as_str().len(), 256);
        let over = LinkLine::observation(
            Share::Ro,
            Some("n"),
            LinkOp::Readlink,
            &Outcome::Value(LinkValue::try_new(&format!("{fit}a")).unwrap()),
        );
        assert_eq!(
            over.as_str(),
            format!("{P}share=ro name=n op=readlink result=unprintable")
        );
        assert!(LinkValue::try_new("a\nb").is_none());
        assert!(LinkValue::try_new("a\u{1b}[2J").is_none());
    }

    fn outcome(directives: &[(&str, &str, Access)]) -> ProcessOutcome {
        ProcessOutcome {
            mounted: directives.len(),
            mounted_directives: directives
                .iter()
                .map(|(t, m, a)| Directive {
                    tag: Tag::try_new(t).unwrap(),
                    mount_point: MountPoint::try_new(m).unwrap(),
                    access: *a,
                })
                .collect(),
            failed: 0,
            rejected: None,
            rejected_reports: 0,
        }
    }

    /// MAC-1・SEC-4・#1877: 起動条件はキーと共有ごとの mount 成功の AND で、access・tag・mount point は完全一致。
    #[test]
    fn mac1_sec4_link_plan_requires_key_and_exact_mounts() {
        use Access::{ReadOnly, ReadWrite};
        let ok = outcome(&[(RO_TAG, RO_MOUNT, ReadOnly), (RW_TAG, RW_MOUNT, ReadWrite)]);
        assert_eq!(link_plan(TestMode::VirtiofsLink, &ok), Some(RUN));
        for mode in [TestMode::Absent, TestMode::Invalid, TestMode::VirtiofsIo] {
            assert_eq!(link_plan(mode, &ok), None);
        }
        let plan = |o| link_plan(TestMode::VirtiofsLink, &o).unwrap();
        let missing_all = LinkPlan {
            ro: SharePlan::Missing,
            rw: SharePlan::Missing,
        };
        assert_eq!(plan(outcome(&[])), missing_all);
        // access が逆（ro が RW・rw が RO）なら不成立。
        assert_eq!(
            plan(outcome(&[
                (RO_TAG, RO_MOUNT, ReadWrite),
                (RW_TAG, RW_MOUNT, ReadOnly)
            ])),
            missing_all
        );
        assert_eq!(
            plan(outcome(&[(RO_TAG, RO_MOUNT, ReadOnly)])),
            LinkPlan {
                ro: SharePlan::Run,
                rw: SharePlan::Missing
            }
        );
        assert_eq!(
            plan(outcome(&[(RW_TAG, "/mnt/fandhe/other", ReadWrite)])),
            missing_all
        );
        assert_eq!(
            plan(outcome(&[("other", RW_MOUNT, ReadWrite)])),
            missing_all
        );
    }

    /// MAC-1・#1877: 名前空間と接頭辞は他の行の名前空間・マーカーと包含関係にない。
    #[test]
    fn mac1_link_namespace_is_disjoint() {
        assert!(LINK_PREFIX.starts_with(LINK_NAMESPACE));
        assert!(!LINK_NAMESPACE.starts_with(crate::report::PROBE_NAMESPACE));
        assert!(!crate::report::PROBE_NAMESPACE.starts_with(LINK_NAMESPACE));
    }
}
