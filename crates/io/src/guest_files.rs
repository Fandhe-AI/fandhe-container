//! サーバー側のファイル作成入口: 大文字小文字衝突の検出をファイル作成経路へ
//! 組み込む（TASK-19.2・IO-5・#100。検出ロジック本体は TASK-19.1・#99 の
//! [`crate::fs_normalize`]）。
//!
//! # 役割
//! ゲスト（ext4）は大文字小文字を区別するが、ホスト（APFS / NTFS）は区別しない。
//! ゲストが `Foo.txt` と `foo.txt` を同時に作ると、ホスト側で同一ファイルになり
//! 黙った上書き（データ損失）が起きる。[`GuestFileCreator`] は共有ルート配下への
//! ファイル作成の前に、共有の [`CaseCollisionSet`] で衝突を検査し、衝突なら
//! ファイルシステムに触れずに `AlreadyExists`（`case-insensitive path collision`）
//! の構造化エラーを返す。同じインスタンス内では検査から作成までを 1 つの
//! `Mutex` ガードで直列化するため、同時に届いた大小違いの作成要求の一方だけが
//! 成功する。インスタンス・プロセスをまたぐ競合は作成後の再検証と取り消しで
//! 扱う（下記「プロセス間の競合」）。
//!
//! # 呼び出し文脈
//! サーバーの上位層（将来の要求ディスパッチャ）がゲスト相対パスを渡して
//! [`GuestFileCreator::create_file`] を呼び、戻り値の [`AppendFileSink`] を
//! [`crate::writeback::serve_connection`] / [`crate::settings::BoundConnection::serve`]
//! へ書き込み先（[`crate::writeback::BatchSink`]）として渡す。`Arc` で複数接続から
//! 共有する（`Send + Sync`）。
//!
//! # スタブの明示（REPAIR-3）
//! ワイヤー形式（[`crate::payload`]）の `Write` はパスを持たず、ワイヤー上から
//! 作成要求を受ける経路はまだない。フレーム種別・ペイロードの拡張は IO-1 の
//! I/O 契約変更（`PROTOCOL_VERSION` の繰り上げを伴いうる）であり、本モジュールは
//! ワイヤー形式を変えずにサーバー側 API として組み込む。ワイヤーからの作成要求
//! （IO-1・TASK-14 のファイル操作ペイロード拡張）は後続。
//!
//! # 契約と既知の限界
//! - 閉じ込め: ゲストパスを `Path::join` へ渡さず、検証済みコンポーネント
//!   （ホスト上でちょうど 1 個の `Normal`。`\` と `:` は 3 OS とも拒否して挙動を
//!   揃える）だけを扱う。Linux / macOS では共有ルートのディレクトリ fd を起点に
//!   `mkdirat` / `openat`（`O_DIRECTORY|O_NOFOLLOW`）で祖先を 1 個ずつ辿り、末端は
//!   `O_CREAT|O_EXCL|O_NOFOLLOW` で作る（[`crate::sys::mkdir_beneath`]・
//!   [`crate::sys::open_dir_beneath`]・[`crate::sys::create_leaf_beneath`]）。
//!   パスを再解決しないため、祖先の symlink すり替え（TOCTOU）でも共有ルート外へ
//!   は出られない。
//! - Windows は `NtCreateFile` のルート相対ハンドル作成が未実装のため、祖先を
//!   1 階層ずつ「作成 → reparse point を辿らず `FILE_SHARE_DELETE` なしで開いて
//!   保持 → 通常ディレクトリか確認」で固定し、固定済みの祖先の配下へパス結合で
//!   葉を作る（保持ハンドルが改名・削除・差し替えを OS に拒否させる。REPAIR-3）。
//!   共有ルート自体が symlink のときは構築時に 1 回だけ正規化し、以降のパス結合は
//!   その正規パス（保持ハンドルと同じ実体）から始めて元のルートは再解決しない。
//! - 衝突索引は実在項目だけから作る: 作成のたびに、要求パスの祖先に沿って実在する
//!   ディレクトリのエントリを読み直し、その場限りの [`CaseCollisionSet`] を作って
//!   衝突を検査する（ディスクが唯一の正。インスタンスをまたいで持ち越す索引は持たない
//!   ため、ホスト側で消した・改名した項目が後の作成を拒否し続けることはなく、失敗した
//!   作成が索引を汚すこともない）。別プロセスが後から足した項目も検出する。走査中の
//!   読み取り失敗や、既存項目どうしの大文字小文字衝突は作成を中止する
//!   （fail-closed）。共有ルートに元からある `Foo` があれば `foo/bar` は衝突になる。
//!   走査は衝突の検査だけに使い、書き込み先の解決には使わない（非 UTF-8 名は
//!   取り込めない）。
//! - 件数上限（[`GuestFileCreator::with_max_tracked_paths`]）は、1 回の作成で索引へ
//!   取り込む実在項目の件数と、1 ディレクトリから読むエントリ数の上限（無制限確保の
//!   防止）。超えると `ResourceExhausted` で中止する。衝突は上限より先に検査し、
//!   衝突として返す。
//! - 後始末: 作成が葉で失敗した・再検証で取り消した場合、本呼び出しが新設した
//!   祖先ディレクトリは空であれば同一性を確かめてから取り除く（ベストエフォート。
//!   他者が中に作った等で空でなければ残す）。Windows のフォールバックは祖先を
//!   取り除かない（残った祖先は次回の走査で取り込まれる）。
//! - 作成は全接続で直列化される（性能最適化は範囲外）。
//! - Unicode 正規化（NFC / NFD）は行わない（#103・TASK-21）。260 文字超の検証は
//!   TASK-20。
//!
//! # プロセス間の競合（作成後の再検証と取り消し。Linux / macOS）
//! `Mutex` はインスタンス内にしか効かないため、走査から作成までの間に別プロセス・
//! 別インスタンスが大小違いの項目（`Foo` に対する `foo`）を作ると、大文字小文字を
//! 区別するホスト（Linux・大文字小文字を区別する APFS）では両方の作成が成功し
//! うる。そこで `O_EXCL` での作成の直後に、作成に使ったのと同じディレクトリ
//! ハンドル（名前で開き直さない）を各階層で読み直し、次の 2 点を再検証する。
//! - 同一性: 自分のコンポーネント名のエントリが、保持している祖先のハンドル・
//!   葉の fd と同じ inode を指している（作成直後に改名・削除・差し替えされて
//!   いれば、返す fd は共有パスから辿れないため取り消して `Internal`）。親と子の
//!   デバイスが違う階層はマウントポイントとして照合しない（readdir は下層の inode を
//!   返し、マウントポイントは改名・削除が EBUSY で拒否される）
//! - 衝突: 自分のコンポーネントと大文字小文字だけが違うエントリが現れていない
//!   （見つかれば、自分が作った葉と新設した空の祖先だけを取り消して
//!   `AlreadyExists`〔`case-insensitive path collision`〕）
//!
//! 再検証の読み取りに失敗した場合も取り消して `Internal` を返す（検証できないまま
//! sink を返さない）。同一性の照合は `d_ino` と `st_ino` が一致する FS（ext4・xfs・
//! btrfs・APFS・同一 FS 上の overlayfs 等）を前提とし、一致しない FS では作成が
//! `Internal` で失敗する（fail-closed）。
//!
//! 再検証・取り消しの読み直しは一覧を保持しない走査で行い、作成でエントリ数が
//! 索引の上限を超えても検証・取り消しが止まらないようにする。
//!
//! 取り消しは他者のデータを消さない手順で行う（`remove_file_if_same`）:
//! 1. 読み直した葉の `d_ino` が保持 fd の inode と一致し、デバイスも一致することを
//!    確かめる。別の実体に差し替えられていれば触らずに、別の書き込み元との競合
//!    として `AlreadyExists`（`concurrent writer replaced the created guest file`）を
//!    返す
//! 2. 葉の親に、自分だけが入れる私有ディレクトリ（`.fandhe-rollback-<pid>-<n>-<nanos>`・
//!    mode `0o700`。開いたハンドルの所有者が自プロセスの実効 uid で、グループ・
//!    その他の権限が無いことを確かめる）を新設し、そのハンドルへ葉を `renameat` で
//!    移す。名前の付け替えは原子的なので、1 の直後に別の実体が葉の名前へ差し込まれて
//!    いても、それは消えずに私有ディレクトリへ移るだけになる
//! 3. 私有ディレクトリ内のエントリの `d_ino` が保持 fd と一致するときだけ
//!    `unlinkat` する。私有ディレクトリへは他の uid が改名で差し込めないため、この
//!    確認から削除までの間に別の実体へ差し替えられることはない（同じ uid・root の
//!    プロセスを除く）
//! 4. 一致しなければ（2 で他者の実体を移していたら）、既存の名前を上書きしない
//!    `linkat`（`AT_SYMLINK_FOLLOW` なし）で元の名前へ戻し、私有ディレクトリ側の
//!    名前を `unlinkat` して、競合として `AlreadyExists`（同上）を返す。元の名前が
//!    戻す前に再利用されていた、またはハードリンクを作れない（ハードリンク非対応の
//!    FS・ディレクトリ・Linux の `fs.protected_hardlinks` による拒否）場合は、消さずに
//!    私有ディレクトリへ残し、共有ルートからの退避先のパスを含めて `Internal`
//!    （`created guest file could not be rolled back ... entry left at ...`）を返す
//!    （fail-closed。退避先の実体は私有ディレクトリにあり、所有者以外はそのままでは
//!    読めないため、運用者が戻す）
//! 5. 空になった私有ディレクトリを取り除く（ベストエフォート）
//!
//! 新設した祖先は、同一性を確かめてから `unlinkat(AT_REMOVEDIR)` で取り除く。
//! 確認から削除までの間に差し替えられても、消えうるのは空のディレクトリだけ
//! （空でなければ失敗し、そこで取り消しを止めて残す）。
//!
//! 保証の範囲:
//! - 本方式に従う作成者（本型の別インスタンス・別プロセス）どうしでは、大小違いの
//!   項目が両方とも残ることはない。後から作った側の再検証（作成後に開き直した
//!   ディレクトリストリームは、それ以前から存在するエントリを必ず返す）が先の
//!   項目を必ず見つけるため。ただし双方が互いを見つけて両方とも取り消し、両方が
//!   `AlreadyExists` になることはある（安全側の失敗として許容する）。
//! - 本方式に従わない書き込み元（ホストの別プロセスが直接作る等）が、こちらの
//!   再検証の読み取りより後に大小違いの項目を作った場合は検出できない（次回の
//!   作成時の走査で既存衝突として検出され、以降の作成は中止される）。
//! - 名前で取り消す以上、完全に原子的な取り消しはできない（POSIX には fd を指定して
//!   名前を消す API も、移動元の inode を条件にした改名もない）。残る窓は次のとおり:
//!   - 1 の確認から 2 の `renameat` までに他者の実体が葉の名前へ差し込まれると、
//!     それは私有ディレクトリへ移り、4 の `linkat` で戻すまでの間（数 µs）は元の名前
//!     から見えなくなる。戻せない場合（上記）は私有ディレクトリに残り、報告される。
//!     いずれの場合も他者のデータは消えない
//!   - 3 の確認から `unlinkat` までに私有ディレクトリの中へ別の実体を差し込めるのは、
//!     本プロセスと同じ uid または root のプロセスだけ。その場合はそれを消しうる
//!     （検出できない）が、そうしたプロセスは元から本プロセスのファイルを直接消せる
//!     ため、権限の昇格にはならない
//!   - 前提となる権限: 1 の窓に差し込めるのは、共有ディレクトリへの書き込み権限を
//!     持つ者だけ（元からそのエントリを直接移動・削除できる）。本プロセスは共有
//!     ディレクトリへの書き込み権限（作成に必要なものと同じ）以外を要しない
//! - プロセス間で完全な排他を取るものではない（共有ルートをまたぐロックは持たない）。
//! - 大文字小文字を区別しないホスト（既定の APFS・NTFS）では、大小違いの作成は
//!   `O_EXCL` / `create_new` が既存として失敗するため、この競合自体が起きない。
//!   Windows のフォールバックは再検証を行わない（ディレクトリ単位で大文字小文字の
//!   区別を有効にした NTFS〔`setCaseSensitiveInfo`〕では競合を検出できない。
//!   ハンドル相対の同一性確認つき削除が未実装のため。REPAIR-3）。取り消しも行わない
//!   ため、Windows では他者の実体を動かすことはない。

use std::fs::File;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use crate::error::{IoError, IoErrorCode};
use crate::fs_normalize::{CaseCollisionSet, collision_error, quote_for_message};
use crate::writeback::AppendFileSink;

/// ゲスト相対パスのバイト長の上限（Linux の PATH_MAX 相当。DoS 防止のため
/// 畳み込みやアロケーションの前に検証する）。
pub const MAX_GUEST_PATH_BYTES: usize = 4096;

/// 索引へ登録できるパス件数の上限の最大値（`fs_normalize` は件数上限を呼び出し側の
/// 責務としているため本型が持つ）。
pub const MAX_TRACKED_GUEST_PATHS: usize = 1 << 20;

/// 共有ルート配下へのファイル作成に大文字小文字衝突検出を組み込む入口
/// （モジュール doc 参照。IO-5・TASK-19.2）。
pub struct GuestFileCreator {
    root: PathBuf,
    /// パス結合が必要な Windows の作成・走査が使う、symlink 解決済みの共有ルート。
    /// 構築時に 1 回だけ解決し、`root` のパスは再解決しない（`root` 自体が symlink
    /// でも、構築後に参照先を差し替えて共有範囲外へ書かせない。IO-5）。Linux /
    /// macOS はハンドル起点のため `root` と同値で、パス解決には使われない。
    base: PathBuf,
    /// 構築時に開いた共有ルートのディレクトリハンドル。走査・作成の起点はこの
    /// ハンドルで、`root` のパスは開き直さない（検証後にパスや親のエントリが
    /// 差し替えられても共有範囲外へ出ない。security.md の境界。IO-5）。
    /// Windows ではこのハンドルを `FILE_SHARE_DELETE` なしで保持し、ルートと祖先の
    /// 改名・削除を OS に拒否させる。
    root_dir: File,
    /// 1 回の作成で索引へ取り込む実在項目の件数・1 ディレクトリから読むエントリ数の
    /// 上限。
    max_tracked: usize,
    /// 同じインスタンス内の作成を、走査から作成・再検証まで直列化する。
    lock: Mutex<()>,
}

fn invalid(message: &str) -> IoError {
    IoError::new(IoErrorCode::InvalidArgument, message)
}

fn poisoned() -> IoError {
    IoError::new(IoErrorCode::Internal, "guest file creator lock is poisoned")
}

fn too_many() -> IoError {
    IoError::new(
        IoErrorCode::ResourceExhausted,
        "too many tracked guest paths",
    )
}

/// 単一のゲストパスコンポーネントがホスト上でちょうど 1 個の `Normal` に
/// なることを確かめる（`..`・空・`.`・`\`・`:`・NUL を拒否する）。
fn validate_host_component(component: &str) -> Result<(), IoError> {
    if component.contains(['\\', ':', '\0']) {
        return Err(invalid(
            "guest path component must not contain '\\', ':' or NUL",
        ));
    }
    let mut parts = Path::new(component).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(invalid("guest path component must be a single normal name")),
    }
}

impl GuestFileCreator {
    /// `root`（共有ルート。ディレクトリであること）を起点に作成する入口を作る。
    /// root は信頼できる設定値として扱い、root 自体が symlink でも許す（構築時に
    /// 1 回だけ辿って開き、以降はそのハンドルを起点にする）。
    pub fn new(root: PathBuf) -> Result<Self, IoError> {
        Self::with_max_tracked_paths(root, MAX_TRACKED_GUEST_PATHS)
    }

    /// 1 回の作成で索引へ取り込む実在項目の件数上限（`1..=`[`MAX_TRACKED_GUEST_PATHS`]。
    /// 1 ディレクトリから読むエントリ数の上限にも使う）を指定して作る（モジュール doc
    /// 「契約と既知の限界」）。
    pub fn with_max_tracked_paths(root: PathBuf, max_tracked: usize) -> Result<Self, IoError> {
        if max_tracked == 0 || max_tracked > MAX_TRACKED_GUEST_PATHS {
            return Err(invalid("max tracked guest paths is out of range"));
        }
        let base = resolve_root_base(&root).map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        let root_dir = open_root_handle(&base).map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        let meta = root_dir.metadata().map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        if !meta.is_dir() {
            return Err(invalid("guest file root must be a directory"));
        }
        Ok(Self {
            root,
            base,
            root_dir,
            max_tracked,
            lock: Mutex::new(()),
        })
    }

    /// 共有ルート。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// ゲスト相対パス `guest_path`（`/` 区切り）のファイルを新規作成して sink を返す。
    ///
    /// 大文字小文字だけが違う既存パスと衝突する場合（作成後の再検証で別プロセスの
    /// 項目を見つけて取り消した場合を含む）は `AlreadyExists`
    /// （`case-insensitive path collision: ...`）、同一パスが既に存在する場合は
    /// `AlreadyExists`（`guest file already exists: ...`）、不正なパスは
    /// `InvalidArgument`、実在項目が件数上限を超える場合は `ResourceExhausted`、
    /// 走査・再検証・取り消しの失敗は `Internal`
    /// （IO-5・TASK-19.2）。
    pub fn create_file(&self, guest_path: &str) -> Result<AppendFileSink, IoError> {
        if guest_path.len() > MAX_GUEST_PATH_BYTES {
            return Err(invalid("guest path is too long"));
        }
        // ロックと走査の前にホスト側の検証を済ませる。
        let components: Vec<&str> = guest_path.split('/').collect();
        for component in &components {
            validate_host_component(component)?;
        }

        // 走査から作成・再検証までを同じガードで直列化する。
        let _guard = self.lock.lock().map_err(|_| poisoned())?;
        let (ancestors, leaf) = match components.split_last() {
            Some((leaf, ancestors)) => (ancestors, *leaf),
            None => return Err(invalid("guest path is empty")),
        };
        // 実在する項目（表記違いの祖先など）から、この作成限りの索引を作って検査する。
        let existing = self.index_existing(ancestors)?;
        existing.check_insertable(guest_path)?;

        #[cfg(test)]
        fault::run_hook(fault::Hook::BeforeCreate);
        let created = match create_beneath(&self.root_dir, &self.base, ancestors, leaf) {
            Ok(created) => created,
            Err(CreateError::Exists) => {
                return Err(IoError::new(
                    IoErrorCode::AlreadyExists,
                    format!(
                        "guest file already exists: {}",
                        quote_for_message(guest_path)
                    ),
                ));
            }
            Err(CreateError::ExistsAs(existing)) => {
                // 走査の後に別の作成者が大小違いの項目を作り、大文字小文字を区別しない
                // ホストが既存として拒否した。衝突として返す。
                let prefix: String = ancestors.iter().map(|a| format!("{a}/")).collect();
                return Err(collision_error(
                    guest_path,
                    &format!("{prefix}{existing}"),
                    leaf,
                    &existing,
                ));
            }
            Err(CreateError::Other(err)) => return Err(err),
        };
        #[cfg(test)]
        fault::run_hook(fault::Hook::AfterCreate);
        // 走査から作成までの間に別プロセスが足した大小違いの項目を再検証する
        // （見つかれば自分の作成を取り消して返す。モジュール doc「プロセス間の競合」）。
        let file = verify_created(created, guest_path, ancestors, leaf)?;
        AppendFileSink::new(file)
    }

    /// `ancestors` に沿って実在するディレクトリの項目を読み、この作成限りの衝突
    /// 索引を作る（表記どおりの実在ディレクトリだけを辿る。symlink は辿らない）。
    /// 走査は保持したルートのハンドル起点で行い（Linux / macOS は各階層もハンドル
    /// 相対で開く）、衝突の検査専用で作成先の解決には使わない。取り込む項目が件数
    /// 上限を超えたら `ResourceExhausted`、読み取りの失敗は `Internal`、既存項目
    /// どうしの大文字小文字衝突は `AlreadyExists`（IO-5 の検査を完了できないまま
    /// 作成へ進まない。fail-closed）。
    fn index_existing(&self, ancestors: &[&str]) -> Result<CaseCollisionSet, IoError> {
        let mut set = CaseCollisionSet::new();
        let mut cursor = ScanCursor::root(&self.root_dir, &self.base)?;
        let mut prefix = String::new();
        for level in 0..=ancestors.len() {
            let entries = cursor.read_entries(self.max_tracked)?;
            for name in entries {
                let Some(name) = name.to_str() else { continue };
                let path = format!("{prefix}{name}");
                // 衝突は件数上限より先に報告する（大文字小文字を区別しないホストでは
                // 表記違いの祖先がそのまま開けるため、要求の表記で数えた項目が前の
                // 階層の項目と衝突しうる。上限に達していても衝突として返す）。
                match set.check_insertable(&path) {
                    Ok(()) => {}
                    // 形式不正の名前（ホストで表現できない等）は索引化できないだけで
                    // 無視する。
                    Err(err) if err.code() == IoErrorCode::InvalidArgument => continue,
                    // 共有ルートに元から大文字小文字違いの項目が併存している等、
                    // 衝突検出を完了できない状態は走査順で結果が変わるため、
                    // 握りつぶさず作成を中止する（fail-closed。IO-5）。
                    Err(err) => return Err(err),
                }
                if set.len() >= self.max_tracked {
                    return Err(too_many());
                }
                set.try_insert(&path)?;
            }
            let Some(component) = ancestors.get(level) else {
                break;
            };
            // 未作成・通常ファイル・symlink の祖先より下に取り込む項目は無い
            // （作成時に新設される、または作成側が拒否する）。
            match cursor.descend(component)? {
                Some(next) => cursor = next,
                None => break,
            }
            prefix.push_str(component);
            prefix.push('/');
        }
        Ok(set)
    }
}

/// パス結合に使う共有ルートを決める。Windows では symlink を構築時に解決した
/// 正規パスを返し（以降の作成・走査は元の `root` を再解決しない）、それ以外は
/// ハンドル起点のため `root` をそのまま返す。
#[cfg(windows)]
fn resolve_root_base(root: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(root)
}

#[cfg(not(windows))]
fn resolve_root_base(root: &Path) -> std::io::Result<PathBuf> {
    Ok(root.to_path_buf())
}

/// 共有ルートを開く（symlink は構築時のこの 1 回だけ辿る）。Windows では
/// `FILE_FLAG_BACKUP_SEMANTICS` でディレクトリを開き、`FILE_SHARE_DELETE` を
/// 付けずに共有してルートと祖先の改名・削除を拒否させる。
#[cfg(not(windows))]
fn open_root_handle(root: &Path) -> std::io::Result<File> {
    File::open(root)
}

#[cfg(windows)]
fn open_root_handle(root: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS
    const FLAGS: u32 = 0x0200_0000;
    // FILE_SHARE_READ | FILE_SHARE_WRITE（FILE_SHARE_DELETE は含めない）
    const SHARE: u32 = 0x1 | 0x2;
    OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS)
        .share_mode(SHARE)
        .open(root)
}

fn internal(context: &str, kind: ErrorKind) -> IoError {
    // ホストのパスは載せず kind だけを載せる（情報漏洩防止）。
    IoError::new(IoErrorCode::Internal, format!("{context} ({kind:?})"))
}

/// ディレクトリハンドル直下のエントリ（名前と `d_ino`）をハンドル相対で読む
/// （Linux / macOS の走査・再検証・取り消しが共通で通る唯一の読み取り口。
/// テストではここで読み取り失敗を注入する〔`fault`〕）。失敗は `context` を
/// 付けた `Internal`、件数上限超過は `ResourceExhausted`。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scan_handle(
    dir: &File,
    max_entries: usize,
    context: &str,
) -> Result<Vec<crate::sys::DirEntryName>, IoError> {
    use crate::sys::{ReadDirError, read_dir_entries};
    #[cfg(test)]
    if fault::scan_should_fail() {
        return Err(internal(context, ErrorKind::Other));
    }
    read_dir_entries(dir, max_entries).map_err(|err| match err {
        ReadDirError::TooMany => too_many(),
        ReadDirError::Io(kind) => internal(context, kind),
    })
}

/// ディレクトリハンドル直下のエントリを一覧を保持せずに 1 件ずつ `visit` へ渡す
/// （Linux / macOS の再検証・取り消しの読み取り口。[`scan_handle`] と同じく、テスト
/// ではここで読み取り失敗を注入する〔`fault`〕）。失敗は `context` を付けた `Internal`。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn visit_handle(
    dir: &File,
    context: &str,
    visit: impl FnMut(&std::ffi::OsStr, u64) -> std::ops::ControlFlow<()>,
) -> Result<(), IoError> {
    use crate::sys::{ReadDirError, for_each_dir_entry};
    #[cfg(test)]
    if fault::scan_should_fail() {
        return Err(internal(context, ErrorKind::Other));
    }
    for_each_dir_entry(dir, visit).map_err(|err| match err {
        ReadDirError::TooMany => too_many(),
        ReadDirError::Io(kind) => internal(context, kind),
    })
}

/// ディレクトリハンドル直下の `name` のエントリの inode を探す（無ければ `None`。
/// 一覧を保持しないため件数上限は無い）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_in_handle(dir: &File, name: &str) -> Result<Option<u64>, IoError> {
    use std::ops::ControlFlow;
    let mut found = None;
    visit_handle(dir, "failed to scan guest directory", |entry, ino| {
        if entry == name {
            found = Some(ino);
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(found)
}

/// 走査位置（Linux / macOS はディレクトリハンドル）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ScanCursor(File);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ScanCursor {
    fn root(root_dir: &File, _root: &Path) -> Result<Self, IoError> {
        root_dir
            .try_clone()
            .map(Self)
            .map_err(|err| internal("failed to scan guest directory", err.kind()))
    }

    /// ディレクトリハンドルから直接（`fdopendir`）エントリ名を読む。パスを
    /// 再解決しないため macOS でも動き、ルートの差し替えにも影響されない。
    fn read_entries(&self, max_entries: usize) -> Result<Vec<std::ffi::OsString>, IoError> {
        Ok(
            scan_handle(&self.0, max_entries, "failed to scan guest directory")?
                .into_iter()
                .map(|entry| entry.name)
                .collect(),
        )
    }

    fn descend(self, name: &str) -> Result<Option<Self>, IoError> {
        use crate::sys::{BeneathError, open_dir_beneath};
        match open_dir_beneath(&self.0, name) {
            Ok(dir) => Ok(Some(Self(dir))),
            Err(BeneathError::AncestorNotDirectory) => Ok(None),
            Err(BeneathError::Io(ErrorKind::NotFound)) => Ok(None),
            Err(BeneathError::Io(kind)) => Err(internal("failed to inspect guest directory", kind)),
            Err(BeneathError::AlreadyExists) => Err(internal(
                "failed to inspect guest directory",
                ErrorKind::Other,
            )),
        }
    }
}

/// Windows 等のフォールバック（パス走査）。ルートは `open_root_handle` の
/// 共有拒否で改名・削除されない。降りる祖先は作成側と同じ判定・同じ方式
/// （[`open_pinned_dir`]。reparse point を辿らず、通常ディレクトリだけを
/// `FILE_SHARE_DELETE` なしで開いて保持）で固定するため、走査のパス解決も固定済みの
/// 祖先の配下に留まり、リンク先のエントリを読まない。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct ScanCursor {
    path: PathBuf,
    /// 降りた祖先の保持ハンドル（走査が終わるまで改名・削除・差し替えを拒否させる）。
    pinned: Vec<File>,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl ScanCursor {
    fn root(_root_dir: &File, root: &Path) -> Result<Self, IoError> {
        Ok(Self {
            path: root.to_path_buf(),
            pinned: Vec::new(),
        })
    }

    fn read_entries(&self, max_entries: usize) -> Result<Vec<std::ffi::OsString>, IoError> {
        #[cfg(test)]
        if fault::scan_should_fail() {
            return Err(internal("failed to scan guest directory", ErrorKind::Other));
        }
        let mut names = Vec::new();
        let dir = std::fs::read_dir(&self.path)
            .map_err(|err| internal("failed to scan guest directory", err.kind()))?;
        for entry in dir {
            let entry =
                entry.map_err(|err| internal("failed to scan guest directory", err.kind()))?;
            if names.len() >= max_entries {
                return Err(too_many());
            }
            names.push(entry.file_name());
        }
        Ok(names)
    }

    fn descend(mut self, name: &str) -> Result<Option<Self>, IoError> {
        let next = self.path.join(name);
        match open_pinned_dir(&next) {
            Ok(Some(dir)) => {
                self.pinned.push(dir);
                self.path = next;
                Ok(Some(self))
            }
            // reparse point・非ディレクトリより下は読まない（作成側も拒否する）。
            Ok(None) => Ok(None),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(internal("failed to inspect guest directory", err.kind())),
        }
    }
}

/// Windows: `path` を reparse point を辿らず（`FILE_FLAG_OPEN_REPARSE_POINT`）・
/// `FILE_SHARE_DELETE` なしで開き、通常ディレクトリ（reparse point でない）なら保持用の
/// ハンドルを返す（そうでなければ `None`）。保持中は OS が改名・削除・差し替えを拒否
/// する。走査（`ScanCursor::descend`）と作成（[`create_beneath`]）で同じ判定を使う。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_pinned_dir(path: &Path) -> std::io::Result<Option<File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    const FLAGS: u32 = 0x0200_0000 | 0x0020_0000;
    // FILE_SHARE_READ | FILE_SHARE_WRITE（FILE_SHARE_DELETE なし）
    const SHARE: u32 = 0x1 | 0x2;
    // FILE_ATTRIBUTE_REPARSE_POINT
    const REPARSE: u32 = 0x400;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS)
        .share_mode(SHARE)
        .open(path)?;
    let meta = dir.metadata()?;
    if !meta.is_dir() || meta.file_attributes() & REPARSE != 0 {
        return Ok(None);
    }
    Ok(Some(dir))
}

/// [`create_beneath`] の失敗種別。
enum CreateError {
    /// 末端が同じ表記で既に存在する。
    Exists,
    /// 末端の作成が既存として失敗し、親ディレクトリには大文字小文字だけが違う
    /// 表記（値）のエントリがあった（大文字小文字を区別しないホストで、走査の後に
    /// 別の作成者が作った場合）。
    ExistsAs(String),
    /// 構造化済みのその他のエラー。
    Other(IoError),
}

/// 末端の作成が既存として失敗したとき、親ディレクトリ `parent` で実在する表記を
/// 確かめる（Windows 等のフォールバック。親は固定済みの祖先のため、パス結合による
/// 読み直しも範囲内に留まる）。同じ表記があれば `Exists`、大文字小文字だけが違う
/// 表記があれば `ExistsAs`、どちらも無ければ（作成の失敗後に消えた）`Exists`。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn classify_existing(parent: &Path, leaf: &str) -> CreateError {
    use crate::fs_normalize::fold_component;
    let dir = match std::fs::read_dir(parent) {
        Ok(dir) => dir,
        Err(err) => {
            return CreateError::Other(internal("failed to inspect guest directory", err.kind()));
        }
    };
    let folded = fold_component(leaf);
    let mut variant = None;
    for entry in dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return CreateError::Other(internal(
                    "failed to inspect guest directory",
                    err.kind(),
                ));
            }
        };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name == leaf {
            return CreateError::Exists;
        }
        if variant.is_none() && fold_component(&name) == folded {
            variant = Some(name);
        }
    }
    variant.map_or(CreateError::Exists, CreateError::ExistsAs)
}

/// 作成に成功した結果（Linux / macOS）。再検証・取り消しは、作成に使った
/// ディレクトリハンドルそのもの（名前で開き直さない）に対して行う。
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Created {
    /// 作成した葉（`O_EXCL` で新規作成した通常ファイル）。
    file: File,
    /// `dirs[0]` はルートの複製、`dirs[i + 1]` は `ancestors[i]` を開いたハンドル
    /// （葉の親は最後の要素）。
    dirs: Vec<File>,
    /// `made[i]`: `ancestors[i]` を本呼び出しの `mkdirat` が新設したか
    /// （取り消しで取り除いてよいのは新設したものだけ）。
    made: Vec<bool>,
}

/// 作成に成功した結果（Windows 等のフォールバック。再検証は行わない）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct Created {
    file: File,
}

/// ルートのディレクトリハンドル起点・symlink 非追従で祖先を開き（無ければ作り）
/// 末端を新規作成する（Linux / macOS。`mkdirat` / `openat`。TOCTOU 防止）。
/// 途中で失敗した場合は、新設した空の祖先をベストエフォートで取り除いてから
/// 元のエラーを返す（取り除けなかった祖先は次回の走査で取り込まれる）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_beneath(
    root_dir: &File,
    _root: &Path,
    ancestors: &[&str],
    leaf: &str,
) -> Result<Created, CreateError> {
    use crate::sys::{BeneathError, DirMode, create_leaf_beneath, mkdir_beneath, open_dir_beneath};

    fn map(err: BeneathError) -> CreateError {
        match err {
            BeneathError::AlreadyExists => CreateError::Exists,
            BeneathError::AncestorNotDirectory => {
                CreateError::Other(invalid("guest path ancestor is not a directory"))
            }
            BeneathError::Io(kind) => {
                CreateError::Other(internal("failed to create guest file", kind))
            }
        }
    }

    let root = root_dir
        .try_clone()
        .map_err(|err| CreateError::Other(internal("failed to create guest file", err.kind())))?;
    // 祖先数は MAX_GUEST_PATH_BYTES で検証済みのパス長で抑えられている。
    let mut dirs = Vec::with_capacity(ancestors.len().saturating_add(1));
    dirs.push(root);
    let mut made = Vec::with_capacity(ancestors.len());
    for name in ancestors {
        let Some(parent) = dirs.last() else {
            return Err(CreateError::Other(internal(
                "failed to create guest file",
                ErrorKind::Other,
            )));
        };
        let step = mkdir_beneath(parent, name, DirMode::Shared)
            .and_then(|created| open_dir_beneath(parent, name).map(|dir| (created, dir)));
        match step {
            Ok((created, dir)) => {
                made.push(created);
                dirs.push(dir);
            }
            Err(err) => {
                // mkdirat 後に openat が失敗した祖先はハンドルが無く同一性を確かめ
                // られないため、それより上の新設分だけを取り除く。
                let _ = rollback_dirs(&dirs, &made, ancestors);
                return Err(map(err));
            }
        }
    }
    let Some(parent) = dirs.last() else {
        return Err(CreateError::Other(internal(
            "failed to create guest file",
            ErrorKind::Other,
        )));
    };
    #[cfg(test)]
    fault::run_hook(fault::Hook::BeforeLeaf);
    match create_leaf_beneath(parent, leaf) {
        Ok(file) => Ok(Created { file, dirs, made }),
        Err(BeneathError::AlreadyExists) => {
            // 実在する表記を確かめる（大文字小文字を区別しないホストでは、走査の後に
            // 作られた大小違いの項目でも `O_EXCL` が既存として失敗するため）。
            let folded = crate::fs_normalize::fold_component(leaf);
            let mut exact = false;
            let mut variant: Option<String> = None;
            let scanned = visit_handle(parent, "failed to inspect guest directory", |name, _| {
                if name == leaf {
                    exact = true;
                    return std::ops::ControlFlow::Break(());
                }
                if variant.is_none()
                    && let Some(name) = name.to_str()
                    && crate::fs_normalize::fold_component(name) == folded
                {
                    variant = Some(name.to_string());
                }
                std::ops::ControlFlow::Continue(())
            });
            let outcome = match scanned {
                Err(err) => CreateError::Other(err),
                Ok(()) if exact => CreateError::Exists,
                Ok(()) => variant.map_or(CreateError::Exists, CreateError::ExistsAs),
            };
            // 作成は失敗したので、本呼び出しが新設した祖先を同一性を確かめて取り除く
            // （葉を他者が作っていれば親は空でないため残る）。
            let _ = rollback_dirs(&dirs, &made, ancestors);
            Err(outcome)
        }
        Err(err) => {
            let _ = rollback_dirs(&dirs, &made, ancestors);
            Err(map(err))
        }
    }
}

/// 作成直後の再検証（Linux / macOS。モジュール doc「プロセス間の競合」）。
/// 各階層で、作成に使ったディレクトリハンドルを読み直し、次の 2 点を確かめる。
/// - 同一性: 自分のコンポーネント名のエントリが、保持しているハンドル（祖先の
///   ディレクトリ・葉のファイル）と同じ inode を指している（作成直後に改名・削除・
///   差し替えされていれば、返す fd は共有パスから辿れないため `Internal`）。親と子の
///   デバイスが違う階層はマウントポイント（readdir は下層の inode を返す。改名・
///   削除は EBUSY で拒否される）のため照合しない
/// - 衝突: 自分のコンポーネントと大文字小文字だけが違うエントリが無い
///
/// 読み直しは一覧を保持しない走査（[`crate::sys::for_each_dir_entry`]）で行い、
/// 作成でエントリ数が索引の上限を 1 つ超えても検証できるようにする。どちらかを
/// 満たさない・読み取りに失敗した場合は取り消して返す（検証できないまま sink を
/// 返さない。fail-closed）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_created(
    created: Created,
    guest_path: &str,
    ancestors: &[&str],
    leaf: &str,
) -> Result<File, IoError> {
    use crate::fs_normalize::fold_component;
    use std::ops::ControlFlow;
    use std::os::unix::fs::MetadataExt;

    let fail = |created: &Created, err: IoError| rollback_after(created, ancestors, leaf, err);
    let mut prefix = String::new();
    for level in 0..=ancestors.len() {
        let component = ancestors.get(level).copied().unwrap_or(leaf);
        let child = if level < ancestors.len() {
            created.dirs.get(level + 1)
        } else {
            Some(&created.file)
        };
        let (Some(dir), Some(child)) = (created.dirs.get(level), child) else {
            let err = internal("failed to verify guest directory", ErrorKind::Other);
            return Err(fail(&created, err));
        };
        let metas = dir
            .metadata()
            .and_then(|d| child.metadata().map(|c| (d, c)));
        let (dir_meta, child_meta) = match metas {
            Ok(metas) => metas,
            Err(err) => {
                let err = internal("failed to verify guest directory", err.kind());
                return Err(fail(&created, err));
            }
        };
        let folded = fold_component(component);
        let mut own_ino = None;
        let mut other: Option<(String, u64)> = None;
        let scanned = visit_handle(dir, "failed to verify guest directory", |name, ino| {
            if name == component {
                own_ino = Some(ino);
            } else if other.is_none()
                && let Some(name) = name.to_str()
                && fold_component(name) == folded
            {
                other = Some((name.to_string(), ino));
            }
            ControlFlow::Continue(())
        });
        if let Err(err) = scanned {
            return Err(fail(&created, err));
        }
        if dir_meta.dev() == child_meta.dev() {
            match own_ino {
                Some(ino) if ino == child_meta.ino() => {}
                Some(_) => {
                    let err = IoError::new(
                        IoErrorCode::Internal,
                        "created guest path was replaced during create",
                    );
                    return Err(fail(&created, err));
                }
                None => {
                    // 大文字小文字を区別しないホストでは、走査の後に作られた表記違いの
                    // 祖先をそのまま開いて作成しうる。その場合は衝突として返す。
                    let err = match &other {
                        Some((name, ino)) if *ino == child_meta.ino() => {
                            collision_error(guest_path, &format!("{prefix}{name}"), component, name)
                        }
                        _ => IoError::new(
                            IoErrorCode::Internal,
                            "created guest path was removed or renamed during create",
                        ),
                    };
                    return Err(fail(&created, err));
                }
            }
        }
        if let Some((other, _)) = other {
            let err = collision_error(guest_path, &format!("{prefix}{other}"), component, &other);
            return Err(fail(&created, err));
        }
        prefix.push_str(component);
        prefix.push('/');
    }
    Ok(created.file)
}

/// 再検証を行わないフォールバック（Windows 等。モジュール doc の既知の限界）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn verify_created(
    created: Created,
    _guest_path: &str,
    _ancestors: &[&str],
    _leaf: &str,
) -> Result<File, IoError> {
    Ok(created.file)
}

/// 取り消しが元どおりにできなかった理由。
#[cfg(any(target_os = "linux", target_os = "macos"))]
enum RollbackError {
    /// 自分の葉は既に別の書き込み元の実体へ差し替えられていた。その実体は元の名前に
    /// ある（触らなかった、または退避後に元の名前へ戻した）。データの欠落も退避も
    /// 残っておらず、別の作成者との競合として報告する。
    Conflict(String),
    /// 取り消しを完了できなかった（退避先に他者の実体を残した場合は、その場所を含む）。
    Failed(String),
}

/// `created` を取り消し、成功すれば `cause` を返す。取り消しの結果に応じて、
/// 別の書き込み元との競合（`AlreadyExists`。`concurrent writer replaced the created
/// guest file`）か、取り消し失敗（`Internal`。`created guest file could not be
/// rolled back`）を返す。どちらも理由と `cause` のメッセージを併記する。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_after(created: &Created, ancestors: &[&str], leaf: &str, cause: IoError) -> IoError {
    match rollback_created(created, ancestors, leaf) {
        Ok(()) => cause,
        Err(RollbackError::Conflict(detail)) => IoError::new(
            IoErrorCode::AlreadyExists,
            format!(
                "concurrent writer replaced the created guest file ({detail}); cause: {}",
                cause.message()
            ),
        ),
        Err(RollbackError::Failed(detail)) => IoError::new(
            IoErrorCode::Internal,
            format!(
                "created guest file could not be rolled back ({detail}); cause: {}",
                cause.message()
            ),
        ),
    }
}

/// 作成した葉と、新設した空の祖先を取り消す。失敗の理由（ホストのパスを含まない。
/// 共有ルートからの退避先のパスを含むことがある）を返す。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_created(
    created: &Created,
    ancestors: &[&str],
    leaf: &str,
) -> Result<(), RollbackError> {
    let Some(parent) = created.dirs.last() else {
        return Err(RollbackError::Failed("missing parent handle".to_string()));
    };
    let parent_path: String = ancestors.iter().map(|a| format!("{a}/")).collect();
    let leaf_result = remove_file_if_same(parent, leaf, &created.file, &parent_path);
    // 葉が他者の実体に差し替えられていても、新設した祖先は空なら取り除く（葉が
    // 残っていれば空でないため、取り除かれない）。
    let dirs_result = rollback_dirs(&created.dirs, &created.made, ancestors);
    leaf_result?;
    dirs_result.map_err(RollbackError::Failed)
}

/// 深い方から、本呼び出しが新設した祖先ディレクトリを空であれば取り除く
/// （新設でない祖先に達した・空でなかったらそこで止める。それより上は空でない）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_dirs(dirs: &[File], made: &[bool], ancestors: &[&str]) -> Result<(), String> {
    for level in (0..made.len()).rev() {
        if made.get(level) != Some(&true) {
            return Ok(());
        }
        let (Some(parent), Some(dir), Some(name)) =
            (dirs.get(level), dirs.get(level + 1), ancestors.get(level))
        else {
            return Err("missing ancestor handle".to_string());
        };
        if !remove_empty_dir_if_same(parent, name, dir)? {
            return Ok(());
        }
    }
    Ok(())
}

/// `parent` 直下の `name` のエントリの inode（無ければ `None`）と、保持ハンドル
/// `expected` の inode を返す。`expected` と `parent` のデバイスが違う場合は同一性を
/// 確かめられないため失敗する。一覧を保持しない走査のため件数上限は無い。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entry_ino(parent: &File, name: &str, expected: &File) -> Result<(Option<u64>, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let expected_meta = expected
        .metadata()
        .map_err(|_| "cannot stat created entry".to_string())?;
    let parent_meta = parent
        .metadata()
        .map_err(|_| "cannot stat parent".to_string())?;
    if expected_meta.dev() != parent_meta.dev() {
        return Err("created entry is on a different device".to_string());
    }
    let found =
        find_in_handle(parent, name).map_err(|_| "cannot re-read parent directory".to_string())?;
    Ok((found, expected_meta.ino()))
}

/// 本呼び出しが新設した空の祖先 `parent`/`name` を、保持ハンドル `expected` と
/// 同じ inode であることを確かめてから `unlinkat(AT_REMOVEDIR)` で取り除く。
/// 取り除いた・既に無い場合は `true`、空でない（他者が中に作った）ため残した場合は
/// `false`。確認から削除までの間に差し替えられても、消えうるのは空のディレクトリ
/// だけ（`AT_REMOVEDIR` は空でなければ失敗する）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_empty_dir_if_same(parent: &File, name: &str, expected: &File) -> Result<bool, String> {
    use crate::sys::{BeneathError, UnlinkTarget, unlink_beneath};
    let (found, ino) = entry_ino(parent, name, expected)?;
    match found {
        None => return Ok(true),
        Some(found) if found != ino => {
            return Err("ancestor was replaced by another object".to_string());
        }
        Some(_) => {}
    }
    match unlink_beneath(parent, name, UnlinkTarget::EmptyDirectory) {
        Ok(()) | Err(BeneathError::Io(ErrorKind::NotFound)) => Ok(true),
        // rmdir の非空は ENOTEMPTY（POSIX は EEXIST も許す）。
        Err(BeneathError::Io(ErrorKind::DirectoryNotEmpty | ErrorKind::AlreadyExists)) => Ok(false),
        Err(_) => Err("rmdir failed".to_string()),
    }
}

/// 取り消し用の私有ディレクトリ名の候補（小文字・数字・`-`・`.` だけで、大文字小文字
/// の衝突を起こさない。存在確認は作成側の `mkdirat` が行う）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn quarantine_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".fandhe-rollback-{}-{n}-{nanos}", std::process::id())
}

/// 取り消しで他者の実体を残した場所の報告文字列。私有ディレクトリ名（本モジュールが
/// 生成した短い安全な名前で、共有ルート内で一意）は切り詰めずに先頭へ置き、親の
/// ゲスト相対パスだけを [`quote_for_message`] で衛生化・切り詰める（深い親でも
/// 退避先を特定できるようにする。Cursor 指摘）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn quarantine_location(parent_path: &str, quarantine: &str) -> String {
    let entry = format!("\"{quarantine}/{QUARANTINE_ENTRY}\"");
    if parent_path.is_empty() {
        entry
    } else {
        format!("{entry} under {}", quote_for_message(parent_path))
    }
}

/// 私有ディレクトリ内で退避した葉を置く名前。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const QUARANTINE_ENTRY: &str = "entry";

/// 作成した葉 `parent`/`name` を取り消す（他者のデータを消さない手順。モジュール
/// doc「プロセス間の競合」）。`parent_path` は共有ルートから `parent` までのゲスト
/// 相対パス（`a/b/` の形。報告にだけ使う）。
///
/// 1. 読み直した `name` の inode が保持 fd `expected` と一致することを確かめる
///    （無ければ取り消す対象がなく成功。違えば触らずに `Conflict`）
/// 2. `parent` 直下に自分だけが入れる私有ディレクトリ（`mkdirat` の mode `0o700`。
///    開いたハンドルの所有者が自プロセスの実効 uid で、グループ・その他の権限が
///    無いことを確かめる）を作り、そのハンドルへ `name` を `renameat` で移す。
///    名前の付け替えは原子的なので、1 の直後に `name` へ他者の実体が差し込まれて
///    いても、それは消えずに私有ディレクトリへ移るだけになる
/// 3. 私有ディレクトリ内のエントリの inode が `expected` と一致するときだけ
///    `unlinkat` する。私有ディレクトリへは他の uid が改名で差し込めないため、
///    この確認から削除までの間に別の実体へ差し替えられない（同じ uid・root を除く）
/// 4. 一致しなければ（2 で他者の実体を移していたら）、上書きしない `linkat` で元の
///    名前へ戻し、私有ディレクトリ側の名前を `unlinkat` して `Conflict` を返す。
///    元の名前が既に再利用されていた・ハードリンクを作れない（ハードリンク非対応の
///    FS・ディレクトリ・`fs.protected_hardlinks` による拒否）場合は、消さずに
///    私有ディレクトリに残し、その場所を含めて `Failed` を返す（fail-closed）
/// 5. 空になった私有ディレクトリを取り除く（ベストエフォート）
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_file_if_same(
    parent: &File,
    name: &str,
    expected: &File,
    parent_path: &str,
) -> Result<(), RollbackError> {
    use crate::sys::{
        BeneathError, DirMode, UnlinkTarget, effective_uid, mkdir_beneath, open_dir_beneath,
        rename_beneath, unlink_beneath,
    };
    use std::os::unix::fs::MetadataExt;

    let failed = RollbackError::Failed;
    let (found, ino) = entry_ino(parent, name, expected).map_err(failed)?;
    match found {
        None => return Ok(()),
        Some(found) if found != ino => {
            return Err(RollbackError::Conflict(
                "the entry was already replaced and was left untouched".to_string(),
            ));
        }
        Some(_) => {}
    }

    // 私有ディレクトリを新設する（既存の名前は使わない。候補が埋まっていたら数回
    // だけ選び直す）。
    let mut quarantine = None;
    for _ in 0..8 {
        let candidate = quarantine_name();
        match mkdir_beneath(parent, &candidate, DirMode::Private) {
            Ok(true) => {
                quarantine = Some(candidate);
                break;
            }
            Ok(false) => {}
            Err(_) => return Err(failed("cannot create quarantine directory".to_string())),
        }
    }
    let Some(quarantine) = quarantine else {
        return Err(failed("no free quarantine name".to_string()));
    };
    // 報告用の退避先（共有ルートからのゲスト相対パス。衛生化して埋め込む）。
    let left_at = quarantine_location(parent_path, &quarantine);
    let qdir = open_dir_beneath(parent, &quarantine)
        .map_err(|_| failed(format!("cannot open quarantine directory {quarantine:?}")))?;
    let qmeta = qdir
        .metadata()
        .map_err(|_| failed(format!("cannot stat quarantine directory {quarantine:?}")))?;
    if qmeta.uid() != effective_uid() || qmeta.mode() & 0o077 != 0 {
        // 作成直後に同名へ他者のディレクトリが差し込まれた。触らずに止める。
        return Err(failed(format!(
            "quarantine directory {quarantine:?} is not private"
        )));
    }

    #[cfg(test)]
    fault::run_hook(fault::Hook::BeforeQuarantine);
    match rename_beneath(parent, name, &qdir, QUARANTINE_ENTRY) {
        Ok(()) => {}
        Err(BeneathError::Io(ErrorKind::NotFound)) => {
            let _ = remove_empty_dir_if_same(parent, &quarantine, &qdir);
            return Ok(());
        }
        Err(_) => {
            let _ = remove_empty_dir_if_same(parent, &quarantine, &qdir);
            return Err(failed("rename to quarantine failed".to_string()));
        }
    }
    let moved = find_in_handle(&qdir, QUARANTINE_ENTRY).map_err(|_| {
        failed(format!(
            "cannot re-read quarantine; entry left at {left_at}"
        ))
    })?;
    let outcome = match moved {
        None => Ok(()),
        Some(moved) if moved == ino => {
            match unlink_beneath(&qdir, QUARANTINE_ENTRY, UnlinkTarget::File) {
                Ok(()) | Err(BeneathError::Io(ErrorKind::NotFound)) => Ok(()),
                Err(_) => Err(failed(format!("unlink failed; entry left at {left_at}"))),
            }
        }
        // 確認の直後に差し込まれた他者の実体を移してしまった。上書きしない linkat で
        // 元の名前へ戻す。
        Some(_) => restore_moved(parent, name, &qdir, &left_at),
    };
    // 空の私有ディレクトリの後始末（中に他者の実体を残した場合は空でないため残る）。
    let _ = remove_empty_dir_if_same(parent, &quarantine, &qdir);
    outcome
}

/// 取り消しで私有ディレクトリ `qdir` へ移してしまった他者の実体を、上書きしない
/// `linkat` で `parent`/`name` へ戻す（[`remove_file_if_same`] の 4）。戻せたら
/// 私有ディレクトリ側の名前を消して `Conflict`、戻せなければ消さずに残して `Failed`
/// （`left_at` は報告用の退避先）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn restore_moved(
    parent: &File,
    name: &str,
    qdir: &File,
    left_at: &str,
) -> Result<(), RollbackError> {
    use crate::sys::{BeneathError, UnlinkTarget, link_beneath, unlink_beneath};
    #[cfg(test)]
    fault::run_hook(fault::Hook::BeforeRestore);
    match link_beneath(qdir, QUARANTINE_ENTRY, parent, name) {
        Ok(()) => {}
        Err(BeneathError::AlreadyExists) => {
            return Err(RollbackError::Failed(format!(
                "the name was reused before the replaced entry could be moved back; \
                 entry left at {left_at}"
            )));
        }
        Err(_) => {
            return Err(RollbackError::Failed(format!(
                "the replaced entry could not be linked back; entry left at {left_at}"
            )));
        }
    }
    // 元の名前にも同じ inode のリンクができたので、私有ディレクトリ側を消す（私有
    // ディレクトリへは他の uid が差し込めない）。
    match unlink_beneath(qdir, QUARANTINE_ENTRY, UnlinkTarget::File) {
        Ok(()) | Err(BeneathError::Io(ErrorKind::NotFound)) => Err(RollbackError::Conflict(
            "the replaced entry was moved back to its name".to_string(),
        )),
        Err(_) => Err(RollbackError::Failed(format!(
            "the replaced entry was moved back but an extra link is left at {left_at}"
        ))),
    }
}

/// Windows 等のフォールバック。ルート直下から 1 階層ずつ、作成（`create_dir`）→
/// 「reparse point を辿らず（`FILE_FLAG_OPEN_REPARSE_POINT`）・`FILE_SHARE_DELETE`
/// なしで」ディレクトリを開いて保持→ reparse point / 非ディレクトリでないことを
/// 確認、の順で祖先を固定する。保持中のハンドルは改名・削除・差し替えを OS が
/// 拒否するため、以降のパス結合による解決は固定済みの祖先の配下に留まる
/// （ルートハンドルと同じ方式。TOCTOU 防止。IO-5・REPAIR-3）。`NtCreateFile` の
/// ルート相対ハンドル作成への置き換えは後続。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn create_beneath(
    _root_dir: &File,
    root: &Path,
    ancestors: &[&str],
    leaf: &str,
) -> Result<Created, CreateError> {
    let mut path = root.to_path_buf();
    // 固定済みの祖先ハンドル（葉の作成が終わるまで保持する）。
    let mut pinned: Vec<File> = Vec::with_capacity(ancestors.len());
    for name in ancestors {
        path.push(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(CreateError::Other(internal(
                    "failed to create guest file",
                    err.kind(),
                )));
            }
        }
        let dir = open_pinned_dir(&path)
            .map_err(|err| CreateError::Other(internal("failed to create guest file", err.kind())))?
            .ok_or_else(|| CreateError::Other(invalid("guest path ancestor is not a directory")))?;
        pinned.push(dir);
    }
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join(leaf))
        .map(|file| Created { file })
        .map_err(|err| {
            if err.kind() == ErrorKind::AlreadyExists {
                // 実在する表記を確かめる（NTFS は大文字小文字を区別しないため、走査の
                // 後に作られた大小違いの項目でも `create_new` が既存として失敗する）。
                classify_existing(&path, leaf)
            } else {
                CreateError::Other(internal("failed to create guest file", err.kind()))
            }
        });
    drop(pinned);
    result
}

/// テスト専用の失敗・競合の注入口（本番ビルドには含まれない）。走査の読み取り口
/// （[`scan_handle`] / フォールバックの `ScanCursor::read_entries`）と、作成の
/// 直前・直後にだけ差し込む。状態はスレッドローカルで、呼び出したテストの
/// スレッドにだけ効く（IO-5・Cursor 指摘対応: ハンドル相対の走査は実 FS の操作では
/// 決定的に失敗させられないため）。
#[cfg(test)]
mod fault {
    use std::cell::{Cell, RefCell};

    /// 差し込み位置。
    pub(super) enum Hook {
        /// 走査・検査の後、作成の直前（別プロセスの割り込みを模す）。
        BeforeCreate,
        /// 作成の直後、再検証の直前。
        AfterCreate,
        /// 取り消しで葉を退避名へ改名する直前（同一性確認の後。Linux / macOS）。
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BeforeQuarantine,
        /// 取り消しで移してしまった他者の実体を元の名前へ戻す直前（Linux / macOS）。
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BeforeRestore,
        /// 祖先を作った後、葉を作る直前（Linux / macOS）。
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BeforeLeaf,
    }

    type HookFn = Box<dyn FnOnce()>;

    thread_local! {
        static SCAN_CALLS: Cell<usize> = const { Cell::new(0) };
        static FAIL_SCAN_AT: Cell<Option<usize>> = const { Cell::new(None) };
        static BEFORE_CREATE: RefCell<Option<HookFn>> = const { RefCell::new(None) };
        static AFTER_CREATE: RefCell<Option<HookFn>> = const { RefCell::new(None) };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        static BEFORE_QUARANTINE: RefCell<Option<HookFn>> = const { RefCell::new(None) };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        static BEFORE_RESTORE: RefCell<Option<HookFn>> = const { RefCell::new(None) };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        static BEFORE_LEAF: RefCell<Option<HookFn>> = const { RefCell::new(None) };
    }

    /// 注入状態を初期化する（各テストの先頭で呼ぶ）。
    pub(super) fn reset() {
        SCAN_CALLS.with(|c| c.set(0));
        FAIL_SCAN_AT.with(|f| f.set(None));
        BEFORE_CREATE.with(|h| h.borrow_mut().take());
        AFTER_CREATE.with(|h| h.borrow_mut().take());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BEFORE_QUARANTINE.with(|h| h.borrow_mut().take());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BEFORE_RESTORE.with(|h| h.borrow_mut().take());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BEFORE_LEAF.with(|h| h.borrow_mut().take());
    }

    /// 以降の走査の読み取りのうち `n` 回目（0 起点）を失敗させる。
    pub(super) fn fail_scan_at(n: usize) {
        SCAN_CALLS.with(|c| c.set(0));
        FAIL_SCAN_AT.with(|f| f.set(Some(n)));
    }

    /// 走査の読み取り口から呼ばれ、失敗させる回なら `true`。
    pub(super) fn scan_should_fail() -> bool {
        let n = SCAN_CALLS.with(|c| {
            let n = c.get();
            c.set(n.saturating_add(1));
            n
        });
        FAIL_SCAN_AT.with(|f| f.get() == Some(n))
    }

    /// `hook` の位置で 1 回だけ `f` を実行させる。
    pub(super) fn set_hook(hook: Hook, f: impl FnOnce() + 'static) {
        let slot = match hook {
            Hook::BeforeCreate => &BEFORE_CREATE,
            Hook::AfterCreate => &AFTER_CREATE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeQuarantine => &BEFORE_QUARANTINE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeRestore => &BEFORE_RESTORE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeLeaf => &BEFORE_LEAF,
        };
        slot.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// `hook` の位置に登録された処理があれば取り出して実行する。
    pub(super) fn run_hook(hook: Hook) {
        let slot = match hook {
            Hook::BeforeCreate => &BEFORE_CREATE,
            Hook::AfterCreate => &AFTER_CREATE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeQuarantine => &BEFORE_QUARANTINE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeRestore => &BEFORE_RESTORE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Hook::BeforeLeaf => &BEFORE_LEAF,
        };
        if let Some(f) = slot.with(|h| h.borrow_mut().take()) {
            f();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcio-gf-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entries(p: &Path) -> usize {
        std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0)
    }

    #[test]
    fn io5_case_only_second_create_is_rejected() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("Foo.txt").expect("first");
        let err = c.create_file("foo.txt").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 1);
    }

    #[test]
    fn io5_identical_path_reports_exists_not_collision() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("a").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
    }

    #[test]
    fn io5_depth_differing_collision_creates_no_directory() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("A/b").err().expect("must collide");
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 1);
    }

    #[test]
    fn io5_rejected_paths_do_not_pollute_index_or_fs() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let long = "x".repeat(MAX_GUEST_PATH_BYTES + 1);
        for p in [
            "..",
            "a/../b",
            "/abs",
            "a\\b",
            "C:x",
            "a:b",
            "",
            ".",
            "a//b",
            "a\0b",
            long.as_str(),
        ] {
            let err = c.create_file(p).err().expect("must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument, "path {p:?}");
        }
        assert_eq!(entries(&t.0), 0);
    }

    #[test]
    fn io5_tracked_limit_and_range() {
        let t = Tmp::new();
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 1).expect("creator");
        c.create_file("a").expect("first");
        // 既存 1 件（上限ちょうど）までは取り込める。
        c.create_file("b").expect("second");
        // 既存が 2 件になり、1 回の作成で取り込む上限を超える。
        let err = c.create_file("c").err().expect("limit");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(err.message(), "too many tracked guest paths");
        assert_eq!(entries(&t.0), 2);
        for n in [0, MAX_TRACKED_GUEST_PATHS + 1] {
            let err = GuestFileCreator::with_max_tracked_paths(t.0.clone(), n)
                .err()
                .expect("range");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn io5_root_must_be_directory() {
        let t = Tmp::new();
        let f = t.0.join("f");
        std::fs::write(&f, b"x").expect("write");
        let err = GuestFileCreator::new(f).err().expect("not a dir");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    #[cfg(unix)]
    #[test]
    fn io5_symlink_ancestor_is_rejected() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).expect("root");
        std::os::unix::fs::symlink(&outside.0, root.join("link")).expect("symlink");
        let c = GuestFileCreator::new(root).expect("creator");
        let err = c.create_file("link/f").err().expect("must reject");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(entries(&outside.0), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_failed_create_does_not_pollute_index() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // a は通常ファイルなので a/b の作成は祖先エラーで失敗する。
        std::fs::write(t.0.join("a"), b"x").expect("write");
        let err = c.create_file("a/b").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        // 失敗した `a/b` は何も残さず、実在する `a` はそのまま。
        assert!(t.0.join("a").is_file());
        c.create_file("b").expect("later create is unaffected");
    }

    #[cfg(unix)]
    #[test]
    fn io5_symlink_leaf_is_not_followed() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let target = outside.0.join("victim");
        std::os::unix::fs::symlink(&target, t.0.join("f")).expect("symlink");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("f").err().expect("must reject");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(!target.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_preexisting_directory_case_variant_collides() {
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("Foo")).expect("dir");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("foo/bar").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0.join("Foo")), 0);
        c.create_file("Foo/bar").expect("same spelling is fine");
    }

    /// 葉の作成に失敗したら、本呼び出しが新設した空の祖先は取り除き、元から
    /// あった祖先は残す（エラー時の後始末。IO-5）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_leaf_failure_rolls_back_created_ancestors() {
        fault::reset();
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("keep")).expect("keep");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // 葉が長すぎて作成に失敗する（祖先 `a`・`a/b` は新設後に取り除かれる）。
        let long = "x".repeat(300);
        let err = c
            .create_file(&format!("a/b/{long}"))
            .err()
            .expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(
            err.message(),
            "failed to create guest file (InvalidFilename)"
        );
        assert!(!t.0.join("a").exists());
        let err = c
            .create_file(&format!("keep/{long}"))
            .err()
            .expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(t.0.join("keep").is_dir());
        assert_eq!(entries(&t.0), 1);
        // 取り除かれた `a` は索引にも実体にも残らないため、表記違いも作れる。
        c.create_file("A/b").expect("no leftover ancestor");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn io5_fallback_creates_paths_with_ancestors() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a/b/c").expect("nested create");
        assert!(t.0.join("a").join("b").join("c").is_file());
        c.create_file("top").expect("root-level file is allowed");
        let err = c.create_file("A/x").err().expect("must collide");
        assert!(err.message().starts_with("case-insensitive path collision"));
    }

    /// 別プロセスが作成後に共有ルートへ足した項目とも衝突を検出する。
    #[test]
    fn io5_externally_added_entry_is_detected_on_later_create() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("first").expect("first");
        std::fs::write(t.0.join("Foo"), b"x").expect("external");
        let err = c.create_file("foo").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 2);
    }

    /// 走査を完了できないときは索引不完全のまま作成せず構造化エラーで中止する
    /// （読み取り失敗は `fault` で決定的に注入する。ハンドル相対の走査は、ルートの
    /// パスを消しても開いたハンドル経由で成功してしまうため。Cursor 指摘対応）。
    #[test]
    fn io5_scan_failure_aborts_create() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        fault::fail_scan_at(0);
        let err = c.create_file("a").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(err.message(), "failed to scan guest directory (Other)");
        assert_eq!(entries(&t.0), 0);
        fault::reset();
        c.create_file("a")
            .expect("create succeeds once scanning works");
    }

    /// 祖先の階層の走査に失敗しても、祖先を作らずに中止する。
    #[test]
    fn io5_nested_scan_failure_creates_nothing() {
        fault::reset();
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("d")).expect("d");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // 0 回目はルート、1 回目は `d` の走査。
        fault::fail_scan_at(1);
        let err = c.create_file("d/e/f").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(err.message(), "failed to scan guest directory (Other)");
        assert_eq!(entries(&t.0.join("d")), 0);
    }

    /// 作成直前に同じ名前が外部で作られた場合は既存として報告する（3 OS 共通）。
    #[test]
    fn io5_same_name_created_before_create_reports_exists() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let external = t.0.join("a");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::write(external, b"theirs").expect("external write");
        });
        let err = c.create_file("a").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
        assert_eq!(std::fs::read(t.0.join("a")).expect("read"), b"theirs");
    }

    /// 上限 1: 実在項目が上限以内なら、既存は既存・大小違いは衝突として報告し、
    /// 新しい名前も作れる。実在項目が上限を超えたディレクトリでは
    /// `ResourceExhausted` になる（Codex P1 指摘への対応後の契約）。
    #[test]
    fn io5_limit_applies_only_to_new_paths() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 1).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("a").err().expect("exists");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
        let err = c.create_file("A").err().expect("collision");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        c.create_file("b")
            .expect("one existing entry is within the bound");
        let err = c.create_file("c").err().expect("limit");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(err.message(), "too many tracked guest paths");
        assert_eq!(entries(&t.0), 2);
    }

    /// 作成直後の再検証で読み取りに失敗したら、作成した葉と新設した祖先を
    /// 取り消して `Internal` を返す（sink を返さない。fail-closed）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_verify_failure_rolls_back_created_entries() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // 0 回目はルートの走査（`d` は未作成で降りない）、1 回目が再検証の
        // ルート階層。
        fault::fail_scan_at(1);
        let err = c.create_file("d/e/f").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(err.message(), "failed to verify guest directory (Other)");
        assert_eq!(entries(&t.0), 0);
    }

    /// 走査から作成までの間に別プロセスが大小違いの葉を作った場合、作成後の
    /// 再検証で検出し、自分の葉だけを取り消す（Codex P1 指摘。大文字小文字を
    /// 区別する FS でのみ両方作れるため Linux 限定）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_external_case_variant_before_create_is_rolled_back() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let external = t.0.join("Foo");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::write(external, b"theirs").expect("external write");
        });
        let err = c.create_file("foo").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert!(err.message().contains("\"Foo\""), "{}", err.message());
        assert!(!t.0.join("foo").exists());
        assert_eq!(std::fs::read(t.0.join("Foo")).expect("read"), b"theirs");
        // 退避名も残らない（自分の葉は退避名へ移したうえで消した）。
        assert_eq!(entries(&t.0), 1);
    }

    /// 祖先の大小違いが割り込んだ場合は、葉と本呼び出しが新設した祖先を取り消す
    /// （空の `dir` を残すと以降の走査が既存衝突で中止し続けるため）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_external_ancestor_variant_rolls_back_created_dirs() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let external = t.0.join("Dir");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::create_dir(external).expect("external dir");
        });
        let err = c.create_file("dir/sub/x").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert!(!t.0.join("dir").exists());
        assert!(t.0.join("Dir").is_dir());
        assert_eq!(entries(&t.0), 1);
        // 残っているのは外部の `Dir` だけなので、その表記では作れる。
        c.create_file("Dir/sub/x")
            .expect("create under the existing spelling");
    }

    /// 取り消しの前に同じ名前が別の実体へ差し替えられていたら、消さずに残して
    /// `Internal` を返す（他者のデータを消さない。Linux 限定の理由は上と同じ）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_rollback_does_not_remove_replaced_entry() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let root = t.0.clone();
        fault::set_hook(fault::Hook::AfterCreate, move || {
            std::fs::write(root.join("other"), b"theirs").expect("other");
            std::fs::rename(root.join("other"), root.join("foo")).expect("replace");
            std::fs::write(root.join("Foo"), b"variant").expect("variant");
        });
        let err = c.create_file("foo").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(
            err.message().starts_with(
                "concurrent writer replaced the created guest file (the entry was already replaced and was left untouched); cause: created guest path was replaced during create"
            ),
            "{}",
            err.message()
        );
        assert_eq!(std::fs::read(t.0.join("foo")).expect("read"), b"theirs");
        assert_eq!(std::fs::read(t.0.join("Foo")).expect("read"), b"variant");
    }

    /// 作成直後に葉が改名された場合（大小違いは無い）、返す fd は共有パスから
    /// 辿れないため sink を返さず `Internal` にする（Codex P1 指摘。改名先の実体には
    /// 触らない）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_leaf_renamed_after_create_is_rejected() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let root = t.0.clone();
        fault::set_hook(fault::Hook::AfterCreate, move || {
            std::fs::rename(root.join("foo"), root.join("bar")).expect("rename");
        });
        let err = c.create_file("foo").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(
            err.message(),
            "created guest path was removed or renamed during create"
        );
        assert!(t.0.join("bar").is_file());
        assert!(!t.0.join("foo").exists());
    }

    /// 作成直後に祖先が改名された場合も同様に拒否し、改名先の中の自分の葉は
    /// 保持ハンドル経由で取り消す。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_ancestor_renamed_after_create_is_rejected() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let root = t.0.clone();
        fault::set_hook(fault::Hook::AfterCreate, move || {
            std::fs::rename(root.join("d"), root.join("moved")).expect("rename");
        });
        let err = c.create_file("d/f").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(
            err.message()
                .ends_with("created guest path was removed or renamed during create"),
            "{}",
            err.message()
        );
        assert!(!t.0.join("moved").join("f").exists());
        assert!(!t.0.join("d").exists());
    }

    /// 共有ルート直下の `.fandhe-rollback-*`（取り消しの私有ディレクトリ）の名前。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn quarantine_dirs(root: &Path) -> Vec<String> {
        std::fs::read_dir(root)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".fandhe-rollback-"))
            .collect()
    }

    /// 取り消しの同一性確認の直後に、葉の名前へ他者のファイルが差し込まれた場合、
    /// 私有ディレクトリへ移してしまったそれを上書きしない `linkat` で元の名前へ戻し、
    /// 競合（`AlreadyExists`）として報告する（Codex P0 指摘。取り消しは再検証の
    /// 読み取り失敗の注入で起こす）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_rollback_race_restores_foreign_file() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // 0 回目はルートの走査、1 回目が再検証のルート階層。
        fault::fail_scan_at(1);
        let root = t.0.clone();
        fault::set_hook(fault::Hook::BeforeQuarantine, move || {
            std::fs::write(root.join("other"), b"theirs").expect("other");
            std::fs::rename(root.join("other"), root.join("foo")).expect("replace");
        });
        let err = c.create_file("foo").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert_eq!(
            err.message(),
            "concurrent writer replaced the created guest file (the replaced entry was \
             moved back to its name); cause: failed to verify guest directory (Other)"
        );
        assert_eq!(std::fs::read(t.0.join("foo")).expect("restored"), b"theirs");
        assert!(
            quarantine_dirs(&t.0).is_empty(),
            "{:?}",
            quarantine_dirs(&t.0)
        );
        assert_eq!(entries(&t.0), 1);
    }

    /// 元の名前が戻す前に再利用されていたら、移してしまった他者のファイルは消さずに
    /// 私有ディレクトリへ残し、その場所を含めて `Internal` で報告する。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_rollback_race_keeps_foreign_file_when_name_is_reused() {
        use std::os::unix::fs::MetadataExt;
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        fault::fail_scan_at(1);
        let root = t.0.clone();
        fault::set_hook(fault::Hook::BeforeQuarantine, move || {
            std::fs::write(root.join("other"), b"theirs").expect("other");
            std::fs::rename(root.join("other"), root.join("foo")).expect("replace");
        });
        let root = t.0.clone();
        fault::set_hook(fault::Hook::BeforeRestore, move || {
            std::fs::write(root.join("foo"), b"third").expect("reuse the name");
        });
        let err = c.create_file("foo").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        let dirs = quarantine_dirs(&t.0);
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        let qname = dirs.first().expect("quarantine dir");
        assert_eq!(
            err.message(),
            format!(
                "created guest file could not be rolled back (the name was reused before the \
                 replaced entry could be moved back; entry left at \"{qname}/entry\"); cause: \
                 failed to verify guest directory (Other)"
            )
        );
        let qdir = t.0.join(qname);
        assert_eq!(
            std::fs::metadata(&qdir).expect("quarantine").mode() & 0o077,
            0,
            "quarantine must be private"
        );
        assert_eq!(std::fs::read(qdir.join("entry")).expect("kept"), b"theirs");
        assert_eq!(std::fs::read(t.0.join("foo")).expect("reused"), b"third");
    }

    /// 移してしまった実体がハードリンクを作れないもの（ディレクトリ）なら、戻せないため
    /// 消さずに私有ディレクトリへ残して報告する（ハードリンク非対応の FS・
    /// `fs.protected_hardlinks` による拒否と同じ経路。fail-closed）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_rollback_race_keeps_unlinkable_object_in_quarantine() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        fault::fail_scan_at(1);
        let root = t.0.clone();
        fault::set_hook(fault::Hook::BeforeQuarantine, move || {
            std::fs::remove_file(root.join("foo")).expect("remove");
            std::fs::create_dir(root.join("foo")).expect("dir");
            std::fs::write(root.join("foo").join("inner"), b"theirs").expect("inner");
        });
        let err = c.create_file("foo").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(
            err.message().starts_with(
                "created guest file could not be rolled back (the replaced entry could not be \
                 linked back; entry left at \".fandhe-rollback-"
            ),
            "{}",
            err.message()
        );
        let dirs = quarantine_dirs(&t.0);
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        let kept =
            t.0.join(dirs.first().expect("quarantine dir"))
                .join("entry");
        assert_eq!(std::fs::read(kept.join("inner")).expect("kept"), b"theirs");
        assert!(!t.0.join("foo").exists());
    }

    /// 件数上限は要求パスの祖先に沿って取り込む実在項目の合計に掛かる。上限以内なら
    /// ネストしたパスの既存・衝突を正しく報告する（Cursor・Codex P1 指摘への対応後の
    /// 契約）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_limit_does_not_count_implicit_ancestors() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 2).expect("creator");
        c.create_file("a/b").expect("first");
        let err = c.create_file("a/b").err().expect("exists");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
        for path in ["A/b", "a/B"] {
            let err = c.create_file(path).err().expect("collision");
            assert_eq!(err.code(), IoErrorCode::AlreadyExists, "{path}");
            assert!(
                err.message().starts_with("case-insensitive path collision"),
                "{path}: {}",
                err.message()
            );
        }
        let err = c.create_file("a").err().expect("exists");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
        // `a`・`a/b` の 2 件は上限以内。
        c.create_file("a/c").expect("within the bound");
        // `a`・`a/b`・`a/c` の 3 件で上限を超える。
        let err = c.create_file("a/d").err().expect("limit");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(entries(&t.0.join("a")), 2);
    }

    /// 親ディレクトリのエントリ数がちょうど上限のときに作成して上限を 1 つ超えても、
    /// 再検証・取り消しは一覧を保持しない走査で行うため失敗せず、衝突なら作成した
    /// ファイルを残さない（Codex P1 指摘。非 UTF-8 名は索引に入らないが走査では
    /// 数えられる。大小違いを作れるのは Linux のみ）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_verify_and_rollback_work_past_entry_limit() {
        use std::os::unix::ffi::OsStrExt;
        fault::reset();
        let t = Tmp::new();
        std::fs::write(t.0.join(std::ffi::OsStr::from_bytes(b"raw-\xff")), b"x").expect("non-utf8");
        // 上限 1・既存 1 件（ちょうど上限）の状態から作成して 2 件になっても成功する。
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 1).expect("creator");
        c.create_file("ok")
            .expect("create past the per-directory entry limit");
        // 上限 2・既存 2 件の状態で、作成直前に大小違いが足されて 4 件になっても、
        // 衝突を検出して自分の作成を取り消す。
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 2).expect("creator");
        let external = t.0.join("Foo");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::write(external, b"variant").expect("variant");
        });
        let err = c.create_file("foo").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists, "{err:?}");
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert!(!t.0.join("foo").exists());
        assert_eq!(entries(&t.0), 3);
        assert!(t.0.join("ok").is_file());
    }

    /// 大文字小文字を区別しないホスト（既定の APFS・NTFS）で、走査の後に別の作成者が
    /// 大小違いの項目を作った場合、作成は既存として失敗するが、実在する表記を確かめて
    /// 衝突として返し、要求の表記では登録しない（Codex P1 指摘）。
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn io5_case_insensitive_host_reports_late_variant_as_collision() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let external = t.0.join("Foo");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::write(external, b"theirs").expect("external write");
        });
        let err = c.create_file("foo").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(
            err.message().starts_with("case-insensitive path collision"),
            "{}",
            err.message()
        );
        assert!(err.message().contains("\"Foo\""), "{}", err.message());
        assert_eq!(std::fs::read(t.0.join("Foo")).expect("read"), b"theirs");
        assert_eq!(entries(&t.0), 1);
    }

    /// 大文字小文字を区別しない macOS で、走査の後に大小違いの祖先が作られると、
    /// 作成はその祖先をそのまま開いて進むが、再検証で衝突として取り消す。
    #[cfg(target_os = "macos")]
    #[test]
    fn io5_case_insensitive_host_rolls_back_under_late_ancestor_variant() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let external = t.0.join("Dir");
        fault::set_hook(fault::Hook::BeforeCreate, move || {
            std::fs::create_dir(external).expect("external dir");
        });
        let err = c.create_file("dir/x").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(
            err.message().starts_with("case-insensitive path collision"),
            "{}",
            err.message()
        );
        assert_eq!(entries(&t.0.join("Dir")), 0);
    }

    /// API で作った `Foo` をホスト側で削除・改名した後は、表記を変えた `foo` を作れる
    /// （衝突索引は作成のたびに実在項目から作るため、消えた項目が残らない。Codex P1
    /// 指摘。3 OS 共通）。
    #[test]
    fn io5_removed_or_renamed_entry_does_not_block_later_create() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("Foo").expect("first");
        std::fs::remove_file(t.0.join("Foo")).expect("remove on the host");
        c.create_file("foo")
            .expect("no stale collision after removal");
        assert_eq!(entries(&t.0), 1);

        c.create_file("Dir/x").expect("nested");
        std::fs::rename(t.0.join("Dir"), t.0.join("Other")).expect("rename on the host");
        c.create_file("dir/x")
            .expect("no stale collision after rename");
        assert!(t.0.join("dir").join("x").is_file());
        assert!(t.0.join("Other").join("x").is_file());
    }

    /// 退避先の報告は、親のパスが長く切り詰められても一意な私有ディレクトリ名を
    /// 欠かさない（Cursor 指摘）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_quarantine_location_keeps_unique_name() {
        let qname = ".fandhe-rollback-1-2-3";
        assert_eq!(
            quarantine_location("", qname),
            "\".fandhe-rollback-1-2-3/entry\""
        );
        let parent = format!("{}/", "d".repeat(300));
        let reported = quarantine_location(&parent, qname);
        assert!(
            reported.starts_with("\".fandhe-rollback-1-2-3/entry\" under \"ddd"),
            "{reported}"
        );
        assert!(reported.ends_with("...\""), "{reported}");
    }

    /// 祖先を新設した後に葉が他者に作られて作成が既存で失敗しても、他者の葉と、それを
    /// 含む祖先は残す（空でない祖先は後始末で取り除かれない。Codex P1 指摘）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_exists_after_new_ancestors_keeps_foreign_leaf() {
        fault::reset();
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let root = t.0.clone();
        fault::set_hook(fault::Hook::BeforeLeaf, move || {
            std::fs::write(root.join("d").join("e").join("f"), b"theirs").expect("foreign");
        });
        let err = c.create_file("d/e/f").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
        assert_eq!(
            std::fs::read(t.0.join("d").join("e").join("f")).expect("kept"),
            b"theirs"
        );
    }

    /// Windows: 祖先が reparse point（symlink またはジャンクション）なら、走査も作成も
    /// それを辿らない（リンク先のエントリを衝突索引へ取り込まず、作成は拒否する。
    /// Codex P1 指摘）。
    #[cfg(windows)]
    #[test]
    fn io5_windows_reparse_ancestor_is_not_scanned() {
        let t = Tmp::new();
        let outside = Tmp::new();
        std::fs::write(outside.0.join("Foo"), b"outside").expect("outside");
        link_dir(&outside.0, &t.0.join("j"));
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("j/foo").err().expect("must reject");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument, "{err:?}");
        assert_eq!(entries(&outside.0), 1);
    }

    /// 構築後にルートのパスを範囲外への symlink へ差し替えても、作成は保持した
    /// ハンドルの元のディレクトリ内に留まる（IO-5・Codex P0 指摘）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_swapped_root_path_does_not_escape() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).expect("root");
        let c = GuestFileCreator::new(root.clone()).expect("creator");
        let moved = t.0.join("moved");
        std::fs::rename(&root, &moved).expect("rename");
        std::os::unix::fs::symlink(&outside.0, &root).expect("symlink");
        c.create_file("sub/f").expect("create");
        assert_eq!(entries(&outside.0), 0);
        assert!(moved.join("sub").join("f").exists());
    }

    /// 共有ルートに大文字小文字違いが元から併存する場合は、走査順に依らず作成を
    /// 中止する（IO-5。ケース区別の FS でのみ作れるため Linux 限定）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_preexisting_colliding_entries_abort_create() {
        let t = Tmp::new();
        std::fs::write(t.0.join("Foo"), b"x").expect("Foo");
        std::fs::write(t.0.join("foo"), b"x").expect("foo");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("unrelated").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 2);
    }

    /// Windows: `link` から `target` へのディレクトリリンクを作る。symlink の作成権限
    /// （`SeCreateSymbolicLinkPrivilege`・開発者モード）が無い環境では、権限不要の
    /// ジャンクション（`mklink /J`）で代替する。どちらも作れなければ失敗させる
    /// （権限不足で試験を黙って素通りさせない）。
    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return;
        }
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("cmd /C mklink /J must be runnable");
        assert!(
            status.success(),
            "neither a directory symlink nor a junction could be created: {status:?}"
        );
    }

    /// Windows: root 自体が symlink（またはジャンクション）でも、構築後に参照先を
    /// 差し替えて範囲外へ書けない（作成は構築時に解決した実体に留まる。IO-5）。
    #[cfg(windows)]
    #[test]
    fn io5_windows_swapped_root_symlink_does_not_escape() {
        let t = Tmp::new();
        let real = t.0.join("real");
        let outside = Tmp::new();
        let link = t.0.join("link");
        std::fs::create_dir(&real).expect("real");
        link_dir(&real, &link);
        let c = GuestFileCreator::new(link.clone()).expect("creator");
        std::fs::remove_dir(&link).expect("remove the link itself");
        link_dir(&outside.0, &link);
        assert!(
            std::fs::canonicalize(&link).expect("canonicalize")
                != std::fs::canonicalize(&real).expect("canonicalize"),
            "the link must now point outside"
        );
        c.create_file("sub/f").expect("create");
        assert_eq!(entries(&outside.0), 0);
        assert!(real.join("sub").join("f").exists());
    }

    #[test]
    fn io5_creator_is_send_sync() {
        fn assert_ss<T: Send + Sync>() {}
        assert_ss::<GuestFileCreator>();
    }
}
