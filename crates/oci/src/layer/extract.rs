//! レイヤー tar のルート配下への安全な展開（TASK-52.3・OCI-1・MS-4・#409）。
//!
//! `layer` の gzip 展開（TASK-52.2。`GzipLayerReader`）が返す tar バイトストリームを、rootfs 相当の
//! ステージング用ディレクトリへ書き出す。レイヤー tar は非信頼入力のため、このモジュールは次を担う。
//!
//! - パス検証と正規化（`..`・絶対パス・NUL・過大な長さ / 深さの拒否）。
//! - 親ディレクトリの解決はルートに閉じ込める（symlink を辿ってもホストの絶対パスへ抜けない。chroot 意味論）。
//! - symlink エントリはリンク先がルートより上へ出る場合に拒否し、hardlink はルート内の通常ファイルに限る。
//! - デバイス・FIFO・sparse は拒否する（既定拒否の最小権限）。
//! - エントリ数と累積展開バイト数に必須の上限を課し、超過したら書き込み前に中断する（DoS 対策）。
//! - 展開先 FS が別表記（大文字小文字・Unicode 正規化）を既存の実体へ解決する名前は、
//!   削除・権限変更・リンク作成の前に `AlreadyExists` で拒否する（IO-5。下記「別表記の衝突」）。
//!
//! tar クレートは解析（エントリ列挙）だけに使い、`unpack` / `unpack_in` は使わない（#408 の承認条件）。
//!
//! # 呼び出し契約
//!
//! - 呼び出し側は先に `verify_blob_digest` を通すこと。
//! - `root` は呼び出し側が排他的に所有する既存の空ディレクトリ（ステージング）で、`root` 自体が
//!   symlink であってはならない。空でなければ `FailedPrecondition` で拒否する（別表記の衝突の判定が
//!   「`root` 配下の実在項目はすべてこの展開が作った」ことに依るため）。別プロセスが同時に `root` を
//!   書き換える競合（TOCTOU）は防げない。
//! - 失敗時は部分的な展開物が残るため、呼び出し側が `root` ごと破棄すること。
//! - 複数レイヤーは `extract_layers` / `extract_layer_blobs` で下位から上位の順に同一 `root` へ重ねる
//!   （TASK-52.4・#410）。空であることの検査は最初のレイヤーの前だけで、別表記の索引・遅延ディレクトリ mode・
//!   4 種の上限（`max_input_bytes` を含む）は全レイヤーで共有・累積する。上位が下位のファイルを上書きする。
//!   whiteout・不透明ディレクトリは下位レイヤーの実体にだけ適用する（TASK-53.3・OCI-2。後述）。
//!   未実装: 上位レイヤーがディレクトリの位置へ
//!   ファイルを置く置換（OCI image-spec は再帰削除して置換するが、ここでは `FailedPrecondition` で拒否する）。
//! - tar の終端後に入力を EOF まで読み捨てる（gzip トレーラの CRC32・ISIZE 検証のため）。読み捨てを含む
//!   入力全体は `ExtractLimits::max_input_bytes` で上限を課す（超過は `ResourceExhausted`）。
//!
//! # 別表記の衝突（IO-5）
//!
//! 大文字小文字非区別の FS（Windows・macOS の既定）では `f` と `F`、正規化非区別の FS（APFS）では NFC と NFD の
//! 綴りが同じ実体を指す。綴りの比較（`PathBuf` の一致）だけで同一性を判断すると、`f` の後の hardlink
//! `F → f` が参照元を削除し、`d/` の後の `D/` が先の遅延 mode を残す。
//!
//! 判定は展開先 FS の実際の挙動で行う。`NameIndex` にこの展開が作った名前（親ディレクトリと正確な綴りの組）を
//! 記録し、`lstat` が成功するのに索引に無い綴りは「FS が別表記を既存の実体へ解決した」とみなして拒否する。
//! `root` が空で始まるため、実在するのに索引に無い名前はそれ以外に生じない。
//!
//! - 綴りの畳み込み（`fandhe-container-io` の `fold_component`）で判定しないのは、大文字小文字を区別する FS では
//!   `f` と `F` が別ファイルで正当なレイヤーだからである（区別する FS では `lstat` が `NotFound` になり通す）。
//! - 実体の同一性（inode / file index）で判定しないのは、Windows の file index が安定版の std から取れず、
//!   hardlink が正当に同じ inode を共有するためである。
//! - 検査はパスの全コンポーネント（symlink を辿った先・hardlink の参照先を含む）に、変更操作の前に適用する。
//! - 索引の件数は `ExtractLimits::max_tracked_paths` で上限を課す（超過は `ResourceExhausted`）。
//! - 判定は FS の解決結果だけに依るため、Windows の 8.3 短縮名のような他の別名も同じ経路で拒否されるはずだが、
//!   試験で確かめているのは大文字小文字と NFC / NFD だけである。
//!
//! # whiteout（OCI-2・TASK-53.3）
//!
//! `extract_one_layer` は最終コンポーネントが `.wh.<name>` のエントリを `Extractor::remove_whiteout_target`、
//! `.wh..wh..opq` を `Extractor::clear_opaque_dir` へ渡し、マーカー自体は rootfs へ展開しない（本体は読み捨て、
//! `ExtractedLayer::bytes` に数えない）。image-spec は whiteout を下位レイヤーのリソースにのみ適用すると定めるため、
//! 現在のレイヤーが作成・上書き・経路として通過したエントリの ID を `NameIndex` に世代として持ち、
//! マーカーの前後どちらにあっても同一レイヤーのエントリは消さない（tar 内の並び順に結果が依存しない）。
//! 世代はレイヤーの展開完了で閉じる。
//!
//! - マーカー名の通常ファイル以外（ディレクトリ・symlink・hardlink 等）と、未知の `.wh..wh.` 予約名
//!   （AUFS 由来の `.wh..wh.plnk` 等）は `InvalidArgument` で拒否する（fail-closed）。
//! - whiteout の対象や不透明ディレクトリの親の別表記は `AlreadyExists`（IO-5）。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - uid / gid の写像と `chown`（SEC-5）。展開物は実行ユーザー所有になる。
//! - 通常ファイルの setuid / setgid / sticky の保持。展開物が実行ユーザー所有のまま setuid / setgid を残すと、
//!   ホスト root がほかのユーザーも辿れるステージングへ展開したときに、レイヤー由来の実行ファイルが root 所有の
//!   setuid になり、ホスト上の権限昇格に使える。所有者の写像（SEC-5）が入るまで、通常ファイルの mode は
//!   下位 9 ビット（`FILE_MODE_MASK`）だけを適用し、落とした件数を
//!   `ExtractedLayer::files_with_stripped_special_bits` に返す（黙って落とさない）。ディレクトリの mode は
//!   sticky（`/tmp` の 1777）・setgid を含めてそのまま適用する。
//! - ディレクトリ fd 起点（`openat2` の `RESOLVE_IN_ROOT` 等）の解決。libc 系の依存承認後の後続課題。
//! - 綴りの畳み込みによる名前衝突の検出（展開先 FS が区別する別表記は衝突として扱わない。IO-5）。HFS+ のように
//!   保存時に名前を書き換える FS は前提外。
//! - Windows ホストでの symlink エントリ（`Unimplemented` で拒否する）。

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};

use tar::{Archive, EntryType};

use super::{DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, oci_error_from_layer_io, open_gzip_layer};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};

/// エントリ数上限の参考既定値。API は上限を必須引数にしており、上限なしの経路は提供しない。
pub const DEFAULT_MAX_LAYER_ENTRIES: u64 = 1_000_000;

/// 累積展開バイト数上限の参考既定値（gzip 展開後サイズの参考既定値と同値）。
pub const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;

/// 索引に載せる名前の数の上限の参考既定値（`ExtractLimits::max_tracked_paths`）。
///
/// 親ディレクトリのエントリを省いた tar が暗黙に作るディレクトリの分を見込み、エントリ数の既定の 2 倍とする。
pub const DEFAULT_MAX_TRACKED_PATHS: u64 = 2 * DEFAULT_MAX_LAYER_ENTRIES;

/// 重ねられるレイヤー数の上限（空レイヤーの無限供給による結果 Vec の無制限増加を防ぐ。超過は `ResourceExhausted`）。
const MAX_LAYERS: usize = 1024;
/// パス全体の最大バイト数（Linux の `PATH_MAX`）。
const MAX_PATH_BYTES: usize = 4096;
/// 1 コンポーネントの最大バイト数（`NAME_MAX`）。
const MAX_COMPONENT_BYTES: usize = 255;
/// 1 パスのコンポーネント数の上限。
const MAX_COMPONENTS: usize = 256;
/// symlink の追従回数の上限（`ELOOP` 相当）。
const MAX_SYMLINK_FOLLOWS: u32 = 40;
/// 複写バッファ長（メモリ使用量を入力サイズに依存させない）。
const COPY_BUF_LEN: usize = 64 * 1024;

/// 展開の上限（必須。将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractLimits {
    /// 受け付けるエントリ数の上限（超過は `ResourceExhausted`）。
    pub max_entries: u64,
    /// 累積展開バイト数の上限（ヘッダ宣言サイズで書き込み前に検査。超過は `ResourceExhausted`）。
    pub max_total_bytes: u64,
    /// 入力 tar ストリーム全体（ヘッダ・パディング・終端後の読み捨てを含む）の読み取り上限バイト数
    /// （超過は `ResourceExhausted`）。`max_total_bytes` は通常ファイル本体しか数えないため別に必須とする。
    pub max_input_bytes: u64,
    /// 展開が作る名前（エントリと、暗黙に作る親ディレクトリ）の数の上限（超過は作成前に `ResourceExhausted`）。
    ///
    /// 別表記の衝突検出（IO-5）の索引 `NameIndex` の件数上限で、索引のメモリ使用量を
    /// `max_tracked_paths ×（1 コンポーネントの最大 255 バイト + 固定長）` に抑える。`max_entries` は tar の
    /// エントリしか数えず、1 エントリが多数の親ディレクトリを暗黙に作れるため別に必須とする。
    pub max_tracked_paths: u64,
}

impl ExtractLimits {
    /// 上限を指定して作る。
    pub fn new(
        max_entries: u64,
        max_total_bytes: u64,
        max_input_bytes: u64,
        max_tracked_paths: u64,
    ) -> Self {
        Self {
            max_entries,
            max_total_bytes,
            max_input_bytes,
            max_tracked_paths,
        }
    }
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_LAYER_ENTRIES,
            DEFAULT_MAX_EXTRACTED_BYTES,
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            DEFAULT_MAX_TRACKED_PATHS,
        )
    }
}

/// 展開に成功したレイヤーの結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedLayer {
    /// 処理したエントリ数（PAX グローバルヘッダを除く）。
    pub entries: u64,
    /// 書き出したファイル本体の累積バイト数。
    pub bytes: u64,
    /// tar の mode に setuid / setgid / sticky が付いていて、それを落として展開した通常ファイルのエントリ数。
    ///
    /// 0 でなければ、展開結果の mode はレイヤーの記述と一致しない（所有者の写像〔SEC-5〕が入るまでの措置。
    /// モジュール冒頭の「未実装」を参照）。
    pub files_with_stripped_special_bits: u64,
}

/// 計装なしの `extract_tar_with`（`NoopOciOpRecorder`）。
pub fn extract_tar<R: Read>(
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    extract_tar_with(&NoopOciOpRecorder, src, root, limits)
}

/// 展開全体を `OciOpKind::ExtractLayer` として `recorder` へ記録する（REPAIR-4）。
///
/// `src` は gzip 展開済みの tar バイトストリーム（通常は `GzipLayerReader`）。契約はモジュール冒頭を参照。
/// 複数レイヤーを重ねるときは `extract_layers_with` を使う（これは要素 1 つのスタックと同じ）。
pub fn extract_tar_with<R: Read>(
    recorder: &dyn OciOpRecorder,
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    single(extract_stack(
        recorder,
        [src],
        Ok,
        root,
        limits,
        host_lstat,
    )?)
}

/// 圧縮レイヤー blob（digest 検証済み）を開き、gzip 展開しながら `root` へ展開する便宜関数。
///
/// `max_uncompressed_bytes` は gzip 展開後（tar 全体）の上限で、`limits.max_total_bytes` とは別に効く。
pub fn extract_layer_blob(
    blob_path: &Path,
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    extract_layer_blob_with(
        &NoopOciOpRecorder,
        blob_path,
        root,
        max_uncompressed_bytes,
        limits,
    )
}

/// `extract_layer_blob` の計装版。blob を開く処理から展開完了までを 1 回の
/// `OciOpKind::ExtractLayer` として `recorder` へ記録する（open 失敗も記録対象。REPAIR-4）。
pub fn extract_layer_blob_with(
    recorder: &dyn OciOpRecorder,
    blob_path: &Path,
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    single(extract_stack(
        recorder,
        [blob_path],
        |p| open_gzip_layer(p, max_uncompressed_bytes),
        root,
        limits,
        host_lstat,
    )?)
}

/// 計装なしの `extract_layers_with`（`NoopOciOpRecorder`）。
pub fn extract_layers<R: Read>(
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_layers_with(&NoopOciOpRecorder, layers, root, limits)
}

/// 複数レイヤーの tar を下位から上位の順に同一 `root` へ重ねて展開する（TASK-52.4・OCI-1・#410）。
///
/// `layers` は下位（ベース）から上位の順の tar バイトストリーム。同じパスは後のレイヤーが勝つ。
/// 戻り値はレイヤーごとの結果（入力と同じ順）。`root` が空であることは最初のレイヤーの前に 1 回だけ検査し、
/// 別表記の索引（IO-5）・遅延ディレクトリ mode・上限は全レイヤーで共有する（上限は全体で累積）。
/// 各レイヤーを `OciOpKind::ExtractLayer` として 1 回ずつ `recorder` へ記録する（REPAIR-4）。
/// whiteout（`.wh.*`・`.wh..wh..opq`）は下位レイヤーの実体にだけ適用する（TASK-53.3）。空の `layers` は `InvalidArgument`。契約はモジュール冒頭を参照。
pub fn extract_layers_with<R: Read>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_stack(recorder, layers, Ok, root, limits, host_lstat)
}

/// 計装なしの `extract_layer_blobs_with`（`NoopOciOpRecorder`）。
pub fn extract_layer_blobs(
    blob_paths: &[&Path],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_layer_blobs_with(
        &NoopOciOpRecorder,
        blob_paths,
        root,
        max_uncompressed_bytes,
        limits,
    )
}

/// 圧縮レイヤー blob（すべて digest 検証済み。下位から上位の順）を重ねて展開する（TASK-52.4・OCI-1・#410）。
///
/// `max_uncompressed_bytes` は各レイヤーの gzip 展開後の上限。その他は `extract_layers_with` と同じ。
pub fn extract_layer_blobs_with(
    recorder: &dyn OciOpRecorder,
    blob_paths: &[&Path],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_stack(
        recorder,
        blob_paths.iter().copied(),
        |p| open_gzip_layer(p, max_uncompressed_bytes),
        root,
        limits,
        host_lstat,
    )
}

/// 展開先 FS の名前解決（`lstat`）。既定は `fs::symlink_metadata`。
///
/// 大文字小文字を区別する FS しかない CI（Linux）でも「別表記が同じ実体へ解決される」経路を照合できるよう、
/// テストから差し替える注入点にしている。拒否は変更操作より前に行うため、差し替えるのは解決だけでよい。
type Lstat = fn(&Path) -> std::io::Result<fs::Metadata>;

/// 既定の `Lstat`（ホストの FS をそのまま引く）。
fn host_lstat(path: &Path) -> std::io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

/// `NameIndex` での `root` 自身の ID。
const ROOT_ID: u64 = 0;

/// この展開が作った名前の索引（IO-5 の別表記の衝突検出用）。
///
/// キーは「親ディレクトリの ID と、作成時の正確な綴り」。物理パス全体ではなく親の ID で持つため、1 件あたりの
/// メモリは 1 コンポーネントの長さ（`MAX_COMPONENT_BYTES` 以下）と固定長に収まる。件数は `limit` で頭打ちにする。
/// ディレクトリは展開中に削除しない（`clear_existing_non_dir` が拒否する）ため、ID は展開の間ずっと同じ
/// ディレクトリを指す。
struct NameIndex {
    /// 親 ID から（子の綴り, 子の ID）。親ごとに持つため、`forget_*` は削除した部分木の大きさに比例する
    /// （悪意あるレイヤーの大量 whiteout で全登録の走査が繰り返されないため。DoS 対策）。
    ids: HashMap<u64, HashMap<OsString, u64>>,
    /// 登録の総数（`limit` の判定用）。
    count: u64,
    limit: u64,
    /// 次に採番する ID。`forget_tree` で件数が減っても過去の ID を再利用しない（旧ディレクトリの登録と
    /// 混ざって別表記の判定を誤らないため）。
    next_id: u64,
    /// 現在展開中のレイヤーが作成・上書き・経路として通過したエントリの ID（TASK-53.3・OCI-2）。
    /// image-spec は whiteout・不透明ディレクトリを下位レイヤーのリソースにのみ適用すると定めるため、
    /// 同一レイヤーで作った実体は whiteout の対象にしない。レイヤーの展開完了で空にする。
    touched: HashSet<u64>,
    /// `touched` のうち、現在のレイヤーが明示のディレクトリエントリで定義したものの ID。経路として通過しただけの
    /// 下位由来ディレクトリの mode は、whiteout・不透明の適用順に依らず破棄する判定に使う（OCI-2）。
    defined: HashSet<u64>,
    /// 現在のレイヤーで `prune_lower` を完了したディレクトリの ID。prune 後のそのディレクトリには下位由来の
    /// 実体が残らないため、同じ世代での再走査を省く（不透明マーカーを大量に並べて同じ部分木を毎回全走査させる
    /// O(N×M) の DoS を防ぐ。OCI-2）。
    pruned: HashSet<u64>,
    /// 現在のレイヤーが親パスの解決で通過した、下位由来の symlink の ID。同じレイヤーがその symlink を
    /// whiteout すると、エントリの並び順で rootfs が変わるため拒否する（OCI-2）。
    traversed_links: HashSet<u64>,
    /// 現在のレイヤーの whiteout で消した下位由来の symlink の（親 ID, 綴り）。その名前を親として暗黙作成する
    /// エントリは、並び順で結果が変わるため拒否する（OCI-2）。
    link_tombstones: HashSet<(u64, OsString)>,
}

impl NameIndex {
    fn new(limit: u64) -> Self {
        Self {
            ids: HashMap::new(),
            count: 0,
            limit,
            next_id: ROOT_ID + 1,
            touched: HashSet::new(),
            defined: HashSet::new(),
            pruned: HashSet::new(),
            traversed_links: HashSet::new(),
            link_tombstones: HashSet::new(),
        }
    }

    /// 現在のレイヤーが明示のディレクトリエントリで定義したものとして記録する（`touch` を含む）。
    fn define(&mut self, id: u64) {
        self.touched.insert(id);
        self.defined.insert(id);
    }

    fn is_defined(&self, id: u64) -> bool {
        self.defined.contains(&id)
    }

    /// 現在のレイヤーが触ったエントリとして記録する。
    fn touch(&mut self, id: u64) {
        self.touched.insert(id);
    }

    fn is_touched(&self, id: u64) -> bool {
        self.touched.contains(&id)
    }

    /// レイヤーの区切りで世代（`touched`）を空にする。
    fn clear_touched(&mut self) {
        self.touched.clear();
        self.defined.clear();
        self.pruned.clear();
        self.traversed_links.clear();
        self.link_tombstones.clear();
    }

    /// whiteout で削除した `parent` 直下の `name` と、その配下の登録をすべて索引から外す（IO-5）。
    /// 外さないと、削除済みの綴りを現在の実体の綴りとして受理してしまう。ID は再利用しない。
    fn forget_tree(&mut self, parent: u64, name: &OsStr) {
        let Some(root_id) = self.ids.get_mut(&parent).and_then(|m| m.remove(name)) else {
            return;
        };
        self.count = self.count.saturating_sub(1);
        self.forget_descendants(vec![root_id]);
    }

    /// `work` の各 ID を親とする登録を再帰的に外す。
    fn forget_descendants(&mut self, mut work: Vec<u64>) {
        while let Some(id) = work.pop() {
            if let Some(children) = self.ids.remove(&id) {
                self.count = self
                    .count
                    .saturating_sub(u64::try_from(children.len()).unwrap_or(u64::MAX));
                work.extend(children.into_values());
            }
        }
    }

    /// `parent` 直下に `name` をこの綴りで作っていれば、その ID を返す。
    fn get(&self, parent: u64, name: &OsStr) -> Option<u64> {
        self.ids.get(&parent).and_then(|m| m.get(name)).copied()
    }

    /// `parent` 直下の `name` を索引へ載せて ID を返し、現在のレイヤーが触ったものとして記録する
    /// （登録済みなら同じ ID）。作成操作の前に呼び、上限超過なら何も作らせずに `ResourceExhausted` を返す。
    fn insert(&mut self, parent: u64, name: &OsStr) -> Result<u64, OciError> {
        if let Some(id) = self.get(parent, name) {
            self.touched.insert(id);
            return Ok(id);
        }
        // ROOT_ID（0）と重ならないよう 1 始まりで採番する。
        let id = self.next_id;
        if self.count >= self.limit {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "layer exceeds the tracked path limit",
            ));
        }
        self.next_id = id.checked_add(1).ok_or_else(|| {
            err(
                OciErrorCode::ResourceExhausted,
                "layer exceeds the tracked path limit",
            )
        })?;
        self.count += 1;
        self.ids
            .entry(parent)
            .or_default()
            .insert(name.to_os_string(), id);
        self.touched.insert(id);
        Ok(id)
    }
}

/// `resolve_dir` が解決したディレクトリ（`root` からの物理コンポーネント列と `NameIndex` の ID）。
struct ResolvedDir {
    comps: Vec<OsString>,
    id: u64,
}

/// 親ディレクトリの解決・種別ごとの処理を束ねる状態。
struct Extractor<'a> {
    root: &'a Path,
    limits: ExtractLimits,
    entries: u64,
    bytes: u64,
    /// setuid / setgid / sticky を落として展開した通常ファイルのエントリ数。
    stripped_special: u64,
    /// 所有者の rwx が欠けるディレクトリの mode。子の作成を妨げないよう全エントリ処理後に適用する。
    /// キーは物理パス。別表記は `probe` が先に拒否するため、同じディレクトリのキーは 1 つに定まる。
    /// `BTreeMap` は部分木（あるパス配下）の範囲削除を件数全体の走査なしで行うため（`drop_deferred_subtree`）。
    deferred_dirs: BTreeMap<PathBuf, u32>,
    /// この展開が作った名前（IO-5）。
    names: NameIndex,
    lstat: Lstat,
}

pub(crate) fn err(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

fn escapes() -> OciError {
    err(
        OciErrorCode::PermissionDenied,
        "entry path escapes the extraction root",
    )
}

/// 展開先 FS が別表記を既存の実体へ解決したときのエラー（IO-5。パスは載せない）。
fn spelling_collision() -> OciError {
    err(
        OciErrorCode::AlreadyExists,
        "entry name resolves to an existing entry with a different spelling \
         (case or Unicode normalization) on the destination filesystem",
    )
}

/// tar 解析 / 読み取りの `io::Error` を構造化エラーへ写す。分類不能なものは tar 構文違反として `DataLoss`。
fn map_stream_err(e: std::io::Error) -> OciError {
    if let Some(v) = e.get_ref().and_then(|i| i.downcast_ref::<GuardViolation>()) {
        return err(v.code, v.msg);
    }
    let m = oci_error_from_layer_io(e);
    if m.code() == OciErrorCode::Internal {
        return err(OciErrorCode::DataLoss, "layer tar stream is malformed");
    }
    m
}

/// 拡張ヘッダ（GNU long name / long link・PAX）本体 1 件あたりの上限バイト数。
///
/// `max_total_bytes` は通常ファイル本体のみを制限するため、メタデータには独立した有限の上限を課す（OCI-1）。
/// パスは `MAX_PATH_BYTES` が上限であり、これを超える拡張ヘッダは正当なレイヤーに現れない。
const MAX_META_BYTES: u64 = 1024 * 1024;

/// `TarGuard` が返す検査違反（`io::Error` の内包値。`map_stream_err` が構造化エラーへ戻す）。
#[derive(Debug)]
struct GuardViolation {
    code: OciErrorCode,
    msg: &'static str,
}

impl std::fmt::Display for GuardViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for GuardViolation {}

fn guard_error(code: OciErrorCode, msg: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, GuardViolation { code, msg })
}

/// 読み取った総バイト数を数え、`limit` を超えたら `ResourceExhausted` で中断する読み取りアダプタ。
///
/// tar 解析中と終端後の読み捨ての両方を同じ計数で覆い、終端後に巨大データを付加された入力でも
/// 無制限に読み続けないようにする（OCI-1）。ちょうど `limit` バイトまでは許容する。
struct LimitedReader<R> {
    inner: R,
    read: u64,
    limit: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // 超過検出のため、残りより 1 バイト多く読めるようにする。
        let room = self.limit.saturating_sub(self.read).saturating_add(1);
        let cap = usize::try_from(room).unwrap_or(usize::MAX).min(buf.len());
        let Some(dst) = buf.get_mut(..cap) else {
            return Ok(0);
        };
        let n = self.inner.read(dst)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.limit {
            return Err(guard_error(
                OciErrorCode::ResourceExhausted,
                "layer tar stream exceeds the input size limit",
            ));
        }
        Ok(n)
    }
}

/// `tar` クレートが拡張ヘッダ本体をメモリへ確保する前に、宣言サイズを検査する読み取りアダプタ。
///
/// 512 バイトのヘッダブロック境界で自前に追跡し（データはそのまま通す）、次を拒否する。
/// - GNU long name / long link / PAX の宣言サイズが `MAX_META_BYTES` を超えるもの（確保前に中断する）。
/// - GNU sparse（`S`）: 拡張ヘッダブロックで追跡がずれるうえ、展開でも拒否する種別のため。
/// - PAX の `size` 上書き: ヘッダのサイズと食い違い、追跡をすり抜けて拡張ヘッダを隠せるため。
/// - PAX 形式の GNU sparse（`GNU.sparse.*` キー。typeflag は通常ファイルのまま）: `tar` crate（0.4.46）は
///   これらのキーを解釈せず、穴を詰めた保存データをそのまま通常ファイルとして返す。論理サイズへ膨らむことは
///   ないが、内容が元のファイルと食い違ったまま成功してしまうため、他の sparse と同じく拒否する。
struct TarGuard<R> {
    inner: R,
    header: [u8; 512],
    filled: usize,
    /// 現在のエントリの本体（拡張ヘッダなら内容）の残りバイト数。
    payload_left: u64,
    /// 本体の後ろの 512 バイト境界パディングの残りバイト数。
    pad_left: u64,
    /// PAX ヘッダ本体の収集先（`size` 上書きの検出用。`MAX_META_BYTES` 以下）。
    pax: Option<Vec<u8>>,
}

impl<R> TarGuard<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 512],
            filled: 0,
            payload_left: 0,
            pad_left: 0,
            pax: None,
        }
    }

    fn on_header(&mut self) -> std::io::Result<()> {
        let h = tar::Header::from_byte_slice(&self.header);
        let ty = h.entry_type();
        // サイズが読めないヘッダは tar 側が構文違反として拒否する。
        let size = h.size().unwrap_or(0);
        if ty == EntryType::GNUSparse {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "sparse entries are not supported",
            ));
        }
        // 旧 GNU sparse は typeflag が通常のまま、isextended（offset 482）で sparse map ブロックが後続し、
        // 512 バイト境界の追跡がずれる。GNU magic のヘッダで isextended が立つものは拒否する。
        if h.as_gnu().is_some_and(tar::GnuHeader::is_extended) {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "old GNU sparse entries are not supported",
            ));
        }
        let is_pax = matches!(ty, EntryType::XHeader | EntryType::XGlobalHeader);
        let is_meta = is_pax || matches!(ty, EntryType::GNULongName | EntryType::GNULongLink);
        if is_meta && size > MAX_META_BYTES {
            return Err(guard_error(
                OciErrorCode::ResourceExhausted,
                "extended header exceeds the metadata size limit",
            ));
        }
        self.payload_left = size;
        self.pad_left = size.div_ceil(512).saturating_mul(512) - size;
        self.pax = is_pax.then(Vec::new);
        self.filled = 0;
        Ok(())
    }

    fn after_payload(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.pax.take() {
            pax_reject_unsupported_records(&p)?;
        }
        Ok(())
    }
}

/// PAX 拡張ヘッダ本体を `tar` crate と同じ規則（先に改行で分割し、各行を `<len> <key>=<value>`
/// として解釈。`len` は行 + 改行の長さと一致）で解析し、キーが正確に `size` の行、またはキーが
/// `GNU.sparse.` で始まる行（PAX 形式の GNU sparse 0.0 / 0.1 / 1.0）があれば拒否する（OCI-1）。
/// 長さ欄が後続行にまたがるレコードは `tar` crate も別行として解釈するため、同じ分割で検査して
/// 埋め込み `size` の見逃しを防ぐ。`path` 等の値に ` size=` が含まれるだけの正常な tar は通す。
/// 構文違反（長さ不一致・`=` 欠落・末尾改行欠落・途中の空行）は拒否する。
fn pax_reject_unsupported_records(body: &[u8]) -> std::io::Result<()> {
    let malformed = || {
        guard_error(
            OciErrorCode::InvalidArgument,
            "malformed pax extended header record",
        )
    };
    let mut lines = body.split(|b| *b == b'\n');
    // 本体は改行で終わる必要がある。最後の要素は空でなければ末尾改行欠落。
    let last = lines.next_back();
    if !matches!(last, Some([])) && !body.is_empty() {
        return Err(malformed());
    }
    for line in lines {
        let sp = line.iter().position(|b| *b == b' ').ok_or_else(malformed)?;
        let len: usize = std::str::from_utf8(line.get(..sp).ok_or_else(malformed)?)
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or_else(malformed)?;
        if line.len().checked_add(1) != Some(len) {
            return Err(malformed());
        }
        let kv = line.get(sp.saturating_add(1)..).ok_or_else(malformed)?;
        let eq = kv.iter().position(|b| *b == b'=').ok_or_else(malformed)?;
        let key = kv.get(..eq).ok_or_else(malformed)?;
        if key == b"size" {
            return Err(guard_error(
                OciErrorCode::InvalidArgument,
                "pax size override is not supported",
            ));
        }
        if key.starts_with(b"GNU.sparse.") {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "sparse entries are not supported",
            ));
        }
    }
    Ok(())
}

/// 添字の境界違反を構造化エラーで返す（外部入力経路では添字アクセスを使わない）。
fn oob() -> std::io::Error {
    guard_error(OciErrorCode::Internal, "tar guard buffer bounds violated")
}

impl<R: Read> Read for TarGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.payload_left > 0 {
            let n = usize::try_from(self.payload_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
            if let (Some(p), Some(got)) = (self.pax.as_mut(), buf.get(..r)) {
                p.extend_from_slice(got);
            }
            self.payload_left -= r as u64;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
            return Ok(r);
        }
        if self.pad_left > 0 {
            let n = usize::try_from(self.pad_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
            self.pad_left -= r as u64;
            return Ok(r);
        }
        let n = (512 - self.filled).min(buf.len());
        let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
        let end = self.filled.checked_add(r).ok_or_else(oob)?;
        let dst = self.header.get_mut(self.filled..end).ok_or_else(oob)?;
        dst.copy_from_slice(buf.get(..r).ok_or_else(oob)?);
        self.filled = end;
        if self.filled == 512 {
            self.on_header()?;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
        }
        Ok(r)
    }
}
/// ファイルシステム操作の `io::Error` を写す（パス・OS メッセージは載せない）。
pub(crate) fn map_fs_err(e: &std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::PermissionDenied => err(
            OciErrorCode::PermissionDenied,
            "failed to write the extraction target",
        ),
        ErrorKind::NotFound => err(OciErrorCode::NotFound, "extraction path not found"),
        _ => err(
            OciErrorCode::Internal,
            "failed to write the extraction target",
        ),
    }
}

#[cfg(unix)]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(OsString::from_vec(b.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    let s = std::str::from_utf8(b).map_err(|_| {
        err(
            OciErrorCode::InvalidArgument,
            "entry path is not valid UTF-8",
        )
    })?;
    if s.contains(['\\', ':']) {
        return Err(escapes());
    }
    Ok(OsString::from(s))
}

/// Windows の予約デバイス名（拡張子付きの形を含む。大文字小文字を区別しない）か。
fn is_windows_reserved_name(c: &[u8]) -> bool {
    let stem = c.split(|b| *b == b'.').next().unwrap_or(c);
    let stem = stem.trim_ascii_end();
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || matches!(upper.as_slice(), [b'C', b'O', b'M', b'1'..=b'9'])
        || matches!(upper.as_slice(), [b'L', b'P', b'T', b'1'..=b'9'])
}

/// コンポーネントが Win32 の名前正規化で展開 root を脱出または別物になりうるかを判定する。
///
/// 末尾の `.` と空白を除いた結果が `.` / `..` になるもの（`".. "`・`"..."` 等）は全 OS で拒否する。
/// `windows_names` が真（Windows ホスト）では、末尾が `.` / 空白のもの（Win32 が除去して別名になる）と
/// 予約デバイス名（`CON`・`NUL`・`COM1`〜`COM9`・`LPT1`〜`LPT9` 等）も拒否する（OCI-1）。
fn component_is_unsafe(c: &[u8], windows_names: bool) -> bool {
    let trimmed = c.trim_ascii_end();
    let trimmed = trimmed
        .iter()
        .rposition(|b| *b != b'.')
        .map_or(&[][..], |i| trimmed.get(..=i).unwrap_or(&[]));
    let stripped_is_dots = trimmed.is_empty() && c.first() == Some(&b'.');
    let trailing = matches!(c.last(), Some(b'.' | b' '));
    stripped_is_dots && c != b"." || windows_names && (trailing || is_windows_reserved_name(c))
}

/// アーカイブ内のパスを、`.` を除いたコンポーネント列へ正規化する（`..`・絶対パス・NUL・過大な長さを拒否）。
fn normalize_entry_path(raw: &[u8]) -> Result<Vec<OsString>, OciError> {
    normalize_entry_path_for(raw, cfg!(windows))
}

/// `normalize_entry_path` の本体。`windows_names` でホスト依存の名前規則を切り替える（テストで両方を検証する）。
fn normalize_entry_path_for(raw: &[u8], windows_names: bool) -> Result<Vec<OsString>, OciError> {
    if raw.is_empty() {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
    }
    if raw.len() > MAX_PATH_BYTES || raw.contains(&0) {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is invalid"));
    }
    if raw.first() == Some(&b'/') {
        return Err(escapes());
    }
    let mut out = Vec::new();
    for c in raw.split(|b| *b == b'/') {
        if c.is_empty() || c == b"." {
            continue;
        }
        if c == b".." || component_is_unsafe(c, windows_names) {
            return Err(escapes());
        }
        if c.len() > MAX_COMPONENT_BYTES || out.len() >= MAX_COMPONENTS {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "entry path is too long or too deep",
            ));
        }
        out.push(bytes_to_os(c)?);
    }
    Ok(out)
}

/// tar に親ディレクトリのエントリが無い場合に暗黙作成するディレクトリの既定 mode。
const IMPLICIT_DIR_MODE: u32 = 0o755;

/// ルートと解決済みコンポーネントから物理パスを作る。
fn join_resolved(root: &Path, resolved: &[OsString], name: &OsString) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(resolved);
    p.push(name);
    p
}

/// 最終コンポーネントを取り出す。コンポーネントが空（ルート自身）なら `None`。
fn split_last(mut comps: Vec<OsString>) -> Option<(Vec<OsString>, OsString)> {
    let last = comps.pop()?;
    Some((comps, last))
}

#[cfg(unix)]
fn mode_perms(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    fs::Permissions::from_mode(mode & 0o7777)
}

#[cfg(unix)]
fn apply_file_mode(f: &fs::File, mode: u32) -> Result<(), OciError> {
    f.set_permissions(mode_perms(mode))
        .map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn apply_file_mode(_f: &fs::File, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

#[cfg(unix)]
fn apply_dir_mode(path: &Path, mode: u32) -> Result<(), OciError> {
    fs::set_permissions(path, mode_perms(mode)).map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn apply_dir_mode(_path: &Path, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

/// 通常ファイルへ適用する mode のマスク（下位 9 ビット）。
///
/// setuid / setgid / sticky は適用しない。展開物は実行ユーザー所有になるため、非信頼のレイヤーが指定した
/// setuid / setgid を残すと、ホスト上で実行ユーザー（root なら root）の権限で動く実行ファイルを作れてしまう
/// （SEC-5 の所有者写像が入るまでの措置）。
const FILE_MODE_MASK: u32 = 0o777;

/// 所有者の rwx がそろわない mode か（子の作成を妨げうるため適用を遅延する）。
fn needs_deferral(mode: u32) -> bool {
    mode & 0o700 != 0o700
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), OciError> {
    std::os::unix::fs::symlink(target, link).map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> Result<(), OciError> {
    Err(err(
        OciErrorCode::Unimplemented,
        "symlink entries are not supported on this host",
    ))
}

impl Extractor<'_> {
    /// `dir`（ID は `dir_id`）直下の `name`（物理パスは `path`）を `lstat` する。無ければ `None`、
    /// あればメタデータと `NameIndex` の ID を返す。
    ///
    /// 実在するのにこの展開がその綴りで作っていない名前は、展開先 FS が別表記（大文字小文字・Unicode
    /// 正規化など）を既存の実体へ解決したものである（`root` は空で始まる）。削除・権限変更・リンク作成より
    /// 前にここで `AlreadyExists` として拒否する（IO-5）。実在する名前を見る箇所はすべてここを通す。
    fn probe(
        &self,
        dir_id: u64,
        name: &OsStr,
        path: &Path,
    ) -> Result<Option<(fs::Metadata, u64)>, OciError> {
        match (self.lstat)(path) {
            Ok(m) => match self.names.get(dir_id, name) {
                Some(id) => Ok(Some((m, id))),
                None => Err(spelling_collision()),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(map_fs_err(&e)),
        }
    }

    /// `rel` の各コンポーネントを 1 つずつ `probe`（`lstat`）で確認しながら、ルート内の物理位置を解決する。
    ///
    /// symlink は読み取ってルート基準で辿る（絶対ターゲットはルートへ戻し、`..` はルートで止める）ため、
    /// ホストの任意パスへは出られない。`create` が真なら存在しないディレクトリを作る。
    /// 戻り値はルートからの物理コンポーネント列と、そのディレクトリの `NameIndex` の ID。
    fn resolve_dir(&mut self, rel: &[OsString], create: bool) -> Result<ResolvedDir, OciError> {
        let mut resolved: Vec<OsString> = Vec::new();
        // `resolved` の各コンポーネントの ID（同じ長さを保つ）。
        let mut ids: Vec<u64> = Vec::new();
        let mut queue: VecDeque<OsString> = rel.iter().cloned().collect();
        let mut follows = 0u32;
        while let Some(c) = queue.pop_front() {
            if c == "." {
                continue;
            }
            if c == ".." {
                resolved.pop();
                ids.pop();
                continue;
            }
            let parent_id = ids.last().copied().unwrap_or(ROOT_ID);
            let cand = join_resolved(self.root, &resolved, &c);
            match self.probe(parent_id, &c, &cand)? {
                Some((m, id)) if m.is_dir() => {
                    // 書き込み系の解決は、現在のレイヤーが通過したディレクトリとして記録する（TASK-53.3）。
                    // 親の解決だけの whiteout・hardlink 参照先（`create = false`）は記録しない。
                    if create {
                        self.names.touch(id);
                    }
                    resolved.push(c);
                    ids.push(id);
                }
                Some((m, id)) if m.file_type().is_symlink() => {
                    if create && !self.names.is_touched(id) {
                        self.names.traversed_links.insert(id);
                    }
                    follows += 1;
                    if follows > MAX_SYMLINK_FOLLOWS {
                        return Err(err(
                            OciErrorCode::InvalidArgument,
                            "too many symbolic links while resolving an entry path",
                        ));
                    }
                    let target = fs::read_link(&cand).map_err(|e| map_fs_err(&e))?;
                    let mut pending = Vec::new();
                    for comp in target.components() {
                        match comp {
                            Component::RootDir | Component::Prefix(_) => {
                                resolved.clear();
                                ids.clear();
                                pending.clear();
                            }
                            Component::CurDir => {}
                            Component::ParentDir => pending.push(OsString::from("..")),
                            Component::Normal(n) => pending.push(n.to_os_string()),
                        }
                    }
                    for p in pending.into_iter().rev() {
                        queue.push_front(p);
                    }
                }
                Some(_) => {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "a parent path component is not a directory",
                    ));
                }
                None => {
                    if !create {
                        return Err(err(OciErrorCode::NotFound, "extraction path not found"));
                    }
                    if self.names.link_tombstones.contains(&(parent_id, c.clone())) {
                        return Err(err(
                            OciErrorCode::InvalidArgument,
                            "entry path depends on the order of a symlink whiteout in the same layer",
                        ));
                    }
                    let id = self.names.insert(parent_id, &c)?;
                    fs::create_dir(&cand).map_err(|e| map_fs_err(&e))?;
                    // 暗黙の親ディレクトリはホストの umask に依存させず既定 0755 にする。
                    // 明示的なディレクトリエントリがあれば `make_dir` がその mode で上書きする（OCI-1）。
                    apply_dir_mode(&cand, IMPLICIT_DIR_MODE)?;
                    resolved.push(c);
                    ids.push(id);
                }
            }
        }
        Ok(ResolvedDir {
            id: ids.last().copied().unwrap_or(ROOT_ID),
            comps: resolved,
        })
    }

    /// 既存の非ディレクトリを除去する。ディレクトリなら `FailedPrecondition`。存在しなければ何もしない。
    /// 別表記で既存の実体へ解決される名前は、除去の前に `probe` が拒否する（IO-5）。
    fn clear_existing_non_dir(
        &self,
        dir_id: u64,
        name: &OsStr,
        path: &Path,
    ) -> Result<(), OciError> {
        match self.probe(dir_id, name, path)? {
            Some((m, _)) if m.is_dir() => Err(err(
                OciErrorCode::FailedPrecondition,
                "a directory already exists at the entry path",
            )),
            Some(_) => fs::remove_file(path).map_err(|e| map_fs_err(&e)),
            None => Ok(()),
        }
    }

    fn make_dir(&mut self, comps: Vec<OsString>, mode: u32) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Ok(());
        };
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        // 別表記（`d/` の後の `D/`）は、下の遅延 mode の取り消し・mode の適用より前に `probe` が拒否する（IO-5）。
        match self.probe(dir.id, &name, &path)? {
            Some((m, id)) if m.is_dir() => self.names.define(id),
            Some((_, id)) => {
                self.names.define(id);
                fs::remove_file(&path).map_err(|e| map_fs_err(&e))?;
                fs::create_dir(&path).map_err(|e| map_fs_err(&e))?;
            }
            None => {
                let id = self.names.insert(dir.id, &name)?;
                self.names.define(id);
                fs::create_dir(&path).map_err(|e| map_fs_err(&e))?;
            }
        }
        // 同じディレクトリの再定義は後勝ち。先の遅延 mode を残すと finish_dirs が後の mode を上書きする。
        self.deferred_dirs.remove(&path);
        if needs_deferral(mode) {
            // umask 等で所有者の rwx が欠けても子を作れるよう、finish_dirs まで一時的に 0700 にする。
            apply_dir_mode(&path, 0o700)?;
            self.deferred_dirs.insert(path, mode);
            Ok(())
        } else {
            apply_dir_mode(&path, mode)
        }
    }

    fn write_file<R: Read>(
        &mut self,
        comps: Vec<OsString>,
        mode: u32,
        size: u64,
        data: &mut R,
    ) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        // 宣言サイズで累積上限を書き込み前に検査する（巨大宣言サイズによる DoS を防ぐ）。
        let next = self
            .bytes
            .checked_add(size)
            .filter(|n| *n <= self.limits.max_total_bytes)
            .ok_or_else(|| {
                err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the extracted size limit",
                )
            })?;
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        self.clear_existing_non_dir(dir.id, &name, &path)?;
        self.names.insert(dir.id, &name)?;
        // create_new は O_CREAT|O_EXCL で、最終コンポーネントの symlink を追従しない。
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| map_fs_err(&e))?;
        let mut buf = vec![0u8; COPY_BUF_LEN];
        let mut written = 0u64;
        while written < size {
            let want = usize::try_from(size - written).map_or(buf.len(), |r| r.min(buf.len()));
            let Some(dst) = buf.get_mut(..want) else {
                break;
            };
            let n = match data.read(dst) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_stream_err(e)),
            };
            if let Some(chunk) = buf.get(..n) {
                f.write_all(chunk).map_err(|e| map_fs_err(&e))?;
            }
            written += n as u64;
        }
        if written != size {
            return Err(err(OciErrorCode::DataLoss, "layer tar stream is malformed"));
        }
        apply_file_mode(&f, mode & FILE_MODE_MASK)?;
        if mode & 0o7000 != 0 {
            self.stripped_special = self.stripped_special.saturating_add(1);
        }
        self.bytes = next;
        Ok(())
    }

    fn make_symlink(&mut self, comps: Vec<OsString>, target: &[u8]) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        if target.is_empty() || target.len() > MAX_PATH_BYTES || target.contains(&0) {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "symlink target is invalid",
            ));
        }
        let dir = self.resolve_dir(&parent, true)?;
        // リンク先を配置ディレクトリ基準で字句的に検査し、ルートより上へ出るものを拒否する。
        let mut depth = if target.first() == Some(&b'/') {
            0
        } else {
            dir.comps.len()
        };
        for c in target.split(|b| *b == b'/') {
            if c.is_empty() || c == b"." {
                continue;
            }
            if c == b".." {
                depth = depth.checked_sub(1).ok_or_else(escapes)?;
            } else {
                depth += 1;
            }
        }
        let path = join_resolved(self.root, &dir.comps, &name);
        self.clear_existing_non_dir(dir.id, &name, &path)?;
        self.names.insert(dir.id, &name)?;
        create_symlink(Path::new(&bytes_to_os(target)?), &path)
    }

    fn make_hardlink(&mut self, comps: Vec<OsString>, target: &[u8]) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        let Some((tparent, tname)) = split_last(normalize_entry_path(target)?) else {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "hardlink target is empty",
            ));
        };
        let tdir = self.resolve_dir(&tparent, false)?;
        let tpath = join_resolved(self.root, &tdir.comps, &tname);
        // 参照先も `probe` を通す。別表記で既存の実体へ解決される参照先（`g → F` で実在するのは `f`）は拒否する。
        let target_id = match self.probe(tdir.id, &tname, &tpath)? {
            Some((m, id)) if m.is_file() => id,
            Some(_) => {
                return Err(err(
                    OciErrorCode::PermissionDenied,
                    "hardlink target is not a regular file",
                ));
            }
            None => return Err(err(OciErrorCode::NotFound, "extraction path not found")),
        };
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        // 参照先と同一パス（f → f）なら削除すると参照元を失うため、既存ファイルをそのまま保持する。
        // 綴りだけが違う同じ実体（`F → f`）は、下の `clear_existing_non_dir` が削除の前に拒否する（IO-5）。
        // 明示されたエントリなので現在のレイヤーの世代へ記録し、後続の whiteout・不透明の対象にしない（OCI-2）。
        if tpath == path {
            self.names.touch(target_id);
            return Ok(());
        }
        self.clear_existing_non_dir(dir.id, &name, &path)?;
        self.names.insert(dir.id, &name)?;
        fs::hard_link(&tpath, &path).map_err(|e| map_fs_err(&e))
    }

    /// whiteout の対象（`parent` 直下の `target`）を下位レイヤーの実体として root 内から再帰削除する
    /// （OCI-2・TASK-53.1・#412・TASK-53.3・#414。`extract_one_layer` が `.wh.<target>` で呼ぶ）。
    ///
    /// 親の解決は `resolve_dir` で root に閉じ込め、削除は symlink を追従しない。親や対象が存在しなければ
    /// 下位に消す実体が無いのと同義で何もしない。別表記（大文字小文字・Unicode 正規化）で既存の実体へ
    /// 解決される名前は削除せず `AlreadyExists` で拒否する（IO-5。保守的な fail-closed）。
    ///
    /// 世代管理: image-spec は whiteout を下位レイヤーのリソースにのみ適用すると定める。現在のレイヤーが
    /// 作成・上書きした非ディレクトリは残し（tar 内の並び順に結果を依存させない）、現在のレイヤーが
    /// 作成・通過したディレクトリは下位由来の子だけを消して残す（`prune_lower`）。
    /// 削除した木の配下の遅延ディレクトリ mode は取り除き（`finish_dirs` が置換と誤認しないため）、
    /// 削除した名前と配下の登録は `NameIndex` から外す（IO-5）。
    pub(crate) fn remove_whiteout_target(
        &mut self,
        parent: &[OsString],
        target: &OsStr,
    ) -> Result<(), OciError> {
        let dir = match self.resolve_dir(parent, false) {
            Ok(d) => d,
            Err(e) if e.code() == OciErrorCode::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let path = join_resolved(self.root, &dir.comps, &target.to_os_string());
        let Some((meta, id)) = self.probe(dir.id, target, &path)? else {
            return Ok(());
        };
        if self.names.is_touched(id) {
            // 現在のレイヤー由来。ディレクトリのときだけ、下位由来の子を消す。
            if meta.is_dir() {
                self.prune_lower(&path, id, 0)?;
                self.reset_traversed_dir(&path, id)?;
            }
            return Ok(());
        }
        if meta.file_type().is_symlink() {
            if self.names.traversed_links.contains(&id) {
                return Err(err(
                    OciErrorCode::InvalidArgument,
                    "entry path depends on the order of a symlink whiteout in the same layer",
                ));
            }
            self.names
                .link_tombstones
                .insert((dir.id, target.to_os_string()));
        }
        crate::whiteout::remove_tree_nofollow(&path)?;
        self.drop_deferred_subtree(&path);
        self.names.forget_tree(dir.id, target);
        Ok(())
    }

    /// `path` 配下（`path` 自身を含む）の遅延ディレクトリ mode を取り除く。`BTreeMap` の範囲走査で、
    /// 削除する件数に比例した時間で済む（全件走査の繰り返しによる O(N×M) を避ける。DoS 対策）。
    fn drop_deferred_subtree(&mut self, path: &Path) {
        let keys: Vec<PathBuf> = self
            .deferred_dirs
            .range::<PathBuf, _>(path.to_path_buf()..)
            .take_while(|(p, _)| p.starts_with(path))
            .map(|(p, _)| p.clone())
            .collect();
        for k in keys {
            self.deferred_dirs.remove(&k);
        }
    }

    /// 現在のレイヤーが経路として通過しただけの下位由来ディレクトリの mode を、暗黙作成と同じ既定へ戻す。
    /// whiteout が先に来て削除・暗黙再作成される並びと結果を揃え、同一レイヤー内の順序に依存させない（OCI-2）。
    fn reset_traversed_dir(&mut self, path: &Path, id: u64) -> Result<(), OciError> {
        if self.names.is_defined(id) {
            return Ok(());
        }
        self.deferred_dirs.remove(path);
        apply_dir_mode(path, IMPLICIT_DIR_MODE)
    }

    /// 不透明ディレクトリ（`parent`）の下位レイヤー由来の中身をすべて消す。ディレクトリ自体は残す
    /// （OCI-2・TASK-53.2・#413・TASK-53.3・#414。`parent = []` は root 直下で、root 自体は消さない）。
    ///
    /// 親の解決は `resolve_dir` で root に閉じ込め、削除は symlink を追従しない。親が存在しなければ何もせず、
    /// 非ディレクトリなら `FailedPrecondition`、別表記で既存実体へ解決される親は `AlreadyExists`（IO-5）。
    /// 現在のレイヤーが作成・通過したエントリは残す世代管理は `prune_lower` が担う。
    pub(crate) fn clear_opaque_dir(&mut self, parent: &[OsString]) -> Result<(), OciError> {
        let dir = match self.resolve_dir(parent, false) {
            Ok(d) => d,
            Err(e) if e.code() == OciErrorCode::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let path = dir
            .comps
            .iter()
            .fold(self.root.to_path_buf(), |p, c| p.join(c));
        self.prune_lower(&path, dir.id, 0)
    }

    /// ディレクトリ `dir`（ID は `dir_id`）直下から、現在のレイヤーが触っていない（下位由来の）エントリを
    /// 木ごと削除する。現在のレイヤーが触った非ディレクトリは残し、触ったディレクトリは再帰して
    /// その下位由来の中身だけを消す（深さは `MAX_REMOVE_DEPTH`）。
    /// 消した木の遅延 mode と `NameIndex` 登録は外す（`dir` 自身の mode は残す）。
    fn prune_lower(&mut self, dir: &Path, dir_id: u64, depth: usize) -> Result<(), OciError> {
        if self.names.pruned.contains(&dir_id) {
            return Ok(());
        }
        if depth >= crate::whiteout::MAX_REMOVE_DEPTH {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "directory tree to remove is too deep",
            ));
        }
        let meta = fs::symlink_metadata(dir).map_err(|e| map_fs_err(&e))?;
        if !meta.is_dir() {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                "opaque directory is not a directory",
            ));
        }
        crate::whiteout::make_dir_removable(dir, &meta)?;
        let mut children: Vec<OsString> = Vec::new();
        for entry in fs::read_dir(dir).map_err(|e| map_fs_err(&e))? {
            children.push(entry.map_err(|e| map_fs_err(&e))?.file_name());
        }
        for name in children {
            let child = dir.join(&name);
            match self.names.get(dir_id, &name) {
                Some(id) if self.names.is_touched(id) => {
                    let m = fs::symlink_metadata(&child).map_err(|e| map_fs_err(&e))?;
                    if m.is_dir() {
                        self.prune_lower(&child, id, depth + 1)?;
                        self.reset_traversed_dir(&child, id)?;
                    }
                }
                _ => {
                    crate::whiteout::remove_tree_nofollow(&child)?;
                    self.drop_deferred_subtree(&child);
                    self.names.forget_tree(dir_id, &name);
                }
            }
        }
        self.names.pruned.insert(dir_id);
        Ok(())
    }

    /// 遅延していたディレクトリの mode を深い順に適用する（実ディレクトリであることを再確認する）。
    fn finish_dirs(&mut self) -> Result<(), OciError> {
        let mut dirs: Vec<(PathBuf, u32)> = std::mem::take(&mut self.deferred_dirs)
            .into_iter()
            .collect();
        // 深い順。同じ深さはパス順で決定的にする。
        dirs.sort_by(|(a, _), (b, _)| {
            b.components()
                .count()
                .cmp(&a.components().count())
                .then_with(|| a.cmp(b))
        });
        for (path, mode) in dirs {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => apply_dir_mode(&path, mode)?,
                _ => {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "an extracted directory was replaced during extraction",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `root` が既存の空ディレクトリであることを確かめる（最初のレイヤーの前に 1 回だけ呼ぶ）。
fn check_root_empty(root: &Path) -> Result<(), OciError> {
    match fs::symlink_metadata(root) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "extraction root is not a directory",
            ));
        }
        Err(e) => return Err(map_fs_err(&e)),
    }
    // 別表記の衝突の判定（`Extractor::probe`）は「`root` 配下の実在項目はすべてこの展開が作った」ことに依る。
    // 呼び出し契約（空のステージング）を前提にせず、ここで確かめる（IO-5）。
    match fs::read_dir(root).map_err(|e| map_fs_err(&e))?.next() {
        None => Ok(()),
        Some(Ok(_)) => Err(err(
            OciErrorCode::FailedPrecondition,
            "extraction root is not empty",
        )),
        Some(Err(e)) => Err(map_fs_err(&e)),
    }
}

/// 1 レイヤー分の tar を `x` へ展開する。`input_budget` はこのレイヤーに残された入力バイト数の上限。
///
/// 戻り値は（このレイヤー分の結果〔`x` のカウンタの差分〕, 読み取った入力バイト数）。
/// `finish_dirs` は呼ばない（全レイヤーの展開後に 1 回だけ呼ぶため）。
fn extract_one_layer<R: Read>(
    x: &mut Extractor<'_>,
    src: R,
    input_budget: u64,
) -> Result<(ExtractedLayer, u64), OciError> {
    let (entries0, bytes0, stripped0) = (x.entries, x.bytes, x.stripped_special);
    x.names.clear_touched();
    let max_entries = x.limits.max_entries;
    let mut src = LimitedReader {
        inner: src,
        read: 0,
        limit: input_budget,
    };
    {
        let mut archive = Archive::new(TarGuard::new(&mut src));
        for entry in archive.entries().map_err(map_stream_err)? {
            let mut entry = entry.map_err(map_stream_err)?;
            let ty = entry.header().entry_type();
            if ty == EntryType::XGlobalHeader {
                continue;
            }
            x.entries += 1;
            if x.entries > max_entries {
                return Err(err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the entry count limit",
                ));
            }
            let raw_path = entry.path_bytes().into_owned();
            let is_dir_name = raw_path.last() == Some(&b'/');
            let comps = normalize_entry_path(&raw_path)?;
            // whiteout・不透明マーカーは rootfs へ展開せず、下位レイヤーへの削除として適用する（OCI-2・TASK-53.3）。
            let last_raw = raw_path
                .split(|b| *b == b'/')
                .rfind(|c| !c.is_empty() && *c != b".");
            // 親コンポーネントが whiteout 名・予約名のパスは、暗黙のディレクトリ作成などの副作用の前に拒否する。
            let mut raw_comps = raw_path
                .split(|b| *b == b'/')
                .filter(|c| !c.is_empty() && *c != b".")
                .peekable();
            while let Some(c) = raw_comps.next() {
                if raw_comps.peek().is_some()
                    && crate::whiteout::classify(c)? != crate::whiteout::NameClass::Regular
                {
                    return Err(err(
                        OciErrorCode::InvalidArgument,
                        "whiteout name used as a parent path component",
                    ));
                }
            }
            let class = match last_raw {
                Some(name) => crate::whiteout::classify(name)?,
                None => crate::whiteout::NameClass::Regular,
            };
            if class != crate::whiteout::NameClass::Regular {
                // マーカーは中身の無い通常ファイルに限る。他の型・ディレクトリ名のマーカー名は、
                // 実体として展開もせず意図不明のまま黙って落としもしないよう拒否する（fail-closed）。
                if !matches!(ty, EntryType::Regular | EntryType::Continuous)
                    || is_dir_name
                    || entry.size() != 0
                {
                    return Err(err(
                        OciErrorCode::InvalidArgument,
                        "whiteout marker must be an empty regular file entry",
                    ));
                }
                let Some((parent, _)) = split_last(comps) else {
                    return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
                };
                match class {
                    crate::whiteout::NameClass::Whiteout { target } => {
                        x.remove_whiteout_target(&parent, &bytes_to_os(&target)?)?;
                    }
                    _ => x.clear_opaque_dir(&parent)?,
                }
                continue;
            }
            let mode = entry.header().mode().map_err(map_stream_err)?;
            match ty {
                EntryType::Directory => x.make_dir(comps, mode)?,
                EntryType::Regular | EntryType::Continuous if is_dir_name => {
                    x.make_dir(comps, mode)?;
                }
                EntryType::Regular | EntryType::Continuous => {
                    let size = entry.size();
                    x.write_file(comps, mode, size, &mut entry)?;
                }
                EntryType::Symlink => {
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "symlink target is invalid")
                        })?;
                    x.make_symlink(comps, &target)?;
                }
                EntryType::Link => {
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "hardlink target is invalid")
                        })?;
                    x.make_hardlink(comps, &target)?;
                }
                _ => {
                    return Err(err(
                        OciErrorCode::PermissionDenied,
                        "unsupported entry type",
                    ));
                }
            }
        }
    }
    // 世代（現在のレイヤーが触ったエントリ）はレイヤーごとに閉じる。次のレイヤーの whiteout は
    // このレイヤーの実体を「下位レイヤー由来」として扱う。
    x.names.clear_touched();
    // tar 終端後の残りを読み捨て、gzip トレーラ（CRC32・ISIZE）を検証させる。
    let mut buf = vec![0u8; COPY_BUF_LEN];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if let Some(v) = e.get_ref().and_then(|i| i.downcast_ref::<GuardViolation>()) {
                    return Err(err(v.code, v.msg));
                }
                return Err(oci_error_from_layer_io(e));
            }
        }
    }
    Ok((
        ExtractedLayer {
            entries: x.entries.saturating_sub(entries0),
            bytes: x.bytes.saturating_sub(bytes0),
            files_with_stripped_special_bits: x.stripped_special.saturating_sub(stripped0),
        },
        src.read,
    ))
}

/// レイヤー列を `root` へ下位から順に重ねて展開する本体（単一レイヤー API もこれの 1 要素版）。
///
/// `open` は各要素から tar バイトストリームを開く（blob 版は gzip を開く）。`Extractor`（別表記の索引・
/// 遅延ディレクトリ mode・上限のカウンタ）は全レイヤーで共有し、上限は全体で累積する。`lstat` は
/// テストだけが差し替える（`Lstat` を参照）。
fn extract_stack<T, R: Read>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = T>,
    mut open: impl FnMut(T) -> Result<R, OciError>,
    root: &Path,
    limits: ExtractLimits,
    lstat: Lstat,
) -> Result<Vec<ExtractedLayer>, OciError> {
    let mut x: Option<Extractor<'_>> = None;
    let mut input_used = 0u64;
    let mut out = Vec::new();
    let mut layers = layers.into_iter().peekable();
    while let Some(item) = layers.next() {
        // 空の reader は件数・入力バイトを消費しないため、既存の上限では結果の Vec の増加を止められない。
        if out.len() >= MAX_LAYERS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "image exceeds the layer count limit",
            ));
        }
        let is_last = layers.peek().is_none();
        let res = record_oci_op(recorder, OciOpKind::ExtractLayer, || {
            let src = open(item)?;
            if x.is_none() {
                check_root_empty(root)?;
                x = Some(Extractor {
                    root,
                    limits,
                    entries: 0,
                    bytes: 0,
                    stripped_special: 0,
                    deferred_dirs: BTreeMap::new(),
                    names: NameIndex::new(limits.max_tracked_paths),
                    lstat,
                });
            }
            let Some(ex) = x.as_mut() else {
                return Err(err(OciErrorCode::Internal, "extractor is not initialized"));
            };
            let budget = limits.max_input_bytes.saturating_sub(input_used);
            let (layer, read) = extract_one_layer(ex, src, budget)?;
            input_used = input_used.saturating_add(read);
            // 遅延ディレクトリ権限の適用は最後のレイヤーの記録に含める（失敗・所要時間を計装から漏らさない。REPAIR-4）。
            if is_last {
                ex.finish_dirs()?;
            }
            Ok(layer)
        })?;
        out.push(res);
    }
    if x.is_none() {
        return Err(err(OciErrorCode::InvalidArgument, "no layers to extract"));
    }
    Ok(out)
}

/// 単一レイヤー版の結果（要素 1 つ）を取り出す。
fn single(mut v: Vec<ExtractedLayer>) -> Result<ExtractedLayer, OciError> {
    match (v.pop(), v.is_empty()) {
        (Some(l), true) => Ok(l),
        _ => Err(err(OciErrorCode::Internal, "unexpected layer result count")),
    }
}

/// テスト用の単一レイヤー展開（`lstat` を差し替える）。
#[cfg(test)]
fn extract_with_lstat<R: Read>(
    src: R,
    root: &Path,
    limits: ExtractLimits,
    lstat: Lstat,
) -> Result<ExtractedLayer, OciError> {
    single(extract_stack(
        &NoopOciOpRecorder,
        [src],
        Ok,
        root,
        limits,
        lstat,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::OciOpOutcome;
    use crate::instrument::testing::Collect;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// `base/root` を作る一時ディレクトリ。Drop で `base` ごと消す（番兵でルート外書き込みを検出する）。
    struct Sandbox {
        base: PathBuf,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let base =
                std::env::temp_dir().join(format!("fc-oci-extract-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            let root = base.join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(base.join("sentinel"), b"s").unwrap();
            Self { base, root }
        }

        /// ルート外に番兵以外が増えていないこと。
        fn assert_outside_untouched(&self) {
            let mut names: Vec<_> = fs::read_dir(&self.base)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            assert_eq!(names, vec!["root".to_string(), "sentinel".to_string()]);
            assert_eq!(fs::read(self.base.join("sentinel")).unwrap(), b"s");
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            // 0o555 等のディレクトリを消せるよう権限を戻す。
            #[cfg(unix)]
            restore_perms(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(unix)]
    fn restore_perms(p: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(m) = fs::symlink_metadata(p)
            && m.is_dir()
        {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    restore_perms(&e.path());
                }
            }
        }
    }

    /// 生バイトで 1 エントリ分（ヘッダ + パディング済みデータ）を組み立てる。
    /// `tar::Builder` は `..` や絶対パスを拒否するため、悪意あるアーカイブはここで手組みする。
    fn raw_entry(
        name: &[u8],
        ty: EntryType,
        link: &[u8],
        mode: u32,
        declared: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name);
            old.linkname[..link.len()].copy_from_slice(link);
        }
        h.set_entry_type(ty);
        h.set_mode(mode);
        h.set_size(declared);
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    fn file(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Regular,
            b"",
            mode,
            data.len() as u64,
            data,
        )
    }

    fn dir(name: &str, mode: u32) -> Vec<u8> {
        raw_entry(name.as_bytes(), EntryType::Directory, b"", mode, 0, b"")
    }

    fn symlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Symlink,
            target.as_bytes(),
            0o777,
            0,
            b"",
        )
    }

    fn hardlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Link,
            target.as_bytes(),
            0o644,
            0,
            b"",
        )
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    fn run(sb: &Sandbox, entries: &[Vec<u8>]) -> Result<ExtractedLayer, OciError> {
        extract_tar(
            archive(entries).as_slice(),
            &sb.root,
            ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20),
        )
    }

    /// 大文字小文字と NFC / NFD を区別しない FS の名前解決を模擬する `Lstat`（IO-5）。
    ///
    /// 綴りどおりに無ければ、最終コンポーネントを ASCII 小文字にし `e` + U+0301 を U+00E9 へ畳んで引き直す。
    /// 大文字小文字を区別する FS（Linux の CI）の上で「別表記が既存の実体へ解決される」状況を作る。
    /// 先に小文字・NFC の名前を作り、後から大文字・NFD の綴りで参照する入力に対して使う。
    fn folding_lstat(p: &Path) -> std::io::Result<fs::Metadata> {
        fs::symlink_metadata(p).or_else(|e| {
            let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str()))
            else {
                return Err(e);
            };
            let folded = name.to_ascii_lowercase().replace("e\u{301}", "\u{e9}");
            fs::symlink_metadata(dir.join(folded))
        })
    }

    /// `folding_lstat` を注入して展開する（区別しない FS の模擬）。
    fn run_folding(sb: &Sandbox, entries: &[Vec<u8>]) -> Result<ExtractedLayer, OciError> {
        extract_with_lstat(
            archive(entries).as_slice(),
            &sb.root,
            ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20),
            folding_lstat,
        )
    }

    /// `dir` 直下の名前を綴りのまま昇順で返す。
    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// 別表記の衝突として拒否されたこと（`code` と `message` の具体値）を確かめる。
    fn assert_spelling_collision(r: Result<ExtractedLayer, OciError>) {
        let e = r.expect_err("must be rejected as a spelling collision");
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(e.code().as_str(), "ALREADY_EXISTS");
        assert_eq!(
            e.message(),
            "entry name resolves to an existing entry with a different spelling \
             (case or Unicode normalization) on the destination filesystem"
        );
    }

    /// `base` の FS が `a` と `b` を同じ名前として解決するか（`a` を作って `b` で引く。後始末する）。
    fn fs_resolves_as_same(base: &Path, a: &str, b: &str) -> bool {
        fs::write(base.join(a), b"p").unwrap();
        let same = fs::symlink_metadata(base.join(b)).is_ok();
        fs::remove_file(base.join(a)).unwrap();
        same
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// IO-5 / OCI-1: 通常ファイル `f` の後の hardlink `F → f` は、区別しない FS では参照元を削除する前に拒否する。
    #[test]
    fn io5_hardlink_under_alias_spelling_is_rejected_before_removing_source() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"data"), hardlink("F", "f")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: `d/`（0555）の後の `D/`（0755）は、区別しない FS では mode を変える前に拒否する
    /// （先の遅延 mode が残って後勝ちが崩れる経路を作らない）。
    #[test]
    fn io5_directory_alias_redefinition_is_rejected_before_mode_change() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(&sb, &[dir("d/", 0o555), dir("D/", 0o755)]));
        assert_eq!(names_in(&sb.root), ["d"]);
        // `d/` は遅延中の一時 mode（0700）のままで、`D/` の 0755 は適用されていない。
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.root.join("d")), 0o700);
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: 区別しない FS で別表記の通常ファイルが先の内容を上書きしない（`f` の後の `F`、NFC の後の NFD）。
    #[test]
    fn io5_file_alias_does_not_overwrite() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"one"), file("F", 0o644, b"two")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"one");

        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[
                file("caf\u{e9}", 0o644, b"nfc"),
                file("cafe\u{301}", 0o644, b"nfd"),
            ],
        ));
        assert_eq!(names_in(&sb.root), ["caf\u{e9}"]);
        assert_eq!(fs::read(sb.root.join("caf\u{e9}")).unwrap(), b"nfc");
    }

    /// IO-5 / OCI-1: 別表記は親コンポーネント・hardlink の参照先・symlink を辿った先でも拒否し、何も作らない。
    #[test]
    fn io5_alias_in_parent_and_link_targets_is_rejected() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("d/x", 0o644, b"x"), file("D/y", 0o644, b"y")],
        ));
        assert_eq!(names_in(&sb.root), ["d"]);
        assert_eq!(names_in(&sb.root.join("d")), ["x"]);

        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"data"), hardlink("g", "F")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);

        #[cfg(unix)]
        {
            let sb = Sandbox::new();
            assert_spelling_collision(run_folding(
                &sb,
                &[
                    dir("d/", 0o755),
                    symlink("l", "D"),
                    file("l/x", 0o644, b"x"),
                ],
            ));
            assert_eq!(names_in(&sb.root), ["d", "l"]);
            assert_eq!(names_in(&sb.root.join("d")), Vec::<String>::new());
        }
    }

    /// IO-5 / OCI-1: 区別しない FS の模擬でも、同じ綴りの再定義（後勝ち）と別名は従来どおり通す（過剰に拒否しない）。
    #[test]
    fn io5_same_spelling_redefinition_is_still_accepted_on_folding_fs() {
        let sb = Sandbox::new();
        let r = run_folding(
            &sb,
            &[
                file("f", 0o644, b"one"),
                file("f", 0o644, b"two"),
                hardlink("f", "f"),
                hardlink("g", "f"),
                dir("d/", 0o555),
                dir("d/", 0o755),
                file("d/x", 0o644, b"x"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (7, 7));
        assert_eq!(names_in(&sb.root), ["d", "f", "g"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"two");
        assert_eq!(fs::read(sb.root.join("g")).unwrap(), b"two");
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"x");
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.root.join("d")), 0o755);
    }

    /// IO-5 / OCI-1: 実 FS での大文字小文字の別表記。区別する FS（Linux の既定）では別の実体として両方を
    /// 展開し、区別しない FS（Windows・macOS の既定）では先の実体を変える前に拒否する。
    #[test]
    fn io5_case_variants_follow_destination_fs() {
        let sb = Sandbox::new();
        let folds = fs_resolves_as_same(&sb.base, "probe", "PROBE");
        let layers = [
            vec![file("f", 0o644, b"data"), hardlink("F", "f")],
            vec![file("f", 0o644, b"data"), file("F", 0o644, b"two")],
            vec![dir("d/", 0o555), dir("D/", 0o755)],
        ];
        if folds {
            // hardlink `F → f` は参照元 `f` を削除する前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[0]));
            assert_eq!(names_in(&sb.root), ["f"]);
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
            sb.assert_outside_untouched();

            // 通常ファイル `F` は `f` の内容を上書きする前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[1]));
            assert_eq!(names_in(&sb.root), ["f"]);
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            // ディレクトリ `D/` は `d/` の mode（遅延中の一時 0700）を変える前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[2]));
            assert_eq!(names_in(&sb.root), ["d"]);
            #[cfg(unix)]
            assert_eq!(mode_of(&sb.root.join("d")), 0o700);
        } else {
            let sb = Sandbox::new();
            run(&sb, &layers[0]).unwrap();
            assert_eq!(names_in(&sb.root), ["F", "f"]);
            assert_eq!(fs::read(sb.root.join("F")).unwrap(), b"data");
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            let sb = Sandbox::new();
            run(&sb, &layers[1]).unwrap();
            assert_eq!(names_in(&sb.root), ["F", "f"]);
            assert_eq!(fs::read(sb.root.join("F")).unwrap(), b"two");
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            let sb = Sandbox::new();
            run(&sb, &layers[2]).unwrap();
            assert_eq!(names_in(&sb.root), ["D", "d"]);
            #[cfg(unix)]
            {
                assert_eq!(mode_of(&sb.root.join("d")), 0o555);
                assert_eq!(mode_of(&sb.root.join("D")), 0o755);
            }
        }
    }

    /// IO-5 / OCI-1: 実 FS での NFC / NFD の別表記。正規化を区別する FS（ext4・NTFS）では両方を展開し、
    /// 区別しない FS（APFS）では先の内容を上書きする前に拒否する。
    #[test]
    fn io5_normalization_variants_follow_destination_fs() {
        let (nfc, nfd) = ("caf\u{e9}", "cafe\u{301}");
        let sb = Sandbox::new();
        let folds = fs_resolves_as_same(&sb.base, nfc, nfd);
        let r = run(&sb, &[file(nfc, 0o644, b"nfc"), file(nfd, 0o644, b"nfd")]);
        if folds {
            assert_spelling_collision(r);
            assert_eq!(names_in(&sb.root), [nfc]);
        } else {
            let r = r.unwrap();
            assert_eq!((r.entries, r.bytes), (2, 6));
            assert_eq!(names_in(&sb.root), [nfd, nfc]);
            assert_eq!(fs::read(sb.root.join(nfd)).unwrap(), b"nfd");
        }
        assert_eq!(fs::read(sb.root.join(nfc)).unwrap(), b"nfc");
        sb.assert_outside_untouched();
    }

    /// IO-5: Windows・macOS の既定の一時領域は大文字小文字を区別しない（macOS の APFS は NFC / NFD も区別しない）。
    ///
    /// `io5_case_variants_follow_destination_fs` と `io5_normalization_variants_follow_destination_fs` は
    /// 展開先 FS の挙動で分岐するため、これらの OS の CI で「実 FS が別表記を既存の実体へ解決し、展開が
    /// 拒否する」側が実際に走ったことをここで固定する（区別する側へ黙って流れたら失敗させる）。
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn io5_default_host_fs_resolves_spelling_variants_as_same() {
        let sb = Sandbox::new();
        assert!(fs_resolves_as_same(&sb.base, "probe", "PROBE"));
        #[cfg(target_os = "macos")]
        assert!(fs_resolves_as_same(&sb.base, "caf\u{e9}", "cafe\u{301}"));
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: 空でない展開先は `FailedPrecondition` で拒否し、既存の項目に触れない
    /// （別表記の衝突の判定が「実在項目はすべてこの展開が作った」ことに依るため）。
    #[test]
    fn io5_non_empty_root_is_rejected() {
        let sb = Sandbox::new();
        fs::write(sb.root.join("existing"), b"keep").unwrap();
        let e = run(&sb, &[file("existing", 0o644, b"new")]).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "extraction root is not empty");
        assert_eq!(names_in(&sb.root), ["existing"]);
        assert_eq!(fs::read(sb.root.join("existing")).unwrap(), b"keep");
    }

    /// OCI-1 / IO-5: 展開が作る名前（暗黙の親ディレクトリを含む）は上限ちょうどが成功し、超過は作成前に中断する。
    /// 同じ名前の再定義は件数を増やさない。
    #[test]
    fn oci1_tracked_path_limit() {
        let limits = |n| ExtractLimits::new(10, 100, 1 << 30, n);
        let es = [file("a/b/c", 0o644, b"x"), file("a/b/c", 0o644, b"y")];
        let sb = Sandbox::new();
        let r = extract_tar(archive(&es).as_slice(), &sb.root, limits(3)).unwrap();
        assert_eq!((r.entries, r.bytes), (2, 2));
        assert_eq!(fs::read(sb.root.join("a/b/c")).unwrap(), b"y");

        let sb = Sandbox::new();
        let e = extract_tar(archive(&es).as_slice(), &sb.root, limits(2)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the tracked path limit");
        assert_eq!(names_in(&sb.root.join("a")), ["b"]);
        assert_eq!(names_in(&sb.root.join("a/b")), Vec::<String>::new());

        let sb = Sandbox::new();
        let e = extract_tar(
            archive(&[dir("x/", 0o755), dir("y/", 0o755)]).as_slice(),
            &sb.root,
            limits(1),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(names_in(&sb.root), ["x"]);
    }

    fn code(r: Result<ExtractedLayer, OciError>) -> OciErrorCode {
        r.expect_err("must fail").code()
    }

    /// OCI-1: `..`・絶対パス・NUL・過大な長さは拒否され、ルート外には何も作られない。
    #[test]
    fn oci1_path_traversal_is_rejected() {
        for name in [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "a/b/../../..",
            "./../evil",
        ] {
            let sb = Sandbox::new();
            assert_eq!(
                code(run(&sb, &[file(name, 0o644, b"x")])),
                OciErrorCode::PermissionDenied,
                "{name}"
            );
            sb.assert_outside_untouched();
        }
        // 1 コンポーネント 256 バイトは GNU long name 経由でしか表せない。
        let sb = Sandbox::new();
        let long = "x".repeat(256);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let e = extract_tar(
            bytes.as_slice(),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1 / SEC-5: 通常の展開（暗黙の親ディレクトリ・`./` 正規化・mode・ルート自身の無視）。
    /// 通常ファイルの setuid（04755）は落として 0755 で展開する。
    #[cfg(unix)]
    #[test]
    fn oci1_extracts_regular_tree_with_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                dir("./", 0o755),
                dir("etc/", 0o755),
                file("./etc/hosts", 0o644, b"127.0.0.1"),
                file("usr/bin/tool", 0o4755, b"bin"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (4, 12));
        assert_eq!(fs::read(sb.root.join("etc/hosts")).unwrap(), b"127.0.0.1");
        let mode = |p: &str| fs::metadata(sb.root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("etc/hosts"), 0o644);
        assert_eq!(mode("usr/bin/tool"), 0o755);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(mode("etc"), 0o755);
        sb.assert_outside_untouched();
    }

    /// SEC-5 / OCI-1: 通常ファイルの setuid / setgid / sticky は落とし、落とした件数を結果に返す。
    /// 実行ユーザー所有のまま setuid / setgid を残さない。ディレクトリの mode（sticky の 1777）は変えない。
    #[cfg(unix)]
    #[test]
    fn sec5_special_mode_bits_are_stripped_from_regular_files() {
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                file("suid", 0o4755, b"a"),
                file("sgid", 0o2755, b"b"),
                file("both", 0o6711, b"c"),
                file("sticky", 0o1644, b"d"),
                file("plain", 0o755, b"e"),
                hardlink("link", "suid"),
                dir("tmp/", 0o1777),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (7, 5));
        assert_eq!(r.files_with_stripped_special_bits, 4);
        for (name, want) in [
            ("suid", 0o755),
            ("sgid", 0o755),
            ("both", 0o711),
            ("sticky", 0o644),
            ("plain", 0o755),
            ("link", 0o755),
            ("tmp", 0o1777),
        ] {
            assert_eq!(mode_of(&sb.root.join(name)), want, "{name}");
        }
    }

    /// OCI-1: 親エントリの無い tar の暗黙ディレクトリは既定 0755、後続の明示エントリがあればその mode になる。
    #[cfg(unix)]
    #[test]
    fn oci1_implicit_dirs_get_default_mode_and_explicit_overrides() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(
            &sb,
            &[
                file("usr/bin/tool", 0o755, b"x"),
                file("opt/app/f", 0o644, b"y"),
                dir("opt/", 0o750),
            ],
        )
        .unwrap();
        let mode = |p: &str| fs::metadata(sb.root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("usr"), 0o755);
        assert_eq!(mode("usr/bin"), 0o755);
        assert_eq!(mode("opt/app"), 0o755);
        assert_eq!(mode("opt"), 0o750);
    }

    /// OCI-1: 所有者の権限が欠けるディレクトリでも子を作れ、最終的に mode が適用される。
    #[cfg(unix)]
    #[test]
    fn oci1_readonly_directory_mode_is_deferred() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(&sb, &[dir("ro/", 0o555), file("ro/child", 0o644, b"c")]).unwrap();
        assert_eq!(fs::read(sb.root.join("ro/child")).unwrap(), b"c");
        let m = fs::metadata(sb.root.join("ro"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(m, 0o555);
    }

    /// OCI-1: 同じディレクトリの再定義は後勝ち（0555 の後に 0755 を定義すると最終 mode は 0755）。
    #[cfg(unix)]
    #[test]
    fn oci1_directory_redefinition_is_last_wins() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode_of = |sb: &Sandbox| {
            fs::metadata(sb.root.join("d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o555), dir("d/", 0o755)]).unwrap();
        assert_eq!(mode_of(&sb), 0o755);
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o755), dir("d/", 0o555)]).unwrap();
        assert_eq!(mode_of(&sb), 0o555);
    }

    /// OCI-1: 巨大な拡張ヘッダ（GNU long name / PAX）は本体を確保する前にメタデータ上限で拒否する。
    #[test]
    fn oci1_oversized_extended_header_is_rejected_before_read() {
        for ty in [
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XHeader,
        ] {
            let sb = Sandbox::new();
            // 宣言サイズだけ巨大で本体は無い。確保前に拒否されなければ DataLoss（切り詰め）になる。
            let e = raw_entry(b"././@LongLink", ty, b"", 0o644, 1 << 40, b"");
            assert_eq!(code(run(&sb, &[e])), OciErrorCode::ResourceExhausted);
        }
    }

    /// OCI-1: PAX の size 上書きは追跡をずらせるため拒否する。
    #[test]
    fn oci1_pax_size_override_is_rejected() {
        let sb = Sandbox::new();
        let rec = b"12 size=999\n";
        let e = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            rec.len() as u64,
            rec,
        );
        assert_eq!(
            code(run(&sb, &[e, file("f", 0o644, b"x")])),
            OciErrorCode::InvalidArgument
        );
    }

    /// OCI-1: PAX の path 値に ` size=` を含むだけの正常な tar は拒否しない。
    #[test]
    fn oci1_pax_path_containing_size_text_is_accepted() {
        let sb = Sandbox::new();
        let body = pax_record("path", "a size=b.txt");
        let e = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            body.len() as u64,
            &body,
        );
        let r = run(&sb, &[e, file("ignored", 0o644, b"x")]);
        assert!(r.is_ok(), "{r:?}");
    }

    /// OCI-1: 構文違反の PAX レコードは構造化エラーで拒否する（パニックしない）。
    #[test]
    fn oci1_pax_malformed_record_is_rejected() {
        for bad in [
            &b"999 size=1\n"[..],
            b"x size=1\n",
            b"3 a\n",
            b"12 size=999",
            // 長さ欄が後続行にまたがるレコード（埋め込み size を隠す）は tar crate と同様に不整合として拒否する。
            b"22 path=a\n12 size=999\n",
        ] {
            assert_eq!(
                pax_reject_unsupported_records(bad).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData,
                "{bad:?}"
            );
        }
    }

    fn pax_record(key: &str, val: &str) -> Vec<u8> {
        let base = key.len() + val.len() + 3;
        let mut n = base;
        while n.to_string().len() + base != n {
            n = base + n.to_string().len();
        }
        format!("{n} {key}={val}\n").into_bytes()
    }

    /// OCI-1: 前のレコードの長さ欄に隠された埋め込み `size` 行も拒否する（改行で先に分割する）。
    #[test]
    fn oci1_pax_embedded_size_record_is_rejected() {
        let sb = Sandbox::new();
        // 1 行目の長さ欄が 2 行分を指していても、tar crate は改行で分割して `size` 行を解釈する。
        for rec in [
            &b"22 path=a\n12 size=999\n"[..],
            b"10 path=a\n12 size=999\n",
        ] {
            let e = raw_entry(
                b"pax",
                EntryType::XHeader,
                b"",
                0o644,
                rec.len() as u64,
                rec,
            );
            assert_eq!(
                code(run(&sb, &[e, file("f", 0o644, b"x")])),
                OciErrorCode::InvalidArgument
            );
        }
    }

    /// OCI-1: symlink のターゲットがルートより上へ出るものは拒否、収まるものは成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_targets_are_confined() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("x", "../../etc")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("y", "..")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("z", "/..")])),
            OciErrorCode::PermissionDenied
        );
        assert!(fs::symlink_metadata(sb.root.join("x")).is_err());
        sb.assert_outside_untouched();

        let sb = Sandbox::new();
        run(
            &sb,
            &[
                symlink("a/b/rel", "../sibling"),
                symlink("abs", "/usr/bin/x"),
                symlink("dotdot", "a/b/../.."),
            ],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(sb.root.join("a/b/rel")).unwrap(),
            PathBuf::from("../sibling")
        );
        assert_eq!(
            fs::read_link(sb.root.join("abs")).unwrap(),
            PathBuf::from("/usr/bin/x")
        );
        sb.assert_outside_untouched();
    }

    /// OCI-1: ルートを指す絶対 symlink 越しの書き込みは、ホストではなく `root` 配下に作られる。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_traversal_stays_inside_root() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[symlink("link", "/"), file("link/etc/x", 0o644, b"in")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("etc/x")).unwrap(), b"in");
        sb.assert_outside_untouched();

        // 相対で上へ登るリンク経由でもルートで止まる。
        let sb = Sandbox::new();
        run(
            &sb,
            &[
                dir("d/", 0o755),
                symlink("d/up", "../"),
                file("d/up/d/up/f", 0o644, b"f"),
            ],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"f");
        sb.assert_outside_untouched();
    }

    /// OCI-1: symlink を指す名前への書き込みはリンク先に追従せず、リンクを置換する。
    #[cfg(unix)]
    #[test]
    fn oci1_write_over_symlink_replaces_link() {
        let sb = Sandbox::new();
        // ルート外の実在ファイル（番兵）のホスト絶対パスを指す symlink をレイヤーで置く。絶対ターゲットは
        // 展開時にはルート基準で解決するが、OS が素朴に追従すればホストの番兵へ届く。
        let victim = sb.base.join("sentinel");
        let target = victim.to_str().unwrap();
        run(&sb, &[symlink("t", target), file("t", 0o644, b"new")]).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"s");
        assert!(fs::symlink_metadata(sb.root.join("t")).unwrap().is_file());
        assert_eq!(fs::read(sb.root.join("t")).unwrap(), b"new");
        sb.assert_outside_untouched();
    }

    /// OCI-1: ループする symlink は追従回数の上限で拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_loop_is_rejected() {
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                symlink("a", "b"),
                symlink("b", "a"),
                file("a/x", 0o644, b"x"),
            ],
        );
        assert_eq!(code(r), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1: エントリ数は上限ちょうどが成功し、上限 + 1 は中断して以降を作らない。
    #[test]
    fn oci1_entry_count_limit() {
        let es = [
            file("a", 0o644, b"1"),
            file("b", 0o644, b"2"),
            file("c", 0o644, b"3"),
        ];
        let sb = Sandbox::new();
        let r = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(3, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.entries, 3);

        let sb = Sandbox::new();
        let e = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(2, 100, 1 << 30, 1 << 20),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(sb.root.join("b").exists());
        assert!(!sb.root.join("c").exists());
    }

    /// OCI-1: 累積サイズは上限ちょうどが成功し、超過は中断する。巨大な宣言サイズは書き込み前に拒否する。
    #[test]
    fn oci1_total_bytes_limit() {
        let es = [file("a", 0o644, b"1234"), file("b", 0o644, b"5678")];
        let sb = Sandbox::new();
        let r = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 8, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.bytes, 8);

        let sb = Sandbox::new();
        let e = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 7, 1 << 30, 1 << 20),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(!sb.root.join("b").exists());

        let sb = Sandbox::new();
        let huge = raw_entry(b"big", EntryType::Regular, b"", 0o644, 10 << 30, b"tiny");
        assert_eq!(code(run(&sb, &[huge])), OciErrorCode::ResourceExhausted);
        assert!(!sb.root.join("big").exists());
    }

    /// OCI-1: hardlink はルート内の通常ファイルへのみ成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_hardlink_rules() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[file("orig", 0o644, b"data"), hardlink("sub/copy", "orig")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("sub/copy")).unwrap(), b"data");

        for (es, want) in [
            (
                vec![hardlink("h", "../sentinel")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![hardlink("h", "/etc/passwd")],
                OciErrorCode::PermissionDenied,
            ),
            (vec![hardlink("h", "missing")], OciErrorCode::NotFound),
            (
                vec![symlink("s", "orig"), hardlink("h", "s")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![dir("d/", 0o755), hardlink("h", "d")],
                OciErrorCode::PermissionDenied,
            ),
        ] {
            let sb = Sandbox::new();
            assert_eq!(code(run(&sb, &es)), want);
            sb.assert_outside_untouched();
        }
    }

    /// OCI-1: 自分自身への hardlink（f → f）は参照元を削除せず成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_hardlink_to_self_keeps_file() {
        let sb = Sandbox::new();
        run(&sb, &[file("f", 0o644, b"data"), hardlink("f", "f")]).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
    }

    /// OCI-1: デバイス・FIFO は拒否する。
    #[test]
    fn oci1_special_entries_are_rejected() {
        for ty in [EntryType::Char, EntryType::Block, EntryType::Fifo] {
            let sb = Sandbox::new();
            let e = raw_entry(b"dev", ty, b"", 0o644, 0, b"");
            assert_eq!(
                code(run(&sb, &[e])),
                OciErrorCode::PermissionDenied,
                "{ty:?}"
            );
            assert!(!sb.root.join("dev").exists());
        }
    }

    /// OCI-1: sparse エントリは拒否する（tar 側の解析で不正な sparse ヘッダとして DataLoss になる）。
    #[test]
    fn oci1_sparse_entry_is_rejected() {
        let sb = Sandbox::new();
        let e = raw_entry(b"sp", EntryType::GNUSparse, b"", 0o644, 0, b"");
        assert_eq!(code(run(&sb, &[e])), OciErrorCode::DataLoss);
        assert!(!sb.root.join("sp").exists());
    }

    /// OCI-1: PAX 形式の GNU sparse（`GNU.sparse.*` キー + 通常ファイルの typeflag）は、穴を詰めた内容のまま
    /// 通常ファイルとして展開せずに拒否する。値やパスに同じ文字列を含むだけの PAX レコードは通す。
    #[test]
    fn oci1_pax_gnu_sparse_entry_is_rejected() {
        let pax = |rec: &[u8]| {
            raw_entry(
                b"pax",
                EntryType::XHeader,
                b"",
                0o644,
                rec.len() as u64,
                rec,
            )
        };
        for (key, val) in [
            // 0.0
            ("GNU.sparse.size", "1073741824"),
            ("GNU.sparse.numblocks", "1"),
            // 0.1
            ("GNU.sparse.map", "0,4"),
            // 1.0
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.realsize", "1073741824"),
            ("GNU.sparse.name", "sp"),
        ] {
            let sb = Sandbox::new();
            let e = run(
                &sb,
                &[pax(&pax_record(key, val)), file("sp", 0o644, b"data")],
            )
            .expect_err(key);
            assert_eq!(e.code(), OciErrorCode::DataLoss, "{key}");
            assert_eq!(e.message(), "sparse entries are not supported", "{key}");
            assert_eq!(names_in(&sb.root), Vec::<String>::new(), "{key}");
        }

        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                pax(&pax_record("path", "GNU.sparse.size")),
                file("ignored", 0o644, b"data"),
                pax(&pax_record("comment", "GNU.sparse.map=0,4")),
                file("f", 0o644, b"x"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (2, 5));
        assert_eq!(names_in(&sb.root), ["GNU.sparse.size", "f"]);
        assert_eq!(fs::read(sb.root.join("GNU.sparse.size")).unwrap(), b"data");
    }

    /// OCI-1: 旧 GNU sparse（通常 typeflag + isextended）は拒否する（ヘッダ境界の追跡ずれを防ぐ）。
    #[test]
    fn oci1_old_gnu_sparse_isextended_is_rejected() {
        let sb = Sandbox::new();
        let mut e = file("old", 0o644, b"");
        // GNU ヘッダの isextended は offset 482。チェックサムを再計算する。
        e[482] = 1;
        let mut h = tar::Header::from_byte_slice(&e[..512]).clone();
        h.set_cksum();
        e[..512].copy_from_slice(h.as_bytes());
        assert_eq!(code(run(&sb, &[e])), OciErrorCode::DataLoss);
    }

    /// OCI-1: 末尾ドット・空白付きの `..` は全 OS で脱出として拒否する。
    #[test]
    fn oci1_dotdot_variants_are_rejected() {
        for p in ["a/.. /b", "a/.../b", "a/... /b", ".. "] {
            for win in [false, true] {
                assert!(
                    normalize_entry_path_for(p.as_bytes(), win).is_err(),
                    "{p} win={win}"
                );
            }
        }
        assert!(normalize_entry_path_for(b"a/./b", false).is_ok());
        assert!(normalize_entry_path_for(b"a/.hidden", false).is_ok());
        assert!(normalize_entry_path_for(b"a/foo.", false).is_ok());
    }

    /// OCI-1: Windows ホストでは末尾ドット・空白と予約デバイス名を拒否する。他 OS では通す。
    #[test]
    fn oci1_windows_names_are_rejected_on_windows_only() {
        for p in [
            "CON",
            "con.txt",
            "a/Nul",
            "AUX.tar.gz",
            "COM1",
            "lpt9.x",
            "prn ",
            "foo.",
            "bar ",
        ] {
            assert!(normalize_entry_path_for(p.as_bytes(), true).is_err(), "{p}");
        }
        for p in ["CON", "aux.c", "foo.", "COM0", "COM10", "console", "nul2"] {
            assert!(normalize_entry_path_for(p.as_bytes(), false).is_ok(), "{p}");
        }
        for p in ["COM0", "COM10", "console", "nul2"] {
            assert!(normalize_entry_path_for(p.as_bytes(), true).is_ok(), "{p}");
        }
    }

    /// OCI-1: 所有者権限のないディレクトリの下にも子を作れ、最終 mode は元の値になる。
    #[cfg(unix)]
    #[test]
    fn oci1_zero_mode_directory_accepts_children_then_restores() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(&sb, &[dir("z/", 0o000), file("z/child", 0o644, b"c")]).unwrap();
        let m = fs::metadata(sb.root.join("z"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(m, 0);
        restore_perms(&sb.root);
        assert_eq!(fs::read(sb.root.join("z/child")).unwrap(), b"c");
    }

    /// OCI-1: 後勝ち・ディレクトリ上へのファイルは拒否・長いパス（GNU long name）。
    #[test]
    fn oci1_duplicates_and_long_names() {
        let sb = Sandbox::new();
        run(&sb, &[file("f", 0o644, b"one"), file("f", 0o644, b"two")]).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"two");

        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[dir("d/", 0o755), file("d", 0o644, b"x")])),
            OciErrorCode::FailedPrecondition
        );

        let sb = Sandbox::new();
        let long: String = (0..8)
            .map(|i| format!("{}{i}/", "d".repeat(60)))
            .collect::<String>()
            + "leaf";
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"ok"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        extract_tar(
            bytes.as_slice(),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join(&long)).unwrap(), b"ok");
    }

    /// OCI-1: 途中で切れた tar は DataLoss。
    #[test]
    fn oci1_truncated_tar_is_data_loss() {
        let sb = Sandbox::new();
        let mut bytes = archive(&[file("f", 0o644, &[7u8; 2000])]);
        bytes.truncate(512 + 700);
        let e = extract_tar(
            bytes.as_slice(),
            &sb.root,
            ExtractLimits::new(10, 1 << 20, 1 << 30, 1 << 20),
        )
        .expect_err("truncated");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// OCI-1: gzip トレーラ破損は終端後の読み捨てで DataLoss になる。上限は gzip 側でも効く。
    #[test]
    fn oci1_gzip_trailer_is_verified_after_tar_end() {
        use crate::layer::GzipLayerReader;
        let tar_bytes = archive(&[file("f", 0o644, b"hello")]);
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar_bytes).unwrap();
        let gz = e.finish().unwrap();

        let sb = Sandbox::new();
        let r = extract_tar(
            GzipLayerReader::new(gz.as_slice(), 1 << 20),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.bytes, 5);

        let mut bad = gz.clone();
        let n = bad.len();
        bad[n - 8] ^= 0xff; // CRC32 を壊す。
        let sb = Sandbox::new();
        let e = extract_tar(
            GzipLayerReader::new(bad.as_slice(), 1 << 20),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .expect_err("crc");
        assert_eq!(e.code(), OciErrorCode::DataLoss);

        let sb = Sandbox::new();
        let e = extract_tar(
            GzipLayerReader::new(gz.as_slice(), 600),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .expect_err("gzip limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// REPAIR-4: 成功と失敗でそれぞれ 1 件、種別 `oci.layer.extract` が記録される。
    #[test]
    fn repair4_records_extract_operation() {
        let c = Collect::default();
        let sb = Sandbox::new();
        extract_tar_with(
            &c,
            archive(&[file("f", 0o644, b"x")]).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 10, 1 << 30, 1 << 20),
        )
        .unwrap();
        // 展開先は空である必要があるため、失敗側は別のステージングで行う。
        let sb = Sandbox::new();
        extract_tar_with(
            &c,
            archive(&[file("../f", 0o644, b"x")]).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 10, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        let items = c.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind().as_str(), "oci.layer.extract");
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }

    /// REPAIR-4: blob を開く失敗（不存在）も `oci.layer.extract` の失敗として記録される。
    #[test]
    fn repair4_records_blob_open_failure() {
        let c = Collect::default();
        let sb = Sandbox::new();
        let missing = sb.base.join("no-such-blob");
        let e = extract_layer_blob_with(
            &c,
            &missing,
            &sb.root,
            1 << 20,
            ExtractLimits::new(1, 1, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind().as_str(), "oci.layer.extract");
        assert_eq!(items[0].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[0].error_code(), Some(e.code()));
    }

    /// 終端後に巨大データを付加した入力は、ファイル本体が 0 件でも入力上限で打ち切る（OCI-1）。
    #[test]
    fn trailing_garbage_exceeding_input_limit_is_rejected() {
        let sb = Sandbox::new();
        let mut bytes = archive(&[]);
        bytes.extend(std::iter::repeat_n(0u8, 1 << 20));
        let e = extract_tar(
            bytes.as_slice(),
            &sb.root,
            ExtractLimits::new(0, 0, 64 * 1024, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// 入力がちょうど上限バイトなら受理する（境界）。
    #[test]
    fn input_exactly_at_limit_is_accepted() {
        let sb = Sandbox::new();
        let bytes = archive(&[]);
        let len = bytes.len() as u64;
        extract_tar(
            bytes.as_slice(),
            &sb.root,
            ExtractLimits::new(0, 0, len, 1 << 20),
        )
        .unwrap();
        let sb2 = Sandbox::new();
        let e = extract_tar(
            bytes.as_slice(),
            &sb2.root,
            ExtractLimits::new(0, 0, len - 1, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// root が通常ファイルなら InvalidArgument。
    #[test]
    fn root_must_be_directory() {
        let sb = Sandbox::new();
        let f = sb.base.join("sentinel");
        let e = extract_tar(
            archive(&[]).as_slice(),
            &f,
            ExtractLimits::new(1, 1, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// 非 unix ホストでは symlink エントリを Unimplemented で拒否する。
    #[cfg(not(unix))]
    #[test]
    fn symlink_is_unimplemented_on_non_unix() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("a", "b")])),
            OciErrorCode::Unimplemented
        );
    }

    // ---- 複数レイヤーの重ね合わせ（TASK-52.4・OCI-1・#410） ----

    const LIM: fn() -> ExtractLimits = || ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20);

    fn run_stack(
        sb: &Sandbox,
        layers: &[Vec<Vec<u8>>],
        limits: ExtractLimits,
        lstat: Lstat,
    ) -> Result<Vec<ExtractedLayer>, OciError> {
        let tars: Vec<Vec<u8>> = layers.iter().map(|l| archive(l)).collect();
        extract_stack(
            &NoopOciOpRecorder,
            tars.iter().map(|t| t.as_slice()),
            Ok,
            &sb.root,
            limits,
            lstat,
        )
    }

    /// OCI-1: 上位レイヤーが下位の同名ファイルを上書きし、下位だけのファイルは残る。結果はレイヤーごと。
    #[test]
    fn oci1_stack_upper_layer_overwrites_lower() {
        let sb = Sandbox::new();
        let r = run_stack(
            &sb,
            &[
                vec![file("f", 0o644, b"lower-long"), file("keep", 0o644, b"k")],
                vec![file("f", 0o644, b"up"), file("new", 0o644, b"n")],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap();
        assert_eq!(
            r.iter().map(|l| (l.entries, l.bytes)).collect::<Vec<_>>(),
            vec![(2, 11), (2, 3)]
        );
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"up");
        assert_eq!(fs::read(sb.root.join("keep")).unwrap(), b"k");
        assert_eq!(fs::read(sb.root.join("new")).unwrap(), b"n");
        assert_eq!(names_in(&sb.root), vec!["f", "keep", "new"]);
    }

    /// OCI-1: root が空でなければ最初のレイヤーの前に拒否し、既存項目に触れない。
    #[test]
    fn oci1_stack_rejects_non_empty_root() {
        let sb = Sandbox::new();
        fs::write(sb.root.join("pre"), b"x").unwrap();
        let e = run_stack(&sb, &[vec![file("f", 0o644, b"a")]], LIM(), host_lstat).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(names_in(&sb.root), vec!["pre"]);
    }

    /// OCI-1: 空のレイヤー列は InvalidArgument。
    #[test]
    fn oci1_stack_rejects_empty_layer_list() {
        let sb = Sandbox::new();
        let e = run_stack(&sb, &[], LIM(), host_lstat).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// OCI-1: エントリ数の上限は全レイヤーで累積する（各レイヤーは 2 件、上限 3）。
    #[test]
    fn oci1_stack_entry_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [
            vec![file("a", 0o644, b"1"), file("b", 0o644, b"1")],
            vec![file("c", 0o644, b"1"), file("d", 0o644, b"1")],
        ];
        let e = run_stack(
            &sb,
            &layers,
            ExtractLimits::new(3, 1 << 20, 1 << 30, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the entry count limit");
    }

    /// OCI-1: 展開バイト数の上限は全レイヤーで累積する（各 6 バイト、上限 10）。
    #[test]
    fn oci1_stack_total_bytes_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [
            vec![file("a", 0o644, b"123456")],
            vec![file("b", 0o644, b"123456")],
        ];
        let e = run_stack(
            &sb,
            &layers,
            ExtractLimits::new(100, 10, 1 << 30, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// OCI-1: 入力バイト数の上限も全レイヤーで累積する（1 レイヤー 2048 バイト、上限 3000）。
    #[test]
    fn oci1_stack_input_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [vec![file("a", 0o644, b"1")], vec![file("b", 0o644, b"1")]];
        // 1 レイヤーは 512（ヘッダ）+ 512（データ）+ 1024（終端）= 2048 バイト。
        assert!(
            run_stack(
                &sb,
                &layers[..1],
                ExtractLimits::new(100, 1 << 20, 3000, 1 << 20),
                host_lstat
            )
            .is_ok()
        );
        let sb2 = Sandbox::new();
        let e = run_stack(
            &sb2,
            &layers,
            ExtractLimits::new(100, 1 << 20, 3000, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer tar stream exceeds the input size limit");
    }

    /// IO-5 / OCI-1: 別表記の衝突検出はレイヤーをまたいで効く（下位の `f` に上位が `F` の hardlink を張れない）。
    #[test]
    fn io5_stack_alias_spelling_collision_across_layers() {
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[vec![file("f", 0o644, b"orig")], vec![hardlink("F", "f")]],
            LIM(),
            folding_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"orig");
        assert_eq!(names_in(&sb.root), vec!["f"]);
    }

    /// OCI-1: 上位レイヤーの `..` は既存どおり拒否され、ルート外へは何も書かれない。
    #[test]
    fn oci1_stack_upper_layer_traversal_is_rejected() {
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[
                vec![file("f", 0o644, b"a")],
                vec![file("../escape", 0o644, b"x")],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        sb.assert_outside_untouched();
    }

    /// OCI-1: 上位レイヤーがディレクトリの位置へファイルを置く置換は未実装で、fail-closed に拒否する。
    #[test]
    fn oci1_stack_dir_to_file_replacement_is_rejected() {
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[
                vec![dir("d/", 0o755), file("d/x", 0o644, b"x")],
                vec![file("d", 0o644, b"f")],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"x");
    }

    /// OCI-1: 下位が 0555 のディレクトリへ上位が書き込め、最終 mode は 0555（遅延適用は全レイヤー後）。
    #[cfg(unix)]
    #[test]
    fn oci1_stack_upper_writes_into_readonly_lower_dir() {
        let sb = Sandbox::new();
        run_stack(
            &sb,
            &[vec![dir("d/", 0o555)], vec![file("d/x", 0o644, b"up")]],
            LIM(),
            host_lstat,
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"up");
        assert_eq!(mode_of(&sb.root.join("d")), 0o555);
    }

    /// REPAIR-4: 各レイヤーを ExtractLayer として 1 回ずつ記録する。
    #[test]
    fn repair4_stack_records_one_sample_per_layer() {
        let sb = Sandbox::new();
        let rec = Collect::default();
        let tars = [
            archive(&[file("a", 0o644, b"1")]),
            archive(&[file("b", 0o644, b"1")]),
        ];
        extract_layers_with(&rec, tars.iter().map(|t| t.as_slice()), &sb.root, LIM()).unwrap();
        let s = rec.0.lock().unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.kind() == OciOpKind::ExtractLayer));
        assert!(s.iter().all(|x| x.outcome() == OciOpOutcome::Success));
    }

    /// REPAIR-4: 最終のディレクトリ権限適用（finish_dirs）の失敗は最後のレイヤーの記録に Failure として含まれる。
    #[test]
    fn repair4_finish_dirs_failure_is_recorded() {
        struct SwapAtEof {
            data: std::io::Cursor<Vec<u8>>,
            dir: PathBuf,
            done: bool,
        }
        impl Read for SwapAtEof {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.data.read(buf)?;
                if n == 0 && !self.done {
                    self.done = true;
                    fs::remove_dir(&self.dir)?;
                    fs::write(&self.dir, b"x")?;
                }
                Ok(n)
            }
        }
        let sb = Sandbox::new();
        let rec = Collect::default();
        let src = SwapAtEof {
            data: std::io::Cursor::new(archive(&[dir("d", 0o555)])),
            dir: sb.root.join("d"),
            done: false,
        };
        let e = extract_layers_with(&rec, [src], &sb.root, LIM()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let s = rec.items();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), OciOpOutcome::Failure);
        assert_eq!(s[0].error_code(), Some(OciErrorCode::FailedPrecondition));
    }

    /// 空レイヤーを無限に供給してもレイヤー数の上限で ResourceExhausted になる（結果 Vec が増え続けない）。
    #[test]
    fn stack_rejects_unbounded_empty_layers() {
        let sb = Sandbox::new();
        let layers = std::iter::repeat_with(std::io::empty);
        let e = extract_layers(layers, &sb.root, LIM()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "image exceeds the layer count limit");
    }

    // ---- whiteout の対象削除（TASK-53.1・OCI-2・#412） ----

    fn ex_for(sb: &Sandbox, lstat: Lstat) -> Extractor<'_> {
        let limits = LIM();
        Extractor {
            root: &sb.root,
            limits,
            entries: 0,
            bytes: 0,
            stripped_special: 0,
            deferred_dirs: BTreeMap::new(),
            names: NameIndex::new(limits.max_tracked_paths),
            lstat,
        }
    }

    fn lay(ex: &mut Extractor<'_>, entries: &[Vec<u8>]) {
        extract_one_layer(ex, archive(entries).as_slice(), 1 << 30).unwrap();
    }

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// OCI-2: 下位の `d/foo` を whiteout すると rootfs から消え、同じディレクトリの `d/bar` は残る。
    #[test]
    fn oci2_whiteout_removes_lower_file_and_keeps_siblings() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("d/foo", 0o644, b"1"), file("d/bar", 0o644, b"2")],
        );
        ex.remove_whiteout_target(&os(&["d"]), OsStr::new("foo"))
            .unwrap();
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root.join("d")), vec!["bar".to_string()]);
        assert!(!sb.root.join("d/foo").exists());
        sb.assert_outside_untouched();
    }

    /// OCI-2: ディレクトリの whiteout は中身ごと再帰削除し、深いツリー・0555 の中間ディレクトリも消せる。
    #[test]
    #[cfg(unix)]
    fn oci2_whiteout_removes_directory_tree_recursively() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/sub/x", 0o644, b"1"),
                dir("d/ro", 0o755),
                file("d/ro/c", 0o644, b"c"),
                file("keep", 0o644, b"k"),
            ],
        );
        // 深いツリー（tar の名前長の制約を避け、ディスク上に直接作る）と、権限を落とした中間ディレクトリ。
        let deep: PathBuf = (0..60).map(|i| format!("n{i}")).collect();
        fs::create_dir_all(sb.root.join("d").join(&deep)).unwrap();
        fs::write(sb.root.join("d").join(&deep).join("leaf"), b"z").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(sb.root.join("d/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        }
        ex.remove_whiteout_target(&[], OsStr::new("d")).unwrap();
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root), vec!["keep".to_string()]);
        sb.assert_outside_untouched();
    }

    /// OCI-2: symlink を whiteout してもリンク先の実体は残る。親が symlink でも root 外へ出ない。
    #[test]
    #[cfg(unix)]
    fn oci2_whiteout_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/f", 0o644, b"r"),
                symlink("link", "real"),
                symlink("esc", "/"),
                file("real/g", 0o644, b"g"),
            ],
        );
        ex.remove_whiteout_target(&[], OsStr::new("link")).unwrap();
        assert!(fs::symlink_metadata(sb.root.join("link")).is_err());
        assert_eq!(fs::read(sb.root.join("real/f")).unwrap(), b"r");
        // 親が root 外を指す symlink でも root に閉じ込められ、外部の番兵は無傷。
        ex.remove_whiteout_target(&os(&["esc"]), OsStr::new("sentinel"))
            .unwrap();
        ex.remove_whiteout_target(&os(&["real"]), OsStr::new("g"))
            .unwrap();
        assert_eq!(names_in(&sb.root.join("real")), vec!["f".to_string()]);
        sb.assert_outside_untouched();
    }

    /// OCI-2: 存在しない対象・存在しない親は何もしない。親が非ディレクトリなら FailedPrecondition。
    #[test]
    fn oci2_whiteout_missing_target_or_parent_is_noop() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        ex.remove_whiteout_target(&[], OsStr::new("nope")).unwrap();
        ex.remove_whiteout_target(&os(&["no", "dir"]), OsStr::new("x"))
            .unwrap();
        let e = ex
            .remove_whiteout_target(&os(&["f"]), OsStr::new("x"))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
    }

    /// OCI-2: 遅延 mode のディレクトリ（mode 0）を whiteout した後でも `finish_dirs` が成功する。
    #[test]
    fn oci2_whiteout_clears_deferred_dir_modes() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[dir("d", 0o000), file("d/f", 0o644, b"x")]);
        ex.remove_whiteout_target(&[], OsStr::new("d")).unwrap();
        ex.finish_dirs().unwrap();
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-2・IO-5: 別表記（大文字小文字）で既存の実体へ解決される whiteout は削除せず AlreadyExists。
    #[test]
    fn oci2_whiteout_alias_spelling_is_rejected_without_removal() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        let e = ex.remove_whiteout_target(&[], OsStr::new("F")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
    }

    /// OCI-2: 削除後、上位レイヤーが同名を再作成できる。
    #[test]
    fn oci2_whiteout_then_upper_layer_can_recreate_name() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("foo", 0o644, b"old")]);
        ex.remove_whiteout_target(&[], OsStr::new("foo")).unwrap();
        lay(&mut ex, &[file("foo", 0o644, b"new")]);
        ex.finish_dirs().unwrap();
        assert_eq!(fs::read(sb.root.join("foo")).unwrap(), b"new");
    }

    /// OCI-2・IO-5: 削除した名前の旧綴りで、再作成された別表記の実体を whiteout できない（AlreadyExists）。
    #[test]
    fn oci2_whiteout_forgets_removed_spellings_of_recreated_tree() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[dir("D", 0o755), file("D/F", 0o644, b"old")]);
        ex.remove_whiteout_target(&[], OsStr::new("D")).unwrap();
        lay(&mut ex, &[dir("d", 0o755), file("d/f", 0o644, b"new")]);
        let e = ex
            .remove_whiteout_target(&os(&["d"]), OsStr::new("F"))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        let e = ex.remove_whiteout_target(&[], OsStr::new("D")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"new");
    }

    // ---- 不透明ディレクトリ（TASK-53.2・OCI-2・#413） ----

    /// OCI-2: 不透明ディレクトリは下位由来の子を隠し、上位の子だけが残る。ディレクトリ自体と他は残る。
    #[test]
    fn oci2_opaque_hides_lower_files_in_dir() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/a", 0o644, b"1"),
                file("d/sub/b", 0o644, b"2"),
                file("other/x", 0o644, b"3"),
                file("top", 0o644, b"4"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        lay(&mut ex, &[file("d/new", 0o644, b"n")]);
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root.join("d")), vec!["new".to_string()]);
        assert_eq!(fs::read(sb.root.join("d/new")).unwrap(), b"n");
        assert_eq!(fs::read(sb.root.join("other/x")).unwrap(), b"3");
        assert_eq!(fs::read(sb.root.join("top")).unwrap(), b"4");
        sb.assert_outside_untouched();
    }

    /// OCI-2: root 直下の不透明は中身だけ消し、root は残る。
    #[test]
    fn oci2_opaque_at_root_clears_everything_but_root() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("a/b", 0o644, b"1"), file("c", 0o644, b"2")]);
        ex.clear_opaque_dir(&[]).unwrap();
        assert!(sb.root.is_dir());
        assert!(names_in(&sb.root).is_empty());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 不透明適用後もディレクトリの mode は維持され、0555・0000 の子と深いツリーも消せる。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_keeps_dir_mode_and_removes_readonly_children() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("d", 0o750),
                file("d/ro/c", 0o644, b"c"),
                dir("d/zero", 0o000),
            ],
        );
        let deep: PathBuf = (0..60).map(|i| format!("n{i}")).collect();
        fs::create_dir_all(sb.root.join("d").join(&deep)).unwrap();
        fs::set_permissions(sb.root.join("d/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        ex.finish_dirs().unwrap();
        assert!(names_in(&sb.root.join("d")).is_empty());
        let mode = fs::metadata(sb.root.join("d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o750);
        sb.assert_outside_untouched();
    }

    /// OCI-2: 子の symlink はリンクのみ消えリンク先は残る。親が root 外を指す symlink でも root に閉じ込める。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/f", 0o644, b"r"),
                dir("d", 0o755),
                symlink("d/lnk", "../real"),
                symlink("esc", "/"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        assert!(fs::symlink_metadata(sb.root.join("d/lnk")).is_err());
        assert_eq!(fs::read(sb.root.join("real/f")).unwrap(), b"r");
        // 絶対ターゲット `/` は root へ戻されるため、消えるのは root 配下の中身だけ（root 自体は残る）。
        ex.clear_opaque_dir(&os(&["esc"])).unwrap();
        assert!(sb.root.is_dir());
        assert!(names_in(&sb.root).is_empty());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 存在しない親は何もせず、親が通常ファイルなら FailedPrecondition。
    #[test]
    fn oci2_opaque_missing_dir_is_noop_and_file_parent_is_rejected() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        ex.clear_opaque_dir(&os(&["no", "dir"])).unwrap();
        let e = ex.clear_opaque_dir(&os(&["f"])).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
    }

    /// OCI-2: 配下・トップ自身が mode 0 の遅延ディレクトリでも `finish_dirs` が成功し、トップの mode は復元される。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_clears_deferred_modes_of_descendants() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("d", 0o000),
                dir("d/s", 0o000),
                file("d/s/f", 0o644, b"x"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        ex.finish_dirs().unwrap();
        let mode = fs::metadata(sb.root.join("d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o000);
        fs::set_permissions(sb.root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(names_in(&sb.root.join("d")).is_empty());
    }

    /// OCI-2・IO-5: 中身を消した後、旧綴りの別表記で再作成された実体を操作できない（AlreadyExists）。
    #[test]
    fn oci2_opaque_forgets_removed_spellings() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[dir("d", 0o755), file("d/F", 0o644, b"old")]);
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        lay(&mut ex, &[file("d/f", 0o644, b"new")]);
        let e = ex
            .remove_whiteout_target(&os(&["d"]), OsStr::new("F"))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"new");
    }

    /// OCI-2・IO-5: 親の別表記は削除せず AlreadyExists。
    #[test]
    fn oci2_opaque_alias_parent_is_rejected_without_removal() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[file("d/f", 0o644, b"x")]);
        let e = ex.clear_opaque_dir(&os(&["D"])).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"x");
    }

    // ---- パイプラインへの統合（TASK-53.3・OCI-2・#414） ----

    fn wh(name: &str) -> Vec<u8> {
        file(name, 0o644, b"")
    }

    fn lay_err(ex: &mut Extractor<'_>, entries: &[Vec<u8>]) -> OciErrorCode {
        extract_one_layer(ex, archive(entries).as_slice(), 1 << 30)
            .unwrap_err()
            .code()
    }

    /// OCI-2: 上位レイヤーの `.wh.foo` は下位の `d/foo` だけを消し、マーカーは rootfs に残らない。
    #[test]
    fn oci2_pipeline_whiteout_removes_lower_only() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("d/foo", 0o644, b"1"), file("d/bar", 0o644, b"2")],
        );
        lay(&mut ex, &[wh("d/.wh.foo")]);
        assert_eq!(names_in(&sb.root.join("d")), vec!["bar".to_string()]);
    }

    /// OCI-2: 同一レイヤー内では `foo` と `.wh.foo` のどちらが先でも `foo` は残る（下位の `foo` は置換）。
    #[test]
    fn oci2_pipeline_same_layer_order_independent() {
        for entries in [
            vec![file("d/foo", 0o644, b"new"), wh("d/.wh.foo")],
            vec![wh("d/.wh.foo"), file("d/foo", 0o644, b"new")],
        ] {
            let sb = Sandbox::new();
            let mut ex = ex_for(&sb, host_lstat);
            lay(&mut ex, &[file("d/foo", 0o644, b"old")]);
            lay(&mut ex, &entries);
            assert_eq!(fs::read(sb.root.join("d/foo")).unwrap(), b"new");
            assert_eq!(names_in(&sb.root.join("d")), vec!["foo".to_string()]);
        }
    }

    /// OCI-2: ディレクトリの whiteout は木ごと消す。
    #[test]
    fn oci2_pipeline_whiteout_directory_tree() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("a/b/c", 0o644, b"1"), file("keep", 0o644, b"k")],
        );
        lay(&mut ex, &[wh(".wh.a")]);
        assert_eq!(names_in(&sb.root), vec!["keep".to_string()]);
    }

    /// OCI-2: 不透明ディレクトリは下位の子を消し、マーカーの前後どちらの同レイヤーの子も残す。
    #[test]
    fn oci2_pipeline_opaque_keeps_same_layer_children() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/old", 0o644, b"o"),
                file("d/sub/x", 0o644, b"x"),
                file("e", 0o644, b"e"),
            ],
        );
        lay(
            &mut ex,
            &[
                file("d/before", 0o644, b"b"),
                wh("d/.wh..wh..opq"),
                file("d/after", 0o644, b"a"),
            ],
        );
        assert_eq!(
            names_in(&sb.root.join("d")),
            vec!["after".to_string(), "before".to_string()]
        );
        assert!(sb.root.join("e").exists());
    }

    /// OCI-2: 下位のディレクトリを経路として通過しただけの上位は、不透明適用で下位の中身だけが消える。
    #[test]
    fn oci2_pipeline_opaque_recurses_into_traversed_lower_dir() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("d/sub/old", 0o644, b"o"), file("d/f", 0o644, b"f")],
        );
        lay(
            &mut ex,
            &[file("d/sub/new", 0o644, b"n"), wh("d/.wh..wh..opq")],
        );
        assert_eq!(names_in(&sb.root.join("d")), vec!["sub".to_string()]);
        assert_eq!(names_in(&sb.root.join("d/sub")), vec!["new".to_string()]);
    }

    /// OCI-2: root 直下の不透明マーカーは root の中身を消すが root は残す。対象が無い whiteout は冪等。
    #[test]
    fn oci2_pipeline_root_opaque_and_missing_target() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("a", 0o644, b"1"), file("d/b", 0o644, b"2")]);
        lay(&mut ex, &[wh(".wh.nothing"), wh("nodir/.wh.x")]);
        assert_eq!(names_in(&sb.root), vec!["a".to_string(), "d".to_string()]);
        lay(&mut ex, &[wh(".wh..wh..opq"), file("n", 0o644, b"n")]);
        assert_eq!(names_in(&sb.root), vec!["n".to_string()]);
    }

    /// OCI-2: 下位の mode 0 ディレクトリを `d/new` と `.wh.d` で触る並びが逆でも、最終 mode は同じ（既定 0755）。
    #[test]
    #[cfg(unix)]
    fn oci2_pipeline_whiteout_dir_mode_is_order_independent() {
        use std::os::unix::fs::PermissionsExt as _;
        for entries in [
            vec![file("d/new", 0o644, b"n"), wh(".wh.d")],
            vec![wh(".wh.d"), file("d/new", 0o644, b"n")],
        ] {
            let sb = Sandbox::new();
            let mut ex = ex_for(&sb, host_lstat);
            lay(&mut ex, &[dir("d", 0o000), file("d/old", 0o644, b"o")]);
            lay(&mut ex, &entries);
            ex.finish_dirs().unwrap();
            let mode = fs::metadata(sb.root.join("d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, 0o755);
            assert_eq!(names_in(&sb.root.join("d")), vec!["new".to_string()]);
        }
    }

    /// OCI-2: 同一パスの hardlink エントリも現在のレイヤーの実体として不透明マーカーから保護される。
    #[test]
    fn oci2_pipeline_self_hardlink_is_protected_from_opaque() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("d/f", 0o644, b"x"), file("d/g", 0o644, b"y")],
        );
        lay(&mut ex, &[hardlink("d/f", "d/f"), wh("d/.wh..wh..opq")]);
        assert_eq!(names_in(&sb.root.join("d")), vec!["f".to_string()]);
    }

    /// OCI-2: 非ゼロサイズのマーカーは削除を適用せず InvalidArgument で拒否する。
    #[test]
    fn oci2_pipeline_non_empty_markers_are_rejected() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("d/f", 0o644, b"x")]);
        assert_eq!(
            lay_err(&mut ex, &[file("d/.wh.f", 0o644, b"junk")]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            lay_err(&mut ex, &[file("d/.wh..wh..opq", 0o644, b"junk")]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(names_in(&sb.root.join("d")), vec!["f".to_string()]);
    }

    /// OCI-2: 不透明ディレクトリ配下の遅延 mode を多数持つ木でも、子の削除が全件走査に依らず終わる。
    #[test]
    fn oci2_deferred_subtree_drop_removes_only_subtree() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("a", 0o000),
                dir("a/x", 0o000),
                dir("ab", 0o000),
                dir("b", 0o000),
            ],
        );
        ex.drop_deferred_subtree(&sb.root.join("a"));
        let keys: Vec<_> = ex.deferred_dirs.keys().cloned().collect();
        assert_eq!(keys, vec![sb.root.join("ab"), sb.root.join("b")]);
    }

    /// OCI-2: マーカー名の非 Regular 型・ディレクトリ名・予約名は拒否する（実体化しない）。
    #[test]
    fn oci2_pipeline_invalid_markers_are_rejected() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        assert_eq!(
            lay_err(&mut ex, &[dir(".wh.foo", 0o755)]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            lay_err(&mut ex, &[symlink(".wh.foo", "x")]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            lay_err(&mut ex, &[file(".wh.foo/", 0o644, b"")]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            lay_err(&mut ex, &[wh(".wh..wh.plnk")]),
            OciErrorCode::InvalidArgument
        );
        assert_eq!(
            lay_err(&mut ex, &[wh(".wh...")]),
            OciErrorCode::InvalidArgument
        );
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-2・IO-5: whiteout 対象の別表記は削除せず AlreadyExists。
    #[test]
    fn oci2_pipeline_alias_target_is_rejected() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[file("d/f", 0o644, b"x")]);
        assert_eq!(
            lay_err(&mut ex, &[wh("d/.wh.F")]),
            OciErrorCode::AlreadyExists
        );
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"x");
    }

    /// OCI-2: symlink の親・対象を whiteout しても root の外へは出ず、リンク先は消えない。
    #[test]
    #[cfg(unix)]
    fn oci2_pipeline_whiteout_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/keep", 0o644, b"k"),
                symlink("lnk", "real"),
                symlink("abs", "/"),
            ],
        );
        lay(&mut ex, &[wh(".wh.lnk"), wh("abs/.wh.real")]);
        assert!(!sb.root.join("lnk").exists());
        assert!(!sb.root.join("real").exists());
        assert!(fs::symlink_metadata(sb.root.join("abs")).is_ok());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 0 / 0555 の遅延 mode ディレクトリを whiteout・不透明にしても finish_dirs が成功する。
    #[test]
    #[cfg(unix)]
    fn oci2_pipeline_deferred_dirs_survive_whiteout() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("a", 0o000),
                file("a/x", 0o644, b"x"),
                dir("o", 0o555),
                file("o/y", 0o644, b"y"),
            ],
        );
        lay(&mut ex, &[wh(".wh.a"), wh("o/.wh..wh..opq")]);
        ex.finish_dirs().unwrap();
        assert!(!sb.root.join("a").exists());
        assert_eq!(mode_of(&sb.root.join("o")) & 0o777, 0o555);
        fs::set_permissions(sb.root.join("o"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(names_in(&sb.root.join("o")).is_empty());
    }

    /// OCI-2: 大量の whiteout が妥当な時間で終わる（索引の削除が全登録の走査に依らない）。
    #[test]
    fn oci2_pipeline_many_whiteouts_complete_quickly() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        ex.limits = ExtractLimits::new(20_000, 1 << 20, 1 << 30, 20_000);
        let n = 3000;
        let lower: Vec<Vec<u8>> = (0..n)
            .map(|i| file(&format!("d/f{i}"), 0o644, b""))
            .collect();
        lay(&mut ex, &lower);
        let upper: Vec<Vec<u8>> = (0..n).map(|i| wh(&format!("d/.wh.f{i}"))).collect();
        let t = std::time::Instant::now();
        lay(&mut ex, &upper);
        assert!(t.elapsed() < std::time::Duration::from_secs(20));
        assert!(names_in(&sb.root.join("d")).is_empty());
    }

    /// OCI-2: 親コンポーネントが whiteout 名・予約名のパスは、副作用の前に InvalidArgument で拒否する。
    #[test]
    fn oci2_pipeline_marker_named_parent_is_rejected_without_side_effects() {
        for p in [".wh.foo/child", ".wh..wh.plnk/child", "a/.wh..wh..opq/x"] {
            let sb = Sandbox::new();
            let mut ex = ex_for(&sb, host_lstat);
            let c = lay_err(&mut ex, &[file(p, 0o644, b"x")]);
            assert_eq!(c, OciErrorCode::InvalidArgument, "{p}");
            assert!(names_in(&sb.root).is_empty(), "{p}");
        }
    }

    /// OCI-2: 下位の symlink を経由するエントリと、その symlink の whiteout の併用は並び順に依らず拒否する。
    #[test]
    fn oci2_pipeline_symlink_whiteout_with_traversal_is_rejected_in_both_orders() {
        for entries in [
            vec![file("lnk/new", 0o644, b"x"), wh(".wh.lnk")],
            vec![wh(".wh.lnk"), file("lnk/new", 0o644, b"x")],
        ] {
            let sb = Sandbox::new();
            let mut ex = ex_for(&sb, host_lstat);
            lay(&mut ex, &[dir("real", 0o755), symlink("lnk", "real")]);
            let c = lay_err(&mut ex, &entries);
            assert_eq!(c, OciErrorCode::InvalidArgument);
        }
    }

    /// OCI-2: 大量の不透明マーカーが同じ部分木を繰り返し走査しない（世代ごとに 1 回）。
    #[test]
    fn oci2_pipeline_many_opaque_markers_complete_quickly() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        ex.limits = ExtractLimits::new(30_000, 1 << 20, 1 << 30, 30_000);
        let mut entries: Vec<Vec<u8>> = (0..3000)
            .map(|i| file(&format!("d/f{i}"), 0o644, b""))
            .collect();
        entries.extend((0..3000).map(|_| wh("d/.wh..wh..opq")));
        let t = std::time::Instant::now();
        lay(&mut ex, &entries);
        assert!(t.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(names_in(&sb.root.join("d")).len(), 3000);
    }
}
