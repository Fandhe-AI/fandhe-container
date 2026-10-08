//! エントリポイントのインタープリタ（シェバン・ELF の `PT_INTERP`）がランタイム自身のバイナリを指す経路の拒否
//! （SUP-6・SEC-1・CORE-5・SEC-4・TASK-163 追補・#1458・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `exec/process.rs` の `prepare_exec_child`（launch の PID 1 と、稼働中コンテナへの exec の子が共有する
//! `execveat` 前の手順）が、エントリポイント本体とランタイムの同一性照合（`entrypoint_is_runtime_binary`）の
//! 直後に [`reject_runtime_interpreter`] を呼ぶ。本体の照合だけでは、`#!/proc/self/exe` と書いたスクリプトや、
//! `PT_INTERP` に `/proc/self/exe` を指定した ELF を通してしまう: カーネルは `execve` の中でインタープリタの
//! パスを **exec するプロセス自身の文脈** で開くため、`/proc/self/exe`（や `/proc/<pid>/exe`）はホスト側の
//! ランタイムのバイナリに解決され、コンテナ内でそれが実行される（CVE-2019-5736 型。実行中のプロセスの
//! `/proc/<pid>/exe` から、ホスト側のバイナリを書き換える足掛かりになる）。
//!
//! # 方式の比較と採用（#1458）
//!
//! | 方式 | 防げる範囲 | 残る前提 | 規模 |
//! | ---- | ---------- | -------- | ---- |
//! | A. 解決先の照合（本モジュール） | 検査時点でインタープリタがランタイムに解決される静的な指定すべて（シェバンの連鎖・`PT_INTERP`・symlink 経由・`/proc/<pid>/exe`） | 検査と `execve` の間にパスを差し替える競合（TOCTOU）。`binfmt_misc` | core 内で完結 |
//! | B. ランタイム自身の封印複製（memfd + `F_SEAL_*`。runc の方式。launcher・#1314 の範囲） | `/proc/self/exe` がホスト側のバイナリを指さなくなるため、経路によらず書き換えを防ぐ | 起動のたびの複製コスト（常駐メモリ。CORE-7〜9） | ランタイムの **バイナリの起動処理**（自分自身の再実行）に組み込む必要があり、ライブラリ crate の中では完結しない |
//! | B'. 照合したエントリポイント本体の封印複製（#1529・#1530・#1531。「封印した複製からの実行」節） | **エントリポイント本体の内容の書き換え**（1 行目のシェバン・`PT_INTERP` の文字列が封印されて固定される） | **インタープリタのパスの差し替え**と、インタープリタ自身の内容の書き換え（カーネルが `execve` の中でパスを解決して開く）。A と Landlock に頼る | core 内で完結（`sys` のラッパーは #1530、組み込みは #1531） |
//! | C. Landlock のみ（変更前） | ルール外のホスト側バイナリの `EXECUTE` を拒否する | Landlock の適用とルールの正しさに全面的に依存する | 実装済み |
//!
//! 本モジュールは **A** を実装する。B は最終的な対策だが、exec 専用プロセス・launcher のバイナリ（未結線）の
//! 起動処理に入れるもので本 crate の関数だけでは実現できないため、別の課題とする（下記「限界」）。A は C と
//! 独立に効く層で、Landlock が無くても静的な指定を拒否し、拒否を違反記録
//! （`entrypoint_interpreter_is_runtime_binary`。SEC-4）として返す。B' は A の上に重ねて本体の書き換えの窓を
//! 狭める方式で、設計は下記の節に決め、`sys` のラッパーまでが #1530 の範囲（組み込みは #1531）。
//!
//! # 封印した複製からの実行（B'。設計決定。#1529・#1530・#1531）
//!
//! **未実装**（REPAIR-3）: 本節は設計の決定で、`prepare_exec_child` への組み込み・違反記録（SEC-4）・差し替えの
//! 結合試験は #1531 で行う。#1530 では `sys` に `memfd_create_for_exec_copy`・`add_seals`・`get_seals`・
//! `seal_for_exec`（封印を検証した `SealedMemfd` だけを返す）を足した。実行は既存の `sys::exec_fd`
//! （`execveat(AT_EMPTY_PATH)`）を使い、重複させない。
//!
//! - **複製する対象**: エントリポイント本体（ELF・スクリプトとも）だけ。照合に使ったのと同じ開いた fd から複製する。
//!   - シェバンのインタープリタは複製しない: 閉じるには `binfmt_script` と同じ展開（argv を
//!     `[i_name, i_arg?, /dev/fd/N, argv[1..]]` に組み直す）をユーザー空間で行い、インタープリタの複製を直接
//!     `execveat` する必要がある。展開器を新設することになるため後続の候補とする（本 issue の範囲外）
//!   - `PT_INTERP` の動的リンカは複製しない: カーネルが開くのを避けるには動的リンカを明示起動する
//!     （`ld.so /dev/fd/N`）か複製内の `PT_INTERP` を書き換えるしかなく、どちらも `/proc/self/exe`・`AT_EXECFN`・
//!     `argv[0]` の意味を変えてコンテナのプログラムから見える挙動を壊すため採らない
//!   - `binfmt_misc` は従来どおり対象外（`F` フラグ付きの登録を除き、カーネルは登録されたインタープリタをパスで開く）
//! - **手順の順序（#1531 への契約）**: (1) 本体を fd で開き `(st_dev, st_ino)` をランタイムと照合する（複製は別の
//!   inode になるため、この照合だけは元のファイルに対して行う）→ (2) `fstat` の `st_size` が上限以下であることを
//!   確かめて複製する → (3) 封印する → (4) `F_GET_SEALS` が 0x0F とちょうど一致することを確かめる（`SealedMemfd`
//!   の生成条件）→ (5) シェバン・`PT_INTERP` の解析（[`reject_runtime_interpreter`] の先頭の読み取り）は
//!   **封印した複製に対して** 行う（照合用と実行用で読み取りが 2 回あると、その間の書き換えで食い違う）→ (6) スクリプト
//!   なら `/dev/fd/N` の検証を複製の metadata と比べる → (7) `execveat`
//! - **fd と close-on-exec**: `MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC` で作る（`MFD_ALLOW_SEALING` が無いと
//!   `F_ADD_SEALS` は `EPERM`）。封印の後に procfs の magic link（`reopen_pinned_read` と同じ経路）から
//!   **読み取り専用で開き直し**、書き込み用の fd を閉じてから実行する。書き込み可能な fd を exec 先へ継承させないこと、
//!   書き込み用に開いた fd が残る間の `execve` が `ETXTBSY`（`deny_write_access`）になり得ることが理由。
//!   スクリプトは既存手順どおり、実行用 fd だけ `mark_fds_cloexec` の後に close-on-exec を外す（カーネルがインタープリタへ
//!   `/dev/fd/N` を渡し、procfs の magic link 経由で memfd に解決される）。memfd の名前は固定値で、外部入力を混ぜない
//! - **サイズ上限**: 256 MiB（`MAX_SEALED_COPY_BYTES`。単体の大きいバイナリ〔node・Go の静的バイナリで 100〜150 MB
//!   程度〕に余裕を持たせ、超えるものを拒否する）。複製の前に `st_size` を上限と比べ、コピーしたバイト数が
//!   `st_size` と一致しなければ（途中で伸縮した）拒否する。定数の置き場所と強制は #1531。複製は exec の子が子 cgroup に
//!   参加した後に作るため、コンテナの `memory.max` に計上される（ホストのメモリを直接は奪わない）。一方、memfd の
//!   ページは exec 先が生きている間残る（共有されない shmem）ため、exec 1 回ごとに本体の大きさぶん常駐メモリが
//!   増える。exec は一時的なコマンド向けで、常駐するワークロード（launch）には掛けない（CORE-7〜9 との関係）
//! - **memfd を使えないとき（fail-closed）**: `close_range`（5.11）・新マウント API（5.2）の前例に合わせて拒否し、
//!   照合だけの方式 A へ黙って戻さない。`memfd_create`（3.17）・seal は対応カーネルの下限より古いため `ENOSYS` は
//!   想定外として拒否する。`MFD_EXEC` を知らないカーネル（6.3 未満）の `EINVAL` に限り、`sys` が `MFD_EXEC` を外して
//!   1 回だけ再試行する（6.3 未満の memfd は実行できる）。`vm.memfd_noexec=2` の下では `MFD_EXEC` が `EACCES`、
//!   コンテナの seccomp が `memfd_create` を禁止していれば `EPERM` などになり、いずれも拒否する（`memfd_create`・
//!   `fcntl` は deny-list に含めない契約を `seccomp` のテストで機械照合している）
//! - **Landlock との関係（未確認・#1531 の最初の確認事項）**: exec の子は `EXECUTE` を扱う Landlock ruleset の下で
//!   memfd を `execveat` する。memfd はカーネル内部の shmem マウント（`MNT_INTERNAL`）上にありルールの対象パスが無い。
//!   `security/landlock/fs.c` は、内部マウントの根（nsfs 等）への到達を許可側で扱う実装と認識しているが、一次情報
//!   （対応カーネルのソース）と実プロセスでの確認は #1530 では行っていない。#1531 の結合試験で Landlock 適用下の実行が
//!   通ることを最初に確かめる。拒否される場合は、memfd を worker 側で `restrict_self` の前に作って子へ渡す、または
//!   memfd を `parent_fd` にして `landlock_add_rule` する案があり、複製を作る場所が変わる（#1531 の設計の見直しになる）
//! - **`ETXTBSY`**: 本リポの検証環境（Linux 7.0）では、封印した memfd を読み取り専用で開き直して書き込み用 fd を閉じれば、
//!   実行できることを `sys` のテスト（`sup6_task163_sealed_memfd_is_executable_after_readonly_reopen`）で確認した。
//!   カーネルの版による `deny_write_access` の挙動差（6.11 前後の変更）は一次情報では未確認で、書き込み用 fd を
//!   閉じてから実行する手順は版によらず維持する
//!
//! # 契約
//!
//! - **カーネルと同じ規則で辿る**: `fs/binfmt_script.c`（先頭 256 バイト = `BINPRM_BUF_SIZE` の 1 行目。`#!` の後の
//!   空白・タブを飛ばし、空白・タブ・NUL・改行までをインタープリタ名にする）と `fs/binfmt_elf.c`（最初の
//!   `PT_INTERP` の、NUL までの文字列）に合わせる。スクリプトのインタープリタがさらにスクリプトである連鎖は、
//!   カーネルの上限（5 段）を超える [`MAX_INTERPRETER_DEPTH`] 段まで辿り、収束しなければ拒否する
//! - **解釈の食い違いを拒否側へ倒す**: カーネルの ELF ローダは `EI_CLASS` を見ず `e_machine` でローダ（64 ビット /
//!   互換 32 ビット）を選ぶ。どちらが選ばれるかを推定せず、**64 ビットと 32 ビットの両方のレイアウト** で
//!   `PT_INTERP` を探し、見つかったものをすべて照合する（片方の解釈でしか見えない指定を見逃さない）。
//!   シェバンの 1 行が 256 バイトに収まらず名前が切れる場合は、カーネルは `ENOEXEC` にするが、ここでも拒否する
//! - **開かずに照合する**: インタープリタは `O_PATH`（最終要素の symlink は辿る。カーネルの `open_exec` と同じ
//!   解決）で開き、`fstat` の `(st_dev, st_ino)` をランタイムと比べる。`O_PATH` はデバイス等の `open` を呼ばない。
//!   連鎖の先を読む必要があるときだけ、通常ファイルであることを確かめた後に procfs の magic link 経由で
//!   読み取り専用に開き直す（パスを再解決しない）
//! - **確認できなければ進まない（fail-closed）**: インタープリタを開けない・`fstat` できない・通常ファイルでない・
//!   読めない（実行専用）場合は、ランタイムでないことを確認できないため拒否する（カーネルの `execve` も
//!   同じ理由か別の理由で失敗する入力である）
//! - **fork 後の子から呼ぶ**: 本モジュールが足す処理の成功経路は、スタック上の固定長バッファと syscall だけで
//!   ヒープを確保しない（エラーの組み立ては確保する）。呼び出し元の `prepare_exec_child` 全体は確保を含む
//!   （継承した標準入出力の同一性の `Vec`・std の標準ストリームの初期化・シェバン付きスクリプトの `/dev/fd/N` の
//!   パス組み立て等。いずれも変更前からある）。fork は `Threads: 1` を強制した単一スレッドのプロセスから行うため、
//!   他スレッドが保持したままのアロケータのロックを子が引き継ぐことはない
//!
//! # 限界（REPAIR-3）
//!
//! - **B' は組み込むまで未実装**: 本体の内容の書き換えは #1531 の組み込みで閉じる。B' でもインタープリタのパスの
//!   差し替えとインタープリタ自身の内容の書き換えは閉じず、引き続き Landlock に頼る。launch 経路への適用は
//!   #1314（本番 launcher の構成）の後になる
//! - **検査と実行の間の競合（TOCTOU）は残る**:カーネルは `execve` の中でインタープリタのパスを解決し直す。
//!   稼働中のコンテナが、検査の後・`execve` の前にインタープリタのパス（途中の symlink 等）を
//!   `/proc/self/exe` へ差し替えれば、本検査を通過し得る。エントリポイント本体は fd に固定して `execveat` するため
//!   競合しないが、インタープリタはカーネルがパスで開くため固定できない。この窓は Landlock（ルール外の
//!   バイナリの `EXECUTE` を拒否する）が塞ぐ前提で、Landlock に依存しない形で塞ぐには方式 B（封印した複製から
//!   の実行）が要る。launch 経路は pivot 直後で他のプロセスが居ないため、差し替える主体が無い
//! - **検査の後にファイルの中身を書き換える競合も残る**: エントリポイント本体は fd に固定するが、固定するのは
//!   inode で内容ではない。コンテナ側がそのファイルへの書き込み権限を持てば、検査の後・`execve` の前に 1 行目
//!   （シェバン）や `PT_INTERP` を `/proc/self/exe` へ書き換えられる（カーネルは `execve` の中で内容を読み直す）。
//!   インタープリタのファイルについても同じ。上と同じく Landlock が塞ぐ前提で、方式 B が要る
//! - **launch の実プロセスでの照合は証跡配線の後**: launch と exec は同じ `prepare_exec_child` を通るため同じ照合が
//!   掛かるが、launch の実プロセスは制限適用の証跡（`require_restriction_evidence`）が配線されるまで常に拒否され、
//!   照合まで到達しない。現時点の確認は共有手順を実プロセスで通す結合試験（`tests/exec_child_setup.rs`）と単体
//!   テストに依る。証跡の配線後に launch の実プロセス照合を足す（SUP-6・SEC-1）
//! - **`binfmt_misc` は対象外**: ホスト側に登録された `binfmt_misc` のインタープリタ（拡張子・マジックで選ばれる）
//!   は解釈しない。登録はホストの管理者の操作で、コンテナからは変えられない前提とする
//! - ランタイムの同一性の基準は、検証済みの procfs の `self/exe`（`fstatfs` で procfs と確認したディレクトリから
//!   引く）。ランタイムのバイナリが別名のコピー（別 inode）として存在する場合は一致しない

use std::ffi::CStr;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::{ExecError, IsolationStage, ViolationReason, describe};

/// インタープリタの連鎖を辿る上限（エントリポイントを 0 段目として、その先の段数）。
///
/// カーネル（`fs/exec.c` の `exec_binprm`）はスクリプトの書き換えを 5 段まで許し、超えると `ELOOP` にする。
/// それより 1 段多く辿り、収束しなければ拒否する（カーネルが実行し得る連鎖はすべて検査する）。
pub(super) const MAX_INTERPRETER_DEPTH: usize = 6;

/// カーネルがスクリプトの 1 行目として読むバイト数（`include/uapi/linux/binfmts.h` の `BINPRM_BUF_SIZE`）。
const SCRIPT_HEAD_BYTES: usize = 256;

/// `PT_INTERP` の文字列の上限（`PATH_MAX`。カーネルはこれを超える指定を `ENOEXEC` にする）。
const ELF_INTERP_MAX: usize = 4096;

/// ELF のプログラムヘッダ表の上限バイト数（カーネルは `e_phnum * e_phentsize` が 64KiB を超えると拒否する）。
const ELF_PHDR_TABLE_MAX: usize = 65_536;

/// `PT_INTERP`（`include/uapi/linux/elf.h`）。
const PT_INTERP: u32 = 3;

/// ELF のレイアウト（ヘッダとプログラムヘッダの各フィールドの位置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfLayout {
    /// `Elf64_Ehdr` / `Elf64_Phdr`。
    Elf64,
    /// `Elf32_Ehdr` / `Elf32_Phdr`（互換ローダ）。
    Elf32,
}

impl ElfLayout {
    /// ヘッダの大きさ。
    const fn header_len(self) -> usize {
        match self {
            Self::Elf64 => 64,
            Self::Elf32 => 52,
        }
    }

    /// プログラムヘッダ 1 件の大きさ（`e_phentsize` がこれと一致しなければカーネルは拒否する）。
    const fn phdr_len(self) -> usize {
        match self {
            Self::Elf64 => 56,
            Self::Elf32 => 32,
        }
    }
}

/// `bytes` の `at` から `N` バイトを固定長配列で取り出す（範囲外は `None`。添字アクセスをしない）。
fn field<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// カーネルと同じくネイティブのバイト順で読む（ELF ローダは `EI_DATA` を見ずに構造体をそのまま読む）。
fn read_u16(bytes: &[u8], at: usize) -> Option<u64> {
    field::<2>(bytes, at).map(|b| u64::from(u16::from_ne_bytes(b)))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u64> {
    field::<4>(bytes, at).map(|b| u64::from(u32::from_ne_bytes(b)))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    field::<8>(bytes, at).map(u64::from_ne_bytes)
}

/// ELF ヘッダ `header` を `layout` として読んだときの `(e_phoff, e_phnum)`。`e_phentsize` が `layout` の
/// プログラムヘッダの大きさと一致しなければ `None`（その解釈ではカーネルがロードしない）。
fn elf_program_headers(header: &[u8], layout: ElfLayout) -> Option<(u64, u64)> {
    let (phoff, phentsize, phnum) = match layout {
        ElfLayout::Elf64 => (
            read_u64(header, 32)?,
            read_u16(header, 54)?,
            read_u16(header, 56)?,
        ),
        ElfLayout::Elf32 => (
            read_u32(header, 28)?,
            read_u16(header, 42)?,
            read_u16(header, 44)?,
        ),
    };
    (usize::try_from(phentsize) == Ok(layout.phdr_len())).then_some((phoff, phnum))
}

/// プログラムヘッダ `phdr` を `layout` として読み、`PT_INTERP` なら `(p_offset, p_filesz)` を返す。
fn elf_interp_segment(phdr: &[u8], layout: ElfLayout) -> Option<(u64, u64)> {
    if read_u32(phdr, 0)? != u64::from(PT_INTERP) {
        return None;
    }
    match layout {
        ElfLayout::Elf64 => Some((read_u64(phdr, 8)?, read_u64(phdr, 32)?)),
        ElfLayout::Elf32 => Some((read_u32(phdr, 4)?, read_u32(phdr, 16)?)),
    }
}

/// スクリプトの 1 行目からインタープリタ名を取り出した結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shebang<'a> {
    /// `#!` で始まらない（スクリプトではない）。
    NotScript,
    /// `#!` の後にインタープリタ名が無い（カーネルは `ENOEXEC`）。
    Empty,
    /// 1 行が `SCRIPT_HEAD_BYTES` に収まらず、名前が途中で切れている（カーネルは `ENOEXEC`）。
    Truncated,
    /// インタープリタ名（空でなく、空白・タブ・NUL・改行を含まない）。
    Interpreter(&'a [u8]),
}

/// `head`（ファイルの先頭。最大 `SCRIPT_HEAD_BYTES` バイト）からシェバンのインタープリタ名を取り出す（純関数）。
///
/// `fs/binfmt_script.c` と同じ規則: 1 行目は最初の改行か NUL まで。`#!` の後の空白・タブを飛ばし、次の空白・
/// タブ（または行末）までが名前。カーネルのバッファは 256 バイトで最後の 1 バイトを終端に使うため、改行が無く
/// 名前が 255 バイト目まで続く場合は「切れている」とみなす。
fn parse_shebang(head: &[u8]) -> Shebang<'_> {
    let Some(rest) = head.strip_prefix(b"#!") else {
        return Shebang::NotScript;
    };
    let line_len = rest
        .iter()
        .position(|b| *b == b'\n' || *b == 0)
        .unwrap_or(rest.len());
    let terminated = line_len < rest.len();
    let line = rest.get(..line_len).unwrap_or(rest);
    let is_blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = line.iter().position(|b| !is_blank(b)).unwrap_or(line.len());
    let name = line.get(start..).unwrap_or(&[]);
    let name_len = name.iter().position(is_blank).unwrap_or(name.len());
    let Some(name) = name.get(..name_len).filter(|n| !n.is_empty()) else {
        return Shebang::Empty;
    };
    // 行末（改行・NUL）も、名前の後の空白も無いまま読める範囲の終わりに達した場合は、名前が切れている。
    let reaches_end = start + name_len == line.len();
    if !terminated && reaches_end && head.len() >= SCRIPT_HEAD_BYTES - 1 {
        return Shebang::Truncated;
    }
    Shebang::Interpreter(name)
}

/// 検査の文脈（照合の基準と、パスを解決・開き直す起点）。
struct Inspection<'a> {
    /// ランタイム自身のバイナリの `(st_dev, st_ino)`。
    runtime: (u64, u64),
    /// 相対パスのインタープリタを解決する起点（呼び出しプロセスの cwd。カーネルも cwd から解決する）。
    cwd: BorrowedFd<'a>,
    /// 検証済みの procfs（固定した fd を読み取り専用に開き直す起点）。
    proc_dir: BorrowedFd<'a>,
    /// エラーメッセージ・違反記録へ載せるエントリポイントのパス。
    entry: &'a Path,
}

impl Inspection<'_> {
    fn error(&self, code: ErrorCode, what: &str) -> ExecError {
        ExecError::new(
            code,
            IsolationStage::Exec,
            format!(
                "cannot verify the interpreter of the entrypoint {:?}: {what}",
                self.entry
            ),
        )
    }

    fn sys_error(&self, err: SysError, what: &str) -> ExecError {
        let code = match err {
            SysError::Os(e) if e == sys::ENOENT || e == sys::ENOTDIR => ErrorCode::NotFound,
            SysError::Unsupported => ErrorCode::Unimplemented,
            _ => ErrorCode::PermissionDenied,
        };
        self.error(code, &format!("{what}: {}", describe(err)))
    }

    /// インタープリタ名 `name`（NUL を含まない）を `O_PATH` で開き、ランタイムのバイナリでないことを確かめる。
    /// 返す fd は検証済みの inode を固定する（通常ファイルであることも確認済み）。
    fn pin_interpreter(&self, name: &[u8]) -> Result<OwnedFd, ExecError> {
        // NUL 終端つきでスタック上へ写す（名前は `ELF_INTERP_MAX` 以下であることを呼び出し側が保証する）。
        let mut buf = [0u8; ELF_INTERP_MAX + 1];
        let path = buf
            .get_mut(..name.len())
            .map(|dst| dst.copy_from_slice(name))
            .and_then(|()| buf.get(..=name.len()))
            .and_then(|bytes| CStr::from_bytes_with_nul(bytes).ok())
            .ok_or_else(|| self.error(ErrorCode::InvalidArgument, "the path is malformed"))?;
        let pinned = sys::open_path_follow_at(self.cwd, path)
            .map_err(|e| self.sys_error(e, "cannot open the interpreter"))?;
        let meta = fstat(pinned.as_fd()).ok_or_else(|| {
            self.error(ErrorCode::PermissionDenied, "cannot stat the interpreter")
        })?;
        if (meta.dev(), meta.ino()) == self.runtime {
            return Err(ExecError::from_violation_at(
                ViolationReason::EntrypointInterpreterIsRuntimeBinary,
                Some(self.entry),
                IsolationStage::Exec,
            ));
        }
        if !meta.is_file() {
            return Err(self.error(
                ErrorCode::PermissionDenied,
                "the interpreter is not a regular file",
            ));
        }
        Ok(pinned)
    }

    /// ELF `file` の `PT_INTERP` が指す先を、`layout` の解釈で照合する。その解釈で `PT_INTERP` が無ければ何もしない。
    fn check_elf_interpreter(
        &self,
        file: &std::fs::File,
        header: &[u8],
        layout: ElfLayout,
    ) -> Result<(), ExecError> {
        let Some((phoff, phnum)) = elf_program_headers(header, layout) else {
            return Ok(());
        };
        let entry_len = layout.phdr_len();
        // カーネルが受け付ける表の大きさ（64KiB）までを走査する。それより多い指定はカーネルが拒否する。
        let limit = u64::try_from(ELF_PHDR_TABLE_MAX / entry_len).unwrap_or(0);
        let mut phdr = [0u8; 56];
        for index in 0..phnum.min(limit) {
            let Some(phdr) = phdr.get_mut(..entry_len) else {
                return Ok(());
            };
            let offset = u64::try_from(entry_len)
                .ok()
                .and_then(|len| index.checked_mul(len))
                .and_then(|skip| phoff.checked_add(skip));
            let Some(offset) = offset else {
                return Ok(());
            };
            match file.read_exact_at(phdr, offset) {
                Ok(()) => {}
                // 表が途中で終わるファイルは、カーネルも読み取りに失敗してロードしない。
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                // それ以外（`EIO` 等）は「`PT_INTERP` が無い」ことを確認できていない。カーネルの読み取りは
                // 成功し得るため、通さずに拒否する（fail-closed）。
                Err(_) => {
                    return Err(self.error(
                        ErrorCode::PermissionDenied,
                        "cannot read the ELF program headers",
                    ));
                }
            }
            let Some((interp_offset, interp_len)) = elf_interp_segment(phdr, layout) else {
                continue;
            };
            // カーネルは最初の `PT_INTERP` だけを使う。
            return self.check_elf_interp_string(file, interp_offset, interp_len);
        }
        Ok(())
    }

    /// `PT_INTERP` の文字列（`offset` から `len` バイト。NUL まで）を読み、指す先を照合する。
    fn check_elf_interp_string(
        &self,
        file: &std::fs::File,
        offset: u64,
        len: u64,
    ) -> Result<(), ExecError> {
        let malformed = || {
            self.error(
                ErrorCode::InvalidArgument,
                "the ELF interpreter path is malformed",
            )
        };
        // カーネルは 2 バイト未満・`PATH_MAX` 超の指定を `ENOEXEC` にする。実行されない入力だが、解釈の食い違いを
        // 残さないよう拒否する。
        let len = usize::try_from(len)
            .ok()
            .filter(|n| (2..=ELF_INTERP_MAX).contains(n))
            .ok_or_else(malformed)?;
        let mut buf = [0u8; ELF_INTERP_MAX];
        let bytes = buf.get_mut(..len).ok_or_else(malformed)?;
        file.read_exact_at(bytes, offset).map_err(|_| malformed())?;
        let name = CStr::from_bytes_until_nul(bytes)
            .map_err(|_| malformed())?
            .to_bytes();
        if name.is_empty() {
            return Err(malformed());
        }
        self.pin_interpreter(name).map(drop)
    }
}

/// `O_PATH` を含む fd の `fstat`（パスを再解決しない。複製は同じ open file description を指す）。
fn fstat(fd: BorrowedFd<'_>) -> Option<std::fs::Metadata> {
    std::fs::File::from(fd.try_clone_to_owned().ok()?)
        .metadata()
        .ok()
}

/// `file` の先頭を最大 `buf.len()` バイト読み、読めた長さを返す（短いファイルは読めたぶんだけ）。
fn read_head(file: &std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) {
        match file.read_at(rest, u64::try_from(filled).unwrap_or(u64::MAX)) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// エントリポイント `file`（読み取り可能な fd。パスは `entry`）のインタープリタが、ランタイム自身のバイナリ
/// （`runtime` = `(st_dev, st_ino)`）に解決されないことを確かめる（契約と限界はモジュール doc）。
///
/// スクリプトの連鎖を [`MAX_INTERPRETER_DEPTH`] 段まで辿り、各段のインタープリタと、最後に行き着いた ELF の
/// `PT_INTERP` を照合する。一致は違反 `entrypoint_interpreter_is_runtime_binary`（`PermissionDenied`・段 `Exec`）。
/// `proc_dir` は呼び出し元が本物の procfs と確認したディレクトリ（照合済みの `/` の `proc`。連鎖の先を開き直す
/// 場合だけ使う）。相対パスのインタープリタは呼び出しプロセスの cwd から解決する。
pub(super) fn reject_runtime_interpreter(
    file: &std::fs::File,
    entry: &Path,
    runtime: (u64, u64),
    proc_dir: BorrowedFd<'_>,
) -> Result<(), ExecError> {
    let cwd = sys::open_dir_path_nofollow(None, c".")
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "open the current directory"))?;
    let inspection = Inspection {
        runtime,
        cwd: cwd.as_fd(),
        proc_dir,
        entry,
    };
    // 連鎖の先で開き直したファイル（次の段の検査対象）。最初の段は呼び出し側の `file`。
    let mut reopened: Option<std::fs::File> = None;
    for _ in 0..=MAX_INTERPRETER_DEPTH {
        let current = reopened.as_ref().unwrap_or(file);
        let mut head = [0u8; SCRIPT_HEAD_BYTES];
        let len = read_head(current, &mut head).map_err(|_| {
            inspection.error(ErrorCode::PermissionDenied, "cannot read the file header")
        })?;
        let head = head.get(..len).unwrap_or(&[]);
        match parse_shebang(head) {
            Shebang::NotScript => {
                if head.starts_with(b"\x7fELF") {
                    for layout in [ElfLayout::Elf64, ElfLayout::Elf32] {
                        if head.len() >= layout.header_len() {
                            inspection.check_elf_interpreter(current, head, layout)?;
                        }
                    }
                }
                // ELF のインタープリタ（動的ローダ）は、カーネルがそれ以上辿らない。
                return Ok(());
            }
            // 名前の無いシェバンはカーネルが `ENOEXEC` で拒否する（実行されない）。
            Shebang::Empty => return Ok(()),
            Shebang::Truncated => {
                return Err(
                    inspection.error(ErrorCode::InvalidArgument, "the shebang line is too long")
                );
            }
            Shebang::Interpreter(name) => {
                let pinned = inspection.pin_interpreter(name)?;
                let next = sys::reopen_pinned_read(inspection.proc_dir, pinned.as_fd())
                    .map_err(|e| inspection.sys_error(e, "cannot read the interpreter"))?;
                reopened = Some(std::fs::File::from(next));
            }
        }
    }
    Err(inspection.error(
        ErrorCode::InvalidArgument,
        "too many levels of script interpreters",
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// 手組みの ELF ヘッダ + プログラムヘッダ 2 件（`PT_LOAD`・`PT_INTERP`）+ インタープリタ文字列。
    /// `class` は `EI_CLASS` に書く値（カーネルは見ない）で、`layout` が実際のレイアウト。
    fn elf_with_interp(layout: ElfLayout, class: u8, interp: &[u8]) -> Vec<u8> {
        let mut b = vec![0x7f, b'E', b'L', b'F', class, 1, 1, 0];
        b.resize(16, 0);
        let (hlen, plen) = (layout.header_len(), layout.phdr_len());
        let interp_at = hlen + 2 * plen;
        match layout {
            ElfLayout::Elf64 => {
                b.extend_from_slice(&3u16.to_ne_bytes()); // e_type = ET_DYN
                b.extend_from_slice(&62u16.to_ne_bytes()); // e_machine
                b.extend_from_slice(&1u32.to_ne_bytes()); // e_version
                b.extend_from_slice(&0u64.to_ne_bytes()); // e_entry
                b.extend_from_slice(&(hlen as u64).to_ne_bytes()); // e_phoff
                b.extend_from_slice(&0u64.to_ne_bytes()); // e_shoff
                b.extend_from_slice(&0u32.to_ne_bytes()); // e_flags
                b.extend_from_slice(&(hlen as u16).to_ne_bytes()); // e_ehsize
                b.extend_from_slice(&(plen as u16).to_ne_bytes()); // e_phentsize
                b.extend_from_slice(&2u16.to_ne_bytes()); // e_phnum
                b.extend_from_slice(&[0u8; 6]);
                assert_eq!(b.len(), 64);
                // PT_LOAD（中身は検査に使わない）。
                b.extend_from_slice(&1u32.to_ne_bytes());
                b.resize(64 + 56, 0);
                // PT_INTERP。
                b.extend_from_slice(&PT_INTERP.to_ne_bytes());
                b.extend_from_slice(&4u32.to_ne_bytes()); // p_flags
                b.extend_from_slice(&(interp_at as u64).to_ne_bytes()); // p_offset
                b.extend_from_slice(&[0u8; 16]); // p_vaddr, p_paddr
                b.extend_from_slice(&(interp.len() as u64).to_ne_bytes()); // p_filesz
                b.resize(64 + 2 * 56, 0);
            }
            ElfLayout::Elf32 => {
                b.extend_from_slice(&3u16.to_ne_bytes());
                b.extend_from_slice(&3u16.to_ne_bytes()); // e_machine = EM_386
                b.extend_from_slice(&1u32.to_ne_bytes());
                b.extend_from_slice(&0u32.to_ne_bytes()); // e_entry
                b.extend_from_slice(&(hlen as u32).to_ne_bytes()); // e_phoff
                b.extend_from_slice(&0u32.to_ne_bytes()); // e_shoff
                b.extend_from_slice(&0u32.to_ne_bytes()); // e_flags
                b.extend_from_slice(&(hlen as u16).to_ne_bytes());
                b.extend_from_slice(&(plen as u16).to_ne_bytes());
                b.extend_from_slice(&2u16.to_ne_bytes());
                b.extend_from_slice(&[0u8; 6]);
                assert_eq!(b.len(), 52);
                b.extend_from_slice(&1u32.to_ne_bytes());
                b.resize(52 + 32, 0);
                b.extend_from_slice(&PT_INTERP.to_ne_bytes());
                b.extend_from_slice(&(interp_at as u32).to_ne_bytes()); // p_offset
                b.extend_from_slice(&[0u8; 8]); // p_vaddr, p_paddr
                b.extend_from_slice(&(interp.len() as u32).to_ne_bytes()); // p_filesz
                b.resize(52 + 2 * 32, 0);
            }
        }
        assert_eq!(b.len(), interp_at);
        b.extend_from_slice(interp);
        b
    }

    /// テスト用の一時ディレクトリ（drop で削除。排他的に作る）。
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn create(label: &str) -> Self {
            static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "fandhe-interp-{label}-{}-{nanos}-{seq}",
                    std::process::id()
                ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        /// `name` を `content` で排他的に作り（mode 0755）、そのパスを返す。
        fn file(&self, name: &str, content: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            f.write_all(content).unwrap();
            f.set_permissions(std::fs::Permissions::from_mode(0o755))
                .unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// テストプロセス自身（= 検査の上での「ランタイム」）の同一性。
    fn runtime() -> (u64, u64) {
        let m = std::fs::metadata("/proc/self/exe").unwrap();
        (m.dev(), m.ino())
    }

    /// 実ファイル `path` を、テストプロセス自身をランタイムとして検査する。
    fn inspect(path: &Path) -> Result<(), ExecError> {
        let proc_dir = sys::open_dir_path_nofollow(None, c"/proc").unwrap();
        let file = std::fs::File::open(path).unwrap();
        reject_runtime_interpreter(&file, path, runtime(), proc_dir.as_fd())
    }

    /// 違反 `entrypoint_interpreter_is_runtime_binary`（`PermissionDenied`・段 `Exec`・SEC-1）を照合する。
    fn assert_violation(err: &ExecError, entry: &Path) {
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::PermissionDenied, IsolationStage::Exec)
        );
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(
            v.reason,
            ViolationReason::EntrypointInterpreterIsRuntimeBinary
        );
        assert_eq!(
            v.reason.as_str(),
            "entrypoint_interpreter_is_runtime_binary"
        );
        assert_eq!(v.kind.as_str(), "entrypoint");
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(
            v.subject.as_ref().map(|s| s.as_str().to_owned()),
            Some(entry.display().to_string())
        );
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1458）: シェバンの解釈はカーネル（`binfmt_script.c`）と同じ規則。
    #[test]
    fn sup6_sec1_task163_parse_shebang_follows_kernel_rules() {
        let name = |head: &'static [u8]| match parse_shebang(head) {
            Shebang::Interpreter(n) => Some(n),
            _ => None,
        };
        assert_eq!(name(b"#!/bin/sh\n"), Some(&b"/bin/sh"[..]));
        assert_eq!(name(b"#!/bin/sh"), Some(&b"/bin/sh"[..]));
        assert_eq!(
            name(b"#! \t/usr/bin/env  python3 -u\nrest"),
            Some(&b"/usr/bin/env"[..])
        );
        assert_eq!(
            name(b"#!/proc/self/exe\targ\n"),
            Some(&b"/proc/self/exe"[..])
        );
        // NUL は行の終わりとして扱われる（カーネルのバッファは C 文字列）。
        assert_eq!(name(b"#!/bin/sh\0/proc/self/exe\n"), Some(&b"/bin/sh"[..]));
        assert_eq!(name(b"#!bin/relative\n"), Some(&b"bin/relative"[..]));
        assert_eq!(parse_shebang(b"\x7fELF"), Shebang::NotScript);
        assert_eq!(parse_shebang(b""), Shebang::NotScript);
        assert_eq!(parse_shebang(b"#"), Shebang::NotScript);
        assert_eq!(parse_shebang(b"#!"), Shebang::Empty);
        assert_eq!(parse_shebang(b"#!  \t \n/bin/sh"), Shebang::Empty);
        assert_eq!(parse_shebang(b"#!\0/bin/sh"), Shebang::Empty);

        // 256 バイトの読み取り範囲いっぱいまで名前が続き、行末が無い場合は「切れている」。
        let mut long = b"#!/".to_vec();
        long.resize(SCRIPT_HEAD_BYTES, b'a');
        assert_eq!(parse_shebang(&long), Shebang::Truncated);
        // 範囲内に改行があれば切れていない（名前は 252 バイト）。
        let mut fits = b"#!/".to_vec();
        fits.resize(SCRIPT_HEAD_BYTES - 1, b'a');
        fits.push(b'\n');
        assert_eq!(
            parse_shebang(&fits),
            Shebang::Interpreter(&fits[2..SCRIPT_HEAD_BYTES - 1])
        );
        // 名前の後に空白があれば、引数が切れていても名前は確定している。
        let mut arg = b"#!/bin/sh ".to_vec();
        arg.resize(SCRIPT_HEAD_BYTES, b'x');
        assert_eq!(parse_shebang(&arg), Shebang::Interpreter(b"/bin/sh"));
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1458）: ELF のプログラムヘッダの位置と `PT_INTERP` の取り出しの具体値
    /// （64 ビット・32 ビットの両レイアウト。`e_phentsize` が合わない解釈は採らない）。
    #[test]
    fn sup6_sec1_task163_elf_layouts_are_read_exactly() {
        let elf64 = elf_with_interp(ElfLayout::Elf64, 2, b"/lib/ld.so\0");
        assert_eq!(elf_program_headers(&elf64, ElfLayout::Elf64), Some((64, 2)));
        assert_eq!(elf_program_headers(&elf64, ElfLayout::Elf32), None);
        assert_eq!(elf_interp_segment(&elf64[64..120], ElfLayout::Elf64), None);
        assert_eq!(
            elf_interp_segment(&elf64[120..176], ElfLayout::Elf64),
            Some((176, 11))
        );
        let elf32 = elf_with_interp(ElfLayout::Elf32, 1, b"/lib/ld.so\0");
        assert_eq!(elf_program_headers(&elf32, ElfLayout::Elf32), Some((52, 2)));
        assert_eq!(elf_program_headers(&elf32, ElfLayout::Elf64), None);
        assert_eq!(
            elf_interp_segment(&elf32[84..116], ElfLayout::Elf32),
            Some((116, 11))
        );
        // 範囲外は `None`（添字アクセスで panic しない）。
        assert_eq!(elf_program_headers(&elf64[..40], ElfLayout::Elf64), None);
        assert_eq!(elf_interp_segment(&[3, 0], ElfLayout::Elf64), None);
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163 追補（#1458）: `#!/proc/self/exe`・`#!/proc/<pid>/exe`・実パス・symlink 経由の
    /// いずれでも、インタープリタがランタイム自身に解決されるスクリプトは違反として拒否する。
    #[test]
    fn sup6_sec1_task163_script_interpreter_resolving_to_runtime_is_rejected() {
        let dir = TempDir::create("script");
        let exe = std::env::current_exe().unwrap();
        std::os::unix::fs::symlink("/proc/self/exe", dir.0.join("link")).unwrap();
        let interpreters = [
            "/proc/self/exe".to_owned(),
            format!("/proc/{}/exe", std::process::id()),
            "/proc/thread-self/exe".to_owned(),
            exe.display().to_string(),
            dir.0.join("link").display().to_string(),
        ];
        for (i, interp) in interpreters.iter().enumerate() {
            for line in [
                format!("#!{interp}\n"),
                format!("#! {interp} -x\necho\n"),
                format!("#!{interp}"),
            ] {
                let script = dir.file(&format!("s{i}-{}", line.len()), line.as_bytes());
                let err = inspect(&script).unwrap_err();
                assert_violation(&err, &script);
            }
        }
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1458）: スクリプトのインタープリタがスクリプトである連鎖の先がランタイムでも
    /// 拒否する。収束しない連鎖（自分自身をインタープリタにしたスクリプト）は `InvalidArgument` で拒否する。
    #[test]
    fn sup6_sec1_task163_script_chains_are_followed_to_the_end() {
        let dir = TempDir::create("chain");
        let last = dir.file("last", b"#!/proc/self/exe\n");
        let middle = dir.file("middle", format!("#!{}\n", last.display()).as_bytes());
        let first = dir.file("first", format!("#!{} arg\n", middle.display()).as_bytes());
        assert_violation(&inspect(&first).unwrap_err(), &first);

        // スクリプト → ELF（`PT_INTERP` がランタイム）。
        let elf = dir.file(
            "elf",
            &elf_with_interp(ElfLayout::Elf64, 2, b"/proc/self/exe\0"),
        );
        let wrapper = dir.file("wrapper", format!("#!{}\n", elf.display()).as_bytes());
        assert_violation(&inspect(&wrapper).unwrap_err(), &wrapper);

        let looped = dir.0.join("loop");
        dir.file("loop", format!("#!{}\n", looped.display()).as_bytes());
        let err = inspect(&looped).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::InvalidArgument, IsolationStage::Exec)
        );
        assert_eq!(err.violation, None);
        assert!(
            err.message
                .ends_with("too many levels of script interpreters"),
            "{}",
            err.message
        );
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1458）: ELF の `PT_INTERP` がランタイムを指す場合は、64 ビット・32 ビットの
    /// どちらのレイアウトでも、`EI_CLASS` が実際のレイアウトと食い違っていても拒否する。
    #[test]
    fn sup6_sec1_task163_elf_interpreter_resolving_to_runtime_is_rejected() {
        let dir = TempDir::create("elf");
        let cases = [
            (ElfLayout::Elf64, 2u8),
            (ElfLayout::Elf64, 1),
            (ElfLayout::Elf32, 1),
            (ElfLayout::Elf32, 2),
        ];
        for (i, (layout, class)) in cases.into_iter().enumerate() {
            let elf = dir.file(
                &format!("elf{i}"),
                &elf_with_interp(layout, class, b"/proc/self/exe\0"),
            );
            assert_violation(&inspect(&elf).unwrap_err(), &elf);
            // NUL の後ろは読まれない（カーネルは C 文字列として開く）。
            let padded = dir.file(
                &format!("padded{i}"),
                &elf_with_interp(layout, class, b"/proc/self/exe\0/bin/sh\0"),
            );
            assert_violation(&inspect(&padded).unwrap_err(), &padded);
        }
    }

    /// SUP-6・TASK-163 追補（#1458）: ランタイムに解決されない通常の入力は通す（実在のシェル・シェルスクリプト・
    /// ヘッダだけの ELF・スクリプトでも ELF でもないファイル・空ファイル）。
    #[test]
    fn sup6_task163_ordinary_entrypoints_pass_the_interpreter_check() {
        let dir = TempDir::create("ok");
        inspect(Path::new("/bin/sh")).unwrap();
        inspect(&dir.file("script", b"#!/bin/sh\nexit 0\n")).unwrap();
        inspect(&dir.file("env", b"#! /bin/sh -e\n")).unwrap();
        inspect(&dir.file(
            "static",
            &elf_with_interp(ElfLayout::Elf64, 2, b"/bin/sh\0"),
        ))
        .unwrap();
        inspect(&dir.file("data", b"plain text\n")).unwrap();
        inspect(&dir.file("empty", b"")).unwrap();
        inspect(&dir.file("noname", b"#!\n")).unwrap();
    }

    /// SUP-6・TASK-163 追補（#1458）: プログラムヘッダの表が途中で終わる ELF（カーネルもロードしない）は、EOF として
    /// 検査を終える（拒否の理由にしない）。EOF 以外の読み取り失敗は拒否する（実装側。入出力エラーは再現しない）。
    #[test]
    fn sup6_task163_truncated_program_header_table_ends_the_check() {
        let dir = TempDir::create("trunc");
        let mut elf = elf_with_interp(ElfLayout::Elf64, 2, b"/proc/self/exe\0");
        // ヘッダ（64 バイト）と 1 件目の途中までを残す。
        elf.truncate(64 + 20);
        inspect(&dir.file("truncated", &elf)).unwrap();
        // 1 件目（PT_LOAD）は読めるが 2 件目（PT_INTERP）が切れている。
        let mut elf = elf_with_interp(ElfLayout::Elf64, 2, b"/proc/self/exe\0");
        elf.truncate(64 + 56 + 10);
        inspect(&dir.file("truncated2", &elf)).unwrap();
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1458）: インタープリタを確認できない入力は進めない（fail-closed）。
    /// 不在は `NotFound`（終了コード 127 相当）、通常ファイルでない・`PT_INTERP` の文字列が壊れている・
    /// シェバンの行が長すぎる場合は拒否する。
    #[test]
    fn sup6_sec1_task163_unverifiable_interpreters_are_rejected() {
        let dir = TempDir::create("bad");
        let code = |name: &str, content: &[u8]| {
            let err = inspect(&dir.file(name, content)).unwrap_err();
            assert_eq!(err.stage, IsolationStage::Exec, "{name}");
            assert_eq!(err.violation, None, "{name}");
            err.code
        };
        assert_eq!(
            code("missing", b"#!/no/such/interpreter\n"),
            ErrorCode::NotFound
        );
        assert_eq!(code("dir", b"#!/proc\n"), ErrorCode::PermissionDenied);
        assert_eq!(
            code("device", b"#!/dev/null\n"),
            ErrorCode::PermissionDenied
        );
        let mut long = b"#!/".to_vec();
        long.resize(300, b'a');
        assert_eq!(code("long", &long), ErrorCode::InvalidArgument);
        // `PT_INTERP` の文字列に NUL が無い・空・1 バイト。
        for (i, interp) in [&b"/bin/sh"[..], b"\0\0", b"\0"].into_iter().enumerate() {
            assert_eq!(
                code(
                    &format!("elf{i}"),
                    &elf_with_interp(ElfLayout::Elf64, 2, interp)
                ),
                ErrorCode::InvalidArgument
            );
        }
        // `PT_INTERP` が存在しないファイルを指す。
        assert_eq!(
            code(
                "elf-missing",
                &elf_with_interp(ElfLayout::Elf64, 2, b"/no/such/ld.so\0")
            ),
            ErrorCode::NotFound
        );
    }
}
