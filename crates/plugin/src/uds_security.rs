//! UDS 配置ディレクトリ（runtime directory）の解決・作成・検証（PLUG-12・TASK-123.1・#286）。
//!
//! PLUG-12 は plugin との UDS を `$XDG_RUNTIME_DIR/fandhe-container/` 相当の、0700 かつ core 実行 UID
//! 所有のディレクトリ配下にのみ作ることを求める。本モジュールはその「解決・作成・検証」を担い、
//! 上位（TASK-109 の plugin 発見・TASK-114 の core 側 proxy）が socket の置き場所を得て
//! [`crate::UdsListener::bind`] へ渡す入口になる。
//!
//! # 契約
//! - 既存ディレクトリが自 UID 所有でない・symlink・ディレクトリでない・group / other にアクセス可能
//!   （`mode & 0o077 != 0`。`UdsListener::bind` の親ディレクトリ検証と同じ閾値）、または所有者の
//!   rwx が揃っていない（`mode & 0o700 != 0o700`。0500・000 等）場合は、使用せず
//!   `PermissionDenied` を返す。chmod・chown・削除での自動修復はしない（fail-closed）。
//! - 基底ディレクトリも同様に検証する。自 UID 所有の非 symlink ディレクトリで group / other に
//!   書き込み権が無い（`mode & 0o022 == 0`）ことを要求し、満たさなければ `PermissionDenied`。
//!   基底は末尾 `/` を除いた正規化パスで lstat し（末尾 `/` による symlink 追従を防ぐ）、
//!   symlink なら拒否する。さらに基底を `canonicalize` した実パスの全祖先を検証する。祖先は
//!   実ディレクトリで、所有者が root または自 UID、group / other 書き込み不可（または sticky）で
//!   なければならず、満たさなければ `PermissionDenied`。
//! - 祖先・基底・runtime directory の判定は、実パスをルートから 1 要素ずつ
//!   `openat(O_NOFOLLOW | O_DIRECTORY)` で辿って開いた fd（`crate::sys::open_dir_nofollow`。
//!   `UdsListener::bind` の配置ディレクトリ検証と同じ仕組み）の `fstat` 結果で行う。経路上の要素が
//!   symlink（`canonicalize` 後の差し替えを含む）なら open が失敗し、パスの再解決で検証対象と
//!   別の場所を見ることはない（fail-closed）。基底は lstat した実体と fd の dev / ino の一致も確認する。
//! - 作成は検証済みの基底 fd 基準の `mkdirat`（`crate::sys::mkdirat`）で行い、パスを再解決しない
//!   （#1309）。作成後はルートから symlink 非追従で開き直して検証するため、祖先を差し替えられても
//!   検証済みの基底の外には作られず、開き直しが失敗する。
//! - 残余: 作成前の既存確認（lstat）はパス指定で行う。symlink・非ディレクトリを早く拒否し作成要否を
//!   決めるだけで、この確認が欺かれても `mkdirat` は検証済み fd 基準で最終要素の symlink を辿らないため
//!   安全性には影響しない。返した後の保護は `UdsListener::bind` が bind 時に配置ディレクトリを fd で
//!   再検証して担う。
//! - 作成は非再帰で、基底ディレクトリ（`XDG_RUNTIME_DIR` 自体）は作らない。
//! - エラーメッセージは固定の英語文字列で、パス・環境変数値を含めない。
//! - 既存 socket パス（TASK-123.2・#287）: `UdsListener::bind` が bind 前に検証済みディレクトリ fd 基準で
//!   lstat（symlink 非追従）する。symlink と他 UID 所有のエントリは削除せず `PermissionDenied`。
//!   生存判定は接続 probe ではなく sibling の `<socket 名>.lock` への排他 flock で行う
//!   （listener が生存中保持し、クラッシュ時は kernel が解放する）。接続拒否の回数では削除しない
//!   （macOS は accept queue 満杯の生存 listener にも ECONNREFUSED を返すため区別できず、probe 接続が
//!   既存 listener の accept queue に残る副作用もある）。ロックを取れない（生存中）、socket 以外、
//!   またはロックに記録した同一性（dev / ino / mtime）と一致しない socket（管理下か判別不能。残存ロック
//!   ファイルの存在は根拠にしない）は削除せず `AlreadyExists`。ロックを取れて
//!   管理下の自 UID 所有 socket だけを、再 lstat で同一性（dev / ino / mtime / uid / 種別）を確認したうえで
//!   `unlinkat` し、再 bind を可能にする。
//!   ロックファイルは、記録が空の場合に限り保持者が解放の直前に unlink する（記録が残る場合は残す）。
//!   取得側は flock 取得後に名前が同じ inode を指すことを確認し、外れていれば開き直すため、unlink と
//!   取得が競合しても同名に有効なロックを持つのは 1 者だけ（`BindLock` の doc 参照）。記録は、記録した socket がパス上から無くなったと
//!   確認できた後にだけ消す（listener の後始末と、bind 前の検証で不在・別エントリ・削除済みを確認した時。
//!   unlink に失敗して socket が残る場合は記録も残し、次回 bind で削除できる）。
//!   fork した子は socket fd と一緒にロック fd も継承するため、子が持つ間は生存中として扱う
//!   （`BindLock` の doc 参照）。
//!   残余: bind 成功から記録書き込みまでの間に異常終了すると記録の無い socket が残り、以後は
//!   `AlreadyExists`（手動削除が必要。fail-closed）。記録した socket が外部で削除され、別経路の socket が
//!   同じ inode 番号を再利用しても、記録には mtime（秒・ナノ秒）を含めるため一致しない（後から作られた
//!   socket の mtime は記録時点より新しい）。誤認が残るのは、時計が巻き戻るかタイムスタンプ粒度の
//!   範囲内で、同一 UID が削除と再作成を行い inode 番号まで一致した場合のみ（0700 ディレクトリ内の
//!   同一 UID の操作。脅威モデル外）。
//!   残余: 再確認から unlink までの窓で差し替えられるのは 0700 ディレクトリ内の同一 UID のみ
//!   （脅威モデル外）。既存エントリの識別情報は Linux・macOS とも検証済みディレクトリ fd 基準で取得し、
//!   パスを再解決しない（`fstatat` / `statx`。#1307）。
//! - socket の 0600 化は [`crate::UdsListener::bind`] が検証済みディレクトリ fd 基準の
//!   `fchmodat(AT_SYMLINK_NOFOLLOW)` で行う（TASK-123.3・#288）。パス指定の chmod は、bind 後の
//!   パス・祖先の差し替えで別ファイルの mode を変えうるため使わない（`docs/design/io-protocol.md`）。
//!   親が 0700 かつ自 UID 所有のため、bind から 0600 化までの mode 差は他 UID から到達できない。
//! - [`RuntimeDir::socket_path`] が socket 名の検証と `sun_path` 長検証を bind 前に行う（#288）。
//!
//! # 都度起動の残骸の掃除（#1310・PLUG-7・PLUG-12・REPAIR-5・TASK-110.1）
//! 都度起動（`call_once`）は呼び出しごとに `oneshot-<pid>-<連番>.sock` を bind する。core 側が SIGKILL 等で
//! 異常終了すると socket と記録つきロックファイルが残り、名前が一意なため同名の再 bind（bind 前の stale
//! 削除。TASK-123.2）が起きず、runtime directory に溜まり続ける。[`RuntimeDir::sweep_one_shot_leftovers`] が
//! これを掃除する。
//! - 呼ぶ時機: runtime directory の初期化時（[`RuntimeDir::ensure_under`]・[`RuntimeDir::from_env`]）に
//!   best-effort で 1 回行う（失敗しても初期化は失敗させない。掃除を始められなかった・列挙が途中で
//!   失敗した場合は、構造化ログ `plugin.sweep_one_shot` を stderr へ 1 行出す。REPAIR-4）。残骸は異常終了したプロセスからしか生じず、
//!   プロセスごとの初期化 1 回で収束する（常駐デーモンを持たない CORE-1 では CLI 起動ごとに初期化が走る）。
//!   各 `call_once` の前に置くと全呼び出しにディレクトリ列挙が上乗せされ、境界レイテンシ（PLUG-6）に
//!   響くため採らない。長時間動くプロセスは公開メソッドを任意の時機に呼べる。
//! - 候補: `oneshot-<10 進>-<10 進>.sock.lock` の名前に厳密一致するロックファイルだけ（記録の無い socket は
//!   削除根拠が無いので候補にしない。`resident-*` など他の名前も対象外）。
//! - 判定・削除は bind 前の stale 削除と同じ処理（`acquire_bind_lock`・`clear_stale_socket`）を使い、
//!   新しい削除規則は持たない。ロックを取れない（使用中）・symlink・他 UID 所有・記録が無い／不一致の
//!   ものは削除しない。socket が消えて残ったロックファイルは `BindLock` の drop が unlink する。
//! - 上限（REPAIR-5）: 処理する候補（上記の名前一致）は [`ONE_SHOT_SWEEP_MAX_ENTRIES`] 件まで、走査する
//!   エントリは [`ONE_SHOT_SWEEP_MAX_SCAN`] 件まで。列挙中は何も削除せず、候補名を集めてから処理する。
//!   対象外の名前は候補の件数に数えないため、先頭に対象外ファイルが多くても後方の残骸が飢餓しない。
//! - 再開: 上限で打ち切った場合は、次に読むはずだったエントリの位置を runtime directory 直下の走査位置
//!   ヒント（`fcsweep-cursor`。0600・排他 flock・best-effort）へ保存し、次回の初期化はそこから走査する。
//!   位置は件数ではなくカーネルのディレクトリ位置（`lseek` で設定できる値。`crate::sys::DirStream`）で
//!   持つため、手前のエントリを読み直さずに続きから列挙できる。先頭に走査上限以上の対象外エントリが
//!   あっても、回を重ねるごとに位置が進み、後方の残骸へ到達する。libc は複数エントリをまとめて読み、
//!   カーネルの位置はまとめ読みの境界でしか得られないため、ヒントは「境界の位置」と「そこからの件数」の
//!   組で、再開時は境界の位置から「そこからの件数」だけを読み飛ばす。読み飛ばしは 65,536 件を上限とし
//!   （libc のまとめ読み 1 回分はこれより小さい。ヒントが壊れていても超えない）、1 回の読み取り総数は、
//!   ディレクトリの大きさに依らず「読み飛ばし上限 + 走査上限 + 1」件以内である。ディレクトリ末尾まで
//!   走査し終えるとヒントを削除して先頭へ戻る。削除が起きた回は、並びが詰まって位置がずれるのを避ける
//!   ため、その回の開始位置から次回も走査し直す。
//! - ヒントの性質: 走査範囲を変えるだけで、改ざん・破損しても削除対象は変わらない（判定・削除は検証済み
//!   ディレクトリ fd 基準）。ディレクトリ位置の安定性はファイルシステム依存で（位置が並び順の番号に
//!   なる実装では、手前の削除で後続がずれる）、ずれて飛ばしたエントリは、末尾到達後に先頭から始まる
//!   次の周回で処理する（1 周で消えなくても周回を重ねて収束する）。
//! - 前提と適用範囲: 判定は「ロックファイルの `flock` を取れる = 以前の保持者は消えた」に依る。この前提は
//!   bind 前の stale 削除（同名を再 bind するときだけ）で使っていたもので、本掃除により runtime directory を
//!   初期化するすべてのプロセス起動へ適用範囲が広がる。`flock` が排他にならず黙って成功する
//!   配置先では成り立たず、生存中の listener の socket を残骸と誤認しうる。そのため掃除は毎回、
//!   この runtime directory で `flock` が実際に排他になることを確かめてから行う（走査位置ヒントの
//!   ロックを取り、同じファイルを別の open でロックできないことを確認する）。確認できなければ
//!   何も削除せず `FailedPrecondition` を返す（fail-closed。初期化時は構造化ログに出す）。ヒントの
//!   ファイルを開けない・作れない環境では確認できないため、掃除は毎回行われない（残骸は残る）。
//!   確認できなかった経路では、確認のために作った空の `fcsweep-cursor` を残す。確かめ
//!   られるのは同一ホスト内の排他で、複数ホストが runtime directory を共有しロックがホスト間で
//!   伝わらない構成は検出できない（UDS はホスト内でしか接続できず、runtime directory は
//!   `XDG_RUNTIME_DIR` 等のホスト固有の場所に置く前提）。
//! - bind との競合: 掃除は既存のロックファイルだけを開き、作成しない。bind 側は、自分が作成した直後の
//!   ロックファイルを掃除が先にロックしていた場合に期限つき（1 回の取得につき 100 ms）で待って取り直す
//!   （`crate::sys::lock_file_at`）。掃除が空のロックファイルを unlink した後に bind 側が古い inode を
//!   掴んだ場合は、`acquire_bind_lock` が名前と inode の一致を確かめて作り直す。作り直すたびに同じ
//!   待ちが起こりうるため、bind 1 回の待ちは最悪で作り直しの上限 8 回 × 100 ms（約 0.8 秒）になる。
//!   この待ちは `call_once` の期限とは連動しない。
//! - 削除を拒否する socket（symlink・他 UID 所有・socket 以外・記録なし／不一致）のロックファイルは、
//!   記録も含めて変更・unlink しない（PLUG-12 の拒否対象を保持する）。
//! - 列挙・判定・削除はすべて検証済みディレクトリ fd 基準で行い、パスを再解決しない（列挙は
//!   `openat(dir, ".")` で開き直した fd を読む）。列挙で得た名前は候補の手掛かりにすぎず、削除の可否は
//!   候補ごとに fd 基準で判定し直す。
//! - 残余: bind 成功から記録書き込みまでの間に異常終了した記録なし socket は削除しない（手動削除が必要。
//!   fail-closed）。常駐モードの `resident-*` は対象外。
//!
//! # `XDG_RUNTIME_DIR` 未設定時のフォールバック（TASK-123.4・#289）
//! 未設定または空のときだけ、OS・euid ごとに単一の基底を選び、通常経路と同じ検証
//! （[`RuntimeDir::ensure_under`] 相当）を省略なく適用する。
//!
//! | 条件 | 基底 |
//! | ---- | ---- |
//! | Linux・euid 0 | `/run`（OCI-5 の root 配置と同じツリー） |
//! | Linux・euid != 0 | `/run/user/<euid>` |
//! | macOS | 環境変数 `TMPDIR`（ユーザー固有の 0700 ディレクトリ） |
//! | 上記以外の unix | なし（`FailedPrecondition`） |
//!
//! - 共有書き込み可能な `/tmp` へは落とさない。基底は作らず、無ければ `FailedPrecondition`。
//! - 候補は単一で、検証失敗（`PermissionDenied` 等）時に別候補へ連鎖しない（改ざんを隠さない）。
//! - 設定済みだが不正な値（相対パス・`..`）はフォールバックせずエラーにする。
//! - OCI-5 の state store は別仕様で、未設定時にフォールバックしない（`crates/core`）。
//!
//! # peer credential 検証（TASK-124.1・#292。Linux は SO_PEERCRED。PLUG-12）
//! `transport` の accept / connect が接続直後に `verify_peer` を呼ぶ。契約:
//! - 順序: accept（connect）の直後、フレームの read・write より前に検証する。
//! - fail-closed: 取得失敗も UID 不一致も `Err` を返し、呼び出し側は stream を drop して切断する。
//! - 比較する UID は接続時点の peer の実効 uid と、listener bind 時（client は connect 時）の自 euid。
//!   接続元が別の user namespace にあり uid が未マッピングなら overflowuid（Linux 既定 65534）として見え、
//!   core 自身の euid が overflowuid として観測されない通常の構成では不一致で拒否される（安全側）。core の
//!   euid 自体が 65534 として観測される構成（未マッピングの user namespace 内・nobody 実行等）では数値が
//!   一致して受理される。照合は数値の完全一致のみで overflowuid を特別扱いしない（現状挙動。#1390）。
//! - 限界（残存リスク。対策は未実装。詳細は `crate::sys` のモジュール doc「限界」）: (a) client 側で得られるのは
//!   server が `listen(2)` を呼んだ時点の資格情報（Linux。`man 7 unix`。macOS は未検証）、(b) 接続済み fd を
//!   別プロセスへ渡しても検出できない、(c) pid 照合には PID 再利用の窓が残る。
//! - 同一 UID の別プロセスは脅威モデル外（第 1 層は 0700 の配置ディレクトリ）。
//! - `unsafe` を含む取得処理は `crate::sys::peer_uid`（`sys` モジュール）に閉じる。
//! - macOS は getpeereid で peer uid を取得済み（TASK-124.2・#293）。別 UID 接続拒否の結合試験は `tests/peer_auth.rs`（TASK-124.4・#295。実機前提の 2 件は人間が実行）。accept / connect で最初の読み書きより前に検証する順序は `transport::tests::plug12_order` で機械照合する（TASK-124.6・#1389）。拒否 1 件ごとの監査イベント通知は `crate::audit`（TASK-124.5・#1388・SEC-4）。永続的な監査ログへの配線は core 側 proxy（TASK-114）で未実装（REPAIR-3）。
//!
//! # Windows に固有の peer 認証を持たない理由（WIN-1・PLUG-12。TASK-124.3・#294）
//! 「未実装の残件」ではなく、設計上この crate に Win32 向け実装を置かない判断である。
//! - 対応関係: PLUG-12 は Windows バックエンドを WIN-1（WSL2 経由を MVP 主経路とする）により
//!   Linux 側の機構に乗せると定める。plugin プロセスと UDS は WSL2 内の Linux 環境で動くため、
//!   実際に実行される peer 検証は上記の Linux 経路（`verify_peer` → `crate::sys::peer_uid`）である。
//! - 非 unix ビルドの挙動: `sys` は `cfg(unix)` 限定でコンパイルされず、配置ディレクトリ検証（`RuntimeDir` 系）と
//!   `UdsListener::bind` は `Unimplemented` を返す（fail-closed。接続を一切作らない）。
//!   これはデプロイ経路ではないビルドが安全側に倒れることを示すもので、エラー文言の
//!   "not implemented for this platform" と本節の「実装不要」は矛盾しない。
//! - 保証の範囲: Windows ホスト側の保護を主張するものではない。保護の根拠は WSL2 内で Linux の検証が動くことだけである。
//! - 将来仕様（REPAIR-3）: WSL2 を経由しない Windows 経路（Hyper-V 直接方式など。MVP 外。`docs/architecture.md` 参照）を
//!   採る場合は、Windows 固有の peer 認証を新規に設計する必要があり、本節の前提は成り立たない。
//! - 関連: Windows 側の plugin 化（TASK-116 `fandhe-container-plugin-windows`）は、PLUG-12 を満たしたこの UDS を使う側である。

use std::path::{Component, Path, PathBuf};

use crate::error::{PluginError, PluginErrorCode};

/// runtime directory 名（`$XDG_RUNTIME_DIR` 直下。PLUG-12）。
pub const RUNTIME_DIR_NAME: &str = "fandhe-container";

/// 掃除で処理する候補（都度起動のロックファイル名に一致したもの）の件数上限（REPAIR-5。#1310）。
/// 超えた分は次回の初期化で処理する。
pub const ONE_SHOT_SWEEP_MAX_ENTRIES: usize = 256;

/// 掃除 1 回で走査するディレクトリエントリ数の上限（対象外の名前を含む。REPAIR-5。#1310）。
/// 巨大ディレクトリでの無制限な列挙を防ぐ安全上限で、候補の件数上限とは別に数える。超えた分は
/// 次回の初期化が続きの位置から走査する（手前のエントリは読み直さない）。
pub const ONE_SHOT_SWEEP_MAX_SCAN: usize = 65_536;

/// 都度起動の残骸の掃除結果（#1310・PLUG-7）。呼び出し側（TASK-114）が構造化ログへ出す材料。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct OneShotSweep {
    /// 処理した候補の数（対象外の名前は含まない。上限は [`ONE_SHOT_SWEEP_MAX_ENTRIES`]）。
    pub examined: u32,
    /// 削除した socket 数（掃除前に存在し、掃除後に無いと lstat で確認できたもの。
    /// ロックファイルだけが残っていた場合は数えない）。
    pub removed: u32,
    /// ロックを他者が保持中（使用中）で飛ばした数。
    pub in_use: u32,
    /// 削除根拠が無い・拒否（symlink・他 UID・記録なし／不一致）・エラーで飛ばした数。
    pub skipped: u32,
    /// 候補の件数上限または走査するエントリ数の上限に達して走査を打ち切ったか（続きは次回の掃除が走査する）。
    pub truncated: bool,
    /// 列挙が途中で失敗し、未走査のエントリが残っている可能性があるか（`truncated` とは別。上限では
    /// なくエラーで止まった。次回の掃除は先頭から走査し直す）。`false` かつ `truncated` も `false` の
    /// ときだけ、末尾まで走査し終えている。
    pub incomplete: bool,
}

impl OneShotSweep {
    /// 掃除が完了しなかったことを知らせる構造化ログ（JSON Lines の 1 行。改行なし。REPAIR-4）。
    ///
    /// 初期化時の掃除は best-effort で、失敗しても初期化は続ける。その失敗を無通知にしないため、
    /// 初期化経路が stderr へ出す（成功時は出さない。件数の記録は TASK-114 の core 側 proxy が
    /// [`RuntimeDir::sweep_one_shot_leftovers`] の結果から行う）。値は固定文字列・真偽値だけで、
    /// 外部入力（ファイル名等）を埋め込まない。`error_code` は掃除を始められなかった場合の機械可読な
    /// `code`（ERR-1）、`incomplete` は列挙が途中で失敗した場合に `true`。`error_code` は任意の文字列
    /// ではなく [`PluginErrorCode`] で受け、その固定の表記（英大文字と `_` のみ）だけを埋め込む
    /// （エスケープが要る文字を渡せず、壊れた JSON を組み立てられない。REPAIR-2）。
    pub fn failure_json_line(error_code: Option<PluginErrorCode>, incomplete: bool) -> String {
        let code = match error_code {
            Some(c) => format!("\"{}\"", c.as_str()),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"plugin.sweep_one_shot\",\"success\":false,\"error_code\":{code},\
             \"incomplete\":{incomplete}}}"
        )
    }
}

/// 検証済みの UDS 配置ディレクトリ（PLUG-12）。生の `PathBuf` ではなく newtype で返し、
/// 検証を経ていないパスと型で区別する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    /// 環境変数 `XDG_RUNTIME_DIR` と自プロセスの実効 uid から解決・作成する。
    ///
    /// 未設定・空のときは OS・euid ごとのフォールバック基底を使う（モジュール doc 参照。TASK-123.4・#289）。
    /// 設定済みの相対パスは `FailedPrecondition`、`..` 含みは `InvalidArgument`。
    pub fn from_env() -> Result<Self, PluginError> {
        imp::from_env()
    }

    /// 指定の基底ディレクトリ直下の `fandhe-container` を解決・作成する。
    ///
    /// テストおよびフォールバック（#289）が基底を注入する入口。基底は絶対パス・`..` なしで自 UID 所有・
    /// group/other 書き込み不可の非 symlink ディレクトリ（違反は `PermissionDenied`）で、
    /// 既に存在していなければならない（`NotFound`。基底は作成しない）。
    pub fn ensure_under(base: &Path) -> Result<Self, PluginError> {
        imp::ensure_under(base)
    }

    /// 検証済み runtime directory 直下の socket パスを、bind 前に検証して返す（PLUG-12・TASK-123.3・#288）。
    ///
    /// TASK-109（plugin 発見）・TASK-114（core 側 proxy）が [`crate::UdsListener::bind`] へ渡す前に使い、
    /// 不正な名前と `sun_path` 超過を socket を作る前に検出する。`name` は単一の通常コンポーネント
    /// （空・`.`・`..`・区切り・NUL を含まない）でなければ `InvalidArgument`。結合後のパスが
    /// `sun_path` に収まらなければ `InvalidArgument`（"socket path is too long"）。
    ///
    /// 本メソッドは早期検出であり、`UdsListener::bind` は同じ長さ検証（Linux では bind に使う
    /// `/proc/self/fd/<fd>/<名前>` 側の長さも）を再度行う。0600 化も bind 側が fd 基準で担う。
    pub fn socket_path(&self, name: &str) -> Result<PathBuf, PluginError> {
        imp::socket_path(self, name)
    }

    /// 検証済みディレクトリのパス。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 異常終了で残った都度起動の socket とロックファイルを掃除する（#1310・PLUG-7・PLUG-12）。
    ///
    /// 初期化時に best-effort で呼ばれるほか、TASK-114 の core 側 proxy が結果（件数）を得るために
    /// 呼べる。判定規則・上限・残余はモジュール doc の「都度起動の残骸の掃除」参照。ディレクトリを
    /// 開けない・検証に失敗した場合（初期化後に symlink へ差し替えられた場合を含む。`PermissionDenied`）、
    /// この runtime directory で `flock` の排他を確認できない場合（`FailedPrecondition`。何も削除しない）、
    /// 列挙を始められない場合（`Internal`）に `Err`。個別エントリの失敗は [`OneShotSweep::skipped`] に数える。
    /// 非 unix は `Unimplemented`（fail-closed）。
    pub fn sweep_one_shot_leftovers(&self) -> Result<OneShotSweep, PluginError> {
        imp::sweep_one_shot_leftovers(self)
    }
}

/// 基底パスの共通検証。絶対パスで `..` を含まないこと（外部入力の untrusted 検証）。
#[cfg_attr(not(unix), allow(dead_code))] // 非 unix では imp が Unimplemented を返し呼ばれない
fn validate_base(base: &Path) -> Result<(), PluginError> {
    if !base.is_absolute() {
        return Err(PluginError::new(
            PluginErrorCode::FailedPrecondition,
            "runtime directory base must be an absolute path",
        ));
    }
    if base.components().any(|c| c == Component::ParentDir) {
        return Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            "runtime directory base must not contain parent directory components",
        ));
    }
    Ok(())
}

/// `XDG_RUNTIME_DIR` の値から基底パスを得る純粋関数。未設定・空は `FailedPrecondition`。
#[cfg_attr(not(unix), allow(dead_code))] // 非 unix では imp が Unimplemented を返し呼ばれない
fn runtime_dir_base(xdg: Option<std::ffi::OsString>) -> Result<PathBuf, PluginError> {
    let value = match xdg {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                "XDG_RUNTIME_DIR is not set",
            ));
        }
    };
    let base = PathBuf::from(value);
    validate_base(&base)?;
    Ok(base)
}

/// peer の uid が期待 uid と一致するか（PLUG-12・TASK-124.1）。
#[cfg(unix)]
fn peer_uid_matches(peer: u32, expected: u32) -> bool {
    peer == expected
}

/// 照合で拒否した結果（PLUG-12・SEC-4・TASK-124.5）。
///
/// `error` は呼び出し側へ返すエラー（UID 値を含まない固定文言。従来と同一）、`reason` / `peer_uid` は
/// 監査イベント（`crate::audit::PeerAuthRejection`）の材料で、呼び出し側へは返さない。
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct PeerRejection {
    pub(crate) reason: crate::audit::PeerAuthRejectReason,
    /// 観測できた peer UID（取得失敗では `None`）。
    pub(crate) peer_uid: Option<u32>,
    pub(crate) error: PluginError,
}

/// 取得関数を差し替えられる検証本体（取得失敗の fail-closed をテストで再現するため。PLUG-12）。
#[cfg(unix)]
fn verify_peer_with(
    get: impl FnOnce() -> Result<u32, PluginError>,
    expected_uid: u32,
) -> Result<(), PeerRejection> {
    // 取得失敗はそのまま伝播する（Ok にしない）。
    let peer = get().map_err(|error| PeerRejection {
        reason: crate::audit::PeerAuthRejectReason::PeerUidUnavailable,
        peer_uid: None,
        error,
    })?;
    if !peer_uid_matches(peer, expected_uid) {
        // メッセージは固定文字列で UID 値を含めない。
        return Err(PeerRejection {
            reason: crate::audit::PeerAuthRejectReason::UidMismatch,
            peer_uid: Some(peer),
            error: PluginError::new(
                PluginErrorCode::PermissionDenied,
                "peer credential does not match the current user",
            ),
        });
    }
    Ok(())
}

/// 接続済み stream の peer uid を `expected_uid` と照合する（PLUG-12・TASK-124.1・#292）。
///
/// `transport` の accept 直後・connect 直後（最初の read より前）から呼ばれる。Err なら呼び出し側が
/// stream を drop して切断し、`PeerRejection` から監査イベントを通知して `error` を返す
/// （TASK-124.5）。取得は `crate::sys::peer_uid`（Linux は SO_PEERCRED）。
///
/// client の connect 側で得る peer 資格情報は server が `listen(2)` を呼んだ時点のものであり、接続済み fd の
/// 別プロセスへの受け渡しも検出できない（モジュール doc・`crate::sys` の「限界」）。
#[cfg(unix)]
pub(crate) fn verify_peer(
    stream: &std::os::unix::net::UnixStream,
    expected_uid: u32,
) -> Result<(), PeerRejection> {
    verify_peer_with(|| crate::sys::peer_uid(stream), expected_uid)
}

#[cfg(unix)]
pub(crate) use imp::{BindLock, acquire_bind_lock, clear_stale_socket};

#[cfg(unix)]
mod imp {
    use super::{
        ONE_SHOT_SWEEP_MAX_ENTRIES, ONE_SHOT_SWEEP_MAX_SCAN, OneShotSweep, RUNTIME_DIR_NAME,
        RuntimeDir, runtime_dir_base, validate_base,
    };
    use crate::error::{PluginError, PluginErrorCode};
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    /// runtime directory 名の C 文字列版（`mkdirat` へ渡す。[`RUNTIME_DIR_NAME`] と一致をテストで照合）。
    const RUNTIME_DIR_CNAME: &std::ffi::CStr = c"fandhe-container";

    /// Linux のフォールバック基底の根（root は直下、非 root は `user/<euid>`）。
    const RUN_ROOT: &str = "/run";

    const NO_FALLBACK: &str =
        "XDG_RUNTIME_DIR is not set and no fallback runtime directory is available";

    pub(super) fn from_env() -> Result<RuntimeDir, PluginError> {
        resolve(
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::var_os("TMPDIR"),
            crate::sys::effective_uid(),
            Path::new(RUN_ROOT),
        )
    }

    /// `XDG_RUNTIME_DIR` 未設定・空のときの単一フォールバック基底（PLUG-12・TASK-123.4）。
    /// 基底の存在・所有者・権限の検証は呼び出し元の `ensure_dir` が行う。
    #[allow(unused_variables)] // OS ごとに使う引数が異なる
    fn fallback_base(
        euid: u32,
        run_root: &Path,
        tmpdir: Option<std::ffi::OsString>,
    ) -> Result<PathBuf, PluginError> {
        #[cfg(target_os = "linux")]
        {
            if euid == 0 {
                Ok(run_root.to_path_buf())
            } else {
                Ok(run_root.join("user").join(euid.to_string()))
            }
        }
        #[cfg(target_os = "macos")]
        {
            match tmpdir {
                Some(v) if !v.is_empty() => {
                    let base = PathBuf::from(v);
                    validate_base(&base)?;
                    Ok(base)
                }
                _ => Err(PluginError::new(
                    PluginErrorCode::FailedPrecondition,
                    NO_FALLBACK,
                )),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(PluginError::new(
                PluginErrorCode::FailedPrecondition,
                NO_FALLBACK,
            ))
        }
    }

    /// 環境値を注入できる解決本体。`from_env` とテストが呼ぶ。
    pub(super) fn resolve(
        xdg: Option<std::ffi::OsString>,
        tmpdir: Option<std::ffi::OsString>,
        euid: u32,
        run_root: &Path,
    ) -> Result<RuntimeDir, PluginError> {
        if matches!(&xdg, Some(v) if !v.is_empty()) {
            let base = runtime_dir_base(xdg)?;
            return ensure_dir(&base, euid);
        }
        let base = fallback_base(euid, run_root, tmpdir)?;
        // フォールバック基底が無い場合のみ前提条件違反へ写像する。検証失敗は格下げしない。
        ensure_dir(&base, euid).map_err(|e| {
            if e.code() == PluginErrorCode::NotFound {
                PluginError::new(PluginErrorCode::FailedPrecondition, NO_FALLBACK)
            } else {
                e
            }
        })
    }

    pub(super) fn ensure_under(base: &Path) -> Result<RuntimeDir, PluginError> {
        ensure_dir(base, crate::sys::effective_uid())
    }

    pub(super) fn socket_path(dir: &RuntimeDir, name: &str) -> Result<PathBuf, PluginError> {
        validate_socket_name(name)?;
        let path = dir.path().join(name);
        crate::transport::check_sun_path_len(&path)?;
        Ok(path)
    }

    /// socket 名が単一の通常コンポーネントであることを確認する純粋関数（トラバーサル防止）。
    /// `Path::components()` は末尾 `/` や中間の `.` を正規化するため、元の文字列との一致で拒否する。
    pub(super) fn validate_socket_name(name: &str) -> Result<(), PluginError> {
        let mut comps = Path::new(name).components();
        let ok = !name.contains('\0')
            && matches!(
                (comps.next(), comps.next()),
                (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
            );
        if ok {
            Ok(())
        } else {
            Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "socket name must be a single path component",
            ))
        }
    }

    fn map_io(e: &io::Error) -> PluginError {
        match e.kind() {
            io::ErrorKind::NotFound => PluginError::new(
                PluginErrorCode::NotFound,
                "runtime directory base does not exist",
            ),
            io::ErrorKind::PermissionDenied => PluginError::new(
                PluginErrorCode::PermissionDenied,
                "permission denied while preparing runtime directory",
            ),
            _ => PluginError::new(
                PluginErrorCode::Internal,
                "failed to prepare runtime directory",
            ),
        }
    }

    /// runtime directory を `O_NOFOLLOW` で開いた fd の Metadata を検証する（PLUG-12）。
    fn verify(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory is not a plain directory"));
        }
        if meta.uid() != euid {
            return Err(deny("runtime directory is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(deny(
                "runtime directory must not be accessible by group or other",
            ));
        }
        // 所有者の rwx が揃っていない（0500・000・umask で 0700 より狭まった等）と後続の
        // UDS bind が失敗するため、0700 の契約どおり所有者 rwx も要求する。
        if meta.mode() & 0o700 != 0o700 {
            return Err(deny("runtime directory must be accessible by its owner"));
        }
        Ok(())
    }

    /// 基底ディレクトリの検証（lstat または `O_NOFOLLOW` で開いた fd の Metadata）。自 UID 所有の実ディレクトリで、group / other に
    /// 書き込み権が無いこと（`mode & 0o022 == 0`）を要求する。`/run/user/<uid>`（0700）は通り、
    /// 共有書き込み可能な `/tmp` 等（sticky でも）は拒否する。祖先は [`verify_ancestor`] で別途検証する。
    fn verify_base(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory base is not a plain directory"));
        }
        if meta.uid() != euid {
            return Err(deny(
                "runtime directory base is not owned by the current user",
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(deny(
                "runtime directory base must not be writable by group or other",
            ));
        }
        Ok(())
    }

    /// 基底の祖先ディレクトリの検証（実パス上の各要素を `O_NOFOLLOW` で開いた fd の Metadata。
    /// PLUG-12）。実ディレクトリで、所有者が
    /// root または自 UID、かつ group / other に書き込み権が無い（sticky bit 付きは許容。`/tmp` 等）こと。
    fn verify_ancestor(meta: &Metadata, euid: u32) -> Result<(), PluginError> {
        let deny = |m: &str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(deny("runtime directory ancestor is not a plain directory"));
        }
        if meta.uid() != 0 && meta.uid() != euid {
            return Err(deny("runtime directory ancestor has an untrusted owner"));
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return Err(deny(
                "runtime directory ancestor must not be writable by group or other",
            ));
        }
        Ok(())
    }

    /// 実パス `abs` をルートから 1 要素ずつ symlink 非追従で開く（[`crate::sys::open_dir_nofollow`]）。
    /// 経路上の要素が symlink・非ディレクトリ・読み取り不可なら `PermissionDenied`、
    /// 未対応の OS・アーキテクチャは `Unimplemented`（いずれも fail-closed）。
    fn open_nofollow(abs: &Path) -> Result<File, PluginError> {
        crate::sys::open_dir_nofollow(abs).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => map_io(&e),
            io::ErrorKind::Unsupported => PluginError::new(
                PluginErrorCode::Unimplemented,
                "runtime directory is not implemented on this platform",
            ),
            _ => PluginError::new(
                PluginErrorCode::PermissionDenied,
                "runtime directory path could not be opened without following symlinks",
            ),
        })
    }

    fn fstat(dir: &File) -> Result<Metadata, PluginError> {
        dir.metadata().map_err(|e| map_io(&e))
    }

    /// 基底と全祖先を検証し、基底の実パス（canonical）と検証済みの基底 fd を返す（PLUG-12）。
    ///
    /// 検証は実パスの各要素を symlink 非追従で開いた fd に対して行う。`canonicalize` 後に経路上の
    /// 要素が symlink へ差し替えられた場合は open が失敗する。
    fn resolve_base(base: &Path, euid: u32) -> Result<(PathBuf, File), PluginError> {
        // 末尾 `/` は lstat が最終要素の symlink を辿る原因になるため、components で正規化して除く。
        let normalized: PathBuf = base.components().collect();
        let link_meta = std::fs::symlink_metadata(&normalized).map_err(|e| map_io(&e))?;
        verify_base(&link_meta, euid)?;
        // 基底が実ディレクトリと確定した後の canonicalize は祖先 symlink のみを解決する。
        let real = std::fs::canonicalize(&normalized).map_err(|e| map_io(&e))?;
        // ancestors() は自身を最初に、ルートを最後に返す。自身を除いた各祖先を fd で検証する。
        for ancestor in real.ancestors().skip(1) {
            verify_ancestor(&fstat(&open_nofollow(ancestor)?)?, euid)?;
        }
        let base_fd = open_nofollow(&real)?;
        let meta = fstat(&base_fd)?;
        // 開いた fd が lstat した実体と同一であること（検査と open の間の差し替え検出）。
        if meta.dev() != link_meta.dev() || meta.ino() != link_meta.ino() {
            return Err(PluginError::new(
                PluginErrorCode::PermissionDenied,
                "runtime directory base changed during verification",
            ));
        }
        verify_base(&meta, euid)?;
        Ok((real, base_fd))
    }

    /// `base/fandhe-container` を解決し、無ければ 0700 で作成して検証する。
    pub(super) fn ensure_dir(base: &Path, euid: u32) -> Result<RuntimeDir, PluginError> {
        validate_base(base)?;
        // 基底自体と全祖先を先に検証する。他ユーザーが書ける・symlink の基底や祖先では、
        // 検証済みの子を後から rename・差し替えられ配置パスの安全性が失われるため（PLUG-12）。
        let (real_base, base_fd) = resolve_base(base, euid)?;
        create_in_base(&base_fd, &real_base, euid)
    }

    /// 検証済みの基底 fd 基準で runtime directory を（無ければ）作成し、開き直して検証する。
    /// `ensure_dir` から呼ばれる。検証と作成の間に基底パスが差し替えられる場合をテストで再現するため分離。
    fn create_in_base(
        base_fd: &File,
        real_base: &Path,
        euid: u32,
    ) -> Result<RuntimeDir, PluginError> {
        let dir = real_base.join(RUNTIME_DIR_NAME);
        match std::fs::symlink_metadata(&dir) {
            // 既存の symlink・非ディレクトリは open を試みる前に拒否する（修復・削除はしない）。
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(PluginError::new(
                    PluginErrorCode::PermissionDenied,
                    "runtime directory is not a plain directory",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // 非再帰。検証済みの基底 fd 基準で作る（#1309）。競合作成（AlreadyExists）は
                // 下の fd 検証で判定する。
                match crate::sys::mkdirat(base_fd, RUNTIME_DIR_CNAME, 0o700) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                        return Err(PluginError::new(
                            PluginErrorCode::Unimplemented,
                            "runtime directory is not implemented on this platform",
                        ));
                    }
                    Err(e) => return Err(map_io(&e)),
                }
            }
            Err(e) => return Err(map_io(&e)),
        }
        // ルートから symlink 非追従で開き直し、開いた fd 自体を検証する。lstat・作成との間に
        // 経路上の要素や runtime directory が symlink へ差し替えられていれば open が失敗する。
        let verified = open_nofollow(&dir)?;
        verify(&fstat(&verified)?, euid)?;
        // 異常終了で残った都度起動の残骸を掃除する（#1310）。いま検証した fd をそのまま基準にし、
        // パスを再解決しない。掃除の失敗で初期化を失敗させない（残骸は次回の初期化で再試行され、
        // 判定不能なものは削除しない fail-closed）。
        let swept = sweep_dir(
            &verified,
            euid,
            ONE_SHOT_SWEEP_MAX_SCAN,
            ONE_SHOT_SWEEP_MAX_ENTRIES,
            ONE_SHOT_SWEEP_MAX_SKIP,
        );
        // 掃除を始められなかった・列挙が途中で失敗した場合は、初期化は続けるが無通知にしない
        // （構造化ログを stderr へ 1 行出す。REPAIR-4。書き込み失敗は初期化に影響させない）。
        if let Some(line) = sweep_failure_log(swept.as_ref().map(|(out, _)| out)) {
            use std::io::Write;
            let _ = writeln!(io::stderr(), "{line}");
        }
        Ok(RuntimeDir { path: dir })
    }

    /// 初期化時の掃除結果から、出すべき失敗ログ（[`OneShotSweep::failure_json_line`]）を決める純粋関数。
    /// 末尾まで走査した・上限で打ち切った（次回に続きを走査する正常な経過）場合は `None`。
    pub(super) fn sweep_failure_log(swept: Result<&OneShotSweep, &PluginError>) -> Option<String> {
        match swept {
            Ok(out) if out.incomplete => Some(OneShotSweep::failure_json_line(None, true)),
            Ok(_) => None,
            Err(e) => Some(OneShotSweep::failure_json_line(Some(e.code()), false)),
        }
    }

    /// 公開メソッドの本体。`RuntimeDir` の保存済みパス（初期化時に祖先の symlink を解決済みの基底 +
    /// `fandhe-container`）を、正規化し直さずルートから 1 要素ずつ symlink 非追従で開く。初期化後に
    /// runtime directory や祖先が symlink へ差し替えられていれば open が失敗し、リンク先を走査・削除
    /// しない（PLUG-12。`canonicalize` するとリンク先を辿ってしまう）。開いた fd を検証してから掃除する。
    pub(super) fn sweep_one_shot_leftovers(dir: &RuntimeDir) -> Result<OneShotSweep, PluginError> {
        let euid = crate::sys::effective_uid();
        let verified = open_nofollow(&dir.path)?;
        verify(&fstat(&verified)?, euid)?;
        sweep_dir(
            &verified,
            euid,
            ONE_SHOT_SWEEP_MAX_SCAN,
            ONE_SHOT_SWEEP_MAX_ENTRIES,
            ONE_SHOT_SWEEP_MAX_SKIP,
        )
        .map(|(out, _)| out)
    }

    /// 都度起動のロックファイル名 `oneshot-<10 進>-<10 進>.sock.lock` に厳密一致するとき、対応する
    /// socket 名（`.lock` を除いたもの）を返す純粋関数（#1310）。数字は 1〜20 桁（u64 の桁数）。
    pub(super) fn one_shot_socket_name_of_lock(name: &[u8]) -> Option<&[u8]> {
        let socket = name.strip_suffix(b".lock")?;
        let body = socket.strip_suffix(b".sock")?.strip_prefix(b"oneshot-")?;
        let mut parts = body.split(|c| *c == b'-');
        let (pid, seq) = (parts.next()?, parts.next()?);
        let ok = |x: &[u8]| (1..=20).contains(&x.len()) && x.iter().all(u8::is_ascii_digit);
        (parts.next().is_none() && ok(pid) && ok(seq)).then_some(socket)
    }

    /// テスト用の入口。`dir_path` を正規化して開き、既定の上限で掃除する（#1310）。`euid` は自 UID
    /// （他 UID を注入できるよう引数に取る）。公開メソッドと初期化はパスを正規化し直さない
    /// （[`sweep_one_shot_leftovers`]・`create_in_base`）。
    #[cfg(test)]
    pub(super) fn sweep_one_shot(dir_path: &Path, euid: u32) -> Result<OneShotSweep, PluginError> {
        sweep_one_shot_limited(
            dir_path,
            euid,
            ONE_SHOT_SWEEP_MAX_SCAN,
            ONE_SHOT_SWEEP_MAX_ENTRIES,
        )
    }

    /// 走査位置ヒントを保存するファイル名（runtime directory 直下。候補の名前規則に一致しない）。
    const SWEEP_CURSOR_NAME: &[u8] = b"fcsweep-cursor";
    /// 走査位置ヒントの最大長（`<10 進 u64> <10 進 u64>\n`。10 進 u64 は 20 桁なので内容は最大 42 バイト）。
    const SWEEP_CURSOR_MAX_LEN: usize = 48;

    /// 再開位置までに読み飛ばすエントリ数の上限（REPAIR-5。#1310）。
    ///
    /// 正しく保存された件数は libc のまとめ読み 1 回分のエントリ数より小さい（glibc のバッファは最大
    /// 1 MiB で、dirent は 24 バイト以上なので 43,690 件以下。macOS の実測は 500 件未満）。壊れた・
    /// 改ざんされたヒントでも読み取りがこの件数を超えないようにする上限で、超えた分は読み飛ばさずに
    /// 走査する（再走査になるだけで、未処理を飛ばさない）。
    const ONE_SHOT_SWEEP_MAX_SKIP: u64 = 65_536;

    /// 掃除の走査位置（#1310）。件数ではなくカーネルのディレクトリ位置で表す。
    ///
    /// `offset` は libc がまとめ読みを始めた位置（`lseek` で設定できる不透明な値。0 は先頭）、`skip` は
    /// その位置から読み飛ばす件数（保存時点では、まとめ読み 1 回分の中での件数）。libc は複数エントリをまとめて読み、
    /// カーネルの位置はまとめ読みの境界でしか得られないため、境界の位置と境界からの件数の組で
    /// 「次に読むエントリ」を指す。
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub(super) struct ScanPos {
        pub(super) offset: u64,
        pub(super) skip: u64,
    }

    /// 前回打ち切った位置（[`ScanPos`]）を保存・取得する走査位置ヒント。
    ///
    /// 列挙総数の上限（REPAIR-5）を保ったまま、上限より後方の残骸へも複数回の初期化で到達できる
    /// ようにする（先頭の対象外ファイルが多い巨大ディレクトリで掃除が収束しない問題への対策）。
    /// 位置はカーネルのディレクトリ位置なので、そこまでのエントリを読み直さずに続きから列挙できる。
    /// 値はヒントにすぎず、壊れた・改ざんされた値は走査範囲を変えるだけで削除対象は変えない
    /// （判定・削除は検証済みディレクトリ fd 基準）。
    ///
    /// ヒントのファイルは「自 UID 所有・通常ファイル・単一リンク・空または `<10 進> <10 進>\n` 形式
    /// （その書きかけを含む）」と確認できた場合だけ使う（`BindLock` の専用ファイル検証と同方針）。
    /// 書きかけ（保存の途中で異常終了・書き込み失敗して、形式の先頭側だけが残ったもの。
    /// [`is_scan_pos_fragment`]）は専用ファイルと認めるが位置としては使わず、先頭から走査して、
    /// その回の結果で上書き・削除する（壊れたヒントが残り続けて再開できなくなるのを防ぐ）。確認できない既存ファイル（他
    /// ファイルへのハードリンク・無関係な内容）には書き込み・切り詰め・unlink をせず、ヒントを諦めて
    /// 先頭から走査し、保存もしない。他の掃除が保持中・開けない場合も同様（best-effort）。
    struct SweepCursor {
        handle: crate::sys::LockHandle,
        name: std::ffi::CString,
        /// 読み込んだ開始位置（検証済み。形式不正なら開かない）。
        start: ScanPos,
    }

    /// 走査位置ヒントの内容（`<offset> <skip>\n`。空は先頭）を解釈する純粋関数。
    pub(super) fn parse_scan_pos(text: &[u8]) -> Option<ScanPos> {
        if text.is_empty() {
            return Some(ScanPos::default());
        }
        let body = text.strip_suffix(b"\n")?;
        let mut parts = body.split(|c| *c == b' ');
        let (offset, skip) = (parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        Some(ScanPos {
            offset: parse_decimal(offset)?,
            skip: parse_decimal(skip)?,
        })
    }

    /// 走査位置ヒントの書きかけ（`<offset> <skip>\n` の、改行より手前で切れた先頭側）かを判定する純粋関数。
    /// 保存は切り詰めてから先頭へ 1 回書くため、途中で止まると形式の先頭側だけが残る。1 項目め
    /// （1〜20 桁の数字）と、あれば空白 1 個に続く 2 項目め（0〜20 桁の数字）だけから成るものに限る
    /// （10 進 u64 は 20 桁以内。桁数を超える・無関係な内容は書きかけと認めない）。
    pub(super) fn is_scan_pos_fragment(text: &[u8]) -> bool {
        let digits = |x: &[u8], min: usize| {
            (min..=20).contains(&x.len()) && x.iter().all(u8::is_ascii_digit)
        };
        let mut parts = text.split(|c| *c == b' ');
        let (offset, skip) = (parts.next(), parts.next());
        parts.next().is_none()
            && offset.is_some_and(|x| digits(x, 1))
            && skip.is_none_or(|x| digits(x, 0))
    }

    /// ヒントの内容から開始位置を決める。完全な形式ならその位置、書きかけなら先頭（専用ファイルとして
    /// 上書きを許す）、それ以外（無関係な内容）は `None`（触れない）。
    pub(super) fn cursor_start(text: &[u8]) -> Option<ScanPos> {
        parse_scan_pos(text).or_else(|| is_scan_pos_fragment(text).then(ScanPos::default))
    }

    /// runtime directory で `flock` が排他になるかの確認結果（#1310・PLUG-12）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum FlockProbe {
        /// 保持中のロックを別の open から取れなかった（排他が効いている）。
        Exclusive,
        /// 自分が保持しているロックを別の open からも取れた（排他が効かない）。
        NotExclusive,
        /// 確認できなかった（開けない・ロック非対応等）。
        Unknown,
    }

    /// ロック取得の試行結果（排他の判定に使う分類）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum LockTry {
        /// `flock` を取れた。
        Locked,
        /// `flock` を試み、他者が保持中だった（衝突を検出できた）。
        Held,
        /// それ以外（`flock` を試みる前の open の競合・開けない・ロック非対応等）。`flock` の衝突を
        /// 検出した証拠にならない。
        Other,
    }

    impl LockTry {
        fn of(result: &Result<crate::sys::LockHandle, crate::sys::LockError>) -> Self {
            match result {
                Ok(_) => Self::Locked,
                Err(crate::sys::LockError::Held) => Self::Held,
                Err(crate::sys::LockError::OpenContended | crate::sys::LockError::Io(_)) => {
                    Self::Other
                }
            }
        }
    }

    /// `flock` の排他性の判定（純粋関数）。`first` は走査位置ヒントのロック取得、`second` は取得できた
    /// 場合に同じファイルを別の open file description で開いて試した取得の結果。`flock` は open file
    /// description ごとのロックなので、排他が効くなら 2 回目は必ず「保持中」になる。1 回目が「保持中」
    /// （他の掃除が保持中）なら、衝突を検出できているので排他が効いている。「保持中」と数えるのは
    /// 実際に `flock` を試みて衝突した場合だけで、`flock` を試みる前の open の競合による打ち切り
    /// （`LockError::OpenContended`）は含めない。それ以外（2 回目も取れた・エラー）は排他を確認できない。
    pub(super) fn judge_flock_probe(first: LockTry, second: Option<LockTry>) -> FlockProbe {
        match (first, second) {
            (LockTry::Held, _) => FlockProbe::Exclusive,
            (LockTry::Locked, Some(LockTry::Held)) => FlockProbe::Exclusive,
            (LockTry::Locked, Some(LockTry::Locked)) => FlockProbe::NotExclusive,
            _ => FlockProbe::Unknown,
        }
    }

    /// 排他の確認中に、並行する掃除が走査位置ヒントを unlink・作り直した場合のやり直し回数。
    const FLOCK_PROBE_ATTEMPTS: usize = 4;

    /// 2 つの fd が同じ inode（dev / ino）を指すか。
    fn same_inode(a: &File, b: &File) -> io::Result<bool> {
        let (a, b) = (a.metadata()?, b.metadata()?);
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }

    /// 掃除の前に、この runtime directory で `flock` が排他になることを実際に確かめる（PLUG-12）。
    ///
    /// 掃除は「ロックファイルの `flock` を取れる = 以前の保持者は消えた」を根拠に socket を削除する。
    /// `flock` が黙って成功するだけで排他にならない配置先では、生存中の listener の socket を残骸と
    /// 誤認するため、確認できた場合だけ掃除する（確認できなければ掃除しない。fail-closed）。走査位置
    /// ヒントのロックを取り、同じファイルを別の open でロックできないことを確かめる。戻り値の
    /// ハンドルは、取得できた場合の走査位置ヒントのロック（そのまま [`SweepCursor`] に使う）。
    ///
    /// 2 回目の open は名前を引き直すため、並行する掃除がヒントを unlink・作り直すと別の inode を
    /// 開きうる。同じファイルで試したと言えるよう、2 回目の前後で名前が 1 回目の inode を指している
    /// ことを確かめ、2 回目も取れた場合は両方の fd が同じ inode のときだけ「排他が効かない」と判定する。
    /// 食い違った場合は [`FLOCK_PROBE_ATTEMPTS`] 回までやり直し、それでも確かめられなければ確認不能とする。
    ///
    /// 確かめられるのは同一ホスト内の排他だけである。複数ホストが同じ runtime directory を共有し、
    /// ロックがホスト間で伝わらない構成は検出できない（UDS はホスト内でしか接続できず、runtime
    /// directory は `XDG_RUNTIME_DIR` 等のホスト固有の場所に置く前提）。
    ///
    /// 確認にはヒントのファイルを開く・作る必要がある。開けない・作れない環境（書き込み不可・
    /// 同名が通常ファイル以外・ロック非対応等）では確認不能になり、掃除は毎回行われない（残骸は残る。
    /// 初期化時は構造化ログに出る）。確認不能・排他が効かないと判定した経路では、確認のために作った
    /// 空の `fcsweep-cursor` を削除せず残す（次回も同じファイルで確認する。掃除を行えた回は、
    /// 末尾まで走査し終えた時点で削除する）。
    fn probe_flock(dir: &File) -> (FlockProbe, Option<crate::sys::LockHandle>) {
        use crate::sys::{LockError, LockOpen, lock_file_at, names_open_file};
        let Ok(name) = std::ffi::CString::new(SWEEP_CURSOR_NAME) else {
            return (FlockProbe::Unknown, None);
        };
        for _ in 0..FLOCK_PROBE_ATTEMPTS {
            let first = lock_file_at(dir, &name, LockOpen::Create);
            let first_try = LockTry::of(&first);
            let Ok(held) = first else {
                return (judge_flock_probe(first_try, None), None);
            };
            match names_open_file(dir, &name, &held.file) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => return (FlockProbe::Unknown, None),
            }
            let second = lock_file_at(dir, &name, LockOpen::Existing);
            let second_try = LockTry::of(&second);
            // 2 回目が同じファイルを試したと言える場合だけ判定に使う。
            let same_file = match &second {
                Ok(other) => same_inode(&held.file, &other.file),
                Err(LockError::Held) => names_open_file(dir, &name, &held.file),
                // 並行する掃除が unlink した直後（名前が無い）。やり直す。
                Err(LockError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(_) => return (FlockProbe::Unknown, None),
            };
            match same_file {
                Ok(true) => {
                    let probe = judge_flock_probe(first_try, Some(second_try));
                    let handle = (probe == FlockProbe::Exclusive).then_some(held);
                    return (probe, handle);
                }
                Ok(false) => continue,
                Err(_) => return (FlockProbe::Unknown, None),
            }
        }
        (FlockProbe::Unknown, None)
    }

    impl SweepCursor {
        /// 取得済みのロック（[`probe_flock`]）から、検証して走査位置ヒントを開く。
        fn open(handle: crate::sys::LockHandle, euid: u32) -> Option<Self> {
            use std::os::unix::fs::FileExt;
            let name = std::ffi::CString::new(SWEEP_CURSOR_NAME).ok()?;
            let meta = handle.file.metadata().ok()?;
            if !meta.is_file()
                || meta.uid() != euid
                || meta.nlink() != 1
                || meta.len() > SWEEP_CURSOR_MAX_LEN as u64
            {
                return None;
            }
            let mut buf = [0u8; SWEEP_CURSOR_MAX_LEN];
            let n = handle.file.read_at(&mut buf, 0).ok()?;
            if n as u64 != meta.len() {
                return None;
            }
            let start = cursor_start(buf.get(..n)?)?;
            Some(Self {
                handle,
                name,
                start,
            })
        }

        /// 次回の開始位置を保存する。`None`（末尾まで走査し終えた）ならファイルを残さない。
        fn store(&self, dir: &File, next: Option<ScanPos>) {
            use std::os::unix::fs::FileExt;
            let Some(next) = next else {
                let _ = self.handle.file.set_len(0);
                // 名前がまだ自分の inode を指す場合だけ unlink する（別ファイルには触れない）。
                if matches!(
                    crate::sys::names_open_file(dir, &self.name, &self.handle.file),
                    Ok(true)
                ) {
                    let _ = crate::sys::unlinkat(dir, &self.name);
                }
                return;
            };
            if self.handle.file.set_len(0).is_ok() {
                let _ = self
                    .handle
                    .file
                    .write_all_at(format!("{} {}\n", next.offset, next.skip).as_bytes(), 0);
            }
        }
    }

    /// 列挙（段階 1）の結果。
    #[derive(Debug, Default)]
    struct Scan {
        /// 候補の socket 名（ロックファイル名から `.lock` を除いたもの）。`max_entries` 件以内。
        candidates: Vec<std::ffi::CString>,
        /// 上限で打ち切った場合の次回の開始位置。`None` は末尾まで走査し終えた。
        next: Option<ScanPos>,
        /// 読んだエントリの総数（再開位置までの読み飛ばし・打ち切り判定の 1 件を含む）。
        read: usize,
        /// 列挙の途中でエラーになった（残りは次回、先頭から走査し直す）。
        failed: bool,
    }

    /// 列挙の結果を掃除結果の初期値へ写す純粋関数。列挙が途中で失敗した場合は `incomplete` を立て
    /// （走査完了と区別する）、`skipped` に 1 件数える。
    fn scan_outcome(scan: &Scan) -> OneShotSweep {
        OneShotSweep {
            truncated: scan.next.is_some(),
            incomplete: scan.failed,
            skipped: u32::from(scan.failed),
            ..OneShotSweep::default()
        }
    }

    /// `start` から列挙して候補名を集める（何も削除しない）。
    ///
    /// 読み取り数の上限（REPAIR-5）: 走査するのは `max_scan` 件まで（打ち切り判定の 1 件を加えて
    /// `max_scan + 1` 件）。これとは別に `start.skip` 件を読み飛ばすが、`max_skip` 件を上限とする
    /// （ヒントが壊れていても超えない。超えた分は読み飛ばさずに走査する）。したがって 1 回の読み取り
    /// 総数は、ディレクトリの大きさに依らず `max_skip + max_scan + 1` 件以内に収まる。読み飛ばす件数は
    /// 位置からの通し件数で、libc のまとめ読みの区切り方（開き直すと変わりうる）には依らない。
    ///
    /// 打ち切るときは、次に読むはずだったエントリの位置（そのまとめ読みを始めたカーネル位置と、
    /// その中での件数）を `next` に返す。位置はまとめ読みの境界を越えるたびに先へ進むため、
    /// 削除対象外のエントリが何件続いても、次回は上限より後方から再開できる。
    fn scan_candidates(
        dir: &File,
        start: ScanPos,
        max_scan: usize,
        max_entries: usize,
        max_skip: u64,
    ) -> io::Result<Scan> {
        let mut stream = crate::sys::DirStream::open_at(dir, start.offset)?;
        let mut out = Scan::default();
        // 最後に観測したカーネル位置。fdopendir が最初のまとめ読みを先に済ませる実装でも境界を
        // 検出できるよう、初期値は開いた直後の位置ではなく自分で設定した `start.offset` にする。
        let mut kernel_pos = start.offset;
        // 次に読むエントリの位置（まとめ読みを始めた位置と、その中での件数）。
        let mut here = ScanPos {
            offset: start.offset,
            skip: 0,
        };
        let mut to_skip = start.skip.min(max_skip);
        let mut scanned = 0usize;
        loop {
            let entry =
                stream.next_entry(|name| one_shot_socket_name_of_lock(name).map(<[u8]>::to_vec));
            let candidate = match entry {
                Ok(Some(candidate)) => candidate,
                // 末尾まで走査し終えた。
                Ok(None) => return Ok(out),
                // 残りを諦め、次回は先頭から走査する。
                Err(_) => {
                    out.failed = true;
                    return Ok(out);
                }
            };
            let Ok(now) = stream.position() else {
                out.failed = true;
                return Ok(out);
            };
            out.read += 1;
            if now != kernel_pos {
                // このエントリは、`kernel_pos` から始まる新しいまとめ読みの先頭。
                here = ScanPos {
                    offset: kernel_pos,
                    skip: 0,
                };
                kernel_pos = now;
            }
            let this = here;
            here.skip = here.skip.saturating_add(1);
            if to_skip > 0 {
                to_skip -= 1;
                continue;
            }
            if scanned >= max_scan {
                out.next = Some(this);
                return Ok(out);
            }
            scanned += 1;
            let Some(socket) = candidate else {
                continue;
            };
            // 件数上限は候補だけを数える（対象外の名前で枠を消費して後方の残骸が飢餓しないように）。
            if out.candidates.len() >= max_entries {
                out.next = Some(this);
                return Ok(out);
            }
            // readdir の名前は NUL を含まないため失敗しない（失敗しても候補にしないだけ）。
            if let Ok(name) = std::ffi::CString::new(socket) {
                out.candidates.push(name);
            }
        }
    }

    /// 上限を引数に取る [`sweep_one_shot`] の本体（テストで小さい上限を注入する）。
    #[cfg(test)]
    pub(super) fn sweep_one_shot_limited(
        dir_path: &Path,
        euid: u32,
        max_scan: usize,
        max_entries: usize,
    ) -> Result<OneShotSweep, PluginError> {
        sweep_one_shot_counted(
            dir_path,
            euid,
            max_scan,
            max_entries,
            ONE_SHOT_SWEEP_MAX_SKIP,
        )
        .map(|(out, _)| out)
    }

    /// パスを正規化して runtime directory を開いて検証し、[`sweep_dir`] を呼ぶ（テスト用の入口。一時
    /// ディレクトリのパスは祖先に symlink を含みうるため正規化する。製品の経路は正規化し直さない）。
    #[cfg(test)]
    fn sweep_one_shot_counted(
        dir_path: &Path,
        euid: u32,
        max_scan: usize,
        max_entries: usize,
        max_skip: u64,
    ) -> Result<(OneShotSweep, usize), PluginError> {
        let real = std::fs::canonicalize(dir_path).map_err(|e| map_io(&e))?;
        let dir = open_nofollow(&real)?;
        verify(&fstat(&dir)?, euid)?;
        sweep_dir(&dir, euid, max_scan, max_entries, max_skip)
    }

    /// 掃除の本体（`dir` は検証済みの runtime directory の fd）。掃除結果と、列挙で読んだエントリの総数
    /// （読み取り上限の照合用）を返す。
    ///
    /// 走査は 2 段階: (1) 走査位置ヒントの位置から列挙して候補名だけを集める（[`scan_candidates`]。
    /// この間は何も削除しない。列挙中のディレクトリ変更で後続エントリが落ちないように）。列挙は
    /// 検証済みディレクトリ fd 基準で行い、パスを再解決しない。(2) 集めた候補を処理する。上限で
    /// 打ち切った場合は次回の開始位置を保存し、末尾まで走査し終えたらヒントを削除して先頭へ戻る（#1310）。
    ///
    /// この回に socket・ロックファイルを 1 つでも削除した場合は、打ち切り位置ではなく「この回の開始位置」を
    /// 保存し、次回は同じ位置から走査し直す。削除でディレクトリの並びが詰まると、打ち切り位置（まとめ
    /// 読みの境界からの件数）が指すエントリがずれ、未処理の残骸を飛ばしうるため。開始位置から走査し直せば、
    /// この回に走査した範囲のずれは影響しない。走査し直しても処理済みは消えており、削除が起きるたびに
    /// 残骸は減る。ただし開始位置そのものも常に不変ではない。削除される socket は候補のロックファイルとは
    /// 別のエントリで、開始位置より手前にありうる。位置が並び順の番号になるファイルシステムでは、その
    /// 削除で開始位置が指すエントリが後ろへずれ、間のエントリを飛ばしうる。飛ばした残骸は、末尾到達後に
    /// 先頭から始まる次の周回で処理する。1 つも削除しなかった回（候補がすべて使用中・削除根拠なし）は
    /// 打ち切り位置へ進むので、削除できない候補が上限を埋めても後方へ到達する。
    ///
    /// ヒントの位置から 1 件も読めなかった場合（ディレクトリが縮んだ・ヒントが壊れている・`lseek` が
    /// 拒否した）は、同じ回のうちに先頭から走査し直す（先頭側の取りこぼしを避ける）。
    fn sweep_dir(
        dir: &File,
        euid: u32,
        max_scan: usize,
        max_entries: usize,
        max_skip: u64,
    ) -> Result<(OneShotSweep, usize), PluginError> {
        // `flock` が排他になると確認できた場合だけ掃除する（PLUG-12。確認できなければ何も削除しない）。
        let (probe, handle) = probe_flock(dir);
        if probe != FlockProbe::Exclusive {
            return Err(err(
                PluginErrorCode::FailedPrecondition,
                "runtime directory does not provide verified exclusive file locks",
            ));
        }
        let cursor = handle.and_then(|h| SweepCursor::open(h, euid));
        let start = cursor.as_ref().map_or_else(ScanPos::default, |c| c.start);
        // 段階 1: 列挙して候補名を集める（削除しない）。
        let head = ScanPos::default();
        let mut read = 0usize;
        let mut resumed = None;
        // この回に実際に走査を始めた位置（ヒントを使えなかった場合は先頭）。
        let mut from = start;
        if start != head
            && let Ok(scan) = scan_candidates(dir, start, max_scan, max_entries, max_skip)
        {
            read = scan.read;
            resumed = (scan.read > 0).then_some(scan);
        }
        let scan = match resumed {
            Some(scan) => scan,
            None => {
                from = head;
                let scan =
                    scan_candidates(dir, head, max_scan, max_entries, max_skip).map_err(|_| {
                        err(
                            PluginErrorCode::Internal,
                            "failed to enumerate runtime directory",
                        )
                    })?;
                read = read.saturating_add(scan.read);
                scan
            }
        };
        let mut out = scan_outcome(&scan);
        // 段階 2: 集めた候補を処理する。socket・ロックファイルが実際に消えたかを確かめる。
        let mut removed_any = false;
        for name in &scan.candidates {
            out.examined += 1;
            let before = entry_count(dir, name);
            sweep_one(dir, name, euid, &mut out);
            removed_any |= entry_count(dir, name) < before;
        }
        if let Some(cursor) = &cursor {
            // 削除した回は開始位置から走査し直す（打ち切り位置は削除で並びが詰まるとずれるため）。
            cursor.store(
                dir,
                scan.next.map(|next| if removed_any { from } else { next }),
            );
        }
        Ok((out, read))
    }
    /// 候補の socket とそのロックファイルのうち、現在存在するエントリ数（0〜2）を返す。
    fn entry_count(dir: &File, socket: &std::ffi::CStr) -> usize {
        let mut lock = socket.to_bytes().to_vec();
        lock.extend_from_slice(b".lock");
        let lock_exists = std::ffi::CString::new(lock)
            .ok()
            .is_some_and(|l| !matches!(lstat_opt(dir, &l), Ok(None)));
        let socket_exists = !matches!(lstat_opt(dir, socket), Ok(None));
        usize::from(lock_exists) + usize::from(socket_exists)
    }

    /// 1 つの候補を stale 削除と同じ手順で処理し、結果を `out` に数える。
    fn sweep_one(dir: &File, name: &std::ffi::CStr, euid: u32, out: &mut OneShotSweep) {
        // 既存のロックファイルだけを開く（作成しない）。列挙後に消えた名前でロックファイルを作り直すと、
        // 同じ名前を bind しようとしている別プロセスと競合するため。
        let mut lock = match acquire_lock(dir, name, euid, crate::sys::LockOpen::Existing) {
            Ok(l) => l,
            // 列挙後に消えた（他の掃除・保持者の解放が片付けた）。何もしない。
            Err(e) if e.code() == PluginErrorCode::NotFound => return,
            Err(e) if e.code() == PluginErrorCode::AlreadyExists => {
                out.in_use += 1;
                return;
            }
            Err(_) => {
                out.skipped += 1;
                return;
            }
        };
        // 削除できない socket（symlink・他 UID 所有・socket 以外・記録なし／不一致・判定不能）には、
        // `clear_stale_socket` を呼ばずロックファイルも保持する。`clear_stale_socket` は拒否時にも
        // 記録を消す場合があり、空になったロックを drop が unlink すると、拒否した socket の
        // 削除根拠（PLUG-12）が失われるため。
        match lstat_opt(dir, name) {
            Ok(None) => {}
            Ok(Some(ident)) => {
                let deletable = matches!(
                    classify_existing(Some(&ident), euid),
                    ExistingEntry::OwnSocket(_)
                ) && record_key(&ident).is_some()
                    && lock.recorded() == record_key(&ident);
                if !deletable {
                    lock.retain();
                    out.skipped += 1;
                    return;
                }
            }
            Err(_) => {
                lock.retain();
                out.skipped += 1;
                return;
            }
        }
        let existed = matches!(lstat_opt(dir, name), Ok(Some(_)));
        let cleared = clear_stale_socket(dir, name, euid, &lock);
        let remains = !matches!(lstat_opt(dir, name), Ok(None));
        match (cleared, existed, remains) {
            (Ok(()), true, false) => out.removed += 1,
            // ロックファイルだけの残骸（socket は無い）。ロックの drop が unlink する。
            (Ok(()), false, false) => {}
            _ => out.skipped += 1,
        }
        // `lock` の drop で、記録が空になったロックファイルを unlink する。
    }

    /// 既存エントリの分類結果（PLUG-12・TASK-123.2）。
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum ExistingEntry {
        Absent,
        Symlink,
        ForeignOwner,
        NotSocket,
        OwnSocket(crate::sys::FileIdent),
    }

    /// lstat 結果と自 UID から分類する純粋関数（判定順: symlink → 所有者 → 種別）。
    pub(super) fn classify_existing(
        ident: Option<&crate::sys::FileIdent>,
        euid: u32,
    ) -> ExistingEntry {
        match ident {
            None => ExistingEntry::Absent,
            Some(i) if i.is_symlink => ExistingEntry::Symlink,
            Some(i) if i.uid != euid => ExistingEntry::ForeignOwner,
            Some(i) if !i.is_socket => ExistingEntry::NotSocket,
            Some(i) => ExistingEntry::OwnSocket(*i),
        }
    }

    fn err(code: PluginErrorCode, msg: &'static str) -> PluginError {
        PluginError::new(code, msg)
    }

    fn lstat_opt(
        dir: &File,
        name: &std::ffi::CStr,
    ) -> Result<Option<crate::sys::FileIdent>, PluginError> {
        match crate::sys::lstat_at(dir, name) {
            Ok(i) => Ok(Some(i)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(err(
                PluginErrorCode::PermissionDenied,
                "permission denied while inspecting existing socket path",
            )),
            Err(_) => Err(err(
                PluginErrorCode::Internal,
                "failed to inspect existing socket path",
            )),
        }
    }

    /// bind 用ロック（sibling の `<socket 名>.lock` への排他 flock。PLUG-12・TASK-123.2）。
    ///
    /// 保持者は listener の生存期間中ロックを持ち続ける（[`crate::transport::UdsListener`] の内部が
    /// 保持）。kernel はプロセス終了・クラッシュ時に自動解放するため、「ロックを取れる」ことが
    /// 「以前の保持者はもういない」の証拠になる。接続 probe は使わない（macOS では accept queue 満杯の
    /// 生存 listener にも ECONNREFUSED が返り stale と区別できず、probe 接続が相手の accept queue に
    /// 残る副作用もあるため）。
    ///
    /// # ロックファイルの削除
    /// ロックファイルは、記録が空（管理下の socket が残っていない）の場合に限り、保持者が解放の
    /// 直前に flock を持ったまま unlink する（bind 失敗時・正常終了時。記録が残る場合＝異常終了や
    /// socket の unlink 失敗時は残す）。socket 名ごとのロックファイルを溜めないため（都度起動モードは
    /// 起動ごとに別名の socket を使う）。排他は次の手順で保つ:
    /// - 取得側は flock の取得後に、ロックファイル名がいま持っている inode を指すことを確認し、
    ///   指していなければ（保持者が unlink した古い inode を掴んだ）捨てて開き直す。
    /// - 保持者が unlink するのは、自分の socket 操作をすべて終えた後（解放の直前）だけ。
    ///
    /// これにより、同じ名前に対して有効なロックを持てるのは常に 1 者になる。残ったロックファイルは
    /// 「管理下の証拠」にはならない（証拠は下記の記録と socket の同一性の一致だけ）。
    ///
    /// # fork
    /// flock は open file description に紐付くため、fork した子は listener の socket fd と一緒に
    /// ロック fd も継承する（どちらも `O_CLOEXEC` で exec 時に閉じる）。子が両方を持つ間は socket も
    /// 実際に接続可能なので stale ではなく、再 bind は `AlreadyExists` になる（fail-closed）。
    /// 子側のロックだけを外すと、生存中の socket を stale と誤認して削除し得るため行わない。
    /// 正常な解放では明示的に unlock する（unlock は open file description 単位で効くため、別スレッドの
    /// プロセス起動で fork から exec までの間だけ子が fd の複製を持っていても、解放が遅れない）。
    #[derive(Debug)]
    pub(crate) struct BindLock {
        /// flock を保持する fd（drop で解放）。
        file: File,
        /// 配置ディレクトリ fd の複製（解放時にロックファイルを fd 基準で unlink する）。
        dir: File,
        /// ロックファイル名（`<socket 名>.lock`）。
        lock_name: std::ffi::CString,
        /// true の間は drop でロックファイルを unlink しない（掃除が削除を拒否した socket の
        /// ロックを保持するため。#1310・PLUG-12）。
        keep: bool,
    }

    impl Drop for BindLock {
        fn drop(&mut self) {
            // 記録が空なら、このロックファイルを根拠に削除できる socket は無い。flock を持ったまま、
            // 名前がまだ自分の inode を指す場合だけ unlink する（別の inode には触れない）。
            let unrecorded = self.file.metadata().is_ok_and(|m| m.len() == 0);
            if !self.keep
                && unrecorded
                && matches!(
                    crate::sys::names_open_file(&self.dir, &self.lock_name, &self.file),
                    Ok(true)
                )
            {
                let _ = crate::sys::unlinkat(&self.dir, &self.lock_name);
            }
            let _ = self.file.unlock();
        }
    }

    /// ロックファイルへ書く「この socket は自分が bind した」記録の接頭辞（版付き）。
    /// 記録は `fcus2 <dev> <ino> <mtime 秒> <mtime ナノ秒>\n`（すべて 10 進）。
    const RECORD_PREFIX: &str = "fcus2";
    /// 記録の項目数（dev・ino・mtime 秒・mtime ナノ秒）。
    const RECORD_FIELDS: usize = 4;
    /// 旧形式（`fcus1 <dev> <ino>\n`）の接頭辞と項目数。専用ロックファイルとしては認めるが、mtime を
    /// 持たないため管理下の証拠にはしない。
    const LEGACY_RECORD: (&str, usize) = ("fcus1", 2);
    /// 記録の最大長（接頭辞＋u64 の 10 進 20 桁×4＋区切り＝90 を超えない範囲の上限）。
    const RECORD_MAX_LEN: usize = 96;

    /// socket の同一性を記録の項目へ変換する。dev / ino に加えて mtime を含めるのは、記録した socket が
    /// 外部で削除され、同じ inode 番号を再利用した別の socket がパスに置かれても一致させないため
    /// （後から作られた socket の mtime は記録時点より新しい）。負の mtime は表現せず None。
    fn record_key(ident: &crate::sys::FileIdent) -> Option<[u64; RECORD_FIELDS]> {
        Some([
            ident.dev,
            ident.ino,
            u64::try_from(ident.mtime_sec).ok()?,
            u64::from(ident.mtime_nsec),
        ])
    }

    impl BindLock {
        /// bind 済み socket の同一性（dev / ino / mtime）をロックファイルへ記録する。stale 判定は、残存
        /// ロックファイルの存在ではなく、この記録と socket の同一性の一致だけを管理下の証拠にする
        /// （他実装・別経路が同じパスに bind した socket を誤って削除しない。PLUG-12）。
        pub(crate) fn record_socket(&self, ident: &crate::sys::FileIdent) -> io::Result<()> {
            use std::os::unix::fs::FileExt;
            let [dev, ino, sec, nsec] =
                record_key(ident).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            self.file.set_len(0)?;
            let text = format!("{RECORD_PREFIX} {dev} {ino} {sec} {nsec}\n");
            self.file.write_all_at(text.as_bytes(), 0)
        }

        /// 記録を消す。記録した socket がパス上から無くなったと確認できた後にだけ呼ぶ
        /// （[`crate::transport::UdsListener`] の後始末と [`clear_stale_socket`] が、unlink 成功・不在・
        /// 別エントリへの差し替えを確認した後）。socket が残る場合は記録も残し、次回の bind が stale
        /// として削除できるようにする。
        pub(crate) fn clear_record(&self) -> io::Result<()> {
            self.file.set_len(0)
        }

        /// 記録された同一性（[`record_key`] と同じ並び）。無い・壊れている・旧形式の場合は None
        /// （管理下と見なさない）。
        fn recorded(&self) -> Option<[u64; RECORD_FIELDS]> {
            parse_record(&read_record(&self.file)?)
        }

        /// drop 時のロックファイル unlink を止める（記録も変更しない）。
        fn retain(&mut self) {
            self.keep = true;
        }
    }

    /// ロックファイルの先頭（記録の最大長まで）を読む。
    fn read_record(file: &File) -> Option<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let mut buf = [0u8; RECORD_MAX_LEN];
        let n = file.read_at(&mut buf, 0).ok()?;
        Some(buf.get(..n)?.to_vec())
    }

    /// 10 進数字だけからなる空でないバイト列を u64 として読む（符号・空白は受け付けない）。
    fn parse_decimal(b: &[u8]) -> Option<u64> {
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(b).ok()?.parse().ok()
    }

    /// 完全な記録（現行形式・末尾改行つき）だけを受け付ける。末尾の改行を必須にして、書き込みが
    /// 途中で止まった記録（数字が途中で切れた項目）を別の socket の同一性として読まない。
    pub(super) fn parse_record(b: &[u8]) -> Option<[u64; RECORD_FIELDS]> {
        let body = b.strip_suffix(b"\n")?;
        let rest = body
            .strip_prefix(RECORD_PREFIX.as_bytes())?
            .strip_prefix(b" ")?;
        let mut out = [0u64; RECORD_FIELDS];
        let mut tokens = rest.split(|c| *c == b' ');
        for slot in &mut out {
            *slot = parse_decimal(tokens.next()?)?;
        }
        tokens.next().is_none().then_some(out)
    }

    /// 完全な記録、または記録の書き込みが途中で止まったもの（完全な記録の接頭辞）か。現行形式と
    /// 旧形式の両方を認める。既存ロックファイルを「本実装の専用ファイル」と認める判定に使う。
    /// 書きかけ・旧形式を拒否するとその socket 名を以後 bind できなくなるため、管理下の証拠には
    /// しないが専用ファイルとしては認める。
    pub(super) fn is_record_fragment(b: &[u8]) -> bool {
        is_fragment_of(b, RECORD_PREFIX, RECORD_FIELDS)
            || is_fragment_of(b, LEGACY_RECORD.0, LEGACY_RECORD.1)
    }

    /// `b` が `<prefix> <10 進>×fields\n` の接頭辞（完全一致を含む）か。
    fn is_fragment_of(b: &[u8], prefix: &str, fields: usize) -> bool {
        let head = [prefix.as_bytes(), b" "].concat();
        let Some(rest) = b.strip_prefix(head.as_slice()) else {
            return head.starts_with(b);
        };
        let (body, complete) = match rest.strip_suffix(b"\n") {
            Some(x) => (x, true),
            None => (rest, false),
        };
        let tokens: Vec<&[u8]> = body.split(|c| *c == b' ').collect();
        let Some((last, init)) = tokens.split_last() else {
            return false;
        };
        let digits = |x: &[u8]| x.iter().all(u8::is_ascii_digit);
        // 途中の項目は空でない 10 進、最後の項目は書きかけ（空を含む）を許す。改行まで書かれて
        // いれば全項目が揃っていること。
        tokens.len() <= fields
            && init.iter().all(|t| !t.is_empty() && digits(t))
            && digits(last)
            && (!complete || (tokens.len() == fields && !last.is_empty()))
    }

    /// 取得した inode がロックファイル名から外れていた場合（保持者が解放時に unlink した）の再試行回数。
    const LOCK_ATTEMPTS: usize = 8;

    /// `name` に対応するロックを取得する。他者が保持中（生存中の listener）は `AlreadyExists`、
    /// symlink・他 UID 所有・通常ファイル以外は `PermissionDenied`（fail-closed）。
    ///
    /// 自分が作成した直後のロックファイルを掃除が先にロックしていた場合は、期限つきで待って取り直す
    /// （`crate::sys::lock_file_at` の「作成直後の競合」。#1310）。待ちは取得 1 回につき 100 ms で、
    /// 名前から外れた inode を掴むたびに作り直して取得し直すため、最悪は [`LOCK_ATTEMPTS`]（8 回）×
    /// 100 ms（約 0.8 秒）になる。呼び出し側の期限（`call_once` の合計期限等）とは連動しない。
    pub(crate) fn acquire_bind_lock(
        dir: &File,
        name: &std::ffi::CStr,
        euid: u32,
    ) -> Result<BindLock, PluginError> {
        acquire_lock(dir, name, euid, crate::sys::LockOpen::Bind)
    }

    /// [`acquire_bind_lock`] の本体。掃除は `LockOpen::Existing` で呼び、ロックファイルを作成しない
    /// （無ければ `NotFound`）。
    fn acquire_lock(
        dir: &File,
        name: &std::ffi::CStr,
        euid: u32,
        open: crate::sys::LockOpen,
    ) -> Result<BindLock, PluginError> {
        let invalid = || err(PluginErrorCode::InvalidArgument, "invalid socket path");
        let mut bytes = name.to_bytes().to_vec();
        bytes.extend_from_slice(b".lock");
        let lock_name = std::ffi::CString::new(bytes).map_err(|_| invalid())?;
        for _ in 0..LOCK_ATTEMPTS {
            let handle = match crate::sys::lock_file_at(dir, &lock_name, open) {
                Ok(h) => h,
                // 他者が保持中、または open の競合が上限まで続いた。どちらも使用中として扱う。
                Err(crate::sys::LockError::Held | crate::sys::LockError::OpenContended) => {
                    return Err(busy());
                }
                Err(crate::sys::LockError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(err(
                        PluginErrorCode::NotFound,
                        "socket lock file does not exist",
                    ));
                }
                Err(crate::sys::LockError::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied
                        || e.raw_os_error().is_some_and(is_symlink_errno) =>
                {
                    return Err(err(
                        PluginErrorCode::PermissionDenied,
                        "permission denied while locking socket path",
                    ));
                }
                Err(_) => {
                    return Err(err(PluginErrorCode::Internal, "failed to lock socket path"));
                }
            };
            // flock を取れても、名前が別の inode を指す（または消えた）なら、以前の保持者が解放時に
            // unlink した古い inode を掴んでいる。これを有効なロックと見なすと、同名の新しい inode を
            // ロックした別の bind と並走するため、捨てて開き直す。
            match crate::sys::names_open_file(dir, &lock_name, &handle.file) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => {
                    return Err(err(
                        PluginErrorCode::Internal,
                        "failed to inspect socket lock file",
                    ));
                }
            }
            return validate_lock(handle, dir, lock_name, euid);
        }
        // 取得と解放が繰り返し競合した。使用中として扱う（待ち続けない。REPAIR-5）。
        Err(busy())
    }

    /// 取得したロックファイルが自 UID 所有の専用ファイルかを確認し、[`BindLock`] にする。
    /// 拒否する場合はファイルに触れず（切り詰め・unlink をしない）fd を閉じるだけ。
    fn validate_lock(
        handle: crate::sys::LockHandle,
        dir: &File,
        lock_name: std::ffi::CString,
        euid: u32,
    ) -> Result<BindLock, PluginError> {
        let inspect = || {
            err(
                PluginErrorCode::Internal,
                "failed to inspect socket lock file",
            )
        };
        let meta = handle.file.metadata().map_err(|_| inspect())?;
        if !meta.is_file() || meta.uid() != euid {
            return Err(err(
                PluginErrorCode::PermissionDenied,
                "socket lock file is not owned by the current user",
            ));
        }
        // 既存ファイルは「専用ロックファイル」と確認できたものだけ受け入れる。ハードリンクされた
        // 他ファイル・無関係な既存ファイルを `record_socket` の `set_len(0)` や解放時の unlink で
        // 壊さないため、単一リンク（nlink == 1）かつ、空または本実装の記録形式（書きかけ・旧形式を
        // 含む・小サイズ）のみ許可する。
        if !handle.created {
            let valid = meta.nlink() == 1
                && meta.len() <= RECORD_MAX_LEN as u64
                && read_record(&handle.file)
                    .is_some_and(|b| b.len() as u64 == meta.len() && is_record_fragment(&b));
            if !valid {
                return Err(err(
                    PluginErrorCode::PermissionDenied,
                    "socket lock path is not a dedicated lock file",
                ));
            }
        }
        let dir = dir.try_clone().map_err(|_| inspect())?;
        Ok(BindLock {
            keep: false,
            file: handle.file,
            dir,
            lock_name,
        })
    }

    /// `O_NOFOLLOW` が symlink に対して返す errno（Linux: ELOOP=40、macOS: ELOOP=62）。
    fn is_symlink_errno(code: i32) -> bool {
        if cfg!(target_os = "macos") {
            code == 62
        } else {
            code == 40
        }
    }

    /// bind 前に既存エントリを検証し、自 UID 所有の stale socket のみ削除する（PLUG-12・TASK-123.2）。
    ///
    /// `UdsListener::bind` から、配置ディレクトリ検証後・`UnixListener::bind` の前に、`lock`
    /// 取得後に呼ばれる。ロックを保持している＝同ロックを使う生存中の listener は存在しないため、
    /// 自 UID 所有の socket のうち「ロックに記録した同一性（dev / ino / mtime）と一致する（管理下の）」
    /// ものだけを削除する。記録が無い・不一致の socket（他実装・旧版・残存ロックだけが根拠の
    /// もの）は生存中か判別できないため削除せず `AlreadyExists`（fail-closed）。削除は検証済み
    /// `dir` fd 基準の `unlinkat` のみ。
    ///
    /// 記録した socket がパス上に無いと確認できた場合（不在・別エントリ・今回削除した）は、戻る前に
    /// 記録を消す。削除済み socket の dev / ino を残すと、この後の bind が失敗した場合などに inode
    /// 番号の再利用で別経路の socket を管理下と誤認し得るため。検証が成功していて消去だけ失敗した場合は
    /// `Internal`（検証が既にエラーならそのエラーを優先して返す。記録は次回の bind で再度消去を試みる）。
    pub(crate) fn clear_stale_socket(
        dir: &File,
        name: &std::ffi::CStr,
        euid: u32,
        lock: &BindLock,
    ) -> Result<(), PluginError> {
        let (recorded_socket_remains, result) = remove_recorded_socket(dir, name, euid, lock);
        if !recorded_socket_remains && lock.clear_record().is_err() && result.is_ok() {
            return Err(err(
                PluginErrorCode::Internal,
                "failed to update socket lock record",
            ));
        }
        result
    }

    /// [`clear_stale_socket`] の本体。戻り値の bool は「記録した socket がパス上に残っている
    /// （または確認できなかった）」か。false のときだけ呼び出し側が記録を消す。
    fn remove_recorded_socket(
        dir: &File,
        name: &std::ffi::CStr,
        euid: u32,
        lock: &BindLock,
    ) -> (bool, Result<(), PluginError>) {
        let existing = match lstat_opt(dir, name) {
            Ok(i) => i,
            Err(e) => return (true, Err(e)),
        };
        let first = match classify_existing(existing.as_ref(), euid) {
            ExistingEntry::Absent => return (false, Ok(())),
            ExistingEntry::Symlink => {
                return (
                    false,
                    Err(err(
                        PluginErrorCode::PermissionDenied,
                        "socket path is a symlink",
                    )),
                );
            }
            ExistingEntry::ForeignOwner => {
                return (
                    false,
                    Err(err(
                        PluginErrorCode::PermissionDenied,
                        "socket path is owned by another user",
                    )),
                );
            }
            ExistingEntry::NotSocket => return (false, Err(busy())),
            ExistingEntry::OwnSocket(i) => i,
        };
        // 管理下の証拠は「ロックファイルの存在」ではなく、ロックに記録した socket の同一性
        // （dev / ino / mtime）と現在の socket の一致のみ。dev / ino だけでは、記録した socket が
        // 外部で削除された後に同じ inode 番号を再利用した別の socket と区別できない。記録が無い・不一致なら他実装や別経路が bind した
        // 可能性があるため削除しない（fail-closed）。
        let key = record_key(&first);
        if key.is_none() || lock.recorded() != key {
            return (false, Err(busy()));
        }
        // 削除直前に同一性を再確認する。
        match lstat_opt(dir, name) {
            Ok(None) => return (false, Ok(())),
            Ok(Some(now)) if now == first => {}
            Ok(Some(_)) => return (false, Err(busy())),
            Err(e) => return (true, Err(e)),
        }
        match crate::sys::unlinkat(dir, name) {
            Ok(()) => (false, Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (false, Ok(())),
            Err(_) => (
                true,
                Err(err(
                    PluginErrorCode::Internal,
                    "failed to remove stale socket",
                )),
            ),
        }
    }

    fn busy() -> PluginError {
        err(PluginErrorCode::AlreadyExists, "socket path already exists")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;

        fn ident(uid: u32, is_socket: bool, is_symlink: bool) -> crate::sys::FileIdent {
            crate::sys::FileIdent {
                dev: 1,
                ino: 2,
                uid,
                is_socket,
                is_symlink,
                mtime_sec: 3,
                mtime_nsec: 4,
            }
        }

        /// 走査位置ヒントの現在値を読む（無ければ `None`）。
        fn stored_pos(dir: &Path) -> Option<ScanPos> {
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            std::fs::read(dir.join(name))
                .ok()
                .map(|b| parse_scan_pos(&b).unwrap())
        }

        /// PLUG-7・REPAIR-5（#1310）: 保存の途中で切れた走査位置ヒント（書きかけ）は専用ファイルと認め、位置と
        /// しては使わず先頭から走査して、その回の結果で上書き・削除する（壊れたヒントが残り続けない）。
        /// 無関係な内容・旧形式（改行で終わるが項目が足りない）は書きかけと認めない。
        #[test]
        fn plug7_torn_cursor_is_recovered() {
            for torn in [&b"12"[..], b"12 ", b"12 3", b"18446744073709551615 1844"] {
                assert!(is_scan_pos_fragment(torn), "{torn:?}");
                assert_eq!(cursor_start(torn), Some(ScanPos::default()), "{torn:?}");
            }
            for other in [
                &b"12\n"[..],
                b" 12",
                b"12  3",
                b"12 3 4",
                b"not a hint",
                b"-1 0",
                b"123456789012345678901",
                b"1 123456789012345678901",
            ] {
                assert!(!is_scan_pos_fragment(other), "{other:?}");
                assert_eq!(cursor_start(other), None, "{other:?}");
            }
            assert_eq!(
                cursor_start(b"12 3\n"),
                Some(ScanPos {
                    offset: 12,
                    skip: 3
                })
            );
            let euid = crate::sys::effective_uid();
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            // 末尾まで走査し終えた回: 書きかけのヒントは削除される。
            let t = Tmp::new();
            std::fs::write(t.0.join(name), b"123 4").unwrap();
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 1024, 256, 65_536).unwrap();
            assert_eq!((r.examined, r.truncated, read), (1, false, 2));
            assert!(!lock.exists());
            assert_eq!(stored_pos(&t.0), None);
            // 上限で打ち切った回: 書きかけのヒントは完全な形式で上書きされ、次回から再開できる。
            let t = Tmp::new();
            std::fs::write(t.0.join(name), b"123 4").unwrap();
            for i in 0..5 {
                std::fs::write(t.0.join(format!("other-{i}")), b"").unwrap();
            }
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 2, 256, 65_536).unwrap();
            assert_eq!((r.truncated, read), (true, 3));
            let stored = std::fs::read(t.0.join(name)).unwrap();
            let pos = parse_scan_pos(&stored).expect("hint must be rewritten in full form");
            assert_eq!(pos.skip, 2);
        }

        /// PLUG-7・REPAIR-5（#1310）: 走査位置ヒントは `<offset> <skip>\n` に厳密一致する内容だけを受け付ける。
        #[test]
        fn plug7_scan_pos_parser_is_strict() {
            assert_eq!(parse_scan_pos(b""), Some(ScanPos { offset: 0, skip: 0 }));
            assert_eq!(
                parse_scan_pos(b"12 3\n"),
                Some(ScanPos {
                    offset: 12,
                    skip: 3
                })
            );
            assert_eq!(
                parse_scan_pos(b"18446744073709551615 0\n"),
                Some(ScanPos {
                    offset: u64::MAX,
                    skip: 0
                })
            );
            for bad in [
                &b"12\n"[..],
                b"12 3",
                b"12 3 4\n",
                b"12  3\n",
                b" 12 3\n",
                b"-1 0\n",
                b"a b\n",
                b"18446744073709551616 0\n",
                b"not a hint",
            ] {
                assert_eq!(parse_scan_pos(bad), None, "{bad:?}");
            }
        }

        /// PLUG-7・REPAIR-5（#1310）: 先頭に走査上限（8 件）以上の対象外エントリがあっても、1 回の読み取りを
        /// 上限内に保ったまま複数回の掃除で後方の残骸へ到達する。20 件の対象外 + ロック 1 件 + ヒント自身の
        /// 22 エントリを 8 件ずつ走査するので、3 回（打ち切った回にロックを消した場合は、その回を同じ位置から
        /// 走査し直すため 4 回）で末尾に達してヒントが消える。
        #[test]
        fn plug7_repair5_sweep_reaches_leftover_behind_scan_limit() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            const MAX_SCAN: usize = 8;
            for i in 0..20 {
                std::fs::write(t.0.join(format!("other-{i}")), b"").unwrap();
            }
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let mut truncated = Vec::new();
            // 削除した回は同じ位置から走査し直すため、打ち切った回にロックを消したら 1 回増える。
            let mut repeated = 0;
            loop {
                let skip = stored_pos(&t.0).map_or(0, |p| p.skip) as usize;
                let existed = lock.exists();
                let (r, read) = sweep_one_shot_counted(&t.0, euid, MAX_SCAN, 256, 65_536).unwrap();
                assert!(read <= skip + MAX_SCAN + 1, "read={read} skip={skip}");
                truncated.push(r.truncated);
                repeated += usize::from(existed && !lock.exists() && r.truncated);
                if !r.truncated {
                    break;
                }
                assert!(truncated.len() < 4, "truncated={truncated:?}");
            }
            assert_eq!(truncated.len(), 3 + repeated, "truncated={truncated:?}");
            assert!(!lock.exists());
            assert_eq!(stored_pos(&t.0), None);
        }

        /// PLUG-7・REPAIR-5（#1310）: libc のまとめ読みをまたぐ大きさ（対象外 6,100 件）でも、再開位置は
        /// カーネルのディレクトリ位置で進み、各回の読み取りは「読み飛ばし + 上限 500 件 + 1」以内に収まる。
        /// 6,102 エントリ（対象外 + ロック + ヒント自身）を 500 件ずつ走査するので 13 回（打ち切った回に
        /// ロックを消した場合は、その回を同じ位置から走査し直すため 14 回）で末尾に達し、どこにあっても
        /// 残骸のロックが消える。読み取り総数はエントリ数に比例する（件数で読み飛ばす
        /// 方式では回ごとに先頭から読み直すため、回数に比例して増える）。
        #[test]
        fn plug7_repair5_sweep_resumes_by_kernel_position_in_large_directory() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            const MAX_SCAN: usize = 500;
            const OTHERS: usize = 6_100;
            for i in 0..OTHERS {
                std::fs::write(t.0.join(format!("other-{i:04}")), b"").unwrap();
            }
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let mut passes = 0;
            let mut repeated = 0;
            let mut total_read = 0;
            let mut offsets = std::collections::BTreeSet::new();
            // 失敗時の診断用: 各回の（開始位置, 読み取り数, 打ち切り）。
            let mut history = Vec::new();
            loop {
                let before = stored_pos(&t.0);
                let skip = before.map_or(0, |p| p.skip) as usize;
                let existed = lock.exists();
                let (r, read) = sweep_one_shot_counted(&t.0, euid, MAX_SCAN, 256, 65_536).unwrap();
                history.push((before, read, r.truncated));
                repeated += usize::from(existed && !lock.exists() && r.truncated);
                passes += 1;
                total_read += read;
                assert!(skip < OTHERS, "skip={skip}");
                assert!(read <= skip + MAX_SCAN + 1, "read={read} skip={skip}");
                if let Some(p) = stored_pos(&t.0) {
                    offsets.insert(p.offset);
                }
                if !r.truncated {
                    break;
                }
                assert!(passes < 14, "sweep did not reach the end: {history:?}");
            }
            assert_eq!(passes, 13 + repeated, "history={history:?}");
            assert!(!lock.exists());
            assert_eq!(stored_pos(&t.0), None);
            // 先頭（0）以外のカーネル位置から再開した回がある（まとめ読みの境界を越えて進んだ）。
            assert!(offsets.iter().any(|o| *o != 0), "offsets={offsets:?}");
            // 読み取り総数はエントリ数に比例する（各回の読み飛ばしはまとめ読み 1 回分のエントリ数未満）。
            assert!(total_read < 4 * OTHERS, "total_read={total_read}");
        }

        /// PLUG-7・REPAIR-5（#1310）: `lseek` が拒否する位置・巨大な読み飛ばし件数のヒント（破損・改ざん）でも
        /// 有限の読み取りで終わり、残骸は高々 2 回の掃除で消える。
        #[test]
        fn plug7_cursor_garbage_position_terminates_and_recovers() {
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            let euid = crate::sys::effective_uid();
            // (a) 位置が不正（`lseek` が失敗する）: 同じ回のうちに先頭から走査し直す。
            let t = Tmp::new();
            std::fs::write(t.0.join(name), b"18446744073709551615 7\n").unwrap();
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 1024, 256, 65_536).unwrap();
            assert_eq!((r.examined, r.truncated, read), (1, false, 2));
            assert!(!lock.exists());
            assert_eq!(stored_pos(&t.0), None);
            // (b) 読み飛ばし件数が巨大: 読み飛ばしの途中（2 エントリ）で末尾に達して終わり、ヒントを
            // 消す。残骸は次の回に先頭から走査して消える。
            let t = Tmp::new();
            std::fs::write(t.0.join(name), b"0 999999999\n").unwrap();
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 1024, 256, 65_536).unwrap();
            assert_eq!((r.examined, r.truncated, read), (0, false, 2));
            assert!(lock.exists());
            assert_eq!(stored_pos(&t.0), None);
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 1024, 256, 65_536).unwrap();
            assert_eq!((r.examined, r.truncated, read), (1, false, 2));
            assert!(!lock.exists());
        }

        /// REPAIR-5（#1310）: ヒントの読み飛ばし件数は上限（ここでは 4 件）で打ち切り、超えた分は読み飛ばさずに
        /// 走査する。ロック 30 件 + ヒント自身の 31 エントリに対し「先頭から 25 件読み飛ばす」ヒントを与えても、
        /// 読み飛ばすのは 4 件だけで、残り 27 エントリ（ロックは 26 件以上）を走査する。
        #[test]
        fn repair5_cursor_skip_is_capped() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            for i in 0..30 {
                std::fs::write(t.0.join(format!("oneshot-1-{i}.sock.lock")), b"").unwrap();
            }
            std::fs::write(t.0.join(name), b"0 25\n").unwrap();
            let (r, read) = sweep_one_shot_counted(&t.0, euid, 1024, 256, 4).unwrap();
            assert_eq!((read, r.truncated), (31, false));
            assert!((26..=27).contains(&r.examined), "examined={}", r.examined);
            assert_eq!(stored_pos(&t.0), None);
        }

        /// PLUG-7（#1310）: 削除した回は開始位置から走査し直すため、削除で並びが詰まっても未処理の残骸を
        /// 飛ばさない。候補上限 2 件でロック 6 件を掃除すると、ちょうど 3 回ですべて消える。
        #[test]
        fn plug7_cursor_restarts_pass_after_removal() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let locks: Vec<_> = (0..6)
                .map(|i| t.0.join(format!("oneshot-1-{i}.sock.lock")))
                .collect();
            for l in &locks {
                std::fs::write(l, b"").unwrap();
            }
            let mut results = Vec::new();
            for _ in 0..3 {
                let r = sweep_one_shot_limited(&t.0, euid, 1024, 2).unwrap();
                results.push((r.examined, r.truncated));
            }
            assert_eq!(results, [(2, true), (2, true), (2, false)]);
            assert_eq!(locks.iter().filter(|l| l.exists()).count(), 0);
            assert_eq!(stored_pos(&t.0), None);
        }

        /// PLUG-12（#1310）: 削除を拒否する socket（symlink・記録なしの socket 以外）のロックファイルは、
        /// 掃除で記録も unlink もされず保持される。
        #[test]
        fn plug12_sweep_keeps_lock_of_refused_socket() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let target = t.0.join("target");
            std::fs::write(&target, b"x").unwrap();
            std::os::unix::fs::symlink(&target, t.0.join("oneshot-1-0.sock")).unwrap();
            std::fs::write(t.0.join("oneshot-1-0.sock.lock"), b"").unwrap();
            std::fs::write(t.0.join("oneshot-1-1.sock"), b"regular").unwrap();
            std::fs::write(t.0.join("oneshot-1-1.sock.lock"), b"").unwrap();
            let r = sweep_one_shot_limited(&t.0, euid, 1024, 256).unwrap();
            assert_eq!(r.removed, 0);
            assert_eq!(r.skipped, 2);
            assert!(t.0.join("oneshot-1-0.sock.lock").exists());
            assert!(t.0.join("oneshot-1-1.sock.lock").exists());
            assert!(t.0.join("oneshot-1-0.sock").symlink_metadata().is_ok());
            assert_eq!(std::fs::read(&target).unwrap(), b"x");
        }

        /// REPAIR-5・PLUG-7（#1310）: ハードリンクされた既存ファイル・無関係な内容の既存ファイルを
        /// 走査位置ヒントとして使わず、内容を壊さない。
        #[test]
        fn plug7_cursor_rejects_non_dedicated_file_and_keeps_content() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            let victim = t.0.join("victim");
            std::fs::write(&victim, b"precious data").unwrap();
            std::fs::hard_link(&victim, t.0.join(name)).unwrap();
            std::fs::write(t.0.join("oneshot-1-0.sock.lock"), b"").unwrap();
            let r = sweep_one_shot_limited(&t.0, euid, 1024, 256).unwrap();
            assert!(!r.truncated);
            assert_eq!(std::fs::read(&victim).unwrap(), b"precious data");
            assert!(t.0.join(name).exists());
            // 単一リンクでも内容が形式外なら使わず、触れない。
            std::fs::remove_file(t.0.join(name)).unwrap();
            std::fs::write(t.0.join(name), b"not a hint").unwrap();
            sweep_one_shot_limited(&t.0, euid, 1024, 256).unwrap();
            assert_eq!(std::fs::read(t.0.join(name)).unwrap(), b"not a hint");
        }

        /// REPAIR-5・PLUG-7（#1310）: 削除できない候補（使用中）が上限を埋めても、保存位置は巻き戻らず
        /// 後方の残骸へ複数回で到達する。
        #[test]
        fn plug7_cursor_advances_past_undeletable_candidates() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let mut held = Vec::new();
            for i in 0..4 {
                let p = t.0.join(format!("oneshot-1-{i}.sock.lock"));
                let f = std::fs::File::create(&p).unwrap();
                f.lock().unwrap();
                held.push(f);
            }
            for i in 0..4 {
                std::fs::write(t.0.join(format!("other-{i}")), b"").unwrap();
            }
            let tail = t.0.join("oneshot-2-0.sock.lock");
            std::fs::write(&tail, b"").unwrap();
            for _ in 0..40 {
                let r = sweep_one_shot_limited(&t.0, euid, 16, 2).unwrap();
                if !r.truncated {
                    break;
                }
            }
            assert!(!tail.exists());
            drop(held);
        }

        /// REPAIR-5（#1310）: ディレクトリの末尾より先を指す位置のヒントでも 1 件も読まずに末尾と分かり、
        /// 同じ回のうちに先頭から走査し直して走査完了（ヒント削除）に戻る。
        #[test]
        fn plug7_cursor_beyond_directory_size_terminates_and_resets() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let name = std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap();
            std::fs::write(t.0.join(name), b"999999999 0\n").unwrap();
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let r = sweep_one_shot_limited(&t.0, euid, 1024, 256).unwrap();
            assert_eq!(r.examined, 1);
            assert!(!lock.exists());
            assert!(!t.0.join(name).exists());
        }

        #[test]
        fn plug12_classify_existing_symlink_wins_over_owner() {
            let i = ident(7, false, true);
            assert_eq!(classify_existing(Some(&i), 7), ExistingEntry::Symlink);
            assert_eq!(classify_existing(Some(&i), 8), ExistingEntry::Symlink);
        }

        #[test]
        fn plug12_classify_existing_foreign_owner_for_file_and_socket() {
            for sock in [false, true] {
                let i = ident(7, sock, false);
                assert_eq!(
                    classify_existing(Some(&i), 7u32.wrapping_add(1)),
                    ExistingEntry::ForeignOwner
                );
            }
        }

        #[test]
        fn plug12_classify_existing_own_entries() {
            assert_eq!(classify_existing(None, 7), ExistingEntry::Absent);
            let f = ident(7, false, false);
            assert_eq!(classify_existing(Some(&f), 7), ExistingEntry::NotSocket);
            let s = ident(7, true, false);
            assert_eq!(classify_existing(Some(&s), 7), ExistingEntry::OwnSocket(s));
        }

        #[test]
        fn plug12_clear_stale_socket_rejects_foreign_uid_and_keeps_file() {
            let d = std::env::temp_dir().join(format!("fcst-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            let sock = d.join("s");
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let dir = File::open(&d).unwrap();
            let name = std::ffi::CString::new("s").unwrap();
            let euid = crate::sys::effective_uid();
            let lock = acquire_bind_lock(&dir, &name, euid).unwrap();
            let e = clear_stale_socket(&dir, &name, euid.wrapping_add(1), &lock).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert!(sock.exists());
            // 存在しない名前は Ok。
            let none = std::ffi::CString::new("nope").unwrap();
            let lock2 = acquire_bind_lock(&dir, &none, euid).unwrap();
            assert_eq!(clear_stale_socket(&dir, &none, euid, &lock2), Ok(()));
            drop(_l);
            std::fs::remove_dir_all(&d).ok();
        }

        struct Tmp(std::path::PathBuf);
        impl Tmp {
            fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "fcus-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                DirBuilder::new().mode(0o700).create(&p).unwrap();
                Self(p)
            }
        }
        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// PLUG-12（#1310）: bind 側がロックファイルを作成（`O_EXCL`）してから `flock` を取るまでの間に、
        /// 別プロセスの掃除が先に `flock` を取った場合を再現する。割り込んだ側は 20 ms 後に空のロック
        /// ファイルを unlink して解放する（掃除の `BindLock` の drop と同じ）。bind 側は待って取り直し、
        /// 名前から外れた inode を捨てて作り直すので、`AlreadyExists` で失敗せずロックを得る。
        #[test]
        fn plug12_bind_lock_waits_for_sweeper_that_won_flock_after_create() {
            use std::sync::{Arc, Mutex};
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = File::open(&t.0).unwrap();
            let name = c"oneshot-1-0.sock";
            let lock_path = t.0.join("oneshot-1-0.sock.lock");
            let intruder = Arc::new(Mutex::new(None));
            let (slot, path) = (Arc::clone(&intruder), lock_path.clone());
            crate::sys::lock_test_hook::set(move |_, _| {
                let held = File::open(&path).unwrap();
                held.try_lock().unwrap();
                *slot.lock().unwrap() = Some(std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    std::fs::remove_file(&path).unwrap();
                    drop(held);
                }));
            });
            let lock = acquire_bind_lock(&dir, name, euid).unwrap();
            let handle = intruder.lock().unwrap().take();
            handle.expect("hook must have run once").join().unwrap();
            // 得たロックは、いま名前が指しているファイルのもの（他者は取れない）。
            assert!(lock_path.exists());
            let other = File::open(&lock_path).unwrap();
            assert!(matches!(
                other.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            assert_eq!(
                acquire_bind_lock(&dir, name, euid).unwrap_err().code(),
                PluginErrorCode::AlreadyExists
            );
            drop(lock);
        }

        /// PLUG-12（#1310）: 実際の掃除（`sweep_one`）が、bind 側の作成と `flock` の間に走り切った場合。
        /// 掃除は socket の無い空のロックファイルを unlink する（削除 0・使用中 0・飛ばし 0）。bind 側は
        /// 名前から外れた inode を掴むが、それを捨てて作り直し、ロックを得る。
        #[test]
        fn plug12_bind_lock_survives_sweep_between_create_and_flock() {
            use std::sync::{Arc, Mutex};
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = File::open(&t.0).unwrap();
            let name = c"oneshot-1-0.sock";
            let lock_path = t.0.join("oneshot-1-0.sock.lock");
            let seen = Arc::new(Mutex::new(None));
            let (slot, path) = (Arc::clone(&seen), lock_path.clone());
            crate::sys::lock_test_hook::set(move |d, _| {
                let existed = path.exists();
                let mut out = OneShotSweep::default();
                sweep_one(d, c"oneshot-1-0.sock", euid, &mut out);
                *slot.lock().unwrap() = Some((existed, path.exists(), out));
            });
            let lock = acquire_bind_lock(&dir, name, euid).unwrap();
            assert_eq!(
                *seen.lock().unwrap(),
                Some((true, false, OneShotSweep::default()))
            );
            assert!(lock_path.exists());
            assert_eq!(
                acquire_bind_lock(&dir, name, euid).unwrap_err().code(),
                PluginErrorCode::AlreadyExists
            );
            drop(lock);
        }

        /// PLUG-12・REPAIR-5（#1310）: 作成直後に割り込んだ側がロックを解放しない場合、bind 側は取得 1 回分の
        /// 100 ms（1 ms × 100 回）だけ待って `AlreadyExists` を返す（待ち続けない）。走査位置ヒント用の
        /// `LockOpen::Create` は待たずに `WouldBlock` を返す。
        #[test]
        fn repair5_bind_lock_wait_after_create_is_bounded() {
            use std::sync::{Arc, Mutex};
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = File::open(&t.0).unwrap();
            let held = Arc::new(Mutex::new(Vec::new()));
            let hold = |file: &'static str| {
                let (slot, path) = (Arc::clone(&held), t.0.join(file));
                crate::sys::lock_test_hook::set(move |_, _| {
                    let f = File::open(&path).unwrap();
                    f.try_lock().unwrap();
                    slot.lock().unwrap().push(f);
                });
            };
            hold("oneshot-1-0.sock.lock");
            let started = std::time::Instant::now();
            let e = acquire_bind_lock(&dir, c"oneshot-1-0.sock", euid).unwrap_err();
            let waited = started.elapsed();
            assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
            assert!(
                waited >= std::time::Duration::from_millis(100)
                    && waited < std::time::Duration::from_secs(10),
                "waited={waited:?}"
            );
            hold("hint");
            let started = std::time::Instant::now();
            let e =
                crate::sys::lock_file_at(&dir, c"hint", crate::sys::LockOpen::Create).unwrap_err();
            assert!(matches!(e, crate::sys::LockError::Held), "{e:?}");
            assert!(started.elapsed() < std::time::Duration::from_millis(100));
            assert_eq!(held.lock().unwrap().len(), 2);
        }

        /// REPAIR-4・PLUG-7（#1310）: 列挙が途中で失敗した掃除は走査完了と区別でき（`incomplete`）、初期化時は
        /// 失敗の構造化ログを出す。末尾まで走査した・上限で打ち切った場合は出さない。
        #[test]
        fn repair4_sweep_failure_is_reported_not_dropped() {
            let failed = scan_outcome(&Scan {
                failed: true,
                ..Scan::default()
            });
            assert_eq!(
                (failed.incomplete, failed.truncated, failed.skipped),
                (true, false, 1)
            );
            assert_eq!(
                sweep_failure_log(Ok(&failed)).as_deref(),
                Some(
                    "{\"op\":\"plugin.sweep_one_shot\",\"success\":false,\
                     \"error_code\":null,\"incomplete\":true}"
                )
            );
            let e = err(
                PluginErrorCode::Internal,
                "failed to enumerate runtime directory",
            );
            assert_eq!(
                OneShotSweep::failure_json_line(Some(PluginErrorCode::PermissionDenied), false),
                "{\"op\":\"plugin.sweep_one_shot\",\"success\":false,\
                 \"error_code\":\"PERMISSION_DENIED\",\"incomplete\":false}"
            );
            assert_eq!(
                sweep_failure_log(Err(&e)).as_deref(),
                Some(
                    "{\"op\":\"plugin.sweep_one_shot\",\"success\":false,\
                     \"error_code\":\"INTERNAL\",\"incomplete\":false}"
                )
            );
            let truncated = scan_outcome(&Scan {
                next: Some(ScanPos { offset: 7, skip: 1 }),
                ..Scan::default()
            });
            assert_eq!(
                (truncated.incomplete, truncated.truncated, truncated.skipped),
                (false, true, 0)
            );
            assert_eq!(sweep_failure_log(Ok(&truncated)), None);
            assert_eq!(sweep_failure_log(Ok(&OneShotSweep::default())), None);
        }

        /// PLUG-12（#1310）: 初期化後に runtime directory の名前が symlink へ差し替えられた場合、公開の掃除は
        /// リンク先を辿らず `PermissionDenied` で拒否し、リンク先の残骸（削除できる形のロックファイル）にも
        /// 元のディレクトリの残骸にも触れない。
        #[test]
        fn plug12_public_sweep_rejects_runtime_dir_swapped_to_symlink() {
            let t = Tmp::new();
            let base = t.0.canonicalize().unwrap();
            let euid = crate::sys::effective_uid();
            let dir = ensure_dir(&base, euid).unwrap();
            let original_lock = dir.path().join("oneshot-1-0.sock.lock");
            std::fs::write(&original_lock, b"").unwrap();
            let moved = base.join("moved");
            std::fs::rename(dir.path(), &moved).unwrap();
            let decoy = base.join("decoy");
            DirBuilder::new().mode(0o700).create(&decoy).unwrap();
            let decoy_lock = decoy.join("oneshot-2-0.sock.lock");
            std::fs::write(&decoy_lock, b"").unwrap();
            std::os::unix::fs::symlink(&decoy, dir.path()).unwrap();
            let e = sweep_one_shot_leftovers(&dir).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert!(decoy_lock.exists());
            assert!(moved.join("oneshot-1-0.sock.lock").exists());
            assert_eq!(std::fs::read_dir(&decoy).unwrap().count(), 1);
            // 差し替えを戻せば、同じ `RuntimeDir` で掃除できる。
            std::fs::remove_file(dir.path()).unwrap();
            std::fs::rename(&moved, dir.path()).unwrap();
            let r = sweep_one_shot_leftovers(&dir).unwrap();
            assert_eq!((r.examined, r.truncated), (1, false));
            assert!(!original_lock.exists());
        }

        /// PLUG-12（#1310）: 掃除は `flock` の排他を確認できた場合だけ行う。自分が保持するロックを別の open
        /// からも取れた（排他が効かない）・確認できなかった場合は排他と判定しない。実際の一時ディレクトリ
        /// では排他と判定され、他者が走査位置ヒントを保持中でも（衝突を検出できるので）排他と判定する。
        #[test]
        fn plug12_sweep_requires_verified_exclusive_flock() {
            use LockTry::{Held, Locked, Other};
            assert_eq!(judge_flock_probe(Locked, Some(Held)), FlockProbe::Exclusive);
            assert_eq!(judge_flock_probe(Held, None), FlockProbe::Exclusive);
            assert_eq!(
                judge_flock_probe(Locked, Some(Locked)),
                FlockProbe::NotExclusive
            );
            assert_eq!(judge_flock_probe(Locked, Some(Other)), FlockProbe::Unknown);
            assert_eq!(judge_flock_probe(Locked, None), FlockProbe::Unknown);
            assert_eq!(judge_flock_probe(Other, None), FlockProbe::Unknown);
            let t = Tmp::new();
            let dir = File::open(&t.0).unwrap();
            let (probe, handle) = probe_flock(&dir);
            assert_eq!((probe, handle.is_some()), (FlockProbe::Exclusive, true));
            // 他者（別の open）が走査位置ヒントを保持中: 排他と判定し、ヒントは使わない。
            let (probe, second) = probe_flock(&dir);
            assert_eq!((probe, second.is_some()), (FlockProbe::Exclusive, false));
            drop(handle);
            // 確認できた一時ディレクトリでは、掃除は従来どおり残骸を消す。
            let lock = t.0.join("oneshot-1-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let r = sweep_one_shot_limited(&t.0, crate::sys::effective_uid(), 1024, 256).unwrap();
            assert_eq!((r.examined, r.truncated, r.incomplete), (1, false, false));
            assert!(!lock.exists());
        }

        /// PLUG-12・REPAIR-5（#1310）: `flock` を試みる前の open の競合が上限（8 回）まで続いた打ち切りは、
        /// 「保持中」とは別の失敗（`OpenContended`）で返る。`flock` の衝突を検出した証拠にならないので
        /// 排他の確認は確認不能になり、掃除は `FailedPrecondition` で何も削除しない。bind にとっては
        /// 従来どおり使用中（`AlreadyExists`）。
        #[test]
        fn plug12_open_contention_is_not_evidence_of_exclusive_flock() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = File::open(&t.0).unwrap();
            crate::sys::lock_test_hook::contend_opens(8);
            let e =
                crate::sys::lock_file_at(&dir, c"hint", crate::sys::LockOpen::Create).unwrap_err();
            assert!(matches!(e, crate::sys::LockError::OpenContended), "{e:?}");
            assert_eq!(std::fs::read_dir(&t.0).unwrap().count(), 0);

            crate::sys::lock_test_hook::contend_opens(8);
            assert_eq!(
                acquire_bind_lock(&dir, c"oneshot-1-0.sock", euid)
                    .unwrap_err()
                    .code(),
                PluginErrorCode::AlreadyExists
            );

            let lock = t.0.join("oneshot-2-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            crate::sys::lock_test_hook::contend_opens(8);
            let (probe, handle) = probe_flock(&dir);
            assert_eq!((probe, handle.is_some()), (FlockProbe::Unknown, false));
            crate::sys::lock_test_hook::contend_opens(8);
            let e = sweep_dir(&dir, euid, 1024, 256, 65_536).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
            assert!(lock.exists());
            // 競合が無ければ、同じディレクトリで排他を確認でき、残骸を消す。
            let (r, _) = sweep_dir(&dir, euid, 1024, 256, 65_536).unwrap();
            assert_eq!((r.examined, r.truncated), (1, false));
            assert!(!lock.exists());
        }

        /// PLUG-12（#1310）: 排他の確認は、並行する掃除が走査位置ヒントを unlink・作り直しても誤判定しない。
        /// 1 回目の取得（作成）の直後に名前が別の inode へ差し替わった場合は、その回を判定に使わず
        /// やり直し、排他と判定する（得たロックは、いま名前が指しているファイルのもの）。
        #[test]
        fn plug12_flock_probe_retries_when_hint_is_replaced() {
            let t = Tmp::new();
            let dir = File::open(&t.0).unwrap();
            let path = t.0.join(std::str::from_utf8(SWEEP_CURSOR_NAME).unwrap());
            crate::sys::lock_test_hook::set(move |_, _| {
                std::fs::remove_file(&path).unwrap();
                std::fs::write(&path, b"").unwrap();
            });
            let (probe, handle) = probe_flock(&dir);
            assert_eq!((probe, handle.is_some()), (FlockProbe::Exclusive, true));
            let held = handle.unwrap();
            assert!(crate::sys::names_open_file(&dir, c"fcsweep-cursor", &held.file).unwrap());
        }

        /// PLUG-7・PLUG-12（#1310）: 掃除はロックファイルを作成しない。列挙後に消えた名前を処理しても
        /// 何も作らず、何も数えない（bind しようとしている別プロセスと同じ名前で競合しない）。
        #[test]
        fn plug7_sweep_does_not_create_lock_files() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = File::open(&t.0).unwrap();
            let mut out = OneShotSweep::default();
            sweep_one(&dir, c"oneshot-1-0.sock", euid, &mut out);
            assert_eq!(out, OneShotSweep::default());
            assert_eq!(std::fs::read_dir(&t.0).unwrap().count(), 0);
            let e = crate::sys::lock_file_at(
                &dir,
                c"oneshot-1-0.sock.lock",
                crate::sys::LockOpen::Existing,
            )
            .unwrap_err();
            assert!(
                matches!(&e, crate::sys::LockError::Io(e) if e.kind() == io::ErrorKind::NotFound),
                "{e:?}"
            );
            assert_eq!(std::fs::read_dir(&t.0).unwrap().count(), 0);
        }

        /// #1310・PLUG-7: 掃除候補は `oneshot-<10 進>-<10 進>.sock.lock` に厳密一致する名前だけ。
        #[test]
        fn plug7_one_shot_lock_name_parser_is_strict() {
            fn ok(n: &str) -> Option<&[u8]> {
                one_shot_socket_name_of_lock(n.as_bytes())
            }
            assert_eq!(
                ok("oneshot-1-0.sock.lock"),
                Some(b"oneshot-1-0.sock".as_slice())
            );
            let max = format!("oneshot-{}-{}.sock.lock", u64::MAX, u64::MAX);
            assert!(ok(&max).is_some());
            for bad in [
                "resident-1-0.sock.lock",
                "oneshot-a-0.sock.lock",
                "oneshot-1-0.sock",
                "oneshot--0.sock.lock",
                "oneshot-1-.sock.lock",
                "oneshot-1-0-2.sock.lock",
                "oneshot-1.sock.lock",
                "oneshot-1-0.sock.lock.lock",
                "xoneshot-1-0.sock.lock",
                "oneshot-1-0.sock.lockx",
                "oneshot-1-+0.sock.lock",
                "oneshot-1-000000000000000000000.sock.lock",
            ] {
                assert_eq!(ok(bad), None, "{bad}");
            }
            assert_eq!(
                one_shot_socket_name_of_lock(b"oneshot-1-\xff.sock.lock"),
                None
            );
        }

        /// #1310・PLUG-12: 自 UID でないとして走査するとディレクトリ検証で拒否され、何も削除しない。
        #[test]
        fn plug12_sweep_rejects_foreign_uid_and_keeps_files() {
            let t = Tmp::new();
            let sock = t.0.join("oneshot-9-0.sock");
            let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let lock = t.0.join("oneshot-9-0.sock.lock");
            std::fs::write(&lock, b"").unwrap();
            let e = sweep_one_shot(&t.0, crate::sys::effective_uid().wrapping_add(1)).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert!(sock.exists() && lock.exists());
            drop(l);
        }

        /// #1310・REPAIR-5: 対象外の名前は候補の件数上限を消費せず、後方の候補も処理される。
        #[test]
        fn repair5_sweep_does_not_count_non_candidates() {
            let t = Tmp::new();
            for i in 0..=ONE_SHOT_SWEEP_MAX_ENTRIES {
                std::fs::write(t.0.join(format!("other-{i}")), b"").unwrap();
            }
            let sock = t.0.join("oneshot-9-0.sock");
            let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            drop(l);
            std::fs::write(t.0.join("oneshot-9-0.sock.lock"), b"").unwrap();
            let r = sweep_one_shot(&t.0, crate::sys::effective_uid()).unwrap();
            assert_eq!(r.examined, 1);
            assert!(!r.truncated);
        }

        /// #1310・REPAIR-5: 候補の件数は上限で打ち切る。
        #[test]
        fn repair5_sweep_truncates_candidates_at_limit() {
            let t = Tmp::new();
            for i in 0..=ONE_SHOT_SWEEP_MAX_ENTRIES {
                std::fs::write(t.0.join(format!("oneshot-1-{i}.sock.lock")), b"").unwrap();
            }
            let r = sweep_one_shot(&t.0, crate::sys::effective_uid()).unwrap();
            assert_eq!(r.examined as usize, ONE_SHOT_SWEEP_MAX_ENTRIES);
            assert!(r.truncated);
            assert_eq!(r.removed, 0);
        }

        /// PLUG-12: 記録は完全な形式（末尾改行つき）だけを同一性として読む。書きかけは専用ファイルとは
        /// 認めるが、管理下の証拠にはしない（TASK-123.2）。
        #[test]
        fn plug12_record_parsing_rejects_torn_and_foreign_content() {
            assert_eq!(
                parse_record(b"fcus2 2049 8912910 1790000000 123456789\n"),
                Some([2049, 8912910, 1790000000, 123456789])
            );
            assert_eq!(parse_record(b"fcus2 2049 8912910 1790000000 1234"), None); // 改行なし
            assert_eq!(parse_record(b"fcus2 2049 8912910 1790000000\n"), None); // 項目不足
            assert_eq!(parse_record(b"fcus2 1 2 3 4 5\n"), None);
            assert_eq!(parse_record(b"fcus2 1 2 3 4\nx"), None);
            assert_eq!(parse_record(b"fcus2 +1 2 3 4\n"), None);
            assert_eq!(parse_record(b"fcus2  1 2 3 4\n"), None);
            assert_eq!(parse_record(b"fcus2 1 2 3 \n"), None);
            assert_eq!(parse_record(b"fcus1 2049 8912910\n"), None); // 旧形式は証拠にしない
            assert_eq!(parse_record(b""), None);
            for ok in [
                &b""[..],
                b"fc",
                b"fcus2 ",
                b"fcus2 20",
                b"fcus2 2049 ",
                b"fcus2 2049 891 17",
                b"fcus2 2049 8912910 1790000000 ",
                b"fcus2 2049 8912910 1790000000 123456789\n",
                b"fcus1 2049 891",
                b"fcus1 2049 8912910\n",
            ] {
                assert!(is_record_fragment(ok), "{ok:?}");
            }
            for ng in [
                &b"hello"[..],
                b"fcus2 x",
                b"fcus2 2049\n",
                b"fcus2 2049 1 2 \n",
                b"fcus2  1 2 3 4\n",
                b"fcus2 1 2 3 4 5\n",
                b"fcus2 1 2 3 4\nx",
                b"fcus1 1 2 3\n",
                b"fcus3 1 2 3 4\n",
            ] {
                assert!(!is_record_fragment(ng), "{ng:?}");
            }
        }

        /// PLUG-12: 書きかけの記録が残ったロックファイルは受け入れ（以後も bind できる）、その記録では
        /// socket を削除しない（TASK-123.2）。
        #[test]
        fn plug12_torn_record_is_accepted_as_lock_but_not_as_evidence() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = open_dir_for_test(&t.0);
            let sock = t.0.join("a.sock");
            let _other = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let m = std::fs::symlink_metadata(&sock).unwrap();
            let name = std::ffi::CString::new("a.sock").unwrap();
            let ident = crate::sys::lstat_at(&dir, &name).unwrap();
            // 改行だけが欠けた（数値は現在の socket と一致する）記録。
            let [dev, ino, sec, nsec] = record_key(&ident).unwrap();
            let torn = format!("fcus2 {dev} {ino} {sec} {nsec}");
            std::fs::write(t.0.join("a.sock.lock"), &torn).unwrap();
            let lock = acquire_bind_lock(&dir, &name, euid).unwrap();
            let e = clear_stale_socket(&dir, &name, euid, &lock).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
            assert_eq!(std::fs::symlink_metadata(&sock).unwrap().ino(), m.ino());
        }

        /// PLUG-12: 記録と一致する stale socket を削除したら、再 bind の成否を待たずに記録を消す
        /// （削除済み socket の dev / ino を残さない。TASK-123.2）。
        #[test]
        fn plug12_clear_stale_socket_clears_record_after_removal() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = open_dir_for_test(&t.0);
            let sock = t.0.join("a.sock");
            drop(std::os::unix::net::UnixListener::bind(&sock).unwrap()); // stale socket
            let name = std::ffi::CString::new("a.sock").unwrap();
            let ident = crate::sys::lstat_at(&dir, &name).unwrap();
            let lock_path = t.0.join("a.sock.lock");
            let [dev, ino, sec, nsec] = record_key(&ident).unwrap();
            std::fs::write(&lock_path, format!("fcus2 {dev} {ino} {sec} {nsec}\n")).unwrap();
            let lock = acquire_bind_lock(&dir, &name, euid).unwrap();
            assert_eq!(clear_stale_socket(&dir, &name, euid, &lock), Ok(()));
            assert!(std::fs::symlink_metadata(&sock).is_err());
            assert_eq!(std::fs::read(&lock_path).unwrap(), b"");
        }

        /// PLUG-12: dev / ino が一致しても mtime が違う socket（inode 番号を再利用した別の socket に
        /// 相当）と、旧形式（mtime なし）の記録は管理下と見なさず、削除しない（TASK-123.2）。
        #[test]
        fn plug12_same_inode_number_with_different_mtime_is_not_removed() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = open_dir_for_test(&t.0);
            let sock = t.0.join("a.sock");
            let _other = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let name = std::ffi::CString::new("a.sock").unwrap();
            let ident = crate::sys::lstat_at(&dir, &name).unwrap();
            let [dev, ino, sec, nsec] = record_key(&ident).unwrap();
            let lock_path = t.0.join("a.sock.lock");
            for stale in [
                format!("fcus2 {dev} {ino} {} {nsec}\n", sec - 1),
                format!("fcus2 {dev} {ino} {sec} {}\n", (nsec + 1) % 1_000_000_000),
                format!("fcus1 {dev} {ino}\n"),
            ] {
                std::fs::write(&lock_path, &stale).unwrap();
                let lock = acquire_bind_lock(&dir, &name, euid).unwrap();
                let e = clear_stale_socket(&dir, &name, euid, &lock).unwrap_err();
                assert_eq!(e.code(), PluginErrorCode::AlreadyExists, "{stale:?}");
                // 一致しない記録は消え、生存中の別 listener は残って接続できる。
                assert_eq!(std::fs::read(&lock_path).unwrap(), b"");
                std::os::unix::net::UnixStream::connect(&sock).unwrap();
            }
        }

        /// PLUG-12: 既存の `.lock` 名が無関係ファイル・ハードリンクなら拒否し、内容を壊さない。
        #[test]
        fn plug12_rejects_non_dedicated_lock_file_without_truncating() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = open_dir_for_test(&t.0);
            let victim = t.0.join("victim");
            std::fs::write(&victim, b"precious").unwrap();
            // 1) 無関係な内容の既存ファイル
            let foreign = t.0.join("a.sock.lock");
            std::fs::write(&foreign, b"hello").unwrap();
            let name = std::ffi::CString::new("a.sock").unwrap();
            let e = acquire_bind_lock(&dir, &name, euid).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(std::fs::read(&foreign).unwrap(), b"hello");
            // 2) 他ファイルへのハードリンク（内容が空でも nlink > 1 は拒否）
            std::fs::remove_file(&foreign).unwrap();
            std::fs::hard_link(&victim, t.0.join("b.sock.lock")).unwrap();
            let name = std::ffi::CString::new("b.sock").unwrap();
            let e = acquire_bind_lock(&dir, &name, euid).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
            // 拒否したロック名は unlink もしない（ハードリンクの名前を消さない）。
            assert_eq!(std::fs::read(t.0.join("b.sock.lock")).unwrap(), b"precious");
        }

        fn open_dir_for_test(p: &Path) -> File {
            File::open(p).unwrap()
        }

        /// PLUG-12・#1309: runtime directory 名の C 文字列定数が公開名と一致する。
        #[test]
        fn plug12_runtime_dir_cname_matches_name() {
            assert_eq!(RUNTIME_DIR_CNAME.to_bytes(), RUNTIME_DIR_NAME.as_bytes());
        }

        /// PLUG-12・#1309: mkdirat は 0700 で作成し、既存・同名 symlink は AlreadyExists（リンク先に作らない）。
        #[test]
        fn plug12_mkdirat_creates_0700_and_reports_existing() {
            let t = Tmp::new();
            let fd = open_dir_for_test(&t.0);
            crate::sys::mkdirat(&fd, RUNTIME_DIR_CNAME, 0o700).unwrap();
            let mode = std::fs::metadata(t.0.join(RUNTIME_DIR_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o700);
            let e = crate::sys::mkdirat(&fd, RUNTIME_DIR_CNAME, 0o700).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);

            let target = t.0.join("target");
            DirBuilder::new().mode(0o700).create(&target).unwrap();
            std::os::unix::fs::symlink(&target, t.0.join("lnk")).unwrap();
            let e = crate::sys::mkdirat(&fd, c"lnk", 0o700).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        }

        /// PLUG-12・#1309: 検証後に基底パスが symlink へ差し替えられても、作成は検証済み fd の側で
        /// 行われ、差し替え先には作られない。開き直しは失敗する。
        #[test]
        fn plug12_create_fails_when_base_is_swapped_to_symlink() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let base = t.0.join("base");
            let decoy = t.0.join("decoy");
            let moved = t.0.join("moved");
            DirBuilder::new().mode(0o700).create(&base).unwrap();
            DirBuilder::new().mode(0o700).create(&decoy).unwrap();
            let (real, fd) = resolve_base(&base, euid).unwrap();
            std::fs::rename(&base, &moved).unwrap();
            std::os::unix::fs::symlink(&decoy, &base).unwrap();
            let err = create_in_base(&fd, &real, euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!decoy.join(RUNTIME_DIR_NAME).exists());
            let mode = std::fs::metadata(moved.join(RUNTIME_DIR_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o700);
        }

        /// PLUG-12: 所有者不一致は 0700 でも拒否する（別 UID を用意せず分岐を照合する）。
        #[test]
        fn plug12_rejects_owner_mismatch() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            ensure_dir(&t.0, euid).unwrap();
            let err = ensure_dir(&t.0, euid.wrapping_add(1)).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            let mode = std::fs::metadata(t.0.join(RUNTIME_DIR_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        /// PLUG-12: 所有者 rwx が欠けた既存ディレクトリ（0500・000）は拒否し、修復しない。
        #[test]
        fn plug12_rejects_existing_dir_without_owner_rwx() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let dir = t.0.join(RUNTIME_DIR_NAME);
            for mode in [0o500u32, 0o000] {
                DirBuilder::new().mode(0o700).create(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
                let err = ensure_dir(&t.0, euid).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
                let got = std::fs::metadata(&dir).unwrap().permissions().mode();
                assert_eq!(got & 0o777, mode);
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::remove_dir(&dir).unwrap();
            }
        }

        /// PLUG-12: 基底が他ユーザー書き込み可・他 UID 所有・symlink なら拒否する。
        #[test]
        fn plug12_rejects_untrusted_base() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            for mode in [0o770u32, 0o707, 0o777] {
                std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(mode)).unwrap();
                let err = ensure_dir(&t.0, euid).unwrap_err();
                assert_eq!(
                    err.code(),
                    PluginErrorCode::PermissionDenied,
                    "mode {mode:o}"
                );
                assert!(!t.0.join(RUNTIME_DIR_NAME).exists());
            }
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
            let err = ensure_dir(&t.0, euid.wrapping_add(1)).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&t.0, &link).unwrap();
            let err = ensure_dir(&link, euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        }

        /// PLUG-12: 末尾 `/` 付きの symlink 基底も拒否する（lstat が symlink を辿らない）。
        #[test]
        fn plug12_rejects_symlink_base_with_trailing_slash() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let target = t.0.join("real");
            DirBuilder::new().mode(0o700).create(&target).unwrap();
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let mut with_slash = link.into_os_string();
            with_slash.push("/");
            let err = ensure_dir(Path::new(&with_slash), euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!target.join(RUNTIME_DIR_NAME).exists());
        }

        /// PLUG-12: 祖先が group / other 書き込み可（非 sticky）なら、基底が安全でも拒否する。
        #[test]
        fn plug12_rejects_writable_ancestor() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let mid = t.0.join("mid");
            let base = mid.join("base");
            DirBuilder::new().mode(0o700).create(&mid).unwrap();
            DirBuilder::new().mode(0o700).create(&base).unwrap();
            std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = ensure_dir(&base, euid).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
            std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(ensure_dir(&base, euid).is_ok());
        }

        /// PLUG-12: 基底の祖先（最終要素以外）の symlink は実パスへ解決し、返すパスは実パス側になる
        /// （以降の検証・open は実パスを symlink 非追従で辿る）。
        #[test]
        fn plug12_resolves_ancestor_symlink_to_real_path() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let real_mid = t.0.join("mid");
            let real_base = real_mid.join("base");
            DirBuilder::new().mode(0o700).create(&real_mid).unwrap();
            DirBuilder::new().mode(0o700).create(&real_base).unwrap();
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&real_mid, &link).unwrap();
            let got = ensure_dir(&link.join("base"), euid).unwrap();
            let expected = std::fs::canonicalize(&real_base)
                .unwrap()
                .join(RUNTIME_DIR_NAME);
            assert_eq!(got.path(), expected.as_path());
            let mode = std::fs::symlink_metadata(&expected).unwrap().mode();
            assert_eq!(mode & 0o7777, 0o700);
        }

        /// PLUG-12: 祖先の所有者が root・自 UID 以外なら拒否する（別 UID を用意せず分岐を照合する）。
        #[test]
        fn plug12_verify_ancestor_rejects_untrusted_owner_and_accepts_sticky() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let meta = std::fs::symlink_metadata(&t.0).unwrap();
            assert!(verify_ancestor(&meta, euid).is_ok());
            if euid != 0 {
                let err = verify_ancestor(&meta, euid.wrapping_add(1)).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
                assert_eq!(
                    err.message(),
                    "runtime directory ancestor has an untrusted owner"
                );
            }
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o1777)).unwrap();
            let sticky = std::fs::symlink_metadata(&t.0).unwrap();
            assert!(verify_ancestor(&sticky, euid).is_ok());
            std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn osv(s: &str) -> Option<std::ffi::OsString> {
            Some(s.into())
        }

        /// 試験用の「フォールバック基底」を Tmp 内に用意する。Linux は euid に応じ
        /// `run_root`（root）または `run_root/user/<euid>` を返し、macOS は TMPDIR 値として Tmp を使う。
        fn fallback_fixture(t: &Tmp, euid: u32) -> (PathBuf, Option<std::ffi::OsString>) {
            if cfg!(target_os = "linux") {
                if euid == 0 {
                    (t.0.clone(), None)
                } else {
                    let b = t.0.join("user").join(euid.to_string());
                    DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(&b)
                        .unwrap();
                    (b, None)
                }
            } else {
                (t.0.clone(), Some(t.0.clone().into_os_string()))
            }
        }

        /// PLUG-12・TASK-123.4: Linux のフォールバック基底は euid で決まる（具体値）。
        #[cfg(target_os = "linux")]
        #[test]
        fn plug12_fallback_base_linux() {
            let root = Path::new("/run");
            assert_eq!(fallback_base(0, root, None).unwrap(), PathBuf::from("/run"));
            assert_eq!(
                fallback_base(1000, root, None).unwrap(),
                PathBuf::from("/run/user/1000")
            );
        }

        /// PLUG-12・TASK-123.4: macOS は TMPDIR のみ。未設定・空・相対は FailedPrecondition。
        #[cfg(target_os = "macos")]
        #[test]
        fn plug12_fallback_base_macos() {
            let root = Path::new("/run");
            assert_eq!(
                fallback_base(501, root, osv("/var/folders/x/T")).unwrap(),
                PathBuf::from("/var/folders/x/T")
            );
            for v in [None, osv(""), osv("relative")] {
                let err = fallback_base(501, root, v).unwrap_err();
                assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            }
            let err = fallback_base(501, root, osv("/a/../b")).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        }

        /// PLUG-12・TASK-123.4: XDG 未設定・空でフォールバック基底直下に 0700・自 UID で作成する。
        #[test]
        fn plug12_resolve_falls_back_when_xdg_unset_or_empty() {
            let euid = crate::sys::effective_uid();
            for xdg in [None, osv("")] {
                let t = Tmp::new();
                let (base, tmpdir) = fallback_fixture(&t, euid);
                let got = resolve(xdg, tmpdir, euid, &t.0).unwrap();
                let expected = std::fs::canonicalize(&base).unwrap().join(RUNTIME_DIR_NAME);
                assert_eq!(got.path(), expected.as_path());
                let meta = std::fs::symlink_metadata(&expected).unwrap();
                assert_eq!(meta.mode() & 0o7777, 0o700);
                assert_eq!(meta.uid(), euid);
            }
        }

        /// PLUG-12・TASK-123.4: フォールバック基底が無ければ FailedPrecondition で、基底は作らない。
        #[test]
        fn plug12_resolve_fallback_missing_base_is_failed_precondition() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let missing = t.0.join("missing");
            let tmpdir = Some(missing.clone().into_os_string());
            // root の Linux は run_root 自体、非 root は run_root/user/<euid>、macOS は TMPDIR が無い状況。
            let err = resolve(None, tmpdir, euid, &missing).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            assert!(!missing.exists());
        }

        /// PLUG-12・TASK-123.4: フォールバック先にも通常経路と同じ検証が適用され、修復されない。
        #[test]
        fn plug12_resolve_fallback_applies_verification() {
            let euid = crate::sys::effective_uid();
            let t = Tmp::new();
            let (base, tmpdir) = fallback_fixture(&t, euid);
            // 基底が group/other 書き込み可。
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = resolve(None, tmpdir.clone(), euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
            // 既存 runtime directory が 0755。
            let dir = base.join(RUNTIME_DIR_NAME);
            DirBuilder::new().mode(0o755).create(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let err = resolve(None, tmpdir, euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }

        /// PLUG-12・TASK-123.4: 設定済みで不正な XDG はフォールバックで隠さない。
        #[test]
        fn plug12_resolve_does_not_fall_back_for_invalid_xdg() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let (base, tmpdir) = fallback_fixture(&t, euid);
            let err = resolve(osv("relative"), tmpdir, euid, &t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
            assert!(!base.join(RUNTIME_DIR_NAME).exists());
        }

        /// PLUG-12・TASK-123.4: XDG が有効ならフォールバック候補を使わない。
        #[test]
        fn plug12_resolve_prefers_xdg_when_set() {
            let t = Tmp::new();
            let euid = crate::sys::effective_uid();
            let (fb, tmpdir) = fallback_fixture(&t, euid);
            let xdg = t.0.join("xdg");
            DirBuilder::new().mode(0o700).create(&xdg).unwrap();
            let got = resolve(Some(xdg.clone().into_os_string()), tmpdir, euid, &t.0).unwrap();
            let expected = std::fs::canonicalize(&xdg).unwrap().join(RUNTIME_DIR_NAME);
            assert_eq!(got.path(), expected.as_path());
            assert!(!fb.join(RUNTIME_DIR_NAME).exists());
        }

        #[test]
        fn plug12_runtime_dir_base_accepts_absolute() {
            let p = runtime_dir_base(Some("/run/user/1000".into())).unwrap();
            assert_eq!(p, std::path::PathBuf::from("/run/user/1000"));
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::RuntimeDir;
    use crate::error::{PluginError, PluginErrorCode};
    use std::path::Path;

    fn unimplemented() -> PluginError {
        PluginError::new(
            PluginErrorCode::Unimplemented,
            "runtime directory is not implemented on this platform",
        )
    }

    pub(super) fn from_env() -> Result<RuntimeDir, PluginError> {
        Err(unimplemented())
    }

    pub(super) fn ensure_under(_base: &Path) -> Result<RuntimeDir, PluginError> {
        Err(unimplemented())
    }

    pub(super) fn socket_path(
        _dir: &RuntimeDir,
        _name: &str,
    ) -> Result<std::path::PathBuf, PluginError> {
        Err(unimplemented())
    }

    pub(super) fn sweep_one_shot_leftovers(
        _dir: &RuntimeDir,
    ) -> Result<super::OneShotSweep, PluginError> {
        Err(unimplemented())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-12: uid は完全一致のみ許可する。
    #[cfg(unix)]
    #[test]
    fn plug12_peer_uid_matches_only_identical_uid() {
        assert!(peer_uid_matches(1000, 1000));
        for (p, e) in [(1000, 1001), (0, 1000), (1000, 0), (65534, 1000)] {
            assert!(!peer_uid_matches(p, e), "{p} vs {e}");
        }
    }

    /// PLUG-12・#1390: core の euid 自体が overflowuid（65534）として観測される構成では、peer も 65534 なら
    /// 数値一致で受理される（現状挙動の固定。前提条件はモジュール doc 参照）。対照として 65534 対 1000 は拒否。
    #[cfg(unix)]
    #[test]
    fn plug12_peer_uid_overflowuid_pair_is_accepted_as_identical() {
        assert!(peer_uid_matches(65534, 65534));
        assert!(verify_peer_with(|| Ok(65534), 65534).is_ok());
        let rej = verify_peer_with(|| Ok(65534), 1000).unwrap_err();
        assert_eq!(rej.error.code(), PluginErrorCode::PermissionDenied);
        // 監査イベントには観測した peer uid（65534）をそのまま載せる（TASK-124.5・SEC-4）。
        assert_eq!(rej.peer_uid, Some(65534));
    }

    /// PLUG-12: 不一致は PermissionDenied・固定メッセージで UID 値を含まない。
    #[cfg(unix)]
    #[test]
    fn plug12_verify_peer_rejects_mismatched_uid_with_permission_denied() {
        let err = verify_peer_with(|| Ok(1001), 1000).unwrap_err();
        assert_eq!(err.reason, crate::audit::PeerAuthRejectReason::UidMismatch);
        assert_eq!(err.peer_uid, Some(1001));
        let err = err.error;
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        let msg = err.to_string();
        assert!(msg.contains("peer credential does not match the current user"));
        assert!(!msg.contains("1000") && !msg.contains("1001"), "{msg}");
    }

    /// PLUG-12: 取得失敗は Ok にならず同じコードで Err（fail-closed）。
    #[cfg(unix)]
    #[test]
    fn plug12_verify_peer_fails_closed_when_credential_unavailable() {
        for code in [PluginErrorCode::Internal, PluginErrorCode::Unimplemented] {
            let rej = verify_peer_with(|| Err(PluginError::new(code, "x")), 1000).unwrap_err();
            assert_eq!(
                rej.reason,
                crate::audit::PeerAuthRejectReason::PeerUidUnavailable
            );
            assert_eq!(rej.peer_uid, None);
            let err = rej.error;
            assert_eq!(err.code(), code);
        }
    }

    /// PLUG-12・TASK-124.4・#295: peer UID の取得失敗は期待 UID によらず Ok にならない（fail-closed）。
    ///
    /// transport の accept / connect は `verify_peer` の Err を `?` で返し stream を drop して切断する。
    /// 公開 API からは取得失敗を注入できないため、`tests/peer_auth.rs` ではなく本テストで取得関数を
    /// 差し替えて照合する。再試行・既定値へのフォールバックをしないことも固定する。
    #[cfg(unix)]
    #[test]
    fn plug12_fail_closed_on_peercred_error() {
        use std::cell::Cell;
        for code in [PluginErrorCode::Internal, PluginErrorCode::Unimplemented] {
            for expected in [crate::sys::effective_uid(), 0, u32::MAX] {
                let calls = Cell::new(0u32);
                let err = verify_peer_with(
                    || {
                        calls.set(calls.get() + 1);
                        Err(PluginError::new(code, "failed to obtain peer credential"))
                    },
                    expected,
                )
                .unwrap_err()
                .error;
                assert_eq!(err.code(), code);
                assert_ne!(err.code(), PluginErrorCode::PermissionDenied);
                assert_eq!(err.message(), "failed to obtain peer credential");
                assert_eq!(calls.get(), 1);
                assert!(!err.message().contains(&expected.to_string()));
            }
        }
    }

    /// PLUG-12: 実際の peer credential 経路（自己接続）で一致は Ok、ずらした期待値は拒否。
    /// `sys::peer_uid` が実装済みの OS・アーキテクチャに限定する（他は Unimplemented を返すため）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn plug12_verify_peer_accepts_same_uid_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = crate::sys::effective_uid();
        assert!(verify_peer(&a, me).is_ok());
        let err = verify_peer(&a, me.wrapping_add(1)).unwrap_err();
        assert_eq!(err.peer_uid, Some(me));
        assert_eq!(err.error.code(), PluginErrorCode::PermissionDenied);
    }

    /// PLUG-12: 未設定・空・相対は FailedPrecondition（`/tmp` 等へ落とさない）。
    #[test]
    fn plug12_runtime_dir_base_rejects_unset_empty_relative() {
        for v in [None, Some("".into()), Some("relative/dir".into())] {
            let err = runtime_dir_base(v).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
        }
    }

    /// PLUG-12: `..` 要素は InvalidArgument。
    #[test]
    fn plug12_runtime_dir_base_rejects_parent_dir_component() {
        let abs = std::env::temp_dir().join("a").join("..").join("b");
        let err = runtime_dir_base(Some(abs.into_os_string())).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
    }
}
