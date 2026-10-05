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
//! `transport` の accept / connect が接続直後に [`verify_peer`] を呼ぶ。契約:
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
//! - macOS は getpeereid で peer uid を取得済み（TASK-124.2・#293）。別 UID 接続拒否の結合試験は `tests/peer_auth.rs`（TASK-124.4・#295。実機前提の 2 件は人間が実行）。accept / connect で最初の読み書きより前に検証する順序は `transport::tests::plug12_order` で機械照合する（TASK-124.6・#1389）。未実装は拒否の監査ログ（SEC-4）。
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

/// 取得関数を差し替えられる検証本体（取得失敗の fail-closed をテストで再現するため。PLUG-12）。
#[cfg(unix)]
fn verify_peer_with(
    get: impl FnOnce() -> Result<u32, PluginError>,
    expected_uid: u32,
) -> Result<(), PluginError> {
    // 取得失敗はそのまま伝播する（Ok にしない）。
    let peer = get()?;
    if !peer_uid_matches(peer, expected_uid) {
        // メッセージは固定文字列で UID 値を含めない。
        return Err(PluginError::new(
            PluginErrorCode::PermissionDenied,
            "peer credential does not match the current user",
        ));
    }
    Ok(())
}

/// 接続済み stream の peer uid を `expected_uid` と照合する（PLUG-12・TASK-124.1・#292）。
///
/// `transport` の accept 直後・connect 直後（最初の read より前）から呼ばれる。Err なら呼び出し側が
/// stream を drop して切断する。取得は `crate::sys::peer_uid`（Linux は SO_PEERCRED）。
///
/// client の connect 側で得る peer 資格情報は server が `listen(2)` を呼んだ時点のものであり、接続済み fd の
/// 別プロセスへの受け渡しも検出できない（モジュール doc・`crate::sys` の「限界」）。
#[cfg(unix)]
pub(crate) fn verify_peer(
    stream: &std::os::unix::net::UnixStream,
    expected_uid: u32,
) -> Result<(), PluginError> {
    verify_peer_with(|| crate::sys::peer_uid(stream), expected_uid)
}

#[cfg(unix)]
pub(crate) use imp::{BindLock, acquire_bind_lock, clear_stale_socket};

#[cfg(unix)]
mod imp {
    use super::{RUNTIME_DIR_NAME, RuntimeDir, runtime_dir_base, validate_base};
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
        verify(&fstat(&open_nofollow(&dir)?)?, euid)?;
        Ok(RuntimeDir { path: dir })
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
    }

    impl Drop for BindLock {
        fn drop(&mut self) {
            // 記録が空なら、このロックファイルを根拠に削除できる socket は無い。flock を持ったまま、
            // 名前がまだ自分の inode を指す場合だけ unlink する（別の inode には触れない）。
            let unrecorded = self.file.metadata().is_ok_and(|m| m.len() == 0);
            if unrecorded
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
    pub(crate) fn acquire_bind_lock(
        dir: &File,
        name: &std::ffi::CStr,
        euid: u32,
    ) -> Result<BindLock, PluginError> {
        let invalid = || err(PluginErrorCode::InvalidArgument, "invalid socket path");
        let mut bytes = name.to_bytes().to_vec();
        bytes.extend_from_slice(b".lock");
        let lock_name = std::ffi::CString::new(bytes).map_err(|_| invalid())?;
        for _ in 0..LOCK_ATTEMPTS {
            let handle = match crate::sys::lock_file_at(dir, &lock_name) {
                Ok(h) => h,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(busy()),
                Err(e)
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
        let err = verify_peer_with(|| Ok(65534), 1000).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
    }

    /// PLUG-12: 不一致は PermissionDenied・固定メッセージで UID 値を含まない。
    #[cfg(unix)]
    #[test]
    fn plug12_verify_peer_rejects_mismatched_uid_with_permission_denied() {
        let err = verify_peer_with(|| Ok(1001), 1000).unwrap_err();
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
            let err = verify_peer_with(|| Err(PluginError::new(code, "x")), 1000).unwrap_err();
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
                .unwrap_err();
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
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
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
