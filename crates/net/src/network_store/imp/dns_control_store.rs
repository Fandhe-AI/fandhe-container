//! ネットワークのディレクトリに置く DNS ヘルパーの制御 UDS（`dns.ctl`）の置き場の検査・削除と、ロックを取らない
//! メンバー記録の読み取り口（NET-5・PLUG-12・SEC-1・REPAIR-5・#3071）。
//!
//! # 役割と契約
//! `dns_helper::control` が使う。形式（フレーム）は `dns_helper::control::frame`、ここは置き場の検査だけを担う。
//! - 経路は検査済みのネットワークのディレクトリの fd 起点（`/proc/self/fd/<fd>/dns.ctl`）で組む。`sun_path` の
//!   108 バイト制限を避け、状態ルートの途中の差し替えを受けない
//! - 送り手は connect の前に lstat で検査する（socket・所有者・0600・nlink 1。[`check_socket_meta`]）
//! - ソケットファイルの削除は排他ロックを持つ側（停止・起動・回収・`network rm`）だけが行う。ヘルパー自身は
//!   消さない（新しいヘルパーの socket を古いヘルパーの終了処理が誤って消さないため）。socket でないもの・
//!   他の所有者のものは消さず `FailedPrecondition` / `PermissionDenied`
//!
//! # ロックを取らない読み取り（NetworkDir）
//! `attach_recorded_with` は排他ロックを持ったまま記録を書き、`spawn_inner` も排他ロックを持ったまま `READY` を
//! 待つ。ヘルパーがネットワークの共有ロックを取ると 5 秒待ち、2 秒の `Loaded` の期限（D15）を必ず超える。
//! そこでヘルパーは [`NetworkStore::open_network_dir`] の [`NetworkDir`] でロックを取らずに読む。読む記録は
//! rename か link で原子的に公開された完全なファイルだけで、書き手は排他ロックの保持者だけ、読み込みはその保持者からの
//! `Reload` の後（と起動時の初回）に限る。食い違えば（`DataLoss` 等）呼び出し側が前のレジストリを保って
//! `Error` を返す。

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use super::{Dir, NetworkLockGuard, NetworkStore, err, map_io};
use crate::error::{NetError, NetErrorCode};
use crate::network::NetworkName;
use crate::network_store::member::MemberRecord;
use crate::network_store::{FILE_MODE, check_socket_meta};
use crate::sys;

/// 制御 UDS のファイル名（ネットワークのディレクトリ直下）。
pub const CONTROL_SOCKET_FILE: &str = crate::dns_helper::control::CONTROL_SOCKET_NAME;

impl Dir {
    /// 制御ソケットの経路（この `Dir` の fd 起点）。
    fn control_path(&self) -> PathBuf {
        self.path(CONTROL_SOCKET_FILE)
    }

    /// 制御ソケットを lstat で検査する（socket・所有者・0600・nlink 1）。無ければ `NotFound`。
    fn check_control_socket(&self) -> Result<(), NetError> {
        let m = fs::symlink_metadata(self.control_path())
            .map_err(|e| map_io(&e, "failed to stat dns control socket"))?;
        check_socket_meta(
            m.file_type().is_socket(),
            m.uid(),
            m.mode(),
            m.nlink(),
            sys::effective_uid(),
        )
    }
}

/// 検査済みのネットワークのディレクトリ（ロックを取らない読み取り口。ヘルパー側が使う）。
#[derive(Debug)]
pub(crate) struct NetworkDir {
    dir: Dir,
}

impl NetworkStore {
    /// `open` に渡された状態ルート。
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// ネットワークのディレクトリを **ロックを取らずに** 開く（ヘルパー側の読み取り口。理由はモジュール doc）。
    /// 無ければ `NotFound`。権限・所有者・symlink は通常どおり検査する。
    pub(crate) fn open_network_dir(&self, name: &NetworkName) -> Result<NetworkDir, NetError> {
        Ok(NetworkDir {
            dir: self.dir.open_subdir(name.as_str())?,
        })
    }
}

impl NetworkDir {
    /// 制御ソケットの経路。
    pub(crate) fn control_socket_path(&self) -> PathBuf {
        self.dir.control_path()
    }

    /// bind 直後のソケットを 0600 にし、socket・所有者・0600 を検査し直す。
    pub(crate) fn secure_control_socket(&self) -> Result<(), NetError> {
        fs::set_permissions(
            self.dir.control_path(),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .map_err(|e| map_io(&e, "failed to set dns control socket mode"))?;
        self.dir.check_control_socket()
    }

    /// 確定したメンバー記録を ID 順に読む（ロックを取らない。モジュール doc の前提を満たす呼び出し元に限る）。
    pub(crate) fn members(&self) -> Result<Vec<MemberRecord>, NetError> {
        self.dir.read_members()
    }
}

impl NetworkLockGuard<'_> {
    /// ストアの状態ルート（絶対パスに限る。ヘルパーが `NetworkStore::open` で開き直すために引数で渡す）。
    pub(crate) fn state_root(&self) -> Result<&Path, NetError> {
        if self.state_root.is_absolute() {
            Ok(&self.state_root)
        } else {
            Err(err(
                NetErrorCode::InvalidArgument,
                "network store state root must be absolute to start a dns helper",
            ))
        }
    }

    /// 制御ソケットの経路。
    pub(crate) fn control_socket_path(&self) -> PathBuf {
        self.dir.control_path()
    }

    /// 送り手が connect の前に行う検査（socket・所有者・0600・nlink 1）。無ければ `NotFound`。
    pub(crate) fn check_control_socket(&self) -> Result<(), NetError> {
        self.dir.check_control_socket()
    }

    /// 残っている制御ソケットを消す（排他ロックの下だけ）。消したら true、無ければ false。
    ///
    /// socket でない・他の所有者のものは消さず `FailedPrecondition` / `PermissionDenied`（フルパスに署名を残さない
    /// 固定文言）。消したら親ディレクトリを fsync する。
    pub(crate) fn remove_dns_control_socket(&self) -> Result<bool, NetError> {
        self.require_exclusive()?;
        let path = self.dir.control_path();
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(map_io(&e, "failed to stat dns control socket")),
        };
        if !m.file_type().is_socket() {
            return Err(err(
                NetErrorCode::FailedPrecondition,
                "dns control socket path is not a socket",
            ));
        }
        if m.uid() != sys::effective_uid() {
            return Err(err(
                NetErrorCode::PermissionDenied,
                "dns control socket owner mismatch",
            ));
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(map_io(&e, "failed to remove dns control socket")),
        }
        self.dir.sync()?;
        Ok(true)
    }

    /// `network rm` の前に、記録（`dns-helper`・`dns-helper.intent`）が両方無いときだけ、残った制御ソケットを消す
    /// （死んだヘルパーの残骸が削除を止めない。ベストエフォート。消せないものは既知項目の検査が拒否する）。
    pub(super) fn discard_orphan_dns_control_socket(&self) {
        let exists = |name: &str| fs::symlink_metadata(self.dir.path(name)).is_ok();
        if exists(super::dns_helper_store::DNS_HELPER_FILE)
            || exists(super::dns_helper_store::DNS_HELPER_INTENT_FILE)
        {
            return;
        }
        let _ = self.remove_dns_control_socket();
    }
}
