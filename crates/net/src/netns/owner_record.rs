//! netns の pin の永続的な所有記録（NET-1・REPAIR-3・REPAIR-5。#2824）。
//!
//! `super::create_pinned` が作った pin について「このモジュールが作った実体」を置き場ディレクトリ配下の
//! `.owned/<endpoint>` に 1 ファイルずつ記録する。プロセス内の所有記録（`super::PINS`）は再起動で消えるため、
//! 再起動後に attach の取り残しの請求書（`network::attach_claim`）の `pin=<dev>:<ino>:<serial>` と
//! 照合して pin を外すには、同じ情報を永続させる必要がある。照合そのもの（請求書 ↔ 本記録 ↔ カーネルの
//! 実状態の三者照合）は `super::unpin_in_dir` が行い、本モジュールは記録の符号化・復号と、固定した
//! 置き場 fd 経由の読み書きだけを担う（`unsafe` なし。`sys` の既存ラッパーと std のみ）。
//!
//! 記録が欠けている・壊れている・属性が想定と違う場合はすべて「照合不能」として扱い、呼び出し側は
//! 何も外さない（fail-closed）。記録は fsync しない。欠落は拒否側に倒れるだけで安全性に影響せず、
//! 必要なのは原子的な置き換え（一時ファイル → rename）だけであるため。設計は
//! `docs/design/network-reclaim-persistence.md` 「netns の pin の所有記録」を参照。

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{FileId, PinDir, check_base_dir_attrs, io_error, sys_error};
use crate::error::{NetError, NetErrorCode};
use crate::sys::{self, SysError};

/// 置き場ディレクトリ直下の所有記録ディレクトリ名。`EndpointId` は `.` で始まらないため pin 名と衝突しない。
const OWNED_DIR_NAME: &std::ffi::CStr = c".owned";

/// 記録ファイル 1 件の最大バイト数（無制限確保の防止）。通常は 100 バイト前後。
const MAX_RECORD_BYTES: u64 = 256;

const HEADER: &str = "fandhe-net-pin-owner v1";

/// 一時ファイル名の連番。
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// 永続化する所有記録の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OwnerRecord {
    /// pin の名前（`EndpointId`）。ファイル名と一致しなければ照合不能。
    pub endpoint: String,
    /// pin ファイル自身の (dev, ino)。
    pub file: FileId,
    /// bind マウント後に見える netns の (dev, ino)。作成の途中は `None`（`ns=-`）。
    pub ns: Option<FileId>,
    /// 作成の連番（請求書の `pin=` の第 3 要素）。
    pub serial: u64,
}

fn fmt_id(id: FileId) -> String {
    format!("{}:{}", id.0, id.1)
}

fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_id(s: &str) -> Option<FileId> {
    let (d, i) = s.split_once(':')?;
    Some((parse_u64(d)?, parse_u64(i)?))
}

impl OwnerRecord {
    /// 固定テキスト形式へ符号化する（LF・ASCII）。
    pub(super) fn to_text(&self) -> String {
        let ns = self.ns.map_or_else(|| "-".to_owned(), fmt_id);
        format!(
            "{HEADER}\nendpoint={}\nfile={}\nns={ns}\nserial={}\n",
            self.endpoint,
            fmt_id(self.file),
            self.serial
        )
    }

    /// 復号する。版・キーの順序・重複・余分な行・CRLF・桁数・長さ・`endpoint` の不一致のどれかに
    /// 違反すれば `None`（照合不能）。入力値はエラーに載せない。
    pub(super) fn parse(bytes: &[u8], expect_endpoint: &str) -> Option<Self> {
        if u64::try_from(bytes.len()).ok()? > MAX_RECORD_BYTES {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let body = text.strip_suffix('\n')?;
        let mut lines = body.split('\n');
        if lines.next()? != HEADER {
            return None;
        }
        let endpoint = lines.next()?.strip_prefix("endpoint=")?;
        let file = parse_id(lines.next()?.strip_prefix("file=")?)?;
        let ns_text = lines.next()?.strip_prefix("ns=")?;
        let ns = if ns_text == "-" {
            None
        } else {
            Some(parse_id(ns_text)?)
        };
        let serial = parse_u64(lines.next()?.strip_prefix("serial=")?)?;
        if lines.next().is_some() || endpoint != expect_endpoint {
            return None;
        }
        Some(Self {
            endpoint: endpoint.to_owned(),
            file,
            ns,
            serial,
        })
    }
}

fn no_record() -> NetError {
    NetError::new(
        NetErrorCode::FailedPrecondition,
        "netns pin has no valid ownership record",
    )
}

/// 固定した置き場ディレクトリ配下の `.owned` ディレクトリ（開いた fd で固定）。
pub(super) struct OwnedDir {
    file: File,
}

impl OwnedDir {
    /// `.owned` を開く。無ければ（`create` のとき）0700 で作る。symlink・非ディレクトリ・実効 UID 以外の所有・
    /// group / other 書き込み可は拒否する（fail-closed）。
    pub(super) fn open(dir: &PinDir, create: bool) -> Result<Self, NetError> {
        let mut created = false;
        let fd = match sys::open_dir_nofollow_at(dir.file.as_fd(), OWNED_DIR_NAME) {
            Ok(fd) => fd,
            Err(SysError::Os(e)) if e == sys::ENOENT && create => {
                let path = dir.entry(std::ffi::OsStr::new(".owned"));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => created = true,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(io_error("create netns owner directory", &e)),
                }
                sys::open_dir_nofollow_at(dir.file.as_fd(), OWNED_DIR_NAME)
                    .map_err(|e| sys_error("open netns owner directory", e))?
            }
            Err(SysError::Os(e)) if e == sys::ENOENT => return Err(no_record()),
            Err(e) => return Err(sys_error("open netns owner directory", e)),
        };
        let file = File::from(fd);
        if created {
            // `DirBuilder::mode` は umask の影響を受ける（umask 0200 なら 0500 になり記録を作れない）。
            // 開いた fd で固定した実体に対して明示的に 0700 へ揃える（fchmod）。
            file.set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|e| io_error("chmod netns owner directory", &e))?;
        }
        let meta = file
            .metadata()
            .map_err(|e| io_error("stat netns owner directory", &e))?;
        check_base_dir_attrs(
            meta.file_type().is_dir(),
            meta.mode(),
            meta.uid(),
            sys::effective_uid(),
        )?;
        Ok(Self { file })
    }

    fn entry(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd())).join(name)
    }

    /// `name` の記録を一時ファイル経由で原子的に置き換える（前の世代の記録は上書きされる）。
    pub(super) fn replace(&self, name: &str, rec: &OwnerRecord) -> Result<(), NetError> {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.entry(&format!(".{name}.tmp.{}.{seq}", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| io_error("create netns pin ownership record", &e))?;
        // umask で削られうるため、保持した fd で 0600 を明示する。
        let written = f
            .write_all(rec.to_text().as_bytes())
            .and_then(|()| f.set_permissions(fs::Permissions::from_mode(0o600)));
        drop(f);
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(io_error("write netns pin ownership record", &e));
        }
        if let Err(e) = fs::rename(&tmp, self.entry(name)) {
            let _ = fs::remove_file(&tmp);
            return Err(io_error("install netns pin ownership record", &e));
        }
        Ok(())
    }

    /// `name` の記録を読む。無い・symlink・実効 UID 以外の所有・mode 0600 以外・上限超過・復号失敗は
    /// すべて同じ `FailedPrecondition`（照合不能）。
    pub(super) fn read(&self, name: &str) -> Result<OwnerRecord, NetError> {
        let c_name = CString::new(name).map_err(|_| no_record())?;
        let path_fd =
            sys::open_path_nofollow_at(self.file.as_fd(), &c_name).map_err(|_| no_record())?;
        let pf = File::from(path_fd);
        let m = pf.metadata().map_err(|_| no_record())?;
        if !(m.file_type().is_file()
            && m.mode() & 0o7777 == 0o600
            && m.uid() == sys::effective_uid()
            && m.len() <= MAX_RECORD_BYTES)
        {
            return Err(no_record());
        }
        let mut buf = Vec::new();
        File::open(format!("/proc/self/fd/{}", pf.as_raw_fd()))
            .and_then(|f| f.take(MAX_RECORD_BYTES + 1).read_to_end(&mut buf))
            .map_err(|_| no_record())?;
        OwnerRecord::parse(&buf, name).ok_or_else(no_record)
    }

    /// 記録の中身が (`file`, `serial`) と一致するときだけ消す。不一致（新しい世代の記録）・読めない場合は
    /// 消さない。消せなくても失敗にしない（pin の無い古い記録は無害。次の作成が上書きする）。
    pub(super) fn remove_if_matches(&self, name: &str, file: FileId, serial: u64) {
        if let Ok(r) = self.read(name)
            && r.file == file
            && r.serial == serial
        {
            let _ = fs::remove_file(self.entry(name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OwnerRecord {
        OwnerRecord {
            endpoint: "web-1".to_owned(),
            file: (64768, 12345),
            ns: Some((4, 4026531992)),
            serial: 1_700_000_000_123_456_789,
        }
    }

    /// NET-1・REPAIR-3: 符号化結果は固定テキストで、復号で元に戻る。
    #[test]
    fn net1_owner_record_roundtrip() {
        let r = sample();
        assert_eq!(
            r.to_text(),
            "fandhe-net-pin-owner v1\nendpoint=web-1\nfile=64768:12345\nns=4:4026531992\nserial=1700000000123456789\n"
        );
        assert_eq!(OwnerRecord::parse(r.to_text().as_bytes(), "web-1"), Some(r));
        let none_ns = OwnerRecord {
            ns: None,
            ..sample()
        };
        assert!(none_ns.to_text().contains("\nns=-\n"));
        assert_eq!(
            OwnerRecord::parse(none_ns.to_text().as_bytes(), "web-1"),
            Some(none_ns)
        );
    }

    /// NET-1・REPAIR-3: 版・順序・余分な行・CRLF・桁数・非数字・endpoint 不一致・長さ上限は復号を拒否する。
    #[test]
    fn net1_owner_record_rejects_malformed() {
        let good = sample().to_text();
        let cases: Vec<(&str, String)> = vec![
            ("version", good.replace("v1", "v2")),
            (
                "order",
                "fandhe-net-pin-owner v1\nfile=1:2\nendpoint=web-1\nns=-\nserial=1\n".to_owned(),
            ),
            ("extra line", format!("{good}extra=1\n")),
            ("crlf", good.replace('\n', "\r\n")),
            ("no trailing lf", good.trim_end().to_owned()),
            ("21 digits", good.replace("12345", "123456789012345678901")),
            ("non digit", good.replace("12345", "12x45")),
            ("sign", good.replace("serial=17", "serial=+7")),
            (
                "empty number",
                good.replace("file=64768:12345", "file=64768:"),
            ),
            ("unknown key", good.replace("serial=", "serail=")),
            ("too long", format!("{good}{}", "a".repeat(300))),
        ];
        for (what, text) in cases {
            assert_eq!(OwnerRecord::parse(text.as_bytes(), "web-1"), None, "{what}");
        }
        assert_eq!(OwnerRecord::parse(good.as_bytes(), "web-2"), None);
        assert_eq!(OwnerRecord::parse(&[0xff, 0xfe], "web-1"), None);
    }
}
