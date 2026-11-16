//! userns helper の展開モードが blob の fd を受け渡すための `SCM_RIGHTS` の送受信（`unsafe` 事前承認の範囲。
//! SEC-5・OCI-1・REPAIR-5。#4847。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! 親の `userns_helper::launcher`（展開要求の frame の後に [`send_fds`]）と、helper の `userns_helper::helper`
//! （参加の後に [`recv_fds`]）だけが使う。fd は 1 バイトの token に添えて 1 通にまとめる（上限 [`MAX_FDS`] 本）。
//!
//! # 契約
//! - `unsafe` はこのモジュールに閉じ、公開するのは安全な関数のみ（`unsafe fn` を公開しない）。
//! - 受け取る側は `MSG_CMSG_CLOEXEC` で受け、制御バッファを `CMSG_LEN(期待本数 × 4)` に切る。超えた分はカーネルが閉じて
//!   `MSG_CTRUNC` が立ち、受けた分も閉じてから `InvalidData` を返す。形式違反・負値の fd も同じく全部閉じて拒否する。
//!   受けた fd は検証の前にすべて所有型にする（漏らさない）。
//! - LP64 の x86_64・aarch64 の Linux だけ実装し、他の組は `Unsupported` を返す（呼び出し側は fail-closed）。
//!   `msghdr`・`cmsghdr` のレイアウトと定数は両アーキテクチャで同じで、`abi_values` で具体値として固定する
//!   （plugin-cri は libc を dev-dependency に持たないため照合ではない。#3290）。参考実装は net の `sys/holder.rs`。

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

/// 1 通で運べる fd の上限（`SCM_MAX_FD` の 253 以下）。
pub(crate) const MAX_FDS: usize = 128;

/// 受信結果。
#[derive(Debug)]
pub(crate) struct Received {
    /// データ 1 バイト（token）。
    pub token: u8,
    /// 受け取った fd（`MAX_FDS` 以下。drop で閉じる）。
    pub fds: Vec<OwnedFd>,
}

#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};

    use super::{MAX_FDS, Received};

    pub(super) const SOL_SOCKET: i32 = 1;
    pub(super) const SCM_RIGHTS: i32 = 1;
    pub(super) const MSG_CTRUNC: i32 = 0x8;
    pub(super) const MSG_NOSIGNAL: i32 = 0x4000;
    pub(super) const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
    /// `sizeof(struct cmsghdr)`（`size_t` + `int` + `int`）。
    pub(super) const CMSG_HDR_LEN: usize = 16;
    /// `CMSG_SPACE(MAX_FDS * 4)`（8 バイト境界）。
    const CONTROL_CAP: usize = (CMSG_HDR_LEN + MAX_FDS * 4).next_multiple_of(8);

    #[repr(C)]
    struct IoVec {
        base: *mut c_void,
        len: usize,
    }

    #[repr(C)]
    struct MsgHdr {
        name: *mut c_void,
        namelen: u32,
        iov: *mut IoVec,
        iovlen: usize,
        control: *mut c_void,
        controllen: usize,
        flags: i32,
    }

    /// 制御バッファ（`cmsghdr` の整列のため 8 バイト境界）。
    #[repr(C, align(8))]
    struct Control([u8; CONTROL_CAP]);

    unsafe extern "C" {
        // SAFETY（宣言の妥当性）: glibc・musl の `ssize_t sendmsg(int, const struct msghdr *, int)` と
        // `ssize_t recvmsg(int, struct msghdr *, int)`。`MsgHdr` は LP64 の Linux の `struct msghdr`（56 バイト）と同じ並び。
        fn sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> isize;
        fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    }

    pub(super) fn send_fds(
        sock: BorrowedFd<'_>,
        token: u8,
        fds: &[BorrowedFd<'_>],
    ) -> io::Result<()> {
        if fds.is_empty() || fds.len() > MAX_FDS {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let data_len = fds.len() * 4;
        let mut control = Control([0; CONTROL_CAP]);
        let mut bytes: Vec<u8> = Vec::with_capacity(CMSG_HDR_LEN + data_len);
        bytes.extend_from_slice(&(CMSG_HDR_LEN + data_len).to_ne_bytes());
        bytes.extend_from_slice(&SOL_SOCKET.to_ne_bytes());
        bytes.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
        for f in fds {
            bytes.extend_from_slice(&f.as_raw_fd().to_ne_bytes());
        }
        control
            .0
            .get_mut(..bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .copy_from_slice(&bytes);
        let buf = [token];
        let mut iov = IoVec {
            base: buf.as_ptr().cast_mut().cast(),
            len: 1,
        };
        let msg = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: &raw mut iov,
            iovlen: 1,
            control: control.0.as_mut_ptr().cast(),
            // `CMSG_SPACE(data_len)`: 8 バイト境界へ切り上げた長さ（`CONTROL_CAP` 以下）。
            controllen: bytes.len().next_multiple_of(8),
            flags: 0,
        };
        loop {
            // SAFETY: `msg` が指す `iov`（1 バイトの `buf`。`sendmsg` は読むだけで、`cast_mut` は C の `void *` 型に
            // 合わせるためだけ）と `control`（`controllen` ≤ `CONTROL_CAP` バイト・8 バイト整列・0 初期化済みで、先頭に
            // 組んだ `SCM_RIGHTS` 1 件）は呼び出しの間生存する。`fds` と `sock` は生存中の `BorrowedFd` で、fd 番号は開いている。
            let n = unsafe { sendmsg(sock.as_raw_fd(), &raw const msg, MSG_NOSIGNAL) };
            match usize::try_from(n) {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Err(_) => {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// 制御データから `SCM_RIGHTS` の fd 番号を取り出す（境界はすべて checked）。形式違反は `None`。
    pub(super) fn parse_rights(ctrl: &[u8]) -> Option<Vec<RawFd>> {
        let mut fds = Vec::new();
        let mut off = 0usize;
        while off < ctrl.len() {
            let hdr = ctrl.get(off..off.checked_add(CMSG_HDR_LEN)?)?;
            let len = usize::from_ne_bytes(hdr.get(0..8)?.try_into().ok()?);
            let level = i32::from_ne_bytes(hdr.get(8..12)?.try_into().ok()?);
            let kind = i32::from_ne_bytes(hdr.get(12..16)?.try_into().ok()?);
            if len < CMSG_HDR_LEN {
                return None;
            }
            let data = ctrl.get(off.checked_add(CMSG_HDR_LEN)?..off.checked_add(len)?)?;
            if level == SOL_SOCKET && kind == SCM_RIGHTS {
                if data.len() % 4 != 0 {
                    return None;
                }
                for c in data.as_chunks::<4>().0 {
                    fds.push(i32::from_ne_bytes(*c));
                }
            }
            off = off.checked_add(len.checked_next_multiple_of(8)?)?;
        }
        Some(fds)
    }

    /// 取り出した fd 番号を所有する。負値があれば、非負の分を所有して閉じてから `None`。
    ///
    /// # Safety
    /// 非負の番号は、直前の `recvmsg` がこのプロセスへ新規に割り当てた fd で、他に所有者がおらず、互いに重複しない。
    /// 呼び出し後にその番号を使わない・閉じない。private のまま置く。
    unsafe fn adopt(raw: &[RawFd]) -> Option<Vec<OwnedFd>> {
        let owned: Vec<OwnedFd> = raw
            .iter()
            .filter(|fd| **fd >= 0)
            // SAFETY: 非負であることは filter で確かめた。開いている・他に所有者がいない・重複しないことは本関数の契約。
            .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
            .collect();
        (owned.len() == raw.len()).then_some(owned)
    }

    pub(super) fn recv_fds(sock: BorrowedFd<'_>, max_fds: usize) -> io::Result<Received> {
        if max_fds == 0 || max_fds > MAX_FDS {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut data = [0u8; 1];
        let mut iov = IoVec {
            base: data.as_mut_ptr().cast(),
            len: 1,
        };
        let mut control = Control([0; CONTROL_CAP]);
        // `CMSG_LEN(max_fds * 4)`: ちょうどこの本数まで。超えた分はカーネルが閉じて `MSG_CTRUNC` が立つ。
        let ctl_len = CMSG_HDR_LEN + max_fds * 4;
        let mut msg = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: &raw mut iov,
            iovlen: 1,
            control: control.0.as_mut_ptr().cast(),
            controllen: ctl_len,
            flags: 0,
        };
        let n = loop {
            // SAFETY: `msg` が指す `iov`（1 バイトの `data`・排他借用）と `control`（`ctl_len` ≤ `CONTROL_CAP` バイト・
            // 8 バイト整列・書き込み可能）は呼び出しの間生存する。カーネルは確保サイズを超えて書かない。`sock` は生存中の
            // `BorrowedFd`。ソケットの受信期限（`SO_RCVTIMEO`）が切れれば `EAGAIN`（`WouldBlock`）で返る。
            let n = unsafe { recvmsg(sock.as_raw_fd(), &raw mut msg, MSG_CMSG_CLOEXEC) };
            if n >= 0 {
                break n;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        };
        let used = msg.controllen.min(ctl_len);
        let ctrl = control.0.get(..used).unwrap_or(&[]);
        // 形式違反でも、読めた番号は所有して閉じてから拒否する（漏らさない）。
        let raw = parse_rights(ctrl);
        let parsed_ok = raw.is_some();
        // SAFETY: `recvmsg` は成功済み。`MSG_CMSG_CLOEXEC` つきで受けた `SCM_RIGHTS` の fd は、カーネルがこの呼び出しで
        // 新規に割り当てたもので、他に所有者がおらず互いに重複しない。`control` は 0 初期化済みで、`ctrl` はカーネルが書いた
        // 範囲に切ってある。以降この番号は他で使わない（所有は戻り値か drop へ移る）。
        let adopted = raw.as_deref().and_then(|r| unsafe { adopt(r) });
        let truncated = msg.flags & MSG_CTRUNC != 0;
        match (n, adopted, parsed_ok, truncated) {
            (1, Some(fds), true, false) => Ok(Received {
                token: data[0],
                fds,
            }),
            (0, ..) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            // 所有した fd は `adopted` の drop で閉じる。
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }

    #[cfg(test)]
    mod abi_values {
        use super::*;

        const _: () = assert!(SOL_SOCKET == 1);
        const _: () = assert!(SCM_RIGHTS == 1);
        const _: () = assert!(MSG_CTRUNC == 8);
        const _: () = assert!(MSG_NOSIGNAL == 0x4000);
        const _: () = assert!(MSG_CMSG_CLOEXEC == 0x4000_0000);
        const _: () = assert!(CMSG_HDR_LEN == 16);
        const _: () = assert!(std::mem::size_of::<MsgHdr>() == 56);
        const _: () = assert!(std::mem::size_of::<IoVec>() == 16);
        const _: () = assert!(CONTROL_CAP == 528);

        #[test]
        fn sec5_4847_fd_passing_abi_values_are_fixed() {
            assert_eq!(SOL_SOCKET, 1);
            assert_eq!(SCM_RIGHTS, 1);
            assert_eq!(MSG_CTRUNC, 8);
            assert_eq!(MSG_NOSIGNAL, 0x4000);
            assert_eq!(MSG_CMSG_CLOEXEC, 0x4000_0000);
            assert_eq!(std::mem::size_of::<MsgHdr>(), 56);
            assert_eq!(std::mem::offset_of!(MsgHdr, control), 32);
            assert_eq!(std::mem::offset_of!(MsgHdr, flags), 48);
        }

        /// 制御データの解析は境界を越えず、形式違反を `None` にする。
        #[test]
        fn sec5_4847_parse_rights_rejects_malformed_control_data() {
            let mut ok = Vec::new();
            ok.extend_from_slice(&(16usize + 8).to_ne_bytes());
            ok.extend_from_slice(&SOL_SOCKET.to_ne_bytes());
            ok.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
            ok.extend_from_slice(&7i32.to_ne_bytes());
            ok.extend_from_slice(&9i32.to_ne_bytes());
            assert_eq!(parse_rights(&ok), Some(vec![7, 9]));
            assert_eq!(parse_rights(&[]), Some(vec![]));
            // cmsg_len が 16 未満・終端越え・4 の倍数でないデータ・ヘッダー切れ。
            let mut short = ok.clone();
            short[..8].copy_from_slice(&15usize.to_ne_bytes());
            assert_eq!(parse_rights(&short), None);
            let mut long = ok.clone();
            long[..8].copy_from_slice(&(16usize + 64).to_ne_bytes());
            assert_eq!(parse_rights(&long), None);
            let mut odd = ok.clone();
            odd[..8].copy_from_slice(&(16usize + 6).to_ne_bytes());
            assert_eq!(parse_rights(&odd), None);
            let mut huge = ok.clone();
            huge[..8].copy_from_slice(&usize::MAX.to_ne_bytes());
            assert_eq!(parse_rights(&huge), None);
            assert_eq!(parse_rights(&ok[..10]), None);
        }
    }
}

#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use std::io;
    use std::os::fd::BorrowedFd;

    use super::Received;

    pub(super) fn send_fds(_: BorrowedFd<'_>, _: u8, _: &[BorrowedFd<'_>]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn recv_fds(_: BorrowedFd<'_>, _: usize) -> io::Result<Received> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// `token` 1 バイトに `fds`（1〜[`MAX_FDS`] 本）を添えて 1 通で送る。fd は複製されて相手へ渡るだけで、呼び出し側の fd は閉じない。
/// 相手が閉じていれば `BrokenPipe`（`SIGPIPE` は `MSG_NOSIGNAL` で抑止）。
pub(crate) fn send_fds(sock: BorrowedFd<'_>, token: u8, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    imp::send_fds(sock, token, fds)
}

/// 1 通を受けて、token と fd（最大 `max_fds` 本。`MAX_FDS` 以下）を返す。fd が 0 本でも成功で返す（本数の検査は呼び出し側）。
/// 本数超過（`MSG_CTRUNC`）・形式違反・負値の fd は、受けた fd をすべて閉じて `InvalidData`、相手が閉じていれば `UnexpectedEof`。
/// ソケットの受信期限が切れれば `WouldBlock` / `TimedOut`。
pub(crate) fn recv_fds(sock: BorrowedFd<'_>, max_fds: usize) -> io::Result<Received> {
    imp::recv_fds(sock, max_fds)
}

#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::*;

    fn pair_with_timeout() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().expect("pair");
        b.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        (a, b)
    }

    /// SEC-5・OCI-1・#4847: 3 本の fd が token つきで往復し、中身が一致する。
    #[test]
    fn sec5_4847_three_fds_round_trip() {
        let (tx, rx) = pair_with_timeout();
        let mut ends: Vec<(UnixStream, UnixStream)> = (0..3).map(|_| pair_with_timeout()).collect();
        let borrowed: Vec<_> = ends.iter().map(|(a, _)| a.as_fd()).collect();
        send_fds(tx.as_fd(), 0x58, &borrowed).expect("send");
        let got = recv_fds(rx.as_fd(), 3).expect("recv");
        assert_eq!(got.token, 0x58);
        assert_eq!(got.fds.len(), 3);
        for (i, (fd, (_, peer))) in got.fds.into_iter().zip(ends.iter_mut()).enumerate() {
            let mut s = UnixStream::from(fd);
            let msg = [b'a' + u8::try_from(i).unwrap()];
            s.write_all(&msg).expect("write");
            let mut buf = [0u8; 1];
            peer.read_exact(&mut buf).expect("read");
            assert_eq!(buf, msg);
        }
    }

    /// SEC-5・REPAIR-5・#4847: 期待より多い fd は `InvalidData` で、受けた分も溢れた分も全部閉じる（相手側が EOF を見る）。
    #[test]
    fn sec5_4847_excess_fds_are_rejected_and_all_closed() {
        let (tx, rx) = pair_with_timeout();
        let mut ends: Vec<(UnixStream, UnixStream)> = (0..3).map(|_| pair_with_timeout()).collect();
        let borrowed: Vec<_> = ends.iter().map(|(a, _)| a.as_fd()).collect();
        send_fds(tx.as_fd(), 1, &borrowed).expect("send");
        let err = recv_fds(rx.as_fd(), 2).expect_err("too many");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // 送り側の複製を閉じる。受け側が 1 本でも漏らしていれば、相手は EOF を見られず期限（5 秒）で失敗する。
        for (a, mut peer) in ends.drain(..) {
            drop(a);
            let mut buf = [0u8; 1];
            assert_eq!(peer.read(&mut buf).expect("eof"), 0);
        }
    }

    /// SEC-5・#4847: fd を添えない通信は 0 本として返る（本数の検査は呼び出し側）。相手が閉じれば `UnexpectedEof`。
    #[test]
    fn sec5_4847_plain_byte_has_no_fds_and_closed_peer_is_eof() {
        let (mut tx, rx) = pair_with_timeout();
        tx.write_all(&[7]).expect("write");
        let got = recv_fds(rx.as_fd(), 4).expect("recv");
        assert_eq!((got.token, got.fds.len()), (7, 0));
        drop(tx);
        let err = recv_fds(rx.as_fd(), 4).expect_err("eof");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// 本数の境界: 0 本と上限 + 1 は拒否する。
    #[test]
    fn sec5_4847_fd_count_bounds() {
        let (tx, rx) = pair_with_timeout();
        assert_eq!(
            send_fds(tx.as_fd(), 1, &[]).expect_err("zero").kind(),
            std::io::ErrorKind::InvalidInput
        );
        let one = tx.as_fd();
        let many = vec![one; MAX_FDS + 1];
        assert_eq!(
            send_fds(tx.as_fd(), 1, &many).expect_err("over").kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            recv_fds(rx.as_fd(), 0).expect_err("zero").kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            recv_fds(rx.as_fd(), MAX_FDS + 1).expect_err("over").kind(),
            std::io::ErrorKind::InvalidInput
        );
        // 上限ちょうどは送受信できる。
        let many = vec![one; MAX_FDS];
        send_fds(tx.as_fd(), 2, &many).expect("send max");
        assert_eq!(
            recv_fds(rx.as_fd(), MAX_FDS).expect("recv").fds.len(),
            MAX_FDS
        );
    }

    /// REPAIR-5・#4847: 受信期限が切れれば `WouldBlock` / `TimedOut`（無限に待たない）。
    #[test]
    fn sec5_4847_recv_times_out() {
        let (_tx, rx) = UnixStream::pair().expect("pair");
        rx.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        let err = recv_fds(rx.as_fd(), 1).expect_err("timeout");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }
}
