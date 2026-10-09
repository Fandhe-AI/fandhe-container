//! vhost-user の fd 受け渡しとゲストメモリ mmap の結合試験（GPU-6・TASK-172 F1.2・#1517）。
//!
//! memfd・`SCM_RIGHTS`・`/proc/self` は Linux 固有で、syscall の定数は x86_64 / aarch64 にだけ定義している。それ以外では
//! skip を明示するテスト 1 本だけを走らせる（`benches/tests/macos_cold_start.rs` と同じ流儀。対応外アーキの Linux では
//! API が `UNSUPPORTED` を返す）。root・KVM・GPU は要らない。期待値は具体値で照合する。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_transport_is_linux_only() {
    eprintln!(
        "skip: fd passing and guest memory mmap are Linux x86_64 / aarch64 only (memfd, MSG_CMSG_CLOEXEC)"
    );
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{
        MAX_FDS, create_memfd, create_memfd_unsealed, recv_with_fds, send_with_fds,
    };
    use fandhe_container_poc_venus_jig::vhost_user::guest_memory::{
        GuestMemory, GuestMemoryRegion, MAX_REGION_SIZE, MAX_TOTAL_MAP_LEN,
    };
    use fandhe_container_poc_venus_jig::vhost_user::{MemRegion, MemTable, TransportErrorCode};

    const T: Duration = Duration::from_secs(5);
    const O_CLOEXEC: u32 = 0o200_0000;

    /// テストごとに一意な memfd 名（並列実行でも `/proc/self` の照合が干渉しない）。
    fn unique_name(tag: &str) -> String {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            "jig-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn memfd(name: &str, len: u64) -> File {
        let c = CString::new(name).expect("name has no NUL");
        create_memfd(&c, len).expect("memfd_create")
    }

    /// `/proc/self/fd` のうち名前 `name` の memfd を指すエントリ数。
    fn count_fds(name: &str) -> usize {
        let needle = format!("/memfd:{name} (deleted)");
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .filter_map(|e| e.ok())
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter(|l| l.to_string_lossy() == needle)
            .count()
    }

    /// `/proc/self/maps` のうち名前 `name` の memfd の行数。
    fn count_maps(name: &str) -> usize {
        let needle = format!("/memfd:{name} (deleted)");
        std::fs::read_to_string("/proc/self/maps")
            .expect("read maps")
            .lines()
            .filter(|l| l.ends_with(&needle))
            .count()
    }

    fn fd_flags(fd: &OwnedFd) -> u32 {
        let s = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
            .expect("read fdinfo");
        let line = s
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .expect("flags line");
        u32::from_str_radix(line.trim(), 8).expect("octal flags")
    }

    fn borrow_n(f: &File, n: usize) -> Vec<BorrowedFd<'_>> {
        (0..n).map(|_| f.as_fd()).collect()
    }

    #[test]
    fn gpu6_three_fds_roundtrip_with_cloexec_and_shared_content() {
        let (a, b) = UnixStream::pair().expect("pair");
        let files: Vec<File> = (0..3)
            .map(|i| memfd(&unique_name(&format!("rt{i}")), 16))
            .collect();
        for (i, f) in files.iter().enumerate() {
            f.write_all_at(&[i as u8 + 1; 4], 0).expect("write");
        }
        let fds: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
        assert_eq!(send_with_fds(&a, b"hello", &fds, T).expect("send").len, 5);

        let mut buf = [0u8; 64];
        let got = recv_with_fds(&b, &mut buf, 3, T).expect("recv");
        assert_eq!(got.len, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(got.fds.len(), 3);
        for (i, fd) in got.fds.iter().enumerate() {
            assert_eq!(
                fd_flags(fd) & O_CLOEXEC,
                O_CLOEXEC,
                "fd {i} must be CLOEXEC"
            );
            let f = File::from(fd.try_clone().expect("dup"));
            let mut v = [0u8; 4];
            f.read_exact_at(&mut v, 0).expect("read");
            assert_eq!(v, [i as u8 + 1; 4]);
        }
        // 受信側から書いた値が送信元の fd でも見える（同じ memfd を指す）。
        let f0 = File::from(got.fds[0].try_clone().expect("dup"));
        f0.write_all_at(&[9, 9], 8).expect("write");
        let mut v = [0u8; 2];
        files[0].read_exact_at(&mut v, 8).expect("read");
        assert_eq!(v, [9, 9]);
    }

    #[test]
    fn gpu6_too_many_fds_is_rejected_without_leaking() {
        let (a, b) = UnixStream::pair().expect("pair");
        let name = unique_name("many");
        let f = memfd(&name, 8);
        send_with_fds(&a, b"x", &borrow_n(&f, 3), T).expect("send");
        let mut buf = [0u8; 8];
        let e = recv_with_fds(&b, &mut buf, 2, T).expect_err("must reject");
        assert_eq!(e.code, TransportErrorCode::TooManyFds);
        assert_eq!(e.code.as_str(), "TOO_MANY_FDS");
        // 受け取った 3 個はすべて閉じられ、残るのは送信側の元の fd 1 個だけ。
        assert_eq!(count_fds(&name), 1);
        drop(f);
        assert_eq!(count_fds(&name), 0);
    }

    #[test]
    fn gpu6_max_fds_boundary_and_oversize_send() {
        let (a, b) = UnixStream::pair().expect("pair");
        let name = unique_name("max");
        let f = memfd(&name, 8);
        // 送信 API は MAX_FDS 超を拒否する。
        let e = send_with_fds(&a, b"x", &borrow_n(&f, MAX_FDS + 1), T).expect_err("oversize");
        assert_eq!(e.code, TransportErrorCode::InvalidArgument);
        // MAX_FDS ちょうどは切り詰められずに受け取れる（切り詰めの検出は fd_passing の単体試験で照合する）。
        send_with_fds(&a, b"x", &borrow_n(&f, MAX_FDS), T).expect("send 32");
        let mut buf = [0u8; 8];
        let ok = recv_with_fds(&b, &mut buf, MAX_FDS, T).expect("32 fds fit");
        assert_eq!(ok.fds.len(), 32);
        drop(ok);
        assert_eq!(count_fds(&name), 1);
    }

    #[test]
    fn gpu6_recv_timeout_is_reported_within_bound() {
        let (_a, b) = UnixStream::pair().expect("pair");
        let mut buf = [0u8; 8];
        let t0 = Instant::now();
        let e = recv_with_fds(&b, &mut buf, 1, Duration::from_millis(50)).expect_err("timeout");
        assert_eq!(e.code, TransportErrorCode::Timeout);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn gpu6_peer_close_and_invalid_arguments() {
        let (a, b) = UnixStream::pair().expect("pair");
        drop(a);
        let mut buf = [0u8; 8];
        let e = recv_with_fds(&b, &mut buf, 1, T).expect_err("closed");
        assert_eq!(e.code, TransportErrorCode::PeerClosed);
        let e = recv_with_fds(&b, &mut buf, MAX_FDS + 1, T).expect_err("max_fds");
        assert_eq!(e.code, TransportErrorCode::InvalidArgument);
        let e = recv_with_fds(&b, &mut buf, 1, Duration::ZERO).expect_err("timeout 0");
        assert_eq!(e.code, TransportErrorCode::InvalidArgument);
        let e = recv_with_fds(&b, &mut [], 1, T).expect_err("empty buf");
        assert_eq!(e.code, TransportErrorCode::InvalidArgument);
    }

    fn region(gpa: u64, size: u64, off: u64) -> MemRegion {
        MemRegion {
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: 0x7f00_0000_0000,
            mmap_offset: off,
        }
    }

    #[test]
    fn gpu6_region_read_write_is_shared_with_the_file() {
        let name = unique_name("rw");
        let f = memfd(&name, 0x3000);
        let r = GuestMemoryRegion::map(&f, &region(0x1000_0000, 0x2000, 0x1000)).expect("map");
        assert_eq!(count_maps(&name), 1);
        r.write_at(0x1000_0010, &[1, 2, 3, 4]).expect("write");
        let mut v = [0u8; 4];
        r.read_at(0x1000_0010, &mut v).expect("read");
        assert_eq!(v, [1, 2, 3, 4]);
        // MAP_SHARED: mmap_offset (0x1000) + 0x10 のファイル位置に見える。
        let mut file_v = [0u8; 4];
        f.read_exact_at(&mut file_v, 0x1010).expect("file read");
        assert_eq!(file_v, [1, 2, 3, 4]);
        // 領域の末尾ちょうどまでは読める。
        let mut last = [0u8; 1];
        r.read_at(0x1000_1fff, &mut last).expect("last byte");
        drop(r);
        drop(f);
        assert_eq!(count_maps(&name), 0, "Drop must munmap");
    }

    #[test]
    fn gpu6_region_out_of_bounds_access_is_rejected() {
        let f = memfd(&unique_name("oob"), 0x2000);
        let r = GuestMemoryRegion::map(&f, &region(0x1000, 0x1000, 0)).expect("map");
        let mut b4 = [0u8; 4];
        for gpa in [0xfff, 0x2000, 0x1ffd, u64::MAX - 1, 0] {
            let e = r.read_at(gpa, &mut b4).expect_err("must be OOB");
            assert_eq!(e.code, TransportErrorCode::OutOfBounds, "gpa {gpa:#x}");
        }
        let e = r.write_at(0x1ffd, &[0; 4]).expect_err("write OOB");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
        // 長さ 0 は領域内（末尾を含む）に限り成功する。
        r.read_at(0x2000, &mut []).expect("zero length at end");
        let e = r
            .read_at(0x2001, &mut [])
            .expect_err("zero length past end");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
    }

    #[test]
    fn gpu6_region_validation_errors() {
        let f = memfd(&unique_name("val"), 0x1000);
        let code = |r: MemRegion| GuestMemoryRegion::map(&f, &r).expect_err("reject").code;
        assert_eq!(code(region(0, 0, 0)), TransportErrorCode::InvalidRegion);
        assert_eq!(code(region(0, 0x2000, 0)), TransportErrorCode::FileTooShort);
        assert_eq!(code(region(0, 0x1000, 1)), TransportErrorCode::FileTooShort);
        assert_eq!(
            code(region(u64::MAX, 2, 0)),
            TransportErrorCode::InvalidRegion
        );
        assert_eq!(
            code(region(0, 1, u64::MAX)),
            TransportErrorCode::InvalidRegion
        );
        assert_eq!(
            code(region(0, MAX_REGION_SIZE + 1, 0)),
            TransportErrorCode::InvalidRegion
        );
    }

    fn table(rs: &[MemRegion]) -> MemTable {
        MemTable::new(rs).expect("table")
    }

    fn owned(f: File) -> OwnedFd {
        OwnedFd::from(f)
    }

    #[test]
    fn gpu6_guest_memory_resolves_regions_and_rejects_bad_tables() {
        let a = memfd(&unique_name("gm-a"), 0x1000);
        let b = memfd(&unique_name("gm-b"), 0x1000);
        let t = table(&[region(0x1000, 0x1000, 0), region(0x4000, 0x1000, 0)]);
        let gm = GuestMemory::from_table(&t, vec![owned(a), owned(b)]).expect("map");
        gm.write_at(0x1004, &[7, 7]).expect("w a");
        gm.write_at(0x4008, &[8]).expect("w b");
        let mut v = [0u8; 2];
        gm.read_at(0x1004, &mut v).expect("r a");
        assert_eq!(v, [7, 7]);
        let mut w = [0u8; 1];
        gm.read_at(0x4008, &mut w).expect("r b");
        assert_eq!(w, [8]);
        assert_eq!(gm.regions().len(), 2);
        // 隙間・領域をまたぐアクセスは拒否する。
        let e = gm.read_at(0x2000, &mut w).expect_err("gap");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
        let e = gm.read_at(0x1fff, &mut v).expect_err("cross end");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);

        let c = memfd(&unique_name("gm-c"), 0x1000);
        let e = GuestMemory::from_table(&t, vec![owned(c)]).expect_err("count mismatch");
        assert_eq!(e.code, TransportErrorCode::FdCountMismatch);

        let (d, e2) = (
            memfd(&unique_name("gm-d"), 0x2000),
            memfd(&unique_name("gm-e"), 0x2000),
        );
        let ov = table(&[region(0x1000, 0x1000, 0), region(0x1800, 0x1000, 0)]);
        let e = GuestMemory::from_table(&ov, vec![owned(d), owned(e2)]).expect_err("overlap");
        assert_eq!(e.code, TransportErrorCode::OverlappingRegions);
    }

    #[test]
    fn gpu6_failed_table_unmaps_already_mapped_regions() {
        let name = unique_name("gm-fail");
        let a = memfd(&name, 0x1000);
        let b = memfd(&unique_name("gm-fail2"), 0x10);
        let t = table(&[region(0, 0x1000, 0), region(0x1000, 0x1000, 0)]);
        let e =
            GuestMemory::from_table(&t, vec![owned(a), owned(b)]).expect_err("second too short");
        assert_eq!(e.code, TransportErrorCode::FileTooShort);
        assert_eq!(count_maps(&name), 0);
        assert_eq!(count_fds(&name), 0);
    }

    /// GPU-6・REPAIR-5: 縮小が封じられていない fd は map 前に `SHRINK_NOT_SEALED` で拒否する（SIGBUS 対策）。
    #[test]
    fn gpu6_unsealed_or_unsealable_fd_is_rejected_before_mmap() {
        let name = unique_name("unsealed");
        let c = CString::new(name.as_str()).expect("name");
        let f = create_memfd_unsealed(&c, 0x1000).expect("memfd");
        let e = GuestMemoryRegion::map(&f, &region(0, 0x1000, 0)).expect_err("no seal");
        assert_eq!(e.code, TransportErrorCode::ShrinkNotSealed);
        assert_eq!(e.code.as_str(), "SHRINK_NOT_SEALED");
        assert_eq!(count_maps(&name), 0);
        // 通常ファイルは治具の memfd と st_dev が違うので、seal を調べる前に `UNSUPPORTED_BACKING` で拒否する
        // （hugetlb の memfd も同じ経路。長さが足りる場合でも同じ）。
        let exe = File::open("/proc/self/exe").expect("open exe");
        let e = GuestMemoryRegion::map(&exe, &region(0, 1, 0)).expect_err("regular file");
        assert_eq!(e.code, TransportErrorCode::UnsupportedBacking);
        assert_eq!(e.code.as_str(), "UNSUPPORTED_BACKING");
        assert_eq!(
            e.to_string(),
            "UNSUPPORTED_BACKING: backing file is not a shmem memfd supported by the jig"
        );
        // GuestMemory 経由でも同じ。
        let g = create_memfd_unsealed(&c, 0x1000).expect("memfd");
        let t = table(&[region(0, 0x1000, 0)]);
        let e = GuestMemory::from_table(&t, vec![owned(g)]).expect_err("table");
        assert_eq!(e.code, TransportErrorCode::ShrinkNotSealed);
    }

    /// GPU-6: seal 済みの memfd は map 後に縮められず、領域内のアクセスが SIGBUS にならない。
    #[test]
    fn gpu6_sealed_memfd_cannot_shrink_after_map() {
        let f = memfd(&unique_name("seal"), 0x2000);
        let r = GuestMemoryRegion::map(&f, &region(0, 0x2000, 0)).expect("map");
        assert!(f.set_len(0).is_err(), "shrink must be refused by the seal");
        let mut b = [0u8; 1];
        r.read_at(0x1fff, &mut b).expect("still readable");
    }

    /// GPU-6: 同じ backing memory を複製した `File` で 2 スレッドから同時に map しても、重なる範囲は 1 領域しか
    /// 生きられない（もう一方は mmap 前に `BACKING_IN_USE`）。safe API だけで非アトミックなコピーを並行させない。
    #[test]
    fn gpu6_two_threads_cannot_map_the_same_backing_range() {
        let name = unique_name("excl");
        let f = memfd(&name, 0x2000);
        let files = [f.try_clone().expect("dup 1"), f.try_clone().expect("dup 2")];
        let barrier = std::sync::Barrier::new(2);
        let codes: Vec<Option<&'static str>> = std::thread::scope(|s| {
            let handles: Vec<_> = files
                .iter()
                .enumerate()
                .map(|(i, file)| {
                    let barrier = &barrier;
                    s.spawn(move || {
                        let gpa = 0x1000_0000 * (u64::try_from(i).expect("index") + 1);
                        let r = GuestMemoryRegion::map(file, &region(gpa, 0x2000, 0));
                        // 両方の map が終わるまで成功した領域を生かしておく（先に drop すると両方成功し得る）。
                        barrier.wait();
                        r.err().map(|e| e.code.as_str())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("join"))
                .collect()
        });
        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![None, Some("BACKING_IN_USE")],
            "codes={codes:?}"
        );
        // 成功した側の drop 後は map も占有も残らない。
        assert_eq!(count_maps(&name), 0);
        let r = GuestMemoryRegion::map(&f, &region(0, 0x2000, 0)).expect("after both dropped");
        assert_eq!(r.mapped_len(), 0x2000);
    }

    /// GPU-6: 合計上限は mmap より前に判定する（3 x 64 GiB は map されず `INVALID_REGION`）。
    #[test]
    fn gpu6_total_limit_is_checked_before_any_mmap() {
        assert_eq!(MAX_TOTAL_MAP_LEN, 2 * MAX_REGION_SIZE);
        let names: Vec<String> = (0..3).map(|i| unique_name(&format!("tot{i}"))).collect();
        let fds: Vec<OwnedFd> = names.iter().map(|n| owned(memfd(n, 0x1000))).collect();
        let g = MAX_REGION_SIZE;
        let t = table(&[region(0, g, 0), region(g, g, 0), region(2 * g, g, 0)]);
        let e = GuestMemory::from_table(&t, fds).expect_err("over total");
        // 先に map していれば先頭領域が FILE_TOO_SHORT になる。mmap 前の判定なら INVALID_REGION。
        assert_eq!(e.code, TransportErrorCode::InvalidRegion);
        for n in &names {
            assert_eq!(count_maps(n), 0);
            assert_eq!(count_fds(n), 0);
        }
    }
}
