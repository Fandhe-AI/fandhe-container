//! リング（共有メモリ）の中身の記録の結合試験（GPU-6・REPAIR-2・REPAIR-5・REPAIR-12・TASK-172 後続・#1884）。
//!
//! 偽 frontend は主ソケットと backend 要求ソケットを持ち、`SHMEM_MAP` で受け取った memfd を保持して、ゲストの代わりに
//! リングの buffer と tail を `write_at` で書く。照合するのは、記録ファイル（`replay::validate` を通る FCVNSREC）のレコードの順と
//! 中身、ログ行、ゲストへの ctrl 応答、そして治具がリングを消費しない（head・status を書かない）こと。
//! memfd と SCM_RIGHTS を使うため Linux x86_64 / aarch64 のみ（他は skip を明示）。
//! 実機でゲストが mmap で書いた内容が `read_at` で見えるかは本リポでは未実測で、#725 で確かめる。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_ring_record_is_linux_only() {
    eprintln!("skip: the vhost-user session is Linux x86_64 / aarch64 only (memfd, SCM_RIGHTS)");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod common;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::common::*;
    use std::fs::File;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};

    use fandhe_container_plugin_macos::gpu::venus::replay::validate;
    use fandhe_container_poc_venus_jig::recording::{RecorderLimits, SubmitRecorder};
    use fandhe_container_poc_venus_jig::ring_record::RecordingHooks;
    use fandhe_container_poc_venus_jig::session::{
        SessionEnd, SessionError, SessionLimits, run, run_with_hooks,
    };
    use fandhe_container_poc_venus_jig::vhost_user::backend_req::{
        BackendRequestCode, decode_backend_request, encode_backend_reply,
    };
    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{recv_with_fds, send_with_fds};

    const BLOB: u64 = 0x21000;
    const WRITABLE: u32 = 408;
    const OK_NODATA: u32 = 0x1100;
    const OK_MAP_INFO: u32 = 0x1106;
    const BUF_OFF: u64 = 256;
    const BUF_SIZE: u64 = 4096;
    const RING_SIZE: u64 = 0x2000;

    fn ctrl(cmd: u32, ctx: u32, total: usize, words: &[(usize, u32)]) -> Vec<u8> {
        ctrl_req(cmd, ctx, total, words)
    }

    fn create_blob(res: u32, size: u64) -> Vec<u8> {
        let mut v = ctrl(0x010c, 1, 56, &[(24, res), (28, 2), (32, 1)]);
        v[48..56].copy_from_slice(&size.to_le_bytes());
        v
    }

    fn map_blob(res: u32) -> Vec<u8> {
        let mut v = ctrl(0x0208, 0, 40, &[(24, res)]);
        v[32..40].copy_from_slice(&0u64.to_le_bytes());
        v
    }

    /// `vkCreateRingMESA` の合成本体（Monitor つき。wire 規則は `ring_record` の doc）。
    fn create_ring_body(ring: u64, res: u32, size: u64, buf_size: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&188u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&ring.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&1_000_384_000i32.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&1_000_384_006i32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&7u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&res.to_le_bytes());
        for x in [0u64, size, 0, 0, 64, 128, BUF_OFF, buf_size, 0, 0] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    fn other_body() -> Vec<u8> {
        // vkDestroyRingMESA(189) の ring 77（表に無い ring で、本体として記録されるだけ）。
        let mut v = Vec::new();
        v.extend_from_slice(&189u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&77u64.to_le_bytes());
        v
    }

    type Outcome = (Result<SessionEnd, SessionError>, Vec<String>, Vec<Vec<u8>>);

    fn spawn_backend(sock: UnixStream, record: bool) -> JoinHandle<Outcome> {
        thread::spawn(move || {
            let limits = SessionLimits::new(T, T).expect("limits");
            let mut lines = Vec::new();
            if !record {
                let end = run(&sock, &limits, &mut |l: &str| lines.push(l.to_string()));
                return (end, lines, Vec::new());
            }
            let mut hooks =
                RecordingHooks::new(SubmitRecorder::new(Vec::new(), RecorderLimits::default()));
            let end = run_with_hooks(
                &sock,
                &limits,
                &mut |l: &str| lines.push(l.to_string()),
                &mut hooks,
            );
            let (bytes, _) = hooks.into_recorder().finish();
            let bytes = bytes.expect("finish");
            let payloads = validate(&bytes)
                .expect("validate")
                .records()
                .iter()
                .map(|r| r.payload.to_vec())
                .collect();
            (end, lines, payloads)
        })
    }

    /// backend channel の偽 frontend: `SHMEM_MAP` で受けた memfd を送り出して応答し、EOF まで読み続けて要求の種別を数える。
    fn frontend_channel(
        b: UnixStream,
        tx: mpsc::Sender<File>,
    ) -> JoinHandle<Vec<BackendRequestCode>> {
        thread::spawn(move || {
            let mut seen = Vec::new();
            loop {
                let mut buf = [0u8; 64];
                let Ok(r) = recv_with_fds(&b, &mut buf, 1, T) else {
                    break;
                };
                let d = decode_backend_request(buf.get(..r.len).expect("len")).expect("decode");
                for fd in r.fds {
                    let _ = tx.send(File::from(fd));
                }
                seen.push(d.request);
                send_with_fds(&b, &encode_backend_reply(d.request, 0), &[], T).expect("reply");
            }
            seen
        })
    }

    struct Rig {
        fe: Frontend,
        memfd: File,
        backend: JoinHandle<Outcome>,
        channel: JoinHandle<Vec<BackendRequestCode>>,
        next: u16,
    }

    fn start(tag: &str, record: bool) -> Rig {
        let (front, back) = UnixStream::pair().expect("pair");
        let (chan_front, chan_give) = UnixStream::pair().expect("chan");
        let backend = spawn_backend(back, record);
        let fe = setup_ring0_shmem_checked(front, WRITABLE, tag, chan_give.as_fd());
        drop(chan_give);
        let (tx, rx) = mpsc::channel();
        let channel = frontend_channel(chan_front, tx);
        let mut rig = Rig {
            fe,
            memfd: File::open("/dev/null").expect("placeholder"),
            backend,
            channel,
            next: 0,
        };
        assert_eq!(
            rig.post(&ctrl(0x0200, 1, 96, &[(24, 3), (28, 4)])),
            OK_NODATA
        );
        assert_eq!(rig.post(&create_blob(1, BLOB)), OK_NODATA);
        assert_eq!(rig.post(&map_blob(1)), OK_MAP_INFO);
        rig.memfd = rx.recv_timeout(T).expect("memfd from SHMEM_MAP");
        assert_eq!(rig.post(&ctrl(0x0202, 1, 32, &[(24, 1)])), OK_NODATA);
        rig
    }

    impl Rig {
        fn post(&mut self, req: &[u8]) -> u32 {
            let n = self.next;
            self.next += 1;
            post(&self.fe, n, req, WRITABLE);
            resp_type(&self.fe, n)
        }

        fn submit(&mut self, body: &[u8]) -> u32 {
            self.post(&submit_3d_req(1, body))
        }

        fn guest_write(&self, off: u64, data: &[u8]) {
            self.memfd.write_all_at(data, off).expect("guest write");
        }

        fn guest_tail(&self, tail: u32) {
            self.guest_write(64, &tail.to_le_bytes());
        }

        fn finish(self) -> (Outcome, Vec<BackendRequestCode>, File) {
            drop(self.fe);
            let out = self.backend.join().expect("join");
            let seen = self.channel.join().expect("join");
            (out, seen, self.memfd)
        }
    }

    fn ring_lines(lines: &[String]) -> Vec<&str> {
        lines
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("venus_jig event=ring_"))
            .collect()
    }

    /// 基本の流れ: CreateRing → ゲストがリングへ書く → 次の SUBMIT_3D の後にスナップショット。順序と中身を具体値で照合する。
    #[test]
    fn gpu6_1884_ring_diff_is_recorded_after_next_submit() {
        let mut rig = start("ring-basic", true);
        let create = create_ring_body(1, 1, RING_SIZE, BUF_SIZE);
        assert_eq!(rig.submit(&create), OK_NODATA);
        let cmds: Vec<u8> = (1..=24u8).collect();
        rig.guest_write(BUF_OFF, &cmds);
        rig.guest_tail(24);
        assert_eq!(rig.submit(&other_body()), OK_NODATA);
        let ((end, lines, payloads), seen, memfd) = rig.finish();
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        // ゲストの書き込みは call の後に起きるため、直前の kick の after_notify と競合する。リング由来のレコードは
        // 2 件目の本体の前後どちらにも入りうる（どちらでも内容は同じ）。先頭は CreateRing の本体で固定。
        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads[0], create);
        let mut rest = payloads[1..].to_vec();
        rest.sort();
        let mut want = vec![other_body(), cmds.clone()];
        want.sort();
        assert_eq!(rest, want);
        let rl = ring_lines(&lines);
        assert_eq!(rl.len(), 2, "{rl:?}");
        assert_eq!(
            rl[0],
            "venus_jig event=ring_create ring=1 res_id=1 buffer_size=4096 result=ok"
        );
        assert!(
            rl[1].starts_with(
                "venus_jig event=ring_record ring=1 res_id=1 from=0 to=24 len=24 seqno="
            ) && rl[1].ends_with(" outcome=recorded"),
            "{rl:?}"
        );
        // 治具は SHMEM_MAP / SHMEM_UNMAP 以外の backend 要求を送らず、リングを消費しない（head・status は 0 のまま）。
        assert_eq!(
            seen,
            vec![BackendRequestCode::ShmemMap, BackendRequestCode::ShmemUnmap]
        );
        let mut head_tail_status = [0u8; 4];
        memfd.read_exact_at(&mut head_tail_status, 0).expect("head");
        assert_eq!(head_tail_status, [0; 4]);
        memfd
            .read_exact_at(&mut head_tail_status, 128)
            .expect("status");
        assert_eq!(head_tail_status, [0; 4]);
        memfd
            .read_exact_at(&mut head_tail_status, 64)
            .expect("tail");
        assert_eq!(u32::from_le_bytes(head_tail_status), 24);
        let mut buf = vec![0u8; 24];
        memfd.read_exact_at(&mut buf, BUF_OFF).expect("buffer");
        assert_eq!(buf, cmds);
    }

    /// 終了時のスナップショット: SUBMIT_3D を送らずに切断しても、リングへ書かれた分が記録される（実機の想定経路）。
    #[test]
    fn gpu6_1884_ring_is_snapshotted_at_session_end() {
        let mut rig = start("ring-end", true);
        let create = create_ring_body(2, 1, RING_SIZE, BUF_SIZE);
        assert_eq!(rig.submit(&create), OK_NODATA);
        let cmds = vec![0xabu8; 40];
        rig.guest_write(BUF_OFF, &cmds);
        rig.guest_tail(40);
        let ((end, lines, payloads), _, _) = rig.finish();
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        assert_eq!(payloads, vec![create, cmds]);
        assert_eq!(
            ring_lines(&lines).last().copied(),
            Some(
                "venus_jig event=ring_record ring=2 res_id=1 from=0 to=40 len=40 seqno=1 outcome=recorded"
            )
        );
    }

    /// 拒否: 範囲外の tail・存在しない blob・blob より大きい CreateRing は語彙つきのログだけを出し、セッションは続く。
    #[test]
    fn gpu6_1884_bad_ring_is_logged_and_session_continues() {
        let mut rig = start("ring-bad", true);
        let create = create_ring_body(3, 1, RING_SIZE, BUF_SIZE);
        assert_eq!(rig.submit(&create), OK_NODATA);
        rig.guest_tail(BUF_SIZE as u32 + 1);
        assert_eq!(rig.submit(&other_body()), OK_NODATA);
        // 存在しない res_id の CreateRing（スナップショットで blob_not_held）。
        assert_eq!(
            rig.submit(&create_ring_body(4, 9, RING_SIZE, BUF_SIZE)),
            OK_NODATA
        );
        // blob より大きい（OutOfRange はスナップショットで検出する）。
        assert_eq!(
            rig.submit(&create_ring_body(5, 1, BLOB * 2, BUF_SIZE)),
            OK_NODATA
        );
        let ((end, lines, payloads), _, _) = rig.finish();
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        // リング由来のレコードは無い（本体 4 件だけ）。
        assert_eq!(payloads.len(), 4);
        let rl = ring_lines(&lines);
        assert!(
            rl.contains(&"venus_jig event=ring_error ring=3 code=tail_out_of_range"),
            "{rl:?}"
        );
        assert!(
            rl.contains(&"venus_jig event=ring_error ring=4 code=blob_not_held"),
            "{rl:?}"
        );
        assert!(
            rl.contains(&"venus_jig event=ring_error ring=5 code=out_of_range"),
            "{rl:?}"
        );
        assert_eq!(
            rl.iter()
                .filter(|l| l.contains("event=ring_record"))
                .count(),
            0
        );
    }

    /// 記録の有無で変わらないもの: ゲストへの ctrl 応答の種別と、`ring_`・`record_` 以外のログ行。
    #[test]
    fn gpu6_1884_recording_does_not_change_responses_or_other_logs() {
        let run_once = |record: bool, tag: &str| {
            let mut rig = start(tag, record);
            let mut resp = vec![rig.submit(&create_ring_body(1, 1, RING_SIZE, BUF_SIZE))];
            rig.guest_write(BUF_OFF, &[1, 2, 3, 4]);
            rig.guest_tail(4);
            resp.push(rig.submit(&other_body()));
            let ((end, lines, _), _, _) = rig.finish();
            assert_eq!(end, Ok(SessionEnd::PeerClosed));
            let other: Vec<String> = lines
                .into_iter()
                .filter(|l| {
                    !l.starts_with("venus_jig event=ring_")
                        && !l.starts_with("venus_jig event=record_")
                        && !l.starts_with("venus_jig event=session_op")
                        && !l.starts_with("venus_jig event=vhost_user_io")
                })
                .collect();
            (resp, other)
        };
        let (r1, l1) = run_once(false, "ring-off");
        let (r2, l2) = run_once(true, "ring-on");
        assert_eq!(r1, vec![OK_NODATA, OK_NODATA]);
        assert_eq!(r1, r2);
        assert_eq!(l1, l2);
    }
}
