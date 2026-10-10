//! 共有メモリの一連の結合試験: ネゴシエーションから blob の解放まで、ゲストのカーネルと同じ順で通す
//! （GPU-6・REPAIR-5・REPAIR-12・TASK-172 F5.2b.4b・#1645）。
//!
//! 偽 frontend は主ソケット（vhost-user）と backend 要求ソケット（`SET_BACKEND_REQ_FD` で渡す socketpair の片端）の 2 本を持つ。
//! ゲストのカーネル（Linux v6.12）の順は `RESOURCE_CREATE_BLOB` → `RESOURCE_MAP_BLOB` → `CTX_ATTACH_RESOURCE`、解放は
//! detach → unmap → unref（設計書 10.4.2）。照合するのは、backend 要求の列とその値（shmid・shm_offset・len・fd の本数・fd の大きさ）、
//! ゲストへの ctrl 応答の種別の列、セッションの結果とログ。解放の扱い（設計書 10.4.3 の D1〜D3）も具体値で固定する。
//! memfd と SCM_RIGHTS を使うため Linux x86_64 / aarch64 のみ（他は skip を明示）。memfd の閉じ忘れの照合は fd 数を数える
//! 必要があり、同じテストバイナリの並列スレッドと干渉するので、ユニットテスト（`session::map_blob_tests`）で行う。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_shmem_lifecycle_is_linux_only() {
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
    use std::os::unix::net::UnixStream;
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use fandhe_container_poc_venus_jig::session::{
        SessionEnd, SessionError, SessionErrorCode, SessionLimits, run,
    };
    use fandhe_container_poc_venus_jig::vhost_user::backend_req::{
        BackendRequestCode, decode_backend_request, encode_backend_reply,
    };
    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{recv_with_fds, send_with_fds};
    use fandhe_container_poc_venus_jig::vhost_user::{Request, VringState};

    type Outcome = (Result<SessionEnd, SessionError>, Vec<String>);
    /// 偽 frontend が受けた backend 要求（種別・shmid・shm_offset・len・添付 fd の本数・その fd の大きさ）。
    type Seen = (BackendRequestCode, u8, u64, u64, usize, Option<u64>);

    const OK_NODATA: u32 = 0x1100;
    const OK_MAP_INFO: u32 = 0x1106;
    const ERR_INVALID_PARAMETER: u32 = 0x1205;
    /// ring の 128 KiB + 4 をページで切り上げた大きさ（設計書 10.3 のログ例と同じ）。
    const BLOB: u64 = 0x21000;
    const WRITABLE: u32 = 408;

    fn spawn_backend(sock: UnixStream, timeout: std::time::Duration) -> JoinHandle<Outcome> {
        thread::spawn(move || {
            let limits = SessionLimits::new(timeout, timeout).expect("limits");
            let mut lines = Vec::new();
            let end = run(&sock, &limits, &mut |l: &str| lines.push(l.to_string()));
            (end, lines)
        })
    }

    /// backend 要求側の偽 frontend の記録。
    struct Record {
        seen: Vec<Seen>,
        /// 受け取った fd の複製（セッション終了後も閉じずに持ち、大きさが変わらないことを確かめる）。
        kept: Vec<File>,
    }

    /// backend channel の偽 frontend: `replies` の数だけ要求に順に応じ、その後も EOF（セッション側の close）まで読み続ける。
    /// 治具が送った要求を漏れなく数えるため（「ほかに送っていない」ことを列の完全一致で示す）。
    /// `close_after_replies` なら、応答を返し終えた時点で channel を閉じる。
    fn frontend_channel(
        b: UnixStream,
        replies: Vec<u64>,
        close_after_replies: bool,
    ) -> JoinHandle<Record> {
        thread::spawn(move || {
            let mut rec = Record {
                seen: Vec::new(),
                kept: Vec::new(),
            };
            let mut remaining = replies.into_iter();
            loop {
                let mut buf = [0u8; 64];
                let Ok(r) = recv_with_fds(&b, &mut buf, 1, T) else {
                    break;
                };
                let d = decode_backend_request(buf.get(..r.len).expect("len")).expect("decode");
                let mut meta = None;
                for fd in r.fds {
                    let f = File::from(fd);
                    meta = Some(f.metadata().expect("meta").len());
                    rec.kept.push(f);
                }
                rec.seen.push((
                    d.request,
                    d.shmid,
                    d.shm_offset,
                    d.len,
                    usize::from(meta.is_some()),
                    meta,
                ));
                if let Some(v) = remaining.next() {
                    send_with_fds(&b, &encode_backend_reply(d.request, v), &[], T).expect("reply");
                }
                if close_after_replies && remaining.len() == 0 {
                    break;
                }
            }
            rec
        })
    }

    fn create_blob(res: u32, size: u64) -> Vec<u8> {
        let mut v = ctrl_req(0x010c, 1, 56, &[(24, res), (28, 2), (32, 1)]);
        v[48..56].copy_from_slice(&size.to_le_bytes());
        v
    }

    fn map_blob(res: u32, offset: u64) -> Vec<u8> {
        let mut v = ctrl_req(0x0208, 0, 40, &[(24, res)]);
        v[32..40].copy_from_slice(&offset.to_le_bytes());
        v
    }

    fn unmap_blob(res: u32) -> Vec<u8> {
        ctrl_req(0x0209, 0, 32, &[(24, res)])
    }

    fn attach(res: u32) -> Vec<u8> {
        ctrl_req(0x0202, 1, 32, &[(24, res)])
    }

    fn detach(res: u32) -> Vec<u8> {
        ctrl_req(0x0203, 1, 32, &[(24, res)])
    }

    fn unref(res: u32) -> Vec<u8> {
        ctrl_req(0x0102, 0, 32, &[(24, res)])
    }

    fn ctx_destroy() -> Vec<u8> {
        ctrl_req(0x0201, 1, 24, &[])
    }

    /// ネゴシエーション（値を照合）を済ませて ring 0 を返す。
    fn start(
        tag: &str,
        timeout: std::time::Duration,
    ) -> (Frontend, UnixStream, JoinHandle<Outcome>) {
        let (front, back) = UnixStream::pair().expect("pair");
        let (chan_front, chan_give) = UnixStream::pair().expect("chan");
        let backend = spawn_backend(back, timeout);
        let fe = setup_ring0_shmem_checked(front, WRITABLE, tag, chan_give.as_fd());
        drop(chan_give);
        (fe, chan_front, backend)
    }

    /// 要求を順に積み、各応答の種別と used len を読む（応答の領域は使い回されるので積むたびに読む）。
    fn post_all(fe: &Frontend, first: u16, reqs: &[Vec<u8>]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for (i, r) in reqs.iter().enumerate() {
            let n = first + u16::try_from(i).expect("index");
            post(fe, n, r, WRITABLE);
            out.push((resp_type(fe, n), used_len(fe, n)));
        }
        out
    }

    fn count(lines: &[String], want: &str) -> usize {
        lines.iter().filter(|l| l.as_str() == want).count()
    }

    const MAP_SEEN: Seen = (BackendRequestCode::ShmemMap, 1, 0, BLOB, 1, Some(BLOB));
    const UNMAP_SEEN: Seen = (BackendRequestCode::ShmemUnmap, 1, 0, BLOB, 0, None);

    /// カーネルの順（CREATE_BLOB → MAP_BLOB → CTX_ATTACH）と Issue 本文の順（CREATE → ATTACH → MAP）で同じ結果になる。
    fn full_sequence(tag: &str, attach_before_map: bool) {
        let (fe, chan, backend) = start(tag, T);
        let h = frontend_channel(chan, vec![0, 0], false);
        let mut reqs = vec![ctx_create_req(1), create_blob(1, BLOB)];
        if attach_before_map {
            reqs.extend([attach(1), map_blob(1, 0)]);
        } else {
            reqs.extend([map_blob(1, 0), attach(1)]);
        }
        reqs.extend([detach(1), unmap_blob(1), unref(1), ctx_destroy()]);
        let resp = post_all(&fe, 0, &reqs);
        let map_idx = if attach_before_map { 3 } else { 2 };
        let want: Vec<(u32, u32)> = (0..8)
            .map(|i| {
                if i == map_idx {
                    (OK_MAP_INFO, 32)
                } else {
                    (OK_NODATA, 24)
                }
            })
            .collect();
        assert_eq!(resp, want);
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        let rec = h.join().expect("join");
        assert_eq!(rec.seen, vec![MAP_SEEN, UNMAP_SEEN]);
        assert_eq!(
            count(&lines, "venus_jig event=host_visible status=ready"),
            1,
            "{lines:?}"
        );
        assert_eq!(
            count(
                &lines,
                "venus_jig event=blob_release mapped=0 unmapped=0 memfds=0"
            ),
            1,
            "{lines:?}"
        );
        assert_eq!(
            count(
                &lines,
                "venus_jig event=backend_req cmd=SHMEM_MAP shmid=1 shm_offset=0 len=135168 result=ok status=0"
            ),
            1,
            "{lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("venus_jig event=session_end result=peer_closed")
        );
    }

    /// GPU-6（#1645）: ネゴシエーションから解放まで、ゲストのカーネルの順で通す。
    #[test]
    fn f5_2b_4b_gpu6_full_sequence_kernel_order() {
        full_sequence("seqkernel", false);
    }

    /// GPU-6（#1645）: Issue 本文の順（CREATE → ATTACH → MAP）でも同じ応答と backend 要求の列になる
    /// （治具は MAP に attach を要求しない。MAP_BLOB のヘッダの ctx_id は 0）。
    #[test]
    fn f5_2b_4b_gpu6_full_sequence_attach_before_map() {
        full_sequence("seqattach", true);
    }

    /// GPU-6（#1645・D1）: map 中の `UNREF` は `ERR_INVALID_PARAMETER` で拒否し、frontend へは何も送らない。
    #[test]
    fn f5_2b_4b_gpu6_unref_while_mapped_is_rejected_without_backend_request() {
        let (fe, chan, backend) = start("d1", T);
        let h = frontend_channel(chan, vec![0, 0], false);
        let resp = post_all(
            &fe,
            0,
            &[
                ctx_create_req(1),
                create_blob(1, BLOB),
                map_blob(1, 0),
                unref(1),
                unmap_blob(1),
                unref(1),
            ],
        );
        assert_eq!(
            resp,
            vec![
                (OK_NODATA, 24),
                (OK_NODATA, 24),
                (OK_MAP_INFO, 32),
                (ERR_INVALID_PARAMETER, 24),
                (OK_NODATA, 24),
                (OK_NODATA, 24),
            ]
        );
        drop(fe);
        assert_eq!(backend.join().expect("join").0, Ok(SessionEnd::PeerClosed));
        assert_eq!(h.join().expect("join").seen, vec![MAP_SEEN, UNMAP_SEEN]);
    }

    /// GPU-6（#1645・D2）: map 中の res を attach した ctx の `CTX_DESTROY` は detach だけ行い、map は残す。
    /// `CTX_DESTROY` の時点で backend 要求は `SHMEM_MAP` だけで、その後の `UNMAP_BLOB` と `UNREF` は成功する。
    #[test]
    fn f5_2b_4b_gpu6_ctx_destroy_keeps_mapping() {
        let (fe, chan, backend) = start("d2", T);
        let h = frontend_channel(chan, vec![0, 0], false);
        let first = post_all(
            &fe,
            0,
            &[
                ctx_create_req(1),
                create_blob(1, BLOB),
                map_blob(1, 0),
                attach(1),
                ctx_destroy(),
            ],
        );
        assert_eq!(
            first,
            vec![
                (OK_NODATA, 24),
                (OK_NODATA, 24),
                (OK_MAP_INFO, 32),
                (OK_NODATA, 24),
                (OK_NODATA, 24),
            ]
        );
        let rest = post_all(&fe, 5, &[unmap_blob(1), unref(1)]);
        assert_eq!(rest, vec![(OK_NODATA, 24), (OK_NODATA, 24)]);
        drop(fe);
        assert_eq!(backend.join().expect("join").0, Ok(SessionEnd::PeerClosed));
        // UNMAP は UNMAP_BLOB の 1 回だけ（CTX_DESTROY では送られていない）。
        assert_eq!(h.join().expect("join").seen, vec![MAP_SEEN, UNMAP_SEEN]);
    }

    /// GPU-6・REPAIR-5（#1645・D3）: map が残ったままの正常終了では、治具が `SHMEM_UNMAP` を送ってから memfd を閉じる。
    #[test]
    fn f5_2b_4b_gpu6_session_end_with_mapping_sends_unmap() {
        let (fe, chan, backend) = start("d3ok", T);
        let h = frontend_channel(chan, vec![0, 0], false);
        let resp = post_all(
            &fe,
            0,
            &[ctx_create_req(1), create_blob(1, BLOB), map_blob(1, 0)],
        );
        assert_eq!(
            resp,
            vec![(OK_NODATA, 24), (OK_NODATA, 24), (OK_MAP_INFO, 32)]
        );
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        let rec = h.join().expect("join");
        assert_eq!(rec.seen, vec![MAP_SEEN, UNMAP_SEEN]);
        assert_eq!(
            count(
                &lines,
                "venus_jig event=backend_req cmd=SHMEM_UNMAP shmid=1 shm_offset=0 len=135168 result=ok status=0"
            ),
            1,
            "{lines:?}"
        );
        assert_eq!(
            count(
                &lines,
                "venus_jig event=blob_release mapped=1 unmapped=1 memfds=1"
            ),
            1,
            "{lines:?}"
        );
        // 治具が閉じても、frontend が受け取った複製の fd は有効なまま。
        let sizes: Vec<u64> = rec
            .kept
            .iter()
            .map(|f| f.metadata().expect("meta").len())
            .collect();
        assert_eq!(sizes, vec![BLOB]);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("venus_jig event=session_end result=peer_closed")
        );
    }

    /// GPU-6・REPAIR-5（#1645・D3）: エラー終了でも片づけを行い、セッションの結果は元のエラーのまま。
    #[test]
    fn f5_2b_4b_gpu6_session_error_with_mapping_sends_unmap_and_keeps_error() {
        let (fe, chan, backend) = start("d3err", T);
        let h = frontend_channel(chan, vec![0, 0], false);
        let resp = post_all(
            &fe,
            0,
            &[ctx_create_req(1), create_blob(1, BLOB), map_blob(1, 0)],
        );
        assert_eq!(
            resp,
            vec![(OK_NODATA, 24), (OK_NODATA, 24), (OK_MAP_INFO, 32)]
        );
        // 不正な値: virtqueue の大きさ 3（2 の冪でない）は INVALID_VALUE（request = 8）でセッションを終える。
        send(
            &fe._sock,
            &Request::SetVringNum(VringState { index: 0, num: 3 }),
            &[],
        );
        let (end, lines) = backend.join().expect("join");
        let e = end.expect_err("must fail");
        assert_eq!(
            (e.code, e.request),
            (SessionErrorCode::InvalidValue, Some(8))
        );
        assert_eq!(h.join().expect("join").seen, vec![MAP_SEEN, UNMAP_SEEN]);
        assert_eq!(
            count(
                &lines,
                "venus_jig event=blob_release mapped=1 unmapped=1 memfds=1"
            ),
            1,
            "{lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("venus_jig event=session_error code=INVALID_VALUE request=8")
        );
        drop(fe);
    }

    /// GPU-6・REPAIR-5（#1645・D3）: channel が閉じていると片づけの `SHMEM_UNMAP` は失敗して打ち切られるが、
    /// セッションの結果は変わらず、片づけは `message_timeout` の範囲で終わる。
    #[test]
    fn f5_2b_4b_gpu6_session_end_with_closed_channel_keeps_result() {
        let (fe, chan, backend) = start("d3gone", T);
        let h = frontend_channel(chan, vec![0], true);
        let resp = post_all(
            &fe,
            0,
            &[ctx_create_req(1), create_blob(1, BLOB), map_blob(1, 0)],
        );
        assert_eq!(
            resp,
            vec![(OK_NODATA, 24), (OK_NODATA, 24), (OK_MAP_INFO, 32)]
        );
        // channel の相手が閉じるのを待ってから主ソケットを閉じる。
        let rec = h.join().expect("join");
        assert_eq!(rec.seen, vec![MAP_SEEN]);
        let started = Instant::now();
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert!(started.elapsed() < T * 2, "cleanup bounded");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        assert_eq!(
            count(
                &lines,
                "venus_jig event=blob_release mapped=1 unmapped=0 memfds=1"
            ),
            1,
            "{lines:?}"
        );
        let unmap_lines: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("cmd=SHMEM_UNMAP"))
            .collect();
        assert_eq!(unmap_lines.len(), 1, "{lines:?}");
        assert_eq!(
            unmap_lines[0].as_str(),
            "venus_jig event=backend_req cmd=SHMEM_UNMAP shmid=1 shm_offset=0 len=135168 result=err code=TRANSPORT"
        );
    }
}
