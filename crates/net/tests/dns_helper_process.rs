//! DNS ヘルパーのプロセス起動・準備完了待ち・UDP 往復・回収の結合試験（非特権・3 OS。
//! NET-5・TASK-141.1・#321・MS-8）。
//!
//! 自身の実行ファイルをヘルパーとして再実行する（`--listen` つきで起動されたらヘルパー本体 `run_dns_helper_main`
//! として振る舞う）ため `harness = false`。ループバック `127.0.0.1:0` のみを使い root を要さない。
//! 待ちはすべて期限つき（REPAIR-5）。

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use fandhe_container_net::dns_helper::{
    DnsListenAddr, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT, run_dns_helper_main,
    spawn_dns_helper,
};
use fandhe_container_net::error::NetErrorCode;

fn query(id: u16, flags: u16, qd: u16) -> Vec<u8> {
    let mut v = id.to_be_bytes().to_vec();
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&qd.to_be_bytes());
    v.extend_from_slice(&[0; 6]);
    v
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--listen") {
        return run_dns_helper_main(args.into_iter().skip(1));
    }
    let exe = std::env::current_exe().expect("current_exe");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen addr");

    // 起動 -> READY 受理 -> 不正は無応答・正常は応答 -> 回収。
    let helper = spawn_dns_helper(&exe, listen, READY_TIMEOUT_DEFAULT).expect("spawn helper");
    let target = helper.listen_addr();
    assert_ne!(target.port(), 0);
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut buf = [0u8; 600];
    for bad in [vec![0u8; 5], query(1, 0x8100, 1), query(1, 0x0100, 0)] {
        client.send_to(&bad, target).expect("send");
        assert!(client.recv_from(&mut buf).is_err(), "must not be answered");
    }
    let mut ok = false;
    for _ in 0..20 {
        client
            .send_to(&query(0xABCD, 0x0100, 1), target)
            .expect("send");
        if let Ok((n, _)) = client.recv_from(&mut buf) {
            assert_eq!(
                buf.get(..n),
                Some(&[0xAB, 0xCD, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0][..])
            );
            ok = true;
            break;
        }
    }
    assert!(ok, "helper did not answer a valid query");
    helper.stop(REAP_TIMEOUT_DEFAULT).expect("reap helper");

    // 存在しない絶対パスは spawn 失敗。
    let missing = std::env::temp_dir().join("fandhe-dns-helper-does-not-exist");
    let e = spawn_dns_helper(&missing, listen, READY_TIMEOUT_DEFAULT).expect_err("missing");
    assert_eq!(e.code(), NetErrorCode::NotFound);

    // bind できないアドレス（使用中 port）ではヘルパーが READY 前に終了し FailedPrecondition。
    let busy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("busy socket");
    let port = busy.local_addr().expect("addr").port();
    let busy_listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, port).expect("busy addr");
    let e = spawn_dns_helper(&exe, busy_listen, READY_TIMEOUT_DEFAULT).expect_err("busy");
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    println!("dns_helper_process: ok");
    std::process::ExitCode::SUCCESS
}
