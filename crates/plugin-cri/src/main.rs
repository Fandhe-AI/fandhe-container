//! `fandhe-container-plugin-cri` バイナリの入口（TASK-114.1・#457、TASK-114.3.1・#849。PLUG-1・CRI-2）。
//!
//! 呼び出し元: 将来は core 側 plugin proxy（#1869 の設計。承認待ち）が検証済みの起動対象として spawn する。
//! 役割は起動引数の解析（`startup::parse_args`）を終了コードと stderr の 1 行へ写すことと、`--socket <PATH>` で
//! 受けた UDS 上で `CriRuntimeService` と `CriImageService` をサーブすること（`server::serve`。unix のみ）。
//! 実装の組み立ては `adapter::CriPluginBackends::production`（失敗したら fail-closed で起動しない）。
//! 既定の socket パスは未定義のため、引数なしの起動は `UNIMPLEMENTED` で失敗させる（REPAIR-3）。
//! Linux では peer 認証の拒否と、create の `mounts[].destination` の拒否（#2594）を core の監査ログ（`@audit.log`）へ永続化する（#2484）。記録経路を作れなければ起動しない。
//! 起動時に `<状態ルート>/.cri/@instance.lock` を期限つきで排他ロックし、取れなければ `TIMEOUT` の固定文言で起動しない（二重起動の拒否。#2931・CRI-2・CORE-1）。
//! 次に `<状態ルート>/.cri/images` の残り pull を回収してから受け付ける（`recover_stale_image_pulls`。失敗・期限超過は起動しない。#2819・OCI-7）。
//! 続けて記録ストア（`<状態ルート>/.cri/records`）を開いて `CriRuntimeService` へ注入し、受付の前に 1 回だけ記録を再採用する
//! （sandbox → コンテナと core の照合 → 作成途中の取り残しの解放 → 孤児 bundle の回収。`CriPluginBackends::readopt_records`。#2938・CRI-1・CRI-2・CORE-1）。
//! 列挙の失敗・件数または保持量の上限超過・期限切れは `error: <CODE>: failed to readopt cri records` で起動しない。壊れた記録は消さず数えるだけで起動は止めない。
//! 何かを再採用・回収したときだけ、固定語彙の要約 1 行を stderr へ出す（初回起動は静か）。
//! SIGTERM・SIGINT で正常停止する（#3226・CRI-1・REPAIR-5。`sys` の自前の `signal(3)` 宣言で受ける）。受けたら新しい接続と RPC を受け付けず、
//! 実行中の RPC を `PLUGIN_SHUTDOWN_GRACE`（10 秒）まで待ち、超えたら接続を強制的に閉じて `TIMEOUT` で終える（結果不明の記録は再起動時に再採用が扱う）。
//! socket は listener の drop で削除し、ロックは終了時の fd の close で外れる（ロックファイルは消さない）。
//! 起動段（ロック取得・pull の回収・記録の再採用）は段の境界でだけ受信を見る（段の途中では各段の予算まで待つ）。
//! 正常停止は stderr に固定の 1 行 `cri plugin shutdown: signal=<SIGTERM|SIGINT> stage=<startup|serve>` を出し、終了コード 0。
//! 監査 relay の helper は SIGTERM・SIGINT を無視し、本体の終了（EOF）で終わる（グループ・cgroup 宛ての停止で先に死なず、ドレイン中の拒否も
//! `@audit.log` に届く。#3300）。fork した子へのハンドラの継承は `sys` の doc「fork した子への継承」。SIGHUP は対象外。
//!
//! 終了コード: 0 = `--help` と正常停止、2 = `InvalidArgument`（plugin-macos / plugin-mcp と同じ値）、1 = それ以外の失敗
//! （未実装・起動失敗・serve の失敗）。
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（固定文言のみ。引数の値は含めない。REPAIR-4）。
//! stdout に書くのは `--help` の usage だけ。起動完了の通知行は出さない（呼び出し側は socket の出現と接続の成否で判定する）。

use std::process::ExitCode;

use fandhe_container_plugin::{PluginError, PluginErrorCode};
use fandhe_container_plugin_cri::startup::{self, Invocation};
#[cfg(unix)]
use fandhe_container_plugin_cri::{
    shutdown::{self, ShutdownStage},
    sys,
};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// 未実装・その他の起動失敗の終了コード。
const EXIT_FAILURE: u8 = 1;

fn fail(code: PluginErrorCode, message: &str) -> ExitCode {
    eprintln!("error: {}: {}", code.as_str(), message);
    if code == PluginErrorCode::InvalidArgument {
        ExitCode::from(EXIT_INVALID_ARGUMENT)
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn fail_err(e: &PluginError) -> ExitCode {
    fail(e.code(), e.message())
}

/// serve 後（停止猶予超過を含む）の失敗行を `LineSink` へ積み、期限つきで書き終えるのを待って終了コード 1 を返す。
/// stderr のパイプが満杯でも同期の `eprintln!` のように無期限に待たない（REPAIR-5）。
#[cfg(unix)]
fn fail_err_bounded(e: &PluginError) -> ExitCode {
    let sink = fandhe_container_plugin_cri::telemetry::stderr_sink();
    let _ = sink.submit(format!("error: {}: {}", e.code().as_str(), e.message()));
    sink.wait_idle(shutdown::FINAL_FLUSH_WAIT);
    if e.code() == PluginErrorCode::InvalidArgument {
        ExitCode::from(EXIT_INVALID_ARGUMENT)
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

/// 正常停止の完了を示す固定の 1 行を stderr へ出し、期限つきで書き終えるのを待つ（REPAIR-4・REPAIR-5）。
#[cfg(unix)]
fn report_shutdown(signal: sys::ShutdownSignal, stage: ShutdownStage) {
    let sink = fandhe_container_plugin_cri::telemetry::stderr_sink();
    let _ = sink.submit(shutdown::shutdown_line(signal, stage));
    sink.wait_idle(shutdown::FINAL_FLUSH_WAIT);
}

/// 起動段の境界で停止シグナルを見る。受けていれば bind せずに正常停止の 1 行を出して終了コード 0 を返す。
#[cfg(unix)]
fn stop_at_startup_boundary() -> Option<ExitCode> {
    let signal = sys::received()?;
    report_shutdown(signal, ShutdownStage::Startup);
    Some(ExitCode::SUCCESS)
}

/// `Serve` の本体。UDS を持たない OS では未実装を返す（WIN-1）。
#[cfg(unix)]
fn serve(socket: &std::path::Path) -> ExitCode {
    use fandhe_container_plugin::grpc::GrpcServerConfig;
    use fandhe_container_plugin_cri::adapter::{
        self, CriPluginBackends, PLUGIN_REQUEST_TIMEOUT, StartupPullRecovery,
    };
    use fandhe_container_plugin_cri::{server, telemetry};

    // 監査の記録経路（Linux）は、スレッド・listener・ランタイムを作る前に用意する（SEC-4・PLUG-12・#2484）。
    // `ControlAuditRelay::spawn` は単一スレッドのときだけ成功し、helper は fd 3 以上を閉じるため。
    // 作れなければ「記録されないまま受け付ける」状態を避けて起動しない（fail-closed。supervisor の #2027 と同じ）。
    #[cfg(target_os = "linux")]
    let audit_sink = match fandhe_container_plugin_cri::audit_relay::open_audit_relay_in(None) {
        Ok(relay) => relay as std::sync::Arc<dyn fandhe_container_core::audit_log::AuditSink>,
        Err(e) => {
            let code = e.code().as_str();
            eprintln!("error: {code}: failed to open the audit log");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    // 停止シグナルの受信記録は relay の fork の後、受付の前に登録する（#3226・CRI-1）。helper は fork の直後に自分で
    // SIGTERM・SIGINT を無視にしている（#3300）ので、登録の順序には依らない。exec しない fork の子へのハンドラの継承は
    // `sys` の doc「fork した子への継承」と結合試験 `shutdown_audit_helper` が固定する。
    // 登録できなければ、後始末を経ずに死ぬ状態で動かさないため起動しない（fail-closed）。
    if let Err(e) = sys::install_shutdown_signals() {
        return fail(e.code(), e.message());
    }
    // create の `mounts[].destination` 拒否も同じ relay で永続化する（SEC-4・OCI-4・#2594）。プロセスは常に複数スレッドで
    // `FileAuditSink` を直接使えないため、`PeerAuditForwarder` と共有する。非 Linux は記録先が無く記録しない。
    #[cfg(target_os = "linux")]
    let backends =
        CriPluginBackends::production_with_audit_sink(std::sync::Arc::clone(&audit_sink));
    #[cfg(not(target_os = "linux"))]
    let backends = CriPluginBackends::production();
    let backends = match backends {
        Ok(b) => b,
        // インスタンスロックは `production*` が回収記録の読み込みより前に取り、`backends` の生存の間持つ（CRI-2・CORE-1・#2931）。
        Err(e)
            if e.code() == fandhe_container_core::traits::ErrorCode::Timeout
                && e.message()
                    == fandhe_container_plugin_cri::instance_lock::MSG_INSTANCE_LOCK_BUSY =>
        {
            return fail(
                PluginErrorCode::Timeout,
                fandhe_container_plugin_cri::instance_lock::MSG_INSTANCE_LOCK_BUSY,
            );
        }
        Err(e) => {
            // 状態ルートが解決できない等は fail-closed。メッセージは固定文言のコードだけ写す。
            eprintln!(
                "error: {}: failed to open the state store",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    if let Some(code) = stop_at_startup_boundary() {
        return code;
    }
    let recorder = std::sync::Arc::clone(backends.op_recorder());
    let oci_recorder = std::sync::Arc::clone(backends.oci_op_recorder());
    let sweep_store = std::sync::Arc::clone(backends.state());
    let sweep_recorder = std::sync::Arc::clone(&recorder);
    // bundle の供給は fail-closed。置き場を用意できなければ（fixed 文言のみ出して）起動しない。
    let bundles = match backends.production_bundle_provider() {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "error: {}: failed to prepare the bundle store",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    // 記録ストア（`<状態ルート>/.cri/records`）。インスタンスロックの取得後・受付の前に開く（CRI-1・CRI-2・#2938）。
    let records = match backends.production_record_store() {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "error: {}: failed to prepare the record store",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    // ImageService（PullImage と create のタグ解決で同じ在庫・キャッシュ設定を共有。#2592）。fail-closed:
    // レジストリクライアントを作れなければ起動しない（固定文言のコードだけ出す）。
    let images = match backends.image_service() {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "error: {}: failed to prepare the image service",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    // 前回までに残った pull のステージングとリースを、受け付けの前に 1 回回収する（OCI-7・OCI-1・#2819）。
    // 生存判定は `@pull.lock` の OS ロックで、生きている別プロセスの pull は残す。fail-closed: 在庫の root を
    // 信頼できない・排他を取れない・期限（REPAIR-5）を超えた場合は起動しない（取り残した worker が `@lock` を握ったまま
    // 受け付けると PullImage が全て Timeout になるため）。一部の削除失敗は余分に残す側（次回の起動で再試行）なので続行する。
    match backends.recover_stale_image_pulls(adapter::STARTUP_PULL_RECOVERY_BUDGET) {
        StartupPullRecovery::Completed(counts) => {
            // 何も無かった（初回起動・空の置き場）ときは出さない。起動の失敗時の stderr を静かに保つ。
            if counts != Default::default() {
                let _ = telemetry::stderr_sink().submit(counts.summary_line());
            }
        }
        StartupPullRecovery::Failed(code) => {
            eprintln!("error: {code}: failed to recover stale image pulls");
            return ExitCode::from(EXIT_FAILURE);
        }
        StartupPullRecovery::TimedOut | StartupPullRecovery::SpawnFailed | _ => {
            return fail(
                PluginErrorCode::Timeout,
                "failed to recover stale image pulls in time",
            );
        }
    }
    if let Some(code) = stop_at_startup_boundary() {
        return code;
    }
    // 記録ストアを注入した CRI サービスを組み、受付の前に 1 回だけ記録を再採用する（CRI-1・CRI-2・CORE-1・#2938）。
    // 列挙の失敗・上限超過・期限切れは fail-closed で起動しない（壊れた記録は数えるだけで止めない）。
    let svc = backends.runtime_service_with_record_store(
        std::sync::Arc::clone(&bundles)
            as std::sync::Arc<dyn fandhe_container_cri::adapter::BundleProvider>,
        std::sync::Arc::clone(&records)
            as std::sync::Arc<dyn fandhe_container_cri::runtime_service::RecordStore>,
    );
    match backends.readopt_records(
        &svc,
        &bundles,
        &*records,
        adapter::STARTUP_RECORD_READOPTION_BUDGET,
    ) {
        Ok(report) => {
            // 何も無かった（初回起動・空の置き場）ときは出さない。起動の失敗時の stderr を静かに保つ。
            if !report.is_empty() {
                let _ = telemetry::stderr_sink().submit(report.summary_line());
            }
        }
        Err(e) => {
            eprintln!(
                "error: {}: failed to readopt cri records",
                e.code().as_str()
            );
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    if let Some(code) = stop_at_startup_boundary() {
        return code;
    }
    // 1 リクエストの待ち上限は PullImage・StartContainer が収まる値に引き上げる（既定 10 秒では途中で切れる。REPAIR-5）。
    // 停止シグナルを受けてからの猶予は `PLUGIN_SHUTDOWN_GRACE`（超えたら接続を強制的に閉じる。REPAIR-5・#3226）。
    let grpc_config = match GrpcServerConfig::new()
        .with_request_timeout(PLUGIN_REQUEST_TIMEOUT)
        .and_then(|c| c.with_shutdown_grace(adapter::PLUGIN_SHUTDOWN_GRACE))
    {
        Ok(c) => c,
        Err(e) => return fail_err(&e),
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return fail(PluginErrorCode::Internal, "failed to start the runtime"),
    };
    // 配送 thread を作れなければ listener の bind 前に起動を中止する（SEC-4・PLUG-12・#2484）。
    #[cfg(target_os = "linux")]
    let audit = match telemetry::PeerAuditForwarder::spawn(
        audit_sink,
        telemetry::PEER_AUDIT_QUEUE_CAPACITY,
        telemetry::stderr_sink().clone(),
    ) {
        Ok(f) => Some(std::sync::Arc::new(f)),
        Err(_) => {
            // code は PluginErrorCode のトークンに揃える（`error: <CODE>: <message>` の契約）。
            return fail(
                PluginErrorCode::Unavailable,
                "audit delivery unavailable: failed to start the audit thread",
            );
        }
    };
    // 非 Linux は永続化経路が未実装（#2430 の判断待ち。REPAIR-3）。拒否は stderr にだけ残る。
    #[cfg(not(target_os = "linux"))]
    let audit = None;
    let result = rt.block_on(async {
        // 前回までに残ったコンテナログを 1 回だけ回収する（サーブの開始は待たせない。監査 relay は作成済みで、単一スレッド前提を壊さない。#2760）。
        drop(tokio::task::spawn_blocking(move || {
            if let Some(report) = adapter::sweep_leftover_container_logs(
                &sweep_store,
                &sweep_recorder,
                adapter::STARTUP_LOG_SWEEP_BUDGET,
            ) {
                // 走査に何も無かった（空の状態ルート等）ときは出さない。起動の失敗時の stderr を静かに保つ。
                if report != Default::default() {
                    let _ = telemetry::stderr_sink().submit(adapter::sweep_summary_line(&report));
                }
            }
        }));
        // 操作の件数・レイテンシを定期的に構造化ログとして stderr へ出す（REPAIR-4）。
        let stats = tokio::spawn(telemetry::op_stats_export_loop_many(
            vec![recorder, oci_recorder],
            telemetry::OP_STATS_EXPORT_INTERVAL,
        ));
        let r = server::serve_with_audit(
            socket,
            svc,
            Some(images),
            &grpc_config,
            audit,
            shutdown::wait_for_signal(),
        )
        .await;
        stats.abort();
        r
    });
    // `Runtime` の暗黙の drop は `spawn_blocking` のタスクの完了を無期限に待つため、期限つきで置き去りにする（REPAIR-5）。
    // 置き去りにしたタスクの結果は不明のまま残り、再起動時に再採用・回収が扱う。
    rt.shutdown_timeout(shutdown::RUNTIME_SHUTDOWN_WAIT);
    // インスタンスロックは `backends` が持つ。`shutdown_timeout` は未完了の blocking worker を残して返るため、
    // ここで drop すると worker が状態を変えうる間に別インスタンスがロックを取り再採用・回収を始められる。
    // プロセス終了（fd の close）まで保持するため leak させる（CRI-2・CORE-1。終了行の書き出しの窓も覆う）。
    std::mem::forget(backends);
    std::mem::forget(bundles);
    std::mem::forget(records);
    match result {
        Ok(()) => match sys::received() {
            Some(signal) => {
                report_shutdown(signal, ShutdownStage::Serve);
                ExitCode::SUCCESS
            }
            // 受信なしで止まるのは想定外。成功を装わず失敗扱いにする。
            None => fail_err_bounded(&PluginError::new(
                PluginErrorCode::Internal,
                "server stopped unexpectedly",
            )),
        },
        // 猶予超過は `TIMEOUT`（接続を強制的に閉じた）。記録は結果不明のまま残る。
        // stderr が詰まっても終われるよう、書き出しは期限つきの `LineSink` 経由にする（REPAIR-5）。
        Err(e) => fail_err_bounded(&e),
    }
}

#[cfg(not(unix))]
fn serve(_socket: &std::path::Path) -> ExitCode {
    fail(
        PluginErrorCode::Unimplemented,
        "cri plugin server requires unix domain sockets on this platform",
    )
}

fn main() -> ExitCode {
    match startup::parse_args(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{}", startup::usage());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Serve { socket }) => serve(&socket),
        Ok(_) => {
            // `Run` と、将来足される値は成功扱いにしない。
            fail(
                PluginErrorCode::Unimplemented,
                startup::MSG_SOCKET_DEFAULT_UNDEFINED,
            )
        }
        Err(e) => fail_err(&e),
    }
}
