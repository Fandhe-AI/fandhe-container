//! SIGTERM 受信フラグの登録（`unsafe` 事前承認の範囲。TASK-115.5・#389。MAC-1・PLUG-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `main.rs` が接続前に [`install_sigterm_flag`] を 1 回呼び、得たフラグを
//! `frame_loop::serve_until` へ渡す。SIGTERM は core 以外（運用者・OS・launchd 等）から届く経路で、
//! フラグが立つとフレームループが次の受信境界で抜け、`stop_all` で起動中の VM を停止してから終了する。
//! core 自身の終了要求は SIGTERM を使わず接続切断（EOF）で伝わる（`ResidentPlugin::shutdown`）。
//!
//! 製品の依存に `libc` は入れず（dev-dependencies で照合にだけ使う。#1318）、`nix` は不採用（dependency-policy）で、std にシグナル API が無いため、
//! `crates/plugin/src/sys.rs` と同じ流儀で最小限の `extern "C"` 宣言を自前で持つ。`struct sigaction` は
//! OS・アーキテクチャでレイアウトが異なるため使わず、番号とハンドラのアドレスだけを取る `signal(3)`
//! （glibc・musl・macOS とも BSD セマンティクスで、ハンドラは解除されず再設定も不要）を使う。
//!
//! 自前宣言の正しさは dev-dependencies の `libc` との機械照合（コンパイル時 `const`）で守る
//! （#1318・#1845・MVM-4・REPAIR-12。`imp::libc_abi` と `libc_abi`。方式は `docs/design/ffi-libc-check.md`）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`install_sigterm_flag`] のみ。
//! - ハンドラは `static AtomicBool` への `store` だけを行う（async-signal-safe。確保・ロック・I/O をしない）。
//! - 登録するのは `SIGTERM` の番号を確認済みの組（Linux の x86_64 / aarch64・macOS）だけ。
//! - Linux の他アーキテクチャは番号が未確認のため登録を試みず、`UNIMPLEMENTED` を返す（呼び出し側は
//!   fail-closed で終了する。SIGTERM の既定動作で後始末を経ずに終了する状態では起動させない）。
//! - Linux 以外の非対応 OS（Windows・FreeBSD 等の他の unix）は何も登録せず、決して立たないフラグを `Ok` で
//!   返す（実装済みを装わない。REPAIR-3）。Windows には SIGTERM 経路が無い。他の unix では SIGTERM が
//!   既定動作のまま届き、後始末を経ずに即終了する。
//! - 返したフラグを立てるのはハンドラだけ、というのは呼び出し側の規約である。戻り値は
//!   `&'static AtomicBool` で `store` を呼べるため、型では強制していない。
//!
//! # 限界（残存リスク）
//! SIGKILL は捕捉できない。SIGTERM 送信側の猶予内に `stop_all`（最大 `SHUTDOWN_BUDGET` 4 秒）が終わらず
//! SIGKILL された場合、VM は残留しうる。SIGINT / SIGHUP は本モジュールの対象外（#389 の受入基準は SIGTERM のみ）。
//! 何も登録しない OS（契約の項を参照）では、SIGTERM は既定動作で即終了するか（他の unix）
//! そもそも届かず（Windows）、VM は停止されない。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::PluginError;

/// SIGTERM 受信で立つフラグ。本モジュール内で立てるのはハンドラだけ。[`install_sigterm_flag`] が
/// `&'static AtomicBool` として外へ渡すため、呼び出し側が立てないことは規約であり型では強制していない。
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

// `SIGTERM` の番号を定義した組だけで有効にする。Linux の他アーキテクチャは [`install_sigterm_flag`] が
// 実行時に `UNIMPLEMENTED` で拒否する。`crates/plugin/src/sys.rs` の流儀に合わせた選択で、同ファイルは
// 未確認のアーキテクチャを `compile_error!` でなく実行時のエラー（`Unsupported`。fail-closed）で扱い、
// `compile_error!` は構造体レイアウトの取り違えが未定義動作になる箇所に限っている。番号とハンドラの
// アドレスしか渡さない `signal(3)` にその危険は無く、ビルドを拒否すると workspace 全体がそのターゲットで
// ビルドできなくなる。OS だけで分岐していた従来は Linux の他アーキテクチャで定数未定義のコンパイル
// エラーになっていた。ビルドは通すが起動は拒否するため、後始末なしで動く構成は増やさない。
// 対応済みの組と Linux 以外の OS の挙動は変えていない。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use std::sync::atomic::Ordering;

    use super::SIGTERM_RECEIVED;

    // SIGTERM は Linux（x86_64 / aarch64）・macOS とも 15 だが、アーキテクチャ差の流用を避けるため個別に定義する。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(target_os = "macos")]
    pub(super) const SIGTERM: i32 = 15;

    /// `signal(3)` の失敗値 `SIG_ERR`（`(sighandler_t)-1`）。
    const SIG_ERR: usize = usize::MAX;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `sighandler_t signal(int, sighandler_t)`。
        // 前提は、本モジュールが有効になる組（外側の cfg）で `sighandler_t`（関数ポインタ）と `usize` が
        // 同じ幅で、整数レジスタで同じように受け渡されること。ポインタ幅が 64 ビットであることには頼らない。
        // 幅は直下の const assert がコンパイル時に確かめる。
        fn signal(signum: i32, handler: usize) -> usize;
    }

    // 上の宣言の前提（関数ポインタと `usize` が同幅）をコンパイル時に確かめる。
    const _: () = assert!(size_of::<extern "C" fn(i32)>() == size_of::<usize>());

    /// SIGTERM ハンドラ。atomic store のみ（async-signal-safe）。
    extern "C" fn on_sigterm(_signum: i32) {
        SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
    }

    /// ハンドラを登録する。成功なら `true`。
    pub(super) fn install() -> bool {
        let handler: extern "C" fn(i32) = on_sigterm;
        // SAFETY: ハンドラは `'static` な関数で、単一の `static AtomicBool` 以外に触れない。
        // シグナルはどのスレッドにも配送され得るが、atomic store のみのため安全。BSD セマンティクスで
        // ハンドラは解除されないため、2 回目以降の SIGTERM もフラグを再度立てるだけでプロセスを殺さない。
        let prev = unsafe { signal(SIGTERM, handler as usize) };
        prev != SIG_ERR
    }

    /// 自前の FFI 宣言を dev-dependencies の `libc` とコンパイル時に照合する（#1845・MVM-4・REPAIR-12。
    /// 方式は `docs/design/ffi-libc-check.md`）。`const` の評価なので食い違えばビルドが落ちる。
    /// 関数は呼ばず型だけを比べる（`unsafe` は足さない）。
    ///
    /// 対象外: 構造体は無い（`struct sigaction` は使わない）。`install` は FFI でない安全なラッパー。
    /// 宣言側に gnu / musl の分岐は無く、`libc` 0.2.189 の値も arch ごとに env で同一のため `target_env` 分岐は不要。
    #[cfg(test)]
    mod libc_abi {
        // SIGTERM は宣言と同じ cfg の腕ごとに、同じ組の `libc` の値と比べる。
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);

        // `sighandler_t` は `libc` で `size_t`。自前は `usize`（`as` で合わせず値と幅を直接比べる）。
        const _: () = assert!(super::SIG_ERR == libc::SIG_ERR);
        const _: () = assert!(size_of::<usize>() == size_of::<libc::sighandler_t>());

        // `signal` の型（引数・戻り値）を `libc` の宣言と同一視できるか。
        const _: unsafe extern "C" fn(libc::c_int, libc::sighandler_t) -> libc::sighandler_t =
            super::signal;
        const _: unsafe extern "C" fn(libc::c_int, libc::sighandler_t) -> libc::sighandler_t =
            libc::signal;

        // `libc` に型付きのハンドラ型は無い（`sighandler_t` は整数）ため、引数型だけを確かめる。
        const _: extern "C" fn(libc::c_int) = super::on_sigterm;
    }
}

/// SIGTERM 受信フラグを登録して返す。接続前に 1 回だけ呼ぶ。
///
/// 登録失敗は `INTERNAL`、Linux の未確認アーキテクチャは `UNIMPLEMENTED`（どちらも固定文言）。
/// VM を安全に止められない状態で動かさないため、呼び出し側は fail-closed で終了する。
/// Linux 以外の非対応 OS（Windows・他の unix）では登録せず、決して立たないフラグを `Ok` で返す
/// （SIGTERM での後始末は効かない。モジュール doc「契約」参照。REPAIR-3）。
pub fn install_sigterm_flag() -> Result<&'static AtomicBool, PluginError> {
    register()?;
    Ok(&SIGTERM_RECEIVED)
}

/// 対応済みの組: ハンドラを登録する。失敗は `INTERNAL`。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn register() -> Result<(), PluginError> {
    if imp::install() {
        Ok(())
    } else {
        Err(PluginError::new(
            fandhe_container_plugin::PluginErrorCode::Internal,
            "failed to install SIGTERM handler",
        ))
    }
}

/// Linux の未確認アーキテクチャ: `SIGTERM` の番号を持たないため登録を試みず拒否する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn register() -> Result<(), PluginError> {
    Err(PluginError::new(
        fandhe_container_plugin::PluginErrorCode::Unimplemented,
        "SIGTERM handler is not supported on this architecture",
    ))
}

/// Linux 以外の非対応 OS: 何も登録しない（決して立たないフラグを返す側。REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register() -> Result<(), PluginError> {
    Ok(())
}

/// 記録ファイル読み込み用の open（TASK-177.x の venus 再生器。REPAIR-5）。
///
/// unix では `O_NOFOLLOW | O_NONBLOCK` を付けて開く。検査から open までの間に FIFO へ差し替えられても
/// open が書き手待ちでブロックせず、symlink へ差し替えられても末尾の symlink を辿らず `ELOOP` で失敗する。
/// 呼び出し側は開いた fd の種別を `metadata` で必ず再検証する。`std::os::unix::fs::OpenOptionsExt` の
/// `custom_flags` だけで済むため `unsafe` は使わない。フラグ値は OS・アーキテクチャで異なるため
/// `cfg` で分け、値を確認済みの組（Linux x86_64 / aarch64・macOS）以外では通常の open にフォールバックする
/// （その場合の保護は呼び出し側の事前検査と事後検証のみで、TOCTOU は塞がらない）。
///
/// パスは正規化せずそのまま `open(2)` へ渡す。通常ファイルに末尾 `/` を付けるとカーネルが `ENOTDIR` で拒否する
/// （試験 `sec1_3866_open_nofollow_nonblock_rejects_trailing_slash_on_regular_file`）。一方 Linux では、
/// 末尾 `/` があると `O_NOFOLLOW` があっても最終要素のディレクトリへの symlink を辿るため、
/// 「ディレクトリへの symlink + 末尾 `/`」は open が成功しうる（`plugin-microvm` の `open_regular_nofollow` は
/// components の正規化で `/` を落とし `ELOOP` で拒否するので、ここは既知の差）。挙動は変えない: 呼び出し元の
/// `gpu::venus::replay::player` が先に `symlink_metadata` で通常ファイルかを確かめ（`lstat("link/")` は辿った先の
/// ディレクトリを返すので拒否される）、open の後にも `metadata` で再検証するため、通常ファイル以外は読まない
/// （SEC-1・#3866）。
pub fn open_nofollow_nonblock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(flags) = NOFOLLOW_NONBLOCK_FLAGS {
            opts.custom_flags(flags);
        }
    }
    opts.open(path)
}

/// `O_NOFOLLOW | O_NONBLOCK`（Linux x86_64: 0x20000 | 0x800）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NOFOLLOW_NONBLOCK_FLAGS: Option<i32> = Some(0x20000 | 0x800);
/// `O_NOFOLLOW | O_NONBLOCK`（Linux aarch64: 0x8000 | 0x800）。
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const NOFOLLOW_NONBLOCK_FLAGS: Option<i32> = Some(0x8000 | 0x800);
/// `O_NOFOLLOW | O_NONBLOCK`（macOS: 0x100 | 0x4）。
#[cfg(target_os = "macos")]
const NOFOLLOW_NONBLOCK_FLAGS: Option<i32> = Some(0x100 | 0x4);
/// フラグ値が未確認の unix。通常の open にフォールバックする。
#[cfg(all(
    unix,
    not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))
))]
const NOFOLLOW_NONBLOCK_FLAGS: Option<i32> = None;

/// `O_NOFOLLOW` で symlink を開こうとしたときの errno（`ELOOP`。Linux 40・macOS 62）。
#[cfg(target_os = "linux")]
pub const ELOOP: i32 = 40;
#[cfg(not(target_os = "linux"))]
pub const ELOOP: i32 = 62;

/// 直下の自前定数を `libc` と照合する（#1845・MVM-4・REPAIR-12）。`imp::libc_abi` が SIGTERM・`signal` を担当する。
///
/// 対象外（理由）:
/// - `NOFOLLOW_NONBLOCK_FLAGS = None` の腕: 値を持たず、通常の open へフォールバックする。
/// - `ELOOP` の Windows 腕: dev-dependency の `libc` は `cfg(unix)` で無く、Windows の `raw_os_error` は errno でない。
/// - `open_nofollow_nonblock`・`install_sigterm_flag`・`register`・`SIGTERM_RECEIVED`: FFI でない安全なラッパー・状態。
///
/// 既知の潜在的な食い違い（評価対象外のターゲット。CI は Linux x86_64 / aarch64・macOS のみ。
/// `libc` 0.2.189 の `src/unix/` を出典）: `ELOOP` の Linux 腕は全アーキテクチャで 40 だが、Linux の
/// mips / mips64 は 90、sparc64 は 62。非 Linux 腕の 62 も illumos / solaris 等は 90。宣言の修正は別 issue。
#[cfg(all(test, unix))]
mod libc_abi {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const _: () = assert!(matches!(
        super::NOFOLLOW_NONBLOCK_FLAGS,
        Some(f) if f == libc::O_NOFOLLOW | libc::O_NONBLOCK
    ));
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const _: () = assert!(matches!(
        super::NOFOLLOW_NONBLOCK_FLAGS,
        Some(f) if f == libc::O_NOFOLLOW | libc::O_NONBLOCK
    ));
    #[cfg(target_os = "macos")]
    const _: () = assert!(matches!(
        super::NOFOLLOW_NONBLOCK_FLAGS,
        Some(f) if f == libc::O_NOFOLLOW | libc::O_NONBLOCK
    ));

    // ELOOP は宣言の 2 腕と `libc` の入る cfg（unix）の積で照合する。CI で評価される非 Linux は macOS のみ。
    #[cfg(target_os = "linux")]
    const _: () = assert!(super::ELOOP == libc::ELOOP);
    #[cfg(all(unix, not(target_os = "linux")))]
    const _: () = assert!(super::ELOOP == libc::ELOOP);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    /// 子プロセス（自己再実行）の役を示す環境変数。値 `1` のときだけ、下の試験が登録と送信を行う。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    const SIGTERM_CHILD_ENV: &str = "FANDHE_CONTAINER_PLUGIN_MACOS_SIGTERM_CHILD";

    /// TASK-115.5・MAC-1・PLUG-1・REPAIR-5・REPAIR-12・#3866: 登録に成功してフラグが立つこと、
    /// 子は落ちず 2 回目でも立ったままであること。送信は `kill` コマンドで行い、`unsafe` の面を `signal` 1 箇所に保つ。
    ///
    /// `install_sigterm_flag` はプロセス全体の SIGTERM の disposition を変え解除しないため、試験バイナリ自身で
    /// 呼ぶと同じバイナリの他の試験や、外からの SIGTERM による停止（CI の watchdog・ステップ期限）が効かなくなる。
    /// そこで自己再実行した子プロセスの中でだけ登録と送信を行い、親は登録せず子の固定行と `1 passed` を
    /// 期限つきで照合する（子のハングは kill して失敗にする。REPAIR-5）。plugin-microvm の同名方式（#3842）と同じ。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn task115_5_mac1_install_succeeds_and_flag_starts_false() {
        use std::time::{Duration, Instant};

        if std::env::var(SIGTERM_CHILD_ENV).as_deref() == Ok("1") {
            fn send_term() {
                let status = std::process::Command::new("kill")
                    .args(["-TERM", &std::process::id().to_string()])
                    .status()
                    .expect("spawn kill");
                assert!(status.success(), "kill -TERM failed: {status:?}");
            }

            assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
            let flag = install_sigterm_flag().expect("install");
            assert!(std::ptr::eq(flag, &SIGTERM_RECEIVED));
            assert!(!flag.load(Ordering::SeqCst));

            send_term();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "SIGTERM flag not set within 5s of kill -TERM"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            println!("sigterm-child: flag_set=1");

            // BSD セマンティクスでハンドラが残ること: 2 回目でもプロセスが生きていて、フラグは立ったまま。
            send_term();
            std::thread::sleep(Duration::from_millis(50));
            assert!(flag.load(Ordering::SeqCst));
            println!("sigterm-child: survived_second=1");
            return;
        }

        // 親: 試験バイナリ本体は登録しない（SIGTERM の disposition を変えない）。初期値は偽。
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
        // `module_path!()` は `<crate>::sys::tests`。libtest の試験名は crate 名を含まない。
        let module = module_path!();
        let name = format!(
            "{}::task115_5_mac1_install_succeeds_and_flag_starts_false",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", &name, "--test-threads=1", "--nocapture"])
            .env(SIGTERM_CHILD_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn child");
        // 出力は別スレッドで読み切る（パイプ詰まりで子が止まるのを避ける）。
        let mut out = child.stdout.take().expect("stdout");
        let mut err = child.stderr.take().expect("stderr");
        let t_out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut out, &mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut err, &mut s);
            s
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sigterm child did not finish within 30s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = t_out.join().expect("join stdout");
        let stderr = t_err.join().expect("join stderr");
        assert!(
            status.success(),
            "child failed: {status:?}\n{stdout}\n{stderr}"
        );
        for want in [
            "sigterm-child: flag_set=1",
            "sigterm-child: survived_second=1",
        ] {
            let n = stdout.lines().filter(|l| l.contains(want)).count();
            assert_eq!(n, 1, "expected exactly one `{want}`:\n{stdout}");
        }
        // 名前の誤りで 0 件実行になった場合は固定行が欠けて上で失敗する。要約行も具体値で確認する。
        assert!(
            stdout.lines().any(|l| l.contains("1 passed")),
            "libtest summary missing:\n{stdout}"
        );
    }

    /// TASK-115.5・MAC-1・REPAIR-3: Linux 以外の非対応 OS（Windows・他の unix）は何も登録せず、
    /// 決して立たないフラグを `Ok` で返す。登録しないのでプロセス内で実行してよい。
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn task115_5_mac1_install_succeeds_and_flag_starts_false() {
        let flag = install_sigterm_flag().expect("install");
        assert!(std::ptr::eq(flag, &SIGTERM_RECEIVED));
        assert!(!flag.load(Ordering::SeqCst));
    }

    /// TASK-115.5・MAC-1・REPAIR-3: Linux の未確認アーキテクチャは登録せず `UNIMPLEMENTED` で拒否する（fail-closed）。
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    #[test]
    fn task115_5_mac1_unverified_linux_arch_is_rejected() {
        let err = install_sigterm_flag().expect_err("must reject");
        assert_eq!(
            err.code(),
            fandhe_container_plugin::PluginErrorCode::Unimplemented
        );
        assert_eq!(
            err.message(),
            "SIGTERM handler is not supported on this architecture"
        );
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
    }

    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn task115_5_mac1_sigterm_number_is_15() {
        assert_eq!(imp::SIGTERM, 15);
    }

    /// 試験専用の一時ディレクトリ（`Drop` で消す）。
    #[cfg(unix)]
    struct TmpDir(std::path::PathBuf);

    #[cfg(unix)]
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("fandhe-plugin-macos-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("create tmp dir");
            Self(p)
        }
    }

    #[cfg(unix)]
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// SEC-1・#3866: 通常ファイルに末尾 `/` を付けたパスは、正規化せず `open(2)` へ渡すためカーネルが
    /// `ENOTDIR` で拒否する。末尾 `/` なしでは同じファイルが読める（陽性対照）。
    #[cfg(unix)]
    #[test]
    fn sec1_3866_open_nofollow_nonblock_rejects_trailing_slash_on_regular_file() {
        use std::io::Read;
        let dir = TmpDir::new("trailing-slash");
        let file = dir.0.join("k");
        std::fs::write(&file, b"payload").expect("write");

        let mut s = String::new();
        open_nofollow_nonblock(&file)
            .expect("open without slash")
            .read_to_string(&mut s)
            .expect("read");
        assert_eq!(s, "payload");

        let with_slash = std::path::PathBuf::from(format!("{}/", file.display()));
        let err = open_nofollow_nonblock(&with_slash).expect_err("trailing slash must be rejected");
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
    }
}
