//! 実 Linux カーネル起動試験の共有補助（MVM-5・MVM-1・REPAIR-1・REPAIR-12・#3986）。
//!
//! `tests/kernel_boot.rs`（Linux・KVM。x86_64 と aarch64）と `tests/hvf_kernel_boot.rs`（macOS・HVF）が
//! `#[path = "support/guest_boot.rs"] mod guest_boot;` で取り込む。両方で同じ入力検査・ゲスト出力の照合を使うことで、
//! 検査の食い違い（片方だけ緩む・FIFO で無期限に止まる等）を防ぐ。ゲストの `/init` が出す固定文字列 `MARKER` の正本は
//! `scripts/build-microvm-test-initrd.sh` の `init_message`（`kernel_boot.rs` の単体試験で照合）。
//!
//! ここは試験専用の補助で、製品コードからは参照されない。ゲストの出力は非信頼入力として扱い、添字・`unwrap` を使わない。
//! 単体試験（`tests` モジュール）は KVM・HVF を使わず、取り込み側のどちらでも既定の `cargo test` で走る。
//! 未使用警告: 取り込み側が使わない項目が出ないよう、単体試験からすべての項目を参照する。

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// `/init` が出す固定文字列。x86_64・aarch64・macOS の試験が共有する（複製しない・REPAIR-1）。
pub const MARKER: &str = "fandhe-microvm-test: init ok v1";

/// `read_bounded` が開くときの `O_NONBLOCK`。値は OS で異なる: Linux は `0o4000`、macOS（`sys/fcntl.h`）は `0x0004`。
/// macOS で `0o4000` を渡すと `O_EXCL` 相当になり、FIFO の無期限待ちを防げない（REPAIR-5）。`libc` は本 crate の
/// 依存に無いので定数を持つ。
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(not(target_os = "macos"))]
const O_NONBLOCK: i32 = 0o4000;

/// 行単位の完全一致の件数（tty の ONLCR による `\r\n` を許容。部分一致・混入は数えない）。
pub fn count_marker_lines(output: &[u8], marker: &str) -> usize {
    output
        .split(|b| *b == b'\n')
        .filter(|line| line.strip_suffix(b"\r").unwrap_or(line) == marker.as_bytes())
        .count()
}

/// 非信頼のゲスト出力を、末尾 `n` バイトだけエスケープして診断に載せる（端末制御の注入を防ぐ）。
pub fn escape_tail(output: &[u8], n: usize) -> String {
    let start = output.len().saturating_sub(n);
    output
        .get(start..)
        .unwrap_or(&[])
        .escape_ascii()
        .to_string()
}

/// 上限つきでファイルを読む。空・上限超過・通常ファイルでないものは拒否する。
/// REPAIR-5: 書き手のいない FIFO で open が無期限に止まらないよう `O_NONBLOCK` で開く。通常ファイルには影響せず、
/// FIFO・デバイス等は通常ファイル検査で拒否する。
pub fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open file: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat file: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() == 0 || meta.len() > cap {
        return Err(format!("file size {} not in 1..={cap}", meta.len()));
    }
    let mut buf = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read file: {e}"))?;
    if buf.is_empty() || buf.len() as u64 > cap {
        return Err("file size changed while reading".into());
    }
    Ok(buf)
}

/// `FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS` の解釈（1..=600 秒。未設定は `default_secs`）。
pub fn parse_boot_timeout_or(raw: Option<&str>, default_secs: u64) -> Result<u64, String> {
    match raw {
        None => Ok(default_secs),
        Some(s) => match s.parse::<u64>() {
            Ok(n) if (1..=600).contains(&n) => Ok(n),
            _ => Err(
                "FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS must be an integer in 1..=600".into(),
            ),
        },
    }
}

/// `FANDHE_CONTAINER_MICROVM_CMDLINE` の検査（空でない印字可能 ASCII のみ。未設定は `default`）。
pub fn validate_cmdline_or(raw: Option<&str>, default: &str) -> Result<String, String> {
    let s = raw.unwrap_or(default);
    if s.is_empty() || s.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
        return Err("FANDHE_CONTAINER_MICROVM_CMDLINE must be non-empty printable ASCII".into());
    }
    Ok(s.to_owned())
}

/// 陽性・負の対照の両方に使う cmdline（arm64）。Linux の `panic=` は後勝ちなので末尾に `panic=0` を足し、利用者の
/// `panic=N` による init 起動失敗後の自動 reboot（SYSTEM_RESET → `GuestShutdown`）を陽性が受理する偽陽性を抑える。
/// x86_64 の試験は使わないが、単体試験が参照するので未使用警告にはならない。
pub fn force_panic_zero(base: &str) -> String {
    format!("{base} panic=0")
}

/// `uart_report_port` の行から読んだアドレス（Linux v6.12 `drivers/tty/serial/serial_core.c`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyAddress {
    /// `MMIO 0x<hex>`（`UPIO_MEM` 系）。
    Mmio(u64),
    /// `I/O 0x<hex>`（`UPIO_PORT`）。
    Io(u64),
}

/// `parse_tty_report` の結果。真偽値に潰さず、失敗の種類を診断に残す（MVM-1・REPAIR-12・#3958）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtyReport {
    /// `<tty> at ` を含む行が無い（`quiet`・`loglevel=` で KERN_INFO が抑止された場合も含む）。
    Missing,
    /// 該当行が 2 行以上ある（件数）。
    Multiple(usize),
    /// 該当行はあるが書式が想定と違う（理由）。
    Malformed(&'static str),
    /// 1 行だけあり、読めた。`irq` は Linux の virq であり GIC の INTID ではない。
    Found { address: TtyAddress, irq: u32 },
}

/// ゲストの出力から 8250 の登録行 `<dev>: ttyS0 at MMIO 0x9000000 (irq = N, base_baud = B) is a 16550A` を読む。
///
/// 書式は Linux v6.12 `uart_report_port` の `pr_info("%s%s%s at %s (irq = %d, base_baud = %d) is a %s\n", ...)`。
/// `irq = 0` は DT に `interrupts` が無い構成（ポーリング）で `8250_of.c` の `of_irq_get` が失敗したときに出る。
/// 非 0 の値は virq で INTID 33 とは一致しないため、呼び出し側は `== 33` ではなく `!= 0` で照合する。
/// `base_baud` 以降は UART モデルの autoconfig に依存するので読まない。
/// 出力はゲスト由来の非信頼入力なので、添字・`unwrap` を使わず、桁数に上限を置いて panic しない。
/// 呼び出し元: aarch64 の実機前提の陽性（`kernel_boot.rs` の `arm64`・`hvf_kernel_boot.rs`）と本ファイルの単体試験。
pub fn parse_tty_report(output: &[u8], tty: &str) -> TtyReport {
    let needle = format!("{tty} at ");
    let needle = needle.as_bytes();
    let mut lines: Vec<&[u8]> = Vec::new();
    for raw in output.split(|b| *b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        // 直前が英数字の出現（`xttyS0 at` 等）は別の名前なので数えない。
        let hit = line
            .windows(needle.len())
            .position(|w| w == needle)
            .filter(|pos| {
                pos.checked_sub(1)
                    .and_then(|p| line.get(p))
                    .is_none_or(|b| !b.is_ascii_alphanumeric())
            });
        if let Some(pos) = hit
            && let Some(rest) = line.get(pos + needle.len()..)
        {
            lines.push(rest);
        }
    }
    let rest = match lines.as_slice() {
        [] => return TtyReport::Missing,
        [one] => *one,
        many => return TtyReport::Multiple(many.len()),
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return TtyReport::Malformed("non-utf8 report line");
    };
    let (is_mmio, rest) = if let Some(r) = rest.strip_prefix("MMIO 0x") {
        (true, r)
    } else if let Some(r) = rest.strip_prefix("I/O 0x") {
        (false, r)
    } else {
        return TtyReport::Malformed("unknown address kind");
    };
    let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex_len == 0 || hex_len > 16 {
        return TtyReport::Malformed("address digits out of range");
    }
    let (Some(hex), Some(rest)) = (rest.get(..hex_len), rest.get(hex_len..)) else {
        return TtyReport::Malformed("address split");
    };
    let Ok(value) = u64::from_str_radix(hex, 16) else {
        return TtyReport::Malformed("address not a number");
    };
    let Some(rest) = rest.strip_prefix(" (irq = ") else {
        return TtyReport::Malformed("missing irq field");
    };
    let dec_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if dec_len == 0 || dec_len > 10 {
        return TtyReport::Malformed("irq digits out of range");
    }
    let (Some(dec), Some(rest)) = (rest.get(..dec_len), rest.get(dec_len..)) else {
        return TtyReport::Malformed("irq split");
    };
    let Ok(irq) = dec.parse::<u32>() else {
        return TtyReport::Malformed("irq overflow");
    };
    if !rest.starts_with(',') {
        return TtyReport::Malformed("irq not followed by comma");
    }
    let address = if is_mmio {
        TtyAddress::Mmio(value)
    } else {
        TtyAddress::Io(value)
    };
    TtyReport::Found { address, irq }
}

// --- serial-echo（#3987・MVM-5・MVM-1）: UART の送受信の照合に使う固定文字列と `/proc/interrupts` の解析 ---
// 正本は `scripts/build-microvm-test-initrd.sh` の `serial_*`（単体試験で行頭の名前を抜き出して照合する）。

/// 送信 FIFO（16 バイト）の 10 倍の行（改行は含まない。159 バイト）。THRE 割り込みで送信が進まないと完走しない。
pub const SERIAL_TX_LINE: &str = "fandhe-microvm-test: serial tx \
     0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
     0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// 送信の完走（tcdrain の復帰）の後にゲストが出す行。ホストはこれを見てから入力を押す。
pub const SERIAL_READY: &str = "fandhe-microvm-test: serial ready v1";
/// ゲストが読んだ入力の前に付ける接頭辞（末尾の空白 1 個を含む）。
pub const SERIAL_RX_PREFIX: &str = "fandhe-microvm-test: serial rx ";
/// 全往復と 2 回目の `/proc/interrupts` の出力が済んだ印。
pub const SERIAL_OK: &str = "fandhe-microvm-test: serial echo ok v1";
/// `ppoll`（5 秒）が入力無しで切れたときの行。
pub const SERIAL_RX_TIMEOUT: &str = "fandhe-microvm-test: serial rx timeout v1";
/// syscall の失敗の行。
pub const SERIAL_FAILED: &str = "fandhe-microvm-test: serial echo failed v1";
/// ゲストが入力を待って書き戻す往復の回数（機械語のループ回数に固定）。
pub const SERIAL_RX_ROUNDS: usize = 4;

/// `/proc/interrupts` の 1 行（名前が一致したもの）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqRow {
    /// CPU ごとの回数の合計。
    pub count: u64,
    /// コントローラ内の番号（GIC では INTID。SPI n は `n + 32`）。先頭の virq ではない。
    pub hwirq: u32,
    /// `Level`（偽なら `Edge`）。
    pub level: bool,
}

/// `/proc/interrupts` から、割り込みの名前が `name` の行を読む。
///
/// 期待する形は arm64 の `13:  123  GICv3  33 Level  ttyS0`（virq・CPU ごとの回数・コントローラ名・hwirq・
/// トリガ・名前。Linux の `kernel/irq/proc.c` の `show_interrupts` と `GENERIC_IRQ_SHOW_LEVEL` による。
/// 版を固定した一次情報での照合は未実施）。行頭が `<数字>:` で、最後のトークンが `name` の行だけを対象にし、
/// 8250 の登録行（`... ttyS0 at MMIO ...`）は拾わない。対象の行の形が崩れていれば `Err`（失敗の種類を潰さない）。
/// ゲスト出力は非信頼入力なので、添字・`unwrap` を使わず、件数・桁数に上限を置き、加算は checked にする。
pub fn parse_irq_rows(output: &[u8], name: &str) -> Result<Vec<IrqRow>, &'static str> {
    const MAX_ROWS: usize = 16;
    const MAX_TOKENS: usize = 4096;
    let mut rows = Vec::new();
    for raw in output.split(|b| *b == b'\n') {
        let Ok(line) = std::str::from_utf8(raw) else {
            continue;
        };
        if line.split_whitespace().next_back() != Some(name) {
            continue;
        }
        let token_count = line.split_whitespace().count();
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        let Some(virq) = first.strip_suffix(':') else {
            continue;
        };
        if virq.is_empty() || !virq.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if token_count > MAX_TOKENS {
            return Err("too many tokens in an interrupt row");
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some((_, rest)) = tokens.split_first() else {
            continue;
        };
        // 右から: 名前・トリガ・hwirq。残りは CPU ごとの回数（1 個以上）とコントローラ名（1 個以上）。
        let [middle @ .., hwirq, kind, _name] = rest else {
            return Err("interrupt row is too short");
        };
        let level = match *kind {
            "Level" => true,
            "Edge" => false,
            _ => return Err("unknown trigger kind"),
        };
        let hwirq: u32 = hwirq.parse().map_err(|_| "hwirq is not a number")?;
        let mut count: u64 = 0;
        let mut counted = 0usize;
        for t in middle {
            let Ok(n) = t.parse::<u64>() else { break };
            count = count.checked_add(n).ok_or("interrupt count overflow")?;
            counted += 1;
        }
        if counted == 0 || counted >= middle.len() {
            return Err("missing per-cpu counts or controller name");
        }
        if rows.len() >= MAX_ROWS {
            return Err("too many matching interrupt rows");
        }
        rows.push(IrqRow {
            count,
            hwirq,
            level,
        });
    }
    Ok(rows)
}

/// 2 CPU がオンラインになった行（Linux v6.12 `arch/arm64/kernel/smp.c` の `smp_cpus_done()`。arm64 固有）。行末一致。
pub const ARM64_SMP_TOTAL_LINE: &str = "SMP: Total of 2 processors activated.";
/// 2 CPU がオンラインになった汎用の行（Linux v6.12 `kernel/smp.c` の `smp_init()` の `pr_info`。x86_64 と arm64 で同じ書式。
/// `CONFIG_NUMA=n` で node は 1）。`CONFIG_PRINTK_TIME` の接頭辞（`[    0.1] `）を許すため、行末一致で数える。
pub const SMP_ONLINE_LINE: &str = "smp: Brought up 1 node, 2 CPUs";
/// AP（vCPU 1）が起きた行の目印。`secondary_start_kernel` の `"CPU%u: Booted secondary processor 0x%010lx [0x%08x]"` のうち
/// MPIDR（`MPIDR_HWID_BITMASK` 後の affinity）が FDT の `cpu@1` の reg（1）と一致した値を含む前半。後半（MIDR）はホスト依存のため見ない。
pub const AP_BOOTED_PREFIX: &str = "CPU1: Booted secondary processor 0x0000000001";

/// 行末が `suffix` で終わる行の件数（`\r` は除く。接頭辞の時刻表示を許し、行頭の混入は区別しない）。
/// x86_64 の SMP 照合（#3888）と arm64 の SMP 照合（KVM #3899・HVF #3998）が共有する（複製しない・REPAIR-1）。
pub fn count_lines_ending_with(output: &[u8], suffix: &str) -> usize {
    output
        .split(|b| *b == b'\n')
        .filter(|line| {
            line.strip_suffix(b"\r")
                .unwrap_or(line)
                .ends_with(suffix.as_bytes())
        })
        .count()
}

/// `needle` を含む行の件数（`\r` は除く。後ろにホスト依存の値が続く行用）。
pub fn count_lines_containing(output: &[u8], needle: &str) -> usize {
    output
        .split(|b| *b == b'\n')
        .filter(|line| {
            line.windows(needle.len().max(1))
                .any(|w| w == needle.as_bytes())
        })
        .count()
}

/// 利用者の cmdline が SMP を無効化する指定（`nosmp`・`maxcpus=`）を含めば、その理由を返す（2 CPU の照合が成り立たないため）。
pub fn smp_disabling_param(cmdline: &str) -> Option<&str> {
    cmdline
        .split_ascii_whitespace()
        .find(|w| *w == "nosmp" || w.starts_with("maxcpus="))
}

/// 共有補助の単体試験（KVM・HVF 不要。取り込み側のどちらでも既定で走る。MVM-1・MVM-5・REPAIR-12）。
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const LINE: &str =
        "9000000.serial: ttyS0 at MMIO 0x9000000 (irq = 14, base_baud = 115200) is a 16550A";

    #[test]
    fn mvm1_3888_count_lines_ending_with() {
        let l = SMP_ONLINE_LINE;
        assert_eq!(count_lines_ending_with(b"", l), 0);
        assert_eq!(count_lines_ending_with(format!("{l}\r\n").as_bytes(), l), 1);
        assert_eq!(
            count_lines_ending_with(format!("[    0.123456] {l}\n").as_bytes(), l),
            1
        );
        assert_eq!(count_lines_ending_with(format!("{l}y\n").as_bytes(), l), 0);
        assert_eq!(
            count_lines_ending_with(
                b"smp: Brought up 1 node, 1 CPU\nsmp: Brought up 1 node, 12 CPUs\n",
                l
            ),
            0
        );
        assert_eq!(
            count_lines_ending_with(format!("{l}\nx\n[ 1.0] {l}\n").as_bytes(), l),
            2
        );
    }

    /// MVM-1・#3899・#3998: SMP を無効化する cmdline の見分けと、arm64 の SMP 行の照合（KVM・HVF 共通）。
    #[test]
    fn mvm1_3899_arm64_smp_cmdline_guard() {
        assert_eq!(smp_disabling_param("console=ttyS0 rdinit=/init"), None);
        assert_eq!(smp_disabling_param("console=ttyS0 nosmp"), Some("nosmp"));
        assert_eq!(smp_disabling_param("maxcpus=1 x"), Some("maxcpus=1"));
        assert_eq!(smp_disabling_param("nosmpx maxcpu=1"), None);
        let l = format!(
            "[    0.5] {ARM64_SMP_TOTAL_LINE}\r\nCPU1: Booted secondary processor 0x0000000001 [0x413fd0c1]\n"
        );
        assert_eq!(
            count_lines_ending_with(l.as_bytes(), ARM64_SMP_TOTAL_LINE),
            1
        );
        assert_eq!(count_lines_containing(l.as_bytes(), AP_BOOTED_PREFIX), 1);
        assert_eq!(
            count_lines_containing(
                b"CPU1: Booted secondary processor 0x0000000101\n",
                AP_BOOTED_PREFIX
            ),
            0
        );
    }

    #[test]
    fn mvm1_3958_parse_tty_report_irq_values() {
        let found = |s: &str| parse_tty_report(s.as_bytes(), "ttyS0");
        let expect = TtyReport::Found {
            address: TtyAddress::Mmio(0x0900_0000),
            irq: 14,
        };
        assert_eq!(found(&format!("{LINE}\n")), expect);
        assert_eq!(found(&format!("[    0.312345] {LINE}\r\n")), expect);
        assert_eq!(
            found(&LINE.replace("irq = 14", "irq = 0")),
            TtyReport::Found {
                address: TtyAddress::Mmio(0x0900_0000),
                irq: 0
            }
        );
        assert_eq!(
            found("serial8250: ttyS0 at I/O 0x3f8 (irq = 4, base_baud = 115200) is a 16550A\n"),
            TtyReport::Found {
                address: TtyAddress::Io(0x3f8),
                irq: 4
            }
        );
        let mixed = format!(
            "earlycon: uart8250 at MMIO 0x0000000009000000 (options '')\n{LINE}\n\
             9001000.serial: ttyS1 at MMIO 0x9001000 (irq = 15, base_baud = 115200) is a 16550A\n"
        );
        match found(&mixed) {
            TtyReport::Found { address, irq } => {
                assert_eq!(address, TtyAddress::Mmio(0x0900_0000));
                assert_eq!(irq, 14);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn mvm1_3958_parse_tty_report_missing_and_malformed() {
        let p = |s: &str| parse_tty_report(s.as_bytes(), "ttyS0");
        assert_eq!(p(""), TtyReport::Missing);
        assert_eq!(
            p("earlycon: uart8250 at MMIO 0x0000000009000000 (options '')\n"),
            TtyReport::Missing
        );
        assert_eq!(
            p("xttyS0 at MMIO 0x9000000 (irq = 14, base_baud = 1) is a 16550A\n"),
            TtyReport::Missing
        );
        assert_eq!(p(&format!("{LINE}\n{LINE}\n")), TtyReport::Multiple(2));
        for bad in [
            "ttyS0 at MMIO 0x9000000 (irq = abc, base_baud = 1)",
            "ttyS0 at MMIO 0x9000000 (irq = -1, base_baud = 1)",
            "ttyS0 at MMIO 0x9000000 (irq = 99999999999, base_baud = 1)",
            "ttyS0 at MMIO 0x9000000 (irq = 4294967296, base_baud = 1)",
            "ttyS0 at MMIO 0x9000000 (irq = 14 base_baud = 1)",
            "ttyS0 at MMIO 0x (irq = 14, base_baud = 1)",
            "ttyS0 at *unknown* (irq = 14, base_baud = 1)",
        ] {
            assert!(
                matches!(p(&format!("{bad}\n")), TtyReport::Malformed(_)),
                "{bad}"
            );
        }
    }

    #[test]
    fn mvm1_3771_count_marker_lines() {
        let m = MARKER;
        assert_eq!(count_marker_lines(b"", m), 0);
        assert_eq!(count_marker_lines(format!("{m}\n").as_bytes(), m), 1);
        assert_eq!(count_marker_lines(format!("{m}\r\n").as_bytes(), m), 1);
        assert_eq!(count_marker_lines(m.as_bytes(), m), 1);
        assert_eq!(count_marker_lines(format!("x{m}\n").as_bytes(), m), 0);
        assert_eq!(count_marker_lines(format!("{m}y\n").as_bytes(), m), 0);
        assert_eq!(
            count_marker_lines(format!("{m}\nboot\n{m}\n").as_bytes(), m),
            2
        );
    }

    #[test]
    fn mvm1_3771_escape_tail() {
        assert_eq!(escape_tail(b"abc\x1b[0m\n", 100), "abc\\x1b[0m\\n");
        assert_eq!(escape_tail(b"abcdef", 3), "def");
        assert_eq!(escape_tail(b"", 3), "");
    }

    #[test]
    fn mvm1_3771_parse_boot_timeout_or() {
        assert_eq!(parse_boot_timeout_or(None, 60), Ok(60));
        assert_eq!(parse_boot_timeout_or(None, 7), Ok(7));
        assert_eq!(parse_boot_timeout_or(Some("1"), 60), Ok(1));
        assert_eq!(parse_boot_timeout_or(Some("600"), 60), Ok(600));
        for bad in ["0", "601", "abc", "", "-1"] {
            assert!(parse_boot_timeout_or(Some(bad), 60).is_err(), "{bad}");
        }
    }

    #[test]
    fn mvm1_3771_validate_cmdline_or() {
        assert_eq!(validate_cmdline_or(None, "a b").unwrap(), "a b");
        assert_eq!(validate_cmdline_or(Some("quiet"), "a b").unwrap(), "quiet");
        assert!(validate_cmdline_or(Some(""), "a b").is_err());
        assert!(validate_cmdline_or(Some("a\nb"), "a b").is_err());
    }

    #[test]
    fn mvm1_3897_force_panic_zero_appends_last() {
        assert_eq!(force_panic_zero("rdinit=/init"), "rdinit=/init panic=0");
        assert_eq!(
            force_panic_zero("console=x panic=5"),
            "console=x panic=5 panic=0"
        );
        // 利用者が `rdinit=/missing panic=1` を渡しても末尾が panic=0 になる（陽性の自動再起動の偽陽性を防ぐ）。
        assert!(force_panic_zero("rdinit=/missing panic=1").ends_with(" panic=0"));
    }

    #[test]
    fn mvm1_3771_read_bounded() {
        let dir = std::env::temp_dir().join(format!("fandhe-guest-boot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok");
        let empty = dir.join("empty");
        std::fs::write(&ok, [7u8; 8]).unwrap();
        std::fs::write(&empty, []).unwrap();
        assert_eq!(read_bounded(&ok, 8).unwrap(), vec![7u8; 8]);
        assert!(read_bounded(&ok, 7).is_err());
        assert!(read_bounded(&empty, 8).is_err());
        assert!(read_bounded(&dir, 8).is_err());
        assert!(read_bounded(&dir.join("missing"), 8).is_err());
        // 書き手のいない FIFO は期限内に明示的に拒否される（REPAIR-5）。macOS では O_NONBLOCK の値が Linux と違う。
        let fifo = dir.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let (tx, rx) = mpsc::channel();
        let f = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_bounded(&f, 8));
        });
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("read_bounded blocked on FIFO");
        assert_eq!(r.unwrap_err(), "not a regular file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const IRQ_ROW: &str = " 13:        123  GICv3  33 Level     ttyS0\n";

    #[test]
    fn mvm5_3987_parse_irq_rows_values() {
        let p = |s: &str| parse_irq_rows(s.as_bytes(), "ttyS0");
        let expect = IrqRow {
            count: 123,
            hwirq: 33,
            level: true,
        };
        assert_eq!(p(IRQ_ROW), Ok(vec![expect]));
        assert_eq!(p(&IRQ_ROW.replace('\n', "\r\n")), Ok(vec![expect]));
        // 2 CPU は合計する。
        assert_eq!(
            p(" 13:   100    23  GICv3  33 Level  ttyS0\n"),
            Ok(vec![expect])
        );
        assert_eq!(
            p(" 9:  5  GICv3  27 Edge  timer\n 13:  1  GICv3  33 Edge  ttyS0\n"),
            Ok(vec![IrqRow {
                count: 1,
                hwirq: 33,
                level: false
            }])
        );
        // 2 回の出力は 2 行になる。
        assert_eq!(p(&format!("{IRQ_ROW}x\n{IRQ_ROW}")).map(|v| v.len()), Ok(2));
    }

    #[test]
    fn mvm5_3987_parse_irq_rows_ignores_other_lines() {
        let p = |s: &str| parse_irq_rows(s.as_bytes(), "ttyS0");
        assert_eq!(p(""), Ok(vec![]));
        // 8250 の登録行・名前が部分一致の行・別の名前の行は拾わない。
        assert_eq!(
            p("9000000.serial: ttyS0 at MMIO 0x9000000 (irq = 14, base_baud = 1) is a 16550A\n"),
            Ok(vec![])
        );
        assert_eq!(p(" 13:  1  GICv3  33 Level  xttyS0\n"), Ok(vec![]));
        assert_eq!(p(" 13:  1  GICv3  33 Level  ttyS01\n"), Ok(vec![]));
        assert_eq!(p("IPI0:  1  Rescheduling interrupts\n"), Ok(vec![]));
        assert_eq!(parse_irq_rows(b"\xff\xfe 13: ttyS0\n", "ttyS0"), Ok(vec![]));
    }

    #[test]
    fn mvm5_3987_parse_irq_rows_malformed_and_overflow() {
        let p = |s: &str| parse_irq_rows(s.as_bytes(), "ttyS0");
        for bad in [
            " 13: ttyS0\n",
            " 13:  1  33 Level  ttyS0\n",
            " 13:  GICv3  33 Level  ttyS0\n",
            " 13:  1  GICv3  33 Other  ttyS0\n",
            " 13:  1  GICv3  abc Level  ttyS0\n",
            " 13:  1  GICv3  4294967296 Level  ttyS0\n",
            " 13:  18446744073709551615 1  GICv3  33 Level  ttyS0\n",
            " 13:  99999999999999999999  GICv3  33 Level  ttyS0\n",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        let many = IRQ_ROW.repeat(17);
        assert_eq!(p(&many), Err("too many matching interrupt rows"));
        let long = format!(" 13: {} GICv3 33 Level ttyS0\n", "1 ".repeat(5000));
        assert_eq!(p(&long), Err("too many tokens in an interrupt row"));
    }

    #[test]
    fn mvm5_3987_serial_constants_match_initrd_script() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build-microvm-test-initrd.sh");
        let text = std::fs::read_to_string(script).unwrap();
        let find = |prefix: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix(prefix))
                .filter_map(|l| l.strip_suffix('"'))
                .map(str::to_owned)
                .collect()
        };
        for (name, value) in [
            ("serial_tx_line", SERIAL_TX_LINE),
            ("serial_ready_message", SERIAL_READY),
            ("serial_rx_prefix", SERIAL_RX_PREFIX),
            ("serial_ok_message", SERIAL_OK),
            ("serial_rx_timeout_message", SERIAL_RX_TIMEOUT),
            ("serial_failed_message", SERIAL_FAILED),
        ] {
            assert_eq!(
                find(&format!("{name}=\"")),
                vec![value.to_owned()],
                "{name}"
            );
        }
        assert!(
            text.lines()
                .any(|l| l == format!("serial_rx_rounds={SERIAL_RX_ROUNDS}"))
        );
        // 機械語の mov x2 に焼き込まれた長さ。
        assert_eq!(SERIAL_TX_LINE.len() + 1, 160);
        assert_eq!(SERIAL_TX_LINE.len(), 16 * 10 - 1);
        assert_eq!(SERIAL_READY.len() + 1, 37);
        assert_eq!(SERIAL_RX_PREFIX.len(), 31);
        assert_eq!(SERIAL_OK.len() + 1, 39);
        assert_eq!(SERIAL_RX_TIMEOUT.len() + 1, 42);
        assert_eq!(SERIAL_FAILED.len() + 1, 43);
        assert!(SERIAL_RX_PREFIX.ends_with(' '));
    }
}
