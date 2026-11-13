//! power button（evdev の `KEY_POWER`）の復号と監視ループ（OS 非依存。MAC-4・TASK-191・#2270）。
//!
//! ホストの VZ `requestStop` は、arm64 ゲストでは仮想 PL061 GPIO として届き、ゲストの `gpio-keys` が
//! evdev の `KEY_POWER` を出す想定（Apple Developer Forums の報告による。実 VM での到達は未確認で
//! #1628・#2282。REPAIR-3）。`init` が `/dev/input/event0..` を開いたデバイスごとに監視スレッドを
//! 起動し、本モジュールの [`watch`] が `input_event` を読んで、押下で停止要求の通知を呼ぶ。
//!
//! 入力はカーネル由来だが untrusted として扱い、固定長の buffer へ `get` と `try_into` で復号する。
//! 読み取りの失敗・EOF・短い読みではスレッドを終える（busy loop にしない）。

use std::io::Read;

/// 開く入力デバイスの最大数（`/dev/input/event0..7`）。スレッド数の上限でもある。
pub const MAX_INPUT_DEVICES: usize = 8;
/// LP64 の Linux（x86_64・aarch64）の `struct input_event` の大きさ（`timeval` 16 + type 2 + code 2 + value 4）。
pub const INPUT_EVENT_SIZE: usize = 24;
/// `EV_KEY`（キーの押下・離し）。
pub const EV_KEY: u16 = 1;
/// `KEY_POWER`。
pub const KEY_POWER: u16 = 116;

/// 復号した入力イベント（時刻は使わない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    /// イベントの type（`EV_KEY` 等）。
    pub kind: u16,
    /// キーコード等。
    pub code: u16,
    /// 値（キーでは 1 が押下、0 が離し、2 が自動リピート）。
    pub value: i32,
}

/// 入力デバイスのパス（`/dev/input/event<i>`）。
pub fn device_path(i: usize) -> String {
    format!("/dev/input/event{i}")
}

/// 24 バイトの `input_event` を復号する。時刻（先頭 16 バイト）は読まない。
pub fn decode_input_event(buf: &[u8; INPUT_EVENT_SIZE]) -> InputEvent {
    let u16_at = |off: usize| {
        buf.get(off..off + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map_or(0, u16::from_ne_bytes)
    };
    let value = buf
        .get(20..24)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, i32::from_ne_bytes);
    InputEvent {
        kind: u16_at(16),
        code: u16_at(18),
        value,
    }
}

/// 電源ボタンの押下か（離し・自動リピート・他のキー・他の type は偽）。
pub fn is_power_press(ev: &InputEvent) -> bool {
    ev.kind == EV_KEY && ev.code == KEY_POWER && ev.value == 1
}

/// `r` から `input_event` を読み続け、電源ボタンの押下で `on_press` を呼ぶ。`on_press` が真を返したら
/// （通知に成功したら）終える。読み取りの失敗・EOF・短い読みでも終える。
pub fn watch<R: Read>(mut r: R, mut on_press: impl FnMut() -> bool) {
    let mut buf = [0u8; INPUT_EVENT_SIZE];
    loop {
        if r.read_exact(&mut buf).is_err() {
            return;
        }
        if is_power_press(&decode_input_event(&buf)) && on_press() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, code: u16, value: i32) -> [u8; INPUT_EVENT_SIZE] {
        let mut b = [0u8; INPUT_EVENT_SIZE];
        // 時刻の領域は意味のない値で埋めて、復号が読まないことを確かめる。
        b[..16].copy_from_slice(&[0xAA; 16]);
        b[16..18].copy_from_slice(&kind.to_ne_bytes());
        b[18..20].copy_from_slice(&code.to_ne_bytes());
        b[20..24].copy_from_slice(&value.to_ne_bytes());
        b
    }

    #[test]
    fn mac4_2270_constants_match_linux_uapi() {
        assert_eq!(INPUT_EVENT_SIZE, 24);
        assert_eq!(EV_KEY, 1);
        assert_eq!(KEY_POWER, 116);
        assert_eq!(device_path(3), "/dev/input/event3");
    }

    #[test]
    fn mac4_2270_decode_input_event() {
        let ev = decode_input_event(&event(1, 116, 1));
        assert_eq!(
            ev,
            InputEvent {
                kind: 1,
                code: 116,
                value: 1
            }
        );
        assert_eq!(decode_input_event(&event(1, 116, -1)).value, -1);
    }

    #[test]
    fn mac4_2270_only_power_key_press_counts() {
        assert!(is_power_press(&decode_input_event(&event(1, 116, 1))));
        // 離し・自動リピート・他のキー・他の type。
        assert!(!is_power_press(&decode_input_event(&event(1, 116, 0))));
        assert!(!is_power_press(&decode_input_event(&event(1, 116, 2))));
        assert!(!is_power_press(&decode_input_event(&event(1, 30, 1))));
        assert!(!is_power_press(&decode_input_event(&event(0, 116, 1))));
        assert!(!is_power_press(&decode_input_event(&event(2, 116, 1))));
    }

    #[test]
    fn mac4_2270_watch_notifies_on_press_and_stops() {
        let mut stream = Vec::new();
        for e in [
            event(0, 0, 0),
            event(1, 30, 1),
            event(1, 116, 0),
            event(1, 116, 1),
        ] {
            stream.extend_from_slice(&e);
        }
        // 押下の後ろにもデータがあるが、通知に成功したら読まない。
        stream.extend_from_slice(&event(1, 116, 1));
        let mut cur = std::io::Cursor::new(stream);
        let mut calls = 0;
        watch(&mut cur, || {
            calls += 1;
            true
        });
        assert_eq!(calls, 1);
        assert_eq!(cur.position(), 4 * INPUT_EVENT_SIZE as u64);
    }

    #[test]
    fn mac4_2270_watch_retries_when_notification_fails() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&event(1, 116, 1));
        stream.extend_from_slice(&event(1, 116, 1));
        let mut calls = 0;
        watch(std::io::Cursor::new(stream), || {
            calls += 1;
            calls == 2
        });
        assert_eq!(calls, 2);
    }

    /// EOF・短い読みでは通知せずに終わる（busy loop にならない）。
    #[test]
    fn mac4_2270_watch_ends_on_eof_and_short_read() {
        watch(std::io::Cursor::new(Vec::new()), || panic!("no press"));
        let mut short = event(1, 116, 1).to_vec();
        short.truncate(INPUT_EVENT_SIZE - 1);
        watch(std::io::Cursor::new(short), || panic!("no press"));
    }
}
