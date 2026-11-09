//! 制御クライアントが最後に見た OS の errno を、同じスレッドの呼び出し元へ渡す小さな受け渡し口
//! （stream-exec helper の診断行用。SUP-6・REPAIR-4・SEC-1・#4284）。
//!
//! 役割: `client`・`listener` の関数は core の `TraitError`（errno を持たない）を返す公開契約を保つ必要がある。
//! 既存の呼び出し元（CLI の signal・cancel・attach 等）の型を変えずに errno を取り出せるよう、失敗を作った地点
//! （[`record`]）で thread-local に書き、`obtain_with_errno` / `notify_created_with_errno` だけが呼び出しの前に
//! [`clear`]・後に [`take`] する。helper は単一スレッドで、同じスレッドで呼び出しを完結させるため、他の呼び出しの
//! 値を拾わない。errno は数値だけで、文字列・パスは保持しない。`record` は最終的に失敗にした OS エラーだけで
//! 呼ぶこと（再試行で吸収したエラーでは呼ばない）。

use std::cell::Cell;
use std::io;

thread_local! {
    static LAST: Cell<Option<i32>> = const { Cell::new(None) };
}

/// OS 由来のエラーなら errno を覚える（OS 由来でなければ何もしない）。
pub(crate) fn record(e: &io::Error) {
    if let Some(n) = e.raw_os_error() {
        LAST.with(|c| c.set(Some(n)));
    }
}

/// 覚えている errno を捨てる（呼び出しの前）。
pub(crate) fn clear() {
    LAST.with(|c| c.set(None));
}

/// 覚えている errno を取り出して捨てる（呼び出しの後）。
pub(crate) fn take() -> Option<i32> {
    LAST.with(Cell::take)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-6・REPAIR-4（#4284）: OS 由来のエラーだけを覚え、取り出すと空になる。
    #[test]
    fn sup6_4284_record_take_clear() {
        clear();
        record(&io::Error::from(io::ErrorKind::Other));
        assert_eq!(take(), None);
        record(&io::Error::from_raw_os_error(2));
        assert_eq!(take(), Some(2));
        assert_eq!(take(), None);
        record(&io::Error::from_raw_os_error(13));
        clear();
        assert_eq!(take(), None);
    }
}
