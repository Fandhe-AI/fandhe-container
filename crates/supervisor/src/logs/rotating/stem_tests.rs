//! ファイル名 stem の逆変換と名前の分類のユニットテスト（#2760・SUP-7・CRI-2）。

use super::*;

/// stem の往復: 符号化した ID が元に戻る。予約名（`_0`）・大文字・`_`・`.` を含む ID を具体値で照合する。
#[test]
fn sup7_cri2_decode_file_stem_roundtrips_encoded_ids() {
    for raw in ["c1", "con", "Ab_C", "a.log", "x__y", "com1.x", "Con", "_a"] {
        let id = ContainerId::new(raw).unwrap();
        let stem = encode_file_stem(raw);
        assert_eq!(decode_file_stem(&stem), Some(id), "{raw} -> {stem}");
    }
    assert_eq!(encode_file_stem("con"), "_0con");
    assert_eq!(encode_file_stem("Ab_C"), "_ab___c");
}

/// 符号化の出力にならない stem（不正な `_` の並び・大文字・予約名でない `_0` 接頭辞）は ID に戻さない。
#[test]
fn sup7_cri2_decode_file_stem_rejects_non_canonical_stems() {
    for stem in ["_1", "a_", "Foo", "_0", "_0abc", "_a_", "_"] {
        assert_eq!(decode_file_stem(stem), None, "{stem}");
    }
}

/// 名前から stem を取り出す 3 形式と、無関係な名前。
#[test]
fn sup7_cri2_stem_of_log_name_handles_three_forms() {
    assert_eq!(stem_of_log_name("a1.log"), Some("a1"));
    assert_eq!(stem_of_log_name("a1.log.lock"), Some("a1"));
    assert_eq!(stem_of_log_name("a1.log.12"), Some("a1"));
    assert_eq!(stem_of_log_name("a.log.log.1"), Some("a.log"));
    assert_eq!(stem_of_log_name("a1.txt"), None);
    assert_eq!(stem_of_log_name("a1.log.x"), None);
    assert_eq!(stem_of_log_name("a1.log."), None);
}
