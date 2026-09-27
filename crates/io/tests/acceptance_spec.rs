//! REPAIR-12（AI 自己補修方針・確定）: ビルド・回帰テストが通っていても
//! 「タスクで要求された出力仕様を満たさない」失敗モード（PoC-12 で観測。
//! 7B モデルがビルド・既存回帰を通したのに `flush_every=...` 等の要求出力を
//! 実装しなかった事例）を、タスク固有の受け入れ基準を機械照合するテストで
//! 検出する。
//!
//! # 位置づけ
//!
//! - 本ファイルは TASK-91.1（#129）の成果物。対象仕様の選定一覧・照合ヘルパ・
//!   雛形テストを実装する（少なくとも 1 件が実際に動く状態にする）
//! - 本照合（選定した対象仕様のうち最低 2 件について、仕様未達の実装に
//!   差し替えると実際に fail することの確認）は TASK-91.2（#130）で行う
//! - 配置理由: spec（`docs/spec/05-tasks.md` の TASK-91）上の成果物パスは
//!   `crates/core/tests/acceptance_spec.rs` だが、親 #128 の受け入れ条件が
//!   「MS-1 時点で core は雛形のみで本タスクの照合対象（io の出力仕様）を
//!   持たない」ことを理由に `crates/io/tests/acceptance_spec.rs` へ変更して
//!   いる。core から io を参照するには crate 間依存の追加が必要になるため、
//!   親 issue の決定に従い io 配下に置く（spec との差分は報告事項として
//!   別途扱う。spec 本体は本リポから編集しない。[spec-reference]）
//!
//! [spec-reference]: ../../../.claude/rules/spec-reference.md
//!
//! # 選定した対象仕様（機械照合できる出力仕様の一覧）
//!
//! 選定は G2（TASK-11〜25）の中から、io の実出力（設定の実効値・ACK 種別・
//! エラー構造・文書中の契約文言）を文字列パターンまたは構造化データとして
//! 照合できるものに限った。一覧の内容はこの表を正としつつ、機械的にも確認
//! できるよう [`ACCEPTANCE_TARGETS`] に同じ内容を Rust のデータとして持つ
//! （表とデータが食い違ったらデータ表を正とする）。
//!
//! | TASK    | ビヘイビア  | 機械照合する出力仕様                                                                  | 照合方法            | 状態                          |
//! | ------- | ----------- | -------------------------------------------------------------------------------------- | ------------------- | ----------------------------- |
//! | TASK-13 | IO-1        | バッチサイズの既定値 64 が設定の実効値に反映されること（`batch_size=<N>`）             | 構造化 assert       | 未接続（TASK-13 で接続）      |
//! | TASK-15 | IO-2        | 書き込み ACK と FLUSH ACK が別種別として区別され、FLUSH ACK はバリア以前の書き込みの永続化後にのみ返ること | 構造化 assert | 未接続（TASK-11 / 15 で接続） |
//! | TASK-16 | IO-10       | 未フラッシュ滞留量の上限が設定可能で、上限到達時に自動フラッシュが発行されること（`flush_every=<N>`） | 構造化 assert | 未接続（TASK-16 で接続）      |
//! | TASK-17 | IO-2        | `docs/api/io-barrier.md` に ACK / FLUSH ACK の永続化保証の違いが明記されていること      | 文字列パターン照合  | 未接続（TASK-17 で文書作成後に接続） |
//! | TASK-19 | IO-5        | 大文字小文字の違いのみで衝突する 2 ファイル作成が構造化エラー（`code`・`message`）で返ること | 構造化 assert  | 未接続（TASK-19 で接続）      |
//! | TASK-20 | IO-5・WIN-4 | 260 文字を超える共有パスに警告またはエラーが返ること（しきい値 260/261 の境界）        | 構造化 assert       | 未接続（TASK-20 で接続）      |
//!
//! 対象外にした TASK と理由:
//!
//! - TASK-14: 整合性スイート自体が別の成果物であり、照合対象の出力仕様ではない
//! - TASK-18: SIGKILL 実測レポートの妥当性判断は人間が行う「共同」タスク
//! - TASK-21: 正規化方針の決定自体を人間が行う
//! - TASK-22〜26: 担当が人間、または実機実測・評価レポート
//!
//! # スタブについて（REPAIR-3）
//!
//! `crates/io` は雛形のみで TASK-11〜25 の本体は未実装のため、現時点では
//! io の実 API を呼び出して出力を照合できない。本ファイルの雛形テストは
//! 「照合器（マッチャ）そのものが仕様どおりに動くこと」を、仕様から作った
//! 暫定サンプル行に対して検証する。サンプル文字列（`batch_size=64` 等）は
//! fandhe-container の確定契約ではなく、PoC-12 の観測結果と TASK-91 計画を
//! もとにした暫定値であり、io の実 API が確定するタイミング（TASK-13 の
//! バッチ設定 API 確定・TASK-15 の ACK フレーム型確定）で実出力に接続する。

/// 照合方法の分類。[`AcceptanceTarget::method`] に使う。
///
/// - `StringPattern`: 出力文字列中の必須文言・見出しの有無を照合する
/// - `StructuredAssert`: 出力を `key=value` 等に分解し、具体値を比較する
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchMethod {
    StringPattern,
    StructuredAssert,
}

/// 対象仕様がまだ io の実 API に接続されていないことを表す状態。
///
/// 現時点では `NotWired` のみを持つ。TASK-11〜25 の実装が進み、実出力を
/// 呼び出せるようになった対象から `Wired` 相当の状態（将来のバリアント）
/// を追加し、このテストファイルから実 API を呼ぶ形に差し替える
/// （本照合は TASK-91.2・#130）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetStatus {
    NotWired { planned_task: &'static str },
}

/// 機械照合の対象仕様 1 件を表す。モジュールドキュメントの表と同じ内容を
/// Rust のデータとして持ち、[`repair_12_acceptance_targets_are_listed`] で
/// 機械的に確認する。
#[derive(Debug, Clone, Copy)]
struct AcceptanceTarget {
    task: &'static str,
    behavior: &'static str,
    spec_fact: &'static str,
    method: MatchMethod,
    status: TargetStatus,
}

/// TASK-91.1 で選定した対象仕様の一覧（モジュールドキュメントの表を正とし、
/// このデータは表と同じ内容を機械照合できる形で保持したもの）。
const ACCEPTANCE_TARGETS: &[AcceptanceTarget] = &[
    AcceptanceTarget {
        task: "TASK-13",
        behavior: "IO-1",
        spec_fact: "バッチサイズの既定値 64 が設定の実効値に反映されること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-13",
        },
    },
    AcceptanceTarget {
        task: "TASK-15",
        behavior: "IO-2",
        spec_fact: "書き込み ACK と FLUSH ACK が別種別として区別されること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-11 / TASK-15",
        },
    },
    AcceptanceTarget {
        task: "TASK-16",
        behavior: "IO-10",
        spec_fact: "未フラッシュ滞留量の上限到達時に自動フラッシュが発行されること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-16",
        },
    },
    AcceptanceTarget {
        task: "TASK-17",
        behavior: "IO-2",
        spec_fact: "docs/api/io-barrier.md に ACK / FLUSH ACK の永続化保証の違いが明記されていること",
        method: MatchMethod::StringPattern,
        status: TargetStatus::NotWired {
            planned_task: "TASK-17",
        },
    },
    AcceptanceTarget {
        task: "TASK-19",
        behavior: "IO-5",
        spec_fact: "大文字小文字の違いのみで衝突する 2 ファイル作成が構造化エラーで返ること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-19",
        },
    },
    AcceptanceTarget {
        task: "TASK-20",
        behavior: "IO-5・WIN-4",
        spec_fact: "260 文字を超える共有パスに警告またはエラーが返ること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-20",
        },
    },
];

/// `key=value` 形式のトークン列を空白区切りで分解する。
///
/// 呼び出し元: 本ファイルの雛形テスト（将来は io の実出力の 1 行）。
/// `=` を含まないトークンは無視する（外部入力ではなくテスト内部の固定
/// サンプルのみを扱うため `unwrap` 等は使わず `filter_map` で読み飛ばす）。
fn parse_key_values(line: &str) -> Vec<(&str, &str)> {
    line.split_whitespace()
        .filter_map(|token| token.split_once('='))
        .collect()
}

/// `parse_key_values` の結果から指定した `key` の値を探す。
///
/// 見つからない場合は `None` を返す（PoC-12 のように要求されたフィールドが
/// 出力から欠けている失敗モードを、この `None` で検出する）。
fn find_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    parse_key_values(line)
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// REPAIR-12 の雛形マッチャが、仕様から作った暫定サンプル行を正しく
/// 具体値で照合できることを確認する（TASK-91.1・#129）。
///
/// サンプル行は PoC-12 の失敗事例（`batch_size` / `flush_every` の要求）を
/// もとにした暫定値であり、確定契約ではない（本ファイルのモジュール
/// ドキュメント「スタブについて」を参照）。
#[test]
fn repair_12_scaffold_matcher_accepts_spec_sample() {
    let sample = "batch: n=200 batch_size=64 flush_every=Some(20) flush_acks=10";

    assert_eq!(find_value(sample, "batch_size"), Some("64"));
    assert_eq!(find_value(sample, "flush_every"), Some("Some(20)"));
    assert_eq!(find_value(sample, "flush_acks"), Some("10"));
}

/// マッチャが「ビルドは通るが仕様未達」の失敗モード（PoC-12: 要求された
/// フィールドが出力から欠落）を検出できることを確認する（REPAIR-12）。
#[test]
fn repair_12_scaffold_matcher_detects_missing_field() {
    // flush_every を欠いたサンプル（PoC-12 の失敗モードの再現）。
    let sample_missing_flush_every = "batch: n=200 batch_size=64 flush_acks=10";

    assert_eq!(
        find_value(sample_missing_flush_every, "flush_every"),
        None,
        "flush_every が出力に含まれないことをマッチャが検出できていない"
    );
    // batch_size 自体は存在するため、マッチャが全フィールドを一律に
    // 見失っているわけではないことも合わせて確認する。
    assert_eq!(
        find_value(sample_missing_flush_every, "batch_size"),
        Some("64")
    );
}

/// 選定した対象仕様の一覧（[`ACCEPTANCE_TARGETS`]）が、モジュール
/// ドキュメントの表と一致する件数・内容を持つことを機械照合する
/// （TASK-91.1 の受け入れ条件「一覧化」を機械照合するテスト）。
#[test]
fn repair_12_acceptance_targets_are_listed() {
    assert_eq!(ACCEPTANCE_TARGETS.len(), 6);

    for target in ACCEPTANCE_TARGETS {
        assert!(
            target.task.starts_with("TASK-"),
            "task は TASK- 接頭辞を持つ想定: {:?}",
            target.task
        );
        assert!(
            !target.behavior.is_empty(),
            "behavior（ビヘイビア ID）は必須: {target:?}"
        );
        assert!(
            !target.spec_fact.is_empty(),
            "spec_fact（照合する出力仕様の説明）は必須: {target:?}"
        );
    }

    let task_13 = ACCEPTANCE_TARGETS
        .iter()
        .find(|t| t.task == "TASK-13")
        .expect("TASK-13 の行が一覧に含まれる想定");
    assert_eq!(task_13.behavior, "IO-1");
    assert_eq!(task_13.method, MatchMethod::StructuredAssert);
    assert_eq!(
        task_13.status,
        TargetStatus::NotWired {
            planned_task: "TASK-13"
        }
    );
}
