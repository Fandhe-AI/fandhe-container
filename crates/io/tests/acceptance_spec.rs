//! REPAIR-12（AI 自己補修方針・確定）: ビルド・回帰テストが通っていても
//! 「タスクで要求された出力仕様を満たさない」失敗モード（PoC-12 で観測。
//! 7B モデルがビルド・既存回帰を通したのに `flush_every=...` 等の要求出力を
//! 実装しなかった事例）を、タスク固有の受け入れ基準を機械照合するテストで
//! 検出する。
//!
//! # 位置づけ
//!
//! - 本ファイルは TASK-91.1（#129・MS-1 Phase 2）の成果物。対象仕様の選定
//!   一覧・照合ヘルパ・雛形テストを実装する（少なくとも 1 件が実際に動く
//!   状態にする）
//! - 本照合（選定した対象仕様のうち最低 2 件について、仕様未達の実装に
//!   差し替えると実際に fail することの確認）は TASK-91.2（#130・MS-1
//!   Phase 2）で行う
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
        spec_fact: "書き込み ACK と FLUSH ACK が別種別として区別され、\
            FLUSH ACK はバリア以前の書き込みの永続化後にのみ返ること",
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

/// モジュールドキュメントの表を Rust ソースへ複製した期待値。
///
/// [`repair_12_acceptance_targets_are_listed`] が [`ACCEPTANCE_TARGETS`] の
/// 各行を `behavior`・`spec_fact`・`method`・`status` まで含めて個別に
/// 照合するための対照データ（Codex レビュー指摘: 件数と TASK-13 の一部しか
/// 検証しておらず、他の行を改変しても検出できなかった穴を塞ぐ）。
const EXPECTED_ACCEPTANCE_TARGETS: &[AcceptanceTarget] = &[
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
        spec_fact: "書き込み ACK と FLUSH ACK が別種別として区別され、\
            FLUSH ACK はバリア以前の書き込みの永続化後にのみ返ること",
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

/// TASK-15（IO-2）の FLUSH ACK 永続化条件を照合するための、単一
/// io イベントの暫定表現（Codex レビュー指摘対応）。
///
/// `persisted_before_barrier=true` のような固定文字列 1 個の一致判定では、
/// 「FLUSH ACK を返す前に実際に永続化が完了したか」という順序関係を
/// 検証できない（永続化未完了のまま `persisted_before_barrier=true` という
/// 値だけを出力する回帰があっても検出できない）。そこで ACK 応答を
/// 「イベント列」として表現し、[`flush_ack_follows_persistence`] で
/// `PersistedBeforeBarrier` イベントが `FlushAckSent` より前に実際に
/// 記録されていることを、列の走査により機械的に確認する。
///
/// io の実 API 接続後（TASK-11 / TASK-15）は、このイベント列を io の
/// 実際の ACK 送出順序ログ・永続化完了通知に置き換える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckEvent {
    /// バリア以前に発行された書き込みの永続化（fsync 相当）が完了した。
    PersistedBeforeBarrier,
    /// FLUSH ACK をクライアントへ送出した。
    FlushAckSent,
}

/// `events` を先頭から走査し、`FlushAckSent` が現れた時点で、それより
/// 前に `PersistedBeforeBarrier` が記録済みであることを確認する。
///
/// - `FlushAckSent` が一度も現れない列は判定対象がないため `false` を返す
/// - `PersistedBeforeBarrier` を伴わない・それより後にしか永続化が記録
///   されない `FlushAckSent` は違反として `false` を返す（PoC-12 型の
///   「ビルドは通るが仕様未達」を、値の一致ではなく順序の観測で検出する）
fn flush_ack_follows_persistence(events: &[AckEvent]) -> bool {
    let mut persisted = false;
    let mut saw_flush_ack = false;
    for event in events {
        match event {
            AckEvent::PersistedBeforeBarrier => persisted = true,
            AckEvent::FlushAckSent => {
                saw_flush_ack = true;
                if !persisted {
                    return false;
                }
            }
        }
    }
    saw_flush_ack
}

/// マッチャが TASK-15（IO-2）の FLUSH ACK 永続化条件（バリア以前の
/// 書き込みが永続化された後にのみ FLUSH ACK を返すこと）を、ACK の
/// 返却順序と永続化状態の観測によって機械照合できることを確認する
/// （REPAIR-12。[`ACCEPTANCE_TARGETS`] の TASK-15 行に対応。Codex レビュー
/// 指摘: 固定文字列 `persisted_before_barrier=true` の一致判定では
/// 永続化前に FLUSH ACK を返す回帰を検出できないため、イベント順序を
/// 観測する [`flush_ack_follows_persistence`] へ置き換えた）。
///
/// イベント列は TASK-11 / TASK-15 で ACK フレーム型が確定するまでの暫定
/// 表現であり、確定契約ではない（本ファイルのモジュールドキュメント
/// 「スタブについて」を参照）。
#[test]
fn repair_12_scaffold_matcher_detects_premature_flush_ack() {
    // 仕様どおり: バリア以前の書き込みが永続化済みになってから FLUSH ACK。
    let ordered = [AckEvent::PersistedBeforeBarrier, AckEvent::FlushAckSent];
    assert!(
        flush_ack_follows_persistence(&ordered),
        "永続化後の FLUSH ACK を正当な列として受理できていない"
    );

    // 仕様違反の再現 (1): 永続化イベントを伴わずに FLUSH ACK を送出する
    // 回帰（PoC-12 型の失敗モード。値だけを見れば `persisted_before_barrier`
    // 相当のフィールドを立てていても、実際の永続化完了イベントが無い）。
    let missing_persistence = [AckEvent::FlushAckSent];
    assert!(
        !flush_ack_follows_persistence(&missing_persistence),
        "永続化イベントを伴わない FLUSH ACK 送出をマッチャが検出できていない"
    );

    // 仕様違反の再現 (2): 永続化完了が FLUSH ACK 送出より後に記録される
    // 回帰（返却順序の違反。文字列の値一致だけでは検出できない失敗モード）。
    let out_of_order = [AckEvent::FlushAckSent, AckEvent::PersistedBeforeBarrier];
    assert!(
        !flush_ack_follows_persistence(&out_of_order),
        "永続化完了より先に FLUSH ACK を送出する順序違反をマッチャが検出できていない"
    );
}

/// 選定した対象仕様の一覧（[`ACCEPTANCE_TARGETS`]）が、モジュール
/// ドキュメントの表と一致する件数・内容を持つことを機械照合する
/// （TASK-91.1 の受け入れ条件「一覧化」を機械照合するテスト）。
///
/// 件数と `task` の前方一致チェックに加え、[`EXPECTED_ACCEPTANCE_TARGETS`]
/// との突き合わせで全行の `behavior`・`spec_fact`・`method`・`status` を
/// 個別に照合する。行の内容（TASK-15 の FLUSH ACK 永続化条件を含む）が
/// 改変されても検出できる。
#[test]
fn repair_12_acceptance_targets_are_listed() {
    assert_eq!(ACCEPTANCE_TARGETS.len(), 6);
    assert_eq!(ACCEPTANCE_TARGETS.len(), EXPECTED_ACCEPTANCE_TARGETS.len());

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

    for (actual, expected) in ACCEPTANCE_TARGETS
        .iter()
        .zip(EXPECTED_ACCEPTANCE_TARGETS.iter())
    {
        assert_eq!(actual.task, expected.task, "task の不一致");
        assert_eq!(
            actual.behavior, expected.behavior,
            "{}: behavior の不一致",
            actual.task
        );
        assert_eq!(
            actual.spec_fact, expected.spec_fact,
            "{}: spec_fact の不一致",
            actual.task
        );
        assert_eq!(
            actual.method, expected.method,
            "{}: method の不一致",
            actual.task
        );
        assert_eq!(
            actual.status, expected.status,
            "{}: status の不一致",
            actual.task
        );
    }
}
