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
        spec_fact: "未フラッシュ滞留量の上限が設定可能で、\
            上限到達時に自動フラッシュが発行されること",
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
        spec_fact: "大文字小文字の違いのみで衝突する 2 ファイル作成が\
            構造化エラー（`code`・`message`）で返ること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-19",
        },
    },
    AcceptanceTarget {
        task: "TASK-20",
        behavior: "IO-5・WIN-4",
        spec_fact: "260 文字を超える共有パスに警告またはエラーが返ること\
            （しきい値 260/261 の境界）",
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
/// 具体値で照合できることを確認する（TASK-91.1・#129。IO-1・IO-10 に対応:
/// `batch_size` は IO-1〔TASK-13〕の既定値反映、`flush_every` は
/// IO-10〔TASK-16〕の上限設定を照合する）。
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
/// フィールドが出力から欠落）を検出できることを確認する（REPAIR-12。
/// 欠落させる `flush_every` は IO-10〔TASK-16〕、健在を確認する
/// `batch_size` は IO-1〔TASK-13〕に対応する）。
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
        spec_fact: "未フラッシュ滞留量の上限が設定可能で、\
            上限到達時に自動フラッシュが発行されること",
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
        spec_fact: "大文字小文字の違いのみで衝突する 2 ファイル作成が\
            構造化エラー（`code`・`message`）で返ること",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-19",
        },
    },
    AcceptanceTarget {
        task: "TASK-20",
        behavior: "IO-5・WIN-4",
        spec_fact: "260 文字を超える共有パスに警告またはエラーが返ること\
            （しきい値 260/261 の境界）",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-20",
        },
    },
];

/// TASK-15（IO-2）の FLUSH ACK 永続化条件・ACK 種別区別を照合するための、
/// 単一 io イベントの暫定表現（Codex レビュー指摘対応・2 巡目）。
///
/// 1 巡目の修正（`PersistedBeforeBarrier` / `FlushAckSent` の 2 種のみ）には
/// 残っていた 2 つの穴を、`generation`（バリアの通し番号）付きの 4 変種で
/// 塞ぐ:
///
/// - **世代の使い捨て漏れ**: `persisted` を単一の真偽値で持つと、1 回目の
///   バリアの永続化完了後は真のまま戻らず、2 回目以降のバリア（新たな
///   書き込み後の再フラッシュ）に対する FLUSH ACK を無条件で正当と判定
///   してしまう（IO-2「各バリア以前に受理した書き込みの永続化完了」という
///   契約は世代ごとに個別に満たす必要がある）。`generation` を全イベントに
///   持たせ、[`flush_ack_follows_persistence`] で世代ごとに厳密照合する
///   （`generation` が一致する `PersistedBeforeBarrier` のみを有効とし、
///   他世代の永続化完了で代用させない）
/// - **ACK 種別の取り違え未検出**: 通常の書き込み ACK（`WriteAckSent`。
///   永続化完了を待たずに返してよい）と FLUSH ACK（永続化完了必須）の
///   どちらを返すべきかという区別自体を、以前は表現できなかった。
///   `BarrierRequested` を追加し、「バリア要求に対して FLUSH ACK ではなく
///   通常 ACK しか返らない」「バリア要求が無いのに FLUSH ACK を返す」の
///   双方向の取り違えを [`flush_ack_follows_persistence`] で検出する
///
/// io の実 API 接続後（TASK-11 / TASK-15）は、このイベント列を io の
/// 実際の ACK 送出順序ログ・永続化完了通知に置き換える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckEvent {
    /// クライアントが FLUSH バリアを要求した（`generation` はバリアの
    /// 通し番号。同じ番号を持つ `PersistedBeforeBarrier` / `FlushAckSent`
    /// と対応づける）。
    BarrierRequested { generation: u32 },
    /// バリア以前に発行された書き込みの永続化（fsync 相当）が、
    /// `generation` の世代について完了した。
    PersistedBeforeBarrier { generation: u32 },
    /// 通常の書き込み ACK を送出した（IO-1・IO-2: 永続化完了を待たずに
    /// 返してよい種別。FLUSH ACK とは別種別として区別する）。
    WriteAckSent { generation: u32 },
    /// FLUSH ACK をクライアントへ送出した（`generation` に対応する
    /// バリア要求への応答。永続化完了後にのみ送出してよい）。
    FlushAckSent { generation: u32 },
}

/// [`flush_ack_follows_persistence`] の判定結果。
///
/// 真偽値のみの assert では「どの契約に違反したか」が失われる
/// （[coding-rust] のテスト規約「期待値は具体値で書く」）ため、違反した
/// 世代まで含めて表現する。
///
/// [coding-rust]: ../../../.claude/rules/coding-rust.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushAckVerdict {
    /// 送出された FLUSH ACK はすべて仕様どおり（対応するバリア要求があり、
    /// 同一世代の永続化完了後に送出された）。
    Ok,
    /// FLUSH ACK が一度も送出されなかった（判定対象がない。バリア要求に
    /// 対して通常 ACK しか返らない取り違えもここに含まれる）。
    NoFlushAck,
    /// `generation` に対応する永続化完了より前に FLUSH ACK を送出した
    /// （IO-2 のバリア以前の書き込み永続化契約への違反）。
    PrematureFlushAck { generation: u32 },
    /// 対応する `BarrierRequested` が無いのに FLUSH ACK を送出した
    /// （通常の書き込み ACK を返すべき場面で FLUSH ACK を返す取り違え）。
    FlushAckWithoutBarrier { generation: u32 },
}

/// `events` を先頭から走査し、各 `FlushAckSent { generation }` について
/// 同じ `generation` の `BarrierRequested` が先行し、かつ同じ `generation`
/// の `PersistedBeforeBarrier` が FLUSH ACK 送出より前に記録済みであること
/// を確認する。
///
/// - 世代ごとに個別照合するため、他世代の永続化完了（過去に完了した
///   世代の使い回し）では通らない（世代の使い捨て漏れの検出）
/// - `WriteAckSent` は永続化完了の有無を問わず許容する（IO-1・IO-2 の
///   契約差: 通常 ACK は永続化完了を待たずに返してよい）
/// - `FlushAckSent` が一度も現れない列は [`FlushAckVerdict::NoFlushAck`]
///   を返す（PoC-12 型の「ビルドは通るが仕様未達」を、値の一致ではなく
///   イベント種別・順序の観測で検出する）
fn flush_ack_follows_persistence(events: &[AckEvent]) -> FlushAckVerdict {
    let mut requested_generations: Vec<u32> = Vec::new();
    let mut persisted_generations: Vec<u32> = Vec::new();
    let mut verdict = FlushAckVerdict::NoFlushAck;

    for event in events {
        match event {
            AckEvent::BarrierRequested { generation } => {
                requested_generations.push(*generation);
            }
            AckEvent::PersistedBeforeBarrier { generation } => {
                persisted_generations.push(*generation);
            }
            AckEvent::WriteAckSent { .. } => {}
            AckEvent::FlushAckSent { generation } => {
                if !requested_generations.contains(generation) {
                    return FlushAckVerdict::FlushAckWithoutBarrier {
                        generation: *generation,
                    };
                }
                if !persisted_generations.contains(generation) {
                    return FlushAckVerdict::PrematureFlushAck {
                        generation: *generation,
                    };
                }
                verdict = FlushAckVerdict::Ok;
            }
        }
    }

    verdict
}

/// マッチャが TASK-15（IO-2）の FLUSH ACK 永続化条件（バリア以前の
/// 書き込みが永続化された後にのみ FLUSH ACK を返すこと）を、世代ごとの
/// イベント順序の観測によって機械照合できることを確認する（REPAIR-12。
/// [`ACCEPTANCE_TARGETS`] の TASK-15 行に対応。Codex レビュー指摘・2 巡目:
/// 単一の真偽値 `persisted` は一度真になると戻らず 2 回目以降のバリアの
/// FLUSH ACK を無条件で正当と判定してしまうため、`generation` 付きの
/// 世代別照合に置き換えた）。
///
/// イベント列は TASK-11 / TASK-15 で ACK フレーム型が確定するまでの暫定
/// 表現であり、確定契約ではない（本ファイルのモジュールドキュメント
/// 「スタブについて」を参照）。
#[test]
fn repair_12_scaffold_matcher_detects_premature_flush_ack() {
    // 仕様どおり: バリア要求 → 永続化完了 → FLUSH ACK の順。
    let ordered = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&ordered),
        FlushAckVerdict::Ok,
        "永続化後の FLUSH ACK を正当な列として受理できていない"
    );

    // 仕様どおり (2 世代目): 1 世代目の FLUSH ACK 後、新たな書き込みに
    // 対する 2 世代目のバリアも、2 世代目自身の永続化完了後であれば正当。
    let two_generations_ok = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::BarrierRequested { generation: 2 },
        AckEvent::PersistedBeforeBarrier { generation: 2 },
        AckEvent::FlushAckSent { generation: 2 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&two_generations_ok),
        FlushAckVerdict::Ok,
        "2 世代目も自身の永続化完了後であれば正当と判定できていない"
    );

    // 仕様違反の再現 (1): 1 世代目の永続化完了を、2 世代目の FLUSH ACK の
    // 根拠として使い回す回帰（世代の使い捨て漏れ。単一の真偽値
    // `persisted` を使う旧実装はこれを検出できなかった）。
    let stale_persistence_reused = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::BarrierRequested { generation: 2 },
        AckEvent::FlushAckSent { generation: 2 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&stale_persistence_reused),
        FlushAckVerdict::PrematureFlushAck { generation: 2 },
        "1 世代目の永続化完了を 2 世代目の FLUSH ACK の根拠として\
            使い回す回帰をマッチャが検出できていない"
    );

    // 仕様違反の再現 (2): バリア要求はあるが永続化イベントを伴わずに
    // FLUSH ACK を送出する回帰（PoC-12 型の失敗モード）。
    let missing_persistence = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&missing_persistence),
        FlushAckVerdict::PrematureFlushAck { generation: 1 },
        "永続化イベントを伴わない FLUSH ACK 送出をマッチャが検出できていない"
    );

    // 仕様違反の再現 (3): 永続化完了が FLUSH ACK 送出より後に記録される
    // 回帰（返却順序の違反）。
    let out_of_order = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&out_of_order),
        FlushAckVerdict::PrematureFlushAck { generation: 1 },
        "永続化完了より先に FLUSH ACK を送出する順序違反をマッチャが検出できていない"
    );
}

/// マッチャが TASK-15（IO-1・IO-2）の「通常の書き込み ACK と FLUSH ACK の
/// 種別の違い」を区別して照合できることを確認する（REPAIR-12。Codex
/// レビュー指摘・2 巡目: 旧 `AckEvent` は永続化完了と FLUSH ACK の 2 種
/// しか持たず、通常の書き込み ACK を表現できなかったため、両者を取り
/// 違える実装があっても検出できなかった）。
#[test]
fn repair_12_scaffold_matcher_distinguishes_write_ack_from_flush_ack() {
    // 仕様どおり: 通常の書き込み ACK は永続化完了を待たずに返してよい
    // （IO-1・IO-2 の契約差）。その後バリア要求・永続化完了・FLUSH ACK が
    // 続く列は正当と判定される。
    let write_ack_before_persistence = [
        AckEvent::WriteAckSent { generation: 1 },
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&write_ack_before_persistence),
        FlushAckVerdict::Ok,
        "永続化完了前の通常書き込み ACK を不当に拒否している\
            （IO-1・IO-2 は通常 ACK に永続化完了を要求しない）"
    );

    // 仕様違反の再現 (1): バリア要求に対して通常の書き込み ACK しか
    // 返さない取り違え（FLUSH ACK を返すべき場面で通常 ACK を返す）。
    let write_ack_instead_of_flush_ack = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::WriteAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&write_ack_instead_of_flush_ack),
        FlushAckVerdict::NoFlushAck,
        "バリア要求に対して通常書き込み ACK しか返らない取り違えを\
            マッチャが検出できていない"
    );

    // 仕様違反の再現 (2): バリア要求が無いのに FLUSH ACK を返す取り違え
    // （通常 ACK を返すべき場面で FLUSH ACK を返す。方向が逆の取り違え）。
    let flush_ack_without_barrier = [
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&flush_ack_without_barrier),
        FlushAckVerdict::FlushAckWithoutBarrier { generation: 1 },
        "バリア要求を伴わない FLUSH ACK 送出をマッチャが検出できていない"
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
