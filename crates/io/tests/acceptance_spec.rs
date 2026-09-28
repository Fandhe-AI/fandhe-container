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
//! 照合できるものに限った。この表を正とし、[`ACCEPTANCE_TARGETS`] は表と
//! 同じ内容を Rust のデータとして持つ。両者が食い違っていないことは
//! [`repair_12_acceptance_targets_are_listed`] が本ファイル自身のソースから
//! この表を解析して機械照合する（表だけの書き換えでも検出できる）。
//!
//! | TASK    | ビヘイビア  | 機械照合する出力仕様                                                                  | 照合方法            | 状態                          |
//! | ------- | ----------- | -------------------------------------------------------------------------------------- | ------------------- | ----------------------------- |
//! | TASK-13 | IO-1        | バッチサイズの既定値 64 が設定の実効値に反映されること（`batch_size=<N>`）             | 構造化 assert       | 未接続（TASK-13 で接続）      |
//! | TASK-15 | IO-2        | 書き込み ACK と FLUSH ACK が別種別として区別され、FLUSH ACK はバリア以前の書き込みの永続化後にのみ返ること（書き込み ACK（IO-1）自体の対応照合は本照合器の対象外で、TASK-12・13 の結合試験が担う） | 構造化 assert | 未接続（TASK-11 / TASK-15 で接続） |
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

/// TASK-91.1 で選定した対象仕様の一覧。モジュールドキュメントの表と同じ
/// 内容を機械照合できる形で保持したもの（各フィールドは表の対応する列と
/// 文字単位で一致させる。[`repair_12_acceptance_targets_are_listed`] が
/// 本ファイル自身のソースから表を解析して突き合わせるため、フィールドを
/// 表の文言から乖離させると当該テストが fail する）。
const ACCEPTANCE_TARGETS: &[AcceptanceTarget] = &[
    AcceptanceTarget {
        task: "TASK-13",
        behavior: "IO-1",
        spec_fact: "バッチサイズの既定値 64 が設定の実効値に反映されること（`batch_size=<N>`）",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-13",
        },
    },
    AcceptanceTarget {
        task: "TASK-15",
        behavior: "IO-2",
        spec_fact: "書き込み ACK と FLUSH ACK が別種別として区別され、\
            FLUSH ACK はバリア以前の書き込みの永続化後にのみ返ること\
            （書き込み ACK（IO-1）自体の対応照合は本照合器の対象外で、\
            TASK-12・13 の結合試験が担う）",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-11 / TASK-15",
        },
    },
    AcceptanceTarget {
        task: "TASK-16",
        behavior: "IO-10",
        spec_fact: "未フラッシュ滞留量の上限が設定可能で、\
            上限到達時に自動フラッシュが発行されること（`flush_every=<N>`）",
        method: MatchMethod::StructuredAssert,
        status: TargetStatus::NotWired {
            planned_task: "TASK-16",
        },
    },
    AcceptanceTarget {
        task: "TASK-17",
        behavior: "IO-2",
        spec_fact: "`docs/api/io-barrier.md` に ACK / FLUSH ACK の永続化保証の違いが明記されていること",
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

/// [`find_value`] の照合結果。
///
/// 単純に `Option<&str>` を返すと「最初に一致した値だけを採用する」実装に
/// なり、将来の実出力に `batch_size=64 batch_size=32` のような矛盾する
/// 値が重複して出力されても、期待値が先に現れていれば照合を通過してしまう
/// （Codex レビュー指摘。PoC-12 型の「ビルド・回帰は通るが仕様未達」失敗
/// モードの一種）。対象キーの出現回数を欠落・単一・重複の 3 通りに区別し、
/// 重複時は両方の値を保持したまま `Duplicate` として返すことで、
/// [coding-rust] の「期待値は具体値で書く」方針に沿って重複した値の内容
/// ごと照合失敗させられるようにする。
///
/// [coding-rust]: ../../../.claude/rules/coding-rust.md
#[derive(Debug, Clone, PartialEq, Eq)]
enum FindValueOutcome<'a> {
    /// 対象キーがちょうど 1 回だけ現れ、その値を採用できた。
    Found(&'a str),
    /// 対象キーが 1 回も現れなかった（PoC-12 の要求フィールド欠落と同じ
    /// 失敗モード）。
    Missing,
    /// 対象キーが 2 回以上現れた（矛盾する値が出力に混在している可能性が
    /// あるため、どちらか一方を無条件で採用せず失敗として扱う）。
    /// 出現順にすべての値を保持する。
    Duplicate(Vec<&'a str>),
}

/// `parse_key_values` の結果から指定した `key` の値を探す。
///
/// 対象キーの出現回数によって [`FindValueOutcome`] の 3 通りの結果を返す。
/// 呼び出し元は `Found` 以外を照合失敗として扱うこと（欠落・重複のいずれも
/// 期待する具体値と一致したとはみなさない）。
fn find_value<'a>(line: &'a str, key: &str) -> FindValueOutcome<'a> {
    let matches: Vec<&'a str> = parse_key_values(line)
        .into_iter()
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .collect();

    if let [value] = matches.as_slice() {
        return FindValueOutcome::Found(value);
    }
    if matches.is_empty() {
        FindValueOutcome::Missing
    } else {
        FindValueOutcome::Duplicate(matches)
    }
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

    assert_eq!(
        find_value(sample, "batch_size"),
        FindValueOutcome::Found("64")
    );
    assert_eq!(
        find_value(sample, "flush_every"),
        FindValueOutcome::Found("Some(20)")
    );
    assert_eq!(
        find_value(sample, "flush_acks"),
        FindValueOutcome::Found("10")
    );
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
        FindValueOutcome::Missing,
        "flush_every が出力に含まれないことをマッチャが検出できていない"
    );
    // batch_size 自体は存在するため、マッチャが全フィールドを一律に
    // 見失っているわけではないことも合わせて確認する。
    assert_eq!(
        find_value(sample_missing_flush_every, "batch_size"),
        FindValueOutcome::Found("64")
    );
}

/// マッチャが、対象キーが重複して出現する出力を「最初に一致した値」で
/// 通過させず、重複そのものを検出できることを確認する（Codex レビュー
/// 指摘: `find_value` が最初に一致した値だけを返す実装のままだと、将来の
/// 実出力に `batch_size=64 batch_size=32` のような矛盾する値が含まれても
/// 期待値が先に現れていれば照合を通過してしまう）。
#[test]
fn repair_12_scaffold_matcher_rejects_duplicate_key_occurrence() {
    let sample_duplicate_batch_size = "batch: n=200 batch_size=64 batch_size=32 flush_acks=10";

    assert_eq!(
        find_value(sample_duplicate_batch_size, "batch_size"),
        FindValueOutcome::Duplicate(vec!["64", "32"]),
        "batch_size の重複出現をマッチャが検出できていない\
            （最初に一致した値だけを採用する実装への回帰）"
    );

    // 重複していない flush_acks は従来どおり単一の値として照合できる
    // ことも合わせて確認する（重複検出の追加で正常系を壊していないか）。
    assert_eq!(
        find_value(sample_duplicate_batch_size, "flush_acks"),
        FindValueOutcome::Found("10")
    );
}

/// 本ファイル自身のソース（コンパイル時に埋め込む）。
///
/// [`parse_doc_table`] がこの文字列からモジュールドキュメントの表
/// （本ファイル冒頭の `//!` コメント内）を解析し、[`ACCEPTANCE_TARGETS`]
/// と突き合わせる（Codex レビュー指摘・4 巡目: 表と同じ内容を複製した
/// Rust 定数同士を比較するだけでは、表だけを書き換えても検出できない。
/// 表そのものを解析して比較する）。`include_str!` は自ファイルを対象と
/// するため、`docs/spec` を含む外部ファイルへは一切アクセスしない。
const SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/acceptance_spec.rs"
));

/// [`parse_doc_table`] が抽出した、モジュールドキュメントの表 1 行分。
///
/// フィールドは表の列（TASK・ビヘイビア・機械照合する出力仕様・照合方法・
/// 状態）にそれぞれ対応する。`status` 列は `未接続（<planned_task> で
/// 接続）` / `未接続（<planned_task> で文書作成後に接続）` の形式を前提に
/// `planned_task` 部分だけを取り出す（現時点で表に現れる状態は `NotWired`
/// のみのため）。
struct DocTableRow<'a> {
    task: &'a str,
    behavior: &'a str,
    spec_fact: &'a str,
    method: MatchMethod,
    planned_task: &'a str,
}

/// `source` からモジュールドキュメントの表の行（`//! | TASK-... | ... |`
/// の形式）を抽出する。
///
/// 呼び出し元は [`repair_12_acceptance_targets_are_listed`]。ヘッダ行・
/// 区切り行（`| ---`）・表以外の `//!` 行・本文中のその他の記述は無視する。
/// 表の書式（列数・列の文言）が想定と異なる行を見つけた場合は、`unwrap`
/// 等で panic させず、どの行のどの列が想定と違うかを含む `Err(String)` を
/// 返す（本ファイル自身の整形式チェックであり外部入力ではないが、
/// [coding-rust] の「明確な失敗メッセージ」の方針に倣う）。
///
/// [coding-rust]: ../../../.claude/rules/coding-rust.md
fn parse_doc_table(source: &str) -> Result<Vec<DocTableRow<'_>>, String> {
    let mut rows = Vec::new();

    for line in source.lines() {
        let Some(content) = line.trim_start().strip_prefix("//!") else {
            continue;
        };
        let content = content.trim();
        if !content.starts_with("| TASK-") {
            continue;
        }

        let columns: Vec<&str> = content
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let (task, behavior, spec_fact, method_text, status_text) = match columns.as_slice() {
            [task, behavior, spec_fact, method_text, status_text] => {
                (*task, *behavior, *spec_fact, *method_text, *status_text)
            }
            other => {
                return Err(format!(
                    "表の行の列数が想定（5 列）と異なる（{} 列）: {content:?}",
                    other.len()
                ));
            }
        };

        let method = match method_text {
            "構造化 assert" => MatchMethod::StructuredAssert,
            "文字列パターン照合" => MatchMethod::StringPattern,
            other => return Err(format!("未知の照合方法列: {other:?}")),
        };

        let inner = status_text
            .strip_prefix("未接続（")
            .and_then(|rest| rest.strip_suffix('）'))
            .ok_or_else(|| format!("未接続の状態列の形式が想定と異なる: {status_text:?}"))?;
        let planned_task = inner
            .split(" で")
            .next()
            .ok_or_else(|| format!("状態列から planned_task を抽出できない: {status_text:?}"))?;

        rows.push(DocTableRow {
            task,
            behavior,
            spec_fact,
            method,
            planned_task,
        });
    }

    Ok(rows)
}

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
    ///
    /// 本照合器（[`flush_ack_follows_persistence`]）は `WriteAckSent` を
    /// 「FLUSH ACK と取り違えていないか」の判定にのみ使い、`generation` を
    /// 含めて無条件で許容する（Codex レビュー指摘・5 巡目 P2: 通常の
    /// 書き込み要求と、それに対応する書き込み ACK が 1 対 1 で発行されて
    /// いるかという IO-1 自体の対応照合は、本照合器の保証範囲に含まない。
    /// その照合は TASK-12・13 の結合試験が担う）。
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
    /// 同一世代の永続化完了後に送出された）。バリア要求した全世代について
    /// 対応する FLUSH ACK が揃っている場合にのみこの verdict になる
    /// （Codex レビュー指摘・3 巡目: 一部世代だけ判定して他世代の応答欠落を
    /// 見逃さないよう、全世代を走査し終えてから確定する）。
    Ok,
    /// FLUSH ACK が一度も送出されなかった（判定対象がない）、または
    /// `BarrierRequested` した世代のうち少なくとも 1 つに対応する
    /// `FlushAckSent` が最後まで現れなかった（バリア要求に対して通常 ACK
    /// しか返らない取り違えもここに含まれる）。
    NoFlushAck,
    /// `generation` に対応する永続化完了（同一世代の `BarrierRequested`
    /// より後に記録された `PersistedBeforeBarrier`）より前に FLUSH ACK を
    /// 送出した（IO-2 のバリア以前の書き込み永続化契約への違反。バリア
    /// 要求より前に記録された古い永続化通知の使い回しもここに含まれる）。
    PrematureFlushAck { generation: u32 },
    /// 対応する `BarrierRequested` が無いのに FLUSH ACK を送出した
    /// （通常の書き込み ACK を返すべき場面で FLUSH ACK を返す取り違え）。
    FlushAckWithoutBarrier { generation: u32 },
    /// 既に `BarrierRequested` 済みの世代番号に対し、再度 `BarrierRequested`
    /// を観測した（世代番号の再利用。Codex レビュー指摘・4 巡目: 世代番号を
    /// 使い捨てにせず再利用すると、`BarrierRequested(1) →
    /// PersistedBeforeBarrier(1) → FlushAckSent(1) → BarrierRequested(1) →
    /// FlushAckSent(1)` のように、1 回目のバリアで得た永続化完了フラグを
    /// 2 回目のバリアの根拠として使い回せてしまい、IO-2 の「各バリア以前に
    /// 受理した書き込みの永続化完了」を世代ごとに満たしていなくても `Ok`
    /// と誤判定する。同一世代番号の 2 度目の `BarrierRequested` は、1 回目が
    /// 未完了か完了済みかによらず違反として拒否する）。
    GenerationReused { generation: u32 },
    /// 既に `FlushAckSent` を送出済みの世代番号に対して、再度
    /// `FlushAckSent` を観測した（Codex レビュー指摘・5 巡目 P1: 旧実装は
    /// `FlushAckSent` の処理を `flush_ack_sent` を再び `true` にするだけの
    /// 冪等な代入として扱っていたため、`BarrierRequested(1) →
    /// PersistedBeforeBarrier(1) → FlushAckSent(1) → FlushAckSent(1)` が
    /// `Ok` と誤判定されていた。1 回のバリア要求に対して複数回 FLUSH ACK を
    /// 返す異常はクライアント側の二重処理・二重の永続化完了通知を招くため、
    /// `GenerationReused`〔バリア要求の再利用〕とは別の専用の違反種別として
    /// 拒否する）。
    DuplicateFlushAck { generation: u32 },
}

/// 世代ごとの `flush_ack_follows_persistence` 内部状態。
///
/// - `requested`: この世代の `BarrierRequested` を観測済みか
/// - `persisted_after_request`: `requested` になった後に観測した
///   `PersistedBeforeBarrier` があるか（`requested` より前に記録された
///   ものは数えない。Codex レビュー指摘・3 巡目: バリア要求前の永続化
///   通知を後続のバリアの根拠として使い回す取り違えを検出するため）
/// - `flush_ack_sent`: この世代の `FlushAckSent` を観測済みか
#[derive(Debug, Clone, Copy, Default)]
struct GenerationState {
    requested: bool,
    persisted_after_request: bool,
    flush_ack_sent: bool,
}

/// `generation` に対応する状態を `states` から探し、無ければ `order` に
/// 記録した上で既定状態を追加する（世代の初出順を保つための補助）。
fn generation_state_mut<'a>(
    states: &'a mut Vec<(u32, GenerationState)>,
    order: &mut Vec<u32>,
    generation: u32,
) -> &'a mut GenerationState {
    if !states.iter().any(|(g, _)| *g == generation) {
        order.push(generation);
        states.push((generation, GenerationState::default()));
    }
    &mut states
        .iter_mut()
        .find(|(g, _)| *g == generation)
        .expect("直前に存在を保証したエントリが見つからない")
        .1
}

/// `events` を先頭から走査し、`BarrierRequested` した各世代について、
/// 同じ世代の `FlushAckSent` が「バリア要求後に記録された同世代の
/// `PersistedBeforeBarrier`」より後に、かつちょうど 1 回だけ送出されて
/// いることを世代ごとに個別照合する。
///
/// # 受理する状態機械（`BarrierRequested` を観測した世代ごと）
///
/// 本照合器が `Ok` と判定するのは、`events` に現れる `BarrierRequested`
/// を伴う各世代について、以下の順序をちょうど 1 回ずつ満たす場合に限る:
///
/// 1. `BarrierRequested { generation }` を 1 回観測する
/// 2. その後、同じ `generation` の `PersistedBeforeBarrier` を 1 回以上
///    観測する
/// 3. その後、同じ `generation` の `FlushAckSent` をちょうど 1 回観測する
///
/// この順序に違反する系列（重複・順序逆転・未要求世代への FLUSH ACK・
/// バリア要求前後の永続化通知の使い回し）はすべて拒否する。各違反パターンと
/// 対応する verdict は以下のとおり:
///
/// - 世代ごとに個別照合するため、他世代の永続化完了（過去に完了した
///   世代の使い回し）では通らない（世代の使い捨て漏れの検出。
///   [`FlushAckVerdict::PrematureFlushAck`]）
/// - `PersistedBeforeBarrier` は同世代の `BarrierRequested` より後に
///   記録されたものだけを「その世代の FLUSH ACK の根拠」として数える
///   （Codex レビュー指摘・3 巡目: バリア要求より前の古い永続化通知を
///   使い回す取り違えの検出。IO-2 はバリア要求以降の永続化完了を保証と
///   するため、要求前の通知では保証を満たさない。
///   [`FlushAckVerdict::PrematureFlushAck`]）
/// - `WriteAckSent` は永続化完了の有無を問わず許容する（IO-1・IO-2 の
///   契約差: 通常 ACK は永続化完了を待たずに返してよい。書き込み要求と
///   書き込み ACK の対応そのものの照合は本照合器の対象外で、TASK-12・13
///   の結合試験が担う ─ [`AckEvent::WriteAckSent`] のドキュメントを参照）
/// - 同一の世代番号に対する 2 度目の `BarrierRequested` は
///   [`FlushAckVerdict::GenerationReused`] として即座に拒否する（Codex
///   レビュー指摘・4 巡目: 世代番号を使い捨てにしないと、1 回目のバリアの
///   永続化完了フラグが 2 回目のバリアの FLUSH ACK の根拠として使い回され、
///   IO-2 の世代ごとの永続化完了保証を満たさないまま `Ok` と誤判定する）
/// - 既に `FlushAckSent` を送出済みの世代番号への 2 度目の `FlushAckSent`
///   は [`FlushAckVerdict::DuplicateFlushAck`] として即座に拒否する
///   （Codex レビュー指摘・5 巡目 P1: `BarrierRequested(1) →
///   PersistedBeforeBarrier(1) → FlushAckSent(1) → FlushAckSent(1)` の
///   ように、1 回の要求に対して複数回 FLUSH ACK を返す異常を見逃さない）
/// - `BarrierRequested` した世代のうち 1 つでも `FlushAckSent` が最後まで
///   現れなければ [`FlushAckVerdict::NoFlushAck`] を返す（Codex レビュー
///   指摘・3 巡目: 従来は最後に処理した世代の判定結果で上書きされ、他の
///   世代の応答欠落を見逃していた。全世代を走査し終えてから確定する）
///
/// # 無視する入力（違反として拒否せず、`Ok` の根拠にもしない）
///
/// IO-2 が制約するのは FLUSH ACK の送出条件（バリア以前の書き込みの
/// 永続化完了後にのみ返すこと）であり、バックグラウンドの永続化完了
/// 通知そのものの発生タイミングは制約しない。そのため以下は違反として
/// 拒否しない（Codex レビュー指摘・5 巡目 P1 の追加確認: 状態機械の
/// 説明を「ちょうど 1 回ずつ」と書いたことで、これらの通知が実際には
/// 無視されている実装との乖離が生じないよう明記する）:
///
/// - 一度も `BarrierRequested` を観測していない世代の `PersistedBeforeBarrier`
///   （バックグラウンドの fsync 完了。まだバリア要求が来ていないだけで
///   不正ではない）
/// - 同じ世代の `FlushAckSent` より後に記録された `PersistedBeforeBarrier`
///   （次のバリアに備えた継続的な永続化。この世代の判定には影響しない）
/// - `WriteAckSent`（`generation` を問わず何回現れても判定に影響しない）
fn flush_ack_follows_persistence(events: &[AckEvent]) -> FlushAckVerdict {
    let mut order: Vec<u32> = Vec::new();
    let mut states: Vec<(u32, GenerationState)> = Vec::new();

    for event in events {
        match event {
            AckEvent::BarrierRequested { generation } => {
                let state = generation_state_mut(&mut states, &mut order, *generation);
                if state.requested {
                    return FlushAckVerdict::GenerationReused {
                        generation: *generation,
                    };
                }
                state.requested = true;
            }
            AckEvent::PersistedBeforeBarrier { generation } => {
                let state = generation_state_mut(&mut states, &mut order, *generation);
                // バリア要求より前に記録された永続化通知は、この世代の
                // FLUSH ACK の根拠にしない（要求前の通知の使い回し防止）。
                if state.requested {
                    state.persisted_after_request = true;
                }
            }
            AckEvent::WriteAckSent { .. } => {}
            AckEvent::FlushAckSent { generation } => {
                let state = generation_state_mut(&mut states, &mut order, *generation);
                if !state.requested {
                    return FlushAckVerdict::FlushAckWithoutBarrier {
                        generation: *generation,
                    };
                }
                if !state.persisted_after_request {
                    return FlushAckVerdict::PrematureFlushAck {
                        generation: *generation,
                    };
                }
                if state.flush_ack_sent {
                    return FlushAckVerdict::DuplicateFlushAck {
                        generation: *generation,
                    };
                }
                state.flush_ack_sent = true;
            }
        }
    }

    let requested_generations: Vec<u32> = order
        .iter()
        .copied()
        .filter(|generation| {
            states
                .iter()
                .find(|(g, _)| g == generation)
                .is_some_and(|(_, state)| state.requested)
        })
        .collect();

    if requested_generations.is_empty() {
        return FlushAckVerdict::NoFlushAck;
    }

    let all_acked = requested_generations.iter().all(|generation| {
        states
            .iter()
            .find(|(g, _)| g == generation)
            .is_some_and(|(_, state)| state.flush_ack_sent)
    });

    if all_acked {
        FlushAckVerdict::Ok
    } else {
        FlushAckVerdict::NoFlushAck
    }
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

/// マッチャが、一部の世代だけ FLUSH ACK が揃っていても他の世代の応答
/// 欠落を見逃さないことを確認する（REPAIR-12・IO-2。Codex レビュー指摘・
/// 3 巡目 #1: 旧実装は最後に処理した `FlushAckSent` の判定結果で
/// `verdict` を上書きしていたため、1 世代目が仕様どおりでも 2 世代目の
/// バリア要求に応答が無いまま `Ok` になっていた）。
#[test]
fn repair_12_scaffold_matcher_detects_missing_flush_ack_for_later_barrier() {
    // 1 世代目は仕様どおり（バリア要求 → 永続化完了 → FLUSH ACK）。
    // 2 世代目はバリア要求のみで、対応する FLUSH ACK が最後まで現れない。
    let second_barrier_never_acked = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::BarrierRequested { generation: 2 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&second_barrier_never_acked),
        FlushAckVerdict::NoFlushAck,
        "1 世代目が仕様どおりでも、2 世代目のバリア要求に対する \
            FLUSH ACK 欠落を見逃して Ok と判定してしまっている"
    );
}

/// マッチャが、バリア要求より前に記録された永続化通知を、そのバリアの
/// FLUSH ACK の根拠として使い回せないことを確認する（REPAIR-12・IO-2。
/// Codex レビュー指摘・3 巡目 #2: 旧実装は `persisted_generations` に
/// 世代番号が含まれるかしか見ておらず、`PersistedBeforeBarrier` が
/// `BarrierRequested` より前後どちらに記録されたかを区別できなかった）。
#[test]
fn repair_12_scaffold_matcher_rejects_persistence_notification_before_barrier_request() {
    // バリア要求より前に届いた（古い）永続化通知を使い回すパターン:
    // PersistedBeforeBarrier(1) → BarrierRequested(1) → FlushAckSent(1)。
    // IO-2 が保証するのは「バリア要求以降の永続化完了」であり、要求前の
    // 通知はこの世代のバリアに対する保証を満たさない。
    let persisted_before_request = [
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&persisted_before_request),
        FlushAckVerdict::PrematureFlushAck { generation: 1 },
        "バリア要求より前の永続化通知を FLUSH ACK の根拠として \
            使い回す取り違えをマッチャが検出できていない"
    );
}

/// マッチャが、既に `FlushAckSent` まで完了した世代番号の `BarrierRequested`
/// 再利用を検出できることを確認する（REPAIR-12・IO-2。Codex レビュー指摘・
/// 4 巡目: 1 回目のバリアの永続化完了フラグが世代を跨いでリセットされない
/// ため、`BarrierRequested(1) → PersistedBeforeBarrier(1) →
/// FlushAckSent(1) → BarrierRequested(1) → FlushAckSent(1)` が誤って `Ok`
/// と判定されていた。後半のバリアには新たな永続化完了が無いため、この列は
/// IO-2 の「各バリア以前に受理した書き込みの永続化完了」を満たさない）。
#[test]
fn repair_12_scaffold_matcher_rejects_generation_reuse_after_ack() {
    let generation_reused_after_ack = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&generation_reused_after_ack),
        FlushAckVerdict::GenerationReused { generation: 1 },
        "FLUSH ACK 済みの世代番号を再利用したバリア要求をマッチャが\
            検出できていない（1 回目の永続化完了を 2 回目の根拠に使い回す回帰）"
    );
}

/// マッチャが、まだ `FlushAckSent` が届いていない未完了の世代番号に対する
/// `BarrierRequested` の重複も検出できることを確認する（REPAIR-12・IO-2。
/// ACK 完了の有無によらず、同一世代番号の 2 度目のバリア要求自体を
/// 拒否対象とする）。
#[test]
fn repair_12_scaffold_matcher_rejects_duplicate_barrier_request_before_ack() {
    let duplicate_barrier_before_ack = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::BarrierRequested { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&duplicate_barrier_before_ack),
        FlushAckVerdict::GenerationReused { generation: 1 },
        "未完了の世代番号への重複バリア要求をマッチャが検出できていない"
    );
}

/// マッチャが、既に `FlushAckSent` まで完了した世代番号への 2 度目の
/// `FlushAckSent`（FLUSH ACK の重複送出）を検出できることを確認する
/// （REPAIR-12・IO-2。Codex レビュー指摘・5 巡目 P1: `FlushAckSent` の処理が
/// `flush_ack_sent` を再び `true` にするだけだったため、
/// `BarrierRequested(1) → PersistedBeforeBarrier(1) → FlushAckSent(1) →
/// FlushAckSent(1)` が `Ok` となり、1 回の要求に対する複数回の FLUSH ACK
/// 送出という異常を見逃していた）。
#[test]
fn repair_12_scaffold_matcher_rejects_duplicate_flush_ack() {
    let duplicate_flush_ack = [
        AckEvent::BarrierRequested { generation: 1 },
        AckEvent::PersistedBeforeBarrier { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
        AckEvent::FlushAckSent { generation: 1 },
    ];
    assert_eq!(
        flush_ack_follows_persistence(&duplicate_flush_ack),
        FlushAckVerdict::DuplicateFlushAck { generation: 1 },
        "送出済みの世代番号への 2 度目の FlushAckSent（FLUSH ACK の \
            重複送出）をマッチャが検出できていない"
    );
}

/// [`flush_ack_follows_persistence`] のドキュメントコメントに明記した
/// 状態機械（各世代について: `BarrierRequested` 1 回 →
/// `PersistedBeforeBarrier` 1 回以上 → `FlushAckSent` 1 回、の順）を
/// 表駆動で網羅的に確認する（REPAIR-12・IO-2。Codex レビュー指摘・5 巡目:
/// 個別の回帰テストが増えるたびに規則の全体像が見えにくくなるのを防ぐため、
/// 受理する系列・拒否する系列（重複・順序逆転・未要求世代への ACK・
/// 未要求世代の永続化）を 1 箇所の表にまとめる）。
#[test]
fn repair_12_flush_ack_state_machine_table() {
    let cases: &[(&str, &[AckEvent], FlushAckVerdict)] = &[
        (
            "単一世代・仕様どおりの順序",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::Ok,
        ),
        (
            "複数世代・各世代とも仕様どおりの順序",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::BarrierRequested { generation: 2 },
                AckEvent::PersistedBeforeBarrier { generation: 2 },
                AckEvent::FlushAckSent { generation: 2 },
            ],
            FlushAckVerdict::Ok,
        ),
        (
            "通常書き込み ACK が混在しても仕様どおりと判定される",
            &[
                AckEvent::WriteAckSent { generation: 1 },
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::Ok,
        ),
        (
            "永続化を伴わない FLUSH ACK（未接続の永続化通知）",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::PrematureFlushAck { generation: 1 },
        ),
        (
            "永続化通知がバリア要求より前（要求前の通知の使い回し）",
            &[
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::PrematureFlushAck { generation: 1 },
        ),
        (
            "他世代の永続化完了の使い回し（世代の使い捨て漏れ）",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::BarrierRequested { generation: 2 },
                AckEvent::FlushAckSent { generation: 2 },
            ],
            FlushAckVerdict::PrematureFlushAck { generation: 2 },
        ),
        (
            "永続化完了が FLUSH ACK 送出より後（順序逆転）",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
            ],
            FlushAckVerdict::PrematureFlushAck { generation: 1 },
        ),
        (
            "バリア要求を伴わない FLUSH ACK（未要求世代への ACK）",
            &[
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::FlushAckWithoutBarrier { generation: 1 },
        ),
        (
            "バリア要求に通常 ACK しか返らない（FLUSH ACK 欠落）",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::WriteAckSent { generation: 1 },
            ],
            FlushAckVerdict::NoFlushAck,
        ),
        (
            "後続世代のバリア要求に FLUSH ACK が最後まで現れない",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::BarrierRequested { generation: 2 },
            ],
            FlushAckVerdict::NoFlushAck,
        ),
        (
            "未完了の世代番号への重複バリア要求",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::BarrierRequested { generation: 1 },
            ],
            FlushAckVerdict::GenerationReused { generation: 1 },
        ),
        (
            "FLUSH ACK 済みの世代番号を再利用したバリア要求の重複",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::GenerationReused { generation: 1 },
        ),
        (
            "同一世代への FLUSH ACK の重複送出",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
            ],
            FlushAckVerdict::DuplicateFlushAck { generation: 1 },
        ),
        (
            "未要求世代の永続化通知は無視される（違反にも Ok の根拠にもならない）",
            &[AckEvent::PersistedBeforeBarrier { generation: 2 }],
            FlushAckVerdict::NoFlushAck,
        ),
        (
            "有効な世代 1 に、一度も要求されていない世代 2 の永続化通知が\
                混在しても、世代 1 の判定は影響を受けない",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 2 },
            ],
            FlushAckVerdict::Ok,
        ),
        (
            "FLUSH ACK 送出後に届いた同世代の永続化通知は無視される\
                （次のバリアに備えた継続的な永続化であり、この世代の \
                判定を覆さない）",
            &[
                AckEvent::BarrierRequested { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
                AckEvent::FlushAckSent { generation: 1 },
                AckEvent::PersistedBeforeBarrier { generation: 1 },
            ],
            FlushAckVerdict::Ok,
        ),
    ];

    for (description, events, expected) in cases {
        assert_eq!(
            flush_ack_follows_persistence(events),
            *expected,
            "系列 {description:?} の判定結果が状態機械の規則と一致しない: {events:?}"
        );
    }
}

/// 選定した対象仕様の一覧（[`ACCEPTANCE_TARGETS`]）が、モジュール
/// ドキュメントの表と一致する件数・内容を持つことを機械照合する
/// （TASK-91.1 の受け入れ条件「一覧化」を機械照合するテスト）。
///
/// 単純な複製定数同士の突き合わせでは表だけの書き換えを検出できない
/// （Codex レビュー指摘・4 巡目）ため、[`parse_doc_table`] で本ファイル
/// 自身のソースからモジュールドキュメントの表を実際に解析し、
/// [`ACCEPTANCE_TARGETS`] の全行を `task`・`behavior`・`spec_fact`・
/// `method`・`status`（`planned_task`）まで個別に照合する。
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

    let doc_rows = parse_doc_table(SOURCE)
        .expect("モジュールドキュメントの表の解析に失敗した（表の書式を確認する）");
    assert_eq!(
        ACCEPTANCE_TARGETS.len(),
        doc_rows.len(),
        "モジュールドキュメントの表の行数と ACCEPTANCE_TARGETS の件数が一致しない"
    );

    for (target, row) in ACCEPTANCE_TARGETS.iter().zip(doc_rows.iter()) {
        assert_eq!(target.task, row.task, "task の不一致（表 vs データ）");
        assert_eq!(
            target.behavior, row.behavior,
            "{}: behavior の不一致（表 vs データ）",
            target.task
        );
        assert_eq!(
            target.spec_fact, row.spec_fact,
            "{}: spec_fact の不一致（表 vs データ）",
            target.task
        );
        assert_eq!(
            target.method, row.method,
            "{}: method の不一致（表 vs データ）",
            target.task
        );
        let TargetStatus::NotWired { planned_task } = target.status;
        assert_eq!(
            planned_task, row.planned_task,
            "{}: status（planned_task）の不一致（表 vs データ）",
            target.task
        );
    }
}
