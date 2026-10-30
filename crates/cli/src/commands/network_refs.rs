//! `network rm` の使用中判定: 起動オプション文書(FCOPT1)が参照するユーザー定義ネットワークの走査
//! (#3529・NET-6・NET-9・CLI-1・ERR-1・REPAIR-5)。
//!
//! # 役割と呼び出し文脈
//!
//! `network::run_network_recorded` の `rm` が、定義ストアの `remove`(net。bridge のメンバー記録と孤児の記録を拒否する)
//! の前に呼ぶ。rootless のユーザー定義名(pasta 構成)のコンテナは `@networks/<name>/members/<id>` を持たないため、
//! net の `remove` だけでは参照中でも定義を消せてしまう。そこで状態ストアの記録を一覧し、コンテナごとの起動オプション
//! 文書(`@container-options/<id>`)の `network` が対象名を指すかを調べる(設計は `docs/design/network-wiring.md` D10)。
//! 走査は net のロックの外で行う(全体の排他ロックを持ったまま状態ストアを読まない)。
//!
//! # 判定表(1 記録ごと)
//!
//! | 状態記録の世代注釈 | 文書 | 判定 |
//! | ------------------ | ---- | ---- |
//! | なし(plugin-cri・旧形式) | 問わない | 参照なし |
//! | あり | 一致する世代で `network` が対象名 | 参照あり |
//! | あり | 一致する世代で別の名前・`none`・`host`・無し | 参照なし |
//! | あり | 無い・世代不一致・読めない・権限不正・壊れている | 判定不能(fail-closed。拒否) |
//!
//! 状態記録の無い文書(create の途中・失敗の残骸)は一覧に出ないため対象外。一覧と読み取りの間に delete された記録
//! (`get` が `NotFound`)は飛ばす。
//!
//! # 残余(REPAIR-3)
//!
//! create の定義照合から状態記録の作成までの間は記録が無いため、この間の `network rm` は防げない(その後の `start` の
//! 再照合が `FAILED_PRECONDITION` で拒否する。分離は弱まらない)。窓を閉じるには create の順序(D2)を変える必要がある。

use std::num::NonZeroU32;
use std::path::PathBuf;

use fandhe_container_core::traits::{
    ContainerId, ErrorCode, GetStateRequest, ListStateRequest, MAX_PAGE_SIZE, StateStore,
    TraitError,
};
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_mode::NetworkChoice;
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store::{
    self as options_store, GENERATION_ANNOTATION, select_document,
};

use super::create_start::run_options_io;
use super::list_logs::MAX_LIST_PAGES;

/// 走査の結果。真偽値にせず、判定不能を区別する(将来の拡張と fail-closed のため)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RefScan {
    /// 参照するコンテナも判定不能の記録も無い。
    Clear,
    /// 参照するコンテナが 1 件以上ある。`count` は計測用で、出力には出さない。
    Referenced { count: usize },
    /// 参照の有無を判定できない記録がある(文書の欠落・世代不一致・破損・権限不正)。
    Unverifiable,
}

/// 状態ストアの全記録を走査し、`name` を参照するコンテナを探す(純粋な判定。文書の読み取りは差し替え可能)。
///
/// 一覧の失敗とページ数の上限超過は `Err`。1 件ごとの判定不能は `RefScan::Unverifiable` に集約し、参照が 1 件でも
/// 見つかれば `Referenced` を優先する。
pub(super) fn find_references(
    store: &dyn StateStore,
    read_doc: &dyn Fn(&ContainerId) -> Result<Option<ContainerOptionsDocument>, TraitError>,
    name: &NetworkName,
) -> Result<RefScan, TraitError> {
    let page_size = NonZeroU32::new(MAX_PAGE_SIZE).unwrap_or(NonZeroU32::MIN);
    let mut req = ListStateRequest::new(page_size)?;
    let mut referenced = 0usize;
    let mut unverifiable = false;
    for _ in 0..MAX_LIST_PAGES {
        let page = store.list(&req)?;
        for record in page.records() {
            // 世代注釈の無い記録(plugin-cri・旧形式)は起動オプション文書を使わない。
            let Some(recorded) = record.annotations().get(GENERATION_ANNOTATION) else {
                continue;
            };
            let id = record.id();
            match read_doc(id).and_then(|doc| select_document(doc, Some(recorded))) {
                Ok(Some(doc)) => {
                    if doc_names_network(&doc, name) {
                        referenced += 1;
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    // 一覧と読み取りの間に delete された記録は対象から外す。それ以外は判定不能。
                    let gone = matches!(
                        store.get(&GetStateRequest::new(id.clone())),
                        Err(e) if e.code() == ErrorCode::NotFound
                    );
                    if !gone {
                        unverifiable = true;
                    }
                }
            }
        }
        match page.next_cursor() {
            Some(cursor) => req = req.with_cursor(cursor.clone()),
            None => {
                return Ok(if referenced > 0 {
                    RefScan::Referenced { count: referenced }
                } else if unverifiable {
                    RefScan::Unverifiable
                } else {
                    RefScan::Clear
                });
            }
        }
    }
    Err(TraitError::new(
        ErrorCode::Internal,
        "state listing did not terminate",
    ))
}

/// 文書の `network`(生の `--network`)が `name` を指すか。字面ではなく `NetworkChoice` で再検証して比べる。
fn doc_names_network(doc: &ContainerOptionsDocument, name: &NetworkName) -> bool {
    match doc.network().map(NetworkChoice::parse) {
        Some(Ok(NetworkChoice::Named(n))) => n == *name,
        _ => false,
    }
}

/// 本番の走査。文書の読み取りは `options_store::read`(`O_NOFOLLOW`・所有者・権限・サイズの検査つき)をそのまま使い、
/// 全体を期限つきの作業スレッドで待つ(REPAIR-5。応答しない状態ルートで `rm` が止まらない)。
pub(super) fn scan_bounded<S: StateStore + Send + 'static>(
    store: S,
    root: PathBuf,
    name: NetworkName,
) -> Result<RefScan, TraitError> {
    run_options_io(move || {
        let read = |id: &ContainerId| options_store::read(&root, id);
        find_references(&store, &read, &name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(network: Option<&str>) -> ContainerOptionsDocument {
        ContainerOptionsDocument::default()
            .with_network(network.map(str::to_owned), vec![], vec![])
            .expect("doc")
    }

    fn nn(s: &str) -> NetworkName {
        NetworkName::new(s).expect("name")
    }

    /// NET-6・NET-9・CLI-1(#3529): 文書の `network` は `NetworkChoice` で再検証して比べる(`none`・`host`・別名・無しは参照でない)。
    /// 状態ストアを使う走査の通し試験は `network.rs` の `net6_net9_cli1_3529_*`。
    #[test]
    fn net6_net9_cli1_3529_doc_names_network_uses_parsed_choice() {
        assert!(doc_names_network(&doc(Some("n1")), &nn("n1")));
        assert!(!doc_names_network(&doc(Some("n2")), &nn("n1")));
        assert!(!doc_names_network(&doc(Some("none")), &nn("n1")));
        assert!(!doc_names_network(&doc(Some("host")), &nn("n1")));
        assert!(!doc_names_network(&doc(None), &nn("n1")));
    }
}
