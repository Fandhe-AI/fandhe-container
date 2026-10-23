# 作成失敗で残った資源の観測と手動回収

`create_network` の失敗で bridge・nft テーブルが残ったときの見分け方と、所有を証明できない bridge（印を刻む前の失敗）を手で回収する手順。NET-1・NET-6・REPAIR-3・REPAIR-4・#2604。設計は [network-reclaim-persistence.md](../design/network-reclaim-persistence.md)。

## 自動で回収されるもの

所有トークンを刻んだ後の失敗（アドレス設定・up・nft テーブル作成）で残った bridge・テーブルは、請求書が `<状態ルート>/.cri/net/pending-reclaim/<名前>.claim` に残り、plugin を再起動しても、`delete_network`（RemovePodSandbox の再試行）で自動回収される。成功すると記録ファイルも自動で消える。手で消す必要はない。

## 自動回収されないもの

| 状況 | 理由 |
| ---- | ---- |
| 印を刻む前の失敗（`CreateBridge` の結果不明・ifindex の解決失敗・所有トークンの設定失敗）で残った bridge | 別名が空で所有を証明できない |
| 他者の同名資源が残っている | 自分のものと証明できない |
| 記録の書き込みに失敗した（`could not be persisted`）後に plugin が再起動した | 請求書を失った |
| 壊れた記録 | 復号できない（ファイルは消さずに残る） |

## 観測の方法

- `delete_network` の応答: `FailedPrecondition` の `manual reclaim required`、または `Internal` の `N resource(s) left behind`
- 記録ファイル: `ls <状態ルート>/.cri/net/pending-reclaim/`（残っていれば回収待ち）
- 記録器の失敗件数: `net.delete_network`（回収の失敗）と `net.reclaim_store_load`（起動時に読めなかった記録）
- plugin の stderr の `unusable pending-reclaim record(s)`（件数のみ。ファイル名は出ない）
- カーネルの資源: bridge は `ip -o link show type bridge`（名前は `fcbr` + 11 桁の 16 進で、ネットワーク名から決まる）。所有の印は行内の `alias fandhe-net:<名前>:...`。nft テーブルは `nft list tables`（`fandhe_net_<名前>`）

## 手順（別名の無い bridge）

1. 対象のネットワーク名を、`delete_network` のエラーを返した要求から確認する。bridge 名は `fcbr` + 名前の FNV-1a 64bit の下位 44bit の 11 桁 16 進で、`ip -o link show type bridge` で `alias` の無い行のうち、作成を試みた時刻の近いものを候補にする。**名前から確定できない候補は消さない**
2. 候補が自分の作成の残りであることを確かめる。slave（veth）が付いていないこと（`ip link show master <bridge名>` が空）、別名が空であること
3. ifindex を確認したうえで消す: `ip link delete <bridge名>`。nft テーブルが残っていれば、`fandhe_net_<名前>` であることを確認して `nft delete table ip fandhe_net_<名前>`
4. `delete_network` を再び呼ぶ。bridge が既に無いため回収は収束し、記録ファイルがあれば自動で消える（実カーネルでの確認は `bridge_owner_token_privileged` の (8)）
5. 壊れた記録の場合だけ、残っている資源を上の手順で確認・削除したうえで、記録ファイルを手で消し、plugin を再起動する（メモリ上の登録を捨てるため）

root と `CAP_NET_ADMIN` を要する操作で、ホストの他の bridge を巻き込まないよう、必ず名前を確認してから実行する。
