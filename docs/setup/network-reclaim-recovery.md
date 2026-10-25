# 作成失敗で残った資源の観測と手動回収

`create_network` の失敗で bridge・nft テーブルが残ったときの見分け方と、所有を証明できない bridge（印を刻む前の失敗）を手で回収する手順。NET-1・NET-6・REPAIR-3・REPAIR-4・#2604・#2681。設計は [network-reclaim-persistence.md](../design/network-reclaim-persistence.md)。

## 自動で回収されるもの

所有トークンを刻んだ後の失敗（アドレス設定・up・nft テーブル作成）で残った bridge・テーブルは、請求書が `<状態ルート>/.cri/net/pending-reclaim/<名前>.claim` に残り、plugin を再起動しても、`NetworkPlugin::delete_network` を呼ぶと自動回収される。成功すると記録ファイルも自動で消える。手で消す必要はない。

> 現状の制約（REPAIR-3・CRI-2・NET-1）: `NetworkPlugin` はまだ CRI の RPC（RemovePodSandbox 等）から呼ばれていない（`adapter.rs` の `network()`・`pod_network.rs`）。現時点で回収できる経路は `NetworkPlugin::delete_network` を直接呼ぶ場合だけである。CRI の RemovePodSandbox の再試行による自動回収は、後続の結線後に有効になる将来仕様で、それまでは下の手順で手動回収する。

## 自動回収されないもの

| 状況 | 理由 |
| ---- | ---- |
| 印を刻む前の失敗（`CreateBridge` の結果不明・ifindex の解決失敗・所有トークンの設定失敗）で残った bridge | 別名が空で所有を証明できない |
| 他者の同名資源が残っている | 自分のものと証明できない |
| 記録の書き込みに失敗した（`could not be persisted`）後に plugin が再起動した | 請求書を失った |
| 壊れた記録 | 復号できない（ファイルは消さずに残る） |

## 観測の方法

- `delete_network` の応答（直接呼び出し時）: `FailedPrecondition` の `manual reclaim required`、または `Internal` の `N resource(s) left behind`
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

## attach の取り残し（#2681）

`attach` の巻き戻しで取り残した host 側 veth・netns の pin は、請求書が `<状態ルート>/.cri/net/pending-reclaim/attach/<endpoint>.attach` に残る。`NetworkPlugin::detach`（同じコンテナ）または `delete_network`（ネットワーク）を呼ぶと、別名と master の一致を確かめた veth だけが自動回収され、成功すると記録ファイルも消える。

自動回収されないもの:

| 状況 | 理由 | 手順 |
| ---- | ---- | ---- |
| plugin の再起動後の netns の pin | `netns::unpin_path` はこのプロセスが作った pin しか外さない | 下の手順 |
| 別名の無い・別名の異なる veth、bridge に繋がっていない veth | 所有を証明できない | 手動で確認する（`ip -o link show` の `alias fandhe-net:<名前>:...` が `/ep/<endpoint>` で終わるものだけが対象） |
| 再起動後の bridge・nft テーブル | 作成に成功したネットワークの記録が永続化されていない（#1870 の後続） | 上の「手順（別名の無い bridge）」と同じ確認で手動回収する |
| 壊れた attach の記録 | 復号できない（ファイルは消えずに残り、同じコンテナの再 attach は `AlreadyExists` で拒否される） | 資源を確認・削除したうえで、記録ファイルを手で消して plugin を再起動する |

復元したネットワークで `delete_network` が `attach leftovers were reclaimed; the network itself was not tracked across the plugin restart and needs manual reclaim` の `FailedPrecondition` を返したら、取り残しの回収は済み、ネットワーク本体（bridge・nft テーブル）は手動回収が必要という意味である。

再起動後の pin の手動回収:

1. `<状態ルート>/.netns/<endpoint>` を確認する。`findmnt <パス>` で `nsfs` がマウントされているか見る
2. 他のプロセスがその netns を使っていないことを確かめる（`lsns -t net`）
3. `umount <パス>` でマウントを外し、空の通常ファイルになったことを確認して `rm <パス>`
4. 該当する `attach/<endpoint>.attach` を手で消す

root を要する操作で、ホストの他の netns を巻き込まないよう、必ずパスと endpoint を確認してから実行する。
