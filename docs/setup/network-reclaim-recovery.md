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

## 手順（所有トークンを持つ bridge）

作成に成功した bridge は `IFLA_IFALIAS` に所有トークン `fandhe-net:<名前>:...` を持つ。plugin の再起動後は作成に成功したネットワークの記録が無いため、自動回収されず（上の表）、「別名の無い bridge」の手順（別名が空であることを条件にする）はそのままでは使えない。次の手順で、別名が所有トークンであることを確認して手で回収する（NET-1・REPAIR-3・#2681）。

1. ネットワーク名から bridge 名（`fcbr` + 11 桁の 16 進）を求め、`ip -o link show type bridge` の該当行の `alias` が `fandhe-net:<名前>:` で始まることを確認する。**別名が別のネットワークのもの・空・不明なら消さない**（空なら上の「手順（別名の無い bridge）」）
2. 残っている接続を確認する: `ip link show master <bridge名>`。各 veth の `alias` は `<bridge の別名>/ep/<endpoint>/g/<世代>` の形である。attach の記録（`attach/<endpoint>.attach`）の `token` が bridge の別名と一致し、`endpoint` が veth の別名と一致する veth だけが、その取り残しの対象になる（`generation` が一致しない veth は別の接続のものなので消さない）
3. 生きているコンテナの veth が付いていないことを確かめてから、veth を消す: `ip link delete <host側veth名>`（名前は `VethNames` の導出で、`ip link show master` で確認する）。その後、nft テーブル `fandhe_net_<名前>` が自分のものであることを確認して `nft delete table ip fandhe_net_<名前>`、bridge を `ip link delete <bridge名>` で消す
4. 手順 3 で消した接続の `attach/<endpoint>.attach` と、ネットワークの記録ファイルがあれば手で消し、plugin を再起動してメモリ上の登録を捨てる

root と `CAP_NET_ADMIN` を要する操作で、ホストの他の bridge・veth を巻き込まないよう、名前・別名・ifindex を確認してから実行する。

## attach の取り残し（#2681）

`attach` の巻き戻しで取り残した host 側 veth・netns の pin は、請求書が `<状態ルート>/.cri/net/pending-reclaim/attach/<endpoint>.attach` に残る。`NetworkPlugin::detach`（同じコンテナ）または `delete_network`（ネットワーク）を呼ぶと、別名と master の一致を確かめた veth だけが自動回収され、成功すると記録ファイルも消える。

自動回収されないもの:

| 状況 | 理由 | 手順 |
| ---- | ---- | ---- |
| 照合できない netns の pin（旧いバイナリの請求書、置き場の `.owned/<endpoint>` の欠落・破損・不一致、`ns=-` のままの pin、none モードの pin） | 請求書と永続の所有記録とカーネルの実状態の三者が一致する pin しか外さない（一致する pin は plugin の再起動後も自動回収される。#2824） | 下の手順 |
| 別名の無い・別名の異なる veth、bridge に繋がっていない veth | 所有を証明できない | 手動で確認する（`ip -o link show` の `alias fandhe-net:<名前>:...` が `/ep/<endpoint>/g/<32 桁の 16 進>` で終わるものだけが対象。`<32 桁の 16 進>` は接続ごとの世代で、同じ endpoint の再接続では変わる。請求書の `generation` と一致しない veth は別の接続のもので消さない） |
| 再起動後の bridge・nft テーブル | 作成に成功したネットワークの記録が永続化されていない（#1870 の後続） | 下の「手順（所有トークンを持つ bridge）」 |
| アドレス・ポート予約と、ルールのハンドルを持てなかった DNAT ルール（quarantine）がカーネル側の回収後も残るとき（`detach` の失敗でルールのハンドルを請求書に載せられた DNAT ルールは、`detach` の回収が消す。#3285） | プロセス内の保持で、`detach` は `released only when the network is deleted` の `FailedPrecondition` を返し登録を保持する（同じコンテナの再 attach は拒否） | `delete_network` を呼ぶとネットワークごと解放される |
| 壊れた attach の記録 | 復号できない（ファイルは消えずに残り、同じコンテナの再 attach は `AlreadyExists` で拒否される） | 資源を確認・削除したうえで、記録ファイルを手で消して plugin を再起動する |

復元したネットワークで `delete_network` が `attach leftovers were reclaimed; the network itself was not tracked across the plugin restart and needs manual reclaim` の `FailedPrecondition` を返したら、取り残しの回収は済み、ネットワーク本体（bridge・nft テーブル）は手動回収が必要という意味である。

照合できない pin の手動回収:

1. `<状態ルート>/.netns/<endpoint>` を確認する。`findmnt <パス>` で `nsfs` がマウントされているか見る
2. 他のプロセスがその netns を使っていないことを確かめる（`lsns -t net`）
3. `umount <パス>` でマウントを外し、空の通常ファイルになったことを確認して `rm <パス>`。所有記録 `<状態ルート>/.netns/.owned/<endpoint>` が残っていれば `rm` してよい（残っていても次の作成が上書きし、無害）
4. 請求書に veth も含まれる場合は、請求書を手で消さない。pin の削除後に `NetworkPlugin::detach`（同じコンテナ）または `delete_network` を再試行して、残りの veth を自動回収させる
5. `ip -o link show` で、その endpoint の host veth（世代が請求書と一致するもの）と pin の両方が無いことを確認してから、`attach/<endpoint>.attach` を手で消す（請求書は全対象資源の回収を確認した後にだけ消す。veth が残ったまま消すと追跡できなくなり、再 attach が `AlreadyExists` になる）

root を要する操作で、ホストの他の netns を巻き込まないよう、必ずパスと endpoint を確認してから実行する。

## 未完了の操作の記録（`realized.intent`）と接続の意図記録（`members-intent`）（#3346）

状態ストア（`<状態ルート>/@networks/<名前>/`）の `realized.intent` は作成・削除のカーネル操作の途中で、`members-intent/<id>` は attach の途中で落ちたことを示す記録である。残っている間、`create` / `attach` / `detach` / `delete` は `network has an unreconciled operation`（`FailedPrecondition`）、`delete` は `network still has members` で拒否される。次の記録つきの操作の先頭、または `reconcile_network_recorded` が、所有トークンでカーネルを照合して自動で処理する。

自動で処理されるもの:

| 状況 | 処理 |
| ---- | ---- |
| create の途中で落ち、bridge とテーブルの両方がトークン一致で揃っている | `realized` へ昇格 |
| create の途中で落ち、片方だけトークン一致で残っている | 残った方を巻き戻して意図記録を消す |
| create の途中で落ち、カーネルに何も無い | 意図記録を消す |
| delete の途中で落ちた | 残った資源を巻き戻して `realized` と意図記録を消す（削除済みなら記録だけ消す） |
| 確定記録（`members/<id>`）と同一の `members-intent` | 意図記録だけ消す |
| 実体の無い `members-intent`（attach の請求書・host veth・pin が無く、DNAT が公開の記録で説明できる） | 消す（アドレスは次の操作で再び払い出せる） |

自動で処理されないもの（意図記録を残す。見分け方は `ReconcileReport` の `Unresolved` / `IntentKeep` と、上のエラー）:

| 状況 | 理由 |
| ---- | ---- |
| bridge の別名が空・他のトークン、テーブルの `NFTA_TABLE_USERDATA` が無い・不一致、カーネル照会の失敗 | 所有を証明できないため触れない |
| 巻き戻しの取り残し（`RollbackIncomplete`） | 次の照合が再試行する。繰り返すときは原因（権限・カーネルのエラー）を確認する |
| 旧形式（gateway の無い）の `realized.intent` | 復号が `DataLoss` で失敗する。下の手順で手動回収する |
| attach の請求書（`pending-reclaim/attach/<endpoint>`）が残る `members-intent`（`AttachClaim`） | quarantine または取り残しの追跡中。先に請求書の回収（上の「attach の取り残し」）を行う |
| host veth が残る（`VethPresent`）・判定不能（`VethUnproven`）、pin が残る（`PinPresent`）・判定不能（`PinUnknown`、置き場が与えられない場合を含む） | 実体が生きている可能性がある |
| DNAT の受け口が公開の記録で説明できない（`DnatUnaccounted`） | 残った DNAT がそのアドレスへ転送し続けうるため、再割り当てしない |

手動回収の手順:

1. 記録を読む: `<状態ルート>/@networks/<名前>/realized.intent` の `op`（create / delete）と `token`、`members-intent/<id>` の `address`・`token` を確認する
2. カーネルの状態を確認する: `ip -o link show` で bridge（`fcbr` + 11 桁の 16 進）の `alias` が記録の `token` と一致するか、`nft list table ip fandhe_net_<名前>` でテーブルが自分のものか、`ip -o link show master <bridge名>` で接続中の veth があるかを見る
3. 別名がトークンと一致する資源だけを消す: DNAT ルールがあれば `nft delete table ip fandhe_net_<名前>` でテーブルごと、bridge は `ip link delete <bridge名>`。別名が空・他のトークンの link は触らない
4. `members-intent/<id>` を消すのは、その endpoint の host veth と pin（`<netns置き場>/<endpoint>`）が無く、`nft list table ip fandhe_net_<名前>` に記録されていない DNAT（`dnat to <アドレス>` が意図記録のアドレスを指すもの）が残っていないことを確かめた後だけ。`pending-reclaim/attach/<endpoint>` が残る間は消さない
5. 資源を片付けたら、`realized.intent`（delete の途中なら `realized` も）と該当の `members-intent/<id>` を手で消し、plugin を再起動してメモリ上の登録を捨てる

root と `CAP_NET_ADMIN` を要する操作で、ホストの他の bridge・veth・テーブルを巻き込まないよう、名前・別名・ifindex を確認してから実行する。

## 記録の検証で拒否された detach の見分け方と、記録からの回収（#3347）

`detach_container_recorded` は、渡された `AttachedContainer` がメンバー記録と一致しないと、カーネル操作の前に拒否して渡されたコンテナを破棄する。破棄されるのは netns の fd だけで、netns の pin（nsfs のマウント）・host veth・DNAT ルールは残る。拒否の時点では渡されたコンテナと記録が同じものと証明できず、外すと別メンバーの pin を外しうるため、意図して外さない（fail-closed）。NET-1・NET-6・REPAIR-4・SEC-1。

見分け方（すべてが当てはまると、この拒否で資源が残っている）:

1. 戻り値が `RecordedError::Store` で、`message` が `container does not match the member record` / `network has an unreconciled operation` / `recorded nft handles belong to another boot or network namespace` / `network operations need the exclusive network lock` / `member not found` のいずれか
2. `<状態ルート>/…/@networks/<ネットワーク名>/members/<メンバー ID>` が残っている（`member not found` は無い）
3. `<netns_dir>/<endpoint>`（nsfs のマウント）と `<netns_dir>/.owned/<endpoint>` が残っている
4. host veth の別名が `<token>/ep/<endpoint>/g/<世代>` のまま残っている（`ip -o link show` の `alias`）

回収:

- メンバー記録が残っている場合は、`detach_member_recorded`（記録だけから行う入口）を同じメンバー ID で呼ぶ。排他ロック・世代の一致・回収待ちの請求書が無いことが前提で、`netns_dir` は接続時と同じ固定設定を渡す。失敗しても記録は残り、再実行で収束する。`pending-reclaim/attach` に同じ endpoint の請求書があるときは先に `reclaim_failed_attach` で回収する。公開に解除の印が残るときは先に `unpublish_port_recorded` を呼ぶ
- 記録が無い（`member not found`）・ホストの再起動をまたいで世代が違う場合は、記録から回収できない。「照合できない netns の pin の手動回収」の手順で、パスと endpoint を確認してから `umount` と `rm` を行い、veth は別名を確認して削除する
- 旧形式の記録（`pin` 項目が無い）は pin が残っていると `Unknown` の取り残しで断られる。手動回収の後に、同じ入口を再実行すると記録が消える

## 削除後に残る conntrack の NAT エントリ（NET-1・NET-10・NET-11・#3348）

`delete_network` は専用の nft テーブル（masquerade を含む）をテーブルごと消すが、カーネルの conntrack に既にあるエントリ（変換済みの接続の記録）は flush しない。masquerade の仕組みが conntrack を消すのは出口 interface の down・アドレス削除に紐づくエントリだけで、bridge の削除では消えない。残ったエントリはプロトコルごとのタイムアウト（`net.netfilter.nf_conntrack_*_timeout` の sysctl）まで生きる。

- 影響: 同じサブネット・アドレスでネットワークを作り直した直後、残ったエントリに一致する通信が古い変換のまま扱われうる。NET-10 の診断で案内する前提である
- 観測: `conntrack -L -s <サブネット>`（conntrack-tools）。モジュールの構成によっては `/proc/net/nf_conntrack`
- 手動の消し方: `conntrack -D -s <サブネット>`。root と `CAP_NET_ADMIN` が要る。他のコンテナ基盤が同じホストにあるときは、そのエントリを巻き込まないようサブネットを確かめてから実行する
- 本製品は conntrack を自動では flush しない（現状の範囲。REPAIR-3）。実機での確認は行っていない（#1626・人間担当）
