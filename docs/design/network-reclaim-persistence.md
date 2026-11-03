# 作成失敗の回収待ちの記録の永続化

`create_network` の失敗で残った bridge・nft テーブルと、`attach` の巻き戻しで取り残した veth・pin を、plugin（plugin-cri）の再起動をまたいで回収できるようにする設計。NET-1・NET-6・REPAIR-3・REPAIR-4（あわせて REPAIR-5・CORE-1）、TASK-139・TASK-185 追補、#2604（前提は #2467 の所有トークン回収）・#2681（attach の取り残しと write-ahead の判断）。

## 背景

- `network::reclaim_failed_create` は、bridge の `IFLA_IFALIAS`・nft テーブルの `NFTA_TABLE_USERDATA` に刻んだ所有トークンの一致を証明してから資源を消す。証明に使う請求書（`FailedCreateClaim`）は、plugin-cri の `NetsetupNetwork` のメモリ（`Mutex<Registry>`）にしか無かった
- plugin プロセスが再起動すると請求書が消え、同じ名前の再作成は `AlreadyExists` のまま恒久的に失敗して、資源は手動回収になっていた

## 範囲

| 対象 | 本設計での扱い |
| ---- | -------------- |
| 作成失敗の回収待ちの記録（請求書） | 決定し、実装する（#2604） |
| attach の取り残しの記録（請求書） | 決定し、実装する（#2681。下の「attach の取り残しの記録」） |
| write-ahead（作成前・attach 前の記録） | #2681 では採らないと判断し、#3067 で意図記録として実装した（下の「write-ahead の判断」） |
| IPAM 状態（`StaticIpam`・`NetnsDirRecord`）、作成に成功したネットワーク（`CreatedNetwork`）、削除中の印 | 置き場所と形式の方針だけを決め、実装は後続（#1870 の network 結線の設計と一緒に決める。CLI の経路と共有しうるため） |

（#1870 の設計で、CLI と共有する置き場は `<状態ルート>/@networks/` に決まった。[network-wiring.md](network-wiring.md) D10・D11、実装は #3059・#3067・#3075。以下は決定前の記述。）後続で実装するときの置き場は、同じ階層の `<状態ルート>/.cri/net/networks/<名前>/`（`ipam`・`netns-dir` の記録）とする。#1870 で CLI と共有する置き場に決まった場合は、そちらへ移す手順を後続 issue に書く。

## 置き場所

`<状態ルート>/.cri/net/pending-reclaim/<ネットワーク名>.claim`（1 ネットワーク 1 ファイル）。

- パスは固定で、要求の入力からは受けない。ファイル名は `NetworkName`（`[a-z0-9][a-z0-9_.-]*`・1〜64 バイト）で検証済みの文字だけで、`/`・`..` にならない
- `.cri/net` と `pending-reclaim` は 0700 で作る。既存のものは、symlink でないこと・ディレクトリであること・所有者が状態ルートと同じこと・group / other の権限が無いことを確認し、反すれば消さずに拒否する（`bundle_provider_in` と同じ基準。unix のみ。他 OS は種別だけ見る）

## 形式

serde を使わない固定のテキスト記録（LF・UTF-8・ASCII のみ）。符号化と復号は net の `FailedCreateClaim::to_record` / `from_record` に置く（フィールドの非公開を保ち、検証を 1 か所にまとめる）。

```text
fandhe-net-claim v1
network=<名前>
token=<所有トークン>
bridge=<0|1>
table=<0|1>
```

`from_record` は次を厳密に検証し、違反は `InvalidArgument`（メッセージに入力値を載せない）。

- 先頭行（版）の完全一致、キーの順序固定、重複・未知キー・余分な行・CRLF が無いこと
- `network` が `NetworkName` の規則を満たすこと
- `token` が ASCII の可視文字だけで 256 バイト以下、かつ `fandhe-net:<network>:` で始まること
- `bridge` / `table` が `0` か `1` で、少なくとも一方が `1` であること
- 記録全体が 8192 バイト以下（読み込み側も先に確認する。attach の請求書の v2 の最悪値は約 5.6 KB。#3285）

トークン内の pid は発行したプロセスのもので、再起動後の照合は名前と接頭辞だけで成り立つため直さない。所有の最終的な判定は、これまでどおりカーネル側の別名・userdata とトークンの完全一致で行う。トークンは bridge の別名として誰でも読める公開情報で、記録の改ざん耐性は置き場の所有者と権限の検査で守る。

## 排他と不可分性

- プロセス内の直列化は既存の `Mutex<Registry>`
- プロセス間の排他は `pending-reclaim/.lock` の `File::try_lock` を、5 秒の期限つきで再試行して取る（REPAIR-5。期限超過は `Timeout`）。ロックは読み込み・書き込み・削除の各操作の間だけ持つ。回収は冪等（`NotFound` は消えたものとみなす）なので、二重に起動しても安全側に収まる
- 書き込みは同じディレクトリの一時ファイル（`O_EXCL`・0600）へ書いて `fsync` してから `rename` し、ディレクトリも `fsync` する。読み込みは通常ファイルであることと長さの上限を先に確かめる

## 書く時点と消す時点

- 書く: `create_network` が取り残し付きで失敗し、請求書があるとき、メモリの記録を登録する時点（エラーを返す前）。`LinuxNetsetup` の `StaticIpam::for_network` の失敗経路も同じ道を通る
- 書けなかった場合: メモリの記録は保持し、元のエラーに「回収の記録を永続化できなかった」を足した `Internal` を返す（成功を装わない）。この場合、再起動後は手動回収になる
- 請求書が無い取り残し（所有を証明できない）: 永続化しない。引き継ぐ手がかりが無いため。再起動後は同じ名前の再作成で `AlreadyExists` になるが、実際には記録が無いので、手動回収の後に再作成できる
- 消す: `delete_network` で回収を確認して登録を外した直後。消せなかったときは `Internal` を返し、記録は残る（次の起動で読み込まれて再回収される。冪等）

## 起動時の読み込み

- 本番（`CriPluginBackends::production`）が `NetsetupNetwork::with_reclaim_store` で置き場の全記録を読み、作成失敗の回収待ちとして登録する（件数の上限は `MAX_NETWORKS`。超えたら起動を失敗させる）
- `gateway` は回収待ちの記録では使わない（接続系の操作は回収待ちを拒否する）。`NetworkEntry` では `Option` で表す
- 壊れた記録（復号の失敗・ファイル名と記録内の名前の不一致・長すぎる）は、ファイルを消さず、請求書なしの回収待ち（手動回収）として登録して同じ名前の再作成を防ぐ。件数は記録器の `net.reclaim_store_load` の失敗件数と、固定語彙の stderr 1 行で出す（ファイル名・トークン・パスは出さない。REPAIR-4）。ネットワーク名として不正なファイル名の `.claim` は登録せず、同じ件数に数える
- 読み込み自体の失敗（置き場の検査違反など）は `production()` を fail-closed で失敗させる

## 印を刻む前に失敗した bridge

`CreateBridge` の結果不明・`ResolveIndex`・`SetOwnerToken` の失敗で残った bridge は別名が空で、所有を証明できないため自動回収しない（名前の接頭辞や pid からの推定はしない。分離の境界を越えうるため）。観測の方法と手動の手順は [network-reclaim-recovery.md](../setup/network-reclaim-recovery.md)。

## 試験

- net の単体試験: 記録の往復と、不正な記録の拒否（`net1_claim_record_*`）
- plugin-cri の結合試験（root 不要・3 OS の既定集合）: 再起動後の回収、壊れた記録、別ネットワークの記録、書き込み失敗（`crates/plugin-cri/tests/netsetup.rs`）と置き場の単体試験
- 実機前提（root・`unshare --net`・`ip`）: `bridge_owner_token_privileged` の (7)(8)。`harness = false` で `-- --ignored` のときだけ実行する（理由は同ファイルの冒頭と `AGENTS.md`「実機前提テスト」）

## 未対応（後続）

- IPAM 状態・`CreatedNetwork`・削除中の印の永続化は #3067 で `@networks` に実装済み（plugin-cri の利用と旧置き場からの移行は #3075。下の「`@networks` への移行」）
- write-ahead は #3067 で意図記録として実装済み（カーネル照合は後続。下の「write-ahead の判断」）
- 再起動後に復元したネットワークの bridge・nft テーブルの自動回収（link の dump API か、#1870 の永続化の後）

## attach の取り残しの記録（#2681）

`attach_container` の巻き戻しで取り残した host 側 veth・netns の pin も、作成失敗の請求書と同じ置き場と形式で永続化する。NET-1・REPAIR-5（あわせて REPAIR-3・REPAIR-4・NET-6・CORE-1）。

- 置き場: `<状態ルート>/.cri/net/pending-reclaim/attach/<endpoint>.attach`。`attach/` は `open` が 0700 で作り、親と同じ検査（symlink でない・状態ルートと同じ所有者・group / other の権限なし）にかける。排他は親の `.lock` を共有する。一時ファイル（`O_EXCL`・0600）→ fsync → rename → ディレクトリの fsync、長さの上限 8192 バイト（`CLAIM_RECORD_MAX_LEN`。#3285 で 1024 から引き上げ）、読み込み時の件数の上限（`MAX_NETWORKS` × `MAX_CONTAINERS_PER_NETWORK`）は作成失敗の記録と同じ
- 形式（net の `FailedAttachClaim::to_record` / `from_record`）: 版の行 `fandhe-net-attach-claim v1` の後に `network` / `endpoint` / `token` / `generation` / `veth` / `netns` / `pin` / `quarantine` を固定順で書く。`pin` は取り残した netns の pin の実体の識別子（`dev:ino:作成の連番` または `-`）で、同じ endpoint・置き場に作り直された新しい pin を古い請求書で解除しないために、解除の直前に所有記録と照合する（不一致は解除せず fail-closed）。保存済みの記録の更新（quarantine だけへの置き換え）は、プロセス間ロックの下で現在の中身が元の請求書と一致するときだけ行う（比較交換。別世代の請求書を上書きしない）。現在の中身が既に置き換え先と一致するときは、前回の置き換えが `rename` 後のディレクトリの同期だけで失敗した再試行とみなし、同期だけをやり直して成功する（REPAIR-5）。`generation` は接続ごとの世代（小文字 16 進 32 桁）で、host 側 veth の別名 `<token>/ep/<endpoint>/g/<generation>` に含まれる。同じ endpoint の再接続で別の値になるため、古い請求書は新しい接続の veth の所有を証明できず、正常な veth を消さない。版・順序・LF・余分な行・名前の規則・トークンの形式（そのネットワークの発行形式で 256 バイト以下の可視 ASCII）・フラグ（`0` か `1`。すべて `0` は拒否）を厳密に検証し、違反は `InvalidArgument`（入力値は載せない）。所有の最終判定は記録ではなく、カーネル側の別名（`host_owner_token`）と master の一致で行う
- 書く時点: attach が取り残し付きで失敗し、請求書があるとき。書けなくてもメモリの記録は保持し、元のエラーに `the reclaim record could not be persisted` を足した `Internal` を返す
- 消す時点: `detach` または `delete_network` が回収に成功した後、記録ファイルを中身が一致するときだけ消し（別プロセスが書いた新しい記録を消さない）、そのあとでメモリの記録を外す。回収に失敗したら記録・ファイルとも保持して再試行できる
- 回収の順序: `delete_network` は bridge を解放する前に、attach の取り残しを先に回収する（veth の所有の証明は bridge への所属で、bridge を消すと証明を失うため）。バックエンドでの解放後は bridge が無く証明できないため試みない（手動回収）
- 回収の内容（`network::reclaim_failed_attach`）: host 側 veth は、別名が endpoint のトークンに一致し、master が所有を確かめた bridge に一致するときだけ、照会で得た ifindex で消す。不一致・bridge 無し・判定不能は `Unknown` のまま触れない。netns の pin は請求書の識別子を `netns::unpin_path_expecting` で所有記録と照合して外し（再起動後の扱いは次節）、pin の置き場は記録ではなく plugin の固定設定（`<状態ルート>/.netns`）から受ける。quarantine（アドレス・ポート予約と、ハンドルを持てなかった DNAT ルール）はプロセス内の保持で、解放は `delete_network` が行う。plugin-cri はカーネル側の回収後も quarantine が生きたネットワークに残る間、`detach` を成功させず登録と記録（quarantine だけの請求書へ置き換え）を保持し、同じ endpoint の再 attach を `unreclaimed` で拒否する。`delete_network` はそれを回収待ちに数えず、ネットワークの解放後に登録と記録を外す。エラーコードは `net1_reclaim_attach_refuses_unproven_veth` がケースごとに照合する（所有の不一致は `FailedPrecondition`、bridge 無しは `NotFound` のまま。#3559）。否定確認（#3576。手元のみ・非コミット）: bridge 無しのケースの期待値を `FailedPrecondition` に替えると `case 4` で、別名の偽装のケースの期待値を `NotFound` に替えると `case 0` で落ちる

### 再起動後に回収できるもの・できないもの

作成に成功したネットワーク（`CreatedNetwork`・IPAM）は永続化されていない（#1870 の後続）ため、再起動後は attach の記録だけから「復元したネットワーク」を作る。

- 回収できる: 所有を確かめた veth
- 回収しない: bridge・nft テーブル（記録の無い健全なコンテナがまだ繋がっていないことを証明できず、消すと生きているコンテナの通信を断ち、veth の所有の証明も失うため）。復元したネットワークの `delete_network` は、取り残しを回収し終えたら記録を外し、固定の文言（`MSG_RECOVERED_NETWORK_UNTRACKED`）の `FailedPrecondition` を返して、ネットワーク本体が手動回収であることを知らせる。「ネットワークを丸ごと復旧できる」とは書かない
- 回収できる（条件つき）: netns の pin。請求書の `pin=` と、置き場の永続の所有記録 `.owned/<endpoint>`（次節・#2824）と、カーネルの実状態の三者が一致するときだけ外す。所有記録が無い・壊れている・一致しない pin（旧い請求書・手動回収後に作り直された別世代・none モードの pin）は `FailedPrecondition` で拒否され、手動回収に残る（fail-closed）
- 回収できる（条件つき）: detach（`detach_container`。#3062）の失敗時の DNAT ルール（#3285・NET-1・NET-6・REPAIR-4）。請求書は v1 の 9 行に、`table-handle=<u64>` と公開ごとの `rule=<tcp|udp addr:port cport pre out>`（1〜64 行）を足した v2 で符号化する。DNAT ルールを持たない請求書は従来どおり v1 で、保存済みの v1 は復号して再符号化してもバイト単位で同じになる（内容照合の削除・比較交換を壊さない）。旧バイナリは v2 を版の不一致として拒否する（fail-closed。v2 から v1 への引き戻しは非対応）。
  - 載せる公開: 解除に失敗して残りうる（`Present`・`Unknown`）もので、テーブルハンドルを持つもの。期限切れで要求を送らなかった公開を含む。テーブルハンドルは公開の時点で取れたものだけを載せ、未束縛の公開（ハンドルを取れなかったもの）は請求書に載せない。テーブルのハンドルが 0 のときは同一性を比べられないため、作り直しと読まず DELRULE を送らずに `Unknown` の取り残しにして請求書を保つ。載せない公開: 解除済み、`StaleHandles`（記録した実体はもう無い）、テーブルハンドルが無いもの、載せる公開のテーブルハンドルが食い違うとき（手動回収と quarantine）
  - 回収（`reclaim_failed_attach`。veth より前）: テーブルの `NFTA_TABLE_USERDATA` がトークンと一致（所有）し、生きたテーブルのハンドルが請求書と一致（実体の同一性）するときだけ、ハンドル指定で DELRULE する。テーブルが無い・作り直された場合はルールも無いので回収済み、所有を証明できない場合は何も送らず `Unknown`。2 本の一括削除が ENOENT で中止されたら 1 本ずつ消し直し、片方だけ残る場合も残りを消す（ハンドルはテーブルの寿命の中で再利用されず、実体の同一性を確かめた後なので、ENOENT は「既に無い」と読める）。アドレス・予約の quarantine は `delete_network` が解放する
  - 残余リスク: 所有の証明と DELRULE の間に、同じ権限の者がテーブルを差し替える窓が残る（`unpublish` と同じ水準）。1 件ごとに最大 3 要求を送り、各要求は `timeout` で打ち切る（REPAIR-5）
  - attach の巻き戻しの請求書は DNAT のハンドルを載せず常に v1（#3413）: 投入が成功すれば attach は `Ok` で巻き戻す後段が無く、結果不明の投入は `NftApplyFailure` がハンドルを持たず、記録の無い attach の経路はテーブルハンドルも持たない（`ClaimedRules` はテーブルハンドル必須）。確定的な失敗（`Aborted`・`NotSent`）ではルールが残らず請求書も無い。具体値は `net1_3413_attach_rollback_claim_carries_no_rule_handles` で固定する。部分的な echo ハンドルを Err 側へ出す案は ACK 判定の契約（REPAIR-2・SEC-1 #2905）に関わるため採らない
  - テーブルハンドルを持たない公開（記録の無い経路・照合前に断られた公開・テーブルハンドルが食い違う公開）は自動回収しない（#3413）: テーブルを作り直すとルールのハンドルの採番もやり直しになり、古いハンドルの DELRULE は別のルールを消しうる（fail-closed）。quarantine のまま手動回収（`docs/setup/network-reclaim-recovery.md`）に倒す。記録の無い経路は `delete_network` でも解放できるが、記録つきの経路は請求書が残る間 `delete_recorded_with` が `network has pending reclaim records` で拒否するため、対象資源の手動回収と請求書・意図記録の整理を先に行う
- 回収できる（条件つき）: 記録だけからの detach（`network::recorded::detach_member_recorded`。#3347・NET-1・NET-6・REPAIR-4）。`@networks` の `members/<id>`（FCMEM1）から請求書を合成し、上の DNAT ルール・veth・pin の回収に流す。条件は、世代（boot ID と network namespace）が `realized` と一致すること、同じ endpoint の `pending-reclaim/attach` の請求書が無いこと（あれば先に `reclaim_failed_attach`。detach の失敗で残る請求書は記録に無い追加公開のルールを載せうるため合成で代えない）、解除の印つきの公開が無いこと（先に `unpublish_port_recorded`）、`netns_dir` が記録と一致すること。pin の識別子はメンバー記録の `pin` 項目から取る（無い旧形式は pin が残っていれば `Unknown` で手動回収）。ホストの再起動をまたぐ場合（boot ID が違う記録）は世代が違うため断り、次節の入口（#3412）で回収する。同じ boot で netns だけ違う記録は手動回収に回す
- 復元したネットワークへの `create_netns`・`attach` は拒否する
- 壊れた記録（復号の失敗・ファイル名と記録の不一致・不正なファイル名）は、ファイルを消さず、登録もしない。件数は `net.reclaim_store_load` の失敗件数と stderr の 1 行に足す。同じコンテナの再 attach は、カーネルの `NLM_F_EXCL` による `AlreadyExists` で fail-closed になる。件数の上限を超える場合は起動を失敗させる

## ホストの再起動をまたぐ記録の回収（#3412・NET-1・NET-3・NET-6・REPAIR-4）

PR #3396（#3347）で記録だけの detach、PR #3392（#3343）で公開の墓標が入った。両 PR の対象外に残った 3 項目の採否を決めた。再起動で veth・nsfs のマウント・nft テーブル・bridge はカーネルから消え、記録（`@networks/<名前>/members/<id>`・`realized`）と予約・pin ファイルだけが残る。

| 項目 | 採否 | 要点 |
| ---- | ---- | ---- |
| 1. 再起動（boot ID の違い）をまたぐ記録だけの detach | 採る（範囲を絞る） | boot ID が違うときだけ受ける。同じ boot で netns だけ違う場合は従来どおり断る。カーネルに資源が無いことを照会で確かめてから、記録・予約・残った空の pin ファイルだけを片付ける。DELRULE は送らない |
| 2. 再起動後に残る前の世代の予約（Active・解除中・墓標の `publish` 行） | 採る（1 に含める。別の仕組みは作らない） | 1 の入口がメンバーの `ports.release(name, endpoint)` とメンバー記録の削除を行い、予約をすべて解放する。`unpublish_port_recorded`・`restore_unpublished_ports` の世代の照合は変えない |
| 3. `detach_container_recorded` が `member not found` で拒否して破棄した pin | 採らない（手動回収のまま） | 所有記録 `.owned/<endpoint>` は「このモジュールが作った」ことしか示さず、ネットワーク・メンバー・接続の世代に結びつかない。記録の無い生きた利用者（attach 前の `create_netns` の pin、none モード、移行中の `.cri/net` の経路、複数ネットワーク）を除外できない。veth の別名で帰属させても、接続の世代を持っていたのは消えた記録だけである |

PR #3392 は前の世代の予約を「`delete_network` の回収に委ねる」と書いたが、`delete_recorded_with` はメンバー記録が残る間 `network still has members` で断るため、実際は詰まっていて手動でしか抜けられなかった。2 はこの詰まりを 1 の入口で解く。

### 入口

`network::recorded::detach_member_recorded_after_reboot`（本体は OS 非依存の `detach_member_after_reboot_with`）。生きた `AttachedContainer` を取らず、記録だけから行う。請求書は veth・netns のみで合成し、**ルールは載せない（`rules = None`）・quarantine も立てない**。nft のルールハンドルはテーブルごとの採番で、新しい boot で作り直されたテーブルでは同じ番号が再利用されうるため、DELRULE を一切送らない。カーネル資源は消さない（照会と、残った空の pin ファイルの除去だけ）。

### 関門（カーネル照会の前に、何も変えずに断る）

通常の `detach_member_recorded_with` から引き継ぐもの: 排他ロックのガード、`realized` があり `realized.intent` が無いこと、メンバー記録があり所有トークンがこのネットワークのもの（`DataLoss`）、同じ endpoint の `pending-reclaim/attach` の請求書が無いこと、`netns_dir` が記録とバイト単位で一致すること。

違う点:

- **boot ID が同じなら断る**。netns も同じなら `member belongs to the current boot; use detach_member_recorded`、netns だけ違えば `record is from another network namespace of the same boot`（資源が別 namespace で生きている可能性があるため。`reconcile` が `GenerationMismatch` で据え置くのと同じ理由）
- **解除の印（`unpublishing`）では断らない**。前の boot のルールは残っておらず、`unpublish_port_recorded` は世代の照合で必ず断るため、断ると抜けられなくなる

### カーネル照会（`delete::member_after_reboot`。fail-closed）

boot ID の不一致だけは信用しない。記録の改ざんや、nftables.service によるルールセットの復元（userdata が往復で残りうる。#3361 の (9) で観測中）に備え、次をすべて確かめてから進む。満たさなければ `DeleteStep::Validate` の `FailedPrecondition` で何も変えずに断る。

1. 専用テーブル `fandhe_net_<名前>` の照会が `NotFound`（所有トークンの一致・不一致を問わず、あれば断る。`NotFound` 以外のエラーも断る）
2. bridge（導出名）の照会が `NotFound`
3. host 側 veth の照会が `NotFound`
4. pin:
   - 記録の置き場（`NetnsDirRecord` の dev:ino）が今の置き場と一致する場合は、マウントされていない空ファイルで、`.owned/<endpoint>` と請求書の `pin` 識別子が一致するときだけ消す（所有記録も消す）。マウントされていれば種別を問わず umount せず断る（前の boot のマウントは残らないので、マウントがあれば今の boot のものである。nsfs の inode 番号は boot をまたいで再利用されうるため、識別子の照合だけで umount させない）
   - 置き場の識別子が違う場合（tmpfs の作り直し、btrfs などで st_dev が変わる）は、設定の置き場に同名の pin が無いと確かめられたときだけ進む。あれば断る（手動）
   - 記録に `pin` 項目の無い旧形式は、pin が無ければ進み、あれば断る

全体で 1 つの期限を持つ（REPAIR-5）。`realized` には触れない。全メンバーを片付けた後は既存の `delete_network_recorded`（`delete_recorded_with` は意図して世代を照合しない。bridge・テーブルの `NotFound` を冪等な完了として扱う）が `realized` を消し、同じ名前で作り直せる。

### 残余（この Issue では直さない）

- (a) 再起動前に残った `pending-reclaim/attach` の請求書は、`reclaim_failed_attach` が `HostGeneration` を照合せず、作り直されたテーブルに対してルールハンドルを比べうる（ハンドル再利用の同じ危険）。請求書がある endpoint は、再起動モードでも従来どおり関門で断る
- (b) 再起動後の請求書（`pending-reclaim/*`）と、前の世代の `members-intent/*` が残ると `delete_recorded_with` は断る（reconcile は世代が違うと掃除しない）。請求書を消費する結線は #3075 系
- (c) 同じ boot で netns が違う記録、置き場に pin が残る場合、カーネルに同名の資源がある場合は手動回収のまま（`docs/setup/network-reclaim-recovery.md`）
- 3 の代案「`member not found` のとき、生きた `AttachedContainer` から請求書を作って保存してから破棄する」も検討したが、採らない。保存した請求書は消費する結線（#3075 系）が無いまま `delete_network` とその endpoint の `detach_member_recorded` を止めるうえ、誤った ID の呼び出しで生きたメンバーの資源を消しうる。再評価の条件は、#3075 系で `@networks` の請求書の回収が結線された後とする
- supervisor（#3074）・plugin-cri（#3075）から本入口を呼ぶ結線は後続。実機（root）での照合は `network_publish_record_privileged` の (10)。実行は #1626 に足す（人間担当）

## netns の pin の所有記録（#2824）

プロセスをまたいで残った netns の pin を、永続的な所有記録と照合して外す。NET-1・REPAIR-3・REPAIR-5（あわせて REPAIR-4）。経緯: プロセス内の所有記録 `PINS` だけでは再起動後に照合できず、請求書の `pin=<dev>:<ino>:<serial>` も、連番が 0 から数え直しになるうえ、`dev:ino` が pin ファイル自身の inode（nsfs がマウントされている間は stat しても netns の inode しか見えない）で、nsfs の inum も ext4 の inode も再利用されうるため、単独では別世代の pin と区別できなかった。

- 置き場: `<netns_dir>/.owned/<endpoint>`（1 pin につき 1 ファイル）。`.owned` は最初の `create_pinned` が 0700 で作り、固定した置き場の fd からの相対で `O_NOFOLLOW` で開く。symlink でない・ディレクトリである・実効 UID の所有・group / other に書き込み権限が無い、を fstat で検査し、違反なら何も作らずに拒否する（fail-closed）。`EndpointId` は `.` で始まらないため pin 名と衝突せず、置き場を列挙する箇所は無い（`pin_exists_in`・`pin_absent_in` は完全一致の名前で stat する）
- 記録ファイル: 0600・実効 UID の所有の通常ファイル。読むときは `O_PATH|O_NOFOLLOW` で開いて fstat で種別・所有者・mode・長さ（256 バイト以下）を確かめてから読む
- 形式（固定テキスト・LF・ASCII。`crates/net/src/netns/owner_record.rs`）: 版の行 `fandhe-net-pin-owner v1` の後に `endpoint=<EndpointId>`・`file=<dev>:<ino>`（pin ファイル自身）・`ns=<dev>:<ino>`（マウント後に見える netns。作成の途中は `-`）・`serial=<u64>` を固定順で書く。版・順序・重複・余分な行・CRLF・桁数（1〜20 桁の 10 進）・`endpoint` とファイル名の一致・長さを検証し、違反はすべて照合不能として扱う。入力値はエラーに載せない
- 連番: 現在時刻（UNIX epoch からの ns）を下限にプロセス内で単調増加させる。再起動後の値は前のプロセスの値より大きく、古い請求書の連番と衝突しない。請求書の形式と版（`fandhe-net-attach-claim v1`）は変えない
- 書く時点: `create_pinned` が pin ファイルを作って chmod した直後に `ns=-` で置き、netns の固定が成功したら `ns` つきの完全な記録へ置き換える。どちらも一時ファイル（`O_EXCL`・0600）→ rename で原子的に置き換える（前の世代の記録はここで上書きされる）。記録できなければ pin を作らずに（または固定した pin を解除して）失敗する。生きている pin の所有記録は常に完全である
- 消す時点: pin の解除に成功した後（`unpin_in_dir` の成功・既に無かった場合、`create_pinned` の失敗時の後始末、期限切れ後にワーカーが行う回収）に、記録の中身が自分の世代（`file` と `serial`）と一致するときだけ消す。新しい世代の記録は消さない。消せなくても解除の成功は維持する。pin の無い古い記録は無害で、次の作成が上書きし、照合では pin の不存在が冪等な成功になる
- 照合（`unpin_path_expecting` のメモリに記録が無い場合のみ）: 所有記録を読み（欠落・復号の失敗・属性違反は `netns pin has no valid ownership record` で拒否）、`file` と `serial` が請求書の識別子と一致することを確かめる（不一致は `netns pin is not the one this claim was issued for`）。そのうえで既存の判定へ渡す: 未マウントなら pin ファイルの inode が記録と一致し形（実効 UID 所有・0400・空）が合うこと、nsfs なら umount の前に netns の inode が記録の `ns` と一致すること（`ns=-` なら拒否）を確かめ、umount 後の実体が記録の `file` と一致して形が合ってから unlink する。それ以外のマウントは拒否する。識別子を取らない `unpin_path` は、連番で世代を固定できないため再起動後の pin を扱わない
- fsync しない理由: 記録の欠落・壊れは拒否側に倒れるだけで安全性に影響せず、必要なのは原子的な置き換えだけである。クラッシュで rename が永続化されず古い中身に戻っても、マウントは再起動で消えており、照合に通りうるのは未マウントの空ファイルの削除だけで無害である。作成のたびの fsync を避け、NET-4 の所要時間への影響も小さく抑える
- write-ahead との関係: 所有記録は「このモジュールが作った」という所有の表明で、回収の指示ではない。回収は引き続き attach の請求書と veth の所有の証明で制御されるため、次節で採らないとした「作成の途中で落ちたのか成功したのか」の曖昧さは生じない
- 試験: 単体試験（非 root。`crates/net/src/netns.rs`・`netns/owner_record.rs`）で、記録と一致する pin を外すこと、記録の欠落・壊れ・symlink・mode 違反・識別子の 1 項目の不一致で拒否すること、作り直された新しい pin を古い請求書で外さないこと（AC3）を具体値で確かめる。実機（root）でのプロセスをまたぐ回収は未確認で、実機前提の試験は人間が実行する。その試験は `crates/net/tests/network_attach_privileged.rs` に準備済み（#2906。子プロセスを SIGKILL した後の別プロセスによる回収と、作り直した新しい pin を古い請求書で外さないこと。成功行 `reclaim_xproc=ok reclaim_xproc_newer=kept`）に加え、試験用 feature `attach-fault-test-support` の故障注入（`attach_container_with_fault_for_test`。#2971）で巻き戻しの失敗を作り、取り残しの請求書を別プロセスが回収すること（S3。成功行 `reclaim_fault=ok`）と、別名の無い veth は回収が拒否して残すこと（S4。成功行 `reclaim_fault_unowned=kept`）も同じ試験に準備済み。IPAM 払い出し後の段は、回収後も quarantine（アドレス・予約）が `delete_network` まで残ること（S5。成功行 `reclaim_fault_post_ipam=ok`）と、巻き戻しが成功すれば即時に解放されること（S6。成功行 `rollback_post_ipam=released`。#3040）を確かめる。事前作成 netns の経路は単体試験（`net1_attach_fault_prepared_*`）で扱う。段ごとの残る資源と請求書の記録は単体試験（`net1_attach_fault_*`）で具体値照合する。実行は #1626
- 残余リスク: 同じ UID の利用者による手動操作（pin を消し、所有記録を残したまま inode を再利用した空ファイルを置く等）は排除できない（置き場は実効 UID の所有で group / other の書き込みを検査済み）。記録の比較から削除までの間に新しい世代の記録を消す競合は、拒否側（照合不能）に倒れる。時計が戻ると連番が衝突しうるが、照合は `dev:ino` の一致も要る。旧いバイナリの請求書と、記録の書き込みが無かった pin（期限切れ後に完了したワーカーの pin は `ns=-` のまま）は手動回収に残る

## write-ahead の判断（#2681。#3067 で更新）

作成前・attach 前に記録を書く方式（write-ahead）は、#2681 の時点では採らなかった。#1870 の設計（network-wiring.md D11）で、作成結果（`realized`）とメンバーを永続化し、カーネル操作の前に意図記録（`realized.intent`・`members-intent/<id>`）を書く方式に転じた。#3067 で意図記録の書き込みと後始末、記録から IPAM を組み直すことを実装した（`crates/net/src/network/recorded.rs`）。残った意図記録のカーネル照合（所有トークンでの昇格または巻き戻し）は後続で、それまで残った `realized.intent` は次の操作を `FailedPrecondition` で止め、残った `members-intent/*` のアドレスは使用中として数え続ける。以下は #2681 の時点の判断の記録である。

- 理由: `CreatedNetwork` が永続化されていないと、再起動後に残った作成前の記録が「作成の途中で落ちた」のか「作成に成功した後、記録を消す前に落ちた」のかを見分けられない。後者を自動回収すると、繋がっている veth の所有の証明（bridge）を消し、生きているコンテナの通信も断ちうる
- 2 段の記録（作成前に手動のみの記録を置く）も検討した。自動回収できないなら、今の挙動（カーネルの `AlreadyExists` による再作成の拒否と手動回収）に比べて得るものが小さく、作成のたびに fsync が 2 回増える（NET-4 の所要時間に響く）ため採らない
- 再検討の条件: #1870 で作成に成功したネットワークの記録を永続化した後。「成功の記録がある」と「作成前の記録しかない」を見分けられるようになり、トークンを先に発行する net の API（例: `OwnerToken::issue(&NetworkName)` と、それを受ける `create_network`）と一緒に入れられる
- attach の途中でのクラッシュも、`AttachedContainer` と IPAM が永続化されていないため同じ理由で採らない

## `@networks` への移行（#3067・#3075）

plugin-cri の請求書は、現在 `<状態ルート>/.cri/net/pending-reclaim/` にある。CLI と共有する状態ストア（network-wiring.md D10）では、同じ請求書をネットワークごとの `<状態ルート>/@networks/<名前>/pending-reclaim/{create,attach/<endpoint>}` に置く（#3067 で `NetworkLockGuard::save_reclaim_create` / `save_reclaim_attach` / `reclaim_records` / `remove_reclaim_*_if` を実装済み）。記録の形式は v1 のまま（`FailedCreateClaim::to_record` / `FailedAttachClaim::to_record`）で、ファイル名にネットワーク名は入れず、拡張子で判別しない。ファイルは 0600、ディレクトリは 0700 で、一時ファイル（`@tmp-` 接頭辞）→ fsync → rename → 親ディレクトリの fsync の順に書く。

前提: 移行先にネットワークの定義（bridge）があること。plugin-cri が使うネットワークの定義の作成は #3075 で行う。移行の実装も #3075 の担当で、手順は次のとおり。

1. 全体の排他ロックとネットワークの排他ロックを取り、旧置き場の `.lock` も取る
2. 旧記録を `from_record` で検証し、ファイル名と記録内のネットワーク名・endpoint が一致するものだけを移行先へ書く（一時ファイル → fsync → rename → ディレクトリの fsync）
3. 書けたことを読み戻して確かめてから、中身の一致を条件に旧記録を消す
4. 両方にあって中身が異なる記録は消さずに残し、手動回収として扱う（fail-closed）
5. 壊れた旧記録は移さずに残し、`net.reclaim_store_load` の失敗件数に数える
6. 旧置き場が空になったら消す。途中で落ちても再実行は冪等で、移行が済むまでは両方の置き場を読む

Issue #3067 の範囲外（後続）: 残った `realized.intent` のカーネル照合、実体の無い `members-intent/*` の掃除、`.cri/net` の `CreatedNetwork`・IPAM の移行（#3075）。
