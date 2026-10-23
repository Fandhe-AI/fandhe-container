# 作成失敗の回収待ちの記録の永続化

`create_network` の失敗で残った bridge・nft テーブルを、plugin（plugin-cri）の再起動をまたいで回収できるようにする設計。NET-1・NET-6・REPAIR-3・REPAIR-4（あわせて REPAIR-5・CORE-1）、TASK-139・TASK-185 追補、#2604（前提は #2467 の所有トークン回収）。

## 背景

- `network::reclaim_failed_create` は、bridge の `IFLA_IFALIAS`・nft テーブルの `NFTA_TABLE_USERDATA` に刻んだ所有トークンの一致を証明してから資源を消す。証明に使う請求書（`FailedCreateClaim`）は、plugin-cri の `NetsetupNetwork` のメモリ（`Mutex<Registry>`）にしか無かった
- plugin プロセスが再起動すると請求書が消え、同じ名前の再作成は `AlreadyExists` のまま恒久的に失敗して、資源は手動回収になっていた

## 範囲

| 対象 | 本設計での扱い |
| ---- | -------------- |
| 作成失敗の回収待ちの記録（請求書） | 決定し、実装する（#2604） |
| IPAM 状態（`StaticIpam`・`NetnsDirRecord`）、作成に成功したネットワーク（`CreatedNetwork`）、削除中の印、attach の取り残しの印 | 置き場所と形式の方針だけを決め、実装は後続（#1870 の network 結線の設計と一緒に決める。CLI の経路と共有しうるため） |

後続で実装するときの置き場は、同じ階層の `<状態ルート>/.cri/net/networks/<名前>/`（`ipam`・`netns-dir` の記録）とする。#1870 で CLI と共有する置き場に決まった場合は、そちらへ移す手順を後続 issue に書く。

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
- 記録全体が 1024 バイト以下（読み込み側も先に確認する）

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

- IPAM 状態・`CreatedNetwork`・削除中の印・attach の取り残しの永続化（#1870 の設計の後）
- 作成の途中でプロセスが落ちた場合に備え、作成前に記録を書く（write-ahead。net がトークンを先に発行する API が要る）
