# CRI の Status RPC の判定と応答（設計記録）

`RuntimeService.Status` の応答（`RuntimeReady`・`NetworkReady`・`runtime_handlers`・`features`・`info`）を何で決めるかの記録（CRI-1・CRI-2・REPAIR-3・REPAIR-4・REPAIR-5。#2830）。実装は `crates/cri/src/runtime_service.rs` の `CriRuntimeService::status_response`。

## 一次情報（commit 指定）

| 対象 | 確認した版 | 要点 |
| ---- | ---------- | ---- |
| kubelet `pkg/kubelet/kubelet.go` の `updateRuntimeUp` | kubernetes v1.37.1（`f78e722310e50bcaca9276be22276d9e91d91308`） | 5 秒ごとに `Status`（`verbose=false`。`kuberuntime_manager.go` の `Status`）を呼ぶ。`NetworkReady` が無いか false なら network state にエラーを置く。`RuntimeReady` が無いか false ならランタイム停止として扱い、handlers・features の取り込みと初期化を飛ばす。応答がエラーでも同様に失敗として扱う |
| kubelet の `SyncPod` 系 | 同上 | network state がエラーのとき、hostNetwork でない Pod は `NetworkNotReady` で拒否する。hostNetwork の Pod は動く |
| containerd `internal/cri/server/status.go` | containerd v2.1.4（`75cb2b7193e4e490e9fbdc236c0e811ccaba3376`） | `RuntimeReady` は常に true（CRI が応答できる = 準備済み）。`NetworkReady` は CNI の状態から決め、false のときの reason は `NetworkPluginNotReady`。`verbose` のときだけ `info` に config 一式・CNI の設定・Go のバージョンを入れる |

## 判定

- **待ちを持たない**: kubelet が頻繁に呼ぶため、I/O・スレッド生成・実行層や `PodNetworkProvider` の呼び出し・レジストリのロック取得をしない。持っている構成だけで決める。REPAIR-5 の期限は構造上いらない
- `RuntimeReady`: 実行層を注入済み（`with_runtime`）かつレジストリが poisoned でないとき true。実行層が無ければ false・reason `RuntimeNotConnected`（記録だけの構成を ready と装わない。REPAIR-3）、poisoned なら false・reason `RuntimeStateUnavailable`。poisoned でも RPC は `OK` で返す（他の RPC は `INTERNAL`。kubelet はどちらもランタイム停止として扱い、condition の方が理由が伝わる）
- `NetworkReady`: `PodNetworkProvider` を注入済み（`with_pod_network`）なら true、無ければ false・reason `NetworkPluginNotReady`（containerd と同じ語彙）
- message は固定の英語文言で、入力や内部パスを含めない。並びは `RuntimeReady`、`NetworkReady` の固定
- 採らなかった案: core の `ContainerRuntime` や `PodNetworkProvider` に死活確認のメソッドを足し、期限つきで呼ぶ。公開トレイトの変更（PLUG-1・PLUG-4）になるため本 issue の範囲外。必要になったら別 issue で扱う

## 本番での帰結

plugin-cri の本番は `with_runtime` を通るので `RuntimeReady=true`。一方 core の network namespace の join が未実装のため `with_pod_network` を差しておらず（[cri-config-acceptance.md](cri-config-acceptance.md) の順 13・#2675）、**本番は `NetworkReady=false`** を返す。これは意図した値で、true に装わない。kubelet ではノードの Ready が False になり、hostNetwork でない Pod は `NetworkNotReady` で拒否される（hostNetwork の Pod は動く）。join が入って `with_pod_network` を差した時点で true になる。

## runtime_handlers・features

- `runtime_handlers`: 既定ハンドラ（名前が空）の 1 件。`SUPPORTED_RUNTIME_HANDLERS` から組み立てる。`recursive_read_only_mounts=false`（`mounts.recursive_read_only` を bundle の変換が拒否）・`user_namespaces=false`（userns の写像を拒否〔#2240〕）。その拒否を外す変更はこのフラグも反転させる
- `features`: `runtime_features()` をそのまま使う（`supplemental_groups_policy=true`、`user_namespaces_host_network=false`、`mount_options=false`。後 2 つは対応する入力を拒否している現状と整合）

## verbose と info

`verbose` は受け付けるが、値によらず `info` は常に空にする。proto は空の `info` を許す。containerd のように config 一式を出すと状態ルートなどの内部パスや構成が漏れる（情報露出）。将来診断情報を足すなら、パス・環境変数・資格情報を含まない固定キーに限る。

## 可観測性

`cri.status`（`CriOpKind::Status`）を他の RPC と同じく全終了経路で 1 件記録する（REPAIR-4）。request の内容は記録しない。

## 試験

- `crates/cri/tests/runtime_service_status.rs`（構成ごとの応答を具体値で照合。provider・実行層が呼ばれないこと・verbose・記録）と `runtime_service.rs` の単体試験（poisoned）
- `crates/plugin-cri/tests/container_grpc.rs` の段 A（本番バイナリ）と段 B（フェイクの実行層）
