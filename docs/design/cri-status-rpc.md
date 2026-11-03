# CRI の Status・Version・UpdateRuntimeConfig RPC の判定と応答（設計記録）

`RuntimeService.Status` の応答（`RuntimeReady`・`NetworkReady`・`runtime_handlers`・`features`・`info`）を何で決めるかの記録（CRI-1・CRI-2・REPAIR-3・REPAIR-4・REPAIR-5。#2830）。実装は `crates/cri/src/runtime_service.rs` の `CriRuntimeService::status_response`。

`Version`・`UpdateRuntimeConfig`（CRI-1・CRI-2・REPAIR-3・REPAIR-4・REPAIR-5。#2896）も同じ観点で下の「Version」「UpdateRuntimeConfig」に記録する。

## 一次情報（commit 指定）

| 対象 | 確認した版 | 要点 |
| ---- | ---------- | ---- |
| kubelet `pkg/kubelet/kubelet.go` の `updateRuntimeUp` | kubernetes v1.37.1（`f78e722310e50bcaca9276be22276d9e91d91308`） | 5 秒ごとに `Status`（`verbose=false`。`kuberuntime_manager.go` の `Status`）を呼ぶ。`NetworkReady` が無いか false なら network state にエラーを置く。`RuntimeReady` が無いか false ならランタイム停止として扱い、handlers・features の取り込みと初期化を飛ばす。応答がエラーでも同様に失敗として扱う |
| kubelet の `SyncPod` 系 | 同上 | network state がエラーのとき、hostNetwork でない Pod は `NetworkNotReady` で拒否する。hostNetwork の Pod は動く |
| containerd `internal/cri/server/status.go` | containerd v2.1.4（`75cb2b7193e4e490e9fbdc236c0e811ccaba3376`） | `RuntimeReady` は常に true（CRI が応答できる = 準備済み）。`NetworkReady` は CNI の状態から決め、false のときの reason は `NetworkPluginNotReady`。`verbose` のときだけ `info` に config 一式・CNI の設定・Go のバージョンを入れる |
| kubelet `kuberuntime_manager.go` | 同上 | 82 行 `kubeRuntimeAPIVersion = "0.1.0"`。307〜311 行で `Version.version` が `"0.1.0"` と一致しなければ `ErrVersionNotSupported` で runtime manager が作れず kubelet が起動しない。`Version` の取得失敗も同様。395〜399 行 `newRuntimeVersion` は `ParseSemantic`、失敗なら `ParseGeneric`（`runtime_version`・`runtime_api_version` に使う）。403 行で要求の `version` に `"0.1.0"` を送る。2311 行 `UpdatePodCIDR` は `RuntimeConfig.NetworkConfig.PodCidr` を素通しする |
| kubelet `kubelet_node_status.go`・`kubelet.go` | 同上 | `node.Spec.PodCIDRs` を `,` で連結して `updatePodCIDR` へ渡す（560〜562 行。デュアルスタックは 2 件）。起動時にも `kubeCfg.PodCIDR`（既定は空）で呼ぶ（904〜906 行）。エラーはログのみで非致命 |
| kubelet `nodestatus/setters.go` | 同上 | 364 行 `ContainerRuntimeVersion = "<runtime_name>://<runtime_version>"` |
| containerd `internal/cri/server/version.go`・`constants/constants.go` | containerd v2.1.4（`75cb2b7193e4e490e9fbdc236c0e811ccaba3376`） | `version` は `"0.1.0"`、`runtime_name` は `"containerd"`、`runtime_version` はビルド版、`runtime_api_version` は `CRIVersion = "v1"`。要求の `version` は読まない |
| containerd `internal/cri/server/update_runtime_config.go` | 同上 | `pod_cidr` が空なら即 OK。`,` で分割し各要素を `TrimSpace` → `net.ParseCIDR`（失敗はエラー）。CNI 設定テンプレートが未設定なら何もしない。値は保持しない |

## 判定

- **待ちを持たない**: kubelet が頻繁に呼ぶため、I/O・スレッド生成・実行層や `PodNetworkProvider` の呼び出し・レジストリのロック取得をしない。持っている構成だけで決める。REPAIR-5 の期限は構造上いらない
- `RuntimeReady`: 実行層を注入済み（`with_runtime`）かつレジストリが poisoned でないとき true。実行層が無ければ false・reason `RuntimeNotConnected`（記録だけの構成を ready と装わない。REPAIR-3）、poisoned なら false・reason `RuntimeStateUnavailable`。poisoned でも RPC は `OK` で返す（他の RPC は `INTERNAL`。kubelet はどちらもランタイム停止として扱い、condition の方が理由が伝わる）
- `NetworkReady`: `PodNetworkProvider` を注入済み（`with_pod_network`）なら true、無ければ false・reason `NetworkPluginNotReady`（containerd と同じ語彙）
- message は固定の英語文言で、入力や内部パスを含めない。並びは `RuntimeReady`、`NetworkReady` の固定
- 死活確認は足さない（#2897 の判断）。詳細は次節

## 死活確認を足さない判断（#2897）

`ContainerRuntime`・`PodNetworkProvider` に死活確認を足さず、上の「構成の有無で決め、待ちを持たない」判定を保つ（CRI-1・CRI-2・PLUG-1・PLUG-4・REPAIR-3・REPAIR-5）。

決め手になった事実:

- 本番の実行層（`CoreLifecycleRuntime`）と `PodNetworkProvider` の実装（`NetsetupPodNetwork`）は plugin-cri と同一プロセス内で、UDS 越しの proxy は無い。死活確認を書いても「状態ルートや netlink への I/O の成否」になり、死活ではない。I/O の失敗は各 RPC が既に `Err` で返す
- 本番は core の netns join 未実装（#2675）のため provider を注入せず、`NetworkReady` は意図的に false
- `ContainerRuntime` のシグネチャは #19（TASK-4.h1）の人間レビュー前の暫定版

| 案 | 内容 | 棄却理由 |
| -- | ---- | -------- |
| B1 既定実装つきメソッド | `probe` を既定 `Ok(())` で足す | 何も調べずに alive を返す既定は REPAIR-3（実装済みを装わない）に反する |
| B2 必須メソッド | 全実装に書かせる | 約 13 + 3 箇所の実装変更で波及が大きい（REPAIR-1）。#19 前の暫定シグネチャの拡張になる |
| B3 Status から期限つきで呼ぶ | 既存の worker スレッドと `runtime_timeout` に乗せる | kubelet の約 5 秒間隔に既定 10 秒の期限が重なり、呼び出しが積み上がる。「待ちを持たない」設計を崩し、Status ごとのスレッド生成が DoS 面になる |

- PLUG-4: core の差分は無い。トレイトの形を変えないため、plugin の追加で core を変える必要は生じない
- PLUG-1: 拡張点の変更は、死活に意味が生じる #1869 の proxy 導入時に設計する。「トレイトに足す」か「proxy 固有の口（`Ping`）を別の注入点で cri へ渡す」かを比べる（後者なら core のトレイトは不変）

containerd との差:

- `RuntimeReady`: containerd は常に true。本実装は未注入（`RuntimeNotConnected`）と poisoned（`RuntimeStateUnavailable`）で false にする分だけ厳しい。死活を確かめない点は同じ
- `NetworkReady`: containerd は CNI の設定が読めた状態で true（疎通は確かめない）。本実装の「provider を注入済み」も同じ粒度の「設定済み」で、疎通を主張しない。#2675 で本番が `with_pod_network` を差して true に変わっても、意味は「設定済み」のまま

再評価のトリガー: (1) #1869 の proxy 導入で実行層がプロセス外になったとき、(2) #2675 で本番が `with_pod_network` を差すとき（NetworkPlugin がプロセス外になる場合を含む）。

将来足す場合の要件: 期限は kubelet の呼び出し間隔（5 秒）未満、同時実行の確認は 1 件までに上限を設け（結果のキャッシュで Status 自体は待たない形が候補）、期限切れ・失敗は `false` と固定語彙の reason（例: `RuntimeNotResponding`）に写し、message に入力値・パスを含めない

## 本番での帰結

plugin-cri の本番は `with_runtime` を通るので `RuntimeReady=true`。一方 core の network namespace の join が未実装のため `with_pod_network` を差しておらず（[cri-config-acceptance.md](cri-config-acceptance.md) の順 13・#2675）、**本番は `NetworkReady=false`** を返す。これは意図した値で、true に装わない。kubelet ではノードの Ready が False になり、hostNetwork でない Pod は `NetworkNotReady` で拒否される（hostNetwork の Pod は動く）。join が入って `with_pod_network` を差した時点で true になる。

## runtime_handlers・features

- `runtime_handlers`: 既定ハンドラ（名前が空）の 1 件。`SUPPORTED_RUNTIME_HANDLERS` から組み立てる。`recursive_read_only_mounts=false`（`mounts.recursive_read_only` を bundle の変換が拒否）・`user_namespaces=false`（userns の写像を拒否〔#2240〕）。その拒否を外す変更はこのフラグも反転させる
- `features`: `runtime_features()` をそのまま使う（`supplemental_groups_policy=true`、`user_namespaces_host_network=false`、`mount_options=false`。後 2 つは対応する入力を拒否している現状と整合）

## verbose と info

`verbose` は受け付けるが、値によらず `info` は常に空にする。proto は空の `info` を許す。containerd のように config 一式を出すと状態ルートなどの内部パスや構成が漏れる（情報露出）。将来診断情報を足すなら、パス・環境変数・資格情報を含まない固定キーに限る。

## Version

| 項目 | 値 | 根拠 |
| ---- | -- | ---- |
| `version` | `"0.1.0"`（固定） | kubelet の `kubeRuntimeAPIVersion` と完全一致が必須。containerd も同値 |
| `runtime_name` | `"fandhe-container"` | プロジェクト名・CLI 名。node の `ContainerRuntimeVersion` が `fandhe-container://<版>` になる |
| `runtime_version` | `fandhe-container-cri` の crate 版（`CARGO_PKG_VERSION`。現状 `0.0.0`） | semver として kubelet の `ParseSemantic` を通る。`Cargo.toml` に version を足す方針（リリース版数）は本件の範囲外で、決まれば自動で追随する |
| `runtime_api_version` | `"v1"` | containerd と同値。proto のコメントは semver 互換とするが、kubelet は `ParseGeneric` で解釈でき crictl も表示するだけで困らない |

- 要求の `version` は読まない（containerd と同じ）。応答・ログ・記録へ反映せず、拒否もしない（kubelet・crictl の版差で接続不能にしない）
- 待ちを持たない（レジストリのロック・I/O・実行層・`PodNetworkProvider` を呼ばない。REPAIR-5 の期限は構造上いらない）

## UpdateRuntimeConfig

kubelet がノードの pod CIDR を渡す経路。**検証して受け、最後に受け入れた値をサービス内に記録する。`PodNetworkProvider` へは渡さない**（`CriRuntimeService::pod_cidrs`）。

- 受理規則: `runtime_config`・`network_config` が無い、または `pod_cidr` が空なら何もせず `OK`（記録は変えない。containerd と同じ）。長さは分割前に 128 バイト以下。`,` で分割し各要素の前後の ASCII 空白を除去、1〜2 件（空要素・3 件以上は `INVALID_ARGUMENT`）。各要素は `<IP>/<プレフィックス>`（IPv4 は 0〜32、IPv6 は 0〜128、先頭 0 の桁・符号・zone・角括弧は拒否）。2 件のときは IPv4 と IPv6 が 1 件ずつ（kubelet のデュアルスタックの形。containerd はこの検査をしないため差）。ホスト部のビットが立った値（`10.0.0.1/24`）は containerd の `ParseCIDR` と同じく受け、正規化せずそのまま記録する
- 検証がすべて成功してから記録を差し替える（all-or-nothing）。エラー文言・ログ・計測に入力値を含めない
- 渡さない理由: `PodNetworkProvider` へのメソッド追加は PLUG-1 の境界に近い公開トレイトの変更になる。本番の plugin-cri は `with_pod_network` を差しておらず、渡しても使われない。pod 用サブネットの出どころ（`docs/design/cri-config-acceptance.md` の「pod netns の作成・結線」の既知の差）は kubelet の pod CIDR が候補の 1 つで、記録しておけば後続で `PodSubnetPool` へ結線できる
- 未実装（REPAIR-3）: 記録した値を読む利用者はまだ無い。結線は pod network の本番注入（`cri-config-acceptance.md` の順 13）と一緒に後続で行う

## 可観測性

`cri.status`（`CriOpKind::Status`）・`cri.version`・`cri.update_runtime_config` を他の RPC と同じく全終了経路で 1 件記録する（REPAIR-4）。request の内容は記録しない。

## 試験

- `crates/cri/tests/runtime_service_version_config.rs`（`Version`・`UpdateRuntimeConfig` の具体値・不正値で記録が変わらないこと・記録）と `crates/cri/src/runtime_service/runtime_config.rs` の単体試験（境界値）
- `crates/cri/tests/runtime_service_status.rs`（構成ごとの応答を具体値で照合。provider・実行層が呼ばれないこと・provider だけの構成・応答しない実行層と provider を注入しても 2 秒以内に具体値で返ること〔#2897・REPAIR-5〕・verbose・記録）と `runtime_service.rs` の単体試験（poisoned）
- `crates/plugin-cri/tests/container_grpc.rs` の段 A（本番バイナリ）と段 B（フェイクの実行層）
