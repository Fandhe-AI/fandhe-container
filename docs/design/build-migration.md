# `build:` と Docker ソケットの移行（外部ビルド手順・CI ランナー等の移行方針）

- 関連 issue: [#613](https://github.com/Fandhe-AI/fandhe-container/issues/613)（TASK-154）・[#614](https://github.com/Fandhe-AI/fandhe-container/issues/614)（TASK-154.1。PR #3600）・[#615](https://github.com/Fandhe-AI/fandhe-container/issues/615)（TASK-154.2）
- ステータス: 「現状」「移行手順の概要」は現行実装の記述。「移行方針」（未解決疑問点 13・15）はオーナー承認待ちの判断記録で、採否は決めていない
- 対象ビヘイビア: STACK-7（関連: STACK-3・STACK-5・D-16・D-17・D-18。SEC-1）。マイルストーン: MS-12
- 出典: `docs/spec` は ID で参照するだけで本文は転記しない。一次判定の対象コーパスの名称・件数・内容も転記しない（[declarative-config.md](declarative-config.md) と同じ扱い）

## 現状（実装済みの範囲）

- compose 変換器（`crates/compose-convert`）は `services.*.build` と、Docker ソケット（`/var/run/docker.sock`・`/run/docker.sock` の完全一致。short / long syntax）の bind mount を `error-incompatible` に分類し、blocker に `guidance` を付ける（TASK-154.1・STACK-7）
- `guidance.code` は `external-build`（`build:`）と `docker-socket`（ソケット bind）の 2 種。案内文は固定の英語で、サービス名や build context を含まない。文言の正は `classify.rs` の `IncompatibleGuidance`
- `--downgrade` が格下げできるのは `error-unsupported-yet` だけで、`build:`・ソケット bind は格下げできない（TASK-182.1）
- 未実装（REPAIR-3）: TOML の書き出し（集計行に `toml_output:"unimplemented"` が出る）、`up` / `down` / `ps` / `logs`（TASK-155）、CLI の `pull`、ローカルからのイメージ取り込み（OCI レイアウト・tar）
- 案内文 `external-build` は「push it to a registry or load it locally」と言うが、ローカル取り込みの経路は存在しない。現行で動く経路は registry 経由だけである

## D-16 で変換しない理由

- Docker Engine API（REST・ソケット）は提供しない（D-16）。そのため、イメージのビルド API を前提にした `build:` と、API を叩くジョブは動かない
- ソケットの bind は、コンテナにホストの Docker デーモンの操作権（実質的にホスト root 相当）を渡す。API 非互換に加えて、分離を既定で閉じる方針（SEC-1・fail-closed）からも受けない
- 回避策としてソケットの bind や `privileged` を勧めない

## 移行手順の概要

1. 変換レポートの blocker で、`guidance.code` が `external-build` / `docker-socket` のサービスを特定する
2. `build:` のサービスは、イメージを外部ツール（例: `docker build`・`podman build`・`buildah`。特定ツールは推奨しない）で別工程としてビルドする
3. ビルドしたイメージをレジストリへ push する（例: `registry.example.com/app:1.0`。完全性の担保には digest 指定の参照が望ましい）
4. 変換元の compose の `build:` を `image:` の参照に置き換え、変換し直す
5. 実行側はレジストリから pull する。現行の pull は CRI（plugin-cri の ImageService → `OciImagePuller::pull`）の経路だけで、CLI の `create --image-root <dir> --image <ref>` は既存のストアを使う
6. ソケットを要するジョブ（CI ランナー・docker-in-docker のビルド）は、Docker Engine のあるホストで動かすか、ビルドを外部化して `image:` で参照する（案内文 `docker-socket` と同じ内容）

手順 4〜5 のうち「変換 → TOML → `up`」は、TOML の書き出しと `up`（TASK-155）が入るまで通しでは成り立たない。CLI の `pull` とローカル取り込みも未実装である。

## 移行方針（判断記録・オーナー承認待ち）

CI ランナー等の既存構成を移行する方針は、spec で未解決疑問点 13（ビルド機能の扱い）・15（既存構成の移行方針）として未決である。以下は判断材料の整理で、採否は決めない。

- 判断材料: PoC-16 では、変換不能の `build:` とソケット bind が CI ランナー等の構成に集中した。PoC-15 では、Docker の `FORWARD` drop を自前の nft テーブルで覆せず、併存させるには利用者側の設定が要った

| 案 | 内容 | 利点 | 代償・前提 |
| -- | ---- | ---- | ---------- |
| (a) | Docker を併存させ、該当構成を移行対象外とする | 追加実装が不要 | 併存には PoC-15 の利用者側設定が要る。対象外の構成が残る |
| (b) | CI ランナー側のコンテナ実行の差し替え機構で置き換える | ソケットに依存しない構成へ寄せられる | 機構の有無は spec で要調査。一次情報で未確認のため本書では断定しない |
| (c) | 新書式（TOML）へ段階的に移行する | 方針と整合する | TOML の書き出し・`up`（TASK-155）が前提で、未実装 |

- 未決事項: 移行の優先順位を PoC-16 の変換カバー率で決めてよいか
- 推奨は置かない。採否はオーナーが決める（spec の変更が必要ならユーザーへ報告する）

## 残る作業・再評価条件

- TOML の書き出し・`up`（TASK-155）・CLI の pull / ローカル取り込みが入ったら、手順の節を更新する
- オーナーが 13・15 を決めたら、判断記録を確定に移し、[architecture.md](../architecture.md) の項目を「確定済み設計判断」の表へ移す
- 自前のビルド・push の扱い（13 の後半）は将来（Could）
- `external-build` の案内文の "load it locally" と実装の食い違いは別途追跡する
