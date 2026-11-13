# `--image-root` の既定の位置と `image prune` の配線

`image ls` / `image rm` / `image tag` / `image prune` / `system df` が `--image-root` を省いたときの既定の位置と、
`image prune` の CLI 配線の判断記録（#2384・OCI-7・CLI-1・MAC-4・WIN-1・OCI-5）。実装は `crates/cli/src/commands/image_root.rs`
（解決）と `image.rs`（配線）。

## 判断の状態

| 項目 | 状態 |
| ---- | ---- |
| macOS ホストは既定なし（恒久の fail-closed） | 承認済み（#2431 案 A。[macos-state-root.md](macos-state-root.md) 節 5） |
| Linux の既定 `<状態ルート>/.cri/images` | Agent の記録した判断。オーナー確認待ち |
| Windows ホストは `UNIMPLEMENTED`（ゲスト内は Linux の規則） | Agent の記録した判断。オーナー確認待ち |
| `image prune` の構文・出力・終了コード | Agent の記録した判断。オーナー確認待ち |

## 決定

### 1. Linux の既定 `<状態ルート>/.cri/images`

- 状態ルートは `StateRoot::resolve(--root)` の結果（root は `/run/fandhe-container`、rootless は `$XDG_RUNTIME_DIR/fandhe-container`、
  `--root` を渡せばその値）。既定はその直下の `.cri/images`
- 根拠: 在庫を埋める経路は plugin-cri の `PullImage` だけで（CLI に `pull` は無い。[pull-inventory-wiring.md](pull-inventory-wiring.md)）、
  そのキャッシュは既定の状態ルート直下の `.cri/images`（`crates/plugin-cri/src/adapter.rs` の `IMAGES_DIR`）。これ以外を既定にすると
  何も入っていない空のストアを開くことになる
- `--root` を渡すと、その状態ルートの `.cri/images` になる。plugin-cri は `--root` を受けないため、`--root` を省いたときだけ
  plugin-cri と同じストアになる
- 解決では何も作らない。存在・symlink・所有者・mode・祖先の検査は `ImageStore::open` が行う（#2381・#2547）。無ければ従来どおり
  `NOT_FOUND`（`image store root not found`）
- rootless で `XDG_RUNTIME_DIR` が無いときは `StateRoot::resolve` の `FAILED_PRECONDITION` をそのまま返す（`/tmp` へ落とさない。ERR-2）
- 不採用: 永続の `/var/lib/fandhe-container/images`・`$XDG_DATA_HOME/fandhe-container/images`（どの経路も埋めず、plugin-cri の
  置き場と食い違う）、`--image-root` を必須のままにする案（受け入れ条件に反する）。再評価条件は「再起動をまたいでイメージを残す要件が
  確定したとき」「plugin-cri のキャッシュを移すとき」

### 2. macOS ホスト: 既定なし

`--root` の有無によらず `FAILED_PRECONDITION` と固定文言
（`default image root is not defined on a macOS host by design; pass --image-root or use the Linux guest path`）で拒否する。
`StateRoot::resolve` には委ねない（委ねると `--root` つきで既定ができてしまう）。

### 3. Windows

core と CLI は WSL2 ゲストの中で動く（[windows-execution-layout.md](windows-execution-layout.md) 節 1）ため、ゲスト内は Linux の規則が
そのまま効く。Windows ホスト側の `ImageStore::open` は恒久拒否（#2428 案 C）なので、`--image-root` を省いたときは
`UNIMPLEMENTED` と固定文言（`default image root is defined only inside a Linux guest`）で拒否する。

### 4. 解決の順序

`--image-root` を省いたときは、非 Linux の plugin 解決の失敗（`non_linux_failure`）より先に既定を解決する。これで macOS の
「既定なし」と Windows の `UNIMPLEMENTED` が観測できる。`--image-root` を渡したときの非 Linux の挙動は従来どおり。

### 5. `image prune`

- 構文は `image prune [--image-root <abs>]`。位置引数・`--force`・`--all` は受けない。oci の prune は「タグもコンテナ参照も無い
  manifest」だけを消すので Docker の既定（dangling）と同じ意味。確認の対話はしない
- 実行前に契機 B の照合を行う（[container-ref-reconcile.md](container-ref-reconcile.md) 決定 2）。タグが 0 件でコンテナ参照のある
  manifest の参照を候補として集め、ガードを手放した状態で照合・回収し、もう一度ガードを取って prune を実行する。照合は
  `NotFound` の状態だけを回収し、上限は 256 件、ゲートの排他が取れなければ飛ばす（残す側に誤る）
- 出力（stdout・タブ区切り・LF）: `deleted<TAB><manifest>`・`deleted-blob<TAB><digest>`・`undeleted-blob<TAB><digest>`、
  末尾に必ず `reclaimed-bytes<TAB><n>`（0 件なら `reclaimed-bytes<TAB>0` のみ）
- 終了コード: `undeleted-blob` があれば出力したうえで `INTERNAL`（1）。`FailedPrecondition` は blob ディレクトリの不正と未完了の
  削除が同じ code で来るため、両方を含む固定文言にする。`Lock` / `Timeout` は `image store is locked by another operation`

## 残余

- 引数なしの `image prune` は、CRI が digest 指定で pull したタグなしのイメージも消しうる。その結果 plugin-cri の
  `@cri-image-records.json` が古いまま残る。記録と在庫の突き合わせは #4264 で追う
- `/run` は tmpfs のため、既定のストアは再起動で消える（plugin-cri と同じ）
- cli の `CRI_IMAGE_STORE_SUBDIR` と plugin-cri の `IMAGES_DIR` は二重定義で、試験は cli 側の値を固定するだけ
- `create --image`（`--image-root` との組が必須）と `delete`（記録した root を使う）は今回変えない
- `crates/cli/tests/local_image_gc.rs` の prune は oci の API を直接呼ぶまま（CLI 経由への切り替えは別 issue）
