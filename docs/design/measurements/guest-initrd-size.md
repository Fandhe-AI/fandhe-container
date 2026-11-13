# ゲスト向け cli・supervisor を入れた initrd のサイズ測定記録

macOS の共用ゲスト VM（既定方式）に入れる CLI（Linux 版）と supervisor を initrd に梱包するスクリプトの拡張（#2275・MAC-4・TASK-191・G8）と、そのサイズの記録。設計は [macos-shared-vm.md](../macos-shared-vm.md) の「ゲスト向けバイナリ」。

## 梱包の配置（実装済み）

`scripts/build-guest-initrd.sh --with-runtime`（環境変数 `GUEST_INITRD_WITH_RUNTIME=1`）で有効になる opt-in。指定しない場合の出力（cpio のバイト列）は従来と同じで、`/init` 1 個だけである。

| パス | 種別 | mode | 所有者 |
| ---- | ---- | ---- | ------ |
| `/init` | file | 0755 | root |
| `/usr/libexec/fandhe-container/fandhe-container` | file（CLI） | 0755 | root |
| `/usr/libexec/fandhe-container/fandhe-container-supervisor` | file | 0755 | root |

- 親ディレクトリ（`usr`・`usr/libexec`・`usr/libexec/fandhe-container`）は 0755・root で、ファイルより先に cpio へ置く（カーネルの initramfs 展開は親のエントリが無いファイルを落とすため）
- CLI は `current_exe()` と同じディレクトリの固定名 `fandhe-container-supervisor` を起動するため、2 つは同じディレクトリに置く。ゲスト内の呼び出し側（#2273・#4658）はこの固定の絶対パスで呼び、`PATH` を探さない
- 特権ランチャー `fandhe-container-launcher` は入れない。CLI の隣にあると rootful 扱いでランチャー経由になるため。ゲスト内での要否は #4660 で決める
- 非特権ユーザーがバイナリを書き換えられないよう、所有者は root・mode は 0755 にする
- 入力は `--cli` / `--supervisor`（両方指定か両方省略）で渡せる。省略時は `aarch64-unknown-linux-musl` で `-p fandhe-container-cli --bin fandhe-container -p fandhe-container-supervisor --bin fandhe-container-supervisor` を 1 回の `cargo build --release --locked` で作る（feature は既定のまま）
- 上限: 入力 1 個 64 MiB、init・cli・supervisor の合計 192 MiB。検査（静的リンク・ET_EXEC・aarch64・所有者・書き込み権限）は 3 個に同じものを適用する
- `build-info.txt` の既存 8 行の後ろに `runtime`・`cpio_bytes`・`initrd_bytes` と、`--with-runtime` のときは各バイナリの path・sha256・bytes を追記する

## 実測値

未計測。ローカルで `scripts/build-guest-initrd.sh --with-runtime` を実行したところ、`aarch64-unknown-linux-musl` の実リンクが失敗した（2026-11-13、rustc stable、ホスト Linux x86_64、リンカ rust-lld）。

```text
rust-lld: error: undefined symbol: renameat2
>>> referenced by fandhe_container_core::sys::rename_noreplace_at
>>> did you mean: renameat
>>> defined in: .../aarch64-unknown-linux-musl/lib/self-contained/libc.a(renameat.lo)
```

- 原因: `crates/core/src/sys.rs` が `renameat2` を `extern "C"` で宣言して直接呼んでいるが、この toolchain 同梱の musl の `libc.a` には `renameat2` のラッパーが無い。CLI と supervisor の両方が core を経由して参照する。#2274 の `cross-target-check` は型検査だけでリンクしないため検出できなかった
- 本 issue の範囲は梱包スクリプトで、core の `sys` は変えない（別 issue で扱う。`syscall(2)` 経由に直す等。追跡先の issue 番号は未起票で、オーナー承認後の起票を待つ）。解消後に同じコマンドで測定し、本節へ貼る
- 測定手順（解消後）: リポ外の容量のある一時領域を `TMPDIR` に向け、`GUEST_INITRD_WITH_RUNTIME=1 scripts/build-guest-initrd.sh --output-dir <新規ディレクトリ>` を実行する。`build-info.txt` の `init_bytes`・`cli_bytes`・`supervisor_bytes`・`cpio_bytes`・`initrd_bytes`（gzip）と、`file` / `od` による ET_EXEC・静的の確認結果、rustc の版、所要時間を記録する

| 項目 | bytes |
| ---- | ----- |
| init | 未計測 |
| cli | 未計測 |
| supervisor | 未計測 |
| cpio（無圧縮） | 未計測 |
| initrd（gzip） | 未計測 |

## 未決事項（判断事項）

- initrd に入れるか、データディスクに置くか: 実測値が得られてから判断する（上の表が埋まるまで保留）
- `--with-runtime` を既定にするか: 同上。それまでは opt-in で、既存の実機手順（`/init` だけの initrd）を変えない
- ET_DYN（static-pie）になった場合: 現行の検査は PIE を拒否する。リンクが通った後に PIE と判定された場合は、非 PIE の指定（`-C relocation-model=static`）で通るかを先に確かめる

## 対象外（追跡先）

- `/etc/passwd` 相当の梱包と降格: #4658
- subordinate ID の梱包と launcher の要否: #4660
- ゲスト内の supervisor 起動モード: #4659
- guest-init からの固定パスでの起動と vsock の中継: #2273
- macOS ホストでのリンク、VM での起動、ゲスト内での実行の確認: #1628・#2282（人間担当）
- 配布を有効にするときの `NOTICE`・third-party licenses の同梱: [licensing](../../../.claude/rules/licensing.md) の「配布物への同梱」に従う
