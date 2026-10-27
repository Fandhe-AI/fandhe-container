# macOS セットアップ前提条件

macOS 利用者が fandhe-container を使う前に整えておく前提条件（対応版・Virtualization.framework の entitlement とコード署名・ゲストカーネルと initrd の用意）を定める。実装済みのものと未実装・判断待ちのものを分けて書く。

- 対象ビヘイビア: MAC-1・CLI-2（関連: CLI-1・MAC-4・PLUG-11・OCI-5・REPAIR-3）
- タスク: TASK-80 追補・TASK-64
- 関連 issue: #2602・#2452・#1906（既定方式）・#1628（実機確認）・#1867・#1868・#1869・#2431・#1823

> 未検証の注記（REPAIR-3）: 本書は実装（`crates/platform-macos`・`crates/cli`・`guest/kernel/`・`scripts/build-guest-initrd.sh`）と `AGENTS.md` の手順に合わせて書いたもので、macOS 実機では未確認である。実機での確認は #1628（人間担当）で行う。一次資料で確かめられていない事項は「要確認」と明記している。

## 現状（実装済みと未実装）

| 項目 | 状態 | 備考 |
| ---- | ---- | ---- |
| VM の設定・起動・停止、virtiofs のデバイス構成、ゲスト内 mount の指示と報告の検証（`crates/platform-macos`） | 実装済み（実機未確認） | 実行前提は entitlement とコード署名（下記）。実機確認は #1628 |
| macOS backend plugin（`fandhe-container-plugin-macos`）の UDS 越しの create / start / stop | 実装済み（実機未確認） | create 要求ごとに kernel・initrd のパスを受け取る |
| ゲストカーネル・initrd のビルドスクリプト | 実装済み（macOS ホストでのビルド・リンクと VM での起動は未確認） | `make guest-kernel-build`・`make guest-initrd-build` |
| `fandhe-container setup` の手順表示 | 実装済み | 表示のみ。検出も適用もしない |
| CLI から plugin を起動する経路と RPC | 未実装（設計案 #1869 は承認待ち） | 現状、日常操作コマンドは `FAILED_PRECONDITION`（5）などで fail-closed に止まる |
| 非 Linux の plugin の信頼性検証（PLUG-11） | 未実装 | 検証は常に拒否される。許可済みハッシュ一覧は未配線（#1868、承認待ち） |
| `setup` のステップの自動検出・適用 | 未実装（TASK-125） | |

判断待ち:

- 既定方式（常駐 VM の共用）の未決事項: #1906（`docs/design/macos-shared-vm.md`、承認待ち）
- 状態ルートの既定: #2431（`docs/design/macos-state-root.md`、承認待ち）
- 許可済みハッシュ一覧の置き場所と作り方: #1868（`docs/design/plugin-hash-allowlist.md`、承認待ち）
- Intel Mac への対応: ゲストカーネルは arm64 のみ（#1823 で決定済み）

## `fandhe-container setup` の表示

macOS で `fandhe-container setup` を実行すると、次の 2 ステップを 1 行 1 JSON で表示する（CLI-1・CLI-2。#2452）。各行の `instructions` は本書の該当節と同じ手順の固定文言（英語）で、CLI は表示するだけで実行しない。

| ステップ ID | 本書の節 | 管理者権限 |
| ----------- | -------- | ---------- |
| `virtualization-entitlement` | entitlement とコード署名 | 不要 |
| `macos-min-version` | macOS の版 | 不要 |

- `setup` は macOS の版も署名も検出・変更しない。ステップが残るため終了コードは 8（`UNIMPLEMENTED`）になる
- ステップの検出・適用は `setup` の範囲外で、plugin 経由の将来仕様（TASK-125。#1869 の設計）である（REPAIR-3）

## macOS の版

ステップ ID: `macos-min-version`。対象: MAC-1

- macOS 13 以上は Virtualization.framework を使うための暫定の最低版で、spec では未定義である。確定したら spec 側の更新が必要になるため、ユーザーへ報告する
- 確認コマンド:

  ```sh
  sw_vers -productVersion
  ```

- fandhe-container は macOS の版を確認も更新もしない
- ゲストカーネルは arm64 のみのため、実質的な対象は Apple Silicon である（#1823）

## entitlement とコード署名

ステップ ID: `virtualization-entitlement`。対象: MAC-1

- 署名の対象は backend plugin の `fandhe-container-plugin-macos` である。CLI やほかのバイナリではない
- 必要な entitlement は `com.apple.security.virtualization` のみ。ad-hoc 署名でよい
- entitlements の plist は次のとおり（`crates/platform-macos/tests/vm_boot.entitlements` と同じ内容。同ファイルを流用してよい）:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
      <key>com.apple.security.virtualization</key>
      <true/>
  </dict>
  </plist>
  ```

- 署名コマンド（`<...>` は環境に合わせて置き換える）:

  ```sh
  codesign --sign - --force --entitlements <plist のパス> <fandhe-container-plugin-macos のパス>
  ```

- 再ビルドすると署名が外れるため、ビルドのたびに署名し直す
- 署名の確認方法（例: `codesign --display --entitlements - <パス>`）は一次資料で確かめていないため要確認
- 注意: この entitlement は、署名したバイナリに VM の作成を許す。`fandhe-container-plugin-macos` 以外に付けない。sudo も SIP の変更も要らない。fandhe-container はバイナリへの署名を行わない

## ゲストカーネルと initrd の用意と配置

- カーネル: `make guest-kernel-build` で作る。出力は `target/guest-kernel/<guest/kernel/source.lock の版>/arm64/Image`（ほかに `config`・`build-info.txt`）。GPL-2.0 で、ソース提供の材料と取得物の sha256 照合は `guest/kernel/README.md` にある。tarball の署名検証は未確認
- initrd: `make guest-initrd-build` で作る（`rustup target add aarch64-unknown-linux-musl` が要る）。出力は `target/guest-initrd/aarch64/initrd.cpio.gz` と `build-info.txt`
- どちらの成果物もコミットしない。macOS ホストでのビルド・リンクと VM での起動は未確認である（#1628）
- 配置は判断待ちである。製品として kernel・initrd を置く既定の場所は無い。plugin-macos は create 要求ごとにパスを受け取るが、CLI から渡す経路は未実装（#1869）。共用 VM の保持役とゲスト向けバイナリの配置は #1906 の判断待ち
- 実機前提テストでは環境変数 `FANDHE_CONTAINER_MACOS_VM_KERNEL` などで渡す（`AGENTS.md`「実機前提テスト」の「ゲスト資産の用意」を参照）。試験専用で、製品の設定経路ではない

## plugin の配置と信頼性検証

未実装・判断待ち。既定の探索先は system の `/usr/local/libexec/fandhe-container/plugins` と user の `<XDG_DATA_HOME>/fandhe-container/plugins`（無ければ `~/Library/Application Support/fandhe-container/plugins`）の 2 か所（#1539・#1863）だが、信頼性検証（PLUG-11）は #1865 まで常に拒否される（fail-closed）。許可済みハッシュ一覧の作り方（署名後のバイナリのハッシュを載せる方針は #1539）は #1868 の承認後に本節へ書く。

## 状態ルート

判断待ち。macOS には状態ルートの既定が無く、`--root` の指定が要る（#2431）。`FileStateStore` は所有者・権限（0700）・拡張 ACL の有無を検査する（OCI-5）。

## 判断待ちの一覧

| issue | 内容 | 影響する節 |
| ----- | ---- | ---------- |
| #1906 | 既定方式（常駐 VM の共用）の未決事項 | ゲストカーネルと initrd の用意と配置 |
| #1628 | 実機での最小 VM の起動確認（人間担当） | 全節 |
| #1867 | macOS の信頼性検証の結果を CLI に反映 | plugin の配置と信頼性検証 |
| #1868 | 許可済みハッシュ一覧 | plugin の配置と信頼性検証 |
| #1869 | plugin の起動と RPC の配線 | 現状、ゲストカーネルと initrd の用意と配置 |
| #2431 | 状態ルートの既定 | 状態ルート |
