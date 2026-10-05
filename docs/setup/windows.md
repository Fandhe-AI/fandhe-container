# Windows セットアップ手順（WSL2）

Windows ホスト（NTFS）と WSL2 内ゲスト（ext4）の間でディレクトリを共有するときの、ファイルシステムセマンティクス差異への対応手順をまとめる。

> **位置づけ**: 本書は利用者向けのセットアップ手順である。**実機（Windows）での手順確認は未実施**で、確認は #379（TASK-68.h1。人間担当）で行う。外部コマンドの挙動のうち一次資料で確認できていない事項は「要確認」と明記する。

- 対象ビヘイビア: WIN-4（Should・確定。関連: IO-5・WIN-5）
- タスク: TASK-68（MS-5。本書は #378）
- 関連 issue: #379（実機確認。人間担当）・#380（TASK-69。WSL2 有効化・Developer Mode 有効化・`.wslconfig` 設定。WIN-5）
- 出典: `docs/spec` の `04-behavior/api-platform-windows.md` の `WIN-4`、`05-tasks.md` の `TASK-68`

## 前提条件（TASK-69・WIN-5 で追記）

WSL2 の有効化・Developer Mode の有効化手順・`.wslconfig` の設定は TASK-69（#380・WIN-5）で本節に追記する。本書の WIN-4 の各節は、それらが済んでいることを前提とする。

## NTFS セマンティクス差異への対応（WIN-4）

| 項目 | Windows ホスト（NTFS） | WSL2 ゲスト（ext4） | 起きうる問題 |
| ---- | ---------------------- | ------------------- | ------------ |
| 大文字小文字 | 既定で区別しない | 区別する | 大文字小文字違いのみのファイルが黙って上書きされる |
| パス長 | `MAX_PATH`（260 文字）が既定の上限 | 制限が緩い | 長いパスの作成・参照が失敗する |
| シンボリックリンク | 作成に権限が必要 | 制限なし | 作成に失敗する |

### 大文字小文字の区別: per-directory case-sensitive フラグ

NTFS のディレクトリ単位の case-sensitive フラグを、fandhe-container の共有ルート配下のディレクトリに設定すると、そのディレクトリでは大文字小文字が区別される。

Windows 側（管理者権限の PowerShell。要確認: 権限と WSL 機能の要否）:

```powershell
fsutil.exe file setCaseSensitiveInfo "C:\fc\proj" enable
fsutil.exe file queryCaseSensitiveInfo "C:\fc\proj"
```

WSL 側（拡張属性。値 `1` が有効）:

```sh
setfattr -n system.wsl_case_sensitive -v 1 "/mnt/c/fc/proj"
getfattr -n system.wsl_case_sensitive "/mnt/c/fc/proj"
```

注意事項（いずれも一次資料の記述に基づく想定で、#379 で実機確認する）:

- 適用先は共有ルート配下に限る。システムディレクトリやドライブ直下には設定しない
- 新規に作成されるサブディレクトリはフラグを継承するが、既存のサブディレクトリには及ばない
- 大文字小文字だけが違う名前が既に存在するディレクトリでは、フラグを無効化できない
- フラグを設定したディレクトリでは、大文字小文字を区別しない前提の Windows アプリが誤動作することがある
- 管理者権限の操作はローカルの攻撃面を広げる。必要な範囲に限って実行する
- DrvFs のマウントオプション `case=dir|off|force`（`/etc/wsl.conf` の `[automount] options`）はフラグの扱いに関わる。既定値は要確認。fandhe-container の共有マウントは `case=` を渡していない（`nosuid,nodev` と、読み取り専用時の `ro` のみ）
- virtiofs（`.wslconfig` の `virtiofs=true`）経由のマウントで、フラグ・拡張属性が同様に機能するかは**未確認**（要確認。#379）

fandhe-container 側の挙動（IO-5）:

- 大文字小文字違いのみの衝突は、フラグの有無にかかわらず `AlreadyExists` の構造化エラー（`code`・`message`）として検出する方針である。フラグを観測しないため、フラグを設定したディレクトリでは過検出側に倒れる
- 検出関数（`check_case_collisions`・`CaseCollisionSet`）は `crates/io` に実装済みだが、稼働中コンテナのワイヤー上の作成要求への組み込みは**未実装**（REPAIR-3）。現状、フラグを設定しない構成での黙った上書きは fandhe-container では防げない

### パス長: 260 文字以内の推奨

ホストのフルパス（共有ルート＋コンテナ内の相対パス）を 260 文字以内に収める。共有ルートは短くする（例: `C:\fc\proj`）。per-directory case-sensitive フラグは `MAX_PATH` を緩めない。

fandhe-container 側の挙動（IO-5・TASK-20）:

- `check_host_path_length` は 260 を許容し、261 以上を `InvalidArgument` で拒否する。メッセージに計測値と上限を含む
- `measure_host_path_length` は失敗しない計測で、警告用途に使う
- 計数単位は UTF-16 コード単位である。共有ルート自体の検証（`HostDir::parse`）は Unicode スカラー値単位で最大 260 文字を許容し、受け付けるのはドライブレター付き絶対パス（`X:\dir`）のみである（UNC・デバイスパス・ドライブ直下は拒否）。両者の計数単位が異なる点に注意する

未対応（REPAIR-3）:

- 書き込み経路への組み込み（検証関数のみ実装済み）
- `\\?\` 長パスと `LongPathsEnabled`（有効化しても現状は 260 で判定する）
- コンポーネント単位（255）の制限の検証
- シンボリックリンクのリンク先パス長の検証

### シンボリックリンク: Developer Mode が前提条件

Windows ホストでシンボリックリンクを作成するには、**Developer Mode の有効化**（またはシンボリックリンク作成特権の付与）が前提条件である。未設定だと作成に失敗する。有効化の手順は「前提条件」節（TASK-69・WIN-5 で追記）を参照する。

- fandhe-container は Developer Mode の有効状態を検査しない（現状）
- Developer Mode や特権の付与はローカルの攻撃面を広げるトレードオフがある。シンボリックリンクが必要な構成に限って有効化する

### 現状の挙動と既知の制限（REPAIR-3）

| 項目 | 現状 |
| ---- | ---- |
| 大文字小文字の衝突検出 | 検出関数は実装済み。ワイヤー経路へは未組み込み |
| パス長の検証 | 検証関数は実装済み。書き込み経路へは未組み込み |
| per-directory フラグの設定・読み取り | fandhe-container は行わない。本書の手順で利用者が設定する |
| Developer Mode の検査 | 行わない |
| virtiofs 経由でのフラグの有効性 | 未確認（#379） |
