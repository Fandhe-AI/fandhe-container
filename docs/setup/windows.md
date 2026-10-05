# Windows セットアップ前提条件

Windows 利用者が fandhe-container を使う前に整えておく前提条件（WSL2・Developer Mode・`.wslconfig` の virtiofs）を定める。

- 対象ビヘイビア: WIN-5（関連: WIN-1・WIN-2・WIN-4・ERR-1）
- タスク: TASK-69（MS-5）。前提は TASK-67（#352）
- 関連 issue: #380（NTFS 差異の節は #378〔TASK-68〕、GPU の追記予定は TASK-135）
- 出典: `docs/spec/04-behavior/api-platform-windows.md` の `WIN-4`・`WIN-5`、`05-tasks.md` の `TASK-68`（submodule リビジョン `984f8a2`）

> 未検証の注記（REPAIR-3）: 本書の手順は `crates/platform-windows` の実装（TASK-67）と整合させて書いたもので、Windows 実機では未確認である。実機での再検証は TASK-67.6（#377）・TASK-68.h1（#379）で行う。NTFS 差異の節の外部コマンドの挙動も、一次資料で確認できていない事項は「要確認」と明記している。

## 前提環境の概要

- 対象は Windows 10 / 11。主経路は WSL2 経由とする（WIN-1）。Windows ネイティブコンテナと Hyper-V 直接方式は MVP の対象外（WIN-6）
- 各手順に必要な権限は次のとおり

| 手順 | 管理者権限 |
| ---- | ---------- |
| WSL2 の有効化 | 必要 |
| Developer Mode の有効化 | 必要 |
| `.wslconfig` の編集 | 不要 |

## WSL2 の有効化

対象: WIN-1・WIN-5

1. 管理者として PowerShell を開き、次を実行して再起動する。

   ```powershell
   wsl --install
   ```

2. `wsl --install` を使わない場合は、Windows 機能「Virtual Machine Platform」と「Windows Subsystem for Linux」を有効にして再起動し、次を実行する。

   ```powershell
   wsl --set-default-version 2
   ```

3. WSL2 のディストリビューションを 1 つ以上導入し、VERSION が 2 で状態が Running か Stopped であることを確かめる。

   ```powershell
   wsl -l -v
   ```

4. 次のコマンドが成功することを確かめる。実装の検出処理はこのコマンドを実行する。失敗する場合は `wsl --update` を試す。

   ```powershell
   wsl --version
   ```

virtiofs に必要な WSL の最小バージョンは、根拠となる資料がリポジトリ内にないため記載しない。

## Developer Mode の有効化

対象: WIN-4（前提）・WIN-5

- 場所: Windows 11 は「設定 > システム > 開発者向け」、Windows 10 は「設定 > 更新とセキュリティ > 開発者向け」。管理者権限が必要
- 理由: シンボリックリンクの作成に必要（WIN-4）
- 注意: 開発者向けの機能が有効になり攻撃面が広がる。不要になったら無効化してよい

大文字小文字の扱いやパス長などの NTFS 差異は「NTFS セマンティクス差異への対応（WIN-4）」節で扱う。

## `.wslconfig` で virtiofs を有効化

対象: WIN-2・WIN-5

1. `%UserProfile%\.wslconfig` を開く（なければ作る）。
2. `[wsl2]` セクションに `virtiofs=true` を書く。

   ```ini
   [wsl2]
   virtiofs=true
   ```

3. PowerShell で `wsl --shutdown` を実行し、WSL を再起動する。稼働中の VM には設定が反映されない。

   ```powershell
   wsl --shutdown
   ```

ファイル形式の注意（実装の解釈規則）:

- セクション名とキー名は大文字小文字を区別しない
- 値は `true` / `false`（大文字小文字不問）だけが真偽として扱われる
- 行末コメントは解釈されず値の一部になる。コメントは `#` か `;` で始まる独立した行に書く
- 文字コードは UTF-8（BOM は可）。サイズは 64 KiB まで
- 読み取り専用のファイルは実装が書き換えない。属性や ACL を外す必要はない

確認方法: ディストリ内で `/proc/self/mountinfo`（または `findmnt`）を見て、共有の fstype が `virtiofs` であることを確かめる。実装もマウント後に fstype で検証している。

未検証の注記（REPAIR-3）: `[wsl2]` の `virtiofs=true` というキーの配置と、drvfs のマウントが virtiofs で成立するかは Windows 実機で未検証（WIN-2 の再検証条件 1。手順は TASK-67.6〔#377〕）。なお現状、実装が `.wslconfig` を自動で書く経路は本番コードに配線されていない（plugin-windows への配線は TASK-116）ため、手作業で設定する。

## virtiofs が使えないとき（9P フォールバック）

- 既定の `TransportPolicy::PreferVirtiofs` では、警告を出したうえで 9P に切り替えて続行する（暗黙には降格しない）
- `TransportPolicy::RequireVirtiofs` では `FAILED_PRECONDITION` で起動を拒否する

| 警告コード | 意味 | 対処 |
| ---------- | ---- | ---- |
| `VIRTIOFS_NOT_ENABLED` | `.wslconfig` で virtiofs が有効でない | 「`.wslconfig` で virtiofs を有効化」の手順を実施する |
| `VIRTIOFS_NOT_APPLIED` | `.wslconfig` では有効だが共有が 9P になっている | `wsl --shutdown` してから再試行する。直らない場合は WSL カーネルが virtiofs に未対応の可能性がある |

## エラー・警告と本書の節の対応表

| 実装のメッセージ（抜粋） | 参照する節 |
| ---------------------- | ---------- |
| `WSL2 is not enabled. Run 'wsl --install' ...`（`FAILED_PRECONDITION`） | WSL2 の有効化 |
| `wsl.exe was not found. WSL is not installed. ...`（`NOT_FOUND`） | WSL2 の有効化 |
| `no usable WSL2 distribution is available. ...` | WSL2 の有効化（手順 3） |
| `Set 'virtiofs=true' under [wsl2] in .wslconfig and run 'wsl --shutdown' ...` | `.wslconfig` で virtiofs を有効化 |
| `VIRTIOFS_NOT_ENABLED` / `VIRTIOFS_NOT_APPLIED` | virtiofs が使えないとき（9P フォールバック） |

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

Windows ホストでシンボリックリンクを作成するには、**Developer Mode の有効化**（またはシンボリックリンク作成特権の付与）が前提条件である。未設定だと作成に失敗する。有効化の手順は「Developer Mode の有効化」節（TASK-69・WIN-5）を参照する。

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

## GPU 付きコンテナの追加設定（WIN-5 追記候補）

TASK-135 で、実機の実測後に追記する予定。WIN-5 の追記候補は「検討中」のため確定扱いにしない（GPU-7）。本節は予約で、内容は未記載。
