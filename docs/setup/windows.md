# Windows セットアップ前提条件

Windows 利用者が fandhe-container を使う前に整えておく前提条件（WSL2・Developer Mode・`.wslconfig` の virtiofs）を定める。

- 対象ビヘイビア: WIN-5（関連: WIN-1・WIN-2・WIN-4・ERR-1）
- タスク: TASK-69（MS-5）。前提は TASK-67（#352）
- 関連 issue: #380（NTFS 差異の節は #378〔TASK-68〕、GPU の追記予定は TASK-135）・#1317（Win32 固有の名前の決定）・#1855（8.3 短縮名の節）・#3113（fsutil 8dot3name の一次資料確認）
- 出典: `docs/spec/04-behavior/api-platform-windows.md` の `WIN-4`・`WIN-5`、`05-tasks.md` の `TASK-68`（submodule リビジョン `984f8a2`）

> 未検証の注記（REPAIR-3）: 本書の手順は `crates/platform-windows` の実装（TASK-67）と整合させて書いたもので、Windows 実機では未確認である。実機での再検証は TASK-67.6（#377）・TASK-68.h1（#379）で行う。NTFS 差異の節の外部コマンドの挙動も、一次資料で確認できていない事項は「要確認」と明記している。

実行構成（設計のみ・未実装）: core・CLI・supervisor は WSL2 ゲストの中で動かし、ホストには薄い起動役だけを置く（#1415）。詳細と未決事項は [windows-execution-layout.md](../design/windows-execution-layout.md)（#1862）。

## 前提環境の概要

- 対象は Windows 10 / 11。主経路は WSL2 経由とする（WIN-1）。Windows ネイティブコンテナと Hyper-V 直接方式は MVP の対象外（WIN-6）
- 各手順に必要な権限は次のとおり

| 手順 | 管理者権限 |
| ---- | ---------- |
| WSL2 の有効化 | 必要 |
| Developer Mode の有効化 | 必要 |
| `.wslconfig` の編集 | 不要 |

## `fandhe-container setup` の表示

Windows で `fandhe-container setup` を実行すると、次の 3 ステップを 1 行 1 JSON で表示する（CLI-1・CLI-2。#2452）。各行の `instructions` は本書の該当節と同じ手順の固定文言（英語）で、CLI は表示するだけで実行しない。

| ステップ ID | 本書の節 | 管理者権限 |
| ----------- | -------- | ---------- |
| `wsl2-enable` | WSL2 の有効化 | 必要 |
| `developer-mode` | Developer Mode の有効化 | 必要 |
| `wslconfig-virtiofs` | `.wslconfig` で virtiofs を有効化 | 不要 |

- `setup` は WSL2・Developer Mode・`.wslconfig` を検出も変更もしない。ステップが残るため終了コードは 8（`UNIMPLEMENTED`）になる
- ステップの検出・適用は `setup` の範囲外で、plugin 経由の将来仕様（TASK-125。#1869 の設計）である（REPAIR-3）

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

未検証の注記（REPAIR-3）: `[wsl2]` の `virtiofs=true` というキーの配置と、drvfs のマウントが virtiofs で成立するかは Windows 実機で未検証（WIN-2 の再検証条件 1。手順は TASK-67.6〔#377〕）。なお現状、実装が `.wslconfig` を自動で書く経路は本番コードに配線されていない（`.wslconfig` を確認・設定するのはホストの起動役で、まだ配線されていない。構成は [windows-execution-layout.md](../design/windows-execution-layout.md)〔設計ドラフト・承認待ち〕）ため、手作業で設定する。

## ゲスト側の前提（共有マウントの解除。SEC-1・WIN-1）

共有マウントの解除では、ゲスト内のスクリプトがマウント先のパスを実際に開いた fd の `mnt_id`（`/proc/self/fdinfo/<fd>`）を記録値と照合してから `umount` する。祖先（`/mnt/fandhe` 等）に別のマウントが重ねられても、別のマウントを外さないための確認である（不一致は外さず終了コード 214、準備の自己後始末では 210。#2973）。ゲストに次を求める。

- 既定ディストリビューション（Ubuntu）の `/bin/sh`（dash。bash でも動く）
- util-linux の `flock`・`mount`・`umount`、coreutils の `stat`
- fdinfo に `mnt_id:` 行があるカーネル（Linux 3.15 以降。WSL2 のカーネルは満たす）

未検証の注記（REPAIR-3）: busybox 系など `/bin/sh` が dash でないディストリビューションと、Windows 実機の WSL2 ゲストでの動作は未検証。実機確認は人間担当の [#1629](https://github.com/Fandhe-AI/fandhe-container/issues/1629) で行う。

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

### 8.3 短縮名（8dot3）

NTFS は長い名前に別名（例: `LONGFI~1.TXT`）を作ることがある。ゲストから別の名前に見えるものが、ホストでは同じ実体を指しうる。fandhe-container はこの同一視を検出しない。短縮名が作られるかはボリュームの設定と既存ファイルで決まり、名前から判定できないためである（#1317。理由は [fs-normalization.md](../design/fs-normalization.md) の「Win32 固有の名前の同一視」節）。

推奨: 共有するボリュームでだけ短縮名の生成を無効にする。ただしボリューム単位の設定は、システム既定（レジストリ `NtfsDisable8dot3NameCreation`）が `2`（ボリュームごと）のときにだけ行える。`2` への変更はシステム全体のレジストリ書き込みになるが、全ボリュームで生成を無効にするものではない。`fsutil` は管理者（Administrators グループのメンバー）としてログオンして実行する必要があるため、以下はすべて管理者権限の PowerShell で行う。

システム既定の値の意味（`fsutil 8dot3name set <defaultvalue>` が書く値）:

| 既定値 | 意味 | 共有ボリューム（例 `C:`）での対処 |
| ------ | ---- | ---------------------------------- |
| 0 | 全ボリュームで生成を有効 | `set 2` で既定をボリュームごとへ切り替え、`set C: 1` |
| 1 | 全ボリュームで生成を無効 | 追加の設定は不要（既に生成しない） |
| 2 | ボリュームごとに設定 | `set C: 1` のみ |
| 3 | システムボリューム以外で生成を無効 | 共有ルートがシステムボリューム（例の `C:\fc\proj` は通常これに当たる）なら `set 2` → `set C: 1`。システムボリューム以外なら追加の設定は不要 |

ボリューム単位の値（`fsutil 8dot3name set <volumepath> {1|0}`）は `0` がそのボリュームで有効、`1` が無効で、ディスク上のボリュームのフラグに書かれる。

```powershell
# 1. システム既定を照会（volumepath を省くと既定の生成設定を表示）
fsutil.exe 8dot3name query
# 2. 共有ボリュームを照会
fsutil.exe 8dot3name query C:
# 3. 既定値が 0 または 3（システムボリュームの場合）のときだけ、ボリュームごとの管理へ切り替える
fsutil.exe 8dot3name set 2
# 4. 共有ボリュームの生成を無効にする
fsutil.exe 8dot3name set C: 1
# 5. 設定後に再度照会する
fsutil.exe 8dot3name query C:
```

`fsutil.exe behavior query disable8dot3 C:` でも同じ照会ができる（`fsutil behavior` の `disable8dot3` は同じレジストリ値を更新する）。`<volumepath>` はドライブ名とコロン（例 `C:`）または `volume{GUID}` で指定する。

注意:

- `set 2` に切り替えると、他のボリュームの挙動は各ボリュームのフラグに従う。そのフラグの既定値は資料に記載が無く**未確認**のため、切り替えた後に他のボリュームも `query <volumepath>` で確かめる
- `fsutil 8dot3name strip` は推奨しない。指定ディレクトリの短縮名を恒久的に削除し、短縮名を指すレジストリキーは列挙するだけで直さないため、アプリの異常（アンインストール不能を含む）を招きうると資料が警告し、事前のバックアップを推奨している（`/f` はキーが指していても削除する）。どうしても使う場合は先に `/t`（テストモード）で影響を確かめる
- 次の事項は一次資料に記載が無く**未確認**で、#379（TASK-68.h1）の実機で確かめる: 再起動・再マウントの要否（資料は `disable8dot3` について再起動の要否を記していない）、無効化後に既存の短縮名が残るか、新しいボリュームのフラグの既定値、`query` が表示する文言、Windows 11 での同一性（資料の適用対象は Windows 10 までの記載で Windows 11 を明記しない）
- 管理者権限の操作とレジストリの書き込みはローカルの攻撃面を広げる。共有ボリュームに限り、必要な場合だけ実行する

出典（Microsoft Learn。取得日 2026-10-28。括弧内はページの git_commit_id）:

- [fsutil 8dot3name](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name)（`1dde3f07`）
- [fsutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil)（`4282dd47`。管理者権限の要件）
- [fsutil behavior](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior)（`f565202e`）
- [Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)（`63e70903`。ボリューム単位の無効化は Windows 7 / Windows Server 2008 R2 以降）

未検証の注記（REPAIR-3）: 実機では未確認で、#379（TASK-68.h1）で確認する。

### 現状の挙動と既知の制限（REPAIR-3）

| 項目 | 現状 |
| ---- | ---- |
| 大文字小文字の衝突検出 | 検出関数は実装済み。ワイヤー経路へは未組み込み |
| パス長の検証 | 検証関数は実装済み。書き込み経路へは未組み込み |
| per-directory フラグの設定・読み取り | fandhe-container は行わない。本書の手順で利用者が設定する |
| Developer Mode の検査 | 行わない |
| virtiofs 経由でのフラグの有効性 | 未確認（#379） |
| Win32 固有の名前の同一視（末尾の `.` / 空白・8.3 短縮名・予約デバイス名） | 検出しない（#1317）。実機観測待ち（#379） |
| 8.3 短縮名の生成の無効化 | fandhe-container は行わない。本書の手順で利用者が設定する |

## ゲスト内への導入（設計のみ・未実装）

- ゲスト内の `fandhe-container`・supervisor・launcher は、Linux 版と同じ配置規則で distro の中に置く。手順は [linux.md](linux.md) に従う
- ホストの起動役は、ゲスト内の固定の絶対パスを直接呼び、ゲストの `PATH` は探さない
- 起動役とゲスト内の版の照合は未実装。MVP では利用者が手で導入し、版を合わせる想定（推奨案・承認待ち。[windows-execution-layout.md](../design/windows-execution-layout.md) 7 節）

## GPU 付きコンテナの追加設定（WIN-5 追記候補）

TASK-135 で、実機の実測後に追記する予定。WIN-5 の追記候補は「検討中」のため確定扱いにしない（GPU-7）。本節は予約で、内容は未記載。
