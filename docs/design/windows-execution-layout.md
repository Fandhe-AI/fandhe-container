# Windows の実行構成（WSL2 ゲスト内の core とホストの起動役）（設計ドラフト）

Windows で core・CLI・supervisor を WSL2 ゲストの中で動かし、Windows ホストには薄い起動役だけを置く構成の、未決事項と中継の契約を整理する。

> 位置づけ: 「決定済みの事項」（#1415・#1539 のオーナー決定）だけが確定である。「論点 1〜5」と「中継の契約」は推奨案で、**オーナー承認待ち**（Issue #1862 は 5 点の承認を確定の条件としている）。実装は未着手で、本書の内容は実装済みを意味しない（REPAIR-3）。承認後に「確定済み設計判断」として `docs/architecture.md` の表へ移す。

- 対象ビヘイビア: WIN-1・WIN-2（関連: PLUG-1・PLUG-7・PLUG-11・PLUG-12・OCI-5・CLI-1・ERR-1・ERR-2・REPAIR-3・REPAIR-5・CORE-10）
- タスク: TASK-116（#391）の追補・TASK-67（#352）の追補（MS-5）
- 関連 issue: #1862（本書）・#1415（構成 C の決定）・#1539（plugin の発見を Windows ホストで行わない）・#1319（Windows ホスト用の環境変数を扱わない）・#1412（共有マウントの回収。中核は #2473 で実装済み・closed。呼び出し側の接続は論点 4 の承認後）・#1629（plugin-windows の E2E。人間担当）・#27（Windows 実機）
- 出典: spec の `api-platform-windows.md`（WIN-1・WIN-2）・`plugin-system.md`（PLUG-1・PLUG-11）・`05-tasks.md`（TASK-116）。本書の作成時点では `docs/spec` を読み込めない環境だったが、spec `fe33bef` の時点で差分を確認した（結果は 11 節。spec と食い違う場合は spec を正とする）
- 作成日: 2026-10-18

## 1. 決定済みの事項（確定。#1415・#1539）

- 実行場所は構成 C: core・CLI・supervisor は WSL2 ゲストの中で動く（Linux の経路をそのまま使う）。Windows ホストには薄い起動役だけを置く
- ホストとゲストの接続は `wsl.exe` での中継（引数・標準入出力・終了コード）。期限は起動役が持つ
- ゲスト内の plugin 境界（UDS・peer 認証・信頼性検証）は Linux の実装をそのまま使う。Windows 固有の peer 認証は作らない（PLUG-12）
- ホストの起動役が受け持つのは次の 3 つ: WSL2 と distro の検出、`.wslconfig` の確認、ホストのディレクトリ共有の準備と解除
- Windows ホストでは plugin の発見も信頼性検証もしない。起動役と補助の実行ファイルは CLI と同じ導入場所に置き、`PATH` から探さない（#1539）。Windows ホスト用の環境変数は扱わない（#1319）
- 採らなかった案
  - A（Windows ホストで plugin を動かす）: Windows 用の IPC・peer 認証・停止経路を新しく作る必要がある。namespace・cgroup・seccomp はホストでは適用できず、ホストに core を置いても中継にしかならない
  - B（plugin だけをゲストに置く）: ホストの core とゲストの plugin をまたぐ接続を UDS で作れない。マウントの準備もゲスト内の操作として作り直しになる

## 2. 現状（main `8fe23c0d` 時点）

| 対象 | 現状 |
| ---- | ---- |
| `crates/plugin-windows` | フレームループ・adapter・UDS 接続・SIGTERM・`release_all` がある。doc は「#1415 待ち」のまま。ホストで動かす前提とゲストで動かす前提が混在し、どちらで動かしても create は成功しない（fail-closed） |
| `crates/platform-windows` | `wsl.exe` をシステムディレクトリから解決し、Job Object・期限つきの `run_capture`・`HostDir` / `MountName` / `DistroName` の newtype・`/mnt/fandhe/<MountName>`・`/run/fandhe/<nonce>` の記録・`.wslconfig` を扱う。Windows 以外では `UNIMPLEMENTED` |
| `crates/cli` | Windows では `plugin_backend` 経由で必ず失敗する。`setup` は手順を示すだけ |
| `crates/plugin` | UDS は unix 限定 |
| `make check-cli-backend-deps` | cli が platform-windows / plugin-windows に依存しないことを検査する |

## 3. 論点 1: 起動役をどの crate の bin にするか（推奨案・承認待ち）

- **推奨: 規則に例外を作らない。** Windows 版の `fandhe-container.exe`（cli crate の `cfg(windows)` の分岐）は、隣に置いた補助の実行ファイルを固定名で起動し、引数・標準入出力・終了コードを中継するだけにする
  - 補助のパスは `std::env::current_exe()` の親ディレクトリと固定名（案: `fandhe-container-windows-host.exe`）で決め、`PATH` を探さない
  - 前例: `start` が同じディレクトリの supervisor を `launcher::SUPERVISOR_FILE_NAME` で起動している（#1718）
  - cli は platform-windows に依存しないままなので、一方向依存の規則 2 と `make check-cli-backend-deps` を変えずに済む
  - Windows 上の cli 自身は `wsl.exe` を一切起動しない
- 代替案: 規則 2 に「Windows の起動役」の例外を設け、cli が `cfg(windows)` でだけ platform-windows に依存する。プロセスが 1 段減るが、機械判定の例外・境界の侵食・cli の Windows 依存コードの増加を招くため推奨しない
- 起動が 1 段増える分（cli → 補助 → `wsl.exe` → ゲスト内の cli）のレイテンシは未計測で、実機確認の一覧に入れる（CORE-10）

## 4. 論点 2: plugin-windows crate の扱い（推奨案・承認待ち）

- **推奨 2a: plugin-windows crate を起動役の補助に作り替える。** crate 名は変えない
  - bin 名を補助の固定名に変える
  - UDS 越しの plugin 経路（`frame_loop`・`adapter` の RPC 部分・`UdsStream::connect`・SIGTERM のフラグ・`plugin.*` の stderr 契約）は廃止する
  - `fandhe-container-plugin` への依存を外し、platform-windows への依存だけを残す
  - PLUG-1 の区分を「plugin」から「Windows ホストの起動役（plugin 境界の外）」に変える
  - crate の数は変わらないので 19 crate の一覧（REPAIR-1）の数は変わらない。ただし `crate-naming.md` の表 #17 の説明と区分は変わるため承認事項にする。crate 名の変更（`plugin-` を外す）は別の承認事項で、本案には含めない
- 代替 2b: 補助を platform-windows の `[[bin]]` にし、plugin-windows crate は廃止する。crate が 1 つ減り、crate-naming の決定 1 の変更になる
- 代替 2c: ゲスト内の plugin として残す。ゲストは Linux なので core が直接動き、ゲスト内に Windows 用のバックエンドは要らない。platform-windows の `wsl.exe` 経路もゲストでは動かない。採らない
- 使わなくなる試験の扱い（試験を弱めて残すことはしない）

| 試験 | 推奨案での扱い |
| ---- | -------------- |
| `tests/frame_loop.rs` | UDS のフレームループを廃止するので削除 |
| `tests/peer_auth.rs` | peer 認証はゲスト内の Linux 実装が担うので削除 |
| `tests/e2e.rs` | 補助の中継（argv・stdio・終了コード）の試験に書き換える |
| `tests/startup.rs` | 補助の起動と前提不成立の終了コードの試験に書き換える |
| `tests/shutdown_cleanup.rs` | 共有の解除（create 失敗時・delete 時）の試験に書き換える |

- #1629（plugin-windows の E2E。人間担当）の手順は書き換えが要る
- `make check-cli-backend-deps` の禁止対象は変えない（cli は補助 crate にも依存しない）

## 5. 論点 3: ホストのパスの対応づけ（推奨案・承認待ち）

- 対応づけるのは、サブコマンドごとに「パスを取る」と決めた引数だけにする。表で持つ（例: `create --bundle`）。ほかの引数は手を加えずに渡し、Windows のパスらしく見えても推測で変換しない
- `--root`: 状態はゲスト内に置く（OCI-5 の (4)）ので、`--root` はゲストの絶対パス（`/` で始まる）だけを受け、ドライブレターのパスは `INVALID_ARGUMENT` で拒否する
- 検証
  - 既存の `HostDir::parse` を土台にする（ドライブレターつきの絶対パスだけ・UNC やデバイスパスやドライブ直下は拒否・260 文字以内）
  - 加える検証: `..`・`.` の要素、予約名（CON・PRN・AUX・NUL・COM1〜9・LPT1〜9。拡張子つきも含む）、末尾の空白とドット、ADS（`:`）、制御文字
  - symlink とジャンクションの扱い（ホスト側で実体を確かめるか）は実機確認の項目にする
- 対応づけの先: 起動役が virtiofs（または 9P）で `/mnt/fandhe/<MountName>` へ共有し、引数をゲストのパスに置き換える
  - `MountName` はコンテナ ID から決まる決定的な短縮名 `b-<hex32>`（`<hex32>` はコンテナ ID の SHA-256 の先頭 16 バイトを小文字 hex にした 32 文字。接頭辞込みで 34 バイト）にする。通常の 64 文字の ID を `b-` 付きでそのまま使うと 66 バイトとなり `MountName` の 64 バイト上限を超えて対応づけが失敗し、通常の `create` が拒否されるため、ID をそのまま埋め込まず必ずハッシュで短縮する
  - 衝突耐性: 128 ビットの切り詰めで、同時に存在するコンテナ数（高々数千）に対し誕生日衝突の確率は無視できる。万一同じ `MountName` が既に別のコンテナで使われていれば、共有せず `INVALID_ARGUMENT` で拒否する（fail-closed）
  - bundle の中の `rootfs` などの相対パスは、ゲスト側の検証にそのまま任せる
- 対応づけられない場合は、`wsl.exe` を起動する前に構造化エラーを返す（`INVALID_ARGUMENT`・終了コード 2）。メッセージは英語の固定文言で、パスは載せない
- 代替案: WSL の自動マウント（`/mnt/c/...`・`wslpath`）に任せる。#1415 の「共有の準備と解除は起動役」に反し、`nosuid,nodev,ro` の制御や virtiofs の検証もできないので採らない

## 6. 論点 4: 共有マウントの寿命と #1412（推奨案・承認待ち）

- 寿命: `create` のときに起動役が準備し、コンテナが生きているあいだ保つ。別のプロセスである `delete` の起動役が解除する。`stop` では解除しない
- `create` が失敗したら、同じ起動役がその場で解除する。準備の途中で失敗したときの後始末は、既存の `MountError::unreleased` の経路を使う
- 解除のための所有情報はゲスト内の記録を正とする（#1412 の方向と同じ）
  - `/run/fandhe/` の記録にコンテナ ID とマウント先を加え、コンテナ ID から引けるようにする
  - 使う前に記録を検証する（root 所有・symlink でない・マウント ID が `/proc/self/mountinfo` の最上位と一致）
  - ホスト側には所有情報を置かない（WSL の VM が再起動すると記録が古くなり、別のマウントを外す恐れがあるため）
  - `/run` は tmpfs なので、VM が再起動するとマウントと記録が一緒に消える
- 起動時に一括で解除することはしない（別のコンテナのマウントを外さないため）
- `PreparedLaunch` を外から組み立てられない制約は保つ。記録からの復元は、platform-windows の内側にある検証つきの関数に限る
- #1412 との関係: 回収の主体が「新しい plugin プロセスの stop」から「起動役の delete」に変わる。#1412 は呼び出し側に依らない中核だけを実装して閉じた（#2473）。回収の主体の選択と呼び出し側の接続は、本節の承認後に 12 節の 5 番で行う
- `delete --force` では、ゲスト内の delete が失敗した場合も解除の順序はコンテナが消えた後とし、解除できなければ構造化エラーで報告する
- 実装の現状（#1412。呼び出し側に依らない中核だけを先行して実装した。回収の主体の承認〔本節の論点 4・#2230〕は待っていない）
  - 記録 `/run/fandhe/<nonce>` は 3 行（1 行目: マウント ID または `none`、2 行目: マウント先、3 行目: コンテナ ID または印 `.`）。既存の読み手は 1 行目だけを読む
  - コンテナ ID は `LaunchRequest::with_owner(OwnerId)` で付ける。ID を付けずに準備した記録は ID では引けない
  - `release_container_mounts(distro, owner, timeout)`（platform-windows）が、ゲスト内の検索（`/`・`/run`・`/run/fandhe` と各記録を root 所有・symlink でない・他者書き込み不可で確かめる）→ 形式とマウント先の検証 → `mountinfo` の最上位との照合 → 既存の umount の経路（ロックの下でマウント ID を再照合）の順で、その ID の記録のマウントだけを外す
  - 改ざんが 1 件でもあれば、同じ ID の他の記録も含めて何も外さず `FAILED_PRECONDITION` を返す。記録が無ければ `found` が 0 の `Ok`
  - 呼び出し側（起動役の delete、または plugin の stop）への接続は未実装。論点 4 の承認後に、12 節の 5 番で行う

## 7. 論点 5: Ctrl+C の中継とゲスト内への導入・更新（推奨案・承認待ち）

Ctrl+C

- 起動役は `SetConsoleCtrlHandler` で CTRL_C と CTRL_BREAK を受ける。自分は終了せず、`wsl.exe` がゲストのプロセスへ SIGINT を届けるのに任せる
- 「`wsl.exe` がコンソールの制御イベントをゲスト内の SIGINT に変える」ことは**未確認**で、実機確認の一覧に入れる
- 届かない場合の代替: 起動役が別の `wsl.exe --exec` でゲスト内の cli に停止要求を送る（入口は実装 issue で決める）
- 猶予を過ぎたら、起動役は Job Object で `wsl.exe` の子孫を終了させ、ERR-2 の終了コードを返す。ゲスト側のプロセスが残るかどうかは未確認
- 承認事項: `windows-sys` の feature に `Win32_System_Console` を足す必要がある（依存の更新。[dependency-policy](../../.claude/rules/dependency-policy.md)）。本 PR では足さない

導入・更新

- ゲスト内の `fandhe-container`・supervisor・launcher は、Linux 版と同じ配置規則で distro の中に置く（[linux.md](../setup/linux.md)）
- 起動役は、ゲスト内の固定の絶対パスを `--exec` で直接呼ぶ。ゲストの `PATH` は探さない
- MVP では利用者が手で導入し、`setup`（CLI-2）は手順を示すだけにする。自動の導入・更新は将来の実装 issue に回す
- 版の不一致の検出
  - 起動役は自分のビルドの識別子（版と、可能ならビルド ID）を持つ
  - ゲスト内の cli に版を問い合わせる入口（現状の cli には無く、実装 issue で足す）で照合し、合わなければ `FAILED_PRECONDITION` と固定文言の案内を返す
  - 現在の版は全 crate が 0.0.0 なので、識別子の決め方も実装 issue の論点とする

## 8. 起動役の中継の契約（推奨案・承認待ち）

- 起動の形: `wsl.exe -d <distro> --exec <ゲスト内の固定の絶対パス> <引数...>`
  - シェルを経由させない（`sh -c`・`bash -c` は使わない）。引数は配列のまま `std::process::Command` へ渡す
  - Windows のコマンドライン化（MSVC の引用規則）を `wsl.exe` の解釈が正しく往復できるかは**未確認**。往復を保証できない文字（引用符・空白・Unicode の正規化の違い等）を含む引数を拒否するかは実機の結果で決め、それまでは fail-closed とする
  - NUL を含む引数は扱えないので拒否する
- distro の選び方: 既定の distro で、WSL2 かつ使えるものだけを使う（既存の `detect` の結果から選ぶ）。条件に合わなければ `FAILED_PRECONDITION`。明示的に選ぶ手段（設定ファイルなど）は将来の論点で、環境変数は使わない（#1319）
- 標準入出力: 対話のために継承する（取り込まない）。起動役自身の診断は stderr の英語 1 行 JSON で区別して出す（例: `"source":"host-launcher"`）
- 終了コード
  - ゲストの終了コード（0〜255）をそのまま返す
  - 起動役自身の失敗は ERR-2 の表に揃える（使い方は 2、前提不成立は 5、UNAVAILABLE、期限切れなど）
  - `wsl.exe` 自身の失敗（ゲストが起動しないなど）の写し方と、ゲストの終了コードとの見分け方（区別できない範囲を含む）は実機で確かめる
- 期限（REPAIR-5）
  - 前処理（検出・`.wslconfig`・共有の準備と解除）の `wsl.exe` の呼び出しには、どれも合計期限と出力量の上限を付ける。既存の `run_capture` の仕組みを使う
  - 本体の中継の期限はサブコマンドごとの表で持つ（ゲスト内の cli の期限＋余裕）。長く動くコマンド（`start` の待ち・将来の `logs -f`）の扱いは実装 issue で決める
  - 期限を過ぎたら Job Object で回収する
- `wsl.exe` の解決: `GetSystemDirectoryW` の配下に限る（既存の `wsl_exe_path`）。`PATH` からは探さない
- 失敗の構造化エラー: `code` と `message`（ERR-1）。ホストのパス・ユーザー名・`.wslconfig` の中身・`wsl.exe` の生の出力は載せない

## 9. ホスト側に何も要らないもの

- 状態: OCI-5 の (4) のとおり、ゲスト VM 内の Linux パスに置く。ホストには状態ファイルを置かない
- plugin の発見と信頼性検証: ゲスト内で Linux の規則（PLUG-11）を使う。Windows ホストでは行わない（#1539）
- peer 認証: ゲスト内の Linux の実装を使う（PLUG-12・TASK-124・#294）
- 前提にしないこと: 判断資料の時点で未確認だった次の 2 点は、この構成では使わない
  - Windows の AF_UNIX を Rust の std から使えるか
  - WSL2 のゲストと Windows ホストの間で AF_UNIX の接続ができるか

## 10. Windows 実機（#27）で確かめる事項

確かめるまで、どれも「未確認」である。

- `wsl.exe --exec` で引数がどう往復するか（引用・空白・Unicode・長さ）
- Ctrl+C / CTRL_BREAK がゲストの SIGINT として届くか
- Job Object で `wsl.exe` を終了させたとき、ゲスト側のプロセスがどうなるか
- `wsl.exe` の終了コードの範囲と、ゲストの終了コードがそのまま届くか
- virtiofs と drvfs のマウントと `nosuid,nodev,ro`（#377 と重なる）
- ホストのパスにある symlink / ジャンクションの扱い
- 中継が足すレイテンシ（CORE-10 との関係）
- VM の再起動と `wsl --shutdown` で、マウントと記録がどう消えるか
- 標準入出力を継承したときの TTY と非 TTY の挙動

## 11. spec 側の課題（spec リポ側の変更案。本リポからは編集しない）

spec `fe33bef` の時点で差分を確認した結果と、承認後に spec リポ側で直す案（#2230 で確認）。

- `05-tasks.md` の TASK-116: 2026-10-12 の追補は反映済みだが、成果物欄は `crates/plugin-windows/src/adapter.rs`（仮称）のまま。承認後の形に合わせる（推奨の 2a なら、起動役の補助の bin と中継、共有の準備と解除）
- `plugin-system.md` の PLUG-11: 「Windows ホストでは plugin の発見も信頼性検証も行わず、ゲスト内の Linux の規則で検証する」旨が #1539 の決定として記載済みのため、追記は不要（確認済み）
- 境界表と PLUG-1: #1415 の構成は反映済み。残るのは「#1862 で確定する」の参照を、確定した内容への参照に置き換えること（承認後）
- `api-platform-windows.md` の WIN-1: #1415 の補足は反映済み。残るのは起動役の crate と導入方法の補足（承認後）

## 12. 確定後に起こす実装 issue の一覧（本 PR では起票しない）

1 件あたり実装 2h 以下・1 PR・1 関心事とする。親は #2308（Phase 7 の続き。#58 は sub-issue の上限に達しており、TASK-116 の親 #391 は closed）。

1. 起動役の補助の入口と中継（argv・stdio・終了コード・期限・`wsl.exe` の解決。前処理なし）
2. Windows 版の cli から隣の補助を固定名で起動する（`cfg(windows)`・`PATH` を探さない・`check-cli-backend-deps` を変えない）
3. 起動役の前処理（検出・distro の選択・`.wslconfig` の確認）を platform-windows の既存 API へ配線する
4. パスを取る引数の表と、ホストのパスの検証・対応づけ（予約名・トラバーサル・長さ）
5. 共有の準備（create）と解除（delete）の呼び出し。#2473 で実装済みの `release_container_mounts` を呼ぶ
6. （実装済み: #2473・#1412）ゲスト内の記録へのコンテナ ID の追加と、記録からの復元。起票は不要で、以下の番号は 6 番を残したまま数える（起票対象は 6 番を除く 10 件）
7. Ctrl+C の中継（`windows-sys` の feature 追加の承認が前提）
8. ゲスト内の版の問い合わせの入口と、版の照合
9. plugin-windows の位置づけの変更（UDS の経路・試験の廃止または書き換え、`crate-naming.md` の表 #17、`architecture.md` の区分）
10. コードの doc の「未確定（#1415）」の解消（`crates/plugin-windows/src/main.rs`・`src/sys.rs`・`tests/frame_loop.rs`・`tests/peer_auth.rs`）
11. `docs/setup/windows.md` のゲスト内への導入手順の確定（実装の後）

## 13. Windows を MVP の後に回す場合に止めておく追補

- #1412: 中核（`LaunchRequest::with_owner`・`release_container_mounts`・記録の 3 行化）は #2473 で実装済み。呼び出し側の接続は論点 4 の承認まで行わない
- #1629（E2E の手順）、#661（CLI の 3 OS 確認）の Windows 分、TASK-125 の Windows 分は、新しい構成に合わせた読み替えが要る
- plugin-windows への新しい機能追加は止める

## 14. セキュリティの考慮（契約として定めるもの）

- インジェクション: `wsl.exe` へは引数を配列で渡し、シェルを経由させない。ゲスト内の固定の絶対パスを `--exec` で呼び、ゲストの `PATH` は探さない
- パストラバーサル: ホストのパスは検証してから対応づける。マウント先は固定の基底 `/mnt/fandhe/<MountName>` の下だけにし、`nosuid,nodev`（読み取り専用の指定は `ro`）で共有する。記録は root 所有・symlink でない・mountinfo と一致することを検証してから使う
- 無制限確保・タイムアウト: `wsl.exe` の呼び出しには期限と出力量の上限を付ける（REPAIR-5）。失敗したらどの経路でも解除し、解除できなければ構造化エラーで報告する
- 完全性: `wsl.exe` はシステムディレクトリからだけ解決する。補助の実行ファイルは CLI と同じ導入場所に置き固定名で起動する（#1539）。起動役とゲスト内の版の不一致は拒否する
- 情報漏えい: エラーは英語の固定文言だけにし、ホストのパス・ユーザー名・`.wslconfig` の中身・`wsl.exe` の生の出力を出さない

## 15. 承認事項・報告事項（判断シート）

オーナーに判断してほしい事項。承認の窓口は #2230 で、すべて**未決**（承認済みのものは無い）。返信は「D1: 推奨どおり / D2: 2b」のように番号で答えられる。

| 番号 | 判断事項 | 選択肢 | 推奨 | 影響 | 判断 |
| ---- | -------- | ------ | ---- | ---- | ---- |
| D1 | 論点 1: 起動役をどの crate の bin にするか（3 節） | 推奨: cli の `cfg(windows)` から隣の補助を固定名で起動 / 代替: 規則 2 の例外 | 推奨 | 推奨なら一方向依存と `check-cli-backend-deps` は不変 | 未決 |
| D2 | 論点 2: plugin-windows の扱い（4 節） | 2a: 補助へ作り替え / 2b: platform-windows の bin にして crate 廃止 / 2c: ゲスト内 plugin | 2a | 2a と 2b で 12 節の実装 issue の構成と試験の扱いが変わる。2b は crate-naming の決定 1 の変更 | 未決 |
| D3 | 論点 3: ホストのパスの対応づけ（5 節） | 推奨案の承認 / 修正点の提示 | 推奨案 | `MountName` の決め方・拒否するパスの範囲が確定する | 未決 |
| D4 | 論点 4: 共有マウントの寿命と回収の主体（6 節） | 推奨案（起動役の delete が回収）の承認 / 修正点の提示 | 推奨案 | #1412 の呼び出し側の接続（12 節 5 番）の前提 | 未決 |
| D5 | 論点 5: Ctrl+C の中継・導入と更新（7 節） | 推奨案の承認 / 修正点の提示 | 推奨案 | Ctrl+C の経路と版照合の入口（12 節 7・8 番）が確定する | 未決 |
| D6 | 起動役の中継の契約（8 節） | 推奨案の承認 / 修正点の提示 | 推奨案 | 終了コード・期限の契約が確定する | 未決 |
| D7 | `crate-naming.md` の表 #17（D2 が 2b なら #7 も）の役割・区分の変更と、crate 名変更（`plugin-` を外す）の要否 | 変更する / 変更しない / 名前も変える | D2 の結果に従う。名前は変えない | 12 節 9 番の範囲 | 未決 |
| D8 | `windows-sys`（現行 `=0.61.2`）の feature `Win32_System_Console` の追加 | 承認 / 不承認 | 承認（用途: `SetConsoleCtrlHandler`。配置先は補助の bin を置く crate で D2 に従う） | dependency-policy の 5 項目（ライセンス `MIT OR Apache-2.0` の確認、メンテナンス状況、推移依存、サイズ）は承認依頼時に提示する。本書の時点では feature を足していない。推移依存の増減は未確認 | 未決 |
| D9 | #1629・#661・TASK-125 の Windows 分の読み替え（13 節） | D1・D2 の結果に合わせて読み替える | 従属 | 実機確認の手順が変わる | 未決 |

報告事項:

- spec リポ側の課題は 11 節（オーナーが spec リポへ反映する）。実装 issue は 12 節のとおりで、承認後に起票する（起票していない）
- #1412 の中核は #2473 で実装済み。残りは D4 の承認後の呼び出し側の接続
