# macOS 既定方式（常駐 VM 共用）の未決事項の設計案

TASK-191 の着手前に確定が要る未決事項 4 点と計測対象を、設計案として文書化する（MAC-4）。

> **状態: 承認待ち（#1906）**。本書はすべて設計案で、承認されるまで確定扱いしない。コードは変更していない（設計のみ。REPAIR-3）。Apple Silicon の macOS 実機を要する事項は「未確認」と明記し、確認済みのようには書かない（[実機で未確認の事項](#実機で未確認の事項)）。

- 対象ビヘイビア: MAC-4（関連: MAC-1・MAC-2・MAC-3・MVM-1・MVM-3・MVM-5・PLUG-1・PLUG-6・PLUG-12・CORE-1・CORE-8・OCI-5・REPAIR-5）
- タスク: TASK-191（前提 TASK-64・65・66・115）。計測対象は TASK-70・TASK-49
- 関連 issue: #1905（本書）・#1906（設計の承認）・#2232（#1869 の承認）・#1869（`plugin-backend-wiring.md`）・#1862（`windows-execution-layout.md`）・#1823・#1875（guest-init）・#1879・#1880（計測）・#1628（実機）・#1877・#1374（symlink）
- 出典: `docs/spec/04-behavior/api-platform-macos.md` の `MAC-4`、`05-tasks.md` の TASK-191（submodule リビジョン `fe33bef`）
- 前提文書: [macos-vm-strategy.md](macos-vm-strategy.md)（2 方式の比較と現状）。#1869 の 4.4（保持役の段階 1 / 2）も承認待ち（#2232）であり、本書はそれを「承認待ちの推奨」として引用する。本設計は #1869 の W11・W12 の内容を吸収するので、#2232 の起票では W11・W12 を落としてよい

## 現状（要約）

- `Vm::launch` は 1 回で 1 VM を構成・起動する。virtiofs 共有は構成時に固定される（`MAX_VIRTIOFS_SHARES` = 8）
- plugin-macos は 1 コンテナ = 1 VM で、状態はメモリだけに持つ。kill・delete・state は `UNIMPLEMENTED`。要求本体は `Vec<String>` の暫定ワイヤー契約
- macOS の VZ vsock は `Unimplemented`。ゲスト init は mount・報告・ready マーカーまでで、子を作らず、協調停止も無く、mount にパス由来の TOCTOU が残る（#2080 の P2-4）
- 詳細は [macos-vm-strategy.md](macos-vm-strategy.md) の「現状の事実」を参照

## 設計上の制約

| ID | 制約 |
| -- | ---- |
| C1 | `VZVirtualMachine` は生成したプロセス（virtualization の entitlement で署名された plugin-macos）の中にしか存在しない。プロセスが終われば VM も止まる（`Vm` の `Drop` も停止を要求する）。「保持する主体」とは、常駐の plugin-macos を生かし続け、複数 CLI からの操作を直列化するプロセスである |
| C2 | plugin-macos 自身が bind して待ち受ける形（#1869 4.4 の C）は、「plugin は connect 側だけ」と PLUG-12 に反するので取らない |
| C3 | CORE-1・D-19 により、コンテナ 0 個のときは保持役も VM も残さない（アイドル時の資源 0） |
| C4 | macOS には pidfd と `PR_SET_PDEATHSIG` が無い。保持役の死の検出はシグナルに頼らず、ロックファイルの `flock`（プロセスが死ねばカーネルが解放する）で行う |

## 項目 1: 共用 VM を保持する主体と寿命

候補

- (a) plugin-macos の常駐モード（PLUG-6）を中央に 1 つ置く
- (b) **VM ごとの保持役**（推奨。仮称 VM keeper）
- (c) コンテナごとの保持役（#1869 4.4 の段階 2 の方向）
- (d) CLI が 1 コマンドのあいだだけ持つ（#1869 の段階 1）

採る案は (b)。

- 起動と寿命: 最初のコンテナの create が起動する。保持役は core 側の起動口（#1869 の W4）で plugin-macos を `ResidentPlugin` として起動する。socket は保持役が bind し、plugin が connect する（PLUG-12 のまま）。最後のコンテナが delete されて参照数が 0 になったら、固定の猶予（案: 30 秒。実測で見直す）の後に VM を協調停止し、plugin を回収して終了する
- 置き場所（crate 境界の判断事項）: 推奨は supervisor crate に macOS 用の bin（または macOS モード）を足すこと。役割が「コンテナのライフサイクルに従属する監視・保持」で supervisor に近く、core → plugin の依存の向きを守れる。cli に置く案は常駐の責務が入るため取らない。plugin-macos に置く案は C2 により取らない。保持役は platform-macos に依存しない（plugin 境界越しに使うだけ）
- CORE-1 との整合: 保持役が存在するのはコンテナが 1 個以上ある間（と猶予）だけで、中央集権の常駐デーモンではない。単一障害点の範囲は 1 VM に閉じる（D-19 の supervisor の読み替えと同じ理屈）
- 起動の競合（排他と期限）
  - ホストの状態ディレクトリに `vm/<vm 名>/keeper.lock` を置く。ディレクトリは `getpwuid` の home 配下の固定パスを環境変数に頼らず解決し、0700・自 UID 所有・symlink 不可を検証する（`HOME` / `TMPDIR` の要否は #1869 4.6 と合わせて実機確認項目）
  - 起動したい CLI は `flock(LOCK_EX|LOCK_NB)` を期限つき（`RESIDENT_START_TIMEOUT_DEFAULT` = 10 秒）でポーリングする
  - ロックを取れたら保持役を起動し、保持役がロックを継承して持ち続ける。取れなければ既存の保持役の UDS へ接続する（peer の UID を照合）
  - 期限を過ぎたら `Timeout`（fail-closed。二重起動はしない）
- 参照の数え方: 正は保持役のメモリ上の登録簿（コンテナ ID → 共有の登録）。ホストに書くのは、保持役のロックと、VM の世代 ID つきの所属記録（コンテナ ID の一覧。上限つき）だけ。状態ファイル本体は OCI-5 の (4) のとおりゲスト内の Linux パスに置く。保持役の起動時に所属記録の世代が自分と違えば、古い記録として扱う
- 保持役の異常終了: C1 により plugin-macos と VM も止まる。検出は「ロックが空いている」と「UDS に接続できない」の組で行い、回収は「古い socket・所属記録を検証つきで削除 → 新しい世代の起動」の順に行う。コンソールログは診断材料として残す。
  - 保持役の死と VM の停止完了を区別する: 保持役が SIGKILL されると `ResidentPlugin` の `Drop` は走らず、plugin は UDS の切断を検出してから自分で `stop_all`（VM の協調停止 → 電源断 → 強制停止）を行って終わる。そのため、ロックの解放と保持役の UDS の消失は、旧 VM の停止完了より先に起こり得る。この 2 条件だけで次の世代を起動すると旧 VM と重複する。異常終了時の回収契約として、「旧世代の plugin-macos プロセスの終了を確認するまで新しい世代を起動しない」を明記する。確認は、旧 plugin の pid（所属記録に世代 ID と併せて残す）の消滅、または plugin 側の終了通知で行い、期限（案: VM の協調停止の期限＋電源断・強制停止の期限＋余裕）内に終わらなければ新世代の起動を `Timeout` で失敗させて残存を報告する（黙って重複起動しない。REPAIR-5）
- VM 喪失時: 全コンテナが止まる（ゲストの `/run` は tmpfs で状態も消える。Windows の `/run` と同じ形）。所属記録にあるのに VM が無いコンテナへの state / kill / delete は決定的なエラーで返す。推奨は state を `UNAVAILABLE`（固定文言 `backend vm lost`）、delete は所属記録の削除だけで成功とする
- 上限: 1 VM あたりのコンテナ数（案 64。実機のメモリで見直す）、VM のメモリ・vCPU（VM 生成時に固定。既存 `VmConfigSpec` の上限）、所属記録の行数と長さ。超えた create は `RESOURCE_EXHAUSTED`（または表に従い `FAILED_PRECONDITION`）で拒否する
- 採らなかった案: (a) は中央の常駐で CORE-1 に反し、障害がホスト全体に及ぶ。(c) は共用方式では保持の単位が VM なので、コンテナごとに持つと VM の所有者が複数になる。(d) はコマンドをまたいで VM を保てない
- **#1869 との食い違い**: #1869 4.4 の段階 2 は「コンテナごとの保持役」を推奨するが、本案は「VM ごと」にする。理由は C1 と共用の性質。オプション方式（項目 4）では 1 VM = 1 コンテナなので両者は一致する。#1906 で確認する

## 項目 2: VM 生成後にコンテナ単位の bind mount を届ける方法

候補

- (A) **VM の生成時に構成済みの共有ルートを virtiofs で共有し、ゲスト内でサブツリーを bind する**（推奨）
- (B) I/O 共有プロトコル（`crates/io`）でコンテナ単位に届ける
- (C) 共有を変えるたびに VM を作り直す
- (D) 実行中の VM で virtiofs デバイスの共有を差し替える（`VZVirtioFileSystemDevice` の `share` を実行時に変え、`VZMultipleDirectoryShare` を使う）。一次情報と実機で可否が未確認。後続の候補

採る案は (A)。

- 共有ルートは設定で明示する。上限は `MAX_VIRTIOFS_SHARES` = 8 の範囲内で、既定はホームディレクトリ配下の作業用ルート 1 件とする（既定値は判断事項）
- create の bind mount（`config.json` の `mounts[]`）のソースが共有ルートのどれかの配下にあることをホスト側で検証する（`SharedDirectoryPath::try_new` と同等の正規化、`..`・symlink の拒否）。配下になければ `INVALID_ARGUMENT` で拒否する（fail-closed。VM は作り直さない）
- ゲスト内では core の既存の bind mount 経路（`open_tree` 系・`MOUNT_ATTR_RDONLY`）で、該当サブツリーだけをコンテナの rootfs へ bind する
- アクセス制御: 各コンテナに見えるのは自分の `mounts[]` のサブツリーだけ（mount namespace による）。読み取り専用は bind 時の `ro` で守る。共有ルート自体の `readOnly`（VZ のデバイス構成）はホスト側の境界として別に指定できる
- **残る露出（受け入れる trade-off）**: ゲスト内の特権プロセス（ゲストカーネルや PID 1 を含む）が侵害されると全共有ルートが見える。既定方式（カーネル共有）の性質であり、緩和策はオプション方式を使うこと
- symlink とハードリンク（#1374・#1877）の挙動は未確認。確認できるまで、共有ルート内の symlink は解決せず、bind のソースに含まれる symlink は拒否する
- 上限: 1 コンテナあたりの bind mount 数（既存の `mounts[]` の上限に合わせる）、パス長（全体 4096 バイト・要素 255 バイト）
- 後始末: delete でゲスト内の bind を外す（コンテナの mount namespace と一緒に消える）。共有ルートは VM の寿命のあいだ保つ
- 採らなかった案: (B) は macOS の vsock と `VirtiofsIoClient` の具象トランスポートが未実装で TASK-191 の範囲で届かない。(C) は他コンテナを止め、既定方式の目的（起動レイテンシ）に反する。(D) は可否が未確認で推奨にしない（確認できたら上限 8 件の制約を外す改善として検討）
- **判断事項**: MAC-1・MAC-3 が想定するデータパス（virtiofs を I/O 共有プロトコルへ接続する）と (A) の関係。推奨は「TASK-191 は (A) で届け、I/O 共有プロトコルの接続は MAC-1・MAC-3 の後続で (B) として重ねる」

## 項目 3: 共用ゲスト内でコンテナを実行する機構

候補

- (i) **ゲスト内で `crates/core`・supervisor・CLI（Linux 版）をそのまま動かし、ホストは中継する**（推奨。Windows の構成 C〔#1415〕と同じ形）
- (ii) ゲスト init に実行役を持たせる（namespace・cgroup・seccomp を init に実装し直す）

採る案は (i)。

- ゲスト内の構成: PID 1 は guest-init のまま。mount・報告に加え、子の回収・協調停止・制御チャネルの受け口を持つ。コンテナの作成と実行はゲスト内の CLI → core → supervisor の Linux の経路で行い、分離は namespaces・cgroups v2・seccomp・Landlock（MAC-4 の期待どおり）。ゲストカーネルは #1874 の Kconfig で cgroup v2・user namespace・seccomp・Landlock を有効にする（足りない設定は実装 issue）
- **ゲスト内の実行ユーザー（root で動かさない）**: 既存 CLI の `supervisor_start` の `privilege_gate` は、UID のいずれかが 0 のとき `start` を `UNIMPLEMENTED` で拒否する（rootful 非対応。CORE-3）。この拒否は解除しない。ゲスト内の CLI・core・supervisor は、guest-init が用意する非特権ユーザー（案: UID 1000。`/etc/passwd` 相当は initrd に固定で梱包）として動かす。guest-init（PID 1）だけが root で、ユーザーの降格（`setgroups`・`setgid`・`setuid`。`sys` モジュール内）の後にゲスト内 CLI を起動する。コンテナ内 root の写像は rootless の user namespace（SEC-5）と、ゲスト内の subordinate ID 範囲（launcher 経由の写像。#2209 の系統）で行う。ゲスト内の launcher を置くか、ゲスト用に subordinate ID を固定の範囲で渡すかは実装 issue で決める（承認事項）
- **ゲスト内の cgroup 委譲と supervisor の起動（systemd を使わない）**: 既存の `supervisor_start` は `systemd-run --user --scope -p Delegate=yes` と systemd の user マネージャを必須とするが、ゲストは PID 1 を guest-init のままにするため systemd が無い。したがって既存の Linux 起動経路はそのままでは使えない。ゲスト向けには次の方式を案とする
  - guest-init が起動時に cgroup v2 を mount し、共有の親 `/sys/fs/cgroup/fandhe` を作って上記の非特権ユーザーへ所有を移し（`chown`）、必要な controller（`cpu`・`memory`・`pids`・`io`）を `subtree_control` で有効にする。さらに親の下に、コンテナ用の領域 `/sys/fs/cgroup/fandhe/containers`（同じく非特権ユーザー所有・同じ controller を有効化）と、CLI 用の領域 `/sys/fs/cgroup/fandhe/cli` を別々に作る。名前空間を分けるのは、`<container-id>` に `cli` が有効な値として使えるため、同じ階層に置くと衝突するからである（REPAIR-1・CORE-3）。cgroup v2 の no internal process 制約により、controller を有効にした `fandhe` と `containers` にはプロセスを置かず、子 cgroup を束ねるだけにする
  - コンテナごとに専用の委譲 cgroup `/sys/fs/cgroup/fandhe/containers/fc-<container-id>` を作り（名前は `crates/core/src/cgroups.rs` の `CONTAINER_PREFIX`（`fc-`）と同じ接頭辞で組む。`ContainerId::new` は `cgroup.procs`・`cgroup.events`・`memory.max` などのインターフェースファイル名も有効な ID として受理するため、ID をそのまま名前にすると `mkdir` がカーネルのインターフェースファイルと衝突する。接頭辞により衝突しない。CORE-3）（非特権ユーザー所有）、その中に当該コンテナの supervisor だけを置く。これにより supervisor 側の `DelegatedCgroup::prepare` の前提（委譲された cgroup に自分以外のプロセスがいない）を、コンテナが 2 つ目以降でも満たす。`DelegatedCgroup::detect` は自プロセスの cgroup を対象にするため、supervisor は spawn 直後（コンテナ起動の前）に自分をこの専用 cgroup へ移してから `detect` と `prepare` を呼ぶ
  - ゲスト内 CLI は root cgroup には置かない。`DelegatedCgroup::detect` は非 root の euid でルート cgroup を拒否し、ゲストの `delete`・`stop` が CLI から `detect` を呼ぶと失敗するため。guest-init は CLI を `/sys/fs/cgroup/fandhe/cli`（非特権ユーザー所有のリーフで、`subtree_control` は有効にしない。`containers` 配下とは別の兄弟のため、どのコンテナ ID とも衝突しない）へ入れてから起動する。この経路は systemd-run を使わず、特権ランチャーも要らない（guest-init が root で cgroup を用意し、以降は非特権ユーザーだけで成立する）
  - コンテナの cgroup の回収順序と担当: systemd が無いため、`prepare` が専用 cgroup の下に作る `fc-runtime` と `fc-<id>@<instance>` は、systemd のスコープ終了では片付かない。削除は非特権ユーザー（`containers` の所有者）で、次の順に行う。(1) supervisor の終了を確認する（終了確認は delete を呼ぶ CLI が担い、期限内に終わらなければ失敗を返す。REPAIR-5）。(2) `fc-<id>@<instance>` を既存の delete が rmdir する。(3) ゲスト向けモードでは `fc-runtime` も delete が rmdir する（既存 delete は前者しか消さないため、この削除を追加する実装課題とする）。(4) 最後に専用 cgroup `containers/fc-<container-id>` を rmdir する（作成時と同じ命名で回収パスを組む）。(1)〜(3) のいずれかが残る間は (4) を行わず、エラーを返して残存を報告する（スコープの漏れを黙って無視しない。CORE-3）
  - 上記の構成が `DelegatedCgroup::prepare`・`detect` の前提と矛盾しないことは、実装 issue (1)・(2) の結合試験（ゲスト相当の環境で 2 コンテナ以上の同時起動と、非 root の CLI からの delete）で確かめる
  - ゲスト内 CLI の起動は、systemd-run を介さず、委譲済みの cgroup 配下へ supervisor を直接 spawn する承認済みの別経路（ゲスト向けの起動モード）とする。`privilege_gate` の判定と systemd 経路は変えず、ゲスト向けモードは明示的な構成（ビルドの feature または固定の起動引数）でのみ有効にする。通常の Linux ホストで誤って有効にならないことを試験で確かめる
  - 実装課題として、(1) guest-init の cgroup 委譲と非特権ユーザーへの降格、(2) ゲスト向け supervisor 起動モード（cli）、(3) ゲスト内の subordinate ID の供給を新規に起票する（起票は #1906 の承認後。G6・G9 の依存に加える）
- ホストとゲストの制御経路: vsock（`VZVirtioSocketDevice`）。**接続の方向はホスト開始・ゲスト受け側に統一する**。guest-init がゲスト内の固定ポート（案: 1024。実装 issue で確定）で `listen` し、保持役配下の plugin-macos が `VZVirtioSocketDevice` の `connectToPort` で接続する（VM のデバイスに触れるのは plugin-macos だけ）。ゲストからホストへ接続する経路は作らない（ホスト側にゲスト由来の待受を持たない）。シリアルコンソール（hvc0）は起動時の報告と ready マーカー専用で、制御には使わない
- **承認事項**: `objc2-virtualization` に vsock 関連の feature（`VZVirtioSocketDevice*` など）を足す必要がある。依存の更新にあたるため [dependency-policy](../../.claude/rules/dependency-policy.md) に従いユーザー承認を要する
- 接続元の確認: ゲスト側の受け口（G6）は accept した peer の CID が `VMADDR_CID_HOST`（2）であることを検証し、それ以外は即切断する。ホスト側の接続（G5）は固定ポートへ接続するだけで、待受（listen）を持たない。network namespace は vsock を分離しないため、コンテナから `socket(AF_VSOCK, …)` を使わせないよう seccomp で拒否し、結合試験で確かめる。ホスト側の CLI・plugin と保持役の間は UDS の peer UID 照合で守る（PLUG-12）
- 中継の契約: Windows の起動役の中継（[windows-execution-layout.md](windows-execution-layout.md)）と同じ形にする。引数の配列・標準入出力・終了コードを中継し、シェルを経由させない。ゲスト内のバイナリは固定の絶対パスで呼び、`PATH` を探さない。フレームは長さの上限とチェックサムつき（REPAIR-2）。plugin のフレーム（PLUG-2）を再利用するかは実装 issue で決める
- rootfs とイメージ: 推奨は、イメージとコンテナの rootfs をゲスト側の永続ディスク（virtio-blk のデータディスク）に置くこと。bundle をホストで作る経路（#1869 4.3 の (a)）では共有ルート経由でゲストへ渡す。MVP は「共有ルート経由の bundle」とし、ゲスト内の pull（VZ の NAT のネットワークと feature 追加が要る）は後続とする（判断事項）
- 状態ファイル: ゲスト内の `/run/fandhe-container/<id>/state.json`（OCI-5 の (1)。上記の非特権ユーザーが書ける `/run` 配下の所有で用意する）。ホストに置くのは項目 1 の所属記録だけ
- ログ: コンテナと supervisor のログはゲスト内に置く（SUP-7 の回転規則）。ホストの `logs` はゲスト内の CLI を中継して読む。hvc0 のコンソールログは guest-init の診断専用
- ゲスト向けバイナリ: core・supervisor・CLI を `aarch64-unknown-linux-musl` の静的リンクでビルドし、`scripts/build-guest-initrd.sh` で initrd に入れる（またはデータディスクに置く。サイズで判断）。musl で型検査しているのは guest-init だけなので、`cross-target-check` に CLI・supervisor の musl 型検査を足す
- guest-init（#1823・#1875）に足すもの: 子の `waitpid` ループと孤児の回収、協調停止（ホストの停止要求 → ゲスト内のコンテナ停止 → `sync` → `reboot(RB_POWER_OFF)`。期限を過ぎたらホストが VZ の強制停止へ切り替える）、子を動かす前の fd 起点の mount（#2080 の P2-4。`openat`＋`O_NOFOLLOW` → `/proc/self/fd`、または `open_tree` / `move_mount`）、vsock の受け口とゲスト内 CLI の起動、doc の「TASK-115 で未実装」の記述の修正。#1823 の決定（workspace のメンバー crate・musl・arm64 のみ）は変えない
- 協調停止を先行させるか: 協調停止と回収は 1 コンテナ = 1 VM の現状でも書き込みの損失を減らすので、共用 VM の実装より先に着手できる順序にする。ただし #1906 への依存は付ける
- 採らなかった案: (ii) は分離機構の二重実装になり、core の試験資産が効かず、REPAIR-1 の波及最小化にも反する

## 項目 4: オプション方式（1 コンテナ = 1 VM）の実現経路と選択の UI

- 経路の推奨: 現行の `Vm::launch`（Virtualization.framework）をコンテナごとに使う。項目 1 の保持役を「容量 1 の VM」として使い、ゲスト内の構成（項目 3）も同じにする。両方式の違いを「VM に入れるコンテナ数の上限」と「共有ルートを他コンテナと共有しないこと」に限定でき、コードの経路を分けずに済む
- MVM-5（Hypervisor.framework 上の自前 VMM）の系統は #688・#695・#705 が open で未着手。将来の別バックエンドとして扱い、TASK-191 の範囲に入れない
- 選択の UI は spec に定義が無いため本リポでは決めない。文言の案のみ: CLI は `create --isolation=<shared-vm|vm>`、TOML は `isolation = "vm"`。CLI-1（3 OS 同一構文）により、Linux では MVM-1 の microVM、Windows では未定義（`UNIMPLEMENTED`）の意味を持たせる必要があるため、spec 側の課題とする
- MVM-3（切り替えしきい値）は「検討中」のまま。確定扱いしない

## 項目 5: TASK-70・TASK-49 の計測対象

- MAC-2 の「2 秒以内」は、**共用 VM の初回起動**（保持役の起動 → VM の start → ゲストの ready マーカー）を指すと解釈する案。暖まった VM でのコンテナ起動は別指標（CORE-10 型の起動レイテンシ）、オプション方式の 1 コンテナあたりの VM 起動は参考値として測る
- TASK-70（#381）の MAC-3: 既定方式で、共有ルート配下の bind mount の上で測る
- TASK-49（#354）の CORE-8（**判断事項**）: CORE-1 に従う保持役ではコンテナ 0 個のとき VM が無いので、「アイドル時の常駐メモリ（Docker Desktop 比）」の条件を定め直す必要がある。推奨は (1) 猶予後（VM なし）と (2) コンテナ 1 個がアイドル（VM は常駐）の 2 本を測り、Docker Desktop と比べるのは (2) にする
- #1879（cold start の計測ハーネス。実装は [macos-vm-cold-start-bench.md](macos-vm-cold-start-bench.md)。ラベルの対応づけは #1906 の承認後）は計測区間を「ready マーカーまで」にし、方式のラベル（既定 / オプション、初回 / 暖まった状態）を出力に足す。#1880（MAC-3 の手順）は共有ルートの構成を手順に足す

## 期限の表（REPAIR-5）

既存の定数: `RpcTimeout` は 10 秒を超えられない。一方 `DEFAULT_START_TIMEOUT` は 30 秒、`DEFAULT_GUEST_MOUNT_TIMEOUT` は 60 秒、plugin-macos の `LAUNCH_TOTAL_TIMEOUT` は 7 秒である。共用 VM の初回起動を CLI の 1 往復の RPC に収めることはできない。

方式: 保持役が VM を CLI の RPC の外で起動する。CLI は「起動を要求する（即答）→ 期限つきの状態問い合わせでポーリングする（1 往復ごとに `RpcTimeout` 以内）」形で待つ。全体の上限は「VM 起動の期限＋ゲストの ready の期限＋余裕」とし、超えたら保持役が VM を止めて回収し `Timeout` を返す。`LAUNCH_TOTAL_TIMEOUT` 7 秒と VM の start 30 秒の食い違いは、保持役の側だけでは吸収できない。plugin-macos の `PlatformBackend::launch` は 7 秒で打ち切って取り消しフラグを立て、内部の start・ゲスト mount 待ちも各 3 秒に設定しているため、保持役が待ち続けても plugin 側で失敗する。このため非同期化は保持役と plugin の間にも適用する（下記）。

### 保持役と plugin 間の起動契約（plugin-macos の変更。REPAIR-5）

1. 即答と状態照会: 保持役から plugin への起動要求は即答（受理）とし、起動の進行は状態照会（ポーリング。1 往復ごとに `RpcTimeout` 以内）で確認する。CLI と保持役の間と同じ形にそろえる
2. plugin 内部の起動予算: `LAUNCH_TOTAL_TIMEOUT`（7 秒）と start・ゲスト mount 待ちの各 3 秒を、上の期限表（start 30 秒・ready 60 秒）に整合させる。共用 VM の初回起動の経路では、全体の予算を「start 30 秒＋ready 60 秒＋余裕」とし、段階ごとの期限は `OpTimeouts::start`（`DEFAULT_START_TIMEOUT`）と `DEFAULT_GUEST_MOUNT_TIMEOUT` から導く。コンテナ単位の create は VM 起動済みを前提に従来の短い期限を保つ（値は実測で見直す）
3. 取り消しと回収: 全体の上限を超えたら plugin は取り消しフラグを立てて VM の協調停止 → 電源断 → 強制停止の順で回収し、`Timeout` を返す。保持役からの取り消し要求でも同じ回収を行い、起動途中の VM とスレッドを残さない
4. 実装 issue: 上記は G14（#2281）の対象に含める（plugin-macos のアダプタ切り替えと同時に、起動の即答・状態照会・予算の整合・取り消しと回収を実装する）

| 段階 | 期限 | 出どころ |
| ---- | ---- | -------- |
| 保持役のロック待ち | 10 秒 | `RESIDENT_START_TIMEOUT_DEFAULT` |
| plugin の常駐起動 | `ResidentStartTimeout` | 既存 |
| plugin 内部の起動予算 | 30 秒＋60 秒＋余裕（案） | `LAUNCH_TOTAL_TIMEOUT` 7 秒を共用 VM の初回起動で置き換える（承認待ち） |
| VM の start | 30 秒 | `OpTimeouts::start`（`DEFAULT_START_TIMEOUT`） |
| ゲストの ready | 60 秒 | `DEFAULT_GUEST_MOUNT_TIMEOUT` |
| vsock の接続・中継の 1 往復 | 10 秒以内 | `RpcTimeout` の上限（値は案） |
| 協調停止（ゲスト内停止 → 電源断 → 強制停止） | 案: 30 秒 | 新規（承認待ち） |
| 保持役の終了猶予 | 案: 30 秒 | 新規（承認待ち） |

## Windows の実行構成との比較と PLUG-1 の変化

同じにする点: core・supervisor・CLI はゲスト内で動く。状態はゲスト内に置く（OCI-5 の (4)）。ホストの役割は中継と共有の準備に限る。中継は引数の配列・stdio・終了コードで行いシェルを経由させない。固定の絶対パスで呼び `PATH` を探さない。エラーは固定文言で返す。

| 観点 | macOS（本案） | Windows（#1862） |
| ---- | ------------- | ---------------- |
| ホスト側の役 | plugin（plugin-macos）のまま。VZ の VM が entitlement つきプロセス内にしか存在しない（C1）ため | plugin でない起動役 |
| VM の保持 | 保持役が要る | WSL のサービスが VM を持つ |
| 制御経路 | vsock | `wsl.exe` |
| 共有 | VM 生成時に固定のルート（項目 2） | コンテナごとに準備と解除 |

PLUG-1 の境界表の macOS の行は「plugin（常駐。保持役が持つ）＋ゲスト内の core」になる。plugin-macos の `ContainerRuntime` アダプタは、create = 「VM の確保（保持役）＋共有の検証＋ゲストへの中継」、start・stop・kill・delete・state = ゲストへの中継、に変わる。暫定の `Vec<String>` 契約は #1869 の W1（DTO・`PROTOCOL_VERSION` 2）へ置き換える前提とする。中継を実装するまでは `UNIMPLEMENTED` のまま返し、実装済みを装わない。

## セキュリティ（OWASP の観点）

- インジェクション: 中継は引数の配列でシェルを経由させない。ゲスト内のパスは固定。共有パスは正規化と検証をしてから使う
- アクセス制御: UDS は 0700 と peer UID の照合。ゲストの vsock の受け口は CID 2 のホストからの接続だけを受ける（接続はホスト開始）。コンテナからの AF_VSOCK は seccomp で拒否する。共有ルートの露出範囲は trade-off として明記済み
- 不安全な設計: すべての待ちに期限を付ける。件数・長さに上限を設ける。異常時は VM・plugin・mount・ゲスト内プロセスを回収する。二重起動はロックで防ぎ、取れなければ fail-closed
- 完全性: plugin-macos は検証済みの fd で起動する（#1869 4.2）。ゲスト向けバイナリは initrd に梱包し、ゲストの `PATH` は探さない。版の不一致の照合を実装 issue にする
- 情報漏えい: エラーは英語の固定文言だけにし、ホストのパスや plugin 由来の文字列は出さない

## 実機で未確認の事項

Apple Silicon の macOS 実機で確かめないと決まらない。すべて「未確認」である。

- VZ の vsock（`VZVirtioSocketDevice`）の接続と、ゲストの CID 2 の判定
- guest-init の報告と ready マーカーが実機で届くか（#1628）
- 保持役が CLI の終了後も生き続けるか（launchd・セッションとの関係）。`flock` が死亡時に解放されること
- `HOME` / `TMPDIR` の要否とホスト状態ディレクトリの決め方（#1869 4.6）
- 共有ルート配下のサブツリーの bind の意味論（virtiofs 上の `open_tree`）と symlink・ハードリンク（#1374）
- (D) の実行時の share の差し替えの可否と最低 macOS 版（一次情報の確認も未了）
- `objc2-virtualization` 0.3.2 の vsock 関連 feature 名（未確認）
- cold start の実測値（MAC-2）と暖まった VM でのコンテナ起動
- VM のメモリ、コンテナ数の上限の妥当性（CORE-8）
- ゲストカーネルの cgroup v2・Landlock・user namespace の動作
- 協調停止（`reboot(RB_POWER_OFF)`）が VZ でどの状態遷移になるか

## 判断事項・承認事項の一覧（#1906 で確認）

承認事項

- `objc2-virtualization` の vsock 関連 feature の追加（依存の更新）
- 保持役を置く crate（推奨: supervisor）
- ゲスト内の非特権ユーザー降格・cgroup 委譲・ゲスト向け supervisor 起動モード・subordinate ID の供給方式（`privilege_gate` は変えない）
- vsock の方向（ホスト開始・ゲスト受け側）
- MVP のイメージ経路（推奨: 共有ルート経由の bundle）
- 猶予・上限・協調停止の期限の値（案: 猶予 30 秒、コンテナ上限 64、協調停止 30 秒）

判断事項

- #1869 4.4 との食い違い（VM ごと / コンテナごと）
- MAC-1・MAC-3 のデータパスとの関係（(A) を先、(B) を後続）
- CORE-8 のアイドル時の計測条件（2 本測る）
- 協調停止（G1〜G3）を共用 VM より先行させるか
- 共有ルートの既定値

## spec 側の課題（spec リポ側で扱う。本リポからは編集しない）

- TASK-191 の成果物: 「VM ごとの保持役・ゲスト内の core 実行・共有ルート方式（承認後の内容）」を具体化する
- MAC-4: 選択の UI（`--isolation`・TOML キーの案）と 3 OS での意味
- TASK-70・MAC-2: 「2 秒」は共用 VM の初回起動（ready マーカーまで）を指すと明記する。暖まった VM でのコンテナ起動は別指標
- TASK-49・CORE-8: 既定方式のアイドル時の計測条件（猶予後の VM なし / コンテナ 1 個のアイドル）を書き足す
- PLUG-1 の境界表の macOS の行と、OCI-5 の (4) の「ホストに置くのは所属記録だけ」の補足

## 起票した実装 issue

親は Phase 7（#58）。すべて依存欄の行頭に #1906（承認）を置く。

| 案 | issue | 内容 |
| -- | ----- | ---- |
| G1 | #2268 | refactor(platform): guest-init の virtiofs mount を fd 起点にする（#2080 P2-4） |
| G2 | #2269 | feat(platform): guest-init（PID 1）に子の waitpid ループと孤児の回収を足す |
| G3 | #2270 | feat(platform): guest-init の協調停止とホスト側の期限つき強制停止への切り替え |
| G4 | #2271 | build(platform): objc2-virtualization の vsock 関連 feature の追加（承認事項） |
| G5 | #2272 | feat(platform): ホスト側の VZ vsock 接続（ホスト開始・`connectToPort`。platform-macos）と io の vsock 表の更新 |
| G6 | #2273 | feat(platform): guest-init の vsock 受け口（ゲストが listen・CID 2 の peer のみ許可）とゲスト内 CLI の中継 |
| G7 | #2274 | build: core・supervisor・cli の aarch64-unknown-linux-musl 型検査を cross-target-check に足す |
| G8 | #2275 | build(platform): ゲスト向け cli・supervisor を initrd に梱包する |
| G9 | #2276 | feat(platform): ゲストカーネルの Kconfig に cgroup v2・userns・seccomp・Landlock を足す |
| G10 | #2277 | feat(core): seccomp の既定で AF_VSOCK の socket を拒否し結合試験で確かめる |
| G11 | #2278 | feat(supervisor): macOS の VM 保持役（ロック・peer 照合つき UDS・参照数・猶予後の終了） |
| G12 | #2279 | feat(supervisor): 保持役の上限・所属記録の世代と VM 喪失時の応答 |
| G13 | #2280 | feat(platform): 共有ルートの構成と bind ソースの検証 |
| G14 | #2281 | feat(platform): plugin-macos のアダプタを保持役とゲストへの中継に切り替える（起動の即答・状態照会・起動予算の整合・取り消しと回収を含む） |
| G15 | #2282 | chore(platform): macOS 実機で共用 VM の起動・2 コンテナ・保持役の終了を確かめる（人間担当） |
| G16 | #2283 | feat(cli): オプション方式（容量 1 VM）の選択の入口 |

上記に加え、ゲスト内の非特権実行（降格・cgroup 委譲・ゲスト向け起動モード・subordinate ID）の実装 issue を #1906 の承認後に起票する（番号は未定）。G1・G2 は #58 の、G3〜G16 は #1905 の sub-issue（#58 が sub-issue 上限 100 件に達したため）。G1〜G3 と G7・G9・G10 は共用 VM を待たずに進められる。既存の #1877・#1628・#1879・#1880 は新規起票せず関連として参照する。
