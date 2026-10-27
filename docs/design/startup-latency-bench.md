# コンテナ起動レイテンシ p95 ベンチの計測定義（TASK-190・MS-2・CORE-10・REPAIR-8）

- 対応: TASK-190（MS-2。前提の TASK-29・TASK-157 と後続の TASK-88 が MS-2 にあるため割り当て）・ビヘイビア CORE-10・REPAIR-8
- 対象: `benches/benches/startup_latency.rs`（薄い入口）と `benches/src/startup_latency/`（計測ロジック）。Issue #1900
- ステータス: **ベンチ実装済み・実測は未実施（人間担当）・CI の回帰ゲートには未接続**。`metrics.json` へは実機前提として登録済み（#1901）。`BENCH_NAMES`・共有 `baseline.json` には入れておらず、基準値 `benches/baseline-manual.json` は未作成（実測は #230）。基準値は `make bench-baseline-manual`（#2095）で作り、比較は人が実機で `make bench-check-manual`（結果の `arch`・`host_kind` と基準値の `host` を照合。`host_kind` が `unknown` か無い結果は `BENCH_HOST_KIND` で指定）。CI では回帰を検出できない（実装済みを装わない。REPAIR-3）
- CI での扱い（実機前提として分離・REPAIR-8 の「CI で 15% 超の悪化を fail」は未充足）は [bench-calibration.md](bench-calibration.md)「CI の扱いの決定（TASK-190）」

## 計測区間

| 項目 | 内容 |
| ---- | ---- |
| 始点 | core の `oci_runtime::create` を呼ぶ直前 |
| 終点 | supervisor の bin が結果チャネル（stdout の pipe）へ書く `FCSUP1 OK <pid>` の 1 行を、読み取りスレッドが読み終えた直後の時刻（チャネルの待ちは区間に入れない）。復号は `StartReport::decode` だけで行う |
| 経路 | core `create` → `systemd-run`（`USER_SCOPE_WRAPPER_ARGS`。本番の start と同じ包み込み・環境・cwd。下の「包み込みの一致」）→ supervisor の bin → core の本番 launcher。CLI は経由しない（CLI の start は MS-6 のため、経由すると MS-2 の TASK-88 と依存が逆転する） |
| 区間に入るもの | create（状態の作成・bundle 検証）・user スコープの取得（D-Bus 往復。本番の start が起動のたびに払う費用〔#2081・#2122〕のため含める）・supervisor の手順 1〜9（argv 検証・cgroup の連鎖・監査 sink・本番 launcher による中間プロセス → PID 1・Landlock・pre-pivot 段・開始ゲート・Running の記録・報告） |
| 区間に入らないもの | bundle の作成・試行後の後始末（CLI の `delete`・scope・cgroup・プローブの回収。所要時間は標本に入らない。OCI-6）・ワークロードの睡眠・CLI と `state` の往復・`XDG_RUNTIME_DIR` の検査など計測前の検証 |
| metric | `startup_create_to_supervisor_ok_p95_ms`（ms）。`startup_latency_p50_ms`（TASK-46.1）とは区間・統計量が違う。区間の始点・終点・中身は変わらず包み込みの忠実度だけが上がったため、metric 名と `method` は変えない（#2089） |

### 包み込みの一致（#2089・CORE-3・CORE-4）

| 項目 | 内容 |
| ---- | ---- |
| argv | `USER_SCOPE_WRAPPER_ARGS` の末尾 `--` の直前にベンチだけの `--unit=<名前>` を足す（後始末が scope の cgroup を名前で探すため。名前は実行ごとの nonce を含み一意） |
| 環境 | `env_clear()` の後、固定 `PATH` と検証済み `XDG_RUNTIME_DIR` だけ。`DBUS_SESSION_BUS_ADDRESS` は渡さず user マネージャの直結ソケット `$XDG_RUNTIME_DIR/systemd/private` を使う |
| cwd・その他 | cwd は `/`、`process_group(0)`、stdin は null、stderr は null |
| 事前検査 | `$XDG_RUNTIME_DIR/systemd/private` が自 euid 所有のソケットでなければ、試行の前に `unsupported-environment` で止まる（CLI の `user_manager_env` と同じ判定。値は出力しない）。スモークの `user_manager=` も同じ判定を使う（CORE-10・REPAIR-8） |

詳細は [cgroups.md](cgroups.md) を参照。

### CORE-10 の「プロセス実行開始」との差

- OK が出るのは、launcher が `K <pid>` を受領し、開始ゲートを許可し、pre-pivot 段の状態を読み、Running を記録した後である。ワークロードの `execve` が OK の前に終わる保証はない（launch 経路は exec の成功を通知する pipe を持たない）。本区間は「PID 1 の生成・分離設定・Running の記録まで」を測り、CORE-10 の定義との差は Running の記録の書き込みと、exec が OK の後にずれ込みうる部分である
- `systemd-run` のスコープ取得は rootless で委譲 cgroup を得るための費用として区間に含める（`method` にも明示）。#2081 で本番の start が起動のたびに scope を取得すると決まったため、含めるのが本番と一致する。子 cgroup へ直接置く方式（`pre_exec`〔unsafe〕・core の API 追加）は本番の経路から離れるため採らない（#2089）。scope 取得の費用は systemd・D-Bus の状態で揺れ、製品側の回帰と区別しにくい。切り分けには診断モード `--scope-only` を使う（下記）

### `scripts/bench/startup_latency.sh`（TASK-46.1）との差

あちらは CLI の `create`・`start` の後、`state` が `running` / `stopped` を返した時点で区間を終え、Docker との実機比較のために中央値をとる。本ベンチは CLI と `state` の往復を含まず、p95 をとる回帰検出用である。

## bundle とワークロード

- 外部イメージを使わない。ベンチ自身の実行ファイルを rootfs の `/probe` へコピーし、動的ローダと読み込み済みの共有ライブラリを同じ絶対パスへ写す（`supervisor_bin_real.rs`〔#1819〕と同じ方式）。`config.json` は user / pid / mount / uts / ipc の namespace・uid / gid 0
- ワークロードは同じ実行ファイルを `--startup-latency-probe <nonce>` で再実行したもの。約 300ms 眠って終了コード 0 で終わる（OK の報告まで PID 1 を生かすためで、この時間は区間の外）。nonce は実行ごとの英数字で、後始末が `/proc` を走査して自分のプローブだけを数える目印
- bundle は計測の前に 1 回だけ作り、全試行で再利用する（区間の外）。試行は直列で、後始末が済んでから次の create へ進む
- 既知の注意: bundle の所有ロックで再利用が拒否される場合は、試行ごとに bundle をコピーする方式へ変える（区間の外）。実機で初めて走らせたときに確認する

## 試行・統計

| 項目 | 値 |
| ---- | ---- |
| `--trials` | 既定 30・範囲 20〜200（20 未満だと p95 が最大値と同じ順位になる） |
| `--warmup` | 既定 3・範囲 0〜20（標本に入れない。失敗は数える） |
| `--cli-bin` | 後始末の `delete` を呼ぶ CLI（`fandhe-container`）の絶対パス。計測では必須で、`PATH` からは探さない。`--supervisor-bin` と同じ検証（通常ファイル・所有者が自分か root・group/other 書き込み不可・祖先も安全）を通す。`--scope-only` とは併用できない |
| `--timeout-secs` | 全体の期限。既定 1800・範囲 60〜7200。各試行の前と、各試行の後始末を終えた直後（結果の公開前）に照合し、超えたら成功結果・metric を出さず `deadline-exceeded` で失敗する |
| p95 | nearest-rank 法。昇順に並べ、順位 `ceil(95·n/100)` の要素。p50・max は診断用 |

## 失敗の扱い（REPAIR-3・fail-closed）

- 失敗は種別ごとに数える: `create` / `spawn` / `report_err`（`CODE` 別の内訳つき）/ `report_timeout` / `report_eof` / `report_invalid` / `supervisor_exit`（supervisor の終了コード不一致・ワークロードの終了コードが 0 でない場合を含む）/ `cleanup` / `cleanup_delete_rejected`（後始末の `delete` の拒否・期限超過・起動失敗。`cleanup_delete_codes` にコード別の内訳。OCI-6・#2157）
- 1 件でも失敗または後始末の残りがあれば、`metrics` を空 `{}` にして `failures` を載せた JSON を出し、終了コード 1 で終わる。部分的な標本の p95 をゲートへ流さない
- 分離を弱める経路（Landlock なし・フェイクの launcher・supervisor の迂回）は実装しない。launcher が拒否したら `report_err` として数える

## 後始末と期限（REPAIR-5）

後始末は計測区間の外で行う（標本の `total` は OK 行を読んだ時点で確定済みで、後始末の所要時間は入らない。REPAIR-8・CORE-10）。状態と cgroup の削除は手書きせず、CLI の実バイナリ（`--cli-bin`）の `delete` に任せる（OCI-6・#2157）。区間の起動経路は CLI を経由しない（MS-2 / MS-6 の依存の向き）という決まりは変わらず、CLI を呼ぶのは区間の外の `delete` だけである。

`delete` は本番の `start` と同じ包み込み（`USER_SCOPE_WRAPPER_ARGS` ＋ `--unit=fcsl-del-<id>`）で `<cli> --root <状態ルート> delete <id>` を実行する。包むことで CLI 自身が委譲スコープの中で動き、委譲スコープの検出が成功する。検出したスコープは試行のスコープと食い違うため、core の `delete` は記録済みスコープを fd 起点で検証して開く `remove_recorded`（#2096）へ回り、試行スコープの外からでも記録の cgroup を消せる。ログインセッションから直接呼ぶと検出が失敗するので、包みは必須である。stdin・stdout は `/dev/null`、stderr は作業ディレクトリ（0700）内の排他作成ファイルへ書かせ、先頭 4096 バイトだけを読む。

1. supervisor の終了を 30 秒まで待つ（成功は終了コード 0、ERR は報告の終了コードと一致）。超えたら kill し、回収を 10 秒まで待つ
2. スコープ内の残存を `cgroup.kill` で止めて空を確かめる。残れば後始末失敗
3. 状態を確かめる（成功は `Stopped`、ERR は `Created` かつ pid なし）
4. CLI の `delete` を 10 秒を上限に 1 回呼ぶ
5. 正常系（`delete` が終了コード 0）: 記録の cgroup（`fc-<id>@<instance>`）が消えたこと、`delete` 用スコープ（`fcsl-del-<id>`）が空であること、`/proc` の nonce を持つプローブが 0 件であること（10 秒まで待つ）だけを確かめる。cgroup の手書きの削除はしない。残っていれば製品側の不具合のしるしとして後始末失敗にする。満たしたら状態ルート（`delete` が消さないロックファイル等を含む）を消す
6. 異常系（`delete` の拒否・期限超過・起動失敗）: 拒否は握りつぶさず `failures.cleanup_delete_rejected` と `cleanup_delete_codes` に残し、`metrics` を空にする。コードは CLI の stderr の JSON の `code`（既知の `ErrorCode` のときだけ。それ以外・読めない場合は `UNPARSED`）、期限超過は `TIMEOUT`、起動失敗は `SPAWN` の固定語彙で、message・パス・errno は出さない。そのうえで従来の強制後始末（GC 猶予 → `cgroup.kill` → `rmdir`、プローブの消滅確認、状態ルートの削除）を行い、ホストに残骸を残さない。強制後始末が成功すれば試行は続くが、結果は clean にならない。強制後始末も失敗したら ID を `leftover_ids` に積み、以後の試行を止める（fail-closed）。作業ディレクトリは調査用に残す（相対名だけを stderr へ出す）。systemd-run の stderr は捨てる（絶対パス・OS のエラー文字列を出さない）

採らなかった案: ベンチ内で core の `oci_runtime::delete` を直接呼び、ベンチ専用の `ContainerCgroupRemover` を作る案。`scope()` に検証していない値を返すことになり、「委譲スコープの検出の失敗を記録の経路へ回すか」というオーナー判断待ち（#2133）をベンチ側で先取りしてしまうため採らない。

応答待ち（結果 1 行・supervisor の終了・回収・cgroup・プローブ）はすべて期限つきで、全体の期限の残りで切り詰める。

## 前提と実行

必要環境・ビルド・実行コマンド・出力の読み方は `AGENTS.md`「実機前提テスト」の `startup_latency` を参照。実測は人間担当で、結果は #230 か PR に記録する（Agent は実測値を書かない）。

## セキュリティ上の扱い

- 外部コマンドは argv 配列で渡し、シェルを使わない。`--supervisor-bin`・`--systemd-run` は絶対パスに限り、`PATH` から探さない
- 起動前に、通常ファイル（symlink 不可）・実行ビットあり・group / other 書き込み不可・所有者が実効 UID か root・全祖先ディレクトリ（字面上と symlink 解決後の両方）が実効 UID か root 所有で other 書き込み不可・group 書き込み不可（自分の group でも拒否する。同 group の別 UID による差し替えを防ぐため。umask 002 で 0775 になる `target/` 配下は `chmod g-w` してから使う。sticky 付きは可）であることを検証する。検証から exec までの自分自身（同一 UID）による差し替えの TOCTOU は残る（開発者のローカル target 配下のバイナリを対象とする計測道具のため許容）。別 UID・別 group による差し替えは上の検証で拒否する
- 子の環境は許可リスト（固定 `PATH` と検証済み `XDG_RUNTIME_DIR`）だけで、`LD_PRELOAD`・`DBUS_SESSION_BUS_ADDRESS` 等を継承しない
- 作業ディレクトリ・状態ルートは 0700 で排他作成する。rootful（euid 0）は拒否する（SEC-5）
- 出力に絶対パス・ホスト名・ユーザー名・OS のエラー文字列を載せない。新規の外部依存は無い。`unsafe` は `benches/src/sys.rs` の中断シグナル用 FFI ラッパー（`pthread_sigmask`・`sigpending`・子の `pre_exec` でのブロック解除、試験のみ `raise`）だけで、`sys` の外へ公開しない（各ブロックに `// SAFETY:` を付け、Linux の x86_64 / aarch64 に限る。ハンドラは登録せず、ブロックして保留を確かめるだけ）

## 診断モード `--scope-only`（CORE-10・REPAIR-8）

scope 取得だけを測る。本計測と同じ包み込み（`scope_wrap::scoped_noop_command`）で、自分自身の `--startup-latency-noop`（すぐ終了コード 0 で終わる）を起動し、`systemd-run` の起動から終了を回収するまでを試行ごとに測る。create・supervisor・ランチャー・Landlock は含まない。

- 実行: `cargo bench -p fandhe-container-benches --bench startup_latency -- --scope-only [--trials N] [--warmup N] [--timeout-secs S] [--systemd-run <絶対パス>] [--output <絶対パス>]`。`--supervisor-bin`・`--cli-bin`・`--work-dir` は受け付けない。実機前提（Linux・非 root・`systemd-run --user`）で CI では実行しない
- 出力: `kind: "diagnostic"`・`metrics` は常に空（`bench-check-manual`・`bench-baseline-manual` の入力にならず、渡しても metric の集合が合わず 2 で拒否される）。統計は `summary`（p50・p95・max）に入る。失敗・scope の残りがあれば終了コード 1
- 読み方: 本計測の p95 と診断の p95 を同じホストで並べる。両方悪化していれば systemd・D-Bus の揺れ、本計測だけ悪化していれば製品側の回帰

## ホストの種類（`host_kind`）

結果 JSON の `host_kind` は `/proc/sys/kernel/osrelease`・`/sys/hypervisor/type`・DMI（`/sys/class/dmi/id`）・`/proc/cpuinfo` の `hypervisor` フラグから判定する（プロセスは起動しない）。値は `bare-metal` / `vm` / `wsl2`、根拠が足りなければ `unknown`（`bare-metal` を既定値にしない）。DMI の文字列は結果に出さない。語彙の見直しと実測は #230 の担当。

## 残余・フォローアップ

- `user_manager_env` の判定の CLI との共通化（`start_contract` 等）
- 委譲スコープの検出が失敗したときに記録の経路へ回すか（core の `delete` の契約の変更。オーナー判断待ち。#2133）
- restart の再 launch（#2043）は対象外
- CI の回帰ゲートへの接続は、オーナー判断（[bench-calibration.md](bench-calibration.md) の選択肢 (c)/(d)/(e)。#230）待ち。#1901 は暫定の実機前提として登録した
