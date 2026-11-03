# ランタイム自身の封印複製（方式 B）の扱い（判断記録）

`crates/core/src/exec/interpreter.rs` の方式比較表の「B. ランタイム自身の封印複製（memfd + `F_SEAL_*`。runc の方式）」を、launcher・exec 専用プロセスの起動処理へ組み込むかの判断材料を整理する（CORE-5・REPAIR-3。参照: CORE-7〜9・SUP-2・SEC-1・SEC-2・SEC-5・SUP-14・CORE-6。#2686）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまで現行（A・B'・C・non-dumpable）を保ち、挙動は変えない（fail-closed）。判断の窓口は #2686（open のまま。末尾の「承認事項（判断シート）」）。関連: #1458・#1529・#1531・#2687（launch への B' の適用の再検討）・#2241（`rootful-host-root.md`）・#2631。

## 現状

| 箇所 | 挙動 |
| ---- | ---- |
| A（`exec/interpreter.rs`） | `#!/proc/self/exe`・`PT_INTERP`・symlink 経由でランタイムに解決される静的な指定を拒否する |
| B'（`exec/sealed_copy.rs`） | 稼働中コンテナへの exec のエントリポイント本体だけを封印 memfd に複製する。LSM が許可リスト外なら使わない（`SealPolicy`） |
| non-dumpable（`exec/exec_command.rs`） | exec worker は `setns` の前から、launch は資格情報の切り替え後に設定し直す。他プロセスから `/proc/<pid>/exe` へ届かない |
| Landlock（`exec/stages.rs`・`oci_runtime/launch.rs`） | 本番は必須。`escape_suite.rs` の ESC-07（`attack_esc07_runtime_binary_write` / `_landlock`）が `/proc/self/exe` の書き込み open と読み取り open の拒否を照合している |
| B（本書の対象） | 未着手 |

プロセスの構造は次のとおり。launcher のバイナリがコンテナの exec に届くことはない。

```text
launcher / CLI --execveat(検証済み fd)--> supervisor --fork--> PID 1（launch）
                                                     --fork--> exec worker --fork--> コマンドの子
```

PID 1・exec worker・コマンドの子は supervisor を fork しただけなので、最後の `execveat` までの `/proc/self/exe` はホスト側の supervisor のバイナリを指す。したがって「launcher・exec 専用プロセスに組み込む」は、launcher 自身を封印するのではなく、次のどちらかを意味する。

- **L**: launcher（rootful 相当の特権ランチャー）または CLI（rootless）が supervisor を封印 memfd に複製し、その fd を `execveat` する。supervisor の `/proc/self/exe` は生涯 memfd を指す
- **C**: fork した子が最後の `execveat` の直前に、自分自身（ランタイム）を memfd から再実行する（runc init 型の再入）

## 脅威の整理（CVE-2019-5736 型）

成立条件は (i) ホスト側ランタイムの inode に `/proc/<pid>/exe`・`/proc/self/exe` 経由で届くこと、(ii) その inode に書けること。

| 経路 | 塞いでいる層 |
| ---- | ------------ |
| launch（pivot 直後で他プロセスが居ない） | A、Landlock |
| exec（稼働中のコンテナ内から別プロセスが `/proc/<pid>/exe` を開く） | non-dumpable、A、Landlock の `EXECUTE`（インタープリタのパス差し替え〔TOCTOU〕はこれに頼る） |
| ホスト側ランタイムへの書き込み | Landlock（ESC-07）。DAC は root 所有のインストールに限る |

権限モデル別の残余リスク（B が無い場合）:

- **rootless（CORE-6 の既定）**: コンテナの uid 0 は起動ユーザーの uid に写る。`docs/setup/linux.md` の手順では supervisor を利用者所有のディレクトリに 0755 で置くため、コンテナ root とバイナリの所有者が同じ uid になり、**DAC では書き込みを止められない**。止めているのは non-dumpable・A・Landlock だけ。B が多層防御として効くのは主にここ
- **特権ランチャーの構成（SUP-14）**: uid は非 root のまま `RootlessSingleId` に入り、supervisor は root 所有でインストールされる（`install-privileged-launcher.sh`）。DAC でも書き込みを止められる
- **`RootfulHostRoot`**: 現在は本番経路で拒否している（#2241 は判断待ち）。許すことになればコンテナ root がホスト root になり DAC が効かない

## 選択肢

| 案 | 内容 | 論点 |
| -- | ---- | ---- |
| L | supervisor を封印 memfd から exec する | 下記のコスト。組み込み先は launcher の `execveat_fd` と CLI の supervisor 起動（`start_client`）。supervisor 内で自分の exe パスに依存する箇所は、本書時点の `git grep` で `launcher.rs` の `read_link("/proc/self/exe")`（launcher 側）と試験コードの `current_exe()` だけ。CLI 側の `current_exe()`（`supervisor_start.rs`・`doctor/launcher_check.rs`）は supervisor の置き場所の解決用で、L では supervisor の exe だけが変わる |
| C | fork した子が自分を memfd から再実行する | 再入プロトコル（引数・fd・pidfd・証跡 `ExecReady`・`LaunchReady` の受け渡し）の新設が要る。`setns` の後は `/proc/self` を使えないため exe の fd は `setns` の前に確保する。証跡設計（#1532・#1714）を作り直す規模 |
| D | 小さな静的 shim を経由する（runc の dmz 型） | 照合済み（下の「runc の照合」）。runc は dmz を v1.2.1 で削除しており、v1.3.0・v1.5.2 のどちらにも無い。採用の先例としては使えず、独自に設計する案になる |
| O | overlayfs 等で読み取り専用に見せる（runc 1.2 系の zero-copy 方式） | 照合済み（同上）。runc の実装は特権ユーザーかつ `fsopen` が使えるカーネルでだけ動き、失敗すると複製（memfd → `O_TMPFILE`）へ縮退する。user namespace 内（rootless）では成立しない（コード中の注記）。rootless が主な残余リスクなので、O はそこを塞がない |
| E | 複製せず、インストールを root 所有（0755）にする | rootless でも DAC で書き込みを止められる。`doctor` が利用者の書ける supervisor を通知すればコスト 0 の補強になる。実装は別 issue の候補 |
| N | 見送り（見直し条件つき） | **推奨** |

LSM との関係: B' の `SealPolicy` は、許可リスト外の LSM（apparmor・selinux・ima・evm 等）が有効なら複製を使わない。memfd から実行するとパスに結び付いたプロファイル・ドメイン遷移・IMA の計測が元のファイルについて働かない、という論点は B も同じである。同じゲートを掛けると、Ubuntu の既定（AppArmor）や Fedora（SELinux）では B は働かない。ゲートを外せば AppArmor・SELinux・IMA の拘束を自分で外すことになる。

## runc の照合（#2772）

確認日は 2026-10-26。照合に使った版は、runc `v1.3.0`（commit `4ca628d1d4c974f92d24daccb901aa078aad748e`）と、取得時点の最新リリース `v1.5.2`（commit `29dd3dc2b13b4123162e5fe132504bb4b15569f1`）。

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| dmz 型 shim の導入・削除 | [v1.3.0 `CHANGELOG.md`](https://github.com/opencontainers/runc/blob/4ca628d1d4c974f92d24daccb901aa078aad748e/CHANGELOG.md) の 1.2.0-rc.1 の項（L400-409。`runc-dmz` は約 8K の追加の execve 段で、`RUNC_DMZ=true` の opt-in）と 1.2.1 の「Removed」（L212-215。`runc-dmz` を削除。1.2.0 のリリースだけに含まれ、opt-in だった） | 結果: 現行版では採っていない。dmz は導入後に削除された。v1.3.0 と v1.5.2 のどちらにも `libcontainer/dmz/` が無い（contents API が 404） |
| 現行の保護の構成 | v1.3.0 の [`libcontainer/exeseal/`](https://github.com/opencontainers/runc/tree/4ca628d1d4c974f92d24daccb901aa078aad748e/libcontainer/exeseal)（`cloned_binary_linux.go`・`overlayfs_linux.go`）。v1.5.2 も同じ 2 ファイルに `doc.go` を足した構成。`CloneSelfExe`（v1.3.0 `cloned_binary_linux.go` L218-L248）は先に `sealedOverlayfs` を試し、失敗したら `CloneBinary` で複製する。複製の取得は `getSealableFile`（L124-L173。memfd → `O_TMPFILE` → `mktemp`） | 一致。文書が挙げたパス `libcontainer/exeseal/` は正しい。現行の主方式は overlayfs（特権時）と、封印した複製（memfd）の縮退 |
| overlayfs 方式の導入版 | v1.3.0 `CHANGELOG.md` の 1.2.0 の「Added」（L226-L232）。「十分な権限があり、カーネルが対応しているときに使う」と書かれ、性能・メモリの上乗せはほぼ無い | 一致（導入は 1.2.0） |
| overlayfs 方式の成立条件 | [v1.3.0 `overlayfs_linux.go`](https://github.com/opencontainers/runc/blob/4ca628d1d4c974f92d24daccb901aa078aad748e/libcontainer/exeseal/overlayfs_linux.go) の `sealedOverlayfs` の注記（L42-L47。「特権ユーザーと、overlayfs・`fsopen()` を有効にしたカーネルでだけ動く」）と、user namespace 内での overlayfs（Linux 5.11 以降）を使う旨の TODO（L49 付近）。v1.5.2 も同じ注記（L42-L47） | 一致（rootless では不成立）。最新版でも user namespace 内の対応は TODO のまま |

含意（判断はオーナー）: D は上流が捨てた方式で、採否の根拠にならない。O は特権時の最適化で、rootless（CORE-6 の既定）の残余リスクを減らさない。本書の推奨 N（見送り）は、この照合で変わらない。見直しの条件にある「O が rootless で成立すると分かったとき」は、上流が user namespace 対応を入れたときに再確認する。

## コストの見積り

実測（release ビルド、`cargo build --release -p fandhe-container-supervisor`。x86_64・rustc 1.99.0・commit a86a7491。リポ外の target で計測し削除済み）:

| 成果物 | サイズ |
| ------ | ------ |
| supervisor（strip 前） | 4,012,776 B（約 3.8 MiB） |
| supervisor（strip 後） | 2,986,440 B（約 2.8 MiB） |
| launcher（strip 前） | 972,488 B（約 0.93 MiB） |

CLI のサイズと、PSS・複製時間は未計測。以下の式はモデルであり、実測値ではない。

- **L**: supervisor 1 つにつき memfd にバイナリ全体が常駐する（共有されない shmem。書き込んだ側の cgroup に計上）。今はページキャッシュの text を N 個の supervisor が共有し PSS で按分される。L ではこれが各プロセス固有になる。ホスト全体の増分は約 N ×（バイナリサイズ）。50 コンテナ（CORE-9）で strip 後を使うと約 142 MiB で、SUP-2（supervisor 1 つあたりの PSS 中央値 2MB 以下）と正面から衝突しうる（マップして触れた text 分が PSS に乗る。触れる割合は未計測）
- **C**: exec 1 回ごとに一時的にバイナリサイズぶん（約 2.8〜3.8 MiB）の memfd と複製の時間がかかる。エントリポイントの `execve` で解放されるため常駐はしない。時間は未計測
- 見直し時の測り方: memfd 経由起動の試作を `scripts/bench/supervisor_pss.sh` で測る（本書の範囲外）

## 推奨と理由（N）

- (a) L は SUP-2・CORE-9 と衝突する見込みが大きい（上の見積り。PSS の実測は未実施）
- (b) LSM ゲートを B' と揃えると、主要なホストで働かない
- (c) 本番は Landlock 必須で、ESC-07 が書き込み・読み取りの拒否を照合している。A と non-dumpable も重なる
- (d) C は証跡設計の作り直しになり規模が大きい

残余リスク（Landlock の不具合・迂回、rootless の利用者所有インストール）は残る。低コストの補強として E を推す。

## 見直しの条件

- #2241 で `RootfulHostRoot` を条件つきで許す方針になるとき: **それより先に** 本件を再判断する（DAC が効かなくなるため）
- Landlock を必須でなくす構成（古いカーネルへの縮退等）を入れるとき
- IMA・AppArmor の memfd に対する挙動を一次情報で確かめ、`SealPolicy` を緩められたとき
- SUP-2 の予算に余裕がある実測が出たとき、または O が rootless で成立すると分かったとき
- #2687 の判断でメモリの評価軸が変わったとき

## 承認事項（判断シート）

| ID | 論点 | 選択肢 | 推奨 | 状態 |
| -- | ---- | ------ | ---- | ---- |
| D1 | 方式 B を採るか | L / C / D・O（一次情報で確認済み。D は先例なし、O は rootless で不成立） / N | N | 未決 |
| D2 | E（root 所有インストールの推奨と doctor の通知）を別 issue で進めるか | 進める / 進めない | 進める | 未決 |
| D3 | 見直しの条件を上のとおりとするか | 承認 / 修正 | 承認 | 未決 |
| D4 | #2241 との順序の拘束（先に本件を再判断）を受け入れるか | 受け入れる / 受け入れない | 受け入れる | 未決 |

## 決定後の変更の棚卸し

本書の時点では何も変えていない。

- N: `interpreter.rs` の表の B の行を「見送り（本書）」に替える
- L / C: 組み込み先（launcher の `execveat_fd`・CLI の supervisor 起動、または exec 子の再入）を実装し、`sys` の `memfd_create_for_exec_copy`・`seal_for_exec` を再利用する。結合試験（`production_launcher`・supervisor の exec 系）で `/proc/<pid>/exe` が `/memfd:` を指すことと封印が揃っていることを照合し、SUP-2 を `supervisor_pss.sh` で再計測する
