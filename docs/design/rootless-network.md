# rootless ネットワークの外部ヘルパー選択肢（判断記録）

非特権 user namespace（rootless）で host / none 以外のネットワークとポート公開を成立させる方式の選択肢を整理し、その判断を記録する（NET-9）。

> **位置づけ**: 本書は 2026-10-12 に #340 で採用を決定した判断記録である。2026-10-27 に #1935 で起動点・同期・設定の入口・版の固定の設計を確定し、12 章に記録した（自動運転で選んだ項目はオーナー承認が未取得で、12.15 に分けた）。決定の要点は下の「決定」のとおり。NET-9 は 2026-10-12 に spec 上も「確定」になった（Fandhe-AI/fandhe-container-spec#18）。

- 対象ビヘイビア: NET-9（Should・確定。関連: CORE-6・SEC-5・NET-11・NET-6・PLUG-1・ERR-1・REPAIR-5）
- タスク: TASK-147（MS-8・G10。本書は TASK-147.1・#339。前提は TASK-8〔#26。完了済み〕）
- 関連 issue: #338（親）・#340（採否判断。2026-10-12 に採用を決定）・#341（実装・実証）
- 出典: `docs/spec/04-behavior/api-network.md` の `NET-9`・`NET-11`、`01-brainstorm.md` の D-18 論点 3・4・未解決疑問点 11・14、`05-tasks.md` の TASK-147（submodule リビジョン `0b284cf`。2026-10-12 の決定の反映後で、pasta と DNS ヘルパーの配置の決定も反映済み。NET-9 が確定になり、rootless でのネットワークの指定の読みと待ち受けアドレスの規則が NET-9 に追記された。未解決疑問点 11 の rootless 転送の部分と 14 の外部ヘルパーの部分が解消された。起草時のリビジョン `984f8a2` は履歴として残す）。関連: `NET-6`（コンテナ単位のネットワークの既定は `none`。NET-9 の確定後に見直した結果、rootless でも `none` のまま。2026-10-12 のオーナー決定）。外部事実の出典は 3 章に URL と確認日（2026-10-02）を付す

## 決定（2026-10-12・#340）

オーナーの決定の記録は [#340 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/340#issuecomment-6127294645)。

| 判断事項 | 決定 |
| -- | ---- |
| 採否 | 採用する（2 章の選択肢 (a)）。rootless のネットワークは外部ヘルパーによるユーザー空間転送で構成する |
| 外部ヘルパー | pasta（passt）。同梱もリンクもしない。利用者が導入し、fandhe-container は別プロセスとして exec するだけ |
| ライセンス | GPL-2.0-or-later のバイナリを、同梱しない・リンクしない・exec のみ、という使い方で使うことを認める。中核のライセンス（Apache-2.0 単独）と、依存を permissive ライセンスに限る規約は変えない。pasta は Cargo の依存ではなく、ビルドにも成果物にも入らない。同梱・再配布はしない（将来する場合は改めて判断する） |
| D-14 | rootless のユーザー空間転送を例外として認める。転送プロセスがデータパス上に載るのを許すのは rootless の経路に限る。rootful の経路（veth・bridge・nftables）は変えない |
| フルスクラッチ方針 | 例外として認める。netlink・nftables を自前実装する決定（NET-11）は変えない |
| rootless での `--network <ユーザー定義ネットワーク名>` | pasta の構成として読む。コンテナごとに pasta を 1 プロセス起動する。同じネットワーク名のコンテナ同士の通信と名前解決は約束しない。NET-6 の値は 3 種のまま増やさない |
| pasta の場所の指定の入口 | CLI のグローバルフラグ（`--plugin-path-search` に倣う形。フラグの名前は #1935 の設計で決める）。環境変数では受けない（特権ランチャーが環境を作り直すため）。作成時に解決・検証した結果を状態に記録し、起動時に再検証する |
| 版の固定 | 最小版以上。`--version` の出力を解釈できないものは拒否する。最小版の値は #1935 の設計で決める |
| 待ち受けアドレス | 省略時は常に loopback。明示されたアドレスは loopback 以外（`0.0.0.0` を含む）も受ける。IPv6 は最初の版では受けず、作成前に拒否する。rootful の `PortPublish`（loopback と未指定を拒否する）との差は利用者向けの doc に書く |
| `--network` の指定が無いときの既定（NET-6） | rootless でも `none` のまま。pasta 経由の構成は、利用者が明示したときに使う |

上の 4 点の記録先は [#1935 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/1935#issuecomment-6128208117)である。

spec には 2026-10-12 に反映済みである（Fandhe-AI/fandhe-container-spec#18。NET-9 は確定、未解決疑問点 11 は rootless 転送の部分だけ解消、14 は外部ヘルパーの部分が解消）。DNS ヘルパー（NET-5）も 2026-10-12 に D-14 の例外として認められた（#4 のコメント。本書の範囲外）。spec への反映は Fandhe-AI/fandhe-container-spec#18・#19。本書は spec を変更しない。

## 1. 前提と制約

- 非特権 user namespace ではホストの network namespace での `CAP_NET_ADMIN` がなく、bridge・veth・nftables（NET-1・NET-11 の自前実装）をホスト側に構成できない（CORE-6 と同一の制約）。host / none 以外のネットワークとポート公開にはユーザー空間転送が必要になる
- 対象は Linux ネイティブの rootless のみ。macOS / Windows は VM 内で rootful 相当のため本書の対象外
- 根拠 PoC がない。network-bridge-nft（PoC-15）・supervisor-model（PoC-17）は AppArmor 制約（非特権 user namespace の制限）により rootless 経路が未検証で、pasta は未導入・未計測だった（PoC の時点。2026-10-12 に pasta 単体の実機確認を行った。3 章）
- 再検証条件: AppArmor 変更が可能な環境（TASK-8 で調達する環境）での別 PoC（TASK-147 の採用時分岐、#341）

## 2. 選択肢

spec D-18 論点 3 の 3 案。spec には「(a) を MVP、(b) を将来」という推奨が記録されているが、これは記録された推奨であり未確定である。

| 案 | 内容 | 主な論点 |
| -- | ---- | -------- |
| (a) | 外部ヘルパー（pasta 等）を exec してユーザー空間転送を構成する | 外部バイナリ依存・ライセンス・フルスクラッチ方針との整合（4・5 章） |
| (b) | ユーザー空間の TCP/IP 転送を自前実装する | 工数が大きい（8 章）。フルスクラッチ方針とは整合する |
| (c) | rootless は host / none モード（NET-6）のみ対応する | NET-9（Should）の期待を満たさない。spec 側の判断が必要 |

決定: (a)。外部ヘルパーは pasta。

## 3. 外部ヘルパー候補の比較

確認日は 2026-10-02。出典に明記されていない項目は「未確認」とし、推測で埋めない。

| 項目 | pasta（passt） | slirp4netns |
| ---- | -------------- | ----------- |
| ライセンス | GPL-2.0-or-later（[README](https://passt.top/passt/tree/README.md)・[man](https://passt.top/builds/latest/web/passt.1.html)）。ファイル別の例外は、Ubuntu のパッケージの copyright で `checksum.c` が `GPL-2+ and BSD-3-Clause` と確認（実機確認 2026-10-12） | GPL-2.0-or-later（[リポジトリ](https://github.com/rootless-containers/slirp4netns)）。依存する libslirp のライセンスは未確認 |
| 対象 netns の指定 | `pasta [OPTION]... PID` または `--netns [PATH\|NAME]`。`--netns-only` で user namespace に参加しない | PID 指定で attach（例: `slirp4netns ... <pid> tap0`） |
| ポート公開 | `-t` / `-u` で `[address[%interface]/]ports`（範囲・変換可）。bind アドレスを指定できる | マニュアル上の API ソケットで管理（詳細な指定構文は未確認） |
| readiness | `--pid file` が初期化完了後に PID を書く。既定はバックグラウンド化、`--foreground` で前面実行。DHCP・NDP・DHCPv6 を内蔵 | `--ready-fd` 等の有無は未確認 |
| 終了・後始末 | 対象 netns の消滅（バインドされたパスの削除・プロセス終了）で終了する（`--no-netns-quit` で抑止） | 未確認 |
| 特権 | 権限・capability なしで動作し、root 動作は user namespace 外では不許可（[about](https://passt.top/passt/about/)） | 非特権を前提とする設計（詳細は未確認） |
| メンテナンス・配布 | Alpine・Arch・CentOS Stream・Debian・Fedora・Ubuntu 等にパッケージあり。最新リリース日は未確認 | v1.2.x が Active、v1.1.x は EOL（2022-05-02）と README に記載。最新リリース日は未確認 |
| MAC との関係 | AppArmor・SELinux のプロファイル例が contrib に存在する。Ubuntu の `apparmor_restrict_unprivileged_userns` との関係は、制限が既定の `1` のままでも pasta が自分で namespace を作る形は動いたことを確認（実機確認 2026-10-12）。既存の namespace へ後から付ける形は制限を `0` に緩和した状態でのみ確認し、`1` のままは未確認（#341） | 未確認 |
| 公開性能 | IPv4 TCP スループットが比較対象の 4〜50 倍（MTU 依存。pasta 側の主張）。独立した検証は未確認 | MTU 65520 で 9.21 Gbps（netns からホスト、README 記載） |

- 2026-10-12 に実機確認を行った（x86_64 の Linux・Ubuntu 26.04.1 LTS・カーネル 7.0.0-34-generic・KVM の VM・passt `0.0~git20260120.386b5f5-1`）。以下は pasta 単体の参考値で、fandhe-container の製品コードとはつないでいない。セットアップ時間の中央値 39.5 ms（`pasta --config-net -- true` を 10 回）、常駐時の RSS 約 18.6 MB、loopback 越しのスループット 3,430 MiB/s（対照 8,535 MiB/s。python の socket で 1 回だけ計測。iperf3 は未使用）。rootful 比の劣化は未計測。上の公開性能の主張の検証ではない
- 本表の「未確認」のうち、上記の実機確認で分かった項目は埋めた。残りは一次情報（man・リリースページ・ディストリのパッケージ情報）による確認を #341 で行う

## 4. フルスクラッチ方針との整合

両論は次のとおり。オーナーは 2026-10-12 に、フルスクラッチ方針の例外として外部ヘルパーを認めた（#340）。NET-11 の決定（netlink・nftables の自前実装。`ip`・`nft` への委譲はしない）は変えない。例外は rootless のユーザー空間転送に限る。

- 整合するとみる論拠: Cargo の依存ではなく外部バイナリの exec である（`from-scratch-policy.md` の依存基準は Cargo 依存が対象）。`newuidmap` / `newgidmap`（SEC-5）と同型の外部コマンド利用という整理が D-18 に記録されている
- 整合しないとみる論拠: NET-11 は `ip`・`nft` コマンドへの委譲を、フルスクラッチ方針（決定 2）を理由に不採用とした。外部コマンドへの委譲を netlink では退け rootless では認める場合、線引きの説明が要る。`newuidmap` は特権ヘルパーとしてカーネル機能の補完に限られるのに対し、pasta はデータパス上の転送を担う点で性質が異なる
- 外部ヘルパーはデータパス（転送）そのものを担うため、依存の重みは `newuidmap` より大きい

## 5. ライセンス・配布

- 外部バイナリは `cargo deny` の対象外（[licensing](../../.claude/rules/licensing.md)「非 Cargo 資産」）
- 候補はいずれも GPL-2.0-or-later（3 章）。2026-10-12 のオーナー決定（#340）で、次のとおりとした
  - 別プロセスとして exec するだけ（リンク・同梱なし。利用者が別途導入）での利用を認める
  - 同梱・再配布はしない。する場合は改めて判断する（ソース提供義務・帰属表示の要否を含む）
  - コピーレフトのコードをリンク・流用しない前提は変えない
  - 帰属表示: 同梱・再配布をしない前提では、fandhe-container の配布物側に帰属表示・ソース提供は生じない、と整理する（法的な断定ではない）

## 6. D-14 との関係

- D-14 は「データパスに plugin 境界を置かない」原則。rootful 構成ではパケットがカーネル（veth・bridge・nftables）を通り、plugin が担うのは制御面のみで整合する
- rootless のユーザー空間転送は転送プロセス自体がデータパス上にある。IPC 往復がデータパスに入るのとは性質が異なる、という整理案が D-18 に記録されている。オーナーは 2026-10-12 に例外として認めた（#340）。例外は rootless の経路に限る。未解決疑問点 11 は、rootless 転送と DNS ヘルパーを例外とするかの部分が解消された。配置も同日に決まった（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6129145225)）。pasta は core 側で、コンテナごとの supervisor が起動・監視・回収する（寿命がコンテナと同じで、親の supervisor が確実に回収できるため。常駐デーモンを置かない CORE-1 の下で plugin 側に置くと、都度起動の plugin が親になり回収の仕組みを別に作ることになる）。DNS ヘルパーは plugin 側で、`NetworkPlugin` の実装が起動・停止する（NET-5・NET-7）。未解決疑問点 11 のほかの論点も 2026-10-15 に決まった（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6200154873)）。rootful のネットワーク設定（veth・bridge・nftables）は `NetworkPlugin` の実装が行い、core は network namespace を渡すだけにする。rootless の経路（本書）は変わらない
- 関連: `docs/architecture.md`（境界表は rootless 転送の行と DNS ヘルパーの行に分かれ、配置の決定が反映された）、[crate-naming.md](crate-naming.md)（net crate の PLUG-1 区分は core 側のライブラリに確定した）。両書は spec のステータスに従う

## 7. 採用時の実装方針・工数概略（#341 の範囲）

- 設計の選択 4 点（上の「決定」）は 2026-10-12 に決まった。起動主体は supervisor に決まった。起動の時点・同期・失敗の分類・寿命・フラグの名前・最小版の値などの残りの設計は #1935 で確定した（12 章）
- 決定した構成: pasta を利用者が導入し、fandhe-container は `crates/net` から別プロセスとして exec する。同梱・リンクはしない。ポート公開の bind の既定は loopback
- 実装で守る点:
  - pasta の既定（`auto`）と、アドレスを省いた明示の指定は、ホストの全アドレスでポートを開く。loopback を既定にするには待ち受けアドレスを必ず明示する
  - `-t none` と明示のポートは併用できない。明示の `-t` に `-u none -T none -U none` を足す
- 12 章（#1935）で、起動の時点と同期（12.2）・入口のフラグ（12.4〜12.5）・pasta の引数（12.7）・準備完了と PID ファイル（12.8）・失敗の分類と期限（12.9）・寿命と回収（12.10）・版の固定（12.12）を確定した。実機で確かめていない点の一覧は 12.11
- まだ確かめていない点（#341）: 制限 `1` のまま既存の namespace へ後から付ける形、IPv6、`--netns <パス>` の指定、`-T none -U none` を付けたときの名前解決、常駐時の PSS、rootful 比のスループット劣化
- AppArmor の補足: Ubuntu 26.04 では `sleep` の実体が pasta の AppArmor プロファイルの exec 規則の外にあり、pasta から直接は起動できなかった。`sh -c` を挟めば動いた（実機確認 2026-10-12）
- #341 の実証範囲: rootless の経路で host / none 以外のネットワーク構成（ポート公開を含む）が実機で成り立つこと（NET-9）。実装の issue は #1935（設計の確定）・#1936〜#1941（実装と試験）
- 配置（決定）: `crates/net`（core 側のライブラリ）に pasta の起動・待機・回収の関数を置き、supervisor から呼ぶ（NET-9・CORE-1。pasta の起動関数は未実装で、実装は #1936〜#1941。supervisor → `net` の依存は feature を切らない通常の依存に決まった〔[network-wiring.md](network-wiring.md) D5・#1870〕）。`NetworkPlugin` は plugin 側のまま。ヘルパーの寿命は supervisor のコンテナ寿命に連動させ、コンテナ終了時に確実に回収する
- ヘルパー探索: 絶対パス指定または opt-in の探索のみとし、所有者・権限・版数を検証する（9 章）
- ポート公開指定の変換: 利用者入力を検証してから `-t` / `-u` 相当の引数配列へ変換する。シェルを介さない
- 失敗時の挙動: ヘルパー不在・版不一致・起動失敗は fail-closed とし、作成前に ERR-1 形式で拒否する。起動・readiness 待ちにタイムアウトを設ける（REPAIR-5）
- テスト: ヘルパーと AppArmor 変更可能な環境を要するため実機前提テストとして分離する（[ci](../../.claude/rules/ci.md)）。実証と計測は #341
- 工数概略（概算。TASK-147 の 2 人日の枠内。精度は低い）:

| 内訳 | 目安 |
| ---- | ---- |
| 設計確定（#340 の判断を受けた具体化） | 約 0.5 人日 |
| 起動・監視・引数変換の実装とテスト | 約 1 人日 |
| 実機実証・計測レポート（#341） | 約 0.5 人日 |

## 8. 不採用の場合の実装方針・工数概略

不採用としなかったため、本章は判断時の比較の記録として残す。

- (c) host / none のみ対応: rootless で bridge 等が指定された場合は、作成前に ERR-1 形式のエラーで拒否し、制約をドキュメントに明記する。工数は小（概算で 0.5 人日未満）。NET-9（Should）の期待を満たさないため、spec 側の扱い変更の判断が必要で、ユーザー報告対象とする
- (b) 自前実装を将来課題とする: TCP/IP スタック相当のユーザー空間転送が必要で、2 人日を大きく超える見込み。別タスク化と spec 側への反映が必要
- いずれの場合も、spec の修正は本リポから行わず、ユーザーへ報告する

## 9. セキュリティ考慮（採用時の設計要件）

| 観点 | 要件 |
| ---- | ---- |
| インジェクション | ポート公開・アドレス等の利用者入力を検証し、引数配列で exec する（NET-12 と同じ ERR-1 方針） |
| アクセス制御 | ヘルパーは user namespace 内の非特権で動かし、setuid を要求しない。ポート公開の bind アドレスを既定で全インターフェースへ開かない。既定は loopback（2026-10-12 の決定）。pasta はアドレスを省くと全アドレスで開くため、待ち受けアドレスを必ず明示する。利用者が明示したアドレスは loopback 以外も受ける。IPv6 は最初の版では作成前に拒否する |
| 不安全な設計 | 起動・readiness 待ちにタイムアウト（REPAIR-5）。不在・版不一致・異常終了は fail-closed。コンテナ終了時に回収する |
| 完全性 | ヘルパーは絶対パス・所有者・権限を検証し、信頼できない `PATH` の暗黙探索をしない（PLUG-11 の opt-in 方針に倣う）。対応版数は最小版以上とし、`--version` の出力を解釈できないものは拒否する |
| サプライチェーン | `cargo deny` で検出できないため、ライセンス・脆弱性への追随を手動で確認する運用が必要 |
| 監査 | 起動失敗・分離違反の試行を構造化ログ・監査ログへ記録する（SEC-4・REPAIR-4） |
| ホストの loopback・ホストのサービス | pasta の既定は gateway をホストの loopback へ写し、コンテナからホストの 127.0.0.1 専用のサービスへ届く。`--map-host-loopback none` と `--map-guest-addr none` で閉じ、`--host-lo-to-ns-lo` は付けない（12.7） |
| holder の露出 | netns holder は capability を落とし、secret・fd を継承せず、no_new_privs にする。同じ uid への露出は owner が元々持つ権限の範囲（12.2） |

## 10. 判断した項目（#340）

1. 採否（2 章の (a)・(b)・(c)）と、NET-9 の spec 上の扱い: (a) を採用した。NET-9 の spec 上の扱い（起草時は「検討中」のまま）は spec に反映済み（Fandhe-AI/fandhe-container-spec#18）
2. ライセンス・帰属表示の判断（5 章）: exec のみでの利用を認めた。同梱・再配布をしない前提では帰属表示は生じない、と整理した。法的な断定ではない
3. D-14 の例外として認めるか（6 章。未解決疑問点 11）: rootless のユーザー空間転送に限り認めた。疑問点 11 の rootless 転送の部分は spec に反映済み（Fandhe-AI/fandhe-container-spec#18）
4. ヘルパーを同梱するか、利用者導入とするか。候補は pasta・slirp4netns のどちらにするか: 利用者導入とし、pasta を採用した。同梱はしない
5. ポート公開の bind アドレスの既定方針: loopback とした
6. 実機で確認する計測項目: 2026-10-12 の実機確認で、pasta 単体の参考値（セットアップ時間の中央値 39.5 ms・常駐 RSS 約 18.6 MB・loopback 越しのスループット 3,430 MiB/s〔対照 8,535 MiB/s〕）を得た。製品コードとはつないでいない。rootful 比のスループット劣化・常駐 PSS は未計測で、3 章の未確認項目の一次情報による確認とともに #341 に残す

## 11. 見直し条件

- 2026-10-12 に判断記録へ更新した
- 2026-10-12 に spec の更新（Fandhe-AI/fandhe-container-spec#18・#19。NET-9 の確定、未解決疑問点 11・14、NET-6 の既定、rootless でのネットワークの指定の読みと待ち受けアドレスの規則）へ追従した
- 2026-10-12 に配置の決定（pasta は supervisor〔core 側〕、DNS ヘルパーは `NetworkPlugin` の実装〔plugin 側〕）へ追従した。2026-10-15 に未解決疑問点 11 のほかの論点の決定（Fandhe-AI/fandhe-container-spec#22）へ 6 章を追従した
- 2026-10-27 に #1935 の設計（起動点・同期・入口・版の固定）を 12 章に確定し、7 章・9 章を追従した。12 章の実機未確認の点（12.11）が確かめられて設計が変わったら 12 章を更新する
- pasta を同梱・再配布することにした場合は、ライセンスの判断をやり直す

## 12. 起動点・同期・設定の入口・版の固定（#1935・TASK-147 追補）

rootless の pasta 構成について、起動の時点と同期、pasta に渡す引数、設定の入口、版の固定、失敗の分類、寿命と回収を確定する（NET-9・NET-6・PLUG-11・SEC-1・SEC-4・ERR-1・REPAIR-4・REPAIR-5）。#1870 の [network-wiring.md](network-wiring.md) の D1・D4・D6〜D8・D10・D14・D15 と矛盾しない範囲で細目を決める。実装は #1936〜#1941 と 12.14 の後続 issue が担う。

- **自動運転で選んだ項目**: 12.1 のオーナー決定以外（12.2・12.3・12.5〜12.10・12.12）は、自動運転で安全側に選んだ方式で、オーナーの承認は未取得である（`rootless-id-map-holder.md` §3 と同じ扱い）。承認待ちの点は 12.15 に分けた
- **一次情報**（確認日 2026-10-27。GPL のソースはコードを写さず、挙動の事実だけを書く）:
  - passt の `conf.c`（`conf_pasta_ns`）と `man pasta`: `pasta [OPTION]... PID` は `/proc/<PID>/ns/net` と `/proc/<PID>/ns/user` を組み立てて開く。`--netns` は PID と併用できず、`--netns PATH` に `--userns` を付けないと `--netns-only` 扱いになる。`--map-host-loopback` は既定で gateway をホストの loopback へ写し、`none` は `--no-map-gw` も含意する。`-T` / `-U` の既定は `auto`。`--version` は「pasta」と空白に続けて版の文字列を出し、exit 0 で終わる
  - passt の `isolation.c`・`passt.c`: 起動直後の `isolate_fds()` が fd 3 以上を `close_range` で閉じる（`--fd` の tap 用だけが例外）。この処理は引数の解釈より前に走る。したがって継承した fd を `/proc/self/fd/N` で渡す形は成り立たない
  - passt の `pasta.c`: netns-quit は対象が procfs の `/proc/<pid>/ns` なら 1 秒周期のタイマーで消滅を検出する
  - 本機の AppArmor プロファイル（`/etc/apparmor.d/usr.bin.pasta`）: 書き込みは `/tmp/**`・`owner @{HOME}/**`・`@{run}/user/@{uid}/**` に限り、`/proc/<pid>/ns/{net,user}` の読みと `ptrace r` は許す
  - 本リポ: `network-wiring.md` D8（本番の supervisor は `PR_SET_DUMPABLE=0` で、exec 前の子もこれを継承する。親は子の `/proc/<pid>/ns/*` を開けない。dumpable を 1 に戻すことも `CAP_SYS_PTRACE` を足すことも禁じる）、`rootless-id-map-holder.md` §4、rootless の既定の状態ルートは `$XDG_RUNTIME_DIR/fandhe-container`

### 12.1 既決事項（再決定しない）

| 事項 | 決定 | 出典 |
| ---- | ---- | ---- |
| `--network <名前>` の読み | rootless のユーザー定義名は pasta 構成。コンテナごとに pasta を 1 プロセス | #340（2026-10-12） |
| 既定 | `none` のまま（NET-6） | #340 |
| 場所の入口 | CLI のグローバルフラグ。環境変数では受けない。作成時に解決・検証して記録し、起動時に再検証 | [#1935 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/1935#issuecomment-6128208117) |
| 版 | 最小版以上。解釈できない出力は拒否 | 同上 |
| 待ち受けアドレス | 省略時は loopback。明示は `0.0.0.0` を含めて受ける。IPv6 は作成前に拒否 | 同上 |
| 起動主体 | コンテナごとの supervisor（core 側）。起動・待機・回収の関数は `crates/net` | [#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6129145225) |
| 依存の向き | `supervisor` → `net` は通常の依存。`core` → `net` は足さない | network-wiring.md D5（#3065） |
| 予約名・定義の状態 | D1・D10 のまま。pasta 構成でも名前の照合は変えない | network-wiring.md |

### 12.2 netns の作り手・pasta の対象・付ける時点

- **決定**
  - **netns の作り手**は core の rootless 経路とする。D6 の `CLONE_NEWNET` と `lo` の up をそのまま使い、`LaunchOptions` の network モードに「外から付ける netns」（名前は #1939 で決める。例: `Attachable`）を足す。中身は Loopback と同じで、exec 前の同期点で fd を渡して親の合図を待つ点だけが違う。core は pasta を知らない
  - **同期点**は D8 を拡張する。子は `process.user` の資格情報を切り替える前・exec の前の同期点で、`/proc/self/ns/net` と `/proc/self/ns/user` をこの順で `O_RDONLY|O_CLOEXEC` で開き、同期用の `SOCK_SEQPACKET` に 1 メッセージの `SCM_RIGHTS` で載せて親へ送る。親は fd がちょうど 2 本であること・control メッセージ長・余分な fd が無いこと（あれば閉じる）・各 fd の `fstat`・nsfs であること・netns の (dev, ino) が supervisor の基準と違うこと（D8 の `Other`）を検証し、不一致なら子を止めて `FailedPrecondition` にする。待ちは期限つき。型の最終照合は holder の `setns(fd, CLONE_NEWUSER / CLONE_NEWNET)` が行う（型違いは `EINVAL`）。Loopback・Host のモードは D8 のとおり 1 本のまま
  - **pasta の対象（PID）**は、コンテナのプロセスではなく専用の **netns holder** とする。holder は supervisor が `/proc/self/exe` を exec し直して作る（argv は `netns-holder`、`env_clear`、stdin は socketpair の片端、stdout は null、stderr は supervisor のログ）。exec 直後で単一スレッド・メモリは空・dumpable は既定のまま。holder は最初に `PR_SET_PDEATHSIG=SIGKILL` を設定して `getppid` で親を確かめ、socketpair から 2 本の fd を受け、`setns(user)` → `setns(net)` の順で参加し、参加後の `/proc/self/ns/net` の (dev, ino) が受けた fd と一致することを確かめて fd を閉じる。続けて全 capability を落とし（capset で空）`PR_SET_NO_NEW_PRIVS` を設定し、固定長の READY フレームを返して、以後は socket の EOF または STOP を待つだけにする。ロジックは `crates/net` の `run_netns_holder_main` に置き（DNS ヘルパーの `run_dns_helper_main` と同じ形）、supervisor の bin の main が `netns-holder` で振り分ける
  - **pasta が holder の ns を開ける根拠**: pasta は supervisor と同じ uid で init の user namespace にいる。holder は dumpable で uid も同じなので `ptrace_may_access(READ_FSCREDS)` を通る（dumpable なら能力の検査に入らない）。AppArmor も `ptrace r` を許す。#340 で確かめた `pasta --config-net <PID>`（`unshare --user --net` の子が対象）と同じ形である
  - **付ける時点**は launch の中で、子が同期点で待っている間に、(1) fd を受けて検証、(2) holder を起動して READY を待つ、(3) pasta を起動、(4) 準備完了を待つ（12.8）、(5) 子へ合図、(6) 子が資格情報を切り替えて exec、の順に進める。合図の前のコンテナには `lo` しかない
- **理由**: pasta は fd 3 以上を閉じるので fd を渡す形は成り立たない。PID の形の対象は ptrace で読める必要があり、exec 前のコンテナの子（non-dumpable）は対象にできず、D8 は dumpable を戻すことも `CAP_SYS_PTRACE` を足すことも禁じている。holder は exec し直すので supervisor のメモリ（注入ファイル等。#2628）を継承しない。SingleId でも SubordinateIds でも同じ形で使える。文書化され実機で確かめた PID の形だけを使える
- **却下した案**
  - コンテナの子を対象にする（non-dumpable のため開けない）
  - 同期点の間だけ子を dumpable にする（D8・SEC-1 が禁じる。子は secret の memfd などを持つ）
  - `--netns /proc/self/fd/N --userns ...` で fd を渡す（`isolate_fds` で閉じられる）
  - netns を bind mount して `--netns <パス>` を使う（rootless はホストの mount namespace に bind できず、パスの寿命の管理も要る）
  - holder U（`rootless-id-map-holder.md`）に netns も作らせる（SubordinateIds の経路にしか無く、U は RELEASE で消え、dumpable の窓が延び、#2374 の設計を崩す）
  - exec の後に PID 1 へ付ける（entrypoint がネットワークの準備前に走る競合が残る）
  - holder を fork だけで作る（supervisor のメモリを継承する）
- **残る露出**: 同じ uid のホスト側プロセスは holder の ns を開いてコンテナの user namespace と netns に入れる。これは exec 後の PID 1（dumpable で owner は全 capability を持つ）から owner が元々できることと同じで、新しい権限は与えない。holder は capability を落としているので乗っ取られても netns を書き換える権限が残らず、fd 3 以上と secret を持たない

- **実装（#3197）**: `crates/net/src/netns_holder.rs`（入口 `run_netns_holder_main`・期限の定数）と子モジュール `holder`（holder 側の手順）・`channel`（supervisor 側の端 `NetnsHolderChannel`・`NetnsHolderFds`）・`frame`（固定長 32 バイトのフレーム。magic `FCNH`・version 1・kind・LE の 3 欄。OS 非依存）。syscall は `sys/holder.rs` の薄いラッパーと libc 照合。supervisor の bin の振り分け・起動と回収は #3198（下の「実装（#3198）」）、fd 2 本の送出は #1939、pasta の起動は #1938・#1940 の担当で、本実装には含まない。実機の確認は `netns_holder_userns`（CI の `platform-ci` ubuntu）で行う
- **実装（#3198）**: `crates/supervisor/src/netns_holder.rs`（Linux のみ）と `src/main.rs` の振り分け。bin の main は第 1 引数が `netns-holder` なら `run_main`（継承 fd の整理・結果チャネル・`set_dumpable(false)`）より前に `run_netns_holder_main` へ振り分ける（特権ランチャーは `StartArgs::parse` を通った argv だけを転送するため入口にならない）。`spawn_netns_holder(fds, deadline)` は期限の確認 → 前提の確認（main スレッドか・`CapPrm` / `CapEff` / `CapAmb` が 0 か。満たさなければ `FailedPrecondition`）→ `/proc/self/exe`（`arg0` 固定・`env_clear`・`current_dir("/")`・stdout は null・stderr は pipe・`pre_exec` なし）の spawn → fd の送出 → READY の待ち（`min(READY_TIMEOUT, 残り)`）の順で、READY までの失敗は SIGKILL と回収をして返す。`NetnsHolderProcess::stop` は STOP → `STOP_GRACE` → SIGKILL → `REAP_TIMEOUT`、`Drop` は EOF と SIGKILL・回収を試み、回収できなければ zombie のまま残す（単一スレッドの区間でスレッドを作らないため）。生存確認は未回収の `Child` の `try_wait`（pidfd は #1940。unsafe を足さない）。構造化ログ（`netns_holder_ready` / `netns_holder_exit`）は材料（`HolderReady`・`HolderStopOutcome`・stderr のエスケープ済み 4 KiB 以下）を返すだけで、出力は呼び出し側（#1940）が単一スレッドの区間を抜けた後に行う。launch・monitor からの呼び出し（起動途中の失敗で逆順に止める・PID 1 の回収後に pasta → holder の順で止める・restart で作り直す・途中死の検知）は #1940、fd 2 本の送出は #1939 の担当で、本実装には含まない。自動運転で安全側に選んだ細部（承認は未取得）: main スレッドでなければ拒否する／spawn の前に capability が 0 であることを確かめる／`arg0` を固定し `current_dir("/")` にする／stderr は回収した後だけ読み上限を 4 KiB にする／`Drop` で回収できなければ zombie を残す／`ReapTimedOut` のとき未回収の `Child` を呼び出し側へ戻す。試験は `tests/netns_holder_launch.rs`（既定の集合）と `tests/netns_holder_launch_userns.rs`（実機前提・メモリを継承しないことの陽性対照つき走査・中間 supervisor の SIGKILL で holder が消えること）
- **同期点の実装（#3206）**: 12.3 が使う exec 直前の同期点は core の `crates/core/src/exec/netns_sync.rs` に入った（Loopback と Host は fd 1 本。受信側は期待する fd の本数を引数に取る）。pasta 構成の fd 2 本（netns と user namespace）は #1939 が本数 2 を渡して使う。詳細は `network-wiring.md` D8 の「実装（#3206）」。
- **実装（#1939）**: pasta 構成向けの同期点の拡張を core に入れた。自動運転で安全側に選んだ細部で、オーナーの承認は未取得である。
  - モード: `LaunchNetworkMode::Attachable`（`#[non_exhaustive]` へ足した変種）。D7 の行は `Loopback` と同じ（エントリ無し・path 無しは `NewLoopback`、path 付き・重複は `InvalidArgument`）。`EffectiveNetwork` には変種を足さない
  - 同期の形: 位置とワイヤーは #3206 のまま（開始ゲートの後・`child_main` の前。`SOCK_SEQPACKET`・本文 `N` / `A`）。子は `/proc/thread-self/ns/net` と `/proc/thread-self/ns/user` を**この順で** 1 通の `SCM_RIGHTS` で渡す。C は位置ごとの種別（`net:` / `user:`）を検証し、netns が基準と異なること・user namespace が C 自身と異なることを確かめ、フックを呼び、Ok かつ期限内のときだけ ACK を送る。失敗はどれも PID 1 を kill して回収する
  - フック: `oci_runtime::NetnsAttachHook`（`attach(AttachableNamespaces, deadline)`）。`AttachableNamespaces::into_parts` は `(user, net)` の順で、`NetnsHolderFds::new(user, net)` に合わせる。注入は `ProductionLauncherBuilder::netns_attach_hook`。core は pasta を知らない（`core → net` の依存を足さない）。holder の保持と pasta の起動、`Ok` の後に launch が失敗したときの巻き戻しは #1940 が担う
  - `build` の検査（fork の前）: `Attachable` でフック無し・フックがあるのに `Attachable` でない（どちらも `InvalidArgument`）・`Attachable` が rootless 以外の権限モデル（`Unimplemented`）。launch にも多重防御（`Internal`）がある
  - 段と監査: 段 `netns_attach`（`IsolationStage::NetnsAttach`）を足した。launcher の固定文言は `container launch failed in the NetnsAttach stage`（Timeout は従来の文言）。形式違反・user namespace が基準と同じ場合は既存の理由（`netns_handoff_invalid`・`netns_identity_mismatch`）で記録する。フックの失敗・期限切れは系のエラーで記録しない（pasta の失敗の分類と記録は #1940〔12.9〕）
  - user namespace と netns の所有関係は core では照合しない（`NS_GET_USERNS` の ioctl は新しい `unsafe`）。holder が `setns(user)` → `setns(net)` の順で参加し、組が違えば `EPERM` / `EINVAL` で fail-closed になる
  - 試験: 単体（`netns_sync`・`launch_intermediate`・`launcher`・`network_mode`）と、実機前提の `production_launcher` のシナリオ `attachable`（成功行 `(scenario=attachable)` / `(scenario=attachable-subordinate)`）
- **実装（#1940）**: `crates/supervisor/src/pasta_attach.rs`（Linux のみ。試験は `pasta_attach/tests.rs`）。(1) start の手順 7（`ProductionStartDeps::build_launcher`）が、起動オプションの network がユーザー定義名（`LaunchNetworkMode::Attachable`）のときだけ `PastaWiring` を作り、`PastaAttachHook`（`NetnsAttachHook`）を `ProductionLauncherBuilder::netns_attach_hook` へ渡し、できた launcher を `PastaAttachingLauncher` で包む。(2) フックは holder の起動と READY → pasta の起動と準備完了の待ち（`min(5 秒, 残り)`）の順で行い、途中の失敗は pasta → `@pasta/<id>` → holder の逆順で止めてから `Err` を返す（スレッドは作らず、ログは `PastaLogBuffer` に積んで start の報告の後に `StartDeps::flush_deferred_logs` が出す）。(3) 起動時の再検証は手順 2c の作業スレッドで `reverify_recorded_pasta` を呼び（`pasta_verify` を記録）、通った `PastaBinary` だけを `ContainerOptions` に持たせる。手順 4 は、ユーザー定義名なのに再検証済みの pasta が無ければ `FailedPrecondition`（`pasta path is not configured`）、pasta の記録があるのにユーザー定義名でなければ `InvalidArgument` で cgroup に触れる前に拒否する。(4) launch が `Ok` なら起動済みの組が `PastaGuardedProcess` に載る。`wait` が PID 1 の回収を返したら pasta → holder の順で停止し、`@pasta/<id>` を消す（`terminate`・drop でも 1 回だけ）。(5) 生存確認は pidfd を採らず、`wait` の周期ごとに未回収の `Child` の `try_wait` を呼ぶ（新しい unsafe を足さない。pasta の stderr を読む責務も兼ねる）。(6) 途中死は分離を緩めずコンテナへ SIGTERM を 1 回送り、10 秒（`TERM_GRACE`）を超えたら SIGKILL する。(7) CLI の delete は `@pasta/<id>` の残骸だけを消す（`remove_pasta_leftovers`。記録の pid でのプロセス操作はしない）。**残余**: restart の再 launch は同じ launcher とフックを通る形にしたが、本番 launcher の再 launch は #2043 まで拒否されるため restart での成立は未確認。CLI が `network <名前>`・`pasta` を FCOPT1 に書く入口と start での D10 の再照合は #3329、SEC-4 の監査への記録は #3330、実機の通し確認（`pgrep` が空・cgroup・netns-quit）と D5 のサイズは #3331。自動運転で安全側に選んだ細部（承認は未取得）: 遅延ログの上限 64 行／途中死の猶予 10 秒／二重の attach の拒否／フックが走らなかった launch の `Ok` はプロセスを止めて拒否
- **実装で決めた細部（自動運転で安全側に選んだ。承認は未取得）**: (1) 親の確認は argv が固定で期待値を受けられないため、stdin が `SOCK_SEQPACKET` であることと、`SO_PEERCRED` の pid（socketpair の作成者）が `getppid` と一致し 1 でないことで行う。(2) fd の待ちに期限を付ける（2 秒。親が送る前に壊れても残らないため。スレッドは使わず `poll`）。(3) 参加の後、capability を落とし `NO_NEW_PRIVS` を立てた後に PDEATHSIG を設定し直し、PDEATHSIG が SIGKILL のままであることと dumpable が 1 のままであることを READY の前に自己確認する（崩れたら `FailedPrecondition` で止まる。回避しない）。(4) 参加前後の失敗は固定の英文と code だけの stderr 1 行と、ワイヤー上の `Error` フレームで返す。(5) nsfs であることの `fstatfs` 確認は足さず、型の最終照合は `setns` の `EINVAL` と参加後の (dev, ino) 照合に任せる。(6) 受信の制御バッファは fd ちょうど 2 本分で、3 本目以降はカーネルが閉じて `MSG_CTRUNC` になり拒否する。(7) READY の後の待ちは期限なし（終わる経路は PDEATHSIG・EOF・STOP）。READY の後に fd や STOP 以外を受けたら fail-closed で終了する

### 12.3 #1870 との分担

- **決定**: rootful の netns の渡し方（D12）と Host・Loopback の照合（D8）は変えない。pasta 構成は rootless のユーザー定義名だけに限り、D8 の同期点を「fd を 2 本」に拡張して使う。config.json との突き合わせは D7 の Loopback の行と同じ規則にする（path の無い network エントリは受け、path 付きは `InvalidArgument`）。#1870 は close 済みなので、記録は network-wiring.md の D4・D7・D8・D15 と残余の参照の行で行う
- **理由**: D8 が「pasta の同期点〔#1939〕と共有する」と定めており、同期点を 2 つ作らない
- **却下した案**: pasta 専用の別の同期点を作る

### 12.4 pasta の場所の入口（フラグの名前・作成時の記録・起動時の再検証）

- **決定**: グローバルフラグを 2 つ足す: `--pasta-path <絶対パス>` と `--pasta-path-search`
  - `--root`・`--plugin-path-search` と順不同で各 1 回まで。両方の指定は使い方エラー
  - 使うのはコンテナを作る subcommand（`create`。stack の up が入ったらそれも）で、rootless のインストールかつユーザー定義名の `--network` のときだけ。それ以外で指定したら `InvalidArgument`（効かない指定を黙って受けない）
  - rootless のユーザー定義名でどちらも無い場合は `FailedPrecondition`（固定文言 `pasta path is not configured`）。既定のパスは持たない（12.15）
  - 作成時: CLI が #1936 の検証関数で解決・検証し、FCOPT1（D4）に kind `pasta` を 1 レコード書く（上限 4 KiB）。値は、絶対パス（UTF-8・制御文字なし・3072 バイト以下。識別情報・版の日付・符号化の枠を 4 KiB のレコード内に収める余裕を確保するための上限で、超えるパスは作成時に解決段階で `invalid-argument` 相当の構造化エラーで拒否し、切り詰めない）、fd の `fstat` から得る識別（dev・ino・size・mtime・ctime〔ns〕・uid・mode）、解釈した版の日付
  - 起動時: supervisor が文書を復号するたびに未信頼の入力として再検証する。パスを同じ規則で辿り直し、得た正規パスと識別（dev・ino・size・mtime・ctime・uid・mode）を **`--version` の実行より前に**記録と照合する（不一致なら子を実行せず固定の変更エラーで返し、版のエラーに埋もれさせない）。一致したときだけ `--version` を実行し直して版を照合する。不一致は `FailedPrecondition` とし、監査ログ（SEC-4）に「作成から起動までの間にバイナリが替わった」を記録する
  - 実行は検証したパスで行い、`argv[0]` は常に `pasta` に固定する（12.7）
  - 版の固定は 12.12
- **理由**: 特権ランチャーの `sanitize_env` は環境を許可リストで作り直し、supervisor は契約の値を環境から読まず、argv は `StartArgs::parse` で固定されている。どちらも変えずに済む経路は既存の文書 FCOPT1 だけである（[container-options-delivery.md](container-options-delivery.md) の却下理由と同じ）。`--plugin-path-search` とは信頼の対象が違うので opt-in は別のフラグにする
- **実装（#3199）**: 2 フラグの解析は `crates/cli/src/commands/args.rs`、`create` での判定・解決・検証は `commands/create_pasta.rs`（判定表は同ファイルの doc）、`create` 以外への指定の拒否は `commands.rs`。FCOPT1 の kind `pasta` は `crates/supervisor/src/container_options/document.rs`、本文の符号化・復号（`<YYYYMMDD> <dev> <ino> <size> <mtime_sec> <mtime_nsec> <ctime_sec> <ctime_nsec> <uid> <mode(8 進)>\n<絶対パス>`・本文 4096 バイト以下）と `reverify` は `crates/net/src/pasta/record.rs`。復号は本文の形だけを検証し（副作用なし）、バイナリの辿り直しと識別の照合は `reverify_recorded_pasta`（`container_options/pasta.rs`）が行う。**残余**: (1) `--network` のユーザー定義名は #1873 まで `UNIMPLEMENTED` で拒否されるため、本番の `create` が `pasta` を書くのはその後。(2) start 経路からの `reverify_recorded_pasta` の呼び出しと SEC-4 の監査の記録（作成時の `PermissionDenied`・起動時の識別の不一致）は #1940。作成時の記録先は状態ストアを開いた後にしか作れず D2（状態ルートを作る前の拒否）と両立せず、core の `AuditLayer` に pasta の語彙も無いため、本実装は分類（`PastaReverifyError::tamper_suspected`）だけを返す。(3) pasta の解決・検証の子（`--version`）が、`UNIMPLEMENTED` の拒否より前に 1 回起動される（`FailedPrecondition` と検証失敗の分類を作成前に返すため）。
- **却下した案**: 環境変数・設定ファイル（オーナー決定で不採用）、`--plugin-path-search` を pasta にも効かせる（plugin と pasta の opt-in が結合する）、supervisor の argv に足す（`MAX_ARGS` と契約が変わる）、core の `StateRecord` に同梱する（plugin 境界の型が変わる）

### 12.5 opt-in の `PATH` 探索

- **決定**: `--pasta-path-search` のときだけ、CLI 自身の `PATH` を先頭から見て、名前 `pasta` の最初の候補を採る。空の要素と相対の要素は飛ばす。最初の候補が検証に落ちたら、後ろの候補へ進まずその失敗を返す。採ったパスは警告として 1 行 stderr に出す（`PathSearchWarning` と同じ流儀）。記録以降は 12.4 と同じ
  - 検証の基準は PLUG-11 と同じ: 全祖先とバイナリが root または実効 UID の所有で `mode & 0o022 == 0`（sticky でも例外にしない）。通常ファイルで実行可能。symlink は解決先まで検証し、判定は fd の `fstat` で行う。細部は #1936
- **却下した案**: 失敗した候補を飛ばして次へ進む（どのバイナリが選ばれたか分かりにくい）、supervisor 側で探索する（supervisor は環境を読まない）

### 12.6 待ち受けアドレスとポート公開の入口

- **決定**: 公開は IPv4 だけ。アドレスを省いたら `127.0.0.1` へ解決する。明示したアドレスは `0.0.0.0` を含めて受け、IPv6 のリテラルは作成前に `InvalidArgument`。ポート 0 と範囲指定は v1 では受けない。件数の上限は `MAX_PORT_PUBLISHES`
  - `--freebind` は付けない。ホストに無いアドレスを明示すると pasta の起動が失敗し、準備完了前に終われば `FailedPrecondition`（12.9）。pasta が警告だけで続ける場合の扱いは未確認（12.11）
  - CLI の入口は `create` の `-p` / `--publish`（`[<ipv4>:]<host>:<container>[/tcp|udp]`）で、FCOPT1 に kind `publish` を足す（1 件 64 バイト以下）。rootful の `-p` は D13 の判断が出てから扱い、v1 では rootful で指定すると `UNIMPLEMENTED`
  - 利用者向けの doc に、rootful の `PortPublish`（DNAT。loopback と未指定を拒否）との差を書く。pasta はホスト側の socket を bind するので loopback も `0.0.0.0` も成り立つ
- **却下した案**: 省略時に全アドレスで開く（オーナー決定）、`PortPublish` を流用する（loopback を表せない）

### 12.7 pasta の argv（常に固定で渡すもの）

- **決定**: 引数は OS 文字列の配列で組み、シェルを介さない（#1937）。

```text
argv[0]=pasta  -f  --quiet  -P <@pasta/<id>/pid の絶対パス>  --config-net  -4  -I eth0
  --map-host-loopback none  --map-guest-addr none  --dns-forward 169.254.1.1
  -t <addr>/<host>:<ctr>[,...] | -t none   -u ... | -u none   -T none  -U none   <holder の PID>
```

| 引数 | 理由 |
| ---- | ---- |
| `-f` | supervisor の直接の子のまま pidfd で監視・回収するため（背景化すると別 PID になる）。PID ファイルも初期化の完了後に書かれる |
| `-P` | 準備完了の合図に使う（12.8） |
| `--config-net` | アドレス・経路・up を pasta に設定させる（#340 で確かめた形） |
| `-4` | IPv6 は v1 で受けない。外向きの IPv6 も同時に閉じ、確かめていない経路を開かない |
| `-I eth0` | rootful の peer 名（#3061）と揃える |
| `--map-host-loopback none` | 既定のままだと gateway がホストの 127.0.0.1 へ写り、コンテナからホストの loopback 専用のサービスへ届く。閉じる側にする |
| `--map-guest-addr none` | 既定はホストの global アドレスへの写像に従う。ホストのサービスへの到達は v1 では約束しない |
| `--dns-forward 169.254.1.1` | コンテナの nameserver をこのアドレスにする（D9 の `@container-etc` の生成に pasta 構成の行を足す）。`--dns` 指定があればそちらを使う（loopback は D1 の検証で拒否） |
| `-T none -U none`、0 件時の `-t none -u none` | 既定の `auto` を止める（7 章） |
| `--host-lo-to-ns-lo` は付けない | 付けると、ホストの loopback から来た接続がコンテナ内で loopback 発に見え、netns 内の loopback 専用のサービスがホストへ漏れる（man の記述） |

- `argv[0]` は `--pasta-path` の basename に関係なく `pasta` にする（pasta は実行名でモードを決めうる。`/usr/bin/pasta` と `/usr/bin/passt` はリンク数 2 の同一実体）
- 公開指定は `crates/net` の `pasta::port_forward`（#1937）が検証して組む。待ち受けアドレスごとに `-t <addr>/<h>:<c>[,...]` を 1 つにまとめ、アドレスが違えば `-t` を複数並べる（passt の `conf_ports` は SPEC を累積し、`/` の前のアドレスはその spec 全体にかかる。tag `2026_01_20.386b5f5` の挙動の読み取り）。公開の無いプロトコルは `none`
- **却下した案**: アドレスを省いた `-t`（全アドレスで開く）、既定の `--map-host-loopback` のまま、IPv6 を有効のまま

### 12.8 PID ファイル・準備完了・置き場所

- **決定**: 置き場所は `<state_root>/@pasta/<container-id>/`（0700・所有者は euid）。supervisor が状態ルートの fd から `mkdirat` と `O_NOFOLLOW` で作る。既存のエントリが `pid` という名前の通常ファイル（所有者 euid・nlink 1）なら消し、それ以外なら `FailedPrecondition`。pasta へは `pid` の絶対パスを渡す
  - 準備完了は、`pid` が現れ、32 バイト以下の 10 進で spawn した子の PID と一致することで判定し、並行して pidfd で子の生存も見る。期限 `ready_timeout` は既定 5 秒・上限 10 秒で、0 は `InvalidArgument`
  - stop・delete でディレクトリを消し、CLI の delete も残骸を消す（`@container-options` と同じ扱い）
  - 既定の rootless の状態ルートは `/run/user/<uid>/` の下にあり AppArmor が許す。`--root` を許可外（`/tmp`・`$HOME`・`/run/user/<uid>` 以外）に置き、プロファイルが enforce のときは、pasta が書けず準備完了前に終わる（`FailedPrecondition`）。黙って別の場所へ逃がさない（fail-closed）。注意は #1941 の手順と setup の doc に書く
- **実装（#1938。`crates/net/src/pasta/process.rs`・`run_dir.rs`・`sys/pasta.rs`。承認は未取得の自動運転での判断）**:
  - 置き場所は `PastaRunDir::prepare(state_root_fd, id)`。パス文字列を受けず、状態ルートの fd から `/proc/thread-self/fd/N` と `openat(O_NOFOLLOW)` で `@pasta`・`<id>` を作って検査する（種別・所有者 euid・`mode & 0o077 == 0`。基準外は直さず `FailedPrecondition`）。既存の `pid` は通常ファイル・所有者 euid・nlink 1 のときだけ消す。CLI の delete は `remove_pasta_run_dir`（記録の pid でのプロセス操作はしない）
  - 準備完了は `pid` を `O_NOFOLLOW | O_NONBLOCK` で開き、通常ファイル・所有者 euid・nlink 1 を確かめてから 33 バイトまで読み、10 進（末尾の改行 1 個は可）が spawn した子の PID と**完全一致**したときに限る。空・書き込み途中・別の値は「まだ」、10 進以外・32 バイト超は `FailedPrecondition`。並行して `try_wait` で子の生存を見る（pidfd ではなく未回収の `Child`。pid の再利用に影響されない）
  - argv は `pasta_argv` の固定の並び（`-f --quiet -P <pid> --config-net -4 -I eth0 --map-host-loopback none --map-guest-addr none --dns-forward 169.254.1.1 <#1937 の引数> <対象 PID>`）。`--host-lo-to-ns-lo` は付けない。`PastaTarget` は 0・1・自分自身を拒否する
  - 起動は env 空・cwd `/`・stdin / stdout null・stderr pipe。pre_exec は `sys::pasta::set_pdeathsig_on_spawn`（`PR_SET_PDEATHSIG=SIGKILL` と `getppid` の照合。不一致は `FailedPrecondition`）
  - stderr は先頭 4 KiB（エスケープ後）だけ保持し以降は読み捨てる。準備完了の待ちの間と `is_alive` / `stop*` のたびに読めるだけ読む（待たない）。準備完了後の定期呼び出しは #1940 の監視の責務（長時間呼ばれないと 64 KiB の pipe が満ちて pasta の書き込みが止まりうる）
  - スレッドを作らない（launch の手順 8 が単一スレッドの区間のため。issue の「回収スレッドへ移す」から変更）。期限切れの `stop_checked` は `Timeout` を返して子を手元に残し、`stop` は未回収のハンドルをエラーに入れて返す。`Drop` は SIGKILL と 1 秒の回収待ちで、回収できなければ zombie のまま残す（zombie の間は pid が再利用されない）。スレッドへ移す `detach_reaper` は単一スレッドの区間の外から呼ぶ明示の opt-in（生成失敗は子を `unreaped` に戻して構造化エラーで返し、回収は 30 秒の期限つきで超えたらハンドルを手放す）
  - 計装は `NetOpKind::PastaStart` / `PastaStop`（`spawn_pasta_with_recorder`・`stop_with_recorder`）。構造化ログの `pasta_ready` / `pasta_exit` と SEC-4 の監査は、`PastaReady` / `PastaStopOutcome` / `PastaDiagnostics` を材料に supervisor（#1940）が書く
- **却下した案**: `/tmp` の固定の場所（名前の衝突と symlink を仕込まれる余地）、pipe を `-P /proc/self/fd/N` で渡す（fd は閉じられる）、stderr の文言で判定する（契約ではない）

### 12.9 失敗の分類（ERR-1・NetErrorCode）・監査・期限

| 事象 | code | 監査（SEC-4） |
| ---- | ---- | ---- |
| 相対パス・両フラグ・効かない指定・IPv6・ポート 0・範囲指定 | InvalidArgument | なし |
| パスの要素が無い | NotFound | なし |
| 所有者・権限・symlink 先が基準外 | PermissionDenied | 記録する（改ざんの可能性） |
| 通常ファイルでない・実行できない・フラグが無い | FailedPrecondition | なし |
| `--version` の期限超過 | Timeout | なし |
| `--version` の非 0 終了・解釈できない・最小版未満 | FailedPrecondition | なし |
| 作成時と起動時の識別の不一致 | FailedPrecondition | 記録する |
| supervisor が capability を持つ（rootless でない構成での誤用） | FailedPrecondition | なし |
| holder の起動失敗・READY の不正 | Internal / FailedPrecondition | なし |
| holder の READY 待ちの期限超過 | Timeout | なし |
| holder の setns の EPERM | PermissionDenied | なし |
| pasta の exec 失敗 | Internal（EACCES は PermissionDenied） | なし |
| 準備完了の期限超過 | Timeout | なし |
| 準備完了前の終了 | FailedPrecondition | なし |
| 実行中の pasta・holder の死 | コンテナを止める（12.10） | なし（構造化ログ） |

- message は固定の英文にし、パス・pasta の出力・利用者の入力値を含めない。pasta の stderr は pipe で受け、4 KiB を上限に非印字文字をエスケープして supervisor のログ（`@supervisor-logs`・0600）にだけ書く
- 構造化ログ（REPAIR-4）の event は `pasta_verify`・`netns_holder_ready`・`pasta_ready`・`pasta_exit`・`netns_holder_exit`。項目は container id・code・所要 ms・版の日付・終了 status / signal・公開の件数
- 期限（REPAIR-5。D15 の表に参照を足す）:

| 操作 | 期限 |
| ---- | ---- |
| `--version` | 2 秒 |
| holder の READY | 2 秒 |
| 準備完了（`ready_timeout`） | 5 秒（上限 10 秒） |
| pasta の停止 | SIGTERM → 2 秒 → SIGKILL → 回収 1 秒 |
| holder の停止 | STOP / EOF → 1 秒 → SIGKILL → 回収 1 秒 |

- 起動側の合計は既存の `result_deadline` と `launch_step_budget` に収め、spawn の前に残りの予算を確かめる
- **却下した案**: `Unavailable` などの新しい code を足す（`NetErrorCode` を変えない）

### 12.10 寿命と回収

| 場面 | 何が起きるか |
| ---- | ---- |
| 起動の途中の失敗 | 起動したものを逆順に止める（pasta を kill・回収 → holder を kill・回収 → 同期点の子を kill）。コンテナを `Running` にしない。netns はプロセスと一緒に消える（pin しない） |
| コンテナの終了・stop | PID 1 を回収した後、pasta を先に止める（ホストのポートを持つため）。続けて holder を止め、`@pasta/<id>` を消す |
| restart | 新しい netns に、同じ関数で holder と pasta を作り直す（起動の経路を 1 つに保つ） |
| delete | stop 済みが前提。ディレクトリの残骸だけを消し、記録の pid でのプロセスの探索・kill はしない（pid の再利用を避ける） |
| supervisor の異常終了 | (1) pasta は pre_exec で `PR_SET_PDEATHSIG=SIGKILL` を設定し `getppid` で確かめる。(2) holder は自分で設定した PDEATHSIG と socket の EOF で終わる。(3) 3 段目として pasta の netns-quit（holder が消えると約 1 秒）が効く。PDEATHSIG は spawn したスレッドの終了でも届くので、**pasta は supervisor と同じ寿命のスレッド（入口の main スレッド）から spawn する**。これは #1940 の受け入れ条件と試験に入れる。孤児になったコンテナは稼働を続けるが（SUP-5）、ネットワークの転送は失われる（12.13 で報告） |
| pasta・holder の途中死 | supervisor が pidfd で検出して構造化ログに残し、コンテナを stop と同じ手順で止めて終了理由を記録する。その後は restart policy に従う。分離は緩めない |

- 配置: pasta と holder は launch の後に起動するので supervisor の退避リーフを継承する。companion には登録しない。コンテナの cgroup と委譲親のどちらにも入らないことを #1940 で確かめる
- unsafe: pre_exec と holder の `setns`・capset・prctl は `crates/net/src/sys.rs` の薄いラッパーに置く。事前承認の範囲に収まるかは該当 PR で security-auditor が判断し、収まらなければユーザーの承認を求める。net は libc 照合が入っている crate なので、定数・宣言の照合も同じ PR で足す
- **却下した案**: pasta の netns-quit だけに頼る（issue が禁じる）、pasta だけを再接続する（起動の経路が 2 つになる）、コンテナを止めずにネットワーク無しで続ける（公開ポートが黙って消える）、pasta を holder の子にする（holder に fork と exec の unsafe が増え、supervisor から監視できない）、pasta を companion にする（コンテナの cgroup の上限と OOM の巻き添え）

### 12.11 実機で確かめていない点と担当 issue

| 項目 | 担当 |
| ---- | ---- |
| AppArmor の制限が `1` のままで、既存の user namespace に PID の形で付けられるか | #1941（試験の用意）・#341（人間の実行） |
| 対象を holder（exec し直して setns したプロセス）にした PID の形で動くか | #1941 |
| IPv6 | v1 は `-4` で閉じる。有効にするのは将来 |
| `--netns <パス>` | 設計で使わないので確認しない |
| `-T none -U none` と `--dns-forward 169.254.1.1` で名前解決できるか | #1941 |
| Ubuntu 26.04 のプロファイルの exec 規則 | PID の形では pasta がコマンドを起動しないので該当しない |
| `-f` のときの PID ファイルの書き込みの時点 | #1938 で man を確認済み: `-P` は「初期化が終わった後、バックグラウンド化の前に自分の PID を書く」、`-f` は「バックグラウンド化せず PID が変わらない」（pasta 0.0~git20260120）。PID ファイルを引数の解析時に空で作るかは man に記述が無く未確認のため、準備完了は「中身が子の PID と完全一致」で判定し（空・部分読みは「まだ」）、古い `pid` を spawn の前に消す。実機での書き込み時点の確認は #1941 |
| `argv[0]` とモード（名前を変えたファイル・リンク数 2） | #1936 は検証の入口の実装まで（`--version` は `argv[0]` を常に `pasta` にして実行する）。上流の一次情報での確認は未実施のため #1941 に残す |
| 他のディストリビューション・上流の版の表記 | #1936 では一次情報を確かめていないため、Debian / Ubuntu の形式のみを受け、他は拒否する（12.12）。足すときは `pasta::version` に確かめた形を足す |
| 明示の `-t` の bind に失敗したとき pasta が終わるか、警告だけで続けるか | #1941。続ける場合は準備完了後に待ち受けを確かめる後続 issue を起こす |
| `--map-host-loopback none` でホストの loopback に届かないこと | #1941 |
| PDEATHSIG と、holder が消えた後の netns-quit | #1941 |
| 状態ルートの下の PID ファイルを AppArmor が許すか | #1941 |
| 同じプロトコルの `-t` を複数回渡したとき、規則が累積して bind されるか | #1941 |
| `-u none` のとき、TCP と同じ番号の UDP が開かないこと | #1941 |

### 12.12 版の固定

- **決定**: `--version` を `env_clear`・stdin null・stdout の読み取り 4 KiB 上限・期限 2 秒で実行する。exit 0 で、1 行目が「pasta」と空白で始まる 128 バイト以下の ASCII であること
  - 受ける形式: Debian / Ubuntu（実機で確認済み）の `0.0~git<YYYYMMDD>.<hex 7〜40>-<rev>`。上流の tag 形式 `YYYY_MM_DD.<hex>`（任意で `-N-g<hex>`）は、#1936 が一次情報で確かめた場合に限り足す。それ以外（Fedora・Arch・Alpine・`unknown version` を含む）は確かめるまで拒否する
  - 比較は日付だけで行う（実在する暦日であること）。最小版は `20260120`（#340 で実機確認した版）
- **理由**: 上流の `VERSION` は `git describe` の結果で失敗時は `unknown version` になり、ディストリビューションは独自の文字列を渡す。形式を絞り、確かめた形だけを受ける方が fail-closed に合う
- **却下した案**: 完全一致（ディストリビューションの更新のたびに壊れる）、許可リスト（保守の手間）、semver として解釈（pasta の版は semver ではない）

- **実装（#1936）**: `crates/net/src/pasta/binary.rs`（`PastaBinary`・`verify_pasta_binary`・`search_pasta_in_path`）と `pasta/version.rs`（版の解釈）。上流の tag 形式は一次情報で確かめていないため足しておらず、拒否のまま（本節の決定が認める扱い）。rev の文字種は `[0-9A-Za-z+.~]` の 1〜32 文字、epoch（`1:`）は拒否する
- **実装で決めた細部（自動運転で安全側に選んだ。承認は未取得）**: (1) exec には実体の正規パス（`PastaBinary::path`）を使い、FCOPT1 にもそれを記録する。(2) setuid / setgid のバイナリは拒否する。(3) 実行可能性は fstat だけで判定し、グループ経由でだけ実行できるものは拒否する。(4) 祖先の symlink は拒否する（merged-usr の `/bin/pasta` は `/usr/bin/pasta` を指定する）。(5) 版の確認の後に識別を取り直し、一致しなければ差し替えとして拒否する。(6) `pasta` モジュールは全 OS で公開し、Linux 以外は `Unimplemented`

### 12.13 spec 側への報告事項（本リポで決めない）

1. SUP-5 の「孤児化で失われるもの」に、rootless の pasta の転送を足すこと
2. CLI の `-p` / `--publish`（#1870 でも報告済み。pasta の形式を添える）
3. 新しいグローバルフラグ `--pasta-path` / `--pasta-path-search`（CLI-1・PLUG-11 に無い）
4. NET-9 の補足: ホストの loopback へは届かないこと、v1 は外向きも IPv4 だけであること、DNS は 169.254.1.1 経由であること
5. 最小版の値 `20260120`

### 12.14 後続の実装単位

既存の #1936〜#1941 に収まらない単位を次に起票する（番号は #1935 に記録する）。

| 単位 | crate | 依存 |
| ---- | ----- | ---- |
| netns holder（`run_netns_holder_main`・fd の受信・setns・capset・READY / STOP・PDEATHSIG） | net | #1936 |
| bin の `netns-holder` の振り分けと holder の起動・回収 | supervisor | 上の holder・#3065 |
| `--pasta-path` / `--pasta-path-search` と作成時の検証・FCOPT1 の `pasta` の書き込み | cli | #1936・#3065 |
| `-p` / `--publish` と FCOPT1 の `publish`（rootless の pasta のみ） | cli | #1937・#3065。実装は #3200。CLI が `publish` を文書へ書くのは `network`（ユーザー定義名）を書く #3329 の後（それまでは検証済みの `-p` も `UNIMPLEMENTED`） |

### 12.15 オーナー確認事項（実装は止めない）

- 既定のパス（`/usr/bin/pasta` 等）を持つか。現状は持たない
- ポート公開の細部（#1937。自動運転で安全側に決めた）: 同じプロトコルでアドレスが違う公開は `-t` を複数並べる / 明示アドレスのうち bind できないもの（`0.0.0.0` 以外の `0.0.0.0/8`・multicast・予約）は拒否 / `0.0.0.0` と個別アドレスの同じ（プロトコル・ホストのポート）は重なりとして拒否 / プロトコル省略は TCP（`/TCP` の大文字は不可）/ 1 件 64 バイトの上限を解析の入口にも置く / ポートの名前（`http` 等）は受けない
- `-p` の組の細部（#3200。自動運転で安全側に決めた）: `-p` に `--network` が無い、または `none` / `host` / `container:` が付くときは、権限モデルによらず `INVALID_ARGUMENT`（12.4 の `--pasta-path` と同じく、効かない指定を黙って受けない）。この検査は rootful の `UNIMPLEMENTED` より前に置くため、rootful で `-p` と `none` を指定すると `UNIMPLEMENTED` ではなく `INVALID_ARGUMENT` になる。利用者向けの説明は [port-publish.md](../api/port-publish.md)
- 12.2 の holder 方式、12.10 の「途中死でコンテナを止める」、12.7 の固定の argv は自動運転で決めた。承認は未取得
