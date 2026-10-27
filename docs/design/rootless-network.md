# rootless ネットワークの外部ヘルパー選択肢（判断記録）

非特権 user namespace（rootless）で host / none 以外のネットワークとポート公開を成立させる方式の選択肢を整理し、その判断を記録する（NET-9）。

> **位置づけ**: 本書は 2026-10-12 に #340 で採用を決定した判断記録である。決定の要点は下の「決定」のとおり。NET-9 は 2026-10-12 に spec 上も「確定」になった（Fandhe-AI/fandhe-container-spec#18）。

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

- 設計の選択 4 点（上の「決定」）は 2026-10-12 に決まった。起動主体は supervisor に決まった。起動の時点・同期・失敗の分類・寿命・フラグの名前・最小版の値などの残りの設計は #1935 で確定する
- 決定した構成: pasta を利用者が導入し、fandhe-container は `crates/net` から別プロセスとして exec する。同梱・リンクはしない。ポート公開の bind の既定は loopback
- 実装で守る点:
  - pasta の既定（`auto`）と、アドレスを省いた明示の指定は、ホストの全アドレスでポートを開く。loopback を既定にするには待ち受けアドレスを必ず明示する
  - `-t none` と明示のポートは併用できない。明示の `-t` に `-u none -T none -U none` を足す
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
- #1935 の設計の確定で 7 章の内容が変わった場合は追従する
- pasta を同梱・再配布することにした場合は、ライセンスの判断をやり直す
