# subuid / subgid の所有者名の解決（NSS と /etc/passwd の食い違い）

- 対象: #2390（SEC-5・CORE-6）。実装は `crates/supervisor/src/user_db.rs`・`id_model.rs`、CLI の `doctor`（`id_mapping_check.rs`）
- 状態: 実装済みの方針の記録。オーナーの承認を得たものではない（自動運転で、安全側に倒して決めた）

## 課題

PR #2367（#2243）の `start` は所有者名を `/etc/passwd` だけから得ていた。LDAP・sssd のように `/etc/passwd` に載らないユーザーは名前が得られず、`/etc/subuid` に名前で書かれた自分の行（例: `ldapuser:100000:65536`）が「行が無い」と判定されていた。結果は、黙って 1 対 1 写像へ落ちるか、片側だけ一致して `FailedPrecondition` になるかのどちらかだった。

## 基準: `newuidmap` の挙動（shadow 4.13 の原文で確認）

- 呼び出し元の名前は `libmisc/myname.c` の `get_my_pwent()`。`getlogin()` か `getpwuid(getuid())` で、どちらも NSS 経由
- `lib/subordinateio.c` の `find_range()` は 2 段で照合する。1 段目は第 1 欄が呼び出し元の名前と完全一致する行。2 段目は `getpwnam(owner)->pw_uid` を求め、第 1 欄が uid の 10 進文字列の行、または第 1 欄の名前を `getpwnam` で引いた uid が一致する行（同じ uid の別名）を受理する
- `/etc/subgid` の数値の行も、gid ではなく **uid** で照合する（`newgidmap` も同じ `find_range`）
- 所有者名の文字種・長さの制限は shadow 側に無い
- `/etc/nsswitch.conf` に `subid:` があると、ファイルを読まずに libsubid へ問い合わせる場合がある。判定は `lib/nss.c` の `nss_init()`（4.13 の commit `24b44b686ea2221405cfd806dede046cf1fd9584` の L42〜146）で、NSS を使う箇所は `lib/subordinateio.c` の `have_sub_uids`（L613）・`have_sub_gids`（L704）・`list_owner_ranges`（L814）・`find_subid_owners`（L931）が呼ぶ `get_subid_nss_handle()`。`newuidmap` は `src/newuidmap.c` の L35 で `have_sub_uids` を呼ぶ
- `nss_init()` の挙動: `/etc/nsswitch.conf` を開けなければ files（L60〜64）。`#` で始まる行だけ読み飛ばし、行の途中の `#` は注釈にしない（L66〜67）。`strncasecmp(line, "subid:", 6)` で大文字小文字を区別せず行頭だけで照合する（L70）。`:` の後ろの空白を読み飛ばし、値が空ならその行を捨てる（L72〜76）。区切り `" \n\t"` の `strtok_r` で最初の語だけを見て、`files` なら files に決まり、後ろの語・後ろの行は読まない。角括弧は特別扱いしない（L77〜85）。語が 50 文字を超えると files（L86〜91）。それ以外は `dlopen("libsubid_<語>.so")` を試し、失敗するか必要なシンボルが無ければ files、揃えば NSS を使う（L92〜130）
- 4.19.4（commit `115f7aa445f051a413d8b771efaa2ab0ca302770`）の `lib/nss.c` も、大文字小文字を区別しない `subid:`・`#` で始まる行だけ注釈・値が空でない最初の行の最初の語・`files` なら files、の形は同じ。違いは区切り文字と非テキストの扱いだけ

## 決定

1. **名前の解決順序は passwd 優先・NSS は行が無いときだけ**。大多数のホストは passwd で終わり、子プロセスを起動しない（CORE-10 の起動レイテンシを変えない）
2. NSS は **固定パスの `getent passwd <uid>` を子プロセスで期限つき（5 秒）に実行**して引く
3. 照合は名前と数値 uid の両方（`SubIdOwner::matches` は元から両方を受理する。課題の本体は名前を得られないことだった）
4. 我々が選ぶ行は「NSS 上の自分の名前の行」と「数値 uid の行」。`newuidmap` が受理する集合（名前・数値・別名）の**部分集合**なので、所有者の不一致で helper に拒否されることは無い（`subid:` NSS の構成を除く）
5. 所有者名の規則を緩和した: 空でない・256 バイト以内（`LOGIN_NAME_MAX`）・`:`・空白・ASCII 制御文字を含まない UTF-8。名前は分割した欄との `==` 比較にしか使わず、helper にもシェルにも渡さないため、文字種は注入面にならない。旧規則（`[A-Za-z0-9._-]`・32 文字）のままだと、NSS で `user@example.com` のような名前を得た途端に `start` が止まり、退行になる
6. **fail-closed**: passwd に行が無く NSS の参照が失敗・期限切れ・不正な出力のときは `start` を拒否する。名前の行の有無を判定できないまま 1 対 1 へ落とさない。信頼できる `getent` が無いときだけ、従来どおり数値 uid の行だけで照合する（`doctor` が通知）
7. **期限は出力の読み取りにも掛ける**（REPAIR-5）: バックグラウンドの孫が標準出力を継承して EOF が来なくても、全体で 5 秒を超えたら kill して `Timeout`。標準出力は `UnixStream` 対の読み取り側を読み取りタイムアウトつきで読む（スレッドも `unsafe` も増やさない）
8. **終了コード 2 は源がローカルのときだけ「名前なし」**: `getent` は NSS の障害でも 2 を返し得て区別できない。`/etc/nsswitch.conf` の `passwd`・`passwd_compat` が `files`・`compat`・`db`・`altfiles`・`systemd`・`usrfiles` だけのときに限り名前なしとし、それ以外（`ldap`・`sss` 等の遠隔源、読めない・上限超過・不正な角括弧）は参照失敗として `start` を拒否する。`passwd` が `compat` を含むのに `passwd_compat` の行が無いときは、glibc の既定（`nis`）があるためローカルのみとは証明できず拒否する。ファイルが無いときは glibc の既定（`files`）とみなす
9. **名前を引けないまま名前の行で 1 対 1 へ落とさない**（#2545）: 信頼できる `getent` が無く（`LookupUnavailable`）、選ばれるモデルが 1 対 1 で、subuid / subgid のどちらかに名前の行（第 1 欄が `u32` でない行）があれば、自分の行か判定できないため `start` は `FailedPrecondition` で拒否し、`doctor` は `SUBID_OWNER_UNDETERMINED`（警告）にする。名前の行が無い（ファイル無し・数値行だけ・空）なら従来どおり 1 対 1 ＋通知。`NotFound`（遠隔源の無い NSS が不在を確定）は名前の行が自分のものでないと証明済みのため 1 対 1 のまま
10. **グループ kill は未回収の子にだけ送る**（#2545・REPAIR-5）: `try_wait` を標準出力の EOF の後まで呼ばず、期限切れ・出力超過・読み取り失敗の kill は未回収の子（ゾンビは pid / pgid を保持する）に対してだけ送る。回収後に pid が一周して別プロセスのグループリーダーになる窓をなくす。回収後に期限を超えた場合は kill せず `Timeout` を返す
11. **root の呼び出し元では NSS を引かない**（#2545・SEC-5）: 実 uid / 実効 uid が 0 の exec は、ambient を消しても実行ファイルの capability が全ビットとみなされる。real / effective / saved / fs uid のどれかが 0（`/proc/self/status` を読めなければ root とみなす）なら `getent` を起動せず、`FailedPrecondition`（`RefusedAsRoot`）にする。passwd に行があれば従来どおり成功する。現状は start・doctor が rootful を拒否しており、pull 時の展開（`image_ownership`）を本番へ配線したときに root から呼ばれうるための先回りの契約。uid を落として引く方式は #2241（rootful の承認）で再検討する
12. **argv[0] は選んだ候補のパス**（#2545）: 実体は `canonicalize` 後のパスで exec するが、busybox 等の multi-call バイナリがアプレットを argv[0] の basename で解決するため、`CommandExt::arg0` に候補のパスを渡す
13. **`subid:` の最初の語が `files` 以外なら拒否**（#2545・#2636・CORE-6）: shadow 4.13 の `lib/nss.c` `nss_init()` の判定に合わせる。`/etc/nsswitch.conf` の `subid:` の最初の語が `files` 以外（libsubid・sssd・FreeIPA）だと、ファイルを読む方式では範囲を得られないため `start` は拒否し、`doctor` は `SUBID_NAME_SERVICE_UNSUPPORTED`（警告）にする。規則は次のとおり。(a) `#` で始まる行だけを注釈として読み飛ばす（行の途中の `#` は注釈にしない）。(b) 行頭が大文字小文字を区別せず `subid:` の行だけが対象（前置きの空白・`:` の前の空白は対象外）。(c) 値の先頭の空白とタブを読み飛ばし、空ならその行を捨てる。(d) 値が空でない最初の行の最初の語だけを見て、`files` なら `Files`、それ以外は `NameService`（後ろの語・後ろの行は読まない）。(e) 本文に NUL がある、または対象行の値に `\v`・`\f`・`\r` があるときは `Unusable`（`NSSWITCH_UNUSABLE`。版によって区切りの扱いが違うため）。読めない・上限超過・UTF-8 不正も `Unusable`。対象の行が無い・ファイルが無いときは従来どおり `Files`。shadow は最初の語が `files` でなければ `dlopen("libsubid_<語>.so")` の成否で NSS を使うか決めるが、成否はファイルの内容から分からないため、`files` 以外はすべて拒否する。50 文字を超える語は shadow では files になるが、拒否の安全側に倒す。#2636 以前の規則（`files` 以外の語が 1 つでもあれば拒否）との差: `SUBID:` の大文字・`files#x`・`files\r` を files と誤る甘い側を締め、`files sss`・`files [..]`・値が空・行頭の空白・`subid :` を拒否しすぎていた側を緩めた
14. **判定を型にして共有する**（#2545）: 所有者名の解決の失敗は `OwnerLookupFailure`、`start` / `doctor` 共通の拒否は `RefusalReason`（`id_model::diagnose_rootless_id_source_with`）で返し、`doctor` はエラー文言の文字列比較をしない。固定の英語文言は変えない
15. **`doctor` と inspect の `idMapping` を突き合わせない**（#2636・SEC-5・CORE-6）: 記録（`RecordedIdModel`）と現在のホスト設定で選ばれるモデルの食い違いを `doctor` の診断にしない。理由: (1) 1 つのコンテナの写像は一生変わらない（OCI の `start` は `Created` のときしか受けず、supervisor の restart は start で使った launcher と `LaunchSpec` をそのまま使うため）。食い違っても、既存のコンテナは作った時点の設定で動き続け、利用者が取れる行動が無い。記録は観測専用で、選択にも権限の判断にも使わない。新しいコンテナがどの写像になるかは `doctor` の既存の `id_model` の診断がすでに示す。`start` が通らない前提の不成立という Warning の定義にも当たらない。(2) `doctor` の契約（読み取り専用・状態ルートを使わない・引数なし）を崩す。`FileStateStore::open` は状態ルートが無ければ作って `@revision` を初期化し、`@lock` は start と競合する（REPAIR-5。Windows では未実装）。`--root` を受けるための引数の変更も要る。(3) inspect は CLI へ未配線。見直す条件: 止まったコンテナを再び `start` できるようにする、または supervisor が再接続のときに写像を選び直すようになったとき。

## `getent` の子プロセスにした理由と却下した案

- `getpwuid_r` の FFI: 期限を切れず、LDAP の停止でハングする（REPAIR-5）。NSS モジュールを supervisor に dlopen することにもなる（security.md「動的ライブラリの実行時ロードを行わない」に反する）。新規 FFI 宣言と libc 照合も要る
- argv での名前の受け渡し: 呼び出し元の入力を信頼することになる（`USER` と同じ問題）
- 数値 uid だけで照合: 名前で書かれた行（一般的な書き方）が使えない

## 子プロセスの安全策

- 実行ファイルは固定候補（`/usr/bin/getent`・`/bin/getent`・`/usr/sbin/getent`・`/sbin/getent`・`/run/current-system/sw/bin/getent`）のみ。`PATH` は探索しない。`canonicalize` した実体と全祖先ディレクトリが root 所有で group / other から書き込めないこと（`plugin_trust::check_owner_and_mode`）。NixOS の `/nix/store` などこれを満たさないものは「利用不可」になる（例外は作らない）
- `env_clear`（`LD_*` を渡さない）、stdin / stderr は null、stdout は pipe
- **ambient capability は exec 直前に全消去**（`sys::clear_ambient_caps_on_exec`。`pre_exec` で `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`。失敗したら exec しない）。supervisor は特権ランチャー経由で ambient capability を持つため、setuid でない `getent` へそのまま渡さないための措置
- 読み取り用スレッドを作らない（`start_entry` の手順 8 より前に常駐スレッドを作らない制約）。`try_wait` で期限まで待ち、超えたら kill して回収する。出力は 4 KiB まで。1 エントリは通常パイプの容量に収まり、超える出力は期限切れで fail-closed になる
- 出力は `名前:…:uid:…` の uid 欄が要求した uid と一致するときだけ採用する

## SEC-5 上の位置づけ

`start` の範囲写像は setuid の `newuidmap` / `newgidmap` が自分の NSS で所有者を再検証するため、名前の解決を誤っても他人の範囲は写像できない（helper が拒否する）。pull 時の展開（`ChownMapped`。現状は未配線、#2377・#2241 待ち）には helper の再検証が無いが、名前の出所は root が設定する NSS で、出力の uid 欄が要求した uid と一致することも検証するため、攻撃者が制御できる入力ではない。

## 対象外（既知の差）

- `subid:` の NSS で範囲を配る構成の**利用**（検出と拒否は決定 13。libsubid 経由で範囲を得る実装は無い）
- `doctor` と状態ストアの `idMapping`（`RecordedIdModel`）の突き合わせは行わない（決定 15）。イメージ展開の所有者（`image_ownership`。#2377・#2241 待ちで未配線）と現在の写像の食い違いは別の問題として残す
- root の呼び出し元で uid を落として NSS を引く方式（決定 11。#2241 で rootful が承認されたときに再検討）
- 同じ uid の別名の行（`newuidmap` の 2 段目の別名照合）は範囲として使わない（部分集合のため helper の拒否は起きない）
- ambient capability つきの本番構成で `getent` に capability が渡らないことの実機での実証、LDAP / sssd の実環境での範囲写像の確認（いずれも実機・人間担当）

## 診断コード（`doctor`）

| code | severity | 意味 |
| ---- | -------- | ---- |
| `SUBID_OWNER_NAME_UNRESOLVED` | notice | passwd にも NSS にも行が無い（数値 uid の行だけで照合） |
| `SUBID_OWNER_LOOKUP_UNAVAILABLE` | notice | passwd に行が無く、信頼できる `getent` も無い |
| `SUBID_OWNER_LOOKUP_FAILED` | warning | NSS の参照が失敗・期限切れ（`start` は拒否する。終了コード 3） |
| `SUBID_OWNER_UNDETERMINED` | warning | 名前を引けず、名前の行が自分のものか判定できない（決定 9。state `owner_undetermined`） |
| `SUBID_NAME_SERVICE_UNSUPPORTED` | warning | `subid:` の最初の語が `files` 以外（決定 13。check `nsswitch`・state `subid_name_service`） |
| `NSSWITCH_UNUSABLE` | warning | `nsswitch.conf` が読めない・NUL などで判定できない（決定 13。check `nsswitch`・state `unusable`） |
| `ID_MAP_HELPER_NOT_FOUND` / `ID_MAP_HELPER_UNTRUSTED` | warning | `newuidmap` / `newgidmap` のどちらかが無い・信頼できない。欠けた側ごとに 1 件、state は `newuidmap_not_found`・`newgidmap_untrusted` 等（#2545） |
