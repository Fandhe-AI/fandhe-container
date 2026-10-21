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
- `/etc/nsswitch.conf` に `subid:` があると、ファイルを読まずに libsubid へ問い合わせる

## 決定

1. **名前の解決順序は passwd 優先・NSS は行が無いときだけ**。大多数のホストは passwd で終わり、子プロセスを起動しない（CORE-10 の起動レイテンシを変えない）
2. NSS は **固定パスの `getent passwd <uid>` を子プロセスで期限つき（5 秒）に実行**して引く
3. 照合は名前と数値 uid の両方（`SubIdOwner::matches` は元から両方を受理する。課題の本体は名前を得られないことだった）
4. 我々が選ぶ行は「NSS 上の自分の名前の行」と「数値 uid の行」。`newuidmap` が受理する集合（名前・数値・別名）の**部分集合**なので、所有者の不一致で helper に拒否されることは無い（`subid:` NSS の構成を除く）
5. 所有者名の規則を緩和した: 空でない・256 バイト以内（`LOGIN_NAME_MAX`）・`:`・空白・ASCII 制御文字を含まない UTF-8。名前は分割した欄との `==` 比較にしか使わず、helper にもシェルにも渡さないため、文字種は注入面にならない。旧規則（`[A-Za-z0-9._-]`・32 文字）のままだと、NSS で `user@example.com` のような名前を得た途端に `start` が止まり、退行になる
6. **fail-closed**: passwd に行が無く NSS の参照が失敗・期限切れ・不正な出力のときは `start` を拒否する。名前の行の有無を判定できないまま 1 対 1 へ落とさない。信頼できる `getent` が無いときだけ、従来どおり数値 uid の行だけで照合する（`doctor` が通知）
7. **期限は出力の読み取りにも掛ける**（REPAIR-5）: バックグラウンドの孫が標準出力を継承して EOF が来なくても、全体で 5 秒を超えたら kill して `Timeout`。標準出力は `UnixStream` 対の読み取り側を読み取りタイムアウトつきで読む（スレッドも `unsafe` も増やさない）
8. **終了コード 2 は源がローカルのときだけ「名前なし」**: `getent` は NSS の障害でも 2 を返し得て区別できない。`/etc/nsswitch.conf` の `passwd`・`passwd_compat` が `files`・`compat`・`db`・`altfiles`・`systemd`・`usrfiles` だけのときに限り名前なしとし、それ以外（`ldap`・`sss` 等の遠隔源、読めない・上限超過・不正な角括弧）は参照失敗として `start` を拒否する。ファイルが無いときは glibc の既定（`files`）とみなす

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

- `subid:` の NSS で範囲を配る構成。ファイルを読む方式では範囲を得られない。検出（`doctor` での通知など）は別途検討
- 同じ uid の別名の行（`newuidmap` の 2 段目の別名照合）は範囲として使わない（部分集合のため helper の拒否は起きない）
- ambient capability つきの本番構成で `getent` に capability が渡らないことの実機での実証、LDAP / sssd の実環境での範囲写像の確認（いずれも実機・人間担当）

## 診断コード（`doctor`）

| code | severity | 意味 |
| ---- | -------- | ---- |
| `SUBID_OWNER_NAME_UNRESOLVED` | notice | passwd にも NSS にも行が無い（数値 uid の行だけで照合） |
| `SUBID_OWNER_LOOKUP_UNAVAILABLE` | notice | passwd に行が無く、信頼できる `getent` も無い |
| `SUBID_OWNER_LOOKUP_FAILED` | warning | NSS の参照が失敗・期限切れ（`start` は拒否する。終了コード 3） |
