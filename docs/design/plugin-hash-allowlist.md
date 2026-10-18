# plugin の許可済みハッシュ一覧の置き場所と読み込み経路（設計案）

PLUG-11 の既定の検証方式は「許可済み sha256 ハッシュ一覧に一致するバイナリだけを登録する」方式（#280・TASK-122.h1）である。しかし一覧の置き場所と読み込み経路が決まっておらず、コード上も読み込み経路が無い。このため一覧は常に空で、plugin は全件拒否になっている（fail-closed）。本書は一覧の置き場所・指定方法・信頼性検証・失敗時の挙動を整理し、オーナーの判断材料にする。

> **位置づけ**: TASK-122 追補・#1868 の設計案。**オーナーの承認は未取得（承認待ち）**。本書の「推奨」は確定ではない。承認後に 6 章の実装 issue を起票する（本 PR では起票しない）。

- 対象ビヘイビア: PLUG-11（関連: PLUG-4・PLUG-7・PLUG-12・CORE-1・CLI-1・MAC-1・WIN-1）
- タスク: TASK-122 追補（関連: TASK-109・TASK-79・TASK-114）、MS-3
- 関連 issue: #1539（探索先のオーナー判断 2026-10-12）・#280・#279・#282・#1608・#1869・#1865・#1867・#1863・#1862・#1415
- 出典: spec の `04-behavior/plugin-system.md` PLUG-11

## 1. 問題の整理

- `crates/core/src/plugin_trust.rs`: 一覧の形式（`sha256sum` 互換・LF・UTF-8、上限 `MAX_ALLOWLIST_BYTES`・`MAX_ALLOWLIST_ENTRIES`）は決まっている。`AllowedPluginHashes::parse` はバイト列だけを受け取り、置き場所・指定方法・一覧ファイル自体の所有者とモードの検証の配線は未実装
- `crates/cli/src/commands/plugin_backend.rs`: 検証は `PluginVerificationMethod::default()`（空の一覧）で行うため必ず失敗する。`PATH` 由来の候補の扱い（A1）も配線時の再評価待ち
- `crates/core/src/plugin_discovery.rs`: `PluginDirKind::Path` の採否は配線時に決める契約
- 一覧は plugin の信頼の根である。ここを書き換えられる者は任意の plugin を登録できるため、置き場所の選択は信頼境界の設計そのものになる

## 2. 前提と制約

- 常駐デーモンを持たない（CORE-1）。一覧の読み込みは各 CLI 呼び出しの中で完結させる
- core バイナリに埋め込み値を持たない（PLUG-4）。plugin の追加で core を変えない
- 新しい依存を前提にしない。形式は `sha256sum` 互換のまま、`sha2` と既存の `sys` ラッパーだけを使う
- Windows はゲスト内の Linux の規則に従う（#1415）。ホスト側の Windows 実行層は別文書で扱う
- macOS の検証は拡張 ACL の拒否（#1865）と探索先（#1863）に依存する
- `user_scope.rs` の「呼び出し元の `PATH` を信頼の根拠にしない」方針と、PLUG-7 の「環境変数を暗黙に継承しない」決定を踏襲する

## 3. 決める項目（選択肢・影響・推奨）

### 3.1 置き場所と合成の規則

| 案 | 内容 | 影響 |
| -- | ---- | ---- |
| A（推奨） | 管理ディレクトリごとに一覧ファイルを 1 つ置く（例 `<探索先>/allowed-sha256sums`）。名前に `fandhe-container-plugin-` の接頭辞が無いので発見の対象にならない | 探索先と同じ `verify_plugin_dir(dir)?.verify_file(name)` で検証でき、fd のコードを増やさない。macOS の拡張 ACL の拒否も自動で効く。信頼の根がスコープごとに 1 つに決まる |
| B | 設定ディレクトリ（`/etc/fandhe-container/`・`$XDG_CONFIG_HOME/fandhe-container/`）に置く | macOS は `/etc` が `/private/etc` への symlink で祖先の symlink 拒否に当たる。`/usr/local/etc` は `/usr/local` が group 書き込み可の環境で拒否される（#1865 と同じ注意）。探索先と別の祖先連鎖の検証が要る |

パス（案 A）: Linux の system は `/usr/libexec/fandhe-container/plugins/`、user は `<XDG_DATA_HOME>/fandhe-container/plugins/`。macOS は #1539 の探索先（`/usr/local/libexec/...`、user は `$XDG_DATA_HOME` の下、無ければ `~/Library/Application Support/...`）。

合成: **スコープ対応**を推奨する。system の候補は system の一覧、user の候補は user の一覧で照合する。和集合（どちらかにあれば可）は単純だが、user の一覧で system の候補を通せてしまい、`PATH` 由来の候補のスコープも決まらない。

### 3.2 指定方法

固定パスだけにし、CLI フラグ・環境変数・`--root` による上書きは許さない（推奨）。信頼の根を呼び出し側の入力で差し替えさせないため。上書きを許す案（`PATH` の opt-in と同様に警告つき）は柔軟だが、環境変数を設定できる者が信頼の根を差し替えられる。試験は core の API にパスを渡す形で行い、本番の入口は固定パスだけを解決する。

### 3.3 一覧ファイル自体の信頼性検証

`VerifiedPluginFile` を `verify_file` で得て、その fd から読む（パスを開き直さない）。読む量は `MAX_ALLOWLIST_BYTES + 1` で止め、超えたら上限超過で拒否する（plugin 用の大きな上限は使わない）。読んだバイト列だけを `AllowedPluginHashes::parse` に渡す。本番の生成経路は検証済み fd を受ける 1 つの関数（例 `AllowedPluginHashes::from_verified`）に限り、`parse` は試験と内部用にする。最終要素の symlink は plugin と同じく実体で判定する。所有者は root か実効 UID、group / other 書き込み不可、全祖先も同じ基準とし、sticky bit も例外にしない。

### 3.4 無い・読めない・不正なときの挙動

- 一覧ファイルが無い（ENOENT）: 空の一覧として全件拒否する。ただし理由（`reason`）は区別する（例 `allowlist_missing`）
- 所有者・モードの不正、読めない、構文エラー、上限超過: エラーで止める。黙って空にしない（改ざんが「登録なし」に見えないようにするため）。それぞれ別の `reason` を付ける
- 現状の `verify_plugin_dir` / `verify_file` は ENOENT を `Io` に写すので、「無い」を区別する種別（または一覧専用の写像）が要る
- CLI: `BackendFailure` に一覧用の種別と固定の英語文言を足す（案 `plugin hash allowlist is missing`・`plugin hash allowlist is untrusted or malformed`）。パス・plugin 名・行番号は出力に出さない（C2 の方針）。#1867 の分類の見直しと並べて決める

### 3.5 `PATH` 由来の候補

登録前に `PluginDirKind::Path` を除く（推奨。警告の出力は残す）。スコープ対応の合成ではどの一覧にも当てはまらないため。代案は「ハッシュが一致すれば採る（優先度は最低のままで shadow しない）」。この場合、`PATH` に置ける者が一覧の既知ハッシュのバイナリを置くだけで登録できる点は変わらないが、内容は一致しているため実害は限定的である一方、スコープ別の一覧の意味が曖昧になる。推奨案は現在の `backend_failure` の挙動を変える（`plugin_backend.rs` の試験は PATH の候補がレジストリへ届くことを確かめている）ため、変更は実装 issue で試験とともに行う。

### 3.6 読む入口とタイミング

`plugin_trust` に一覧の読み込み API を置き、#1869 で設計する「発見 → 検証 → 起動」の core 側の共通入口がそれを呼ぶ。CLI と CRI plugin の起動経路（TASK-114）は同じ入口を使う。supervisor は plugin を発見しないので対象外。CORE-1 により**呼び出しごとに読み、キャッシュしない**。

### 3.7 作り方と更新の手順

利用者が `sha256sum <plugin> >> <一覧>` で書き足す（ラベル部分は無視されるのでパスを残すと人が読みやすい）。system スコープは root が要るので、手順書には `sudo tee -a` を書くだけにし、実行は利用者が行う。Linux は `docs/setup/linux.md`、macOS は #1867 で作る文書に書く。macOS は署名後のバイナリのハッシュを載せる（#1539）。インストールスクリプトが一覧を書く案と、CLI に追加用のサブコマンドを足す案は将来の選択肢とする。

### 3.8 検証方式の切替点

MVP では方式を選ぶ設定を置かず `Sha256Allowlist` 固定とする。将来、署名方式の設定を足すときは system スコープだけで受け、未知の方式名は拒否する。設定ファイルの形式は新たに決めない（core に TOML の解析は無く、依存も足さない）。

## 4. 決定事項の一覧

| 項目 | 推奨 | 状態 |
| ---- | ---- | ---- |
| 置き場所 | 探索先ごとに `allowed-sha256sums`（案 A） | 承認待ち |
| 合成 | スコープ対応 | 承認待ち |
| 指定方法 | 固定パスのみ。上書き不可 | 承認待ち |
| 一覧の検証 | `verify_file` の fd から上限 + 1 で読む | 承認待ち |
| 無い | 全件拒否（reason で区別） | 承認待ち |
| 読めない・不正 | エラーで停止（空にしない） | 承認待ち |
| `PATH` 由来 | 登録前に除外 | 承認待ち |
| 読み込み | 呼び出しごと。キャッシュなし | 承認待ち |
| 方式の切替 | MVP は固定。未知の方式名は拒否 | 承認待ち |

## 5. spec に入れる文言の案（spec リポ側の課題）

許可済みハッシュ一覧は、管理ディレクトリ（system / user）ごとに固定のパスに置き、そのスコープの候補だけを照合する。一覧ファイルにも、ディレクトリ・バイナリと同じ所有者・モード・祖先・symlink の検証を当てる。CLI フラグ・環境変数で場所を上書きしない。一覧が無いときは全件拒否する。読めない・信頼できない・不正なときは error-format に沿ったエラーで止める。`PATH` 由来の候補は登録しない（推奨案が採られた場合の文言。別の案が採られたら合わせて直す）。

`docs/spec` は本リポから編集しない。上の追記は spec リポ側で行う。

## 6. 確定後の実装 issue（起票はしない。親 Phase 7・#58）

| # | タイトル案 | 依存 | 受け入れ条件の骨子 |
| - | ---------- | ---- | ------------------ |
| I1 | feat(core): plugin の信頼性検証で「無い」（ENOENT）を区別する種別を足す | なし | 種別を足すか一覧専用の写像を作る。reason の表・`ErrorCode` への写像・CLI の写像の試験を具体値で更新 |
| I2 | feat(core): スコープごとの一覧ファイルの既定パスを解決する | I1（macOS 分は #1863） | Linux・macOS のパス、Windows・その他は空。具体値の試験 |
| I3 | feat(core): 検証済み fd から一覧を読む API を足す | I1・I2 | `verify_file` 経由・上限 + 1 で停止。無い・不正・上限超過・所有者不正の分類を具体値で試験 |
| I4 | feat(core): 登録前に `PATH` 由来の候補を除き、スコープ対応で照合する | I3 | 3.1・3.5 の決定どおり。PATH の警告は残す |
| I5 | feat(cli): plugin_backend に一覧の読み込みを配線し `BackendFailure` に一覧用の種別を足す | I3・I4・#1867・#1869 | 固定文言表の試験を更新し、パスを出力しないことを確かめる |
| I6 | docs(setup): Linux・macOS の一覧の作り方と更新手順を書く | I5・#1867 | `docs/setup/linux.md` と macOS の文書 |
| I7 | test: 一覧ファイルの別 UID 所有・書き込み可の拒否を実機で確かめる（人間担当） | I3 | 実機の結果を PR に記録 |

## 7. 未確認事項・再検証条件

- macOS の実機での祖先の所有者・モード（`/usr/local/libexec` 等）は未確認。#1865・#1863 の実装後に確かめる
- rootful の実行で `HOME` が利用者のディレクトリを指すとき、user スコープの一覧を信頼してよいかは未確認
- ファイルシステム上で O_NONBLOCK の fd から通常ファイルを読む挙動は Linux では問題ないと考えるが、実装 issue で試験する
