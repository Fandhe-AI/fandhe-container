# supervisor 不在時（孤児化・再起動後）の exec の方式（判断記録）

supervisor が不在のとき（孤児化・再起動後）に、稼働中コンテナへの exec をどう成立させるか、または成立させないかの判断材料を整理する（SUP-4・SUP-5・SUP-6・SUP-8・SEC-1・CORE-1・REPAIR-3。TASK-163 追補・TASK-165。#2688）。

> **位置づけ**: **判断記録（オーナー承認待ち）**。本書は決定ではなく判断材料である。決まるまで現行の拒否（fail-closed）を保つ。関連: #1461・#1617（起動時 pidfd の恒久策）・#2626 / PR #2708（CLI の exec の配線）・#2441（healthcheck の配線）・#2631 / PR #2684（本 issue が追跡先になった経緯）・#513・#514・#515（re-adopt。TASK-165）。spec は孤児時の exec の方式を定めておらず、本書の判断は実装側の判断である。実装は本書の対象外（docs のみ）で、新しい試験も足さない。

## 現状（fail-closed の根拠）

| 箇所 | 挙動 |
| ---- | ---- |
| `crates/supervisor/src/exec.rs` | 本番の通しの入口は `run_command_with_pidfd` だけ。起動時（fork 直後・回収前）から supervisor が保持する pidfd（`LaunchedProcess::launch_pidfd`）を引数の型で必須にする |
| 縮退経路 | 記録 pid から開く入口 `run_command` は `exec-test-support` feature の試験専用で、既定ビルドには無い（#1617） |
| `crates/supervisor/src/control/target.rs` | 起動時 pidfd を持つのは稼働中 supervisor の `ControlledProcess` だけ |
| `crates/supervisor/src/control/client.rs` | ソケットが無い・接続拒否のとき `Unavailable` を返す。CLI の exec は `state.json` の記録 pid からの `pidfd_open` へ縮退しない（#2626 の設計） |
| `crates/core/src/exec/setns.rs` | `Pid1Target::open`（記録 pid から開き cgroup パスの完全一致で照合）は「コンテナから cgroupfs に書けない」前提の間だけの縮退経路。`open_with_launch_pidfd` は渡された pidfd の `Pid:` と記録 pid の一致を同一性の根拠にする |
| spec | SUP-5: 孤児化したコンテナは稼働を続けるが restart・healthcheck・ログ捕捉は失われる。SUP-8: re-adopt か終了かを決める。SUP-4: healthcheck は exec と同じ関数で動く |

結果として、孤児の間は CLI の exec も healthcheck も拒否される。これは SUP-5 で失われる監視機能と同じ範囲である。

## 論点の核心

pidfd をあとから開いても、それ自体では何も証明されない。起動時の pidfd の持ち主が消えた後、`pidfd_open(記録 pid)` が元のコンテナの PID 1 を指していると何で確かめるか、が論点の中心である（「どうやって pidfd を取り直すか」ではない）。記録 pid は終了後に再利用されうる（SEC-1）。

## 案の比較

| 案 | 内容 | 評価 |
| -- | ---- | ---- |
| (i) 拒否を保つ | re-adopt まで exec を拒否し、exec 側に縮退経路を持たない | 現状。安全。孤児の間は exec と healthcheck が使えない |
| (ii) cgroup パスでの同一性（`Pid1Target::open`）を本番で使う | 記録 pid から開き `<scope>/fc-<id>@<instance>` との一致で照合する | cgroupfs に書けない前提に頼る。前提を崩す変更（cgroupfs のマウント・cgroup namespace・`/sys/fs/cgroup` の rw bind）で壊れる。#1461 が恒久策を入れた理由そのもの。不採用を推奨 |
| (iii) 起動時の同一性の証跡を `state.json` に記録して照合する | 起動時にコンテナが偽れない証跡を記録する。候補は (a) pidfd の inode 番号（pidfd の `fstat` の `st_ino`）、(b) `/proc/<pid>/stat` の starttime と `boot_id` の組。取り直しのとき `pidfd_open(記録 pid)` → 証跡の照合 → pidfd の未終了の確認、の順に固定する | cgroupfs の前提に頼らない。`state.json` のスキーマ追加が要る（現状の exec は instance を使ってスキーマを変えない方針）。カーネル版数の要件と、満たさない環境の扱いを決める必要がある |
| (iv) supervisor の外で pidfd を持ち続ける | systemd の fd store・常駐の holder など | supervisor は `systemd-run --user --scope` で包んで起動される（`crates/cli` の start）。fd store は service 単位の機能で scope では使えない見込み（要確認）。常駐の holder は CORE-1（中央の常駐デーモンを持たない）と衝突する。不採用を推奨 |

誰が取り直すかも分けて考える。

- (α) CLI の exec が自分で取り直す
- (β) re-adopt（#513 で検知、#514 で再監視）した supervisor が取り直して保持する。以後は既存の制御チャネルの受け渡しで、CLI の exec も healthcheck も今のまま動く

## Agent の推奨（決定ではない）

- 同一性を確立し直すのは re-adopt（#514）の責務とし、exec は持たない（(β)）。re-adopt の前は (i) で拒否を保つ
- 証跡には (iii) を使う。pidfs の inode が使える環境ではそれを優先し、使えない環境で starttime と `boot_id` に切り替えるか拒否するかはオーナー判断として残す
- (β) を推す理由: pidfd を持つ主体が supervisor 1 つに保たれる（CORE-1）／exec と healthcheck（SUP-4 の共通関数）の経路を変えずに済む／孤児の状態を exec が覆い隠さない（SUP-5・SUP-8 の「再監視下に戻る、または明示的に終了する」と合う）／本番の入口に縮退経路を新しく作らない

#514 が満たすべき契約（案）:

1. 証跡の照合を通った pidfd だけを `ControlledProcess` へ登録する
2. 照合できない（証跡が無い・一致しない・既に終了している）ときは re-adopt せず、終了ポリシーか拒否に倒す（fail-closed）
3. 照合の順序は、pidfd を先に開いて固定し、読み取りの後で未終了を確認する（`setns.rs` の TOCTOU の契約と同じ）
4. 受け取った pidfd は core の `Pid1Target::open_with_launch_pidfd` がそのまま受け入れる（`Pid:` と記録 pid の一致、cgroup の照合は多層防御）
5. 証跡はカーネルが付ける値に限り、コンテナ内から書ける値（cgroup の所属・環境・ファイル）を同一性の根拠にしない

## カーネルの事実（要確認）

pidfs の導入版、inode 番号の一意性（再利用されないか）、starttime の欄番号と単位、`boot_id` のパス、`PIDFD_GET_INFO` の導入版は、本書では版を固定した原文で確かめていない。リポは別の判断で Linux 6.9 を閾値として扱っているが、本件の根拠としては要確認とする。実装の issue で、版を固定したカーネルの原文で確かめてから書く。

## 確認が必要な点（オーナー判断）

- 推奨の採否（(β) と (i)、または (α)）
- `state.json` への証跡の追加（スキーマ変更。証跡の無い旧レコードは re-adopt を拒否する方向）
- カーネル版数未満の環境の扱い
- CLI の exec が supervisor 不在を `Unavailable` で返すことの利用者への案内（構造化エラーの `message` の語彙。英語の固定文言で、ホスト側のパスを載せない）

## 範囲外・後続

| 項目 | 担当 |
| ---- | ---- |
| 証跡の記録と照合の実装（core・supervisor） | 未起票（承認後に起票） |
| re-adopt 本体 | #514 |
| 孤児の検知 | #513 |
| 結合試験 | #515 |
| healthcheck の配線 | #2441 |
| CLI の exec の stdio 等 | #2712 |
