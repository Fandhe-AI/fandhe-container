#!/usr/bin/env bash
# restart レイテンシ実機実測スクリプト（TASK-160・SUP-3・MS-9。実測・合否判定は #491・TASK-160.h1 で人間が行う）。
#
# 役割: restart ポリシー下で、コンテナ側プロセスを SIGKILL してから supervisor が新しいコンテナを起動し終えるまでの
# レイテンシを複数試行計測し、中央値・p95 を JSON で出力する。supervisor の bin にはバックオフを指定する引数が無く
# （既定 100ms 固定。crates/supervisor/src/restart.rs の DEFAULT_BACKOFF）、計測値にはバックオフが含まれる。
# 本スクリプトは生の値（observed・supervisor_reported）に加え、バックオフを差し引いた値（*_minus_backoff）も出す。
# SUP-3 の目標は「バックオフ 0 の再起動レイテンシ中央値 100ms 以下」（PoC-17 own 実測: 中央値 1.79ms・p95 2.29ms）。
# 本スクリプトは合否を出さない（目標値との比較・レポート化は #491 の担当）。
# 実装済みを装わない（REPAIR-3）: 製品バイナリ（CLI・supervisor の bin。#1717・#1819）は提供済みだが、restart の
# 再 launch は #2043 で本番 launcher でも成立する（常駐スレッドを止めて監視スレッドで直接 launch）。実測は #491（人間担当）。
# CI で動かすのはスタブの自己テスト scripts/measure-restart-latency-selftest.sh のみ。
#
# 呼び出し元: Makefile の `restart-latency`（操作者が明示実行。make ci には含めない）。sudo は呼ばない
# （権限が要る場合は操作者が権限付きシェルから実行する）。crates/supervisor の restart ループ
# （restart.rs の supervise_with_restart）と、state.json（crates/core の StateStore）を外から観測する。
# supervisor は rootful 起動を拒否する（SEC-5）ため、非 root の利用者で実行する（root では起動前に終了コード 3）。
#
# 起動契約（crates/supervisor/src/start_contract.rs。差し替え点は build_launch_cmd・sup_create・sup_report）:
#   1. <bin-dir>/fandhe-container --root <状態ルート> create --bundle <bundle> <id> を済ませる。
#   2. <systemd-run> --user --scope --quiet -p Delegate=yes -- <bin-dir>/fandhe-container-supervisor start --root <状態ルート>
#      --restart <policy> <id> をフォアグラウンドで実行（配列で直接 exec。eval・sh -c を使わない。--scope は同じ
#      プロセスのまま exec する。supervisor は親 cgroup に自分だけがいることを要求するため新しいスコープへ入れる）。
#      標準出力は名前付き FIFO にする（supervisor は FIFO 以外の標準出力を拒否する）。環境変数 FANDHE_BENCH_OWNER の
#      実行ごとのトークンを渡す。停止は SIGTERM、期限超過で SIGKILL。
#   3. 結果は標準出力の 1 行 `FCSUP1 OK <pid>`（pid はコンテナ側 init のホスト上 pid。state.json の pid と一致する）か
#      `FCSUP1 ERR <CODE> <exit> <msg>`。
#   CLI の start を経由しない理由: CLI の start は supervisor を別プロセスグループで起動し、標準エラー（restart の
#   構造化ログ）を捨て、--restart を渡さず、子として wait しない。直接起動すれば supervisor が本スクリプトの
#   直接の子になり、子孫の帰属証明と後始末が成立する。
#   コンテナ側プロセスは supervisor の子孫で、state.json（<状態ルート>/<id>/state.json。camelCase の
#   status・pid・restartCount）に実行中 pid と再起動回数が反映される。状態ルートは --state-root の値、省略時は
#   本スクリプトが mktemp で作る 0700 のディレクトリ（後始末の正常系では CLI の delete が <id>/ を消し、一時ディレクトリは
#   rm -rf する。下記「後始末の delete」）。
#   restart のたびに構造化ログ {"component":"supervisor.monitor","operation":"restart","result":"ok",
#   "elapsed_us":N} が<状態ルート>/@supervisor-logs/<id>.log へ `stderr ` 接頭辞つきで残る（無ければ supervisor_reported は null）。--bundle は計測専用の使い捨てを使う。
#   標準エラーはファイルへ記録する。ulimit での肥大化防止は、コンテナへ継承され計測条件が変わるため行わない
#   （supervisor の標準エラーは restart・終了ごとの行だけで、全体期限が上限になる）。
#
# バックオフの差し引き（SUP-3）: supervisor の bin にバックオフ引数は無い。製品の引数を足す案は spec の確認が要るため
#   足さず、定数 supervisor_backoff_ms（DEFAULT_BACKOFF と同値。自己テストが restart.rs と機械照合する）を
#   両系列の各値から引いた値を *_minus_backoff として出す。supervisor は backoff 以上眠る（sleep_unless_stopped は
#   現在時刻が開始 + backoff に達するまで待つ）ので、差し引いた値は「バックオフを除いた遅延の上側の推定」
#   （寝過ごし分を含む保守側）になる。差し引いた結果が負なら計測異常として終了コード 1 にする。
#   両系列とも区間にバックオフを含む（observed は SIGKILL から state.json 更新まで、supervisor_reported の
#   elapsed_us は終了検知から Running 記録完了まで）。observed は終了検知のポーリング粒度も含む。
#
# 計測区間（出力 method にも明記）:
#   observed            : コンテナ側プロセスへ SIGKILL を送る直前 → state.json が status=running・pid 変化・
#                         restartCount+1 を初めて返した時点。シグナル配送・終了検知・本スクリプトのポーリング粒度を
#                         含む上側推定（主系列）。
#   supervisor_reported : launcher ログの restart 行 elapsed_us（終了検知 → Running 記録完了。検知待ちを含まない。
#                         SUP-3 の定義に近い副系列）。件数が trials+warmup と一致しないときは null。
#   PoC-17 はワークロード自身が記録した「次の開始時刻 − 前の終了時刻」で区間が異なるため、直接比較しない。
# 集計: 中央値は偶数個のとき中央 2 値の平均。p95 は昇順の ceil(n*95/100)-1 番目（restart_latency.rs と同じ。
#   net_setup_timing.sh の p90 式とは別物）。
#
# 使い方:
#   measure-restart-latency.sh --bin-dir <絶対パス> --bundle <dir> [--systemd-run <絶対パス（既定 /usr/bin/systemd-run）>]
#       [--trials N（1〜200。既定 20＝PoC-17）] [--warmup W（0〜20。既定 1。集計から除外）]
#       [--timeout SECS（各待機の上限 1〜600。既定 30）] [--policy on-failure|always（既定 on-failure）]
#       [--state-root <絶対パス>] [--poll-us N（100〜100000。既定 1000）] [--settle-ms N（0〜5000。既定 50）]
#       [--label STR] [--id-prefix STR（既定 fc-restart-lat）] [--output FILE（新規ファイルのみ）]
#       [--print-budget（実行全体の所要時間の上限〔秒〕だけを出して終了。supervisor は起動しない）] [--help]
#   --state-root 省略時: 本スクリプトが作る一時ディレクトリを --root に渡す。指定時はそのディレクトリを --root に使う。
#
# 出力: JSON（標準出力。--output 指定時はそのファイル）。launcher・bundle・state-root のパス、cmdline、環境変数は出さない。
#   結果は後始末の成功を確認した後にだけ公開する（失敗・中断・後始末失敗では標準出力・--output とも出さない）。
# 終了コード: 0 = 成功 / 1 = 計測失敗（FCSUP1 OK なし・期限切れ・再起動未観測・時計変更・launcher 異常終了・想定外の
#   内部エラー）/ 2 = 引数・入力・出力先エラー / 3 = 前提欠如（非 Linux・bash 5 未満・jq・/proc。0 で合格に見せない）/
#   4 = 後始末失敗（delete の拒否・期限超過・残存プロセス・帰属を証明できない生存 pid・報告 pid か state.json の pid を記録できず追跡不能な場合。launcher の生存を問わない。最優先）/ 129・130・143 = HUP・INT・TERM による中断
#   （後始末の完了後）。set -e による想定外の中断は、そのコマンドの終了コードに関わらず 1 に正規化する。
# 期限: 各待機（create・FCSUP1・running・試行ごとの再起動観測）は --timeout を上限とし、単調時計（/proc/uptime）で判定する。
#   実行全体の上限は --print-budget の値（既定の 20 試行・warmup 1・--timeout 30 で 843 秒）。本スクリプト自身は
#   全体期限を持たないので、外側で timeout をかける場合はこの値以上にする（Makefile の restart-latency は未指定時に
#   この値を使う）。
# 新プロセスの検証: 観測時と確定時に、新 pid が生存し（ゾンビ除外）launcher の子孫で、起動時刻が一致することを
#   確認する（SUP-3。state.json だけ残って新プロセスが終了した試行は採用しない）。
#
# シグナル送信の規則（実機でプロセスへシグナルを送るため、全経路で次を守る）:
#   - 送信先は「本計測が起動したと証明できたプロセス」だけ。証明の根拠は次のいずれか:
#       (a) launcher 本体: 本スクリプトの直接の子（親 pid = $$）で、起動直後に記録した起動時刻と一致する。
#       (b) launcher の子孫: launcher が (a) で生存中に PPid 連鎖が launcher へ届き、連鎖の全プロセスが辿った前後で
#           同じ起動時刻のまま存在する（試行で kill するコンテナ側プロセス・停止前に採取する子孫スナップショット）。
#       (c) 所有トークン: 環境変数に FANDHE_BENCH_OWNER=<本実行の 128 bit 乱数> の完全一致エントリを持つ。
#       (d) launcher 停止後に state.json へ現れた pid: (c) か、launcher の session に属し、かつ同じ session に
#           (b) で記録済みの生存プロセスがいる（session 番号が再利用されていないことの証明）場合だけ。
#     state.json の pid・起動時刻が launcher 以降・comm 名の一致は、いずれも単独では根拠にしない。
#   - 送信はすべて sig_same_proc を通し、pid 単体へ送る（プロセスグループ・session 宛や名前一致では送らない）。
#     直前に「記録した起動時刻のまま生存している同一プロセスか」を再照合する。
#   - 証明できない生存 pid（state.json にあるが子孫でも (c)(d) でもない）にはシグナルを送らず、警告を出して
#     終了コード 4 にする（結果は公開しない）。launcher より前から動いていたプロセスは無関係と確定するので 4 にしない。
# CLI の stop は後始末に使わない（#2163・SUP-9・CLI-1）: --restart の下では stop による終了が restart の対象になる
#   （stop の意図の伝達 SUP-9 は #2162・#2440 で実装済みだが、stop 経由への切り替えは未実施）。計測の起点はコンテナ側プロセスへの SIGKILL のままで、stop 経由にしない。
# 後始末の delete（OCI-6・#2157）: 正常系（--policy on-failure で、最後の試行の再起動で再起動回数を使い切っているため、
#   最後のコンテナ側プロセスへ SIGKILL を 1 回送って supervisor が RetriesExhausted で Stopped を記録して自分で終わる）は、
#   計測値を確定した後（計測区間の外）に、プロセスの回収を確認してから CLI の delete を呼んで状態を消す。
#   呼び出しは本番の start と同じ包み込み（<systemd-run> --user --scope --quiet -p Delegate=yes -- <cli> --root <状態ルート>
#   delete <id>。配列で直接 exec）で、CLI 自身を委譲スコープの中に入れる。こうすると core の delete は記録済みスコープを
#   fd 起点で開く経路（remove_recorded。#2096）で試行スコープの外からでも cgroup を消せる。
#   stopped にならない場合（--policy always は本スクリプトが stop ではなく SIGKILL で終わらせるため再起動されて自然に止まらず、on-failure でも
#   期限内に stopped にならなければ）delete は呼ばず（必ず FAILED_PRECONDITION になるため）、従来どおりプロセスを回収して
#   一時ディレクトリを rm -rf する。結果 JSON の cleanup.delete に ok / skipped（reason: state-not-stopped）を載せて隠さない。
#   delete の拒否・期限超過は後始末失敗（終了コード 4）にし、状態を残す（結果は公開しない契約のため、拒否は stderr の
#   固定書式の行 `cleanup-failed: delete was rejected (<CODE>)` と終了コードで残す。CODE は CLI の stderr の JSON の code か
#   UNPARSED・TIMEOUT）。上限: 自然停止の待ち RESTART_LATENCY_STOP_WAIT_S 秒（既定 10。0 は自然停止を試みず delete を
#   スキップ。実機では使わない）、delete RESTART_LATENCY_DELETE_TIMEOUT_S 秒（既定 20。いずれも後始末の枠 60 秒に収まる）。
# 後始末: launcher の子孫を記録 → launcher へ SIGTERM（5 秒で止まらなければ SIGKILL）→ 帰属不明 pid の再判定 →
#   所有トークン一致と記録済みのプロセスへ SIGKILL（最大 5 秒再試行）→ 最終走査で 1 つでも生存していれば 4。
#   restart ログの副系列は launcher 停止後に集計する（最後の restart ログが状態更新より遅れても欠損にしない）。
# 原理的に残る制約（sh では pidfd_open・pidfd_send_signal を使えないことによる。隠さず明記する）:
#   - 同一性の照合と kill(2) は不可分にできない。照合の直後に対象が終了し、その pid が kill までの間に別プロセスへ
#     割り当て直されると誤送信になる。窓は組み込みコマンド数個分（fork・待機なし）に絞ってあり、成立にはその間に
#     pid 空間が一巡する必要がある（Linux の pid 割り当ては循環式）。
#   - 起動時刻（/proc/<pid>/stat の field 22）は 1/100 秒刻み。同じ刻みの中で pid が再利用された場合は区別できない。
#   - 検出できない残存: トークンを継承せず、launcher 停止前の子孫スナップショットにも state.json にも現れない
#     プロセス（スナップショット後に生まれた孤児・launcher が記録前に異常終了した場合の孤児）は検出できない。
#     コンテナの init（supervisor の報告 pid・state.json の pid）を記録できないまま後始末へ入った場合は（launcher の生存を問わない）、一時的な
#     中間プロセスを記録済みでもコンテナ全体を追跡できた証明にせず、終了コード 4 にして状態を残す。ただし、
#     報告も state.json の pid も出る前に生まれた init は観測できない（原理的な制約）。
#   - 本スクリプト自身が SIGKILL された場合（外側 timeout の --kill-after を含む）は後始末できない。launcher は
#     setsid で別 session にあり、外側 timeout のシグナルは届かないため残存し得る。
set -euo pipefail

readonly num_re='^(0|[1-9][0-9]{0,8})$'
readonly pid_re='^[1-9][0-9]{0,9}$'
readonly dig_re='^[0-9]{1,18}$'
readonly id_re='^[A-Za-z0-9_-]{1,32}$'
readonly label_re='^[A-Za-z0-9._-]{1,64}$'

err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

bin_dir=""
systemd_run="/usr/bin/systemd-run"
bundle=""
trials=20
warmup=1
timeout_s=30
policy="on-failure"
state_root=""
poll_us=1000
settle_ms=50
print_budget=0
label=""
id_prefix="fc-restart-lat"
output=""

need_val() { [ "$1" -ge 2 ] || { err "invalid-argument" "$2 requires a value"; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) need_val $# "$1"; bin_dir="$2"; shift 2 ;;
    --systemd-run) need_val $# "$1"; systemd_run="$2"; shift 2 ;;
    --launcher) err "invalid-argument" "--launcher was replaced by --bin-dir"; exit 2 ;;
    --bundle) need_val $# "$1"; bundle="$2"; shift 2 ;;
    --trials) need_val $# "$1"; trials="$2"; shift 2 ;;
    --warmup) need_val $# "$1"; warmup="$2"; shift 2 ;;
    --timeout) need_val $# "$1"; timeout_s="$2"; shift 2 ;;
    --policy) need_val $# "$1"; policy="$2"; shift 2 ;;
    --state-root) need_val $# "$1"; state_root="$2"; shift 2 ;;
    --poll-us) need_val $# "$1"; poll_us="$2"; shift 2 ;;
    --settle-ms) need_val $# "$1"; settle_ms="$2"; shift 2 ;;
    --label) need_val $# "$1"; label="$2"; shift 2 ;;
    --id-prefix) need_val $# "$1"; id_prefix="$2"; shift 2 ;;
    --output) need_val $# "$1"; output="$2"; shift 2 ;;
    --print-budget) print_budget=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) err "invalid-argument" "unknown option"; exit 2 ;;
  esac
done

check_range() { # <名前> <値> <最小> <最大>
  [[ "$2" =~ $num_re ]] || { err "invalid-argument" "$1 must be a non-negative integer"; exit 2; }
  { [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; } || { err "invalid-argument" "$1 must be from $3 to $4"; exit 2; }
}

check_range "--trials" "$trials" 1 200
check_range "--warmup" "$warmup" 0 20
check_range "--timeout" "$timeout_s" 1 600
check_range "--poll-us" "$poll_us" 100 100000
check_range "--settle-ms" "$settle_ms" 0 5000
# --print-budget: 実行全体の所要時間の上限（秒）だけを出して終わる（launcher は起動しない）。外側の timeout
# （Makefile の restart-latency）はこの値を使う。内訳は「create・FCSUP1・running・各試行の待機 = (試行数 + 3) × --timeout」
# ＋「試行ごとの settle（秒へ切り上げ）と検証・子孫記録の余裕 2 秒」＋「後始末 60 秒（do_cleanup の上限約 20 秒に余裕）」。
if [ "$print_budget" -eq 1 ]; then
  printf '%s\n' "$(((trials + warmup + 3) * timeout_s + (trials + warmup) * ((settle_ms + 999) / 1000 + 2) + 60))"
  exit 0
fi
# 後始末の delete の上限（環境変数。--print-budget の後始末枠 60 秒に収まる値に限る）。
stop_wait_s="${RESTART_LATENCY_STOP_WAIT_S:-10}"
delete_timeout_s="${RESTART_LATENCY_DELETE_TIMEOUT_S:-20}"
check_range "RESTART_LATENCY_STOP_WAIT_S" "$stop_wait_s" 0 20
check_range "RESTART_LATENCY_DELETE_TIMEOUT_S" "$delete_timeout_s" 1 30
[ -n "$bin_dir" ] || { err "invalid-argument" "--bin-dir is required"; exit 2; }
[ -n "$bundle" ] || { err "invalid-argument" "--bundle is required"; exit 2; }
case "$policy" in on-failure | always) ;; *) err "invalid-argument" "--policy must be on-failure or always"; exit 2 ;; esac
[[ "$id_prefix" =~ $id_re ]] || { err "invalid-argument" "--id-prefix must match [A-Za-z0-9_-]{1,32}"; exit 2; }
if [ -n "$label" ] && ! [[ "$label" =~ $label_re ]]; then
  err "invalid-argument" "--label must match [A-Za-z0-9._-]{1,64}"; exit 2
fi
case "$bin_dir" in /*) ;; *) err "invalid-argument" "--bin-dir must be an absolute path"; exit 2 ;; esac
case "$systemd_run" in /*) ;; *) err "invalid-argument" "--systemd-run must be an absolute path"; exit 2 ;; esac
if [ -n "$state_root" ]; then
  case "$state_root" in /*) ;; *) err "invalid-argument" "--state-root must be an absolute path"; exit 2 ;; esac
fi
case "$bin_dir$systemd_run$bundle$state_root$output" in *$'\n'*) err "invalid-argument" "paths must not contain newlines"; exit 2 ;; esac
[ -d "$bundle" ] || { err "invalid-argument" "--bundle is not a directory"; exit 2; }
bundle="$(cd -- "$bundle" && pwd -P)" || { err "invalid-argument" "--bundle cannot be resolved"; exit 2; }
[ -z "$state_root" ] || [ -d "$state_root" ] || { err "invalid-argument" "--state-root is not a directory"; exit 2; }

# 祖先を含むディレクトリが他ユーザーに差し替えられないこと（verify-supervisor-independence.sh と同じ規則）。
dir_is_safe() {
  local d="$1" uid
  uid="$(id -u)"
  [ -n "$(find -P "$d" -maxdepth 0 -type d \( -user "$uid" -o -user 0 \) -print 2>/dev/null)" ] || return 1
  [ -z "$(find -P "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) ! -perm -1000 -print 2>/dev/null)" ]
}

path_chain_is_safe() { # <dir>
  local logical physical d parent depth=0
  logical="$(cd -- "$1" && pwd -L)" || return 1
  physical="$(cd -- "$1" && pwd -P)" || return 1
  [ "$logical" = "$physical" ] || return 1
  d="$physical"
  while :; do
    dir_is_safe "$d" || return 1
    parent="$(dirname -- "$d")"
    [ "$parent" = "$d" ] && break
    depth=$((depth + 1))
    [ "$depth" -le 256 ] || return 1
    d="$parent"
  done
}

for req in find id dirname; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
# --state-root の state.json は kill 対象 pid の入力になる。他ユーザーが差し替えられる場所は受け付けない。
if [ -n "$state_root" ] && ! path_chain_is_safe "$state_root"; then
  err "invalid-argument" "--state-root and the directories above it must be symlink-free, owned by you or root, and not writable by others (unless sticky)"
  exit 2
fi
uid_now="$(id -u)"
# 起動する 3 つの実行ファイル（CLI・supervisor の bin・systemd-run）を他ユーザーが差し替えられないこと。bin-dir 内は固定名で
# 解決し PATH 探索はしない。非 symlink の通常ファイルで実行可能・所有者が実行ユーザーか root・group / other 書き込み不可・祖先も安全。
check_exe() { # <表示名> <パス>
  if [ -L "$2" ] || [ ! -f "$2" ] || [ ! -x "$2" ]; then
    err "invalid-argument" "$1 must be an executable regular file (not a symlink)"
    exit 2
  fi
  if [ -z "$(find -P "$2" -maxdepth 0 -type f \( -user "$uid_now" -o -user 0 \) ! -perm -0020 ! -perm -0002 -print 2>/dev/null)" ]; then
    err "invalid-argument" "$1 must be owned by you or root and not writable by group or others"
    exit 2
  fi
  if ! path_chain_is_safe "$(dirname -- "$2")"; then
    err "invalid-argument" "the directories above $1 must be symlink-free, owned by you or root, and not writable by others (unless sticky)"
    exit 2
  fi
}
cli_bin="${bin_dir}/fandhe-container"
sup_bin="${bin_dir}/fandhe-container-supervisor"
check_exe "fandhe-container in --bin-dir" "$cli_bin"
check_exe "fandhe-container-supervisor in --bin-dir" "$sup_bin"
check_exe "--systemd-run" "$systemd_run"

if [ -n "$output" ]; then
  # 既存のパス（symlink・ディレクトリを含む）は拒否し上書きしない。公開は ln -T で「存在しない場合だけ作成」。
  if [ -e "$output" ] || [ -L "$output" ]; then
    err "invalid-argument" "output path already exists (refusing to overwrite; --output must be a new file)"
    exit 2
  fi
  output_dir="${output%/*}"
  [ "$output_dir" != "$output" ] || output_dir="."
  [ -n "$output_dir" ] || output_dir="/"
  [ -d "$output_dir" ] || { err "invalid-argument" "output directory does not exist"; exit 2; }
  if ! path_chain_is_safe "$output_dir"; then
    err "invalid-argument" "the path of --output must not contain symlinks, and every directory above it must be owned by you or root and not writable by others (unless sticky)"
    exit 2
  fi
  output_dir="$(cd -- "$output_dir" && pwd -P)" || { err "invalid-argument" "output directory cannot be resolved"; exit 2; }
  case "$output_dir" in
    /) output="/${output##*/}" ;;
    *) output="${output_dir}/${output##*/}" ;;
  esac
fi

# --- 前提確認（欠如は 3。0 を返して合格に見せない） ---
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then err "unsupported-os" "bash 5 or later is required"; exit 3; fi
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then err "unsupported-os" "only Linux is supported"; exit 3; fi
for req in mktemp ln grep sleep kill uname od tr jq setsid env rm mkfifo timeout; do
  command -v "$req" >/dev/null 2>&1 || { err "unsupported-os" "$req is required"; exit 3; }
done
[ -r /proc/self/stat ] && [ -r /proc/uptime ] || { err "unsupported-os" "/proc is required"; exit 3; }
# supervisor は rootful 起動を拒否する（SEC-5）。0 を返して合格に見せないよう起動前に 3 で止める。
if [ "$uid_now" -eq 0 ]; then err "unsupported-os" "supervisor rejects rootful start (SEC-5); run as a non-root user"; exit 3; fi
# supervisor の既定バックオフ（crates/supervisor/src/restart.rs の DEFAULT_BACKOFF。自己テストが同値を機械照合する）。
readonly supervisor_backoff_ms=100

# --- 状態 ---
workdir=""
owner_tok=""
launcher_pid=""
launcher_start=""
outfd=""
report_pid=""
report_buf=""
intended_rc=""
in_launch=0
pending_rc=""
reported="null"
reported_err=0
collect_log=0
snap_seen=0
keep_state=0
# 後始末の delete（OCI-6）。delete_wanted=1 は「stopped を確認できた」ことを表す。delete_result は結果 JSON の
# cleanup.delete（ok / skipped）、delete_reason は skipped の理由。
delete_wanted=0
delete_result=""
delete_reason=""
last_snap_cs=0
# 本計測への帰属を証明済みのプロセスの「pid → 起動時刻」（試行で kill 対象にしたコンテナ側プロセスと、launcher の
# 生存中に採取した子孫のスナップショット）。後始末で全件を同一性照合のうえ回収する。
declare -A tracked=()
# state.json に現れたが帰属を証明できなかった生存 pid の「pid → 起動時刻」。シグナルは送らず、後始末の最後まで
# 帰属を証明できずに生存していれば終了コード 4 にする。launcher より前に起動していたものは入れない（無関係と確定）。
declare -A suspects=()
cleaned=0
napfd=""
out_tmp=""
state_file=""
container_id=""

# 待機は組み込みの read -t（fork しない）で行う。ポーリング中に一過性の子プロセスを作らないため。
nap() { read -r -t "$1" -u "$napfd" || true; }

# マイクロ秒の現在時刻（EPOCHREALTIME の小数点は locale により , の場合がある）。計測値にだけ使う。
now_us() { local t="$EPOCHREALTIME"; t="${t/[.,]/}"; REPLY_US=$((10#$t)); }
# 単調時計（/proc/uptime。1/100 秒）。待機の期限はすべてこちらで判定する（壁時計の変更で期限がずれない）。
up_cs() { local up; read -r up _ </proc/uptime; up="${up/[.,]/}"; REPLY_CS=$((10#$up)); }

# /proc/<pid>/stat から状態・ppid・session・起動時刻（field 22）を得る。comm は空白・括弧・改行を含み得るため
# 全体を読み、最後の ") " 以降だけを使う（comm に ") Z " 等を仕込んでも状態を偽れない）。fork しない。
proc_info() { # <pid> → REPLY_STATE / REPLY_PPID / REPLY_SID / REPLY_START（読めない・形式不正は return 1）
  local s="" rest
  local -a f=()
  [[ "$1" =~ $pid_re ]] || return 1
  { IFS= read -r -d '' s <"/proc/$1/stat" || true; } 2>/dev/null
  [ -n "$s" ] || return 1
  rest="${s##*) }"
  read -ra f <<<"$rest"
  [ "${#f[@]}" -ge 20 ] || return 1
  [[ "${f[0]}" =~ ^[A-Za-z]$ && "${f[1]}" =~ $dig_re && "${f[3]}" =~ $dig_re && "${f[19]}" =~ $dig_re ]] || return 1
  REPLY_STATE="${f[0]}"
  REPLY_PPID="${f[1]}"
  REPLY_SID="${f[3]}"
  REPLY_START="${f[19]}"
}

# 生存判定。kill -0 はゾンビも真になるため /proc の状態が Z（ゾンビ）・X（終了済み）でないことを見る。
alive() { # <pid>
  proc_info "$1" || return 1
  case "$REPLY_STATE" in Z | X | x) return 1 ;; esac
  return 0
}

# pid が「記録した起動時刻のまま生存している同一プロセス」か（PID 再利用の判別）。記録が空なら不一致扱い
# （同一性を証明できないものには送らない）。第 3 引数（親 pid）を渡すと親の一致も要求する。
same_proc() { # <pid> <記録した起動時刻> [<親 pid>]
  [ -n "${2:-}" ] || return 1
  alive "$1" || return 1
  [ "$REPLY_START" = "$2" ] || return 1
  [ -z "${3:-}" ] || [ "$REPLY_PPID" = "$3" ]
}

# 本スクリプトのシグナル送信はすべてここを通す（kill を直接呼ぶ箇所は他にない）。送信先は pid 単体だけで、
# プロセスグループ・セッション宛（負の pid・0）や名前一致（pkill）では送らない。直前に same_proc で同一性を
# 再照合し、照合から kill(2) までは組み込みコマンドだけ（fork・待機なし）にして窓を最小にする。
# 戻り値: 0 = 送信した / 1 = 同一性を確認できず送信しなかった / 2 = kill が失敗した。
sig_same_proc() { # <シグナル名> <pid> <記録した起動時刻> [<親 pid>]
  [[ "$2" =~ $pid_re ]] || return 1
  if [ "$2" -le 1 ] || [ "$2" = "$$" ]; then return 1; fi
  same_proc "$2" "$3" "${4:-}" || return 1
  kill "-$1" "$2" 2>/dev/null || return 2
}

# launcher が起動時に記録した同一プロセスのまま生存しているか。launcher は本スクリプトの直接の子なので
# 起動時刻に加えて親 pid（$$）の一致も要求する。
launcher_ok() { [ -n "$launcher_pid" ] && same_proc "$launcher_pid" "$launcher_start" "$$"; }

# /proc/<pid>/environ の NUL 区切りエントリに FANDHE_BENCH_OWNER=<token> が完全一致で含まれるか。
# 他プロセスの環境変数値に部分文字列として含まれるだけの場合（grep -F の部分一致）は所有と認めない。
env_owned() { # <pid>
  local e
  [ -n "$owner_tok" ] || return 1
  while IFS= read -r -d '' e; do
    [ "$e" = "FANDHE_BENCH_OWNER=$owner_tok" ] && return 0
  done <"/proc/$1/environ" 2>/dev/null
  return 1
}

# pid が launcher の子孫か（PPid 連鎖を 64 段まで辿る）。成功時の REPLY_START は対象 pid 自身の起動時刻。
# 連鎖の途中で pid が再利用されても誤認しないよう、(1) 親の起動時刻は子以前、(2) launcher へ到達した後に
# launcher と連鎖の全プロセスが記録した起動時刻のまま存在すること、を確認する（辿っている間ずっと同じ
# プロセスだったことの証明。孤児の引き取り先は祖先か init なので (1) は正当な木で常に成り立つ）。
is_descendant() { # <pid>
  local p="$1" depth=0 i
  local -a cp=() cs=()
  [ -n "$launcher_pid" ] || return 1
  while [ "$depth" -lt 64 ]; do
    proc_info "$p" || return 1
    if [ "$depth" -gt 0 ] && [ "$REPLY_START" -gt "${cs[$((depth - 1))]}" ]; then return 1; fi
    cp+=("$p")
    cs+=("$REPLY_START")
    p="$REPLY_PPID"
    if [ "$p" = "$launcher_pid" ]; then
      [ "$launcher_start" -le "$REPLY_START" ] || return 1
      launcher_ok || return 1
      for i in "${!cp[@]}"; do
        proc_info "${cp[$i]}" || return 1
        [ "$REPLY_START" = "${cs[$i]}" ] || return 1
      done
      REPLY_START="${cs[0]}"
      return 0
    fi
    [ "$p" -gt 1 ] || return 1
    depth=$((depth + 1))
  done
  return 1
}

# 帰属を証明済みのプロセスとして記録する（同一 pid は起動時刻を更新。pid 再利用後の古い記録は死んでいるので無害）。
track_pid() { tracked["$1"]="$2"; }

# launcher の生存中に、その子孫（state.json に現れない補助プロセス・トークンを継承しないプロセスを含む）を
# 「pid → 起動時刻」で tracked へ記録する（scripts/verify-supervisor-independence.sh の track_descendants と同じ考え方）。
# launcher 停止後は親子関係が失われ、孤児の帰属を証明できなくなるため、停止前に採取する。
# /proc の走査は非アトミックなので、走査後に launcher の同一性を確認し、各子孫を親から順に「親が検証済み・
# 親の起動時刻は子以前・走査時と同じ起動時刻で今も存在」の条件で検証できたものだけ記録する。上限 4096 件。
snapshot_descendants() {
  local d p q e n=0
  local -A sp=() ss=() ch=() ok=()
  local -a queue=() next=() order=()
  launcher_ok || return 1
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    proc_info "$p" || continue
    sp["$p"]="$REPLY_PPID"
    ss["$p"]="$REPLY_START"
  done
  launcher_ok || return 1
  for p in "${!sp[@]}"; do ch["${sp[$p]}"]+=" $p"; done
  queue=("$launcher_pid")
  while [ "${#queue[@]}" -gt 0 ] && [ "$n" -lt 4096 ]; do
    next=()
    for q in "${queue[@]}"; do
      for p in ${ch[$q]:-}; do
        [ "$n" -lt 4096 ] || break
        order+=("$p:$q")
        next+=("$p")
        n=$((n + 1))
      done
    done
    queue=(${next[@]+"${next[@]}"})
  done
  ok["$launcher_pid"]=1
  ss["$launcher_pid"]="$launcher_start"
  for e in ${order[@]+"${order[@]}"}; do
    p="${e%%:*}"
    q="${e#*:}"
    [ -n "${ok[$q]:-}" ] || continue
    [ "${ss[$q]}" -le "${ss[$p]}" ] || continue
    proc_info "$p" || continue
    [ "$REPLY_START" = "${ss[$p]}" ] || continue
    ok["$p"]=1
    track_pid "$p" "${ss[$p]}"
  done
  # 「観測済み」にできるのは、コンテナの init（supervisor が報告した pid・state.json の pid）を記録できたときだけ。
  # 一時的な中間プロセスを 1 件記録しただけでは、コンテナ全体を追跡できた証明にならない（untracked の fail-closed を
  # 飛ばさないため。SUP-5）。
  if init_tracked; then snap_seen=1; fi
  return 0
}

# コンテナの init（FCSUP1 OK の報告 pid か state.json の pid）の同一性（pid・起動時刻）を tracked へ記録済みなら 0。
# state.json を読み直す（ST_* を更新する。呼び出し側は read_state し直してから ST_* を使う）。
init_tracked() {
  local ip
  read_state || true
  for ip in "$report_pid" "${ST_PID:-}"; do
    if [ -n "$ip" ] && [ -n "${tracked[$ip]:-}" ]; then return 0; fi
  done
  return 1
}

# 待機ループから呼ぶ間引きつきスナップショット（0.2 秒に 1 回まで）。launcher が途中で異常終了しても、
# それまでに見えた子孫は記録済みになる。
snapshot_throttled() {
  up_cs
  [ "$REPLY_CS" -ge $((last_snap_cs + 20)) ] || return 0
  last_snap_cs="$REPLY_CS"
  snapshot_descendants || true
}

# state.json を純 bash で読む（計測区間内で jq を fork しない）。1 MiB 上限・symlink 拒否・通常ファイルのみ。
# 結果: ST_STATUS / ST_PID / ST_COUNT / ST_RAW。読めない・途中の内容は return 1（呼び出し側が再ポーリング）。
read_state() {
  local c=""
  ST_STATUS="" ST_PID="" ST_COUNT="" ST_RAW=""
  [ -L "$state_file" ] && return 1
  [ -f "$state_file" ] || return 1
  IFS= read -r -d '' -N 1048577 c <"$state_file" 2>/dev/null || true
  [ "${#c}" -le 1048576 ] || return 1
  [[ "$c" =~ \"status\"[[:space:]]*:[[:space:]]*\"([a-z]+)\" ]] || return 1
  ST_STATUS="${BASH_REMATCH[1]}"
  [[ "$c" =~ \"restartCount\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]] || return 1
  ST_COUNT=$((10#${BASH_REMATCH[1]}))
  if [[ "$c" =~ \"pid\"[[:space:]]*:[[:space:]]*([0-9]{1,9})[^0-9] ]]; then ST_PID=$((10#${BASH_REMATCH[1]})); else ST_PID=""; fi
  ST_RAW="$c"
  return 0
}

# 観測が終わった後に state.json を再読込して jq で厳密検証する。id 一致・status=running・観測した新 pid・
# restartCount == 旧 + 1 のすべてを満たさなければ失敗（ポーリング後に状態が変わった試行は採用しない）。
# jq には read_state が上限つきで読んだ内容を渡す（jq にファイルを直接開かせない）。
validate_state_strict() { # <観測した新 pid> <期待 restartCount>
  read_state || return 1
  jq -e --arg id "$container_id" --argjson pid "$1" --argjson cnt "$2" \
    '.id == $id and .status == "running" and (.pid|type=="number") and .pid == $pid and (.restartCount|type=="number") and .restartCount == $cnt' \
    <<<"$ST_RAW" >/dev/null 2>&1
}

# 後始末の delete（OCI-6）。本番の start と同じ包み込みで CLI の delete を 1 回呼ぶ。成功は 0、拒否・期限超過は 1。
# stdin・stdout は /dev/null、stderr は作業ディレクトリ（0700）内のファイルへ。コードは先頭 4096 バイトから
# `"code":"[A-Z_]{1,32}"` だけを取り出す（message・パスは出さない。外部入力は信頼しない）。
run_delete() {
  local rc=0 code="" errf="$workdir/delete.err"
  : >"$errf" || return 1
  timeout --kill-after=5 "$delete_timeout_s" "$systemd_run" --user --scope --quiet -p Delegate=yes -- \
    "$cli_bin" --root "$state_dir" delete "$container_id" </dev/null >/dev/null 2>"$errf" || rc=$?
  if [ "$rc" -eq 0 ]; then
    delete_result="ok"
    return 0
  fi
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    code="TIMEOUT"
  else
    code="$(head -c 4096 -- "$errf" 2>/dev/null | grep -o '"code":"[A-Z_]\{1,32\}"' | head -n 1 | cut -d'"' -f4 || true)"
    [ -n "$code" ] || code="UNPARSED"
  fi
  err "cleanup-failed" "delete was rejected ($code)"
  return 1
}

# 計測区間の外で、delete できる状態（stopped）まで進める。on-failure は最後の再起動で回数を使い切っているので、最後の
# コンテナ側プロセスへ SIGKILL を 1 回送る（同一性を再照合する sig_same_proc 経由）。supervisor は RetriesExhausted で
# Stopped を記録して自分で終わる。stopped と launcher の終了を期限内に確認できたときだけ delete_wanted=1 にする。
stop_for_delete() {
  local end
  if [ "$policy" = "on-failure" ] && [ "$stop_wait_s" -gt 0 ] && [ -n "${new_pid:-}" ]; then
    sig_same_proc KILL "$new_pid" "$new_start" || true
    up_cs; end=$((REPLY_CS + stop_wait_s * 100))
    while :; do
      if read_state && [ "$ST_STATUS" = "stopped" ] && ! launcher_ok; then
        delete_wanted=1
        return 0
      fi
      up_cs
      [ "$REPLY_CS" -lt "$end" ] || break
      nap "$poll_s"
    done
  fi
  delete_result="skipped"
  delete_reason="state-not-stopped"
}

# 起動契約の差し替え点（根拠は冒頭コメント）。supervisor の起動行を LAUNCH_CMD へ組む。
build_launch_cmd() {
  local pol="$policy"
  [ "$policy" = "always" ] || pol="on-failure:$((trials + warmup))"
  LAUNCH_CMD=("$systemd_run" --user --scope --quiet -p Delegate=yes -- "$sup_bin" start --root "$state_dir" --restart "$pol" "$container_id")
}

# create を期限付きで実行する（REPAIR-5）。失敗は終了コードだけを出す（出力・パスは出さない）。
sup_create() {
  local rc=0
  timeout --kill-after=5 "$timeout_s" "$cli_bin" --root "$state_dir" create --bundle "$bundle" "$container_id" </dev/null >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || fail "create failed (exit $rc)"
}

# 結果チャネル（FIFO）から FCSUP1 の 1 行を読み、OK なら report_pid を記録して 0。ERR・書式不正は計測失敗。未到着は 1。
# 引数 <1 バイトあたりの待ち秒>（既定 0.01。launcher 終了後の読み切りだけ長めを渡す）。
# 1 バイトずつ `read -N 1` で読む（Issue #2213・SUP-3・REPAIR-5）。旧実装の `read -r -n 640 -t 0.01` は、bash 5.2 の
# read.def が区切り文字（改行）を読んで break した後の check_read_timeout で期限切れを検知すると、改行を消費して
# 完全な行を変数へ入れたまま終了コード 142 を返す。これを「行の途中」と見て改行を待ち続けると、supervisor は
# 1 行しか書かないため改行は二度と来ず、FCSUP1 OK 待ちが --timeout まで固まった（並列負荷で読みがプリエンプトされると起きる）。
# -N は区切りを無視して改行もデータとして変数へ入れるため、期限切れの longjmp でも取りこぼさない。
# 終了コードより先に ch を見る（期限切れでも ch に入ったバイトは有効なデータ）。-n 640 -t に戻さないこと。
# -N は bash 4.1 以上が必要だが、本スクリプトは {var} の fd 割り当てを使う Linux 限定で要件は変わらない。
# 行は 640 バイトを上限とし、行の途中で切れても report_buf は呼び出しをまたいで保持して次回に継ぎ足す。
sup_report() {
  local wait_s="${1:-0.01}" ch rc line
  [ -z "$report_pid" ] || return 0
  while :; do
    ch="" rc=0
    IFS= read -r -N 1 -t "$wait_s" -u "$outfd" ch || rc=$?
    [ -n "$ch" ] || return 1
    if [ "$ch" != $'\n' ]; then
      report_buf+="$ch"
      [ "${#report_buf}" -lt 640 ] || fail "supervisor printed an unrecognized report line"
      continue
    fi
    line="$report_buf"
    report_buf=""
    break
  done
  if [[ "$line" =~ ^FCSUP1\ OK\ ([1-9][0-9]{0,9})$ ]]; then
    report_pid="${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$line" =~ ^FCSUP1\ ERR\ ([A-Z_]{1,32})\ ([0-9]{1,3})\  ]]; then
    fail "supervisor reported ERR ${BASH_REMATCH[1]} (exit ${BASH_REMATCH[2]})"
  fi
  fail "supervisor printed an unrecognized report line"
}

# コンテナ ID を supervisor ログのファイル名の語幹へ変換する（RotatingFileSink の encode_file_stem と同じ規則。
# 大文字 X は `_x`、`_` は `__`。大文字小文字非区別の FS で別 ID が衝突しないための可逆表現。IO-5）。
# ID は [A-Za-z0-9_-] と '-' 区切りの乱数だけで、'.' を含まず予約デバイス名にもならない。bash 3.2 でも動く書き方にする。
encode_log_stem() { # <id>
  local in="$1" out="" c i
  for ((i = 0; i < ${#in}; i++)); do
    c="${in:i:1}"
    case "$c" in
      _) out+="__" ;;
      [A-Z]) out+="_$(printf '%s' "$c" | tr 'A-Z' 'a-z')" ;;
      *) out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

# launcher ログから副系列を集計する（launcher 停止後に do_cleanup から呼ぶ。非信頼入力として値域を検証し、
# 数値のみ採用する）。結果は reported（null または改行区切り数値）・reported_err（失敗した restart 行の有無）。
collect_reported() {
  local -a rep=()
  # supervisor の構造化ログは状態ルート配下の <root>/@supervisor-logs/<id>.log（古い世代 .log.2 .log.1 が先）に
  # `stderr <JSON 1 行>` 形式で残る（#2067・REPAIR-4）。launcher の stderr（err.log）には出ないため、世代順に連結し、
  # 接頭辞 `stderr ` の行だけを JSON として取り出す。
  local logbase f
  logbase="$state_dir/@supervisor-logs/$(encode_log_stem "$container_id")"
  local merged="$workdir/sup-merged.log"
  : >"$merged"
  for f in "$logbase.log.2" "$logbase.log.1" "$logbase.log"; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then
      grep -a '^stderr ' "$f" 2>/dev/null | cut -c8- >>"$merged" || true
    fi
  done
  [ -s "$merged" ] || return 0
  # jq の出力を grep -q へ直接パイプすると、失敗行が多く出力が複数回の書き込みになったとき、grep が先に
  # 終わった後の jq の書き込みが SIGPIPE（141）になり、pipefail で判定が偽（失敗の見落とし）になる。
  # 変数に取ってから照合する（#1726）。
  local err_hits=""
  if err_hits="$(jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="error") | "x"' "$merged" 2>/dev/null)" &&
    grep -q x <<<"$err_hits"; then
    reported_err=1
    return 0
  fi
  mapfile -t rep < <(jq -Rre 'fromjson? | select(type=="object" and .component=="supervisor.monitor" and .operation=="restart" and .result=="ok") | .elapsed_us | select(type=="number" and .>=0 and .==floor and .<=3600000000)' "$merged" 2>/dev/null || true)
  if [ "${#rep[@]}" -eq "$total" ]; then
    reported="$(printf '%s\n' "${rep[@]:$warmup}")"
  fi
}

# state.json の pid のうち launcher の子孫と確認できなかった生存プロセスを記録する（試行中と後始末から呼ぶ）。
# launcher より前から動いていたプロセスは本計測の生成物ではあり得ない（無関係と確定）ので記録しない。
# それ以外は帰属不明として suspects に入れ、後始末で帰属を再判定する。いずれの場合もシグナルは送らない。
note_suspect() { # <pid>
  alive "$1" || return 0
  if [ -n "$launcher_start" ] && [ "$REPLY_START" -lt "$launcher_start" ]; then return 0; fi
  suspects["$1"]="$REPLY_START"
}

# 追跡済みで、いまも launcher の session に属して生存しているプロセスがあるか。あれば session 番号
# （= launcher の pid）は本計測の session に割り当てられたままで、再利用されていないと証明できる。
session_anchor_alive() {
  local a
  for a in "${!tracked[@]}"; do
    if same_proc "$a" "${tracked[$a]}" && [ "$REPLY_SID" = "$launcher_pid" ]; then return 0; fi
  done
  return 1
}

# 帰属不明の pid（suspects）と、launcher 停止後の state.json の pid を再判定する。launcher 停止後は子孫関係を
# 辿れないので、帰属の根拠は (1) 環境変数に本実行の所有トークン（128 bit 乱数）の完全一致エントリを持つ、
# (2) launcher（setsid の leader）の session に属し、かつ同じ session に追跡済みの生存プロセスがいる
# （session_anchor_alive。launcher 終了後に同じ番号の session が別物として作り直されていないことの証明）、
# のいずれかに限る。起動時刻が launcher 以降というだけでは根拠にしない。証明できたものは tracked へ移し、
# できないものは kill せず警告を出して 1 を返す（呼び出し側が終了コード 4 にする）。
# 追跡済みプロセスを回収する前に呼ぶこと（(2) の証明に追跡済みの生存プロセスを使うため）。
attribute_suspects() {
  local p s sid rc=0
  if [ -n "$state_file" ] && [ -n "$launcher_pid" ] && read_state && [ -n "$ST_PID" ]; then
    p="$ST_PID"
    if [ "$p" != "$$" ] && ! same_proc "$p" "${tracked[$p]:-}"; then note_suspect "$p"; fi
  fi
  for p in "${!suspects[@]}"; do
    s="${suspects[$p]}"
    same_proc "$p" "$s" || continue
    sid="$REPLY_SID"
    if env_owned "$p" && same_proc "$p" "$s"; then
      track_pid "$p" "$s"
    elif [ "$sid" = "$launcher_pid" ] && session_anchor_alive && same_proc "$p" "$s" && [ "$REPLY_SID" = "$launcher_pid" ]; then
      track_pid "$p" "$s"
    else
      printf 'warning: pid %s in state.json cannot be attributed to this run; not signaling it\n' "$p" >&2 || true
      rc=1
    fi
  done
  return "$rc"
}

# 環境変数トークンが完全一致する生存プロセス（孤児化した launcher の子孫を含む）を "pid:起動時刻" で OWNED へ入れる。
# grep -F は候補の絞り込みだけに使い、所有判定は env_owned で行う。起動時刻は environ を読む前に控え、後で再照合する。
owned_scan() {
  local f p s
  OWNED=()
  [ -n "$owner_tok" ] || return 0
  while IFS= read -r f; do
    p="${f#/proc/}"
    p="${p%%/*}"
    [ "$p" != "$$" ] || continue
    alive "$p" || continue
    s="$REPLY_START"
    env_owned "$p" || continue
    if same_proc "$p" "$s"; then OWNED+=("$p:$s"); fi
  done < <(grep -l -a -F -s -- "FANDHE_BENCH_OWNER=$owner_tok" /proc/[0-9]*/environ 2>/dev/null || true)
}

tracked_alive() {
  local p
  for p in "${!tracked[@]}"; do
    if same_proc "$p" "${tracked[$p]}"; then return 0; fi
  done
  return 1
}

# 回収。戻り値 0 = 回収確認済み / 非 0 = 残存または帰属不明（呼び出し側が終了コード 4 にする）。
# 所要時間の上限は約 20 秒（launcher の停止待ち 5 + 2 秒、回収の再試行 5 秒、/proc 走査）。--print-budget は 60 秒を見込む。
do_cleanup() {
  local i d p rc=0 untracked=0
  [ "$cleaned" -eq 0 ] || return 0
  cleaned=1
  trap '' INT TERM HUP
  # 1. launcher の生存中に子孫を記録する（停止後は親子関係を辿れない）。
  if launcher_ok; then snapshot_descendants || true; fi
  if [ -n "$launcher_pid" ] && [ "$snap_seen" -eq 0 ]; then
    # コンテナの init（報告 pid・state.json の pid）を記録できていない。launcher の生存・FCSUP1 ERR の報告・
    # 一時的な中間プロセスの観測は、init の追跡も未生成も証明しない（最後のスナップショットの後に init が生まれ、
    # その直後に launcher を止める順序が成立する。製品の start_contract.rs は ERR を後始末より先に報告し、
    # start_entry.rs には未回収ハンドルを伴う失敗経路もある。init は所有トークンも継承しない）。後段で init の帰属を
    # 証明できなければ、追跡不能として終了コード 4 にし、手動回収のため状態を残す（SUP-5）。
    untracked=1
  fi
  # 2. launcher を止める（同一性を確認できる間だけ送る。先に終了して PID が再利用されていれば送らない）。
  if launcher_ok; then
    sig_same_proc TERM "$launcher_pid" "$launcher_start" "$$" || true
    for ((i = 0; i < 100; i++)); do
      launcher_ok || break
      nap 0.05
    done
    # TERM で止まらなかった場合だけ届く（既に終了していれば sig_same_proc は送らない）。
    sig_same_proc KILL "$launcher_pid" "$launcher_start" "$$" || true
    for ((i = 0; i < 40; i++)); do
      launcher_ok || break
      nap 0.05
    done
  fi
  # 3. 帰属不明の pid を再判定する（追跡済みプロセスを回収する前に行う）。証明できなければ残存として 4。
  attribute_suspects || rc=4
  # 4. launcher 停止後なので restart ログは出尽くしている。副系列はここで集計する。
  if [ "$collect_log" -eq 1 ]; then collect_reported; fi
  # 5. トークン一致の所有プロセスと追跡済みプロセスを回収する。消えるまで最大 5 秒再試行する。
  for ((i = 0; i < 25; i++)); do
    owned_scan
    if [ "${#OWNED[@]}" -eq 0 ] && ! tracked_alive; then break; fi
    for d in ${OWNED[@]+"${OWNED[@]}"}; do
      p="${d%%:*}"
      if env_owned "$p"; then sig_same_proc KILL "$p" "${d#*:}" || true; fi
    done
    for p in "${!tracked[@]}"; do sig_same_proc KILL "$p" "${tracked[$p]}" || true; done
    [ -n "$napfd" ] || break
    nap 0.2
  done
  # 6. 最終確認。再試行の後に現れたものを含め、所有・追跡済みプロセスが 1 つでも生存していれば残存。
  owned_scan
  if [ "${#OWNED[@]}" -gt 0 ] || tracked_alive; then rc=4; fi
  # 追跡不能の確定は init の記録の有無だけで行う。中間プロセスの記録や所有トークンの観測（init は継承しない）は
  # コンテナ全体の追跡の証明にならない。attribute_suspects が init を帰属させていれば init_tracked が真になる。
  if [ "$untracked" -eq 1 ] && ! init_tracked; then
    printf 'warning: the launcher exited before the container init was recorded; container-side processes cannot be tracked (state kept at %s)\n' "${workdir:-<none>}" >&2 || true
    rc=4
    keep_state=1
  fi
  if [ -n "$launcher_pid" ]; then
    if launcher_ok; then
      rc=4
    elif [ -z "$launcher_start" ] && alive "$launcher_pid" && [ "$REPLY_PPID" = "$$" ]; then
      rc=4 # 起動時刻を記録できず同一性を確認できないまま生存している子（シグナルは送っていない）
    else
      wait "$launcher_pid" 2>/dev/null || true
    fi
  fi
  # 7. 後始末の正常系: プロセスの回収を確認できた（rc=0）うえで stopped を確認済みなら、CLI の delete で状態を消す。
  #    拒否・期限超過は後始末失敗（4）にして状態を残す（握りつぶさない）。
  if [ "$delete_wanted" -eq 1 ] && [ "$rc" -eq 0 ]; then
    if ! run_delete; then rc=4; fi
  fi
  # 回収失敗（rc=4）の全経路で作業ディレクトリを残し、手動回収のため場所を通知する（SUP-5）。
  if [ "$rc" -eq 4 ] && [ -n "$workdir" ] && [ "${keep_state:-0}" -eq 0 ]; then
    keep_state=1
    printf 'warning: cleanup incomplete; state kept at %s\n' "$workdir" >&2 || true
  fi
  if [ -n "$workdir" ] && [ "${keep_state:-0}" -eq 0 ]; then rm -rf -- "$workdir" 2>/dev/null || true; fi
  if [ -n "$state_root" ] && [ -n "$container_id" ] && [ "$rc" -eq 0 ] && [ "$delete_result" != "ok" ]; then
    # --state-root は操作者の領域。<id>/ は削除しない（残置を通知する）。
    printf 'note: left state entry for id %s under --state-root (operator-owned)\n' "$container_id" >&2 || true
  fi
  return "$rc"
}

# 終了コードは finish 経由で明示したものだけを返す。set -e による想定外の中断（jq 等の終了コードが 2〜4 と
# 偶然一致する場合を含む）は計測失敗（1）に正規化し、引数エラー・前提欠如・後始末失敗と取り違えさせない。
finish() { intended_rc="$1"; exit "$1"; }

# shellcheck disable=SC2329 # EXIT trap から呼ぶ
on_exit() {
  local rc=$?
  trap '' INT TERM HUP
  if [ -n "$intended_rc" ]; then
    rc="$intended_rc"
  else
    err "measurement-failed" "unexpected internal failure (status $rc); no result is published"
    rc=1
  fi
  if ! do_cleanup; then
    err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
    rc=4
  fi
  [ -z "$out_tmp" ] || rm -f -- "$out_tmp" 2>/dev/null || true
  trap - EXIT
  exit "$rc"
}

# launcher の起動から pid・起動時刻の記録までの間に届いたシグナルは保留し、記録後に処理する
# （記録前に後始末へ入ると、起動直後の launcher を止められないまま終了し得る）。
# shellcheck disable=SC2329 # INT・TERM・HUP trap から呼ぶ
on_signal() {
  if [ "$in_launch" -eq 1 ]; then pending_rc="$1"; else finish "$1"; fi
}
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP

fail() { err "measurement-failed" "$1"; finish 1; }

# --- 準備 ---
umask 077
workdir="$(mktemp -d)"
mkfifo "$workdir/nap.fifo"
exec {napfd}<>"$workdir/nap.fifo"
owner_tok="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$owner_tok" =~ ^[0-9a-f]{32}$ ]] || { err "unsupported-os" "cannot generate an owner token"; finish 3; }
rand8="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$rand8" =~ ^[0-9a-f]{8}$ ]] || { err "unsupported-os" "cannot generate a container id"; finish 3; }
container_id="${id_prefix}-${rand8}"
if [ -n "$state_root" ]; then
  state_dir="$state_root"
else
  state_dir="$workdir/state"
  mkdir -m 0700 "$state_dir"
fi
state_file="$state_dir/$container_id/state.json"
printf -v poll_s '0.%06d' "$poll_us"
printf -v settle_s '%d.%03d' "$((settle_ms / 1000))" "$((settle_ms % 1000))"
total=$((trials + warmup))

build_launch_cmd
sup_create
# 結果チャネルは FIFO（supervisor は FIFO 以外の標準出力を拒否する）。読み手を先に RDWR で開く。
mkfifo "$workdir/out.fifo"
exec {outfd}<>"$workdir/out.fifo"
in_launch=1
(
  exec setsid env "FANDHE_BENCH_OWNER=$owner_tok" "${LAUNCH_CMD[@]}" \
    >"$workdir/out.fifo" 2>"$workdir/err.log" </dev/null
) &
launcher_pid=$!
# 直接の子（親が $$）であることを確かめてから起動時刻を記録する。以後の同一性照合はこの記録だけを根拠にする。
if proc_info "$launcher_pid" && [ "$REPLY_PPID" = "$$" ]; then launcher_start="$REPLY_START"; fi
in_launch=0
[ -z "$pending_rc" ] || finish "$pending_rc"
[ -n "$launcher_start" ] || fail "could not record the launcher start time (the launcher exited immediately or /proc is unreadable)"

deadline_wait() { # <説明> : 条件関数 "$@" が真になるまで --timeout まで待つ（期限は単調時計）
  local what="$1" end
  shift
  up_cs
  end=$((REPLY_CS + timeout_s * 100))
  while ! "$@"; do
    if ! launcher_ok; then
      # launcher が報告の直後に終了した場合、ERR の行が FIFO に残っている。先に読んで原因（エラーコード）を報告する。
      # ERR・書式不正なら sup_report 内の fail で終了する。
      # 書き手は終了済みで残りは FIFO 内にある。負荷で 1 回の読みが途中までになっても入力が尽きるまで読み切る
      # （read -t 0 は消費せず入力の有無だけ確かめる。毎回 1 バイト以上消費するか 640 バイト上限で fail するため有限。Issue #2213）。
      if [ "$what" = "FCSUP1 OK" ]; then
        while [ -z "$report_pid" ] && read -r -t 0 -u "$outfd"; do sup_report 1 || break; done
      fi
      fail "launcher exited while waiting for $what"
    fi
    up_cs
    [ "$REPLY_CS" -lt "$end" ] || fail "timed out waiting for $what"
    snapshot_throttled
    nap "$poll_s"
  done
}

# shellcheck disable=SC2329 # deadline_wait へ関数名で渡す
ready_seen() { sup_report; }
running_seen() { read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ]; }

deadline_wait "FCSUP1 OK" ready_seen
deadline_wait "the container to be running in state.json" running_seen
[ "$ST_PID" = "$report_pid" ] || fail "state.json pid differs from the pid reported by the supervisor"

vals=()
for ((n = 1; n <= total; n++)); do
  if ! running_seen; then fail "state.json is not in the running state before trial $n"; fi
  old_pid="$ST_PID"
  old_count="$ST_COUNT"
  launcher_ok || fail "launcher exited before trial $n"
  # kill の条件: state.json の pid が launcher の子孫であること（帰属の証明）と、送信直前の同一性再照合。
  # 子孫と確認できない pid にはシグナルを送らず失敗にする（偽造・無関係・契約違反）。後始末で残存を判定する。
  if ! is_descendant "$old_pid"; then
    note_suspect "$old_pid"
    fail "pid in state.json is not a descendant of the launcher; refusing to send a signal"
  fi
  start1="$REPLY_START"
  track_pid "$old_pid" "$start1"
  up_cs; up0="$REPLY_CS"
  end_cs=$((up0 + timeout_s * 100))
  # 計測開始時刻は同一性の再照合（sig_same_proc 内）の前に取る。再照合の所要時間は observed に含まれるが
  # （上側推定のまま）、照合と kill(2) の間に時刻取得を挟まない。
  now_us; t0="$REPLY_US"
  sig_rc=0
  sig_same_proc KILL "$old_pid" "$start1" || sig_rc=$?
  case "$sig_rc" in
    0) ;;
    1) fail "container process changed or exited before the signal in trial $n; no signal was sent" ;;
    *) fail "could not signal the container process in trial $n" ;;
  esac
  t1=""
  while :; do
    if read_state && [ "$ST_STATUS" = "running" ] && [ -n "$ST_PID" ] && [ "$ST_PID" != "$old_pid" ]; then
      now_us; t1="$REPLY_US"
      [ "$ST_COUNT" -eq $((old_count + 1)) ] || fail "restartCount jumped from $old_count to $ST_COUNT in trial $n"
      break
    fi
    launcher_ok || fail "launcher exited before the restart was observed in trial $n"
    up_cs
    [ "$REPLY_CS" -lt "$end_cs" ] || fail "restart was not observed within ${timeout_s}s in trial $n"
    nap "$poll_s"
  done
  up_cs; up1="$REPLY_CS"
  d_wall=$((t1 - t0))
  d_up=$(((up1 - up0) * 10000))
  diff=$((d_wall - d_up))
  [ "${diff#-}" -le 50000 ] || fail "clock changed during trial $n (wall and monotonic clocks disagree)"
  new_pid="$ST_PID"
  # 観測時: 新 pid が生存し launcher の子孫であること（SUP-3。state.json だけ残って新プロセスが既に終了した試行は採用しない）。
  # 計測区間（t1）の外で行うのでレイテンシには含まれない。起動時刻を控えて確定時に再照合する。
  if ! { alive "$new_pid" && is_descendant "$new_pid"; }; then
    note_suspect "$new_pid"
    fail "new container process is not alive as a launcher descendant at observation in trial $n"
  fi
  new_start="$REPLY_START"
  track_pid "$new_pid" "$new_start"
  validate_state_strict "$new_pid" "$((old_count + 1))" || fail "state.json failed strict validation in trial $n"
  # 確定時: 同じ新 pid・起動時刻のプロセスがまだ生存していること。
  same_proc "$new_pid" "$new_start" || fail "new container process exited before the trial $n result was confirmed"
  [ "$n" -le "$warmup" ] || vals+=("$d_wall")
  # 計測区間の外で launcher の子孫を記録する（launcher が後で異常終了しても回収対象に残る）。
  snapshot_descendants || true
  nap "$settle_s"
done

# --- 計測区間の外: delete できる状態（stopped）まで進める。値は上で確定済み（vals）でここでの時間は入らない ---
stop_for_delete

# --- 副系列は launcher 停止後（do_cleanup 内の collect_reported）に集計する。ここで停止・回収を先に行う ---
collect_log=1
if ! do_cleanup; then
  err "cleanup-failed" "processes may remain after the run; inspect and kill them manually"
  finish 4
fi
[ "$reported_err" -eq 0 ] || fail "launcher reported a failed restart"
[ "${#vals[@]}" -eq "$trials" ] || fail "collected ${#vals[@]} samples, want $trials"

# 集計（jq）。中央値は偶数個で中央 2 値の平均、p95 は昇順の ceil(n*95/100)-1 番目。単位は ms（小数 3 桁）。
# shellcheck disable=SC2016 # jq のフィルタ（$s・$n は jq の変数。シェル展開させない）
stats_filter='
  def r3: (. * 1000 | round) / 1000;
  def stats: sort as $s | ($s | length) as $n
    | { samples: $n,
        median: ((if ($n % 2) == 1 then $s[($n - 1) / 2] else ($s[$n / 2 - 1] + $s[$n / 2]) / 2 end) / 1000 | r3),
        p95: ($s[((($n * 95) / 100) | ceil) - 1] / 1000 | r3),
        min: ($s[0] / 1000 | r3), max: ($s[$n - 1] / 1000 | r3),
        mean: (($s | add) / $n / 1000 | r3),
        values: ($s | map(. / 1000 | r3)) };
'
observed_json="$(printf '%s\n' "${vals[@]}" | jq -s "$stats_filter stats")"
backoff_us=$((supervisor_backoff_ms * 1000))
# バックオフを差し引いた系列（µs）。負の値は計測異常（supervisor は backoff 以上眠る）として失敗にする。
minus_filter="$stats_filter map(. - $backoff_us) | if any(. < 0) then error(\"negative\") else stats end"
observed_net_json="$(printf '%s\n' "${vals[@]}" | jq -s "$minus_filter" 2>/dev/null)" ||
  fail "an observed latency is below the supervisor backoff (${supervisor_backoff_ms}ms); cannot subtract the backoff"
if [ "$reported" = "null" ]; then
  reported_json="null"
  reported_net_json="null"
else
  reported_json="$(printf '%s\n' "$reported" | jq -s "$stats_filter stats")"
  reported_net_json="$(printf '%s\n' "$reported" | jq -s "$minus_filter" 2>/dev/null)" ||
    fail "a supervisor-reported latency is below the supervisor backoff (${supervisor_backoff_ms}ms); cannot subtract the backoff"
fi

result="$(jq -n \
  --arg label "$label" --arg policy "$policy" --argjson backoff "$supervisor_backoff_ms" \
  --argjson trials "$trials" --argjson warmup "$warmup" \
  --argjson observed "$observed_json" --argjson reported "$reported_json" \
  --argjson observed_net "$observed_net_json" --argjson reported_net "$reported_net_json" \
  --arg dres "$delete_result" --arg dreason "$delete_reason" '
  { schema: "fandhe-container.restart-latency/v1", behavior: "SUP-3", task: "TASK-160", unit: "ms",
    label: $label, trials: $trials, warmup: $warmup, policy: $policy, backoff_ms_assumed: $backoff,
    observed: $observed, supervisor_reported: $reported,
    observed_minus_backoff: $observed_net, supervisor_reported_minus_backoff: $reported_net,
    cleanup: ({delete: $dres} + (if $dreason != "" then {reason: $dreason} else {} end)),
    method: {
      observed: "SIGKILL to the container process until state.json shows running, a new pid and restartCount+1; includes the supervisor restart backoff, the pre-signal identity check, signal delivery, exit detection and the polling granularity of this script (upper bound)",
      supervisor_reported: "elapsed_us of the supervisor.monitor restart log line (exit detected until the new Running state is recorded, including the restart backoff); null when the supervisor log does not provide trials+warmup ok lines",
      backoff_subtraction: "the supervisor bin has no backoff argument (fixed default, backoff_ms_assumed); *_minus_backoff subtracts it from every sample. The supervisor sleeps at least the backoff, so the result is an upper estimate of the latency without the backoff (it includes any oversleep); a negative value is a measurement error",
      poc17_difference: "PoC-17 measured the next start time minus the previous end time recorded by a self-exiting workload, which is a different interval; do not compare the numbers directly",
      percentile: "nearest-rank ceil(n*95/100)-1 on sorted samples; median averages the two middle values for an even count" } }')"

# 後始末は上で完了済み（残存があれば 4 で結果を出さない）。結果を公開する。
if [ -n "$output" ]; then
  out_tmp="$(mktemp "${output}.XXXXXX")"
  printf '%s\n' "$result" >"$out_tmp"
  if ! ln -T -- "$out_tmp" "$output" 2>/dev/null; then
    err "invalid-argument" "output path already exists or cannot be created"
    finish 2
  fi
  rm -f -- "$out_tmp"
  out_tmp=""
else
  printf '%s\n' "$result"
fi
finish 0
