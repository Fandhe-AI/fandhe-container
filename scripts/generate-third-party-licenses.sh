#!/usr/bin/env bash
# サードパーティのライセンス表記生成スクリプト（TASK-103.1・OSS-5・MS-1 Phase 2）。
#
# 役割: `cargo about generate` で Cargo.lock に固定された依存のライセンス表記（Markdown）を
# 生成する。設定は ルートの about.toml、テンプレートは about.hbs。許可外ライセンスの
# 検出（fail-closed）は deny.toml の cargo-deny の役目で、本スクリプトは表記の生成だけを担う。
# 呼び出し元は Makefile の `third-party-licenses` ターゲットと自己テスト
# （scripts/generate-third-party-licenses-selftest.sh）。
#
# 依存承認との関係: cargo-about は cargo のサブコマンドで Cargo.toml の dependencies に入らない
# ため、dependency-policy の依存承認の対象外。本スクリプトは cargo-about を導入しない
# （版を固定した導入と版のユーザー承認は #830〔TASK-103.2〕の範囲）。未導入なら
# 自動導入も黙ってスキップもせず、tool-missing で止まる（fail-closed）。
#
# 使い方:
#   generate-third-party-licenses.sh [--output <path>] [--timeout <秒>]
#   --output   既定: <repo>/target/third-party-licenses/THIRD-PARTY-LICENSES.md
#              （target/ は lint-docs の除外対象かつ .gitignore 済みで、生成物を誤コミットしない）
#   --timeout  cargo fetch と cargo about generate それぞれの上限秒（既定 600。1〜3600。REPAIR-5）
# 環境変数: CARGO（cargo コマンドの差し替え。自己テストがスタブを渡す）
#
# タイムアウト（REPAIR-5）: cargo は独立したプロセスグループで起動し、期限超過時はグループ全体
# （cargo が起動した cargo-about・補助プロセスを含む）へ TERM、猶予 2 秒後に KILL を送り、
# 終了を確かめる。
#
# 前提ツール: cargo・cargo-about・mktemp・mv・find・id・sleep・kill（Git Bash でも動く bash 構文に限る）
#
# 出力先の安全性（security.md）: 出力先ディレクトリの祖先を含むパス要素のどれかが symlink
# なら（mkdir・書き込みより前に）拒否する。ただし非 root 実行時に限り root 所有の symlink
# （macOS の /var・/tmp 等のシステム設定）は許容する。既存の出力先が通常ファイル以外でも拒否する。同じディレクトリの一時ファイルへ生成し、空でないことを
# 確かめてから mv で置き換える（途中までのファイルを残さない）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功（stdout に出力先のパスを 1 行出す）
#   1: cargo fetch / cargo about generate が失敗した（ライセンスを確定できない crate を含む）
#   2: 引数・環境・ツール未導入・出力先が不正（mktemp・mkdir・mv の失敗を含む）
#   3: タイムアウト
# エラーは stderr に `error: code=<code> message=<英語>` の 1 行で出す。
set -euo pipefail

err() {
    printf 'error: code=%s message=%s\n' "$1" "$2" >&2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
cargo="${CARGO:-cargo}"
output=""
timeout_s=600

while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            [ $# -ge 2 ] || { err bad-argument "--output requires a value"; exit 2; }
            output="$2"
            shift 2
            ;;
        --timeout)
            [ $# -ge 2 ] || { err bad-argument "--timeout requires a value"; exit 2; }
            timeout_s="$2"
            shift 2
            ;;
        *)
            err bad-argument "unknown argument: $1"
            exit 2
            ;;
    esac
done

if ! [[ "$timeout_s" =~ ^[0-9]{1,4}$ ]] || [ "$timeout_s" -lt 1 ] || [ "$timeout_s" -gt 3600 ]; then
    err bad-argument "--timeout must be an integer between 1 and 3600"
    exit 2
fi

for f in Cargo.toml about.toml about.hbs; do
    [ -f "$root/$f" ] || { err bad-environment "missing $f in repository root"; exit 2; }
done

# 一時領域（タイムアウト印の置き場）。後始末は cleanup が行う。
work_dir=""
tmp=""
child_pid=""
wd_pid=""
cleanup() {
    if [ -n "$child_pid" ]; then
        kill -TERM -- "-$child_pid" 2>/dev/null || true
        kill -KILL -- "-$child_pid" 2>/dev/null || true
    fi
    if [ -n "$wd_pid" ]; then
        kill "$wd_pid" 2>/dev/null || true
    fi
    [ -z "$tmp" ] || rm -f "$tmp"
    [ -z "$work_dir" ] || rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 143' INT TERM

work_dir="$(mktemp -d)" || { work_dir=""; err bad-environment "cannot create a temporary directory"; exit 2; }

# 子プロセスを上限秒で打ち切る（macOS に timeout が無いため見張り役方式）。
# 子は job control（set -m）で独立したプロセスグループにし、超過時はグループ全体へ
# TERM → 猶予後 KILL を送って終了を確認する。超過時は 124 を返す。
run_limited() {
    local limit="$1"
    shift
    local marker="$work_dir/timeout-marker"
    rm -f "$marker"
    set -m
    "$@" &
    local pid=$!
    set +m
    child_pid="$pid"
    (
        i=0
        while [ "$i" -lt "$limit" ]; do
            sleep 1
            kill -0 "$pid" 2>/dev/null || exit 0
            i=$((i + 1))
        done
        : >"$marker"
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        sleep 2
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    ) &
    wd_pid=$!
    local rc=0
    wait "$pid" || rc=$?
    if [ -e "$marker" ]; then
        # 見張り役が KILL まで送り終えるのを待ち、グループの消滅を確認する。
        wait "$wd_pid" 2>/dev/null || true
        local n=0
        while kill -0 -- "-$pid" 2>/dev/null && [ "$n" -lt 5 ]; do
            sleep 1
            n=$((n + 1))
        done
        wd_pid=""
        child_pid=""
        rm -f "$marker"
        return 124
    fi
    kill "$wd_pid" 2>/dev/null || true
    wait "$wd_pid" 2>/dev/null || true
    wd_pid=""
    child_pid=""
    return "$rc"
}

# パス要素のいずれかが symlink なら 1（symlink なし・未存在なら 0）を返す（存在する要素のみ検査し、無い要素で打ち切る）。
# 非 root 実行時は root 所有の symlink（システム設定）を許容する。".." は字句的に畳む
# （手前の要素が symlink でないことを検査済みのため意味が変わらない）。
path_is_symlink_free() {
    local path="$1" cur="" part
    local -a parts
    case "$path" in
        /*) ;;
        *) path="$PWD/$path" ;;
    esac
    IFS=/ read -r -a parts <<<"${path#/}"
    for part in "${parts[@]}"; do
        case "$part" in
            "" | .) continue ;;
            ..) cur="${cur%/*}"; continue ;;
        esac
        cur="$cur/$part"
        [ -e "$cur" ] || [ -L "$cur" ] || return 0
        if [ -L "$cur" ]; then
            if [ "$(id -u)" -ne 0 ] && [ -n "$(find "$cur" -maxdepth 0 -user 0 2>/dev/null)" ]; then
                continue
            fi
            return 1
        fi
    done
    return 0
}

# ツール確認は入力検証より先に行い、未導入を別の失敗と誤分類しない。
if ! run_limited 30 "$cargo" about --version >/dev/null 2>&1; then
    err tool-missing "cargo-about is not installed (installation is tracked in #830)"
    exit 2
fi

default_dir="$root/target/third-party-licenses"
if [ -z "$output" ]; then
    output="$default_dir/THIRD-PARTY-LICENSES.md"
    # mkdir より前に祖先（target 等）の symlink を検査する。
    if ! path_is_symlink_free "$default_dir"; then
        err bad-output "output directory path must not contain a symlink"
        exit 2
    fi
    mkdir -p "$default_dir" 2>/dev/null || { err bad-output "cannot create the default output directory"; exit 2; }
fi
out_dir="$(dirname "$output")"
if ! path_is_symlink_free "$out_dir"; then
    err bad-output "output directory path must not contain a symlink"
    exit 2
fi
if [ ! -d "$out_dir" ]; then
    err bad-output "output directory does not exist"
    exit 2
fi
out_dir="$(cd "$out_dir" && pwd)" || { err bad-output "cannot enter the output directory"; exit 2; }
output="$out_dir/$(basename "$output")"
if [ -L "$output" ]; then
    err bad-output "output path must not be a symlink"
    exit 2
fi
if [ -e "$output" ] && [ ! -f "$output" ]; then
    err bad-output "output path exists and is not a regular file"
    exit 2
fi

tmp="$(mktemp "$out_dir/.third-party-licenses.XXXXXX" 2>/dev/null)" \
    || { tmp=""; err bad-output "cannot create a temporary file in the output directory"; exit 2; }

rc=0
run_limited "$timeout_s" "$cargo" fetch --locked --manifest-path "$root/Cargo.toml" >&2 || rc=$?
if [ "$rc" -eq 124 ]; then
    err timeout "cargo fetch exceeded ${timeout_s}s"
    exit 3
elif [ "$rc" -ne 0 ]; then
    err fetch-failed "cargo fetch failed"
    exit 1
fi

# --frozen: Cargo.lock を書き換えず、clearlydefined.io へも通信しない。
# --fail: ライセンスを確定できない crate があれば非ゼロで終える。
rc=0
run_limited "$timeout_s" "$cargo" about generate --frozen --workspace --all-features --fail \
    -m "$root/Cargo.toml" -c "$root/about.toml" -o "$tmp" "$root/about.hbs" >&2 || rc=$?
if [ "$rc" -eq 124 ]; then
    err timeout "cargo about generate exceeded ${timeout_s}s"
    exit 3
elif [ "$rc" -ne 0 ]; then
    err generate-failed "cargo about generate failed"
    exit 1
fi

if [ ! -s "$tmp" ]; then
    err generate-failed "cargo about generate produced an empty output"
    exit 1
fi

mv -f "$tmp" "$output" 2>/dev/null || { err bad-output "cannot move the generated file to the output path"; exit 2; }
tmp=""
printf '%s\n' "$output"
