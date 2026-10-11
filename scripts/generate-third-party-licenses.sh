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
# 前提ツール: cargo・cargo-about・mktemp・mv・sleep・kill（Git Bash でも動く bash 構文に限る）
#
# 出力先の安全性（security.md）: 出力先とその親が symlink なら拒否し、既存の出力先が
# 通常ファイル以外でも拒否する。同じディレクトリの一時ファイルへ生成し、空でないことを
# 確かめてから mv で置き換える（途中までのファイルを残さない）。
#
# 終了コード（呼び出し元はこの具体値で分岐する）:
#   0: 成功（stdout に出力先のパスを 1 行出す）
#   1: cargo fetch / cargo about generate が失敗した（ライセンスを確定できない crate を含む）
#   2: 引数・環境・ツール未導入・出力先が不正
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

# 子プロセスを上限秒で打ち切る（macOS に timeout が無いため見張り役方式）。
# 超過時は 124 を返す。
run_limited() {
    local limit="$1"
    shift
    local marker
    marker="$(mktemp)"
    rm -f "$marker"
    "$@" &
    local pid=$!
    (
        i=0
        while [ "$i" -lt "$limit" ]; do
            sleep 1
            kill -0 "$pid" 2>/dev/null || exit 0
            i=$((i + 1))
        done
        : >"$marker"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 1
        kill -KILL "$pid" 2>/dev/null || true
    ) &
    local wd=$!
    local rc=0
    wait "$pid" || rc=$?
    kill "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true
    if [ -e "$marker" ]; then
        rm -f "$marker"
        return 124
    fi
    return "$rc"
}

# ツール確認は入力検証より先に行い、未導入を別の失敗と誤分類しない。
if ! run_limited 30 "$cargo" about --version >/dev/null 2>&1; then
    err tool-missing "cargo-about is not installed (installation is tracked in #830)"
    exit 2
fi

default_dir="$root/target/third-party-licenses"
if [ -z "$output" ]; then
    output="$default_dir/THIRD-PARTY-LICENSES.md"
    mkdir -p "$default_dir"
fi
out_dir="$(dirname "$output")"
if [ -L "$out_dir" ]; then
    err bad-output "output directory must not be a symlink"
    exit 2
fi
if [ ! -d "$out_dir" ]; then
    err bad-output "output directory does not exist"
    exit 2
fi
out_dir="$(cd "$out_dir" && pwd)"
output="$out_dir/$(basename "$output")"
if [ -L "$output" ]; then
    err bad-output "output path must not be a symlink"
    exit 2
fi
if [ -e "$output" ] && [ ! -f "$output" ]; then
    err bad-output "output path exists and is not a regular file"
    exit 2
fi

tmp="$(mktemp "$out_dir/.third-party-licenses.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

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

mv -f "$tmp" "$output"
printf '%s\n' "$output"
