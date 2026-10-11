#!/usr/bin/env bash
# scripts/targets/*.sh が使う固定バージョン（scripts/lib.sh 経由で source される）。直接実行しない。
#
# 単一の定義元（旧 Makefile の変数）。以下と同期させる:
#   - lint ツール: Fandhe-AI/actions の lint-docs reusable workflow の既定値（CI 側が正。乖離したら追従する）。
#     EC_NPM_VERSION は npm ラッパーパッケージの版（CI は Go バイナリの release v3.8.0 を直接取得するため版番号体系が異なる）
#   - CARGO_DENY_VERSION: Dockerfile・.github/workflows/ci.yml（rust-ci の cargo-deny-version）
#   - CARGO_ABOUT_VERSION: Dockerfile（cargo install cargo-about@x.y.z）・.github/workflows/ci.yml
#   - LEFTHOOK_VERSION: `make hooks` の npx フォールバック用の exact 固定版
# 環境変数で上書きできる（未設定時のみ既定値を入れる）。

MARKDOWNLINT_VERSION="${MARKDOWNLINT_VERSION:-0.49.1}"
YAMLLINT_VERSION="${YAMLLINT_VERSION:-1.38.0}"
EC_NPM_VERSION="${EC_NPM_VERSION:-6.1.1}"
COMMITLINT_VERSION="${COMMITLINT_VERSION:-21.2.1}"
COMMITLINT_CONFIG_VERSION="${COMMITLINT_CONFIG_VERSION:-21.2.0}"
LEFTHOOK_VERSION="${LEFTHOOK_VERSION:-2.1.10}"
CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.20.2}"
CARGO_ABOUT_VERSION="${CARGO_ABOUT_VERSION:-0.9.2}"
