#!/usr/bin/env bash
# Pinned tool versions shared by scripts/targets/*.sh (sourced via scripts/lib.sh).
#
# Single source of truth (previously the Makefile variables). Keep in sync with:
#   - lint tools: the defaults of the Fandhe-AI/actions lint-docs reusable workflow
#     (CI is authoritative; follow it when they drift). EC_NPM_VERSION is the npm wrapper
#     version (CI fetches the Go binary release v3.8.0 directly, so the numbering differs).
#   - CARGO_DENY_VERSION: Dockerfile, .github/workflows/ci.yml (rust-ci.with.cargo-deny-version).
#   - CARGO_ABOUT_VERSION: Dockerfile (cargo install cargo-about@x.y.z), .github/workflows/ci.yml.
#   - LEFTHOOK_VERSION: exact-pinned npx fallback for `make hooks`.
# Do not execute directly.

MARKDOWNLINT_VERSION="${MARKDOWNLINT_VERSION:-0.49.1}"
YAMLLINT_VERSION="${YAMLLINT_VERSION:-1.38.0}"
EC_NPM_VERSION="${EC_NPM_VERSION:-6.1.1}"
COMMITLINT_VERSION="${COMMITLINT_VERSION:-21.2.1}"
COMMITLINT_CONFIG_VERSION="${COMMITLINT_CONFIG_VERSION:-21.2.0}"
LEFTHOOK_VERSION="${LEFTHOOK_VERSION:-2.1.10}"
CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.20.2}"
CARGO_ABOUT_VERSION="${CARGO_ABOUT_VERSION:-0.9.2}"
