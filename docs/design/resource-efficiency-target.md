# リソース効率目標値

ホスト側メモリ消費の MVP 目標値を定め、TASK-49 実測・TASK-26 統合評価の前提とする。

- 決定日: 2026-09-26（ユーザー決定）
- 関連 issue: #29（TASK-48・CORE-8）

## 採用目標値

**ホスト側プロセス RSS 合計が Docker Desktop 現行版比 10% 以内**（CORE-8・TASK-48・MS-0。実測は TASK-49）

- Docker Desktop 基準: 約 2,524MB
- 本基盤の上限: 約 252MB 以下
- 根拠: PoC-11 の実測で同構成の Podman (applehv) 約 71MB（2.8%）・colima (virtiofs) 約 150MB（5.9%）が満たしており達成見込みがある

## 不採用（50% 削減案）

Docker Desktop 比 50% 削減案（約 1.2GB 以下）は採用しない。理由: 何を合計するかの定義が曖昧なうえ、PoC-11 の実測（同構成の既存ツールが 3〜6%）から見て目標として緩すぎるため

## 測定の定義

**対象**: macOS・Windows の VM 経由時。コンテナ 0 個のアイドル状態で、値が安定したときのホスト側プロセスの RSS 合計（CORE-8）

- macOS: PoC-11 と同じく `ps -axo rss,comm` を対象プロセス名で集計する。本基盤の CLI・supervisor・VM を起動・管理するプロセスを合計する。Virtualization.framework が VM のメモリを計上する `com.apple.Virtualization.VirtualMachine`（XPC プロセス）は合計に含めず、参考値として別に記録する（PoC-11 の Podman・colima と同じ条件）
- Windows: `ps` は使えないため、取得方法（対象プロセスと計測 API）と WSL2 関連プロセスの扱いを TASK-49 で定める

**比較対象**: Docker Desktop の版数・測定条件・タイムスタンプを記録。参考値として Docker Desktop VM 内込み約 3.2GB も記載

**比較時の注意**: 独自のハイパーバイザを持ち VM のメモリが自身のプロセスに入るランタイム（OrbStack 等）は、同じ集計方法でも VM メモリ込みの値になるため単純比較できない（2026-09-26 に TASK-10〔#28〕で実測済み。結果は PoC-11 の評価表）

## 留意

- OrbStack・Finch・Rancher Desktop は 2026-09-26 に実測済み（TASK-10・#28）。アイドル時のホスト RSS は Docker Desktop 比で OrbStack 42.1%・Rancher Desktop 18.7%・Finch 4.6%。目標値は見直さない
- 詳細な実測手順・サンプリング間隔・統計処理は TASK-49 で定める
- リソース消費の最小化は CORE-7〜9 の設計制約のため、達成困難と判定した場合はユーザーに報告する
