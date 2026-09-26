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

**対象**: macOS・Windows の VM 経由時。アイドル状態の安定値。ホスト側で本基盤に帰属する全プロセス

- macOS: supervisor・VM プロセス・Virtualization.framework の VM XPC プロセスを含む
- Windows: WSL2 関連プロセスの扱いを TASK-49 で確定

**比較対象**: Docker Desktop の版数・測定条件・タイムスタンプを記録。参考値として Docker Desktop VM 内込み約 3.2GB も記載

## 留意

- OrbStack・Finch・Rancher Desktop の実測は未取得（TASK-10・#28）。取得後に目標値の見直しは不要だが比較表へ追記
- 詳細な実測手順・サンプリング間隔・統計処理は TASK-49 で定める
- リソース消費の最小化は CORE-7〜9 の設計制約のため、達成困難と判定した場合はユーザーに報告する
