# spec 参照規約（リポ固有）

## 前提

- 仕様・ビヘイビア定義の SSOT は [fandhe-container-spec](https://github.com/Fandhe-AI/fandhe-container-spec)（`docs/spec` submodule）の `04-behavior/`。タスク定義は `05-tasks.md`（TASK-n）、マイルストーンは `06-roadmap.md`（MS-n）、PoC 成果物は `03-poc/`、設計判断は `01-brainstorm.md`（D-n）
- spec リポは private として維持するが、完全な機密は含まない。**spec の内容を本リポ（public）のコード・コメント・ドキュメント・Issue・PR・コミットメッセージに載せてよい**（オーナー判断 2026-09-26）
- spec リポへのアクセス権がない環境では `docs/spec` を解決できない

## 参照の仕方

- 対応するビヘイビア ID（`<PREFIX>-<N>`。例: `IO-2`・`PLUG-11`）・TASK-n・MS-n・D-n を必ず併記し、SSOT へ辿れるようにする
- 要約・引用は必要な範囲に留め、spec ファイルの丸ごとコピーはしない（spec 更新時に内容が乖離するため。詳細は ID から spec を参照させる）
- spec と本リポの記述が食い違った場合は spec を正とし、spec 側の変更が必要ならユーザーへ報告する
- ステータスが「検討中」のビヘイビアは確定扱いしない。実装で判断が必要になったらユーザーへ確認する

## 運用

- `docs/spec` 配下のファイルを本リポ側で編集しない（spec リポ側で管理し、本リポは submodule 参照の更新のみ行う）
- ビルド・テストは `docs/spec` 抜きで成立させる。コード・`build.rs`・テストから `docs/spec` 配下を読み込まない
- spec 内に資格情報・個人情報・実機のホスト名 / アドレスなど本来公開すべきでないものを見つけた場合は転記せず、ユーザーに報告する
