//! バイナリ `fandhe-container-compose-convert` の入口（薄い入口。実体は lib）。
//!
//! TASK-151.0・STACK-3 の雛形。引数を解釈せず `UNIMPLEMENTED` を返す stub（REPAIR-3）。
//! stdout は将来 TOML を出す経路として空けておき、何も書かない。
//! 引数解析とキー単位のレポートは TASK-151.7（#602）で足す。
//!
//! 終了コード: 8 = 未実装（ERR-2 の慣行）。
#![deny(unsafe_code)]

fn main() -> std::process::ExitCode {
    fandhe_container_compose_convert::run()
}
