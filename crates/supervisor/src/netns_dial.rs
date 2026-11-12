//! bin の main が `netns-dial` を net の helper へ振り分けるかの判定（CRI-6・NET-3・SEC-1・REPAIR-5・#4482）。
//!
//! helper の本体は net crate の `fandhe_container_net::netns_dial::run_netns_dial_main`（#4479）にあり、
//! 本モジュールは bin の main の振り分けの判定だけを持つ。呼び出し元は plugin-cri の `PodNetnsDialer`
//! （#4484）が dial のたびに起動する supervisor の bin で、保持役の namespace へ参加して
//! `127.0.0.1:<port>`（失敗したら `[::1]:<port>`）への接続済み fd を返す単一スレッドの helper になる。
//!
//! 判定は `run_main` の継承 fd の整理・結果チャネルの検証・スレッド生成より前に行う。`setns(CLONE_NEWUSER)` は
//! 多スレッドのプロセスでは `EINVAL` になり、結果も固定長 frame で返すため。特権ランチャーは
//! `StartArgs::parse` を通った argv だけを転送するので、この分岐の入口にはならない。

use std::ffi::OsStr;

use fandhe_container_net::netns_dial::NETNS_DIAL_SUBCOMMAND;

/// bin の main が netns-dial helper へ振り分ける呼び出しか（第 1 引数が `netns-dial` と完全一致）。
pub fn is_netns_dial_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(NETNS_DIAL_SUBCOMMAND))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-6・#4482: 振り分けは第 1 引数が完全一致のときだけ。
    #[test]
    fn cri6_dispatch_matches_only_the_exact_subcommand() {
        assert!(is_netns_dial_invocation(Some(OsStr::new("netns-dial"))));
        for other in [
            "netns-dial ",
            "netns-dia",
            "netns-dial-x",
            "NETNS-DIAL",
            "netns-holder",
            "pod-holder",
            "",
        ] {
            assert!(
                !is_netns_dial_invocation(Some(OsStr::new(other))),
                "{other:?}"
            );
        }
        assert!(!is_netns_dial_invocation(None));
    }

    /// CRI-6・#4482: 起動側（#4484）との契約の文字列を固定する。
    #[test]
    fn cri6_subcommand_literal_is_fixed() {
        assert_eq!(NETNS_DIAL_SUBCOMMAND, "netns-dial");
    }

    /// CRI-6・#4482: 各 helper の振り分け名は互いに排他で、`start` はどれにも当たらない。
    #[cfg(target_os = "linux")]
    #[test]
    fn cri6_dispatch_names_are_mutually_exclusive() {
        use crate::healthcheck::exec_helper::is_health_exec_invocation;
        use crate::healthcheck::exec_reaper::is_health_reaper_invocation;
        use crate::netns_holder::is_holder_invocation;
        use crate::pod_holder::is_pod_holder_invocation;
        use crate::stream_exec::helper::is_stream_exec_invocation;

        for (name, expected) in [
            ("netns-holder", 1),
            ("healthcheck-exec", 1),
            ("healthcheck-reaper", 1),
            ("stream-exec", 1),
            ("pod-holder", 1),
            ("netns-dial", 1),
            ("start", 0),
        ] {
            let f = Some(OsStr::new(name));
            let hits = [
                is_holder_invocation(f),
                is_health_exec_invocation(f),
                is_health_reaper_invocation(f),
                is_stream_exec_invocation(f),
                is_pod_holder_invocation(f),
                is_netns_dial_invocation(f),
            ]
            .iter()
            .filter(|&&b| b)
            .count();
            assert_eq!(hits, expected, "{name}");
        }
    }
}
