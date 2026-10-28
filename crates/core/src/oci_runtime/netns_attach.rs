//! rootless の pasta 構成向けに、exec 直前の同期点で呼び出し側へ netns と user namespace の fd を渡す口
//! (NET-9・CORE-6・SEC-1・SEC-5・REPAIR-5。#1939。方式は `docs/design/rootless-network.md` 12.2・
//! `docs/design/network-wiring.md` D8)。
//!
//! # 役割と呼び出し文脈
//!
//! `LaunchNetworkMode::Attachable` の起動では、コンテナの PID 1 が exec の直前(開始ゲートの通過後・pivot と資格情報の
//! 切り替えより前)に、自分の network namespace と user namespace の fd を**この順で**呼び出しプロセス(launcher。
//! supervisor そのもの)へ渡す。launcher は fd を検証してから、この [`NetnsAttachHook`] を呼ぶ。フックが成功したときだけ
//! PID 1 へ合図(ACK)が届き、PID 1 は exec に進む。失敗・期限切れのときは PID 1 を exec させずに kill して回収する。
//!
//! core は pasta を知らない(`core → net` の依存を足さない。D5)。holder プロセスの保持(`NetnsHolderFds`)と pasta の起動は、
//! フックの実装を持つ supervisor が #1940 で担う。`ProductionLauncherBuilder::netns_attach_hook` で注入する。
//!
//! # 契約(フックの実装者が守ること)
//!
//! - launcher の単一スレッドの区間(fork 済みで PID 1 が同期点を待っている間)から呼ばれる。スレッドを作らない
//! - `deadline` までに返る(返った後に期限を越えていれば、launcher は Ok でも失敗として扱う)
//! - 失敗したら、自分が起動したものを自分で片付けてから `Err` を返す
//! - `Ok` を返した後でも launch が失敗することがある(合図の送信の失敗・pivot 前段の失敗など)。その後始末(holder と
//!   pasta の停止)は、呼び出し側が launch の `Err` を見て行う
//! - `Err` の `code` は保たれるが、`message` は launcher の固定文言に置き換わる(外部ヘルパーの出力を漏らさない)
//!
//! # 範囲と残余(REPAIR-3)
//!
//! user namespace と netns の所有関係は launcher では照合しない(`NS_GET_USERNS` の ioctl は新しい `unsafe` になる)。
//! holder が `setns(user)` → `setns(net)` の順で参加するため、組が違えば `EPERM` か `EINVAL` になり fail-closed になる。

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::Instant;

use crate::traits::types::TraitError;

/// 検証済みの、PID 1 の network namespace と user namespace の fd(同期点で受け取ったもの)。
///
/// どちらも close-on-exec で、nsfs の fd であり、種別(`net:` / `user:`)を `readlink` で確かめてある。
/// `Debug` は fd 番号のみを出す(素性を含めない)。
pub struct AttachableNamespaces {
    net: OwnedFd,
    user: OwnedFd,
}

impl AttachableNamespaces {
    pub(crate) fn new(net: OwnedFd, user: OwnedFd) -> Self {
        Self { net, user }
    }

    /// network namespace の fd(借用)。
    pub fn net(&self) -> BorrowedFd<'_> {
        self.net.as_fd()
    }

    /// user namespace の fd(借用)。
    pub fn user(&self) -> BorrowedFd<'_> {
        self.user.as_fd()
    }

    /// 所有権を取り出す。戻りの順は `(user, net)` で、holder の受け口 `NetnsHolderFds::new(user, net)` の引数の順に合わせる。
    pub fn into_parts(self) -> (OwnedFd, OwnedFd) {
        (self.user, self.net)
    }
}

impl std::fmt::Debug for AttachableNamespaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::os::fd::AsRawFd as _;
        f.debug_struct("AttachableNamespaces")
            .field("net_fd", &self.net.as_raw_fd())
            .field("user_fd", &self.user.as_raw_fd())
            .finish()
    }
}

/// 同期点の中で呼ばれる、呼び出し側の準備処理(pasta 構成の holder の保持と外部ヘルパーの起動。#1940)。
///
/// 契約はモジュール doc を参照。`namespaces` の所有権を受け取り、不要になれば drop で閉じる。
pub trait NetnsAttachHook: Send + Sync {
    /// 準備を行う。`deadline` までに返ること。成功したときだけ launcher は PID 1 へ合図を送る。
    fn attach(&self, namespaces: AttachableNamespaces, deadline: Instant)
    -> Result<(), TraitError>;
}
