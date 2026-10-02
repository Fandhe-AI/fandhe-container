//! `NETLINK_ROUTE` 側の入口モジュール（TASK-136・NET-11・MS-8）。
//!
//! 現時点ではファミリ非依存の nlmsghdr / rtattr コーデック（`crate::netlink`。TASK-136.1・#298）
//! を再公開するのみ。ソケット送受信（#843・#844）・link 操作（#845・#846）・address / route
//! 操作（#301）は未実装で、各 Issue でここへ追加する（REPAIR-3。実装済みを装わない）。

pub use crate::netlink::*;
