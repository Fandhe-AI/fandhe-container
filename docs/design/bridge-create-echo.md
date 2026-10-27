# bridge 作成の `NLM_F_ECHO` による ifindex 取得（Issue #1972・TASK-139 追補・NET-1）

## 背景

bridge の所有トークン（`IFLA_IFALIAS`）は、作成の ACK 後に ifindex 指定の `RTM_SETLINK` で付ける（#1925）。
従来は作成後に名前で `RTM_GETLINK` して ifindex を引いていたため、作成から引き直しまでの間に `CAP_NET_ADMIN`
保持者が bridge を別名なしの同名 link に差し替えると、その link に印を付けてしまう窓があった。

## 判断（採用）

作成要求に `NLM_F_ECHO` を付け、カーネルが返す作成通知（`RTM_NEWLINK`）から作成した link 自身の ifindex を
得る。名前での引き直しをなくし、印を付ける相手を「自分が作った link」に固定する。

- 実装: `LinkCreate::with_echo`（flags 0x0608）、`decode_created_link`（通知の検証）、`network.rs` の
  `BridgeCreated` / `EchoedIndex`。echo は bridge の作成だけに付ける（veth は後続候補）
- 読み戻し（`verify_owned`）は残す。echo が保証するのは作成時点の同一性だけで、印が付いたことと名前が今も
  その ifindex を指すことは読み戻しで確かめる

## 一次資料（torvalds/linux）

- v6.2 の `net/core/rtnetlink.c`: `rtnl_newlink_create` が `portid` を取り `rtnl_configure_link(dev, ifm, portid, nlh)`
  を呼ぶ。`rtnl_configure_link` → `__dev_notify_flags(..., portid, nlh)` → `rtmsg_ifinfo(RTM_NEWLINK, ...)` →
  `rtmsg_ifinfo_event` は `nlmsg_seq(nlh)` と `portid` で通知を組み、`rtnl_notify` → `nlmsg_notify(report = nlmsg_report(nlh))`
  が `NLM_F_ECHO` のときだけ要求元へ unicast する。すべて doit の中で同期的に走るため、ACK より前に受信キューへ入る
- v6.1 以前: `rtnl_configure_link(dev, ifm)` は portid・`nlh` を受けず、echo は返らない（ACK のみ）
- 下限は v6.2（`rtnl_configure_link` の引数追加。commit 1d997f101307・d88e136cab37）
- 作成中は `register_netdevice` の通知が抑えられ、`rtnl_configure_link` の `changed = ~0U` の 1 回だけが echo される
- unicast 先は作成先 netns の rtnl ソケット。bridge は要求ソケットと同じ netns に作る（`IFLA_NET_NS_*` を載せない）ため届く

## 戻し経路と fail-closed

| 状況 | 扱い |
| ---- | ---- |
| 通知が 0 件（v6.2 より前など） | 従来どおり名前で `link_state` を引き、別名が空なら続行 |
| 通知がちょうど 1 件で、ifindex が正・名前一致・別名なし | その ifindex に印を付ける。`link_state` は呼ばない |
| 通知が 2 件以上・破損・名前不一致・別名あり | `DataLoss`。ACK 済みで作成済みのため `ResolveIndex` で `Unknown` として報告し、印付けも削除もしない |
| 受信バッファあふれで通知が捨てられた | 通知 0 件と同じ戻し経路（`ENOBUFS` が立てば作成要求が `Unknown` で失敗する。従来と同じ fail-closed） |

## 残る窓

- echo 経路: 作成から印付けまでの差し替えの窓は無い（差し替えられても ifindex 指定の `RTM_SETLINK` は
  `NotFound` になり、他者の link に印は付かない）。印付けから所有再確認・削除までの極小の窓は従来どおり
- 戻し経路（古いカーネル）: 従来の窓が残る（単体テスト `net1_fallback_swap_before_lookup_stamps_foreign` で固定）

## 確認状況

- 単体・結合試験: `network.rs` の `net1_echo_*`、`link.rs` の `net1_decode_created_link_cases` ほか、
  `crates/net/tests/link_create.rs`
- 実機（root）: `bridge_owner_token_privileged` の (9)。実行は人間担当で、**未検証**
