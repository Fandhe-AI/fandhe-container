# bridge・veth 作成の `NLM_F_ECHO` による ifindex 取得（Issue #1972・#3205・TASK-139 追補・NET-1）

## 背景

bridge の所有トークン（`IFLA_IFALIAS`）は、作成の ACK 後に ifindex 指定の `RTM_SETLINK` で付ける（#1925）。
従来は作成後に名前で `RTM_GETLINK` して ifindex を引いていたため、作成から引き直しまでの間に `CAP_NET_ADMIN`
保持者が bridge を別名なしの同名 link に差し替えると、その link に印を付けてしまう窓があった。

## 判断（採用）

作成要求に `NLM_F_ECHO` を付け、カーネルが返す作成通知（`RTM_NEWLINK`）から作成した link 自身の ifindex を
得る。名前での引き直しをなくし、印を付ける相手を「自分が作った link」に固定する。

- 実装: `LinkCreate::with_echo`（flags 0x0608）、`decode_created_link`（通知の検証）、`network.rs` の
  `BridgeCreated` / `EchoedIndex`
- veth（Issue #3205）: 接続（`attach_with_source`）の veth 作成要求にも echo を付け、`decode_created_veth` が
  通知から host 側の ifindex（`ifi_index`）と peer 側の ifindex（`IFLA_LINK`）を取る。後続の操作（所有トークン・
  bridge 接続・up・netns への移動）は名前で引き直さずこの値を使う。型は `network.rs` の `VethCreated` / `EchoedVeth`
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

### veth の経路（Issue #3205）

次は `drivers/net/veth.c` の `veth_newlink` と `net/core/rtnetlink.c` の読み方（v6.2 以降の構造）であり、
本記録の作成時点で各版の原文を取り直しての再確認は**未実施**（REPAIR-3。実カーネルでの確認は
`network_attach_privileged` の `veth_echo`〔#1626・未検証〕）。

- `veth_newlink` は peer を先に登録し、peer 側の `rtnl_configure_link` へは portid・`nlh` を渡さない（0・NULL）。
  このため peer の通知は multicast のみで要求元へ echo されない。echo されるのは `ops->newlink` から戻ったあとに
  `rtnl_newlink_create` が送る主側（`IFLA_IFNAME` の host 名）の 1 件だけ
- peer の ifindex は同じ通知の `IFLA_LINK` に載る（veth の `ndo_get_iflink` が peer の ifindex を返し、
  `rtnl_fill_ifinfo` は `iflink != ifindex` のときに `IFLA_LINK` を出す）。`IFLA_LINK_NETNSID` は peer が別 netns に
  いるときだけ付く。作成時は両端とも要求ソケットと同じ netns のため付かない。付いていたら ifindex が別 netns の
  ものになるので `DataLoss` にする
- 要求ソケットは `nl_groups = 0` で bind している（`sys.rs`）ため、peer の multicast 通知は届かず「通知はちょうど 1 件」
  と判定できる。peer の通知まで echo される版が見つかった場合は、名前一致の 2 件を受ける復号に直す必要がある
- bridge・veth の newlink の経路に、`nlh` 付き（`nlmsg_report` が真になる）の別の通知が他にあるかは、手元で原文を
  再確認できていない（**未確認**）。実装は通知が 2 件以上なら `DataLoss` で拒否するため、あっても誤った ifindex を
  使うことはない
- stable・distro カーネルでの echo の差（5.15.y 等）は #3039 でも netfilter 側について確認項目になっており、
  本件でも**未確認**。echo が返らない版は下の戻し経路で扱う

## 戻し経路と fail-closed

| 状況 | 扱い |
| ---- | ---- |
| 通知が 0 件（v6.2 より前など） | 従来どおり名前で `link_state` を引き、別名が空なら続行 |
| 通知がちょうど 1 件で、ifindex が正・名前一致・別名なし | その ifindex に印を付ける。`link_state` は呼ばない |
| 通知が 2 件以上・破損・名前不一致・別名あり | `DataLoss`。ACK 済みで作成済みのため `ResolveIndex` で `Unknown` として報告し、印付けも削除もしない |
| 受信バッファあふれで通知が捨てられた | 通知 0 件と同じ戻し経路（`ENOBUFS` が立てば作成要求が `Unknown` で失敗する。従来と同じ fail-closed） |

### veth の戻し経路と fail-closed

| 状況 | 扱い |
| ---- | ---- |
| `RTM_NEWLINK` が 0 件（v6.2 より前など） | 従来どおり `link_index(host)`・`link_index(peer)` で名前から引く |
| ちょうど 1 件で、ifindex が正・名前が host と一致・別名なし・`IFLA_LINK` が 4 バイトの正の値で自分と異なる・`IFLA_LINK_NETNSID` なし | `(host, peer)` をそのまま使う。`link_index` は呼ばない |
| 2 件以上・破損・名前の不一致・別名あり・`IFLA_LINK` なし / 不正・`IFLA_LINK_NETNSID` あり | `DataLoss`。ACK 済みで作成済みのため `AttachStep::ResolveIndex` で `Veth(host)` を `Unknown` の leftover として報告する。veth は名前で削除しない（窓が戻る）。netns は従来の規則で戻す |

## 残る窓

- echo 経路: 作成から印付けまでに「異なる ifindex の link」へ差し替えられても、ifindex 指定の `RTM_SETLINK` は
  `NotFound` になり、他者の link に印は付かない（従来の名前引きの窓を塞ぐ改善）。ただし ifindex は link の
  寿命を固定するハンドルではない。`CAP_NET_ADMIN` 保持者が bridge を削除し、同名・同じ ifindex で別 link を
  作ると `RTM_SETLINK` は `NotFound` にならず、その link に印が付き、`verify_owned`（名前・index・トークン）も
  通る。この「同一 ifindex の再利用」は残余リスクで、同じ権限を持つ者が相手のため権限境界は越えない。
  印付けから所有再確認・削除までの極小の窓は従来どおり
- 戻し経路（古いカーネル）: 従来の窓が残る（単体テスト `net1_fallback_swap_before_lookup_stamps_foreign` で固定）
- veth の echo 経路: ifindex の再利用（`CAP_NET_ADMIN` 保持者による削除と同じ ifindex での再作成）の残余リスクは
  bridge と同じで、同じ権限を持つ者が相手のため権限境界は越えない。接続の後続の操作で所有トークンを host 側に刻み、
  削除時に照合する既存の仕組みは変えない
- 範囲外: netns へ移した後の peer の名前による再解決（`configure_in_netns` の `netns_link_index`）は、作成直後の
  私有 netns の中の別の窓であり、本件では変えない

## 確認状況

- 単体・結合試験: `network.rs` の `net1_echo_*`・`net1_attach_veth_echo_*`、`link.rs` の
  `net1_decode_created_link_cases`・`net1_decode_created_veth_cases` ほか、`crates/net/tests/link_create.rs`
- 実機（root）: bridge は `bridge_owner_token_privileged` の (9)、veth は `network_attach_privileged` の
  `veth_echo=index` / `veth_echo=fallback`（v6.2 以上かで出し分け）。実行は人間担当（#1626）で、**未検証**
