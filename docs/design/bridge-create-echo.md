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
- v6.1 以前: `rtnl_configure_link(dev, ifm)` は portid・`nlh` を受けず、echo は返らない（ACK のみ）。
  ただし 6.1.y の stable は 4 引数の形で、newlink は `(dev, ifm, 0, NULL)` を渡すため echo は返らない（下の
  「一次情報の確認」）
- 下限は v6.2（`rtnl_configure_link` の引数追加。commit 1d997f101307・d88e136cab37）
- 作成中は `register_netdevice` の通知が抑えられ、`rtnl_configure_link` の `changed = ~0U` の 1 回だけが echo される
- unicast 先は作成先 netns の rtnl ソケット。bridge は要求ソケットと同じ netns に作る（`IFLA_NET_NS_*` を載せない）ため届く

### veth の経路（Issue #3205）

次は `drivers/net/veth.c` の `veth_newlink` と `net/core/rtnetlink.c` の読み方（v6.2 以降の構造）である。
版ごとの原文での確認結果は次の「一次情報の確認（Issue #3293）」に記す。実カーネルでの確認は
`network_attach_privileged` の `veth_echo`（#1626・未検証）。

- `veth_newlink` は peer を先に登録し、peer 側の `rtnl_configure_link` へは portid・`nlh` を渡さない（0・NULL）。
  このため peer の通知は multicast のみで要求元へ echo されない。echo されるのは `ops->newlink` から戻ったあとに
  `rtnl_newlink_create` が送る主側（`IFLA_IFNAME` の host 名）の 1 件だけ
- peer の ifindex は同じ通知の `IFLA_LINK` に載る（veth の `ndo_get_iflink` が peer の ifindex を返し、
  `rtnl_fill_ifinfo` は `iflink != ifindex` のときに `IFLA_LINK` を出す）。`IFLA_LINK_NETNSID` は peer が別 netns に
  いるときだけ付く。作成時は両端とも要求ソケットと同じ netns のため付かない。付いていたら ifindex が別 netns の
  ものになるので `DataLoss` にする
- 要求ソケットは `nl_groups = 0` で bind している（`sys.rs`）ため、peer の multicast 通知は届かず「通知はちょうど 1 件」
  と判定できる。peer の通知まで echo される版が見つかった場合は、名前一致の 2 件を受ける復号に直す必要がある
  （#3293 の確認範囲では見つかっていない）
- bridge・veth の newlink の経路で `nlh` 付き（`nlmsg_report` が真になりうる）の通知は、主側の
  `rtnl_configure_link` → `__dev_notify_flags` → `rtmsg_ifinfo` の 1 件だけであることを確かめた（#3293、下記）。
  実装は通知が 2 件以上なら `DataLoss` で拒否するため、将来別の通知が増えても誤った ifindex を使うことはない

### 一次情報の確認（Issue #3293・NET-1・REPAIR-3）

前回（Issue #3205）で未確認だった 2 点を、カーネルソースの原文（2026-10-29 に取得）で確かめた。行番号は取得した ref のもので、
stable・Ubuntu はブランチ先頭が動くため Makefile の版（VERSION.PATCHLEVEL.SUBLEVEL）と ref を併記する。

#### (1) newlink の経路で `nlh` を渡す箇所（bridge・veth 共通）

| 版 | 箇所 | 結果 |
| -- | ---- | ---- |
| torvalds v6.2 | `net/core/rtnetlink.c:3223-3245`（`rtnl_configure_link`）・`:3415`（`rtnl_newlink_create` 内の呼び出し） | `(dev, ifm, portid, nlh)`。`nlh` を渡すのはここだけ。初回は `__dev_notify_flags(..., ~0U, portid, nlh)` を 1 回 |
| torvalds v6.2 | `net/core/dev.c:8550`（`__dev_notify_flags`）、他の呼び出し `:8333`・`:8387`・`:8599` | 他の呼び出しはすべて `0, NULL`。登録時の通知も `nlh` を持たない |
| torvalds v6.2 | `net/core/rtnetlink.c:768`（`rtnl_notify` → `nlmsg_notify(..., nlmsg_report(nlh), ...)`） | echo は `NLM_F_ECHO` のときだけ |
| torvalds v6.12 | `rtnetlink.c:3342`（定義）・`:3547`（呼び出し）・`:786`・`:4103`（`nlmsg_report(nlh)`）、`dev.c:8652`・`:8922` | 構造は同じ（ヘッダの portid / seq の付け方のみ差） |

- bridge の `br_dev_newlink`（`net/bridge/br_netlink.c`）は通知を `rtnl_notify(..., NULL, ...)` で出し、echo されない
  （本節の確認は v6.2 と master の読み取りに基づく）
- 本実装は作成要求に `IFLA_MASTER`・`IFLA_LINK_NETNSID`・`IFLA_NET_NS_*` を載せないため、`nlh` を受けない
  `dev_change_net_namespace`・`do_set_master` は経路に入らない

#### (2) veth の peer の通知

| 版 | 箇所 | 結果 |
| -- | ---- | ---- |
| torvalds v6.2 | `drivers/net/veth.c:1777` | `rtnl_configure_link(peer, ifmp, 0, NULL)`。peer の通知は echo されない |
| torvalds v6.12 | `drivers/net/veth.c:1842` | 同上 |
| stable 6.6.y（6.6.160） | `veth.c:1898` | 同上 |
| stable 6.12.y（6.12.114） | `veth.c:1896` | 同上 |

v6.2 以降の取得した版すべてで、echo は主側 1 件だけ（peer の ifindex は主側の `IFLA_LINK`）。

#### (3) stable・Ubuntu LTS での echo の有無

| カーネル | 参照 | newlink の呼び出し | echo |
| -------- | ---- | ------------------ | ---- |
| stable 5.15.y（5.15.223） | `linux-5.15.y` | `rtnetlink.c:3186` は 2 引数、`:3546` `(dev, ifm)`、veth `:1699` | なし（0 件 → 戻し経路） |
| stable 6.1.y（6.1.190） | `linux-6.1.y` | `rtnetlink.c:3248` は 4 引数、`:3444` は `(dev, ifm, 0, NULL)`、veth `:1753` | なし（形は 4 引数でも `0, NULL`） |
| stable 6.6.y（6.6.160） | `linux-6.6.y` | `:3337` 定義、`:3542` `(dev, ifm, portid, nlh)` | 主側 1 件 |
| stable 6.12.y（6.12.114） | `linux-6.12.y` | `:3443` 定義、`:3648` `(dev, ifm, portid, nlh)` | 主側 1 件 |
| Ubuntu 20.04 focal（5.4.284） | launchpad `focal` | `:2923` は 2 引数、`:3274`、veth `:1310` | なし |
| Ubuntu 22.04 jammy（5.15.189） | launchpad `jammy`（既定ブランチ） | `:3172` は 2 引数、`:3532`、veth `:1695` | なし |
| Ubuntu 24.04 noble（6.8.12） | launchpad `noble` | `:3353` 定義、`:3558` `(dev, ifm, portid, nlh)`、veth `:1910` `0, NULL` | 主側 1 件 |
| Ubuntu 26.04 resolute（7.0.14） | launchpad `resolute` の `?h=master-next` | `:3622` 定義、`:3886` `(dev, ifm, portid, nlh)`、veth `:1882` `0, NULL` | 主側 1 件 |

- echo の有無は「newlink が portid・`nlh` を `rtnl_configure_link` へ渡すか」で決まる。5.15.y 以前と 6.1.y・
  focal・jammy は 0 件、6.6.y 以降と noble・resolute は主側 1 件で、通知の形（`RTM_NEWLINK`・`IFLA_IFNAME`・
  `IFLA_LINK`）に差は見つからなかった。いずれも既存の判定（0 件 → 戻し経路、1 件 → 採用、2 件以上 → `DataLoss`）
  で扱え、復号の修正と単体試験の追加は不要
- 6.1.y は、引数の形だけ見て「v6.1 以前は portid・`nlh` を受けない」と読むと不正確（4 引数だが newlink は
  `0, NULL`）。結論（echo なし）は同じ
- 未確認: Ubuntu の HWE カーネル（jammy の 6.8 系等）、他 distro（RHEL 系のバックポート等）、stable の 6.6.y
  より前の 6.2〜6.5 の個別の版、5.15.y の veth 以外の分岐。echo が返る・返らないは戻し経路で吸収されるが、
  実機では確かめていない（#1626）

#### (4) 受信バッファあふれ

`nlmsg_unicast` は `MSG_DONTWAIT` の `netlink_unicast` で、受信バッファ超過の宛先には通知を捨てて
`netlink_overrun` が `sk_err = ENOBUFS` を立てる（`NETLINK_F_RECV_NO_ENOBUFS` が無い場合。v6.2
`net/netlink/af_netlink.c:1240-1254`・`:350-357`）。本実装は `NETLINK_NO_ENOBUFS` を設定していない。`rtnl_notify` は
void で作成要求の結果には影響しない。このため通知は 0 件に見え、`ENOBUFS` は受信側の errno として現れる。
`crates/net/src/netlink_route.rs` の `classify_errno` は `ENOBUFS` を `ResourceExhausted` に写す（`:1309`）。

## 戻し経路と fail-closed

| 状況 | 扱い |
| ---- | ---- |
| 通知が 0 件（v6.2 より前など） | 従来どおり名前で `link_state` を引き、別名が空なら続行 |
| 通知がちょうど 1 件で、ifindex が正・名前一致・別名なし | その ifindex に印を付ける。`link_state` は呼ばない |
| 通知が 2 件以上・破損・名前不一致・別名あり | `DataLoss`。ACK 済みで作成済みのため `ResolveIndex` で `Unknown` として報告し、印付けも削除もしない |
| 受信バッファあふれで通知が捨てられた | 通知 0 件と同じ戻し経路（`ENOBUFS` が立てば受信が `ResourceExhausted` で失敗し、成功と見なさない。従来と同じ fail-closed。出典は上記 (4)） |

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
- `configure_in_netns` の `netns_link_index`（netns へ移した後の peer の名前による引き直し）は、echo で置き換えない
  （#3293 の判断）
  - 移動は `RTM_SETLINK`（`do_setlink`）の `__dev_change_net_namespace` で行われ、旧 netns への
    `rtmsg_ifinfo_newnet(RTM_DELLINK, ...)` と新 netns での `rtmsg_ifinfo(RTM_NEWLINK, ..., 0, NULL)` はどちらも
    portid 0・`nlh` NULL で、`NLM_F_ECHO` を付けても要求元へ何も返らない
  - 移動先で同じ ifindex が使われていれば別の番号が振られるため、作成時の peer の ifindex は移動先で保たれる保証がない
  - 名前の差し替えができる者は移動先 netns で `CAP_NET_ADMIN` を持つ者で、影響はそのコンテナの netns 内の設定に
    閉じ、ホスト側の資源や権限境界は越えない。移動先に同名の link があれば移動自体が `EEXIST` で失敗する
  - 代替案（実装しない）: 移動要求に `IFLA_NEW_IFINDEX` を載せて移動先の ifindex を固定すれば名前の引き直しが
    不要になり、使用中なら失敗する（fail-closed）。採るなら別 Issue（TASK-139 追補・NET-1）とする。
    `IFLA_NEW_IFINDEX` を受ける `do_setlink` は stable 5.15.y
    （`rtnetlink.c:2693-2694`）・v6.2 にある。focal 5.4.284 の `rtnetlink.c` には通知側の出力（`:1699`）のみが
    見え、要求の受理は確認できなかった（未確認として扱う）

## 確認状況

- 単体・結合試験: `network.rs` の `net1_echo_*`・`net1_attach_veth_echo_*`、`link.rs` の
  `net1_decode_created_link_cases`・`net1_decode_created_veth_cases` ほか、`crates/net/tests/link_create.rs`
- 一次情報（#3293）: 上記「一次情報の確認」のとおり、bridge・veth の newlink の echo 経路・peer の通知・
  stable / Ubuntu の版差を原文で確認済み（前提は一致したため復号の変更なし）。未確認の版は同節に列挙した
- 実機（root）: bridge は `bridge_owner_token_privileged` の (9)、veth は `network_attach_privileged` の
  `veth_echo=index` / `veth_echo=fallback`（v6.2 以上かで出し分け）。実行は人間担当（#1626）で、**未検証**
