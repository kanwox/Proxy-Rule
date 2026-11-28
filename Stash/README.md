# Stash

适用于 Stash 客户端（iOS 3.6+ / iPadOS 3.6+ / macOS 4.3+ / tvOS）。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Stash/Stash.yaml` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Stash/Stash.yaml` |

</div>

---

## 📖 使用方法

1. 打开 [Stash.yaml](./Stash.yaml)。
2. 将顶部 `proxy-providers.All.url` 中的 `订阅链接填写处` 替换为真实订阅：
   ```yaml
   proxy-providers:
     All:
       url: "你的真实订阅链接"
   ```
3. 导入 Stash 客户端并启用。

---

## ✨ 核心特性

- **地区测速**：内置 5 大常用地区测速组（HK / JP / SG / TW / US），正则自动归类节点，使用 HTTP `benchmark-url` 降低握手测速开销。
- **规则集与去广告**：采用 MetaCubeX `.mrs` 二进制规则集，广告拦截采用 [AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) `.mrs` 并默认 `REJECT-DROP,no-track`（iOS 3.7+ / macOS 4.4+ Beta 及支持版本可追加 `,pre-matching` 在 DNS 层拦截）。
- **Smart 组提示**：iOS / tvOS / macOS 5.1+ Beta 起已新增 `type: smart` 原生智能组支持，有需求的用户可按需将地区组由 `url-test` 切换为 `smart`。
- **DNS 与内置嗅探**：国内 IP-DoH 加密解析与精细 Fake-IP 过滤名单，依赖 Stash 内核自动 SNI / HTTP / QUIC 域名嗅探（无需 `sniffer:` 配置块）。
- **IPv6 说明**：省略 `ipv6` 选项时，Stash 根据当前网络自动决定是否解析 AAAA 记录；如需接管 IPv6 流量，请在 Stash 客户端界面手动开启 Tunnel IPv6 开关。
