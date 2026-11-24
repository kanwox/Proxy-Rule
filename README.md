<div align="center">

<img src="https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color/GitHub.png" width="72" alt="Logo" />

# Proxy Rule

**高效运行 · 稳定使用 · 智能分流**

一套面向现代代理客户端的高性能分流规则库

[![Clash](https://img.shields.io/badge/Clash-5B8DEF?logo=github&logoColor=white)](./Clash/)
[![Concord](https://img.shields.io/badge/Concord-CE422B?logo=github&logoColor=white)](./Concord/)
[![Egern](https://img.shields.io/badge/Egern-0EA5E9?logo=apple&logoColor=white)](./Egern/)
[![Loon](https://img.shields.io/badge/Loon-4B7BEC?logo=apple&logoColor=white)](./Loon/)
[![Quantumult X](https://img.shields.io/badge/Quantumult%20X-7C3AED?logo=apple&logoColor=white)](./QuantumultX/)
[![Shadowrocket](https://img.shields.io/badge/Shadowrocket-FF6B35?logo=apple&logoColor=white)](./Shadowrocket/)
[![Stash](https://img.shields.io/badge/Stash-10B981?logo=apple&logoColor=white)](./Stash/)
[![Surfboard](https://img.shields.io/badge/Surfboard-F59E0B?logo=android&logoColor=white)](./Surfboard/)
[![Surge](https://img.shields.io/badge/Surge-111827?logo=apple&logoColor=white)](./Surge/)
[![Ruleset](https://img.shields.io/badge/Ruleset-MRS%20%2F%20LIST-8B5CF6)](#-核心架构)

</div>

---

## 📥 导入链接

<div align="center">

| 客户端 | 直达链接 | 镜像链接 |
| :---: | :---: | :---: |
| **Clash / Mihomo** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Clash/Clash_rule.js) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Clash/Clash_rule.js` |
| **Concord** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Concord/Concord_rule.js) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Concord/Concord_rule.js` |
| **Egern** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Egern/Egern.yaml) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Egern/Egern.yaml` |
| **Loon** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Loon/Loon.conf) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Loon/Loon.conf` |
| **Quantumult X** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/QuantumultX/QuantumultX.conf) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/QuantumultX/QuantumultX.conf` |
| **Shadowrocket** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Shadowrocket/Shadowrocket.conf) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Shadowrocket/Shadowrocket.conf` |
| **Stash** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Stash/Stash.yaml) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Stash/Stash.yaml` |
| **Surfboard** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Surfboard/Surfboard.conf) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Surfboard/Surfboard.conf` |
| **Surge** | [查看原件](https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Surge/Surge.conf) | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Surge/Surge.conf` |

</div>

> 💡 提示：首次使用需联网拉取远程规则集；导入前请参阅对应客户端说明配置订阅。

---

## 🧩 核心架构

各端配置保持统一的分流策略与交互设计，标配 **HK / JP / SG / TW / US** 常用地区测速组：

```text
主代理
├─ 地区测速组 (HK / JP / SG / TW / US；默认隐藏，Loon 与 Quantumult X 不支持隐藏)
├─ 静态 (有效节点平铺，便捷手动选点)
└─ DIRECT / 直连 (直连)

13 大独立业务组 (可任意指定主代理 / 地区组 / 直连 / 具体节点)
├─ 常用平台：Google · Apple · Microsoft · GitHub · Telegram · X · YouTube · TikTok · Spotify · Steam · PayPal
├─ 人工智能：AI (ChatGPT · Claude · Gemini)
└─ 流媒体聚合：TV (Netflix · Disney+ · HBO · Prime Video · Apple TV+)

分流流水线
防止代理回环 ➜ 局域网/私网 ➜ 广告拦截 ➜ NAS/NTP对时直连 ➜ 核心应用分流 ➜ 海外常用服务 ➜ 大陆域名/IP直连 ➜ 兜底组 (主代理)
（注：Loon [Rule] 与 Quantumult X [filter_local] 本地规则先于远程规则匹配，含回环防护、NTP 对时、Synology 与 Apple TV+；其中 Quantumult X 按常见对时域名列表匹配 NTP）
```

- **真实 IP 白名单**：网络对时 (NTP)、STUN 探测、系统连通性测试及游戏联机直连走真实 IP，避免 Fake-IP 带来连通性异常。
- **分层广告防护**：Mihomo、Concord、Egern、Loon 与 Quantumult X 支持 DNS 层拒绝（Mihomo / Concord / Stash 采用 `AWAvenue-Ads-Rule`，其余端采用 `Reject`）；各端均保留规则层拦截，Surge 与 Shadowrocket 开启 `pre-matching` 预匹配，Stash 默认 `REJECT-DROP,no-track`（iOS 3.7+ / macOS 4.4+ 可按需追加 `pre-matching`）。
- **远程规则托管**：主流平台业务规则集支持自动定期拉取更新；6 端静态配置内联精简的 Synology（20 域名）与 Apple TV+（8 域名）规则，与 Clash / Concord / Stash 的 MetaCubeX（v2fly）geosite 保持完全一致。
- **IPv6 默认开启**：各端默认启用 IPv6（Clash / Concord 尊重订阅显式 `ipv6: false`；Quantumult X 通过省略 `no-ipv6` 默认启用；Stash 自动按网络解析 AAAA，Tunnel IPv6 在客户端界面开关控制），纯 IPv4 环境如遇异常可按需关闭。

---

## ❓ 常见问题

<details>
<summary><b>Q: 为什么首次启动较慢或部分海外网站打不开？</b></summary>
<br>

**A:** 首次加载需联网拉取远程规则集（`.mrs` / `.list` / `.yaml`）。请在客户端日志中确认规则集下载是否成功。
</details>

<details>
<summary><b>Q: 为什么个别地区策略组没有显示或不可用？</b></summary>
<br>

**A:** 策略组根据节点名称正则自动归类，请确认订阅中是否包含对应地区的有效节点。各端默认过滤了包含“流量/到期/官网”等非节点信息条目。
</details>

---

<div align="center">
<sub>本仓库配置与脚本以 MIT 许可证开源（见 LICENSE） · 引用的远程规则集与图标版权归各自上游项目所有 · 仅供网络路由测试与技术交流 · 不提供任何网络节点 · 请遵守当地法律法规</sub>
</div>
