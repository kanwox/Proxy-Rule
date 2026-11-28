# Concord

适用于支持 JavaScript 扩展脚本的 [Concord](https://github.com/Vialibrex/concord) 内核客户端（如 FlClash），仅支持节点平铺订阅。Concord 是 Rust 实现的独立代理内核，配置采用 Clash 格式；本脚本与 Clash / Mihomo 版保持统一的分流策略，并针对 Concord 的字段支持范围做了净化适配。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Concord/Concord_rule.js` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Concord/Concord_rule.js` |

</div>

---

## 📖 使用方法

1. 打开客户端，进入订阅设置。
2. 选择订阅并编辑其扩展脚本 / 预处理脚本。
3. 复制并贴入 [Concord_rule.js](./Concord_rule.js) 全部内容。
4. 保存并刷新订阅即可。

---

## ✨ 核心特性

- **自动分组**：覆盖 23 个国家/地区，同地区节点 ≥2 个自动创建 **Concord 原生 `smart` 智能组**（支持连接失败自动换节点重拨与 1 小时域名粘性，可通过 `REGION_GROUP_TYPE` 切回 `url-test`）。
- **连接嗅探**：启用 HTTP/TLS/QUIC 嗅探与 `parse-pure-ip`，还原真实域名分流；`skip-domain` 精简为米家与 Apple Push（`+.push.apple.com`）。
- **DNS 优化**：Fake-IP (ARC) + **`fake-ip-filter-mode: rule`**（Apple / Google / Microsoft / AI 优先 `fake-ip`，避免国内 CDN 域名被 `cn-domain` 截走 `real-ip`），国内 IP-DoH 解析（`223.5.5.5` / `1.12.12.12`），广告域名接入 **AWAvenue-Ads-Rule** 并在 DNS 层直接拒答。
- **节点净化**：自动过滤流量/到期等提示节点，重名自动编号并同步重写 `dialer-proxy` 引用，为 TLS 节点（`vless`/`vmess`/`trojan`/`anytls`、带 `shadow-tls`/`jls` 的 `snell` 与 XHTTP `download-settings`）补全 Chrome uTLS 指纹（保留 `chrome120`）。
- **字段净化**：静默剔除 Concord 不支持的顶层/分段死键与节点类型/传输/加密/DNS 协议（原生保留 `tailscale`、`ts://`、`tuic-server` 与 DNS `#网卡名` 绑定），规范化大小写与下划线键名，过滤非法 `DomainTrie` 域名模式，清理非法 hosts 与悬空/成环引用，避免不兼容告警与整份拒载。
- **继承与覆写边界清晰**：
  - **原样继承**：客户端/订阅自管设置如 `dns.listen`（未设置时默认 `127.0.0.1:1053`）、`tun`（仅剔除内核不应用的死键）、`mixed-port`、`allow-lan`、`lan-allowed-ips`、`lan-disallowed-ips`、`listeners` / `tunnels` / `ss-config` / `vmess-config`（并自动清洗悬空的 `rule` 与 `proxy` 引用）、`mode`、`log-level`、`external-controller`、`ntp`、`mitm` 等原样透传；`ipv6` 默认开启，若订阅显式设为 `false` 则尊重。
  - **脚本覆写**：统一设置 `basicOptions`（`unified-delay`、`tcp-concurrent`、`find-process-mode: off`、TCP 保活）、`sniffer`、DNS 分流与 `fake-ip-filter-mode: rule`、`rule-providers`、`proxy-groups` 与 `rules`。

---

## ⚙️ 参数微调

如需调整行为，可修改 [Concord_rule.js](./Concord_rule.js) 头部常量：

<div align="center">

| 参数 | 默认值 | 说明 |
| :---: | :---: | :--- |
| `DEFAULT_IP_VERSION` | `"dual"` | 双栈策略：`dual` / `ipv6-prefer` / `ipv4-prefer` |
| `REGION_GROUP_TYPE` | `"smart"` | 地区组策略类型：`smart`（Concord 原生智能组）或 `url-test` |
| `REGION_MIN_NODES` | `2` | 创建地区组的最低节点数量 |
| `RS_INTERVAL` | `604800` | 规则集更新周期（秒，默认 7 天） |
| `CN_DNS_DOH` | `["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]` | 国内域名与节点解析默认使用的 IP-DoH 上游 |
| `CN_DNS_PLAIN` | `["223.5.5.5", "119.29.29.29"]` | 引导 DNS（`default-nameserver`）与直连兜底 DNS（`direct-nameserver`） |
| `TEST_URL_PROXY` | `"https://www.gstatic.com/generate_204"` | 地区组延迟探测 URL |
| `PREFER_H3` | `false` | DoH 并发尝试 HTTP/3（UDP 受限环境下建议保持关闭） |
| `BLOCK_QUIC` | `false` | 阻断 UDP 443 迫使回退 TCP（仅节点不支持 UDP 时开启） |

</div>
