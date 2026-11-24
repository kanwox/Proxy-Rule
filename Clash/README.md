# Clash / Mihomo

适用于支持 JavaScript 扩展脚本 / 覆写的 Mihomo 内核客户端（内核需 ≥ 1.19.27，仅支持节点平铺订阅），如 Clash Verge Rev、Clash Party、FlClash 等。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Clash/Clash_rule.js` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Clash/Clash_rule.js` |

</div>

---

## 📖 使用方法

支持**远程链接导入**与**本地粘贴**两种方式（不同客户端入口名分别为「扩展脚本」或「覆写」）：

1. **远程导入（推荐）**：在客户端的脚本 / 覆写管理中新建远程脚本，填入上方直达或镜像链接并绑定到对应订阅。
2. **本地粘贴**：在订阅设置中新建或编辑扩展脚本 / 覆写，复制并贴入 [Clash_rule.js](./Clash_rule.js) 全部内容（便于直接修改顶部可调参数）。
3. 保存并刷新订阅，首次启动时在日志确认规则集下载成功即可。

---

## ✨ 核心特性

- **自动分组**：覆盖 23 个国家/地区，同地区节点 ≥2 个自动创建测速组（仅使用官方 Mihomo 原生 `url-test`，无需第三方 Smart 分支）。
- **连接嗅探**：启用 HTTP/TLS/QUIC 嗅探与 `parse-pure-ip`，仅跳过官方最小 `skip-domain`（`Mijia Cloud`、`+.push.apple.com`），确保纯 IP 连接正确还原域名。
- **DNS 优化**：Fake-IP (ARC) + `fake-ip-filter-mode: rule`（优先保证 Apple / Google / Microsoft / AI 域名走 Fake-IP，防止国内 CDN 绕过分流）；国内采用 IP-DoH（`223.5.5.5` / `1.12.12.12`）。
- **广告拦截**：广告规则集采用 `AWAvenue-Ads-Rule`（`.mrs` 格式），兼顾国内外应用广告 SDK 与低误杀率，并在 DNS 层直接拒答。
- **节点净化**：自动过滤流量/到期等提示节点，重名自动编号，为 VLESS / VMess / Trojan / AnyTLS 补全 Chrome uTLS 指纹。
- **IPv6 默认开启**：与其他端一致；订阅显式 `ipv6: false` 则尊重，纯 IPv4 环境如遇异常可显式关闭。
- **注意事项**：规则内置 `IN-TYPE,TUN` + `DST-PORT,853` 阻断以防 DoT 绕过分流；Android 如开启系统「私人 DNS」并设为严格指定主机名可能断网，请改为「自动」或关闭。

---

## ⚙️ 参数微调

如需调整行为，可在本地脚本中修改 [Clash_rule.js](./Clash_rule.js) 头部常量：

<div align="center">

| 参数 | 默认值 | 说明 |
| :---: | :---: | :--- |
| `DEFAULT_IP_VERSION` | `"dual"` | 节点双栈策略：`dual` / `ipv6-prefer` / `ipv4-prefer` |
| `REGION_MIN_NODES` | `2` | 创建地区测速组的最低节点数量 |
| `RS_INTERVAL` | `604800` | 规则集更新周期（秒，默认 7 天） |
| `CN_DNS_DOH` | `["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]` | 国内加密 DNS（IP-DoH，用于 `cn-domain` 与默认节点解析） |
| `CN_DNS_PLAIN` | `["223.5.5.5", "119.29.29.29"]` | 国内明文 IP DNS（用于 `default-nameserver` 与 `direct-nameserver`） |
| `TEST_URL_PROXY` | `"https://www.gstatic.com/generate_204"` | 地区 `url-test` 测速地址（期望状态码 204） |
| `PREFER_H3` | `false` | DoH 并发尝试 HTTP/3（UDP 受限网络建议保持 `false`） |
| `BLOCK_QUIC` | `false` | 阻断 UDP 443 迫使回退 TCP（国内直连 QUIC 也会一并回退） |

</div>
