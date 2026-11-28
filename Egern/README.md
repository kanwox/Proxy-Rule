# Egern

适用于 Egern 客户端（iOS / iPadOS / macOS / tvOS）。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Egern/Egern.yaml` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Egern/Egern.yaml` |

</div>

---

## 📖 使用方法

1. 打开 [Egern.yaml](./Egern.yaml)。
2. 将 `静态` 策略组中 `urls` 下的 `订阅链接填写处` 替换为真实订阅链接（其余业务组与 `兜底` 通过 YAML 锚点自动复用）：
   ```yaml
   - select:
       name: 静态
       urls: &sub_urls
         - "你的真实订阅链接"
   ```
3. 导入 Egern 并启用配置。

---

## ✨ 核心特性

- **原生 YAML**：基于 Egern 原生规范组织分流与策略，开启策略切换自动断连（`close_connections_on_policy_change`），并在全部业务组与 `兜底` 中通过 YAML 1.2 锚点直接展开单节点。
- **Smart 选优**：各地区组通过 `flatten` 展开节点，采用 `smart` 策略自动择优。
- **DNS 层去广告与防污染**：在 `dns.forward` 中引入 `Reject.yaml` 实现 DNS 层拦截，并启用 `hijack_dns` 与 `block_ips` 拦截硬编码 DNS 并过滤污染回环响应，海外 DoH 经 `主代理` 强制出站。
- **规则集与内联精简**：局域网、群晖（Synology）与 Apple TV+ 采用内联规则精准分流；因非国内域名默认经代理走海外 DoH 不会泄露国内 DNS，国内 IP 使用原生 `geoip: CN` 直接解析匹配，确保未收录国内域名也能准确直连。
