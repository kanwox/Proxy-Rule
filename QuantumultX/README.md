# Quantumult X

适用于 Quantumult X 客户端（iOS / iPadOS / macOS (Apple Silicon) / tvOS）。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/QuantumultX/QuantumultX.conf` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/QuantumultX/QuantumultX.conf` |

</div>

---

## 📖 使用方法

1. 打开 [QuantumultX.conf](./QuantumultX.conf)。
2. 将 `[server_remote]` 中的 `订阅链接填写处` 替换为真实订阅：
   ```ini
   [server_remote]
   你的真实订阅链接, tag=All, update-interval=86400, opt-parser=true, enabled=true
   ```
   > `[general]` 已默认配置 KOP-XIAO 资源解析器（`resource_parser_url`），配合 `opt-parser=true` 可直接导入 Clash / V2Ray / URI 等常见订阅格式；若机场已原生提供 QX 格式订阅，可按需将 `opt-parser` 改为 `false`。
3. 导入 Quantumult X 客户端并启用。

---

## ✨ 核心特性

- **开箱即用解析**：`[general]` 默认启用 KOP-XIAO `resource_parser_url`，配合 `[server_remote]` 的 `opt-parser=true` 自动兼容常见订阅格式。
- **延迟基准测试**：五大地区组使用 `url-latency-benchmark`，结合资源与节点双正则筛选（Quantumult X 不支持隐藏地区策略组，五大地区组将在客户端界面中显示）。
- **策略组映射**：远程规则集全部通过 `force-policy` 接入统一策略组。
- **DNS 白名单与双栈**：默认启用 IPv6 解析，配置完整的 `dns_exclusion_list`（含运营商一键登录域名）与私有局域网域名的系统 DNS 转发。
