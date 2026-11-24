# Surge

适用于 Surge 客户端（iOS 5.14.0+ / Mac 5.9.0+；Mac 端图标展示需 6.5.0+）。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Surge/Surge.conf` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Surge/Surge.conf` |

</div>

---

## 📖 使用方法

1. 打开 [Surge.conf](./Surge.conf)。
2. 将 `[Proxy Group]` 中 `静态` 策略组的 `policy-path="订阅链接填写处"` 替换为真实订阅：
   ```ini
   静态 = select, policy-path="你的真实订阅链接", update-interval=86400, ...
   ```
3. 导入 Surge 客户端并启用。

---

## ✨ 核心特性

- **Smart 智能选点**：五大地区组采用 `smart` 策略，结合连接延迟与历史记忆自动优选节点。
- **现代加密 DNS**：使用 IP 直连 DoH（`encrypted-dns-server`）与 `[Host]` 局域网系统解析，避免引导依赖与内网域名解析失败。
- **深度匹配与拦截**：内置 `SYSTEM` / `LAN` 规则集、广告规则 `pre-matching` 预匹配，以及业务规则集 `extended-matching` 扩展匹配。
