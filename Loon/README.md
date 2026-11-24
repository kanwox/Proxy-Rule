# Loon

适用于 Loon 客户端（iOS 3.2.5 (789)+ / macOS / tvOS）。

---

## 📥 导入链接

<div align="center">

| 类型 | 链接 |
| :---: | :---: |
| **直达链接** | `https://raw.githubusercontent.com/kanwox/Proxy-Rule/main/Loon/Loon.conf` |
| **镜像链接** | `https://cdn.jsdmirror.com/gh/kanwox/Proxy-Rule@main/Loon/Loon.conf` |

</div>

---

## 📖 使用方法

1. 打开 [Loon.conf](./Loon.conf)。
2. 将 `[Remote Proxy]` 下 `机场订阅` 中的 `订阅链接填写处` 替换为真实订阅：
   ```ini
   [Remote Proxy]
   机场订阅 = 你的真实订阅链接,parser-enabled=false,...
   ```
   > 若机场仅提供 Clash YAML 格式订阅，请在 `[General]` 中配置 `resource-parser`（如 Sub-Store 解析脚本），并将该订阅行的 `parser-enabled=false` 改为 `parser-enabled=true`。
3. 导入 Loon 客户端并启用。

---

## ✨ 核心特性

- **节点过滤与测速**：通过 `[Remote Filter]` 正则筛选节点，五大地区组使用 `url-test` 自动测速（Loon 不支持隐藏地区策略组，五大地区组将在客户端界面中显示）。
- **双栈与 DNS**：采用 `ip-mode = dual`、IP-DoH 与 `hijack-dns = *:53`（需 Loon 3.2.5 (789)+），支持 SNI 嗅探、Fake-IP 白名单与 DNS 层广告拒答。
- **轻量设计**：默认不加载外部资源解析脚本（`parser-enabled=false`），确保低资源开销；需要导入 Clash YAML 订阅时再按需启用 `resource-parser`。
