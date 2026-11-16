# Concord

适用于 [Concord](https://github.com/chen08209/concord) 内核（Rust 实现的 Clash/mihomo 兼容内核，仅支持节点平铺订阅），如 FlClash `rs` 分支等内置 Concord 的客户端。

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
2. 选择订阅并编辑其扩展脚本 / 覆写脚本。
3. 复制并贴入 [Concord_rule.js](./Concord_rule.js) 全部内容。
4. 保存并刷新订阅即可。

> 脚本以 `main(config)` 为入口，由客户端在生成配置前调用，返回替换后的完整配置。Concord 内核本身不执行脚本。

---

## ✨ 核心特性

- **自动分组**：覆盖 23 个国家/地区，同地区节点 ≥2 个自动创建测速组（`url-test`）。
- **配置自生成**：订阅只提供节点，策略组、规则集、规则、DNS、嗅探由脚本生成，天然不含内核会告警的字段。
- **节点净化**：剔除内核不支持的节点类型 / 传输 / 插件，改写废弃指纹，自动过滤流量、到期等提示节点，重名自动编号。
- **引用修复**：清理悬空的 `dialer-proxy`，避免内核因悬空引用拒绝整份配置。
- **连接嗅探**：启用 HTTP/TLS/QUIC 嗅探与 `parse-pure-ip`，还原真实域名分流。
- **DNS 优化**：Fake-IP 分流，国内 DoH 解析，广告域名 DNS 层直接拒答。

---

## 🔍 与 Clash 版的差异

Concord 读取 Clash/mihomo 配置，但把字段分成「支持 / 忽略并告警 / 未知」三档，并会在遇到非法字段、悬空引用或错误规则时**直接拒绝整份配置**。因此本脚本相比 [Clash_rule.js](../Clash/Clash_rule.js) 多了一层清洗逻辑：

<div align="center">

| 项目 | 处理方式 |
| :--- | :--- |
| 订阅的角色 | 只提供节点；策略组、规则集、规则、DNS、嗅探全部由脚本生成 |
| 节点类型 | 只保留内核支持的 18 种；`tailscale` / `openvpn` / `masque` 等会被剔除 |
| 节点选项 | `shadow-tls-opts` / `restls-opts` / `jls-opts` / `tlsmirror-opts`、SS 插件 `restls` / `kcptun` 等连同节点一并剔除 |
| 废弃指纹 | `chrome_psk` / `randomized` 等改写为 `chrome` / `random` |
| `dialer-proxy` | 指向不存在节点或策略组时移除该字段 |
| 订阅的其他段 | `dns` / `tun` / `sniffer` / `ntp` / `experimental` / `tls` / `geox-url` 等不继承，由脚本生成或交给客户端默认 |
| `tun` / `hosts` | 仅继承 `tun.enable`；`hosts` 过滤内核不接受的条目 |
| `ipv6` | **默认开启**，仅当订阅显式设为 `false` 时关闭 |

</div>

---

## ⚙️ 参数微调

如需调整行为，可修改 [Concord_rule.js](./Concord_rule.js) 头部常量：

<div align="center">

| 参数 | 默认值 | 说明 |
| :---: | :---: | :---: |
| `DEFAULT_IP_VERSION` | `"dual"` | 双栈策略：`dual` / `ipv6-prefer` / `ipv4-prefer` |
| `REGION_MIN_NODES` | `2` | 创建地区测速组的最低节点数量 |
| `BLOCK_QUIC` | `false` | 阻断 UDP 443 迫使回退 TCP |
| `RS_INTERVAL` | `604800` | 规则集更新周期（秒，默认 7 天） |

</div>
