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
- **字段清洗**：按 Concord 的字段白名单裁剪订阅，剔除内核会告警的 T2 字段与未知字段。
- **节点净化**：剔除内核不支持的节点类型 / 传输 / 插件，改写废弃指纹，自动过滤流量、到期等提示节点，重名自动编号。
- **引用修复**：清理悬空的 `dialer-proxy` 与 DNS `#目标`，避免内核因悬空引用拒绝整份配置。
- **连接嗅探**：启用 HTTP/TLS/QUIC 嗅探与 `parse-pure-ip`，还原真实域名分流。
- **DNS 优化**：Fake-IP 分流，国内 DoH 解析，广告域名 DNS 层直接拒答。

---

## 🔍 与 Clash 版的差异

Concord 读取 Clash/mihomo 配置，但把字段分成「支持 / 忽略并告警 / 未知」三档，并会在遇到非法字段、悬空引用或错误规则时**直接拒绝整份配置**。因此本脚本相比 [Clash_rule.js](../Clash/Clash_rule.js) 多了一层清洗逻辑：

| 项目 | 处理方式 |
| :--- | :--- |
| 顶层字段 | 只输出 Concord 读取的字段；`external-controller`、`secret`、`sub-rules` 不输出 |
| `geodata-mode` 等 T2 字段 | 一律不输出（内核会忽略并告警） |
| 节点类型 | 只保留内核支持的 18 种；`tailscale` / `openvpn` / `masque` 等会被剔除 |
| 节点选项 | `shadow-tls-opts` / `restls-opts` / `jls-opts` / `tlsmirror-opts`、SS 插件 `restls` / `kcptun` 等连同节点一并剔除 |
| 废弃指纹 | `chrome_psk` / `randomized` 等改写为 `chrome` / `random` |
| `dialer-proxy` | 指向不存在节点时移除该字段 |
| `dns` | `default-nameserver` 强制纯 IP；`listen` 不输出；`fake-ip-filter` / `nameserver-policy` 只继承合法的域名条目；悬空 `#目标` 修正为 `#RULES` |
| `tun` | 删除内核不生效的 `gso`；`stack` 为 `mixed` / `system` 时不输出，交回客户端默认值 |
| `hosts` | 删除值为 `lan` 的条目与非法域名 |
| `experimental` / `tls` | 只继承内核真正读取的键（`fingerprints`、`dialer-ip4p-convert`、`custom-certifactes`），会告警的键不输出 |
| `dns` 上游 | 订阅的 `nameserver` / `default-nameserver` / `proxy-server-nameserver` / `direct-nameserver` / `fallback` 优先继承，未设置才用脚本默认 |
| `ipv6` | **默认开启**，仅当订阅显式设为 `false` 时关闭 |

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
