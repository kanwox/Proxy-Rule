# Concord

适用于支持 JavaScript 扩展脚本的 [Concord](https://github.com/chen08209/concord) 内核客户端（如 FlClash），仅支持节点平铺订阅。Concord 是 Rust 实现的独立代理内核，配置采用 Clash 格式；本脚本与 Clash / Mihomo 版保持统一的分流策略，并针对 Concord 的字段支持范围做了净化适配。

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

- **自动分组**：覆盖 23 个国家/地区，同地区节点 ≥2 个自动创建测速组（`url-test`）。
- **连接嗅探**：启用 HTTP/TLS/QUIC 嗅探与 `parse-pure-ip`，还原真实域名分流。
- **DNS 优化**：Fake-IP (ARC)，国内 DoH 解析，广告域名 DNS 层直接拒答。
- **节点净化**：自动过滤流量/到期等提示节点，重名自动编号，补全 Chrome uTLS 指纹。
- **字段净化**：静默剔除 Concord 不支持的节点类型/传输/加密与 DNS 协议，废弃字段自动迁移为等价新写法，清理非法 hosts 与悬空引用，避免不兼容告警与整份拒载。
- **尊重客户端设置**：TUN、局域网开关、端口等客户端自管设置原样透传，仅删除内核不应用的死键，不改变任何生效设置。
- **IPv6 默认开启**：与其他端一致；订阅显式 `ipv6: false` 则尊重，纯 IPv4 环境如遇异常可显式关闭。

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
