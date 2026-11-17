// Concord_rule.js V1.1
// Concord 内核（https://github.com/chen08209/concord）的订阅覆写脚本。
// Concord 是独立的代理内核，配置采用 Clash 格式；本脚本从节点平铺的订阅
// 生成地区组、应用分流与 fake-ip DNS。
// 订阅中内核不支持的字段按黑名单静默丢弃，未知键保留；
// 客户端自管设置原样透传，仅删除内核不应用的死键（不改变任何生效设置）。
// 黑名单来源：concord crates/config/src/keys.rs、proxy/parse.rs、docs/compatibility.md。
// 首次启动联网下载规则集，在日志确认全部下载成功。

// ── 可调参数（集中维护） ──
const DEFAULT_IP_VERSION = "dual"; // 双栈偏好：dual(并发择优) / ipv6-prefer / ipv4-prefer
const REGION_MIN_NODES = 2;        // 达到该值才建组
const RS_INTERVAL = 604800;        // 规则集更新周期：一周
const CN_DNS_DOH = [
    "https://223.5.5.5/dns-query",
    "https://doh.pub/dns-query"
];
const CN_DNS_PLAIN = ["223.5.5.5", "119.29.29.29"];
const TEST_URL_PROXY = "https://www.gstatic.com/generate_204";
const PREFER_H3 = false;          // DoH 并发尝试 HTTP/3：UDP 被限速或不支持时反而更慢
const BLOCK_QUIC = false;         // 拒绝 UDP 443 迫使回退 TCP；仅节点不支持 UDP 时开（国内直连 QUIC 会一并回退）

// 部分客户端脚本引擎无 console.warn：统一经此降级输出，避免 TypeError 中断转换
const warnLog = (...args) => {
    if (typeof console === "undefined") return;
    if (typeof console.warn === "function") console.warn(...args);
    else if (typeof console.log === "function") console.log(...args);
};

const isPlainObject = value =>
    value &&
    typeof value === "object" &&
    !Array.isArray(value);

// ── 字段净化：黑名单与节点级助手 ──
// 只处理订阅透传内容；黑名单外的未知键保留

// Concord 未实现的 mihomo 扩展功能键（keys.rs TOP_T2），静默丢弃。
// allow-lan 与 LAN 名单等客户端设置不在此列；LAN 名单存在时 Concord 拒绝开放局域网监听
const CONCORD_TOP_DROP = [
    "geodata-mode", "listeners", "tunnels", "ss-config", "vmess-config",
    "tuic-server", "iptables", "clash-for-android", "inbound-tfo",
    "inbound-mptcp", "bind-address",
    "external-controller-pipe", "external-controller-unix",
    "external-controller-tls", "external-controller-routing-mark",
    "external-ui", "external-ui-url", "external-ui-name",
    "external-doh-server", "geosite-matcher", "etag-support",
    "global-client-fingerprint"
];

// 客户端设置段落中 Concord 不应用的死键：删除不改变任何生效设置，仅消除忽略告警。
// 内核读取并生效的设置（allow-lan、LAN 名单、tun.stack、端口等）不在此列

// tun（keys.rs TUN_T2 + gso）
const CONCORD_TUN_DROP = [
    "gso", "dns-mode", "gso-max-size", "inet6-address",
    "iproute2-table-index", "iproute2-rule-index", "auto-redirect",
    "auto-redirect-input-mark", "auto-redirect-output-mark",
    "auto-redirect-iproute2-fallback-rule-index", "loopback-address",
    "route-address-set", "route-exclude-address-set",
    "include-uid-range", "exclude-uid-range",
    "exclude-src-port-range", "exclude-dst-port-range",
    "include-android-user", "include-package", "exclude-package",
    "include-mac-address", "exclude-mac-address",
    "endpoint-independent-nat", "icmp-timeout", "file-descriptor",
    "recvmsgx", "sendmsgx", "processors-per-channel"
];

// experimental：quic-go 开关不被应用
const CONCORD_EXPERIMENTAL_DROP = [
    "quic-go-disable-gso", "quic-go-disable-ecn"
];

// tls 入站设置不被使用（custom-certifactes 生效，不删）
const CONCORD_TLS_DROP = [
    "certificate", "private-key", "client-auth-type",
    "client-auth-cert", "ech-key"
];

// amnezia-wg-option v3 中 Concord 不应用的子键（proxy/warn.rs），删除消告警。
// random-trailers 部分生效、header-protection-key 生效，均不删；仅 v3 处理，
// 其余版本不产生这些告警
const CONCORD_AMNEZIA_DROP = [
    "content-padding-addition", "rekey-after-time", "rekey-timeout",
    "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
    "disable-cookies"
];

// 不支持的节点类型（parse.rs T2_PROXY_TYPES）：保留会被 Concord 隔离，引用组拒绝连接
const CONCORD_NODE_TYPE_DROP = new Set([
    "tailscale", "easytier", "zerotier", "openvpn", "sudoku", "trusttunnel"
]);

// 不支持的传输网络（parse.rs T2_NETWORKS）
const CONCORD_NETWORK_DROP = new Set(["mkcp", "kcp", "mekya"]);

// 不支持的 TLS 选项（parse.rs T2_TLS_KEYS）：出现即隔离节点（含 xhttp download-settings 内）
const CONCORD_TLS_OPT_DROP = ["restls-opts", "tlsmirror-opts"];

// 不支持的 ss 插件（parse.rs T2_SS_PLUGINS）
const CONCORD_SS_PLUGIN_DROP = new Set(["restls", "kcptun"]);

// Concord 不支持的 ss 加密方式
const CONCORD_SS_CIPHER_DROP = new Set([
    "aes-192-gcm", "aes-192-ccm", "chacha8-ietf-poly1305",
    "xchacha8-ietf-poly1305", "rabbit128-poly1305", "aegis-128l",
    "aegis-256", "aez-384", "deoxys-ii-256-128",
    "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
    "ascon128", "ascon128a",
    "2022-blake3-aes-128-ccm", "2022-blake3-aes-256-ccm"
]);

// Concord 不支持的 DNS 上游协议（剔除后清空的 policy 键会成 REFUSED 黑洞）
const CONCORD_DNS_SCHEME_DROP = /^(ts|tailscale|et|easytier):\/\//i;

// 节点准入：丢弃 Concord 会隔离/拒绝构建的节点，避免策略组引用后整组拒绝连接
const concordNodeSupported = proxy => {
    const type = String(proxy.type || "").toLowerCase();
    if (CONCORD_NODE_TYPE_DROP.has(type)) return false;
    if (CONCORD_NETWORK_DROP.has(String(proxy.network || "").toLowerCase())) {
        return false;
    }

    const download = isPlainObject(proxy["download-settings"])
        ? proxy["download-settings"]
        : {};
    if (
        CONCORD_TLS_OPT_DROP.some(
            key => proxy[key] !== undefined || download[key] !== undefined
        )
    ) {
        return false;
    }

    if (type === "ss") {
        const plugin = String(proxy.plugin || "").toLowerCase();
        if (CONCORD_SS_PLUGIN_DROP.has(plugin)) return false;
        if (
            CONCORD_SS_CIPHER_DROP.has(
                String(proxy.cipher || "").toLowerCase()
            )
        ) {
            return false;
        }
        // v2ray-plugin + ech-opts：构建时拒绝
        if (plugin === "v2ray-plugin" && proxy["ech-opts"]) return false;
    }

    // REALITY over ws：无法构建可用节点
    if (
        proxy["reality-opts"] &&
        String(proxy.network || "").toLowerCase() === "ws"
    ) {
        return false;
    }
    // Hysteria faketcp 不支持
    if (
        type === "hysteria" &&
        String(proxy.protocol || "").toLowerCase() === "faketcp"
    ) {
        return false;
    }
    // mieru UDP 传输 + dialer-proxy：构建时拒绝
    if (
        type === "mieru" &&
        String(proxy.transport || "").toUpperCase() === "UDP" &&
        proxy["dialer-proxy"]
    ) {
        return false;
    }
    // hysteria2 realm-opts + dialer-proxy：构建时拒绝
    if (type === "hysteria2" && proxy["realm-opts"] && proxy["dialer-proxy"]) {
        return false;
    }

    return true;
};

// 节点字段规范化：废弃字段迁移为等价新写法，Concord 忽略的字段删除
const concordNormalizeNode = proxy => {
    // 变体键归一：内核不折叠 type 键本身，type 值区分大小写；
    // 先归一，准入检查与引用校验才能捕获
    ["type", "dialer-proxy"].forEach(canonical => {
        if (canonical in proxy) return;
        const variant = Object.keys(proxy).find(
            key =>
                String(key).toLowerCase().replace(/_/g, "-") === canonical
        );
        if (variant) {
            proxy[canonical] = proxy[variant];
            delete proxy[variant];
        }
    });
    if (typeof proxy.type === "string") proxy.type = proxy.type.toLowerCase();
    if (typeof proxy.plugin === "string") {
        proxy.plugin = proxy.plugin.toLowerCase();
    }

    // ws-path/ws-headers 为 mihomo 已废弃的字段：迁移为 ws-opts，保留功能
    if (
        proxy["ws-path"] !== undefined ||
        proxy["ws-headers"] !== undefined
    ) {
        const opts = isPlainObject(proxy["ws-opts"])
            ? proxy["ws-opts"]
            : {};
        if (proxy["ws-path"] !== undefined && opts.path === undefined) {
            opts.path = proxy["ws-path"];
        }
        if (
            proxy["ws-headers"] !== undefined &&
            opts.headers === undefined
        ) {
            opts.headers = proxy["ws-headers"];
        }
        proxy["ws-opts"] = opts;
        delete proxy["ws-path"];
        delete proxy["ws-headers"];
    }

    // 非 map 的 smux 无效，删除
    if ("smux" in proxy && !isPlainObject(proxy.smux)) delete proxy.smux;

    // 废弃指纹名规范化为 chrome/random
    const fp = proxy["client-fingerprint"];
    if (typeof fp === "string") {
        if (/^chrome/i.test(fp)) proxy["client-fingerprint"] = "chrome";
        else if (fp.toLowerCase() === "randomized") {
            proxy["client-fingerprint"] = "random";
        }
    }

    // mode/userkey 仅 snell v6 有效，其余版本删除（version 缺省按非 v6 处理）
    if (String(proxy.type || "").toLowerCase() === "snell") {
        if (Number(proxy.version) !== 6) {
            delete proxy.mode;
            delete proxy.userkey;
        }
    }

    // amnezia v3 不应用的子键删除
    const amnezia = proxy["amnezia-wg-option"];
    if (isPlainObject(amnezia) && Number(amnezia.version) === 3) {
        CONCORD_AMNEZIA_DROP.forEach(key => delete amnezia[key]);
    }
};

// dialer-proxy 引用校验：悬空引用与环会让 Concord 拒绝整份配置。
// 悬空删字段；成环删除环上节点的 dialer-proxy 断环
const concordFixDialers = (proxies, groups) => {
    const known = new Set([
        ...proxies.map(proxy => proxy.name),
        ...groups.map(group => group.name),
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE"
    ]);
    proxies.forEach(proxy => {
        const target = proxy["dialer-proxy"];
        if (
            typeof target === "string" &&
            target !== "" &&
            !known.has(target)
        ) {
            delete proxy["dialer-proxy"];
        }
    });

    const byName = new Map(proxies.map(proxy => [proxy.name, proxy]));
    const done = new Set();
    proxies.forEach(proxy => {
        if (done.has(proxy.name)) return;
        const path = [];
        const onPath = new Set();
        let cur = proxy.name;
        while (byName.has(cur) && !done.has(cur)) {
            if (onPath.has(cur)) {
                for (let i = path.indexOf(cur); i < path.length; i++) {
                    delete byName.get(path[i])["dialer-proxy"];
                }
                break;
            }
            onPath.add(cur);
            path.push(cur);
            const next = byName.get(cur)["dialer-proxy"];
            if (typeof next !== "string" || next === "") break;
            cur = next;
        }
        path.forEach(name => done.add(name));
    });
};

// hosts 清洗：非法键/值、多值非全 IP、自映射、别名环会被 Concord 拒载或跳过。
// lan 值与指向已删条目的别名合法，保留
const concordCleanHosts = hosts => {
    const isIp = value => {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
            return value.split(".").every(part => Number(part) <= 255);
        }
        if (!value.includes(":")) return false;
        const halves = value.split("::");
        if (halves.length > 2) return false;
        const groups = s => (s === "" ? [] : s.split(":"));
        const validGroup = g =>
            /^[0-9a-fA-F]{1,4}$/.test(g) ||
            /^\d{1,3}(\.\d{1,3}){3}$/.test(g);
        const left = groups(halves[0]);
        const right = halves.length === 2 ? groups(halves[1]) : [];
        if (![...left, ...right].every(validGroup)) return false;
        return halves.length === 2
            ? left.length + right.length <= 7
            : left.length === 8;
    };
    const validKey = key =>
        key !== "" &&
        !key.startsWith(".") &&
        !key.endsWith(".") &&
        !/\s/.test(key);
    const itemsOf = value => {
        const list = Array.isArray(value) ? value : [value];
        if (
            list.length === 0 ||
            list.some(
                item =>
                    typeof item !== "string" &&
                    typeof item !== "number" &&
                    typeof item !== "boolean"
            )
        ) {
            return null;
        }
        return list.map(item => String(item));
    };

    const deleted = new Set();
    const alias = new Map();
    const lowerKeys = new Map(
        Object.keys(hosts).map(key => [key.toLowerCase(), key])
    );

    Object.keys(hosts).forEach(key => {
        const items = itemsOf(hosts[key]);
        if (
            !validKey(key) ||
            items === null ||
            (items.length > 1 && items.some(item => !isIp(item)))
        ) {
            deleted.add(key);
            return;
        }
        if (items.length === 1) {
            const value = items[0];
            if (value !== "lan" && !isIp(value)) {
                if (value.toLowerCase() === key.toLowerCase()) {
                    deleted.add(key);
                    return;
                }
                alias.set(key.toLowerCase(), value.toLowerCase());
            }
        }
    });

    // 别名环（大小写不敏感）：删除环上条目
    alias.forEach((target, start) => {
        if (deleted.has(lowerKeys.get(start))) return;
        const chain = [];
        const onChain = new Set();
        let cur = start;
        while (
            cur !== undefined &&
            alias.has(cur) &&
            !deleted.has(lowerKeys.get(cur))
        ) {
            if (onChain.has(cur)) {
                for (let i = chain.indexOf(cur); i < chain.length; i++) {
                    deleted.add(lowerKeys.get(chain[i]));
                }
                break;
            }
            onChain.add(cur);
            chain.push(cur);
            cur = alias.get(cur);
        }
    });

    deleted.forEach(key => delete hosts[key]);
};

function main(params) {
    if (!params || typeof params !== "object") params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    // 内核要求节点名非空且唯一，空名或 name 非字符串会让整份配置启动失败，直接丢弃
    params.proxies = params.proxies.filter(
        proxy =>
            proxy &&
            typeof proxy.name === "string" &&
            proxy.name !== ""
    );

    // ── 字段净化：节点准入与规范化 ──
    // 先规范化再准入，变体键与大小写差异不会漏过检查；
    // 不支持的节点先行丢弃，后续地区统计、组生成与 DNS 引用校验自然将其排除
    params.proxies.forEach(concordNormalizeNode);
    params.proxies = params.proxies.filter(concordNodeSupported);

    // proxy-providers 订阅的节点在内核运行时才拉取，预处理脚本无法读取节点列表来生成地区组与过滤规则；
    // 不支持该形态，直接拒绝生成
    if (Object.keys(params["proxy-providers"] || {}).length > 0) {
        throw new Error(
            "[Concord_rule.js] 检测到 proxy-providers 订阅，本脚本仅支持节点平铺的订阅形式，已拒绝生成配置。"
        );
    }

    // 记住面板手动选择与 fake-ip 缓存；订阅已设置的项以订阅为准
    params.profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        isPlainObject(params.profile) ? params.profile : {}
    );

    // 订阅原始 rule-providers 快照：判断 rule-set: 依赖是否确有定义，须在下方覆写前读取
    const subRuleProviders = Object.assign(
        {},
        params["rule-providers"] || {}
    );

    const basicOptions = {
        "unified-delay": true,
        "tcp-concurrent": true,
        // 不匹配进程名：省掉每条连接的进程查找
        "find-process-mode": "off",
        // TCP 保活（秒）：平衡移动端电量与 NAT 会话活性，避免被中间网关静默重置
        "keep-alive-idle": 300,
        "keep-alive-interval": 30
    };
    // IPv6 默认开启；订阅显式关闭则尊重（纯 IPv4 下双栈重试与 AAAA fake-ip 有兼容问题）
    const ipv6Enabled = params.ipv6 !== false;
    params.ipv6 = ipv6Enabled;
    Object.assign(params, basicOptions);
    // 内核已移除该字段并会在启动时报错
    delete params["global-client-fingerprint"];

    params.sniffer = {
        enable: true,
        "force-dns-mapping": true,
        // 纯 IP 流量强制嗅探：应用绕过系统 DNS 直连 IP 时，从 TLS SNI / HTTP Host 还原域名参与分流，避免兜底误判
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: {
            HTTP: {
                ports: [80, "8080-8880"],
                "override-destination": true
            },
            TLS: {
                ports: [443, 8443]
            },
            QUIC: {
                ports: [443, 8443]
            }
        },
        "skip-domain": [
            // "Mijia Cloud" 不是域名；现行内核对 skip-domain 按域名模式校验，单标签条目按精确匹配处理：
            // 米家设备 SNI 恰好就是 "Mijia Cloud"，可命中并跳过嗅探；并非子串匹配，SNI 带前后缀时不生效
            "Mijia Cloud",
            "+.apple.com",
            "+.openai.com",
            "+.oaistatic.com",
            "+.oaiusercontent.com",
            "+.chatgpt.com"
        ]
    };

    // 节点名里的信息类关键词（剩余流量、到期时间、群链接等），这些不该单独成为可选节点
    const excludeFilter =
        "(?i)(剩余|官网|套餐|已用|到期|过期|重置|更新|刷新|订阅|通知|本站|网址|客服|欢迎|Expire|Traffic|Reset|(剩余|已用|可用|查询|超出|总)流量|流量([:：]|\\s*(剩余|已用|可用|重置|耗尽|不足|提醒|查询|统计|清零))|(到期|过期|剩余|重置|更新|刷新|有效)时间|时间[:：]|(官网|最新|发布|永久|备用|防失联|防走丢)地址|地址[:：]|有效期|有效至|(QQ|TG|Telegram|电报|交流|官方|通知|用户)群|群([:：|｜\\s]|$)|加群|入群|群聊|群号|群组|群链接|加入(我们|群|TG|电报|频道|Telegram|QQ)|防(失联|走丢)|(^|[^A-Za-z0-9])(\\d+\\s*Days?|(Data|Used|Left|Remain|Quota)\\s*[:：\\s]*\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+(\\.\\d+)?\\s*(GB|TB)\\s*/\\s*\\d+(\\.\\d+)?\\s*(GB|TB))([^A-Za-z0-9]|$))";

    const QURE_ICON_BASE =
        "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color";
    const qureIcon = name => `${QURE_ICON_BASE}/${name}`;

    const FLAG_ICON_BASE =
        "https://cdn.jsdmirror.com/gh/open-assets-hub/country-flag-collection@main/circle/128";
    const flagIcon = code => `${FLAG_ICON_BASE}/${code}.png`;

    // 地区表。regex 仅在 JS 侧经 toJsRegex 转换使用
    const regions = [
        {
            name: "AE",
            regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|Emirates|Dubai|Abu[ -]?Dhabi)",
            icon: flagIcon("ae")
        },
        {
            name: "AR",
            regex: "(?i)(阿根廷|布宜诺斯艾利斯|🇦🇷|(^|[^A-Za-z])AR([^A-Za-z]|$)|(^|[^A-Za-z])ARG([^A-Za-z]|$)|Argentina|Buenos[ -]?Aires)",
            icon: flagIcon("ar")
        },
        {
            name: "AU",
            regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z])AU([^A-Za-z]|$)|(^|[^A-Za-z])AUS([^A-Za-z]|$)|Australia|Sydney|Melbourne|Brisbane|Perth|Adelaide)",
            icon: flagIcon("au")
        },
        {
            name: "BD",
            regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z])BD([^A-Za-z]|$)|(^|[^A-Za-z])BGD([^A-Za-z]|$)|Bangladesh|Dhaka)",
            icon: flagIcon("bd")
        },
        {
            name: "BR",
            regex: "(?i)(巴西|圣保罗|聖保羅|🇧🇷|(^|[^A-Za-z])BR([^A-Za-z]|$)|(^|[^A-Za-z])BRA([^A-Za-z]|$)|Brazil|Brasil|(Sao|São)[ -]?Paulo|Rio[ -]?de[ -]?Janeiro|(^|[^A-Za-z])Rio([^A-Za-z]|$))",
            icon: flagIcon("br")
        },
        {
            name: "CA",
            regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|(^|[^A-Za-z])CA([^A-Za-z]|$)|(^|[^A-Za-z])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver|Montreal|Calgary)",
            icon: flagIcon("ca")
        },
        {
            name: "DE",
            regex: "(?i)(德国|德國|法兰克福|法蘭克福|🇩🇪|(^|[^A-Za-z])DE([^A-Za-z]|$)|(^|[^A-Za-z])DEU([^A-Za-z]|$)|Germany|Frankfurt|Berlin|Munich|Düsseldorf|Dusseldorf|Nuremberg)",
            icon: flagIcon("de")
        },
        {
            name: "FR",
            regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|(^|[^A-Za-z])FRA([^A-Za-z]|$)|France|Paris|Marseille|Lyon)",
            icon: flagIcon("fr")
        },
        {
            name: "GB",
            regex: "(?i)(英国|英國|伦敦|倫敦|🇬🇧|(^|[^A-Za-z])UK([^A-Za-z]|$)|(^|[^A-Za-z])GB([^A-Za-z]|$)|(^|[^A-Za-z])GBR([^A-Za-z]|$)|United[ -]?Kingdom|England|London|Manchester|Edinburgh)",
            icon: flagIcon("gb")
        },
        {
            name: "HK",
            regex: "(?i)(香港|九龙|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong|Kowloon|Tsuen[ -]?Wan)",
            icon: flagIcon("hk")
        },
        {
            name: "ID",
            regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|Surabaya|(^|[^A-Za-z])ID([^A-Za-z]|$)|(^|[^A-Za-z])IDN([^A-Za-z]|$))",
            icon: flagIcon("id")
        },
        {
            // 印度([^尼]|$) 只排除"印度尼西亚"；含独立 token IN 的节点名会同时命中 ID 与 IN，内核各组 filter 相互独立、无组间排除
            name: "IN",
            regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z])India([^A-Za-z]|$)|Mumbai|(New[ -]?)?Delhi|Bangalore|Chennai|Hyderabad|(^|[^A-Za-z])IN([^A-Za-z]|$)|(^|[^A-Za-z])IND([^A-Za-z]|$))",
            icon: flagIcon("in")
        },
        {
            name: "JP",
            regex: "(?i)(日本|东京|東京|大阪|名古屋|福冈|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan|Tokyo|Osaka|Narita|Haneda|Kyoto|Fukuoka|Nagoya|Sapporo)",
            icon: flagIcon("jp")
        },
        {
            name: "KR",
            regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea|Seoul|Busan|Incheon|Chuncheon)",
            icon: flagIcon("kr")
        },
        {
            name: "MY",
            regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z])MY([^A-Za-z]|$)|(^|[^A-Za-z])MYS([^A-Za-z]|$)|Malaysia|Kuala[ -]?Lumpur|Johor[ -]?Bahru|Cyberjaya)",
            icon: flagIcon("my")
        },
        {
            name: "NL",
            regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|🇳🇱|(^|[^A-Za-z])NL([^A-Za-z]|$)|(^|[^A-Za-z])NLD([^A-Za-z]|$)|Netherlands|Amsterdam|Rotterdam)",
            icon: flagIcon("nl")
        },
        {
            name: "PH",
            regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z])PH([^A-Za-z]|$)|(^|[^A-Za-z])PHL([^A-Za-z]|$)|Philippines|Manila|Cebu)",
            icon: flagIcon("ph")
        },
        {
            name: "SG",
            regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)",
            icon: flagIcon("sg")
        },
        {
            name: "TH",
            regex: "(?i)(泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|Pattaya|Chiang[ -]?Mai|(^|[^A-Za-z])TH([^A-Za-z]|$)|(^|[^A-Za-z])THA([^A-Za-z]|$))",
            icon: flagIcon("th")
        },
        {
            name: "TR",
            regex: "(?i)(土耳其|伊斯坦布尔|🇹🇷|(^|[^A-Za-z])TR([^A-Za-z]|$)|(^|[^A-Za-z])TUR([^A-Za-z]|$)|Turkey|Türkiye|Istanbul|Ankara)",
            icon: flagIcon("tr")
        },
        {
            name: "TW",
            regex: "(?i)(台湾|台灣|台北|新北|台中|高雄|🇹🇼|(^|[^A-Za-z])TW([^A-Za-z]|$)|(^|[^A-Za-z])TWN([^A-Za-z]|$)|Taiwan|Taipei|Kaohsiung|Taichung|Hsinchu)",
            icon: flagIcon("tw")
        },
        {
            name: "US",
            regex: "(?i)(美国|美國|美西|美东|达拉斯|芝加哥|拉斯维加斯|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|Silicon[ -]?Valley|New[ -]?York|Seattle|Dallas|Chicago|Fremont|Phoenix|Denver|Atlanta|Miami)",
            icon: flagIcon("us")
        },
        {
            name: "VN",
            regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z])VN([^A-Za-z]|$)|(^|[^A-Za-z])VNM([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)",
            icon: flagIcon("vn")
        }
    ];

    const apps = [
        { name: "AI", icon: "ChatGPT.png" },
        { name: "Apple", icon: "Apple.png" },
        { name: "GitHub", icon: "GitHub.png" },
        { name: "Google", icon: "Google_Search.png" },
        { name: "Microsoft", icon: "Microsoft.png" },
        { name: "PayPal", icon: "PayPal.png" },
        { name: "Spotify", icon: "Spotify.png" },
        { name: "Steam", icon: "Steam.png" },
        { name: "Telegram", icon: "Telegram_X.png" },
        { name: "TikTok", icon: "TikTok_1.png" },
        { name: "TV", icon: "Netflix.png" },
        { name: "X", icon: "X.png" },
        { name: "YouTube", icon: "YouTube.png" }
    ];

    const OWN_GROUPS = [
        "主代理",
        "静态",
        "直连",
        "兜底",
        ...apps.map(app => app.name)
    ];

    // 内建策略名。RULES 由内核单独特判：DNS 连接按路由规则出站，不查策略表
    const BUILTIN_POLICIES = new Set([
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "COMPATIBLE",
        "PASS",
        "PASS-RULE",
        "GLOBAL",
        "RULES"
    ]);

    // 内核中节点与策略组共享同一命名空间，且要求节点名唯一：与自建组/地区组/内建 outbound 重名的节点、
    // 以及订阅内的重名节点，都会让内核启动直接报错，这里抢先改名。须在地区统计、PROXY_NAMES 收集与
    // 组生成前完成；改名后的节点名照常参与地区分类（如 "节点·US" 仍命中 US 正则的独立 token 条件）
    const RESERVED_NAMES = new Set([
        ...OWN_GROUPS,
        ...regions.map(region => region.name),
        ...BUILTIN_POLICIES
    ]);

    const usedProxyNames = new Set();

    params.proxies.forEach(proxy => {
        let name = proxy.name;

        if (RESERVED_NAMES.has(name) || usedProxyNames.has(name)) {
            const reservedHit = RESERVED_NAMES.has(name);
            let candidate = name;
            let suffix = 0;

            do {
                suffix++;
                candidate = reservedHit
                    ? "节点·" + name + (suffix > 1 ? "·" + suffix : "")
                    : name + "·" + suffix;
            } while (
                RESERVED_NAMES.has(candidate) ||
                usedProxyNames.has(candidate)
            );

            name = candidate;
            proxy.name = name;
        }

        usedProxyNames.add(name);
    });

    // 自然排序：名字中的连续数字段按数值比较，保证多位数序号排在个位数之后。
    // 排序结果经下方各组的显式 proxies 列表带入最终配置
    const naturalCompare = (a, b) => {
        const chunk = s => {
            const parts = [];
            // /g 正则的 exec 状态不跨调用共享
            const chunkRe = /(\d+)|(\D+)/g;
            let m;
            while ((m = chunkRe.exec(s)) !== null) {
                parts.push(m[1] !== undefined ? Number(m[1]) : m[2]);
            }
            return parts;
        };
        const pa = chunk(a), pb = chunk(b);
        for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
            const x = pa[i], y = pb[i];
            if (x === y) continue;
            if (typeof x === "number" && typeof y === "number") return x - y;
            return String(x) < String(y) ? -1 : 1;
        }
        return pa.length - pb.length;
    };

    params.proxies.sort((a, b) => naturalCompare(a.name, b.name));

    // 地区正则仅用于 JS 侧分类：去掉 (?i) 前缀转为 JS RegExp
    const toJsRegex = goStyleRegex =>
        new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");

    const allProxies = params.proxies.filter(
        proxy => proxy.type !== "direct" && proxy.type !== "reject"
    );
    const excludeRe = toJsRegex(excludeFilter);

    const usableProxies = allProxies.filter(
        proxy => !excludeRe.test(proxy.name)
    );
    const usableNames = usableProxies.map(proxy => proxy.name);

    const minRegionNodes = Math.max(1, REGION_MIN_NODES);
    const regionNodeNames = new Map();
    const activeRegions = regions.filter(region => {
        const regex = toJsRegex(region.regex);
        const matched = usableProxies
            .filter(proxy => regex.test(proxy.name))
            .map(proxy => proxy.name);

        if (matched.length >= minRegionNodes) {
            regionNodeNames.set(region.name, matched);
            return true;
        }

        return false;
    });

    const hasActiveRegions = activeRegions.length > 0;
    const activeRegionNames = activeRegions.map(region => region.name);

    // ── 订阅 DNS 清洗 ──
    // 清洗指向已重建规则集/策略组的引用及 geosite/geoip，避免内核报错或额外下载 geo 文件

    // 取自实际会建组的 activeRegions，避免引用到节点不足未建组的地区（内核找不到目标组）
    const REGION_NAMES = new Set(activeRegionNames);

    const PROXY_NAMES = new Set(
        allProxies.map(proxy => proxy && proxy.name).filter(Boolean)
    );

    // 校验 DNS 条目尾部 "#目标"：合法整条保留，指向已删除对象则剥掉并补 #RULES
    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    const asPlainObject = value =>
        isPlainObject(value) ? value : {};

    const stringList = value => {
        if (value === undefined || value === null) return [];

        const list = Array.isArray(value) ? value : [value];

        return list
            .filter(item => typeof item === "string")
            .map(item => item.trim())
            .filter(Boolean);
    };

    // 解析 nameserver-policy / proxy-server-nameserver-policy 的 "rule-set:a,b" 逗号多值键
    const ruleSetNames = key => {
        const match = /^rule-set:(.+)$/i.exec(String(key));
        if (!match) return [];

        return match[1]
            .split(",")
            .map(name => name.trim())
            .filter(Boolean);
    };

    // 特殊内建 DNS 协议不走代理路由，无需补 #RULES
    const isSpecialDnsScheme = s =>
        /^(system|rcode|dhcp):\/\//i.test(s) ||
        s.toLowerCase() === "system";

    // # 后按 "&" 分段：含 "=" 的是参数（h3=/ecs= 等）原样保留，裸段是目标名，需校验；
    // 目标全部失效，或原订阅 respect-rules 且条目无目标时，补 #RULES 交给路由，避免裸 URL 直连（污染/泄漏）
    const stripDanglingRef = (entry, respectRules = false) => {
        const s = String(entry).trim();
        const hash = s.indexOf("#");

        if (hash === -1) {
            return respectRules && !isSpecialDnsScheme(s)
                ? s + "#RULES"
                : s;
        }

        const base = s.slice(0, hash);
        const rawParts = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(Boolean);

        const paramParts = rawParts.filter(part => part.includes("="));
        const targetParts = rawParts.filter(part => !part.includes("="));
        const validTargets = targetParts.filter(refValid);

        const needRulesFallback =
            (targetParts.length > 0 && validTargets.length === 0) ||
            (targetParts.length === 0 &&
                respectRules &&
                !isSpecialDnsScheme(base));

        const finalTargets = needRulesFallback ? ["RULES"] : validTargets;
        const finalParts = [...finalTargets, ...paramParts];

        return finalParts.length > 0
            ? base + "#" + finalParts.join("&")
            : base;
    };

    // 节点解析 DNS 不得经代理/策略组出站，否则形成"需要节点才能解析节点"的循环
    const stripProxyRefs = entry => {
        const s = String(entry);
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const params = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(part => part !== "" && part.includes("="));

        return params.length > 0
            ? s.slice(0, hash) + "#" + params.join("&")
            : s.slice(0, hash);
    };

    const stripProxyRefsPolicy = policy => {
        const out = {};

        for (const key of Object.keys(policy)) {
            out[key] = stringList(policy[key]).map(stripProxyRefs);
        }

        return out;
    };

    // ── 读取订阅 DNS ──
    // 不可迁移字段静默丢弃、以脚本配置为准；读取异常则整段放弃订阅 DNS（见下方 catch）
    const deriveSubDNS = rawDNS => {
        const subDNS = isPlainObject(rawDNS) ? rawDNS : {};
        const subRespectRules = subDNS["respect-rules"] === true;
        const hasFallbackComplexity =
            subDNS.fallback !== undefined ||
            subDNS["fallback-filter"] !== undefined;

        const cleanWithRules = item =>
            stripDanglingRef(item, subRespectRules);

        const subPSN = stringList(
            subDNS["proxy-server-nameserver"]
        ).map(stripProxyRefs);

        const subNS = stringList(subDNS.nameserver).map(
            cleanWithRules
        );

        const subPolicy = Object.assign(
            {},
            asPlainObject(subDNS["nameserver-policy"])
        );

        // fake-ip-filter 仅在缺省/blacklist 时继承；whitelist/rule 语义不同，继承会反转过滤含义，固定输出 blacklist
        const modeRaw = subDNS["fake-ip-filter-mode"];
        const mode =
            typeof modeRaw === "string"
                ? modeRaw.trim().toLowerCase()
                : "";

        const subFilter =
            mode === "" || mode === "blacklist"
                ? stringList(subDNS["fake-ip-filter"]).filter(
                      item =>
                          !/^(rule-set|geosite|geoip):/i.test(item)
                  )
                : [];

        // 逐键清洗：通吃键架空分流、指向重建规则集/内建 geo 的键会硬报错，均丢弃；值同样清洗悬空引用
        for (const key of Object.keys(subPolicy)) {
            if (key === "+." || key === "*" || key === "+") {
                delete subPolicy[key];
                continue;
            }

            if (/^(rule-set|geosite|geoip):/i.test(key)) {
                delete subPolicy[key];
                continue;
            }

            subPolicy[key] = stringList(subPolicy[key]).map(
                cleanWithRules
            );
        }

        // ── 清洗 proxy-server-nameserver-policy ──
        // 键：geosite:/geoip: 丢弃；rule-set: 仅在订阅原始 rule-providers 有定义时保留并搬运，否则丢弃
        // 值：stripProxyRefs 清洗；通吃键不删（只作用于节点域名，不会覆盖脚本配置）
        const rawPSNPolicy = asPlainObject(
            subDNS["proxy-server-nameserver-policy"]
        );

        const subPSNPolicy = {};
        const carriedRuleProviders = {};

        for (const key of Object.keys(rawPSNPolicy)) {
            if (/^(geosite|geoip):/i.test(key)) continue;

            const names = ruleSetNames(key);

            if (names.length > 0) {
                const validNames = names.filter(name =>
                    Object.prototype.hasOwnProperty.call(
                        subRuleProviders,
                        name
                    )
                );

                if (validNames.length > 0) {
                    for (const name of validNames) {
                        carriedRuleProviders[name] =
                            subRuleProviders[name];
                    }

                    subPSNPolicy[
                        "rule-set:" + validNames.join(",")
                    ] = stringList(rawPSNPolicy[key]).map(
                        stripProxyRefs
                    );
                }

                continue;
            }

            subPSNPolicy[key] = stringList(rawPSNPolicy[key]).map(
                stripProxyRefs
            );
        }

        let proxyServerNameserver;
        let proxyServerNameserverPolicy;

        if (subPSN.length > 0) {
            // 机场显式设置节点 DNS 时独占使用，不混入公共 DNS
            proxyServerNameserver = [...new Set(subPSN)];
            proxyServerNameserverPolicy = subPSNPolicy;
        } else {
            // 节点 policy 视为未设置：收集的旧 rule-set 依赖一并放弃，否则并入的 provider 无人引用、凭空下载
            for (const key of Object.keys(carriedRuleProviders)) {
                delete carriedRuleProviders[key];
            }

            // 未显式设置节点 DNS 时，以普通解析策略为迁移来源
            if (hasFallbackComplexity) {
                // fallback 无法在单一列表等价表达，忽略；节点解析直接用国内 DoH
                proxyServerNameserver = [...CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            } else if (
                subNS.length > 0 ||
                Object.keys(subPolicy).length > 0
            ) {
                // 按原优先关系迁入（policy 优先于 nameserver）
                proxyServerNameserver =
                    subNS.length > 0
                        ? [...new Set(subNS.map(stripProxyRefs))]
                        : [...CN_DNS_DOH];

                proxyServerNameserverPolicy =
                    Object.keys(subPolicy).length > 0
                        ? stripProxyRefsPolicy(subPolicy)
                        : undefined;
            } else {
                // 无可继承信息，用默认公共 DNS
                proxyServerNameserver = [...CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            }
        }

        return {
            subDNS,
            subNS,
            subPolicy,
            subFilter,
            hasFallbackComplexity,
            carriedRuleProviders,
            proxyServerNameserver,
            proxyServerNameserverPolicy
        };
    };

    let dnsInfo;

    try {
        const rawDNS = params.dns;

        if (
            rawDNS !== undefined &&
            rawDNS !== null &&
            !isPlainObject(rawDNS)
        ) {
            throw new Error("dns 字段不是对象");
        }

        dnsInfo = deriveSubDNS(rawDNS);
    } catch (error) {
        warnLog(
            "[Concord_rule.js] 读取订阅 DNS 时出错（" +
                (error && error.message
                    ? error.message
                    : String(error)) +
                "），已放弃订阅 DNS，改用脚本默认配置。"
        );

        dnsInfo = deriveSubDNS(null);
    }

    const {
        subDNS,
        subNS,
        subPolicy,
        subFilter,
        hasFallbackComplexity,
        carriedRuleProviders,
        proxyServerNameserver,
        proxyServerNameserverPolicy
    } = dnsInfo;

    // DNS 层 IPv6：订阅显式指定则继承，否则跟随全局 ipv6 开关
    const dnsIPv6 =
        typeof subDNS.ipv6 === "boolean"
            ? subDNS.ipv6
            : ipv6Enabled;

    params.dns = {
        enable: true,
        // 固定回环 + 非特权端口：订阅常见 0.0.0.0:53，被系统 DNS 占住会导致内核启动失败；
        // 要给局域网设备当 DNS 用时改这一行并自行确认端口与防火墙
        listen: "127.0.0.1:1053",
        ipv6: dnsIPv6,
        "prefer-h3": PREFER_H3,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        // IPv6 fake-ip 段（仅 DNS 启用 IPv6 时输出）：用官方文档段，勿用 fc00::/7 等内网段（与真实局域网冲突）
        ...(dnsIPv6
            ? { "fake-ip-range6": "fdfe:dcba:9876::/64" }
            : {}),
        "cache-algorithm": "arc",
        "fake-ip-filter-mode": "blacklist",
        "use-hosts":
            typeof subDNS["use-hosts"] === "boolean"
                ? subDNS["use-hosts"]
                : true,
        "use-system-hosts":
            typeof subDNS["use-system-hosts"] === "boolean"
                ? subDNS["use-system-hosts"]
                : true,
        // 前段为 real-ip 刚需：局域网、NTP、连通性探测、游戏平台（对时拿假地址会失败，连带影响 TLS 校验）
        "fake-ip-filter": [
            ...new Set([
                "+.lan",
                "+.local",
                "+.home.arpa",
                "localhost.ptlogin2.qq.com",
                "localhost.sec.qq.com",
                "localhost.work.weixin.qq.com",
                "+.msftconnecttest.com",
                "+.msftncsi.com",
                "+.ntp.org",
                "+.xboxlive.com",
                "+.playstation.net",
                "+.xbox.com",
                "xbox.ipv6.microsoft.com",
                "+.srv.nintendo.net",
                "time.windows.com",
                "time.apple.com",
                "time.asia.apple.com",
                "time.android.com",
                "time.nist.gov",
                "ntp.aliyun.com",
                "ntp.tencent.com",
                "ntp.ntsc.ac.cn",
                // STUN 通配：域名含 stun 段的全部豁免假地址
                "+.stun.*",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "+.stun.*.*.*.*",
                // 由脚本自带的规则集兜底，防手维护清单漏项
                "rule-set:cn-domain",
                "rule-set:private-domain",
                "rule-set:fakeip-filter",
                ...subFilter
            ])
        ],
        // 引导 DNS：仅解析其它 DoH 服务器域名；明文 IP 最快且不依赖证书校验（时钟不准时 DoT 证书校验会失败）
        "default-nameserver": [...CN_DNS_PLAIN],
        "proxy-server-nameserver": proxyServerNameserver,
        ...(proxyServerNameserverPolicy &&
        Object.keys(proxyServerNameserverPolicy).length > 0
            ? {
                  "proxy-server-nameserver-policy":
                      proxyServerNameserverPolicy
              }
            : {}),
        // 订阅无 fallback 且有 nameserver 时独占使用；带 fallback 或未指定则用海外 DoH 兜底
        nameserver:
            !hasFallbackComplexity && subNS.length > 0
                ? [...new Set(subNS)]
                : [
                      "https://1.1.1.1/dns-query#主代理",
                      "https://8.8.8.8/dns-query#主代理"
                  ],
        // DIRECT 命中且未被 policy 覆盖的域名用国内明文 DNS；DoH 在部分环境会反复回退 default-nameserver，拖高延迟
        "direct-nameserver": [...CN_DNS_PLAIN],
        // true：DIRECT 命中域名先走 nameserver-policy，未被覆盖才落到 direct-nameserver
        "direct-nameserver-follow-policy": true,
        // subPolicy 放前：不同名键保留，同名键被下面三条覆盖，不丢订阅意图也不让它盖掉脚本分流
        "nameserver-policy": Object.assign({}, subPolicy, {
            "rule-set:private-domain": ["system://"],
            "rule-set:ads-domain": ["rcode://name_error"],
            "rule-set:cn-domain": [...CN_DNS_DOH]
        })
    };

    // hosts 位于顶层而非 dns 下；若订阅误放在 dns.hosts，迁回顶层（顶层已有同名键优先）
    if (isPlainObject(subDNS.hosts) && Object.keys(subDNS.hosts).length > 0) {
        params.hosts = Object.assign(
            {},
            subDNS.hosts,
            isPlainObject(params.hosts) ? params.hosts : {}
        );
    }

    // 远程规则集：MetaCubeX 官方拆分库，全 mrs
    const RS_BASE =
        "https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@meta/geo";

    const domainProvider = name => ({
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: `${RS_BASE}/geosite/${name}.mrs`,
        path: `./ruleset/geosite-${name}.mrs`,
        interval: RS_INTERVAL
    });

    const ipProvider = name => ({
        type: "http",
        behavior: "ipcidr",
        format: "mrs",
        url: `${RS_BASE}/geoip/${name}.mrs`,
        path: `./ruleset/geoip-${name}.mrs`,
        interval: RS_INTERVAL
    });

    // 引用名 → 官方分类名
    const DOMAIN_SETS = {
        "private-domain": "private",
        "synology-domain": "synology",
        "ads-domain": "category-ads-all",
        "youtube-domain": "youtube",
        "twitter-domain": "twitter",
        "tiktok-domain": "tiktok",
        "telegram-domain": "telegram",
        "github-domain": "github",
        "ai-domain": "category-ai-!cn",
        "netflix-domain": "netflix",
        "disney-domain": "disney",
        "primevideo-domain": "primevideo",
        "appletv-domain": "apple-tvplus",
        "hbo-domain": "hbo",
        "spotify-domain": "spotify",
        "steam-domain": "steam",
        "paypal-domain": "paypal",
        "google-domain": "google",
        "apple-domain": "apple",
        "microsoft-domain": "microsoft",
        "proxy-domain": "geolocation-!cn",
        "cn-domain": "cn"
    };

    const IP_SETS = {
        "private-ip": "private",
        "telegram-ip": "telegram",
        "cn-ip": "cn"
    };

    // 清空重建；必要的旧依赖由下方 carriedRuleProviders 搬运
    params["rule-providers"] = {};

    Object.keys(DOMAIN_SETS).forEach(key => {
        params["rule-providers"][key] = domainProvider(DOMAIN_SETS[key]);
    });

    Object.keys(IP_SETS).forEach(key => {
        params["rule-providers"][key] = ipProvider(IP_SETS[key]);
    });

    // 社区维护的 fake-ip 豁免清单（wwqgtxx/clash-rules，官方未收录），供 dns.fake-ip-filter 引用
    params["rule-providers"]["fakeip-filter"] = {
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: "https://cdn.jsdmirror.com/gh/wwqgtxx/clash-rules@release/fakeip-filter.mrs",
        path: "./ruleset/fakeip-filter.mrs",
        interval: RS_INTERVAL
    };

    const hasOwn = (object, key) =>
        Object.prototype.hasOwnProperty.call(object, key);

    const renamedRS = {};

    // 并入必要的旧 rule-set 依赖；与自建同名时改名 sub-<原名>（冲突加序号），并同步改写 policy 键
    // type: file 指向订阅方本地文件，搬运会令内核启动报错，连同 policy 中的引用一并丢弃
    const droppedCarriedRS = new Set();

    Object.keys(carriedRuleProviders).forEach(name => {
        const provider = carriedRuleProviders[name];

        if (isPlainObject(provider) && provider.type === "file") {
            droppedCarriedRS.add(name);
            return;
        }

        let finalName = name;

        if (hasOwn(params["rule-providers"], name)) {
            let suffix = 1;
            finalName = "sub-" + name;

            while (
                hasOwn(params["rule-providers"], finalName) ||
                hasOwn(carriedRuleProviders, finalName)
            ) {
                suffix++;
                finalName = "sub-" + name + "-" + suffix;
            }

            renamedRS[name] = finalName;
        }

        // path 可能与自建 provider 缓存文件冲突；basename 换成 sub-<原名>，保留原扩展名
        const finalProvider = Object.assign({}, provider);

        if (
            typeof finalProvider.path === "string" &&
            finalProvider.path.length > 0
        ) {
            const segs = finalProvider.path.split(/[\\/]/);
            const base = segs[segs.length - 1];
            const dot = base.lastIndexOf(".");
            const ext = dot > 0 ? base.slice(dot) : "";
            const filePrefix = finalName.startsWith("sub-")
                ? finalName
                : "sub-" + finalName;

            segs[segs.length - 1] = filePrefix + ext;
            finalProvider.path = segs.join("/");
        }

        params["rule-providers"][finalName] = finalProvider;
    });

    if (
        (Object.keys(renamedRS).length > 0 ||
            droppedCarriedRS.size > 0) &&
        params.dns["proxy-server-nameserver-policy"]
    ) {
        const oldPolicy =
            params.dns["proxy-server-nameserver-policy"];
        const newPolicy = {};

        Object.keys(oldPolicy).forEach(key => {
            const names = ruleSetNames(key);

            if (names.length === 0) {
                newPolicy[key] = oldPolicy[key];
                return;
            }

            // 被丢弃的 file 类型引用从键里剔除，整条作废
            const keptNames = names.filter(
                name => !droppedCarriedRS.has(name)
            );

            if (keptNames.length === 0) return;

            const rewrittenNames = keptNames.map(
                name => renamedRS[name] || name
            );

            newPolicy[
                "rule-set:" + rewrittenNames.join(",")
            ] = oldPolicy[key];
        });

        params.dns["proxy-server-nameserver-policy"] = newPolicy;
    }

    // 默认指纹仅补 vless/vmess/trojan 三类常见 TLS 节点；不覆盖订阅已有取值
    const FP_OK = ["vless", "vmess", "trojan"];

    params.proxies.forEach(proxy => {
        // 不覆盖订阅已有的取值
        if (
            proxy.type !== "direct" &&
            !("ip-version" in proxy)
        ) {
            proxy["ip-version"] = DEFAULT_IP_VERSION;
        }

        if (
            FP_OK.indexOf(proxy.type) !== -1 &&
            !proxy["client-fingerprint"]
        ) {
            const usesTLS =
                proxy.type === "trojan" ||
                proxy.tls === true ||
                proxy["reality-opts"];

            if (usesTLS) {
                proxy["client-fingerprint"] = "chrome";
            }
        }
    });

    const groups = [];

    groups.push({
        name: "主代理",
        type: "select",
        icon: qureIcon("Proxy.png"),
        proxies: hasActiveRegions
            ? [
                  ...activeRegionNames,
                  "静态",
                  "直连"
              ]
            : ["静态", "直连"]
    });

    // 静态：收全部节点（排除 direct / reject 与信息类节点），无可用节点时填充 REJECT 占位避免空组报错
    groups.push({
        name: "静态",
        type: "select",
        icon: qureIcon("Static.png"),
        proxies: usableNames.length > 0 ? usableNames : ["REJECT"],
        "empty-fallback": "REJECT"
    });

    // 隐藏直连组：仅供内部选择引用；与内建 DIRECT 区分——这是名为"直连"的策略组，成员才是 DIRECT
    groups.push({
        name: "直连",
        type: "select",
        hidden: true,
        icon: qureIcon("Direct.png"),
        proxies: ["DIRECT"]
    });

    const appProxiesList = [
        "主代理",
        "直连",
        ...activeRegionNames
    ];

    // App 策略组：proxies 前列为切换目标，后列订阅节点本身，两者缺一不可
    apps.forEach(app => {
        groups.push({
            name: app.name,
            type: "select",
            icon: qureIcon(app.icon),
            proxies: [...appProxiesList, ...usableNames]
        });
    });

    activeRegions.forEach(region => {
        groups.push({
            name: region.name,
            type: "url-test",
            hidden: true,
            icon: region.icon,
            proxies: regionNodeNames.get(region.name),
            "empty-fallback": "REJECT",
            url: TEST_URL_PROXY,
            interval: 300,
            tolerance: 30,
            lazy: true,
            timeout: 5000,
            "max-failed-times": 5,
            "expected-status": 204
        });
    });

    // 兜底必须保持为最后一个策略组；默认引用主代理，不改变原脚本的默认出口行为
    groups.push({
        name: "兜底",
        type: "select",
        icon: qureIcon("Final.png"),
        proxies: [...appProxiesList, ...usableNames]
    });

    // 全部节点被 excludeFilter 过滤时「静态」已填充 REJECT 占位，转换期留一条告警便于排查
    if (usableNames.length === 0) {
        warnLog(
            "[Concord_rule.js] 订阅节点全部被 excludeFilter 过滤，「静态」组已填充 REJECT 占位，需代理的流量将被拒绝，直连规则不受影响；请检查 excludeFilter 或节点命名。"
        );
    }

    params["proxy-groups"] = groups;

    // 规则先命中先决定，顺序：私网/广告 → NAS 厂商服务 → 传输层兜底（NTP、QUIC，须先于应用分流）→ 应用分流 → 国内直连 → MATCH
    // cn-domain 排在 Google / Apple / Microsoft 之后，避免其国内 CDN 域名被直连截胡
    params.rules = [
        // 防止代理回环
        "IP-CIDR,127.0.0.0/8,REJECT,no-resolve",
        "IP-CIDR,0.0.0.0/32,REJECT,no-resolve",
        "IP-CIDR6,::1/128,REJECT,no-resolve",
        "IP-CIDR6,::/128,REJECT,no-resolve",
        "AND,((IN-TYPE,TUN),(DST-PORT,853)),REJECT",

        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "RULE-SET,ads-domain,REJECT",
        // 群晖官方服务及其 DDNS 直连；须早于 geolocation-!cn 和 MATCH
        "RULE-SET,synology-domain,DIRECT",
        // 系统对时优先于业务分流：很多节点丢弃/限制 UDP 123，时间偏差会连带导致全局 TLS 证书校验失败
        "AND,((DST-PORT,123),(NETWORK,udp)),DIRECT",
        ...(BLOCK_QUIC
            ? [
                  "AND,((DST-PORT,443),(NETWORK,udp)),REJECT"
              ]
            : []),

        "RULE-SET,youtube-domain,YouTube",
        "RULE-SET,twitter-domain,X",
        "RULE-SET,tiktok-domain,TikTok",
        "RULE-SET,telegram-domain,Telegram",
        // Telegram IP 段规则加 no-resolve 避免域名流量中途触发同步 DNS 解析；客户端仍会对真实 IP 匹配兜底
        "RULE-SET,telegram-ip,Telegram,no-resolve",
        "RULE-SET,spotify-domain,Spotify",
        "RULE-SET,ai-domain,AI",
        "RULE-SET,github-domain,GitHub",
        "RULE-SET,steam-domain,Steam",
        "RULE-SET,paypal-domain,PayPal",

        "RULE-SET,netflix-domain,TV",
        "RULE-SET,disney-domain,TV",
        "RULE-SET,primevideo-domain,TV",
        "RULE-SET,appletv-domain,TV",
        "RULE-SET,hbo-domain,TV",

        "RULE-SET,google-domain,Google",
        "RULE-SET,apple-domain,Apple",
        "RULE-SET,microsoft-domain,Microsoft",

        "RULE-SET,proxy-domain,主代理",

        "RULE-SET,cn-domain,DIRECT",
        
        "RULE-SET,cn-ip,DIRECT",

        "MATCH,兜底"
    ];

    // ── 字段净化：订阅透传内容 ──

    // 1) 顶层功能键黑名单；客户端自管设置原样透传
    CONCORD_TOP_DROP.forEach(key => {
        delete params[key];
    });

    // 订阅 sub-rules 引用原组/规则集，重建后必然悬空；脚本不生成 SUB-RULE 规则，整段丢弃
    delete params["sub-rules"];

    // 2) 客户端设置段落中的死键：只删 Concord 不应用的键，生效设置不动
    if (isPlainObject(params.tun)) {
        CONCORD_TUN_DROP.forEach(key => {
            delete params.tun[key];
        });
    }
    if (isPlainObject(params.experimental)) {
        CONCORD_EXPERIMENTAL_DROP.forEach(key => {
            delete params.experimental[key];
        });
    }
    if (isPlainObject(params.tls)) {
        CONCORD_TLS_DROP.forEach(key => {
            delete params.tls[key];
        });
    }
    if (isPlainObject(params["geox-url"])) {
        delete params["geox-url"].geoip;
    }

    // 3) rule-providers：删 path-in-bundle；带 override-expr 的 provider 在 Concord 中
    // 整体失效，丢弃并清理 DNS 引用（仅涉及搬运的订阅 provider）
    const droppedProviders = new Set();
    Object.keys(params["rule-providers"]).forEach(name => {
        const provider = params["rule-providers"][name];
        if (!isPlainObject(provider)) {
            delete params["rule-providers"][name];
            droppedProviders.add(name);
            return;
        }
        const expr = isPlainObject(provider.override)
            ? provider.override["override-expr"]
            : undefined;
        const hasExpr =
            expr !== undefined &&
            expr !== null &&
            expr !== "" &&
            !(Array.isArray(expr) && expr.length === 0);
        if (hasExpr) {
            delete params["rule-providers"][name];
            droppedProviders.add(name);
            return;
        }
        delete provider["path-in-bundle"];
    });

    // 4) DNS 上游：剔除不支持的协议，dhcp:// 规范化为 system://；
    // 清理后为空的列表回退脚本默认值
    const cleanDnsList = list => [
        ...new Set(
            stringList(list)
                .filter(
                    entry =>
                        !CONCORD_DNS_SCHEME_DROP.test(
                            entry.split("#")[0].trim()
                        )
                )
                .map(entry =>
                    entry.replace(/^dhcp:\/\/[^#]*/i, "system://")
                )
        )
    ];

    const cleanDnsPolicy = policy => {
        const out = {};
        Object.keys(policy).forEach(key => {
            const cleaned = cleanDnsList(policy[key]);
            // 清空的 policy 键整条删除，避免 Concord 对空列表回 REFUSED
            if (cleaned.length > 0) out[key] = cleaned;
        });
        return out;
    };

    params.dns.nameserver = cleanDnsList(params.dns.nameserver);
    if (params.dns.nameserver.length === 0) {
        params.dns.nameserver = [
            "https://1.1.1.1/dns-query#主代理",
            "https://8.8.8.8/dns-query#主代理"
        ];
    }
    params.dns["default-nameserver"] = cleanDnsList(
        params.dns["default-nameserver"]
    );
    if (params.dns["default-nameserver"].length === 0) {
        params.dns["default-nameserver"] = [...CN_DNS_PLAIN];
    }
    params.dns["direct-nameserver"] = cleanDnsList(
        params.dns["direct-nameserver"]
    );
    if (params.dns["direct-nameserver"].length === 0) {
        params.dns["direct-nameserver"] = [...CN_DNS_PLAIN];
    }
    params.dns["proxy-server-nameserver"] = cleanDnsList(
        params.dns["proxy-server-nameserver"]
    );
    if (params.dns["proxy-server-nameserver"].length === 0) {
        // Concord 禁止 policy 存在时 proxy-server-nameserver 为空（硬报错），兜底国内 DoH
        params.dns["proxy-server-nameserver"] = [...CN_DNS_DOH];
    }
    params.dns["nameserver-policy"] = cleanDnsPolicy(
        params.dns["nameserver-policy"]
    );
    if (params.dns["proxy-server-nameserver-policy"]) {
        params.dns["proxy-server-nameserver-policy"] = cleanDnsPolicy(
            params.dns["proxy-server-nameserver-policy"]
        );
    }

    // 5) 被丢弃 provider 的引用清理：DNS policy 的 rule-set 键与 fake-ip-filter 条目
    if (droppedProviders.size > 0) {
        [
            "nameserver-policy",
            "proxy-server-nameserver-policy"
        ].forEach(field => {
            const policy = params.dns[field];
            if (!isPlainObject(policy)) return;
            const next = {};
            Object.keys(policy).forEach(key => {
                const names = ruleSetNames(key);
                if (names.length === 0) {
                    next[key] = policy[key];
                    return;
                }
                const kept = names.filter(
                    name => !droppedProviders.has(name)
                );
                if (kept.length === 0) return;
                next["rule-set:" + kept.join(",")] = policy[key];
            });
            params.dns[field] = next;
        });
        params.dns["fake-ip-filter"] = params.dns[
            "fake-ip-filter"
        ].filter(item => {
            const match = /^rule-set:(.+)$/i.exec(String(item));
            return !match || !droppedProviders.has(match[1].trim());
        });
    }
    if (
        params.dns["proxy-server-nameserver-policy"] &&
        Object.keys(params.dns["proxy-server-nameserver-policy"])
            .length === 0
    ) {
        delete params.dns["proxy-server-nameserver-policy"];
    }

    // 6) hosts：删除非法条目、自映射与别名环
    if (isPlainObject(params.hosts)) {
        concordCleanHosts(params.hosts);
    }

    // 7) dialer-proxy 引用校验：悬空引用与环会导致整份拒载
    concordFixDialers(params.proxies, params["proxy-groups"]);

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
