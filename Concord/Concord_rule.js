// Concord_rule.js V1.0
// 需支持扩展脚本的 Concord 客户端；仅支持节点平铺订阅，首次启动联网下载规则集。

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
const QURE_ICON_BASE =
    "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color";
const FLAG_ICON_BASE =
    "https://cdn.jsdmirror.com/gh/open-assets-hub/country-flag-collection@main/circle/128";
const BLOCK_QUIC = false;         // 拒绝 UDP 443 迫使回退 TCP；仅节点不支持 UDP 时开

// 宿主脚本引擎不一定有 console.warn，缺省时降级到 log，避免 TypeError 中断转换
const warnLog = (...args) => {
    if (typeof console === "undefined") return;
    if (typeof console.warn === "function") console.warn(...args);
    else if (typeof console.log === "function") console.log(...args);
};

const isPlainObject = value =>
    value &&
    typeof value === "object" &&
    !Array.isArray(value);

// ── 顶层字段白名单（镜像内核 crates/config/src/keys.rs） ──
// T0/T1 是内核读取的字段；T2 与未知字段会被忽略并告警，故一律不输出。

const TOP_T0 = [
    "mixed-port", "port", "socks-port", "allow-lan", "mode", "log-level",
    "ipv6", "unified-delay", "tcp-concurrent", "find-process-mode",
    "interface-name", "routing-mark", "keep-alive-idle", "keep-alive-interval",
    "disable-keep-alive", "global-ua", "hosts", "geo-auto-update",
    "geo-update-interval", "geodata-loader"
];

const TOP_T1 = ["redir-port", "tproxy-port"];

// 分段白名单：只保留内核读取的键，其余（含 T2 与未知键）在组装时自然被排除
const TUN_KEYS = [
    "enable", "device", "stack", "auto-route", "auto-detect-interface",
    "dns-hijack", "route-address", "route-exclude-address", "strict-route",
    "mtu", "congestion-controller", "udp-timeout", "disable-icmp-forwarding",
    "include-interface", "exclude-interface", "include-uid", "exclude-uid",
    "exclude-src-port", "exclude-dst-port"
];

const NTP_KEYS = [
    "enable", "server", "port", "interval", "dialer-proxy", "write-to-system"
];

const GEOX_KEYS = ["mmdb", "asn", "geosite"];
const PROFILE_KEYS = ["store-selected", "store-fake-ip"];

// 13 个业务分流组，icon 取自 Qure 图标集
const APP_GROUPS = [
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

// 节点名里的信息类关键词（剩余流量、到期时间、群链接等），这些不该单独成为可选节点
const EXCLUDE_FILTER =
    "(?i)(剩余|官网|套餐|已用|到期|过期|重置|更新|刷新|订阅|通知|本站|网址|客服|欢迎|Expire|Traffic|Reset|(剩余|已用|可用|查询|超出|总)流量|流量([:：]|\\s*(剩余|已用|可用|重置|耗尽|不足|提醒|查询|统计|清零))|(到期|过期|剩余|重置|更新|刷新|有效)时间|时间[:：]|(官网|最新|发布|永久|备用|防失联|防走丢)地址|地址[:：]|有效期|有效至|(QQ|TG|Telegram|电报|交流|官方|通知|用户)群|群([:：|｜\\s]|$)|加群|入群|群聊|群号|群组|群链接|加入(我们|群|TG|电报|频道|Telegram|QQ)|防(失联|走丢)|(^|[^A-Za-z0-9])(\\d+\\s*Days?|(Data|Used|Left|Remain|Quota)\\s*[:：\\s]*\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+(\\.\\d+)?\\s*(GB|TB)\\s*/\\s*\\d+(\\.\\d+)?\\s*(GB|TB))([^A-Za-z0-9]|$))";

// 节点类型：T0 全支持；T1 部分平台支持；其余（T2 与未知）会被剔除并告警
const PROXY_TYPES_T0 = [
    "direct", "reject", "ss", "vmess", "vless", "trojan", "hysteria2",
    "tuic", "anytls", "socks5", "http"
];
const PROXY_TYPES_T1 = [
    "wireguard", "hysteria", "ssr", "snell", "mieru", "ssh", "shadowquic"
];
const PROXY_TYPES_OK = new Set([...PROXY_TYPES_T0, ...PROXY_TYPES_T1]);

// 内核明确不支持、会让节点被剔除的选项
const T2_TLS_KEYS = ["shadow-tls-opts", "restls-opts", "jls-opts", "tlsmirror-opts"];
const T2_SS_PLUGINS = ["restls", "gost-plugin", "kcptun", "jls"];
const T2_NETWORKS = ["mkcp", "kcp", "mekya"];

// 已废弃的指纹名：内核会改写为现代名并告警，这里提前改写
const DEPRECATED_FINGERPRINTS = {
    chrome_psk: "chrome",
    chrome_psk_shuffle: "chrome",
    chrome_padding_psk_shuffle: "chrome",
    chrome_pq: "chrome",
    chrome_pq_psk: "chrome",
    randomized: "random"
};

// amnezia-wg-option v3 中内核不生效、会告警的子键
const AMNEZIA_UNAPPLIED = [
    "content-padding-addition", "rekey-after-time", "rekey-timeout",
    "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
    "disable-cookies"
];

// DNS 上游支持的 scheme；其余（ts://、tailscale://、et://、easytier:// 等）会让整份配置被拒绝
const DNS_SCHEMES_OK = new Set([
    "udp", "tcp", "tls", "https", "http", "quic", "system", "dhcp", "rcode"
]);
const DNS_SCHEMES_REJECT = new Set(["ts", "tailscale", "et", "easytier"]);

// 规则集映射：引用名 → MetaCubeX 官方 mrs 分类名
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

// 规则集统一使用 MetaCubeX 官方 mrs 二进制格式，内核原生支持且体积最小
function buildRuleProviders() {
    const base = "https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@meta/geo";
    const domain = name => ({
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: base + "/geosite/" + name + ".mrs",
        path: "./ruleset/geosite-" + name + ".mrs",
        interval: RS_INTERVAL
    });
    const ip = name => ({
        type: "http",
        behavior: "ipcidr",
        format: "mrs",
        url: base + "/geoip/" + name + ".mrs",
        path: "./ruleset/geoip-" + name + ".mrs",
        interval: RS_INTERVAL
    });

    const providers = {};
    Object.keys(DOMAIN_SETS).forEach(key => {
        providers[key] = domain(DOMAIN_SETS[key]);
    });
    Object.keys(IP_SETS).forEach(key => {
        providers[key] = ip(IP_SETS[key]);
    });
    // 社区维护的 fake-ip 豁免清单（官方未收录），供 dns.fake-ip-filter 引用
    providers["fakeip-filter"] = {
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: "https://cdn.jsdmirror.com/gh/wwqgtxx/clash-rules@release/fakeip-filter.mrs",
        path: "./ruleset/fakeip-filter.mrs",
        interval: RS_INTERVAL
    };
    return providers;
}

// 入口：接收订阅解析出的配置对象，返回清洗并重建后的配置。
// 流程：节点清洗 → 组名与去重 → 地区统计 → 规则集/策略组/规则 → DNS → 引用校验 → 白名单组装
function main(config) {
    if (!isPlainObject(config)) config = {};
    if (!Array.isArray(config.proxies)) config.proxies = [];

    // proxy-providers 的节点在运行时才拉取，脚本期无法据此生成地区组，直接拒绝生成
    if (isPlainObject(config["proxy-providers"]) &&
        Object.keys(config["proxy-providers"]).length > 0) {
        throw new Error(
            "[Concord_rule.js] 检测到 proxy-providers 订阅，本脚本仅支持节点平铺的订阅形式，已拒绝生成配置。"
        );
    }

    // 记住面板手动选择与 fake-ip 缓存
    const profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        pickKeys(isPlainObject(config.profile) ? config.profile : {}, PROFILE_KEYS)
    );

    // ── 节点清洗 ──
    let proxies = sanitizeNodes(config.proxies);
    normalizeProxies(proxies);

    // ── 组名与保留名 ──
    // 节点与策略组在内核中共用一个命名空间且要求唯一，先列出本脚本会占用的名字
    const regions = buildRegions();
    const OWN_GROUPS = ["主代理", "静态", "直连", "兜底", ...APP_GROUPS.map(app => app.name)];
    const BUILTIN_POLICIES = new Set([
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"
    ]);

    const RESERVED_NAMES = new Set([
        ...OWN_GROUPS,
        ...regions.map(region => region.name),
        ...BUILTIN_POLICIES
    ]);

    // 与保留名或订阅内重名的节点抢先改名，重名会让内核启动直接报错
    renameDuplicateProxies(proxies, RESERVED_NAMES);

    // 自然排序：名字中的连续数字段按数值比较，保证 10 排在 9 之后
    proxies.sort((a, b) => naturalCompare(a.name, b.name));

    const allProxies = proxies.filter(
        proxy => proxy.type !== "direct" && proxy.type !== "reject"
    );
    const excludeRe = toJsRegex(EXCLUDE_FILTER);
    const usableProxies = allProxies.filter(proxy => !excludeRe.test(proxy.name));
    const usableNames = usableProxies.map(proxy => proxy.name);

    // ── 地区统计 ──
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
    const activeRegionNames = activeRegions.map(region => region.name);

    // ── 规则集 ──
    const ruleProviders = buildRuleProviders();

    // ── 策略组 ──
    const groups = buildGroups(activeRegions, regionNodeNames, usableNames);

    if (usableNames.length === 0) {
        warnLog(
            "[Concord_rule.js] 订阅节点全部被过滤或不受支持，「静态」组已填充 REJECT 占位，" +
            "需代理的流量将被拒绝，直连规则不受影响；请检查节点命名或订阅内容。"
        );
    }

    // ── 规则 ──
    const rules = [
        "IP-CIDR,127.0.0.0/8,REJECT,no-resolve",
        "IP-CIDR,0.0.0.0/32,REJECT,no-resolve",
        "IP-CIDR6,::1/128,REJECT,no-resolve",
        "IP-CIDR6,::/128,REJECT,no-resolve",
        "AND,((IN-TYPE,TUN),(DST-PORT,853)),REJECT",
        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "RULE-SET,ads-domain,REJECT",
        "RULE-SET,synology-domain,DIRECT",
        "AND,((DST-PORT,123),(NETWORK,udp)),DIRECT",
        ...(BLOCK_QUIC ? ["AND,((DST-PORT,443),(NETWORK,udp)),REJECT"] : []),
        "RULE-SET,youtube-domain,YouTube",
        "RULE-SET,twitter-domain,X",
        "RULE-SET,tiktok-domain,TikTok",
        "RULE-SET,telegram-domain,Telegram",
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

    // ── DNS ──
    // 已知可引用的名字：内建策略、自建组、地区组、最终保留的节点名
    const knownNames = new Set([
        ...BUILTIN_POLICIES,
        // DNS 专用目标：交给路由规则出站
        "RULES",
        ...OWN_GROUPS,
        ...activeRegionNames,
        ...usableNames,
        ...proxies.map(proxy => proxy.name)
    ]);
    const dns = buildDNS(config, ipv6Enabled(config), knownNames);

    // ── 引用校验 ──
    // 组名此时已确定；被过滤的信息节点仍会输出，其 dialer-proxy 同样会被内核校验
    cleanDialerProxies(proxies, [...OWN_GROUPS, ...activeRegionNames]);

    // ── 组装输出：只输出内核读取的字段 ──
    const out = {};
    TOP_T0.concat(TOP_T1).forEach(key => {
        if (key in config) out[key] = config[key];
    });
    // 显式写出 IPv6：内核默认 true、mihomo 默认 false，不写会随客户端漂移
    out.ipv6 = ipv6Enabled(config);
    out.proxies = proxies;
    out["proxy-groups"] = groups;
    out["rule-providers"] = ruleProviders;
    out.rules = rules;
    out.dns = dns;
    out.hosts = sanitizeHosts(config.hosts);
    out.sniffer = buildSniffer(config);
    out.ntp = pickKeys(isPlainObject(config.ntp) ? config.ntp : {}, NTP_KEYS);
    out["geox-url"] = pickKeys(isPlainObject(config["geox-url"]) ? config["geox-url"] : {}, GEOX_KEYS);
    out.profile = profile;
    out.tun = buildTun(config);

    // 内核读取但脚本不重建的段：原样继承，只剔除会告警的键
    out.experimental = sanitizeExperimental(config.experimental);
    out.tls = sanitizeTls(config.tls);
    if (isPlainObject(config.mitm)) out.mitm = config.mitm;

    // 空段不输出，避免内核用默认值之外的空对象覆盖
    ["hosts", "sniffer", "ntp", "geox-url", "tun", "experimental", "tls"].forEach(key => {
        if (isPlainObject(out[key]) && Object.keys(out[key]).length === 0) delete out[key];
    });

    return out;
}

// ── 工具函数 ──

// 按白名单取键，其余一律丢弃
function pickKeys(source, allowed) {
    const out = {};
    if (!isPlainObject(source)) return out;
    allowed.forEach(key => {
        if (key in source) out[key] = source[key];
    });
    return out;
}

// 地区正则沿用 Clash 的 (?i) 前缀写法，JS 的 RegExp 不支持该前缀，转换后再用
function toJsRegex(goStyleRegex) {
    return new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");
}

// 自然排序比较器：数字段按数值比较
function naturalCompare(a, b) {
    const chunk = s => {
        const parts = [];
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
}

// 节点是否会被内核剔除或告警；返回原因则丢弃
function nodeRejectReason(proxy) {
    const type = typeof proxy.type === "string" ? proxy.type.toLowerCase() : "";
    if (!PROXY_TYPES_OK.has(type)) {
        return "节点类型 " + (type || "未知") + " 不受支持";
    }
    for (const key of T2_TLS_KEYS) {
        if (key in proxy) return "选项 " + key + " 不受支持";
    }
    if (type === "ss" && typeof proxy.plugin === "string" &&
        T2_SS_PLUGINS.indexOf(proxy.plugin) !== -1) {
        return "Shadowsocks 插件 " + proxy.plugin + " 不受支持";
    }
    if (typeof proxy.network === "string" &&
        T2_NETWORKS.indexOf(proxy.network.toLowerCase()) !== -1) {
        return "传输 " + proxy.network + " 不受支持";
    }
    // dialer-proxy 指向自身或成环会让整份配置被拒绝
    if (typeof proxy["dialer-proxy"] === "string" && proxy["dialer-proxy"] === proxy.name) {
        return "dialer-proxy 指向自身";
    }
    return "";
}

// 节点清洗：丢弃空名节点与内核不支持的节点（类型/传输/插件/TLS 选项），并汇报剔除数量。
// 空名或非字符串 name 会让内核直接拒绝整份配置
function sanitizeNodes(rawProxies) {
    const valid = rawProxies.filter(
        proxy => proxy && typeof proxy.name === "string" && proxy.name !== ""
    );

    const dropped = [];
    const kept = valid.filter(proxy => {
        const reason = nodeRejectReason(proxy);
        if (reason) {
            dropped.push(proxy.name + "（" + reason + "）");
            return false;
        }
        return true;
    });

    if (dropped.length > 0) {
        warnLog(
            "[Concord_rule.js] 已剔除 " + dropped.length +
            " 个 Concord 不支持的节点：" + dropped.slice(0, 10).join("、") +
            (dropped.length > 10 ? " 等" : "")
        );
    }
    return kept;
}

// 逐节点补全与修正：未指定 ip-version 的补默认值，废弃指纹改写成现代名，
// amnezia-wg-option v3 中内核不生效的子键删除
function normalizeProxies(proxies) {
    proxies.forEach(proxy => {
        if (proxy.type !== "direct" && proxy.type !== "reject" && !("ip-version" in proxy)) {
            proxy["ip-version"] = DEFAULT_IP_VERSION;
        }
        ["client-fingerprint", "fingerprint"].forEach(key => {
            const value = proxy[key];
            if (typeof value === "string" && DEPRECATED_FINGERPRINTS[value]) {
                proxy[key] = DEPRECATED_FINGERPRINTS[value];
            }
        });
        const amnezia = proxy["amnezia-wg-option"];
        if (isPlainObject(amnezia) && Number(amnezia.version) === 3) {
            AMNEZIA_UNAPPLIED.forEach(key => delete amnezia[key]);
            delete amnezia["random-trailers"];
        }
    });
}

// 与保留名或订阅内重名的节点追加后缀，保留名用「节点·」前缀以区别于普通重名
function renameDuplicateProxies(proxies, reservedNames) {
    const used = new Set();
    proxies.forEach(proxy => {
        let name = proxy.name;
        if (reservedNames.has(name) || used.has(name)) {
            const isReserved = reservedNames.has(name);
            let candidate = name;
            let suffix = 0;
            do {
                suffix++;
                candidate = isReserved
                    ? "节点·" + name + (suffix > 1 ? "·" + suffix : "")
                    : name + "·" + suffix;
            } while (reservedNames.has(candidate) || used.has(candidate));
            name = candidate;
            proxy.name = name;
        }
        used.add(name);
    });
}

// 清理悬空的 dialer-proxy：目标必须是最终存在的节点或策略组，否则内核拒绝整份配置
function cleanDialerProxies(proxies, groupNames) {
    const names = new Set([
        ...proxies.map(proxy => proxy.name),
        ...groupNames,
        "DIRECT",
        "REJECT"
    ]);
    proxies.forEach(proxy => {
        const target = proxy["dialer-proxy"];
        if (typeof target === "string" && target !== "" && !names.has(target)) {
            delete proxy["dialer-proxy"];
            warnLog(
                "[Concord_rule.js] 节点 " + proxy.name + " 的 dialer-proxy 指向不存在的 " +
                target + "，已移除该字段。"
            );
        }
    });
}

// IPv6 默认开启，仅当订阅显式设为 false 时关闭
function ipv6Enabled(config) {
    return config.ipv6 !== false;
}

// 策略组：主代理 → 静态 → 直连 → 13 业务组 → 地区测速组 → 兜底（兜底固定最后）
function buildGroups(activeRegions, regionNodeNames, usableNames) {
    const activeRegionNames = activeRegions.map(region => region.name);
    const groups = [
        {
            name: "主代理",
            type: "select",
            icon: qureIcon("Proxy.png"),
            proxies: activeRegionNames.length > 0
                ? [...activeRegionNames, "静态", "直连"]
                : ["静态", "直连"]
        },
        {
            name: "静态",
            type: "select",
            icon: qureIcon("Static.png"),
            // 无可用节点时填 REJECT 占位，内核不允许空组
            proxies: usableNames.length > 0 ? usableNames : ["REJECT"],
            "empty-fallback": "REJECT"
        },
        {
            name: "直连",
            type: "select",
            hidden: true,
            icon: qureIcon("Direct.png"),
            proxies: ["DIRECT"]
        }
    ];

    // 业务组前段为切换目标，后段为订阅节点本身，两者缺一不可
    const switchTargets = ["主代理", "直连", ...activeRegionNames];
    APP_GROUPS.forEach(app => {
        groups.push({
            name: app.name,
            type: "select",
            icon: qureIcon(app.icon),
            proxies: [...switchTargets, ...usableNames]
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

    groups.push({
        name: "兜底",
        type: "select",
        icon: qureIcon("Final.png"),
        proxies: [...switchTargets, ...usableNames]
    });
    return groups;
}

// DNS：以 fake-ip 为设计前提，订阅上游优先继承并逐条清洗，脚本只补齐分流所需策略
function buildDNS(config, ipv6Default, knownNames) {
    const subDNS = isPlainObject(config.dns) ? config.dns : {};

    // nameserver 逐条校验 scheme 与 #目标：任一非法条目都会让整份配置被拒绝
    const respectRules = subDNS["respect-rules"] === true;
    const subNS = sanitizeUpstreams(subDNS.nameserver, knownNames, respectRules);

    // fake-ip-filter 只继承纯域名条目：集合型条目依赖本脚本未定义的 provider
    const subFilter = sanitizeFakeIpFilter(subDNS["fake-ip-filter"]);

    // nameserver-policy 只保留域名键：集合键指向未定义集合会失败，通吃键会架空分流
    const subPolicy = sanitizeNameServerPolicy(subDNS["nameserver-policy"], knownNames, respectRules);

    // 解析上游订阅优先、脚本兜底；引导 DNS 必须是纯 IP，内核会校验
    const subDefaultNS = sanitizeUpstreams(subDNS["default-nameserver"], knownNames, respectRules)
        .filter(entry => /^(\d{1,3}\.){3}\d{1,3}$/.test(entry.split("#")[0]) || entry.split("#")[0].includes(":"));
    const subPSN = sanitizeUpstreams(subDNS["proxy-server-nameserver"], knownNames, respectRules);
    const subDirectNS = sanitizeUpstreams(subDNS["direct-nameserver"], knownNames, respectRules);

    const dns = {
        enable: true,
        ipv6: typeof subDNS.ipv6 === "boolean" ? subDNS.ipv6 : ipv6Default,
        // 分流依赖 fake-ip 还原真实域名，这一项是设计前提，固定开启
        "enhanced-mode": "fake-ip",
        "fake-ip-filter": [
            "+.lan", "+.local", "+.home.arpa",
            "localhost.ptlogin2.qq.com", "localhost.sec.qq.com", "localhost.work.weixin.qq.com",
            "+.msftconnecttest.com", "+.msftncsi.com",
            "+.ntp.org", "+.xboxlive.com", "+.playstation.net", "+.xbox.com",
            "xbox.ipv6.microsoft.com", "+.srv.nintendo.net",
            "time.windows.com", "time.apple.com", "time.asia.apple.com",
            "time.android.com", "time.nist.gov",
            "ntp.aliyun.com", "ntp.tencent.com", "ntp.ntsc.ac.cn",
            "+.stun.*", "+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*",
            "rule-set:cn-domain", "rule-set:private-domain", "rule-set:fakeip-filter",
            ...subFilter
        ],
        "default-nameserver": subDefaultNS.length > 0 ? subDefaultNS : [...CN_DNS_PLAIN],
        "proxy-server-nameserver": subPSN.length > 0 ? subPSN : [...CN_DNS_DOH],
        nameserver: subNS.length > 0
            ? subNS
            : ["https://1.1.1.1/dns-query#主代理", "https://8.8.8.8/dns-query#主代理"],
        // DIRECT 命中且未被 policy 覆盖的域名用国内明文 DNS（DoH 会反复回退引导 DNS，拖高延迟）
        "direct-nameserver": subDirectNS.length > 0 ? subDirectNS : [...CN_DNS_PLAIN],
        "direct-nameserver-follow-policy": true,
        // 订阅策略在前、脚本策略在后：同名键被脚本覆盖，不影响分流语义
        "nameserver-policy": Object.assign({}, subPolicy, {
            "rule-set:private-domain": ["system://"],
            "rule-set:ads-domain": ["rcode://name_error"],
            "rule-set:cn-domain": [...CN_DNS_DOH]
        })
    };

    // 订阅显式设置的 fallback 是内核支持的字段，原样继承（逐条清洗后）
    const subFallback = sanitizeUpstreams(subDNS.fallback, knownNames, respectRules);
    if (subFallback.length > 0) {
        dns.fallback = subFallback;
        const filter = sanitizeFallbackFilter(subDNS["fallback-filter"]);
        if (Object.keys(filter).length > 0) dns["fallback-filter"] = filter;
    }
    // 可选调优项：订阅设了才继承，未设则用内核默认
    ["fallback-lazy-query", "ipv6-timeout", "fake-ip-ttl", "cache-max-size"].forEach(key => {
        if (key in subDNS) dns[key] = subDNS[key];
    });

    // IPv6 fake-ip 段仅在内核启用 IPv6 时输出
    if (dns.ipv6) dns["fake-ip-range6"] = "fdfe:dcba:9876::/64";

    return dns;
}

// 逐条清洗 DNS 上游：丢弃不支持的 scheme，并把悬空的 #目标换成 #RULES
function sanitizeUpstreams(value, knownNames, respectRules) {
    if (value === undefined || value === null) return [];
    const list = Array.isArray(value) ? value : [value];
    const out = [];
    for (const item of list) {
        if (typeof item !== "string") continue;
        const text = item.trim();
        if (!text) continue;

        const hash = text.indexOf("#");
        const base = hash === -1 ? text : text.slice(0, hash);
        const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(base);
        let schemeName = "";
        if (scheme) {
            schemeName = scheme[1].toLowerCase();
            if (DNS_SCHEMES_REJECT.has(schemeName)) {
                warnLog("[Concord_rule.js] 已丢弃不支持的 DNS 上游：" + text);
                continue;
            }
            if (!DNS_SCHEMES_OK.has(schemeName)) {
                warnLog("[Concord_rule.js] 已丢弃未知 scheme 的 DNS 上游：" + text);
                continue;
            }
        }

        // 特殊 scheme 不走代理路由，无需 #目标
        const isSpecial =
            schemeName === "system" || schemeName === "rcode" || schemeName === "dhcp";

        // 无 #目标：保持订阅原语义（直连解析）；订阅开了 respect-rules 时补 #RULES
        if (hash === -1) {
            out.push(isSpecial || !respectRules ? base : base + "#RULES");
            continue;
        }

        const parts = text
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(Boolean);
        const params = parts.filter(part => part.includes("="));
        const targets = parts.filter(part => !part.includes("="));
        const validTargets = targets.filter(target => knownNames.has(target));
        // 目标全部失效：退回 #RULES 交给路由，避免裸 URL 直连造成污染
        const finalTargets =
            validTargets.length > 0
                ? validTargets
                : isSpecial || !respectRules
                  ? []
                  : ["RULES"];
        const merged = [...finalTargets, ...params];
        out.push(merged.length > 0 ? base + "#" + merged.join("&") : base);
    }
    return [...new Set(out)];
}

// fallback-filter 是内核支持的字段，逐键清洗后继承
function sanitizeFallbackFilter(value) {
    const out = {};
    if (!isPlainObject(value)) return out;
    if ("geoip" in value) out.geoip = value.geoip;
    if ("geoip-code" in value) out["geoip-code"] = value["geoip-code"];
    if (Array.isArray(value.ipcidr)) out.ipcidr = value.ipcidr.filter(item => typeof item === "string");
    if (Array.isArray(value.domain)) out.domain = value.domain.filter(item => typeof item === "string");
    if (Array.isArray(value.geosite)) out.geosite = value.geosite.filter(item => typeof item === "string");
    return out;
}

// 只继承合法的域名型 fake-ip-filter 条目
function sanitizeFakeIpFilter(value) {
    if (value === undefined || value === null) return [];
    const list = Array.isArray(value) ? value : [value];
    const out = [];
    for (const item of list) {
        if (typeof item !== "string") continue;
        const text = item.trim();
        if (!text) continue;
        // geosite:/rule-set:/geoip: 依赖集合定义，内核会按集合解析，未定义即失败
        if (/^(rule-set|geosite|geoip):/i.test(text)) continue;
        if (!isValidDomainPattern(text)) continue;
        out.push(text);
    }
    return [...new Set(out)];
}

// 域名模式校验：与内核 split_domain 的规则对齐，非法条目会让配置被拒绝
function isValidDomainPattern(pattern) {
    if (typeof pattern !== "string" || pattern === "") return false;
    if (pattern.endsWith(".")) return false;
    if (/^\s|\s$/.test(pattern)) return false;
    const labels = pattern.split(".");
    if (labels.slice(1).some(label => label === "")) return false;
    for (let i = 0; i < labels.length; i++) {
        const label = labels[i];
        if (label.includes("+")) {
            if (label !== "+") return false;
            if (i !== 0) return false;
            if (labels.length === 1) return false;
        }
        if (label.includes("*") && label !== "*") return false;
    }
    return true;
}

// 只继承域名键的 nameserver-policy，值逐条清洗
function sanitizeNameServerPolicy(value, knownNames, respectRules) {
    const out = {};
    if (!isPlainObject(value)) return out;
    Object.keys(value).forEach(key => {
        // 通吃键会覆盖脚本分流；geosite:/rule-set: 键依赖未定义的集合
        if (key === "+." || key === "*" || key === "+") return;
        if (/^(rule-set|geosite|geoip):/i.test(key)) return;
        const servers = sanitizeUpstreams(value[key], knownNames, respectRules);
        if (servers.length > 0) out[key] = servers;
    });
    return out;
}

// hosts 只保留内核能接受的条目
function sanitizeHosts(value) {
    const out = {};
    if (!isPlainObject(value)) return out;
    Object.keys(value).forEach(domain => {
        if (!validHostDomain(domain)) return;
        const entry = value[domain];
        const list = Array.isArray(entry) ? entry : [entry];
        // 内核不支持 hosts 值 lan，会直接拒绝配置
        if (list.length === 1 && list[0] === "lan") return;
        out[domain] = entry;
    });
    return out;
}

// 内核会跳过含空格、首尾点的域名并告警，这里提前过滤
function validHostDomain(domain) {
    return (
        typeof domain === "string" &&
        domain !== "" &&
        !domain.startsWith(".") &&
        !domain.endsWith(".") &&
        !/\s/.test(domain)
    );
}

// experimental 段：内核读取 fingerprints 与 dialer-ip4p-convert；
// quic-go-disable-gso / quic-go-disable-ecn 不生效且非默认值会告警，直接不输出（回落到内核默认）
function sanitizeExperimental(value) {
    const out = {};
    if (!isPlainObject(value)) return out;
    if ("fingerprints" in value) out.fingerprints = value.fingerprints;
    if ("dialer-ip4p-convert" in value) out["dialer-ip4p-convert"] = value["dialer-ip4p-convert"];
    return out;
}

// tls 段：内核只读 custom-certifactes / custom-certificates；
// certificate、private-key、client-auth-*、ech-key 为入站 TLS 设置，非空会告警，不输出
function sanitizeTls(value) {
    const out = {};
    if (!isPlainObject(value)) return out;
    ["custom-certifactes", "custom-certificates"].forEach(key => {
        if (key in value) out[key] = value[key];
    });
    return out;
}

// 嗅探：纯 IP 流量还原真实域名后参与分流
function buildSniffer(config) {
    const sub = isPlainObject(config.sniffer) ? config.sniffer : {};
    const sniffer = {
        enable: true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: {
            HTTP: { ports: [80, "8080-8880"], "override-destination": true },
            TLS: { ports: [443, 8443] },
            QUIC: { ports: [443, 8443] }
        },
        "skip-domain": [
            "Mijia Cloud",
            "+.apple.com",
            "+.openai.com",
            "+.oaistatic.com",
            "+.oaiusercontent.com",
            "+.chatgpt.com"
        ]
    };
    // 订阅显式关闭嗅探时尊重其选择
    if (sub.enable === false) sniffer.enable = false;
    return sniffer;
}

// tun 段按白名单继承，剔除内核不生效或会回退的键
function buildTun(config) {
    const sub = isPlainObject(config.tun) ? config.tun : {};
    const tun = pickKeys(sub, TUN_KEYS);
    // gso 在内核中不生效并告警
    delete tun.gso;
    // stack 为 mixed/system 时内核回退到用户态栈并告警；直接不输出，由客户端默认值决定
    if (typeof tun.stack === "string") {
        const stack = tun.stack.toLowerCase();
        if (stack === "mixed" || stack === "system") delete tun.stack;
    }
    return tun;
}

function qureIcon(name) {
    return QURE_ICON_BASE + "/" + name;
}

function flagIcon(code) {
    return FLAG_ICON_BASE + "/" + code + ".png";
}

// 23 个地区及其匹配正则；regex 仅经 toJsRegex 用于 JS 侧分类
function buildRegions() {
    return [
        { name: "AE", regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|Emirates|Dubai|Abu[ -]?Dhabi)", icon: flagIcon("ae") },
        { name: "AR", regex: "(?i)(阿根廷|布宜诺斯艾利斯|🇦🇷|(^|[^A-Za-z])AR([^A-Za-z]|$)|(^|[^A-Za-z])ARG([^A-Za-z]|$)|Argentina|Buenos[ -]?Aires)", icon: flagIcon("ar") },
        { name: "AU", regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z])AU([^A-Za-z]|$)|(^|[^A-Za-z])AUS([^A-Za-z]|$)|Australia|Sydney|Melbourne|Brisbane|Perth|Adelaide)", icon: flagIcon("au") },
        { name: "BD", regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z])BD([^A-Za-z]|$)|(^|[^A-Za-z])BGD([^A-Za-z]|$)|Bangladesh|Dhaka)", icon: flagIcon("bd") },
        { name: "BR", regex: "(?i)(巴西|圣保罗|聖保羅|🇧🇷|(^|[^A-Za-z])BR([^A-Za-z]|$)|(^|[^A-Za-z])BRA([^A-Za-z]|$)|Brazil|Brasil|(Sao|São)[ -]?Paulo|Rio[ -]?de[ -]?Janeiro|(^|[^A-Za-z])Rio([^A-Za-z]|$))", icon: flagIcon("br") },
        { name: "CA", regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|(^|[^A-Za-z])CA([^A-Za-z]|$)|(^|[^A-Za-z])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver|Montreal|Calgary)", icon: flagIcon("ca") },
        { name: "DE", regex: "(?i)(德国|德國|法兰克福|法蘭克福|🇩🇪|(^|[^A-Za-z])DE([^A-Za-z]|$)|(^|[^A-Za-z])DEU([^A-Za-z]|$)|Germany|Frankfurt|Berlin|Munich|Düsseldorf|Dusseldorf|Nuremberg)", icon: flagIcon("de") },
        { name: "FR", regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|(^|[^A-Za-z])FRA([^A-Za-z]|$)|France|Paris|Marseille|Lyon)", icon: flagIcon("fr") },
        { name: "GB", regex: "(?i)(英国|英國|伦敦|倫敦|🇬🇧|(^|[^A-Za-z])UK([^A-Za-z]|$)|(^|[^A-Za-z])GB([^A-Za-z]|$)|(^|[^A-Za-z])GBR([^A-Za-z]|$)|United[ -]?Kingdom|England|London|Manchester|Edinburgh)", icon: flagIcon("gb") },
        { name: "HK", regex: "(?i)(香港|九龙|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong|Kowloon|Tsuen[ -]?Wan)", icon: flagIcon("hk") },
        { name: "ID", regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|Surabaya|(^|[^A-Za-z])ID([^A-Za-z]|$)|(^|[^A-Za-z])IDN([^A-Za-z]|$))", icon: flagIcon("id") },
        { name: "IN", regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z])India([^A-Za-z]|$)|Mumbai|(New[ -]?)?Delhi|Bangalore|Chennai|Hyderabad|(^|[^A-Za-z])IN([^A-Za-z]|$)|(^|[^A-Za-z])IND([^A-Za-z]|$))", icon: flagIcon("in") },
        { name: "JP", regex: "(?i)(日本|东京|東京|大阪|名古屋|福冈|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan|Tokyo|Osaka|Narita|Haneda|Kyoto|Fukuoka|Nagoya|Sapporo)", icon: flagIcon("jp") },
        { name: "KR", regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea|Seoul|Busan|Incheon|Chuncheon)", icon: flagIcon("kr") },
        { name: "MY", regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z])MY([^A-Za-z]|$)|(^|[^A-Za-z])MYS([^A-Za-z]|$)|Malaysia|Kuala[ -]?Lumpur|Johor[ -]?Bahru|Cyberjaya)", icon: flagIcon("my") },
        { name: "NL", regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|🇳🇱|(^|[^A-Za-z])NL([^A-Za-z]|$)|(^|[^A-Za-z])NLD([^A-Za-z]|$)|Netherlands|Amsterdam|Rotterdam)", icon: flagIcon("nl") },
        { name: "PH", regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z])PH([^A-Za-z]|$)|(^|[^A-Za-z])PHL([^A-Za-z]|$)|Philippines|Manila|Cebu)", icon: flagIcon("ph") },
        { name: "SG", regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)", icon: flagIcon("sg") },
        { name: "TH", regex: "(?i)(泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|Pattaya|Chiang[ -]?Mai|(^|[^A-Za-z])TH([^A-Za-z]|$)|(^|[^A-Za-z])THA([^A-Za-z]|$))", icon: flagIcon("th") },
        { name: "TR", regex: "(?i)(土耳其|伊斯坦布尔|🇹🇷|(^|[^A-Za-z])TR([^A-Za-z]|$)|(^|[^A-Za-z])TUR([^A-Za-z]|$)|Turkey|Türkiye|Istanbul|Ankara)", icon: flagIcon("tr") },
        { name: "TW", regex: "(?i)(台湾|台灣|台北|新北|台中|高雄|🇹🇼|(^|[^A-Za-z])TW([^A-Za-z]|$)|(^|[^A-Za-z])TWN([^A-Za-z]|$)|Taiwan|Taipei|Kaohsiung|Taichung|Hsinchu)", icon: flagIcon("tw") },
        { name: "US", regex: "(?i)(美国|美國|美西|美东|达拉斯|芝加哥|拉斯维加斯|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|Silicon[ -]?Valley|New[ -]?York|Seattle|Dallas|Chicago|Fremont|Phoenix|Denver|Atlanta|Miami)", icon: flagIcon("us") },
        { name: "VN", regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z])VN([^A-Za-z]|$)|(^|[^A-Za-z])VNM([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)", icon: flagIcon("vn") }
    ];
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
