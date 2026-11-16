// Concord_rule.js V1.0
// 订阅只提供节点；策略组、规则集、DNS、嗅探均由本脚本生成，输出保证零告警。

// ── 可调参数 ──
const DEFAULT_IP_VERSION = "dual"; // 双栈偏好：dual(并发择优) / ipv6-prefer / ipv4-prefer
const REGION_MIN_NODES = 2;        // 达到该值才建地区组
const RS_INTERVAL = 604800;        // 规则集更新周期：一周
const BLOCK_QUIC = false;          // 拒绝 UDP 443 迫使回退 TCP；仅节点不支持 UDP 时开

const CN_DNS_DOH = ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"];
const CN_DNS_PLAIN = ["223.5.5.5", "119.29.29.29"];
const TEST_URL = "https://www.gstatic.com/generate_204";
const QURE_ICON_BASE = "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color";
const FLAG_ICON_BASE =
    "https://cdn.jsdmirror.com/gh/open-assets-hub/country-flag-collection@main/circle/128";

// ── 节点支持范围 ──
// 类型、传输、插件、TLS 选项超出范围的节点会被内核剔除，脚本提前丢弃
const SUPPORTED_TYPES = new Set([
    "direct", "reject", "ss", "vmess", "vless", "trojan", "hysteria2",
    "tuic", "anytls", "socks5", "http",
    "wireguard", "hysteria", "ssr", "snell", "mieru", "ssh", "shadowquic"
]);
const REJECT_TLS_OPTIONS = ["shadow-tls-opts", "restls-opts", "jls-opts", "tlsmirror-opts"];
const REJECT_SS_PLUGINS = ["restls", "gost-plugin", "kcptun", "jls"];
const REJECT_NETWORKS = ["mkcp", "kcp", "mekya"];

// 废弃指纹名：内核会改写并告警，脚本提前改写成现代名
const FINGERPRINT_ALIAS = {
    chrome_psk: "chrome",
    chrome_psk_shuffle: "chrome",
    chrome_padding_psk_shuffle: "chrome",
    chrome_pq: "chrome",
    chrome_pq_psk: "chrome",
    randomized: "random"
};

// amnezia-wg-option v3 中内核不生效的子键
const AMNEZIA_DROP = [
    "content-padding-addition", "rekey-after-time", "rekey-timeout",
    "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
    "disable-cookies", "random-trailers"
];

// ── 分流数据 ──
// 节点名里的信息类关键词，这些不该成为可选节点
const EXCLUDE_FILTER =
    "(?i)(剩余|官网|套餐|已用|到期|过期|重置|更新|刷新|订阅|通知|本站|网址|客服|欢迎|Expire|Traffic|Reset|(剩余|已用|可用|查询|超出|总)流量|流量([:：]|\\s*(剩余|已用|可用|重置|耗尽|不足|提醒|查询|统计|清零))|(到期|过期|剩余|重置|更新|刷新|有效)时间|时间[:：]|(官网|最新|发布|永久|备用|防失联|防走丢)地址|地址[:：]|有效期|有效至|(QQ|TG|Telegram|电报|交流|官方|通知|用户)群|群([:：|｜\\s]|$)|加群|入群|群聊|群号|群组|群链接|加入(我们|群|TG|电报|频道|Telegram|QQ)|防(失联|走丢)|(^|[^A-Za-z0-9])(\\d+\\s*Days?|(Data|Used|Left|Remain|Quota)\\s*[:：\\s]*\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+(\\.\\d+)?\\s*(GB|TB)\\s*/\\s*\\d+(\\.\\d+)?\\s*(GB|TB))([^A-Za-z0-9]|$))";

// 23 个地区及其匹配正则，regex 仅在 JS 侧用于节点归类
const REGIONS = [
    { name: "AE", regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|Emirates|Dubai|Abu[ -]?Dhabi)" },
    { name: "AR", regex: "(?i)(阿根廷|布宜诺斯艾利斯|🇦🇷|(^|[^A-Za-z])AR([^A-Za-z]|$)|(^|[^A-Za-z])ARG([^A-Za-z]|$)|Argentina|Buenos[ -]?Aires)" },
    { name: "AU", regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z])AU([^A-Za-z]|$)|(^|[^A-Za-z])AUS([^A-Za-z]|$)|Australia|Sydney|Melbourne|Brisbane|Perth|Adelaide)" },
    { name: "BD", regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z])BD([^A-Za-z]|$)|(^|[^A-Za-z])BGD([^A-Za-z]|$)|Bangladesh|Dhaka)" },
    { name: "BR", regex: "(?i)(巴西|圣保罗|聖保羅|🇧🇷|(^|[^A-Za-z])BR([^A-Za-z]|$)|(^|[^A-Za-z])BRA([^A-Za-z]|$)|Brazil|Brasil|(Sao|São)[ -]?Paulo|Rio[ -]?de[ -]?Janeiro|(^|[^A-Za-z])Rio([^A-Za-z]|$))" },
    { name: "CA", regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|(^|[^A-Za-z])CA([^A-Za-z]|$)|(^|[^A-Za-z])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver|Montreal|Calgary)" },
    { name: "DE", regex: "(?i)(德国|德國|法兰克福|法蘭克福|🇩🇪|(^|[^A-Za-z])DE([^A-Za-z]|$)|(^|[^A-Za-z])DEU([^A-Za-z]|$)|Germany|Frankfurt|Berlin|Munich|Düsseldorf|Dusseldorf|Nuremberg)" },
    { name: "FR", regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|(^|[^A-Za-z])FRA([^A-Za-z]|$)|France|Paris|Marseille|Lyon)" },
    { name: "GB", regex: "(?i)(英国|英國|伦敦|倫敦|🇬🇧|(^|[^A-Za-z])UK([^A-Za-z]|$)|(^|[^A-Za-z])GB([^A-Za-z]|$)|(^|[^A-Za-z])GBR([^A-Za-z]|$)|United[ -]?Kingdom|England|London|Manchester|Edinburgh)" },
    { name: "HK", regex: "(?i)(香港|九龙|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong|Kowloon|Tsuen[ -]?Wan)" },
    { name: "ID", regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|Surabaya|(^|[^A-Za-z])ID([^A-Za-z]|$)|(^|[^A-Za-z])IDN([^A-Za-z]|$))" },
    { name: "IN", regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z])India([^A-Za-z]|$)|Mumbai|(New[ -]?)?Delhi|Bangalore|Chennai|Hyderabad|(^|[^A-Za-z])IN([^A-Za-z]|$)|(^|[^A-Za-z])IND([^A-Za-z]|$))" },
    { name: "JP", regex: "(?i)(日本|东京|東京|大阪|名古屋|福冈|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan|Tokyo|Osaka|Narita|Haneda|Kyoto|Fukuoka|Nagoya|Sapporo)" },
    { name: "KR", regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea|Seoul|Busan|Incheon|Chuncheon)" },
    { name: "MY", regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z])MY([^A-Za-z]|$)|(^|[^A-Za-z])MYS([^A-Za-z]|$)|Malaysia|Kuala[ -]?Lumpur|Johor[ -]?Bahru|Cyberjaya)" },
    { name: "NL", regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|🇳🇱|(^|[^A-Za-z])NL([^A-Za-z]|$)|(^|[^A-Za-z])NLD([^A-Za-z]|$)|Netherlands|Amsterdam|Rotterdam)" },
    { name: "PH", regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z])PH([^A-Za-z]|$)|(^|[^A-Za-z])PHL([^A-Za-z]|$)|Philippines|Manila|Cebu)" },
    { name: "SG", regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)" },
    { name: "TH", regex: "(?i)(泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|Pattaya|Chiang[ -]?Mai|(^|[^A-Za-z])TH([^A-Za-z]|$)|(^|[^A-Za-z])THA([^A-Za-z]|$))" },
    { name: "TR", regex: "(?i)(土耳其|伊斯坦布尔|🇹🇷|(^|[^A-Za-z])TR([^A-Za-z]|$)|(^|[^A-Za-z])TUR([^A-Za-z]|$)|Turkey|Türkiye|Istanbul|Ankara)" },
    { name: "TW", regex: "(?i)(台湾|台灣|台北|新北|台中|高雄|🇹🇼|(^|[^A-Za-z])TW([^A-Za-z]|$)|(^|[^A-Za-z])TWN([^A-Za-z]|$)|Taiwan|Taipei|Kaohsiung|Taichung|Hsinchu)" },
    { name: "US", regex: "(?i)(美国|美國|美西|美东|达拉斯|芝加哥|拉斯维加斯|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|Silicon[ -]?Valley|New[ -]?York|Seattle|Dallas|Chicago|Fremont|Phoenix|Denver|Atlanta|Miami)" },
    { name: "VN", regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z])VN([^A-Za-z]|$)|(^|[^A-Za-z])VNM([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)" }
];

// 13 个业务分流组
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

// 规则集：引用名 → MetaCubeX 官方 mrs 分类名
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
const IP_SETS = { "private-ip": "private", "telegram-ip": "telegram", "cn-ip": "cn" };

// fake-ip 豁免清单：局域网、对时、连通性探测、游戏平台及规则集兜底
const FAKE_IP_FILTER = [
    "+.lan", "+.local", "+.home.arpa",
    "localhost.ptlogin2.qq.com", "localhost.sec.qq.com", "localhost.work.weixin.qq.com",
    "+.msftconnecttest.com", "+.msftncsi.com",
    "+.ntp.org", "+.xboxlive.com", "+.playstation.net", "+.xbox.com",
    "xbox.ipv6.microsoft.com", "+.srv.nintendo.net",
    "time.windows.com", "time.apple.com", "time.asia.apple.com",
    "time.android.com", "time.nist.gov",
    "ntp.aliyun.com", "ntp.tencent.com", "ntp.ntsc.ac.cn",
    "+.stun.*", "+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*",
    "rule-set:cn-domain", "rule-set:private-domain", "rule-set:fakeip-filter"
];

// 嗅探跳过名单：这些域名在 TLS 层已足够识别，避免重复解析
const SNIFF_SKIP_DOMAIN = [
    "Mijia Cloud", "+.apple.com", "+.openai.com",
    "+.oaistatic.com", "+.oaiusercontent.com", "+.chatgpt.com"
];

const BUILTIN_POLICIES = new Set([
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"
]);

// 入口：订阅节点经清洗后，与脚本生成的分流策略组装成完整配置。
// 流程：节点清洗 → 命名去重 → 地区归类 → 策略组/规则集/规则/DNS 生成 → 组装输出
function main(config) {
    if (!isPlainObject(config)) config = {};
    if (!Array.isArray(config.proxies)) config.proxies = [];

    // 订阅形态校验：proxy-providers 的节点在运行时才拉取，脚本期无法据此生成地区组
    if (isPlainObject(config["proxy-providers"]) &&
        Object.keys(config["proxy-providers"]).length > 0) {
        throw new Error(
            "[Concord_rule.js] 检测到 proxy-providers 订阅，本脚本仅支持节点平铺的订阅形式，已拒绝生成配置。"
        );
    }

    // ── 节点 ──
    const proxies = prepareProxies(config.proxies);
    // 信息类节点（流量、到期、群链接等）仍输出，但不作为可选节点
    const excludeRe = toJsRegex(EXCLUDE_FILTER);
    const usableNames = proxies
        .filter(proxy => proxy.type !== "direct" && proxy.type !== "reject")
        .filter(proxy => !excludeRe.test(proxy.name))
        .map(proxy => proxy.name);

    // 无可用节点时配置虽能加载，但所有需代理的流量都会被拒绝，必须让用户知道
    if (usableNames.length === 0) {
        const say = typeof console !== "undefined" ? console.warn || console.log : undefined;
        if (typeof say === "function") {
            say.call(
                console,
                "[Concord_rule.js] 订阅中没有可用节点，需代理的流量将被拒绝；请检查订阅内容或节点命名。"
            );
        }
    }

    // ── 地区归类 ──
    const regionNodes = new Map();
    REGIONS.forEach(region => {
        const regex = toJsRegex(region.regex);
        const matched = usableNames.filter(name => regex.test(name));
        if (matched.length >= Math.max(1, REGION_MIN_NODES)) {
            regionNodes.set(region.name, matched);
        }
    });
    const activeRegions = REGIONS.filter(region => regionNodes.has(region.name));

    // ── 引用校验 ──
    // 组名确定后清理悬空 dialer-proxy：被过滤的信息节点仍会输出，同样要过内核校验
    const groupNames = [
        "主代理", "静态", "直连", "兜底",
        ...APP_GROUPS.map(app => app.name),
        ...activeRegions.map(region => region.name)
    ];
    dropDanglingDialer(proxies, groupNames);

    // ── 组装 ──
    const ipv6 = config.ipv6 !== false;
    const out = {
        // 性能与行为：脚本按分流需要固定
        "unified-delay": true,
        "tcp-concurrent": true,
        "find-process-mode": "off",
        "keep-alive-idle": 300,
        "keep-alive-interval": 30,
        ipv6: ipv6,
        profile: { "store-selected": true, "store-fake-ip": true },

        proxies: proxies,
        "proxy-groups": buildGroups(activeRegions, regionNodes, usableNames),
        "rule-providers": buildRuleProviders(),
        rules: buildRules(),
        dns: buildDNS(ipv6),
        sniffer: buildSniffer()
    };

    // 用户偏好：仅继承明确表达意图的字段，其余交给客户端默认值
    const tun = buildTun(config);
    if (tun) out.tun = tun;
    const hosts = buildHosts(config.hosts);
    if (hosts) out.hosts = hosts;

    return out;
}

// ── 节点处理 ──

// 清洗：丢弃空名节点与内核不支持的节点，补全默认值，改写废弃指纹，处理重名
function prepareProxies(rawProxies) {
    const kept = rawProxies.filter(
        proxy =>
            proxy &&
            typeof proxy.name === "string" &&
            proxy.name !== "" &&
            !isUnsupportedNode(proxy)
    );

    kept.forEach(proxy => {
        if (proxy.type !== "direct" && proxy.type !== "reject" && !("ip-version" in proxy)) {
            proxy["ip-version"] = DEFAULT_IP_VERSION;
        }
        ["client-fingerprint", "fingerprint"].forEach(key => {
            const value = proxy[key];
            if (typeof value === "string" && FINGERPRINT_ALIAS[value]) {
                proxy[key] = FINGERPRINT_ALIAS[value];
            }
        });
        const amnezia = proxy["amnezia-wg-option"];
        if (isPlainObject(amnezia) && Number(amnezia.version) === 3) {
            AMNEZIA_DROP.forEach(key => delete amnezia[key]);
        }
    });

    renameDuplicates(kept, buildReservedNames());
    kept.sort((a, b) => naturalCompare(a.name, b.name));
    return kept;
}

// 节点是否超出内核支持范围
function isUnsupportedNode(proxy) {
    const type = typeof proxy.type === "string" ? proxy.type.toLowerCase() : "";
    if (!SUPPORTED_TYPES.has(type)) return true;
    if (REJECT_TLS_OPTIONS.some(key => key in proxy)) return true;
    if (type === "ss" && typeof proxy.plugin === "string" &&
        REJECT_SS_PLUGINS.indexOf(proxy.plugin) !== -1) return true;
    if (typeof proxy.network === "string" &&
        REJECT_NETWORKS.indexOf(proxy.network.toLowerCase()) !== -1) return true;
    // dialer-proxy 指向自身会让内核拒绝整份配置
    return typeof proxy["dialer-proxy"] === "string" && proxy["dialer-proxy"] === proxy.name;
}

// 节点与策略组共用命名空间，重名会让内核启动失败
function buildReservedNames() {
    return new Set([
        "主代理", "静态", "直连", "兜底",
        ...APP_GROUPS.map(app => app.name),
        ...REGIONS.map(region => region.name),
        ...BUILTIN_POLICIES
    ]);
}

function renameDuplicates(proxies, reserved) {
    const used = new Set();
    proxies.forEach(proxy => {
        if (reserved.has(proxy.name) || used.has(proxy.name)) {
            const base = proxy.name;
            const isReserved = reserved.has(base);
            let suffix = 0;
            do {
                suffix++;
                proxy.name = isReserved
                    ? "节点·" + base + (suffix > 1 ? "·" + suffix : "")
                    : base + "·" + suffix;
            } while (reserved.has(proxy.name) || used.has(proxy.name));
        }
        used.add(proxy.name);
    });
}

// dialer-proxy 的目标必须存在，否则内核拒绝整份配置
function dropDanglingDialer(proxies, groupNames) {
    const known = new Set([
        ...proxies.map(proxy => proxy.name),
        ...groupNames,
        "DIRECT",
        "REJECT"
    ]);
    proxies.forEach(proxy => {
        const target = proxy["dialer-proxy"];
        if (typeof target === "string" && target !== "" && !known.has(target)) {
            delete proxy["dialer-proxy"];
        }
    });
}

// ── 配置生成 ──

function buildGroups(activeRegions, regionNodes, usableNames) {
    const regionNames = activeRegions.map(region => region.name);
    const switchTargets = ["主代理", "直连", ...regionNames];
    const staticMembers = usableNames.length > 0 ? usableNames : ["REJECT"];

    const groups = [
        {
            name: "主代理",
            type: "select",
            icon: qureIcon("Proxy.png"),
            proxies: regionNames.length > 0 ? [...regionNames, "静态", "直连"] : ["静态", "直连"]
        },
        {
            name: "静态",
            type: "select",
            icon: qureIcon("Static.png"),
            proxies: staticMembers,
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

    // 业务组：前段为切换目标，后段为具体节点
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
            icon: FLAG_ICON_BASE + "/" + region.name.toLowerCase() + ".png",
            proxies: regionNodes.get(region.name),
            "empty-fallback": "REJECT",
            url: TEST_URL,
            interval: 300,
            tolerance: 30,
            lazy: true,
            timeout: 5000,
            "max-failed-times": 5,
            "expected-status": 204
        });
    });

    // 兜底固定为最后一个策略组
    groups.push({
        name: "兜底",
        type: "select",
        icon: qureIcon("Final.png"),
        proxies: [...switchTargets, ...usableNames]
    });
    return groups;
}

function buildRuleProviders() {
    const base = "https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@meta/geo";
    const provider = (behavior, dir, name, path) => ({
        type: "http",
        behavior: behavior,
        format: "mrs",
        url: base + "/" + dir + "/" + name + ".mrs",
        path: "./ruleset/" + path + ".mrs",
        interval: RS_INTERVAL
    });

    const providers = {};
    Object.keys(DOMAIN_SETS).forEach(key => {
        providers[key] = provider("domain", "geosite", DOMAIN_SETS[key], "geosite-" + DOMAIN_SETS[key]);
    });
    Object.keys(IP_SETS).forEach(key => {
        providers[key] = provider("ipcidr", "geoip", IP_SETS[key], "geoip-" + IP_SETS[key]);
    });
    // 社区维护的 fake-ip 豁免清单，官方未收录
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

function buildRules() {
    // 顺序即优先级：防回环 → 私网/广告 → NAS/对时 → 应用分流 → 海外 → 国内直连 → 兜底
    const head = [
        "IP-CIDR,127.0.0.0/8,REJECT,no-resolve",
        "IP-CIDR,0.0.0.0/32,REJECT,no-resolve",
        "IP-CIDR6,::1/128,REJECT,no-resolve",
        "IP-CIDR6,::/128,REJECT,no-resolve",
        "AND,((IN-TYPE,TUN),(DST-PORT,853)),REJECT",
        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "RULE-SET,ads-domain,REJECT",
        "RULE-SET,synology-domain,DIRECT",
        // 系统对时须先于业务分流：部分节点丢弃 UDP 123，时间偏差会连带导致 TLS 校验失败
        "AND,((DST-PORT,123),(NETWORK,udp)),DIRECT"
    ];
    if (BLOCK_QUIC) head.push("AND,((DST-PORT,443),(NETWORK,udp)),REJECT");

    const app = [
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
        // 国内 CDN 域名晚于海外应用匹配，避免被直连截胡
        "RULE-SET,google-domain,Google",
        "RULE-SET,apple-domain,Apple",
        "RULE-SET,microsoft-domain,Microsoft",
        "RULE-SET,proxy-domain,主代理",
        "RULE-SET,cn-domain,DIRECT",
        "RULE-SET,cn-ip,DIRECT"
    ];

    return [...head, ...app, "MATCH,兜底"];
}

function buildDNS(ipv6) {
    const dns = {
        enable: true,
        ipv6: ipv6,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "cache-algorithm": "arc",
        "fake-ip-filter-mode": "blacklist",
        "use-hosts": true,
        "use-system-hosts": true,
        "fake-ip-filter": [...FAKE_IP_FILTER],
        // 引导 DNS 只解析其它 DoH 的域名，必须是纯 IP
        "default-nameserver": [...CN_DNS_PLAIN],
        // 节点域名走国内 DNS，不经代理，避免「要节点才能解析节点」的循环
        "proxy-server-nameserver": [...CN_DNS_DOH],
        nameserver: [
            "https://1.1.1.1/dns-query#主代理",
            "https://8.8.8.8/dns-query#主代理"
        ],
        // DIRECT 命中且未被策略覆盖的域名用国内明文 DNS，DoH 回退引导 DNS 会拖高延迟
        "direct-nameserver": [...CN_DNS_PLAIN],
        "direct-nameserver-follow-policy": true,
        "nameserver-policy": {
            "rule-set:private-domain": ["system://"],
            "rule-set:ads-domain": ["rcode://name_error"],
            "rule-set:cn-domain": [...CN_DNS_DOH]
        }
    };
    // IPv6 fake-ip 段仅在启用 IPv6 时输出，使用官方文档段避免与内网冲突
    if (ipv6) dns["fake-ip-range6"] = "fdfe:dcba:9876::/64";
    return dns;
}

function buildSniffer() {
    return {
        enable: true,
        "force-dns-mapping": true,
        // 应用绕过系统 DNS 直连 IP 时，从 TLS SNI / HTTP Host 还原域名参与分流
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: {
            HTTP: { ports: [80, "8080-8880"], "override-destination": true },
            TLS: { ports: [443, 8443] },
            QUIC: { ports: [443, 8443] }
        },
        "skip-domain": [...SNIFF_SKIP_DOMAIN]
    };
}

// tun 只继承开关，其余交客户端默认：栈、MTU 等由客户端按平台决定更稳妥
function buildTun(config) {
    const sub = isPlainObject(config.tun) ? config.tun : null;
    if (!sub || typeof sub.enable !== "boolean") return null;
    return { enable: sub.enable };
}

// hosts 只保留内核能接受的条目
function buildHosts(raw) {
    if (!isPlainObject(raw)) return null;
    const out = {};
    Object.keys(raw).forEach(domain => {
        if (!isHostDomain(domain)) return;
        const value = raw[domain];
        const values = Array.isArray(value) ? value : [value];
        // 内核不支持 hosts 值 lan，会直接拒绝配置
        if (values.some(item => item === "lan")) return;
        out[domain] = value;
    });
    return Object.keys(out).length > 0 ? out : null;
}

function isHostDomain(domain) {
    return (
        typeof domain === "string" &&
        domain !== "" &&
        !domain.startsWith(".") &&
        !domain.endsWith(".") &&
        !/\s/.test(domain)
    );
}

// ── 工具 ──

const isPlainObject = value =>
    value && typeof value === "object" && !Array.isArray(value);

// 地区正则沿用 Clash 的 (?i) 前缀写法，JS 的 RegExp 不支持该前缀
function toJsRegex(goStyleRegex) {
    return new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");
}

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

function qureIcon(name) {
    return QURE_ICON_BASE + "/" + name;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
