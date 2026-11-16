// Concord_rule.js V1.1
// 订阅只提供节点；策略组、规则集、DNS、嗅探均由本脚本生成。
// 节点清洗镜像 Concord 内核的配置解析期校验（crates/config/src/proxy/parse.rs）
// 与构建期校验（crates/proxy/src/* 的 build 函数）：无法修复的节点直接剔除，
// 可规范化的键值（大小写/下划线变体、废弃指纹等）改写为内核接受的形式，
// 保证输出零告警、不触发整份配置拒绝。

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

// ── 节点支持范围（镜像 parse.rs 的 T2 清单）──
// 类型、传输、插件、TLS 选项超出范围的节点会被内核隔离并告警，脚本提前剔除
const SUPPORTED_TYPES = new Set([
    "direct", "reject", "ss", "vmess", "vless", "trojan", "hysteria2",
    "tuic", "anytls", "socks5", "http",
    "wireguard", "hysteria", "ssr", "snell", "mieru", "ssh", "shadowquic"
]);
const REJECT_TLS_OPTIONS = ["shadow-tls-opts", "restls-opts", "jls-opts", "tlsmirror-opts"];
const REJECT_SS_PLUGINS = ["restls", "gost-plugin", "kcptun", "jls"];
const REJECT_NETWORKS = ["mkcp", "kcp", "mekya"];

// 废弃指纹名：内核会改写并告警（warn.rs），脚本提前改写成现代名以消除告警
const FINGERPRINT_ALIAS = {
    chrome_psk: "chrome",
    chrome_psk_shuffle: "chrome",
    chrome_padding_psk_shuffle: "chrome",
    chrome_pq: "chrome",
    chrome_pq_psk: "chrome",
    randomized: "random"
};

// amnezia-wg-option v3 中内核不生效的子键（warn.rs 告警清单）：
// 对 v3 删除以消除告警；对 legacy(≠3) 这些是 v3-only 键，保留会触发构建期硬错误，同样删除。
// 注：random-trailers 在握手消息上部分生效，删除会损失该效果，为保零告警仍删除。
const AMNEZIA_DROP = [
    "content-padding-addition", "rekey-after-time", "rekey-timeout",
    "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
    "disable-cookies", "random-trailers"
];

// ── 构建期白名单（镜像 crates/proxy 各 build 函数的精确匹配）──
// ss cipher 大小写敏感（ss/crypto.rs:parse_method），脚本已将值规范化为小写
const SS_CIPHERS = new Set([
    "none", "aes-128-gcm", "aes-256-gcm", "aes-128-ccm", "aes-256-ccm",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "2022-blake3-chacha8-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf"
]);
// 2022 密码的密钥长度（字节）
const SS_2022_KEYLEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
    "2022-blake3-chacha8-poly1305": 32
};
// vmess cipher 内核先 to_lowercase（vmess/mod.rs:build）
const VMESS_CIPHERS = new Set([
    "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"
]);
// trojan ss-opts method 内核 to_ascii_uppercase（trojan.rs:ss_layer）
const TROJAN_SS_METHODS = new Set([
    "DUMMY", "AES-128-GCM", "AES-256-GCM", "AES-128-CCM", "AES-256-CCM",
    "CHACHA20-IETF-POLY1305", "XCHACHA20-IETF-POLY1305", "RC4-MD5",
    "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
    "AES-128-CFB", "AES-192-CFB", "AES-256-CFB", "CHACHA20-IETF"
]);
// ssr cipher 大小写不敏感；obfs/protocol 大小写敏感（脚本已规范化为小写）
const SSR_CIPHERS = new Set([
    "none", "dummy", "rc4-md5",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "chacha20-ietf"
]);
const SSR_OBFS = new Set([
    "plain", "http_simple", "http_post", "random_head",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"
]);
const SSR_PROTOCOLS = new Set([
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b"
]);
// mieru 枚举大小写敏感（mieru/mod.rs:construct）
const MIERU_MULTIPLEXING = new Set([
    "", "MULTIPLEXING_DEFAULT", "MULTIPLEXING_LOW", "MULTIPLEXING_OFF",
    "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"
]);
const MIERU_HANDSHAKE = new Set([
    "", "HANDSHAKE_DEFAULT", "HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"
]);
// shadowquic 版本（规范化：trim + 小写 + 下划线→连字符）
const SHADOWQUIC_VERSIONS = new Set([
    "v1", "1", "rfc9000", "rfc-9000", "v2", "2", "rfc9369", "rfc-9369"
]);
const SHADOWQUIC_V1 = new Set(["v1", "1", "rfc9000", "rfc-9000"]);
// 证书 pin（fingerprint 键）不能是浏览器名（tls/policy.rs:parse_pin）
const BROWSER_PIN_NAMES = new Set([
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized"
]);
// REALITY 要求的 client-fingerprint 有效名（tlsmap.rs → ClientFingerprint::from_str）
const FINGERPRINT_NAMES = new Set([
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "chrome120", "firefox120", "safari16", "none"
]);
const HY2_OBFS = new Set(["salamander", "gecko"]);
const WG_IP_STACK_MODES = new Set(["", "auto", "mips", "gvisor"]);
const SMUX_PROTOCOLS = new Set(["", "smux", "yamux", "h2mux"]);

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

// 嗅探跳过名单：这些域名在 TLS 层已足够识别，避免重复解析。
// "Mijia Cloud" 不是域名；内核按域名模式校验，单标签条目按精确匹配处理：
// 米家设备 SNI 恰好就是 "Mijia Cloud"，可命中并跳过嗅探
const SNIFF_SKIP_DOMAIN = [
    "Mijia Cloud", "+.apple.com", "+.openai.com",
    "+.oaistatic.com", "+.oaiusercontent.com", "+.chatgpt.com"
];

const BUILTIN_POLICIES = new Set([
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"
]);

// 入口：订阅节点经清洗后，与脚本生成的分流策略组装成完整配置。
// 流程：节点清洗(规范化→支持范围→双层校验) → 命名去重 → 地区归类
//       → 悬空/成环 dialer 修复 → 策略组/规则集/规则/DNS 生成 → 组装输出
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
    // 组名确定后清理悬空与成环的 dialer-proxy：两者都会让内核拒绝整份配置
    const groupNames = [
        "主代理", "静态", "直连", "兜底",
        ...APP_GROUPS.map(app => app.name),
        ...activeRegions.map(region => region.name)
    ];
    dropDanglingDialer(proxies, groupNames);
    breakDialerCycles(proxies);

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

// 清洗流水线：键值规范化 → 支持范围过滤 → 解析期/构建期校验 → 补默认值 → 去重排序。
// 被剔除的节点静默丢弃（内核自己处理会告警或拒绝整份配置，这里提前拦下）
function prepareProxies(rawProxies) {
    const kept = [];
    rawProxies.forEach(raw => {
        if (!isPlainObject(raw)) return;
        const proxy = normalizeNode(raw);
        if (typeof proxy.name !== "string" || proxy.name === "") return;
        normalizeValues(proxy);
        if (isUnsupportedNode(proxy)) return;
        if (!isValidNode(proxy)) return;
        kept.push(proxy);
    });

    kept.forEach(proxy => {
        if (proxy.type !== "direct" && proxy.type !== "reject" && !("ip-version" in proxy)) {
            proxy["ip-version"] = DEFAULT_IP_VERSION;
        }
    });

    renameDuplicates(kept, buildReservedNames());
    kept.sort((a, b) => naturalCompare(a.name, b.name));
    return kept;
}

// 键名规范化：内核对节点键做小写 + 下划线→连字符折叠（lenient.rs Fields，
// 同名变体先出现者胜）；唯一例外是 plugin-opts 内部只折叠大小写、不折叠下划线。
// headers 子树是 HTTP 头名而非配置键，原样保留。"type" 键本身内核不折叠，
// 订阅写 "Type" 会直接硬错误，这里统一折成 "type"
function normalizeNode(raw) {
    const out = {};
    Object.keys(raw).forEach(key => {
        const nk = foldKey(key, true);
        if (nk in out) return;
        out[nk] = normalizeValue(key, raw[key], true);
    });
    return out;
}

function foldKey(key, underscore) {
    let k = String(key).toLowerCase();
    if (underscore) k = k.replace(/_/g, "-");
    return k;
}

function normalizeValue(origKey, value, underscore) {
    if (!isPlainObject(value)) return value;
    // plugin-opts 子树继承「不折叠下划线」；其余子树与父级一致
    const foldUnderscore = underscore && foldKey(origKey, false) !== "plugin-opts";
    const out = {};
    Object.keys(value).forEach(key => {
        const nk = foldKey(key, foldUnderscore);
        if (nk in out) return;
        if (nk === "headers") {
            out[nk] = value[key];
            return;
        }
        out[nk] = normalizeValue(key, value[key], foldUnderscore);
    });
    return out;
}

// 值规范化：内核按精确大小写匹配的值，统一改写成内核接受的形式
function normalizeValues(proxy) {
    if (typeof proxy.type === "string") proxy.type = proxy.type.toLowerCase();
    if (typeof proxy.network === "string") proxy.network = proxy.network.toLowerCase();
    if (typeof proxy.plugin === "string") proxy.plugin = proxy.plugin.toLowerCase();
    // ss cipher 大小写敏感，订阅常见大写写法规范化为小写
    if (proxy.type === "ss" && typeof proxy.cipher === "string") {
        proxy.cipher = proxy.cipher.toLowerCase();
    }
    // 废弃指纹别名：内核大小写敏感匹配，先转小写再映射；只处理 client-fingerprint，
    // fingerprint 是证书 pin，不做别名改写
    if (typeof proxy["client-fingerprint"] === "string") {
        const fp = proxy["client-fingerprint"].toLowerCase();
        proxy["client-fingerprint"] = FINGERPRINT_ALIAS[fp] || fp;
    }
    // vless encryption 仅接受 ""/"none"（大小写敏感），规范化大小写
    if (proxy.type === "vless" && typeof proxy.encryption === "string" &&
        proxy.encryption !== "" && proxy.encryption.toLowerCase() === "none") {
        proxy.encryption = "none";
    }
    // ssr obfs/protocol 大小写敏感须精确小写
    if (proxy.type === "ssr") {
        if (typeof proxy.obfs === "string") proxy.obfs = proxy.obfs.toLowerCase();
        if (typeof proxy.protocol === "string") proxy.protocol = proxy.protocol.toLowerCase();
    }
    // mieru transport 须精确大写 TCP/UDP
    if (proxy.type === "mieru" && typeof proxy.transport === "string") {
        const t = proxy.transport.toUpperCase();
        if (t === "TCP" || t === "UDP") proxy.transport = t;
    }
    // snell obfs mode 精确小写匹配
    if (proxy.type === "snell" && isPlainObject(proxy["obfs-opts"]) &&
        typeof proxy["obfs-opts"].mode === "string") {
        proxy["obfs-opts"].mode = proxy["obfs-opts"].mode.toLowerCase();
    }
    // hysteria protocol 精确小写匹配
    if (proxy.type === "hysteria") {
        if (typeof proxy.protocol === "string") proxy.protocol = proxy.protocol.toLowerCase();
        if (typeof proxy["obfs-protocol"] === "string") {
            proxy["obfs-protocol"] = proxy["obfs-protocol"].toLowerCase();
        }
    }
}

// 节点是否超出内核支持范围（镜像 parse.rs 的 T2 清单；键值已规范化）
function isUnsupportedNode(proxy) {
    if (!SUPPORTED_TYPES.has(proxy.type)) return true;
    if (REJECT_TLS_OPTIONS.some(key => key in proxy)) return true;
    if (proxy.type === "ss" && typeof proxy.plugin === "string" &&
        REJECT_SS_PLUGINS.indexOf(proxy.plugin) !== -1) return true;
    if (typeof proxy.network === "string" &&
        REJECT_NETWORKS.indexOf(proxy.network) !== -1) return true;
    return false;
}

// 节点能否通过内核配置解析期与构建期校验；任一不过即剔除。
// 解析期硬错误 → 整份配置拒绝；构建期 Invalid → 整份配置拒绝；
// 构建期 Unsupported → 节点被静默隔离（组引用它时拒绝连接），同样提前剔除
function isValidNode(proxy) {
    const type = proxy.type;
    if (type === "direct" || type === "reject") return true;
    if (!checkTlsCommon(proxy)) return false;
    switch (type) {
        case "ss": return isValidSs(proxy);
        case "vmess": return isValidVmess(proxy);
        case "vless": return isValidVless(proxy);
        case "trojan": return isValidTrojan(proxy);
        case "hysteria2": return isValidHysteria2(proxy);
        case "hysteria": return isValidHysteria(proxy);
        case "tuic": return isValidTuic(proxy);
        case "anytls": return isValidAnytls(proxy);
        case "socks5":
        case "http": return hasServerPort(proxy);
        case "wireguard": return isValidWireguard(proxy);
        case "ssr": return isValidSsr(proxy);
        case "snell": return isValidSnell(proxy);
        case "mieru": return isValidMieru(proxy);
        case "ssh": return isValidSsh(proxy);
        case "shadowquic": return isValidShadowquic(proxy);
        default: return true;
    }
}

// 跨类型 TLS 层校验（镜像 tlsmap.rs / link.rs 的构建期行为）
function checkTlsCommon(proxy) {
    // smux.protocol 非法 → 配置期硬错误（parse.rs:smux_opts）
    const smux = proxy.smux;
    if (isPlainObject(smux) && toBool(smux.enabled) &&
        typeof smux.protocol === "string" && !SMUX_PROTOCOLS.has(smux.protocol)) {
        return false;
    }
    // ech-opts：enable 且 config 非空时必须是合法标准 base64（配置期硬错误）
    const ech = proxy["ech-opts"];
    if (isPlainObject(ech) && toBool(ech.enable) &&
        typeof ech.config === "string" && ech.config !== "" &&
        base64Bytes(ech.config) < 0) {
        return false;
    }
    // REALITY（parse.rs 配置期 + tlsmap.rs 构建期）
    const reality = proxy["reality-opts"];
    if (isPlainObject(reality)) {
        const pk = reality["public-key"];
        if (typeof pk !== "string" || !isRealityKey(pk)) return false;
        const sid = reality["short-id"];
        if (sid !== undefined && sid !== null &&
            !(typeof sid === "string" && sid.length <= 16 && sid.length % 2 === 0 && isHex(sid))) {
            return false;
        }
        // 构建期前提：REALITY 要求 TLS 开启（vmess/vless 的 tls 标志须显式为 true）
        if ((proxy.type === "vmess" || proxy.type === "vless") && proxy.tls !== true) return false;
        // 要求有效的 client-fingerprint 且非 none（未知名字会被忽略→视同缺失→硬错误）
        const fp = typeof proxy["client-fingerprint"] === "string"
            ? proxy["client-fingerprint"] : "";
        if (!FINGERPRINT_NAMES.has(fp) || fp === "none") return false;
        // 不支持 ws / httpupgrade 传输
        if (proxy.network === "ws" || proxy.network === "httpupgrade") return false;
        // 不支持客户端证书
        if (nonEmptyText(proxy.certificate) || nonEmptyText(proxy["private-key"])) return false;
    }
    // fingerprint 是证书 pin：浏览器名或非法 hex 都会让构建失败（tls/policy.rs:parse_pin）
    if ("fingerprint" in proxy && nonEmptyText(proxy.fingerprint)) {
        if (BROWSER_PIN_NAMES.has(String(proxy.fingerprint).toLowerCase())) return false;
        const hex = String(proxy.fingerprint).replace(/:/g, "");
        if (hex.length !== 64 || !isHex(hex)) return false;
    }
    // h2 传输必须开启 TLS（link.rs:build_link 构建期硬错误；trojan 等恒开 TLS 不受影响）
    if (proxy.network === "h2" && proxy.tls === false) return false;
    // xhttp 的 alpn 恰为 ["h3"] → 构建期隔离
    if (proxy.network === "xhttp" && Array.isArray(proxy.alpn) &&
        proxy.alpn.length === 1 && proxy.alpn[0] === "h3") {
        return false;
    }
    return true;
}

function hasServerPort(proxy) {
    if (!nonEmptyText(proxy.server)) return false;
    return "port" in proxy && parsePortValue(proxy.port);
}

function isValidSs(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.password !== "string" || typeof proxy.cipher !== "string") return false;
    const cipher = proxy.cipher;
    // 未知 cipher → 构建期隔离（ss/crypto.rs:parse_method）
    if (!SS_CIPHERS.has(cipher)) return false;
    // 2022 密码：标准 base64（padding 可有可无），解码长度须等于密钥长度；
    // EIH 多密钥（冒号分隔）仅 AES 可用（ss/mod.rs:build）
    if (cipher in SS_2022_KEYLEN) {
        const need = SS_2022_KEYLEN[cipher];
        const segments = proxy.password.split(":");
        if (segments.length > 1 && cipher.indexOf("aes") === -1) return false;
        for (let i = 0; i < segments.length; i++) {
            if (base64Bytes(segments[i], true) !== need) return false;
        }
    }
    // udp-over-tcp-version：构建期仅接受 0/1/2（ss/mod.rs:build）
    if (toBool(proxy["udp-over-tcp"]) &&
        "udp-over-tcp-version" in proxy &&
        proxy["udp-over-tcp-version"] !== null) {
        const n = toUint(proxy["udp-over-tcp-version"]);
        if (n < 0) return false; // 不可解析 → 配置期类型错误
        const v = n <= 255 ? n : 0; // 内核 u8 溢出归 0
        if (v !== 0 && v !== 1 && v !== 2) return false;
    }
    // 插件构建期复核（配置期已校验一次，此处覆盖值非法的边界）
    const opts = isPlainObject(proxy["plugin-opts"]) ? proxy["plugin-opts"] : {};
    if (proxy.plugin === "obfs") {
        if (opts.mode !== "tls" && opts.mode !== "http") return false;
    } else if (proxy.plugin === "v2ray-plugin") {
        if (opts.mode !== "websocket") return false;
    } else if (proxy.plugin === "shadow-tls") {
        if (!nonEmptyText(opts.host)) return false;
        if ("version" in opts && opts.version !== null) {
            const v = Number(opts.version);
            if (!Number.isInteger(v) || v < 1 || v > 3) return false;
        }
    }
    return true;
}

function isValidVmess(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.uuid !== "string" || typeof proxy.cipher !== "string") return false;
    // 未知 cipher → 构建期硬错误（vmess/mod.rs:build，内核先转小写）
    return VMESS_CIPHERS.has(proxy.cipher.toLowerCase());
}

function isValidVless(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.uuid !== "string") return false;
    // flow ≥16 字节必须以 xtls-rprx-vision 开头，否则构建期硬错误（vless/mod.rs:build）
    const flow = typeof proxy.flow === "string" ? proxy.flow : "";
    if (flow.length >= 16 && flow.slice(0, 16) !== "xtls-rprx-vision") return false;
    // encryption 仅接受 ""/"none"，其余构建期隔离
    const enc = typeof proxy.encryption === "string" ? proxy.encryption : "";
    return enc === "" || enc === "none";
}

function isValidTrojan(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.password !== "string") return false;
    // ss-opts 仅 enabled 时校验（trojan.rs:ss_layer）
    const ss = proxy["ss-opts"];
    if (isPlainObject(ss) && toBool(ss.enabled)) {
        if (!nonEmptyText(ss.password)) return false; // 空密码 → 构建期硬错误
        const method = nonEmptyText(ss.method) ? String(ss.method).toUpperCase() : "AES-128-GCM";
        if (!TROJAN_SS_METHODS.has(method)) return false; // 未知 method → 构建期隔离
    }
    return true;
}

function isValidHysteria2(proxy) {
    if (!nonEmptyText(proxy.server)) return false;
    const portVal = "port" in proxy && parsePortValue(proxy.port) ? Number(proxy.port) : 0;
    const ports = typeof proxy.ports === "string" ? proxy.ports : "";
    const portsValid = ports !== "" && parsePortsList(ports);
    // port 与 ports 至少一个（配置期硬错误）
    if (portVal === 0 && !portsValid) return false;
    // obfs（hysteria2/mod.rs:obfs_spec）
    const obfs = typeof proxy.obfs === "string" ? proxy.obfs : "";
    if (obfs !== "") {
        if (!nonEmptyText(proxy["obfs-password"])) return false;
        if (!HY2_OBFS.has(obfs)) return false;
        if (obfs === "gecko") {
            const min = Number(proxy["obfs-min-packet-size"]) || 0;
            const max = Number(proxy["obfs-max-packet-size"]) || 0;
            const lo = min === 0 ? 512 : min;
            const hi = max === 0 ? 1200 : max;
            if (lo > hi || hi > 2048) return false;
        }
    }
    // hop-interval：""/N/N-M 十进制（hysteria2/mod.rs:hop_interval）
    if (proxy["hop-interval"] !== undefined && proxy["hop-interval"] !== null) {
        const s = String(proxy["hop-interval"]).trim();
        if (s !== "" && !/^\d+(-\d+)?$/.test(s)) return false;
    }
    // realm 互斥与组合限制（hysteria2/mod.rs:build_hy2）
    const realm = proxy["realm-opts"];
    if (isPlainObject(realm) && toBool(realm.enable)) {
        if (portsValid) return false; // realm 与端口跳跃互斥 → 构建期硬错误
        // realm + dialer-proxy → 构建期隔离：移除 dialer-proxy 保住节点
        if (nonEmptyText(proxy["dialer-proxy"])) delete proxy["dialer-proxy"];
    }
    return true;
}

function isValidHysteria(proxy) {
    if (!nonEmptyText(proxy.server)) return false;
    const portVal = "port" in proxy && parsePortValue(proxy.port) ? Number(proxy.port) : 0;
    const ports = typeof proxy.ports === "string" ? proxy.ports : "";
    const portsValid = ports !== "" && parsePortsList(ports);
    if (portVal === 0 && !portsValid) return false;
    // up/down 必填且带宽字符串可解析为非零值（hysteria/mod.rs:rates）
    const up = textOf(proxy.up);
    const down = textOf(proxy.down);
    if (up === null || down === null) return false;
    if (parseBps(up) === 0 || parseBps(down) === 0) return false;
    // protocol：obfs-protocol 优先；faketcp 构建期隔离，其余未知值硬错误
    const proto = nonEmptyText(proxy["obfs-protocol"])
        ? proxy["obfs-protocol"]
        : (nonEmptyText(proxy.protocol) ? proxy.protocol : "udp");
    if (proto !== "udp" && proto !== "wechat-video") return false;
    // auth 非空时须为合法标准 base64（hysteria/mod.rs:auth）
    const auth = typeof proxy.auth === "string" ? proxy.auth : "";
    if (auth !== "" && base64Bytes(auth) < 0) return false;
    return true;
}

function isValidTuic(proxy) {
    if (!hasServerPort(proxy)) return false;
    const token = typeof proxy.token === "string" ? proxy.token : "";
    const uuid = typeof proxy.uuid === "string" ? proxy.uuid : "";
    const password = typeof proxy.password === "string" ? proxy.password : "";
    // token 或 (uuid+password) 必须齐备（配置期硬错误）
    if (token === "" && (uuid === "" || password === "")) return false;
    // 无 token 时走 V5 认证，uuid 必须可解析（构建期硬错误）
    if (token === "" && !isUuid(uuid)) return false;
    // udp-over-stream-version 仅 0/1/2（构建期硬错误）
    if (proxy["udp-over-stream-version"] !== undefined &&
        proxy["udp-over-stream-version"] !== null) {
        const n = toUint(proxy["udp-over-stream-version"]);
        if (n < 0) return false;
        const v = n <= 255 ? n : 0;
        if (v > 2) return false;
    }
    return true;
}

function isValidAnytls(proxy) {
    if (!hasServerPort(proxy)) return false;
    return typeof proxy.password === "string";
}

function isValidWireguard(proxy) {
    // private-key 必填且为 32 字节 base64（配置期必填 + 构建期解码）
    if (!nonEmptyText(proxy["private-key"])) return false;
    if (base64Bytes(proxy["private-key"]) !== 32) return false;
    const peers = Array.isArray(proxy.peers) ? proxy.peers : [];
    if (peers.length === 0) {
        // 无 peers 时 server 必填（配置期硬错误）
        if (!nonEmptyText(proxy.server)) return false;
        if ("port" in proxy && !parsePortValue(proxy.port)) return false;
        if (nonEmptyText(proxy["public-key"]) && base64Bytes(proxy["public-key"]) !== 32) return false;
    } else {
        for (let i = 0; i < peers.length; i++) {
            const peer = peers[i];
            if (!isPlainObject(peer)) return false;
            // peers 的 allowed-ips 必填（配置期硬错误）
            const allowed = peer["allowed-ips"];
            const list = Array.isArray(allowed) ? allowed
                : (nonEmptyText(allowed) ? [allowed] : []);
            if (list.length === 0) return false;
            if (nonEmptyText(peer["public-key"]) && base64Bytes(peer["public-key"]) !== 32) return false;
            if (nonEmptyText(peer["pre-shared-key"]) && base64Bytes(peer["pre-shared-key"]) !== 32) return false;
            if ("reserved" in peer && !validReserved(peer.reserved)) return false;
        }
    }
    if (nonEmptyText(proxy["pre-shared-key"]) && base64Bytes(proxy["pre-shared-key"]) !== 32) return false;
    if ("reserved" in proxy && !validReserved(proxy.reserved)) return false;
    // 本地地址 ip/ipv6 至少一个（构建期硬错误）
    if (!nonEmptyText(proxy.ip) && !nonEmptyText(proxy.ipv6)) return false;
    // ip-stack.mode 枚举（构建期硬错误，内核转小写）
    const stack = proxy["ip-stack"];
    if (isPlainObject(stack) && typeof stack.mode === "string" &&
        !WG_IP_STACK_MODES.has(stack.mode.toLowerCase())) {
        return false;
    }
    // amnezia-wg-option 清理（详见 AMNEZIA_DROP 注释）
    const am = proxy["amnezia-wg-option"];
    if (isPlainObject(am)) {
        const version = Number(am.version) || 0;
        if (version === 3) {
            // v3：header-protection-key 须为 32 字节 base64；jmin/jmax 范围校验
            if (nonEmptyText(am["header-protection-key"]) &&
                base64Bytes(am["header-protection-key"]) !== 32) return false;
            const jmin = Number(am.jmin) || 0;
            const jmax = Number(am.jmax) || 0;
            if (jmax >= 65535 || (jmin !== 0 && jmax !== 0 && jmax < jmin)) return false;
        }
        AMNEZIA_DROP.forEach(key => delete am[key]);
    }
    return true;
}

function validReserved(res) {
    // 字符串按标准 base64 解码（配置期），数组按字节数；构建期要求 0 或 3 字节
    if (typeof res === "string") {
        const n = base64Bytes(res);
        return n === 0 || n === 3;
    }
    if (Array.isArray(res)) return res.length === 0 || res.length === 3;
    return false;
}

function isValidSsr(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.password !== "string" || typeof proxy.cipher !== "string" ||
        typeof proxy.obfs !== "string" || typeof proxy.protocol !== "string") {
        return false;
    }
    // cipher（ssr/cipher.rs:pick，内核转大写匹配）：
    // chacha20/xchacha20 → 构建期隔离；AEAD → 硬错误；其余未知 → 硬错误
    const cipher = proxy.cipher.toLowerCase();
    if (cipher === "chacha20" || cipher === "xchacha20") return false;
    const upper = cipher.toUpperCase();
    if (upper.indexOf("GCM") !== -1 || upper.indexOf("POLY1305") !== -1 ||
        upper.indexOf("CCM") !== -1 || upper.indexOf("AEAD_") === 0) {
        return false;
    }
    if (!SSR_CIPHERS.has(cipher)) return false;
    // obfs/protocol 大小写敏感，未知值 → 构建期硬错误
    if (!SSR_OBFS.has(proxy.obfs)) return false;
    if (!SSR_PROTOCOLS.has(proxy.protocol)) return false;
    return true;
}

function isValidSnell(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.psk !== "string") return false;
    // version：0→1、5→4，映射后须 ∈ 1..4（snell/mod.rs:build）
    const raw = proxy.version;
    const v = raw === undefined || raw === null ? 0 : Number(raw);
    if (!Number.isInteger(v)) return false;
    const mapped = v === 0 ? 1 : (v === 5 ? 4 : v);
    if (mapped < 1 || mapped > 4) return false;
    // v1/v2 不支持 UDP（构建期硬错误）
    if ((mapped === 1 || mapped === 2) && toBool(proxy.udp)) return false;
    // obfs mode：restls/jls → 构建期隔离，其余未知值 → 硬错误
    const opts = isPlainObject(proxy["obfs-opts"]) ? proxy["obfs-opts"] : {};
    const mode = typeof opts.mode === "string" ? opts.mode : "";
    if (mode === "" || mode === "tls" || mode === "http") return true;
    if (mode === "shadow-tls") {
        if (!nonEmptyText(opts.host)) return false;
        if ("version" in opts && opts.version !== null) {
            const sv = Number(opts.version);
            if (!Number.isInteger(sv) || sv < 1 || sv > 3) return false;
        }
        return true;
    }
    return false;
}

function isValidMieru(proxy) {
    if (!nonEmptyText(proxy.server)) return false;
    const portVal = "port" in proxy && parsePortValue(proxy.port) ? Number(proxy.port) : 0;
    const pr = typeof proxy["port-range"] === "string" ? proxy["port-range"] : "";
    // port 与 port-range 恰好一个（配置期要求至少一个，构建期禁止同时设置）
    if (portVal === 0 && pr === "") return false;
    if (portVal !== 0 && pr !== "") return false;
    if (pr !== "") {
        const m = /^(\d+)-(\d+)$/.exec(pr);
        if (!m) return false;
        const lo = Number(m[1]), hi = Number(m[2]);
        if (lo < 1 || hi > 65535 || lo > hi) return false;
    }
    // transport 须精确 TCP/UDP（大小写敏感，已规范化）
    if (proxy.transport !== "TCP" && proxy.transport !== "UDP") return false;
    // 凭据非空且 ≤64 字节（mieru/mod.rs:construct）
    const user = typeof proxy.username === "string" ? proxy.username : "";
    const pass = typeof proxy.password === "string" ? proxy.password : "";
    if (user === "" || pass === "" || byteLength(user) > 64 || byteLength(pass) > 64) return false;
    const mux = typeof proxy.multiplexing === "string" ? proxy.multiplexing : "";
    if (!MIERU_MULTIPLEXING.has(mux)) return false;
    const hs = typeof proxy["handshake-mode"] === "string" ? proxy["handshake-mode"] : "";
    if (!MIERU_HANDSHAKE.has(hs)) return false;
    // traffic-pattern 非空时须为合法标准 base64（protobuf 内容无法在 JS 校验）
    const tp = typeof proxy["traffic-pattern"] === "string" ? proxy["traffic-pattern"] : "";
    if (tp !== "" && base64Bytes(tp) < 0) return false;
    return true;
}

function isValidSsh(proxy) {
    if (!hasServerPort(proxy)) return false;
    if (typeof proxy.username !== "string") return false;
    // host-key：OpenSSH 公钥格式；RSA 主机密钥 → 构建期隔离（ssh/mod.rs）
    const keys = Array.isArray(proxy["host-key"]) ? proxy["host-key"]
        : (nonEmptyText(proxy["host-key"]) ? [proxy["host-key"]] : []);
    for (let i = 0; i < keys.length; i++) {
        if (typeof keys[i] !== "string") return false;
        const parts = keys[i].trim().split(/\s+/);
        if (parts.length < 2 || parts[1] === "" || base64Bytes(parts[1]) < 0) return false;
        if (/rsa/i.test(parts[0])) return false;
    }
    // host-key-algorithms：RSA 族 → 构建期隔离
    const algos = Array.isArray(proxy["host-key-algorithms"]) ? proxy["host-key-algorithms"]
        : (nonEmptyText(proxy["host-key-algorithms"]) ? [proxy["host-key-algorithms"]] : []);
    for (let i = 0; i < algos.length; i++) {
        if (typeof algos[i] !== "string") return false;
        if (/rsa/i.test(algos[i])) return false;
    }
    return true;
}

function isValidShadowquic(proxy) {
    if (!hasServerPort(proxy)) return false;
    // quic-versions 每项规范化后须在白名单内；仅 v2（无 v1）→ 构建期隔离
    const versions = proxy["quic-versions"];
    const list = Array.isArray(versions) ? versions
        : (nonEmptyText(versions) ? [versions] : []);
    let hasV1 = false;
    for (let i = 0; i < list.length; i++) {
        if (typeof list[i] !== "string") return false;
        const norm = list[i].trim().toLowerCase().replace(/_/g, "-");
        if (!SHADOWQUIC_VERSIONS.has(norm)) return false;
        if (SHADOWQUIC_V1.has(norm)) hasV1 = true;
    }
    if (list.length > 0 && !hasV1) return false;
    return true;
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

// dialer-proxy 的目标必须存在，否则内核拒绝整份配置（profile.rs:validate_dialers）
function dropDanglingDialer(proxies, groupNames) {
    const known = new Set([
        ...proxies.map(proxy => proxy.name),
        ...groupNames,
        ...BUILTIN_POLICIES
    ]);
    proxies.forEach(proxy => {
        const target = proxy["dialer-proxy"];
        if (typeof target === "string" && target !== "" && !known.has(target)) {
            delete proxy["dialer-proxy"];
        }
    });
}

// dialer-proxy 成环（含自环）→ 内核整份拒绝；移除环上节点的 dialer-proxy 断环，保住节点
function breakDialerCycles(proxies) {
    const byName = new Map(proxies.map(proxy => [proxy.name, proxy]));
    const state = new Map(); // 1=当前路径上 2=已完成
    proxies.forEach(proxy => {
        if (state.get(proxy.name) === 2) return;
        const path = [];
        let cur = proxy.name;
        while (true) {
            if (state.get(cur) === 2) break;
            if (state.get(cur) === 1) {
                // 发现环：断开环上每个节点的 dialer-proxy
                const start = path.indexOf(cur);
                for (let i = start; i < path.length; i++) {
                    const node = byName.get(path[i]);
                    if (node) delete node["dialer-proxy"];
                }
                break;
            }
            state.set(cur, 1);
            path.push(cur);
            const node = byName.get(cur);
            const next = node ? node["dialer-proxy"] : undefined;
            if (typeof next !== "string" || next === "" || !byName.has(next)) break;
            cur = next;
        }
        path.forEach(name => {
            if (state.get(name) === 1) state.set(name, 2);
        });
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

// hosts 清洗：内核对该段的非法值（对象/null、含 lan、多值非全 IP、域名映射成环）
// 会直接拒绝整份配置（hosts.rs:parse_hosts），这里逐条过滤
function buildHosts(raw) {
    if (!isPlainObject(raw)) return null;
    const map = new Map();
    Object.keys(raw).forEach(domain => {
        if (!isHostDomain(domain)) return;
        const value = raw[domain];
        const values = Array.isArray(value) ? value : [value];
        // 空数组、含非标量（对象/数组嵌套）的值会让内核解析失败
        if (values.length === 0) return;
        if (values.some(item => !isScalar(item))) return;
        const texts = values.map(item => String(item));
        // 特殊值 lan 内核不支持；数组中出现也会令多值 IP 解析失败
        if (texts.some(item => item === "lan")) return;
        // 多值必须全为 IP（单值可以是 IP 或域名别名）
        if (texts.length > 1 && texts.some(item => !isIpAddr(item))) return;
        map.set(domain, Array.isArray(value) ? texts : value);
    });
    // 域名别名成环（含自映射）→ 内核整份拒绝；删除整个环，
    // 再级联删除指向已删条目的别名（悬空别名内核虽接受，但已失去原意）。
    // 指向 hosts 之外域名的别名是合法用法（如别名到真实域名），不删除
    const deleted = new Set();
    Array.from(map.keys()).forEach(domain => {
        if (deleted.has(domain)) return;
        const chain = [];
        let cur = domain;
        while (true) {
            if (deleted.has(cur)) break;
            const at = chain.indexOf(cur);
            if (at !== -1) {
                for (let i = at; i < chain.length; i++) deleted.add(chain[i]);
                break;
            }
            const value = map.get(cur);
            if (typeof value !== "string" || isIpAddr(value)) break;
            if (!map.has(value)) break;
            chain.push(cur);
            cur = value;
        }
    });
    let changed = true;
    while (changed) {
        changed = false;
        Array.from(map.keys()).forEach(domain => {
            if (deleted.has(domain)) return;
            const value = map.get(domain);
            if (typeof value === "string" && !isIpAddr(value) && deleted.has(value)) {
                deleted.add(domain);
                changed = true;
            }
        });
    }
    deleted.forEach(domain => map.delete(domain));
    if (map.size === 0) return null;
    const out = {};
    map.forEach((value, domain) => {
        out[domain] = value;
    });
    return out;
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

const isScalar = value =>
    typeof value === "string" || typeof value === "number" || typeof value === "boolean";

const nonEmptyText = value => typeof value === "string" && value !== "";

// 标量转文本（镜像内核 scalar_text）；不可转换返回 null
function textOf(value) {
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return null;
}

// 镜像内核 lenient.rs 的布尔解析
function toBool(value) {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") {
        const t = value.trim().toLowerCase();
        return t === "true" || t === "t" || t === "1" || t === "yes" || t === "y" || t === "on";
    }
    return false;
}

// 非负整数解析；不可解析返回 -1（内核此处会判类型错误）
function toUint(value) {
    if (typeof value === "number") {
        return Number.isInteger(value) && value >= 0 ? value : -1;
    }
    if (typeof value === "string") {
        const t = value.trim();
        if (!/^\d+$/.test(t)) return -1;
        return Number(t);
    }
    return -1;
}

// 端口值合法性（内核 req_u16：0-65535 整数或十进制字符串）
function parsePortValue(value) {
    if (typeof value === "number") {
        return Number.isInteger(value) && value >= 0 && value <= 65535;
    }
    if (typeof value === "string") {
        const t = value.trim();
        return /^\d+$/.test(t) && Number(t) <= 65535;
    }
    return false;
}

// base64 解码字节数；非法返回 -1。indifferent=true 时 padding 可省略
// （镜像 shadowsocks 2022 密码的 DecodePaddingMode::Indifferent）
function base64Bytes(s, indifferent) {
    if (typeof s !== "string") return -1;
    const t = s.trim();
    if (t === "") return 0;
    let body = t;
    let pad = 0;
    while (body.endsWith("=")) {
        pad++;
        body = body.slice(0, -1);
    }
    if (pad > 2 || !/^[A-Za-z0-9+/]*$/.test(body)) return -1;
    if (pad > 0) {
        if ((body.length + pad) % 4 !== 0) return -1;
        return ((body.length + pad) / 4) * 3 - pad;
    }
    const rem = body.length % 4;
    if (rem === 1) return -1;
    if (rem === 0) return (body.length / 4) * 3;
    if (!indifferent) return -1;
    return Math.floor((body.length * 6) / 8);
}

// REALITY public-key：URL-safe 无 padding base64，43 字符 → 32 字节
const isRealityKey = s => typeof s === "string" && /^[A-Za-z0-9_-]{43}$/.test(s);

const isHex = s => typeof s === "string" && /^[0-9a-fA-F]*$/.test(s);

// uuid::Uuid::parse_str 的三种接受形式
const isUuid = s => typeof s === "string" && (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s) ||
    /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i.test(s) ||
    /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)
);

// 带宽字符串解析（镜像 hysteria 的 util.rs:parse_bps）；非法或为零返回 0
function parseBps(text) {
    if (typeof text === "number") text = String(text);
    if (typeof text !== "string") return 0;
    text = text.trim();
    const m = /^(\d+)/.exec(text);
    if (!m) return 0;
    const value = Number(m[1]);
    let unit = text.slice(m[1].length).trim();
    if (unit === "") return Math.floor((value * 1000000) / 8);
    if (!unit.endsWith("ps")) return 0;
    unit = unit.slice(0, -2);
    let scale, bytes;
    if (unit === "B") { scale = 1; bytes = true; }
    else if (unit === "b") { scale = 1; bytes = false; }
    else if (unit.length === 2 && "KMGT".indexOf(unit[0]) !== -1 &&
        (unit[1] === "B" || unit[1] === "b")) {
        scale = { K: 1e3, M: 1e6, G: 1e9, T: 1e12 }[unit[0]];
        bytes = unit[1] === "B";
    } else {
        return 0;
    }
    const total = value * scale;
    return bytes ? total : Math.floor(total / 8);
}

// 端口列表解析（镜像 util.rs:parse_ports）：逗号/斜杠分隔，low-high 区间
function parsePortsList(text) {
    if (typeof text !== "string") return false;
    const parts = text.split(/[,/]/).map(s => s.trim()).filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
        const seg = parts[i].split("-");
        const ends = seg.length === 1 ? [seg[0], seg[0]]
            : (seg.length === 2 ? seg : null);
        if (!ends) return false;
        for (let j = 0; j < ends.length; j++) {
            const t = ends[j].trim();
            if (!/^\d+$/.test(t) || Number(t) > 65535) return false;
        }
    }
    return true;
}

// UTF-8 字节长度（用于 mieru 凭据 ≤64 字节校验）
function byteLength(s) {
    let n = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s.codePointAt(i);
        if (c > 0xFFFF) { n += 4; i++; }
        else if (c > 0x7FF) n += 3;
        else if (c > 0x7F) n += 2;
        else n += 1;
    }
    return n;
}

function isIpAddr(s) {
    if (typeof s !== "string") return false;
    const t = s.trim();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t)) {
        return t.split(".").every(o => Number(o) <= 255);
    }
    return isIpv6(t);
}

function isIpv6(s) {
    if (typeof s !== "string" || s.indexOf(":") === -1) return false;
    const halves = s.split("::");
    if (halves.length > 2) return false;
    const validGroup = g => /^[0-9a-fA-F]{1,4}$/.test(g);
    if (halves.length === 2) {
        const left = halves[0] === "" ? [] : halves[0].split(":");
        const right = halves[1] === "" ? [] : halves[1].split(":");
        return left.every(validGroup) && right.every(validGroup) &&
            left.length + right.length <= 7;
    }
    const groups = s.split(":");
    return groups.length === 8 && groups.every(validGroup);
}

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
