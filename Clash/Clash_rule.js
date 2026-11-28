// Clash_rule.js V5.7
// 需较新的 mihomo 内核；首次启动联网下载规则集，在日志确认全部下载成功。

// ── 可调参数（集中维护） ──
const DEFAULT_IP_VERSION = "dual"; // 双栈偏好：dual(并发择优) / ipv6-prefer / ipv4-prefer
const REGION_MIN_NODES = 2;        // 达到该值才建组
const RS_INTERVAL = 604800;        // 规则集更新周期：一周
const CN_DNS_DOH = [
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query"
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

function main(params, profileName) {
    if (!params || typeof params !== "object") params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    // 内核要求节点名非空且唯一，空名或 name 非字符串会让整份配置启动失败，直接丢弃
    params.proxies = params.proxies.filter(
        proxy =>
            proxy &&
            typeof proxy.name === "string" &&
            proxy.name !== ""
    );

    // proxy-providers 订阅的节点在内核运行时才拉取，预处理脚本无法读取节点列表来生成地区组与过滤规则；
    // 不支持该形态，直接拒绝生成
    if (Object.keys(params["proxy-providers"] || {}).length > 0) {
        throw new Error(
            "[Clash_rule.js] 检测到 proxy-providers 订阅，本脚本仅支持节点平铺的订阅形式，已拒绝生成配置。"
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
        // 全量规则均使用 .mrs rule-providers，关闭订阅可能残留的 Geo 数据库后台自动更新
        "geo-auto-update": false,
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
    // 订阅 sub-rules 引用原组/规则集，重建后必然悬空并导致内核拒载；脚本不生成 SUB-RULE，整段丢弃
    delete params["sub-rules"];

    params.sniffer = {
        enable: true,
        "force-dns-mapping": true,
        // 纯 IP 流量强制嗅探：应用绕过系统 DNS 直连 IP 时，从 TLS SNI / HTTP Host 还原域名参与分流，避免兜底误判
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: {
            HTTP: {
                ports: [80, "8080-8880"]
            },
            TLS: {
                ports: [443, 8443]
            },
            QUIC: {
                ports: [443, 8443]
            }
        },
        "skip-domain": [
            // 仅跳过官方建议的最小集合：米家设备非标准 SNI 与 Apple 推送长连，避免截断 Apple/AI 纯 IP 嗅探
            "Mijia Cloud",
            "+.push.apple.com"
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

    // 地区表。regex 与可选大小写敏感 codeRegex 仅在 JS 侧经 toJsRegex 转换使用
    const regions = [
        {
            name: "AE",
            regex: "(?i)(阿联酋|阿聯酋|迪拜|杜拜|阿布扎比|阿布達比|🇦🇪|(^|[^A-Za-z0-9])UAE([^A-Za-z]|$)|Emirates|Dubai|Abu[ -]?Dhabi)",
            icon: flagIcon("ae")
        },
        {
            name: "AR",
            regex: "(?i)(阿根廷|布宜诺斯艾利斯|布宜諾斯艾利斯|🇦🇷|(^|[^A-Za-z0-9])ARG?([^A-Za-z]|$)|Argentina|Buenos[ -]?Aires)",
            icon: flagIcon("ar")
        },
        {
            name: "AU",
            regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|雪梨|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z0-9])AUS?([^A-Za-z]|$)|Australia|Sydney|Melbourne|Brisbane|Perth|Adelaide)",
            icon: flagIcon("au")
        },
        {
            name: "BD",
            regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z0-9])(BD|BGD)([^A-Za-z]|$)|Bangladesh|Dhaka)",
            icon: flagIcon("bd")
        },
        {
            name: "BR",
            regex: "(?i)(巴西|圣保罗|聖保羅|里约|里約|🇧🇷|(^|[^A-Za-z0-9])BRA?([^A-Za-z]|$)|Brazil|Brasil|(Sao|São)[ -]?Paulo|Rio[ -]?de[ -]?Janeiro|(^|[^A-Za-z0-9])Rio([^A-Za-z]|$))",
            icon: flagIcon("br")
        },
        {
            name: "CA",
            regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|蒙特利尔|蒙特利爾|🇨🇦|(^|[^A-Za-z0-9])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver|Montreal|Calgary)",
            codeRegex: "^(?!.*(?:美国|美國|美西|美东|美東|🇺🇸|(^|[^A-Za-z0-9])(?:US|USA|us|usa)([^A-Za-z]|$)|United[ -]?States|California|CALIFORNIA|Los[ -]?Angeles|San[ -]?Jose|Silicon[ -]?Valley|Fremont|San[ -]?Francisco|LAX|SJC)).*(^|[^A-Za-z0-9])CA([^A-Za-z]|$)",
            icon: flagIcon("ca")
        },
        {
            name: "DE",
            regex: "(?i)(德国|德國|法兰克福|法蘭克福|柏林|慕尼黑|🇩🇪|(^|[^A-Za-z0-9])DEU([^A-Za-z]|$)|Germany|Frankfurt|Berlin|Munich|Düsseldorf|Dusseldorf|Nuremberg)",
            codeRegex: "^(?!.*RIO[ -]?DE[ -]?JANEIRO).*(^|[^A-Za-z0-9])DE([^A-Za-z]|$)",
            icon: flagIcon("de")
        },
        {
            name: "FR",
            regex: "(?i)(法国|法國|巴黎|马赛|馬賽|里昂|🇫🇷|(^|[^A-Za-z0-9])FRA?([^A-Za-z]|$)|France|Paris|Marseille|Lyon)",
            icon: flagIcon("fr")
        },
        {
            name: "GB",
            regex: "(?i)(英国|英國|伦敦|倫敦|曼彻斯特|曼徹斯特|🇬🇧|(^|[^A-Za-z0-9])(UK|GB|GBR)([^A-Za-z]|$)|United[ -]?Kingdom|England|London|Manchester|Edinburgh)",
            icon: flagIcon("gb")
        },
        {
            name: "HK",
            regex: "(?i)(香港|九龙|九龍|🇭🇰|(^|[^A-Za-z0-9])HKG?([^A-Za-z]|$)|Hong[ -]?Kong|Kowloon|Tsuen[ -]?Wan)",
            icon: flagIcon("hk")
        },
        {
            name: "ID",
            regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|Surabaya|(^|[^A-Za-z0-9])IDN([^A-Za-z]|$))",
            codeRegex: "^(?!.*(?:Node|NODE|node|Server|SERVER|server|Relay|RELAY|relay|Proxy|PROXY|proxy|User|USER|user|Client|CLIENT|client|Line|LINE|line|Group|GROUP|group|Device|DEVICE|device|Account|ACCOUNT|account|Host|HOST|host)[ _-]+ID([^A-Za-z]|$)).*(^|[^A-Za-z0-9])ID([^A-Za-z:=：]|$)",
            icon: flagIcon("id")
        },
        {
            name: "IN",
            regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z0-9])India([^A-Za-z]|$)|Mumbai|(New[ -]?)?Delhi|Bangalore|Chennai|Hyderabad|(^|[^A-Za-z0-9])IND([^A-Za-z]|$))",
            codeRegex: "^(?!.*(?:RELAY|DIRECT|MADE|SERVER|NODE|PROXY|FAST)[ _-]+IN([^A-Za-z]|$)).*(^|[^A-Za-z0-9])IN([^A-Za-z]|$)",
            icon: flagIcon("in")
        },
        {
            name: "JP",
            regex: "(?i)(日本|东京|東京|大阪|名古屋|福冈|福岡|札幌|京都|🇯🇵|(^|[^A-Za-z0-9])JPN?([^A-Za-z]|$)|Japan|Tokyo|Osaka|Narita|Haneda|Kyoto|Fukuoka|Nagoya|Sapporo)",
            icon: flagIcon("jp")
        },
        {
            name: "KR",
            regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|釜山|仁川|🇰🇷|(^|[^A-Za-z0-9])(KR|KOR)([^A-Za-z]|$)|Korea|Seoul|Busan|Incheon|Chuncheon)",
            icon: flagIcon("kr")
        },
        {
            name: "MY",
            regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z0-9])MYS([^A-Za-z]|$)|Malaysia|Kuala[ -]?Lumpur|Johor[ -]?Bahru|Cyberjaya)",
            codeRegex: "(^|[^A-Za-z0-9])MY([^A-Za-z]|$)",
            icon: flagIcon("my")
        },
        {
            name: "NL",
            regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|鹿特丹|🇳🇱|(^|[^A-Za-z0-9])(NL|NLD)([^A-Za-z]|$)|Netherlands|Amsterdam|Rotterdam)",
            icon: flagIcon("nl")
        },
        {
            name: "PH",
            regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z0-9])PHL?([^A-Za-z]|$)|Philippines|Manila|Cebu)",
            icon: flagIcon("ph")
        },
        {
            name: "SG",
            regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z0-9])SGP?([^A-Za-z]|$)|Singapore)",
            icon: flagIcon("sg")
        },
        {
            name: "TH",
            regex: "(?i)(泰国|泰國|曼谷|清迈|清邁|🇹🇭|Thailand|Bangkok|Pattaya|Chiang[ -]?Mai|(^|[^A-Za-z0-9])THA([^A-Za-z]|$))",
            codeRegex: "(^|[^A-Za-z0-9])TH([^A-Za-z]|$)",
            icon: flagIcon("th")
        },
        {
            name: "TR",
            regex: "(?i)(土耳其|伊斯坦布尔|伊斯坦布爾|安卡拉|🇹🇷|(^|[^A-Za-z0-9])TUR([^A-Za-z]|$)|Turkey|Türkiye|Turkiye|Istanbul|Ankara)",
            codeRegex: "^(?!.*(?:香港|九龙|九龍|日本|东京|東京|大阪|新加坡|狮城|獅城|台湾|台灣|臺灣|台北|臺北|美国|美國|美西|美东|美東|英国|英國|德国|德國|法国|法國|荷兰|荷蘭|加拿大|澳洲|澳大利亚|澳大利亞|韩国|韓國|越南|泰国|泰國|马来西亚|馬來西亞|菲律宾|菲律賓|印尼|印度|巴西|阿根廷|阿联酋|阿聯酋|迪拜|杜拜|孟加拉|🇭🇰|🇯🇵|🇸🇬|🇹🇼|🇺🇸|🇬🇧|🇩🇪|🇫🇷|🇳🇱|🇨🇦|🇦🇺|🇰🇷|🇻🇳|🇹🇭|🇲🇾|🇵🇭|🇮🇩|🇮🇳|🇧🇷|🇦🇷|🇦🇪|🇧🇩|Hong[ -]?Kong|Singapore|Japan|Tokyo|Taiwan|Taipei|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|Germany|Frankfurt|United[ -]?Kingdom|London|(^|[^A-Za-z0-9])(?:HK|HKG|JP|JPN|SG|SGP|TW|TWN|US|USA|UK|GB|GBR|DE|DEU|FR|FRA|NL|NLD|CA|CAN|AU|AUS|KR|KOR|VN|VNM|TH|THA|MY|MYS|PH|PHL|ID|IDN|IN|IND|BR|BRA|AR|ARG|AE|UAE|BD|BGD|hk|jp|sg|tw|us|uk|gb|de|fr|nl|ca|au|kr|vn|th|my|ph|id|in|br|ar|ae|bd)([^A-Za-z]|$))).*(^|[^A-Za-z0-9])TR([^A-Za-z]|$)",
            icon: flagIcon("tr")
        },
        {
            name: "TW",
            regex: "(?i)(台湾|台灣|臺灣|台北|臺北|新北|台中|臺中|高雄|新竹|🇹🇼|(^|[^A-Za-z0-9])TWN?([^A-Za-z]|$)|Taiwan|Taipei|Kaohsiung|Taichung|Hsinchu)",
            icon: flagIcon("tw")
        },
        {
            name: "US",
            regex: "(?i)(美国|美國|美西|美东|美東|达拉斯|達拉斯|芝加哥|拉斯维加斯|拉斯維加斯|洛杉矶|洛杉磯|圣何塞|聖何塞|旧金山|舊金山|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z0-9])USA?([^A-Za-z]|$)|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|San[ -]?Francisco|Silicon[ -]?Valley|New[ -]?York|Seattle|Dallas|Chicago|Fremont|Phoenix|Denver|Atlanta|Miami)",
            icon: flagIcon("us")
        },
        {
            name: "VN",
            regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z0-9])(VN|VNM)([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)",
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
    const proxyRenames = new Map();

    params.proxies.forEach(proxy => {
        let name = proxy.name;
        const originalName = name;

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

        if (name !== originalName && !proxyRenames.has(originalName)) {
            proxyRenames.set(originalName, name);
        }

        usedProxyNames.add(name);
    });

    // 旧名仍被最终节点占用时不改写引用：此时旧名指向原节点而非被改名的副本
    const finalProxyNames = new Set(params.proxies.map(proxy => proxy.name));

    [...proxyRenames.keys()].forEach(oldName => {
        if (finalProxyNames.has(oldName)) proxyRenames.delete(oldName);
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

    // 内核用 Go 正则，JS 侧按是否有 (?i) 前缀决定是否开启大小写不敏感
    const toJsRegex = goStyleRegex => {
        const ci = goStyleRegex.startsWith("(?i)");
        return new RegExp(
            ci ? goStyleRegex.slice(4) : goStyleRegex,
            ci ? "i" : ""
        );
    };

    const allProxies = params.proxies.filter(
        proxy =>
            proxy.type !== "direct" &&
            proxy.type !== "reject" &&
            proxy.type !== "dns"
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
        const codeRe = region.codeRegex ? toJsRegex(region.codeRegex) : null;
        const matched = usableProxies
            .filter(
                proxy =>
                    regex.test(proxy.name) ||
                    (codeRe && codeRe.test(proxy.name))
            )
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

    const hasOwn = (object, key) =>
        Object.prototype.hasOwnProperty.call(object, key);

    // 取自实际会建组的 activeRegions，避免引用到节点不足未建组的地区（内核找不到目标组）
    const REGION_NAMES = new Set(activeRegionNames);

    // 包含自定义 type: direct 节点（DNS 可经直连出站指定网卡/参数），排除 reject / dns
    const PROXY_NAMES = new Set(
        params.proxies
            .filter(
                proxy =>
                    proxy &&
                    proxy.type !== "reject" &&
                    proxy.type !== "dns" &&
                    proxy.name
            )
            .map(proxy => proxy.name)
    );

    // 校验 DNS 条目尾部 "#目标"：合法整条保留，指向已删除对象则剥掉并补 #RULES
    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    // Mihomo DNS URL 尾部 # 后支持的无等号布尔参数（保留原样，不按代理目标校验）
    const DNS_BARE_FLAGS = new Set([
        "h3",
        "ecs-override",
        "skip-cert-verify",
        "disable-ipv4",
        "disable-ipv6",
        "name-cert-verify",
        "respect-rules"
    ]);
    const isDnsBareFlag = part => {
        const lower = part.toLowerCase();
        return DNS_BARE_FLAGS.has(lower) || /^disable-qtype-\d+$/.test(lower);
    };

    const safeDecode = value => {
        try {
            return decodeURIComponent(value);
        } catch {
            return value;
        }
    };

    const subInterfaceName =
        typeof params["interface-name"] === "string"
            ? params["interface-name"].trim()
            : "";

    // 常见网卡名模式（Linux / macOS / BSD / Android / OpenWrt），避免误把网卡绑定当成悬空策略组改写为 #RULES
    const INTERFACE_NAME_RE =
        /^(?:eth|en|em|igb|ix|re|vtnet|wlan|wifi|utun|tun|tap|wg|ppp|br|bond|vlan|docker|virbr|veth|rmnet_data|ccmni|pdp_ip|tailscale|lo)\d+(?:\.\d+)?$|^(?:en|wl)[opsx][a-z0-9]+(?:\.\d+)?$|^(?:br|pppoe)-[a-z0-9_-]+$|^zt[a-z0-9]+$|^lo$/i;

    const isInterfaceBinding = ref =>
        (subInterfaceName !== "" && ref === subInterfaceName) ||
        INTERFACE_NAME_RE.test(ref);

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

    const isCatchAllDomain = pattern =>
        pattern === "*" ||
        pattern === "+" ||
        pattern === "+." ||
        pattern === ".";

    // 拆分逗号分隔的 nameserver-policy / proxy-server-nameserver-policy 键，
    // 区分 domain、rule-set 与 geo（geosite/geoip），兼容 "rule-set:a,b" / "geosite:cn,private" 续接写法
    const parsePolicyKey = key => {
        const parts = String(key)
            .split(",")
            .map(part => part.trim())
            .filter(Boolean);
        const out = [];
        let activePrefix = null; // "rule-set" | "geo" | null

        for (const part of parts) {
            const rsMatch = /^rule-set:(.*)$/i.exec(part);
            if (rsMatch) {
                activePrefix = "rule-set";
                const name = rsMatch[1].trim();
                if (name) out.push({ kind: "rule-set", value: name });
                continue;
            }

            if (/^(geosite|geoip):/i.test(part)) {
                activePrefix = "geo";
                out.push({ kind: "geo", value: part });
                continue;
            }

            if (
                activePrefix === "rule-set" &&
                hasOwn(subRuleProviders, part)
            ) {
                out.push({ kind: "rule-set", value: part });
                continue;
            }

            // 裸标识符紧跟在 rule-set:/geosite:/geoip: 后视为同类续接；
            // 含域名特征字符（. / * / + / :）时结束续接，按独立域名模式处理（如 "rule-set:a,+.node.com"）
            if (activePrefix && !/[.*+:]/.test(part)) {
                out.push({ kind: activePrefix, value: part });
                continue;
            }

            activePrefix = null;
            out.push({ kind: "domain", value: part });
        }

        return out;
    };

    // 提取逗号多值键中的全部 rule-set 名称（支持 "rule-set:a,b"、"rule-set:a,+.node.com"、"+.node.com,rule-set:a"）
    const ruleSetNames = key =>
        parsePolicyKey(key)
            .filter(seg => seg.kind === "rule-set")
            .map(seg => seg.value);

    // 将传统 blacklist 模式的 fake-ip-filter 域名模式转为 rule 模式条目数组；
    // Mihomo DOMAIN-WILDCARD 仅支持 * / ?（+ 与前导 . 会按字面匹配），须展开为合法通配规则
    const toRealIpRules = pattern => {
        const s = String(pattern).trim();
        if (!s || s.includes(",") || isCatchAllDomain(s)) return [];
        if (/^(rule-set|geosite|geoip):/i.test(s)) return [];

        if (s.startsWith("+.")) {
            const rest = s.slice(2);
            if (
                !rest ||
                rest.startsWith(".") ||
                rest.includes("+") ||
                isCatchAllDomain(rest)
            ) {
                return [];
            }
            if (/[*?]/.test(rest)) {
                return [
                    "DOMAIN-WILDCARD," + rest + ",real-ip",
                    "DOMAIN-WILDCARD,*." + rest + ",real-ip"
                ];
            }
            return ["DOMAIN-SUFFIX," + rest + ",real-ip"];
        }

        if (s.includes("+")) return [];

        if (s.startsWith(".")) {
            const rest = s.slice(1);
            if (!rest || rest.startsWith(".") || isCatchAllDomain(rest)) {
                return [];
            }
            return ["DOMAIN-WILDCARD,*." + rest + ",real-ip"];
        }

        if (/[*?]/.test(s)) {
            return ["DOMAIN-WILDCARD," + s + ",real-ip"];
        }

        return ["DOMAIN," + s + ",real-ip"];
    };

    // 清洗订阅已有的 rule 模式 fake-ip-filter 条目：过滤 MATCH / rule-set / geosite / geoip 与通吃通配
    const sanitizeFakeIpRule = rule => {
        const s = String(rule).trim();
        if (!s) return null;

        const lastComma = s.lastIndexOf(",");
        if (lastComma === -1) return null;

        const action = s.slice(lastComma + 1).trim().toLowerCase();
        if (action !== "fake-ip" && action !== "real-ip") return null;

        const head = s.slice(0, lastComma).trim();
        if (!head || /^MATCH$/i.test(head)) return null;

        const firstComma = head.indexOf(",");
        if (firstComma === -1) return null;

        const ruleType = head.slice(0, firstComma).trim().toUpperCase();
        const payload = head.slice(firstComma + 1).trim();
        if (!payload) return null;

        if (
            ruleType === "RULE-SET" ||
            ruleType === "GEOSITE" ||
            ruleType === "GEOIP" ||
            /(^|[,(])\s*(rule-set|geosite|geoip)\s*,/i.test(head)
        ) {
            return null;
        }

        if (
            (ruleType === "DOMAIN" ||
                ruleType === "DOMAIN-SUFFIX" ||
                ruleType === "DOMAIN-WILDCARD") &&
            isCatchAllDomain(payload)
        ) {
            return null;
        }

        if (
            ruleType === "DOMAIN-WILDCARD" &&
            (payload.includes("+") || payload.startsWith("."))
        ) {
            return null;
        }

        return head + "," + action;
    };

    const mergePolicyEntry = (target, key, servers) => {
        if (!key || servers.length === 0) return;

        if (hasOwn(target, key)) {
            target[key] = [...new Set([...target[key], ...servers])];
        } else {
            target[key] = [...new Set(servers)];
        }
    };

    // 特殊内建 DNS 协议不走代理路由，无需补 #RULES
    const isSpecialDnsScheme = s =>
        /^(system|rcode|dhcp):\/\//i.test(s) ||
        s.toLowerCase() === "system";

    // # 后按 "&" 分段：含 "=" 的参数、合法布尔开关（h3 / disable-ipv6 / respect-rules / disable-qtype-* 等）与网卡绑定原样保留；
    // 代理/策略组名经百分号解码并结合 proxyRenames 校验，全部失效或原订阅 respect-rules 且无路由目标时补 #RULES
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

        const paramParts = [];
        const flagParts = [];
        const targetParts = [];
        let hasRespectRulesFlag = false;

        for (const part of rawParts) {
            if (part.includes("=")) {
                paramParts.push(part);
            } else if (isDnsBareFlag(part)) {
                flagParts.push(part);
                if (part.toLowerCase() === "respect-rules") {
                    hasRespectRulesFlag = true;
                }
            } else {
                targetParts.push(part);
            }
        }

        const validTargets = [];

        for (const part of targetParts) {
            const decoded = safeDecode(part);

            if (refValid(decoded) || isInterfaceBinding(decoded)) {
                validTargets.push(part);
                continue;
            }

            const renamed = proxyRenames.get(decoded);
            if (renamed !== undefined && refValid(renamed)) {
                const encoded =
                    part !== decoded || /[\s#&%]/.test(renamed)
                        ? encodeURIComponent(renamed)
                        : renamed;
                validTargets.push(encoded);
            }
        }

        const needRulesFallback =
            !isSpecialDnsScheme(base) &&
            !hasRespectRulesFlag &&
            ((targetParts.length > 0 && validTargets.length === 0) ||
                (targetParts.length === 0 && respectRules));

        const finalTargets = needRulesFallback ? ["RULES"] : validTargets;
        const finalParts = [...finalTargets, ...flagParts, ...paramParts];

        return finalParts.length > 0
            ? base + "#" + finalParts.join("&")
            : base;
    };

    // 节点解析 DNS 不得经代理/策略组或 respect-rules 出站，否则形成"需要节点才能解析节点"的循环；
    // 合法传输参数、非路由布尔开关与网卡绑定予以保留
    const stripProxyRefs = entry => {
        const s = String(entry).trim();
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const kept = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(
                part =>
                    part !== "" &&
                    (part.includes("=") ||
                        (isDnsBareFlag(part) &&
                            part.toLowerCase() !== "respect-rules") ||
                        isInterfaceBinding(safeDecode(part)))
            );

        return kept.length > 0
            ? s.slice(0, hash) + "#" + kept.join("&")
            : s.slice(0, hash);
    };

    const stripProxyRefsPolicy = policy => {
        const out = {};

        for (const key of Object.keys(policy)) {
            const servers = stringList(policy[key]).map(stripProxyRefs);
            if (servers.length > 0) {
                out[key] = [...new Set(servers)];
            }
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

        const rawPolicy = asPlainObject(subDNS["nameserver-policy"]);
        const subPolicy = {};

        // 统一输出 fake-ip-filter-mode: rule；
        // 订阅为缺省/blacklist 时逐项转换为 rule 条目，已为 rule 时清洗并保留合法条目，whitelist 语义相反直接跳过
        const modeRaw = subDNS["fake-ip-filter-mode"];
        const mode =
            typeof modeRaw === "string"
                ? modeRaw.trim().toLowerCase()
                : "";

        const subFilter =
            mode === "" || mode === "blacklist"
                ? stringList(subDNS["fake-ip-filter"]).flatMap(
                      toRealIpRules
                  )
                : mode === "rule"
                  ? stringList(subDNS["fake-ip-filter"])
                        .map(sanitizeFakeIpRule)
                        .filter(Boolean)
                  : [];

        // 逐键按逗号分段清洗：丢弃通吃段、rule-set:/geosite:/geoip: 段及空服务器列表；值同步清洗悬空引用
        for (const key of Object.keys(rawPolicy)) {
            const servers = stringList(rawPolicy[key]).map(cleanWithRules);
            if (servers.length === 0) continue;

            const safeDomains = parsePolicyKey(key)
                .filter(
                    seg =>
                        seg.kind === "domain" &&
                        !isCatchAllDomain(seg.value)
                )
                .map(seg => seg.value);

            if (safeDomains.length === 0) continue;

            mergePolicyEntry(subPolicy, safeDomains.join(","), servers);
        }

        // ── 清洗 proxy-server-nameserver-policy ──
        // 键：按逗号分段解析；geosite:/geoip: 丢弃；rule-set: 仅在订阅原始 rule-providers 有定义时保留并搬运；
        // 混合键拆分输出（域名段与 rule-set: 段独立），避免内核将逗号后的域名误解析为规则集名；空服务器列表直接丢弃
        const rawPSNPolicy = asPlainObject(
            subDNS["proxy-server-nameserver-policy"]
        );

        const subPSNPolicy = {};
        const carriedRuleProviders = {};

        for (const key of Object.keys(rawPSNPolicy)) {
            const servers = stringList(rawPSNPolicy[key]).map(stripProxyRefs);
            if (servers.length === 0) continue;

            const segments = parsePolicyKey(key);
            const domainSegs = [];
            const validRSNames = [];

            for (const seg of segments) {
                if (seg.kind === "geo") continue;

                if (seg.kind === "rule-set") {
                    if (hasOwn(subRuleProviders, seg.value)) {
                        carriedRuleProviders[seg.value] =
                            subRuleProviders[seg.value];
                        if (validRSNames.indexOf(seg.value) === -1) {
                            validRSNames.push(seg.value);
                        }
                    }
                    continue;
                }

                domainSegs.push(seg.value);
            }

            if (domainSegs.length > 0) {
                mergePolicyEntry(subPSNPolicy, domainSegs.join(","), servers);
            }

            if (validRSNames.length > 0) {
                mergePolicyEntry(
                    subPSNPolicy,
                    "rule-set:" + validRSNames.join(","),
                    servers
                );
            }
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
            "[Clash_rule.js] 读取订阅 DNS 时出错（" +
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
        // IPv6 fake-ip 段（仅 DNS 启用 IPv6 时输出）：沿用官方文档与多数客户端 TUN 兼容的 ULA 默认段（属 fc00::/7 内固定高熵前缀，避免与常见局域网 ULA 冲突）
        ...(dnsIPv6
            ? { "fake-ip-range6": "fdfe:dcba:9876::/64" }
            : {}),
        "cache-algorithm": "arc",
        "fake-ip-filter-mode": "rule",
        "use-hosts":
            typeof subDNS["use-hosts"] === "boolean"
                ? subDNS["use-hosts"]
                : true,
        "use-system-hosts":
            typeof subDNS["use-system-hosts"] === "boolean"
                ? subDNS["use-system-hosts"]
                : true,
        // rule 模式按从上到下顺序决策：
        // 1) 窄范围 real-ip 刚需（局域网、NCSI、NTP、游戏平台、STUN），置顶避免 time.apple.com / time.windows.com / msftconnecttest.com 等被下方大规则集遮蔽
        // 2) Apple / Google / Microsoft / AI 强制 fake-ip（早于 cn-domain，避免其 @cn 国内 CDN 域名拿到真实 IP 绕过策略组分流）
        // 3) 继承并清洗后的订阅条目 + private-domain / cn-domain / fakeip-filter 兜底 real-ip + MATCH,fake-ip
        "fake-ip-filter": [
            ...new Set([
                "DOMAIN-SUFFIX,lan,real-ip",
                "DOMAIN-SUFFIX,local,real-ip",
                "DOMAIN-SUFFIX,home.arpa,real-ip",
                "DOMAIN,localhost.ptlogin2.qq.com,real-ip",
                "DOMAIN,localhost.sec.qq.com,real-ip",
                "DOMAIN,localhost.work.weixin.qq.com,real-ip",
                "DOMAIN-SUFFIX,msftconnecttest.com,real-ip",
                "DOMAIN-SUFFIX,msftncsi.com,real-ip",
                "DOMAIN-SUFFIX,ntp.org,real-ip",
                "DOMAIN-SUFFIX,xboxlive.com,real-ip",
                "DOMAIN-SUFFIX,playstation.net,real-ip",
                "DOMAIN-SUFFIX,xbox.com,real-ip",
                "DOMAIN,xbox.ipv6.microsoft.com,real-ip",
                "DOMAIN-SUFFIX,srv.nintendo.net,real-ip",
                "DOMAIN,time.windows.com,real-ip",
                "DOMAIN,time.apple.com,real-ip",
                "DOMAIN,time.asia.apple.com,real-ip",
                "DOMAIN,time.android.com,real-ip",
                "DOMAIN,time.nist.gov,real-ip",
                "DOMAIN,ntp.aliyun.com,real-ip",
                "DOMAIN,ntp.tencent.com,real-ip",
                "DOMAIN,ntp.ntsc.ac.cn,real-ip",
                "DOMAIN-WILDCARD,stun.*,real-ip",
                "DOMAIN-WILDCARD,*.stun.*,real-ip",
                "RULE-SET,apple-domain,fake-ip",
                "RULE-SET,google-domain,fake-ip",
                "RULE-SET,microsoft-domain,fake-ip",
                "RULE-SET,ai-domain,fake-ip",
                ...subFilter,
                "RULE-SET,private-domain,real-ip",
                "RULE-SET,cn-domain,real-ip",
                "RULE-SET,fakeip-filter,real-ip",
                "MATCH,fake-ip"
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

    // mihomo 的 hosts 位于顶层而非 dns 下；若订阅误放在 dns.hosts，迁回顶层（顶层已有同名键优先）
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

    // 广告拦截：AWAvenue 秋风广告规则（低误杀、兼顾国内与国际应用广告 SDK）
    params["rule-providers"]["ads-domain"] = {
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: "https://cdn.jsdmirror.com/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.mrs",
        path: "./ruleset/ads-domain.mrs",
        interval: RS_INTERVAL
    };

    // 社区维护的 fake-ip 豁免清单（wwqgtxx/clash-rules，官方未收录），供 dns.fake-ip-filter 引用
    params["rule-providers"]["fakeip-filter"] = {
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: "https://cdn.jsdmirror.com/gh/wwqgtxx/clash-rules@release/fakeip-filter.mrs",
        path: "./ruleset/fakeip-filter.mrs",
        interval: RS_INTERVAL
    };

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
                mergePolicyEntry(newPolicy, key, oldPolicy[key]);
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

            mergePolicyEntry(
                newPolicy,
                "rule-set:" + rewrittenNames.join(","),
                oldPolicy[key]
            );
        });

        if (Object.keys(newPolicy).length > 0) {
            params.dns["proxy-server-nameserver-policy"] = newPolicy;
        } else {
            delete params.dns["proxy-server-nameserver-policy"];
        }
    }

    // 仅这四类协议顶层按 TLS 补全默认指纹，hysteria2 / tuic 内核未提供该字段；
    // snell（shadow-tls/restls/jls）与 xhttp download-settings 同步规范化废弃指纹并按需补全
    const FP_OK = ["vless", "vmess", "trojan", "anytls"];
    const NO_IP_VERSION_TYPES = new Set(["direct", "reject", "dns"]);
    const SNELL_TLS_OBFS = new Set(["shadow-tls", "restls", "jls"]);

    const hasRealityKey = opts =>
        isPlainObject(opts) &&
        typeof opts["public-key"] === "string" &&
        opts["public-key"].trim() !== "";

    const normalizeFingerprint = target => {
        if (!isPlainObject(target)) return;
        const fp = target["client-fingerprint"];
        if (typeof fp !== "string") return;
        if (/^chrome_/i.test(fp)) target["client-fingerprint"] = "chrome";
        else if (fp.toLowerCase() === "randomized") {
            target["client-fingerprint"] = "random";
        }
    };

    params.proxies.forEach(proxy => {
        // 不覆盖订阅已有的取值
        if (
            !NO_IP_VERSION_TYPES.has(proxy.type) &&
            !("ip-version" in proxy)
        ) {
            proxy["ip-version"] = DEFAULT_IP_VERSION;
        }

        normalizeFingerprint(proxy);

        if (
            FP_OK.indexOf(proxy.type) !== -1 &&
            !proxy["client-fingerprint"]
        ) {
            const usesTLS =
                proxy.type === "trojan" ||
                proxy.type === "anytls" ||
                proxy.tls === true ||
                hasRealityKey(proxy["reality-opts"]);

            if (usesTLS) {
                proxy["client-fingerprint"] = "chrome";
            }
        }

        if (proxy.type === "snell" && !proxy["client-fingerprint"]) {
            const obfsMode = isPlainObject(proxy["obfs-opts"])
                ? String(proxy["obfs-opts"].mode || "").toLowerCase()
                : "";
            if (SNELL_TLS_OBFS.has(obfsMode)) {
                proxy["client-fingerprint"] = "chrome";
            }
        }

        if (
            (proxy.type === "vless" ||
                proxy.type === "vmess" ||
                proxy.type === "trojan") &&
            isPlainObject(proxy["xhttp-opts"]) &&
            isPlainObject(proxy["xhttp-opts"]["download-settings"])
        ) {
            const ds = proxy["xhttp-opts"]["download-settings"];
            normalizeFingerprint(ds);
            if (!ds["client-fingerprint"] && !proxy["client-fingerprint"]) {
                const dsUsesTLS =
                    ds.tls === true || hasRealityKey(ds["reality-opts"]);
                if (dsUsesTLS) {
                    ds["client-fingerprint"] = "chrome";
                }
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
            "[Clash_rule.js] 订阅节点全部被 excludeFilter 过滤，「静态」组已填充 REJECT 占位，需代理的流量将被拒绝，直连规则不受影响；请检查 excludeFilter 或节点命名。"
        );
    }

    // dialer-proxy 在连接时按名字查找前置代理：旧名已不再命中任何目标时，
    // 若它对应一个被改名的节点则改到新名字；悬空引用删除，节点之间的环断开；
    // 组与内建策略只作为端点，不参与环检测
    const fixDialerProxies = (proxies, groupList) => {
        const known = new Set([
            ...proxies.map(proxy => proxy.name),
            ...groupList.map(group => group.name),
            ...BUILTIN_POLICIES
        ]);

        proxies.forEach(proxy => {
            const target = proxy["dialer-proxy"];

            if (typeof target !== "string" || target === "") return;

            const renamed = proxyRenames.get(target);

            if (!known.has(target) && renamed !== undefined) {
                proxy["dialer-proxy"] = renamed;
            }

            if (!known.has(proxy["dialer-proxy"])) {
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

    // listeners / tunnels 引用校验：指向不存在节点/组或已删除 sub-rules 会导致内核拒载；
    // 同步改名映射，清除悬空 proxy 与 rule 引用，让连接回退到主规则集
    const fixInbounds = () => {
        const known = new Set([
            ...params.proxies.map(proxy => proxy.name),
            ...groups.map(group => group.name),
            ...[...BUILTIN_POLICIES].filter(name => name !== "RULES")
        ]);

        const resolveProxy = name => {
            if (typeof name !== "string") return null;
            const trimmed = name.trim();
            if (trimmed === "") return null;
            const resolved = proxyRenames.get(trimmed) || trimmed;
            return known.has(resolved) ? resolved : null;
        };

        if (Array.isArray(params.listeners)) {
            params.listeners.forEach(listener => {
                if (!isPlainObject(listener)) return;
                Object.keys(listener).forEach(key => {
                    const lower = key.toLowerCase();
                    if (lower === "rule") {
                        delete listener[key];
                    } else if (lower === "proxy") {
                        const resolved = resolveProxy(listener[key]);
                        if (resolved) listener[key] = resolved;
                        else delete listener[key];
                    }
                });
            });
        }

        if (Array.isArray(params.tunnels)) {
            params.tunnels = params.tunnels.map(item => {
                if (typeof item === "string") {
                    const parts = item.split(",");
                    if (parts.length === 4) {
                        const rawProxy = parts[3].trim();
                        if (rawProxy !== "") {
                            const resolved = resolveProxy(rawProxy);
                            if (resolved) {
                                parts[3] = resolved;
                                return parts.join(",");
                            }
                            return parts.slice(0, 3).join(",");
                        }
                    }
                    return item;
                }
                if (isPlainObject(item)) {
                    Object.keys(item).forEach(key => {
                        if (key.toLowerCase() === "proxy") {
                            const resolved = resolveProxy(item[key]);
                            if (resolved) item[key] = resolved;
                            else delete item[key];
                        }
                    });
                }
                return item;
            });
        }
    };

    fixDialerProxies(params.proxies, groups);

    params["proxy-groups"] = groups;

    fixInbounds();

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

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
