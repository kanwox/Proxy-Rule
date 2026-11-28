// Concord_rule.js V1.5
// Concord 内核（https://github.com/Vialibrex/concord）的订阅覆写脚本。
// Concord 是独立的代理内核，配置采用 Clash 格式；本脚本从节点平铺的订阅
// 生成地区组、应用分流与 fake-ip DNS。
// 订阅中内核不支持的字段按黑名单静默丢弃，未知键保留；
// 客户端自管设置原样透传，仅删除内核不应用的死键（不改变任何生效设置）。
// 净化依据：concord crates/config/src/keys.rs、proxy/parse.rs、listener/、dns.rs 与 crates/proxy 节点构建行为
// （2026-11-29 按内核源码复核；docs/compatibility.md 滞后于代码时以代码为准）。
// 首次启动联网下载规则集，在日志确认全部下载成功。

// ── 可调参数（集中维护） ──
const DEFAULT_IP_VERSION = "dual"; // 双栈偏好：dual(并发择优) / ipv6-prefer / ipv4-prefer
const REGION_GROUP_TYPE = "smart"; // 地区组类型：smart(Concord 原生智能组：支持失败自动换节点重拨与 1h 域名粘性) / url-test
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

// UTF-8 字节数：snell 的 PSK/userkey 长度限制按字节计，不是 JS 字符数
const utf8Bytes = str => {
    let n = 0;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        if (c < 0x80) n += 1;
        else if (c < 0x800) n += 2;
        else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
            n += 4;
            i++;
        } else n += 3;
    }
    return n;
};

// ── 字段净化：黑名单与节点级助手 ──
// 只处理订阅透传内容；黑名单外的未知键保留

// Concord 未实现的 mihomo 扩展功能键（keys.rs TOP_T2），静默丢弃。
// allow-lan、lan-allowed-ips、lan-disallowed-ips、listeners、tunnels、ss-config、vmess-config、tuic-server 等均被 Concord 支持，
// geodata-mode、geosite-matcher、etag-support 已归入 TOP_INERT 静默忽略，均原样透传
const CONCORD_TOP_DROP = [
    "iptables", "clash-for-android", "inbound-tfo",
    "inbound-mptcp",
    "external-controller-pipe", "external-controller-unix",
    "external-controller-tls", "external-controller-routing-mark",
    "external-ui", "external-ui-url", "external-ui-name",
    "external-doh-server",
    "global-client-fingerprint",
    "lgbm-auto-update", "lgbm-update-interval", "lgbm-url"
];

// 内建策略名（含 Concord builtin.rs 的 7 个 REJECT-* 变体）。
// RULES 仅用于 DNS 连接按路由规则出站，不作为普通 dialer-proxy 出站目标
const BUILTIN_POLICIES = new Set([
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "REJECT-IMG",
    "REJECT-DICT",
    "REJECT-ARRAY",
    "REJECT-200",
    "REJECT-VIDEO",
    "COMPATIBLE",
    "PASS",
    "PASS-RULE",
    "GLOBAL",
    "RULES"
]);

// 客户端设置段落中 Concord 不应用的死键：删除不改变任何生效设置，仅消除忽略告警。
// 内核读取并生效的设置（allow-lan、LAN 名单、端口等）及 INERT 静默键（tun.stack、gso-max-size 等）不在此列

// tun（keys.rs TUN_T2）
const CONCORD_TUN_DROP = [
    "dns-mode", "inet6-address",
    "iproute2-table-index", "iproute2-rule-index", "auto-redirect",
    "auto-redirect-input-mark", "auto-redirect-output-mark",
    "auto-redirect-iproute2-fallback-rule-index", "loopback-address",
    "route-address-set", "route-exclude-address-set",
    "include-uid-range", "exclude-uid-range",
    "exclude-src-port-range", "exclude-dst-port-range",
    "include-android-user", "include-package", "exclude-package",
    "include-mac-address", "exclude-mac-address",
    "endpoint-independent-nat", "icmp-timeout", "file-descriptor"
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
// openvpn 与 tailscale 均已原生支持（T1_PROXY_TYPES），不再丢弃
const CONCORD_NODE_TYPE_DROP = new Set([
    "easytier", "zerotier", "sudoku", "trusttunnel"
]);

// 不支持的传输网络（parse.rs T2_NETWORKS）
const CONCORD_NETWORK_DROP = new Set(["mkcp", "kcp", "mekya"]);

// 不支持的 TLS 选项（parse.rs T2_TLS_KEYS）：出现即隔离节点（含 xhttp download-settings 内）
const CONCORD_TLS_OPT_DROP = ["restls-opts", "tlsmirror-opts"];

// 不支持的 ss 插件（parse.rs T2_SS_PLUGINS）
const CONCORD_SS_PLUGIN_DROP = new Set(["restls", "kcptun"]);

// ss 加密白名单（proxy/src/ss/crypto.rs parse_method + legacy 的 chacha20/xchacha20）：
// 内核按白名单构建，名单外一律拒绝；黑名单盖不住未知加密名，故改用白名单
const CONCORD_SS_CIPHER_OK = new Set([
    "none",
    "aes-128-gcm", "aes-256-gcm",
    "aes-128-ccm", "aes-256-ccm",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "2022-blake3-chacha8-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "chacha20", "xchacha20"
]);

// Concord 不支持的 DNS 上游协议（剔除后清空的 policy 键会成 REFUSED 黑洞；ts:// / tailscale:// 已原生支持）
const CONCORD_DNS_SCHEME_DROP = /^(et|easytier):\/\//i;

// 节点准入：丢弃 Concord 会隔离/拒绝构建的节点，避免策略组引用后整组拒绝连接
const concordNodeSupported = proxy => {
    const type = String(proxy.type || "").toLowerCase();
    if (CONCORD_NODE_TYPE_DROP.has(type)) return false;
    if (CONCORD_NETWORK_DROP.has(String(proxy.network || "").toLowerCase())) {
        return false;
    }

    // download-settings 嵌套在 xhttp-opts 下（parse.rs xhttp_download），顶层并无此键
    const xhttp = isPlainObject(proxy["xhttp-opts"])
        ? proxy["xhttp-opts"]
        : {};
    const download = isPlainObject(xhttp["download-settings"])
        ? xhttp["download-settings"]
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
            !CONCORD_SS_CIPHER_OK.has(
                String(proxy.cipher || "").toLowerCase()
            )
        ) {
            return false;
        }
        // v2ray-plugin + TLS + ECH：crates/proxy/src/ss/mod.rs 已完整支持，不再误删
        // （docs/compatibility.md 仍写拒绝，为滞后表述）
    }

    // REALITY 以 public-key 非空为启用；内核仅允许 tcp/grpc/h2/http/xhttp，
    // ws 与 httpupgrade 构建时拒绝（proxy/src/link.rs）；空壳 reality-opts 不影响节点
    const reality = isPlainObject(proxy["reality-opts"])
        ? proxy["reality-opts"]
        : {};
    const network = String(proxy.network || "").toLowerCase();
    if (
        typeof reality["public-key"] === "string" &&
        reality["public-key"] !== "" &&
        (network === "ws" || network === "httpupgrade")
    ) {
        return false;
    }
    // Hysteria faketcp 不支持：内核取 obfs-protocol 优先、protocol 兜底
    if (type === "hysteria") {
        const proto = String(
            proxy["obfs-protocol"] || proxy.protocol || ""
        ).toLowerCase();
        if (proto === "faketcp") return false;
    }
    // mieru UDP + dialer-proxy：内核 2026-11-18 起经 associate_via 支持，不再丢弃
    // （docs/compatibility.md 仍写拒绝，为滞后表述）

    // hysteria2 realm（enable: true）与端口跳跃 ports、dialer-proxy 均互斥；
    // realm 未启用时两条限制都不生效（proxy/src/hysteria2/mod.rs）
    if (type === "hysteria2") {
        const realm = isPlainObject(proxy["realm-opts"])
            ? proxy["realm-opts"]
            : {};
        if (realm.enable === true) {
            if (String(proxy.ports || "").trim() !== "") return false;
            if (proxy["dialer-proxy"]) return false;
        }
    }

    // snell 构建期限制（proxy/src/snell/mod.rs validate）：
    // version 0 按 1、5 按 4 处理；v1/v2 不支持 UDP；v6 PSK 须 12–255 字节、
    // userkey 至多 255 字节，且拒绝 simple-obfs tls/http；restls 任何版本都不支持
    if (type === "snell") {
        const rawVersion = Number(proxy.version) || 0;
        const version =
            rawVersion === 0 ? 1 : rawVersion === 5 ? 4 : rawVersion;
        const obfs = isPlainObject(proxy["obfs-opts"])
            ? proxy["obfs-opts"]
            : {};
        const obfsMode = String(obfs.mode || "");
        if (obfsMode === "restls") return false;
        if ((version === 1 || version === 2) && proxy.udp === true) {
            return false;
        }
        if (version === 6) {
            const pskLen = utf8Bytes(String(proxy.psk || ""));
            if (pskLen < 12 || pskLen > 255) return false;
            if (utf8Bytes(String(proxy.userkey || "")) > 255) return false;
            if (obfsMode === "tls" || obfsMode === "http") return false;
        }
    }

    return true;
};

// 折叠映射键名：ASCII 小写并将 "_" 转为 "-"（对齐 Concord lenient.rs Fields 折叠规则）
const foldKeys = obj => {
    if (!isPlainObject(obj)) return;
    Object.keys(obj).forEach(key => {
        const canonical = String(key).toLowerCase().replace(/_/g, "-");
        if (canonical === key) return;
        if (!(canonical in obj)) {
            obj[canonical] = obj[key];
        }
        delete obj[key];
    });
};

// 节点字段规范化：废弃字段迁移为等价新写法，Concord 忽略的字段删除
const concordNormalizeNode = proxy => {
    // 变体键归一：Concord 解析节点时折叠大写与 "_" -> "-"（lenient.rs），但脚本后续检查按连字符小写作匹配；
    // 先归一顶层及常见选项子对象键，避免 ws_path / client_fingerprint / reality_opts 等漏检
    foldKeys(proxy);
    [
        "xhttp-opts",
        "reality-opts",
        "realm-opts",
        "obfs-opts",
        "ss-opts",
        "amnezia-wg-option"
    ].forEach(sub => {
        if (isPlainObject(proxy[sub])) foldKeys(proxy[sub]);
    });
    if (
        isPlainObject(proxy["xhttp-opts"]) &&
        isPlainObject(proxy["xhttp-opts"]["download-settings"])
    ) {
        foldKeys(proxy["xhttp-opts"]["download-settings"]);
    }

    if (typeof proxy.type === "string") proxy.type = proxy.type.toLowerCase();
    if (typeof proxy.plugin === "string") {
        proxy.plugin = proxy.plugin.toLowerCase();
    }
    // Concord ss/crypto.rs parse_method 区分大小写（仅认小写），大写加密名会导致节点被隔离
    if (proxy.type === "ss" && typeof proxy.cipher === "string") {
        proxy.cipher = proxy.cipher.toLowerCase();
    }
    if (
        proxy.type === "trojan" &&
        isPlainObject(proxy["ss-opts"]) &&
        typeof proxy["ss-opts"].method === "string"
    ) {
        proxy["ss-opts"].method = proxy["ss-opts"].method.toLowerCase();
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

    // 仅废弃的 chrome_* 下划线变体与 randomized 需规范化；chrome120 为 Concord 有效指纹，保留不动
    const fp = proxy["client-fingerprint"];
    if (typeof fp === "string") {
        if (/^chrome_/i.test(fp)) proxy["client-fingerprint"] = "chrome";
        else if (fp.toLowerCase() === "randomized") {
            proxy["client-fingerprint"] = "random";
        }
    }

    // xhttp download-settings 内的指纹同样参与废弃名告警（proxy/warn.rs）
    const xhttpOpts = isPlainObject(proxy["xhttp-opts"])
        ? proxy["xhttp-opts"]
        : {};
    if (isPlainObject(xhttpOpts["download-settings"])) {
        const target = xhttpOpts["download-settings"];
        const dfp = target["client-fingerprint"];
        if (typeof dfp === "string") {
            if (/^chrome_/i.test(dfp)) target["client-fingerprint"] = "chrome";
            else if (dfp.toLowerCase() === "randomized") {
                target["client-fingerprint"] = "random";
            }
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

// dialer-proxy 引用校验：先按改名表同步重定向，再清除悬空引用与环（避免 Concord 拒绝整份配置）
const concordFixDialers = (proxies, groups, proxyRenames = new Map()) => {
    proxies.forEach(proxy => {
        const target = proxy["dialer-proxy"];
        if (typeof target === "string" && proxyRenames.has(target)) {
            proxy["dialer-proxy"] = proxyRenames.get(target);
        }
    });

    const known = new Set([
        ...proxies.map(proxy => proxy.name),
        ...groups.map(group => group.name),
        ...[...BUILTIN_POLICIES].filter(name => name !== "RULES")
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

// listeners / tunnels 引用校验（listener/mod.rs check_refs）：
// 指向不存在节点/组或已被删除的 sub-rules 会导致整份配置拒载；
// 同步改名映射，清除悬空 proxy 与 rule 引用，让连接回退到主规则集
const concordFixInbounds = (params, proxyRenames = new Map()) => {
    const known = new Set([
        ...params.proxies.map(proxy => proxy.name),
        ...params["proxy-groups"].map(group => group.name),
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
                    // 脚本不生成且已删除 sub-rules，任何非空 rule 都会触发拒载
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

// hosts 清洗：非法键/值、多值非全 IP、自映射、别名环会被 Concord 拒载或跳过。
// lan 值与指向已删条目的别名合法，保留
const concordCleanHosts = hosts => {
    const isIpv4 = value => {
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
        return value.split(".").every(part => {
            if (part.length > 1 && part.startsWith("0")) return false;
            return Number(part) <= 255;
        });
    };
    const isIp = value => {
        if (isIpv4(value)) return true;
        if (!value.includes(":")) return false;
        const halves = value.split("::");
        if (halves.length > 2) return false;
        const splitGroups = s => (s === "" ? [] : s.split(":"));
        const left = splitGroups(halves[0]);
        const right = halves.length === 2 ? splitGroups(halves[1]) : [];
        if (left.includes("") || right.includes("")) return false;
        const all = [...left, ...right];
        const isHex = g => /^[0-9a-fA-F]{1,4}$/.test(g);
        let hasV4Tail = false;
        if (all.length > 0 && all[all.length - 1].includes(".")) {
            if (halves.length === 2 && right.length === 0) return false;
            if (!isIpv4(all[all.length - 1])) return false;
            hasV4Tail = true;
        }
        const hexGroups = hasV4Tail ? all.slice(0, -1) : all;
        if (!hexGroups.every(isHex)) return false;
        const units = hexGroups.length + (hasV4Tail ? 2 : 0);
        return halves.length === 2 ? units <= 7 : units === 8;
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
                    (typeof item !== "string" &&
                        typeof item !== "number" &&
                        typeof item !== "boolean") ||
                    String(item).trim() === ""
            )
        ) {
            return null;
        }
        return list.map(item => String(item).trim());
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
            if (value === "lan" || isIp(value) || value.startsWith("script:")) {
                return;
            }
            if (value.includes(":") || value.toLowerCase() === key.toLowerCase()) {
                deleted.add(key);
                return;
            }
            alias.set(key.toLowerCase(), value.toLowerCase());
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

    // 记住面板手动选择与 fake-ip 缓存；订阅已设置的项以订阅为准，删除 Concord 不支持的 profile T2 死键
    params.profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        isPlainObject(params.profile) ? params.profile : {}
    );
    delete params.profile["smart-collector-size"];

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
    // Concord 将 global-client-fingerprint 归为 TOP_T2（忽略并告警），提前删除消除告警
    delete params["global-client-fingerprint"];

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
            // 仅豁免米家与 Apple Push（APNs）：Concord 对含空格的 "Mijia Cloud" 会在域名校验阶段直接跳过嗅探，
            // 保留该条目以与 Clash 配置保持兼容
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

    // 地区表。regex 与可选的大小写敏感 codeRegex 仅在 JS 侧经 toJsRegex 转换使用
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

    // 地区正则仅用于 JS 侧分类：按 (?i) 前缀决定是否忽略大小写（支持大小写敏感 codeRegex）
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

    // 取自实际会建组的 activeRegions，避免引用到节点不足未建组的地区（内核找不到目标组）
    const REGION_NAMES = new Set(activeRegionNames);

    // 包含 type: direct 的命名出站（常用于指定网卡出口的 DNS 上游），排除 reject / dns
    const PROXY_NAMES = new Set(
        params.proxies
            .filter(
                proxy =>
                    proxy &&
                    proxy.name &&
                    proxy.type !== "reject" &&
                    proxy.type !== "dns"
            )
            .map(proxy => proxy.name)
    );

    // 校验 DNS 条目尾部 "#目标"：合法整条保留，指向已删除对象则剥掉并补 #RULES
    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    const subInterfaceName =
        typeof params["interface-name"] === "string"
            ? params["interface-name"].trim()
            : "";

    // 常见网卡名模式（Linux / macOS / BSD / Android / OpenWrt），避免误把网卡绑定（如 #en0 / #eth0）当成悬空策略组改写为 #RULES
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

    const hasOwn = (object, key) =>
        Object.prototype.hasOwnProperty.call(object, key);

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

    const mergePolicyEntry = (target, key, servers) => {
        if (!key || servers.length === 0) return;

        if (hasOwn(target, key)) {
            target[key] = [...new Set([...target[key], ...servers])];
        } else {
            target[key] = [...new Set(servers)];
        }
    };

    // 校验域名模式是否能通过 Concord DomainTrie::split_domain（crates/dns/src/trie.rs）：
    // 拒绝尾部点、空白、空标签（首个 "." 除外）、局部通配（time*.com / *a.com）、非首段 "+" 及裸通吃项
    const isValidConcordDomainPattern = (pattern, allowStar = false) => {
        if (typeof pattern !== "string" || pattern.length === 0) return false;
        if (/\s/.test(pattern) || pattern.endsWith(".")) return false;
        if (pattern === "*") return allowStar;
        if (pattern === "+" || pattern === "+." || pattern === ".") {
            return false;
        }
        const labels = pattern.split(".");
        if (labels.slice(1).some(label => label === "")) return false;
        for (let i = 0; i < labels.length; i++) {
            const label = labels[i];
            if (label.includes("+")) {
                if (label !== "+" || i !== 0 || labels.length === 1) {
                    return false;
                }
            }
            if (label.includes("*") && label !== "*") return false;
        }
        return labels.some(
            label => label !== "" && label !== "+" && label !== "*"
        );
    };

    // 将通过 DomainTrie 校验的黑名单域名模式转换为 Concord fake-ip-filter-mode: rule 规则
    const domainPatternToFilterRules = pattern => {
        if (pattern.startsWith("+.")) {
            const rest = pattern.slice(2);
            if (!rest.includes("*")) {
                return [`DOMAIN-SUFFIX,${rest},real-ip`];
            }
            return [
                `DOMAIN-WILDCARD,${rest},real-ip`,
                `DOMAIN-WILDCARD,*.${rest},real-ip`
            ];
        }
        if (pattern.startsWith(".")) {
            return [`DOMAIN-WILDCARD,*.${pattern.slice(1)},real-ip`];
        }
        if (pattern.includes("*")) {
            return [`DOMAIN-WILDCARD,${pattern},real-ip`];
        }
        return [`DOMAIN,${pattern},real-ip`];
    };

    // 清洗订阅已为 fake-ip-filter-mode: rule 时的单条规则（仅保留安全的纯域名规则）
    const sanitizeSubFilterRule = line => {
        const parts = String(line)
            .split(",")
            .map(part => part.trim());
        if (parts.length !== 3) return null;
        const type = parts[0].toUpperCase();
        const payload = parts[1];
        const action = parts[2].toLowerCase();
        if (action !== "real-ip" && action !== "fake-ip") return null;
        if (payload === "" || /\s/.test(payload)) return null;
        if (type === "DOMAIN" || type === "DOMAIN-SUFFIX") {
            if (
                payload.includes("*") ||
                payload.includes("+") ||
                payload.startsWith(".") ||
                !isValidConcordDomainPattern(payload)
            ) {
                return null;
            }
            return `${type},${payload},${action}`;
        }
        if (type === "DOMAIN-KEYWORD") {
            return `${type},${payload},${action}`;
        }
        if (type === "DOMAIN-WILDCARD") {
            if (
                payload.includes("+") ||
                !isValidConcordDomainPattern(payload)
            ) {
                return null;
            }
            return `${type},${payload},${action}`;
        }
        return null;
    };

    // 特殊内建 DNS 协议不走代理路由，无需补 #RULES
    const isSpecialDnsScheme = s =>
        /^(system|rcode|dhcp):\/\//i.test(s) ||
        s.toLowerCase() === "system";

    // Clash/Mihomo/Concord 常见裸布尔 DNS 参数（不含 "="），不得误判为悬空代理名
    const BARE_DNS_FLAGS = new Set([
        "h3",
        "ecs-override",
        "skip-cert-verify",
        "disable-ipv4",
        "disable-ipv6",
        "name-cert-verify",
        "respect-rules",
        "no-ecs"
    ]);
    const isBareDnsFlag = part => {
        const lower = part.toLowerCase();
        return (
            BARE_DNS_FLAGS.has(lower) ||
            /^disable-qtype-\d+$/i.test(lower)
        );
    };
    const decodeFragmentPart = part => {
        try {
            return decodeURIComponent(part);
        } catch {
            return part;
        }
    };

    // # 后按 "&" 分段：含 "=" 或已知裸布尔标志为参数原样保留，其余段经百分号解码并查改名表后校验；
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

        const paramParts = [];
        const targetParts = [];
        rawParts.forEach(part => {
            const decoded = decodeFragmentPart(part);
            if (decoded.includes("=") || isBareDnsFlag(decoded)) {
                paramParts.push(part);
            } else {
                targetParts.push({ raw: part, decoded });
            }
        });

        const validTargets = [];
        targetParts.forEach(({ raw, decoded }) => {
            const renamed = proxyRenames.get(decoded);
            const resolved = renamed || decoded;
            if (refValid(resolved) || isInterfaceBinding(decoded)) {
                validTargets.push(
                    renamed
                        ? renamed
                              .replace(/%/g, "%25")
                              .replace(/&/g, "%26")
                              .replace(/#/g, "%23")
                        : raw
                );
            }
        });

        const hasRespectRulesFlag = paramParts.some(
            part => decodeFragmentPart(part).toLowerCase() === "respect-rules"
        );

        const needRulesFallback =
            (targetParts.length > 0 && validTargets.length === 0) ||
            (targetParts.length === 0 &&
                respectRules &&
                !hasRespectRulesFlag &&
                !isSpecialDnsScheme(base));

        const finalTargets = needRulesFallback ? ["RULES"] : validTargets;
        const finalParts = [...finalTargets, ...paramParts];

        return finalParts.length > 0
            ? base + "#" + finalParts.join("&")
            : base;
    };

    // 节点解析 DNS 不得经代理/策略组或 respect-rules 出站，否则形成"需要节点才能解析节点"的循环；
    // 保留传输参数与非路由裸布尔标志
    const stripProxyRefs = entry => {
        const s = String(entry).trim();
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const params = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(part => {
                if (part === "") return false;
                const decoded = decodeFragmentPart(part);
                return (
                    decoded.includes("=") ||
                    (isBareDnsFlag(decoded) &&
                        decoded.toLowerCase() !== "respect-rules") ||
                    isInterfaceBinding(decoded)
                );
            });

        return params.length > 0
            ? s.slice(0, hash) + "#" + params.join("&")
            : s.slice(0, hash);
    };

    const stripProxyRefsPolicy = policy => {
        const out = {};

        for (const key of Object.keys(policy)) {
            const cleaned = stringList(policy[key]).map(stripProxyRefs);
            if (cleaned.length > 0) out[key] = [...new Set(cleaned)];
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

        // fake-ip-filter 继承并转换为 rule 模式条目：
        // - 缺省/blacklist：过滤 rule-set/geosite/geoip 与不合法 DomainTrie 模式，再转 DOMAIN/DOMAIN-SUFFIX/DOMAIN-WILDCARD
        // - rule：仅保留安全的纯域名规则（剔除 RULE-SET/GEOSITE/MATCH/IP 等）
        // - whitelist：语义相反，放弃继承
        const modeRaw = subDNS["fake-ip-filter-mode"];
        const mode =
            typeof modeRaw === "string"
                ? modeRaw.trim().toLowerCase()
                : "";

        let subFilterRules = [];
        if (mode === "" || mode === "blacklist") {
            stringList(subDNS["fake-ip-filter"]).forEach(item => {
                if (/^(rule-set|geosite|geoip):/i.test(item)) return;
                if (!isValidConcordDomainPattern(item)) return;
                subFilterRules.push(...domainPatternToFilterRules(item));
            });
        } else if (mode === "rule") {
            stringList(subDNS["fake-ip-filter"]).forEach(line => {
                const rule = sanitizeSubFilterRule(line);
                if (rule) subFilterRules.push(rule);
            });
        }

        // 逐键清洗 nameserver-policy：按逗号分段解析，剔除 rule-set:/geosite:/geoip:、通吃键与非法 DomainTrie 模式，
        // 规范化后重名键自动合并服务器列表
        const rawSubPolicy = asPlainObject(subDNS["nameserver-policy"]);
        const subPolicy = {};
        for (const key of Object.keys(rawSubPolicy)) {
            const cleanedServers = stringList(rawSubPolicy[key]).map(
                cleanWithRules
            );
            if (cleanedServers.length === 0) continue;

            const keptDomains = parsePolicyKey(key)
                .filter(
                    seg =>
                        seg.kind === "domain" &&
                        isValidConcordDomainPattern(seg.value)
                )
                .map(seg => seg.value);

            if (keptDomains.length === 0) continue;

            mergePolicyEntry(subPolicy, keptDomains.join(","), cleanedServers);
        }

        // ── 清洗 proxy-server-nameserver-policy ──
        // 键：按逗号分段解析；geosite:/geoip: 与非法 DomainTrie 丢弃；rule-set: 仅在订阅原始 rule-providers 有定义时保留并搬运；
        // 混合键拆分输出（域名段与 rule-set: 段独立），重名键合并；允许 "*"，拒绝 Concord DomainTrie 硬报错的 "+" / "+."
        const rawPSNPolicy = asPlainObject(
            subDNS["proxy-server-nameserver-policy"]
        );

        const subPSNPolicy = {};
        const carriedRuleProviders = {};

        for (const key of Object.keys(rawPSNPolicy)) {
            const cleanedServers = stringList(rawPSNPolicy[key]).map(
                stripProxyRefs
            );
            if (cleanedServers.length === 0) continue;

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

                if (isValidConcordDomainPattern(seg.value, true)) {
                    domainSegs.push(seg.value);
                }
            }

            if (domainSegs.length > 0) {
                mergePolicyEntry(
                    subPSNPolicy,
                    domainSegs.join(","),
                    cleanedServers
                );
            }
            if (validRSNames.length > 0) {
                mergePolicyEntry(
                    subPSNPolicy,
                    "rule-set:" + validRSNames.join(","),
                    cleanedServers
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
            subFilterRules,
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
        subFilterRules,
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

    // 客户端/订阅显式设置 dns.listen 时原样继承，缺省回落至回环非特权端口 127.0.0.1:1053
    const dnsListen =
        typeof subDNS.listen === "string" && subDNS.listen.trim() !== ""
            ? subDNS.listen.trim()
            : "127.0.0.1:1053";

    params.dns = {
        enable: true,
        listen: dnsListen,
        ipv6: dnsIPv6,
        ...(subDNS["append-system"] === false
            ? { "append-system": false }
            : {}),
        "prefer-h3": PREFER_H3,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        // IPv6 fake-ip 段（仅 DNS 启用 IPv6 时输出）：沿用官方文档示例的 RFC 4193 ULA 私有子网（低碰撞随机前缀），
        // 避免与常见局域网 ULA 网段冲突
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
        // 规则模式按序匹配：
        // 1) 局域网、NTP、连通性探测、游戏平台、STUN 刚需 real-ip 置顶（避免 time.apple.com / time.windows.com /
        //    msftconnecttest.com / xboxlive.com 等被下方 apple/google/microsoft 规则集抢先命中 fake-ip）
        // 2) Apple / Google / Microsoft / AI 优先 fake-ip，避免其国内 CDN 域名被后续 cn-domain 截走 real-ip
        // 3) 订阅合法条目与私网 / 国内 / 社区 fakeip-filter 规则集兜底 real-ip，其余一律 fake-ip
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
                // STUN 通配：Concord DOMAIN-WILDCARD 的 * 支持跨级匹配，覆盖所有含 stun 段的域名
                "DOMAIN-WILDCARD,stun.*,real-ip",
                "DOMAIN-WILDCARD,*.stun.*,real-ip",
                "RULE-SET,apple-domain,fake-ip",
                "RULE-SET,google-domain,fake-ip",
                "RULE-SET,microsoft-domain,fake-ip",
                "RULE-SET,ai-domain,fake-ip",
                ...subFilterRules,
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

    // 广告域名拦截规则（TG-Twilight/AWAvenue-Ads-Rule，低误杀、轻量 .mrs）
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

    // 默认指纹补全：vless/vmess/trojan/anytls TLS 节点、snell（shadow-tls / jls）与 xhttp download-settings；不覆盖已有取值
    const FP_OK = ["vless", "vmess", "trojan", "anytls"];
    const hasRealityKey = opts =>
        isPlainObject(opts) &&
        typeof opts["public-key"] === "string" &&
        opts["public-key"].trim() !== "";

    params.proxies.forEach(proxy => {
        // 不覆盖订阅已有的取值；direct/reject/dns 虚拟出站无需 ip-version
        if (
            proxy.type !== "direct" &&
            proxy.type !== "reject" &&
            proxy.type !== "dns" &&
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
            if (obfsMode === "shadow-tls" || obfsMode === "jls") {
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

    // 地区组默认使用 Concord 原生 GROUP_T0 smart 组（支持失败重拨、1h 域名粘性与 tolerance/max-failed-times）
    const regionGroupType =
        REGION_GROUP_TYPE === "url-test" ? "url-test" : "smart";

    activeRegions.forEach(region => {
        groups.push({
            name: region.name,
            type: regionGroupType,
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

    // 2) 客户端设置段落中的死键：只删 Concord 不应用的键，生效设置与 INERT 静默键不动
    if (isPlainObject(params.tun)) {
        CONCORD_TUN_DROP.forEach(key => {
            delete params.tun[key];
        });
    }
    if (isPlainObject(params.tls)) {
        CONCORD_TLS_DROP.forEach(key => {
            delete params.tls[key];
        });
    }

    // 3) rule-providers：删无效非对象条目与 path-in-bundle（override-expr 仅属 proxy-providers）
    const droppedProviders = new Set();
    Object.keys(params["rule-providers"]).forEach(name => {
        const provider = params["rule-providers"][name];
        if (!isPlainObject(provider)) {
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
            const text = String(item);
            const legacy = /^rule-set:(.+)$/i.exec(text);
            if (legacy) return !droppedProviders.has(legacy[1].trim());
            const rule = /^RULE-SET,([^,]+),/i.exec(text);
            if (rule) return !droppedProviders.has(rule[1].trim());
            return true;
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

    // 7) dialer-proxy 引用校验：同步改名映射，再清除悬空引用与环（避免整份拒载）
    concordFixDialers(params.proxies, params["proxy-groups"], proxyRenames);

    // 8) listeners / tunnels 引用校验：同步改名映射，清除悬空 proxy 与已删 sub-rules 的 rule 引用（避免整份拒载）
    concordFixInbounds(params, proxyRenames);

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
