#!/usr/bin/env node
/**
 * 仓库配置静态检查与 Clash 脚本运行时回归验证脚本（零外部依赖）。
 * 用法：node scripts/verify.mjs
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const ROOT = path.resolve(import.meta.dirname, "..");

const TEXT_FILES = [
    "README.md",
    "Clash/README.md",
    "Clash/Clash_rule.js",
    "Concord/README.md",
    "Concord/Concord_rule.js",
    "Surge/README.md",
    "Surge/Surge.conf",
    "Surfboard/README.md",
    "Surfboard/Surfboard.conf",
    "Loon/README.md",
    "Loon/Loon.conf",
    "Shadowrocket/README.md",
    "Shadowrocket/Shadowrocket.conf",
    "QuantumultX/README.md",
    "QuantumultX/QuantumultX.conf",
    "Stash/README.md",
    "Stash/Stash.yaml",
    "Egern/README.md",
    "Egern/Egern.yaml",
    "scripts/verify.mjs"
];

let passed = 0;
let failed = 0;

function check(name, fn) {
    try {
        fn();
        passed += 1;
        console.log(`PASS  ${name}`);
    } catch (err) {
        failed += 1;
        console.error(`FAIL  ${name}\n      ${err instanceof Error ? err.stack || err.message : String(err)}`);
    }
}

function readRaw(relPath) {
    return fs.readFileSync(path.join(ROOT, relPath));
}

function readUtf8(relPath) {
    return fs.readFileSync(path.join(ROOT, relPath), "utf8");
}

function toJsRegex(clashRegex) {
    const caseInsensitive = clashRegex.startsWith("(?i)");
    const body = caseInsensitive ? clashRegex.slice(4) : clashRegex;
    return new RegExp(body, caseInsensitive ? "i" : "");
}

function escapeRegExpLiteral(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractLineMatch(content, regex, label) {
    const m = content.match(regex);
    assert.ok(m && m[1], `未找到 ${label}`);
    return m[1];
}

// 1. 编码与换行符检查（UTF-8 无 BOM + LF）
check("encoding-and-lf: 全部文件为 UTF-8 无 BOM 且使用 LF 换行", () => {
    for (const rel of TEXT_FILES) {
        const buf = readRaw(rel);
        assert.ok(
            !(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf),
            `${rel} 包含 UTF-8 BOM`
        );
        const crlfIdx = buf.indexOf(Buffer.from("\r\n"));
        assert.equal(crlfIdx, -1, `${rel} 包含 CRLF（首个偏移 ${crlfIdx}）`);
    }
});

// 2. 各端配置文件关键语法与 Bug 修复检查
const surge = readUtf8("Surge/Surge.conf");
const surfboard = readUtf8("Surfboard/Surfboard.conf");
const loon = readUtf8("Loon/Loon.conf");
const shadowrocket = readUtf8("Shadowrocket/Shadowrocket.conf");
const qx = readUtf8("QuantumultX/QuantumultX.conf");
const stash = readUtf8("Stash/Stash.yaml");
const egern = readUtf8("Egern/Egern.yaml");
const clashJs = readUtf8("Clash/Clash_rule.js");

const FLAG_ICON_BASE =
    "https://cdn.jsdmirror.com/gh/open-assets-hub/country-flag-collection@main/circle/128";
const CORE_FLAG_CODES = ["hk", "jp", "sg", "tw", "us"];

function assertCirclePngFlags(content, client) {
    for (const code of CORE_FLAG_CODES) {
        assert.ok(
            content.includes(`${FLAG_ICON_BASE}/${code}.png`),
            `${client} 缺少 ${code}.png 地区图标`
        );
        assert.ok(
            !content.includes(`Koolson/Qure@master/IconSet/Color/${code.toUpperCase()}.png`),
            `${client} 仍残留旧 Qure ${code.toUpperCase()}.png 地区图标`
        );
    }
    assert.ok(!content.includes("circle-flags"), `${client} 仍残留 circle-flags`);
}

check("surge: 保留 FINAL dns-failed、pre-matching 与 circle/128 PNG 地区图标", () => {
    assert.match(surge, /^FINAL,兜底,dns-failed$/m);
    assert.match(surge, /REJECT,pre-matching(?:,|$)/m);
    assertCirclePngFlags(surge, "Surge");
});

check("surfboard: FINAL 已移除 dns-failed 并使用 circle/128 PNG 地区图标", () => {
    assert.match(surfboard, /^FINAL,兜底$/m);
    assert.ok(!surfboard.includes("dns-failed"), "Surfboard 不应包含 dns-failed");
    assertCirclePngFlags(surfboard, "Surfboard");
});

check("loon: FINAL 已移除 dns-failed 并使用 circle/128 PNG 地区图标", () => {
    assert.match(loon, /^FINAL,兜底$/m);
    assert.ok(!loon.includes("dns-failed"), "Loon 不应包含 dns-failed");
    assertCirclePngFlags(loon, "Loon");
});

check("shadowrocket: 移除 policy-regex-filter 引号、修复 DST-PORT 与 FINAL", () => {
    assert.match(shadowrocket, /^FINAL,兜底$/m);
    assert.ok(!shadowrocket.includes("dns-failed"), "Shadowrocket 不应包含 dns-failed");
    assert.ok(
        !shadowrocket.includes('policy-regex-filter="'),
        "Shadowrocket policy-regex-filter 不应带双引号"
    );
    const filterMatches = shadowrocket.match(/policy-regex-filter=\(\?i\)/g) || [];
    assert.equal(filterMatches.length, 20, "Shadowrocket 应有 20 个未加引号的 policy-regex-filter");
    assert.ok(shadowrocket.includes("AND,((DST-PORT,123),(PROTOCOL,UDP)),DIRECT"));
    assert.ok(!shadowrocket.includes("DEST-PORT"), "Shadowrocket 不应残留 DEST-PORT");
});

check("quantumultx: [dns] 单行双 IP DoH、移除无效 server= 与 circle/128 PNG 图标", () => {
    const dnsSection = qx.slice(qx.indexOf("\n[dns]\n"), qx.indexOf("\n[server_remote]\n"));
    assert.ok(!/^\s*server\s*=/m.test(dnsSection), "QX [dns] 不应保留被 doh-server 覆盖的 server=");
    assert.match(
        dnsSection,
        /^doh-server = https:\/\/223\.5\.5\.5\/dns-query, https:\/\/1\.12\.12\.12\/dns-query$/m
    );
    assertCirclePngFlags(qx, "QX");
});

check("stash: provider benchmark-url、移除无效 dns 字段与 pre-matching、circle/128 PNG 图标", () => {
    assert.match(stash, /^\s{4}benchmark-url:\s*http:\/\/www\.gstatic\.com\/generate_204$/m);
    const dnsBlock = stash.slice(stash.indexOf("\ndns:\n"), stash.indexOf("\nsniffer:\n"));
    assert.ok(!/^\s+enable:/m.test(dnsBlock), "Stash dns 不应包含 enable");
    assert.ok(!/^\s+enhanced-mode:/m.test(dnsBlock), "Stash dns 不应包含 enhanced-mode");
    assert.ok(!/^\s+ipv6:/m.test(dnsBlock), "Stash dns 不应包含 ipv6");
    assert.ok(!stash.includes("pre-matching"), "Stash 不应使用 beta 的 pre-matching");
    assert.match(stash, /-\s+RULE-SET,telegram-ip,Telegram,no-resolve$/m);
    assertCirclePngFlags(stash, "Stash");
});

check("egern: 13 业务组与兜底组策略顺序一致、circle/128 PNG 图标", () => {
    const policyBlocks = egern.match(/policies:\s*\[主代理, DIRECT, HK, JP, SG, TW, US, 静态\]/g) || [];
    assert.equal(policyBlocks.length, 14, "Egern 13 个业务组 + 兜底组应全部使用 [主代理, DIRECT, ..., 静态]");
    assertCirclePngFlags(egern, "Egern");
});

// 3. README 版本与平台说明一致性检查
check("readmes: 根目录与各端 README 版本及特性描述准确", () => {
    assert.ok(readUtf8("README.md").includes("Apple 媒体服务（Clash / Stash 仅分流 Apple TV+）"));
    assert.ok(readUtf8("Clash/README.md").includes("1.19.27"));
    assert.ok(readUtf8("Concord/README.md").includes("chen08209/concord"));
    assert.ok(readUtf8("Concord/README.md").includes("Concord_rule.js"));
    assert.ok(readUtf8("Surge/README.md").includes("iOS 5.14.0+ / Mac 5.9.0+"));
    assert.ok(readUtf8("Surge/README.md").includes("6.5.0+"));
    const egernReadme = readUtf8("Egern/README.md");
    assert.ok(egernReadme.includes("iOS / iPadOS"));
    assert.ok(!egernReadme.includes("iOS / macOS / tvOS"));
    assert.ok(readUtf8("Stash/README.md").includes("iOS 3.6+"));
    assert.ok(readUtf8("Stash/README.md").includes("macOS 4.3+"));
    assert.ok(readUtf8("Loon/README.md").includes("iOS 3.1.7+"));
    assert.ok(readUtf8("Shadowrocket/README.md").includes("2.2.66 (2649)+"));
});

// 4. 8 端正则表达式提取与一致性格局测试
const excludeSamples = {
    shouldExclude: [
        "剩余流量：120.5 GB",
        "到期时间：2026-12-31",
        "官网地址 example.com",
        "套餐到期: 2026-01-01",
        "已用流量 50GB / 100GB",
        "重置时间 15天",
        "加入TG群获取最新地址",
        "QQ群: 123456",
        "官方群 | 防失联",
        "客服联系",
        "订阅更新通知",
        "Expire: 30 Days",
        "Traffic Reset: 100GB",
        "Data: 100GB",
        "Remain 12.5 TB",
        "50GB / 100GB",
        "永久地址发布的通知",
        "防走丢备用链接"
    ],
    shouldKeep: [
        "法罗群岛 01",
        "香港 | 无限流量 CN2 GIA",
        "美国 | 不限流量",
        "新加坡 | IPLC | 500GB",
        "日本 东京 1Gbps",
        "台湾 台北 原生IP",
        "加拿大 Ontario 02",
        "Priority Transit US",
        "时间序列节点 DE",
        "有效载荷 HK 01",
        "防止拥塞 SG 01",
        "加入VIP专线 JP 01",
        "静态地址 US 01",
        "群友专线 TW 01",
        "香港 | 30DaysVPS"
    ]
};

check("regex-exclude: 8 端 excludeFilter 对测试样本表现完全一致且无误杀", () => {
    const surgeStatic = extractLineMatch(surge, /^静态 = .*?policy-regex-filter="([^"]+)"/m, "Surge excludeFilter");
    const surfboardStatic = extractLineMatch(surfboard, /^静态 = .*?policy-regex-filter="([^"]+)"/m, "Surfboard excludeFilter");
    const loonAll = extractLineMatch(loon, /^All = NameRegex, FilterKey = "(.+)"$/m, "Loon excludeFilter");
    const srStatic = extractLineMatch(shadowrocket, /^静态 = select,policy-regex-filter=(.+)$/m, "Shadowrocket excludeFilter");
    const qxStatic = extractLineMatch(qx, /^static = 静态, resource-tag-regex=\^All\$, server-tag-regex=([^,]+),/m, "QX excludeFilter");
    const stashFilter = extractLineMatch(stash, /^\s{4}filter:\s*'(.+)'$/m, "Stash excludeFilter");
    const egernFilterRaw = extractLineMatch(egern, /^  - select:\n\s+name: 静态[\s\S]*?\n\s+filter: ("[^"]+")/m, "Egern excludeFilter");
    const egernFilter = JSON.parse(egernFilterRaw);
    const clashExcludeRaw = extractLineMatch(clashJs, /const excludeFilter =\s*\n\s*("[^"]+");/m, "Clash excludeFilter");
    const clashExclude = JSON.parse(clashExcludeRaw);

    const negativeWrapperClients = [
        ["Surge", surgeStatic],
        ["Surfboard", surfboardStatic],
        ["Loon", loonAll],
        ["Shadowrocket", srStatic],
        ["QuantumultX", qxStatic],
        ["Stash", stashFilter],
        ["Egern", egernFilter]
    ];

    for (const [client, raw] of negativeWrapperClients) {
        const re = toJsRegex(raw);
        for (const s of excludeSamples.shouldExclude) {
            assert.equal(re.test(s), false, `${client} 未排除信息节点: ${s}`);
        }
        for (const s of excludeSamples.shouldKeep) {
            assert.equal(re.test(s), true, `${client} 误杀正常节点: ${s}`);
        }
    }

    const clashRe = toJsRegex(clashExclude);
    for (const s of excludeSamples.shouldExclude) {
        assert.equal(clashRe.test(s), true, `Clash 未排除信息节点: ${s}`);
    }
    for (const s of excludeSamples.shouldKeep) {
        assert.equal(clashRe.test(s), false, `Clash 误杀正常节点: ${s}`);
    }
});

const regionSamples = {
    HK: ["香港 01", "Hong Kong 01", "HongKong 02", "Kowloon BGP", "Tsuen Wan 01"],
    JP: ["日本 01", "Tokyo 01", "Osaka 02", "Narita", "Haneda", "Kyoto", "Fukuoka", "Nagoya", "Sapporo"],
    SG: ["新加坡 01", "Singapore 01", "SG 01"],
    TW: ["台湾 01", "Taipei 01", "Kaohsiung", "Taichung", "Hsinchu"],
    US: [
        "美国 01", "Los Angeles", "Los-Angeles", "San Jose", "Silicon Valley",
        "New York", "Seattle", "Dallas", "Chicago", "Fremont", "Phoenix",
        "Denver", "Atlanta", "Miami"
    ]
};

check("regex-regions: 8 端核心 5 地区（HK/JP/SG/TW/US）英文字段匹配一致", () => {
    const extractors = {
        Surge: code =>
            extractLineMatch(surge, new RegExp(`^${code} = .*?policy-regex-filter="([^"]+)"`, "m"), `Surge ${code}`),
        Surfboard: code =>
            extractLineMatch(surfboard, new RegExp(`^${code} = .*?policy-regex-filter="([^"]+)"`, "m"), `Surfboard ${code}`),
        Loon: code =>
            extractLineMatch(loon, new RegExp(`^${code}_Filter = NameRegex, FilterKey = "(.+)"$`, "m"), `Loon ${code}`),
        Shadowrocket: code =>
            extractLineMatch(shadowrocket, new RegExp(`^${code} = url-test,policy-regex-filter=([^,]+),`, "m"), `SR ${code}`),
        QuantumultX: code =>
            extractLineMatch(qx, new RegExp(`^url-latency-benchmark = ${code}, resource-tag-regex=\\^All\\$, server-tag-regex=([^,]+),`, "m"), `QX ${code}`),
        Stash: code =>
            extractLineMatch(stash, new RegExp(`name: ${code}\\n\\s+type: url-test[\\s\\S]*?\\n\\s+filter: '([^']+)'`, "m"), `Stash ${code}`),
        Egern: code =>
            JSON.parse(
                extractLineMatch(egern, new RegExp(`name: ${code}\\n[\\s\\S]*?\\n\\s+filter: ("[^"]+")`, "m"), `Egern ${code}`)
            ),
        Clash: code =>
            JSON.parse(
                extractLineMatch(clashJs, new RegExp(`name: "${code}",\\s*\\n\\s*regex: ("[^"]+")`, "m"), `Clash ${code}`)
            )
    };

    for (const [client, fn] of Object.entries(extractors)) {
        for (const [code, samples] of Object.entries(regionSamples)) {
            const re = toJsRegex(fn(code));
            for (const node of samples) {
                assert.equal(re.test(node), true, `${client} ${code} 未匹配样本: ${node}`);
            }
        }
    }
});

// 5. Clash_rule.js vm 沙箱运行回归测试
function loadClashMain(sourceOverride = clashJs) {
    const warnings = [];
    const sandbox = {
        console: {
            warn: (...args) => warnings.push(args.join(" ")),
            log: (...args) => warnings.push(args.join(" "))
        }
    };
    vm.createContext(sandbox);
    vm.runInContext(sourceOverride, sandbox);
    return {
        main: input => JSON.parse(JSON.stringify(sandbox.main(input))),
        warnings
    };
}

check("clash-runtime: 正常订阅、城市识别与巴西 Rio 边界防护", () => {
    const { main, warnings } = loadClashMain();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443 },
            { name: "法罗群岛 01", type: "ss", server: "1.1.1.2", port: 443 },
            { name: "Kowloon BGP", type: "trojan", server: "1.1.1.3", port: 443 },
            { name: "Tsuen Wan 01", type: "ss", server: "1.1.1.4", port: 443 },
            { name: "Tokyo 01", type: "ss", server: "1.1.1.5", port: 443 },
            { name: "Sapporo 02", type: "ss", server: "1.1.1.6", port: 443 },
            { name: "São Paulo 01", type: "ss", server: "1.1.1.7", port: 443 },
            { name: "Rio 02", type: "ss", server: "1.1.1.8", port: 443 },
            { name: "CA Ontario 01", type: "ss", server: "1.1.1.9", port: 443 },
            { name: "US Priority 02", type: "ss", server: "1.1.1.10", port: 443 },
            { name: "Montreal 03", type: "ss", server: "1.1.1.11", port: 443 }
        ]
    });
    assert.equal(warnings.length, 0, `不应触发告警: ${warnings.join("; ")}`);

    const staticGroup = out["proxy-groups"].find(g => g.name === "静态");
    assert.ok(staticGroup.proxies.includes("法罗群岛 01"), "法罗群岛不应被过滤");
    assert.ok(!staticGroup.proxies.includes("剩余流量：10GB"), "信息节点应被过滤");

    const hkGroup = out["proxy-groups"].find(g => g.name === "HK");
    assert.deepEqual(hkGroup.proxies, ["Kowloon BGP", "Tsuen Wan 01"]);

    const brGroup = out["proxy-groups"].find(g => g.name === "BR");
    assert.deepEqual(brGroup.proxies, ["Rio 02", "São Paulo 01"]);

    const caGroup = out["proxy-groups"].find(g => g.name === "CA");
    assert.deepEqual(caGroup.proxies, ["CA Ontario 01", "Montreal 03"]);

    assert.equal(
        out.proxies.find(p => p.name === "Kowloon BGP")["client-fingerprint"],
        "chrome",
        "TLS 节点应补全 chrome 指纹"
    );
    assert.equal(
        out.proxies.find(p => p.name === "法罗群岛 01")["client-fingerprint"],
        undefined,
        "非 TLS ss 节点不应误加指纹"
    );
});

check("clash-runtime: 全节点被过滤时 静态 填充 REJECT 占位且无空 proxies", () => {
    const { main, warnings } = loadClashMain();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443 },
            { name: "到期时间：2026-12-31", type: "ss", server: "1.1.1.2", port: 443 }
        ]
    });
    const staticGroup = out["proxy-groups"].find(g => g.name === "静态");
    assert.deepEqual(staticGroup.proxies, ["REJECT"]);
    for (const g of out["proxy-groups"]) {
        assert.ok(Array.isArray(g.proxies) && g.proxies.length > 0, `组 ${g.name} 不应为空`);
    }
    assert.ok(warnings.some(w => w.includes("REJECT")), "应发出 REJECT 占位告警");
});

check("clash-runtime: subDNS.hosts 正确迁移至顶层 params.hosts（顶层已有键优先）", () => {
    const { main } = loadClashMain();

    const out1 = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }],
        dns: { hosts: { "sub.example": "10.0.0.1" } }
    });
    assert.equal(out1.dns.hosts, undefined, "params.dns.hosts 不应存在");
    assert.deepEqual(out1.hosts, { "sub.example": "10.0.0.1" });

    const out2 = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }],
        dns: { hosts: {} }
    });
    assert.equal(out2.dns.hosts, undefined);
    assert.equal(out2.hosts, undefined, "空 subDNS.hosts 不应生成顶层 hosts");

    const out3 = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }],
        hosts: { "shared.example": "9.9.9.9", "top.example": "8.8.8.8" },
        dns: { hosts: { "shared.example": "1.1.1.1", "sub.example": "2.2.2.2" } }
    });
    assert.deepEqual(out3.hosts, {
        "shared.example": "9.9.9.9",
        "top.example": "8.8.8.8",
        "sub.example": "2.2.2.2"
    });
});

check("clash-runtime: 拒绝含 proxy-providers 的订阅", () => {
    const { main } = loadClashMain();
    assert.throws(
        () =>
            main({
                "proxy-providers": { sub: { url: "https://example.com" } },
                proxies: []
            }),
        /proxy-providers/
    );
});

check("clash-runtime: REGION_MIN_NODES=0 下限保护不会产生空地区组", () => {
    const patched = clashJs.replace(/const REGION_MIN_NODES = \d+;/, "const REGION_MIN_NODES = 0;");
    assert.notEqual(patched, clashJs);
    const { main } = loadClashMain(patched);
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }]
    });
    const regionGroups = out["proxy-groups"].filter(g => g.type === "url-test");
    assert.equal(regionGroups.length, 1, "只应建有至少 1 个匹配节点的 HK 组");
    assert.deepEqual(regionGroups[0].proxies, ["HK 01"]);
});

check("clash-runtime: 23 个地区扩展城市与印度尼西亚防误匹配", () => {
    const extraNodes = [
        "Abu Dhabi 01", "Buenos Aires 01", "Perth 01", "Dhaka 01", "São Paulo 01",
        "Montreal 01", "Munich 01", "Lyon 01", "Edinburgh 01", "Kowloon 01",
        "Surabaya 01", "印度尼西亚 01", "New Delhi 01", "Nagoya 01", "Seoul 01",
        "Kuala Lumpur 01", "Rotterdam 01", "Cebu 01", "SG 01", "Chiang Mai 01",
        "Ankara 01", "Hsinchu 01", "Miami 01", "Hanoi 01"
    ];
    const proxies = extraNodes.map((name, i) => ({
        name,
        type: "ss",
        server: `1.1.2.${i + 1}`,
        port: 443
    }));
    const patched = clashJs.replace(/const REGION_MIN_NODES = \d+;/, "const REGION_MIN_NODES = 1;");
    const { main } = loadClashMain(patched);
    const out = main({ proxies });
    const byRegion = new Map(
        out["proxy-groups"]
            .filter(g => g.type === "url-test")
            .map(g => [g.name, g.proxies])
    );
    assert.equal(byRegion.size, 23, "23 个地区应全部建组");
    assert.deepEqual(byRegion.get("ID"), ["Surabaya 01", "印度尼西亚 01"]);
    assert.deepEqual(byRegion.get("IN"), ["New Delhi 01"]);
    assert.deepEqual(byRegion.get("KR"), ["Seoul 01"]);
    assert.deepEqual(byRegion.get("MY"), ["Kuala Lumpur 01"]);
    assert.deepEqual(byRegion.get("BR"), ["São Paulo 01"]);
    assert.ok(!clashJs.includes("circle-flags"), "Clash_rule.js 不应残留 circle-flags");
    for (const g of out["proxy-groups"]) {
        if (g.type === "url-test") {
            assert.equal(
                g.icon,
                `${FLAG_ICON_BASE}/${g.name.toLowerCase()}.png`,
                `Clash 地区组 ${g.name} 图标未使用 circle/128 PNG`
            );
        } else {
            assert.ok(
                g.icon.startsWith("https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color/") &&
                    g.icon.endsWith(".png"),
                `Clash 非地区组 ${g.name} 应保留 Qure PNG 图标`
            );
        }
    }
});


// 6. Concord_rule.js 运行时回归测试
const concordJs = readUtf8("Concord/Concord_rule.js");

// Concord 内核字段白名单（镜像 crates/config/src/keys.rs），脚本输出不得越界
const CONCORD_TOP_ALLOWED = new Set([
    "mixed-port", "port", "socks-port", "allow-lan", "authentication",
    "skip-auth-prefixes", "mode", "log-level", "ipv6", "unified-delay",
    "tcp-concurrent", "find-process-mode", "interface-name", "routing-mark",
    "keep-alive-idle", "keep-alive-interval", "disable-keep-alive", "global-ua",
    "proxies", "proxy-groups", "proxy-providers", "rule-providers", "sub-rules",
    "rules", "dns", "tun", "sniffer", "hosts", "geox-url", "geo-auto-update",
    "geo-update-interval", "geodata-loader", "profile", "redir-port",
    "tproxy-port", "ntp", "experimental", "tls", "mitm"
]);

const CONCORD_DNS_ALLOWED = new Set([
    "enable", "enhanced-mode", "nameserver", "default-nameserver",
    "nameserver-policy", "proxy-server-nameserver", "direct-nameserver",
    "direct-nameserver-follow-policy", "use-hosts", "use-system-hosts",
    "respect-rules", "fake-ip-range", "fake-ip-filter", "fake-ip-filter-mode",
    "fake-ip-ttl", "ipv6", "fallback", "fallback-lazy-query", "fallback-filter",
    "ipv6-timeout", "prefer-h3", "cache-algorithm", "cache-max-size",
    "fake-ip-range6", "proxy-server-nameserver-policy", "listen",
    "listen-routing-mark"
]);

function loadConcordMain() {
    const warnings = [];
    const sandbox = {
        console: {
            warn: (...args) => warnings.push(args.join(" ")),
            log: (...args) => warnings.push(args.join(" "))
        }
    };
    vm.createContext(sandbox);
    vm.runInContext(concordJs, sandbox);
    return {
        main: input => JSON.parse(JSON.stringify(sandbox.main(input))),
        warnings
    };
}

check("concord-runtime: 输出只含 Concord 读取的字段，且不含 T2/未知键", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "香港 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Tokyo 01", type: "trojan", server: "t.1.1.1", port: 443, password: "p" }
        ],
        ipv6: false,
        "external-controller": "127.0.0.1:9090",
        secret: "x",
        "external-ui": "ui",
        "geodata-mode": true,
        "global-client-fingerprint": "chrome",
        "bind-address": "*",
        listeners: [],
        experimental: { "quic-go-disable-ecn": false },
        tls: { certificate: "a" },
        mitm: { enable: true },
        "sub-rules": { a: ["MATCH,DIRECT"] }
    });
    for (const key of Object.keys(out)) {
        assert.ok(CONCORD_TOP_ALLOWED.has(key), "Concord 输出含内核不读取的顶层键: " + key);
    }
    for (const key of Object.keys(out.dns)) {
        assert.ok(CONCORD_DNS_ALLOWED.has(key), "Concord dns 含内核不读取的键: " + key);
    }
});

check("concord-runtime: 剔除不支持的节点类型、传输与插件", () => {
    const { main, warnings } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "香港 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "TS", type: "tailscale", server: "x", port: 1 },
            { name: "OVPN", type: "openvpn", server: "x", port: 1 },
            { name: "KCP", type: "vmess", server: "x", port: 1, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", cipher: "auto", network: "kcp" },
            { name: "Restls", type: "ss", server: "x", port: 1, cipher: "aes-128-gcm", password: "p", plugin: "restls" },
            { name: "TLSMirror", type: "vless", server: "x", port: 1, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", "tlsmirror-opts": {} }
        ]
    });
    const names = out.proxies.map(p => p.name);
    assert.deepEqual(names, ["香港 01"], "不支持的节点应全部剔除，实际: " + names.join(","));
    assert.equal(warnings.length, 0, "默认应完全静默，实际输出: " + warnings.join("; "));
});

check("concord-runtime: 改写废弃指纹并补全 ip-version", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "A", type: "vless", server: "1.1.1.1", port: 443, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", "client-fingerprint": "chrome_psk" },
            { name: "B", type: "vless", server: "1.1.1.2", port: 443, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", "client-fingerprint": "randomized" },
            { name: "C", type: "ss", server: "1.1.1.3", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    });
    const byName = new Map(out.proxies.map(p => [p.name, p]));
    assert.equal(byName.get("A")["client-fingerprint"], "chrome");
    assert.equal(byName.get("B")["client-fingerprint"], "random");
    for (const name of ["A", "B", "C"]) {
        assert.equal(byName.get(name)["ip-version"], "dual", name + " 应补全 ip-version");
    }
});

check("concord-runtime: DNS 全部由脚本生成，不继承订阅的同名段", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }],
        dns: {
            listen: "0.0.0.0:53",
            nameserver: ["ts://bad"],
            "default-nameserver": ["2400:3200::1"],
            "fake-ip-filter": ["geosite:cn"]
        }
    });
    assert.equal(out.dns.listen, undefined, "dns.listen 不应输出");
    for (const server of out.dns["default-nameserver"]) {
        assert.match(server, /^(\d{1,3}\.){3}\d{1,3}$/, "引导 DNS 必须是纯 IP: " + server);
    }
    assert.ok(!out.dns.nameserver.some(ns => ns.startsWith("ts://")), "订阅的非法上游不应进入输出");
    assert.deepEqual(out.dns["nameserver-policy"]["rule-set:ads-domain"], ["rcode://name_error"]);
    assert.equal(out.dns["enhanced-mode"], "fake-ip", "分流依赖 fake-ip 还原域名");
});

check("concord-runtime: tun 只继承开关，hosts 过滤内核不接受的条目", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }],
        tun: { enable: true, stack: "mixed", gso: true, "dns-mode": "hijack", mtu: 9000 },
        hosts: { "router.lan": "192.168.1.1", "bad.lan": "lan", "bad entry": "1.2.3.4" }
    });
    // 栈与 MTU 由客户端按平台决定，脚本只传递开关
    assert.deepEqual(out.tun, { enable: true });
    assert.deepEqual(out.hosts, { "router.lan": "192.168.1.1" });

    const noTun = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }]
    });
    assert.equal(noTun.tun, undefined, "订阅未声明 tun 时不输出该段");
});

check("concord-runtime: 清理悬空 dialer-proxy 与空组兜底", () => {
    const { main, warnings } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "A", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p", "dialer-proxy": "Gone" },
            { name: "B", type: "ss", server: "1.1.1.2", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    });
    assert.equal(out.proxies.find(p => p.name === "A")["dialer-proxy"], undefined);
    assert.equal(warnings.length, 0, "默认应完全静默");

    const empty = main({ proxies: [] });
    const staticGroup = empty["proxy-groups"].find(g => g.name === "静态");
    assert.deepEqual(staticGroup.proxies, ["REJECT"]);
    for (const g of empty["proxy-groups"]) {
        assert.ok(Array.isArray(g.proxies) && g.proxies.length > 0, "组 " + g.name + " 不应为空");
    }
});

check("concord-runtime: 规则与规则集引用完整，MATCH 唯一且最后", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }]
    });
    const providers = new Set(Object.keys(out["rule-providers"]));
    const groups = new Set(out["proxy-groups"].map(g => g.name));
    const builtin = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"]);
    const matches = out.rules.filter(r => r.startsWith("MATCH,"));
    assert.equal(matches.length, 1, "MATCH 必须唯一");
    assert.equal(out.rules[out.rules.length - 1], matches[0], "MATCH 必须是最后一条规则");
    for (const rule of out.rules) {
        const parts = rule.split(",");
        const set = parts.find((p, i) => parts[i - 1] === "RULE-SET");
        if (set) assert.ok(providers.has(set), "规则引用了不存在的规则集: " + set);
        if (rule.startsWith("MATCH,")) continue;
        // 目标之后可能跟 no-resolve / src 等参数
        const params = new Set(["no-resolve", "src"]);
        const tail = parts.filter(part => !params.has(part));
        const target = tail[tail.length - 1];
        assert.ok(groups.has(target) || builtin.has(target), "规则目标不存在: " + target);
    }
});

check("concord-runtime: 被过滤节点上的悬空 dialer-proxy 也会被清理", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p", "dialer-proxy": "Gone" },
            { name: "HK 01", type: "ss", server: "1.1.1.2", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    });
    for (const proxy of out.proxies) {
        assert.equal(proxy["dialer-proxy"], undefined, proxy.name + " 的 dialer-proxy 应被清理");
    }
});

check("concord-runtime: IPv6 默认开启，订阅显式 false 才关闭", () => {
    const { main } = loadConcordMain();
    const on = main({ proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }] });
    assert.equal(on.ipv6, true, "IPv6 应默认开启");
    assert.equal(on.dns.ipv6, true);
    assert.ok(on.dns["fake-ip-range6"], "IPv6 开启时应输出 fake-ip-range6");
    const off = main({ proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }], ipv6: false });
    assert.equal(off.ipv6, false);
    assert.equal(off.dns.ipv6, false);
    assert.equal(off.dns["fake-ip-range6"], undefined);
});

check("concord-runtime: 生成配置只含内核读取的字段，订阅的非分流段不输出", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }],
        mode: "bogus",
        "log-level": "bogus",
        experimental: { fingerprints: { a: "b" }, "quic-go-disable-gso": true },
        tls: { "custom-certifactes": ["c"], certificate: "cert" },
        ntp: { port: "abc", server: "time.apple.com" },
        "geox-url": { mmdb: 123 }
    });
    // 这些段与分流无关，交给客户端默认，不继承订阅值
    assert.equal(out.mode, undefined);
    assert.equal(out["log-level"], undefined);
    assert.equal(out.experimental, undefined);
    assert.equal(out.tls, undefined);
    assert.equal(out.ntp, undefined);
    assert.equal(out["geox-url"], undefined);
});

check("concord-runtime: 订阅 DNS 段不继承，输出为脚本生成", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }],
        dns: {
            "default-nameserver": ["1.2.3.4", "dns.google", "2400:3200::1"],
            nameserver: ["2400:3200::1", "ts://bad"],
            fallback: ["https://8.8.4.4/dns-query"]
        }
    });
    assert.deepEqual(out.dns["default-nameserver"], ["223.5.5.5", "119.29.29.29"], "引导 DNS 由脚本固定");
    assert.equal(out.dns.fallback, undefined, "订阅 fallback 不继承");
    assert.ok(!out.dns.nameserver.some(ns => ns.startsWith("ts://")));
    assert.ok(!out.dns.nameserver.some(ns => ns.includes("2400:3200::1")));
});

check("concord-runtime: 脚本始终静默，不向客户端输出任何日志", () => {
    const { main, warnings } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p", "dialer-proxy": "Gone" },
            { name: "TS", type: "tailscale", server: "x", port: 1 },
            { name: "香港 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" }
        ],
        mode: "bogus",
        dns: {
            nameserver: ["ts://bad", "https://1.1.1.1/dns-query"],
            "default-nameserver": ["not-an-ip", "223.5.5.5"],
            "ipv6-timeout": "abc"
        },
        tun: { enable: true, stack: "bogus", mtu: "abc" }
    });
    // 仍有可用节点时，所有清洗过程保持静默
    assert.equal(warnings.length, 0, "正常可用时不应输出任何日志，实际: " + warnings.join("; "));
    // 不支持的节点被剔除，信息类节点保留在输出中但不进可选组
    assert.deepEqual(out.proxies.map(p => p.name), ["剩余流量：10GB", "香港 01"]);
    assert.equal(out.mode, undefined, "非法值仍应被丢弃");
});

check("concord-runtime: 无可用节点时只提示一次，其余保持静默", () => {
    const { main, warnings } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "TS", type: "tailscale", server: "x", port: 1 }
        ]
    });
    // 配置仍能加载，但必须让用户知道「用不了」及其原因
    assert.equal(warnings.length, 1, "无可用节点时应且仅应提示一次，实际: " + warnings.join("; "));
    assert.ok(warnings[0].includes("没有可用节点"), "提示应说明无可用节点");
    assert.deepEqual(out["proxy-groups"].find(g => g.name === "静态").proxies, ["REJECT"]);

    const empty = main({ proxies: [] });
    assert.equal(warnings.length, 2, "空订阅同样应提示");
    assert.deepEqual(empty["proxy-groups"].find(g => g.name === "静态").proxies, ["REJECT"]);
});

// 7. Concord_rule.js 脏数据清洗回归（镜像内核配置解析期 + 构建期校验）
// 内核行为依据：crates/config/src/proxy/parse.rs（解析期硬错误/隔离）、
// crates/proxy/src/*（构建期 Invalid=整份拒绝 / Unsupported=静默隔离）、
// crates/config/src/hosts.rs、profile.rs（dialer 环/重名）

const CONCORD_OK = { name: "OK", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" };
const concordNames = out => out.proxies.map(p => p.name);
const concordHas = (out, name) => concordNames(out).includes(name);

check("concord-dirty: 解析期硬错误节点全部剔除，不触发整份拒绝", () => {
    const { main, warnings } = loadConcordMain();
    const bad = [
        { name: "D1", type: "ss", server: "x", port: 1 },
        { name: "D2", type: "ss", server: "x", port: "abc", cipher: "c", password: "p" },
        { name: "D3", type: "vmess", server: "x", port: 1, cipher: "auto" },
        { name: "D4", type: "vless", server: "x", port: 1 },
        { name: "D5", type: "trojan", server: "x", port: 1 },
        { name: "D6", type: "hysteria", server: "x", port: 1 },
        { name: "D7", type: "hysteria2", server: "x" },
        { name: "D8", type: "snell", server: "x", port: 1 },
        { name: "D9", type: "mieru", server: "x", port: 1, username: "u", password: "p" },
        { name: "D10", type: "ssh", server: "x", port: 1 },
        { name: "D11", type: "ssr", server: "x", port: 1, password: "p", cipher: "c", protocol: "origin" },
        { name: "D12", type: "wireguard", server: "x", port: 1 },
        { name: "D13", type: "anytls", server: "x", port: 1 },
        { name: "D14", type: "tuic", server: "x", port: 1 },
        { name: "D15", type: "ss", server: "x", port: 1, cipher: "c", password: "p", plugin: "obfs", "plugin-opts": { mode: "bogus" } },
        { name: "D16", type: "vless", server: "x", port: 1, uuid: "u", tls: true, "reality-opts": { "public-key": "short" } },
        { name: "D17", type: "ss", server: "x", port: 1, cipher: "c", password: "p", smux: { enabled: true, protocol: "bogus" } },
        { name: "D18", type: "wireguard", "private-key": "A".repeat(43) + "=", ip: "10.0.0.2", peers: [{ server: "a", port: 1, "public-key": "p" }] },
        { name: "D19", type: "mieru", server: "x", port: 1, "port-range": "1-2", transport: "TCP", username: "u", password: "p" }
    ];
    const out = main({ proxies: [CONCORD_OK, ...bad] });
    assert.deepEqual(concordNames(out), ["OK"], "解析期硬错误节点应全部剔除，实际保留: " + concordNames(out).join(","));
    assert.equal(warnings.length, 0, "剔除过程应保持静默");
});

check("concord-dirty: dialer-proxy 成环断环保节点，自环同样处理", () => {
    const { main } = loadConcordMain();
    const two = main({
        proxies: [
            CONCORD_OK,
            { ...CONCORD_OK, name: "A", server: "1.1.1.2", "dialer-proxy": "B" },
            { ...CONCORD_OK, name: "B", server: "1.1.1.3", "dialer-proxy": "A" }
        ]
    });
    assert.ok(concordHas(two, "A") && concordHas(two, "B"), "环上节点应保留");
    assert.equal(two.proxies.filter(p => p["dialer-proxy"]).length, 0, "环上 dialer-proxy 应全部断开");

    const three = main({
        proxies: [
            CONCORD_OK,
            { ...CONCORD_OK, name: "A", server: "1.1.1.2", "dialer-proxy": "B" },
            { ...CONCORD_OK, name: "B", server: "1.1.1.3", "dialer-proxy": "C" },
            { ...CONCORD_OK, name: "C", server: "1.1.1.4", "dialer-proxy": "A" }
        ]
    });
    assert.equal(three.proxies.filter(p => p["dialer-proxy"]).length, 0, "三节点环应全部断开");

    // 链式引用（无环）不受影响
    const chain = main({
        proxies: [
            CONCORD_OK,
            { ...CONCORD_OK, name: "A", server: "1.1.1.2", "dialer-proxy": "OK" },
            { ...CONCORD_OK, name: "B", server: "1.1.1.3", "dialer-proxy": "A" }
        ]
    });
    assert.equal(chain.proxies.find(p => p.name === "A")["dialer-proxy"], "OK");
    assert.equal(chain.proxies.find(p => p.name === "B")["dialer-proxy"], "A");

    const self = main({
        proxies: [CONCORD_OK, { ...CONCORD_OK, name: "S", server: "1.1.1.2", "dialer-proxy": "S" }]
    });
    assert.ok(concordHas(self, "S"));
    assert.equal(self.proxies.find(p => p.name === "S")["dialer-proxy"], undefined, "自环应断开");
});

check("concord-dirty: 键名与值规范化（大小写/下划线变体）", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            CONCORD_OK,
            // type 大写：规范化为小写后保留
            { ...CONCORD_OK, name: "UP", type: "SS" },
            // 下划线 T2 键：折叠后命中剔除清单
            { name: "UL", type: "vless", server: "x", port: 1, uuid: "u", shadow_tls_opts: { host: "h" } },
            // plugin 大写：规范化后命中剔除清单
            { ...CONCORD_OK, name: "PL", plugin: "Restls" },
            // ws_opts 折叠为 ws-opts 保留
            { name: "WS", type: "vmess", server: "x", port: 1, uuid: "u", cipher: "auto", network: "ws", ws_opts: { path: "/x" } },
            // network 大写 KCP：规范化后命中剔除清单
            { name: "KP", type: "vmess", server: "x", port: 1, uuid: "u", cipher: "auto", network: "KCP" }
        ]
    });
    assert.ok(concordHas(out, "UP"), "大写 type 应规范化保留");
    assert.equal(out.proxies.find(p => p.name === "UP").type, "ss");
    assert.ok(!concordHas(out, "UL"), "下划线 T2 键节点应剔除");
    assert.ok(!concordHas(out, "PL"), "大写 plugin 节点应剔除");
    assert.ok(!concordHas(out, "KP"), "大写 network 节点应剔除");
    const ws = out.proxies.find(p => p.name === "WS");
    assert.ok(ws && ws["ws-opts"] && ws["ws-opts"].path === "/x", "ws_opts 应折叠为 ws-opts 保留");
});

check("concord-dirty: 废弃指纹大小写不敏感改写，且只改 client-fingerprint", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "F1", type: "vless", server: "x", port: 1, uuid: "u", "client-fingerprint": "Chrome_Psk" },
            { name: "F2", type: "vless", server: "x", port: 1, uuid: "u", "client-fingerprint": "RANDOMIZED" },
            { name: "F3", type: "vless", server: "x", port: 1, uuid: "u", "client-fingerprint": "chrome" }
        ]
    });
    const byName = new Map(out.proxies.map(p => [p.name, p]));
    assert.equal(byName.get("F1")["client-fingerprint"], "chrome");
    assert.equal(byName.get("F2")["client-fingerprint"], "random");
    assert.equal(byName.get("F3")["client-fingerprint"], "chrome", "现代名不应被改动");
});

check("concord-dirty: 构建期校验剔除（cipher/flow/版本/带宽等）", () => {
    const { main, warnings } = loadConcordMain();
    const bad = [
        // ss 未知 cipher → 构建期隔离
        { ...CONCORD_OK, name: "K1", cipher: "aes-192-gcm" },
        // ss 2022 密码长度不符 → 构建期硬错误
        { ...CONCORD_OK, name: "K2", cipher: "2022-blake3-aes-128-gcm", password: "AAAA" },
        // ss 2022 EIH 仅 AES：chacha20 冒号密码 → 硬错误
        { ...CONCORD_OK, name: "K3", cipher: "2022-blake3-chacha20-poly1305", password: "A".repeat(43) + ":" + "B".repeat(43) },
        // vless flow 前 16 字节非法 → 硬错误
        { name: "K4", type: "vless", server: "x", port: 1, uuid: "u", flow: "xtls-rprx-bogus!" },
        // vless encryption 非空非 none → 隔离
        { name: "K5", type: "vless", server: "x", port: 1, uuid: "u", encryption: "aes" },
        // vmess cipher 未知 → 硬错误
        { name: "K6", type: "vmess", server: "x", port: 1, uuid: "u", cipher: "bogus" },
        // ssr chacha20 → 隔离；AEAD → 硬错误；未知 obfs → 硬错误
        { name: "K7", type: "ssr", server: "x", port: 1, password: "p", cipher: "chacha20", obfs: "plain", protocol: "origin" },
        { name: "K8", type: "ssr", server: "x", port: 1, password: "p", cipher: "aes-128-gcm", obfs: "plain", protocol: "origin" },
        { name: "K9", type: "ssr", server: "x", port: 1, password: "p", cipher: "none", obfs: "bogus", protocol: "origin" },
        // hysteria faketcp → 隔离；up 不可解析 → 硬错误
        { name: "K10", type: "hysteria", server: "x", port: 1, up: "10", down: "20", protocol: "faketcp" },
        { name: "K11", type: "hysteria", server: "x", port: 1, up: "fast", down: "20" },
        // shadowquic 仅 v2 → 隔离；未知版本串 → 硬错误
        { name: "K12", type: "shadowquic", server: "x", port: 1, "quic-versions": ["v2"] },
        { name: "K13", type: "shadowquic", server: "x", port: 1, "quic-versions": ["v9"] },
        // snell v1+udp / version 越界 → 硬错误
        { name: "K14", type: "snell", server: "x", port: 1, psk: "p", version: 1, udp: true },
        { name: "K15", type: "snell", server: "x", port: 1, psk: "p", version: 9 },
        // fingerprint 填浏览器名 → 构建期硬错误
        { ...CONCORD_OK, name: "K16", fingerprint: "chrome" },
        // REALITY 前提缺失 → 硬错误
        { name: "K17", type: "vless", server: "x", port: 1, uuid: "u", "reality-opts": { "public-key": "A".repeat(43) }, "client-fingerprint": "chrome" },
        { name: "K18", type: "vless", server: "x", port: 1, uuid: "u", tls: true, "reality-opts": { "public-key": "A".repeat(43) } },
        { name: "K19", type: "vless", server: "x", port: 1, uuid: "u", tls: true, network: "ws", "client-fingerprint": "chrome", "reality-opts": { "public-key": "A".repeat(43) } },
        // wireguard reserved 长度错 / 无本地地址 → 硬错误
        { name: "K20", type: "wireguard", server: "x", port: 1, "private-key": "A".repeat(43) + "=", ip: "10.0.0.2", reserved: [1, 2] },
        { name: "K21", type: "wireguard", server: "x", port: 1, "private-key": "A".repeat(43) + "=" },
        // hysteria2 realm 互斥 → 硬错误；obfs 缺密码 → 硬错误
        { name: "K22", type: "hysteria2", server: "x", port: 1, ports: "1000-2000", "realm-opts": { enable: true, "server-url": "https://r" } },
        { name: "K23", type: "hysteria2", server: "x", port: 1, obfs: "salamander" },
        // trojan ss-opts 空密码 → 硬错误；未知 method → 隔离
        { name: "K24", type: "trojan", server: "x", port: 1, password: "p", "ss-opts": { enabled: true, password: "" } },
        { name: "K25", type: "trojan", server: "x", port: 1, password: "p", "ss-opts": { enabled: true, password: "p", method: "bogus" } },
        // tuic 无 token 且 uuid 非法 → 硬错误
        { name: "K26", type: "tuic", server: "x", port: 1, uuid: "not-a-uuid", password: "p" },
        // ssh RSA host-key → 隔离
        { name: "K27", type: "ssh", server: "x", port: 1, username: "u", "host-key": ["ssh-rsa AAAA"] }
    ];
    const out = main({ proxies: [CONCORD_OK, ...bad] });
    assert.deepEqual(concordNames(out), ["OK"], "构建期问题节点应全部剔除，实际保留: " + concordNames(out).join(","));
    assert.equal(warnings.length, 0, "剔除过程应保持静默");
});

check("concord-dirty: 构建期可修复项被修复而非剔除", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            CONCORD_OK,
            // ss 2022 密码正确 → 保留
            { ...CONCORD_OK, name: "G1", cipher: "2022-blake3-aes-128-gcm", password: "AAAAAAAAAAAAAAAAAAAAAA==" },
            // mieru transport 小写 → 规范化为 TCP 保留
            { name: "G2", type: "mieru", server: "x", port: 1, transport: "tcp", username: "u", password: "p" },
            // hysteria2 realm + dialer-proxy → 移除 dialer 保住节点（内核会隔离）
            { name: "G3", type: "hysteria2", server: "x", port: 1, "dialer-proxy": "OK", "realm-opts": { enable: true, "server-url": "https://r" } },
            // shadowquic v1+v2 共存 → 保留
            { name: "G4", type: "shadowquic", server: "x", port: 1, "quic-versions": ["v1", "v2"] },
            // fingerprint 合法 hex → 保留
            { ...CONCORD_OK, name: "G5", fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99" },
            // tuic 合法 uuid → 保留
            { name: "G6", type: "tuic", server: "x", port: 1, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", password: "p" }
        ]
    });
    for (const name of ["G1", "G2", "G3", "G4", "G5", "G6"]) {
        assert.ok(concordHas(out, name), name + " 应保留");
    }
    assert.equal(out.proxies.find(p => p.name === "G2").transport, "TCP");
    assert.equal(out.proxies.find(p => p.name === "G3")["dialer-proxy"], undefined, "realm 节点的 dialer-proxy 应被移除");
});

check("concord-dirty: hosts 非法值与域名映射环被清洗", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [CONCORD_OK],
        hosts: {
            "ok.lan": "192.168.1.1",
            "obj.lan": { a: 1 },
            "null.lan": null,
            "arr.lan": ["1.2.3.4", "lan"],
            "multi.lan": ["1.2.3.4", "5.6.7.8"],
            "alias.lan": ["1.2.3.4", "other.lan"],
            "cyc-a.lan": "cyc-b.lan",
            "cyc-b.lan": "cyc-a.lan",
            "self.lan": "self.lan",
            "chain.lan": "ok.lan",
            "ext.lan": "example.com"
        }
    });
    assert.equal(out.hosts["ok.lan"], "192.168.1.1");
    assert.equal(out.hosts["obj.lan"], undefined, "对象值应剔除");
    assert.equal(out.hosts["null.lan"], undefined, "null 值应剔除");
    assert.equal(out.hosts["arr.lan"], undefined, "数组含 lan 应剔除");
    assert.deepEqual(out.hosts["multi.lan"], ["1.2.3.4", "5.6.7.8"], "多 IP 数组应保留");
    assert.equal(out.hosts["alias.lan"], undefined, "多值含域名应剔除");
    assert.equal(out.hosts["cyc-a.lan"], undefined, "环上条目应剔除");
    assert.equal(out.hosts["cyc-b.lan"], undefined, "环上条目应剔除");
    assert.equal(out.hosts["self.lan"], undefined, "自映射应剔除");
    assert.equal(out.hosts["chain.lan"], "ok.lan", "指向存活条目的别名应保留");
    assert.equal(out.hosts["ext.lan"], "example.com", "指向外部域名的别名应保留");

    // 悬空别名级联删除：环删除后指向环的别名也应删除
    const out2 = main({
        proxies: [CONCORD_OK],
        hosts: { "a.lan": "b.lan", "b.lan": "a.lan", "ref.lan": "a.lan" }
    });
    assert.equal(out2.hosts, undefined, "环与悬空别名全部删除后不应输出 hosts 段");
});

check("concord-dirty: 信息节点同样过校验，残缺信息节点不输出", () => {
    const { main } = loadConcordMain();
    const out = main({
        proxies: [
            CONCORD_OK,
            // 信息节点且字段完整：输出但不进组
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.9", port: 443, cipher: "aes-128-gcm", password: "p" },
            // 信息节点且缺必填：剔除（否则内核解析它时整份拒绝）
            { name: "到期时间：2026-12-31", type: "ss", server: "x", port: 1 }
        ]
    });
    assert.ok(concordHas(out, "剩余流量：10GB"), "完整信息节点应输出");
    assert.ok(!concordHas(out, "到期时间：2026-12-31"), "残缺信息节点应剔除");
    assert.ok(!out["proxy-groups"].find(g => g.name === "静态").proxies.includes("剩余流量：10GB"), "信息节点不进可选组");
});

check("concord-dirty: 规范订阅仍零告警零剔除，输出结构完整", () => {
    const { main, warnings } = loadConcordMain();
    const out = main({
        proxies: [
            { name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "HK 02", type: "trojan", server: "t.example", port: 443, password: "p", sni: "t.example" },
            { name: "JP 01", type: "vmess", server: "j.example", port: 443, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", cipher: "auto", tls: true, servername: "j.example", network: "ws", "ws-opts": { path: "/x" } },
            { name: "US 01", type: "vless", server: "u.example", port: 443, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", tls: true, servername: "u.example", flow: "xtls-rprx-vision", "client-fingerprint": "chrome", "reality-opts": { "public-key": "A".repeat(43), "short-id": "ab" } },
            { name: "SG 01", type: "hysteria2", server: "s.example", port: 443, password: "p", sni: "s.example" },
            { name: "TW 01", type: "wireguard", server: "w.example", port: 51820, "private-key": "A".repeat(43) + "=", "public-key": "B".repeat(43) + "=", ip: "10.0.0.2" }
        ]
    });
    assert.equal(warnings.length, 0, "规范订阅不应有任何日志");
    assert.equal(out.proxies.length, 6, "规范节点应全部保留");
    for (const key of ["proxies", "proxy-groups", "rule-providers", "rules", "dns", "sniffer"]) {
        assert.ok(out[key], "输出应包含 " + key);
    }
});

console.log(`\nSummary: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
