#!/usr/bin/env node
/**
 * 仓库配置静态检查与 Clash / Concord 脚本运行时回归验证脚本（零外部依赖）。
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
    "scripts/verify.mjs",
    ".github/workflows/verify.yml",
    ".github/workflows/check-urls.yml",
    ".gitattributes",
    "LICENSE"
];

const SYNOLOGY_DOMAINS = [
    "gofile.me",
    "quickconnect.to",
    "quickconnect.cn",
    "synology.com",
    "synology.cn",
    "synology.me",
    "synologydownload.com",
    "synologyupdate.com",
    "diskstation.me",
    "dscloud.biz",
    "dscloud.me",
    "dscloud.mobi",
    "dsmynas.com",
    "dsmynas.net",
    "dsmynas.org",
    "familyds.com",
    "familyds.net",
    "familyds.org",
    "i234.me",
    "myds.me"
];

const APPLE_TV_EXACT_DOMAINS = [
    "apple-tv-plus-press.apple.com",
    "hls-amt.itunes.apple.com",
    "hls.itunes.apple.com",
    "np-edge.itunes.apple.com",
    "play-edge.itunes.apple.com",
    "tv.applemusic.com",
    "uts-api.itunes.apple.com"
];

const APPLE_TV_SUFFIX_DOMAIN = "tv.apple.com";

const AWA_ADS_MRS_URL =
    "https://cdn.jsdmirror.com/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.mrs";

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

function extractLineMatch(content, regex, label) {
    const m = content.match(regex);
    assert.ok(m && m[1], `未找到 ${label}`);
    return m[1];
}

function sliceSection(content, startMarker, endMarker, label) {
    const startIdx = content.indexOf(startMarker);
    assert.notEqual(startIdx, -1, `${label}: 未找到起始标记 ${JSON.stringify(startMarker)}`);
    if (endMarker === null || endMarker === undefined) {
        return content.slice(startIdx);
    }
    const endIdx = content.indexOf(endMarker, startIdx + startMarker.length);
    assert.notEqual(endIdx, -1, `${label}: 未找到结束标记 ${JSON.stringify(endMarker)}`);
    return content.slice(startIdx, endIdx);
}

// 1. 编码、换行符与末尾换行检查（UTF-8 无 BOM + LF + EOF LF；LICENSE 免检末尾换行）
const EOF_NEWLINE_EXEMPT = new Set(["LICENSE"]);

check("encoding-and-lf: 全部文件为 UTF-8 无 BOM、LF 换行且末尾含换行符", () => {
    for (const rel of TEXT_FILES) {
        const buf = readRaw(rel);
        assert.ok(
            !(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf),
            `${rel} 包含 UTF-8 BOM`
        );
        const crlfIdx = buf.indexOf(Buffer.from("\r\n"));
        assert.equal(crlfIdx, -1, `${rel} 包含 CRLF（首个偏移 ${crlfIdx}）`);
        if (!EOF_NEWLINE_EXEMPT.has(rel)) {
            assert.ok(buf.length > 0 && buf[buf.length - 1] === 0x0a, `${rel} 缺少末尾 LF 换行符`);
        }
    }
});

// 2. 各端配置文件关键语法与回归检查
const surge = readUtf8("Surge/Surge.conf");
const surfboard = readUtf8("Surfboard/Surfboard.conf");
const loon = readUtf8("Loon/Loon.conf");
const shadowrocket = readUtf8("Shadowrocket/Shadowrocket.conf");
const qx = readUtf8("QuantumultX/QuantumultX.conf");
const stash = readUtf8("Stash/Stash.yaml");
const egern = readUtf8("Egern/Egern.yaml");
const clashJs = readUtf8("Clash/Clash_rule.js");
const concordJs = readUtf8("Concord/Concord_rule.js");

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

function assertInlineSynologyAndAppleTV(ruleSection, client, style = "surge") {
    assert.ok(!ruleSection.includes("Synology.list") && !ruleSection.includes("Synology.yaml"), `${client} 不应引用外部 Synology 规则集`);
    assert.ok(!ruleSection.includes("AppleMedia.list") && !ruleSection.includes("AppleMedia.yaml"), `${client} 不应引用外部 AppleMedia 规则集`);

    if (style === "surge") {
        for (const d of SYNOLOGY_DOMAINS) {
            assert.ok(ruleSection.includes(`DOMAIN-SUFFIX,${d},DIRECT`), `${client} 缺少内联 Synology 域名: ${d}`);
        }
        for (const d of APPLE_TV_EXACT_DOMAINS) {
            assert.ok(ruleSection.includes(`DOMAIN,${d},TV`), `${client} 缺少内联 Apple TV+ 域名: ${d}`);
        }
        assert.ok(ruleSection.includes(`DOMAIN-SUFFIX,${APPLE_TV_SUFFIX_DOMAIN},TV`), `${client} 缺少内联 Apple TV+ 后缀: ${APPLE_TV_SUFFIX_DOMAIN}`);
    } else if (style === "qx") {
        for (const d of SYNOLOGY_DOMAINS) {
            assert.ok(ruleSection.includes(`host-suffix, ${d}, direct`), `${client} 缺少内联 Synology 域名: ${d}`);
        }
        for (const d of APPLE_TV_EXACT_DOMAINS) {
            assert.ok(ruleSection.includes(`host, ${d}, TV`), `${client} 缺少内联 Apple TV+ 域名: ${d}`);
        }
        assert.ok(ruleSection.includes(`host-suffix, ${APPLE_TV_SUFFIX_DOMAIN}, TV`), `${client} 缺少内联 Apple TV+ 后缀: ${APPLE_TV_SUFFIX_DOMAIN}`);
    } else if (style === "egern") {
        for (const d of SYNOLOGY_DOMAINS) {
            assert.match(
                ruleSection,
                new RegExp(`- domain_suffix:\\n\\s+match: ${d.replace(/\./g, "\\.")}\\n\\s+policy: DIRECT`),
                `${client} 缺少内联 Synology 域名: ${d}`
            );
        }
        for (const d of APPLE_TV_EXACT_DOMAINS) {
            assert.match(
                ruleSection,
                new RegExp(`- domain:\\n\\s+match: ${d.replace(/\./g, "\\.")}\\n\\s+policy: TV`),
                `${client} 缺少内联 Apple TV+ 域名: ${d}`
            );
        }
        assert.match(
            ruleSection,
            new RegExp(`- domain_suffix:\\n\\s+match: ${APPLE_TV_SUFFIX_DOMAIN.replace(/\./g, "\\.")}\\n\\s+policy: TV`),
            `${client} 缺少内联 Apple TV+ 后缀: ${APPLE_TV_SUFFIX_DOMAIN}`
        );
    }
}

function assertGithubBeforeAI(section, client) {
    const ghIdx = section.indexOf("Github.");
    const aiIdx = section.indexOf("AI.");
    assert.notEqual(ghIdx, -1, `${client} 缺少 Github 规则集`);
    assert.notEqual(aiIdx, -1, `${client} 缺少 AI 规则集`);
    assert.ok(ghIdx < aiIdx, `${client} Github 规则集应位于 AI 规则集之前`);
}

check("surge: 无引号 policy-regex-filter、HTTP 测速、[Host]、内置 LAN/SYSTEM、内联规则与 circle/128 图标", () => {
    assert.match(surge, /^FINAL,兜底,dns-failed$/m);
    assert.match(surge, /^proxy-test-url = http:\/\/www\.gstatic\.com\/generate_204$/m);
    assert.match(surge, /^encrypted-dns-server = https:\/\/223\.5\.5\.5\/dns-query, https:\/\/1\.12\.12\.12\/dns-query$/m);
    assert.match(surge, /^skip-proxy = .*127\.0\.0\.1, ::1/m);

    const hostSection = sliceSection(surge, "\n[Host]\n", "\n[Proxy Group]\n", "Surge [Host]");
    assert.match(hostSection, /^\*\.lan = server:system$/m);
    assert.match(hostSection, /^\*\.home\.arpa = server:system$/m);
    assert.match(hostSection, /^\*\.home = server:system$/m);

    assert.ok(!surge.includes('policy-regex-filter="'), "Surge policy-regex-filter 不应带双引号");
    const unquotedFilters = surge.match(/policy-regex-filter=\(\?i\)/g) || [];
    assert.equal(unquotedFilters.length, 6, "Surge 应有 6 个未加引号的 policy-regex-filter");

    const ruleSection = sliceSection(surge, "\n[Rule]\n", null, "Surge [Rule]");
    assert.match(ruleSection, /^RULE-SET,SYSTEM,DIRECT$/m);
    assert.match(ruleSection, /^RULE-SET,LAN,DIRECT,no-resolve$/m);
    assert.ok(!ruleSection.includes("Lan.list"), "Surge 不应再引用远程 Lan.list");
    assert.match(ruleSection, /Reject\.list,REJECT,pre-matching,extended-matching,update-interval=604800$/m);
    assert.match(ruleSection, /ChinaIP\.list,DIRECT,update-interval=604800$/m);
    assert.ok(!/ChinaIP\.list,.*extended-matching/m.test(ruleSection), "Surge ChinaIP.list 不应添加 extended-matching");
    const extMatches = ruleSection.match(/,extended-matching,/g) || [];
    assert.equal(extMatches.length, 19, "Surge 19 条远程域名/服务规则集应开启 extended-matching");
    assertGithubBeforeAI(ruleSection, "Surge");
    assertInlineSynologyAndAppleTV(ruleSection, "Surge", "surge");
    assertCirclePngFlags(surge, "Surge");
});

check("surfboard: 移除 icon-url、HTTP url-test、[Host]、内联 LAN/Synology/Apple TV+ 与 Github 顺序", () => {
    assert.match(surfboard, /^FINAL,兜底$/m);
    assert.ok(!surfboard.includes("dns-failed"), "Surfboard 不应包含 dns-failed");
    assert.ok(!surfboard.includes("icon-url"), "Surfboard 不应包含无效的 icon-url");
    assert.match(surfboard, /^proxy-test-url = http:\/\/www\.gstatic\.com\/generate_204$/m);
    assert.match(surfboard, /^test-timeout = 5$/m);

    const hostSection = sliceSection(surfboard, "\n[Host]\n", "\n[Proxy Group]\n", "Surfboard [Host]");
    for (const pat of ["*.lan", "*.local", "*.home.arpa", "*.home"]) {
        assert.ok(hostSection.includes(`${pat} = server:system`), `Surfboard [Host] 缺少 ${pat}`);
    }

    const groupSection = sliceSection(surfboard, "\n[Proxy Group]\n", "\n[Rule]\n", "Surfboard [Proxy Group]");
    const httpUrlTests = groupSection.match(/url=http:\/\/www\.gstatic\.com\/generate_204/g) || [];
    assert.equal(httpUrlTests.length, 5, "Surfboard 5 个地区 url-test 组均应使用 http:// 测速地址");

    const ruleSection = sliceSection(surfboard, "\n[Rule]\n", null, "Surfboard [Rule]");
    assert.ok(!ruleSection.includes("Lan.list"), "Surfboard 不应再引用远程 Lan.list");
    assert.ok(ruleSection.includes("DOMAIN-SUFFIX,local,DIRECT"));
    assert.ok(ruleSection.includes("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"));
    assert.ok(ruleSection.includes("IP-CIDR6,fe80::/10,DIRECT,no-resolve"));
    assertGithubBeforeAI(ruleSection, "Surfboard");
    assertInlineSynologyAndAppleTV(ruleSection, "Surfboard", "surge");
});

check("loon: 无 hidden=true、tag= 补全、SNI/hijack-dns、内联规则、Github 顺序与 circle/128 图标", () => {
    assert.match(loon, /^FINAL,兜底$/m);
    assert.ok(!loon.includes("dns-failed"), "Loon 不应包含 dns-failed");
    assert.ok(!loon.includes("hidden=true"), "Loon 不支持隐藏策略组，不应包含 hidden=true");
    assert.match(loon, /^sni-sniffing = true$/m);
    assert.match(loon, /^hijack-dns = \*:53$/m);
    assert.match(loon, /^disconnect-on-policy-change = true$/m);
    assert.match(loon, /^proxy-test-url = http:\/\/www\.gstatic\.com\/generate_204$/m);
    assert.match(loon, /^doh-server = https:\/\/223\.5\.5\.5\/dns-query, https:\/\/1\.12\.12\.12\/dns-query$/m);

    const groupSection = sliceSection(loon, "\n[Proxy Group]\n", "\n[Rule]\n", "Loon [Proxy Group]");
    const httpUrlTests = groupSection.match(/url=http:\/\/www\.gstatic\.com\/generate_204/g) || [];
    assert.equal(httpUrlTests.length, 5, "Loon 5 个地区 url-test 组均应使用 http:// 测速地址");

    const localRuleSection = sliceSection(loon, "\n[Rule]\n", "\n[Remote Rule]\n", "Loon [Rule]");
    assertInlineSynologyAndAppleTV(localRuleSection, "Loon", "surge");
    assert.ok(
        localRuleSection.indexOf("DOMAIN-SUFFIX,tv.apple.com,TV") < localRuleSection.indexOf("FINAL,兜底"),
        "Loon 内联规则须位于 FINAL,兜底 之前"
    );

    const remoteRuleSection = sliceSection(loon, "\n[Remote Rule]\n", null, "Loon [Remote Rule]");
    const remoteLines = remoteRuleSection
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#") && !l.startsWith("["));
    assert.ok(remoteLines.length >= 20, "Loon [Remote Rule] 条目数量异常");
    for (const line of remoteLines) {
        assert.match(line, /,tag=[^,]+,/, `Loon [Remote Rule] 缺少 tag=: ${line}`);
    }
    assert.ok(!remoteRuleSection.includes("Synology.list"), "Loon [Remote Rule] 不应残留 Synology.list");
    assert.ok(!remoteRuleSection.includes("AppleMedia.list"), "Loon [Remote Rule] 不应残留 AppleMedia.list");
    assertGithubBeforeAI(remoteRuleSection, "Loon");
    assertCirclePngFlags(loon, "Loon");
});

check("shadowrocket: private-ip-answer、block-quic、[Host]、无引号 filter、DST-PORT、内联规则与 Github 顺序", () => {
    assert.match(shadowrocket, /^FINAL,兜底$/m);
    assert.ok(!shadowrocket.includes("dns-failed"), "Shadowrocket 不应包含 dns-failed");
    assert.match(shadowrocket, /^private-ip-answer = true$/m);
    assert.match(shadowrocket, /^block-quic = all-proxy$/m);
    assert.match(shadowrocket, /^icmp-auto-reply = true$/m);
    assert.match(shadowrocket, /^hijack-dns = 8\.8\.8\.8:53, 8\.8\.4\.4:53$/m);
    assert.match(shadowrocket, /^dns-server = https:\/\/223\.5\.5\.5\/dns-query, https:\/\/1\.12\.12\.12\/dns-query, 223\.5\.5\.5, 119\.29\.29\.29$/m);

    const hostSection = sliceSection(shadowrocket, "\n[Host]\n", "\n[Proxy Group]\n", "Shadowrocket [Host]");
    for (const pat of ["*.lan", "*.local", "*.home.arpa", "*.home"]) {
        assert.ok(hostSection.includes(`${pat} = server:system`), `Shadowrocket [Host] 缺少 ${pat}`);
    }

    assert.ok(
        !shadowrocket.includes('policy-regex-filter="'),
        "Shadowrocket policy-regex-filter 不应带双引号"
    );
    const filterMatches = shadowrocket.match(/policy-regex-filter=\(\?i\)/g) || [];
    assert.equal(filterMatches.length, 20, "Shadowrocket 应有 20 个未加引号的 policy-regex-filter");
    const httpUrlTests = shadowrocket.match(/url=http:\/\/www\.gstatic\.com\/generate_204/g) || [];
    assert.equal(httpUrlTests.length, 5, "Shadowrocket 5 个地区 url-test 组均应使用 http:// 测速地址");

    const ruleSection = sliceSection(shadowrocket, "\n[Rule]\n", null, "Shadowrocket [Rule]");
    assert.ok(ruleSection.includes("AND,((DST-PORT,123),(PROTOCOL,UDP)),DIRECT"));
    assert.ok(!ruleSection.includes("DEST-PORT"), "Shadowrocket 不应残留 DEST-PORT");
    assert.ok(!ruleSection.includes("Lan.list"), "Shadowrocket 不应再引用远程 Lan.list");
    assert.ok(ruleSection.includes("DOMAIN-SUFFIX,local,DIRECT"));
    assert.ok(ruleSection.includes("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"));
    assertGithubBeforeAI(ruleSection, "Shadowrocket");
    assertInlineSynologyAndAppleTV(ruleSection, "Shadowrocket", "surge");
});

check("quantumultx: resource_parser_url、无 hidden=1、LAN DNS、excluded_routes、无 no-resolve 与内联规则", () => {
    const generalSection = sliceSection(qx, "\n[general]\n", "\n[dns]\n", "QX [general]");
    assert.match(
        generalSection,
        /^resource_parser_url = https:\/\/cdn\.jsdmirror\.com\/gh\/KOP-XIAO\/QuantumultX@master\/Scripts\/resource-parser\.js$/m
    );
    assert.match(generalSection, /^excluded_routes = .*127\.0\.0\.0\/8/m);
    assert.match(generalSection, /^dns_exclusion_list = .*\*\.cmpassport\.com/m);

    const dnsSection = sliceSection(qx, "\n[dns]\n", "\n[server_remote]\n", "QX [dns]");
    assert.match(
        dnsSection,
        /^doh-server = https:\/\/223\.5\.5\.5\/dns-query, https:\/\/1\.12\.12\.12\/dns-query$/m
    );
    for (const pat of ["*.lan", "*.local", "*.home.arpa", "*.home"]) {
        assert.ok(dnsSection.includes(`server = /${pat}/system`), `QX [dns] 缺少局域网系统解析: ${pat}`);
    }
    const serverLines = dnsSection.split("\n").map(l => l.trim()).filter(l => /^server\s*=/.test(l));
    for (const line of serverLines) {
        assert.match(line, /^server = \/[^/]+\/system$/, `QX [dns] 不应保留会被 doh-server 覆盖的全局 server=: ${line}`);
    }

    assert.ok(!qx.includes("hidden=1"), "QX 不支持隐藏策略组，不应包含 hidden=1");
    assertCirclePngFlags(qx, "QX");

    const filterRemote = sliceSection(qx, "\n[filter_remote]\n", "\n[filter_local]\n", "QX [filter_remote]");
    assert.ok(!filterRemote.includes("Synology.list"), "QX [filter_remote] 不应残留 Synology.list");
    assert.ok(!filterRemote.includes("AppleMedia.list"), "QX [filter_remote] 不应残留 AppleMedia.list");
    assertGithubBeforeAI(filterRemote, "QX");

    const filterLocal = sliceSection(qx, "\n[filter_local]\n", null, "QX [filter_local]");
    assert.ok(!/,\s*no-resolve\b/i.test(filterLocal), "QX [filter_local] 不应包含无效的 no-resolve 参数");
    assert.match(filterLocal, /^host, time\.apple\.com, direct$/m, "QX 应有对时域名本地直连规则");
    assert.match(filterLocal, /^host-suffix, ntp\.org, direct$/m);
    assertInlineSynologyAndAppleTV(filterLocal, "QX", "qx");
    assert.ok(
        filterLocal.indexOf("host, time.apple.com, direct") < filterLocal.indexOf("final, 兜底"),
        "对时直连规则须位于 final 之前"
    );
    assert.ok(
        filterLocal.indexOf("host-suffix, tv.apple.com, TV") < filterLocal.indexOf("final, 兜底"),
        "内联 Apple TV+ 规则须位于 final 之前"
    );
});

check("stash: HTTP benchmark-url、移除 sniffer、AWAvenue .mrs、REJECT-DROP,no-track、cn-ip no-resolve 与图标", () => {
    assert.match(stash, /^\s{4}benchmark-url:\s*http:\/\/www\.gstatic\.com\/generate_204$/m);
    assert.match(stash, /^\s{4}benchmark-timeout:\s*5$/m);
    assert.ok(!/^sniffer:/m.test(stash), "Stash 不应包含 Mihomo 专用的 sniffer: 块");

    const dnsBlock = sliceSection(stash, "\ndns:\n", "\nproxy-groups:\n", "Stash dns:");
    assert.ok(!/^\s+enable:/m.test(dnsBlock), "Stash dns 不应包含 enable");
    assert.ok(!/^\s+enhanced-mode:/m.test(dnsBlock), "Stash dns 不应包含 enhanced-mode");
    assert.ok(!/^\s+ipv6:/m.test(dnsBlock), "Stash dns 不应包含 ipv6");
    assert.ok(dnsBlock.includes("https://223.5.5.5/dns-query"), "Stash dns 应使用 223.5.5.5 IP-DoH");
    assert.ok(dnsBlock.includes("https://1.12.12.12/dns-query"), "Stash dns 应使用 1.12.12.12 IP-DoH");

    const groupsBlock = sliceSection(stash, "\nproxy-groups:\n", "\nrule-providers:\n", "Stash proxy-groups:");
    assert.ok(!/^\s+url:/m.test(groupsBlock), "Stash url-test 组应由 provider benchmark-url 统一测速，不应冗余配置 url:");

    const providersBlock = sliceSection(stash, "\nrule-providers:\n", "\nrules:\n", "Stash rule-providers:");
    assert.ok(providersBlock.includes(`url: "${AWA_ADS_MRS_URL}"`), "Stash ads-domain 应使用 AWAvenue-Ads-Rule-Clash.mrs");

    const rulesBlock = sliceSection(stash, "\nrules:\n", null, "Stash rules:");
    assert.ok(!/^\s*-\s+.*pre-matching/m.test(rulesBlock), "Stash 默认规则不应开启 beta 的 pre-matching");
    assert.match(rulesBlock, /^\s+-\s+RULE-SET,ads-domain,REJECT-DROP,no-track$/m);
    assert.match(rulesBlock, /^\s+-\s+RULE-SET,telegram-ip,Telegram,no-resolve$/m);
    assert.match(rulesBlock, /^\s+-\s+RULE-SET,cn-ip,DIRECT,no-resolve$/m);
    assertCirclePngFlags(stash, "Stash");
});

check("egern: YAML 1.2 锚点直选节点、内联 LAN/Synology/Apple TV+、geoip: CN、海外 DoH 规则与图标", () => {
    assert.match(egern, /^close_connections_on_policy_change:\s*true$/m);
    const groupsBlock = sliceSection(egern, "\npolicy_groups:\n", "\nrules:\n", "Egern policy_groups:");
    const businessGroups = groupsBlock.match(
        /policies:\s*\[主代理, DIRECT, HK, JP, SG, TW, US\]\n\s+urls:\s*\*sub_urls\n\s+filter:\s*\*exclude_filter/g
    ) || [];
    assert.equal(businessGroups.length, 14, "Egern 13 业务组 + 兜底组应全部使用 policies + *sub_urls + *exclude_filter");
    assert.ok(groupsBlock.includes("urls: &sub_urls"), "Egern 应定义 &sub_urls 锚点");
    assert.ok(groupsBlock.includes("filter: &exclude_filter "), "Egern 应定义 &exclude_filter 锚点");
    assertCirclePngFlags(egern, "Egern");

    const rulesBlock = sliceSection(egern, "\nrules:\n", null, "Egern rules:");
    assert.ok(!rulesBlock.includes("Lan.yaml"), "Egern 不应再引用远程 Lan.yaml");
    assert.ok(!rulesBlock.includes("ChinaIP.yaml"), "Egern 应使用原生 geoip: CN，不应再引用 ChinaIP.yaml");
    assert.match(rulesBlock, /- ip_cidr:\n\s+match: 1\.1\.1\.1\/32\n\s+policy: 主代理\n\s+no_resolve: true/);
    assert.match(rulesBlock, /- ip_cidr:\n\s+match: 8\.8\.8\.8\/32\n\s+policy: 主代理\n\s+no_resolve: true/);
    assert.match(rulesBlock, /- geoip:\n\s+match: CN\n\s+policy: DIRECT\n\s+no_resolve: true/);
    assertGithubBeforeAI(rulesBlock, "Egern");
    assertInlineSynologyAndAppleTV(rulesBlock, "Egern", "egern");
});

check("egern: DNS 国内外拆分——Reject DNS 拦截、block_ips、国内 DoH、海外经代理、节点解析直连", () => {
    const dnsBlock = sliceSection(egern, "\ndns:\n", "\nproxies: []\n", "Egern dns:");
    assert.ok(dnsBlock.includes("block_ips:"), "Egern dns 应配置 block_ips 防污染回环响应");
    assert.ok(dnsBlock.includes("proxy_nameservers:"), "应配置 proxy_nameservers 固定节点解析，避免循环依赖");
    assert.ok(dnsBlock.includes("https://1.1.1.1/dns-query"), "应配置海外 DoH 上游");
    assert.match(
        dnsBlock,
        /proxy_rule_set:\n\s+match: "https:\/\/cdn\.jsdmirror\.com\/gh\/Repcz\/Tool@X\/Egern\/Rules\/Reject\.yaml"\n\s+value: reject/,
        "Egern dns.forward 应通过 Reject.yaml 在 DNS 层拦截广告"
    );
    assert.match(
        dnsBlock,
        /proxy_rule_set:\n\s+match: "https:\/\/cdn\.jsdmirror\.com\/gh\/Repcz\/Tool@X\/Egern\/Rules\/ChinaDomain\.yaml"\n\s+value: china/,
        "国内域名应按规则集拆分到国内上游"
    );
    assert.match(dnsBlock, /match: "\*"\n\s+value: foreign/, "兜底转发应指向海外上游组");
    assert.ok(!/match: "\*"\n\s+value: china/.test(dnsBlock), "不应把全部域名转发到国内上游");
});

// 2b. YAML 基础结构校验（Stash.yaml / Egern.yaml）
check("yaml-structure: Stash.yaml 与 Egern.yaml 无制表符、无重复顶层键且锚点/别名解析有效", () => {
    for (const [name, content] of [["Stash.yaml", stash], ["Egern.yaml", egern]]) {
        assert.ok(!content.includes("\t"), `${name} 不应包含 Tab 制表符`);

        const topKeys = new Set();
        const anchors = new Set();
        const aliasCounts = new Map();

        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (!line.trim() || /^\s*#/.test(line)) continue;

            const topMatch = /^([A-Za-z0-9_-]+):/.exec(line);
            if (topMatch) {
                const key = topMatch[1];
                assert.ok(!topKeys.has(key), `${name}:${i + 1} 存在重复顶层键: ${key}`);
                topKeys.add(key);
            }

            // 解析锚点定义 (&name) 与别名引用 (*name)，避开引号内的字面量与注释
            const anchorMatch = /:\s+&([A-Za-z0-9_-]+)(?:\s|$)/.exec(line);
            if (anchorMatch) {
                assert.ok(!anchors.has(anchorMatch[1]), `${name}:${i + 1} 重复定义锚点: &${anchorMatch[1]}`);
                anchors.add(anchorMatch[1]);
            }
            const aliasMatch = /:\s+\*([A-Za-z0-9_-]+)\s*$/.exec(line);
            if (aliasMatch) {
                const alias = aliasMatch[1];
                assert.ok(anchors.has(alias), `${name}:${i + 1} 引用了未定义或尚未声明的锚点: *${alias}`);
                aliasCounts.set(alias, (aliasCounts.get(alias) || 0) + 1);
            }
        }

        if (name === "Egern.yaml") {
            assert.equal(aliasCounts.get("sub_urls"), 14, "Egern.yaml 应有 14 处 *sub_urls 引用");
            assert.equal(aliasCounts.get("exclude_filter"), 14, "Egern.yaml 应有 14 处 *exclude_filter 引用");
        }
    }
});

// 2c. 7 端静态配置策略组/规则集交叉引用完整性检查
check("static-cross-references: 7 端静态配置规则目标与规则集引用均完整无悬空", () => {
    const surgeBuiltins = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-NO-DROP"]);
    const surgeRuleOptions = new Set(["no-resolve", "pre-matching", "extended-matching", "dns-failed", "force-remote-dns"]);

    function checkIniStyleClient(content, client) {
        const groupSec = sliceSection(content, "\n[Proxy Group]\n", "\n[Rule]\n", `${client} [Proxy Group]`);
        const definedGroups = new Set();
        for (const rawLine of groupSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            const eq = line.indexOf("=");
            assert.notEqual(eq, -1, `${client} [Proxy Group] 行缺少 '=': ${line}`);
            definedGroups.add(line.slice(0, eq).trim());
        }
        assert.ok(definedGroups.has("主代理") && definedGroups.has("静态") && definedGroups.has("兜底"), `${client} 缺少核心策略组`);

        // 检查 include-other-group 引用
        for (const m of groupSec.matchAll(/include-other-group="([^"]+)"/g)) {
            assert.ok(definedGroups.has(m[1]), `${client} include-other-group 引用了不存在的组: ${m[1]}`);
        }

        const ruleSec = sliceSection(content, "\n[Rule]\n", null, `${client} [Rule]`);
        const ruleLines = ruleSec.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#") && !l.startsWith("["));
        assert.ok(ruleLines[ruleLines.length - 1].startsWith("FINAL,"), `${client} 最后一条规则须为 FINAL`);

        for (const line of ruleLines) {
            const parts = line.split(",").map(p => p.trim());
            const filtered = parts.filter(p => !surgeRuleOptions.has(p) && !p.startsWith("update-interval="));
            const target = filtered[filtered.length - 1];
            assert.ok(
                definedGroups.has(target) || surgeBuiltins.has(target),
                `${client} 规则目标不存在: ${target} (${line})`
            );
        }
    }

    checkIniStyleClient(surge, "Surge");
    checkIniStyleClient(surfboard, "Surfboard");
    checkIniStyleClient(shadowrocket, "Shadowrocket");

    // Loon
    {
        const filterSec = sliceSection(loon, "\n[Remote Filter]\n", "\n[Proxy Group]\n", "Loon [Remote Filter]");
        const definedFilters = new Set();
        for (const rawLine of filterSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            definedFilters.add(line.slice(0, line.indexOf("=")).trim());
        }

        const groupSec = sliceSection(loon, "\n[Proxy Group]\n", "\n[Rule]\n", "Loon [Proxy Group]");
        const definedGroups = new Set();
        for (const rawLine of groupSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            definedGroups.add(line.slice(0, line.indexOf("=")).trim());
        }
        for (const rawLine of groupSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            const rhs = line.slice(line.indexOf("=") + 1).trim();
            const tokens = rhs.split(",").map(t => t.trim());
            for (const tok of tokens.slice(1)) {
                if (tok.includes("=")) continue;
                assert.ok(
                    definedGroups.has(tok) || definedFilters.has(tok) || surgeBuiltins.has(tok),
                    `Loon [Proxy Group] 引用了不存在的策略/过滤器: ${tok} (${line})`
                );
            }
        }

        const localRuleSec = sliceSection(loon, "\n[Rule]\n", "\n[Remote Rule]\n", "Loon [Rule]");
        for (const rawLine of localRuleSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            const parts = line.split(",").map(p => p.trim()).filter(p => p !== "no-resolve");
            const target = parts[parts.length - 1];
            assert.ok(definedGroups.has(target) || surgeBuiltins.has(target), `Loon [Rule] 目标不存在: ${target}`);
        }

        const remoteRuleSec = sliceSection(loon, "\n[Remote Rule]\n", null, "Loon [Remote Rule]");
        for (const rawLine of remoteRuleSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith("[")) continue;
            const m = /,policy=([^,]+),/.exec(line);
            assert.ok(m, `Loon [Remote Rule] 缺少 policy=: ${line}`);
            assert.ok(definedGroups.has(m[1]) || surgeBuiltins.has(m[1]), `Loon [Remote Rule] policy 不存在: ${m[1]}`);
        }
    }

    // Quantumult X
    {
        const qxBuiltins = new Set(["direct", "reject", "proxy"]);
        const policySec = sliceSection(qx, "\n[policy]\n", "\n[filter_remote]\n", "QX [policy]");
        const definedPolicies = new Set();
        for (const rawLine of policySec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith(";") || line.startsWith("[")) continue;
            const m = /^(?:static|url-latency-benchmark)\s*=\s*([^,]+),/.exec(line);
            assert.ok(m, `QX [policy] 行格式异常: ${line}`);
            definedPolicies.add(m[1].trim());
        }

        const remoteSec = sliceSection(qx, "\n[filter_remote]\n", "\n[filter_local]\n", "QX [filter_remote]");
        for (const rawLine of remoteSec.split("\n")) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#") || line.startsWith(";") || line.startsWith("[")) continue;
            const m = /force-policy=([^,\s]+)/.exec(line);
            assert.ok(m, `QX [filter_remote] 缺少 force-policy=: ${line}`);
            assert.ok(definedPolicies.has(m[1]) || qxBuiltins.has(m[1]), `QX [filter_remote] 目标不存在: ${m[1]}`);
        }

        const localSec = sliceSection(qx, "\n[filter_local]\n", null, "QX [filter_local]");
        const localLines = localSec.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#") && !l.startsWith(";") && !l.startsWith("["));
        assert.equal(localLines[localLines.length - 1], "final, 兜底", "QX [filter_local] 末行应为 final, 兜底");
        for (const line of localLines) {
            const parts = line.split(",").map(p => p.trim());
            const target = parts[parts.length - 1];
            assert.ok(definedPolicies.has(target) || qxBuiltins.has(target), `QX [filter_local] 目标不存在: ${target} (${line})`);
        }
    }

    // Stash
    {
        const stashBuiltins = new Set(["DIRECT", "REJECT", "REJECT-DROP"]);
        const stashRuleOpts = new Set(["no-resolve", "no-track", "pre-matching"]);

        const ppSec = sliceSection(stash, "\nproxy-providers:\n", "\ndns:\n", "Stash proxy-providers:");
        const proxyProviders = new Set([...ppSec.matchAll(/^  ([A-Za-z0-9_-]+):$/gm)].map(m => m[1]));

        const groupsSec = sliceSection(stash, "\nproxy-groups:\n", "\nrule-providers:\n", "Stash proxy-groups:");
        const definedGroups = new Set([...groupsSec.matchAll(/^  - name:\s*(.+)$/gm)].map(m => m[1].trim()));
        for (const m of groupsSec.matchAll(/^\s+use:\s*\[([^\]]+)\]/gm)) {
            for (const p of m[1].split(",").map(s => s.trim())) {
                assert.ok(proxyProviders.has(p), `Stash proxy-groups 引用了不存在的 proxy-provider: ${p}`);
            }
        }
        for (const m of groupsSec.matchAll(/^\s+proxies:\s*\[([^\]]+)\]/gm)) {
            for (const p of m[1].split(",").map(s => s.trim())) {
                assert.ok(definedGroups.has(p) || stashBuiltins.has(p), `Stash proxy-groups 引用了不存在的成员: ${p}`);
            }
        }

        const rpSec = sliceSection(stash, "\nrule-providers:\n", "\nrules:\n", "Stash rule-providers:");
        const ruleProviders = new Set([...rpSec.matchAll(/^  ([A-Za-z0-9_-]+):$/gm)].map(m => m[1]));

        const dnsSec = sliceSection(stash, "\ndns:\n", "\nproxy-groups:\n", "Stash dns:");
        for (const m of dnsSec.matchAll(/rule-set:([A-Za-z0-9_-]+)/g)) {
            assert.ok(ruleProviders.has(m[1]), `Stash dns 引用了不存在的 rule-provider: ${m[1]}`);
        }

        const rulesSec = sliceSection(stash, "\nrules:\n", null, "Stash rules:");
        const ruleLines = [...rulesSec.matchAll(/^\s+-\s+(.+)$/gm)].map(m => m[1].trim());
        assert.equal(ruleLines[ruleLines.length - 1], "MATCH,兜底", "Stash 末条规则应为 MATCH,兜底");
        for (const rule of ruleLines) {
            const parts = rule.split(",").map(p => p.trim());
            if (parts[0] === "RULE-SET") {
                assert.ok(ruleProviders.has(parts[1]), `Stash rules 引用了不存在的 rule-provider: ${parts[1]}`);
            }
            const tail = parts.filter(p => !stashRuleOpts.has(p));
            const target = tail[tail.length - 1];
            assert.ok(definedGroups.has(target) || stashBuiltins.has(target), `Stash rule 目标不存在: ${target} (${rule})`);
        }
    }

    // Egern
    {
        const egernBuiltins = new Set(["DIRECT", "REJECT", "REJECT_DROP"]);
        const groupsSec = sliceSection(egern, "\npolicy_groups:\n", "\nrules:\n", "Egern policy_groups:");
        const definedGroups = new Set([...groupsSec.matchAll(/^\s+name:\s*(.+)$/gm)].map(m => m[1].trim()));
        for (const m of groupsSec.matchAll(/^\s+policies:\s*\[([^\]]+)\]/gm)) {
            for (const p of m[1].split(",").map(s => s.trim())) {
                assert.ok(definedGroups.has(p) || egernBuiltins.has(p), `Egern policy_groups 引用了不存在的策略: ${p}`);
            }
        }

        const rulesSec = sliceSection(egern, "\nrules:\n", null, "Egern rules:");
        const targets = [...rulesSec.matchAll(/^\s+policy:\s*(.+)$/gm)].map(m => m[1].trim());
        assert.ok(targets.length > 30, "Egern rules 数量异常");
        for (const target of targets) {
            assert.ok(definedGroups.has(target) || egernBuiltins.has(target), `Egern rules 目标不存在: ${target}`);
        }
        assert.match(rulesSec.trimEnd(), /- default:\n\s+policy: 兜底$/, "Egern 末条规则应为 default -> 兜底");
    }
});

// 3. README 与 GitHub Actions 工作流一致性检查
check("readmes: 根目录与各端 README 版本及特性描述准确", () => {
    const rootReadme = readUtf8("README.md");
    assert.ok(!rootReadme.includes("Clash / Stash 仅分流 Apple TV+"), "根 README 不应残留旧 Apple TV+ 差异说明");
    assert.ok(!rootReadme.includes("Apple 媒体服务"), "根 README TV 说明应统一为 Apple TV+");
    assert.ok(rootReadme.includes("Apple TV+"), "根 README 应注明 Apple TV+");
    assert.ok(
        rootReadme.indexOf("地区测速组") < rootReadme.indexOf("├─ 静态"),
        "根 README 主代理层级应先展示地区测速组再展示静态"
    );
    assert.ok(rootReadme.includes("Loon 与 Quantumult X 不支持隐藏"), "根 README 应注明 Loon/QX 不支持隐藏地区组");
    assert.ok(rootReadme.includes("[filter_local]"), "根 README 应注明 Loon/QX 本地规则优先顺序");
    assert.ok(rootReadme.includes("AWAvenue-Ads-Rule"), "根 README 应注明 AWAvenue-Ads-Rule");
    assert.ok(rootReadme.includes("Egern") && rootReadme.includes("DNS 层拒绝"), "根 README 应将 Egern 列入 DNS 层广告拦截");
    assert.ok(rootReadme.includes("Synology（20 域名）") && rootReadme.includes("Apple TV+（8 域名）"), "根 README 应说明内联规则");
    assert.ok(rootReadme.includes("no-ipv6") && rootReadme.includes("Tunnel IPv6"), "根 README 应准确说明 QX 与 Stash IPv6 机制");

    const clashReadme = readUtf8("Clash/README.md");
    assert.ok(clashReadme.includes("1.19.27"));
    assert.ok(clashReadme.includes("Clash Party") && clashReadme.includes("FlClash"));
    assert.ok(clashReadme.includes("AWAvenue-Ads-Rule"));

    const concordReadme = readUtf8("Concord/README.md");
    assert.ok(concordReadme.includes("chen08209/concord"));
    assert.ok(concordReadme.includes("Concord_rule.js"));
    assert.ok(concordReadme.includes("AWAvenue-Ads-Rule") && concordReadme.includes("smart"));

    assert.ok(readUtf8("Surge/README.md").includes("iOS 5.14.0+ / Mac 5.9.0+"));
    assert.ok(readUtf8("Surge/README.md").includes("6.5.0+"));

    const egernReadme = readUtf8("Egern/README.md");
    assert.ok(egernReadme.includes("iOS / iPadOS / macOS / tvOS"), "Egern README 应标明 iOS / iPadOS / macOS / tvOS");

    const stashReadme = readUtf8("Stash/README.md");
    assert.ok(stashReadme.includes("iOS 3.6+"));
    assert.ok(stashReadme.includes("macOS 4.3+"));
    assert.ok(stashReadme.includes("AWAvenue-Ads-Rule"));

    assert.ok(readUtf8("Loon/README.md").includes("iOS 3.2.5 (789)+"));
    assert.ok(readUtf8("Shadowrocket/README.md").includes("2.2.66 (2649)+"));

    const qxReadme = readUtf8("QuantumultX/README.md");
    assert.ok(qxReadme.includes("iOS / iPadOS / macOS (Apple Silicon) / tvOS"));
    assert.ok(qxReadme.includes("resource_parser_url"));
});

check("workflows: verify.yml 与 check-urls.yml 使用 Node 26、Actions v7、最小权限与离线隔离", () => {
    const verifyYml = readUtf8(".github/workflows/verify.yml");
    assert.ok(verifyYml.includes("actions/checkout@v7"));
    assert.ok(verifyYml.includes("actions/setup-node@v7"));
    assert.ok(verifyYml.includes("node-version: 26"));
    assert.ok(verifyYml.includes("contents: read"));
    assert.ok(verifyYml.includes("concurrency:"));
    assert.ok(verifyYml.includes("timeout-minutes: 10"));

    const checkUrlsYml = readUtf8(".github/workflows/check-urls.yml");
    assert.ok(checkUrlsYml.includes("schedule:"));
    assert.ok(checkUrlsYml.includes("workflow_dispatch:"));
    assert.ok(!/^\s+(push|pull_request):/m.test(checkUrlsYml), "check-urls.yml 不应在 push/pull_request 触发");
    assert.ok(checkUrlsYml.includes("actions/checkout@v7"));
    assert.ok(checkUrlsYml.includes("actions/setup-node@v7"));
    assert.ok(checkUrlsYml.includes("node-version: 26"));
    assert.ok(checkUrlsYml.includes("contents: read"));
    assert.ok(checkUrlsYml.includes("timeout-minutes: 10"));
    assert.ok(checkUrlsYml.includes("raw.githubusercontent.com"));
});

// 4. 9 端正则表达式提取与一致性格局测试（含全部重复行一致性校验）
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

check("regex-exclude: 9 端 excludeFilter 行为一致且全部重复行与规范主体完全一致", () => {
    const surgeStatic = extractLineMatch(surge, /^静态 = .*?policy-regex-filter=([^,]+),/m, "Surge excludeFilter");
    const surfboardStatic = extractLineMatch(surfboard, /^静态 = .*?policy-regex-filter="([^"]+)"/m, "Surfboard excludeFilter");
    const loonAll = extractLineMatch(loon, /^All = NameRegex, FilterKey = "(.+)"$/m, "Loon excludeFilter");
    const srStatic = extractLineMatch(shadowrocket, /^静态 = select,policy-regex-filter=(.+)$/m, "Shadowrocket excludeFilter");
    const qxStatic = extractLineMatch(qx, /^static = 静态, resource-tag-regex=\^All\$, server-tag-regex=([^,]+),/m, "QX excludeFilter");
    const stashFilter = extractLineMatch(stash, /^\s{4}filter:\s*'(.+)'$/m, "Stash excludeFilter");
    const egernFilterRaw = extractLineMatch(egern, /name: 静态[\s\S]*?\n\s+filter: &exclude_filter ("[^"]+")/m, "Egern excludeFilter");
    const egernFilter = JSON.parse(egernFilterRaw);
    const clashExcludeRaw = extractLineMatch(clashJs, /const excludeFilter =\s*\n\s*("[^"]+");/m, "Clash excludeFilter");
    const clashExclude = JSON.parse(clashExcludeRaw);
    const concordExcludeRaw = extractLineMatch(concordJs, /const excludeFilter =\s*\n\s*("[^"]+");/m, "Concord excludeFilter");
    const concordExclude = JSON.parse(concordExcludeRaw);

    assert.equal(concordExclude, clashExclude, "Concord 与 Clash excludeFilter 应完全一致");
    assert.ok(clashExclude.startsWith("(?i)"), "规范 excludeFilter 应以 (?i) 开头");
    const canonicalBody = clashExclude.slice(4);
    const expectedLookaheadPrefix = `(?i)^(?!.*${canonicalBody})`;

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
        assert.equal(raw, `${expectedLookaheadPrefix}.*$`, `${client} excludeFilter 主体与规范不一致`);
        const re = toJsRegex(raw);
        for (const s of excludeSamples.shouldExclude) {
            assert.equal(re.test(s), false, `${client} 未排除信息节点: ${s}`);
        }
        for (const s of excludeSamples.shouldKeep) {
            assert.equal(re.test(s), true, `${client} 误杀正常节点: ${s}`);
        }
    }

    for (const [client, raw] of [["Clash", clashExclude], ["Concord", concordExclude]]) {
        const re = toJsRegex(raw);
        for (const s of excludeSamples.shouldExclude) {
            assert.equal(re.test(s), true, `${client} 未排除信息节点: ${s}`);
        }
        for (const s of excludeSamples.shouldKeep) {
            assert.equal(re.test(s), false, `${client} 误杀正常节点: ${s}`);
        }
    }

    // 校验所有重复出现的 exclude 行（Shadowrocket 20 条、QX 20 条、Loon 6 条）
    const srAllFilters = [...shadowrocket.matchAll(/policy-regex-filter=([^,\n]+)/g)].map(m => m[1]);
    assert.equal(srAllFilters.length, 20, "Shadowrocket 应提取到 20 条 policy-regex-filter");
    for (const f of srAllFilters) {
        assert.ok(f.startsWith(expectedLookaheadPrefix), `Shadowrocket 存在偏离规范的 excludeFilter: ${f.slice(0, 60)}`);
    }

    const qxAllFilters = [...qx.matchAll(/server-tag-regex=([^,\n]+)/g)].map(m => m[1]);
    assert.equal(qxAllFilters.length, 20, "Quantumult X 应提取到 20 条 server-tag-regex");
    for (const f of qxAllFilters) {
        assert.ok(f.startsWith(expectedLookaheadPrefix), `Quantumult X 存在偏离规范的 excludeFilter: ${f.slice(0, 60)}`);
    }

    const loonAllFilters = [...loon.matchAll(/NameRegex, FilterKey = "(.+)"$/gm)].map(m => m[1]);
    assert.equal(loonAllFilters.length, 6, "Loon 应提取到 6 条 [Remote Filter]");
    for (const f of loonAllFilters) {
        assert.ok(f.startsWith(expectedLookaheadPrefix), `Loon 存在偏离规范的 excludeFilter: ${f.slice(0, 60)}`);
    }
});

const regionSamples = {
    HK: ["香港 01", "九龍 02", "Hong Kong 01", "HongKong 02", "Kowloon BGP", "Tsuen Wan 01", "HKG 01"],
    JP: ["日本 01", "東京 01", "福岡 02", "札幌 03", "京都 04", "Tokyo 01", "Osaka 02", "Narita", "Haneda", "Kyoto", "Fukuoka", "Nagoya", "Sapporo", "JPN 01"],
    SG: ["新加坡 01", "獅城 02", "Singapore 01", "SG 01", "SGP 02"],
    TW: ["台湾 01", "臺灣 02", "臺北 03", "臺中 04", "新竹 05", "Taipei 01", "Kaohsiung", "Taichung", "Hsinchu", "TWN 01"],
    US: [
        "美国 01", "美東 02", "達拉斯 03", "拉斯維加斯 04", "旧金山 05", "舊金山 06",
        "Los Angeles", "Los-Angeles", "San Jose", "San Francisco", "San-Francisco", "Silicon Valley",
        "New York", "Seattle", "Dallas", "Chicago", "Fremont", "Phoenix",
        "Denver", "Atlanta", "Miami", "USA 01"
    ]
};

check("regex-regions: 9 端核心 5 地区（HK/JP/SG/TW/US）简繁与英文字段匹配一致", () => {
    const extractors = {
        Surge: code =>
            extractLineMatch(surge, new RegExp(`^${code} = .*?policy-regex-filter=([^,]+),`, "m"), `Surge ${code}`),
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
            ),
        Concord: code =>
            JSON.parse(
                extractLineMatch(concordJs, new RegExp(`name: "${code}",\\s*\\n\\s*regex: ("[^"]+")`, "m"), `Concord ${code}`)
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

// 通用：校验脚本输出（Clash / Concord）全部规则、规则集、策略组、DNS 策略引用完整性
function assertScriptCrossReferences(out, label, extraBuiltins = []) {
    const providers = new Set(Object.keys(out["rule-providers"] || {}));
    const groups = new Set((out["proxy-groups"] || []).map(g => g.name));
    const proxies = new Set((out.proxies || []).map(p => p.name));
    const builtins = new Set([
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL",
        ...extraBuiltins
    ]);

    for (const g of out["proxy-groups"]) {
        assert.ok(Array.isArray(g.proxies) && g.proxies.length > 0, `${label} 组 ${g.name} 不应为空`);
        for (const member of g.proxies) {
            assert.ok(
                proxies.has(member) || groups.has(member) || builtins.has(member),
                `${label} 组 ${g.name} 引用了不存在成员: ${member}`
            );
        }
    }

    const matches = out.rules.filter(r => r.startsWith("MATCH,"));
    assert.equal(matches.length, 1, `${label} MATCH 必须唯一`);
    assert.equal(out.rules[out.rules.length - 1], matches[0], `${label} MATCH 必须在最后`);

    for (const rule of out.rules) {
        const parts = rule.split(",");
        const rsIdx = parts.indexOf("RULE-SET");
        if (rsIdx !== -1) {
            const rsName = parts[rsIdx + 1];
            assert.ok(providers.has(rsName), `${label} rules 规则集缺失: ${rsName}`);
        }
        const tail = parts.filter(part => part !== "no-resolve" && part !== "src");
        const target = tail[tail.length - 1];
        assert.ok(groups.has(target) || builtins.has(target), `${label} 规则目标缺失: ${target} (${rule})`);
    }

    for (const item of out.dns["fake-ip-filter"] || []) {
        const legacy = /^rule-set:(.+)$/i.exec(item);
        if (legacy) {
            assert.ok(providers.has(legacy[1].trim()), `${label} fake-ip-filter 规则集缺失: ${item}`);
        }
        const ruleMatch = /^RULE-SET,([^,]+),(real-ip|fake-ip)$/i.exec(item);
        if (ruleMatch) {
            assert.ok(providers.has(ruleMatch[1].trim()), `${label} fake-ip-filter 规则集缺失: ${item}`);
        }
    }

    for (const field of ["nameserver-policy", "proxy-server-nameserver-policy"]) {
        const policy = out.dns[field];
        if (!policy) continue;
        for (const key of Object.keys(policy)) {
            const m = /^rule-set:(.+)$/i.exec(key);
            if (m) {
                for (const rsName of m[1].split(",").map(s => s.trim()).filter(Boolean)) {
                    assert.ok(providers.has(rsName), `${label} ${field} 引用缺失规则集: ${rsName}`);
                }
            }
        }
    }
}

// 通用：B13 地区正反回归用例
function assertB13RegionFixtures(runMainWithMinOne, label, expectedRegionType) {
    const out = runMainWithMinOne({
        proxies: [
            // 易误判反例
            { name: "HK 4th", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Rio de Janeiro", type: "ss", server: "1.1.1.2", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Relay in HK", type: "ss", server: "1.1.1.3", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Node ID 01", type: "ss", server: "1.1.1.4", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "My HK", type: "ss", server: "1.1.1.5", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "US-CA", type: "ss", server: "1.1.1.6", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "HK-TR01", type: "ss", server: "1.1.1.7", port: 443, cipher: "aes-128-gcm", password: "p" },
            // 对应正例
            { name: "TH 01", type: "ss", server: "1.1.2.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "DE 01", type: "ss", server: "1.1.2.2", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "IN 01", type: "ss", server: "1.1.2.3", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "ID 01", type: "ss", server: "1.1.2.4", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "MY 01", type: "ss", server: "1.1.2.5", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "CA 01", type: "ss", server: "1.1.2.6", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "TR 01", type: "ss", server: "1.1.2.7", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    });

    const byRegion = new Map(
        out["proxy-groups"]
            .filter(g => g.type === expectedRegionType)
            .map(g => [g.name, g.proxies])
    );

    assert.deepEqual(byRegion.get("TH"), ["TH 01"], `${label}: HK 4th 不应误归 TH`);
    assert.deepEqual(byRegion.get("DE"), ["DE 01"], `${label}: Rio de Janeiro 不应误归 DE`);
    assert.deepEqual(byRegion.get("BR"), ["Rio de Janeiro"], `${label}: Rio de Janeiro 应归 BR`);
    assert.deepEqual(byRegion.get("IN"), ["IN 01"], `${label}: Relay in HK 不应误归 IN`);
    assert.deepEqual(byRegion.get("ID"), ["ID 01"], `${label}: Node ID 01 不应误归 ID`);
    assert.deepEqual(byRegion.get("MY"), ["MY 01"], `${label}: My HK 不应误归 MY`);
    assert.deepEqual(byRegion.get("CA"), ["CA 01"], `${label}: US-CA 不应误归 CA`);
    assert.deepEqual(byRegion.get("TR"), ["TR 01"], `${label}: HK-TR01 不应误归 TR`);
    assert.deepEqual(byRegion.get("US"), ["US-CA"], `${label}: US-CA 应归 US`);
    assert.deepEqual(
        byRegion.get("HK"),
        ["HK 4th", "HK-TR01", "My HK", "Relay in HK"],
        `${label}: HK 组应包含全部 HK 节点`
    );
}

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
        main: (input, profileName) => JSON.parse(JSON.stringify(sandbox.main(input, profileName))),
        warnings
    };
}

check("clash-runtime: 正常订阅、城市识别、AWAvenue .mrs、rule 模式 fake-ip 与交叉引用", () => {
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

    assert.deepEqual(out["proxy-groups"].find(g => g.name === "HK").proxies, ["Kowloon BGP", "Tsuen Wan 01"]);
    assert.deepEqual(out["proxy-groups"].find(g => g.name === "BR").proxies, ["Rio 02", "São Paulo 01"]);
    assert.deepEqual(out["proxy-groups"].find(g => g.name === "CA").proxies, ["CA Ontario 01", "Montreal 03"]);

    assert.equal(out["rule-providers"]["ads-domain"].url, AWA_ADS_MRS_URL);
    assert.deepEqual(out.sniffer["skip-domain"], ["Mijia Cloud", "+.push.apple.com"]);
    assert.equal(out.sniffer.sniff.HTTP["override-destination"], undefined);

    assert.equal(out.dns["fake-ip-filter-mode"], "rule");
    const fif = out.dns["fake-ip-filter"];
    assert.ok(fif.indexOf("DOMAIN,time.apple.com,real-ip") < fif.indexOf("RULE-SET,apple-domain,fake-ip"));
    assert.ok(fif.indexOf("RULE-SET,apple-domain,fake-ip") < fif.indexOf("RULE-SET,cn-domain,real-ip"));
    assert.equal(fif[fif.length - 1], "MATCH,fake-ip");

    assert.equal(out.proxies.find(p => p.name === "Kowloon BGP")["client-fingerprint"], "chrome");
    assert.equal(out.proxies.find(p => p.name === "法罗群岛 01")["client-fingerprint"], undefined);

    assertScriptCrossReferences(out, "Clash");
});

check("clash-runtime: B11 anytls 指纹、reject/dns 无 ip-version、空 reality-opts 不误加指纹", () => {
    const { main } = loadClashMain();
    const out = main({
        proxies: [
            { name: "AnyTLS 01", type: "anytls", server: "1.1.1.1", port: 443, password: "p" },
            { name: "VLESS Empty Reality", type: "vless", server: "1.1.1.2", port: 80, uuid: "u", "reality-opts": {} },
            { name: "VLESS Real Reality", type: "vless", server: "1.1.1.3", port: 443, uuid: "u", "reality-opts": { "public-key": "abc" } },
            { name: "MyDirect", type: "direct" },
            { name: "MyReject", type: "reject" },
            { name: "MyDns", type: "dns" }
        ]
    });
    const byName = new Map(out.proxies.map(p => [p.name, p]));
    assert.equal(byName.get("AnyTLS 01")["client-fingerprint"], "chrome", "anytls 应补全 chrome 指纹");
    assert.equal(byName.get("AnyTLS 01")["ip-version"], "dual");
    assert.equal(byName.get("VLESS Empty Reality")["client-fingerprint"], undefined, "空 reality-opts 且无 tls 不应加指纹");
    assert.equal(byName.get("VLESS Real Reality")["client-fingerprint"], "chrome", "非空 reality public-key 应补全 chrome 指纹");
    assert.equal(byName.get("MyDirect")["ip-version"], undefined, "direct 不应注入 ip-version");
    assert.equal(byName.get("MyReject")["ip-version"], undefined, "reject 不应注入 ip-version");
    assert.equal(byName.get("MyDns")["ip-version"], undefined, "dns 不应注入 ip-version");
});

check("clash-runtime: B1 逗号分段 DNS policy、B2 裸标志与百分号改名引用、B3 空 policy 清理", () => {
    const { main } = loadClashMain();

    // B1 + B2
    const out1 = main({
        proxies: [
            { name: "JP", type: "ss", server: "1.1.1.1", port: 443 },
            { name: "香港 01", type: "ss", server: "1.1.1.2", port: 443 },
            { name: "MyDirect", type: "direct" }
        ],
        "rule-providers": {
            "sub-nodes": { type: "http", behavior: "domain", url: "https://example.com/nodes.yaml", path: "./sub.yaml" }
        },
        dns: {
            nameserver: [
                "https://1.1.1.1/dns-query#h3&disable-ipv6&disable-qtype-65",
                "https://8.8.8.8/dns-query#%E9%A6%99%E6%B8%AF%2001",
                "https://9.9.9.9/dns-query#JP",
                "https://1.0.0.1/dns-query#MyDirect",
                "https://4.2.2.1/dns-query#respect-rules"
            ],
            "proxy-server-nameserver": [
                "https://223.5.5.5/dns-query#h3&主代理&respect-rules"
            ],
            "nameserver-policy": {
                "geosite:cn,private": ["223.5.5.5"],
                "rule-set:unknown,+.ok.example.com,*": ["223.5.5.5"]
            },
            "proxy-server-nameserver-policy": {
                "rule-set:sub-nodes,+.node.example.com,geosite:cn": ["223.5.5.5#h3&主代理"]
            }
        }
    });

    assert.ok(out1.dns.nameserver.includes("https://1.1.1.1/dns-query#h3&disable-ipv6&disable-qtype-65"), "裸 # 标志应保留");
    assert.ok(out1.dns.nameserver.includes("https://8.8.8.8/dns-query#%E9%A6%99%E6%B8%AF%2001"), "百分号编码合法节点名应保留");
    assert.ok(
        out1.dns.nameserver.some(s => s.startsWith("https://9.9.9.9/dns-query#") && decodeURIComponent(s.split("#")[1]) === "节点·JP"),
        "指向被改名节点的引用应改写为 节点·JP"
    );
    assert.ok(out1.dns.nameserver.includes("https://1.0.0.1/dns-query#MyDirect"), "type: direct 节点引用应保留");
    assert.ok(out1.dns.nameserver.includes("https://4.2.2.1/dns-query#respect-rules"), "#respect-rules 标志应保留");
    assert.deepEqual(out1.dns["proxy-server-nameserver"], ["https://223.5.5.5/dns-query#h3"], "stripProxyRefs 应保留 #h3 并剔除代理与 respect-rules");

    assert.equal(out1.dns["nameserver-policy"]["geosite:cn,private"], undefined, "geosite 逗号段应整段丢弃");
    assert.deepEqual(out1.dns["nameserver-policy"]["+.ok.example.com"], ["223.5.5.5"], "混合段仅保留安全域名");
    assert.deepEqual(out1.dns["proxy-server-nameserver-policy"]["+.node.example.com"], ["223.5.5.5#h3"]);
    assert.deepEqual(out1.dns["proxy-server-nameserver-policy"]["rule-set:sub-nodes"], ["223.5.5.5#h3"]);
    assert.ok(out1["rule-providers"]["sub-nodes"], "被引用的 HTTP rule-provider 应搬运");

    // B3: 唯一搬运的 provider 为 type: file 被丢弃后，空的 proxy-server-nameserver-policy 应被删除
    const out2 = main({
        proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }],
        "rule-providers": {
            "local-file": { type: "file", behavior: "domain", path: "./local.yaml" }
        },
        dns: {
            "proxy-server-nameserver": ["223.5.5.5"],
            "proxy-server-nameserver-policy": {
                "rule-set:local-file": ["223.5.5.5"]
            }
        }
    });
    assert.equal(out2["rule-providers"]["local-file"], undefined, "type: file provider 不应搬运");
    assert.equal(out2.dns["proxy-server-nameserver-policy"], undefined, "清空后的 proxy-server-nameserver-policy 应删除");
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

check("clash-runtime: IPv6 默认开启，订阅显式关闭/开启均被尊重", () => {
    const { main } = loadClashMain();
    const base = { proxies: [{ name: "HK 01", type: "ss", server: "1.1.1.1", port: 443 }] };

    const out1 = main(JSON.parse(JSON.stringify(base)));
    assert.equal(out1.ipv6, true, "未指定时 IPv6 应默认开启");
    assert.equal(out1.dns.ipv6, true, "DNS IPv6 应跟随全局默认开启");
    assert.equal(out1.dns["fake-ip-range6"], "fdfe:dcba:9876::/64", "默认开启时应输出 IPv6 fake-ip 段");

    const out2 = main(Object.assign(JSON.parse(JSON.stringify(base)), { ipv6: false }));
    assert.equal(out2.ipv6, false, "订阅显式关闭应被尊重");
    assert.equal(out2.dns.ipv6, false);
    assert.equal(out2.dns["fake-ip-range6"], undefined);

    const out3 = main(Object.assign(JSON.parse(JSON.stringify(base)), { ipv6: true }));
    assert.equal(out3.ipv6, true, "订阅显式开启应被尊重");
});

check("clash-runtime: dialer-proxy 悬空引用、改名引用与成环被校正", () => {
    const { main } = loadClashMain();
    const out = main({
        proxies: [
            { name: "A", type: "ss", server: "1.1.1.1", port: 443, "dialer-proxy": "B" },
            { name: "B", type: "ss", server: "1.1.1.2", port: 443, "dialer-proxy": "A" },
            { name: "D", type: "ss", server: "1.1.1.3", port: 443, "dialer-proxy": "Gone" },
            { name: "E", type: "ss", server: "1.1.1.4", port: 443, "dialer-proxy": "A" },
            { name: "G", type: "ss", server: "1.1.1.5", port: 443, "dialer-proxy": "主代理" },
            { name: "HK", type: "ss", server: "1.1.1.6", port: 443 },
            { name: "Z", type: "ss", server: "1.1.1.7", port: 443, "dialer-proxy": "HK" }
        ]
    });
    const byName = new Map(out.proxies.map(proxy => [proxy.name, proxy]));

    assert.equal(byName.get("A")["dialer-proxy"], undefined, "A↔B 环应断开");
    assert.equal(byName.get("B")["dialer-proxy"], undefined, "A↔B 环应断开");
    assert.equal(byName.get("D")["dialer-proxy"], undefined, "悬空引用应删除");
    assert.equal(byName.get("E")["dialer-proxy"], "A", "有效引用应保留");
    assert.equal(byName.get("G")["dialer-proxy"], "主代理", "指向策略组的引用应保留");
    assert.equal(byName.get("Z")["dialer-proxy"], "节点·HK", "指向被改名节点的引用应改到新名字");
    assert.ok(byName.has("节点·HK"), "与保留名冲突的节点应改名");
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

check("clash-runtime: 23 地区扩展城市、circle/128 + Qure 图标与 B13 正反用例", () => {
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

    assertB13RegionFixtures(main, "Clash", "url-test");
});


// 6. Concord_rule.js（继承式）契约与运行时回归测试
function loadConcord(source = concordJs) {
    const warnings = [];
    const sandbox = {
        console: {
            warn: (...args) => warnings.push(args.join(" ")),
            log: (...args) => warnings.push(args.join(" "))
        }
    };
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);
    return {
        main: (input, profileName) => JSON.parse(JSON.stringify(sandbox.main(input, profileName))),
        warnings
    };
}

const C_OK = { name: "OK", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" };

check("concord-contract: 不兼容告警源被静默清除（含 B5 保留 ECH、B6 保留 chrome120、B9 剔除 lgbm/smart-collector）", () => {
    const { main, warnings } = loadConcord();
    const out = main({
        proxies: [
            C_OK,
            { name: "TS", type: "tailscale", server: "x", port: 1 },
            { name: "KP", type: "vmess", server: "x", port: 1, uuid: "u", cipher: "auto", network: "kcp" },
            { name: "ST", type: "vless", server: "x", port: 1, uuid: "u", "restls-opts": { password: "p" } },
            { name: "PL", type: "ss", server: "x", port: 1, cipher: "aes-128-gcm", password: "p", plugin: "kcptun" },
            { name: "FP", type: "trojan", server: "x", port: 443, password: "p", "client-fingerprint": "chrome_psk" },
            { name: "FP120", type: "trojan", server: "x", port: 443, password: "p", "client-fingerprint": "chrome120" },
            { name: "XD", type: "vless", server: "x", port: 1, uuid: "u", network: "xhttp", "xhttp-opts": { "download-settings": { "restls-opts": { password: "p" } } } },
            { name: "XF", type: "vless", server: "x", port: 1, uuid: "u", tls: true, network: "xhttp", "xhttp-opts": { "download-settings": { "client-fingerprint": "randomized" } } },
            { name: "XF120", type: "vless", server: "x", port: 1, uuid: "u", tls: true, network: "xhttp", "xhttp-opts": { "download-settings": { "client-fingerprint": "chrome120" } } },
            { name: "MU", type: "mieru", server: "x", port: 1, transport: "UDP", username: "u", password: "p", "dialer-proxy": "OK" },
            { name: "RE", type: "vless", server: "x", port: 1, uuid: "u", network: "ws", "reality-opts": {} },
            { name: "RH", type: "vless", server: "x", port: 1, uuid: "u", tls: true, network: "httpupgrade", "reality-opts": { "public-key": "A".repeat(43) } },
            { name: "HO", type: "hysteria", server: "x", port: 1, up: "10", down: "50", "obfs-protocol": "faketcp" },
            { name: "H2R", type: "hysteria2", server: "x", port: 1, password: "p", ports: "1000-2000", "realm-opts": { enable: true, "server-url": "https://r.test" } },
            { name: "H2D", type: "hysteria2", server: "x", port: 1, password: "p", "dialer-proxy": "OK", "realm-opts": { enable: true, "server-url": "https://r.test" } },
            { name: "H2OFF", type: "hysteria2", server: "x", port: 1, password: "p", ports: "1000-2000", "dialer-proxy": "OK", "realm-opts": { enable: false } },
            { name: "SN6", type: "snell", server: "x", port: 1, psk: "short", version: 6 },
            { name: "SN6O", type: "snell", server: "x", port: 1, psk: "psk-12-bytes!!", version: 6, "obfs-opts": { mode: "tls" } },
            { name: "SNR", type: "snell", server: "x", port: 1, psk: "p", version: 4, "obfs-opts": { mode: "restls" } },
            { name: "SNU", type: "snell", server: "x", port: 1, psk: "p", version: 1, udp: true },
            { name: "SNC", type: "ss", server: "x", port: 1, cipher: "made-up-cipher", password: "p" },
            { name: "SNE", type: "ss", server: "x", port: 1, cipher: "aes-128-gcm", password: "p", plugin: "v2ray-plugin", "plugin-opts": { mode: "websocket", tls: true, "ech-opts": { enable: true } } },
            { name: "SNEOFF", type: "ss", server: "x", port: 1, cipher: "aes-128-gcm", password: "p", plugin: "v2ray-plugin", "plugin-opts": { mode: "websocket", tls: true, "ech-opts": { enable: false } } }
        ],
        "geodata-mode": true,
        "global-client-fingerprint": "chrome",
        "lgbm-auto-update": true,
        "lgbm-update-interval": 72,
        "lgbm-url": "https://example.com/lgbm.bin",
        profile: { "store-selected": true, "smart-collector-size": 100 },
        listeners: [{ name: "l", type: "mixed", port: 1 }],
        "external-ui": "ui",
        "external-controller": "127.0.0.1:9090",
        "bind-address": "192.168.1.2",
        secret: "x",
        "unknown-key": 1,
        tun: { enable: true, stack: "mixed", gso: true, "dns-mode": "hijack", mtu: 9000 },
        experimental: { "quic-go-disable-ecn": false },
        tls: { certificate: "a" },
        dns: {
            nameserver: ["dhcp://en0", "ts://bad", "https://223.5.5.5/dns-query"]
        }
    });
    const names = out.proxies.map(p => p.name);
    assert.deepEqual(
        names.filter(n => ["TS", "KP", "ST", "PL", "XD", "RH", "HO", "H2R", "H2D", "SN6", "SN6O", "SNR", "SNU", "SNC"].includes(n)),
        [],
        "不支持节点应剔除"
    );
    // B5: v2ray-plugin + TLS + ECH (SNE) 内核已支持，应保留
    for (const kept of ["MU", "RE", "H2OFF", "SNE", "SNEOFF", "FP120", "XF120"]) {
        assert.ok(names.includes(kept), kept + " 内核可构建，不应误删");
    }
    // B6: 废弃指纹被改写，chrome120 保留不动
    assert.equal(out.proxies.find(p => p.name === "FP")["client-fingerprint"], "chrome");
    assert.equal(out.proxies.find(p => p.name === "FP120")["client-fingerprint"], "chrome120", "chrome120 应原样保留");
    assert.equal(
        out.proxies.find(p => p.name === "XF")["xhttp-opts"]["download-settings"]["client-fingerprint"],
        "random"
    );
    assert.equal(
        out.proxies.find(p => p.name === "XF120")["xhttp-opts"]["download-settings"]["client-fingerprint"],
        "chrome120",
        "xhttp download-settings 内 chrome120 应原样保留"
    );
    // B9: 顶层 T2 死键（含 lgbm-*）与 profile.smart-collector-size 消失
    for (const key of ["geodata-mode", "global-client-fingerprint", "listeners", "external-ui", "lgbm-auto-update", "lgbm-update-interval", "lgbm-url"]) {
        assert.equal(out[key], undefined, key + " 应被剔除");
    }
    assert.equal(out.profile["smart-collector-size"], undefined, "profile.smart-collector-size 应被剔除");
    assert.equal(out["external-controller"], "127.0.0.1:9090", "客户端自管设置应透传");
    assert.equal(out.secret, "x", "客户端自管设置应透传");
    assert.equal(out["bind-address"], "192.168.1.2", "客户端自管设置应透传");
    assert.equal(out["unknown-key"], 1, "黑名单外的未知键应保留");
    assert.equal(out.tun.gso, true, "受支持的 tun.gso 应透传");
    assert.equal(out.tun["dns-mode"], undefined);
    assert.equal(out.tun.stack, "mixed", "生效的 tun.stack 应透传");
    assert.equal(out.tun.mtu, 9000, "合法 tun 设置应继承");
    assert.equal(out.tun.enable, true);
    assert.equal(out.experimental["quic-go-disable-ecn"], undefined);
    assert.equal(out.tls.certificate, undefined);
    assert.ok(out.dns.nameserver.includes("system://"), "dhcp:// 应改写为 system://");
    assert.ok(!out.dns.nameserver.some(s => s.startsWith("ts://")), "ts:// 应丢弃");
    assert.ok(out.dns.nameserver.includes("https://223.5.5.5/dns-query"), "合法订阅上游应继承");
    assert.equal(warnings.length, 0, "清洗不应产生日志: " + warnings.join("; "));
});

check("concord-contract: B10 尊重订阅与客户端设置（非默认 dns.listen 继承与缺省值、append-system）", () => {
    const { main } = loadConcord();
    const out = main({
        proxies: [C_OK],
        mode: "global",
        "log-level": "debug",
        "mixed-port": 7890,
        ipv6: true,
        "interface-name": "eth0",
        ntp: { enable: true, server: "time.apple.com" },
        "geox-url": { mmdb: "https://example.com/geo.mmdb" },
        tun: { enable: true, stack: "gvisor", mtu: 1500, "auto-route": false },
        dns: {
            listen: "127.0.0.1:5353",
            "append-system": false,
            nameserver: ["https://dns.example/dns-query"]
        },
        profile: { "store-selected": false }
    });
    assert.equal(out.mode, "global", "mode 应继承");
    assert.equal(out["log-level"], "debug");
    assert.equal(out["mixed-port"], 7890);
    assert.equal(out["interface-name"], "eth0");
    assert.equal(out.ntp.enable, true, "ntp 段应继承");
    assert.equal(out.ntp.server, "time.apple.com");
    assert.equal(out["geox-url"].mmdb, "https://example.com/geo.mmdb", "geox-url 应继承");
    assert.equal(out.tun.stack, "gvisor", "合法栈应继承");
    assert.equal(out.tun.mtu, 1500);
    assert.equal(out.tun["auto-route"], false);
    assert.equal(out.dns.listen, "127.0.0.1:5353", "非默认 dns.listen 应原样继承");
    assert.equal(out.dns["append-system"], false, "显式 append-system: false 应保留");
    assert.ok(out.dns.nameserver.includes("https://dns.example/dns-query"), "订阅 DNS 应继承");
    assert.equal(out.profile["store-selected"], false, "订阅 profile 应优先");

    // 省略 dns.listen 时回退默认 127.0.0.1:1053；append-system: true 不输出
    const outDefault = main({
        proxies: [C_OK],
        dns: { "append-system": true }
    });
    assert.equal(outDefault.dns.listen, "127.0.0.1:1053", "省略 dns.listen 时应回退默认 127.0.0.1:1053");
    assert.equal(outDefault.dns["append-system"], undefined, "append-system: true 不应透传");
});

check("concord-contract: B4/B7/B8/B9/B11/C1/C2/C4 运行时专项回归", () => {
    const { main } = loadConcord();
    const out = main({
        proxies: [
            { name: "HK", type: "SS", server: "1.1.1.1", port: 443, cipher: "AES-128-GCM", password: "p" },
            { name: "Z", type: "trojan", server: "1.1.1.2", port: 443, password: "p", dialer_proxy: "HK", client_fingerprint: "chrome120", ss_opts: { enabled: true, method: "AES-256-GCM", password: "s" } },
            { name: "AnyTLS 01", type: "anytls", server: "1.1.1.3", port: 443, password: "p" },
            { name: "VLESS Empty Reality", type: "vless", server: "1.1.1.4", port: 80, uuid: "u", "reality-opts": {} },
            { name: "MyReject", type: "reject" },
            { name: "MyDns", type: "dns" },
            { name: "Tokyo 01", type: "ss", server: "1.1.1.5", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Osaka 02", type: "ss", server: "1.1.1.6", port: 443, cipher: "aes-128-gcm", password: "p" }
        ],
        dns: {
            "fake-ip-filter": [
                "time*.com",
                "*a.com",
                "+",
                "+.",
                "*",
                "a.com.",
                "a..com",
                "a.+.com",
                "+.valid.example.com"
            ],
            "nameserver-policy": {
                "time*.com,*a.com,+,+.,*,a.com.,a..com,a.+.com,ok.example.com": ["223.5.5.5"],
                "geosite:cn,private": ["223.5.5.5"]
            }
        }
    });

    const byName = new Map(out.proxies.map(p => [p.name, p]));
    // B7: cipher/method 小写化 + 下划线键折叠
    assert.equal(byName.get("节点·HK").cipher, "aes-128-gcm", "ss 大写 cipher 应小写化");
    assert.equal(byName.get("Z")["ss-opts"].method, "aes-256-gcm", "trojan ss-opts.method 应小写化");
    assert.equal(byName.get("Z")["client-fingerprint"], "chrome120", "client_fingerprint 应折叠并保留 chrome120");
    assert.equal(byName.get("Z").client_fingerprint, undefined);
    // B4: proxyRenames 重写 dialer-proxy
    assert.equal(byName.get("Z")["dialer-proxy"], "节点·HK", "dialer-proxy 应同步重写为 节点·HK");
    assert.equal(byName.get("Z").dialer_proxy, undefined);

    // B11: anytls / empty reality-opts / reject & dns
    assert.equal(byName.get("AnyTLS 01")["client-fingerprint"], "chrome");
    assert.equal(byName.get("VLESS Empty Reality")["client-fingerprint"], undefined);
    assert.equal(byName.get("MyReject")["ip-version"], undefined);
    assert.equal(byName.get("MyDns")["ip-version"], undefined);

    // B8: DomainTrie 非法模式全部过滤，合法模式保留
    const fif = out.dns["fake-ip-filter"];
    assert.equal(out.dns["fake-ip-filter-mode"], "rule");
    assert.ok(fif.includes("DOMAIN-WILDCARD,stun.*,real-ip"));
    assert.ok(fif.includes("DOMAIN-WILDCARD,*.stun.*,real-ip"));
    assert.ok(fif.includes("DOMAIN-SUFFIX,valid.example.com,real-ip"), "合法订阅 blacklist 域名应转为 rule 条目");
    for (const bad of ["time*.com", "*a.com", "a.com.", "a..com", "a.+.com"]) {
        assert.ok(!fif.some(r => r.includes(bad)), `fake-ip-filter 不应保留非法 DomainTrie 模式: ${bad}`);
    }
    assert.deepEqual(out.dns["nameserver-policy"]["ok.example.com"], ["223.5.5.5"]);
    assert.equal(out.dns["nameserver-policy"]["geosite:cn,private"], undefined);

    // C4: AWAvenue .mrs
    assert.equal(out["rule-providers"]["ads-domain"].url, AWA_ADS_MRS_URL);

    // C2: 默认输出 smart 地区组
    const jpGroup = out["proxy-groups"].find(g => g.name === "JP");
    assert.equal(jpGroup.type, "smart", "Concord 地区组默认应为 smart");

    // 切换 REGION_GROUP_TYPE = "url-test"
    const patchedUrlTest = concordJs.replace(
        /const REGION_GROUP_TYPE = "smart";/,
        'const REGION_GROUP_TYPE = "url-test";'
    );
    assert.notEqual(patchedUrlTest, concordJs);
    const outUrlTest = loadConcord(patchedUrlTest).main({
        proxies: [
            { name: "Tokyo 01", type: "ss", server: "1.1.1.5", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Osaka 02", type: "ss", server: "1.1.1.6", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    });
    assert.equal(outUrlTest["proxy-groups"].find(g => g.name === "JP").type, "url-test");

    // B2 + B3: 裸 # 标志、百分号/改名引用与空 proxy-server-nameserver-policy 清理
    const outDns = main({
        proxies: [
            { name: "SG", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "香港 01", type: "ss", server: "1.1.1.2", port: 443, cipher: "aes-128-gcm", password: "p" }
        ],
        "rule-providers": {
            "local-file": { type: "file", behavior: "domain", path: "./local.yaml" }
        },
        dns: {
            nameserver: [
                "https://1.1.1.1/dns-query#h3&disable-ipv6&disable-qtype-65",
                "https://8.8.8.8/dns-query#%E9%A6%99%E6%B8%AF%2001",
                "https://9.9.9.9/dns-query#SG"
            ],
            "proxy-server-nameserver": ["https://223.5.5.5/dns-query#h3&主代理"],
            "proxy-server-nameserver-policy": {
                "rule-set:local-file": ["223.5.5.5"]
            }
        }
    });
    assert.ok(outDns.dns.nameserver.includes("https://1.1.1.1/dns-query#h3&disable-ipv6&disable-qtype-65"));
    assert.ok(outDns.dns.nameserver.includes("https://8.8.8.8/dns-query#%E9%A6%99%E6%B8%AF%2001"));
    assert.ok(
        outDns.dns.nameserver.some(s => s.startsWith("https://9.9.9.9/dns-query#") && decodeURIComponent(s.split("#")[1]) === "节点·SG")
    );
    assert.deepEqual(outDns.dns["proxy-server-nameserver"], ["https://223.5.5.5/dns-query#h3"]);
    assert.equal(outDns.dns["proxy-server-nameserver-policy"], undefined);
});

check("concord-contract: 引用完整——规则/规则集/dialer/hosts（含 B9 IPv6/script 边界）", () => {
    const { main } = loadConcord();
    const out = main({
        proxies: [
            C_OK,
            { ...C_OK, name: "A", server: "1.1.1.2", "dialer-proxy": "B" },
            { ...C_OK, name: "B", server: "1.1.1.3", "dialer-proxy": "A" },
            { ...C_OK, name: "D", server: "1.1.1.4", "dialer-proxy": "Gone" }
        ],
        hosts: {
            "ok.lan": "192.168.1.1",
            "self.lan": "lan",
            "v4mapped.lan": "0:0:0:0:0:ffff:192.0.2.128",
            "script.lan": "script:custom",
            "bad-v6a.lan": "1.2.3.4::1",
            "bad-v6b.lan": "::ffff:999.0.0.1",
            "empty.lan": "",
            "obj.lan": { a: 1 },
            "cyc-a.lan": "cyc-b.lan",
            "cyc-b.lan": "cyc-a.lan"
        }
    });
    assert.equal(out.proxies.find(p => p.name === "A")["dialer-proxy"], undefined, "环应断开");
    assert.equal(out.proxies.find(p => p.name === "B")["dialer-proxy"], undefined);
    assert.equal(out.proxies.find(p => p.name === "D")["dialer-proxy"], undefined, "悬空应删除");
    assert.ok(out.proxies.some(p => p.name === "A"), "环上节点应保留");

    assert.equal(out.hosts["ok.lan"], "192.168.1.1");
    assert.equal(out.hosts["self.lan"], "lan", "lan 特殊值内核支持，应保留");
    assert.equal(out.hosts["v4mapped.lan"], "0:0:0:0:0:ffff:192.0.2.128", "合法未压缩 IPv4-mapped IPv6 应保留");
    assert.equal(out.hosts["script.lan"], "script:custom", "script:* 值应保留");
    assert.equal(out.hosts["bad-v6a.lan"], undefined, "非法 IPv6 1.2.3.4::1 应剔除");
    assert.equal(out.hosts["bad-v6b.lan"], undefined, "非法 IPv6 ::ffff:999.0.0.1 应剔除");
    assert.equal(out.hosts["empty.lan"], undefined, "空字符串 hosts 应剔除");
    assert.equal(out.hosts["obj.lan"], undefined);
    assert.equal(out.hosts["cyc-a.lan"], undefined);
    assert.equal(out.hosts["cyc-b.lan"], undefined);

    assertScriptCrossReferences(out, "Concord", [
        "REJECT-NO-DROP", "REJECT-TINYGIF", "REJECT-IMG", "REJECT-DICT", "REJECT-ARRAY", "REJECT-200", "REJECT-VIDEO"
    ]);
});

check("concord-contract: 23 地区、circle/128 + Qure 图标与 B13 正反用例", () => {
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
        port: 443,
        cipher: "aes-128-gcm",
        password: "p"
    }));
    const patched = concordJs.replace(/const REGION_MIN_NODES = \d+;/, "const REGION_MIN_NODES = 1;");
    const { main } = loadConcord(patched);
    const out = main({ proxies });
    const byRegion = new Map(
        out["proxy-groups"]
            .filter(g => g.type === "smart")
            .map(g => [g.name, g.proxies])
    );
    assert.equal(byRegion.size, 23, "Concord 23 个地区应全部建组");
    assert.ok(!concordJs.includes("circle-flags"), "Concord_rule.js 不应残留 circle-flags");
    for (const g of out["proxy-groups"]) {
        if (g.type === "smart") {
            assert.equal(
                g.icon,
                `${FLAG_ICON_BASE}/${g.name.toLowerCase()}.png`,
                `Concord 地区组 ${g.name} 图标未使用 circle/128 PNG`
            );
        } else {
            assert.ok(
                g.icon.startsWith("https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color/") &&
                    g.icon.endsWith(".png"),
                `Concord 非地区组 ${g.name} 应保留 Qure PNG 图标`
            );
        }
    }

    assertB13RegionFixtures(main, "Concord", "smart");
});

check("concord-contract: 分流结构与 Clash 版一致（组/规则/地区）", () => {
    const { main } = loadConcord();
    const { main: clashMain } = loadClashMain();
    const input = {
        proxies: [
            { name: "HK 01", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "HK 02", type: "ss", server: "1.1.1.2", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Tokyo 01", type: "ss", server: "1.1.1.3", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "Osaka 02", type: "ss", server: "1.1.1.4", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.9", port: 443, cipher: "aes-128-gcm", password: "p" }
        ]
    };
    const concordOut = main(JSON.parse(JSON.stringify(input)));
    const clashOut = clashMain(JSON.parse(JSON.stringify(input)));
    assert.deepEqual(
        concordOut["proxy-groups"].map(g => g.name),
        clashOut["proxy-groups"].map(g => g.name),
        "策略组结构应与 Clash 版一致"
    );
    assert.deepEqual(concordOut.rules, clashOut.rules, "规则序列应与 Clash 版一致");
    const staticGroup = concordOut["proxy-groups"].find(g => g.name === "静态");
    assert.ok(!staticGroup.proxies.includes("剩余流量：10GB"), "信息节点不进可选组");
    const hk = concordOut["proxy-groups"].find(g => g.name === "HK");
    assert.deepEqual(hk.proxies, ["HK 01", "HK 02"]);
});

check("concord-contract: 无可用节点时提示一次", () => {
    const { main, warnings } = loadConcord();
    const out = main({
        proxies: [
            { name: "剩余流量：10GB", type: "ss", server: "1.1.1.1", port: 443, cipher: "aes-128-gcm", password: "p" },
            { name: "TS", type: "tailscale", server: "x", port: 1 }
        ]
    });
    assert.equal(warnings.length, 1, "无可用节点应提示一次: " + warnings.join("; "));
    assert.ok(warnings[0].includes("REJECT"), "提示应说明 REJECT 占位");
    assert.deepEqual(out["proxy-groups"].find(g => g.name === "静态").proxies, ["REJECT"]);
});

console.log(`\nSummary: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
