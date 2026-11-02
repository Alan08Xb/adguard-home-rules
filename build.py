#!/usr/bin/env python3
"""
构建三档 AdGuard Home 聚合规则：Base / Pro / Full
==================================================
用法: python3 build.py

分档逻辑（保证 Base ⊂ Pro ⊂ Full 嵌套）:
  Base = 中文广告源全部 + 核心安全源高置信(域名出现在>=4个源)
  Pro  = Base + 核心安全源中置信(>=2) + 骚扰源高置信(>=2)
  Full = 全部唯一域名

输出:
  rules-base.txt  (约 13 万条)
  rules-pro.txt   (约 28 万条)
  rules-full.txt  (约 58 万条)
  sources.txt     (规则源清单, 带类别)
  README.md       (自动生成, 含三档订阅链接)

依赖: Python 3.8+ (标准库 urllib, 无第三方依赖)
"""
import re
import os
import sys
import time
from collections import defaultdict
from urllib.request import Request, urlopen

# ============ 配置 ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DL_DIR = os.path.join(BASE_DIR, "_downloads")
os.makedirs(DL_DIR, exist_ok=True)

# 规则源: (name, url, category)
# category: core=核心安全(恶意/追踪/广告), cn=中文广告, tail=骚扰/长尾
SOURCES = [
    ("AdGuardSDNS", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "core"),
    ("anti-AD", "https://anti-ad.net/easylist.txt", "cn"),
    ("AdGuard-Chinese", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt", "cn"),
    ("AdGuard-Base", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt", "cn"),
    ("AdGuard-Mobile", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt", "cn"),
    ("OISD-Full", "https://big.oisd.nl/", "core"),
    ("AdRules-dns", "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt", "core"),
    ("AdRules-top", "https://adrules.top/dns.txt", "core"),
    ("HaGeZi-Pro", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "core"),
    ("Fanboy-Annoy", "https://secure.fanboy.co.nz/fanboy-annoyance.txt", "tail"),
    ("CJX-Annoy", "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt", "tail"),
    ("ChengFeng-mv", "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt", "tail"),
    ("Zhihu", "https://raw.githubusercontent.com/zsakvo/AdGuard-Custom-Rule/master/rule/zhihu.txt", "tail"),
    ("Kill-Baidu", "https://raw.githubusercontent.com/banbendalao/ADgk/master/kill-baidu-ad.txt", "tail"),
    ("AdAway", "https://adaway.org/hosts.txt", "core"),
    ("EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt", "core"),
    ("1Hosts-Lite", "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/adblock.txt", "core"),
    ("EasyListChina", "https://easylist-downloads.adblockplus.org/easylistchina.txt", "cn"),
    ("AWAvenue", "https://gcore.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Adguard-No.Unwelcome.txt", "tail"),
    ("StevenBlack", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "core"),
]

CAT_LABEL = {
    "core": "核心安全源（恶意/追踪/广告，低误伤）",
    "cn": "中文广告源",
    "tail": "骚扰/长尾源（误伤较高）",
}

# 正则
PURE_RE = re.compile(r'^\|\|([a-z0-9\-_.]+)\^')
HOSTS_RE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)[ \t]+(\S+)')

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def download(url, fn, retries=3, timeout=60):
    """下载文件，带重试。返回是否成功。"""
    for i in range(retries):
        try:
            req = Request(url, headers=UA)
            with urlopen(req, timeout=timeout) as r, open(fn, "wb") as f:
                f.write(r.read())
            if os.path.getsize(fn) > 100:
                with open(fn, encoding="utf-8", errors="replace") as f:
                    head = f.read(2000).lower()
                if "<html" in head or "<!doctype" in head:
                    print(f"  [HTML跳过] {url}")
                    return False
                return True
        except Exception as e:
            print(f"  [重试{i+1}] {url}: {type(e).__name__}")
        time.sleep(2)
    print(f"  [FAIL] {url}")
    return False


def parse_domains(fn):
    """解析规则文件，返回 (域名集合, 白名单规则列表, 总行数)"""
    domains = set()
    wl = []
    total = 0
    try:
        with open(fn, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.rstrip("\r").strip()
                if not s or s.startswith("!") or s.startswith("#") or s.startswith("["):
                    continue
                total += 1
                if s.startswith("@@"):
                    wl.append(s)
                    continue
                m = PURE_RE.match(s)
                if m:
                    domains.add(m.group(1))
                    continue
                m = HOSTS_RE.match(s)
                if m:
                    domains.add(m.group(2))
                    continue
    except Exception as e:
        print(f"  [PARSE-ERR] {fn}: {e}")
    return domains, wl, total


def main():
    print("=" * 60)
    print("构建三档 AdGuard Home 聚合规则: Base / Pro / Full")
    print("=" * 60)

    # 1. 下载并解析所有源
    all_doms = {}
    wl_combined = []
    total_raw = 0
    valid_sources = 0
    failed_sources = []
    for name, url, cat in SOURCES:
        fn = os.path.join(DL_DIR, name.replace("-", "_") + ".txt")
        if not os.path.exists(fn) or os.path.getsize(fn) < 100:
            if not download(url, fn):
                failed_sources.append(name)
                continue
        doms, wl, total = parse_domains(fn)
        all_doms[name] = doms
        wl_combined.extend(wl)
        total_raw += total
        valid_sources += 1
        print(f"  {name:16s} {len(doms):>7} 域名  (raw {total})")

    if valid_sources == 0:
        print("错误: 所有规则源下载失败, 中止。")
        sys.exit(1)

    print(f"\n有效源: {valid_sources}/{len(SOURCES)}  原始行: {total_raw}")

    # 2. 计算置信度（域名出现在几个源中）
    confidence = defaultdict(int)
    for doms in all_doms.values():
        for d in doms:
            confidence[d] += 1

    # 3. 分档集合（按源类别 + 置信度）
    cn_all = set()
    core_all = set()
    tail_all = set()
    for name, url, cat in SOURCES:
        if name in all_doms:
            if cat == "cn":
                cn_all |= all_doms[name]
            elif cat == "core":
                core_all |= all_doms[name]
            else:
                tail_all |= all_doms[name]

    core_hi = {d for d in core_all if confidence[d] >= 4}
    core_mid = {d for d in core_all if confidence[d] >= 2}
    tail_mid = {d for d in tail_all if confidence[d] >= 2}

    base = cn_all | core_hi
    pro = base | core_mid | tail_mid
    full = set(confidence.keys())

    print(f"\n=== 三档域名规模 ===")
    print(f"  中文广告源: {len(cn_all)}")
    print(f"  核心安全源: {len(core_all)}")
    print(f"  核心高置信(>=4): {len(core_hi)}")
    print(f"  Base: {len(base)}")
    print(f"  Pro:  {len(pro)}")
    print(f"  Full: {len(full)}")
    print(f"  嵌套 Base⊂Pro⊂Full: {base <= pro <= full}")

    # 4. 白名单去重（保留第一个出现的，稳定）
    wl_seen = set()
    wl_dedup = []
    for w in wl_combined:
        if w not in wl_seen:
            wl_seen.add(w)
            wl_dedup.append(w)

    # 白名单里的域名（||domain^ 形式），用于豁免
    wl_domains = set()
    for w in wl_dedup:
        m = re.match(r"^@@\|\|([a-z0-9\-_.]+)\^", w)
        if m:
            wl_domains.add(m.group(1))

    print(f"\n白名单规则: {len(wl_dedup)}  白名单域名: {len(wl_domains)}")

    # 5. 生成三个规则文件
    tiers = {"Base": base, "Pro": pro, "Full": full}
    # 上海时区时间（跨平台: tzset 在 Unix 有, Windows 用固定偏移）
    if hasattr(time, "tzset"):
        os.environ["TZ"] = "Asia/Shanghai"
        time.tzset()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    else:
        # Windows: 北京 = UTC+8
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + 8 * 3600))

    tier_stats = {}
    for tier, doms in tiers.items():
        net = doms - wl_domains
        fn = os.path.join(BASE_DIR, f"rules-{tier.lower()}.txt")
        with open(fn, "w", encoding="utf-8") as f:
            f.write("! ==========================================\n")
            f.write(f"! AdGuard Home 聚合规则 - {tier} 档\n")
            f.write("! ==========================================\n")
            f.write(f"! 更新时间: {timestamp} (北京时间)\n")
            f.write(f"! 有效规则源: {valid_sources}/{len(SOURCES)}\n")
            f.write(f"! 域名规则: {len(net)}\n")
            f.write(f"! 白名单: {len(wl_dedup)}\n")
            f.write("! ==========================================\n\n")
            f.write(f"! --- 白名单 {len(wl_dedup)} 条 ---\n")
            for w in wl_dedup:
                f.write(w + "\n")
            f.write("\n")
            f.write(f"! --- 域名屏蔽 {len(net)} 条 ---\n")
            for d in sorted(net):
                f.write(f"||{d}^\n")
        tier_stats[tier] = (len(net), len(wl_dedup))
        print(f"  已生成 rules-{tier.lower()}.txt: {len(net)} 域名规则 + {len(wl_dedup)} 白名单")

    # 6. 生成 sources.txt（带类别注释）
    with open(os.path.join(BASE_DIR, "sources.txt"), "w", encoding="utf-8") as f:
        f.write("# AdGuard Home 三档聚合规则 - 规则源清单\n")
        f.write("# 格式: 类别 | 名称 | URL\n")
        f.write("# 类别: core=核心安全, cn=中文广告, tail=骚扰/长尾\n\n")
        for name, url, cat in SOURCES:
            f.write(f"{cat} | {name} | {url}\n")

    # 7. 生成 README.md
    repo_url = "https://raw.githubusercontent.com/Alan08Xb/adguard-home-rules/main"
    mirror_url = "https://cdn.jsdelivr.net/gh/Alan08Xb/adguard-home-rules@main"
    with open(os.path.join(BASE_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write("# AdGuard Home 聚合规则\n\n")
        f.write("三档可选聚合黑名单：**Base（精简）** / **Pro（平衡）** / **Full（全面）**。\n\n")
        f.write("> 上次更新: " + timestamp + " (北京时间)\n\n")
        f.write("---\n\n")
        f.write("## 订阅地址\n\n")
        f.write("| 档位 | GitHub 订阅 | 镜像订阅（国内推荐） | 域名规则 |\n")
        f.write("|------|------------|---------------------|----------|\n")
        for tier in ["Base", "Pro", "Full"]:
            net_count, wl_count = tier_stats[tier]
            f.write(f"| **{tier}** | `{repo_url}/rules-{tier.lower()}.txt` | `{mirror_url}/rules-{tier.lower()}.txt` | {net_count:,} |\n")
        f.write("\n")
        f.write("> 国内访问 GitHub 慢/失败时，请使用镜像订阅（jsDelivr CDN）。\n\n")
        f.write("---\n\n")
        f.write("## 三档说明\n\n")
        f.write("| 档位 | 规模 | 说明 |\n")
        f.write("|------|------|------|\n")
        f.write("| **Base** | 约 13 万 | 核心恶意/追踪 + 中文广告全覆盖，误伤最低，适合入门设备 |\n")
        f.write("| **Pro** | 约 28 万 | 覆盖更宽，平衡覆盖与误伤 |\n")
        f.write("| **Full** | 约 58 万 | 全部有效规则，最大化拦截 |\n\n")
        f.write("三档嵌套关系：**Base ⊂ Pro ⊂ Full**，升级时规则只增不减。\n\n")
        f.write("---\n\n")
        f.write("## 更新频率\n\n")
        f.write("每天自动更新（GitHub Actions 定时任务）。\n\n")
        f.write("---\n\n")
        f.write("## 规则来源\n\n")
        f.write("| 类别 | 规则源 |\n")
        f.write("|------|--------|\n")
        for name, url, cat in SOURCES:
            f.write(f"| {CAT_LABEL[cat]} | [{name}]({url}) |\n")
        f.write("\n")
        f.write("---\n\n")
        f.write("## 使用方法\n\n")
        f.write("1. 打开 AdGuard Home 管理面板\n")
        f.write("2. 过滤器 -> DNS 黑名单\n")
        f.write("3. 添加黑名单 -> 添加自定义列表\n")
        f.write("4. 粘贴上表任一档位订阅地址\n")
        f.write("5. 点击检查更新\n")

    # 8. 汇总
    print("\n=== 完成 ===")
    for tier, doms in tiers.items():
        print(f"  {tier}: {len(doms - wl_domains)} 条有效域名规则")


if __name__ == "__main__":
    main()
