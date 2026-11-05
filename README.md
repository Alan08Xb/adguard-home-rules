# AdGuard Home 聚合规则

三档可选聚合黑名单：**Base（精简）** / **Pro（平衡）** / **Full（全面）**。

> 上次更新: 2026-11-06 01:52:33 (北京时间)

---

## 订阅地址

| 档位 | GitHub 订阅 | 镜像订阅（国内推荐） | 域名规则 |
|------|------------|---------------------|----------|
| **Base** | `https://raw.githubusercontent.com/Alan08Xb/adguard-home-rules/main/rules-base.txt` | `https://cdn.jsdelivr.net/gh/Alan08Xb/adguard-home-rules@main/rules-base.txt` | 127,380 |
| **Pro** | `https://raw.githubusercontent.com/Alan08Xb/adguard-home-rules/main/rules-pro.txt` | `https://cdn.jsdelivr.net/gh/Alan08Xb/adguard-home-rules@main/rules-pro.txt` | 282,950 |
| **Full** | `https://raw.githubusercontent.com/Alan08Xb/adguard-home-rules/main/rules-full.txt` | `https://cdn.jsdelivr.net/gh/Alan08Xb/adguard-home-rules@main/rules-full.txt` | 600,805 |

> 国内访问 GitHub 慢/失败时，请使用镜像订阅（jsDelivr CDN）。

---

## 三档说明

| 档位 | 规模 | 说明 |
|------|------|------|
| **Base** | 约 13 万 | 核心恶意/追踪 + 中文广告全覆盖，误伤最低，适合入门设备 |
| **Pro** | 约 28 万 | 覆盖更宽，平衡覆盖与误伤 |
| **Full** | 约 58 万 | 全部有效规则，最大化拦截 |

三档嵌套关系：**Base ⊂ Pro ⊂ Full**，升级时规则只增不减。

---

## 更新频率

每天自动更新（GitHub Actions 定时任务）。

---

## 规则来源

| 类别 | 规则源 |
|------|--------|
| 核心安全源（恶意/追踪/广告，低误伤） | [AdGuardSDNS](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) |
| 中文广告源 | [anti-AD](https://anti-ad.net/easylist.txt) |
| 中文广告源 | [AdGuard-Chinese](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt) |
| 中文广告源 | [AdGuard-Base](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt) |
| 中文广告源 | [AdGuard-Mobile](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [OISD-Full](https://big.oisd.nl/) |
| 核心安全源（恶意/追踪/广告，低误伤） | [AdRules-dns](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [AdRules-top](https://adrules.top/dns.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [HaGeZi-Pro](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) |
| 骚扰/长尾源（误伤较高） | [Fanboy-Annoy](https://secure.fanboy.co.nz/fanboy-annoyance.txt) |
| 骚扰/长尾源（误伤较高） | [CJX-Annoy](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) |
| 骚扰/长尾源（误伤较高） | [ChengFeng-mv](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt) |
| 骚扰/长尾源（误伤较高） | [Zhihu](https://raw.githubusercontent.com/zsakvo/AdGuard-Custom-Rule/master/rule/zhihu.txt) |
| 骚扰/长尾源（误伤较高） | [Kill-Baidu](https://raw.githubusercontent.com/banbendalao/ADgk/master/kill-baidu-ad.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [AdAway](https://adaway.org/hosts.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [EasyPrivacy](https://easylist.to/easylist/easyprivacy.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [1Hosts-Lite](https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/adblock.txt) |
| 中文广告源 | [EasyListChina](https://easylist-downloads.adblockplus.org/easylistchina.txt) |
| 骚扰/长尾源（误伤较高） | [AWAvenue](https://gcore.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Adguard-No.Unwelcome.txt) |
| 核心安全源（恶意/追踪/广告，低误伤） | [StevenBlack](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) |

---

## 使用方法

1. 打开 AdGuard Home 管理面板
2. 过滤器 -> DNS 黑名单
3. 添加黑名单 -> 添加自定义列表
4. 粘贴上表任一档位订阅地址
5. 点击检查更新
