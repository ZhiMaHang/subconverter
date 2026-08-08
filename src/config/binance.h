#ifndef BINANCE_H_INCLUDED
#define BINANCE_H_INCLUDED

#include <algorithm>
#include <string>
#include <utility>

#include "config/proxygroup.h"
#include "config/ruleset.h"
#include "utils/string.h"

namespace binance_policy
{
inline constexpr const char *Name = "Binance";
inline constexpr const char *TaiwanGroupName = "🇨🇳 台湾节点";
inline constexpr const char *RulesetUrl = "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Binance/Binance.yaml";
inline constexpr const char *TypedRulesetUrl = "clash-classic:https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Binance/Binance.yaml";
inline constexpr const char *TaiwanNodeRegex = R"((?i:\bTW[N]?\d*\b|Taiwan|臺灣|新北|彰化|\bCHT\b|台湾|[^-]台|\bHINET\b))";
inline constexpr int UpdateInterval = 86400;

inline bool hasBinanceName(const std::string &value)
{
    return toLower(trim(value)) == "binance";
}

inline bool hasBinanceRulesetUrl(const std::string &value)
{
    const std::string normalized = trim(value);
    return normalized == RulesetUrl || normalized == TypedRulesetUrl;
}

inline bool isClashCompatibleGroup(const ProxyGroupConfig &group)
{
    switch(group.Type)
    {
    case ProxyGroupType::Select:
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
    case ProxyGroupType::LoadBalance:
    case ProxyGroupType::Relay:
    case ProxyGroupType::Smart:
        return true;
    case ProxyGroupType::SSID:
        return false;
    }
    return false;
}

inline void enforce(ProxyGroupConfigs &groups, RulesetConfigs &rulesets)
{
    bool has_taiwan_group = false;
    for(ProxyGroupConfig &group : groups)
    {
        if(group.Name != TaiwanGroupName || !isClashCompatibleGroup(group))
            continue;

        has_taiwan_group = true;
        if(std::find(group.Proxies.cbegin(), group.Proxies.cend(), "[]REJECT") == group.Proxies.cend())
            group.Proxies.emplace_back("[]REJECT");
    }

    groups.erase(std::remove_if(groups.begin(), groups.end(), [](const ProxyGroupConfig &group)
    {
        return hasBinanceName(group.Name);
    }), groups.end());

    ProxyGroupConfig group;
    group.Name = Name;
    group.Type = ProxyGroupType::Select;
    if(has_taiwan_group)
        group.Proxies.emplace_back(std::string("[]") + TaiwanGroupName);
    group.Proxies.emplace_back(TaiwanNodeRegex);
    group.Proxies.emplace_back("[]REJECT");
    groups.emplace_back(std::move(group));

    rulesets.erase(std::remove_if(rulesets.begin(), rulesets.end(), [](const RulesetConfig &ruleset)
    {
        return hasBinanceName(ruleset.Group) || hasBinanceRulesetUrl(ruleset.Url);
    }), rulesets.end());

    RulesetConfig ruleset;
    ruleset.Group = Name;
    ruleset.Url = TypedRulesetUrl;
    ruleset.Interval = UpdateInterval;
    rulesets.insert(rulesets.begin(), std::move(ruleset));
}
}

#endif // BINANCE_H_INCLUDED
