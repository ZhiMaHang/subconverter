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

inline void enforce(ProxyGroupConfigs &groups, RulesetConfigs &rulesets)
{
    groups.erase(std::remove_if(groups.begin(), groups.end(), [](const ProxyGroupConfig &group)
    {
        return hasBinanceName(group.Name);
    }), groups.end());

    ProxyGroupConfig group;
    group.Name = Name;
    group.Type = ProxyGroupType::Select;
    group.Proxies = {TaiwanNodeRegex, "[]REJECT"};
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
