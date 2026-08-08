#ifndef BINANCE_H_INCLUDED
#define BINANCE_H_INCLUDED

#include "config/service_policy.h"

// Compatibility facade for downstream code that included the original
// Binance-only policy header.
namespace binance_policy
{
inline constexpr const char *Name = service_policy::BinanceName;
inline constexpr const char *TaiwanGroupName = service_policy::TaiwanGroupName;
inline constexpr const char *RulesetUrl = service_policy::BinanceRulesetUrl;
inline constexpr const char *TypedRulesetUrl = service_policy::TypedBinanceRulesetUrl;
inline constexpr const char *TaiwanNodeRegex = service_policy::TaiwanNodeRegex;
inline constexpr int UpdateInterval = service_policy::UpdateInterval;

inline bool hasBinanceName(const std::string &value)
{
    return service_policy::hasName(value, service_policy::Definitions[0]);
}

inline bool hasBinanceRulesetUrl(const std::string &value)
{
    return service_policy::hasRulesetUrl(value, service_policy::Definitions[0]);
}

inline bool isClashCompatibleGroup(const ProxyGroupConfig &group)
{
    return service_policy::isClashCompatibleGroup(group);
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
