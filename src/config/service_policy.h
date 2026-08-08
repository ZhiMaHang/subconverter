#ifndef SERVICE_POLICY_H_INCLUDED
#define SERVICE_POLICY_H_INCLUDED

#include <algorithm>
#include <array>
#include <string>
#include <utility>
#include <vector>

#include "config/proxygroup.h"
#include "config/ruleset.h"
#include "utils/string.h"

namespace service_policy
{
inline constexpr const char *BinanceName = "Binance";
inline constexpr const char *OpenAIName = "OpenAI";
inline constexpr const char *AnthropicName = "Anthropic";

inline constexpr const char *TaiwanGroupName = "🇨🇳 台湾节点";
inline constexpr const char *AIPlatformGroupName = "💬 Ai平台";

inline constexpr const char *BinanceRulesetUrl = "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Binance/Binance.yaml";
inline constexpr const char *OpenAIRulesetUrl = "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml";
inline constexpr const char *AnthropicRulesetUrl = "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Anthropic/Anthropic.yaml";

inline constexpr const char *TypedBinanceRulesetUrl = "clash-classic:https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Binance/Binance.yaml";
inline constexpr const char *TypedOpenAIRulesetUrl = "clash-classic:https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml";
inline constexpr const char *TypedAnthropicRulesetUrl = "clash-classic:https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Anthropic/Anthropic.yaml";

inline constexpr const char *TaiwanNodeRegex = R"((?i:\bTW[N]?\d*\b|Taiwan|臺灣|新北|彰化|\bCHT\b|台湾|[^-]台|\bHINET\b))";
inline constexpr const char *UnitedStatesNodeRegex = R"((?i:🇺🇸|🇺🇲|\bUS[A-Z]?\d*\b|United States|美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|达拉斯|達拉斯|波特兰|波特蘭|俄勒冈|俄勒岡|凤凰城|鳳凰城|费利蒙|費利蒙|拉斯维加斯|拉斯維加斯|圣克拉拉|聖克拉拉|芝加哥))";
inline constexpr int UpdateInterval = 86400;

struct Definition
{
    const char *Name;
    const char *RulesetUrl;
    const char *TypedRulesetUrl;
    const char *PreferredGroupName;
    const char *NodeRegex;
};

inline constexpr std::array<Definition, 3> Definitions{{
    {BinanceName, BinanceRulesetUrl, TypedBinanceRulesetUrl, TaiwanGroupName, TaiwanNodeRegex},
    {OpenAIName, OpenAIRulesetUrl, TypedOpenAIRulesetUrl, AIPlatformGroupName, UnitedStatesNodeRegex},
    {AnthropicName, AnthropicRulesetUrl, TypedAnthropicRulesetUrl, AIPlatformGroupName, UnitedStatesNodeRegex}
}};

inline bool hasName(const std::string &value, const Definition &definition)
{
    return toLower(trim(value)) == toLower(definition.Name);
}

inline bool hasRulesetUrl(const std::string &value, const Definition &definition)
{
    const std::string normalized = trim(value);
    return normalized == definition.RulesetUrl || normalized == definition.TypedRulesetUrl;
}

inline bool isManagedName(const std::string &value)
{
    return std::any_of(Definitions.cbegin(), Definitions.cend(), [&](const Definition &definition)
    {
        return hasName(value, definition);
    });
}

inline bool isManagedRulesetUrl(const std::string &value)
{
    return std::any_of(Definitions.cbegin(), Definitions.cend(), [&](const Definition &definition)
    {
        return hasRulesetUrl(value, definition);
    });
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

inline bool reachesManagedGroup(const ProxyGroupConfig &group, const ProxyGroupConfigs &groups,
                                std::vector<std::string> &visited_groups)
{
    for(const std::string &proxy : group.Proxies)
    {
        const std::string normalized = trim(proxy);
        if(!startsWith(normalized, "[]"))
            continue;

        const std::string referenced_name = trim(normalized.substr(2));
        if(isManagedName(referenced_name))
            return true;
        if(std::find(visited_groups.cbegin(), visited_groups.cend(), referenced_name) != visited_groups.cend())
            continue;

        visited_groups.emplace_back(referenced_name);
        for(const ProxyGroupConfig &referenced_group : groups)
        {
            if(referenced_group.Name == referenced_name &&
               reachesManagedGroup(referenced_group, groups, visited_groups))
                return true;
        }
    }
    return false;
}

inline bool safelyReferencesPreferredGroup(const ProxyGroupConfig &group, const ProxyGroupConfigs &groups)
{
    if(!isClashCompatibleGroup(group))
        return false;
    std::vector<std::string> visited_groups{group.Name};
    return !reachesManagedGroup(group, groups, visited_groups);
}

inline void enforce(ProxyGroupConfigs &groups, RulesetConfigs &rulesets)
{
    std::array<bool, Definitions.size()> has_preferred_group{};
    for(size_t definition_index = 0; definition_index < Definitions.size(); definition_index++)
    {
        const Definition &definition = Definitions[definition_index];
        for(ProxyGroupConfig &group : groups)
        {
            if(group.Name != definition.PreferredGroupName ||
               !safelyReferencesPreferredGroup(group, groups))
                continue;

            has_preferred_group[definition_index] = true;
            if(std::find(group.Proxies.cbegin(), group.Proxies.cend(), "[]REJECT") == group.Proxies.cend())
                group.Proxies.emplace_back("[]REJECT");
        }
    }

    groups.erase(std::remove_if(groups.begin(), groups.end(), [](const ProxyGroupConfig &group)
    {
        return isManagedName(group.Name);
    }), groups.end());

    for(size_t definition_index = 0; definition_index < Definitions.size(); definition_index++)
    {
        const Definition &definition = Definitions[definition_index];
        ProxyGroupConfig group;
        group.Name = definition.Name;
        group.Type = ProxyGroupType::Select;
        if(has_preferred_group[definition_index])
            group.Proxies.emplace_back(std::string("[]") + definition.PreferredGroupName);
        group.Proxies.emplace_back(definition.NodeRegex);
        group.Proxies.emplace_back("[]REJECT");
        groups.emplace_back(std::move(group));
    }

    rulesets.erase(std::remove_if(rulesets.begin(), rulesets.end(), [](const RulesetConfig &ruleset)
    {
        return isManagedName(ruleset.Group) || isManagedRulesetUrl(ruleset.Url);
    }), rulesets.end());

    std::vector<RulesetConfig> canonical_rulesets;
    canonical_rulesets.reserve(Definitions.size());
    for(const Definition &definition : Definitions)
    {
        RulesetConfig ruleset;
        ruleset.Group = definition.Name;
        ruleset.Url = definition.TypedRulesetUrl;
        ruleset.Interval = UpdateInterval;
        canonical_rulesets.emplace_back(std::move(ruleset));
    }
    rulesets.insert(rulesets.begin(), canonical_rulesets.begin(), canonical_rulesets.end());
}
}

#endif // SERVICE_POLICY_H_INCLUDED
