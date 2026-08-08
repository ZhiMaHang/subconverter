#include <algorithm>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/binance.h"
#include "generator/config/subexport.h"
#include "parser/subparser.h"

namespace
{
void require(bool condition, const std::string &message)
{
    if(!condition)
        throw std::runtime_error(message);
}

std::shared_future<std::string> readyFuture(const std::string &value)
{
    return std::async(std::launch::deferred, [value]() { return value; }).share();
}

size_t countBinanceGroups(const ProxyGroupConfigs &groups)
{
    return static_cast<size_t>(std::count_if(groups.cbegin(), groups.cend(), [](const ProxyGroupConfig &group)
    {
        return binance_policy::hasBinanceName(group.Name);
    }));
}

size_t countBinanceRulesets(const RulesetConfigs &rulesets)
{
    return static_cast<size_t>(std::count_if(rulesets.cbegin(), rulesets.cend(), [](const RulesetConfig &ruleset)
    {
        return binance_policy::hasBinanceName(ruleset.Group) || binance_policy::hasBinanceRulesetUrl(ruleset.Url);
    }));
}

std::vector<RulesetContent> makeRulesetContent()
{
    return {
        {binance_policy::Name, binance_policy::RulesetUrl, binance_policy::TypedRulesetUrl,
         RULESET_CLASH_CLASSICAL,
         readyFuture("payload:\n  - DOMAIN-SUFFIX,binance.example\n"),
         binance_policy::UpdateInterval},
        {"Fallback", "", "", RULESET_SURGE, readyFuture("[]FINAL"), 0}
    };
}

std::vector<Proxy> makeNodes()
{
    Proxy taiwan;
    Proxy united_states;
    explode("vless://11111111-1111-4111-8111-111111111111@192.0.2.10:443?encryption=none&security=tls&type=tcp&sni=example.com#TW01", taiwan);
    explode("vless://22222222-2222-4222-8222-222222222222@192.0.2.20:443?encryption=none&security=tls&type=tcp&sni=example.com#US01", united_states);
    return {std::move(taiwan), std::move(united_states)};
}

std::vector<std::string> readRules(const YAML::Node &config)
{
    std::vector<std::string> rules;
    for(const YAML::Node &rule : config["rules"])
        rules.emplace_back(rule.as<std::string>());
    return rules;
}

void testExternalConfigCannotRemoveBinance()
{
    ProxyGroupConfig external_group;
    external_group.Name = "External";
    external_group.Type = ProxyGroupType::Select;
    external_group.Proxies = {".*"};

    ProxyGroupConfig wrong_binance_group;
    wrong_binance_group.Name = " binance ";
    wrong_binance_group.Type = ProxyGroupType::Select;
    wrong_binance_group.Proxies = {".*", "[]DIRECT"};

    ProxyGroupConfigs groups{external_group, wrong_binance_group, wrong_binance_group};
    RulesetConfigs rulesets{
        {"External", "https://rules.example/external.list", 3600},
        {"Wrong", binance_policy::RulesetUrl, 60},
        {"BINANCE", "https://rules.example/wrong.list", 60},
        {"Fallback", "[]FINAL", 0}
    };

    binance_policy::enforce(groups, rulesets);
    binance_policy::enforce(groups, rulesets);

    require(countBinanceGroups(groups) == 1, "Binance proxy group was not normalized to one entry");
    require(countBinanceRulesets(rulesets) == 1, "Binance ruleset was not normalized to one entry");
    require(groups.back().Name == binance_policy::Name, "canonical Binance proxy group is missing");
    require(groups.back().Type == ProxyGroupType::Select, "Binance proxy group must be select");
    require(groups.back().Proxies == string_array({binance_policy::TaiwanNodeRegex, "[]REJECT"}),
            "Binance proxy group must select Taiwan nodes and fall back to REJECT");
    require(rulesets.front().Group == binance_policy::Name, "Binance ruleset must be first");
    require(rulesets.front().Url == binance_policy::TypedRulesetUrl, "Binance ruleset URL/type is wrong");
    require(rulesets.front().Interval == binance_policy::UpdateInterval, "Binance ruleset interval must be 24 hours");
    require(rulesets[1].Group == "External" && rulesets[2].Group == "Fallback",
            "non-Binance ruleset order changed");
}

void testTaiwanPolicyGroupIsPreferredWhenPresent()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = binance_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {binance_policy::TaiwanNodeRegex};

    ProxyGroupConfigs groups{taiwan_group};
    RulesetConfigs rulesets;
    binance_policy::enforce(groups, rulesets);

    require(groups.size() == 2, "Taiwan policy group must be preserved");
    require(groups.front().Proxies == string_array({binance_policy::TaiwanNodeRegex, "[]REJECT"}),
            "Taiwan policy group must reject instead of falling back to DIRECT when empty");
    const ProxyGroupConfig &binance_group = groups.back();
    require(binance_group.Proxies == string_array({
                std::string("[]") + binance_policy::TaiwanGroupName,
                binance_policy::TaiwanNodeRegex,
                "[]REJECT"
            }),
            "Binance must prefer the existing Taiwan policy group and keep safe fallbacks");
}

void testInvalidTaiwanPolicyGroupsDoNotCreateDanglingReferences()
{
    ProxyGroupConfig spaced;
    spaced.Name = std::string(" ") + binance_policy::TaiwanGroupName + " ";
    spaced.Type = ProxyGroupType::Select;

    ProxyGroupConfig unsupported;
    unsupported.Name = binance_policy::TaiwanGroupName;
    unsupported.Type = ProxyGroupType::SSID;

    for(const ProxyGroupConfig &invalid_group : ProxyGroupConfigs{spaced, unsupported})
    {
        ProxyGroupConfigs groups{invalid_group};
        RulesetConfigs rulesets;
        binance_policy::enforce(groups, rulesets);

        const ProxyGroupConfig &binance_group = groups.back();
        require(binance_group.Proxies == string_array({binance_policy::TaiwanNodeRegex, "[]REJECT"}),
                "invalid Taiwan policy groups must not create dangling references");
    }
}

void testProviderModeEmitsBinanceRuleSet()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = binance_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {binance_policy::TaiwanNodeRegex};
    ProxyGroupConfigs groups{taiwan_group};
    RulesetConfigs rulesets;
    binance_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes = makeNodes();
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = true;
    ext.managed_config_prefix = "https://config.example.com";

    const std::string output = proxyToClash(nodes, "mode: rule\n", ruleset_content, groups, false, ext);
    const YAML::Node config = YAML::Load(output);
    const std::vector<std::string> rules = readRules(config);

    require(config["rule-providers"]["Binance"].IsMap(), "Binance rule provider is missing");
    require(config["rule-providers"]["Binance"]["behavior"].as<std::string>() == "classical",
            "Binance rule provider must use classical behavior");
    require(config["rule-providers"]["Binance"]["url"].as<std::string>() == binance_policy::RulesetUrl,
            "Binance rule provider URL is wrong");
    require(config["rule-providers"]["Binance"]["interval"].as<int>() == binance_policy::UpdateInterval,
            "Binance provider interval must be 24 hours");
    require(!rules.empty() && rules.front() == "RULE-SET,Binance,Binance",
            "provider mode must emit RULE-SET,Binance,Binance before other rules");
    require(std::find(rules.cbegin(), rules.cend(), "MATCH,Fallback") != rules.cend(),
            "provider mode terminal rule is missing");

    const YAML::Node proxy_groups = config["proxy-groups"];
    size_t binance_group_count = 0;
    size_t taiwan_group_count = 0;
    for(const YAML::Node &group : proxy_groups)
    {
        if(group["name"].as<std::string>() == binance_policy::TaiwanGroupName)
        {
            taiwan_group_count++;
            require(group["proxies"].size() == 2,
                    "Taiwan policy group must contain its Taiwan node and REJECT");
            require(group["proxies"][0].as<std::string>() == "TW01" &&
                    group["proxies"][1].as<std::string>() == "REJECT",
                    "Taiwan policy group must never fall back to DIRECT");
        }
        if(group["name"].as<std::string>() == binance_policy::Name)
        {
            binance_group_count++;
            require(group["proxies"].size() == 3,
                    "Binance group must contain the Taiwan policy group, Taiwan node and REJECT");
            require(group["proxies"][0].as<std::string>() == binance_policy::TaiwanGroupName,
                    "Binance group must prefer the existing Taiwan policy group");
            require(group["proxies"][1].as<std::string>() == "TW01",
                    "Binance group must retain direct Taiwan-node matching");
            require(group["proxies"][2].as<std::string>() == "REJECT",
                    "Binance group must fall back to REJECT");
        }
    }
    require(taiwan_group_count == 1, "generated config must contain one Taiwan policy group");
    require(binance_group_count == 1, "generated config must contain one Binance proxy group");
}

void testEmptyTaiwanPolicyRejectsInsteadOfUsingDirect()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = binance_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {binance_policy::TaiwanNodeRegex};
    ProxyGroupConfigs groups{taiwan_group};
    RulesetConfigs rulesets;
    binance_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = true;
    ext.managed_config_prefix = "https://config.example.com";

    const YAML::Node config = YAML::Load(proxyToClash(nodes, "mode: rule\n", ruleset_content, groups, false, ext));
    bool found_taiwan_group = false;
    bool found_binance_group = false;
    for(const YAML::Node &group : config["proxy-groups"])
    {
        const std::string name = group["name"].as<std::string>();
        if(name == binance_policy::TaiwanGroupName)
        {
            found_taiwan_group = true;
            require(group["proxies"].size() == 1 && group["proxies"][0].as<std::string>() == "REJECT",
                    "an empty Taiwan group must reject instead of using DIRECT");
        }
        if(name == binance_policy::Name)
        {
            found_binance_group = true;
            require(group["proxies"].size() == 2 &&
                    group["proxies"][0].as<std::string>() == binance_policy::TaiwanGroupName &&
                    group["proxies"][1].as<std::string>() == "REJECT",
                    "Binance must route through the rejecting Taiwan group when no Taiwan node exists");
        }
    }
    require(found_taiwan_group && found_binance_group,
            "empty-node output must retain both Taiwan and Binance policy groups");
}

void testExpandedModeExpandsBinanceRules()
{
    ProxyGroupConfigs groups;
    RulesetConfigs rulesets;
    binance_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = true;

    const std::string output = proxyToClash(nodes, "mode: rule\n", ruleset_content, groups, false, ext);
    const YAML::Node config = YAML::Load(output);
    const std::vector<std::string> rules = readRules(config);

    require(!config["rule-providers"].IsDefined(), "expanded mode must not emit a Binance provider");
    require(std::find(rules.cbegin(), rules.cend(), "RULE-SET,Binance,Binance") == rules.cend(),
            "expanded mode must not emit RULE-SET,Binance,Binance");
    require(!rules.empty() && rules.front() == "DOMAIN-SUFFIX,binance.example,Binance",
            "expanded Binance rule must precede other rules");
    require(std::find(rules.cbegin(), rules.cend(), "MATCH,Fallback") != rules.cend(),
            "expanded mode terminal rule is missing");
}
}

int main()
{
    try
    {
        testExternalConfigCannotRemoveBinance();
        testTaiwanPolicyGroupIsPreferredWhenPresent();
        testInvalidTaiwanPolicyGroupsDoNotCreateDanglingReferences();
        testProviderModeEmitsBinanceRuleSet();
        testEmptyTaiwanPolicyRejectsInsteadOfUsingDirect();
        testExpandedModeExpandsBinanceRules();
        std::cout << "Binance policy tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Binance policy test failure: " << error.what() << std::endl;
        return 1;
    }
}
