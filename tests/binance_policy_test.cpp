#include <algorithm>
#include <array>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/service_policy.h"
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

const ProxyGroupConfig &findGroup(const ProxyGroupConfigs &groups, const std::string &name)
{
    const auto group = std::find_if(groups.cbegin(), groups.cend(), [&](const ProxyGroupConfig &candidate)
    {
        return candidate.Name == name;
    });
    if(group == groups.cend())
        throw std::runtime_error("missing proxy group: " + name);
    return *group;
}

size_t countGroupsNamed(const ProxyGroupConfigs &groups, const std::string &name)
{
    return static_cast<size_t>(std::count_if(groups.cbegin(), groups.cend(), [&](const ProxyGroupConfig &group)
    {
        return group.Name == name;
    }));
}

size_t countRulesetsFor(const RulesetConfigs &rulesets, const std::string &name, const std::string &url)
{
    return static_cast<size_t>(std::count_if(rulesets.cbegin(), rulesets.cend(), [&](const RulesetConfig &ruleset)
    {
        return toLower(trim(ruleset.Group)) == toLower(name) || trim(ruleset.Url) == url ||
               trim(ruleset.Url) == std::string("clash-classic:") + url;
    }));
}

std::vector<RulesetContent> makeRulesetContent()
{
    return {
        {service_policy::BinanceName, service_policy::BinanceRulesetUrl, service_policy::TypedBinanceRulesetUrl,
         RULESET_CLASH_CLASSICAL,
         readyFuture("payload:\n  - DOMAIN-SUFFIX,binance.example\n"),
         service_policy::UpdateInterval},
        {service_policy::OpenAIName, service_policy::OpenAIRulesetUrl, service_policy::TypedOpenAIRulesetUrl,
         RULESET_CLASH_CLASSICAL,
         readyFuture("payload:\n  - DOMAIN-SUFFIX,openai.example\n  - IP-ASN,20473\n"),
         service_policy::UpdateInterval},
        {service_policy::AnthropicName, service_policy::AnthropicRulesetUrl, service_policy::TypedAnthropicRulesetUrl,
         RULESET_CLASH_CLASSICAL,
         readyFuture("payload:\n  - DOMAIN-SUFFIX,anthropic.example\n"),
         service_policy::UpdateInterval},
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

const YAML::Node findYamlGroup(const YAML::Node &config, const std::string &name)
{
    for(const YAML::Node &group : config["proxy-groups"])
    {
        if(group["name"].as<std::string>() == name)
            return group;
    }
    throw std::runtime_error("missing generated proxy group: " + name);
}

void requireYamlProxies(const YAML::Node &group, const std::vector<std::string> &expected,
                        const std::string &message)
{
    require(group["proxies"].size() == expected.size(), message + " (wrong proxy count)");
    for(size_t index = 0; index < expected.size(); index++)
    {
        require(group["proxies"][index].as<std::string>() == expected[index],
                message + " (wrong proxy at index " + std::to_string(index) + ")");
    }
}

void testExternalConfigCannotRemoveManagedPolicies()
{
    ProxyGroupConfig external_group;
    external_group.Name = "External";
    external_group.Type = ProxyGroupType::Select;
    external_group.Proxies = {".*"};

    ProxyGroupConfig ai_platform_group;
    ai_platform_group.Name = service_policy::AIPlatformGroupName;
    ai_platform_group.Type = ProxyGroupType::Select;
    ai_platform_group.Proxies = {service_policy::UnitedStatesNodeRegex};

    ProxyGroupConfigs groups{external_group, ai_platform_group};
    for(const char *name : {service_policy::BinanceName, service_policy::OpenAIName,
                            service_policy::AnthropicName})
    {
        ProxyGroupConfig duplicate;
        duplicate.Name = std::string(" ") + toLower(name) + " ";
        duplicate.Type = ProxyGroupType::Select;
        duplicate.Proxies = {".*", "[]DIRECT"};
        groups.emplace_back(duplicate);
        groups.emplace_back(std::move(duplicate));
    }

    RulesetConfigs rulesets{
        {"External", "https://rules.example/external.list", 3600},
        {"Wrong Binance", service_policy::BinanceRulesetUrl, 60},
        {"OPENAI", "https://rules.example/wrong-openai.list", 60},
        {"Wrong Anthropic", service_policy::TypedAnthropicRulesetUrl, 60},
        {"Fallback", "[]FINAL", 0}
    };

    service_policy::enforce(groups, rulesets);
    service_policy::enforce(groups, rulesets);

    for(const char *name : {service_policy::BinanceName, service_policy::OpenAIName,
                            service_policy::AnthropicName})
        require(countGroupsNamed(groups, name) == 1, std::string(name) + " group was not normalized to one entry");

    require(countRulesetsFor(rulesets, service_policy::BinanceName, service_policy::BinanceRulesetUrl) == 1,
            "Binance ruleset was not normalized to one entry");
    require(countRulesetsFor(rulesets, service_policy::OpenAIName, service_policy::OpenAIRulesetUrl) == 1,
            "OpenAI ruleset was not normalized to one entry");
    require(countRulesetsFor(rulesets, service_policy::AnthropicName, service_policy::AnthropicRulesetUrl) == 1,
            "Anthropic ruleset was not normalized to one entry");

    const std::array<const char *, 3> names{
        service_policy::BinanceName, service_policy::OpenAIName, service_policy::AnthropicName
    };
    const std::array<const char *, 3> typed_urls{
        service_policy::TypedBinanceRulesetUrl,
        service_policy::TypedOpenAIRulesetUrl,
        service_policy::TypedAnthropicRulesetUrl
    };
    require(rulesets.size() == 5, "managed ruleset normalization changed the non-managed rulesets");
    for(size_t index = 0; index < names.size(); index++)
    {
        require(rulesets[index].Group == names[index], "managed rulesets are not in Binance/OpenAI/Anthropic order");
        require(rulesets[index].Url == typed_urls[index], std::string(names[index]) + " ruleset URL/type is wrong");
        require(rulesets[index].Interval == service_policy::UpdateInterval,
                std::string(names[index]) + " ruleset interval must be 24 hours");
    }
    require(rulesets[3].Group == "External" && rulesets[4].Group == "Fallback",
            "non-managed ruleset order changed");
}

void testPreferredPolicyGroupsAndFallbacks()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = service_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {service_policy::TaiwanNodeRegex};

    ProxyGroupConfig ai_platform_group;
    ai_platform_group.Name = service_policy::AIPlatformGroupName;
    ai_platform_group.Type = ProxyGroupType::Select;
    ai_platform_group.Proxies = {service_policy::UnitedStatesNodeRegex};

    ProxyGroupConfigs groups{taiwan_group, ai_platform_group};
    RulesetConfigs rulesets;
    service_policy::enforce(groups, rulesets);

    require(findGroup(groups, service_policy::BinanceName).Proxies == string_array({
                std::string("[]") + service_policy::TaiwanGroupName,
                service_policy::TaiwanNodeRegex,
                "[]REJECT"
            }), "Binance must prefer the exact Taiwan policy group and keep safe fallbacks");
    for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
    {
        require(findGroup(groups, name).Proxies == string_array({
                    std::string("[]") + service_policy::AIPlatformGroupName,
                    service_policy::UnitedStatesNodeRegex,
                    "[]REJECT"
                }), std::string(name) + " must prefer the exact AI platform group, then compatible nodes, then REJECT");
    }

    ProxyGroupConfigs no_ai_group{taiwan_group};
    RulesetConfigs no_ai_rulesets;
    service_policy::enforce(no_ai_group, no_ai_rulesets);
    for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
    {
        require(findGroup(no_ai_group, name).Proxies == string_array({
                    service_policy::UnitedStatesNodeRegex,
                    "[]REJECT"
                }), std::string(name) + " must use compatible nodes then REJECT when the AI platform group is absent");
    }
}

void testInvalidPreferredGroupsDoNotCreateDanglingReferences()
{
    ProxyGroupConfig spaced_ai;
    spaced_ai.Name = std::string(" ") + service_policy::AIPlatformGroupName + " ";
    spaced_ai.Type = ProxyGroupType::Select;

    ProxyGroupConfig unsupported_ai;
    unsupported_ai.Name = service_policy::AIPlatformGroupName;
    unsupported_ai.Type = ProxyGroupType::SSID;

    for(const ProxyGroupConfig &invalid_group : ProxyGroupConfigs{spaced_ai, unsupported_ai})
    {
        ProxyGroupConfigs groups{invalid_group};
        RulesetConfigs rulesets;
        service_policy::enforce(groups, rulesets);

        for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
        {
            require(findGroup(groups, name).Proxies == string_array({
                        service_policy::UnitedStatesNodeRegex,
                        "[]REJECT"
                    }), std::string(name) + " must not reference an invalid AI platform group");
        }
    }

    ProxyGroupConfig cyclic_ai;
    cyclic_ai.Name = service_policy::AIPlatformGroupName;
    cyclic_ai.Type = ProxyGroupType::Select;
    cyclic_ai.Proxies = {"[]Bridge"};

    ProxyGroupConfig bridge;
    bridge.Name = "Bridge";
    bridge.Type = ProxyGroupType::Select;
    bridge.Proxies = {"[]OpenAI"};

    ProxyGroupConfigs cyclic_groups{cyclic_ai, bridge};
    RulesetConfigs cyclic_rulesets;
    service_policy::enforce(cyclic_groups, cyclic_rulesets);
    for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
    {
        require(findGroup(cyclic_groups, name).Proxies == string_array({
                    service_policy::UnitedStatesNodeRegex,
                    "[]REJECT"
                }), std::string(name) + " must not create a cycle through the AI platform group");
    }
}

void testProviderModeEmitsAllManagedRuleSets()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = service_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {service_policy::TaiwanNodeRegex};

    ProxyGroupConfig ai_platform_group;
    ai_platform_group.Name = service_policy::AIPlatformGroupName;
    ai_platform_group.Type = ProxyGroupType::Select;
    ai_platform_group.Proxies = {service_policy::UnitedStatesNodeRegex};

    ProxyGroupConfigs groups{taiwan_group, ai_platform_group};
    RulesetConfigs rulesets;
    service_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes = makeNodes();
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = false;
    ext.managed_config_prefix = "https://config.example.com";
    ext.clash_doh = true;

    const YAML::Node config = YAML::Load(proxyToClash(
        nodes, "mode: rule\nrules:\n  - GEOIP,CN,OpenAI\n  - MATCH,Base\n",
        ruleset_content, groups, false, ext));
    const std::vector<std::string> rules = readRules(config);

    struct ProviderExpectation
    {
        const char *Name;
        const char *Url;
    };
    const std::array<ProviderExpectation, 3> providers{{
        {service_policy::BinanceName, service_policy::BinanceRulesetUrl},
        {service_policy::OpenAIName, service_policy::OpenAIRulesetUrl},
        {service_policy::AnthropicName, service_policy::AnthropicRulesetUrl}
    }};
    require(rules.size() >= providers.size() + 1, "provider mode emitted too few rules");
    for(size_t index = 0; index < providers.size(); index++)
    {
        const ProviderExpectation &expected = providers[index];
        const YAML::Node provider = config["rule-providers"][expected.Name];
        require(provider.IsMap(), std::string(expected.Name) + " rule provider is missing");
        require(provider["behavior"].as<std::string>() == "classical",
                std::string(expected.Name) + " rule provider must use classical behavior");
        require(provider["url"].as<std::string>() == expected.Url,
                std::string(expected.Name) + " rule provider URL is wrong");
        require(provider["interval"].as<int>() == service_policy::UpdateInterval,
                std::string(expected.Name) + " provider interval must be 24 hours");
        require(rules[index] == std::string("RULE-SET,") + expected.Name + "," + expected.Name,
                "managed provider rules are not in Binance/OpenAI/Anthropic order");
    }
    const auto match = std::find(rules.cbegin(), rules.cend(), "MATCH,Fallback");
    require(match != rules.cend() && static_cast<size_t>(std::distance(rules.cbegin(), match)) >= providers.size(),
            "managed provider rules must precede MATCH");
    require(std::find(rules.cbegin(), rules.cend(), "MATCH,Base") != rules.cend(),
            "provider mode must retain base rules when overwrite_original_rules is false");
    const auto doh_rule = std::find(rules.cbegin(), rules.cend(), "GEOIP,CN,DIRECT,no-resolve");
    require(doh_rule != rules.cend() &&
            static_cast<size_t>(std::distance(rules.cbegin(), doh_rule)) >= providers.size(),
            "managed provider rules must remain ahead of the normalized DoH CN rule");

    requireYamlProxies(findYamlGroup(config, service_policy::TaiwanGroupName), {"TW01", "REJECT"},
                       "Taiwan policy group must never fall back to DIRECT");
    requireYamlProxies(findYamlGroup(config, service_policy::AIPlatformGroupName), {"US01", "REJECT"},
                       "AI platform group must retain compatible nodes and reject safely");
    requireYamlProxies(findYamlGroup(config, service_policy::BinanceName),
                       {service_policy::TaiwanGroupName, "TW01", "REJECT"},
                       "Binance must prefer the Taiwan group, then matching nodes, then REJECT");
    for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
    {
        requireYamlProxies(findYamlGroup(config, name), {service_policy::AIPlatformGroupName, "US01", "REJECT"},
                           std::string(name) + " must prefer the AI platform group, then matching nodes, then REJECT");
    }
}

void testEmptyPreferredPolicyGroupsRejectInsteadOfUsingDirect()
{
    ProxyGroupConfig taiwan_group;
    taiwan_group.Name = service_policy::TaiwanGroupName;
    taiwan_group.Type = ProxyGroupType::Select;
    taiwan_group.Proxies = {service_policy::TaiwanNodeRegex};

    ProxyGroupConfig ai_platform_group;
    ai_platform_group.Name = service_policy::AIPlatformGroupName;
    ai_platform_group.Type = ProxyGroupType::Select;
    ai_platform_group.Proxies = {service_policy::UnitedStatesNodeRegex};

    ProxyGroupConfigs groups{taiwan_group, ai_platform_group};
    RulesetConfigs rulesets;
    service_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = true;
    ext.managed_config_prefix = "https://config.example.com";

    const YAML::Node config = YAML::Load(proxyToClash(nodes, "mode: rule\n", ruleset_content, groups, false, ext));
    requireYamlProxies(findYamlGroup(config, service_policy::TaiwanGroupName), {"REJECT"},
                       "an empty Taiwan group must reject instead of using DIRECT");
    requireYamlProxies(findYamlGroup(config, service_policy::AIPlatformGroupName), {"REJECT"},
                       "an empty AI platform group must reject instead of using DIRECT");
    requireYamlProxies(findYamlGroup(config, service_policy::BinanceName),
                       {service_policy::TaiwanGroupName, "REJECT"},
                       "Binance must retain the rejecting Taiwan group when no matching node exists");
    for(const char *name : {service_policy::OpenAIName, service_policy::AnthropicName})
    {
        requireYamlProxies(findYamlGroup(config, name), {service_policy::AIPlatformGroupName, "REJECT"},
                           std::string(name) + " must retain the rejecting AI platform group when no compatible node exists");
    }
}

void testExpandedModeExpandsAllManagedRules()
{
    ProxyGroupConfigs groups;
    RulesetConfigs rulesets;
    service_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = false;
    ext.clash_doh = true;

    const YAML::Node config = YAML::Load(proxyToClash(
        nodes, "mode: rule\nrules:\n  - GEOIP,CN,OpenAI\n  - MATCH,Base\n",
        ruleset_content, groups, false, ext));
    const std::vector<std::string> rules = readRules(config);

    require(!config["rule-providers"].IsDefined(), "expanded mode must not emit managed rule providers");
    require(std::none_of(rules.cbegin(), rules.cend(), [](const std::string &rule)
    {
        return rule.rfind("RULE-SET,", 0) == 0;
    }), "expanded mode must not emit RULE-SET rules");

    const std::vector<std::string> expected{
        "DOMAIN-SUFFIX,binance.example,Binance",
        "DOMAIN-SUFFIX,openai.example,OpenAI",
        "IP-ASN,20473,OpenAI",
        "DOMAIN-SUFFIX,anthropic.example,Anthropic"
    };
    require(rules.size() >= expected.size() + 1, "expanded mode emitted too few rules");
    require(std::equal(expected.cbegin(), expected.cend(), rules.cbegin()),
            "expanded rules must preserve Binance/OpenAI/Anthropic order and the OpenAI IP-ASN rule");
    const auto match = std::find(rules.cbegin(), rules.cend(), "MATCH,Fallback");
    require(match != rules.cend() && static_cast<size_t>(std::distance(rules.cbegin(), match)) >= expected.size(),
            "all expanded managed rules must precede MATCH");
    const auto base_match = std::find(rules.cbegin(), rules.cend(), "MATCH,Base");
    require(base_match != rules.cend() &&
            static_cast<size_t>(std::distance(rules.cbegin(), base_match)) >= expected.size(),
            "expanded managed rules must precede retained base MATCH rules");
    const auto doh_rule = std::find(rules.cbegin(), rules.cend(), "GEOIP,CN,DIRECT,no-resolve");
    require(doh_rule != rules.cend() &&
            static_cast<size_t>(std::distance(rules.cbegin(), doh_rule)) >= expected.size(),
            "expanded managed rules must remain ahead of the normalized DoH CN rule");
}
}

int main()
{
    try
    {
        testExternalConfigCannotRemoveManagedPolicies();
        testPreferredPolicyGroupsAndFallbacks();
        testInvalidPreferredGroupsDoNotCreateDanglingReferences();
        testProviderModeEmitsAllManagedRuleSets();
        testEmptyPreferredPolicyGroupsRejectInsteadOfUsingDirect();
        testExpandedModeExpandsAllManagedRules();
        std::cout << "Managed service policy tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Managed service policy test failure: " << error.what() << std::endl;
        return 1;
    }
}
