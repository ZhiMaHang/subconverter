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
         readyFuture("payload:\n  - DOMAIN-SUFFIX,openai.example\n  - DOMAIN-SUFFIX,ipinfo.cv\n  - IP-ASN,20473\n"),
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
    for(const char *field_name : {"rules", "Rule"})
    {
        for(const auto &entry : config)
        {
            if(entry.first.as<std::string>() != field_name || !entry.second.IsSequence())
                continue;
            for(const YAML::Node &rule : entry.second)
                rules.emplace_back(rule.as<std::string>());
            return rules;
        }
    }
    return rules;
}

bool hasYamlKey(const YAML::Node &config, const std::string &key)
{
    for(const auto &entry : config)
    {
        if(entry.first.as<std::string>() == key)
            return true;
    }
    return false;
}

bool isDomainRuleFor(const std::string &rule, const std::string &domain)
{
    string_view_array fields;
    split(fields, rule, ',');
    if(fields.size() < 2)
        return false;
    const std::string type = toUpper(trim(std::string(fields[0])));
    const std::string value = toLower(trim(std::string(fields[1])));
    return (type == "DOMAIN" || type == "DOMAIN-SUFFIX") && value == domain;
}

size_t countToDeskDomainRules(const std::vector<std::string> &rules)
{
    return static_cast<size_t>(std::count_if(rules.cbegin(), rules.cend(), [](const std::string &rule)
    {
        return isDomainRuleFor(rule, service_policy::ToDeskDomain);
    }));
}

size_t countIPInfoDomainRules(const std::vector<std::string> &rules)
{
    return static_cast<size_t>(std::count_if(rules.cbegin(), rules.cend(), [](const std::string &rule)
    {
        return isDomainRuleFor(rule, service_policy::IPInfoDomain);
    }));
}

size_t ruleIndex(const std::vector<std::string> &rules, const std::string &expected)
{
    const auto rule = std::find(rules.cbegin(), rules.cend(), expected);
    return rule == rules.cend() ? std::string::npos :
           static_cast<size_t>(std::distance(rules.cbegin(), rule));
}

void requireCanonicalToDeskRule(const std::vector<std::string> &rules, const std::string &context)
{
    require(!rules.empty() && rules.front() == service_policy::ToDeskDirectRule,
            context + " must put the canonical ToDesk DIRECT rule first");
    require(countToDeskDomainRules(rules) == 1,
            context + " must remove conflicting and duplicate ToDesk domain rules");
}

void requireCanonicalManagedDomainRules(const std::vector<std::string> &rules, const std::string &context)
{
    requireCanonicalToDeskRule(rules, context);
    require(rules.size() > 1 && rules[1] == service_policy::IPInfoProxyRule,
            context + " must put the canonical ipinfo.cv proxy rule second");
    require(countIPInfoDomainRules(rules) == 1,
            context + " must remove conflicting and duplicate ipinfo.cv domain rules");
}

const YAML::Node proxyGroupsNode(const YAML::Node &config)
{
    for(const auto &entry : config)
    {
        const std::string key = entry.first.as<std::string>();
        if((key == "proxy-groups" || key == "Proxy Group") && entry.second.IsSequence())
            return entry.second;
    }
    return YAML::Node();
}

const YAML::Node findYamlGroup(const YAML::Node &config, const std::string &name)
{
    for(const YAML::Node &group : proxyGroupsNode(config))
    {
        if(group["name"].as<std::string>() == name)
            return group;
    }
    throw std::runtime_error("missing generated proxy group: " + name);
}

size_t countYamlGroupsNamed(const YAML::Node &config, const std::string &name)
{
    size_t count = 0;
    for(const YAML::Node &group : proxyGroupsNode(config))
    {
        if(group["name"].as<std::string>() == name)
            count++;
    }
    return count;
}

void requireIPInfoTargetGroup(const YAML::Node &config, const std::vector<std::string> &rules,
                              const std::string &context)
{
    requireCanonicalManagedDomainRules(rules, context);
    require(countYamlGroupsNamed(config, service_policy::MainProxyGroupName) == 1,
            context + " must emit exactly one ipinfo.cv target proxy group");
    const YAML::Node group = findYamlGroup(config, service_policy::MainProxyGroupName);
    require(group["proxies"].IsSequence() && group["proxies"].size() > 0,
            context + " must not emit an empty ipinfo.cv target proxy group");
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

void testManagedDomainRuleNormalizationIsIdempotent()
{
    std::vector<std::string> rules{
        "DOMAIN-SUFFIX, IPINFO.CV ,DIRECT",
        "DOMAIN,todesk.com,External",
        "DOMAIN-SUFFIX,openai.example,OpenAI",
        "DOMAIN,ipinfo.cv,REJECT",
        "DOMAIN-SUFFIX, ToDesk.COM ,REJECT",
        service_policy::IPInfoProxyRule,
        service_policy::ToDeskDirectRule,
        "DOMAIN-SUFFIX,notipinfo.cv,External",
        "DOMAIN-SUFFIX,ipinfo.cv.example,External",
        "DOMAIN-SUFFIX,example.com,External",
        "MATCH,Fallback"
    };

    prioritizeManagedServiceRules(rules);
    prioritizeManagedServiceRules(rules);

    requireCanonicalManagedDomainRules(rules, "repeated managed-rule finalization");
    require(rules == std::vector<std::string>({
                service_policy::ToDeskDirectRule,
                service_policy::IPInfoProxyRule,
                "DOMAIN-SUFFIX,openai.example,OpenAI",
                "DOMAIN-SUFFIX,notipinfo.cv,External",
                "DOMAIN-SUFFIX,ipinfo.cv.example,External",
                "DOMAIN-SUFFIX,example.com,External",
                "MATCH,Fallback"
            }), "managed-domain normalization changed priority or removed a similar unrelated domain");
}

void testMainProxyGroupNormalization()
{
    auto requireCanonicalFallback = [](ProxyGroupConfigs groups, const std::string &context)
    {
        service_policy::ensureMainProxyGroup(groups);
        service_policy::ensureMainProxyGroup(groups);
        require(countGroupsNamed(groups, service_policy::MainProxyGroupName) == 1,
                context + " must emit exactly one canonical main proxy group");
        const ProxyGroupConfig &group = findGroup(groups, service_policy::MainProxyGroupName);
        require(group.Type == ProxyGroupType::Select,
                context + " must normalize the main proxy group to Select");
        require(group.Proxies == string_array({".*", "[]REJECT"}),
                context + " must normalize the main proxy group to a proxy-only fail-closed fallback");
    };

    requireCanonicalFallback({}, "missing group");

    ProxyGroupConfig spaced_alias;
    spaced_alias.Name = std::string(" ") + service_policy::MainProxyGroupName + " ";
    spaced_alias.Type = ProxyGroupType::Select;
    spaced_alias.Proxies = {".*"};
    ProxyGroupConfig alias_consumer;
    alias_consumer.Name = "LegacyRef";
    alias_consumer.Type = ProxyGroupType::Select;
    alias_consumer.Proxies = {std::string("[]") + spaced_alias.Name};
    ProxyGroupConfigs aliased_groups{spaced_alias, alias_consumer};
    service_policy::ensureMainProxyGroup(aliased_groups);
    service_policy::ensureMainProxyGroup(aliased_groups);
    require(countGroupsNamed(aliased_groups, spaced_alias.Name) == 1 &&
            findGroup(aliased_groups, "LegacyRef").Proxies == string_array({std::string("[]") + spaced_alias.Name}),
            "a whitespace-bearing legacy group name and its exact inbound reference must remain unchanged");
    require(findGroup(aliased_groups, service_policy::MainProxyGroupName).Proxies ==
                string_array({".*", "[]REJECT"}),
            "a whitespace-bearing alias must not replace the exact canonical main proxy group");

    ProxyGroupConfig ssid;
    ssid.Name = service_policy::MainProxyGroupName;
    ssid.Type = ProxyGroupType::SSID;
    requireCanonicalFallback({ssid}, "SSID group");

    ProxyGroupConfig empty;
    empty.Name = service_policy::MainProxyGroupName;
    empty.Type = ProxyGroupType::Select;
    requireCanonicalFallback({empty}, "empty group");

    ProxyGroupConfig direct_only;
    direct_only.Name = service_policy::MainProxyGroupName;
    direct_only.Type = ProxyGroupType::Select;
    direct_only.Proxies = {"[]DIRECT"};
    requireCanonicalFallback({direct_only}, "DIRECT-only group");

    ProxyGroupConfig padded_reject = direct_only;
    padded_reject.Proxies = {" []REJECT"};
    ProxyGroupConfigs padded_reject_groups{padded_reject};
    service_policy::ensureMainProxyGroup(padded_reject_groups);
    service_policy::ensureMainProxyGroup(padded_reject_groups);
    require(findGroup(padded_reject_groups, service_policy::MainProxyGroupName).Proxies ==
                string_array({" []REJECT", "[]REJECT"}),
            "a matcher that only resembles REJECT after trimming must still get an exact fail-closed candidate");

    ProxyGroupConfig provider_only;
    provider_only.Name = service_policy::MainProxyGroupName;
    provider_only.Type = ProxyGroupType::Select;
    provider_only.UsingProvider = {"MissingProvider"};
    requireCanonicalFallback({provider_only}, "provider-only group");
    provider_only.Proxies = {".*"};
    requireCanonicalFallback({provider_only}, "group mixing a matcher with an unverifiable provider");

    ProxyGroupConfig dangling;
    dangling.Name = service_policy::MainProxyGroupName;
    dangling.Type = ProxyGroupType::Select;
    dangling.Proxies = {"[]Missing"};
    requireCanonicalFallback({dangling}, "dangling group reference");
    dangling.Proxies = {".*", "[]Missing"};
    requireCanonicalFallback({dangling}, "group mixing a matcher with a dangling reference");
    ProxyGroupConfig exact_auto;
    exact_auto.Name = "Auto";
    exact_auto.Type = ProxyGroupType::URLTest;
    exact_auto.Proxies = {".*"};
    dangling.Proxies = {".*", "[]Auto "};
    requireCanonicalFallback({dangling, exact_auto}, "literal reference with trailing whitespace");
    dangling.Proxies = {".*", "[] DIRECT "};
    requireCanonicalFallback({dangling}, "whitespace-padded pseudo builtin reference");

    ProxyGroupConfig loop;
    loop.Name = "Loop";
    loop.Type = ProxyGroupType::Select;
    loop.Proxies = {std::string("[]") + service_policy::MainProxyGroupName};
    ProxyGroupConfig cyclic = dangling;
    cyclic.Proxies = {".*", "[]Loop"};
    requireCanonicalFallback({cyclic, loop}, "cyclic group reference");

    ProxyGroupConfig reachable;
    reachable.Name = "Auto";
    reachable.Type = ProxyGroupType::URLTest;
    reachable.Proxies = {".*"};
    ProxyGroupConfig referenced = dangling;
    referenced.Proxies = {"[]Auto"};
    ProxyGroupConfigs referenced_groups{referenced, reachable};
    service_policy::ensureMainProxyGroup(referenced_groups);
    require(findGroup(referenced_groups, service_policy::MainProxyGroupName).Proxies ==
                string_array({"[]Auto", "[]REJECT"}),
            "a main group that reaches generated proxy nodes through another group must be preserved");

    ProxyGroupConfig broken_reachable = reachable;
    broken_reachable.Proxies = {".*", "[]Missing"};
    requireCanonicalFallback({referenced, broken_reachable},
                             "reference to a group that also has a dangling candidate");

    ProxyGroupConfig spaced_reachable = reachable;
    spaced_reachable.Name = " Auto ";
    requireCanonicalFallback({referenced, spaced_reachable},
                             "reference whose target only matches after trimming");

    ProxyGroupConfig invalid_last_reachable = reachable;
    invalid_last_reachable.UsingProvider = {"MissingProvider"};
    requireCanonicalFallback({referenced, reachable, invalid_last_reachable},
                             "reference whose last exported target definition is invalid");

    ProxyGroupConfig valid;
    valid.Name = service_policy::MainProxyGroupName;
    valid.Type = ProxyGroupType::Select;
    valid.Proxies = {"[]Auto", "[]TW", "[]DIRECT", ".*"};
    valid.Url = "https://example.com/preserved";
    valid.Interval = 321;

    ProxyGroupConfig invalid_duplicate = ssid;
    invalid_duplicate.Name = std::string(" ") + service_policy::MainProxyGroupName + " ";
    ProxyGroupConfig taiwan = reachable;
    taiwan.Name = "TW";
    ProxyGroupConfigs full_style_groups{valid, reachable, taiwan, invalid_duplicate};
    service_policy::ensureMainProxyGroup(full_style_groups);
    service_policy::ensureMainProxyGroup(full_style_groups);
    require(countGroupsNamed(full_style_groups, service_policy::MainProxyGroupName) == 1,
            "a valid Full-style group and its invalid duplicate must normalize to one exact group");
    const ProxyGroupConfig &preserved = findGroup(full_style_groups, service_policy::MainProxyGroupName);
    require(preserved.Type == valid.Type && preserved.Url == valid.Url && preserved.Interval == valid.Interval,
            "a valid Full-style main proxy group lost its settings");
    require(preserved.Proxies == string_array({"[]Auto", "[]TW", "[]DIRECT", ".*", "[]REJECT"}),
            "a valid Full-style main proxy group was rebuilt instead of preserving its candidates safely");
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
        nodes, "mode: rule\nrules:\n"
               "  - DOMAIN,todesk.com,External\n"
               "  - DOMAIN-SUFFIX, ToDesk.COM ,REJECT\n"
               "  - DOMAIN,ipinfo.cv,DIRECT\n"
               "  - DOMAIN-SUFFIX, IPINFO.CV ,REJECT\n"
               "  - DOMAIN-SUFFIX,notipinfo.cv,External\n"
               "  - GEOIP,CN,OpenAI\n"
               "  - MATCH,Base\n",
        ruleset_content, groups, false, ext));
    const std::vector<std::string> rules = readRules(config);
    requireIPInfoTargetGroup(config, rules, "provider mode");
    require(std::find(rules.cbegin(), rules.cend(), "DOMAIN-SUFFIX,notipinfo.cv,External") != rules.cend(),
            "provider mode removed a similar non-ipinfo.cv domain");

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
    require(config["rule-providers"].IsMap() && config["rule-providers"].size() == providers.size(),
            "provider mode must not create a provider for either fixed managed domain");
    require(rules.size() >= providers.size() + 3, "provider mode emitted too few rules");
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
        require(rules[index + 2] == std::string("RULE-SET,") + expected.Name + "," + expected.Name,
                "managed provider rules are not in Binance/OpenAI/Anthropic order");
    }
    const auto match = std::find(rules.cbegin(), rules.cend(), "MATCH,Fallback");
    require(match != rules.cend() && static_cast<size_t>(std::distance(rules.cbegin(), match)) > providers.size(),
            "managed provider rules must precede MATCH");
    require(std::find(rules.cbegin(), rules.cend(), "MATCH,Base") != rules.cend(),
            "provider mode must retain base rules when overwrite_original_rules is false");
    const auto doh_rule = std::find(rules.cbegin(), rules.cend(), "GEOIP,CN,DIRECT,no-resolve");
    require(doh_rule != rules.cend() &&
            static_cast<size_t>(std::distance(rules.cbegin(), doh_rule)) > providers.size() + 1 && doh_rule < match,
            "managed provider rules must remain ahead of the normalized DoH CN rule");

    requireYamlProxies(findYamlGroup(config, service_policy::TaiwanGroupName), {"TW01", "REJECT"},
                       "Taiwan policy group must never fall back to DIRECT");
    requireYamlProxies(findYamlGroup(config, service_policy::AIPlatformGroupName), {"US01", "REJECT"},
                       "AI platform group must retain compatible nodes and reject safely");
    requireYamlProxies(findYamlGroup(config, service_policy::MainProxyGroupName), {"TW01", "US01", "REJECT"},
                       "the ipinfo.cv target group must contain real proxy nodes and reject safely");
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
        nodes, "mode: rule\nrules:\n"
               "  - DOMAIN,todesk.com,External\n"
               "  - DOMAIN-SUFFIX, ToDesk.COM ,REJECT\n"
               "  - DOMAIN,ipinfo.cv,DIRECT\n"
               "  - DOMAIN-SUFFIX, IPINFO.CV ,REJECT\n"
               "  - DOMAIN-SUFFIX,notipinfo.cv,External\n"
               "  - GEOIP,CN,OpenAI\n"
               "  - MATCH,Base\n",
        ruleset_content, groups, false, ext));
    const std::vector<std::string> rules = readRules(config);
    requireIPInfoTargetGroup(config, rules, "expanded mode");
    require(std::find(rules.cbegin(), rules.cend(), "DOMAIN-SUFFIX,notipinfo.cv,External") != rules.cend(),
            "expanded mode removed a similar non-ipinfo.cv domain");
    requireYamlProxies(findYamlGroup(config, service_policy::MainProxyGroupName), {"REJECT"},
                       "an empty expanded configuration must keep the ipinfo.cv target group fail closed");

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
    require(rules.size() >= expected.size() + 2, "expanded mode emitted too few rules");
    require(std::equal(expected.cbegin(), expected.cend(), rules.cbegin() + 2),
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
            static_cast<size_t>(std::distance(rules.cbegin(), doh_rule)) > expected.size() + 1 &&
            doh_rule < base_match && doh_rule < match,
            "expanded managed rules must remain ahead of the normalized DoH CN rule");
}

void testDisabledRuleGeneratorNormalizesLegacyRulesWithDoh()
{
    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.clash_new_field_name = false;
    ext.enable_rule_generator = false;
    ext.clash_doh = true;
    ext.clash_script = true;

    const YAML::Node config = YAML::Load(proxyToClash(
        nodes, "Mode: Script\nRule:\n"
               "  - DOMAIN,todesk.com,External\n"
               "  - DOMAIN-SUFFIX, ToDesk.COM ,REJECT\n"
               "  - DOMAIN,ipinfo.cv,DIRECT\n"
               "  - DOMAIN-SUFFIX, IPINFO.CV ,REJECT\n"
               "  - DOMAIN-SUFFIX,notipinfo.cv,External\n"
               "  - GEOIP,CN,External\n"
               "  - MATCH,Fallback\n",
        ruleset_content, groups, true, ext));
    require(hasYamlKey(config, "Rule") && !hasYamlKey(config, "rules"),
            "disabled rule generation must preserve the legacy Rule field");
    require(config["Mode"].as<std::string>() == "Rule" && !hasYamlKey(config, "mode"),
            "disabled rule generation must force rule mode when the base or request selects script mode");

    const std::vector<std::string> rules = readRules(config);
    requireIPInfoTargetGroup(config, rules, "disabled rule generation with legacy Rule");
    require(std::find(rules.cbegin(), rules.cend(), "DOMAIN-SUFFIX,notipinfo.cv,External") != rules.cend(),
            "legacy no-generator mode removed a similar non-ipinfo.cv domain");
    requireYamlProxies(findYamlGroup(config, service_policy::MainProxyGroupName), {"REJECT"},
                       "legacy no-generator mode must keep an empty ipinfo.cv target group fail closed");
    const size_t doh_index = ruleIndex(rules, "GEOIP,CN,DIRECT,no-resolve");
    const size_t match_index = ruleIndex(rules, "MATCH,Fallback");
    require(doh_index > 1 && match_index != std::string::npos && doh_index < match_index,
            "managed domains must precede the one normalized DoH rule and terminal MATCH in legacy mode");
}

void testScriptModeDirectsToDeskBeforeProviders()
{
    ProxyGroupConfigs groups;
    RulesetConfigs rulesets;
    service_policy::enforce(groups, rulesets);

    std::vector<Proxy> nodes;
    std::vector<RulesetContent> ruleset_content = makeRulesetContent();
    extra_settings ext;
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = true;
    ext.overwrite_original_rules = true;
    ext.clash_script = true;

    const YAML::Node config = YAML::Load(proxyToClash(
        nodes, "log-level: info\n", ruleset_content, groups, false, ext));
    require(config["mode"].as<std::string>() == "script", "script mode was not enabled");
    require(config["script"]["code"].IsScalar(), "script mode did not emit executable routing code");
    require(countYamlGroupsNamed(config, service_policy::MainProxyGroupName) == 1,
            "script mode must emit exactly one ipinfo.cv target proxy group");
    requireYamlProxies(findYamlGroup(config, service_policy::MainProxyGroupName), {"REJECT"},
                       "script mode must keep an empty ipinfo.cv target group fail closed");

    const std::string script = config["script"]["code"].as<std::string>();
    const size_t lowercase_host = script.find("host = md[\"host\"].lower()");
    const size_t todest_root_match = script.find("host == \"todesk.com\"");
    const size_t todest_subdomain_match = script.find("host.endswith(\".todesk.com\")");
    const size_t direct_return = script.find("return \"DIRECT\"");
    const size_t ipinfo_root_match = script.find("host == \"ipinfo.cv\"");
    const size_t ipinfo_subdomain_match = script.find("host.endswith(\".ipinfo.cv\")");
    const size_t unsafe_suffix_match = script.find("host.endswith(\"ipinfo.cv\")");
    const size_t proxy_return = script.find(std::string("return \"") + service_policy::MainProxyGroupName + "\"");
    const size_t provider_lookup = script.find("ctx.rule_providers[");
    require(lowercase_host != std::string::npos && todest_root_match != std::string::npos &&
            todest_subdomain_match != std::string::npos,
            "script mode must match ToDesk root and subdomains case-insensitively");
    require(direct_return != std::string::npos && provider_lookup != std::string::npos &&
            lowercase_host < todest_root_match && todest_root_match < direct_return &&
            todest_subdomain_match < direct_return && direct_return < provider_lookup,
            "script mode must return DIRECT for ToDesk before consulting any rule provider");
    require(ipinfo_root_match != std::string::npos && ipinfo_subdomain_match != std::string::npos &&
            unsafe_suffix_match == std::string::npos,
            "script mode must match only the ipinfo.cv root and dot-delimited subdomains");
    require(proxy_return != std::string::npos && direct_return < ipinfo_root_match &&
            ipinfo_root_match < proxy_return && ipinfo_subdomain_match < proxy_return &&
            proxy_return < provider_lookup,
            "script mode must route ipinfo.cv through the main proxy group before consulting providers");
}
}

int main()
{
    try
    {
        testManagedDomainRuleNormalizationIsIdempotent();
        testMainProxyGroupNormalization();
        testExternalConfigCannotRemoveManagedPolicies();
        testPreferredPolicyGroupsAndFallbacks();
        testInvalidPreferredGroupsDoNotCreateDanglingReferences();
        testProviderModeEmitsAllManagedRuleSets();
        testEmptyPreferredPolicyGroupsRejectInsteadOfUsingDirect();
        testExpandedModeExpandsAllManagedRules();
        testDisabledRuleGeneratorNormalizesLegacyRulesWithDoh();
        testScriptModeDirectsToDeskBeforeProviders();
        std::cout << "Managed service policy tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Managed service policy test failure: " << error.what() << std::endl;
        return 1;
    }
}
