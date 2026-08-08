#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "generator/config/ruleconvert.h"
#include "generator/config/subexport.h"
#include "utils/string.h"

namespace
{
void require(bool condition, const std::string &message)
{
    if(!condition)
        throw std::runtime_error(message);
}

size_t countCnRules(const std::vector<std::string> &rules)
{
    return static_cast<size_t>(std::count_if(rules.cbegin(), rules.cend(), [](const std::string &rule)
    {
        const std::vector<std::string> fields = split(rule, ",");
        return fields.size() > 1 && toUpper(trim(fields[0])) == "GEOIP" && toUpper(trim(fields[1])) == "CN";
    }));
}

std::vector<std::string> readRules(const std::string &output)
{
    const YAML::Node config = YAML::Load(output);
    std::vector<std::string> rules;
    for(const YAML::Node &rule : config["rules"])
        rules.emplace_back(rule.as<std::string>());
    return rules;
}

void testReplacesFirstAndRemovesFollowingCnRules()
{
    std::vector<std::string> rules{
        "DOMAIN-SUFFIX,example.com,Proxy",
        "GEOIP,CN,Proxy",
        "DOMAIN-SUFFIX,example.net,DIRECT",
        " geoip , cn ,AnotherProxy ",
        "MATCH,Fallback"
    };

    enforceClashDoHRule(rules);

    require(countCnRules(rules) == 1, "duplicate GEOIP,CN rules were not removed");
    require(rules[1] == "GEOIP,CN,DIRECT,no-resolve", "the first GEOIP,CN rule was not replaced in place");
    require(rules[2] == "DOMAIN-SUFFIX,example.net,DIRECT", "unrelated rule order changed");
}

void testInsertsBeforeTerminalRule()
{
    std::vector<std::string> rules{
        "GEOIP,US,Proxy",
        "DOMAIN-SUFFIX,example.com,Proxy",
        "MATCH,Fallback"
    };

    enforceClashDoHRule(rules);

    require(rules.size() == 4, "DoH GEOIP,CN rule was not added");
    require(rules[2] == "GEOIP,CN,DIRECT,no-resolve", "DoH GEOIP,CN rule must precede MATCH");
    require(rules[0] == "GEOIP,US,Proxy", "other GEOIP rules must remain unchanged");
}

void testYamlRulesAreNormalized()
{
    YAML::Node config;
    config["rules"].push_back("GEOIP,CN,Proxy");
    config["rules"].push_back("GEOIP,CN,DIRECT");
    config["rules"].push_back("MATCH,Fallback");

    enforceClashDoHRule(config, true);

    require(config["rules"].size() == 2, "YAML duplicate GEOIP,CN rules were not removed");
    require(config["rules"][0].as<std::string>() == "GEOIP,CN,DIRECT,no-resolve", "YAML DoH rule is wrong");
    require(config["rules"][1].as<std::string>() == "MATCH,Fallback", "YAML terminal rule order changed");

    YAML::Node legacy_config;
    legacy_config["Rule"].push_back("GEOIP,CN,Proxy");
    legacy_config["Rule"].push_back("FINAL,Fallback");
    enforceClashDoHRule(legacy_config, false);
    require(legacy_config["Rule"].size() == 2, "legacy Rule field was not normalized");
    require(legacy_config["Rule"][0].as<std::string>() == "GEOIP,CN,DIRECT,no-resolve", "legacy Rule DoH rule is wrong");
}

void testExporterBranchesAndDisabledBehavior()
{
    const std::string base = R"(rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - GEOIP,CN,Proxy
  - GEOIP,CN,AnotherProxy
  - MATCH,Fallback
)";

    auto export_config = [&](bool enable_rule_generator, bool managed, bool clash_doh)
    {
        std::vector<Proxy> nodes;
        std::vector<RulesetContent> rulesets;
        ProxyGroupConfigs groups;
        extra_settings ext;
        ext.clash_new_field_name = true;
        ext.overwrite_original_rules = false;
        ext.enable_rule_generator = enable_rule_generator;
        ext.clash_doh = clash_doh;
        if(managed)
            ext.managed_config_prefix = "https://config.example.com";
        return proxyToClash(nodes, base, rulesets, groups, false, ext);
    };

    for(const std::string &output : {export_config(true, false, true), export_config(true, true, true), export_config(false, false, true)})
    {
        const std::vector<std::string> rules = readRules(output);
        require(countCnRules(rules) == 1, "an exporter branch retained duplicate GEOIP,CN rules");
        require(std::find(rules.cbegin(), rules.cend(), "GEOIP,CN,DIRECT,no-resolve") != rules.cend(),
                "an exporter branch omitted the exact DoH rule");
    }

    const std::vector<std::string> disabled_rules = readRules(export_config(true, false, false));
    require(countCnRules(disabled_rules) == 2, "disabled clash.doh unexpectedly changed GEOIP,CN rules");
    require(std::find(disabled_rules.cbegin(), disabled_rules.cend(), "GEOIP,CN,DIRECT,no-resolve") == disabled_rules.cend(),
            "disabled clash.doh unexpectedly added the DoH rule");
}
}

int main()
{
    try
    {
        testReplacesFirstAndRemovesFollowingCnRules();
        testInsertsBeforeTerminalRule();
        testYamlRulesAreNormalized();
        testExporterBranchesAndDisabledBehavior();
        std::cout << "Clash DoH rule tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Clash DoH rule test failure: " << error.what() << std::endl;
        return 1;
    }
}
