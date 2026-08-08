#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/source_group.h"
#include "generator/config/source_batch.h"
#include "generator/config/subexport.h"
#include "handler/settings.h"
#include "utils/string.h"

namespace
{
void require(bool condition, const std::string &message)
{
    if(!condition)
        throw std::runtime_error(message);
}

void testMultilineSources()
{
    const string_array sources = splitUrlSources(
        "  ssr://direct-ssr  \n"
        "vless://direct-vless\r\n"
        "https://airport-a.example/sub\r"
        "https://airport-b.example/sub  ");

    require(sources.size() == 4, "multiline input did not produce four sources");
    require(sources[0] == "ssr://direct-ssr", "SSR source was not trimmed");
    require(sources[1] == "vless://direct-vless", "VLESS source was not retained");
    require(sources[2] == "https://airport-a.example/sub", "first subscription URL was not retained");
    require(sources[3] == "https://airport-b.example/sub", "second subscription URL was not retained");
}

void testPipeAndRepeatedArgumentsRemainCompatible()
{
    string_multimap arguments;
    arguments.emplace("target", "clash");
    arguments.emplace("url", "ssr://one|vless://two");
    arguments.emplace("url", "https://airport-a.example/sub\nhttps://airport-b.example/sub");
    arguments.emplace("url", "  ");

    const string_array sources = getUrlArgs(arguments, "url");
    require(sources.size() == 4, "repeated url arguments were not flattened");
    require(join(sources, "|") ==
            "ssr://one|vless://two|https://airport-a.example/sub|https://airport-b.example/sub",
            "mixed url arguments changed source order");
}

void testStrictSourceFailureDefaults()
{
    const Settings settings;
    require(!settings.skipFailedLinks, "failed subscription sources must be strict by default");

    std::ifstream pref(std::string(SUBCONVERTER_SOURCE_DIR) + "/base/pref.example.toml");
    require(pref.good(), "Docker preference template could not be opened");

    bool found_setting = false;
    std::string line;
    while(std::getline(pref, line))
    {
        line = trim(line);
        if(startsWith(line, "skip_failed_links"))
        {
            found_setting = true;
            require(line == "skip_failed_links = false",
                    "Docker preference template must fail closed for subscription sources");
        }
    }
    require(found_setting, "Docker preference template is missing skip_failed_links");
}

void testAtomicBatchCommitsOnlyAfterEverySourceSucceeds()
{
    const string_array sources{"one", "two", "three"};
    string_array nodes{"stale"};
    const SourceBatchResult result = loadSourcesAtomically<std::string>(sources, nodes,
        [](const std::string &source, string_array &staged, size_t)
        {
            staged.emplace_back("node-" + source);
            return 0;
        });

    require(result.success, "an all-success source batch was rejected");
    require(nodes == string_array({"node-one", "node-two", "node-three"}),
            "an all-success source batch was not committed in order");
}

void testAtomicBatchDiscardsPartialNodesOnFailure()
{
    Settings permissive_settings;
    permissive_settings.skipFailedLinks = true;
    const string_array sources{"one", "two", "three"};
    string_array nodes{"unchanged"};
    const SourceBatchResult result = loadSourcesAtomically<std::string>(sources, nodes,
        [&](const std::string &source, string_array &staged, size_t source_index)
        {
            (void)permissive_settings;
            staged.emplace_back("node-" + source);
            return source_index == 2 ? -1 : 0;
        });

    require(!result.success && result.failed_source_index == 2,
            "the failed source index was not reported");
    require(nodes == string_array({"unchanged"}),
            "nodes from earlier sources escaped a failed atomic batch");
}

void testAtomicBatchMapsParserExceptionsToFailure()
{
    const string_array sources{"one", "broken"};
    string_array nodes;
    const SourceBatchResult result = loadSourcesAtomically<std::string>(sources, nodes,
        [](const std::string &source, string_array &staged, size_t source_index)
        {
            staged.emplace_back("node-" + source);
            if(source_index == 1)
                throw std::runtime_error("synthetic parser exception");
            return 0;
        });

    require(!result.success && result.failed_source_index == 1,
            "a parser exception was not mapped to its source failure");
    require(nodes.empty(), "nodes escaped an exception-failed atomic batch");
}

void testAtomicBatchRejectsEmptySourceContribution()
{
    const string_array sources{"one", "empty", "three"};
    string_array nodes{"unchanged"};
    const SourceBatchResult result = loadSourcesAtomically<std::string>(sources, nodes,
        [](const std::string &source, string_array &staged, size_t source_index)
        {
            if(source_index != 1)
                staged.emplace_back("node-" + source);
            return 0;
        });

    require(!result.success && result.failed_source_index == 1,
            "a source contributing no nodes was accepted");
    require(nodes == string_array({"unchanged"}),
            "nodes escaped an empty-contribution source batch");
}

Proxy makeHttpNode(const std::string &remark, uint32_t source_index, uint16_t port)
{
    Proxy node;
    node.Type = ProxyType::HTTP;
    node.Remark = remark;
    node.GroupId = source_index;
    node.Hostname = "192.0.2." + std::to_string(source_index + 1);
    node.Port = port;
    return node;
}

const ProxyGroupConfig &findGroup(const ProxyGroupConfigs &groups, const std::string &name)
{
    const auto group = std::find_if(groups.cbegin(), groups.cend(), [&](const ProxyGroupConfig &candidate)
    {
        return candidate.Name == name;
    });
    if(group == groups.cend())
        throw std::runtime_error("missing group: " + name);
    return *group;
}

size_t countValue(const string_array &values, const std::string &value)
{
    return static_cast<size_t>(std::count(values.cbegin(), values.cend(), value));
}

void testEveryInputGetsAnIsolatedSourceGroup()
{
    std::vector<Proxy> nodes{
        makeHttpNode("来源 1", 0, 8001),
        makeHttpNode("Shared", 1, 8002),
        makeHttpNode("Shared", 2, 8003),
        makeHttpNode("Last", 3, 8004)
    };

    ProxyGroupConfig select_group;
    select_group.Name = "Main";
    select_group.Type = ProxyGroupType::Select;
    select_group.Proxies = {".*", "[]DIRECT"};

    ProxyGroupConfig url_test_group;
    url_test_group.Name = "Auto";
    url_test_group.Type = ProxyGroupType::URLTest;
    url_test_group.Proxies = {".*"};
    url_test_group.Url = "https://example.com/generate_204";

    ProxyGroupConfig fallback_group;
    fallback_group.Name = "Fallback";
    fallback_group.Type = ProxyGroupType::Fallback;
    fallback_group.Proxies = {".*"};
    fallback_group.Url = "https://example.com/generate_204";

    ProxyGroupConfig load_balance_group;
    load_balance_group.Name = "Balance";
    load_balance_group.Type = ProxyGroupType::LoadBalance;
    load_balance_group.Proxies = {".*"};
    load_balance_group.Url = "https://example.com/generate_204";

    ProxyGroupConfig smart_group;
    smart_group.Name = "Smart";
    smart_group.Type = ProxyGroupType::Smart;
    smart_group.Proxies = {".*"};
    smart_group.Url = "https://example.com/generate_204";

    ProxyGroupConfig managed_group;
    managed_group.Name = "Binance";
    managed_group.Type = ProxyGroupType::Select;
    managed_group.Proxies = {"[]REJECT"};

    ProxyGroupConfig relay_group;
    relay_group.Name = "Relay";
    relay_group.Type = ProxyGroupType::Relay;
    relay_group.Proxies = {".*"};

    ProxyGroupConfig ssid_group;
    ssid_group.Name = "SSID";
    ssid_group.Type = ProxyGroupType::SSID;

    ProxyGroupConfigs groups{select_group, url_test_group, fallback_group, load_balance_group,
                             smart_group, managed_group, relay_group, ssid_group};
    const std::vector<std::string> source_names = source_group::enforce(4, nodes, groups);

    require(source_names.size() == 4, "not every input received a source group");
    require(source_names[0] == "来源 1 (2)", "a source group collided with a node name");
    for(size_t source_index = 0; source_index < source_names.size(); source_index++)
    {
        const ProxyGroupConfig &source = findGroup(groups, source_names[source_index]);
        require(source.GeneratedSourceGroup, "a generated source group lost its marker");
        require(source.Type == ProxyGroupType::Select, "a source group is not selectable");
        require(source.Proxies == string_array({"!!GROUPID=" + std::to_string(source_index), "[]REJECT"}),
                "a source group does not isolate its original input index");
        for(const std::string &other_name : source_names)
            require(countValue(source.Proxies, "[]" + other_name) == 0,
                    "source groups reference themselves or each other");
    }

    for(const std::string &group_name : {std::string("Main"), std::string("Auto"),
                                         std::string("Fallback"), std::string("Balance"),
                                         std::string("Smart"), std::string("Binance")})
    {
        const ProxyGroupConfig &group = findGroup(groups, group_name);
        for(const std::string &source_name : source_names)
            require(countValue(group.Proxies, "[]" + source_name) == 1,
                    "an eligible group cannot select every source group");
    }
    for(const std::string &group_name : {std::string("Relay"), std::string("SSID")})
    {
        const ProxyGroupConfig &group = findGroup(groups, group_name);
        for(const std::string &source_name : source_names)
            require(countValue(group.Proxies, "[]" + source_name) == 0,
                    "a non-selectable group was given source candidates");
    }

    const std::vector<std::string> repeated_names = source_group::enforce(4, nodes, groups);
    require(repeated_names == source_names, "source group generation is not stable across repeated calls");
    require(groups.size() == 12, "repeated source group generation duplicated groups");
    for(const std::string &source_name : source_names)
        require(countValue(findGroup(groups, "Main").Proxies, "[]" + source_name) == 1,
                "repeated source group generation duplicated references");
}

void testClashGroupsKeepEqualNamesSeparatedBySource()
{
    std::vector<Proxy> nodes{
        makeHttpNode("Shared", 0, 8101),
        makeHttpNode("Shared", 1, 8102),
        makeHttpNode("Shared", 2, 8103),
        makeHttpNode("Shared", 3, 8104)
    };

    ProxyGroupConfig main_group;
    main_group.Name = "Main";
    main_group.Type = ProxyGroupType::Select;
    main_group.Proxies = {".*"};
    ProxyGroupConfigs groups{main_group};
    const std::vector<std::string> source_names = source_group::enforce(4, nodes, groups);

    YAML::Node output;
    extra_settings ext;
    ext.clash_new_field_name = true;
    proxyToClash(nodes, output, groups, false, ext);

    const YAML::Node output_groups = output["proxy-groups"];
    require(output_groups.IsSequence(), "Clash output is missing proxy groups");
    for(size_t source_index = 0; source_index < source_names.size(); source_index++)
    {
        YAML::Node source;
        for(const YAML::Node &candidate : output_groups)
        {
            if(candidate["name"].as<std::string>() == source_names[source_index])
            {
                source = candidate;
                break;
            }
        }
        require(source.IsDefined(), "Clash output is missing a source group");
        const YAML::Node candidates = source["proxies"];
        require(candidates.size() == 2, "a source group contains nodes from another input");
        const std::string expected_name = source_index == 0 ? "Shared" : "Shared " + std::to_string(source_index + 1);
        require(candidates[0].as<std::string>() == expected_name && candidates[1].as<std::string>() == "REJECT",
                "equal node names were not isolated by source GroupId");
    }
}

void testEmptyExportedSourceFailsClosed()
{
    Proxy unsupported;
    unsupported.Type = ProxyType::Unknown;
    unsupported.Remark = "Unsupported";
    unsupported.GroupId = 0;
    std::vector<Proxy> nodes{unsupported};

    ProxyGroupConfigs groups;
    const std::vector<std::string> source_names = source_group::enforce(1, nodes, groups);
    YAML::Node output;
    extra_settings ext;
    ext.clash_new_field_name = true;
    proxyToClash(nodes, output, groups, false, ext);

    const YAML::Node output_groups = output["proxy-groups"];
    require(output_groups.size() == 1, "an empty exported source group was removed");
    require(output_groups[0]["name"].as<std::string>() == source_names[0],
            "the wrong empty source group was emitted");
    const YAML::Node candidates = output_groups[0]["proxies"];
    require(candidates.size() == 1 && candidates[0].as<std::string>() == "REJECT",
            "an empty exported source group did not fail closed");
}
}

int main()
{
    try
    {
        testMultilineSources();
        testPipeAndRepeatedArgumentsRemainCompatible();
        testStrictSourceFailureDefaults();
        testAtomicBatchCommitsOnlyAfterEverySourceSucceeds();
        testAtomicBatchDiscardsPartialNodesOnFailure();
        testAtomicBatchMapsParserExceptionsToFailure();
        testAtomicBatchRejectsEmptySourceContribution();
        testEveryInputGetsAnIsolatedSourceGroup();
        testClashGroupsKeepEqualNamesSeparatedBySource();
        testEmptyExportedSourceFailsClosed();
        std::cout << "Mixed subscription input tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Mixed subscription input test failure: " << error.what() << std::endl;
        return 1;
    }
}
