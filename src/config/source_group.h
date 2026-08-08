#ifndef SOURCE_GROUP_H_INCLUDED
#define SOURCE_GROUP_H_INCLUDED

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <unordered_set>
#include <vector>

#include "config/proxygroup.h"
#include "parser/config/proxy.h"

namespace source_group
{
inline constexpr const char *NamePrefix = "来源 ";

inline bool acceptsSelectableSourceGroups(ProxyGroupType type)
{
    switch(type)
    {
    case ProxyGroupType::Select:
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
    case ProxyGroupType::LoadBalance:
    case ProxyGroupType::Smart:
        return true;
    case ProxyGroupType::Relay:
    case ProxyGroupType::SSID:
        return false;
    }
    return false;
}

inline std::string makeUniqueName(const std::string &base_name, std::unordered_set<std::string> &reserved_names)
{
    std::string candidate = base_name;
    size_t suffix = 2;
    while(reserved_names.find(candidate) != reserved_names.end())
        candidate = base_name + " (" + std::to_string(suffix++) + ")";
    reserved_names.emplace(candidate);
    return candidate;
}

// Create one leaf group per user-provided input source. GroupId is assigned by
// the source loader before any rename/sort step, so it remains an exact and
// secret-free source identity even when different sources contain equal names.
inline std::vector<std::string> enforce(size_t source_count, const std::vector<Proxy> &nodes,
                                        ProxyGroupConfigs &groups)
{
    std::vector<std::string> previous_names;
    for(const ProxyGroupConfig &group : groups)
    {
        if(group.GeneratedSourceGroup)
            previous_names.emplace_back(group.Name);
    }

    if(!previous_names.empty())
    {
        for(ProxyGroupConfig &group : groups)
        {
            group.Proxies.erase(std::remove_if(group.Proxies.begin(), group.Proxies.end(),
                [&](const std::string &proxy)
                {
                    if(proxy.size() < 2 || proxy[0] != '[' || proxy[1] != ']')
                        return false;
                    const std::string referenced_name = proxy.substr(2);
                    return std::find(previous_names.cbegin(), previous_names.cend(), referenced_name) !=
                           previous_names.cend();
                }), group.Proxies.end());
        }
        groups.erase(std::remove_if(groups.begin(), groups.end(), [](const ProxyGroupConfig &group)
        {
            return group.GeneratedSourceGroup;
        }), groups.end());
    }

    std::unordered_set<std::string> reserved_names;
    for(const ProxyGroupConfig &group : groups)
        reserved_names.emplace(group.Name);
    for(const Proxy &node : nodes)
        reserved_names.emplace(node.Remark);

    std::vector<std::string> generated_names;
    generated_names.reserve(source_count);
    ProxyGroupConfigs generated_groups;
    generated_groups.reserve(source_count);
    for(size_t source_index = 0; source_index < source_count; source_index++)
    {
        ProxyGroupConfig group;
        group.Name = makeUniqueName(std::string(NamePrefix) + std::to_string(source_index + 1), reserved_names);
        group.Type = ProxyGroupType::Select;
        group.Proxies.emplace_back("!!GROUPID=" + std::to_string(source_index));
        // Prevent an empty or target-incompatible source from silently becoming DIRECT.
        group.Proxies.emplace_back("[]REJECT");
        group.GeneratedSourceGroup = true;
        generated_names.emplace_back(group.Name);
        generated_groups.emplace_back(std::move(group));
    }

    for(ProxyGroupConfig &group : groups)
    {
        if(!acceptsSelectableSourceGroups(group.Type))
            continue;
        for(const std::string &generated_name : generated_names)
        {
            const std::string reference = "[]" + generated_name;
            if(std::find(group.Proxies.cbegin(), group.Proxies.cend(), reference) == group.Proxies.cend())
                group.Proxies.emplace_back(reference);
        }
    }

    groups.insert(groups.end(), std::make_move_iterator(generated_groups.begin()),
                  std::make_move_iterator(generated_groups.end()));
    return generated_names;
}
}

#endif // SOURCE_GROUP_H_INCLUDED
