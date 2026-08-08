#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "generator/config/source_batch.h"
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
        std::cout << "Mixed subscription input tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Mixed subscription input test failure: " << error.what() << std::endl;
        return 1;
    }
}
