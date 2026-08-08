#include <iostream>
#include <stdexcept>
#include <string>

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
}

int main()
{
    try
    {
        testMultilineSources();
        testPipeAndRepeatedArgumentsRemainCompatible();
        std::cout << "Mixed subscription input tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "Mixed subscription input test failure: " << error.what() << std::endl;
        return 1;
    }
}
