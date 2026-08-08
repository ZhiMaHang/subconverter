#ifndef SOURCE_BATCH_H_INCLUDED
#define SOURCE_BATCH_H_INCLUDED

#include <cstddef>
#include <utility>
#include <vector>

#include "utils/string.h"

struct SourceBatchResult
{
    bool success;
    size_t failed_source_index;
};

// Load every source into an isolated staging vector. Every source must add at
// least one item, and the destination is only replaced after the full batch
// succeeds, so a failed or throwing source cannot expose a partial result.
template<typename Item, typename Loader>
SourceBatchResult loadSourcesAtomically(const string_array &sources, std::vector<Item> &destination, Loader &&loader)
{
    std::vector<Item> staged;
    for(size_t source_index = 0; source_index < sources.size(); source_index++)
    {
        try
        {
            const size_t size_before = staged.size();
            if(loader(sources[source_index], staged, source_index) != 0 || staged.size() <= size_before)
                return {false, source_index};
        }
        catch(...)
        {
            return {false, source_index};
        }
    }

    destination.swap(staged);
    return {true, sources.size()};
}

#endif // SOURCE_BATCH_H_INCLUDED
