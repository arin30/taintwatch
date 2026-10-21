# FastSpanIndex: High-Performance Augmented Interval Tree

As LLM agent contexts scale into hundreds of thousands of tokens, linear segment scans
become computationally expensive during real-time filtering, slicing, and security checks.

`taintwatch.spans.fast_index` introduces **`FastSpanIndex`**: an augmented interval tree
structure designed for character-level taint maps.

## Algorithmic Complexities

| Operation | Naive Segment Scan | `FastSpanIndex` |
| :--- | :--- | :--- |
| **Point Query** (`query_point(idx)`) | $O(N)$ | **$O(\log N)$** |
| **Range Intersections** (`query_range(start, end)`) | $O(N)$ | **$O(K + \log N)$** |
| **Pruned Taint Check** (`has_taint_below(floor)`) | $O(N)$ | **$O(\log N)$ pruned** |

## Example

```python
from taintwatch import Integrity, Label
from taintwatch.spans import FastSpanIndex, TStr

# Build large composite labeled string
text = TStr.of("trusted prefix", Label(Integrity.USER)) + ...

# Construct indexed interval tree
index = FastSpanIndex.from_tstr(text)

# O(log N) point lookup
lbl = index.query_point(12840)

# O(log N) branch-pruned taint detection
has_untrusted = index.has_taint_below(Integrity.USER, start=1000, end=50000)
```
