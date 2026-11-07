# Ground truth: toneshell

Set: **testing**  |  Constants: **49**

Algorithm: `h = h * 0xC85E31 + unit  (FUN_100c84a0 exports, FUN_100c8530 modules)`

Custom hash, so no third-party implementation exists. `build_gt.py selfcheck` prints the full hand derivation so one datum needs no trust. Modules are UTF-16 code units, ONE unit per character: feeding the UTF-16LE byte stream instead gives 0xdaae4730 for kernel32.dll, not the 0xd4672bc0 the sample uses.

---

## The nine steps

### Step 1 — Load the sample  `[BINARY]`

_SHA-256, architecture, image base, function count._

TODO

### Step 2 — Locate the hash routine  `[BINARY]`

_How it was found; for a published algorithm, by searching for its defining constant._

TODO

### Step 3 — Read the algorithm off the listing  `[BINARY]`

_Cite one instruction address per element: multiplier, seed, fold, final mix._

TODO

### Step 4 — Read the conventions at the call sites  `[BINARY]`

_Encoding, case fold, length convention, argument registers, per role._

TODO

### Step 5 — Extract constants and use-site addresses  `[BINARY]`

_-> targets.txt. Plus the two completeness checks: no second hashing routine, no missed constants._

TODO

### Step 6 — Build the corpus  `[OURS]`

_Bitness-matched System32 DLLs; every file with its SHA-256 -> corpus_manifest_*.csv._

TODO

### Step 7 — Compute the mapping  `[PUBLIC]`

_python3 build_gt.py <corpus> targets.txt  ->  gt_<sample>.csv_

TODO

### Step 8 — Freeze before testing  `[OURS]`

_Commit the CSV before running the resolver against it._

TODO

### Step 9 — Run the resolver and compare  `[OURS]`

_Compare names at each site. Record rows / identical / differ._

TODO

---

## Result

```
corpus      :
targets     :
unresolved  :
ambiguous   :
```

## Comparison with the resolver

```
rows compared :
identical     :
differ        :
```
