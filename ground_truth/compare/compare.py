# Compare the resolver's output against the ground truth, joined on the constant.
#
# usage: compare.py <gt_SAMPLE.csv> <tool_output> [out.csv]
#
# <tool_output> is the CSV from the prompt's section B
# (address,hash,kind,module,resolved_name) or the resolver's JSON result.

import csv, json, sys
from pathlib import Path

def gt_candidates(row):
    names = [n.strip() for n in row["name"].split("|") if n.strip()]
    if row["role"] == "MODULE":
        return {n.split(" [")[0].lower() for n in names}, True
    out = set()
    for m in (x.strip() for x in row["module"].split("|") if x.strip()):
        short = m.rsplit(".", 1)[0]
        for n in names:
            out.add(f"{short}!{n}")
            out.add(f"{m}!{n}")
    return out, False

def tool_answers(entry):
    if entry.get("name"):
        return {entry["name"]}
    return set(entry.get("candidates") or [])

def load_tool(path):
    raw = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    tool = {}
    if raw.startswith("{") or raw.startswith("["):
        res = json.loads(raw)
        for e in (res.get("lookups") if isinstance(res, dict) else res) or []:
            h = (e.get("hash") or "").lower()
            if h:
                tool[h if h.startswith("0x") else "0x" + h] = e
        return tool
    for r in csv.DictReader(raw.splitlines()):
        h = (r.get("hash") or "").strip().lower()
        if not h:
            continue
        if not h.startswith("0x"):
            h = "0x" + h
        name = (r.get("resolved_name") or "").strip()
        mod = (r.get("module") or "").strip()
        kind = (r.get("kind") or "").strip().upper()
        if name and mod and kind == "API" and "!" not in name:
            name = f"{mod.rsplit('.', 1)[0]}!{name}"
        tool[h] = {"hash": h, "name": name,
                   "verdict": "RECOVERED" if name else "UNRESOLVED"}
    return tool

def main(gt_path, tool_path, out_path=None):
    gt = list(csv.DictReader(open(gt_path)))
    tool = load_tool(tool_path)

    rows = []
    n = {"MATCH": 0, "MISMATCH": 0, "UNRESOLVED": 0, "MISSING": 0}
    amb = 0
    for r in gt:
        c = r["constant"].lower()
        e = tool.get(c)
        cands, is_mod = gt_candidates(r)
        if int(r.get("n_modules") or 0) > 1:
            amb += 1
        if e is None:
            verdict, got = "MISSING", ""
        else:
            answers = tool_answers(e)
            got = "|".join(sorted(answers))
            if not answers or e.get("verdict") == "UNRESOLVED":
                verdict = "UNRESOLVED"
            elif is_mod:
                verdict = ("MATCH" if {a.lower() for a in answers} & cands
                           else "MISMATCH")
            elif answers <= cands and answers:
                verdict = "MATCH"
            else:
                verdict = "MISMATCH"
        n[verdict] += 1
        rows.append({"constant": r["constant"], "site": r.get("site", ""),
                     "role": r["role"], "module": r["module"],
                     "ground_truth": r["name"], "tool_name": got,
                     "tool_verdict": (e or {}).get("verdict", ""),
                     "verdict": verdict})

    gt_set = {r["constant"].lower() for r in gt}
    extra = sorted(set(tool) - gt_set)
    answered = n["MATCH"] + n["MISMATCH"]

    print(f"constants   {len(gt)}")
    print(f"answered    {len(tool)}")
    print(f"match       {n['MATCH']}")
    print(f"mismatch    {n['MISMATCH']}")
    print(f"unresolved  {n['UNRESOLVED']}")
    print(f"missing     {n['MISSING']}")
    print(f"extra       {len(extra)}")
    print(f"ambiguous   {amb}")
    if answered:
        print(f"accuracy    {n['MATCH']}/{answered} "
              f"({100.0 * n['MATCH'] / answered:.1f}%)")

    for e in extra[:10]:
        print(f"  extra {e} {sorted(tool_answers(tool[e]))}")
    for r in rows:
        if r["verdict"] == "MISMATCH":
            print(f"  mismatch {r['constant']} tool={r['tool_name']} "
                  f"gt={r['module']}!{r['ground_truth']}")

    if out_path:
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, ["constant", "site", "role", "module",
                                   "ground_truth", "tool_name",
                                   "tool_verdict", "verdict"])
            w.writeheader(); w.writerows(rows)
        print(f"wrote {out_path}")
    return 1 if (n["MISMATCH"] or n["UNRESOLVED"] or n["MISSING"]) else 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: compare.py <gt_SAMPLE.csv> <tool_output> [out.csv]")
    sys.exit(main(*sys.argv[1:4]))
