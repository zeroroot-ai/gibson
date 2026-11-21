#!/usr/bin/env -S python3 -I
"""Fetch one D3FEND release and distill the facts that the pack needs.

Usage: python3 -I fetch.py <empty-work-dir> <out-extract.json>

The script downloads the D3FEND ontology and the ATT&CK mapping of each
ATT&CK technique from https://d3fend.mitre.org. It treats all downloaded
data as untrusted: it only parses JSON and never runs it. Run it from a
directory that holds no other Python files.

The output is the extract that tools/d3fendgen reads. A person runs this
script only to move to a new D3FEND release. The Go tool never downloads.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "https://d3fend.mitre.org"
ONTOLOGY_URL = BASE + "/ontologies/d3fend.json"
MAPPING_URL = BASE + "/api/offensive-technique/attack/%s.json"
ATTACK_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
NIST_PREFIX = "d3f:NIST_SP_800-53_R5_"


def get(url, retries=4):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "d3fendgen"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            time.sleep(2 * (attempt + 1))
        except OSError:
            time.sleep(2 * (attempt + 1))
    raise SystemExit("download failed: " + url)


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def distill(onto):
    """Return the countermeasures of the graph, with their NIST controls.

    A D3 class with no tactic is no countermeasure, and a NIST control that
    maps to one is skipped.
    """
    by = {n["@id"]: n for n in onto}

    # Defensive techniques: the classes that carry a D3-xxx id.
    techs = {i: n for i, n in by.items() if str(n.get("d3f:d3fend-id", "")).startswith("D3-")}

    def parent(n):
        for s in as_list(n.get("rdfs:subClassOf")):
            p = by.get(s["@id"])
            if p is not None and str(p.get("d3f:d3fend-id", "")).startswith("D3-"):
                return p["@id"]
        return ""

    def tactic(iri, seen=()):
        n = by[iri]
        for s in as_list(n.get("rdfs:subClassOf")):
            r = by.get(s["@id"])
            if r is not None and r.get("@type") == "owl:Restriction" and \
                    r.get("owl:onProperty", {}).get("@id") == "d3f:enables":
                return by[r["owl:someValuesFrom"]["@id"]]["rdfs:label"]
        p = parent(n)
        if p and p not in seen:
            return tactic(p, seen + (iri,))
        return ""

    countermeasures = {}
    for iri, n in techs.items():
        cid = n["d3f:d3fend-id"]
        if not tactic(iri):
            # A class with a D3-xxx id and no tactic (for example D3-ARMA, a
            # model) is not a countermeasure. The pack keeps only the
            # techniques that D3FEND places under a tactic.
            continue
        p = parent(n)
        countermeasures[cid] = {
            "id": cid,
            "name": n["rdfs:label"],
            "tactic": tactic(iri),
            "parent": by[p]["d3f:d3fend-id"] if p else "",
            "counters": [],
            "nist_controls": [],
        }

    # NIST SP 800-53 rev 5 controls that D3FEND maps to a defensive technique.
    for n in onto:
        if not n["@id"].startswith(NIST_PREFIX) or "d3f:control-name" not in n:
            continue
        label = n["rdfs:label"]
        for b in as_list(n.get("d3f:broader")):
            t = by.get(b["@id"])
            if t is not None and str(t.get("d3f:d3fend-id", "")).startswith("D3-"):
                # A NIST control can map to a D3 class with no tactic, which
                # the pack does not keep (see above).
                cm = countermeasures.get(t["d3f:d3fend-id"])
                if cm is None:
                    continue
                if label not in cm["nist_controls"]:
                    cm["nist_controls"].append(label)

    return countermeasures


def main():
    work, out = sys.argv[1], sys.argv[2]
    if os.path.exists(work) and os.listdir(work):
        raise SystemExit("work dir must be empty")
    os.makedirs(os.path.join(work, "mappings"), exist_ok=True)

    raw = get(ONTOLOGY_URL)
    with open(os.path.join(work, "d3fend.json"), "wb") as f:
        f.write(raw)
    onto = json.loads(raw)["@graph"]
    meta = next(n for n in onto if n.get("@type") == "owl:Ontology")
    countermeasures = distill(onto)

    # ATT&CK techniques: the mapping of each one comes from the D3FEND API.
    attack = sorted(
        n["d3f:attack-id"] for n in onto
        if ATTACK_ID.match(str(n.get("d3f:attack-id", ""))) and not n.get("owl:deprecated")
    )
    fetched, absent = 0, []
    for tid in attack:
        body = get(MAPPING_URL % tid)
        time.sleep(0.2)
        if body is None:
            absent.append(tid)
            continue
        with open(os.path.join(work, "mappings", tid + ".json"), "wb") as f:
            f.write(body)
        fetched += 1
        for b in json.loads(body)["off_to_def"]["results"]["bindings"]:
            if "def_tech_id" not in b:
                continue
            cid = b["def_tech_id"]["value"]
            if cid in countermeasures and tid not in countermeasures[cid]["counters"]:
                countermeasures[cid]["counters"].append(tid)

    cms = []
    for cid in sorted(countermeasures):
        cm = countermeasures[cid]
        cm["counters"].sort()
        cm["nist_controls"].sort()
        cms.append(cm)
    extract = {
        "release": meta["owl:versionInfo"],
        "release_date": meta["d3f:release-date"]["@value"],
        "license": meta.get("dcterms:license", ""),
        "ontology_url": ONTOLOGY_URL,
        "ontology_sha256": hashlib.sha256(raw).hexdigest(),
        "mapping_url": MAPPING_URL,
        "attack_techniques_requested": len(attack),
        "attack_techniques_without_mapping_page": absent,
        "countermeasures": cms,
    }
    with open(out, "w") as f:
        json.dump(extract, f, indent=1, sort_keys=True)
        f.write("\n")
    print("release", extract["release"], "countermeasures", len(cms), "attack", fetched, "absent", len(absent))


if __name__ == "__main__":
    main()
