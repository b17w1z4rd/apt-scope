from __future__ import annotations
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ACTORS = {"intrusion-set", "threat-actor"}
PATTERN = re.compile(r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^'\\]+)'\s*\]")


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("STIX timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def load(paths):
    objects, provenance, manifests, warnings = {}, {}, [], []
    for path in paths:
        with Path(path).open("rb") as source_file:
            raw = source_file.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("Bundle exceeds 64 MiB")
        bundle = json.loads(raw)
        if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
            raise ValueError("Expected a STIX bundle")
        digest = hashlib.sha256(raw).hexdigest()
        manifests.append({"file": Path(path).name, "sha256": digest})
        for obj in bundle["objects"]:
            if not isinstance(obj, dict) or not isinstance(obj.get("id"), str) or not obj.get("type"):
                warnings.append("Skipped object without id/type")
                continue
            oid = obj["id"]
            # Latest version wins even when it is revoked: never resurrect an old IOC.
            version = timestamp(obj.get("modified", obj.get("created", "1970-01-01T00:00:00Z")))
            old = objects.get(oid)
            old_version = timestamp(old.get("modified", old.get("created", "1970-01-01T00:00:00Z"))) if old else None
            if old is None or version > old_version:
                objects[oid] = obj
                provenance[oid] = [digest]
            elif version == old_version:
                if obj == old:
                    provenance[oid].append(digest)
                else:
                    # A same-version conflict cannot safely establish attribution.
                    warnings.append("Conflicting same-version object excluded: " + oid)
                    objects[oid] = {"id": oid, "type": obj["type"], "modified": version.isoformat(), "revoked": True}
                    provenance[oid] = []
    return objects, provenance, manifests, warnings


def active(obj, now):
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return False
    for field in ("valid_from", "start_time"):
        if obj.get(field) and timestamp(obj[field]) > now:
            return False
    for field in ("valid_until", "stop_time"):
        if obj.get(field) and timestamp(obj[field]) <= now:
            return False
    return True


def observable(kind, value):
    if kind in ("ipv4-addr", "ipv6-addr"):
        address = ipaddress.ip_address(value)
        if address.version != (4 if kind == "ipv4-addr" else 6):
            raise ValueError("IP version mismatch")
        return str(address)
    if kind == "domain-name":
        value = value.rstrip(".").encode("idna").decode().lower()
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                       for label in value.split(".")):
            raise ValueError("Invalid domain")
        return value
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Unsupported URL")
        if any(ord(c) < 32 for c in value):
            raise ValueError("Invalid URL")
        return value
    raise ValueError("Unsupported observable type")


def actor_list(objects):
    return [{"id": o["id"], "name": o.get("name", o["id"]), "aliases": o.get("aliases", [])}
            for o in objects.values() if o["type"] in ACTORS and not o.get("revoked") and not o.get("x_mitre_deprecated")]


def hunt(paths, query, now=None, max_age_days=180):
    if max_age_days < 1:
        raise ValueError("max_age_days must be positive")
    now = now or datetime.now(timezone.utc)
    objects, provenance, manifests, warnings = load(paths)
    eligible = {k: v for k, v in objects.items() if active(v, now)}
    actors = [o for o in eligible.values() if o["type"] in ACTORS and
              (query == o["id"] or any(normalize(query) == normalize(n)
               for n in [o.get("name", ""), *o.get("aliases", []),
                         *[r.get("external_id", "") for r in o.get("external_references", [])]]))]
    if not actors:
        raise ValueError("APT name/alias not found. Run 'actors' to list the loaded catalog.")
    if len(actors) > 1:
        raise ValueError("Ambiguous actor alias. Select an exact STIX ID: " + ", ".join(a["id"] for a in actors))
    actor = actors[0]
    aid = actor["id"]
    relationships = [o for o in eligible.values() if o["type"] == "relationship"
                     and o.get("source_ref") in eligible and o.get("target_ref") in eligible]
    # Strict path templates prevent unrelated graph neighbors becoming attribution.
    targets = {aid: {"kind": "direct", "path": [aid]}}
    for rel in relationships:
        src, dst, relation = rel["source_ref"], rel["target_ref"], rel["relationship_type"]
        if src == aid and relation in ("uses", "controls", "owns") and eligible[dst]["type"] in ("malware", "infrastructure"):
            targets[dst] = {"kind": "malware_association" if eligible[dst]["type"] == "malware" else "infrastructure_association",
                            "path": [aid, rel["id"], dst]}
    results = {}
    unsupported_patterns = 0

    def add(kind, value, source, path, association):
        nonlocal warnings
        try:
            value = observable(kind, value)
        except ValueError:
            warnings.append("Invalid observable excluded: " + source["id"])
            return
        # Modification means record freshness, never last-seen/liveness.
        dates = [timestamp(eligible[oid]["modified"]) for oid in path if eligible[oid].get("modified")]
        age = max(0, (now - min(dates)).days) if dates else None
        source_refs = [r for oid in path for r in eligible[oid].get("external_references", [])]
        related_actors = set()
        for oid in path:
            if eligible[oid]["type"] in ("malware", "infrastructure"):
                related_actors.update(r["source_ref"] for r in relationships
                    if r["target_ref"] == oid and r["relationship_type"] in ("uses", "controls", "owns")
                    and eligible[r["source_ref"]]["type"] in ACTORS and r["source_ref"] != aid)
        confidence_values = [eligible[oid]["confidence"] for oid in path
                             if isinstance(eligible[oid].get("confidence"), (int, float))
                             and 0 <= eligible[oid]["confidence"] <= 100]
        evidence = {"object_id": source["id"], "association": association, "path": path,
                    "oldest_modified_age_days": age, "stale_or_undated": age is None or age > max_age_days,
                    "source_confidence_min": min(confidence_values) if confidence_values else None,
                    "shared_with_actor_ids": sorted(related_actors),
                    "source_references": source_refs,
                    "bundle_sha256": sorted({s for oid in path for s in provenance.get(oid, [])}),
                    "marking_refs": sorted({s for oid in path for s in eligible[oid].get("object_marking_refs", [])})}
        row = results.setdefault((kind, value), {"type": kind, "value": value, "evidence": [],
                                                "attribution": "candidate_only", "liveness": "not_checked"})
        row["evidence"].append(evidence)

    for rel in relationships:
        src, dst, relation = rel["source_ref"], rel["target_ref"], rel["relationship_type"]
        source = eligible[src]
        if relation == "indicates" and source["type"] == "indicator" and dst in targets:
            if source.get("pattern_type") != "stix":
                unsupported_patterns += 1
                continue
            match = PATTERN.fullmatch(source.get("pattern", ""))
            if not match:
                unsupported_patterns += 1
                continue
            target = targets[dst]
            add(match[1], match[2], source, [*target["path"], rel["id"], src], target["kind"])
        elif (relation == "consists-of" and src in targets and source["type"] == "infrastructure"
              and eligible[dst]["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url")):
            item = eligible[dst]
            add(item["type"], item["value"], item, [*targets[src]["path"], rel["id"], dst], "infrastructure_association")
    candidates = sorted(results.values(), key=lambda r: (r["type"], r["value"]))
    for row in candidates:
        row["stale_only"] = all(e["stale_or_undated"] for e in row["evidence"])
        row["shared_association"] = any(e["shared_with_actor_ids"] for e in row["evidence"])
    marking_ids = {m for row in candidates for e in row["evidence"] for m in e["marking_refs"]}
    return {"schema_version": 1, "tool": "apt-scope", "actor": {"id": aid, "name": actor.get("name"), "aliases": actor.get("aliases", [])},
            "as_of": now.isoformat(), "max_age_days": max_age_days, "candidate_count": len(candidates),
            "candidates": candidates, "input_manifests": manifests, "warnings": warnings,
            "unsupported_patterns": unsupported_patterns,
            "marking_definitions": [objects[mid] for mid in sorted(marking_ids) if mid in objects],
            "limitations": ["Feed-reported association is not proof of actor ownership or current operation.",
                            "Source confidence values are not calibrated ownership probabilities.",
                            "Freshness uses the oldest modified record on the evidence path, not a last-seen observation.",
                            "No extracted IP, domain or URL was contacted.",
                            "Only the documented STIX relationship templates and simple equality patterns are supported."]}
