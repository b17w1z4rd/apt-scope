import copy
import json
import tempfile
import unittest
from pathlib import Path
from apt_scope.intel import hunt, load, timestamp
from apt_scope.cli import write

NOW = timestamp("2026-09-29T00:00:00Z")


def fixture():
    from uuid import UUID
    def oid(kind, number):
        return kind + "--" + str(UUID(int=number, version=4))
    actor, malware, indicator, second = oid("intrusion-set", 1), oid("malware", 2), oid("indicator", 3), oid("intrusion-set", 4)
    def obj(kind, number, **extra):
        return {"type": kind, "spec_version": "2.1", "id": oid(kind, number),
                "created": "2026-09-01T00:00:00Z", "modified": "2026-09-01T00:00:00Z", **extra}
    return {"type": "bundle", "id": oid("bundle", 10), "objects": [
        obj("intrusion-set", 1, name="Demo APT", aliases=["Demo Bear"]),
        obj("malware", 2, name="Demo Loader", is_family=True),
        obj("indicator", 3, pattern_type="stix", pattern="[ipv4-addr:value = '192.0.2.20']", valid_from="2026-09-01T00:00:00Z", confidence=70),
        obj("intrusion-set", 4, name="Other Demo APT"),
        obj("relationship", 5, relationship_type="uses", source_ref=actor, target_ref=malware),
        obj("relationship", 6, relationship_type="indicates", source_ref=indicator, target_ref=malware),
        obj("relationship", 7, relationship_type="uses", source_ref=second, target_ref=malware),
    ]}


class IntelTests(unittest.TestCase):
    def scan(self, bundle, query="Demo APT"):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "feed.json"
            p.write_text(json.dumps(bundle))
            return hunt([p], query, NOW)

    def test_alias_and_shared_malware_provenance(self):
        result = self.scan(fixture(), "demo-bear")
        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertTrue(candidate["shared_association"])
        self.assertEqual(candidate["liveness"], "not_checked")
        self.assertEqual(len(candidate["evidence"][0]["path"]), 5)
        self.assertTrue(candidate["evidence"][0]["bundle_sha256"])

    def test_revoked_latest_version_is_not_resurrected(self):
        bundle = fixture()
        new = copy.deepcopy(bundle["objects"][2])
        new.update(modified="2026-09-15T00:00:00Z", revoked=True)
        bundle["objects"].insert(0, new)
        self.assertEqual(self.scan(bundle)["candidate_count"], 0)

    def test_expired_and_future_indicators_excluded(self):
        for field, value in (("valid_until", "2026-09-20T00:00:00Z"), ("valid_from", "2026-10-01T00:00:00Z")):
            bundle = fixture()
            bundle["objects"][2][field] = value
            self.assertEqual(self.scan(bundle)["candidate_count"], 0)

    def test_expired_relationship_excluded(self):
        bundle = fixture()
        bundle["objects"][5]["stop_time"] = "2026-09-20T00:00:00Z"
        self.assertEqual(self.scan(bundle)["candidate_count"], 0)

    def test_complex_pattern_not_silently_extracted(self):
        bundle = fixture()
        bundle["objects"][2]["pattern"] = "[ipv4-addr:value = '192.0.2.20' OR ipv4-addr:value = '192.0.2.21']"
        result = self.scan(bundle)
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["unsupported_patterns"], 1)

    def test_ambiguous_alias_requires_id(self):
        bundle = fixture()
        bundle["objects"][3]["aliases"] = ["Demo Bear"]
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            self.scan(bundle, "Demo Bear")

    def test_same_version_conflict_excluded(self):
        bundle = fixture()
        modified = copy.deepcopy(bundle["objects"][2])
        modified["pattern"] = "[ipv4-addr:value = '192.0.2.99']"
        bundle["objects"].append(modified)
        result = self.scan(bundle)
        self.assertEqual(result["candidate_count"], 0)
        self.assertTrue(result["warnings"])

    def test_relationship_direction_matters(self):
        bundle = fixture()
        rel = bundle["objects"][5]
        rel["source_ref"], rel["target_ref"] = rel["target_ref"], rel["source_ref"]
        self.assertEqual(self.scan(bundle)["candidate_count"], 0)

    def test_stale_evidence_is_labeled(self):
        bundle = fixture()
        bundle["objects"][2]["modified"] = "2020-01-01T00:00:00Z"
        self.assertTrue(self.scan(bundle)["candidates"][0]["stale_only"])

    def test_direct_attribution_and_markings(self):
        bundle = fixture()
        bundle["objects"][5]["target_ref"] = bundle["objects"][0]["id"]
        bundle["objects"][2]["object_marking_refs"] = ["marking-definition--demo"]
        result = self.scan(bundle)
        self.assertEqual(result["candidates"][0]["evidence"][0]["association"], "direct")
        self.assertIn("marking-definition--demo", result["candidates"][0]["evidence"][0]["marking_refs"])

    def test_markdown_defangs_values(self):
        result = self.scan(fixture())
        with tempfile.TemporaryDirectory() as d:
            write(result, d)
            self.assertIn("192[.]0[.]2[.]20", (Path(d) / "report.md").read_text())
            self.assertEqual(json.loads((Path(d) / "report.json").read_text())["candidate_count"], 1)

    def test_unknown_actor_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            self.scan(fixture(), "Unknown APT")


if __name__ == "__main__":
    unittest.main()
