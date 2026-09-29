# APT Scope

**Find feed-attributed infrastructure candidates for a selected APT, with the evidence preserved.**

APT Scope imports STIX bundles, resolves actor names and aliases, follows explicitly supported attribution relationships, and reports IPv4/IPv6 addresses, domains and HTTP(S) URLs. It filters revoked and expired evidence, flags old evidence and shared malware associations, and writes JSON plus a defanged Markdown report.

It is an intelligence correlation tool. It cannot discover every server operated by an arbitrary APT or prove actor ownership. Coverage depends on the feeds you supply. It does not scan or contact the extracted infrastructure.

## Install and run the offline demo

Python 3.10+, no third-party runtime dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
apt-scope hunt 'Demo Bear' --bundle examples/demo-bundle.json \
  --as-of 2026-09-29T00:00:00Z --out reports/demo
cat reports/demo/report.md
```

The demo uses a fictional actor and the documentation address `192.0.2.20`. It demonstrates one candidate linked through malware shared by two fictional actors. The fixture is not real threat intelligence.

## Use an APT name of your choice

```bash
apt-scope actors --bundle intel/your-export.json
apt-scope hunt 'APT28' --bundle intel/your-export.json --out reports/apt28
```

Use STIX bundle exports from your intelligence platform or trusted feed. `--bundle` can be repeated to combine a catalog and several IOC feeds. Exact names, aliases, external IDs and STIX IDs are supported. Name comparison ignores case and punctuation; ambiguous aliases require an explicit STIX ID. Different STIX IDs are never silently merged on a similar name.

```bash
apt-scope hunt 'APT28' \
  --bundle cache/mitre-enterprise.json \
  --bundle intel/attributed-iocs.json \
  --max-age-days 90 --out reports/apt28
```

Cross-feed relationships must reference the same STIX object IDs. The tool does not guess relationships from report prose, tags, malware name similarity, shared hosting, WHOIS records or a bare IOC list.

## Automatic feed refresh

```bash
apt-scope refresh examples/feeds.json --out cache
```

The starter config downloads the MITRE Enterprise ATT&CK STIX catalog for actor names and relationships. **It is not an APT IP-address feed.** Without a source containing attributed network indicators, a hunt can correctly return zero candidates.

Add your provider's HTTPS endpoint that returns a complete STIX bundle to a private feed config:

```json
{
  "feeds": [
    {"name": "provider-iocs", "url": "https://your-provider.example/export/bundle.json"}
  ]
}
```

For repeatable refresh-and-analysis, chain the commands so a failed refresh stops the hunt:

```bash
apt-scope refresh intel/feeds.json --out cache && \
apt-scope hunt 'APT28' --bundle cache/provider-iocs.json --out reports/apt28
```

This command can be run from your own scheduler. No recurring task is installed automatically. Refresh uses HTTPS, a 64 MiB feed limit, a 30-second socket timeout, no redirects, no proxy environment settings, and atomic replacement of each successful feed file. Failures keep the previous cached file and return exit code 2; inspect `cache/refresh-manifest.json`. Updates across multiple feeds are not atomic as a batch.

Only public/no-auth bundle URLs are supported by the refresh client. Authenticated platform exports can be downloaded with your provider's client and analyzed locally. There is no TAXII pagination or authentication adapter in this version.

## Supported attribution paths

| Path in the source STIX | Output meaning |
| --- | --- |
| Indicator indicates the selected intrusion-set/threat-actor | Direct feed-reported association |
| Actor uses/controls/owns infrastructure; indicator indicates that infrastructure | Infrastructure association |
| Actor uses malware; indicator indicates that malware | Malware association, potentially shared |
| Actor uses/controls/owns infrastructure; infrastructure consists-of a supported observable | Infrastructure association |

The actor `uses` relationship to malware is supported; the parser also accepts `controls`/`owns` for a malware object if supplied, though those are not canonical actor-malware modeling choices. Relationship direction is significant. Campaign bridges, sightings, observed-data embedded objects, arbitrary graph traversal and prose extraction are not implemented.

Indicators must use `pattern_type: stix` and a single exact equality such as:

```text
[ipv4-addr:value = '192.0.2.20']
[domain-name:value = 'c2.example']
[url:value = 'https://c2.example/checkin']
```

Compound patterns, ranges, escaped literals, AND/OR clauses and other pattern types are counted as unsupported. The tool never extracts a tempting substring from an unsupported pattern.

## Evidence and uncertainty

Each candidate carries the complete STIX object/relationship path, source external references, input SHA-256 hashes, known source confidence values, marking references, shared-actor IDs, and freshness labels. `source_confidence_min` is the minimum supplied confidence along the path, not a model score or ownership probability. Missing confidence is not fabricated.

The newest object version wins, including a revoked newest version. Conflicting objects with the same ID/version are excluded. Revoked/deprecated objects, future-valid indicators and expired indicators/relationships are excluded. The tool selects the latest available version before applying time filters; `--as-of` is an evaluation cutoff, not a historical version reconstruction feature.

Freshness uses the oldest available `modified` timestamp along the path. It is intentionally conservative and is **not** a last-seen timestamp. Undated evidence is flagged. Old evidence remains in the report with `stale_only: true`; it must not become an automatic blocklist. Shared infrastructure or reused malware does not establish exclusive actor ownership.

STIX markings are carried into JSON evidence, along with available marking-definition objects. Distribution restrictions are not automatically enforced. Review provider licensing, markings, provenance and current evidence before sharing a report or turning an IOC into a detection/blocking rule.

## Outputs and exit codes

- `report.json`: raw indicator values and full evidence for analyst review.
- `report.md`: defanged summary for reading.
- `refresh-manifest.json`: successful downloads, hashes and failed refreshes.

Exit 0 means the requested command completed, including a hunt with zero results. Exit 2 indicates an input, resolution or refresh error. A successful command does not establish completeness of your intelligence coverage.

Downloaded intelligence, configs and reports belong in ignored `cache/`, `intel/` and `reports/` directories. Bundles may contain sensitive intelligence; the tool creates report files with owner-only Unix permissions.

## Validation

```bash
python -m unittest discover -s tests -v
```

Tests cover alias ambiguity, path direction, shared malware, evidence provenance, revoked/expired records, same-version conflicts, unsupported patterns, marking references, defanged reports and mocked feed refresh. Live provider ingestion was not tested in this environment. CI runs the tests and demo on Python 3.10 and 3.12.

## References

- [OASIS STIX introduction](https://oasis-open.github.io/cti-documentation/stix/intro.html)
- [STIX relationship walkthrough](https://oasis-open.github.io/cti-documentation/stix/walkthrough.html)
- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)

MIT License. See LICENSE.
