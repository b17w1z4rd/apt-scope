"""Refresh explicitly configured HTTPS STIX bundle feeds with bounded reads."""
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

MAX_BYTES = 64 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def refresh(config_path, destination):
    config = json.loads(Path(config_path).read_text())
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {"updated_at": datetime.now(timezone.utc).isoformat(), "feeds": [], "complete": True}
    opener = build_opener(NoRedirect(), ProxyHandler({}))
    used = set()
    for feed in config["feeds"]:
        name = feed["name"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name) or name in used:
            raise ValueError("Feed names must be unique simple labels")
        used.add(name)
        url = urlsplit(feed["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError("Feed URLs must be HTTPS without credentials or fragments")
        try:
            request = Request(feed["url"], headers={"Accept": "application/json", "User-Agent": "APT-Scope/0.1"})
            with opener.open(request, timeout=30) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("feed_too_large")
            bundle = json.loads(raw)
            if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
                raise ValueError("not_a_stix_bundle")
            fd, temporary = tempfile.mkstemp(dir=destination, prefix=".refresh-")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(raw)
                os.replace(temporary, destination / (name + ".json"))
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            manifest["feeds"].append({"name": name, "status": "updated", "sha256": hashlib.sha256(raw).hexdigest(),
                                      "file": name + ".json", "source_url": feed["url"]})
        except Exception as exc:
            manifest["complete"] = False
            manifest["feeds"].append({"name": name, "status": "failed", "error_type": type(exc).__name__,
                                      "old_cache_may_remain": (destination / (name + ".json")).exists()})
    (destination / "refresh-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
