#!/usr/bin/env python3
"""Read-only Launchpad queries for publish-ppa.yml (stdlib only; anonymous API).

Launchpad answers an upload by email, never by failing the dput, so without these checks
a rejected or failed upload looks exactly like a successful one in CI. Subcommands:

  next-rev   --upstream V                  print the next free PPA revision for V
  fetch-orig --upstream V --out DIR        download V's published .orig into DIR, verified
                                           against its .dsc; prints the path, or nothing if
                                           V has never been uploaded
  wait       --upstream V --rev N --series "a b" [--timeout-min M]
                                           wait until each series' upload is accepted, built
                                           on every architecture the PPA enables, and its
                                           binaries are published; exit 1 on any failure
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request

API = "https://api.launchpad.net/devel"
PPA = f"{API}/~vietanhng/+archive/ubuntu/bulwark"
SOURCE = "bulwark"
POLL_SECONDS = 60


def get(url, **params):
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                body = r.read()
            return json.loads(body) if body[:1] in (b"{", b"[") else body
        except OSError as e:  # transient network/5xx; Launchpad is occasionally slow
            if attempt == 4:
                raise
            print(f"   (retrying {url}: {e})", file=sys.stderr)
            time.sleep(10 * (attempt + 1))


def entries(url, **params):
    page = get(url, **params)
    while True:
        yield from page["entries"]
        nxt = page.get("next_collection_link")
        if not nxt:
            return
        page = get(nxt)


def sources(upstream):
    """Every upload of `upstream` in the PPA that Launchpad accepted, in any state."""
    prefix = f"{upstream}-0ppa"
    return [
        s
        for s in entries(PPA, **{"ws.op": "getPublishedSources", "source_name": SOURCE,
                                 "exact_match": "true"})
        if s["source_package_version"].startswith(prefix)
    ]


def rev_of(version):
    m = re.search(r"-0ppa(\d+)~", version)
    return int(m.group(1)) if m else 0


def cmd_next_rev(a):
    revs = [rev_of(s["source_package_version"]) for s in sources(a.upstream)]
    print(max(revs, default=0) + 1)


def cmd_fetch_orig(a):
    pubs = sources(a.upstream)
    if not pubs:
        return
    urls = get(pubs[0]["self_link"], **{"ws.op": "sourceFileUrls"})
    orig_name = f"{SOURCE}_{a.upstream}.orig.tar.xz"
    orig_url = next(u for u in urls if u.endswith("/" + orig_name))
    dsc_url = next(u for u in urls if u.endswith(".dsc"))
    dsc = get(dsc_url).decode()
    m = re.search(rf"^ ([0-9a-f]{{64}}) \d+ {re.escape(orig_name)}$", dsc, re.M)
    if not m:
        sys.exit(f"no SHA-256 for {orig_name} in {dsc_url}")
    data = get(orig_url)
    if hashlib.sha256(data).hexdigest() != m.group(1):
        sys.exit(f"{orig_name} from Launchpad does not match its .dsc checksum")
    path = f"{a.out.rstrip('/')}/{orig_name}"
    with open(path, "wb") as f:
        f.write(data)
    print(path)


def cmd_wait(a):
    arches = sorted(p["name"] for p in entries(f"{PPA}/processors"))
    pending = {f"{a.upstream}-0ppa{a.rev}~{s}1": s for s in a.series.split()}
    print(f">> waiting for {', '.join(pending)} on {', '.join(arches)}")
    deadline = time.time() + a.timeout_min * 60
    # Launchpad usually accepts an upload within ~5 minutes; one that never appears was rejected.
    accept_deadline = time.time() + 30 * 60
    done = set()
    while True:
        accepted = {s["source_package_version"]: s for s in sources(a.upstream)}
        for version in sorted(set(pending) - done):
            pub = accepted.get(version)
            if pub is None:
                if time.time() > accept_deadline:
                    sys.exit(f"::error::{version} was not accepted within 30 minutes — Launchpad "
                             "rejected it; the reason is in the uploader's email")
                continue
            builds = {b["arch_tag"]: b for b in entries(pub["self_link"], **{"ws.op": "getBuilds"})}
            for arch, b in builds.items():
                if b["buildstate"] not in ("Needs building", "Currently building",
                                           "Uploading build", "Successfully built"):
                    sys.exit(f"::error::{version} {arch}: {b['buildstate']} — {b['web_link']}")
            published = {
                b["distro_arch_series_link"].rsplit("/", 1)[-1]
                for b in entries(pub["self_link"], **{"ws.op": "getPublishedBinaries"})
                if b["status"] == "Published"
            }
            state = ", ".join(f"{arch}: {'published' if arch in published else builds[arch]['buildstate'] if arch in builds else 'no build yet'}"
                              for arch in arches)
            print(f"   {version} [{pub['status']}] {state}", flush=True)
            if set(arches) <= published:
                done.add(version)
        if done == set(pending):
            print(">> all series built and published")
            return
        if time.time() > deadline:
            sys.exit(f"::error::timed out after {a.timeout_min} min waiting for "
                     f"{', '.join(sorted(set(pending) - done))}")
        time.sleep(POLL_SECONDS)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("next-rev")
    s.add_argument("--upstream", required=True)
    s.set_defaults(fn=cmd_next_rev)
    s = sub.add_parser("fetch-orig")
    s.add_argument("--upstream", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_fetch_orig)
    s = sub.add_parser("wait")
    s.add_argument("--upstream", required=True)
    s.add_argument("--rev", required=True)
    s.add_argument("--series", required=True)
    s.add_argument("--timeout-min", type=int, default=240)
    s.set_defaults(fn=cmd_wait)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
