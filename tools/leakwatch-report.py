#!/usr/bin/env python3
import collections
import json
import os
import re
import sys

root = sys.argv[1]
days = sorted(d for d in os.listdir(root) if re.match(r"\d{4}-\d{2}-\d{2}$", d))
flows = []
dns = []
for d in days:
    p = os.path.join(root, d, "flows.jsonl")
    if os.path.isfile(p):
        for line in open(p, errors="replace"):
            if line.strip():
                try:
                    f = json.loads(line)
                except ValueError:
                    continue
                f["_day"] = d
                flows.append(f)
    q = os.path.join(root, d, "dns.jsonl")
    if os.path.isfile(q):
        for line in open(q, errors="replace"):
            if line.strip():
                try:
                    dns.append(json.loads(line))
                except ValueError:
                    pass

def kb(n):
    return f"{n / 1024:.1f}K" if n < 1048576 else f"{n / 1048576:.1f}M"

def name(f):
    return f.get("sni") or f.get("http_host") or f.get("dns_name") or f["dst"]

ts = sorted(f["ts_start"] for f in flows)
print(f"days={days} flows={len(flows)} dns={len(dns)} span={ts[0] if ts else None} .. {ts[-1] if ts else None}")
states = collections.Counter(f.get("app_state") for f in flows)
print("app_state:", dict(states))

apps = collections.defaultdict(lambda: {"out": 0, "in": 0, "susp_out": 0, "off_out": 0, "bg_out": 0, "trk": collections.Counter(), "tel": collections.Counter(), "reasons": collections.Counter(), "dest": collections.Counter(), "night_out": 0, "pk": ""})
blocked = [f for f in flows if f.get("close_reason") == "domain_blocked" or f.get("blocked")]
flows = [f for f in flows if not (f.get("close_reason") == "domain_blocked" or f.get("blocked"))]
for f in flows:
    if f.get("dst", "").endswith(":53") and f.get("dst", "").startswith("10.111.0.2"):
        continue
    a = apps[f["label"]]
    a["pk"] = ",".join(f.get("packages") or [])
    a["out"] += f["bytes_out"]
    a["in"] += f["bytes_in"]
    if f.get("suspicious"):
        a["susp_out"] += f["bytes_out"]
    if f.get("app_state") == "screen_off":
        a["off_out"] += f["bytes_out"]
    if f.get("app_state") == "background":
        a["bg_out"] += f["bytes_out"]
    hour = int(f["ts_start"][11:13])
    if hour < 7:
        a["night_out"] += f["bytes_out"]
    for r in f.get("reasons") or []:
        a["reasons"][r] += 1
    n = name(f)
    if f.get("tracker"):
        a["trk"][n] += f["bytes_out"] or 1
    if "telemetry_name" in (f.get("reasons") or []):
        a["tel"][n] += f["bytes_out"] or 1
    a["dest"][n] += f["bytes_out"]

print("\n== offenders (suspicious bytes out, screen-off, background, 00-07h)")
rank = sorted(apps.items(), key=lambda kv: (kv[1]["susp_out"], kv[1]["out"]), reverse=True)
for label, a in rank[:25]:
    if not a["susp_out"] and not a["trk"]:
        continue
    print(f"- {label} [{a['pk']}] susp={kb(a['susp_out'])} off={kb(a['off_out'])} bg={kb(a['bg_out'])} night={kb(a['night_out'])} total_out={kb(a['out'])} reasons={dict(a['reasons'].most_common(5))}")
    if a["trk"]:
        print("    trackers:", ", ".join(f"{h}({kb(b)})" for h, b in a["trk"].most_common(6)))
    if a["tel"]:
        print("    telemetry:", ", ".join(f"{h}({kb(b)})" for h, b in a["tel"].most_common(5)))
    print("    top:", ", ".join(f"{h}({kb(b)})" for h, b in a["dest"].most_common(4)))

print("\n== tracker domains overall (bytes out, apps)")
td = collections.defaultdict(lambda: [0, set()])
for f in flows:
    if f.get("tracker") and not f.get("dst", "").startswith("10.111.0.2:"):
        td[name(f)][0] += f["bytes_out"]
        td[name(f)][1].add(f["label"])
for h, (b, ls) in sorted(td.items(), key=lambda kv: -kv[1][0])[:20]:
    print(f"- {h} {kb(b)} by {sorted(ls)}")

print("\n== cleartext dumps")
pii = {"email": re.compile(rb"[\w.+-]+@[\w-]+\.[\w.]+"), "imei/serial-like": re.compile(rb"(imei|serial|android_?id|adid|gaid|idfa|advertising_?id)", re.I), "geo": re.compile(rb"(lat|latitude|lon|lng|longitude)[\"'=:]", re.I), "phone": re.compile(rb"\+\d{8,15}")}
for f in flows:
    if f.get("dump"):
        p = os.path.join(root, f["_day"], f["dump"])
        if not os.path.isfile(p):
            continue
        body = open(p, "rb").read()
        hits = [k for k, rx in pii.items() if rx.search(body)]
        first = body.split(b"\n", 1)[0][:120].decode("latin-1")
        print(f"- {f['ts_start'][5:16]} {f['label']} -> {name(f)} {kb(f['bytes_out'])} pii={hits} | {first}")

print("\n== blocked (never left the phone): connections refused, lookups refused")
bc = collections.Counter((f["label"], name(f)) for f in blocked)
dc = collections.Counter((r.get("label"), r.get("name")) for r in dns if r.get("blocked"))
for l, h in sorted(set(bc) | set(dc), key=lambda k: -(bc[k] + dc[k]))[:25]:
    print(f"- {l} -> {h} connections={bc[(l, h)]} lookups={dc[(l, h)]}")
