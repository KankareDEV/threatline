#!/usr/bin/env python3
"""
Threatline collector.

Runs on a schedule (every 2 hours by default), pulls public threat sources, scores every item with fixed
rules, sorts it into red / orange / green, builds the CTI analytics, and
writes data.json for the site. The file is only rewritten when something changed.
Standard library only.

    python fetch.py            # writes data.json next to this file

Sources (all public):
  - CISA Known Exploited Vulnerabilities catalogue (JSON)
  - FIRST EPSS API (exploitation probability per CVE)
  - RSS/Atom feeds listed in FEEDS

Only headlines, links and dates are stored from news feeds. Article text is
read to match keywords and is then discarded.
"""
import html
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# ----------------------------------------------------------------- config --
OUT = Path(__file__).with_name("data.json")
USER_AGENT = "Threatline/1.0 (daily digest)"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"

# Add or remove feeds here. A feed that fails is skipped and reported on the site.
FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("CISA advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
]

KEV_WINDOW_DAYS = 30   # show vulnerabilities added to KEV in this window
NEWS_WINDOW_DAYS = 3   # show news published in this window

# Score needed for each colour. Anything below orange is green.
VULN_RED = 70          # exploited vulnerabilities are never green
NEWS_RED, NEWS_ORANGE = 60, 40

# (label, points, patterns) matched against news headlines
SIGNALS = [
    ("Zero-day", 20, [r"zero[- ]day", r"0[- ]day"]),
    ("Exploited in the wild", 20, [r"actively exploited", r"exploited in the wild",
                                    r"under active exploitation", r"active exploitation",
                                    r"exploited in attacks"]),
    ("Ransomware", 15, [r"ransomware"]),
    ("Supply chain", 15, [r"supply[- ]chain"]),
    ("Data breach", 10, [r"data breach", r"breach(ed)?", r"data leak"]),
    ("Critical flaw", 10, [r"critical (vulnerability|flaw|bug|rce)"]),
]
SIGNAL_CAP = 40

STOPWORDS = set("a an the and or of to in on for with by from at as is are was were be "
                "new its it that this after over into how why what says said".split())

# Names looked for in news text for the CTI view. Add your own: (shown as, pattern).
WATCHLIST = [
    ("LockBit", r"lockbit"), ("Akira", r"akira"), ("Qilin", r"qilin"),
    ("Black Basta", r"black ?basta"), ("Cl0p", r"cl[o0]p"), ("RansomHub", r"ransomhub"),
    ("Medusa", r"medusa"), ("INC Ransom", r"inc ransom"), ("DragonForce", r"dragonforce"),
    ("Play ransomware", r"play ransomware"), ("Scattered Spider", r"scattered spider"),
    ("ShinyHunters", r"shinyhunters"), ("Lazarus", r"lazarus"), ("Kimsuky", r"kimsuky"),
    ("APT28", r"apt28|fancy bear"), ("APT29", r"apt29|cozy bear|midnight blizzard"),
    ("Sandworm", r"sandworm"), ("Volt Typhoon", r"volt typhoon"),
    ("Salt Typhoon", r"salt typhoon"), ("MuddyWater", r"muddywater"), ("FIN7", r"fin7"),
    ("Lumma Stealer", r"lumma"), ("ClickFix", r"clickfix"),
]
# Tracking labels such as UNC5221, Storm-1175 or TA577 are picked up automatically.
CLUSTER_RE = re.compile(r"\b(?:UNC\d{3,5}|Storm-\d{4}|TA\d{3,4}|APT-?\d{1,3}|FIN\d{1,2})\b", re.I)

CWE_NAMES = {
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal",
    "CWE-59": "Link following", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection", "CWE-94": "Code injection",
    "CWE-119": "Memory buffer errors", "CWE-121": "Stack buffer overflow",
    "CWE-122": "Heap buffer overflow", "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow", "CWE-200": "Information exposure",
    "CWE-264": "Permissions and privileges", "CWE-269": "Improper privilege management",
    "CWE-284": "Improper access control", "CWE-287": "Improper authentication",
    "CWE-288": "Authentication bypass by alternate path", "CWE-306": "Missing authentication",
    "CWE-352": "Cross-site request forgery", "CWE-362": "Race condition",
    "CWE-400": "Resource exhaustion", "CWE-416": "Use after free",
    "CWE-427": "Uncontrolled search path", "CWE-434": "Unrestricted file upload",
    "CWE-476": "NULL pointer dereference", "CWE-502": "Unsafe deserialization",
    "CWE-522": "Weakly protected credentials", "CWE-611": "XML external entity",
    "CWE-732": "Incorrect permission assignment", "CWE-755": "Improper handling of exceptional conditions",
    "CWE-824": "Access of uninitialized pointer", "CWE-787": "Out-of-bounds write",
    "CWE-798": "Hard-coded credentials", "CWE-843": "Type confusion",
    "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization",
    "CWE-918": "Server-side request forgery",
    "CWE-1325": "Improperly controlled sequential memory allocation",
    "CWE-1419": "Incorrect initialization of resource",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TAG_RE = re.compile(r"<[^>]+>")
NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------- helpers --
def http_get(url, tries=3, timeout=30):
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{url[:80]}: {last}")


def clean(text):
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub(" ", text or ""))).strip()


def level_for(kind, score):
    if kind == "vuln":
        return "red" if score >= VULN_RED else "orange"
    return "red" if score >= NEWS_RED else "orange" if score >= NEWS_ORANGE else "green"


# ------------------------------------------------------------------- KEV --
def load_kev(status):
    for url in KEV_URLS:
        try:
            data = json.loads(http_get(url))
            status.append({"name": "CISA KEV", "ok": True})
            return data["vulnerabilities"]
        except Exception as e:  # noqa: BLE001
            print(f"KEV source failed: {e}", file=sys.stderr)
    status.append({"name": "CISA KEV", "ok": False})
    return None


def load_epss(cves, status):
    scores = {}
    try:
        for i in range(0, len(cves), 50):
            raw = http_get(EPSS_URL.format(cves=",".join(cves[i:i + 50])))
            for row in json.loads(raw).get("data", []):
                scores[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        status.append({"name": "FIRST EPSS", "ok": True})
    except Exception as e:  # noqa: BLE001
        print(f"EPSS failed: {e}", file=sys.stderr)
        status.append({"name": "FIRST EPSS", "ok": False})
    return scores


# ------------------------------------------------------------------ feeds --
def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(raw):
    root = ET.fromstring(raw)
    out = []
    for node in root.iter():
        if local(node.tag) not in ("item", "entry"):
            continue
        f = {"title": "", "link": "", "date": None, "text": ""}
        for ch in node:
            name = local(ch.tag)
            if name == "title":
                f["title"] = clean(ch.text)
            elif name == "link":
                href = ch.attrib.get("href") or (ch.text or "").strip()
                if href and (not f["link"] or ch.attrib.get("rel", "alternate") == "alternate"):
                    f["link"] = href
            elif name in ("pubdate", "published", "updated", "date"):
                f["date"] = f["date"] or parse_date(ch.text)
            elif name in ("description", "summary", "content", "encoded"):
                f["text"] += " " + clean(ch.text)
        if f["title"] and f["link"].startswith("http"):
            out.append(f)
    return out


def load_news(status):
    cutoff = NOW - timedelta(days=NEWS_WINDOW_DAYS)
    items = []
    for name, url in FEEDS:
        try:
            for e in parse_feed(http_get(url)):
                if e["date"] and e["date"] >= cutoff:
                    e["source"] = name
                    items.append(e)
            status.append({"name": name, "ok": True})
        except Exception as ex:  # noqa: BLE001
            print(f"Feed failed: {name}: {ex}", file=sys.stderr)
            status.append({"name": name, "ok": False})
    return items


def title_tokens(title):
    words = re.findall(r"[a-z0-9][a-z0-9\-]+", title.lower())
    return {w for w in words if w not in STOPWORDS and len(w) > 2}


def merge_duplicates(items):
    """Group stories that cover the same event (shared CVE in title, or similar title)."""
    groups = []
    for it in sorted(items, key=lambda x: x["date"]):
        toks = title_tokens(it["title"])
        it["_toks"] = toks
        it["_cves"] = {c.upper() for c in CVE_RE.findall(it["title"] + " " + it["text"])}
        it["_tcves"] = {c.upper() for c in CVE_RE.findall(it["title"])}
        for g in groups:
            lead = g[0]
            union = toks | lead["_toks"]
            sim = len(toks & lead["_toks"]) / len(union) if union else 0
            if sim >= 0.5 or (it["_tcves"] & lead["_tcves"]):
                g.append(it)
                break
        else:
            groups.append([it])
    return groups


# ---------------------------------------------------------------- scoring --
def score_vuln(v, epss, news_by_cve):
    cve = v["cveID"].upper()
    added = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
    age = (NOW - added).days
    ransomware = v.get("knownRansomwareCampaignUse", "").lower() == "known"
    reasons = [{"label": "Confirmed exploited (CISA KEV)", "points": 50}]
    e = epss.get(cve)
    if e:
        reasons.append({"label": f"EPSS {e[0] * 100:.0f}% chance of exploitation in 30 days",
                        "points": round(e[0] * 25)})
    if ransomware:
        reasons.append({"label": "Used in ransomware campaigns", "points": 15})
    if age <= 7:
        reasons.append({"label": "Added in the last 7 days", "points": 10})
    elif age <= 14:
        reasons.append({"label": "Added in the last 14 days", "points": 5})
    related = news_by_cve.get(cve, [])
    if related:
        reasons.append({"label": "In the news this week", "points": 5})
    score = min(100, sum(r["points"] for r in reasons))
    seen, links = set(), [{"label": "NVD entry", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}]
    for n in related:
        if n["source"] not in seen and len(links) < 4:
            seen.add(n["source"])
            links.append({"label": n["source"], "url": n["link"]})
    return {
        "id": cve, "type": "vuln", "title": v.get("vulnerabilityName") or cve,
        "cve": cve, "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
        "date": v["dateAdded"], "summary": v.get("shortDescription", ""),
        "action": v.get("requiredAction", ""), "due": v.get("dueDate", ""),
        "epss": e[0] if e else None, "ransomware": ransomware, "links": links,
        "cwes": [c for c in v.get("cwes", []) if c.startswith("CWE-")],
        "score": score, "level": level_for("vuln", score), "reasons": reasons,
    }


def score_news(group, kev_all):
    lead = max(group, key=lambda x: x["date"])
    headline = " ".join(g["title"] for g in group)
    reasons = [{"label": "Reported by a tracked source", "points": 20}]
    sig_total, ransomware, signals = 0, False, []
    for label, pts, pats in SIGNALS:
        if any(re.search(p, headline, re.I) for p in pats):
            signals.append(label)
            ransomware = ransomware or label == "Ransomware"
            pts = min(pts, SIGNAL_CAP - sig_total)
            if pts > 0:
                reasons.append({"label": label + " in the headline", "points": pts})
                sig_total += pts
    cves = sorted({c for g in group for c in g["_cves"]})
    hit = [c for c in cves if c in kev_all]
    if hit:
        reasons.append({"label": f"Mentions exploited {hit[0]}", "points": 20})
    body = " ".join(f'{g["title"]} {g["text"]}' for g in group)
    actors = {name for name, pat in WATCHLIST if re.search(rf"\b(?:{pat})\b", body, re.I)}
    actors |= {m.upper().replace("STORM", "Storm") for m in CLUSTER_RE.findall(body)}
    sources = sorted({g["source"] for g in group})
    if len(sources) > 1:
        reasons.append({"label": f"Covered by {len(sources)} sources",
                        "points": min(20, 10 * (len(sources) - 1))})
    score = min(100, sum(r["points"] for r in reasons))
    seen, links = set(), []
    for g in sorted(group, key=lambda x: x["date"], reverse=True):
        if g["source"] not in seen:
            seen.add(g["source"])
            links.append({"label": g["source"], "url": g["link"]})
    return {
        "id": lead["link"], "type": "news", "title": lead["title"],
        "date": lead["date"].date().isoformat(), "sources": sources, "cves": cves[:6],
        "ransomware": ransomware, "links": links,
        "signals": signals, "actors": sorted(actors),
        "score": score, "level": level_for("news", score), "reasons": reasons,
    }


# -------------------------------------------------------------- analytics --
def build_analytics(items, kev_all):
    """Counts and groupings for the CTI view. Everything here comes from items."""
    vulns = [i for i in items if i["type"] == "vuln"]
    news = [i for i in items if i["type"] == "news"]
    today = NOW.date()
    per_day = Counter(v["date"] for v in vulns)
    timeline = []
    for d in range(KEV_WINDOW_DAYS, -1, -1):
        day = (today - timedelta(days=d)).isoformat()
        timeline.append({"date": day, "n": per_day.get(day, 0)})
    actors = {}
    for n in news:
        for a in n["actors"]:
            rec = actors.setdefault(a, {"name": a, "n": 0, "links": []})
            rec["n"] += 1
            if len(rec["links"]) < 3:
                rec["links"].append({"label": n["title"], "url": n["links"][0]["url"]})
    sig = Counter(s for n in news for s in n["signals"])
    cve_count = Counter(c for n in news for c in n["cves"])
    epss_known = [v["epss"] for v in vulns if v["epss"] is not None]
    return {
        "totals": {
            "kev_window": len(vulns),
            "ransomware": sum(1 for v in vulns if v["ransomware"]),
            "epss_high": sum(1 for e in epss_known if e >= 0.5),
            "epss_known": len(epss_known),
            "news": len(news),
        },
        "timeline": timeline,
        "vendors": [{"name": k, "n": n} for k, n in
                    Counter(v["vendor"] for v in vulns if v["vendor"]).most_common(8)],
        "cwes": [{"id": k, "name": CWE_NAMES.get(k, ""), "n": n} for k, n in
                 Counter(c for v in vulns for c in v["cwes"]).most_common(8)],
        "deadlines": [{"cve": v["cve"], "title": v["title"], "due": v["due"]}
                      for v in sorted(vulns, key=lambda v: v["due"])
                      if v["due"] >= today.isoformat()][:12],
        "signals": [{"name": label, "n": sig[label]} for label, _, _ in SIGNALS if sig[label]],
        "actors": sorted(actors.values(), key=lambda a: (-a["n"], a["name"]))[:12],
        "news_cves": [{"cve": c, "n": n, "kev": c in kev_all}
                      for c, n in cve_count.most_common(12)],
        "by_source": [{"name": k, "n": n} for k, n in
                      Counter(s for n in news for s in n["sources"]).most_common()],
    }


# ------------------------------------------------------------------- main --
def main():
    status = []
    kev = load_kev(status)
    if kev is None:
        print("KEV unavailable; keeping the previous data.json.", file=sys.stderr)
        return 1
    kev_all = {v["cveID"].upper() for v in kev}
    cutoff = (NOW - timedelta(days=KEV_WINDOW_DAYS)).date().isoformat()
    recent = [v for v in kev if v["dateAdded"] >= cutoff]
    if not recent:  # quiet month: still show the latest entries
        recent = sorted(kev, key=lambda v: v["dateAdded"], reverse=True)[:10]

    epss = load_epss([v["cveID"] for v in recent], status)
    groups = merge_duplicates(load_news(status))

    news_by_cve = {}
    for g in groups:
        for it in g:
            for c in it["_cves"]:
                news_by_cve.setdefault(c, []).append(it)

    items = [score_vuln(v, epss, news_by_cve) for v in recent]
    items += [score_news(g, kev_all) for g in groups]
    items.sort(key=lambda x: x["date"], reverse=True)
    items.sort(key=lambda x: x["score"], reverse=True)

    counts = {k: sum(1 for i in items if i["level"] == k) for k in ("red", "orange", "green")}
    data = {
        "generated": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kev_window_days": KEV_WINDOW_DAYS, "news_window_days": NEWS_WINDOW_DAYS,
        "kev_total": len(kev), "counts": counts, "sources": status,
        "analytics": build_analytics(items, kev_all), "items": items,
    }
    # Leave the file alone when nothing changed, so the site is not redeployed for nothing.
    try:
        old = json.loads(OUT.read_text(encoding="utf-8"))
        if {**old, "generated": ""} == json.loads(json.dumps({**data, "generated": ""})):
            print("No change since the last run.")
            return 0
    except (OSError, ValueError):
        pass
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(items)} items: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
