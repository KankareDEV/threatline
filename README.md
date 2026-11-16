# Vulforce

A continuously updated digest of exploited vulnerabilities and security news, sorted into
red, orange and green on a black page, with a CTI view of counts and
trends. A Python script collects public sources every 2 hours, scores each item with fixed rules, and writes
`data.json`. A static page reads that file.

## Files

| File | Purpose |
| --- | --- |
| `fetch.py` | Collects, deduplicates and scores. Standard library only |
| `index.html` | The site. No build step |
| `globe.gl.min.js`, `countries.json` | The 3D globe library (globe.gl, MIT licence) and country outlines (Natural Earth, public domain) for the Map tab |
| `data.json` | Latest data, rewritten by `fetch.py` |
| `.github/workflows/update.yml` | Runs `fetch.py` every 2 hours and commits `data.json` when it changed |

## Run it locally

    python fetch.py
    python -m http.server 8000

Then open http://localhost:8000. Opening `index.html` as a local file will
not work, because browsers block it from reading `data.json`.

## Put it online (free)

1. Create a public GitHub repository and push these files, including the
   hidden `.github` folder.
2. Settings > Pages > Source: "Deploy from a branch", branch `main`, folder `/`.
3. Actions tab > "Update data" > "Run workflow" once to test it.
4. To use your own domain: Settings > Pages > Custom domain, then add the
   DNS records GitHub shows you at your registrar. Tick "Enforce HTTPS".

## How often it updates

- GitHub runs the collector every 2 hours (`cron` line in `update.yml`).
- `data.json` is committed only when something changed.
- An open page re-reads `data.json` every 10 minutes, so nobody has to reload.
- Cloudflare Pages' free plan allows 500 builds a month and every commit is a
  build. Every 2 hours is at most about 372 a month. Hourly (`"7 * * * *"`)
  can go over that limit; it is fine on GitHub Pages or a paid Cloudflare plan.
- GitHub may start scheduled runs several minutes late when it is busy.

## CTI view

Open the "CTI" tab (`#cti`). It is built from the same run:

- exploited vulnerabilities added per day, most affected vendors, weakness types (CWE)
- upcoming CISA patch deadlines
- news by headline signal, actors and malware named (from `WATCHLIST` in
  `fetch.py`), and CVEs mentioned in the news
- buttons to copy the CVE list or a CSV, and a link to the raw JSON

## Map tab

Open the "Map" tab (`#map`). It is a 3D globe with two layers:

- Ransomware victims per country in the last 30 days, from Ransomware.live.
  Only counts, the most active groups and the most hit sectors are stored.
  No victim names are stored or shown. These are claims posted by the groups.
- Countries named in the news, read from each story by Claude (needs the AI key).

Both show where victims are, not where attacks come from. Ransomware.live asks
to be credited wherever its data is shown and does not allow commercial use
without permission.

## AI summaries (optional)

If the repository has a secret named `ANTHROPIC_API_KEY`, the collector asks
Claude (model `claude-haiku-5-5`) for a short summary and tags (sector, actors,
malware, ATT&CK tactic) for each new story, plus a short note on what matters
today. Without the secret the site works as before.

- Add the key under Settings > Secrets and variables > Actions > New
  repository secret. Never put it in a file in the repository.
- Each story is sent once and the result is reused, at most 40 new stories a run.
- Scores and colours never come from the model. AI text is labelled on the site.
- Set a monthly spend limit in the Claude Console.

## Colours

| Colour | Meaning | Vulnerabilities | News |
| --- | --- | --- | --- |
| Red | Act now | score 70+ | score 60+ |
| Orange | Check this week | below 70 | score 40 to 59 |
| Green | Good to know | never (all are exploited) | below 40 |

## Scoring

Vulnerabilities (from CISA KEV, last 30 days):

| Rule | Points |
| --- | --- |
| Confirmed exploited (in KEV) | 50 |
| EPSS probability x 25 | 0 to 25 |
| CVSS 9.0+ / 7.0 to 8.9 | 10 / 5 |
| Used in ransomware campaigns | 15 |
| Added in the last 7 / 14 days | 10 / 5 |
| In the news this week | 5 |

News (last 3 days):

| Rule | Points |
| --- | --- |
| Reported by a tracked source | 20 |
| Headline signals (zero-day, exploited, ransomware, supply chain, breach, critical flaw) | up to 40 |
| Mentions a CVE that is in KEV | 20 |
| Covered by more than one source | 10 each, up to 20 |

Change the thresholds, weights, windows, keywords and feed list at the top
of `fetch.py`.

## Limits

- It ranks general risk. It knows nothing about any organisation's assets.
- Headline keyword matching is crude and will sometimes misjudge a story.
- Only headlines, dates and links are stored from news feeds. Check each
  feed's terms of use before adding it, and keep linking to the original.
- CVSS comes from the public CVE record (vendor score first, then CISA's).
  Very new CVEs may have no score yet.
