# Sources

## Threat-intel / IOC enrichment feeds (keyless, edge/air-gap)

For cross-referencing triage findings against current intelligence, `yararun`
ships a keyless feed catalog ([`yararun/data_feeds_2026.json`](yararun/data_feeds_2026.json),
35 feeds) consumed via `yararun feeds` — fetched over HTTPS, cached to disk, and
re-served **offline**. Representative sources (all real, attributable, mostly
keyless):

- **OSV.dev** — package/version → known vulnerabilities across ecosystems
- **CISA KEV** — actively-exploited CVE catalog
- **FIRST EPSS** — per-CVE 30-day exploit-probability scores
- **abuse.ch** — Feodo Tracker C2 IPs, ThreatFox IOCs, URLhaus malware URLs, SSLBL/JA3
- **MITRE ATT&CK** — Enterprise / Mobile / ICS technique graphs (STIX 2.1)
- **NIST SP 800-53 (OSCAL)**, **OFAC SDN**, cloud IP ranges, Tor exit nodes

Refresh with `yararun feeds update <id>`; serve air-gapped with
`yararun feeds get <id> --offline`; sneakernet via `feeds snapshot-export` /
`snapshot-import`. No fabricated indicators.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Maritime
- **feed** · https://gcaptain.com/feed/
- **feed** · https://www.maritime-executive.com/rss
- **feed** · https://splash247.com/feed/
- **feed** · https://www.tradewindsnews.com/rss
- **feed** · https://lloydslist.com/rss
- **live search** · `shadow fleet sanctioned tanker AIS`
- **live search** · `ship-to-ship transfer sanctions evasion`
- **live search** · `dark vessel AIS spoofing`
- **live search** · `OFAC sanctioned vessel designation`
- **live search** · `port disruption maritime security`
- **api** · https://aisstream.io (free real-time AIS websocket, key required)
- **api** · https://globalfishingwatch.org/our-apis/ (IUU / dark activity, free API token)
- **api** · https://www.marinetraffic.com (consumer vessel tracking)
- **api** · https://sanctionssearch.ofac.treas.gov (OFAC SDN, free)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

