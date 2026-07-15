# WebScanner

An async [Textual](https://textual.textualize.io/) TUI for website reconnaissance. Point it
at a domain and it concurrently gathers DNS, WHOIS, TLS, security, tech-stack and SEO
intelligence, then lays it out across tabs — with a live country map and a server-status
panel that stay pinned in place.

**No paid APIs.** Everything runs off free, public endpoints and the standard library:
`ip-api.com` for geolocation, Cloudflare/Google DoH and `dig` against public filtering
resolvers for blocklist checks, the system `whois`, and stdlib `ssl`/`socket`. Country
borders are embedded (Natural Earth), so even the map needs no tile service.

![WebScanner](https://raw.githubusercontent.com/iamramizk/web-scanner/main/.github/screenshot-v2.png)

## Features

Ten tabs, scanned concurrently and rendered live as each module finishes:

- **DNS** — A / AAAA / NS / CNAME / SOA / MX / TXT / CAA / DS / DNSKEY records, plus email
  authentication folded in: DMARC (`_dmarc`) and DKIM (probes ~40 common selectors, each
  labelled with its email provider).
- **Whois** — parsed system `whois`, with rich gTLD and ccTLD field support (registrar,
  dates, nameservers, per-contact details).
- **Subdomains** — discovered natively from TLS certificate SANs and `socket` probes of
  common subdomains — no third-party enumeration services.
- **SSL** — certificate issuer, subject, SANs, validity window, trust and expiry, parsed
  from the live TLS handshake.
- **Security** — TCP connect port scan, presence of HTTP security headers (CSP, HSTS,
  X-Frame-Options, …), and blocklist status across public filtering resolvers
  (AdGuard, CleanBrowsing, Cloudflare, Google, OpenDNS, Quad9).
- **Headers** — the full set of HTTP response headers.
- **Tech** — technology-stack detection via [Wappalyzer](https://github.com/tunetheweb/wappalyzer),
  split into one table per technology group, each showing name, category, confidence and version.
- **SEO** — page content (title/description with length hints, H1–H3, social links), top
  keyword n-grams, `robots.txt` and sitemaps, and JSON-LD structured data.
- **Sitemap** — the site's URLs discovered from its `sitemap.xml` (recursing into nested
  sitemap indexes) and rebuilt into a clickable URL-path tree — no crawling.
- **Links** — internal and external links, with their anchor text.

Alongside the tabs, two fixed panels:

- **Country map** — real country outlines auto-framed around the server's location, drawn
  with braille characters (`+` / `-` to zoom).
- **Server** — online status and response time, IP, geolocation, ISP, AS, hosting provider
  and detected CMS (name and version, from the Tech scan).

## Installation

Requires Python 3.11+.

The easiest way is with [pipx](https://pipx.pypa.io/) (or [uv](https://docs.astral.sh/uv/)),
which installs `webscan` into its own isolated environment:

```bash
pipx install web-scanner
# or
uv tool install web-scanner
```

To install the latest unreleased code, point either tool at the repo instead:
`pipx install git+https://github.com/iamramizk/web-scanner`.

### From source (development)

```bash
git clone https://github.com/iamramizk/web-scanner.git
cd web-scanner
python3 -m venv .venv
source .venv/bin/activate     # Unix/macOS  (.venv\Scripts\activate on Windows)
pip install -e .
```

## Usage

```bash
webscan example.com
```

You can also run it as a module (`python -m webscanner example.com`), or from a source
checkout without installing (`python app.py example.com`).

Press `s` inside the app to save every tab to CSV. When installed, results are written to a
`./<domain>_<timestamp>/` folder in your current directory.

## Updating

```bash
pipx upgrade web-scanner
```

If you installed from Git, `pipx upgrade` won't see new commits (the version is unchanged),
so reinstall from source instead:

```bash
pipx install --force git+https://github.com/iamramizk/web-scanner
```

### Keys

| Key              | Action                                                              |
| ---------------- | ------------------------------------------------------------------- |
| `←` / `→` `Tab`  | Switch tabs                                                         |
| `+` / `-`        | Zoom the country map in / out                                       |
| `↑` / `↓` `enter`| Navigate the Sitemap tree (`space` expands/collapses all)          |
| `r`              | Rescan                                                              |
| `s`              | Save — export every tab to CSV under `output/<domain>_<timestamp>/` |
| `esc`            | Edit the domain and scan a new one                                  |
| `q`              | Quit                                                                |
