#!/usr/bin/env python3
"""
safe_recon_enhanced.py — Enhanced SafeRecon (read-only discovery + heuristic detection)

Features:
- Accepts full URL (http/https) or bare domain (assumes http unless full URL provided)
- DNS-based subdomain enumeration via a wordlist
- Directory enumeration + sensitive-file checks via a wordlist
- robots.txt and sitemap.xml fetching/parsing
- Heuristics to detect:
    - directory listing pages (Index of /)
    - exposed .git (presence of .git/HEAD or .git/config)
    - exposed .env-like files (presence of DB_PASSWORD, SECRET, AWS_ACCESS_KEY_ID, PRIVATE KEY markers)
    - backup files (e.g., config.php.bak)
    - common API endpoints (api/, rest/, /graphql etc)
- Verbose mode (see attempted paths)
- Rate-limited, threaded, safe (GET only)

Usage examples:
  python safe_recon_enhanced.py http://localhost:3000 --directories wordlists/directories.txt --subdomains wordlists/subdomains.txt --output juice_report.json --verbose
  python safe_recon_enhanced.py koros.dev --directories wordlists/directories.txt

Note: only use on systems you have permission to test.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import socket
import requests
import time
import json
import re
from urllib.parse import urlparse, urljoin
from xml.etree import ElementTree as ET

# Defaults
DEFAULT_SUBDOMAIN_WORDLIST = "wordlists/subdomains.txt"
DEFAULT_DIRECTORY_WORDLIST = "wordlists/directories.txt"
DEFAULT_RATE = 0.5
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 6.0

# Sensitivity heuristics / signatures (non-exhaustive)
DIR_INDEX_SIGNS = [r"Index of /", r"Directory listing for", r"Parent Directory</a>"]
GIT_SIGNS = [r"refs/heads", r"gitdir:", r"repositoryformatversion"]
ENV_SIGNS = [r"DB_PASSWORD", r"DB_USER", r"DATABASE_URL", r"SECRET", r"AWS_ACCESS_KEY_ID", r"BEGIN RSA PRIVATE KEY", r"PRIVATE KEY"]
BACKUP_EXTS = [".bak", ".old", ".orig", "~"]
API_CANDIDATES = ["api", "rest", "graphql", "v1", "v2", "svc", "svc-api"]

# Helper: pretty snippet
def snippet(text, n=300):
    if not text:
        return ""
    t = text.strip()
    return t[:n].replace("\n", " ") + ("..." if len(t) > n else "")

# Basic robots fetching (naive)
def fetch_robots(base_url, timeout=5):
    disallowed = set()
    try:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        r = requests.get(robots_url, timeout=timeout, headers={"User-Agent":"SafeRecon/1.0"})
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("disallow:"):
                    path = line.split(":",1)[1].strip()
                    if path:
                        disallowed.add(path)
    except Exception:
        pass
    return disallowed

# Simple sitemap fetching -> extract <loc>
def fetch_sitemap(base_url, timeout=5):
    urls = set()
    try:
        parsed = urlparse(base_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        r = requests.get(sitemap_url, timeout=timeout, headers={"User-Agent":"SafeRecon/1.0"})
        if r.status_code == 200:
            try:
                tree = ET.fromstring(r.content)
                # support sitemap namespace or not
                for elem in tree.iter():
                    tag = elem.tag
                    if tag.endswith('loc'):
                        if elem.text:
                            urls.add(elem.text.strip())
            except ET.ParseError:
                pass
    except Exception:
        pass
    return list(sorted(urls))

# DNS subdomain enumeration
def enumerate_subdomains(domain, wordlist_file, rate, verbose=False):
    found = []
    try:
        with open(wordlist_file, "r", encoding="utf-8") as f:
            subs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        if verbose:
            print(f"[!] Subdomain wordlist not found: {wordlist_file}")
        return found

    for sub in subs:
        fqdn = f"{sub}.{domain}"
        if verbose:
            print(f"[~] Resolving {fqdn} ...")
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
            if verbose:
                print(f"[+] {fqdn} -> {ip}")
        except socket.gaierror:
            if verbose:
                print(f"[-] {fqdn} did not resolve")
        time.sleep(rate)
    return found

# Single URL check with heuristics
def check_url(url, rate, timeout, disallowed_paths, verbose=False):
    parsed = urlparse(url)
    # naive robots skip
    for dis in disallowed_paths:
        if parsed.path.startswith(dis):
            if verbose:
                print(f"[-] Skipping {url} due to robots.txt disallow: {dis}")
            return None

    headers = {"User-Agent": "SafeRecon/1.0 (+https://example.com)"}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
    except requests.RequestException as e:
        if verbose:
            print(f"[-] Request failed {url}: {e}")
        time.sleep(rate)
        return None

    result = None
    # Accept anything < 400 (200/301/302) as a found resource
    if r.status_code < 400:
        content_text = ""
        try:
            # try text decoding; may be binary
            content_text = r.text
        except Exception:
            content_text = ""
        matched = []
        # directory index detection
        for sig in DIR_INDEX_SIGNS:
            if re.search(sig, content_text, re.IGNORECASE):
                matched.append("directory_listing")
                break
        # git detection heuristics (if path involved is .git or HEAD)
        if parsed.path.endswith(".git") or parsed.path.endswith(".git/") or parsed.path.endswith("/.git/") or parsed.path.endswith(".git/HEAD") or ".git" in parsed.path:
            # we'll still check contents
            if any(re.search(s, content_text, re.IGNORECASE) for s in GIT_SIGNS) or r.status_code < 400:
                matched.append("possible_git_exposure")
        # env detection heuristics
        if any(re.search(s, content_text, re.IGNORECASE) for s in ENV_SIGNS):
            matched.append("possible_env_or_secret")
        # backup file heuristics (extensions or content indicators)
        for ext in BACKUP_EXTS:
            if parsed.path.lower().endswith(ext):
                matched.append("possible_backup_file")
                break
        # API endpoint heuristics
        # if path contains 'api' or 'rest' etc, mark it
        for p in API_CANDIDATES:
            if f"/{p}" in parsed.path.lower() or parsed.path.lower().endswith(f"/{p}"):
                matched.append("api_like_endpoint")
                break

        result = {
            "url": url,
            "status_code": r.status_code,
            "content_snippet": snippet(content_text, 400),
            "len": len(r.content),
            "matched_signatures": list(set(matched))
        }
        if verbose:
            print(f"[+] {url} ({r.status_code}) len={result['len']} matches={result['matched_signatures']}")
    time.sleep(rate)
    return result

# Directory enumeration (multi-threaded)
def enumerate_directories(base_url, wordlist_file, concurrency, rate, timeout, verbose=False):
    results = []
    disallowed = fetch_robots(base_url, timeout=timeout)
    if verbose and disallowed:
        print(f"[~] robots.txt disallows: {disallowed}")
    # gather candidate paths
    try:
        with open(wordlist_file, "r", encoding="utf-8") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        if verbose:
            print(f"[!] Directory wordlist not found: {wordlist_file}")
        paths = []

    # add some autopopulated candidates (API-like)
    for p in API_CANDIDATES:
        if p not in paths:
            paths.append(p)

    # add sensitive file paths to check explicitly
    sensitive = [".git/HEAD", ".git/config", ".env", "config.php.bak", "backup/config.php.bak"]
    for s in sensitive:
        if s not in paths:
            paths.append(s)

    tasks = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = []
        for p in paths:
            p_s = p.lstrip("/")
            full = urljoin(base_url.rstrip("/") + "/", p_s)
            futures.append(ex.submit(check_url, full, rate, timeout, disallowed, verbose))
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    # optionally fetch sitemap urls and check them as well
    sitemap_urls = fetch_sitemap(base_url, timeout=timeout)
    if sitemap_urls:
        if verbose:
            print(f"[~] Found sitemap URLs: {len(sitemap_urls)}")
        with ThreadPoolExecutor(max_workers=min(8, concurrency)) as ex:
            futs = [ex.submit(check_url, u, rate, timeout, disallowed, verbose) for u in sitemap_urls]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    results.append(r)

    return results

def main():
    parser = argparse.ArgumentParser(description="SafeRecon Enhanced — read-only discovery + heuristics (ethical use)")
    parser.add_argument("target", help="Target domain or full URL (e.g., example.com or https://example.com)")
    parser.add_argument("--subdomains", default=DEFAULT_SUBDOMAIN_WORDLIST, help="Subdomain wordlist file")
    parser.add_argument("--directories", default=DEFAULT_DIRECTORY_WORDLIST, help="Directory wordlist file")
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE, help="Seconds between requests")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent HTTP requests")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP request timeout seconds")
    parser.add_argument("--output", default="safe_recon_enhanced_report.json", help="JSON output file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # determine base_url and domain for subdomain checks
    if args.target.startswith("http://") or args.target.startswith("https://"):
        base_url = args.target.rstrip("/")
        domain = urlparse(base_url).netloc.split(":")[0]
    else:
        scheme = "http"
        base_url = f"{scheme}://{args.target}"
        domain = args.target

    if args.verbose:
        print(f"[*] Target base URL: {base_url}")
        print(f"[*] Domain for DNS checks: {domain}")

    sub_results = enumerate_subdomains(domain, args.subdomains, args.rate, verbose=args.verbose)
    dir_results = enumerate_directories(base_url, args.directories, args.concurrency, args.rate, args.timeout, verbose=args.verbose)

    report = {
        "target": args.target,
        "base_url": base_url,
        "domain": domain,
        "subdomains": sub_results,
        "directories": dir_results,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to {args.output} (subdomains: {len(sub_results)}, directories: {len(dir_results)})")

if __name__ == "__main__":
    main()
