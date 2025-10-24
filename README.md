# SafeRecon  Subdomain & Directory Recon Toolkit (For Educational & Lab Use Only)

SafeRecon is a lightweight reconnaissance script used to enumerate **subdomains** and **directories** in a target web application. It is designed for **SOC analysts, cybersecurity learners, and penetration testing students** who want to understand reconnaissance workflows.

This repository is part of a cybersecurity learning portfolio and is used **only on authorized targets** (CTF labs, intentionally vulnerable applications, and systems with permission).


## Features

- Enumerates subdomains via DNS lookups.
- Performs directory/path discovery using wordlists.
- Adjustable scanning rate & concurrency to prevent overload.
- Outputs results to JSON for analysis or reporting.
- Supports safe testing environments (e.g., Juice Shop, DVWA, local labs).



## Example Usage

```bash
python safe_recon.py http://localhost:3000 \
  --subdomains wordlists/subdomains.txt \
  --directories wordlists/directories.txt \
  --rate 0.3 \
  --concurrency 6 \
  --output safe_report.json
````


## Wordlists

You can expand the wordlists using:

* SecLists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
* Assetnote Wordlists: [https://wordlists.assetnote.io](https://wordlists.assetnote.io)


## Intended Use

This tool is used to understand:

* Web attack surface mapping
* Discovery of hidden endpoints
* Security posture analysis as part of SOC/Blue/Red team workflows

## Ethical & Legal Use Notice

This tool **must only** be used on **systems you own, control, or have explicit permission to test**.

### Allowed:

✅ Local vulnerable labs (Juice Shop, DVWA, WebGoat)

✅ Your own servers, applications, and cloud environments

✅ CTF platforms and approved training ranges

### Not Allowed:

❌ Scanning random websites on the internet

❌ Attempting to break into organizations without written authorization

❌ Using findings to exploit systems illegally


**Unauthorized scanning is illegal** in most countries under laws like:

* Computer Misuse Act
* CFAA (US)
* EU Cybercrime Directive


## Disclaimer

This project is for **educational and defensive research purposes only**.
The author is **not responsible for misuse** of this tool.

By using this repository, **you agree to use it ethically**.

I am **Not Responsible for any liabilities from this software**.

