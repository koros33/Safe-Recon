# Web Reconnaissance Assessment Report  
**Analyst:** Ian Koros  
**Role:** Cybersecurity Student | Blue Team Path  
**Date:** 10/24/25 just finished my lunch  
**Classification:** Educational Lab Assessment



## 1. Overview

This report summarizes a **web reconnaissance assessment** performed against **OWASP Juice Shop**, a purposely vulnerable application used in cybersecurity training environments.  

The purpose of this engagement was to practice **SOC Analyst reconnaissance skills** by identifying internet-facing assets, visible directories, API endpoints, and possible misconfigurations which may increase attack surface.

No exploitation or intrusion was performed.  
All testing was conducted in a **controlled lab environment**.


## 2. Methodology (SOC Perspective)

| Phase | Description |
|------|-------------|
| **Asset Enumeration** | Identified accessible host and web application scope |
| **Subdomain Discovery** | Queried DNS records & common names from wordlists |
| **Directory Discovery** | Tested ~500 directories using safe throttled HTTP requests |
| **Response Analysis** | Reviewed HTTP status codes, response sizes, content patterns |
| **Signature Classification** | Flagged indicators like backup files, exposed Git data, directory listings |

All scanning used **rate-limiting and concurrency controls** to avoid service disruption.


## 3. Tool Used (Custom Internal)

**SafeRecon** — Python-based reconnaissance tool developed for learning and analysis.

```

python safe_recon.py [http://localhost:3000](http://localhost:3000) 
--subdomains wordlists/subdomains.txt 
--directories wordlists/directories.txt 
--rate 0.3 
--concurrency 6 
--output juice_report.json

```

- Average Request Rate: 1 every ~0.3s  
- Concurrency: 6 threads  
- Total Paths Tested: ~500  



## 4. Key Observations

| Finding | Severity | Impact Summary |
|--------|----------|----------------|
| `/uploads/` directory listing enabled | **Medium** | Enables file enumeration; users may view stored or temporary files |
| `.git/HEAD` accessible | **High** | Reveals repository structure → possible credential or code leakage |
| `/config.php.bak` available | **High** | Backup files often contain environment variables or secret keys |
| `/api/` endpoint responds without auth | **Medium** | Attackers may fingerprint API behavior or brute-force tokens |
| `.env` not found | **Safe** | No environment variable leakage observed |


## 5. Detailed Findings

### 5.1 Exposed Git Repository Metadata  
```

URL: [http://localhost:3000/.git/HEAD](http://localhost:3000/.git/HEAD)
Response: refs/heads/main
Severity: HIGH
Security Concern:

* May allow download of the full repository (including secrets).

```

### 5.2 Backup Configuration File  
```

URL: [http://localhost:3000/config.php.bak](http://localhost:3000/config.php.bak)
Indicators: possible_backup_file, possible_env_or_secret
Severity: HIGH
Risk:

* Backup files can reveal database passwords, API keys, JWT secrets.

```

### 5.3 Public Uploads Directory  
```

URL: [http://localhost:3000/uploads/](http://localhost:3000/uploads/)
Behavior: Directory Listing Enabled
Severity: MEDIUM
Risk:

* Can expose sensitive user-uploaded content.

```



## 6. Recommendations (SOC Hardening Controls)

| Recommendation | Priority | SOC Justification |
|---|---|---|
| Remove `.git/` folders from production builds | **High** | Prevent source code leakage and credential exposure |
| Delete `.bak`, `.zip`, `.old` backup files from web root | **High** | Common attack vector for credential harvesting |
| Disable directory listing (`Options -Indexes`) | **Medium** | Reduces reconnaissance value to attackers |
| Require authentication for `/api/` endpoints | **Medium** | Limits probing and brute-force surface |
| Include CI/CD artifact scanning before deployment | **Medium** | Prevents accidental inclusion of sensitive files |


## 7. Ethical and Legal Notice

This assessment was completed **only** in a controlled training environment.  
No unauthorized systems were accessed.  
No sensitive data was extracted or misused.

Understanding recon techniques helps SOC analysts:
- Detect attacker behavior earlier
- Improve monitoring rules
- Strengthen pre-attack defense posture


## 8. Conclusion

The assessment demonstrated how **basic reconnaissance** can reveal **critical security weaknesses** even before exploitation. As a SOC Analyst, identifying these weaknesses early supports stronger defense, better monitoring, and reduced exposure.

This exercise reinforces:
- Attack Surface Awareness
- Security Misconfiguration Detection
- Defensive Control Prioritization


**Prepared by:**  
**Ian Koros**  
Cybersecurity Student | Blue Team Path  
```
