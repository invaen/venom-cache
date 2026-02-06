# venom-cache

**Web cache poisoning detection from the command line.**

Finds unkeyed inputs (headers, parameters, request body) that affect cached responses — the same techniques used to find critical vulnerabilities in Tesla, GitHub, and countless bug bounty programs.

```bash
venom-cache https://target.com
```

No Burp Suite. No $449/year license. Just detection.

---

## Why This Exists

Cache poisoning lets you inject malicious content into cached responses that get served to other users. It's one of the highest-impact web vulnerabilities — a single poisoned cache entry can compromise every visitor to a site.

The standard tool for finding these bugs is **Param Miner**, but it's locked behind Burp Suite Pro. This tool brings the same detection capabilities to the command line, with better output for automation.

---

## Installation

```bash
# Clone and install
git clone https://github.com/invaen/venom-cache.git
cd venom-cache
pip install -e .

# Or just run directly
python -m venom_cache https://target.com
```

**Requirements:** Python 3.8+ (no external dependencies)

---

## Usage

### Basic Scan

```bash
# Scan a single URL for all vulnerability types
venom-cache https://target.com

# Just header poisoning
venom-cache https://target.com

# Add fat GET and web cache deception checks
venom-cache --fat-get --wcd https://target.com

# Everything
venom-cache --all https://target.com
```

### Batch Scanning

```bash
# Scan URLs from a file
venom-cache -f urls.txt

# Pipe from other tools
cat urls.txt | venom-cache -f -
```

### Authenticated Scanning

```bash
# Add cookies for authenticated endpoints
venom-cache -c "session=abc123" https://target.com/dashboard

# Add custom headers
venom-cache -H "Authorization: Bearer token" https://target.com/api
```

### Output Modes

```bash
# JSON for automation/pipelines
venom-cache --json https://target.com > results.json

# Quiet mode (findings only)
venom-cache -q https://target.com

# Verbose for debugging
venom-cache -v https://target.com
venom-cache -vv https://target.com  # Even more detail
```

### Safety Controls

```bash
# Rate limit requests (seconds between requests)
venom-cache --delay 2 https://target.com

# Verify actual cache poisoning (use carefully)
venom-cache --confirm https://target.com
```

---

## What It Detects

### Unkeyed Header Poisoning

Tests 40+ headers commonly excluded from cache keys:

- `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`
- `X-Original-URL`, `X-Rewrite-URL`
- `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`
- And many more...

When a header value appears in the response but isn't part of the cache key, you can poison the cache with malicious values.

### Unkeyed Parameter Poisoning

Tests 33 parameters often excluded from cache keys:

- UTM tracking: `utm_source`, `utm_campaign`, etc.
- Analytics: `fbclid`, `gclid`, `_ga`
- Callbacks: `callback`, `jsonp`
- Debug: `debug`, `test`

### Fat GET Poisoning

Checks if request body content affects GET responses — a technique for bypassing cache key restrictions by smuggling parameters in the body.

### Web Cache Deception

Tests path confusion techniques that trick caches into storing authenticated responses:

- Path delimiters: `;`, `%00`, `%0a`, `#`
- Static extensions: `.css`, `.js`, `.png`

---

## How It Works

1. **Cache Detection** — Identifies if caching is present via response headers (`X-Cache`, `Age`, `CF-Cache-Status`, etc.)

2. **Baseline Capture** — Records the normal response for comparison

3. **Probe Injection** — Injects unique canary values into potential unkeyed inputs

4. **Reflection Detection** — Checks if canary appears in the response

5. **Significance Analysis** — Determines if the reflection affects cached content

### Safe by Default

Every probe request includes a unique cache buster parameter, ensuring your testing doesn't pollute the production cache. The `--confirm` flag explicitly disables this for verification testing.

---

## Output Example

```
[*] Target: https://example.com
[*] Cache detected: Cloudflare (CF-Cache-Status header)
[*] Baseline captured: 200 OK, 15234 bytes

[*] Probing 40 headers for reflection...
[MEDIUM] X-Forwarded-Host: reflected in response body (significant diff)
         Location: <script src="https://venom-abc123.example.com/script.js">
[LOW]    X-Forwarded-Proto: reflected in response body

[*] Probing 33 parameters for reflection...
[MEDIUM] callback: reflected in response body (significant diff)

[*] Summary
    Headers: 2 reflected (1 significant)
    Parameters: 1 reflected (1 significant)
    Potentially vulnerable inputs found
```

---

## Custom Wordlists

```bash
# Use your own header wordlist
venom-cache -w custom-headers.txt https://target.com
```

Wordlist format (one header per line):
```
X-Custom-Header
X-Internal-Id
X-Debug-Mode
```

---

## JSON Output Schema

```json
{
  "metadata": {
    "target": "https://example.com",
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "1.0.0"
  },
  "cache_info": {
    "detected": true,
    "type": "Cloudflare",
    "headers": ["CF-Cache-Status", "Age"]
  },
  "findings": [
    {
      "type": "header",
      "name": "X-Forwarded-Host",
      "severity": "MEDIUM",
      "reflected_in": "body",
      "significant": true,
      "details": "Header value reflected in script src attribute"
    }
  ],
  "summary": {
    "headers_tested": 40,
    "headers_reflected": 2,
    "params_tested": 33,
    "params_reflected": 1
  }
}
```

---

## Flags Reference

| Flag | Description |
|------|-------------|
| `-V, --version` | Show version and exit |
| `-f, --file FILE` | Read URLs from file (use `-` for stdin) |
| `-H, --header HDR` | Add custom header (repeatable) |
| `-c, --cookie COOKIE` | Add cookie (repeatable) |
| `-A, --user-agent UA` | Custom User-Agent string |
| `-w, --wordlist FILE` | Custom header wordlist |
| `--fat-get` | Test fat GET poisoning |
| `--wcd` | Test web cache deception |
| `--all` | Run all detection modes |
| `--confirm` | Verify actual cache poisoning |
| `--delay SECS` | Delay between requests |
| `-j, --json` | JSON output |
| `-q, --quiet` | Quiet mode (findings only) |
| `-v, --verbose` | Verbose output |
| `--timeout SECS` | Request timeout (default: 10) |
| `--insecure` | Skip TLS verification |

---

## Integration Examples

### With nuclei

```bash
# Find URLs, filter for cached endpoints, test for poisoning
echo "target.com" | subfinder | httpx -mc 200 | \
  grep -E '\.(js|css|png)' | venom-cache -f - --json
```

### In CI/CD

```yaml
- name: Cache Poisoning Scan
  run: |
    pip install venom-cache
    venom-cache --json https://staging.example.com > cache-results.json
    if grep -q '"significant": true' cache-results.json; then
      echo "Potential cache poisoning vulnerability found"
      exit 1
    fi
```

### With jq

```bash
# Extract just significant findings
venom-cache --json https://target.com | \
  jq '.findings[] | select(.significant == true)'
```

---

## Credits & References

This tool implements detection techniques from:

- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) — James Kettle
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement) — James Kettle
- [Cached and Confused](https://portswigger.net/research/cached-and-confused) — James Kettle

---

## License

MIT
