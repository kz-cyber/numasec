# Security Policy

## 🔒 Responsible Disclosure

NumaSec is a penetration testing tool. Security vulnerabilities in NumaSec itself could enable:
- Unauthorized testing of targets
- Bypass of safety controls
- Data exfiltration from pentesting sessions

If you discover a security vulnerability, please follow responsible disclosure practices.

---

## 📬 Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@numasec.dev** (or create private GitHub Security Advisory)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within **48 hours** and aim to patch within **7 days** for critical issues.

---

## ⚖️ Legal Notice

### Scope: What You Can Test

✅ **IN SCOPE** (Authorized):
- Your own NumaSec installation
- Targets you have written authorization to test
- CTF platforms (PicoCTF, HackTheBox, TryHackMe, etc.)
- Intentionally vulnerable applications (DVWA, Juice Shop, WebGoat)

❌ **OUT OF SCOPE** (Unauthorized):
- NumaSec infrastructure (we don't have any SaaS yet)
- Third-party targets without authorization
- Real-world systems you don't own

### Liability

NumaSec is provided "AS IS" under MIT License with **NO WARRANTY**.

**You are responsible for:**
- Obtaining written authorization before testing any target
- Compliance with local laws (CFAA, Computer Misuse Act, etc.)
- Any damage caused by misuse of this tool

**We are NOT responsible for:**
- Legal consequences of unauthorized testing
- Damages caused by tool usage
- Accuracy of vulnerability detection

---

## 🛡️ Security Features

NumaSec includes built-in safety controls:
- **Authorization Gateway**: Prompts for confirmation before testing non-whitelisted targets
- **Scope Enforcer**: Prevents testing out-of-scope domains
- **Approval Mode**: Requires user confirmation for dangerous actions
- **Audit Logging**: All actions logged for accountability

To disable safety features (NOT RECOMMENDED):
```bash
# Don't do this unless you know what you're doing
export NUMASEC_SKIP_AUTH=1  # Bypasses authorization check
```

---

## 🔄 Security Updates

- **Critical patches**: Released within 7 days
- **Security advisories**: Posted as GitHub Security Advisories
- **Notification**: Star the repo to receive security update notifications

---

## 📜 Compliance

NumaSec is designed to comply with:
- **PTES (Penetration Testing Execution Standard)**
- **OWASP Testing Guide**
- **NIST SP 800-115**

Always follow your organization's security testing policies.

---

## 🙏 Acknowledgments

We appreciate responsible security researchers who help keep NumaSec safe.

**Hall of Fame**: (Will list researchers who report valid vulnerabilities)

---

**Last Updated**: January 2026
