# 🌐 Web Application Security Checklist

**Maintained by:** [ThreatSignal](https://threatsignal.in)  
**Last Updated:** May 2026  
**Frameworks:** OWASP Top 10 (2021), ASVS Level 2

---

## Authentication & Session Management

- [ ] Enforce MFA for all privileged accounts
- [ ] Implement account lockout after N failed attempts (e.g., 5)
- [ ] Use secure, randomly-generated session tokens (min 128-bit entropy)
- [ ] Invalidate sessions on logout, password change, and privilege change
- [ ] Set `HttpOnly` and `Secure` flags on session cookies
- [ ] Use `SameSite=Strict` or `SameSite=Lax` on cookies
- [ ] Implement session timeout (idle + absolute)
- [ ] Store passwords with bcrypt/Argon2id (never MD5/SHA1)
- [ ] Enforce password complexity and length (min 12 chars)
- [ ] Implement secure "forgot password" flow (time-limited token, one-use)

---

## Input Validation & Injection Prevention

- [ ] Use parameterized queries / prepared statements everywhere
- [ ] Validate and sanitize all user inputs server-side
- [ ] Encode output appropriately for context (HTML, JS, URL, CSS)
- [ ] Implement Content Security Policy (CSP) headers
- [ ] Validate file uploads: type, size, content (not just extension)
- [ ] Store uploaded files outside the web root
- [ ] Prevent path traversal with canonical path checks
- [ ] Use an allowlist for permitted file types/MIME types

---

## Access Control

- [ ] Enforce authorization checks on every endpoint (don't rely on UI)
- [ ] Implement principle of least privilege for all roles
- [ ] Test for IDOR (Insecure Direct Object References)
- [ ] Protect admin interfaces from public access (IP restriction, VPN)
- [ ] Audit all API endpoints for missing auth checks
- [ ] Implement RBAC or ABAC consistently - not ad hoc

---

## Security Headers

Verify these headers are set on all responses:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

Test with: [securityheaders.com](https://securityheaders.com)

---

## HTTPS & TLS

- [ ] Force HTTPS everywhere; redirect HTTP → HTTPS
- [ ] Use TLS 1.2 minimum; prefer TLS 1.3
- [ ] Disable weak ciphers (RC4, 3DES, export ciphers)
- [ ] Enable HSTS with preload
- [ ] Validate TLS cert chain, expiry, and SANs
- [ ] Use DNSSEC and CAA records to prevent cert misissuance
- [ ] Test with: [SSL Labs](https://www.ssllabs.com/ssltest/)

---

## API Security

- [ ] Rate limit all API endpoints
- [ ] Authenticate all API calls (no unauthenticated endpoints unless intentional)
- [ ] Use short-lived JWT tokens; implement refresh token rotation
- [ ] Validate `Content-Type` headers
- [ ] Return minimal data in API responses (avoid over-fetching)
- [ ] Version your API; deprecate old versions
- [ ] Log and monitor API calls for anomalies
- [ ] Implement CORS properly - don't use `*` in production

---

## Error Handling & Logging

- [ ] Never expose stack traces or internal errors to users
- [ ] Use generic error messages for auth failures
- [ ] Log auth events: login, logout, failed attempts, password changes
- [ ] Log access control failures
- [ ] Protect logs from tampering; ship to a separate system
- [ ] Alert on anomalous activity (brute force, mass download)

---

## Dependencies & Supply Chain

- [ ] Audit third-party libraries regularly (`npm audit`, `pip-audit`, Snyk)
- [ ] Pin dependency versions in production
- [ ] Check for abandoned or malicious packages before adding
- [ ] Use a private registry or proxy for packages where possible
- [ ] Verify integrity of CDN-hosted scripts with SRI hashes

```html
<!-- Subresource Integrity example -->
<script src="https://cdn.example.com/lib.min.js"
        integrity="sha384-<hash>"
        crossorigin="anonymous"></script>
```

---

## Testing & Verification

- [ ] Run DAST scans (OWASP ZAP, Burp Suite) before releases
- [ ] Include security tests in CI/CD pipeline
- [ ] Conduct annual penetration tests
- [ ] Use SAST tools in code review (Semgrep, SonarQube)
- [ ] Review OWASP ASVS checklist at target level

---

*More resources at [threatsignal.in](https://threatsignal.in)*
