# 🚀 The Vibe Coder's Guide to Bulletproof Web & App Security

When you "vibe code" with AI assistants like Cursor, Claude Code, or Windsurf, the agent generates large volumes of functional code rapidly. However, agents are trained to make code work first, often taking security shortcuts:

## 1. Top 5 Vulnerabilities AI Introduces & How VibeSecurity Fixes Them

### 1. Dynamic SQL Query Construction (SQL Injection — CWE-89)
- **What the AI writes:**
  ```python
  cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")
  ```
- **The Risk:** An attacker types `' OR 1=1 --` into the login form and accesses all user accounts.
- **How VibeSecurity fixes it:**
  Converts dynamic f-strings into parameterized queries:
  ```python
  cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
  ```

### 2. Rendering HTML Strings directly in React (XSS — CWE-79)
- **What the AI writes:**
  ```tsx
  <div dangerouslySetInnerHTML={{ __html: userBio }} />
  ```
- **The Risk:** Stored XSS allows attackers to execute arbitrary JavaScript, stealing auth cookies and hijacking sessions.
- **How VibeSecurity fixes it:**
  Wraps DOM inputs in sanitization guards (`DOMPurify.sanitize`).

### 3. Missing HTTP Security Headers (CWE-693)
- **What the AI writes:**
  A default `next.config.js` or Express server with no headers configured.
- **The Risk:** The site is vulnerable to Clickjacking (iframe hijacking), MIME-type sniffing, and cross-site script loading.
- **How VibeSecurity fixes it:**
  Injects production-grade headers:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: origin-when-cross-origin`

### 4. Committing `.env` Secrets to Git (CWE-798 / CWE-552)
- **What the AI writes:**
  Creates `.env` or hardcodes `const apiKey = "sk-ant-..."` in frontend/backend files.
- **The Risk:** API keys leaked publicly on GitHub, resulting in stolen cloud resources.
- **How VibeSecurity fixes it:**
  Scans and redacts keys, adds `.env` patterns to `.gitignore`, and extracts keys to environment configuration.

### 5. Overly Permissive CORS (CWE-942)
- **What the AI writes:**
  `res.setHeader('Access-Control-Allow-Origin', '*')`
- **The Risk:** Any malicious website can send authenticated requests or read sensitive user data.
- **How VibeSecurity fixes it:**
  Replaces wildcard origins with validated environment-controlled origin allowlists.

---

## 💡 How to Use VibeSecurity While Vibe Coding

1. **Keep VibeSecurity running in your MCP config.**
   Whenever you finish generating a feature with your AI agent, ask:
   > *"VibeSecurity, audit my changes and auto-remediate any security vulnerabilities."*
2. The agent calls `auto_remediate_project`.
3. VibeSecurity tests existing code, creates a minimal fix, re-runs tests, verifies that the vulnerability is gone, and settles the changes!

