# Contributing to CyberSecurity MCP Server

Thanks for your interest in contributing! 
This project is actively growing and new tools are welcome.

---

## How to Add a New Tool

Adding a tool takes about 30-50 lines of Python. Here's the pattern:

```python
@mcp.tool()
def your_tool_name(domain: str) -> dict:
    """
    One clear sentence describing what this tool does.
    """
    try:
        # validate input
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        # your logic here
        result = {}

        return {
            "success": True,
            "domain": domain,
            # your fields here
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
```

---

## Tool Ideas (open for contribution)

These are planned but not yet built — pick one and open a PR:

- [ ] **CVE Lookup** — search known vulnerabilities by software/version
- [ ] **IP Reputation** — query AbuseIPDB for blacklisted IPs  
- [ ] **Shodan Integration** — internet-wide device search
- [ ] **Phishing Detector** — score domains for phishing likelihood
- [ ] **HTTP Headers Analyzer** — deep analysis of response headers
- [ ] **Certificate Transparency** — search cert logs for subdomains

---

## Steps to Contribute

1. Fork the repo
2. Create a branch: `git checkout -b tool/your-tool-name`
3. Add your tool to `main.py` following the pattern above
4. Test it manually with the MCP inspector
5. Update the tools table in `README.md`
6. Open a pull request with a short description

---

## Guidelines

- Every tool must return `{"success": True/False, ...}`
- Always validate domain input using `is_valid_domain()`
- Handle exceptions — never let a tool crash the server
- Keep dependencies minimal — check if a library is already used before adding new ones
- Test on `scanme.nmap.org` for port scanning tools (the only legal public target)

---

## Questions?

Open an issue or reach out on LinkedIn:
[https://www.linkedin.com/in/gaohar-imran-5a4063379/]