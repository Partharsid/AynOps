from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import whois
from utils.helpers import is_valid_domain

WHOIS_TIMEOUT_SECONDS = 10


def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup for a domain."""
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        def _fetch_whois():
            return whois.whois(domain)

        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(_fetch_whois).result(timeout=WHOIS_TIMEOUT_SECONDS)

        def safe_date(d):
            if d is None:
                return None
            return str(d[0] if isinstance(d, list) else d)

        return {
            "success": True,
            "domain": domain,
            "registrar": result.registrar,
            "whois_server": result.whois_server,
            "creation_date": safe_date(result.creation_date),
            "expiration_date": safe_date(result.expiration_date),
            "updated_date": safe_date(result.updated_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "emails": result.emails,
            "dnssec": result.dnssec,
            "country": result.country,
            "org": result.org
        }
    except FuturesTimeoutError:
        return {"success": False, "error": f"WHOIS lookup timed out after {WHOIS_TIMEOUT_SECONDS} seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}