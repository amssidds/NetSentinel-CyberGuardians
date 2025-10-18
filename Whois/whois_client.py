from datetime import datetime, timezone

import whois

def fetch_whois(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # --- FIX START ---
        if creation_date:
            # Make sure both datetimes are timezone-aware (UTC)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_since_creation = (now - creation_date).days
        else:
            days_since_creation = 9999
        # --- FIX END ---

        whois_data = {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "days_since_creation": days_since_creation,
            "nameservers": w.name_servers or [],
            "tld": domain.split(".")[-1],
            "registrant_privacy": any(
                word in str(w.text).lower() for word in ["privacy", "redacted", "proxy"]
            )
        }

        return whois_data

    except Exception as e:
        return {"error": str(e), "domain": domain}
