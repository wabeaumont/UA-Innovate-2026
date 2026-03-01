import pandas as pd
import ipaddress

def identifyBruteForce(logFile: str) -> bool:
    window = '5min'
    threshold = 10

    # Set up dataframe
    df = pd.read_csv(logFile)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    df.set_index(df["timestamp"], inplace=True)
    failedAttempts = df[df['action'].str.contains("Failed Login")]

    if failedAttempts.empty:
        return False
    
    attack_counts = (
    failedAttempts.groupby("source_ip")["action"]
    .rolling(window)
    .count()
    )
    
    # Determine if any IP exceeded the threshold
    is_attack = (attack_counts > threshold).any()
    
    # Optional: Get the list of offending IPs
    # offending_ips = attack_counts[attack_counts > threshold].index.get_level_values('source_ip').unique()
    
    return is_attack

def identifyPhishing(logfile: str) -> bool:
    # patterns to catch a handful of high-risk domains
    pattern = r'(?:phish|login|\.(?:ru|cn|xyz|tk|buzz|top|ga|pw)$)'

    # read the CSV and normalise the domain field
    df = pd.read_csv(logfile)
    if "domain_queried" not in df.columns:
        raise ValueError("expected column 'domain_queried' in logfile")

    # lowercase/strip makes the regex more reliable
    df["domain_queried"] = df["domain_queried"].astype(str).str.lower().str.strip()

    # boolean mask for suspicious entries
    mask = df["domain_queried"].str.contains(pattern, regex=True, na=False)

    # the simple return value asked for by the caller
    return mask.any()

def identifyMalware(logfile: str) -> bool:
    # check if malware log has entries
    df = pd.read_csv(logfile)
    # If the file only contains headers, pandas produces an empty frame
    return not df.empty

def identifyFirewallExternal(logfile: str) -> bool:
    df = pd.read_csv(logfile)

    # common column names that may contain the source IP
    candidates = ("source_ip", "src_ip", "client_ip", "src", "src_address")
    ipcol = None
    for c in candidates:
        if c in df.columns:
            ipcol = c
            break
    if ipcol is None:
        raise ValueError("expected a source IP column (source_ip, src_ip, client_ip, ...) in logfile")

    # iterate unique non-null values
    for raw in df[ipcol].dropna().astype(str).unique():
        ipstr = raw.strip()
        try:
            a = ipaddress.ip_address(ipstr)
        except Exception:
            continue

        # prefer is_global where available
        if getattr(a, "is_global", None) is not None:
            if a.is_global:
                return True
        else:
            # fallback: consider external if not private/loopback/link-local/reserved
            private = getattr(a, "is_private", False)
            loop = getattr(a, "is_loopback", False)
            link = getattr(a, "is_link_local", False)
            reserved = getattr(a, "is_reserved", False)
            if not (private or loop or link or reserved):
                return True

    return False
