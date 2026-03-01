import pandas as pd

def getPhishingInfo(logfile: str) -> list:
    # return triples of [timestamp, source_ip, suspicious domain]; follows
    # same logic as identifiers.py's identifyPhishing()

    pattern = r'(?:phish|login|\.(?:ru|cn|xyz|tk|buzz|top|ga|pw)$)'

    df = pd.read_csv(logfile)
    if "domain_queried" not in df.columns:
        raise ValueError("expected column 'domain_queried' in logfile")

    # normalize and parse timestamp so returned timestamps match other helpers
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    df["domain_queried"] = df["domain_queried"].astype(str).str.lower().str.strip()
    mask = df["domain_queried"].str.contains(pattern, regex=True, na=False)
    suspicious = df[mask]

    results = []
    for _, row in suspicious.iterrows():
        ts = row.get("timestamp")
        if pd.isna(ts):
            ts_val = None
        else:
            ts_val = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        results.append([ts_val, row.get("client_ip"), row["domain_queried"]])
    return results

def getBruteForceInfo(logfile: str) -> list:
    window = '5min'
    threshold = 10

    df = pd.read_csv(logfile)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    df.set_index(df["timestamp"], inplace=True)

    # only failed login records
    failed = df[df["action"].str.contains("Failed Login", na=False)]
    if failed.empty:
        return []

    attack_counts = (
        failed.groupby("source_ip")["action"]
        .rolling(window)
        .count()
    )

    over = attack_counts[attack_counts > threshold]
    if over.empty:
        return []

    # extract first timestamp where the rolling count exceeded the threshold for each IP
    ips = over.index.get_level_values(0)
    times = over.index.get_level_values(1)
    over_df = pd.DataFrame({"source_ip": ips, "timestamp": times})
    first_times = over_df.groupby("source_ip")["timestamp"].min()

    results = []
    for ip, start_ts in first_times.items():
        # pick a representative user: first failed username seen for that IP
        users = failed[failed["source_ip"] == ip]["user"].dropna().astype(str)
        rep_user = users.iloc[0] if not users.empty else None
        if pd.isna(start_ts):
            start_val = None
        else:
            start_val = start_ts.isoformat() if hasattr(start_ts, "isoformat") else str(start_ts)
        results.append([start_val, ip, rep_user])

    return results


def getMalwareInfo(logfile: str) -> list:
    """Return [[timestamp_iso, hostname, threat_name], ...] from the malware log.

    Timestamps are converted to ISO strings (or ``None`` if missing).
    The logfile must include ``timestamp``, ``hostname`` and
    ``threat_name`` columns.
    """
    df = pd.read_csv(logfile)
    required = {"timestamp", "hostname", "threat_name"}
    if not required.issubset(set(df.columns)):
        raise ValueError("expected columns 'timestamp','hostname','threat_name' in logfile")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    results = []
    for _, row in df.iterrows():
        ts = row.get("timestamp")
        if pd.isna(ts):
            ts_val = None
        else:
            ts_val = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        results.append([ts_val, row.get("hostname"), row.get("threat_name")])
    return results

def getFirewallExternalInfo(logfile: str) -> list:
    """Return all firewall log rows with external source IPs as lists.

    Each row is returned as a list with all column values in order.
    Timestamps (if present) are converted to ISO strings.
    """
    import ipaddress

    df = pd.read_csv(logfile)

    # find source IP column
    candidates = ("source_ip", "src_ip", "client_ip", "src", "src_address")
    ipcol = None
    for c in candidates:
        if c in df.columns:
            ipcol = c
            break
    if ipcol is None:
        raise ValueError("expected a source IP column (source_ip, src_ip, client_ip, ...) in logfile")

    # parse timestamp if present
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    results = []
    seen = set()  # track rows we've already added (excluding timestamp)
    for _, row in df.iterrows():
        raw = row.get(ipcol)
        if pd.isna(raw):
            continue
        ipstr = str(raw).strip()
        try:
            a = ipaddress.ip_address(ipstr)
        except Exception:
            continue

        # check if external (public/global)
        is_external = False
        if getattr(a, "is_global", None) is not None:
            is_external = a.is_global
        else:
            private = getattr(a, "is_private", False)
            loop = getattr(a, "is_loopback", False)
            link = getattr(a, "is_link_local", False)
            reserved = getattr(a, "is_reserved", False)
            is_external = not (private or loop or link or reserved)

        if is_external:
            # convert timestamp to ISO if present and is a datetime
            row_dict = row.to_dict()
            ts = row_dict.get("timestamp")
            if ts is not None and hasattr(ts, "isoformat"):
                row_dict["timestamp"] = ts.isoformat()
            
            # create dedup key: all columns except timestamp
            dedup_key = tuple((k, v) for k, v in sorted(row_dict.items()) if k != "timestamp")
            if dedup_key not in seen:
                seen.add(dedup_key)
                # convert dict to list of values in column order
                row_list = [row_dict[col] for col in df.columns]
                results.append(row_list)

    return results
