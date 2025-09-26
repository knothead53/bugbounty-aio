from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import asyncio
import socket
import datetime
import whois
import dns.resolver
import dns.exception
import re
from typing import List, Dict, Optional
import aiohttp

# Sublist3r imports
from sublist3r import main as sublist3r_main

# Static files serving for the UI
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="BugBounty-AIO", version="0.1.0")

class ReconRequest(BaseModel):
    domain: str = Field(..., description="Target apex domain, e.g. example.com")
    top_ports: int = Field(50, ge=1, le=1000, description="How many common ports to scan on root domain (fast TCP connect scan)")
    alive_timeout_ms: int = Field(2000, ge=200, le=10000, description="HTTP(S) check timeout (ms)")

COMMON_PORTS = [
    80, 443, 21, 22, 25, 53, 110, 111, 135, 139, 143, 161, 389, 445, 465, 587,
    993, 995, 1025, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5601,
    5900, 6379, 8000, 8001, 8080, 8081, 8088, 8443, 8888, 9200, 9300, 27017
]  # ~40 ports; we slice this by top_ports

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    return d

async def tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        if hasattr(writer, "wait_closed"):
            await writer.wait_closed()
        return True
    except Exception:
        return False

async def check_url_alive(session: aiohttp.ClientSession, url: str, timeout_ms: int) -> Optional[Dict]:
    try:
        async with session.get(url, timeout=timeout_ms/1000) as resp:
            return {"url": url, "status": resp.status, "reason": resp.reason}
    except Exception:
        return None

def resolve_A(hostname: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return sorted({a.address for a in answers})
    except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []

def run_sublist3r(domain: str) -> List[str]:
    # sublist3r_main returns None but writes to a file; to capture results we pass savefile=None & print_results=False, then parse from global list it returns
    # The library function signature is: main(domain, savefile, ports, silent, verbose, enable_bruteforce, engines)
    # We’ll call it with defaults but silence output.
    try:
        subs = sublist3r_main(domain, 0, None, True, False, False, None)  # silent=True, verbose=False
        # sublist3r can return None if nothing; normalize
        if not subs:
            subs = []
        # Ensure we only keep valid subdomains under the domain
        suffix = "." + domain
        subs = sorted({s.strip().lower() for s in subs if s.strip().lower().endswith(suffix)})
        return subs
    except Exception:
        return []

def whois_summary(domain: str) -> Dict:
    try:
        w = whois.whois(domain)
        def coerce(v):
            if isinstance(v, (list, tuple)):
                return [str(x) for x in v]
            if isinstance(v, datetime.date):
                return v.isoformat()
            return str(v) if v is not None else None
        return {
            "domain_name": coerce(w.domain_name),
            "registrar": coerce(w.registrar),
            "creation_date": coerce(w.creation_date),
            "expiration_date": coerce(w.expiration_date),
            "name_servers": coerce(w.name_servers),
            "status": coerce(w.status),
        }
    except Exception:
        return {}

@app.get("/health")
async def health():
    return {"ok": True, "ts": datetime.datetime.utcnow().isoformat() + "Z"}

@app.post("/recon")
async def recon(req: ReconRequest):
    domain = normalize_domain(req.domain)
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # WHOIS (quick)
    who = whois_summary(domain)

    # A records for apex
    apex_A = resolve_A(domain)

    # Fast TCP connect scan on apex across top N ports
    ports = COMMON_PORTS[: min(req.top_ports, len(COMMON_PORTS))]
    tcp_tasks = [tcp_connect(domain, p, timeout=1.2) for p in ports]
    tcp_results = await asyncio.gather(*tcp_tasks)
    open_ports = [p for p, ok in zip(ports, tcp_results) if ok]

    # Subdomains via Sublist3r
    subs = run_sublist3r(domain)

    # DNS resolve subdomains + quick alive check for http/https
    sub_records: Dict[str, List[str]] = {}
    for s in subs[:500]:  # keep sane upper bound
        sub_records[s] = resolve_A(s)

    candidates = []
    for host in ([domain] + subs[:200]):  # keep alive checks fast
        candidates.append(f"http://{host}")
        candidates.append(f"https://{host}")

    alive = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_url_alive(session, u, req.alive_timeout_ms) for u in candidates]
        for chunk_start in range(0, len(tasks), 50):
            results = await asyncio.gather(*tasks[chunk_start:chunk_start+50])
            for r in results:
                if r:
                    alive.append(r)

    return {
        "target": domain,
        "whois": who,
        "apex_A": apex_A,
        "open_ports_tcp_connect": open_ports,
        "subdomains_count": len(subs),
        "subdomains": subs,
        "subdomain_A_records": sub_records,
        "alive_endpoints": alive,
        "notes": [
            "This is a lightweight, no-credential, non-intrusive first pass.",
            "Next steps: add naabu/httpx/nuclei/katana as separate services or a tool-runner container."
        ]
    }

# --- Serve the UI at /app ---
# This mounts the `web` directory (relative to working directory) and serves index.html as static.
# Make sure your Dockerfile copies the `web` folder into the image at /app/web (or the working dir you use).
app.mount("/app", StaticFiles(directory="web", html=True), name="app")
