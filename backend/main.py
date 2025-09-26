from fastapi import FastAPI, HTTPException, status
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

# New imports for orchestration + helpers
import os
import time
import uuid
import json
import requests
from urllib.parse import quote_plus
import docker as docker_sdk
from fastapi.responses import StreamingResponse, JSONResponse

# PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

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

# ---------- Utility / Recon helpers (unchanged) ----------
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

# ---------- Expanded subdomain discovery ----------
def fetch_crtsh(domain: str) -> List[str]:
    """Query crt.sh (Certificate Transparency) for subdomains."""
    try:
        url = f"https://crt.sh/?q=%25.{quote_plus(domain)}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        try:
            items = resp.json()
        except ValueError:
            return []
        subs = set()
        for it in items:
            nv = it.get("name_value") or it.get("common_name") or ""
            for candidate in str(nv).splitlines():
                candidate = candidate.strip().lower()
                if candidate.endswith("." + domain) or candidate == domain:
                    candidate = candidate.lstrip("*. ")
                    subs.add(candidate)
        return sorted(subs)
    except Exception:
        return []

COMMON_SUB_PREFIXES = [
    "www","api","dev","test","staging","portal","mail","smtp","webmail","vpn","unifi","ns1","ns2",
    "admin","secure","ftp","mobile","m","blog","shop","git","gitlab","jira","confluence","db","db1"
]

def brute_force_subs(domain: str, prefixes: List[str] = None, resolver_fn=resolve_A) -> List[str]:
    """Try a short list of common prefixes and return those that resolve publicly."""
    if prefixes is None:
        prefixes = COMMON_SUB_PREFIXES
    found = []
    for p in prefixes:
        candidate = f"{p}.{domain}"
        try:
            recs = resolver_fn(candidate)
            if recs:
                found.append(candidate)
        except Exception:
            continue
    return sorted(set(found))

def run_sublist3r(domain: str) -> List[str]:
    """
    Combine Sublist3r (with bruteforce), crt.sh, and a small DNS brute force.
    Returns a sorted, de-duplicated list of subdomains.
    """
    results = set()

    # 1) Sublist3r (enable bruteforce)
    try:
        subs = sublist3r_main(domain, 40, None, True, False, True, None)
        if subs:
            for s in subs:
                s = s.strip().lower().lstrip("*. ")
                if s == domain or s.endswith("." + domain):
                    results.add(s)
    except Exception:
        pass

    # 2) crt.sh
    try:
        for s in fetch_crtsh(domain):
            s = s.strip().lower().lstrip("*. ")
            if s == domain or s.endswith("." + domain):
                results.add(s)
    except Exception:
        pass

    # 3) small brute-force
    try:
        for s in brute_force_subs(domain):
            results.add(s)
    except Exception:
        pass

    # Normalize & return
    suffix = "." + domain
    final = sorted({s for s in results if s == domain or s.endswith(suffix)})
    return final

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

# ---------- Existing endpoints (health / recon) ----------
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

    # Subdomains via combined discovery
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

# ---------- Docker orchestration helpers ----------
DOCKER_CLIENT = None

def get_docker_client():
    global DOCKER_CLIENT
    if DOCKER_CLIENT is None:
        DOCKER_CLIENT = docker_sdk.from_env()
    return DOCKER_CLIENT

def run_container_and_stream(image: str, cmd: list, workdir: str = None, env: dict = None, stdout_to_file: Optional[str] = None, remove: bool = True, timeout: int = 3600):
    """
    Run `image` with arguments `cmd`. Mount host /data -> container /data so tools can read/write job files.
    Writes incremental logs to stdout_to_file (host path) if provided.
    Returns (exit_code:int, logs:str).
    """
    client = get_docker_client()

    # Ensure the /data host folder exists
    host_data = "/data"
    if not os.path.isdir(host_data):
        os.makedirs(host_data, exist_ok=True)

    volumes = { host_data: {'bind': '/data', 'mode': 'rw'} }

    # Try to pull image (best-effort)
    try:
        client.images.pull(image)
    except Exception:
        # ignore pull errors (image may already exist)
        pass

    container = client.containers.run(
        image,
        cmd,
        detach=True,
        volumes=volumes,
        working_dir=workdir,
        environment=env or {},
        tty=False
    )

    logs_accum = []
    start = time.time()
    try:
        for line in container.logs(stream=True, follow=True):
            text = line.decode(errors="ignore")
            logs_accum.append(text)
            if stdout_to_file:
                try:
                    with open(stdout_to_file, "a", encoding="utf-8") as fh:
                        fh.write(text)
                except Exception:
                    pass
            if time.time() - start > timeout:
                try:
                    container.kill()
                except Exception:
                    pass
                logs_accum.append(f"\n--- Timeout after {timeout}s, container killed ---\n")
                break
    except Exception as e:
        logs_accum.append(f"\n--- log stream error: {e} ---\n")
    finally:
        try:
            rc = container.wait(timeout=5)
            exit_code = rc.get("StatusCode", 0) if isinstance(rc, dict) else 0
        except Exception:
            exit_code = -1
        if remove:
            try:
                container.remove(force=True)
            except Exception:
                pass

    return exit_code, "".join(logs_accum)

# ---------- Tool orchestration endpoints ----------
@app.post("/run/tool")
async def run_tool(body: dict):
    """
    Run a named tool container and save outputs under /data/jobs/<target>_<jobid>/output/
    body: {"tool":"subfinder"|"naabu"|"httpx"|"nuclei", "target":"example.com", "input_file":"/data/jobs/.../output/file.txt" (optional)}
    """
    tool = body.get("tool")
    target = body.get("target")
    input_file = body.get("input_file")

    if not tool or not target:
        raise HTTPException(status_code=400, detail="tool and target are required")

    if tool not in ("subfinder", "naabu", "httpx", "nuclei"):
        raise HTTPException(status_code=400, detail="unsupported tool")

    # Default: create a fresh job folder for this run
    job_id = str(uuid.uuid4())[:8]
    job_base = f"/data/jobs/{target}_{job_id}"
    output_dir = os.path.join(job_base, "output")
    os.makedirs(output_dir, exist_ok=True)

    # If an input_file from an earlier job is provided and it lives under /data/jobs/<job>/,
    # reuse that job folder so subsequent outputs land in the same place.
    if input_file and isinstance(input_file, str) and input_file.startswith("/data/jobs/"):
        try:
            normalized = os.path.abspath(input_file)
            parts = normalized.split(os.sep)
            # parts: ['', 'data', 'jobs', '<jobname>', 'output', 'file']
            if "jobs" in parts:
                idx = parts.index("jobs")
                if idx + 1 < len(parts):
                    jobname = parts[idx + 1]
                    job_base = os.path.join("/data", "jobs", jobname)
                    output_dir = os.path.join(job_base, "output")
                    os.makedirs(output_dir, exist_ok=True)
        except Exception:
            # fallback to fresh job (already created)
            pass

    # compute log file path (in chosen job folder)
    log_path = os.path.join(job_base, f"{tool}.log")

    # Build per-job container output paths (container uses /data root)
    # so inside container we write to /data/jobs/<job>/output/...
    if tool == "subfinder":
        image = "projectdiscovery/subfinder:latest"
        container_out = os.path.join(job_base, "output", "subfinder_subs.txt")
        cmd = ["-d", target, "-o", container_out, "-silent"]

    elif tool == "naabu":
        image = "projectdiscovery/naabu:latest"
        container_out = os.path.join(job_base, "output", "naabu.out")
        if input_file:
            in_container = input_file
            # leave input path as-is (it should be an absolute /data/jobs/... path)
            cmd = ["-list", in_container, "-o", container_out]
        else:
            cmd = ["-host", target, "-o", container_out]

    elif tool == "httpx":
        image = "projectdiscovery/httpx:latest"
        container_out = os.path.join(job_base, "output", "httpx.out")
        if input_file:
            in_container = input_file
            cmd = ["-l", in_container, "-o", container_out]
        else:
            cmd = ["-u", target, "-o", container_out]

    else:  # nuclei
        image = "projectdiscovery/nuclei:latest"
        container_out = os.path.join(job_base, "output", "nuclei.out")
        # nuclei expects a list (-l) or single target (-u)
        if input_file:
            in_container = input_file
            cmd = ["-l", in_container, "-o", container_out]
        else:
            cmd = ["-u", target, "-o", container_out]

    # Run and capture logs — wrap with try/except to return JSON on errors
    try:
        client = get_docker_client()
        try:
            client.images.pull(image)
        except Exception:
            # ignore pull errors here; run_container_and_stream will surface issues
            pass

        exit_code, logs = run_container_and_stream(image, cmd, stdout_to_file=log_path, timeout=1800)

        return JSONResponse({
            "job_id": os.path.basename(job_base),
            "tool": tool,
            "exit_code": exit_code,
            "out_dir": job_base,
            "log": logs
        })
    except Exception as e:
        snippet = ""
        try:
            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as fh:
                    snippet = fh.read()[-2000:]
        except Exception:
            snippet = ""
        return JSONResponse(
            {"job_id": os.path.basename(job_base), "tool": tool, "error": str(e), "log_snippet": snippet},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# ---------- Pipeline runner + PDF report generator ----------
def generate_pdf_report(job_base: str, target: str, summary: Dict) -> str:
    """
    Create a simple PDF summary at job_base/output/report.pdf.
    summary is a dict with keys 'tools' -> list of {tool, exit_code, log, out_file}
    Returns path to generated PDF.
    """
    output_dir = os.path.join(job_base, "output")
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, "report.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                            rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"BugBounty-AIO Report — {target}", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Job: {os.path.basename(job_base)}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Spacer(1, 12))

    # For each tool, include status + short log excerpt + show output file snippet (if present)
    for t in summary.get("tools", []):
        story.append(Paragraph(f"<b>{t.get('tool')}</b> — exit={t.get('exit_code')}", styles["Heading2"]))
        # include small log snippet
        log_snip = t.get("log", "")
        if log_snip:
            snippet = log_snip[-2000:] if len(log_snip) > 2000 else log_snip
            # keep line breaks
            snippet = snippet.replace("\n", "<br/>")
            story.append(Paragraph(f"<i>Log (truncated)</i>:", styles["Normal"]))
            story.append(Paragraph(snippet, styles["Code"]))
            story.append(Spacer(1, 8))

        # include the first lines of the primary output file if exists
        out_file = t.get("out_file")
        if out_file and os.path.isfile(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
                # add up to first 40 lines
                display = "\n".join(lines[:40])
                display = display.replace("\n", "<br/>")
                story.append(Paragraph(f"<i>Output file:</i> {os.path.basename(out_file)}", styles["Normal"]))
                story.append(Paragraph(display, styles["Code"]))
                story.append(Spacer(1, 8))
            except Exception:
                pass

    # final notes
    story.append(Spacer(1, 14))
    story.append(Paragraph("Notes:", styles["Heading3"]))
    story.append(Paragraph("This report was generated by BugBounty-AIO. For full raw outputs check the job folder under /data/jobs.", styles["Normal"]))
    doc.build(story)
    return pdf_path

@app.post("/run/pipeline")
async def run_pipeline(body: dict):
    """
    Run the full pipeline sequentially in a single job folder:
      subfinder -> naabu -> httpx -> nuclei
    body: {"target": "example.com", "skip_tools": ["naabu"] (optional)}
    Returns: JSON with job_id, out_dir, and per-tool results, plus path to generated PDF.
    """
    target = body.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    skip_tools = set(body.get("skip_tools") or [])
    job_id = str(uuid.uuid4())[:8]
    job_base = f"/data/jobs/{target}_{job_id}"
    output_dir = os.path.join(job_base, "output")
    os.makedirs(output_dir, exist_ok=True)

    results = {"tools": []}

    try:
        # 1) subfinder
        if "subfinder" not in skip_tools:
            image = "projectdiscovery/subfinder:latest"
            sub_out = os.path.join(job_base, "output", "subfinder_subs.txt")
            cmd = ["-d", target, "-o", sub_out, "-silent"]
            rc, logs = run_container_and_stream(image, cmd, stdout_to_file=os.path.join(job_base, "subfinder.log"), timeout=1800)
            results["tools"].append({"tool": "subfinder", "exit_code": rc, "log": logs, "out_file": sub_out})
        else:
            sub_out = None

        # 2) naabu (use subfinder output if present)
        if "naabu" not in skip_tools:
            image = "projectdiscovery/naabu:latest"
            naabu_out = os.path.join(job_base, "output", "naabu.out")
            if sub_out and os.path.isfile(sub_out):
                cmd = ["-list", sub_out, "-o", naabu_out]
            else:
                cmd = ["-host", target, "-o", naabu_out]
            rc, logs = run_container_and_stream(image, cmd, stdout_to_file=os.path.join(job_base, "naabu.log"), timeout=1800)
            results["tools"].append({"tool": "naabu", "exit_code": rc, "log": logs, "out_file": naabu_out})
        else:
            naabu_out = None

        # 3) httpx (probe hosts; prefer subfinder list)
        if "httpx" not in skip_tools:
            image = "projectdiscovery/httpx:latest"
            httpx_out = os.path.join(job_base, "output", "httpx.out")
            # prefer the subfinder list if present (it contains hostnames)
            if sub_out and os.path.isfile(sub_out):
                cmd = ["-l", sub_out, "-o", httpx_out]
            elif naabu_out and os.path.isfile(naabu_out):
                cmd = ["-l", naabu_out, "-o", httpx_out]
            else:
                cmd = ["-u", target, "-o", httpx_out]
            rc, logs = run_container_and_stream(image, cmd, stdout_to_file=os.path.join(job_base, "httpx.log"), timeout=1800)
            results["tools"].append({"tool": "httpx", "exit_code": rc, "log": logs, "out_file": httpx_out})
        else:
            httpx_out = None

        # 4) nuclei (use httpx output if present, else subfinder list)
        if "nuclei" not in skip_tools:
            image = "projectdiscovery/nuclei:latest"
            nuclei_out = os.path.join(job_base, "output", "nuclei.out")
            if httpx_out and os.path.isfile(httpx_out):
                cmd = ["-l", httpx_out, "-o", nuclei_out]
            elif sub_out and os.path.isfile(sub_out):
                cmd = ["-l", sub_out, "-o", nuclei_out]
            else:
                cmd = ["-u", target, "-o", nuclei_out]
            rc, logs = run_container_and_stream(image, cmd, stdout_to_file=os.path.join(job_base, "nuclei.log"), timeout=1800)
            results["tools"].append({"tool": "nuclei", "exit_code": rc, "log": logs, "out_file": nuclei_out})
        else:
            nuclei_out = None

        # Generate PDF summary
        summary = {"target": target, "tools": results["tools"]}
        try:
            pdf_path = generate_pdf_report(job_base, target, summary)
        except Exception as e:
            # continue but note PDF generation failed
            pdf_path = None
            results.setdefault("warnings", []).append(f"PDF generation failed: {e}")

        return JSONResponse({
            "job_id": os.path.basename(job_base),
            "out_dir": job_base,
            "tools": results["tools"],
            "report": pdf_path
        })

    except Exception as e:
        # best-effort snippet
        snippet = ""
        try:
            # look for any logs in the job output dir
            for fname in ("subfinder.log","naabu.log","httpx.log","nuclei.log"):
                p = os.path.join(job_base, fname)
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                        snippet = fh.read()[-2000:]
                        break
        except Exception:
            snippet = ""
        return JSONResponse({"error": str(e), "log_snippet": snippet}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.get("/jobs/list/{target}")
async def list_jobs(target: str):
    base = "/data/jobs"
    if not os.path.isdir(base):
        return {"jobs": []}
    out = []
    for name in sorted(os.listdir(base), reverse=True):
        if name.startswith(f"{target}_"):
            path = os.path.join(base, name)
            files = []
            for root, _, fnames in os.walk(path):
                for f in fnames:
                    rel = os.path.relpath(os.path.join(root, f), path)
                    files.append(rel)
            out.append({"job": name, "path": path, "files": files})
    return {"jobs": out}

@app.get("/jobs/file")
async def get_job_file(path: str):
    # Only allow files under /data/jobs
    allowed_root = os.path.abspath("/data/jobs")
    full = os.path.abspath(path)
    if not full.startswith(allowed_root):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="Not found")
    def iterfile():
        with open(full, "rb") as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    break
                yield chunk
    return StreamingResponse(iterfile(), media_type="application/octet-stream")

# ---------- Serve the UI at /app ----------
app.mount("/app", StaticFiles(directory="web", html=True), name="app")

