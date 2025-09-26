# Bug Bounty AIO

Single service that will grow into an end-to-end bug bounty recon + reporting tool.

## Run locally with Docker
```bash
docker compose up -d --build
curl http://localhost:8080/health

## Quick Start (Tool Pack A)

1) Build & run (Docker/Portainer stack):
   - Make sure port 8080 is free.
   - Deploy the stack or rebuild the image in Portainer after pulling latest from GitHub.

2) Health check:
   - GET http://<host>:8080/health

3) Recon:
   - POST http://<host>:8080/recon
   - Body:
     {
       "domain": "example.com",
       "top_ports": 50,
       "alive_timeout_ms": 2000
     }

Returns JSON with: whois summary, apex A-records, fast open port probe, subdomains (Sublist3r), DNS for subs, and alive endpoints.
