⸻


# VortexHub AI Container

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/your-org/vortexhub-container)

![VortexHub Container Preview](https://imagedelivery.net/_yJ02hpOMj_EnGvsU2aygw/5aba1fb7-b937-46fd-fa67-138221082200/public)

---

This repository contains a **Container-based AI service** for VortexHub.  
It demonstrates:

- Static Go binary container with AI logic
- Secure endpoints (`/loader`, `/secure-data`)
- HTML/Loader interface for web fetch
- Config and cloud storage integration
- Flexible multi-port access for multiple clients
- CI/CD pipeline ready for automated build & deploy

---

## Getting Started

### 1. Install dependencies

```bash
npm install
# or
yarn install
# or
pnpm install
# or
bun install

2. Run development server

npm run dev

Open http://localhost:8787￼ to see the loader interface.

3. Folder structure

vortexhub-container/
│
├─ container_src/       # Go source code for AI container
│   ├─ main.go
│   ├─ secure_endpoints.py
│   └─ go.mod / go.sum
│
├─ server_src/
│   ├─ static/          # HTML/Loader files
│   └─ config/          # Config, secure JSON, cloud integration
│
├─ Dockerfile
├─ package.json / tsconfig.json
└─ .github/workflows/   # CI/CD pipelines

4. Running the Container

Build and run locally (multi-port support):

docker build -t vortexhub-container:latest .
docker run --rm -d -p 8080-8090:8080-8090 vortexhub-container:latest

You can access:
	•	http://localhost:8080/loader → Loader HTML
	•	http://localhost:8080/secure-data → Secure JSON endpoints

⸻

Deploying to Cloudflare

Command	Action
npm run deploy	Deploy AI container to Cloudflare

Ensure all secure keys and cloud configs are in /server_src/config and never commit secrets directly to repo. Use GitHub Secrets or Vaults.

⸻

CI/CD Integration

The GitHub Actions workflow builds, tests, and pushes the container to GHCR:
	•	Uses Go 1.24 and Alpine builder
	•	Copies static HTML/Loader & secure configs
	•	Builds a static Go binary
	•	Exposes multi-ports for fetch and embed
	•	Runs a quick local curl test on all ports

⸻

Secure Endpoints

/secure-data provides:
	•	API keys & JWT tokens
	•	UUIDs and IPFS/Pinata info
	•	Cloud storage references (RClone, Koofr)
	•	Other Telegram bots and secure links

Fetch example:

import requests

response = requests.get("http://localhost:8080/secure-data")
data = response.json()

api_key = data["api_keys"][0]["key"]
secret = data["api_keys"][0]["secret"]


⸻

Notes
	•	All AI logic runs inside /server Go binary
	•	Static HTML/Loader in /app/static
	•	Config files in /app/config for cloud integration
	•	Multi-port exposed: 8080-8090 for flexible client fetch
	•	Secure endpoints are JSON only, never execute secrets in client code
	•	Ready for pipeline deployment without manual update

⸻

Resources
	•	Cloudflare Containers Docs￼
	•	VortexHub Orchestrator￼
	•	Cloudflare C3 CLI￼

---
