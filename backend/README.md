# PM::OFFSEC Security Scanner — Backend API

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create .env file
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 4. Run the API
python main.py
# API runs at http://localhost:8000
# Docs at http://localhost:8000/docs
```

## Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | /api/health | Health check |
| GET | /api/scan/local | Scan this machine (live) |
| POST | /api/scan/remote | Scan remote machine via SSH |
| POST | /api/scan/network | Discover all devices on subnet |
| POST | /api/ai/analyze | Full AI security report |
| POST | /api/ai/chat | AI chat about scan results |
| GET | /api/history/{ip} | Scan history for a device |

## Deploy to Railway (Free)

```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

Add environment variable in Railway dashboard:
- ANTHROPIC_API_KEY = your-key-here

## Remote SSH Scanning

To scan another device, that device needs:
1. SSH server running (port 22)
2. Valid credentials (password or key)
3. The user must have permission to read /etc/ssh/sshd_config and /var/log/auth.log

For full scanning (packages, auth logs), root or sudo access is recommended.

## Security Notes

- Never expose this API publicly without authentication
- Use environment variables for all secrets
- The remote scan feature requires SSH credentials — never hardcode these
- Add API key authentication before deploying to production
