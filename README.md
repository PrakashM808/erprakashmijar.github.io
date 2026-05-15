# erprakashmijar.com — Complete Portfolio + Security Dashboard

## Project Structure
```
/
├── index.html              Homepage dashboard
├── projects.html           Projects & case studies
├── labs.html               Labs & platforms
├── skills.html             Offensive security skill stack
├── about.html              About & contact
├── roadmap.html            Ethical hacking roadmap (interactive)
├── vibe-stack.html         Vibe coding stack 2026
├── login.html              ← LOGIN PAGE (new)
├── register.html           ← REGISTER PAGE (new)
├── dashboard/
│   └── index.html          ← SECURITY DASHBOARD (new)
├── projects/
│   └── wannacry.html       WannaCry case study
├── assets/
│   ├── style.css           Shared portfolio styles
│   ├── home.css            Homepage-only styles
│   ├── shared.js           Canvas, cursor, nav, scroll reveal
│   ├── auth.css            Login/register styles
│   ├── auth.js             ← AUTH SYSTEM (new)
│   └── Prakash_Mijar_CV.pdf  ← ADD YOUR CV HERE
├── favicon.svg
├── og-image.png
├── .htaccess               Apache: HTTPS, caching, security headers
├── robots.txt
└── sitemap.xml
```

## Auth System
- **Register**: `/register.html` — full form with password strength meter & requirements checklist
- **Login**: `/login.html` — email/password + one-click demo roles
- **Sessions**: stored in localStorage (browser-side, no server needed)
- **Roles**: admin / client / user — each sees different sidebar sections
- **Demo accounts**:
  - Admin: `admin@erprakashmijar.com` / `Admin@2026`
  - Client: `client@demo.com` / `Client@123`

## Security Dashboard Features
- System Scanner (simulated — connect to real FastAPI backend to scan live systems)
- Security score gauge + trend chart
- Open ports, SSH config, outdated packages, file permissions
- Alert system with dismiss
- AI Analysis (Claude API — powered by Claude claude-sonnet-4-20250514)
- AI Chat assistant — ask about any vulnerability
- Report export (TXT + JSON download)
- Admin panel (user list, task tracker)
- Profile editor
- Role-based views (admin/client/user)

## Deploy (cPanel / Hostinger / Namecheap)
1. Upload contents of this folder to `public_html/`
2. Make sure `.htaccess` is uploaded (may be hidden — enable "Show Hidden Files")
3. Add your CV as `assets/Prakash_Mijar_CV.pdf`
4. Set up email: Zoho Mail (free) or Namecheap email forwarding

## Deploy (GitHub Pages)
1. Push to repo `prakashm808.github.io`
2. Settings → Pages → Source: main, root /
3. Note: `.htaccess` doesn't work on GitHub Pages — use Cloudflare Pages instead for HTTPS redirect

## DNS (GitHub Pages)
```
A     @     185.199.108.153
A     @     185.199.109.153
A     @     185.199.110.153
A     @     185.199.111.153
CNAME www   prakashm808.github.io
```

## TODO Before Going Live
- [ ] Drop `assets/Prakash_Mijar_CV.pdf` into assets/
- [ ] Update GitHub links (search `github.com/` in all HTML)
- [ ] Update LinkedIn links (search `linkedin.com/in/`)
- [ ] Add TryHackMe / HTB rank in `labs.html`
- [ ] Set up domain email (Zoho free or Namecheap forwarding)
- [ ] For real scanning: build FastAPI backend + connect to dashboard

## Making the Scanner Real (Phase 2)
The scanner currently uses mock data. To connect to a real Linux system:
1. Build `backend/main.py` with FastAPI
2. Use `subprocess`, `psutil`, `socket` to collect real data
3. Expose `/api/scan` endpoint
4. Replace `mockScan()` in `dashboard/index.html` with a fetch to your API
