# Testing Skill for G4ram

A Cyber Security Skill Assessment Platform with 21 challenges across 6 categories.

## Categories
- **WEB** — Flask Session, The Babel Protocol (3 stages)
- **PWN** — OverVaulted, Obsidian VM, KsmbDead
- **REV** — Vietnamese Identity, Custom Hulk, VaultVM 2, The Abyss
- **CRYPTO** — Spectral, Aegis, Meridian, Triple Veil
- **FORENSICS** — The Echoing Void, Rootkit Extraction, Digital Trail
- **MISC** — The Pulse, Hexagonal Veil, Hidden in Plain Sight

## Features
- Three.js animated background
- Register / Login with JWT auth
- Dynamic scoring (points decay as more players solve)
- Hint system with point cost (50–450 pts depending on difficulty)
- Live scoreboard
- Per-user solve tracking and progress

## Deploy on Render.com
1. Push this repo to GitHub
2. Go to render.com → New → Web Service
3. Connect the repo — Render auto-detects `render.yaml`
4. Click **Deploy**

Or manually:
- Build: `npm install --ignore-scripts`
- Start: `node src/server.js`
- Add env var `JWT_SECRET` (any random string)
- Add a **Disk** mounted at `/opt/render/project/src/data`

## Local Dev
```bash
npm install --ignore-scripts
node src/server.js
# open http://localhost:3000
```
