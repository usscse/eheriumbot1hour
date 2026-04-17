# TSR Data Manager v1.0 Final

TSR Data Manager v1.0 Final is a lightweight Node.js + HTML single-page application for managing TSR records over a local network.

## Files

- `server.js` — network server with file-backed storage, authentication, sessions, SSE, locks, and user admin APIs
- `client.html` — full front-end SPA (data entry, view/search, edit, reports, user admin)
- `start_server.sh` — Linux/macOS startup script
- `START_SERVER.bat` — Windows startup script

## Quick Start

```bash
npm install
npm start
```

Then open: `http://localhost:3000`

## Default Login

- Username: `admin`
- Password: `admin`

Change the admin password after first login.
