# UCCL eTXT Proxy — Cloudflare Worker

Proxies eTXT SMS API calls from the UCCL Asset Inspection Dashboard, resolving the CORS restriction that blocks direct calls from `my.geotab.com`.

## Deploy via GitHub + Cloudflare

1. Push this repo to GitHub
2. In Cloudflare dashboard → **Workers & Pages** → **Create application**
3. Connect your GitHub account and select this repo
4. Click **Deploy**
5. Copy the worker URL (e.g. `https://uccl-etxt-proxy.yourname.workers.dev`)
6. Paste that URL into the **Cloudflare Worker URL** field in the dashboard SMS config

## Endpoints proxied

- `POST /api/sms` — send SMS
- `GET /api/contacts` — fetch contacts

All requests are forwarded to `https://api.etxtservice.co.nz` with your eTXT credentials passed through as a Basic Auth header from the dashboard.
