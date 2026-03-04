/**
 * UCCL eTXT Proxy — Cloudflare Worker
 *
 * SETUP (one-time, ~2 minutes):
 * 1. Go to https://dash.cloudflare.com → Workers & Pages → Create Application → Create Worker
 * 2. Name it: uccl-etxt-proxy
 * 3. Click "Edit code", paste this entire file, click "Deploy"
 * 4. Copy the worker URL (e.g. https://uccl-etxt-proxy.yourname.workers.dev)
 * 5. Paste that URL into the "Worker URL" field in the dashboard SMS config
 *
 * That's it. Free up to 100,000 requests/day.
 */

const ETXT_BASE = 'https://api.etxtservice.co.nz';

// Allow requests from Geotab and local testing
const ALLOWED_ORIGINS = [
  'https://my.geotab.com',
  'http://localhost',
  'null' // local file:// testing
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => (origin || '').startsWith(o))
    ? origin
    : 'https://my.geotab.com';
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '';
    const cors   = corsHeaders(origin);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url  = new URL(request.url);
    const path = url.pathname; // e.g. /api/sms or /api/contacts

    // Only allow eTXT API paths
    if (!path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Invalid path' }), {
        status: 400,
        headers: { ...cors, 'Content-Type': 'application/json' }
      });
    }

    // Forward the request to eTXT
    const targetUrl = ETXT_BASE + path + url.search;

    const forwardHeaders = {
      'Content-Type':  request.headers.get('Content-Type') || 'application/json',
      'Accept':        'application/json',
    };

    // Forward Authorization header
    const auth = request.headers.get('Authorization');
    if (auth) forwardHeaders['Authorization'] = auth;

    const body = request.method !== 'GET' ? await request.text() : undefined;

    const etxtResponse = await fetch(targetUrl, {
      method:  request.method,
      headers: forwardHeaders,
      body:    body,
    });

    const responseText = await etxtResponse.text();

    return new Response(responseText, {
      status:  etxtResponse.status,
      headers: {
        ...cors,
        'Content-Type': etxtResponse.headers.get('Content-Type') || 'application/json',
      }
    });
  }
};
