const ETXT_BASE = 'https://www.etxtservice.co.nz';

const ALLOWED_ORIGINS = [
  'https://my.geotab.com',
  'http://localhost',
  'null'
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => (origin || '').startsWith(o))
    ? origin
    : 'https://my.geotab.com';
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept',
    'Access-Control-Max-Age':       '86400',
  };
}

export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '';
    const cors   = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Invalid path' }), {
        status: 400,
        headers: { ...cors, 'Content-Type': 'application/json' }
      });
    }

    const targetUrl = ETXT_BASE + path + url.search;

    const contentType = request.headers.get('Content-Type') || 'application/x-www-form-urlencoded';
    const forwardHeaders = {
      'Content-Type': contentType,
      'Accept':       request.headers.get('Accept') || 'application/json',
    };

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
