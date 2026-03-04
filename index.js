const ETXT_BASE  = 'https://api.etxtservice.co.nz';
const API_KEY    = 'enXekb2bisbT0H57JniG';
const API_SECRET = 'R9cFJ4oJxaWjlfbkGKDpzRi89s5r6k';

const ALLOWED_ORIGINS = [
  'https://my.geotab.com',
  'http://localhost',
  'null'
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => (origin || '').startsWith(o))
    ? origin : 'https://my.geotab.com';
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age':       '86400',
  };
}

async function hmacSha1Base64(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// Returns lowercase hex MD5 string — matches eTXT spec Content-MD5 format
function md5hex(str) {
  function safeAdd(x, y) { const l=(x&0xFFFF)+(y&0xFFFF); return(((x>>16)+(y>>16)+(l>>16))<<16)|(l&0xFFFF); }
  function rotL(n, c) { return (n << c) | (n >>> (32 - c)); }
  function core(q, a, b, x, shift, t) { return safeAdd(rotL(safeAdd(safeAdd(a,q),safeAdd(x,t)),shift),b); }
  function ff(a,b,c,d,x,s,t){return core((b&c)|(~b&d),a,b,x,s,t);}
  function gg(a,b,c,d,x,s,t){return core((b&d)|(c&~d),a,b,x,s,t);}
  function hh(a,b,c,d,x,s,t){return core(b^c^d,a,b,x,s,t);}
  function ii(a,b,c,d,x,s,t){return core(c^(b|~d),a,b,x,s,t);}
  const utf8 = unescape(encodeURIComponent(str));
  const bytes = [];
  for (let i = 0; i < utf8.length; i++) bytes.push(utf8.charCodeAt(i));
  bytes.push(128);
  while (bytes.length % 64 !== 56) bytes.push(0);
  const bitLen = utf8.length * 8;
  bytes.push(bitLen&0xFF,(bitLen>>8)&0xFF,(bitLen>>16)&0xFF,(bitLen>>24)&0xFF,0,0,0,0);
  let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for (let i = 0; i < bytes.length; i += 64) {
    const m = [];
    for (let j = 0; j < 16; j++)
      m[j] = bytes[i+j*4]|(bytes[i+j*4+1]<<8)|(bytes[i+j*4+2]<<16)|(bytes[i+j*4+3]<<24);
    const [aa,bb,cc,dd] = [a,b,c,d];
    a=ff(a,b,c,d,m[0],7,-680876936);   d=ff(d,a,b,c,m[1],12,-389564586);  c=ff(c,d,a,b,m[2],17,606105819);    b=ff(b,c,d,a,m[3],22,-1044525330);
    a=ff(a,b,c,d,m[4],7,-176418897);   d=ff(d,a,b,c,m[5],12,1200080426);  c=ff(c,d,a,b,m[6],17,-1473231341);  b=ff(b,c,d,a,m[7],22,-45705983);
    a=ff(a,b,c,d,m[8],7,1770035416);   d=ff(d,a,b,c,m[9],12,-1958414417); c=ff(c,d,a,b,m[10],17,-42063);      b=ff(b,c,d,a,m[11],22,-1990404162);
    a=ff(a,b,c,d,m[12],7,1804603682);  d=ff(d,a,b,c,m[13],12,-40341101);  c=ff(c,d,a,b,m[14],17,-1502002290); b=ff(b,c,d,a,m[15],22,1236535329);
    a=gg(a,b,c,d,m[1],5,-165796510);   d=gg(d,a,b,c,m[6],9,-1069501632);  c=gg(c,d,a,b,m[11],14,643717713);   b=gg(b,c,d,a,m[0],20,-373897302);
    a=gg(a,b,c,d,m[5],5,-701558691);   d=gg(d,a,b,c,m[10],9,38016083);    c=gg(c,d,a,b,m[15],14,-660478335);  b=gg(b,c,d,a,m[4],20,-405537848);
    a=gg(a,b,c,d,m[9],5,568446438);    d=gg(d,a,b,c,m[14],9,-1019803690); c=gg(c,d,a,b,m[3],14,-187363961);   b=gg(b,c,d,a,m[8],20,1163531501);
    a=gg(a,b,c,d,m[13],5,-1444681467); d=gg(d,a,b,c,m[2],9,-51403784);    c=gg(c,d,a,b,m[7],14,1735328473);   b=gg(b,c,d,a,m[12],20,-1926607734);
    a=hh(a,b,c,d,m[5],4,-378558);      d=hh(d,a,b,c,m[8],11,-2022574463); c=hh(c,d,a,b,m[11],16,1839030562);  b=hh(b,c,d,a,m[14],23,-35309556);
    a=hh(a,b,c,d,m[1],4,-1530992060);  d=hh(d,a,b,c,m[4],11,1272893353);  c=hh(c,d,a,b,m[7],16,-155497632);   b=hh(b,c,d,a,m[10],23,-1094730640);
    a=hh(a,b,c,d,m[13],4,681279174);   d=hh(d,a,b,c,m[0],11,-358537222);  c=hh(c,d,a,b,m[3],16,-722521979);   b=hh(b,c,d,a,m[6],23,76029189);
    a=hh(a,b,c,d,m[9],4,-640364487);   d=hh(d,a,b,c,m[12],11,-421815835); c=hh(c,d,a,b,m[15],16,530742520);   b=hh(b,c,d,a,m[2],23,-995338651);
    a=ii(a,b,c,d,m[0],6,-198630844);   d=ii(d,a,b,c,m[7],10,1126891415);  c=ii(c,d,a,b,m[14],15,-1416354905); b=ii(b,c,d,a,m[5],21,-57434055);
    a=ii(a,b,c,d,m[12],6,1700485571);  d=ii(d,a,b,c,m[3],10,-1894986606); c=ii(c,d,a,b,m[10],15,-1051523);    b=ii(b,c,d,a,m[1],21,-2054922799);
    a=ii(a,b,c,d,m[8],6,1873313359);   d=ii(d,a,b,c,m[15],10,-30611744);  c=ii(c,d,a,b,m[6],15,-1560198380);  b=ii(b,c,d,a,m[13],21,1309151649);
    a=ii(a,b,c,d,m[4],6,-145523070);   d=ii(d,a,b,c,m[11],10,-1120210379);c=ii(c,d,a,b,m[2],15,718787259);    b=ii(b,c,d,a,m[9],21,-343485551);
    a=safeAdd(a,aa); b=safeAdd(b,bb); c=safeAdd(c,cc); d=safeAdd(d,dd);
  }
  return [a,b,c,d].map(n => {
    let h = '';
    for (let i = 0; i < 4; i++) h += ('0' + ((n >> (i*8)) & 0xFF).toString(16)).slice(-2);
    return h;
  }).join('');
}

async function buildHmacAuth(method, path, bodyText) {
  const date = new Date().toUTCString();
  let signingString, authHeaderValue, contentMd5;

  if (bodyText) {
    // Content-MD5 is hex per eTXT spec example: "5407644fa83bec240dede971307e0cad"
    contentMd5 = md5hex(bodyText);
    signingString = `Date: ${date}\nContent-MD5: ${contentMd5}\n${method} ${path} HTTP/1.1`;
    const sig = await hmacSha1Base64(API_SECRET, signingString);
    authHeaderValue = `hmac username="${API_KEY}", algorithm="hmac-sha1", headers="Date Content-MD5 request-line", signature="${sig}"`;
  } else {
    signingString = `Date: ${date}\n${method} ${path} HTTP/1.1`;
    const sig = await hmacSha1Base64(API_SECRET, signingString);
    authHeaderValue = `hmac username="${API_KEY}", algorithm="hmac-sha1", headers="Date request-line", signature="${sig}"`;
  }

  return { date, contentMd5, authHeaderValue };
}

export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith('/v1/') && !path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Invalid path' }), {
        status: 400, headers: { ...cors, 'Content-Type': 'application/json' }
      });
    }

    const bodyText = (request.method !== 'GET' && request.method !== 'HEAD')
      ? await request.text() : null;

    const { date, contentMd5, authHeaderValue } = await buildHmacAuth(
      request.method, path, bodyText
    );

    const forwardHeaders = {
      'Authorization': authHeaderValue,
      'Date':          date,
      'Accept':        'application/json',
      'Host':          'api.etxtservice.co.nz',
    };

    if (bodyText) {
      forwardHeaders['Content-Type']    = request.headers.get('Content-Type') || 'application/json';
      forwardHeaders['Content-MD5']     = contentMd5;
      forwardHeaders['Content-Length']  = new TextEncoder().encode(bodyText).length.toString();
    }

    const targetUrl = `${ETXT_BASE}${path}${url.search}`;
    const etxtResponse = await fetch(targetUrl, {
      method:  request.method,
      headers: forwardHeaders,
      body:    bodyText || undefined,
    });

    const responseText = await etxtResponse.text();
    return new Response(responseText, {
      status: etxtResponse.status,
      headers: {
        ...cors,
        'Content-Type': etxtResponse.headers.get('Content-Type') || 'application/json',
      }
    });
  }
};
