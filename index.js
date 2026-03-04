const ETXT_BASE = 'https://api.etxtservice.co.nz';
const API_KEY    = '98iipsmdd6huv45D6G6V';
const API_SECRET = 'qYK8GKUWXuZBCGbDAyOpusMO0qpjHv';

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
  // base64 encode
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function md5Base64Hex(body) {
  // MD5 not available in Web Crypto — use a simple JS implementation
  // We only need it for Content-MD5 header
  const msgBuffer = new TextEncoder().encode(body);
  // Cloudflare Workers support MD5 via the non-standard crypto.subtle with MD5
  // Fall back: compute via a small pure-JS md5
  return md5(body);
}

// Minimal pure-JS MD5 (RFC 1321)
function md5(str) {
  function safeAdd(x, y) { const lsw = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xFFFF); }
  function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
  function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
  function md5ff(a, b, c, d, x, s, t) { return md5cmn((b & c) | (~b & d), a, b, x, s, t); }
  function md5gg(a, b, c, d, x, s, t) { return md5cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function md5hh(a, b, c, d, x, s, t) { return md5cmn(b ^ c ^ d, a, b, x, s, t); }
  function md5ii(a, b, c, d, x, s, t) { return md5cmn(c ^ (b | ~d), a, b, x, s, t); }
  const utf8 = unescape(encodeURIComponent(str));
  const bArr = [];
  for (let i = 0; i < utf8.length; i++) bArr.push(utf8.charCodeAt(i));
  bArr.push(128);
  while (bArr.length % 64 !== 56) bArr.push(0);
  const bitLen = utf8.length * 8;
  bArr.push(bitLen & 0xFF, (bitLen >> 8) & 0xFF, (bitLen >> 16) & 0xFF, (bitLen >> 24) & 0xFF, 0, 0, 0, 0);
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < bArr.length; i += 64) {
    const M = [];
    for (let j = 0; j < 16; j++) M[j] = bArr[i+j*4] | (bArr[i+j*4+1] << 8) | (bArr[i+j*4+2] << 16) | (bArr[i+j*4+3] << 24);
    let [aa, bb, cc, dd] = [a, b, c, d];
    a=md5ff(a,b,c,d,M[0],7,-680876936);d=md5ff(d,a,b,c,M[1],12,-389564586);c=md5ff(c,d,a,b,M[2],17,606105819);b=md5ff(b,c,d,a,M[3],22,-1044525330);
    a=md5ff(a,b,c,d,M[4],7,-176418897);d=md5ff(d,a,b,c,M[5],12,1200080426);c=md5ff(c,d,a,b,M[6],17,-1473231341);b=md5ff(b,c,d,a,M[7],22,-45705983);
    a=md5ff(a,b,c,d,M[8],7,1770035416);d=md5ff(d,a,b,c,M[9],12,-1958414417);c=md5ff(c,d,a,b,M[10],17,-42063);b=md5ff(b,c,d,a,M[11],22,-1990404162);
    a=md5ff(a,b,c,d,M[12],7,1804603682);d=md5ff(d,a,b,c,M[13],12,-40341101);c=md5ff(c,d,a,b,M[14],17,-1502002290);b=md5ff(b,c,d,a,M[15],22,1236535329);
    a=md5gg(a,b,c,d,M[1],5,-165796510);d=md5gg(d,a,b,c,M[6],9,-1069501632);c=md5gg(c,d,a,b,M[11],14,643717713);b=md5gg(b,c,d,a,M[0],20,-373897302);
    a=md5gg(a,b,c,d,M[5],5,-701558691);d=md5gg(d,a,b,c,M[10],9,38016083);c=md5gg(c,d,a,b,M[15],14,-660478335);b=md5gg(b,c,d,a,M[4],20,-405537848);
    a=md5gg(a,b,c,d,M[9],5,568446438);d=md5gg(d,a,b,c,M[14],9,-1019803690);c=md5gg(c,d,a,b,M[3],14,-187363961);b=md5gg(b,c,d,a,M[8],20,1163531501);
    a=md5gg(a,b,c,d,M[13],5,-1444681467);d=md5gg(d,a,b,c,M[2],9,-51403784);c=md5gg(c,d,a,b,M[7],14,1735328473);b=md5gg(b,c,d,a,M[12],20,-1926607734);
    a=md5hh(a,b,c,d,M[5],4,-378558);d=md5hh(d,a,b,c,M[8],11,-2022574463);c=md5hh(c,d,a,b,M[11],16,1839030562);b=md5hh(b,c,d,a,M[14],23,-35309556);
    a=md5hh(a,b,c,d,M[1],4,-1530992060);d=md5hh(d,a,b,c,M[4],11,1272893353);c=md5hh(c,d,a,b,M[7],16,-155497632);b=md5hh(b,c,d,a,M[10],23,-1094730640);
    a=md5hh(a,b,c,d,M[13],4,681279174);d=md5hh(d,a,b,c,M[0],11,-358537222);c=md5hh(c,d,a,b,M[3],16,-722521979);b=md5hh(b,c,d,a,M[6],23,76029189);
    a=md5hh(a,b,c,d,M[9],4,-640364487);d=md5hh(d,a,b,c,M[12],11,-421815835);c=md5hh(c,d,a,b,M[15],16,530742520);b=md5hh(b,c,d,a,M[2],23,-995338651);
    a=md5ii(a,b,c,d,M[0],6,-198630844);d=md5ii(d,a,b,c,M[7],10,1126891415);c=md5ii(c,d,a,b,M[14],15,-1416354905);b=md5ii(b,c,d,a,M[5],21,-57434055);
    a=md5ii(a,b,c,d,M[12],6,1700485571);d=md5ii(d,a,b,c,M[3],10,-1894986606);c=md5ii(c,d,a,b,M[10],15,-1051523);b=md5ii(b,c,d,a,M[1],21,-2054922799);
    a=md5ii(a,b,c,d,M[8],6,1873313359);d=md5ii(d,a,b,c,M[15],10,-30611744);c=md5ii(c,d,a,b,M[6],15,-1560198380);b=md5ii(b,c,d,a,M[13],21,1309151649);
    a=md5ii(a,b,c,d,M[4],6,-145523070);d=md5ii(d,a,b,c,M[11],10,-1120210379);c=md5ii(c,d,a,b,M[2],15,718787259);b=md5ii(b,c,d,a,M[9],21,-343485551);
    a=safeAdd(a,aa);b=safeAdd(b,bb);c=safeAdd(c,cc);d=safeAdd(d,dd);
  }
  const hex = [a,b,c,d].map(n => {
    let s=''; for(let i=0;i<4;i++) s+=('0'+(( n>>(i*8))&0xFF).toString(16)).slice(-2); return s;
  }).join('');
  // Convert hex to base64
  const bytes = [];
  for(let i=0;i<hex.length;i+=2) bytes.push(parseInt(hex.substr(i,2),16));
  return btoa(String.fromCharCode(...bytes));
}

async function buildHmacAuth(method, path, body) {
  const date = new Date().toUTCString();
  let signingString, authHeaders;

  if (body) {
    const contentMd5 = md5(body); // hex string — need raw hex for Content-MD5
    const contentMd5Header = hexToBase64(contentMd5Raw(body));
    signingString = `Date: ${date}\nContent-MD5: ${contentMd5Header}\n${method} ${path} HTTP/1.1`;
    authHeaders = `Date Content-MD5 request-line`;
    const sig = await hmacSha1Base64(API_SECRET, signingString);
    return { date, contentMd5: contentMd5Header, authHeader: `hmac username="${API_KEY}", algorithm="hmac-sha1", headers="${authHeaders}", signature="${sig}"` };
  } else {
    signingString = `Date: ${date}\n${method} ${path} HTTP/1.1`;
    authHeaders = `Date request-line`;
    const sig = await hmacSha1Base64(API_SECRET, signingString);
    return { date, authHeader: `hmac username="${API_KEY}", algorithm="hmac-sha1", headers="${authHeaders}", signature="${sig}"` };
  }
}

function hexToBase64(hexStr) {
  const bytes = [];
  for(let i=0;i<hexStr.length;i+=2) bytes.push(parseInt(hexStr.substr(i,2),16));
  return btoa(String.fromCharCode(...bytes));
}

function contentMd5Raw(str) {
  // Returns raw hex MD5
  function safeAdd(x,y){const lsw=(x&0xFFFF)+(y&0xFFFF);return(((x>>16)+(y>>16)+(lsw>>16))<<16)|(lsw&0xFFFF);}
  function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
  function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
  function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|(~b&d),a,b,x,s,t);}
  function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&~d),a,b,x,s,t);}
  function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
  function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|~d),a,b,x,s,t);}
  const utf8=unescape(encodeURIComponent(str));
  const bArr=[];
  for(let i=0;i<utf8.length;i++)bArr.push(utf8.charCodeAt(i));
  bArr.push(128);
  while(bArr.length%64!==56)bArr.push(0);
  const bitLen=utf8.length*8;
  bArr.push(bitLen&0xFF,(bitLen>>8)&0xFF,(bitLen>>16)&0xFF,(bitLen>>24)&0xFF,0,0,0,0);
  let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for(let i=0;i<bArr.length;i+=64){
    const M=[];
    for(let j=0;j<16;j++)M[j]=bArr[i+j*4]|(bArr[i+j*4+1]<<8)|(bArr[i+j*4+2]<<16)|(bArr[i+j*4+3]<<24);
    let[aa,bb,cc,dd]=[a,b,c,d];
    a=md5ff(a,b,c,d,M[0],7,-680876936);d=md5ff(d,a,b,c,M[1],12,-389564586);c=md5ff(c,d,a,b,M[2],17,606105819);b=md5ff(b,c,d,a,M[3],22,-1044525330);
    a=md5ff(a,b,c,d,M[4],7,-176418897);d=md5ff(d,a,b,c,M[5],12,1200080426);c=md5ff(c,d,a,b,M[6],17,-1473231341);b=md5ff(b,c,d,a,M[7],22,-45705983);
    a=md5ff(a,b,c,d,M[8],7,1770035416);d=md5ff(d,a,b,c,M[9],12,-1958414417);c=md5ff(c,d,a,b,M[10],17,-42063);b=md5ff(b,c,d,a,M[11],22,-1990404162);
    a=md5ff(a,b,c,d,M[12],7,1804603682);d=md5ff(d,a,b,c,M[13],12,-40341101);c=md5ff(c,d,a,b,M[14],17,-1502002290);b=md5ff(b,c,d,a,M[15],22,1236535329);
    a=md5gg(a,b,c,d,M[1],5,-165796510);d=md5gg(d,a,b,c,M[6],9,-1069501632);c=md5gg(c,d,a,b,M[11],14,643717713);b=md5gg(b,c,d,a,M[0],20,-373897302);
    a=md5gg(a,b,c,d,M[5],5,-701558691);d=md5gg(d,a,b,c,M[10],9,38016083);c=md5gg(c,d,a,b,M[15],14,-660478335);b=md5gg(b,c,d,a,M[4],20,-405537848);
    a=md5gg(a,b,c,d,M[9],5,568446438);d=md5gg(d,a,b,c,M[14],9,-1019803690);c=md5gg(c,d,a,b,M[3],14,-187363961);b=md5gg(b,c,d,a,M[8],20,1163531501);
    a=md5gg(a,b,c,d,M[13],5,-1444681467);d=md5gg(d,a,b,c,M[2],9,-51403784);c=md5gg(c,d,a,b,M[7],14,1735328473);b=md5gg(b,c,d,a,M[12],20,-1926607734);
    a=md5hh(a,b,c,d,M[5],4,-378558);d=md5hh(d,a,b,c,M[8],11,-2022574463);c=md5hh(c,d,a,b,M[11],16,1839030562);b=md5hh(b,c,d,a,M[14],23,-35309556);
    a=md5hh(a,b,c,d,M[1],4,-1530992060);d=md5hh(d,a,b,c,M[4],11,1272893353);c=md5hh(c,d,a,b,M[7],16,-155497632);b=md5hh(b,c,d,a,M[10],23,-1094730640);
    a=md5hh(a,b,c,d,M[13],4,681279174);d=md5hh(d,a,b,c,M[0],11,-358537222);c=md5hh(c,d,a,b,M[3],16,-722521979);b=md5hh(b,c,d,a,M[6],23,76029189);
    a=md5hh(a,b,c,d,M[9],4,-640364487);d=md5hh(d,a,b,c,M[12],11,-421815835);c=md5hh(c,d,a,b,M[15],16,530742520);b=md5hh(b,c,d,a,M[2],23,-995338651);
    a=md5ii(a,b,c,d,M[0],6,-198630844);d=md5ii(d,a,b,c,M[7],10,1126891415);c=md5ii(c,d,a,b,M[14],15,-1416354905);b=md5ii(b,c,d,a,M[5],21,-57434055);
    a=md5ii(a,b,c,d,M[12],6,1700485571);d=md5ii(d,a,b,c,M[3],10,-1894986606);c=md5ii(c,d,a,b,M[10],15,-1051523);b=md5ii(b,c,d,a,M[1],21,-2054922799);
    a=md5ii(a,b,c,d,M[8],6,1873313359);d=md5ii(d,a,b,c,M[15],10,-30611744);c=md5ii(c,d,a,b,M[6],15,-1560198380);b=md5ii(b,c,d,a,M[13],21,1309151649);
    a=md5ii(a,b,c,d,M[4],6,-145523070);d=md5ii(d,a,b,c,M[11],10,-1120210379);c=md5ii(c,d,a,b,M[2],15,718787259);b=md5ii(b,c,d,a,M[9],21,-343485551);
    a=safeAdd(a,aa);b=safeAdd(b,bb);c=safeAdd(c,cc);d=safeAdd(d,dd);
  }
  return [a,b,c,d].map(n=>{let s='';for(let i=0;i<4;i++)s+=('0'+((n>>(i*8))&0xFF).toString(16)).slice(-2);return s;}).join('');
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

    const bodyText = request.method !== 'GET' ? await request.text() : null;
    const { date, contentMd5, authHeader } = await buildHmacAuth(request.method, path, bodyText);

    const forwardHeaders = {
      'Authorization': authHeader,
      'Date':          date,
      'Accept':        'application/json',
      'Host':          'api.etxtservice.co.nz',
    };

    if (bodyText) {
      forwardHeaders['Content-Type']  = request.headers.get('Content-Type') || 'application/json';
      forwardHeaders['Content-MD5']   = contentMd5;
      forwardHeaders['Content-Length'] = new TextEncoder().encode(bodyText).length.toString();
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
