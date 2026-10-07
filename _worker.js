// DeepSeek 网页聊天 - Worker 代理 + 反馈系统
function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function verifyTurnstile(token, secret, ip) {
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: token, remoteip: ip || '' }),
    });
    const j = await r.json();
    return !!j.success;
  } catch { return false; }
}

// ---------- 简易登录（用户名1-8字母 + 密码1-10数字，防聊天记录丢失） ----------
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
}
function validUsername(u){ return /^[a-zA-Z]{1,8}$/.test(u); }
function validPassword(p){ return /^[0-9]{1,10}$/.test(p); }
function randToken(){
  const a = new Uint8Array(24);
  crypto.getRandomValues(a);
  return Array.from(a).map(function(b){ return b.toString(36); }).join('').replace(/[^a-z0-9]/gi,'').slice(0,32);
}
async function getUserByToken(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(\S+)$/);
  const token = m ? m[1] : new URL(request.url).searchParams.get('token');
  if (!token || !env.FEEDBACK_KV) return null;
  const username = await env.FEEDBACK_KV.get('sess_' + token);
  return username || null;
}
async function handleAuth(request, env) {
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: false, error: '暂未启用' }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  const action = body.action === 'register' ? 'register' : 'login';
  const username = String(body.username || '').trim();
  const password = String(body.password || '').trim();
  if (!validUsername(username)) return json({ ok: false, error: '用户名为1-8个字母' }, 400);
  if (!validPassword(password)) return json({ ok: false, error: '密码为1-10位数字' }, 400);
  const ukey = 'user_' + username.toLowerCase();
  const passHash = await sha256('ds:' + username.toLowerCase() + ':' + password);
  if (action === 'register') {
    const exists = await kv.get(ukey);
    if (exists) return json({ ok: false, error: '用户名已存在，请直接登录' }, 400);
    await kv.put(ukey, JSON.stringify({ ph: passHash, t: Date.now() }));
  } else {
    const raw = await kv.get(ukey);
    if (!raw) return json({ ok: false, error: '用户不存在，请先注册' }, 400);
    try {
      const u = JSON.parse(raw);
      if (u.ph !== passHash) return json({ ok: false, error: '密码错误' }, 401);
    } catch { return json({ ok: false, error: '账户异常' }, 500); }
  }
  const token = randToken();
  await kv.put('sess_' + token, username.toLowerCase(), { expirationTtl: 30*24*3600 });
  return json({ ok: true, token, username });
}
async function handleHistoryGet(request, env) {
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  const kv = env.FEEDBACK_KV;
  let messages = [];
  try {
    const raw = await kv.get('hist_' + username);
    if (raw) messages = JSON.parse(raw);
  } catch {}
  // 图片消息太占地方，只返回最近30条，且图片转占位
  if (!Array.isArray(messages)) messages = [];
  messages = messages.slice(-30).map(function(m){
    if (Array.isArray(m.content)) {
      return { role: m.role, content: m.content.map(function(p){
        if (p.type === 'image_url') return { type: 'image_url', image_url: { url: '[图片]' } };
        return p;
      })};
    }
    return m;
  });
  return json({ ok: true, messages });
}
async function handleHistorySave(request, env) {
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
  let messages = Array.isArray(body.messages) ? body.messages.slice(-50) : [];
  // 清洗：图片 dataURL 太大，存占位符（历史里不保留原图）
  messages = messages.map(function(m){
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    if (Array.isArray(m.content)) {
      const parts = m.content.map(function(p){
        if (p && p.type === 'image_url') return { type: 'text', text: '[图片]' };
        if (p && p.type === 'text') return { type: 'text', text: String(p.text||'').slice(0,5000) };
        return null;
      }).filter(Boolean);
      return { role, content: parts.length ? parts : [{type:'text',text:'(空)'}] };
    }
    return { role, content: String(m.content||'').slice(0, 8000) };
  });
  await env.FEEDBACK_KV.put('hist_' + username, JSON.stringify(messages));
  return json({ ok: true });
}

// ---------- DeepSeek 聊天代理 ----------

async function handleChat(request, env) {
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '请先登录' }, 401);
  const apiKey = (env.DEEPSEEK_API_KEY || '').trim();
  if (!apiKey) return json({ ok: false, error: '未配置 DeepSeek API Key：请在 Cloudflare Pages → Settings → Environment variables 添加 DEEPSEEK_API_KEY（重新部署后生效）' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  const model = body.model === 'deepseek-v4-pro' ? 'deepseek-v4-pro' : 'deepseek-flash';
  const messages = Array.isArray(body.messages) ? body.messages.slice(-30) : [];
  if (!messages.length || !messages.some(function(m){ return m.role === 'user'; }))
    return json({ ok: false, error: '消息为空' }, 400);
  const clean = messages.map(function(m){
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    if (Array.isArray(m.content)) {
      const parts = [];
      for (const p of m.content) {
        if (!p || typeof p !== 'object') continue;
        if (p.type === 'text') parts.push({ type: 'text', text: String(p.text || '').slice(0, 20000) });
        else if (p.type === 'image_url' && p.image_url && typeof p.image_url.url === 'string') {
          const u = p.image_url.url;
          if (u.startsWith('data:image/') && u.length < 7*1024*1024) parts.push({ type: 'image_url', image_url: { url: u } });
        }
      }
      return { role, content: parts.length ? parts : [{ type: 'text', text: '(空)' }] };
    }
    return { role, content: String(m.content || '').slice(0, 20000) };
  });

  try {
    const r = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({ model, messages: clean, stream: true, thinking: { type: 'enabled' } }),
    });
    if (!r.ok || !r.body) {
      const t = await r.text().catch(function(){ return ''; });
      let msg = 'DeepSeek 接口错误(' + r.status + ')';
      try { const j = JSON.parse(t); if (j.error && j.error.message) msg = j.error.message; } catch {}
      if (r.status === 401) msg = 'API Key 无效，请检查 DEEPSEEK_API_KEY';
      if (r.status === 402) msg = 'DeepSeek 账户余额不足，请去 platform.deepseek.com 充值';
      if (r.status === 429) msg = '请求太频繁，请稍后再试';
      return json({ ok: false, error: msg }, r.status);
    }
    return new Response(r.body, {
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (e) {
    return json({ ok: false, error: '连接 DeepSeek 失败，请稍后重试' }, 502);
  }
}

// ---------- 反馈系统（与其他站共用 KV/R2） ----------
function siteTag(){ return '[DeepSeek站]'; }

async function handleFeedbackSubmit(request, env) {
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: false, error: '反馈功能暂未启用' }, 503);
  // 人机验证
  const tsSecret = (env.TURNSTILE_SECRET_KEY || '').trim();
  let text = '', contact = '', tsToken = '';
  let files = [];
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('multipart/form-data')) {
    const form = await request.formData();
    text = String(form.get('text') || '').slice(0, 2000);
    contact = String(form.get('contact') || '').slice(0, 200);
    tsToken = String(form.get('turnstile') || '');
    for (const f of form.getAll('files')) {
      if (f && typeof f.arrayBuffer === 'function' && f.size > 0) {
        if (f.size > 20*1024*1024) return json({ ok: false, error: '单个文件不能超过20MB' }, 400);
        files.push(f);
      }
    }
    if (files.length > 3) return json({ ok: false, error: '最多上传3个文件' }, 400);
  } else {
    try {
      const j = await request.json();
      text = String(j.text || '').slice(0, 2000);
      contact = String(j.contact || '').slice(0, 200);
      tsToken = String(j.turnstile || '');
    } catch {}
  }
  if (!text.trim()) return json({ ok: false, error: '请填写反馈内容' }, 400);
  if (tsSecret) {
    if (!tsToken) return json({ ok: false, error: '请先完成人机验证' }, 400);
    const ok = await verifyTurnstile(tsToken, tsSecret, request.headers.get('cf-connecting-ip'));
    if (!ok) return json({ ok: false, error: '人机验证未通过，请重试' }, 403);
  }
  // 10分钟冷却
  const ip = request.headers.get('cf-connecting-ip') || '';
  if (ip) {
    const last = await kv.get('cool_' + ip);
    if (last) {
      const remain = 600 - Math.floor((Date.now() - Number(last)) / 1000);
      if (remain > 0) return json({ ok: false, error: '提交太频繁，请 ' + Math.ceil(remain/60) + ' 分钟后再试' }, 429);
    }
  }
  // 存附件到 R2
  const bucket = env.FEEDBACK_BUCKET;
  const fkeys = [];
  if (bucket && files.length) {
    for (const f of files) {
      const key = 'fb/' + Date.now() + '_' + Math.random().toString(36).slice(2,8) + '_' + (f.name || 'file').replace(/[^\w.\-]/g,'_').slice(0,60);
      await bucket.put(key, await f.arrayBuffer(), { httpMetadata: { contentType: f.type || 'application/octet-stream' } });
      fkeys.push({ key, name: f.name || 'file', type: f.type || '' });
    }
  }
  const cf = request.cf || {};
  const item = {
    id: 'fb_' + Date.now() + Math.random().toString(36).slice(2,8),
    site: siteTag(),
    text, contact,
    files: fkeys,
    ip,
    cc: String(cf.country || 'XX').toUpperCase(),
    region: cf.region || '', city: cf.city || '',
    t: Date.now(),
  };
  await kv.put(item.id, JSON.stringify(item), { expirationTtl: 90*24*3600 });
  if (ip) await kv.put('cool_' + ip, String(Date.now()), { expirationTtl: 600 });
  return json({ ok: true });
}

function checkAdminKey(url, env) {
  const key = url.searchParams.get('key') || '';
  const adminKey = (env.FEEDBACK_ADMIN_KEY || '').trim();
  return adminKey && key === adminKey;
}

async function handleFeedbackList(request, env) {
  const url = new URL(request.url);
  if (!checkAdminKey(url, env)) return json({ ok: false, error: '无权访问' }, 403);
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: true, items: [] });
  const list = await kv.list({ prefix: 'fb_' });
  const items = [];
  for (const k of list.keys.slice(0, 100)) {
    try {
      const v = await kv.get(k.name);
      if (v) items.push(JSON.parse(v));
    } catch {}
  }
  items.sort(function(a,b){ return (b.t||0) - (a.t||0); });
  return json({ ok: true, items: items.slice(0, 50) });
}

async function handleFeedbackDelete(request, env) {
  const url = new URL(request.url);
  if (!checkAdminKey(url, env)) return json({ ok: false, error: '无权访问' }, 403);
  const id = url.searchParams.get('id') || '';
  if (!id.startsWith('fb_')) return json({ ok: false, error: '无效ID' }, 400);
  const kv = env.FEEDBACK_KV;
  if (kv) await kv.delete(id);
  return json({ ok: true });
}

async function handleFeedbackFile(request, env) {
  const url = new URL(request.url);
  if (!checkAdminKey(url, env)) return new Response('无权访问', { status: 403 });
  const key = url.pathname.replace('/api/fb-file/', '');
  if (!key.startsWith('fb/')) return new Response('无效', { status: 400 });
  const bucket = env.FEEDBACK_BUCKET;
  if (!bucket) return new Response('未配置', { status: 503 });
  const obj = await bucket.get(key);
  if (!obj) return new Response('不存在', { status: 404 });
  const h = new Headers();
  obj.writeHttpMetadata(h);
  h.set('Cache-Control', 'public, max-age=86400');
  return new Response(obj.body, { headers: h });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/chat' && request.method === 'POST') return handleChat(request, env);
    if (url.pathname === '/api/auth' && request.method === 'POST') return handleAuth(request, env);
    if (url.pathname === '/api/history' && request.method === 'GET') return handleHistoryGet(request, env);
    if (url.pathname === '/api/history' && request.method === 'POST') return handleHistorySave(request, env);
    if (url.pathname === '/api/turnstile-key') {
      return json({ ok: true, siteKey: (env.TURNSTILE_SITE_KEY || '').trim() });
    }
    if (url.pathname === '/api/feedback' && request.method === 'POST') return handleFeedbackSubmit(request, env);
    if (url.pathname === '/api/feedback' && request.method === 'GET') return handleFeedbackList(request, env);
    if (url.pathname === '/api/feedback' && request.method === 'DELETE') return handleFeedbackDelete(request, env);
    if (url.pathname.startsWith('/api/fb-file/')) return handleFeedbackFile(request, env);
    return env.ASSETS.fetch(request);
  },
};
