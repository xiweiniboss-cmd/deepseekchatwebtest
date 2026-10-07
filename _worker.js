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
    const regIp = request.headers.get('cf-connecting-ip') || '';
    await kv.put(ukey, JSON.stringify({ ph: passHash, t: Date.now(), ip: regIp }));
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
// ---------- 多会话历史 ----------
function convId(){ return Date.now().toString(36) + Math.random().toString(36).slice(2,7); }
function cleanMessages(messages){
  messages = Array.isArray(messages) ? messages.slice(-60) : [];
  return messages.map(function(m){
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
}
// 兼容旧版单会话：迁移到新格式
async function migrateOldHist(kv, username){
  try {
    const old = await kv.get('hist_' + username);
    if (!old) return;
    const msgs = JSON.parse(old);
    if (!Array.isArray(msgs) || !msgs.length) { await kv.delete('hist_' + username); return; }
    const id = convId();
    const firstUser = msgs.find(function(m){ return m.role === 'user'; });
    let title = '旧对话';
    if (firstUser) {
      const t = Array.isArray(firstUser.content) ? (firstUser.content.find(function(p){return p.type==='text';})||{}).text : firstUser.content;
      title = String(t||'旧对话').slice(0,20) || '旧对话';
    }
    await kv.put('conv_' + username + '_' + id, JSON.stringify(cleanMessages(msgs)));
    await kv.put('convs_' + username, JSON.stringify([{ id, title, t: Date.now() }]));
    await kv.delete('hist_' + username);
  } catch(e){}
}
async function handleConvsList(request, env){
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  const kv = env.FEEDBACK_KV;
  await migrateOldHist(kv, username);
  let list = [];
  try { const raw = await kv.get('convs_' + username); if (raw) list = JSON.parse(raw); } catch(e){}
  if (!Array.isArray(list)) list = [];
  list.sort(function(a,b){ return (b.t||0)-(a.t||0); });
  return json({ ok: true, convs: list.slice(0,50) });
}
async function handleConvGet(request, env){
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  const id = new URL(request.url).searchParams.get('id') || '';
  if (!/^[a-z0-9]{5,20}$/.test(id)) return json({ ok: false, error: '参数错误' }, 400);
  let messages = [];
  try { const raw = await env.FEEDBACK_KV.get('conv_' + username + '_' + id); if (raw) messages = JSON.parse(raw); } catch(e){}
  return json({ ok: true, messages: Array.isArray(messages) ? messages : [] });
}
async function handleConvSave(request, env){
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
  const kv = env.FEEDBACK_KV;
  let id = String(body.id || '');
  if (!/^[a-z0-9]{5,20}$/.test(id)) id = convId();
  const messages = cleanMessages(body.messages);
  if (!messages.length) return json({ ok: true, id });
  let title = String(body.title || '').slice(0,30);
  if (!title) {
    const firstUser = messages.find(function(m){ return m.role === 'user'; });
    if (firstUser) {
      const t = Array.isArray(firstUser.content) ? (firstUser.content.find(function(p){return p.type==='text';})||{}).text : firstUser.content;
      title = String(t||'新对话').replace(/\n/g,' ').slice(0,20) || '新对话';
    } else title = '新对话';
  }
  await kv.put('conv_' + username + '_' + id, JSON.stringify(messages));
  let list = [];
  try { const raw = await kv.get('convs_' + username); if (raw) list = JSON.parse(raw); } catch(e){}
  if (!Array.isArray(list)) list = [];
  list = list.filter(function(c){ return c.id !== id; });
  list.unshift({ id, title, t: Date.now() });
  list = list.slice(0,50);
  // 删除超出的旧会话
  if (list.length >= 50) {
    try {
      const keep = new Set(list.map(function(c){ return c.id; }));
      const all = await kv.list({ prefix: 'conv_' + username + '_' });
      for (const k of all.keys) {
        const cid = k.name.slice(('conv_' + username + '_').length);
        if (!keep.has(cid)) await kv.delete(k.name);
      }
    } catch(e){}
  }
  await kv.put('convs_' + username, JSON.stringify(list));
  return json({ ok: true, id, title });
}
async function handleConvDelete(request, env){
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '未登录' }, 401);
  const id = new URL(request.url).searchParams.get('id') || '';
  if (!/^[a-z0-9]{5,20}$/.test(id)) return json({ ok: false, error: '参数错误' }, 400);
  const kv = env.FEEDBACK_KV;
  await kv.delete('conv_' + username + '_' + id);
  let list = [];
  try { const raw = await kv.get('convs_' + username); if (raw) list = JSON.parse(raw); } catch(e){}
  if (Array.isArray(list)) {
    list = list.filter(function(c){ return c.id !== id; });
    await kv.put('convs_' + username, JSON.stringify(list));
  }
  return json({ ok: true });
}

// ---------- 后台管理 ----------
function adminPage(env){
  const h = '<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
  + '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">'
  + '<title>DeepSeek站 后台</title>'
  + '<style>*{box-sizing:border-box}body{margin:0;background:#0b0b0f;color:#e8e8ec;font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:16px;max-width:720px;margin:0 auto}'
  + 'h1{font-size:20px}.card{background:#14141a;border:1px solid #2c2c36;border-radius:14px;padding:14px;margin-bottom:10px}'
  + '.row{display:flex;justify-content:space-between;align-items:center;gap:8px}'
  + 'button{border:none;border-radius:10px;padding:9px 14px;font-size:14px;cursor:pointer}'
  + '.bv{background:#2a2a34;color:#e8e8ec}.bd{background:#3a2028;color:#ff8ba0}'
  + '.msg{border-left:3px solid #2c2c36;padding:8px 10px;margin:8px 0;font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word}'
  + '.msg.user{border-color:#4a9eff}.msg.assistant{border-color:#22c55e}.rl{font-size:12px;color:#9a9aa3;margin-bottom:4px}'
  + '#kb{text-align:center;margin-top:60px}.hd{display:none}'
  + 'input{background:#101016;border:1px solid #2c2c36;border-radius:10px;color:#e8e8ec;padding:12px;font-size:15px;width:220px;text-align:center}'
  + '</style></head><body>'
  + '<div id="kb"><h1>后台管理</h1><p style="color:#9a9aa3">请输入管理密码</p>'
  + '<input type="password" id="ki"><br><br>'
  + '<button class="bv" id="goBtn">进入</button>'
  + '<div id="lm" style="margin-top:10px;min-height:20px"></div></div>'
  + '<div id="mn" class="hd"><h1>用户管理 <span style="font-size:12px;color:#9a9aa3">[DeepSeek站]</span></h1>'
  + '<button class="bv" id="rfBtn">刷新</button><div id="ul"></div>'
  + '<h2 id="ct" class="hd"></h2><div id="cl"></div>'
  + '<h2 id="mt" class="hd"></h2><div id="ml"></div></div>'
  + '<script>'
  + 'var K="";'
  + 'function lm(t,c){var e=document.getElementById("lm");if(e){e.textContent=t;e.style.color=c||"#ff8ba0";}}'
  + 'function esc(t){return String(t||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}'
  + 'function api(p){return fetch(p+(p.indexOf("?")>=0?"&":"?")+"key="+encodeURIComponent(K)).then(function(r){return r.text();}).then(function(t){try{return JSON.parse(t);}catch(e){return{ok:false,error:"返回异常:"+t.slice(0,80)};}}).catch(function(e){return{ok:false,error:"网络错误"};});}'
  + 'async function doLogin(){lm("验证中…","#9a9aa3");K=document.getElementById("ki").value.trim();if(!K){lm("请输入密码");return;}var j=await api("/api/admin/users");if(!j.ok){lm(j.error||"密码错误");return;}document.getElementById("kb").className="hd";document.getElementById("mn").className="";showUsers(j.users);}'
  + 'function showUsers(us){var h=\'\';if(!us.length)h=\'<div class="card">暂无用户</div>\';for(var i=0;i<us.length;i++){var u=us[i];h+=\'<div class="card"><div class="row"><div><b>\'+esc(u.username)+\'</b> \'+u.convs+\'个对话<br><span style="color:#9a9aa3;font-size:12px">\'+esc(u.model||\'--\')+\' | \'+esc(u.ip||\'--\')+\'</span></div><div><button class="bv" data-u="\'+esc(u.username)+\'" data-a="v">查看</button> <button class="bd" data-u="\'+esc(u.username)+\'" data-a="d">删除</button></div></div></div>\';}document.getElementById(\'ul\').innerHTML=h;bindBtns(\'ul\');}'
  + 'function bindBtns(id){var el=document.getElementById(id);var bs=el.querySelectorAll("button[data-u]");for(var i=0;i<bs.length;i++){bs[i].onclick=function(){var u=this.getAttribute("data-u");var a=this.getAttribute("data-a");if(a==="v")viewConvs(u);else delUser(u);};}}'
  + 'async function viewConvs(u){var j=await api(\'/api/admin/user-convs?user=\'+encodeURIComponent(u));if(!j.ok){alert(\'失败\');return;}document.getElementById(\'ml\').innerHTML=\'\';var t=document.getElementById(\'ct\');t.className=\'\';t.textContent=u+\' 的对话\';var h=\'\';if(!j.convs.length)h=\'<div class="card">无对话</div>\';for(var i=0;i<j.convs.length;i++){var c=j.convs[i];var d=new Date(c.t);var ds=(d.getMonth()+1)+\'-\'+d.getDate()+\' \'+d.getHours()+\':\'+(\'0\'+d.getMinutes()).slice(-2);h+=\'<div class="card"><div class="row"><div><b>\'+esc(c.title)+\'</b><br><span style="color:#9a9aa3;font-size:12px">\'+ds+\'</span></div><button class="bv" data-u="\'+esc(u)+\'" data-c="\'+c.id+\'">查看内容</button></div></div>\';}var cl=document.getElementById(\'cl\');cl.innerHTML=h;var bs=cl.querySelectorAll(\'button[data-c]\');for(var k=0;k<bs.length;k++){bs[k].onclick=function(){viewMsgs(this.getAttribute(\'data-u\'),this.getAttribute(\'data-c\'));};}t.scrollIntoView();}'
  + 'async function viewMsgs(u,id){var j=await api(\'/api/admin/conv?user=\'+encodeURIComponent(u)+\'&id=\'+encodeURIComponent(id));if(!j.ok){alert(\'失败\');return;}var t=document.getElementById(\'mt\');t.className=\'\';t.textContent=\'对话内容\';var h=\'\';for(var i=0;i<j.messages.length;i++){var m=j.messages[i];var txt=Array.isArray(m.content)?m.content.map(function(p){return p.type===\'text\'?p.text:\'[图片]\';}).join(\'\'):String(m.content||\'\');h+=\'<div class="msg \'+m.role+\'"><div class="rl">\'+(m.role===\'user\'?\'用户\':\'AI\')+\'</div>\'+esc(txt).replace(/\\n/g,\'<br>\')+\'</div>\';}document.getElementById(\'ml\').innerHTML=h||\'<div class="card">空</div>\';t.scrollIntoView();}'
  + 'async function delUser(u){if(!confirm("删除 "+u+" 及所有记录？不可恢复！"))return;var r=await fetch("/api/admin/delete-user?key="+encodeURIComponent(K),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:u})});var j=await r.json();if(j.ok){doLogin();}else{alert(j.error||"失败");}}'
  + 'document.getElementById("goBtn").onclick=doLogin;'
  + 'document.getElementById("rfBtn").onclick=doLogin;'
  + 'document.getElementById("ki").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin();});'
  + '</scr'+'ipt></body></html>';
  return new Response(h, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
function adminAuth(request, env){
  const key = (env.FEEDBACK_ADMIN_KEY || '').trim();
  if (!key) return false;
  const url = new URL(request.url);
  return url.searchParams.get('key') === key;
}
async function handleAdminUsers(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const out = [];
  try {
    let cursor = undefined;
    do {
      const res = await kv.list({ prefix: 'user_', cursor });
      for (const k of res.keys) {
        const uname = k.name.slice(5);
        let convCount = 0;
        try {
          const raw = await kv.get('convs_' + uname);
          if (raw) { const l = JSON.parse(raw); if (Array.isArray(l)) convCount = l.length; }
        } catch(e){}
        let regIp2='', lm='';
        try { const ur=await kv.get(k.name); if(ur) regIp2=JSON.parse(ur).ip||''; } catch(e){}
        try { lm=await kv.get('umodel_'+uname)||''; } catch(e){}
        out.push({ username: uname, convs: convCount, ip: regIp2, model: lm });
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch(e){}
  out.sort(function(a,b){ return b.convs - a.convs; });
  return json({ ok: true, users: out });
}
async function handleAdminUserConvs(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const uname = (new URL(request.url).searchParams.get('user') || '').toLowerCase();
  if (!/^[a-z]{1,8}$/.test(uname)) return json({ ok: false, error: '参数错误' }, 400);
  let list = [];
  try { const raw = await env.FEEDBACK_KV.get('convs_' + uname); if (raw) list = JSON.parse(raw); } catch(e){}
  if (!Array.isArray(list)) list = [];
  return json({ ok: true, convs: list });
}
async function handleAdminConvView(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const url = new URL(request.url);
  const uname = (url.searchParams.get('user') || '').toLowerCase();
  const id = url.searchParams.get('id') || '';
  if (!/^[a-z]{1,8}$/.test(uname) || !/^[a-z0-9]{5,20}$/.test(id)) return json({ ok: false, error: '参数错误' }, 400);
  let messages = [];
  try { const raw = await env.FEEDBACK_KV.get('conv_' + uname + '_' + id); if (raw) messages = JSON.parse(raw); } catch(e){}
  return json({ ok: true, messages: Array.isArray(messages) ? messages : [] });
}
async function handleAdminDeleteUser(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
  const uname = String(body.user || '').toLowerCase();
  if (!/^[a-z]{1,8}$/.test(uname)) return json({ ok: false, error: '参数错误' }, 400);
  const kv = env.FEEDBACK_KV;
  const prefixes = ['user_' + uname, 'convs_' + uname, 'conv_' + uname + '_'];
  try {
    for (const p of prefixes) {
      let cursor = undefined;
      do {
        const res = await kv.list({ prefix: p, cursor });
        for (const k of res.keys) await kv.delete(k.name);
        cursor = res.list_complete ? undefined : res.cursor;
      } while (cursor);
    }
    // 删除该用户的所有 session
    let cursor2 = undefined;
    do {
      const res = await kv.list({ prefix: 'sess_', cursor: cursor2 });
      for (const k of res.keys) {
        try { const v = await kv.get(k.name); if (v === uname) await kv.delete(k.name); } catch(e){}
      }
      cursor2 = res.list_complete ? undefined : res.cursor;
    } while (cursor2);
  } catch(e){}
  return json({ ok: true });
}

// ---------- DeepSeek 聊天代理 ----------
// ---------- DeepSeek 聊天代理 ----------

async function handleChat(request, env) {
 try {
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '请先登录' }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }

  // 30秒发送冷却
  const kv = env.FEEDBACK_KV;
  if (kv) {
    const last = await kv.get('chatcool_' + username);
    if (last) {
      const remain = 30 - Math.floor((Date.now() - parseInt(last, 10)) / 1000);
      if (remain > 0) return json({ ok: false, error: '发送太快了，请 ' + remain + ' 秒后再试', remain }, 429);
    }
  }
  // 每次发送都要 Turnstile 验证
  const tsToken = String(body.turnstile || '').trim();
  if (env.TURNSTILE_SECRET_KEY) {
    if (!tsToken) return json({ ok: false, error: '请先完成人机验证' }, 400);
    const ip = request.headers.get('cf-connecting-ip') || '';
    const tsOk = await verifyTurnstile(tsToken, env.TURNSTILE_SECRET_KEY, ip);
    if (!tsOk) return json({ ok: false, error: '人机验证失败，请重试' }, 400);
  }
  if (kv) await kv.put('chatcool_' + username, String(Date.now()), { expirationTtl: 65 });

  const apiKey = (env.DEEPSEEK_API_KEY || '').trim();
  if (!apiKey) return json({ ok: false, error: '未配置 DeepSeek API Key：请在 Cloudflare Pages → Settings → Environment variables 添加 DEEPSEEK_API_KEY（重新部署后生效）' }, 500);
  const model = body.model === 'deepseek-v4-pro' ? 'deepseek-v4-pro' : 'deepseek-v4-flash';
  try { if (kv) await kv.put('umodel_' + username, model, { expirationTtl: 90*24*3600 }); } catch(e){}
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
 } catch (e) {
   return json({ ok: false, error: '服务器内部错误: ' + (e && e.message || '未知') }, 500);
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
    if (url.pathname === '/api/convs' && request.method === 'GET') return handleConvsList(request, env);
    if (url.pathname === '/api/conv' && request.method === 'GET') return handleConvGet(request, env);
    if (url.pathname === '/api/conv' && request.method === 'POST') return handleConvSave(request, env);
    if (url.pathname === '/api/conv' && request.method === 'DELETE') return handleConvDelete(request, env);
    if (url.pathname === '/api/admin/users') return handleAdminUsers(request, env);
    if (url.pathname === '/api/admin/user-convs') return handleAdminUserConvs(request, env);
    if (url.pathname === '/api/admin/conv') return handleAdminConvView(request, env);
    if (url.pathname === '/api/admin/delete-user' && request.method === 'POST') return handleAdminDeleteUser(request, env);
    if (url.pathname === '/admin') return adminPage(env);
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
