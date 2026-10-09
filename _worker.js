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
// Tavily 联网搜索（专为 LLM 设计）：新闻 + 网页双通道，失败返回 null
async function tavilySearch(query, apiKey) {
  async function callApi(topic, timeRange) {
    try {
      const r = await fetch('https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
        body: JSON.stringify({
          query: query,
          topic: topic,
          max_results: 5,
          search_depth: 'basic',
          include_answer: false,
          include_raw_content: false,
          ...(timeRange ? { time_range: timeRange } : {}),
        }),
      });
      if (!r.ok) return [];
      const j = await r.json();
      return j.results || [];
    } catch(e){ return []; }
  }
  const news = await callApi('news', 'month');
  const web = await callApi('general', null);
  const seen = {};
  const all = news.concat(web).filter(function(it){
    const u = String(it.url || '');
    if (!u || !it.title) return false;
    const key = u.split('?')[0].toLowerCase();
    if (seen[key]) return false;
    seen[key] = 1;
    return true;
  }).slice(0, 8);
  if (!all.length) return '（未搜到有效结果）';
  return all.map(function(it, i){
    return '[' + (i+1) + '] ' + (it.title || '') + '\n' + String(it.content || '').slice(0, 400) + '\n来源：' + (it.url || '');
  }).join('\n\n');
}
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
  const bl = await isBlacklisted(request, env);
  if (bl) return json({ ok: false, error: blackMsg(bl) }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  const action = body.action === 'register' ? 'register' : 'login';
  const username = String(body.username || '').trim();
  if (action === 'login') {
    const ban = await checkBan(username, env);
    if (ban) return json({ ok: false, error: banMsg(ban) }, 403);
  }
  const password = String(body.password || '').trim();
  if (!validUsername(username)) return json({ ok: false, error: '用户名为1-8个字母' }, 400);
  if (action === 'register' && brakeHasSensitive(username)) return json({ ok: false, error: '用户名包含敏感词，请换一个' }, 400);
  if (!validPassword(password)) return json({ ok: false, error: '密码为1-10位数字' }, 400);
  if (env.TURNSTILE_SECRET_KEY) {
    const tsToken = String(body.turnstile || '').trim();
    if (!tsToken) return json({ ok: false, error: '请先完成人机验证' }, 400);
    const ip = request.headers.get('cf-connecting-ip') || '';
    const tsOk = await verifyTurnstile(tsToken, env.TURNSTILE_SECRET_KEY, ip);
    if (!tsOk) return json({ ok: false, error: '人机验证失败，请重试' }, 400);
  }
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
  const devId = getDeviceId(request);
  if (devId) {
    try {
      const uk = 'user_' + username.toLowerCase();
      const uraw = await kv.get(uk);
      if (uraw) {
        const u = JSON.parse(uraw);
        u.dev = devId;
        await kv.put(uk, JSON.stringify(u));
      }
    } catch(e){}
  }
  return json({ ok: true, token, username });
}
// ---------- 多会话历史 ----------
function convId(){ return Date.now().toString(36) + Math.random().toString(36).slice(2,7); }
function cleanMessages(messages){
  messages = Array.isArray(messages) ? messages.slice(-60) : [];
  return messages.map(function(m){
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    const t = m.t || Date.now();
    if (Array.isArray(m.content)) {
      const parts = m.content.map(function(p){
        if (p && p.type === 'image_url') return { type: 'text', text: '[图片]' };
        if (p && p.type === 'text') return { type: 'text', text: String(p.text||'').slice(0,5000) };
        return null;
      }).filter(Boolean);
      return { role, content: parts.length ? parts : [{type:'text',text:'(空)'}], t };
    }
    return { role, content: String(m.content||'').slice(0, 8000), t };
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
  const oldEntry = list.find(function(c){ return c.id === id; });
  const thinkLabel = body.think || (oldEntry && oldEntry.think) || '';
  const webFlag = !!(body.web || (oldEntry && oldEntry.web));
  list = list.filter(function(c){ return c.id !== id; });
  list.unshift({ id, title, t: Date.now(), think: thinkLabel, web: webFlag });
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
  const html = "<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>可乐站·DeepSeek 后台</title><style>*{box-sizing:border-box}body{margin:0;background:#0b0b0f;color:#e8e8ec;font-family:-apple-system,sans-serif;padding:16px;max-width:720px;margin:0 auto}h1{font-size:20px}h2{font-size:16px;margin-top:24px}.card{background:#14141a;border:1px solid #2c2c36;border-radius:14px;padding:14px;margin-bottom:10px}.row{display:flex;justify-content:space-between;align-items:center;gap:8px}button{border:none;border-radius:10px;padding:9px 14px;font-size:14px;cursor:pointer}.bv{background:#2a2a34;color:#e8e8ec}.bd{background:#3a2028;color:#ff8ba0}.msg{border-left:3px solid #2c2c36;padding:8px 10px;margin:8px 0;font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word}.msg.user{border-color:#4a9eff}.msg.assistant{border-color:#22c55e}.rl{font-size:12px;color:#9a9aa3;margin-bottom:4px}#kb{text-align:center;margin-top:60px}.hd{display:none}input{background:#101016;border:1px solid #2c2c36;border-radius:10px;color:#e8e8ec;padding:12px;font-size:15px;width:220px;text-align:center}.sm{font-size:12px;color:#9a9aa3}.fb-txt.clamp{max-height:60px;overflow:hidden}.blue{color:#4a9eff;font-size:12px}.bbar{background:#14141a;border:1px solid #2c2c36;border-radius:12px;padding:10px 12px;margin:10px 0}.bbar .br2{display:flex;gap:8px;flex-wrap:wrap}.bbar .br2 button{padding:7px 12px;font-size:12px;border-radius:8px}.bcount{font-size:12px;color:#4a9eff;margin-left:8px}.card.sel{border-color:#4a9eff;background:#16202f}.tg{background:#4a9eff22;color:#4a9eff;border-radius:6px;padding:2px 6px;font-size:11px}.tg2{background:#22c55e22;color:#22c55e;border-radius:6px;padding:2px 6px;font-size:11px}body::after{content:\"\";position:fixed;inset:0;background:url('/bg.jpg') center/cover no-repeat;opacity:.25;pointer-events:none;z-index:2147483647}</style></head><body><div id=\"kb\"><h1>可乐站·DeepSeek 后台</h1><p class=\"sm\">请输入管理密码</p><input type=\"password\" id=\"ki\"><br><br><button class=\"bv\" id=\"goBtn\">进入</button><div id=\"lm\" style=\"margin-top:10px;min-height:20px\"></div></div><div id=\"mn\" class=\"hd\"><div class=\"card\"><div class=\"row\"><div><b>💰 API 余额</b><br><span class=\"sm\" id=\"balInfo\">未查询</span></div><button class=\"bv\" id=\"balBtn\">查询</button></div></div><div class=\"card\"><b>💰 价格设置</b> <span class=\"sm\">元/百万 tokens</span><div style=\"margin-top:8px;font-size:14px;line-height:2.2\">Flash 输入 <input id=\"pr_fi\" style=\"width:70px;text-align:center;background:#101016;border:1px solid #2c2c36;border-radius:8px;color:#e8e8ec;padding:6px;font-size:14px\"> 输出 <input id=\"pr_fo\" style=\"width:70px;text-align:center;background:#101016;border:1px solid #2c2c36;border-radius:8px;color:#e8e8ec;padding:6px;font-size:14px\"><br>Pro 输入 <input id=\"pr_pi\" style=\"width:70px;text-align:center;background:#101016;border:1px solid #2c2c36;border-radius:8px;color:#e8e8ec;padding:6px;font-size:14px\"> 输出 <input id=\"pr_po\" style=\"width:70px;text-align:center;background:#101016;border:1px solid #2c2c36;border-radius:8px;color:#e8e8ec;padding:6px;font-size:14px\"></div><div style=\"margin-top:8px\"><button class=\"bv\" id=\"prSave\">保存</button> <span class=\"sm\" id=\"prMsg\"></span></div><p class=\"sm\" style=\"margin-top:6px\">默认 Flash 输入1元/输出4元，Pro 输入3元/输出6元（Pro 为官方价，Flash 为估算，以官网价格页为准自行调整）。改版前历史用量按 Flash 价格折算。</p></div><h1>用户管理</h1><button class=\"bv\" id=\"rfBtn\">刷新</button><div class=\"bbar\"><div class=\"br2\"><button class=\"bv\" id=\"bSelU\">全选</button><button class=\"bd\" id=\"bDelU\">删除所选</button><button class=\"bd\" id=\"bBlkU\">拉黑所选</button><button class=\"bd\" id=\"bDelBlkU\">删除并拉黑</button><button class=\"bd\" id=\"bBanU\">封禁所选</button><button class=\"bv\" id=\"bCanU\">取消选择</button><span id=\"selUCount\" class=\"bcount\"></span></div></div><div id=\"ul\"></div><h2 id=\"ct\" class=\"hd\"></h2><div id=\"cl\"></div><h2 id=\"mt\" class=\"hd\"></h2><div id=\"ml\"></div><h2 style=\"margin-top:30px\">🔨 封禁名单</h2><button class=\"bv\" id=\"banBtn\">刷新封禁名单</button><div class=\"bbar\"><div class=\"br2\"><button class=\"bv\" id=\"bSelBan\">全选</button><button class=\"bv\" id=\"bUnbBan\">解除所选</button><button class=\"bv\" id=\"bCanBan\">取消选择</button><span id=\"selBanCount\" class=\"bcount\"></span></div></div><div id=\"banl\" style=\"margin-top:10px\"></div><h2 style=\"margin-top:30px\">🚫 黑名单</h2><button class=\"bv\" id=\"blBtn\">刷新黑名单</button><div class=\"bbar\"><div class=\"br2\"><button class=\"bv\" id=\"bSelB\">全选</button><button class=\"bv\" id=\"bUnbB\">解除所选</button><button class=\"bv\" id=\"bCanB\">取消选择</button><span id=\"selBCount\" class=\"bcount\"></span></div></div><div id=\"bl\" style=\"margin-top:10px\"></div><h2 style=\"margin-top:30px\">💬 反馈记录</h2><select id=\"fbSite\" style=\"background:#101016;border:1px solid #2c2c36;border-radius:8px;color:#e8e8ec;padding:8px;font-size:14px;margin-right:8px\"><option value=\"[DeepSeek站]\">[DeepSeek站]</option><option value=\"[刹车站]\">[刹车站]</option><option value=\"\">全部站点</option></select> <button class=\"bv\" id=\"fbBtn\">加载反馈</button><div class=\"bbar\"><div class=\"br2\"><button class=\"bv\" id=\"bSelF\">全选</button><button class=\"bd\" id=\"bDelF\">删除所选</button><button class=\"bv\" id=\"bCanF\">取消选择</button><span id=\"selFCount\" class=\"bcount\"></span></div></div><div id=\"fl\" style=\"margin-top:10px\"></div><h2 style=\"margin-top:30px\">⚙️ 预设提示词</h2><p class=\"sm\">所有用户、所有对话生效（新对话和继续对话都一样）。清空保存即关闭。每次请求会多消耗提示词长度的输入 token。</p><div class=\"card\"><textarea id=\"sysp\" style=\"width:100%;min-height:120px;background:#101016;border:1px solid #2c2c36;border-radius:10px;color:#e8e8ec;padding:10px;font-size:14px;box-sizing:border-box\" placeholder=\"例如：你是一个猫娘，说话结尾要加喵~\"></textarea><div style=\"margin-top:10px;display:flex;gap:8px\"><button class=\"bv\" id=\"syspSave\">保存</button><button class=\"bv\" id=\"syspLoad\">重新加载</button></div><div id=\"syspMsg\" class=\"sm\" style=\"margin-top:6px\"></div></div></div><script>var K=\"\";function lm(t,c){var e=document.getElementById(\"lm\");if(e){e.textContent=t;e.style.color=c||\"#ff8ba0\";}}function esc(t){return String(t||\"\").replace(/&/g,\"&amp;\").replace(/</g,\"&lt;\").replace(/>/g,\"&gt;\");}function fmtT(t){var d=new Date(t);return d.getFullYear()+\"-\"+(d.getMonth()+1)+\"-\"+d.getDate()+\" \"+d.getHours()+\":\"+(\"0\"+d.getMinutes()).slice(-2);}function api(p){return fetch(p+(p.indexOf(\"?\")>=0?\"&\":\"?\")+\"key=\"+encodeURIComponent(K)).then(function(r){return r.text();}).then(function(t){try{return JSON.parse(t);}catch(e){return{ok:false,error:\"返回异常\"}}}).catch(function(e){return{ok:false,error:\"网络错误\"}});}async function doLogin(){lm(\"验证中…\",\"#9a9aa3\");K=document.getElementById(\"ki\").value.trim();if(!K){lm(\"请输入密码\");return;}var j=await api(\"/api/admin/users\");if(!j.ok){lm(j.error||\"密码错误\");return;}document.getElementById(\"kb\").style.display=\"none\";document.getElementById(\"mn\").classList.remove(\"hd\");showUsers(j.users);loadBlacklist();loadBans();loadSysp();loadBalance();loadPricing();}function showUsers(us){var h=\"\";if(!us.length)h='<div class=\"card\">暂无用户</div>';for(var i=0;i<us.length;i++){var u=us[i];var tk=u.cost;h+='<div class=\"card ucard\" data-u=\"'+esc(u.username)+'\" data-ip=\"'+esc(u.ip||\"\")+'\" data-dev=\"'+esc(u.dev||\"\")+'\"><div class=\"row\"><div><b>'+esc(u.username)+'</b> '+u.convs+'个对话<br><span class=\"sm\">'+esc(u.model||\"--\")+' | '+esc(u.ip||\"--\")+'</span><br><span class=\"sm\">最后活跃: '+(u.lastT?fmtT(u.lastT):\"--\")+'</span><br><span class=\"blue\">消耗: '+fmtCost(tk)+'</span></div><div><button class=\"bv\" data-u=\"'+esc(u.username)+'\" data-a=\"v\">查看</button> <button class=\"bd\" data-u=\"'+esc(u.username)+'\" data-a=\"d\">删除</button> <button class=\"bd\" data-u=\"'+esc(u.username)+'\" data-a=\"b\" data-ip=\"'+esc(u.ip||\"\")+'\" data-dev=\"'+esc(u.dev||\"\")+'\">拉黑</button> <button class=\"bd\" data-u=\"'+esc(u.username)+'\" data-a=\"f\" data-ip=\"'+esc(u.ip||\"\")+'\" data-dev=\"'+esc(u.dev||\"\")+'\">封禁</button></div></div></div>';}document.getElementById(\"ul\").innerHTML=h;bindSelU();\nvar bs=document.getElementById(\"ul\").querySelectorAll(\"button[data-u]\");for(var i=0;i<bs.length;i++){bs[i].onclick=function(){var u=this.getAttribute(\"data-u\");var a=this.getAttribute(\"data-a\");if(a===\"v\")viewConvs(u);else if(a===\"b\")blockUser(u,this.getAttribute(\"data-ip\"),this.getAttribute(\"data-dev\"));else if(a===\"f\")banUser(u,this.getAttribute(\"data-ip\"),this.getAttribute(\"data-dev\"));else delUser(u);};}}async function viewConvs(u){var j=await api(\"/api/admin/user-convs?user=\"+encodeURIComponent(u));if(!j.ok){alert(\"失败\");return;}document.getElementById(\"ml\").innerHTML=\"\";var t=document.getElementById(\"ct\");t.classList.remove(\"hd\");t.textContent=u+\" 的对话\";var h=\"\";if(!j.convs.length)h='<div class=\"card\">无对话</div>';for(var i=0;i<j.convs.length;i++){var c=j.convs[i];var lv=c.think===true?'深度思考':(c.think||'关闭');var tags=(c.web?' <span class=\"tg2\">🌐联网</span>':\"\");h+='<div class=\"card\"><div class=\"row\"><div><b>'+esc(c.title)+'</b>'+tags+'<br><span class=\"sm\">'+esc('⚡推理强度：'+lv)+'</span><br><span class=\"sm\">'+(c.t?fmtT(c.t):\"--\")+'</span></div><button class=\"bv\" data-u=\"'+esc(u)+'\" data-c=\"'+c.id+'\">查看内容</button></div></div>';}var cl=document.getElementById(\"cl\");cl.innerHTML=h;var bs=cl.querySelectorAll(\"button[data-c]\");for(var k=0;k<bs.length;k++){bs[k].onclick=function(){viewMsgs(this.getAttribute(\"data-u\"),this.getAttribute(\"data-c\"));};}t.scrollIntoView();}async function viewMsgs(u,id){var j=await api(\"/api/admin/conv?user=\"+encodeURIComponent(u)+\"&id=\"+encodeURIComponent(id));if(!j.ok){alert(\"失败\");return;}var t=document.getElementById(\"mt\");t.classList.remove(\"hd\");t.textContent=\"对话内容\";var h=\"\";for(var i=0;i<j.messages.length;i++){var m=j.messages[i];var txt=Array.isArray(m.content)?m.content.map(function(p){return p.type===\"text\"?p.text:\"[图片]\";}).join(\"\"):String(m.content||\"\");h+='<div class=\"msg '+m.role+'\"><div class=\"rl\">'+(m.role===\"user\"?\"用户\":\"AI\")+(m.t?' <span>'+fmtT(m.t)+'</span>':\"\")+'</div>'+esc(txt).replace(/\\n/g,\"<br>\")+'</div>';}document.getElementById(\"ml\").innerHTML=h||'<div class=\"card\">空</div>';t.scrollIntoView();}async function delUser(u){if(!confirm(\"删除 \"+u+\" 及所有记录？不可恢复！\"))return;var r=await fetch(\"/api/admin/delete-user?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({user:u})});var j=await r.json();if(j.ok){doLogin();}else{alert(j.error||\"失败\");}}async function blockUser(u,ip,dev){if(!ip&&!dev){alert(\"该用户无IP/设备记录\");return;}var reason=prompt(\"拉黑 \"+u+\" 的理由（可空）:\",\"\");if(reason===null)return;reason=reason.trim().slice(0,100);if(ip){await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({type:\"ip\",value:ip,username:u,reason:reason})});}if(dev){await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({type:\"device\",value:dev,username:u,reason:reason})});}alert(\"已拉黑\");loadBlacklist();}async function loadBlacklist(){var j=await api(\"/api/admin/blacklist\");if(!j.ok)return;var h=\"\";if(!j.list.length)h='<div class=\"card\">黑名单为空</div>';for(var i=0;i<j.list.length;i++){var b=j.list[i];h+='<div class=\"card bcard\" data-t=\"'+b.type+'\" data-v=\"'+esc(b.value)+'\"><div class=\"row\"><div><b>'+(b.type===\"ip\"?\"IP\":\"设备\")+'</b> '+esc(b.value)+'<br><span class=\"sm\">'+esc(b.username||\"--\")+' | '+fmtT(b.t)+'</span>'+(b.reason?'<br><span class=\"sm\" style=\"color:#ffb020\">理由: '+esc(b.reason)+'</span>':\"\")+'</div><button class=\"bv\" data-t=\"'+b.type+'\" data-v=\"'+esc(b.value)+'\">解除</button></div></div>';}bindSelB();\nvar el=document.getElementById(\"bl\");el.innerHTML=h;var bs=el.querySelectorAll(\"button[data-v]\");for(var k=0;k<bs.length;k++){bs[k].onclick=function(){unblock(this.getAttribute(\"data-t\"),this.getAttribute(\"data-v\"));};}}async function unblock(t,v){if(!confirm(\"解除拉黑 \"+v+\"？\"))return;var r=await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K)+\"&type=\"+t+\"&value=\"+encodeURIComponent(v),{method:\"DELETE\"});var j=await r.json();if(j.ok)loadBlacklist();else alert(\"失败\");}document.getElementById(\"goBtn\").onclick=doLogin;document.getElementById(\"rfBtn\").onclick=doLogin;document.getElementById(\"blBtn\").onclick=loadBlacklist;\nfunction fmtCost(c){c=+c||0;return \"¥\"+(c>0&&c<0.01?c.toFixed(4):c.toFixed(2));}\nasync function loadPricing(){var j=await api(\"/api/admin/pricing\");if(!j.ok||!j.pricing)return;var p=j.pricing;document.getElementById(\"pr_fi\").value=p.flash_in;document.getElementById(\"pr_fo\").value=p.flash_out;document.getElementById(\"pr_pi\").value=p.pro_in;document.getElementById(\"pr_po\").value=p.pro_out;}\ndocument.getElementById(\"prSave\").onclick=async function(){var b={flash_in:document.getElementById(\"pr_fi\").value,flash_out:document.getElementById(\"pr_fo\").value,pro_in:document.getElementById(\"pr_pi\").value,pro_out:document.getElementById(\"pr_po\").value};var r=await fetch(\"/api/admin/pricing?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify(b)});var j=await r.json();var m=document.getElementById(\"prMsg\");if(j.ok){m.textContent=\"已保存，金额按新价格重算\";m.style.color=\"#22c55e\";var jj=await api(\"/api/admin/users\");if(jj.ok)showUsers(jj.users);}else{m.textContent=j.error||\"保存失败\";m.style.color=\"#ff8ba0\";}};\nasync function loadBalance(){var el=document.getElementById(\"balInfo\");el.textContent=\"查询中…\";var j=await api(\"/api/admin/balance\");if(!j.ok){el.textContent=j.error||\"查询失败\";return;}if(!j.balances.length){el.textContent=\"无余额信息\";return;}var h=j.balances.map(function(b){return b.currency+\" \"+b.total+\"（充值 \"+b.topped+\" / 赠送 \"+b.granted+\"）\";}).join(\"；\");el.textContent=h+(j.is_available?\"\":\"（余额不足）\");}\ndocument.getElementById(\"balBtn\").onclick=loadBalance;\nasync function loadSysp(){var j=await api(\"/api/admin/sysprompt\");if(j.ok){document.getElementById(\"sysp\").value=j.prompt||\"\";var m=document.getElementById(\"syspMsg\");if(m)m.textContent=j.prompt?\"当前已设置预设提示词\":\"当前未设置\";}}\ndocument.getElementById(\"syspSave\").onclick=async function(){var v=document.getElementById(\"sysp\").value.trim().slice(0,4000);var r=await fetch(\"/api/admin/sysprompt?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({prompt:v})});var j=await r.json();var m=document.getElementById(\"syspMsg\");if(j.ok){m.textContent=v?\"已保存，即刻生效\":\"已清空，预设提示词关闭\";m.style.color=\"#22c55e\";}else{m.textContent=j.error||\"保存失败\";m.style.color=\"#ff8ba0\";}};\ndocument.getElementById(\"syspLoad\").onclick=loadSysp;\ndocument.getElementById(\"banBtn\").onclick=loadBans;\nvar selBan={};\nfunction updSelBan(){var n=Object.keys(selBan).length;var e=document.getElementById(\"selBanCount\");if(e)e.textContent=n?(\"已选 \"+n+\" 条\"):\"\";}\nfunction banDaysLabel(d){return d===1?\"一天\":d===3?\"三天\":d===5?\"五天\":d===30?\"一个月\":d===365?\"一年\":d+\"天\";}\nasync function banUser(u,ip,dev){\n  var c=prompt(\"封禁 \"+u+\"，请选择时长：\\n1. 一天\\n2. 三天\\n3. 五天\\n4. 一个月\\n5. 一年\",\"1\");\n  if(c===null)return;\n  var days={\"1\":1,\"2\":3,\"3\":5,\"4\":30,\"5\":365}[c.trim()];\n  if(!days){alert(\"请输入 1-5\");return;}\n  var reason=prompt(\"封禁理由（可空）:\",\"\");\n  if(reason===null)return;\n  reason=reason.trim().slice(0,100);\n  var j=await postJ(\"/api/admin/ban\",{username:u,days:days,reason:reason});\n  if(!j.ok){alert(j.error||\"失败\");return;}\n  var items=[];\n  if(ip)items.push({type:\"ip\",value:ip,username:u,reason:reason});\n  if(dev)items.push({type:\"device\",value:dev,username:u,reason:reason});\n  if(items.length)await postJ(\"/api/admin/blacklist\",{items:items});\n  alert(\"已封禁 \"+banDaysLabel(days)+(items.length?\"，IP/设备已同步拉黑\":\"\"));loadBans();loadBlacklist();\n}\nasync function loadBans(){\n  var j=await api(\"/api/admin/bans\");if(!j.ok)return;\n  var h=\"\";if(!j.list.length)h='<div class=\"card\">封禁名单为空</div>';\n  for(var i=0;i<j.list.length;i++){var b=j.list[i];\n    h+='<div class=\"card bancard\" data-u=\"'+esc(b.username)+'\"><div class=\"row\"><div><b>'+esc(b.username)+'</b> 封禁'+banDaysLabel(b.days)+'<br><span class=\"sm\">解封：'+fmtT(b.until)+'</span>'+(b.reason?'<br><span class=\"sm\" style=\"color:#ffb020\">理由: '+esc(b.reason)+'</span>':\"\")+'</div><button class=\"bv\" data-u=\"'+esc(b.username)+'\">解除</button></div></div>';}\n  document.getElementById(\"banl\").innerHTML=h;bindSelBan();\n  var bs=document.getElementById(\"banl\").querySelectorAll(\"button[data-u]\");\n  for(var k=0;k<bs.length;k++){bs[k].onclick=function(){unbanUser(this.getAttribute(\"data-u\"));};}}\nasync function unbanUser(u){if(!confirm(\"解除封禁 \"+u+\"？\"))return;var r=await fetch(\"/api/admin/ban?key=\"+encodeURIComponent(K),{method:\"DELETE\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({username:u})});var j=await r.json();if(j.ok)loadBans();else alert(\"失败\");}\nfunction bindSelBan(){var cs=document.getElementById(\"banl\").querySelectorAll(\".bancard\");for(var i=0;i<cs.length;i++){var c=cs[i];if(selBan[c.getAttribute(\"data-u\")])c.classList.add(\"sel\");c.onclick=function(e){if(e.target.closest(\"button\"))return;var u=this.getAttribute(\"data-u\");if(this.classList.contains(\"sel\")){this.classList.remove(\"sel\");delete selBan[u];}else{this.classList.add(\"sel\");selBan[u]=1;}updSelBan();};}updSelBan();}\ndocument.getElementById(\"bSelBan\").onclick=function(){var cs=document.getElementById(\"banl\").querySelectorAll(\".bancard\");selBan={};for(var i=0;i<cs.length;i++){cs[i].classList.add(\"sel\");selBan[cs[i].getAttribute(\"data-u\")]=1;}updSelBan();};\ndocument.getElementById(\"bCanBan\").onclick=function(){selBan={};var cs=document.getElementById(\"banl\").querySelectorAll(\".bancard\");for(var i=0;i<cs.length;i++)cs[i].classList.remove(\"sel\");updSelBan();};\ndocument.getElementById(\"bUnbBan\").onclick=async function(){var us=Object.keys(selBan);if(!us.length){alert(\"请先点选\");return;}if(!confirm(\"解除 \"+us.length+\" 个封禁？\"))return;var r=await fetch(\"/api/admin/ban?key=\"+encodeURIComponent(K),{method:\"DELETE\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({usernames:us})});var j=await r.json();if(j.ok){selBan={};loadBans();}else alert(\"失败\");};\ndocument.getElementById(\"bBanU\").onclick=async function(){var us=Object.keys(selU);if(!us.length){alert(\"请先点选用户卡片\");return;}var c=prompt(\"封禁 \"+us.length+\" 个用户，请选择时长：\\n1. 一天\\n2. 三天\\n3. 五天\\n4. 一个月\\n5. 一年\",\"1\");if(c===null)return;var days={\"1\":1,\"2\":3,\"3\":5,\"4\":30,\"5\":365}[c.trim()];if(!days){alert(\"请输入 1-5\");return;}var reason=prompt(\"封禁理由（可空）:\",\"\");if(reason===null)return;reason=reason.trim().slice(0,100);var bans=[];var items=[];for(var i=0;i<us.length;i++){bans.push({username:us[i],days:days,reason:reason});var x=selU[us[i]];if(x.ip)items.push({type:\"ip\",value:x.ip,username:us[i],reason:reason});if(x.dev)items.push({type:\"device\",value:x.dev,username:us[i],reason:reason});}var j=await postJ(\"/api/admin/ban\",{bans:bans});if(!j.ok){alert(j.error||\"失败\");return;}if(items.length)await postJ(\"/api/admin/blacklist\",{items:items});alert(\"已封禁 \"+us.length+\" 个用户 \"+banDaysLabel(days)+(items.length?\"，IP/设备已同步拉黑\":\"\"));loadBans();loadBlacklist();};\nvar selU={},selF={},selB={};\nfunction updSelU(){var n=Object.keys(selU).length;var e=document.getElementById(\"selUCount\");if(e)e.textContent=n?(\"已选 \"+n+\" 个\"):\"\";}\nfunction updSelF(){var n=Object.keys(selF).length;var e=document.getElementById(\"selFCount\");if(e)e.textContent=n?(\"已选 \"+n+\" 条\"):\"\";}\nfunction updSelB(){var n=Object.keys(selB).length;var e=document.getElementById(\"selBCount\");if(e)e.textContent=n?(\"已选 \"+n+\" 条\"):\"\";}\nfunction toggleCard(c,map,key,get){if(c.classList.contains(\"sel\")){c.classList.remove(\"sel\");delete map[key];}else{c.classList.add(\"sel\");map[key]=get();}}\nfunction bindSelU(){var cs=document.getElementById(\"ul\").querySelectorAll(\".ucard\");for(var i=0;i<cs.length;i++){var c=cs[i];if(selU[c.getAttribute(\"data-u\")])c.classList.add(\"sel\");c.onclick=function(e){if(e.target.closest(\"button\"))return;var u=this.getAttribute(\"data-u\");toggleCard(this,selU,u,function(){return{ip:this.getAttribute(\"data-ip\"),dev:this.getAttribute(\"data-dev\")}}.bind(this));updSelU();};}updSelU();}\nfunction bindSelB(){var cs=document.getElementById(\"bl\").querySelectorAll(\".bcard\");for(var i=0;i<cs.length;i++){var c=cs[i];var k=c.getAttribute(\"data-t\")+\":\"+c.getAttribute(\"data-v\");if(selB[k])c.classList.add(\"sel\");c.onclick=function(e){if(e.target.closest(\"button\"))return;var kk=this.getAttribute(\"data-t\")+\":\"+this.getAttribute(\"data-v\");toggleCard(this,selB,kk,function(){return{t:this.getAttribute(\"data-t\"),v:this.getAttribute(\"data-v\")}}.bind(this));updSelB();};}updSelB();}\nfunction bindSelF(){var cs=document.getElementById(\"fl\").querySelectorAll(\".fcard\");for(var i=0;i<cs.length;i++){var c=cs[i];if(selF[c.getAttribute(\"data-id\")])c.classList.add(\"sel\");c.onclick=function(e){if(e.target.closest(\"button\")||e.target.closest(\"a\"))return;var fid=this.getAttribute(\"data-id\");toggleCard(this,selF,fid,function(){return 1;});updSelF();};}updSelF();}\nfunction clearSel(cls,map,upd){selU=cls===\"u\"?{}:selU;selF=cls===\"f\"?{}:selF;selB=cls===\"b\"?{}:selB;var cs=document.querySelectorAll(cls===\"u\"?\".ucard\":cls===\"f\"?\".fcard\":\".bcard\");for(var i=0;i<cs.length;i++)cs[i].classList.remove(\"sel\");upd();}\nasync function postJ(p,b){var r=await fetch(p+\"?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify(b)});return r.json();}\ndocument.getElementById(\"bSelU\").onclick=function(){var cs=document.getElementById(\"ul\").querySelectorAll(\".ucard\");selU={};for(var i=0;i<cs.length;i++){cs[i].classList.add(\"sel\");var u=cs[i].getAttribute(\"data-u\");selU[u]={ip:cs[i].getAttribute(\"data-ip\"),dev:cs[i].getAttribute(\"data-dev\")};}updSelU();};\ndocument.getElementById(\"bCanU\").onclick=function(){clearSel(\"u\",selU,updSelU);};\ndocument.getElementById(\"bDelU\").onclick=async function(){var us=Object.keys(selU);if(!us.length){alert(\"请先点选用户卡片\");return;}if(!confirm(\"删除 \"+us.length+\" 个用户及所有记录？不可恢复！\"))return;var j=await postJ(\"/api/admin/delete-user\",{users:us});if(j.ok){selU={};doLogin();}else alert(j.error||\"失败\");};\ndocument.getElementById(\"bBlkU\").onclick=async function(){var us=Object.keys(selU),items=[];for(var i=0;i<us.length;i++){var x=selU[us[i]];if(x.ip)items.push({type:\"ip\",value:x.ip,username:us[i]});if(x.dev)items.push({type:\"device\",value:x.dev,username:us[i]});}if(!us.length){alert(\"请先点选用户卡片\");return;}var reason=prompt(\"拉黑 \"+us.length+\" 个用户的理由（可空）:\",\"\");if(reason===null)return;reason=reason.trim().slice(0,100);for(var ri=0;ri<items.length;ri++)items[ri].reason=reason;if(!items.length){alert(\"所选用户无IP/设备记录\");return;}var j=await postJ(\"/api/admin/blacklist\",{items:items});if(j.ok){loadBlacklist();alert(\"已拉黑\");}else alert(j.error||\"失败\");};\ndocument.getElementById(\"bDelBlkU\").onclick=async function(){var us=Object.keys(selU),items=[];for(var i=0;i<us.length;i++){var x=selU[us[i]];if(x.ip)items.push({type:\"ip\",value:x.ip,username:us[i]});if(x.dev)items.push({type:\"device\",value:x.dev,username:us[i]});}if(!us.length){alert(\"请先点选用户卡片\");return;}var reason2=prompt(\"删除并拉黑 \"+us.length+\" 个用户的理由（可空）:\",\"\");if(reason2===null)return;reason2=reason2.trim().slice(0,100);for(var rj=0;rj<items.length;rj++)items[rj].reason=reason2;if(!confirm(\"删除并拉黑 \"+us.length+\" 个用户？不可恢复！\"))return;if(items.length)await postJ(\"/api/admin/blacklist\",{items:items});var j=await postJ(\"/api/admin/delete-user\",{users:us});if(j.ok){selU={};doLogin();}else alert(j.error||\"失败\");};\ndocument.getElementById(\"bSelF\").onclick=function(){var cs=document.getElementById(\"fl\").querySelectorAll(\".fcard\");selF={};for(var i=0;i<cs.length;i++){cs[i].classList.add(\"sel\");selF[cs[i].getAttribute(\"data-id\")]=1;}updSelF();};\ndocument.getElementById(\"bCanF\").onclick=function(){clearSel(\"f\",selF,updSelF);};\ndocument.getElementById(\"bDelF\").onclick=async function(){var ids=Object.keys(selF);if(!ids.length){alert(\"请先点选反馈卡片\");return;}if(!confirm(\"删除 \"+ids.length+\" 条反馈（含附件）？不可恢复！\"))return;var r=await fetch(\"/api/admin/feedbacks?key=\"+encodeURIComponent(K),{method:\"DELETE\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({ids:ids})});var j=await r.json();if(j.ok){selF={};document.getElementById(\"fbBtn\").click();}else alert(j.error||\"失败\");};\ndocument.getElementById(\"bSelB\").onclick=function(){var cs=document.getElementById(\"bl\").querySelectorAll(\".bcard\");selB={};for(var i=0;i<cs.length;i++){cs[i].classList.add(\"sel\");selB[cs[i].getAttribute(\"data-t\")+\":\"+cs[i].getAttribute(\"data-v\")]={t:cs[i].getAttribute(\"data-t\"),v:cs[i].getAttribute(\"data-v\")};}updSelB();};\ndocument.getElementById(\"bCanB\").onclick=function(){clearSel(\"b\",selB,updSelB);};\ndocument.getElementById(\"bUnbB\").onclick=async function(){var ks=Object.keys(selB);if(!ks.length){alert(\"请先点选\");return;}if(!confirm(\"解除 \"+ks.length+\" 条拉黑？\"))return;var items=[];for(var i=0;i<ks.length;i++)items.push(selB[ks[i]]);var r=await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K),{method:\"DELETE\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({items:items})});var j=await r.json();if(j.ok){selB={};loadBlacklist();}else alert(j.error||\"失败\");};document.getElementById(\"ki\").addEventListener(\"keydown\",function(e){if(e.key===\"Enter\")doLogin();});function copyFbText(i){\nvar fbs=window._fbs||[];var f=fbs[i];if(!f)return;\nvar txt=f.text||\"\";\nfunction ok(){alert(\"已复制\"); }\nfunction fb(){\nvar ta=document.createElement(\"textarea\");ta.value=txt;\nta.style.position=\"fixed\";ta.style.opacity=\"0\";\ndocument.body.appendChild(ta);ta.select();\ntry{document.execCommand(\"copy\");ok();}catch(e){alert(\"复制失败\");}\nta.remove();\n}\nif(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(ok,fb);}else{fb();}\n}\nasync function saveFbFile(url,name){\ntry{\nvar r=await fetch(url);if(!r.ok)throw 0;\nvar b=await r.blob();\nvar ou=URL.createObjectURL(b);\nvar a=document.createElement(\"a\");a.href=ou;a.download=name||\"file\";\ndocument.body.appendChild(a);a.click();\nsetTimeout(function(){URL.revokeObjectURL(ou);a.remove();},4000);\n}catch(e){alert(\"保存失败，可长按附件手动保存\");}\n}\nfunction showFbFiles(i){\nvar fbs=window._fbs||[];var f=fbs[i];if(!f||!f.files||!f.files.length)return;\nvar el=document.getElementById(\"fbf\"+i);\nif(el.style.display!==\"none\"){el.style.display=\"none\";return;}\nvar h=\"\";\nfor(var k=0;k<f.files.length;k++){\nvar fl=f.files[k];\nvar url=\"/api/admin/feedback-file?key=\"+encodeURIComponent(K)+\"&k=\"+encodeURIComponent(fl.key);\nvar nm=esc(fl.name||\"附件\");\nif((fl.type||\"\").indexOf(\"image/\")===0){\nh+='<div style=\"margin-bottom:8px\"><img src=\"'+url+'\" style=\"max-width:100%;border-radius:8px\"><br><button class=\"bv\" style=\"padding:4px 10px;font-size:12px\" onclick=\"saveFbFile(\\''+url+'\\',\\''+nm.replace(/'/g,\"\")+'\\')\">保存图片</button> <a href=\"'+url+'\" target=\"_blank\" class=\"blue\">'+nm+'</a></div>';\n}else if((fl.type||\"\").indexOf(\"video/\")===0){\nh+='<div style=\"margin-bottom:8px\"><video src=\"'+url+'\" controls style=\"max-width:100%;border-radius:8px\"></video><br><button class=\"bv\" style=\"padding:4px 10px;font-size:12px\" onclick=\"saveFbFile(\\''+url+'\\',\\''+nm.replace(/'/g,\"\")+'\\')\">保存视频</button> <span class=\"sm\">'+nm+'</span></div>';\n}else{\nh+='<div><a href=\"'+url+'\" target=\"_blank\" class=\"blue\">附件: '+nm+'</a></div>';\n}\n}\nel.innerHTML=h;el.style.display=\"block\";\n}\ndocument.getElementById(\"fbBtn\").onclick=async function(){var _fs=document.getElementById(\"fbSite\");var _sv=_fs?_fs.value:\"[DeepSeek站]\";var j=await api(\"/api/admin/feedbacks?site=\"+encodeURIComponent(_sv));if(!j.ok){alert(\"失败\");return;}window._fbs=j.feedbacks;var h=\"\";if(!j.feedbacks.length)h='<div class=\"card\">暂无反馈</div>';for(var i=0;i<j.feedbacks.length;i++){var f=j.feedbacks[i];var txt=esc(f.text).replace(/\\n/g,\"<br>\");var short=txt.length>150;h+='<div class=\"card fcard\" data-id=\"'+f.id+'\"><div class=\"fb-txt'+(short?\" clamp\":\"\")+'\" id=\"fbt'+i+'\">'+txt+'</div>'+(short?'<a href=\"javascript:void(0)\" onclick=\"var e=document.getElementById(\\'fbt'+i+'\\');e.classList.toggle(\\'clamp\\');this.textContent=e.classList.contains(\\'clamp\\')?\\'展开全文\\':\\'收起\\'\" style=\"color:#4a9eff;font-size:12px\">展开全文</a>':\"\")+'<div class=\"sm\" style=\"margin-top:6px\">'+fmtT(f.t)+' | '+esc(f.ip||\"--\")+(f.contact?\" | \"+esc(f.contact):\"\")+' <button class=\"bv\" style=\"padding:4px 10px;font-size:12px\" onclick=\"copyFbText('+i+')\">复制文本</button>'+(f.files&&f.files.length?\" | \"+f.files.length+\"个附件 <button class=\\\"bv\\\" style=\\\"padding:4px 10px;font-size:12px\\\" onclick=\\\"showFbFiles(\"+i+\")\\\">查看</button>\":\"\")+'</div><div id=\"fbf'+i+'\" style=\"display:none;margin-top:8px\"></div></div>';}document.getElementById(\"fl\").innerHTML=h;bindSelF();};try{var _km=/[?&]key=([^&]+)/.exec(location.search);if(_km){document.getElementById(\"ki\").value=decodeURIComponent(_km[1]);doLogin();}}catch(_ke){}</script></body></html>\n";
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
function adminAuth(request, env){
  const key = (env.FEEDBACK_ADMIN_KEY || '').trim();
  if (!key) return false;
  const url = new URL(request.url);
  return url.searchParams.get('key') === key;
}
const DEFAULT_PRICING = { flash_in: 1, flash_out: 4, pro_in: 3, pro_out: 6 };
async function getPricing(env){
  try {
    const v = await env.FEEDBACK_KV.get('pricing');
    if (v) return Object.assign({}, DEFAULT_PRICING, JSON.parse(v));
  } catch(e){}
  return Object.assign({}, DEFAULT_PRICING);
}
function calcCost(tok, pricing){
  let cost = 0;
  const ms = (tok && tok.models) || {};
  const fm = ms['deepseek-v4-flash'] || { p: 0, c: 0 };
  const pm = ms['deepseek-v4-pro'] || { p: 0, c: 0 };
  cost += (fm.p / 1e6) * pricing.flash_in + (fm.c / 1e6) * pricing.flash_out;
  cost += (pm.p / 1e6) * pricing.pro_in + (pm.c / 1e6) * pricing.pro_out;
  const leg = (tok && tok.legacy) || tok || { p: 0, c: 0 };
  cost += ((leg.p || 0) / 1e6) * pricing.flash_in + ((leg.c || 0) / 1e6) * pricing.flash_out;
  return cost;
}
async function handleAdminPricing(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  if (request.method === 'GET') return json({ ok: true, pricing: await getPricing(env) });
  if (request.method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
    const num = function(v){ const n = parseFloat(v); return (isFinite(n) && n >= 0) ? n : 0; };
    const pr = { flash_in: num(body.flash_in), flash_out: num(body.flash_out), pro_in: num(body.pro_in), pro_out: num(body.pro_out) };
    try { await env.FEEDBACK_KV.put('pricing', JSON.stringify(pr)); }
    catch(e){ return json({ ok: false, error: '保存失败' }, 500); }
    return json({ ok: true, pricing: pr });
  }
  return json({ ok: false, error: '方法错误' }, 405);
}
async function handleAdminUsers(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const pricing = await getPricing(env);
  const out = [];
  try {
    let cursor = undefined;
    do {
      const res = await kv.list({ prefix: 'user_', cursor });
      for (const k of res.keys) {
        const uname = k.name.slice(5);
        let convCount = 0, lastT = 0;
        try {
          const raw = await kv.get('convs_' + uname);
          if (raw) { const l = JSON.parse(raw); if (Array.isArray(l)) { convCount = l.length; for (const c of l) if (c.t > lastT) lastT = c.t; } }
        } catch(e){}
        let regIp2='', lm='', tk=null, dev='';
        try { const ur=await kv.get(k.name); if(ur) { const uo=JSON.parse(ur); regIp2=uo.ip||''; dev=uo.dev||''; } } catch(e){}
        try { lm=await kv.get('umodel_'+uname)||''; } catch(e){}
        try { const tr=await kv.get('tokens_'+uname); if(tr) tk=JSON.parse(tr); } catch(e){}
        out.push({ username: uname, convs: convCount, ip: regIp2, model: lm, lastT: lastT, cost: calcCost(tk, pricing), dev: dev });
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
async function deleteUserData(kv, uname){
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
}
async function handleAdminDeleteUser(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
  const kv = env.FEEDBACK_KV;
  let unames = [];
  if (Array.isArray(body.users)) {
    for (const u of body.users.slice(0,100)) {
      const uname = String(u || '').toLowerCase();
      if (/^[a-z]{1,8}$/.test(uname)) unames.push(uname);
    }
  } else {
    const uname = String(body.user || '').toLowerCase();
    if (!/^[a-z]{1,8}$/.test(uname)) return json({ ok: false, error: '参数错误' }, 400);
    unames = [uname];
  }
  for (const u of unames) await deleteUserData(kv, u);
  return json({ ok: true, deleted: unames.length });
}

// ---------- DeepSeek 聊天代理 ----------
// ---------- DeepSeek 聊天代理 ----------

async function handleChat(request, env) {
 try {
  const bl = await isBlacklisted(request, env);
  if (bl) return json({ ok: false, error: blackMsg(bl) }, 403);
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '请先登录' }, 401);
  {
    const ban = await checkBan(username, env);
    if (ban) return json({ ok: false, error: banMsg(ban) }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }

  // 每次发送都要 Turnstile 验证（无发送冷却）
  const kv = env.FEEDBACK_KV;
  const tsToken = String(body.turnstile || '').trim();
  if (env.TURNSTILE_SECRET_KEY) {
    if (!tsToken) return json({ ok: false, error: '请先完成人机验证' }, 400);
    const ip = request.headers.get('cf-connecting-ip') || '';
    const tsOk = await verifyTurnstile(tsToken, env.TURNSTILE_SECRET_KEY, ip);
    if (!tsOk) return json({ ok: false, error: '人机验证失败，请重试' }, 400);
  }
  const apiKey = (env.DEEPSEEK_API_KEY || '').trim();
  if (!apiKey) return json({ ok: false, error: '未配置 DeepSeek API Key：请在 Cloudflare Pages → Settings → Environment variables 添加 DEEPSEEK_API_KEY（重新部署后生效）' }, 500);
  // 推理等级：off→Flash真·不思考；low/high/max→Pro+对应强度；不带effort的旧版前端按model走
  const eff = body.effort;
  let model = 'deepseek-v4-flash';
  let thinking = { type: 'enabled' };
  let reasoningEffort = null;
  if (eff === 'off' || eff === 'low' || eff === 'high' || eff === 'max') {
    if (eff === 'off') { model = 'deepseek-v4-flash'; thinking = { type: 'disabled' }; }
    else { model = 'deepseek-v4-pro'; thinking = { type: 'enabled' }; reasoningEffort = eff; }
  } else {
    model = body.model === 'deepseek-v4-pro' ? 'deepseek-v4-pro' : 'deepseek-v4-flash';
  }
  try { if (kv) await kv.put('umodel_' + username, model, { expirationTtl: 90*24*3600 }); } catch(e){}
  const messages = Array.isArray(body.messages) ? body.messages.slice(-30) : [];
  if (!messages.length || !messages.some(function(m){ return m.role === 'user'; }))
    return json({ ok: false, error: '消息为空' }, 400);
  // 敏感词检测：只查最新一条用户消息原文（联网搜索结果注入前）
  {
    let lastText = '';
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i] && messages[i].role === 'user') {
        const c = messages[i].content;
        if (typeof c === 'string') lastText = c;
        else if (Array.isArray(c)) lastText = c.filter(function (pt) { return pt && pt.type === 'text'; }).map(function (pt) { return pt.text || ''; }).join('\n');
        break;
      }
    }
    if (brakeHasSensitive(lastText)) return json({ ok: false, error: '消息包含敏感词，请修改后重试' }, 400);
  }
  // 联网搜索：用 Brave Search 搜最新信息，注入到最后一条用户消息
  if (body.websearch === true) {
    const tavilyKey = (env.TAVILY_API_KEY || '').trim();
    if (!tavilyKey) return json({ ok: false, error: '联网搜索未配置：请在 Cloudflare Pages → Settings → Environment variables 添加 TAVILY_API_KEY（去 tavily.com 免费注册，每月1000次免费）' }, 500);
    let q = '';
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === 'user') {
        const c = messages[i].content;
        q = Array.isArray(c) ? c.filter(function(p){return p.type==='text';}).map(function(p){return p.text;}).join(' ') : String(c || '');
        break;
      }
    }
    q = q.trim().slice(0, 300);
    if (!q) return json({ ok: false, error: '消息为空' }, 400);
    const sr = await tavilySearch(q, tavilyKey);
    if (!sr) return json({ ok: false, error: '联网搜索失败，请稍后重试' }, 502);
    const today = new Date().toISOString().slice(0, 10);
    const ctx = '\n\n【联网搜索结果（' + today + '）】\n' + sr + '\n【要求】请结合以上最新搜索结果回答用户问题，引用信息时标注来源序号。';
    const lastUser = messages[messages.length - 1];
    if (Array.isArray(lastUser.content)) {
      lastUser.content.push({ type: 'text', text: ctx });
    } else {
      lastUser.content = String(lastUser.content || '') + ctx;
    }
  }
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
  // 预设系统提示词（后台可配，所有对话生效）
  let sysPrompt = '';
  try { sysPrompt = (await kv.get('sysprompt') || '').trim().slice(0, 4000); } catch(e){}
  const finalMessages = sysPrompt ? [{ role: 'system', content: sysPrompt }].concat(clean) : clean;

  try {
    const dsBody = { model, messages: finalMessages, stream: true, stream_options: { include_usage: true }, thinking };
    if (reasoningEffort) dsBody.reasoning_effort = reasoningEffort;
    const r = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify(dsBody),
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
    // 截获 usage 统计 token
    const kv2 = env.FEEDBACK_KV;
    const uname2 = username;
    let buf = '';
    const ts = new TransformStream({
      transform(chunk, ctrl) {
        ctrl.enqueue(chunk);
        try {
          buf += new TextDecoder().decode(chunk);
          const lines = buf.split('\n');
          buf = lines.pop() || '';
          for (const ln of lines) {
            const t = ln.trim();
            if (t.startsWith('data:') && t !== 'data: [DONE]') {
              try {
                const j = JSON.parse(t.slice(5).trim());
                if (j.usage && j.usage.total_tokens) {
                  const pt = j.usage.prompt_tokens || 0, ct2 = j.usage.completion_tokens || 0;
                  if (kv2) {
                    kv2.get('tokens_' + uname2).then(function(v){
                      let o = null;
                      try { if (v) o = JSON.parse(v); } catch(e){}
                      if (!o || !o.models) {
                        const leg = (o && typeof o.p === 'number') ? { p: o.p || 0, c: o.c || 0, t: o.t || 0 } : { p: 0, c: 0, t: 0 };
                        o = { models: {}, legacy: leg };
                      }
                      const mm = o.models[model] || (o.models[model] = { p: 0, c: 0, t: 0 });
                      mm.p += pt; mm.c += ct2; mm.t += (pt + ct2);
                      kv2.put('tokens_' + uname2, JSON.stringify(o)).catch(function(){});
                    }).catch(function(){});
                  }
                }
              } catch(e){}
            }
          }
        } catch(e){}
      }
    });
    const piped = r.body.pipeThrough(ts);
    return new Response(piped, {
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

// ---------- 刹车站昵称敏感词检测 ----------
// 词库来源：https://github.com/geektiger/sensitive-stop-words（Apache-2.0）
// 词库经人工筛选去误伤：色情/政治/涉枪涉爆/广告 + 辱骂脏话（konsheng/Sensitive-lexicon, MIT）
const BRAKE_SENSITIVE_WORDS = "08xz\n08宪\n13亿傻逼纳税人\n17da\n18禁\n198964\n20和谐年\n2o年\n3P\n4事件\n4风\n5月35\n5毛党\n64式手枪出售\n64惨案\n64时期\n64运动\n6位qq\n7大军区\n8341部队\n89年春夏之交\n8的平方事件\n92式手枪出售\n99bb\n9学\n9风\nATOM弹制造\nBT\nC4塑胶炸药\nC4炸药\nC4炸药的成分\nDIY原子弹\nDIY核弹\nJS\nLY\nQQ\nTNT 炸弹的制作\nTNT炸弹制作\nZha药制造进程\na4u\na4y\nadult\namateur\nanal\nasshole\na扁\na片\nbaodong\nbaoluan\nbaozha\nbao炸\nba课\nbbc中文网\nbitch\nbjork\nboycott\ncao你\nchinesedemocracy\ndalai\nda案\nda选\ndick\ndizhi\ndi制\ndl喇嘛\nduli\nfenlie\nfuck\nfuck your mother\ngay片\ngc党\ngfw\ngong党\ngong和\ngoogleblogger\ng产\ng匪\ng点\ng片\nhardcore\nhjt\nhmtd\nhujintao\nh动漫\nh动画\nincest\njieyan\njie严\njing坐\njzm\nlasa\nla萨\nmayingjiu\nmin主\nmorphine\nnarcotic\nnmd\nporn\nqingzhen\nrenquan\nsb国务院\nsecom\nsexinsex\nshangfang\nshit\nsm女王\ntaidu\ntaiwan\ntibet\ntmd\ntnt炸药成分\ntnt炸药配方\ntokyohot\ntwdl\ntxt下载\nwikipedia\nxiao77\nxiao平\nxing伴侣\nxizang\nxi藏\nxjp\nxuechao\nx民党\nx藏\nyin荡\nyoutube\nyouxing\nyou行\nzangdu\nzang人\nzedong\nzemin\nze东\nze民\nzf大楼\nzhadan\nzhayao\nzha弹\nzha药\nzhengfu\nzz炸弹的制作方法\nz东\n「红烧兔子」大餐\n【手枪出售】联系电话\n一ye情\n一丝不挂\n一中一台\n一党专制\n一党专政\n一党执政\n一夜情\n一夜欢\n一本道\n一百块钱的上的那个二逼\n丁一平\n丁子霖\n七个杂种开玩会\n七大军区\n万人大签名\n万人骚动\n万润南\n三个呆婊\n三个婊\n三分钟教你原子弹\n三利达弓弩专卖网\n三利达弓弩军刀\n三利达弓弩直营\n三利达弓弩配件\n三呆婊\n三棱军刺专卖\n三步倒弩箭专卖\n三步倒捕狗药\n三步倒药箭批发\n三步倒麻醉弩箭销售\n三步倒麻醉箭\n三步倒麻醉箭专卖\n三硝基甲苯\n三箭气枪出售\n三级片\n三股势力\n上中央\n上海人缺操\n上海傻逼\n上海帮\n上海逼\n上访\n下体\n下硝化甘油的制作方法\n下贱\n下载速度\n不是黑社会便是和正负官员有亲属关系的败类\n专业代理\n专业弓弩网\n专制政权\n专制走狗\n世界日报\n东北人就这操行\n东北杂种\n东北贱人\n东北逼\n东北骚逼\n东森新闻网\n东森电视\n东突厥斯坦解放组织\n东突解放组织\n丝袜\n丝诱\n两岸战争\n严家其\n个qb\n中gong\n中共\n中共任用\n中共保命\n中共党文化\n中共封网\n中共封锁\n中共就是一群王八蛋\n中共帝国\n中共帮凶\n中共恐惧\n中共政治游戏\n中共是狗屎\n中共权力斗争\n中共洗脑\n中共独裁\n中共的罪恶\n中共的血旗\n中共的走狗拼\n中共腐败\n中共裁\n中共解体\n中共近期权力斗争\n中共退党\n中共邪教\n中共邪毒素\n中共黑\n中共黑帮\n中华局域网\n中华帝国\n中华联邦\n中南海\n中国jc就是一群废物\n中国zf\n中国人是垃圾\n中国人权\n中国复兴党\n中国弓弩专卖网\n中国弓弩狩猎网\n中国弓弩直销\n中国弓弩网\n中国弓驽网\n中国弩弓专卖\n中国当局\n中国战神军用弓弩\n中国户外刀具网\n中国政府就是一坨屎\n中国政府是婊子\n中国新民党\n中国时报\n中国最垃圾的地方\n中国的官员都是人神共愤的杂种\n中国的法律他妈是个笑话\n中国的法律真他妈是个笑话\n中国的陷阱\n中央zf\n中央领导\n中年美妇\n中珙\n丹增嘉措\n主席画像\n主权\n丽女爰是个女子逼\n丽女爰是女子逼\n乖乖粉\n九学\n九风\n习sb\n习二逼\n习仲勋\n习傻逼\n习大傻逼\n习太子\n习婊\n习屌\n习明泽\n习杂种\n习汉奸\n习畜生\n习近平\n习逼格逼格\n买卖54狗\n买卖64狗\n买卖军狗\n买卖军用枪支\n买卖警察枪支\n买小车\n买春\n乱交\n乱伦\n乱伦小\n乱伦类\n乱奸\n乳交\n乳头\n乳房\n乳方\n乳沟\n乳爆\n于幼军\n互联网审查\n五毛们\n五毛党\n五毛拿钱发帖死全家\n五毛死全家\n五毛畜牲\n亚情\n亡党亡国\n亢议\n产党共\n人quan\n人体炸弹\n人体炸弹制作流程\n人兽\n人妻\n人拳\n人木又\n人渣\n人肉炸弹\n仇共\n仓井空\n他妈的\n仙鹤气枪出售\n代孕妈妈\n代开发票\n代理\n代生孩子\n代购\n令计划\n仿品军刺出售\n仿品军刺网\n仿真枪QQ\n伊力哈木\n伊斯兰\n伊斯兰畜生\n伦理大\n伦理毛\n伦理片\n伦理电影\n位的qq\n低价出售\n低制\n体位\n体奸\n何清涟\n作爱\n你他妈\n你们他妈的开始扫黄净网了\n你办事我放心\n你吗b\n你妈个烂比\n你妈妈个大雪碧\n你妈烂了\n你妈的\n你妈血比\n你妈逼拼\n你怎么用土办法做武器\n你除了会操尼玛会认贼作令尊\n你麻痹\n供产\n供应三利达弓弩麻醉箭\n供应三步倒麻醉箭\n供应军用弓弩专卖\n供应军用弩折叠弩\n供应军用手枪\n供应弓弩\n供应弓弩麻醉箭\n供应弩捕狗箭\n供应弩用麻醉箭\n供应汽枪\n供应秦氏弓弩\n供应精品弓弩\n供应钢珠弓弩\n供应麻醉箭\n供应麻醉箭三步倒\n供应麻醉箭批发\n供铲党\n供铲裆\n供铲谠\n侯德健\n保钓组织\n俞正声\n信用卡提现\n信访\n借腹生子\n做爱\n偷拍\n偷欢\n傅锐\n傻b\n傻比\n傻逼\n傻逼政府\n傻逼杂狗\n光复民国\n光腚总局去死\n免费二级域名\n免费使用\n免费索取\n免费订购热线\n党产共\n党的喉舌\n党章\n入耳关\n入联\n全国鸡婆最多\n全套\n全家不得好死\n全家死光\n全家死绝\n全职\n全裸\n全金属仿真枪专卖\n全集在线\n八九年\n公产党\n公头\n公开信\n六位qq\n六合彩\n六和谐四\n六四\n六氟化铀\n六河蟹四\n六百度四\n兰州军区\n共c党\n共x党\n共产专制\n共产主义的幽灵\n共产党\n共产王朝\n共党就是汉奸\n共匪\n共惨\n共操蛋\n共残主义\n共残党\n共残裆\n共狗\n共贪党\n共铲\n关闭所有论坛\n兵力部署\n兼值\n兼职\n兽交\n兽奸\n兽性\n兽欲\n内射\n冒泽东这个杂种\n写的炸弹制作教程\n军事社\n军刀专 卖\n军刀专卖军刺\n军刀专卖刀具批发\n军刀价格军用刀具\n军刀军刺甩棍\n军刀军品网\n军刀匕首直销网\n军刀图片砍刀\n军刀甩棍销售\n军刀电棍销售\n军刀直刀专卖\n军刀直刀军品网\n军刀直销网\n军刀网\n军刀网军刀专卖\n军刺野营砍刀出售\n军品军刺网\n军用54出售\n军用77出售\n军用刀具军品网\n军用弓弩专卖店\n军用弓弩专卖网\n军用弓弩公司\n军用弓弩批发\n军用手枪钢珠枪\n军转\n农村逼\n冷钢刀具专卖\n冷钢刀具军品网\n冷钢刀具直销网\n凌辱\n几吧\n出售54式手枪\n出售:高仿真枪\n出售M1911\n出售三棱刀\n出售仿真枪\n出售军刀\n出售军刺\n出售军刺军刀\n出售军品军刀\n出售各类猎狗\n出售国产军用54手枪\n出售外国枪模\n出售开山刀军刺\n出售弹簧刀\n出售手枪\n出售手枪 QQ\n出售手枪 电话\n出售手枪=货到付款\n出售手狗\n出售步枪\n出售气枪\n出售气枪 QQ\n出售气枪 电话\n出售气狗\n出售汽枪\n出售火枪 –游戏\n出售炸药\n出售炸药 电话\n出售炸药QQ\n出售狙击枪\n出售猎枪\n出售猎枪 QQ\n出售猎枪 电话\n出售猎狗\n出售答案\n出售美军现役军刀\n出售袖珍手枪\n出售警用手铐|仿真枪\n出售跳刀\n出售进口金属枪模\n出售雷管\n出售雷管炸药\n出售麻醉枪免收任何定金\n出现暴动\n刀具直销网\n刁sb\n刁傻逼\n刁婊子\n刁杂种\n刁王八\n刁畜生\n刁逼带着戏子环球\n列确\n刘云山\n刘奇葆\n刘宾雁\n刘少奇\n刘延东\n刘志军\n刘明康\n刘晓竹\n刘永清\n刘瑞龙\n刘翔老婆逼很宽\n则民\n刚操完你娘\n别他吗\n别梦成灰\n到货\n制作性能优良的燃烧弹\n制作火药配方\n制作炸弹首先要\n制作硝化甘油\n制作简易弓弩\n刹笔\n刺刀专卖网\n刻章办\n前凸后翘\n加盟连锁\n劣等民族\n勃朗宁军刀\n募屎淋\n包二奶\n包夜\n匕首蝴蝶甩刀专卖\n北京人欠屌\n北京傻逼\n北京军区\n北京帮\n北京当局\n北京政权\n北京逼\n北京那群傻逼\n北京风波\n北方先锋军刀\n北高联\n十7大\n十七大\n华主席\n华国\n华建敏\n华盛顿邮报\n卖64手枪\n卖92手枪\n卖逼\n卖钢珠枪QQ\n南京军区\n南京逼\n南方军刀网\n南街村\n占领台湾\n卧槽\n卧艹\n印尼事件\n印尼屠华\n历史的伤口\n厕奴\n原味内衣\n原子弹 制作方法\n原子弹DIY教程\n原子弹制作\n原子弹制作 方法\n原子弹制作手册\n原子弹制作方法\n原子弹制作方法DIY\n原子弹制造完全手册\n原子弹配方\n原音铃声\n去中央\n去你的妈的法律\n双臀\n双规\n反party\n反共\n反分裂\n发情\n发浪\n发生关系\n发生暴动\n口交\n口射\n口暴\n口活\n口淫\n口爆\n叫床\n可塑炸弹制作\n可塑炸弹制作方法\n台du\n台wan\n台军\n台完\n台弯\n台毒\n台海危机\n台海大战\n台海局势\n台海战争\n台海统一\n台海问题\n台湾共和国\n台湾国\n台湾应该独立\n台湾有权独立\n台湾版假币\n台湾独立\n台湾问题\n台独\n台百度湾\n叶剑英\n司马仿真枪模型QQ\n司马璐\n吃精\n各式气枪出售\n各种炸药配方大全\n各类军用枪\n各类军用枪支\n后庭\n后穴\n吕祖善\n吞精\n启蒙派\n吴仪\n吴官正\n吴定富\n吴胜利\n吴邦国\n吸精\n吸金逼\n吾尔\n吾尔开希\n吾尔开西\n告全国同胞书\n周小川\n周建南\n周永康\n周生贤\n呻吟\n咪咪\n品香堂\n哒赖\n哪能买到真枪\n哪里有卖双管猎\n哪里有枪出售\n哪里有气枪卖\n哪里有真枪出售\n哪里有真枪卖买\n哪里有连发猎枪买卖\n哪里有钢珠枪\n哪里能买到自制手枪\n售手枪QQ\n售枪购买手枪\n售肾\n啦撒\n啦沙\n啦萨\n喝血社会\n喷精\n四事件\n四二六社论\n四海帮\n四风\n回回\n回复可见\n回教\n回族\n回民\n回良玉\n国wu院\n国产av\n国产汽狗专卖|气枪货\n国峰\n国民党\n国锋\n国际特赦\n土g\n土共\n土炸药成份\n圣战组织\n在家里做原子弹\n在线播放\n地下钱庄\n坦克压大学生\n垃圾a股一片绿色\n垃圾共产党\n垃圾制度\n垃圾国家\n垃圾政府\n垃圾政府拼\n垃圾正奸会\n垃圾治国\n垃圾煮易核心价值观\n垃圾网易\n垃圾郭家\n城管暴力执法\n基地组织\n基本配方是硝酸甘\n塑胶炸弹\n塔利班\n境外媒体\n墓屎淋\n处男\n夏川纯\n外地傻逼\n外地逼\n多人轮\n夜勤病栋\n大sb\n大乳\n大力抽送\n大波\n大赦国际\n大连人都是大傻逼\n大陆官方\n大陆当局\n天按门\n天灭中共\n太子党\n失身粉\n奈美\n套弄\n套牌车\n奚国华\n女优\n女干你麻麻\n奶子\n奸情\n好嫩\n如何制硝化甘油\n如何自制燃烧弹\n妈了个逼\n妈逼\n妓女\n妹上门\n妹按摩\n姚依林\n威胁论\n娘西皮\n娥眉气枪出售\n婊子\n婊子养的\n婊子嫖客领潮\n婊子戏子的几日游\n婊子政府\n婊子满世界扔钱\n婴儿汤\n媚外\n嫩女\n嫩穴\n嫩逼\n子弹货到付款\n孔丹\n孙家正\n孟建柱\n学chao\n学潮\n学生妹\n学百度潮\n安徽人都是垃圾\n安徽傻逼\n安徽杂种\n安徽畜生\n安徽自古出人渣\n安徽逼崽\n安拉\n宋平顺\n完全自杀手册\n官匪\n官商勾结\n官逼民反\n审帖的这种走狗\n客服\n宪政\n宪法法院\n宪章\n家里人天天在村里吹牛逼说我\n寂寞女\n寂寞男\n密穴\n对逼进行分类\n寻找林昭的灵魂\n封从德\n封锁消息\n封面女郎\n射满他妈老比\n射爽\n射精\n射逼里\n射颜\n小xue\n小口径秃鹰沙漠\n小型弓弩专卖店\n小姐\n小泽一郎\n小猎人弓弩网\n小穴\n小逼\n小额贷款\n少修正\n少年阿宾\n尚福林\n就去日\n尼泊尔军刀出售\n屁眼\n屄痒\n屌大瓶\n屌近平\n屎坑核心\n屎进瓶\n屠光绍\n山东畜牲驴\n山东畜生\n山东逼欠插\n崩盘\n工产党\n工字汽狗麻醉枪\n工字牌气枪出售专卖\n左翼联盟\n巨乳\n巨奶\n巨屌\n希葬\n希藏\n席二逼\n帮忙点一下\n帮忙点下\n常万全\n干你\n干你女马\n干你妈\n干你娘\n干死\n干死你\n干穴\n干过你妈\n平反\n平小邓\n平近习\n幼交\n幼女\n幼男\n广东傻逼\n广东婊子\n广东杂种\n广东逼\n广告代理\n广州军区\n广西傻逼\n广西畜生\n广西逼\n应召\n底制\n廖锡龙\n开山刀砍刀出售\n开苞\n异议人士\n弄机电两代汉奸\n弓单\n弓弩一百专卖店\n弓弩专卖\n弓弩专卖店\n弓弩专卖店网\n弓弩专卖网\n弓弩专卖网货到付款\n弓弩专卖货到付款\n弓弩专营\n弓弩亲兄弟货到付款\n弓弩免定金货到付款\n弓弩制作\n弓弩商城\n弓弩商城专卖\n弓弩图纸\n弓弩批发\n弓弩有限公司\n弓弩特许经销\n弓弩狩猎网\n弓弩直销\n弓弩网\n弓弩营销中心\n弓弩论坛\n弓弩销售\n弓弩麻醉箭\n弓弩麻醉镖\n引起暴动\n张培莉\n张定发\n张德江\n张志国\n张志新\n张立昌\n张筱雨\n张荣坤\n张高丽\n弹药制造方法\n弹药配方\n强jian\n强制拆除\n强制捐款\n强卫\n强奸\n强奸处女\n强暴\n当局严密封锁\n形式主义\n彭一定被习操过\n彭二逼\n彭婊\n彭婊子\n彭氏逼\n徐才厚\n徐明\n徐绍史\n微店\n快感\n怎么用土办法做武器\n怎么自制燃烧弹\n性交\n性交图片\n性交视频\n性伙伴\n性伴侣\n性奴\n性奴集中营\n性息\n性感妖娆\n性感少\n性感诱惑\n性技巧\n性服务\n性欲\n性爱\n性福情\n性虎\n性虐\n性饥渴\n恐怖份子\n恐怖分子\n恐怖分子傻瓜手册\n恐怖分子自己制造炸弹\n恶党\n悦逼\n情色\n情趣用品\n惹火身材\n慕屎淋\n戈博军刀\n成人dv\n成人卡通\n成人图\n成人小\n成人小说\n成人文\n成人文学\n成人游戏\n成人片\n成人电\n成人电影\n成人网站\n成人聊\n成人色情\n成人视\n成人论坛\n成都军区\n我严重怀疑这个国家被汉奸和敌对势力掌控了\n我咒你全家死光光\n我就色\n我干\n我操\n我日你\n我日你娘\n我等有王八蛋进贡\n我草\n戒yan\n戒严\n战术军刀出售\n截访\n戴秉国\n户外军刀出售\n户外军刀网\n手工猎刀专卖\n手工猎刀户外刀具\n手把手教你做炸弹\n手把手教你制作原子弹\n手教你做原子弹\n手教你制作原子弹\n手枪|阻击枪\n手枪式折叠三用弩\n手枪气* 枪猎\n手柄制作炸弹引爆器\n手槍买卖自制手枪\n手淫\n扌由插\n打倒中共\n打倒中国\n打倒共产主义\n打倒共产党\n打倒朱镕\n打倒李鹏\n打倒江主席\n打倒江泽民\n打倒温家宝\n打倒罗干\n打倒胡锦涛\n打台湾\n打狗弓弩三步倒\n打砸抢\n扣扣\n找个妈妈\n找个爸爸\n技师\n抓胸\n投公\n抗议\n折刀专卖网\n折刀砍刀专卖\n折刀砍刀军品网\n折叠狗QQ\n抵zhi\n抵制\n抵制中共\n抵制共产主义\n抵制共产党\n抵制朱镕基\n抵制李鹏\n抵制江主席\n抵制江泽民\n抵制温家宝\n抵制罗干\n抵制胡锦涛\n抽一插\n抽插\n抿主\n拉sa\n拉屎\n拉萨\n拔出来\n招妓\n招聘\n招鸡\n择民\n拱铲\n拳交\n拿钱发帖的杂种们\n按摩棒\n挡中央\n捏弄\n换妻俱乐部\n推油\n揉乳\n提供专业及时的气狗\n提供气狗专卖店\n插b\n插了尼玛的逼\n插你\n插我\n插暴\n插比\n插进\n插逼\n插阴\n援交\n援助交际\n援藏\n摇头丸\n摸奶\n摸胸\n操b专车\n操他妈\n操你\n操你全家\n操你大爷\n操你妈\n操你娘\n操你祖宗\n操我\n操死\n操泽东\n操烂\n操爆你\n操着江苏无锡口音的鸟\n操纵股票\n操肛门\n操过逼\n操逼\n操黑\n擦你妈\n支持zd\n支持台湾\n收复台湾\n改卷内幕\n改革历程\n攻占台湾\n放尿\n政f\n政zhi\n政付\n政俯\n政府\n政府+傻逼\n政府+去死\n政府+垃圾\n政治风波\n政腐\n敏主\n救市\n教你制作原子弹\n教你怎么用土办法做武器\n文做\n新僵杂种\n新疆逼\n新疆骚乱\n新闻封锁\n方励之\n无修正\n无官正\n无抵押贷款\n无界浏览\n无界网络\n无码\n无耻\n日你妈\n日本万岁\n日死你妈\n日烂\n日逼\n昝爱宗\n星岛日报\n春药\n暴乳\n暴奸\n暴干\n暴淫\n曹刚川\n曾培炎\n曾宪梓\n曾庆红\n曾荫权\n曾道人\n替考试\n最新销售汽狗\n最淫官员\n有军用枪支出售\n有意者\n期出售手枪气枪猎\n木仓\n木屎林\n本世纪最大的卖国贼是蟾蜍\n本店\n朱云来\n朱容基\n朱容鸡\n朱海仑\n朱镕基\n朱镕鸡\n杀b\n杀毙\n杂种\n杂种大手一挥\n杂种天朝\n杂种拼\n权贵集团\n李peng\n李先念\n李克强\n李天羽\n李学举\n李小琳\n李小鹏\n李岚清\n李干成\n李建国\n李德生\n李春城\n李月月鸟\n李沛瑶\n李洪志\n李源潮\n李瑞环\n李荣融\n李铁映\n李长春\n李鹏\n杜世成\n杜德印\n杨思敏\n杨洁篪\n杭州傻逼\n杭州逼\n松岛枫\n极端武力军品网\n极端武力折刀\n极端武力直销网\n林左鸣\n林文漪\n林树森\n林炎志\n柳斌杰\n柴玲\n标准炸弹教程\n栗智\n校鸡\n核弹制作方法\n核弹头的制造\n核蛋\n桑拿\n档中央\n梁光烈\n楼凤\n榨干你\n欠干\n欧广源\n欲仙欲死\n欲女\n欲火\n款到发货\n正品军刺出售\n正府\n步qiang\n死全家\n死逼\n殃视\n母奸\n母屎淋\n毒豺\n毒龙\n毛zd\n毛zx\n毛人渣\n毛傻逼\n毛大畜牲\n毛大畜生\n毛太祖\n毛杂种\n毛杂种拼\n毛泽东\n毛泽东+人渣\n毛渣东畜牲\n毛灾东这个大畜牲\n毛相\n民一主\n民主女神\n民泽江\n民猪\n民珠\n民竹\n民运人士\n民进党\n气枪\n气枪/出售/专卖网\n气枪/猎枪/钢珠枪\n气枪专卖网\n气枪价格 仿真气枪\n气枪价格，气枪专卖店\n气枪仿真枪出售\n气枪猎枪麻醉枪\n气枪看货加QQ\n气枪联系QQ\n气枪货到付款,汽狗出售\n气枪购买|气枪组装\n气枪迷魂药\n气狗 高压气枪\n气狗出售 进口气狗\n氢弹手工制作方法\n水浴法制TNT\n汉人\n汉维\n江core\n江x\n江zm\n江三婊子\n江三条腿\n江丑闻\n江主席\n江书记\n江人马\n江哥\n江大王八\n江太上\n江婊\n江嫡系\n江宰民\n江家帮\n江戏子\n江某某\n江核心\n江梳头\n江毒\n江氏家族\n江氏政治委员\n江氏政治局\n江氏集团\n江汉奸\n江沢民\n江泉集团\n江泽慧\n江泽民\n江派\n江派人马\n江派和胡派\n江浙民\n江浙闽\n江独裁\n江猪\n江祸心\n江系人\n江系人马\n江绵康\n江绵恒\n江胡\n江胡内斗\n江苏杂种叫喳喳\n江蛤蟆\n江败类\n江贼\n江贼民\n江黑心\n汤加丽\n汪东兴\n汪兆钧\n汽油三分之一白糖混合\n汽狗高压汽枪\n汽车炸弹制作\n沈彤\n沈跃跃\n沈阳军区\n沐屎淋\n沙比\n河南东北畜生\n河南人傻逼\n河南人全家死光\n河南杂种\n河南畜牲\n河南逼\n河蟹社会\n油行\n法轮功\n泽d\n洋垃圾也必须扔掉\n洗屌\n洗屌不吓台\n洗屌瓶\n流淫\n流血冲突\n济南军区\n浙江傻逼\n浪叫\n浪女\n浪妇\n浪逼\n液体炸药配方\n淘宝\n淘宝气枪货到付款\n淫书\n淫乱\n淫亵\n淫兽\n淫兽学\n淫兽学园\n淫叫\n淫声浪语\n淫女\n淫妇\n淫妻\n淫威\n淫娃\n淫媚\n淫情\n淫情女\n淫教师\n淫术炼金士\n淫样\n淫母\n淫水\n淫河\n淫浪\n淫液\n淫照\n淫电影\n淫穴\n淫糜\n淫肉\n淫色\n淫荡\n淫荡照片\n淫荡美女\n淫荡自慰器\n淫荡视频\n淫虐\n淫虫\n淫贱\n淫靡\n淫騷妹\n淫魔\n淫魔舞\n混蛋\n清zhen\n清华帮\n清真\n温jb\n温jia宝\n温x\n温云松\n温加保\n温加宝\n温加饱\n温如春\n温婊家子宝\n温宝宝\n温家宝\n游xing\n游行\n湖南出了一个杂种\n湖紧掏\n湾台\n满洲第三帝国\n满狗\n漏乳\n潮吹\n潮喷\n激情\n激流中国\n火乍\n火药制作简易炸弹\n火药原理\n火药的配方\n火药配方\n灭亡中国\n灭共\n炮友\n炸dan\n炸yao\n炸弹制作\n炸弹制作从入门\n炸弹制作从入门到精\n炸弹制作入门\n炸弹制作手册 硫酸\n炸弹配方\n炸药\n炸药出售\n炸药制造生产工艺\n炸药及其制造方法\n炸药的制作\n炸药的制作配方\n炸药的成分\n炸药的配方\n炸药硝酸甘油制法\n炸药配方\n炸药配方与制作\n烂屄\n烂逼\n热武器QQ\n热比娅\n焚烧中国国旗\n焦国标\n煞笔\n煞逼\n熟女\n熟妇\n熟母\n燃烧剂的简易制作\n燃烧剂的简易制备\n燃烧弹\n燃烧弹 制作\n燃烧弹制作\n燃烧弹的制作方\n燃烧弹的制作方法\n燃烧瓶制作\n燃烧瓶的制作方法\n爆zha\n爆乳\n爆你菊\n爆操\n爆破和杀伤燃烧弹\n爆草\n爱国者同盟\n爱女人\n爱液\n爽死我了\n爽片\n特供\n特共\n特贡\n狂插\n狂操\n狗产蛋\n狗娘养\n狗屎共产党\n狗屎国家\n狗屎政府\n狗屎的天朝法律\n狗操\n狗日的\n狗日的中国社会\n狗日的五毛\n狗日的党\n狗日的共产党\n狗日的制度\n狗日的国家\n狗日的政府\n狗日的毛泽东\n狗日的社会\n狗杂种\n狗草\n狗逼政府\n狩猎器材弓弩\n狩猎器材弓弩专卖\n狩猎弓弩专卖\n狩猎弓弩专卖网\n狩猎弓弩麻醉箭\n独夫民贼\n狼友\n猎枪|真枪\n猎枪专卖店\n猎枪仿真枪QQ\n猎枪出售/枪\n猎枪哪里有卖\n猎枪子弹底火专卖\n猎枪手枪买卖\n猎枪销售手枪销售气枪\n猎枪麻醉枪钢珠枪\n猫则东\n猫泽东\n猫贼洞\n玉乳\n玉女心经\n玉穴\n玉蒲团\n王东明\n王丹\n王乐泉\n王兆国\n王八们有何事上奏\n王八朝\n王八蛋\n王八蛋政府\n王八裆\n王冶坪\n王千源\n王太华\n王学军\n王岐山\n王振华\n王沪宁\n王洛林\n王炳章\n王维林\n王胜俊\n王超华\n王鸿举\n玛雅网\n用刀横向切腹\n用火药混合塑料\n用逼\n由喜贵\n电婊\n电脑传讯\n男公关\n男奴\n畜牲大手一挥\n畜牲毛\n畜生\n畜生习近平\n畜生治国\n畜生的国度\n疆独\n症腐\n瘟假逼\n登陆台湾\n白春礼\n白痴\n皮箱炸弹\n盗撮\n直刀匕首直销网\n相奸\n真主\n真他妈\n知道64\n石肖\n砍刀精品折刀专卖\n砲友\n硒藏\n硝酸甘油\n硝酸甘油制作\n硝酸甘油炸弹制作\n硝酸甘油炸弹制作方法\n硝酸甘油炸药制作\n硝酸铵的简便制取方法\n硝铵炸药配方\n示wei\n示威\n社会主义灭亡\n私人侦探\n私家侦探\n秃鹰气枪货到付款\n秘唇\n稀藏\n穆屎林\n穆屎淋\n穆斯林\n穆罕穆德\n穆罕默德\n穴口\n穴图\n第21集团军\n答an\n简易原子弹教程\n简易大威力炸弹\n简易导弹制作\n简易核弹头的制造\n简易炸弹\n简易炸药\n简易燃烧弹\n粉碎四人帮\n粉穴\n粟戎生\n精叉都在吃屎\n精子\n精液\n精神药品\n糊屌滔爷\n紫阳\n红色贵族\n纽约时报\n组织集体\n组装手枪\n统一台湾\n维吾\n维基百科\n维权\n维汉\n网易去死\n网易我操你妈\n网特\n网络\n网络封锁\n网络工作\n网络评论员\n网评员\n网购\n罗箭\n罢ke\n罢参\n罢吃\n罢学\n罢工\n罢教\n罢考\n罢课\n罢运\n罢食\n罢餐\n罢饭\n美乳\n美国军刀出售\n美国广播公司\n美女上门\n美女写真\n美女裸体\n美少妇\n美幼\n美穴\n美腿\n美艳少妇\n美逼\n群交\n群体事件\n群体性事件\n耀邦\n老j\n老习\n老共\n老娘的巨逼\n老江\n老猫子冬是仲果的败类\n老逼\n考中答案\n聊性\n联名上书\n肉具\n肉唇\n肉棍\n肉棒\n肉欲\n肉洞\n肉穴\n肉缝\n肉茎\n肉逼\n肏你\n肏死\n肛交\n肛门\n股市圈钱\n肥逼\n肿朝isis是行畜生道\n胡boss\n胡jintao\n胡jt\n胡j涛\n胡x\n胡主席\n胡平\n胡总\n胡惊涛\n胡春华\n胡景涛\n胡派\n胡海峰\n胡海清\n胡温\n胡狗屎\n胡王八\n胡紧套\n胡紧掏\n胡锦涛\n胸推\n脑子全是被d灌的屎\n脑残zf\n脑残患儿发病\n脚交\n脱光\n脱内裤\n腐败中国\n腾讯客服电话\n臧人\n臧独\n自制手弩\n自制手枪哪里买\n自制手枪哪里有卖\n自制炸药方法\n自制炸药配方\n自制燃烧弹\n自动跳刀专卖\n自慰\n自由亚洲\n自由时报\n自由门\n舔脚\n舔阴\n舞女\n色b\n色区\n色妹妹\n色小说\n色情图片\n色情小说\n色情影片\n色情服务\n色情片\n色情电影\n色情网站\n色情表演\n色欲\n色猫\n色电影\n色界\n色盟\n色色\n色视频\n色诱\n色逼\n艳情小说\n艹你\n花花公子\n苏晓康\n苏树林\n苏贞昌\n英国金融时报\n茳泽民\n草你\n草你丫\n草你全家\n草你吗\n草你妈网易\n草泥马大勺逼\n草逼\n荡女\n荡妇\n莫洛托夫燃烧弹\n莫洛托夫鸡尾酒的配方\n菊穴\n菊花洞\n菊门\n著名精品折刀出售\n董建华\n葬独\n蒋公纪念歌\n蒋彦永\n蒋捷连\n蒙古分裂分子\n蔡武\n蔡赴朝\n薄一波\n薄熙\n薄熙来\n藏du\n藏m\n藏人\n藏妇会\n藏字石\n藏春阁\n藏暴乱\n藏毒\n藏民\n藏独\n藏独立\n藏獨\n藏西\n藏青会\n虎骑\n蚁力神\n蜜液\n蜜穴\n血书\n血洗京城\n血葫芦逼\n袁纯清\n被干\n被插\n被操\n装b\n裆中央\n裙中性运动\n裤袜\n裸体写真\n裸照\n裸聊\n裸聊网\n裸舞视\n裸陪\n裸露\n裹本\n西z\n西奘\n西点军刀网\n西点军品军刀网\n西独\n西脏\n西臧\n西葬\n西藏\n要射了\n规模冲突\n视频来源\n解决台湾\n解放tw\n解放军\n解放台湾\n警匪\n警用刀具出售\n讨伐中宣部\n讨说法\n记者无疆界\n许其亮\n访民\n证监会\n详情请进入\n诱奸\n请命\n请愿\n请点击进入\n谁是新中国\n调教\n调查婚外情\n谐星习屌\n谜奸药\n谭作人\n豪乳\n贡挡\n败类\n败类改革\n质押贷款\n贪污腐败\n购买枪支QQ\n购买自爆材料\n贰拾周年\n贰拾年\n贱b\n贱人\n贱比\n贱货\n贵州人是杂种\n贵州穷逼\n贺卫方\n贺国强\n贺子珍\n贾庆林\n贾廷安\n资金周转\n资金短缺\n赖达\n赤裸\n赵氏弓弩专卖\n赵氏弓弩专卖店\n赵氏弓弩专卖网\n赵氏弓弩销售\n赵洪祝\n起爆器\n足交\n足球投注\n路甬祥\n转让 猎枪\n轮奸\n轮操\n轮暴\n轻型巡航导弹的制作\n辛灏年\n辛灝年\n达赖\n这群杂种每天还在控制新闻媒体\n进口气枪,气枪子弹\n进攻台湾\n连锁加盟\n迷奸\n迷奸粉\n迷奸药\n迷幻药\n迷幻藥\n迷情水\n迷情粉\n迷情药\n迷昏口\n迷昏药\n迷昏藥\n迷药\n迷藥\n迷魂药\n迷魂藥\n迷魂香\n追风弓弩麻醉箭专卖\n送qb\n选国家主席\n逼你交钱\n逼你做事\n逼养的\n逼奸\n逼死\n逼水\n逼近江泽民曾庆红\n邓xp\n邓小平\n邓晓平\n邓朴方\n邓榕\n邓王八\n邓败类\n邓质方\n邪党\n郑州弓弩专卖\n郭伯雄\n郭金龙\n酥痒\n酸甘油炸药\n醯进逼\n释欲\n里有汽枪出售\n里鹏\n野营军刀出售\n野营刀专卖\n野营刀具专卖\n野营刀具军品网\n野营开山刀军刺\n野营砍刀户外军刀\n金盾工程\n金鳞岂是池中物\n金麟岂是池中物\n针孔摄象\n钓鱼岛\n钢珠弓弩专卖店\n钢珠弓弩专卖网\n钢珠枪小口径步枪\n铁凝\n铃声\n铃木麻\n铅弹 上海工字气枪\n销售/专卖/买卖77式手枪\n销售小口径步枪\n销售气手狗\n销售热线\n销售电手狗\n销售运动步枪\n锋同志\n锡峰气枪出售\n锦涛\n长期出 售手枪\n门安天\n闹独立\n阅尼玛逼的兵\n阅逼\n阉割\n阎明复\n防卫刀具专卖\n防卫刀具军品网\n防卫刀具直销网\n防卫棍刀出售\n防卫棍刀户外刀具\n防卫甩棍出售\n防卫电棍出售\n防卫著名军刀出售\n防卫野营砍刀出售\n防身手枪QQ\n防身武器手枪\n阳具\n阳江军品军刀网\n阳江刀具专卖\n阳江刀具军品网\n阳江刀具批发网\n阳江刀具直销网\n阴b\n阴唇\n阴户\n阴核\n阴毛\n阴精\n阴茎\n阴茎助勃\n阴茎增大\n阴蒂\n阴道\n阴部\n阴间来电\n阴阜\n阻击枪/汽枪/高压气枪\n阿兰得龙野营刀具网\n阿兰德龙户外\n阿兰德龙野营刀\n阿共\n阿扁\n阿拉伯\n阿旺晋美\n阿波罗网\n陆四\n陆肆\n陈s扁\n陈一咨\n陈同海\n陈建国\n陈德铭\n陈水扁\n陈炳德\n陈绍基\n陈至立\n陈良宇\n陈随便\n限量\n陰唇\n陰戶\n陰道\n隐形耳机\n集会\n集体淫\n集合\n集团出售手枪\n集团出售手枪气枪\n集束炸弹制作\n雪山狮子旗\n雷管出售\n露b\n霸工\n霸课\n霸餐\n青天白日\n靖志远\n静zuo\n静坐\n鞑子\n韩国狗\n颜射\n颜色革命\n风月大陆\n风骚\n食屎减刑复读鸡\n食精\n马克屎\n马勒\n马屁精\n马恺\n马英九\n马飚\n驴操北京它妈的不管\n骚嘴\n骚女\n骚妇\n骚屄\n骚比\n骚水\n骚浪\n骚穴\n骚货\n骚逼\n骡屙屎\n高丽棒子\n高勤荣\n高压气枪,气枪子弹\n高压气枪|气枪货到付款\n高压气枪|电狗专卖\n高压气枪专卖店\n高压狗QQ\n高性能爆炸物质混合\n高智晟\n高清在线\n高潮\n高爆炸药基本配方\n高爆炸药的基本配方\n高自联\n魏京生\n鸡吧\n鸡奸\n鸡尾酒炸弹制作\n鸡巴\n麻将透\n麻果丸\n麻痹的\n麻醉弓弩专卖店\n麻醉弹\n麻醉枪\n麻醉枪出售可验货\n麻醉枪猎枪军用\n麻醉槍\n麻醉狗\n麻醉药\n麻醉藥\n黄丽满\n黄兴国\n黄华华\n黄敬\n黄易也开始装逼\n黄易就是典型的走狗奸臣\n黄片\n黄镇\n黑屄\n黑火药和硝酸钾农药混合\n黑火药比例\n黑火药的制作\n黑火药的成分\n黑火药的配方\n黑火药配方\n黑火药配方比例\n黑索金的制造过程\n黑逼\n默罕默德\n龙新民\n龟头08宪章\n08年的四万亿导致房地产暴涨\n09宪章\n0投资\n0风险\n1154871108\n1215出师表\n12任军长\n1314要回血汗钱\n13751893776\n13日9点定在河南省政府\n14亿乘客\n14日9点定在北京中南海\n17名律师\n187蚊你都觉得贵\n1949到1976年这27年\n1949战死\n1953年6月\n1978年\n1989\n1989.06.04\n1989.6.4\n1989天安门\n1989年4日\n1989年6月4\n1989年6月4日\n1989年春夏之交\n1989年诺贝尔和平奖\n1d专正\n1肖\n200多新疆人\n2015大猎杀\n2015年哪些高官倒下\n2015年大审判年\n2016中共崩溃\n2016年的超级大老虎\n20年前\n20年前天安门\n20年前要民主的成了\n20年清廉指数全球第178位\n219.84.8.146:82\n22日下午警方接到报警\n23宪章\n24小时上门\n25连前\n29家互联网签字画押\n2条生命\n2的3次方宪章\n2肖\n3+1+4=85月12号\n303名各界人士\n30年前要民主的成了冤鬼\n3322事件\n363847942\n3d轮盘\n3个自信\n3唑仑\n3岁看老\n3拳芬立\n3肖\n400多名指挥员\n404不让人上\n426社论\n46忘勿\n49后国耻\n49土匪进城\n49年后无中华\n4万军警护驾\n4肖\n512228\n516社论\n51刷人气外挂\n51刷人气精灵\n51小秘书\n51网阳光牧场机器人\n51群回帖赚钱\n52开希\n54.8下调到49.3\n54手枪\n5人被刑拘\n5星宏辉\n5星洪辉\n5星红辉\n5月35日\n5月三十五号\n5肖\n6.4\n6.4事件\n6.4学潮\n6.4运动\n605号决议\n60多年前\n60年练饥肠\n610不法之徒\n610不法人员\n610亲\n610公安\n610办公室\n610办头目\n610同伙\n610国保\n610基地\n610头子\n610头目\n610强化洗脑\n610恐怖\n610恐怖组\n610恶人\n610恶徒\n610恶警\n610成员\n610暴力\n610歹徒\n610洗脑\n610狂妄\n610的恶棍\n610的邪恶\n610盖世太保\n610直接干的\n610组织\n610绑架\n610请来了已经邪悟的帮教人员\n610迫害\n610邪恶\n64\n6420\n6489\n64memo\n64之前\n64之后\n64之役\n64事件\n64二十周年\n64伤残\n64动乱\n64历史\n64天安\n64天安门\n64学潮\n64学生运动\n64学运\n64屠城\n64屠夫\n64屠杀\n64平反\n64式手枪\n64手抢\n64手枪\n64政变\n64旁见\n64暴乱\n64死难\n64母亲\n64民运\n64永远的痛\n64真像\n64真相\n64纪念\n64血案\n64血腥\n64诗集\n64遇难\n64镇压\n64风波\n67式无声手枪\n69大限\n69式\n69试\n6si\n6一4\n6一一4\n6四\n6四事件\n6四学潮\n6四韵动\n6月2加2\n6月3日+北京+广场\n6月4号\n6月4日\n6月fourth\n6月上旬英雄名单\n6月二加二号\n6月份第4天\n6月飘血\n6泗\n7.20迫害\n7.5事件\n75事件\n75惨案\n7600万巨款\n77元的房租\n77元的房租负担的起吗\n77式\n77式手枪\n790415683\n7?5\n7·5事件\n7月4日0时40分去世\n7条底线\n7肖\n8.9\n84微型手枪\n89\n8963\n8964\n89之夏\n89事件\n89二十周年\n89以后无青年\n89国殇\n89天安门\n89学潮\n89年64\n89年天安门\n89年的六月是我的爱\n89暴乱\n89纪念\n89风波\n8台连线\n8月17\n8级地震无预报\n8肖\n8那年9\n9.13事件真凶\n9.1级大地震\n90减1年\n90周年病危\n90年减一年\n90年的前一年\n91宪章\n92式9mm手枪\n956660604\n97爱\n97色色\n98印尼\n98屠杀\n98排华事件\n99神油\n9平视频\n9肖\n9评\na6mm千\nak74\napec会议期间\nav女\nbao熙来\nbbgun\nbei京停尸间玻璃\nbei京太平间玻璃罩\nbet365\nbo书记\nbo熙来\nb好痒\nb嫩\nb毛全潦倒\nb痒\nb穴\ncaoni马\ncao我\ncctv不差钱\ncet4答案\ncet6\ncfx狗\ncfx皮碗\nchinackinfo\nclearwisdom.net\ncnn\ncommunistparty\ncosplay\nct汽车集团\nct透视仪\ncui情用品\ncurvybody\nc罗是不强奸过你地方\ndajiyuan\ndalailama\nda到zgg阐d\nda法好\ndcg导打\nden矮子\nd的喉舌\nepochtaiwan.net\ne光美容\ne圆传奇系统\ne夜温情\ne夜激情\ne时代兼职网\ne畅家园\ne网商务\nfa3车仑g\nfalun\nfapiao\nfa工力\nfa车仑工\nfa轮\nfl功\nfreetibet\nfree光诚\nfree陈光诚\ngamo密封圈\ngamo弹簧\ngamo皮碗\ngay\ngcd\ngcd下台\ngcd亡\ngdp是6.1\ngd不亡\ngd必亡\nghb水\nghb迷幻液\ngong.产一谠\ngong.铲谠\ngongchandang\ngongchan当\ngongchan挡\ngongchan档\ngongchan裆\ngongchan谠\ngong产dang\ngong产党\ngong产当\ngong产挡\ngong产档\ngong产裆\ngong产谠\ngong匪\ngong惨dang\ngong惨党\ngong惨当\ngong惨挡\ngong惨裆\ngong惨谠\ngong掺dang\ngong掺党\ngong掺当\ngong掺挡\ngong掺档\ngong掺裆\ngong残dang\ngong残党\ngong残当\ngong残挡\ngong残档\ngong残裆\ngong残谠\ngong铲d\ngong铲dang\ngong铲党\ngong铲当\ngong铲挡\ngong铲裆\ngong铲谠\ngooton.cn\ng产d下台\ng产g7\ng产党\ng党\ng情图片\ng情网站\ng网\nh1n1防病要诀\nhigh歌\nhomeservice\nhongzhi\nhotbody\nhu景涛\nisis+人类的希望\nisis万岁\nisis斩首一名中国人\nis万岁\nis加油\njiqingshaofu\njiqingshipin\njiu评\njj搓\njj满是伤痕\njj粗\nj吧\nj巴\nj总病危\nkb份子\nkb分子\nkb气息\nkb组织\nke不容huan\nking粉\nkq经济\nktv公主\nktv招聘\nk粉\nk药无罪\nles\nliaoliaoxing\nliu4\nliusi\nliu四\nliu泗\nls事件\nluoliao\nluo聊\nm1911\nm3a1\nmakelove\nmao僵尸\nmao厕东\nmao厕洞\nmassage\nmaya语\nmihuen药\nminghui\nminghui.org\nmi药\nmi魂药\nmkb42\nmm上门\nmm穴\nmp38\nmp3840\nmp40\nmp43\nmp44\nmycool\nmzd给废了\nm泽东\nnbqqqq.cn\no8县张\nopenminded\nordnanceband\no八宪章\no八线樟\npaltalk伺服器\npeng麻麻\npilibaoliao.4pu\nppsh41\nraidcall伺服器\nred匪\nrfa.org\nsb会\nsensual\nsex\nsexybody\nsexybottom\nsexygirl\nshenshou.org\nshentong520.cn\nsmoothskin\nsm交友\nsm图片\nsm用具\nsm用品\nsm电击器\nspringof1989\ntam事件\ntam母亲\ntianandoor\ntj38朝鲜版\ntmd政府\ntui?\ntui党\ntui档\ntui谠\nufco.net\nusa人类的希望和灯塔\nveryqq.cn\nvip公主\nvoa\nwangzhuan\nwujie.net\nxing爱\nxi大大\nx伴侣\nx教组织\nyaosp.cn\nyhkfz.cn\nyindi\nyinshui\nyin道\nyin部\ny户\ny茎\nzen1shan2ren3\nzenshanren\nzg是一个法制国家\nzg特色\nzhengjian.org\nzhong共\nzj50.cn\n①肖\n②肖\n③肖\n④肖\n⑤肖\n⑥肖\n⑦肖\n⑧肖\n⑨肖\n⒍4学潮\n一9捌9\n一9键j退i出x谠y团5队\n一d专正\n一d专治\n一d制国\n一d执政\n一d独财\n一个大新闻\n一个好官被人民币废了\n一个好家被情人废了\n一个政权不经选举\n一个月后的黑夜\n一个民族的罪人\n一个没字\n一个耻辱的奇迹\n一个连生育都用档做主\n一主流组织\n一举消灭8000万\n一久扒久\n一人一个女学生\n一人发言\n一人超生\n一亿五千万人了\n一介农民两个儿子三个老婆\n一会五千年历史\n一会又建国几十年的\n一位主席做到天天被人唾弃\n一党\n一党执政万年红\n一党独裁\n一刀插在那女子的喉部位\n一刁列传\n一分抗日\n一切权力属于人民\n一到床上脱胸罩\n一千九百八十九年\n一只眼的石人\n一号首长\n一国一制\n一国两制最大的笑话\n一国无需两制\n一块红布\n一夜激情\n一夜爆富\n一定将杀害中国人的罪犯绳之以法\n一小撮别\n一层蒙一层层层掺水水到渠成\n一帮拿绿卡的人教你如何爱国\n一心要向里面供奉的僵尸鬼学习\n一手打苍蝇\n一挡专整\n一支想彻广场的自由之歌\n一日乾隆率人微服私访\n一旦发生重大事故\n一晚八炮\n一晚八炮不奇怪\n一晚搞个七八次\n一晚春晓数十炮\n一曰国际接轨\n一机构一证监不知谁在耍老千\n一条三八线+一弯浅海峡\n一桌盛宴\n一次全套\n一生不悔\n一盘大棋\n一票难求在于票价太低\n一等下流胚子\n一等警察赛流氓\n一群权力骗子召集一批经济骗子\n一群猛犬\n一群猛犬是城管\n一群管不住下半身的人抓卖淫嫖娼\n一群职业骗子在打击谣言\n一群贪婪无耻的土匪\n一肖\n一胖子拼命得围着粪堆拍苍蝇\n一般叫打炮\n一蚕缠\n一蛋砖制\n一裆砖制\n一路竟收保护费\n一辆49年生产的老解放牌汽车\n一辆老解放牌汽车载了好多人\n一酒捌9\n一首红歌\n一骂国民党\n丁丙诺啡\n丁磊出来验尿\n丁香五月天\n七.五事件\n七七宪章\n七七式手枪\n七个不要讲\n七个小儿逐鹿鼎\n七个底线\n七中全会\n七五事件\n七五惨案\n七五暴力\n七军区变四战区\n七号已经吹响\n七大娼萎\n七大常委\n七大流氓\n七大肠伟\n七大长老\n七日创造天朝\n七月大麻八月ting\n七条老狗\n七肖\n万万岁的什么\n万人围堵\n万人搞\n万人鼓掌\n万安公墓\n万恶的政府\n万恶的计划生育\n万民血漂\n万生速大\n万维读者\n万能钥匙\n万达帝国与四大家族\n万达没有背景\n万里尘飘\n三zuo仑\n三个代表\n三个代表拼\n三个代表无帮国\n三个学生\n三个戴表\n三中全会\n三中校长净系识抢\n三代轮盘\n三利达\n三匚八一艹刂\n三十年吹嘘了一个主义的天堂\n三十年建立了一个血腥的地狱\n三千万人齐下岗\n三去lung\n三去lungong\n三去车仑\n三去轮\n三只猫头鹰\n三和娱乐城\n三哆论\n三哥戴表\n三唑仑\n三唑化\n三国首脑去打猎\n三坐仑\n三块小表的理论\n三处大火\n三大情妇\n三大扯蛋\n三大烂妇\n三少一宽\n三年饥荒\n三战实际已经从中东开战\n三挫仑\n三方独理\n三日皿家宝\n三月没逛拉萨\n三权不分立\n三条线给习近平设局\n三棱刀\n三棱刮刀\n三民主义\n三民党\n三甲利定\n三百元今晚你千万别把我当人\n三石野爹\n三联帮\n三聚化工集团荣誉出品\n三聚氰胺里加奶粉\n三肖\n三脚蟾蜍\n三英战吕布\n三讲的稿\n三辆警车来\n三连帮\n三退保平安\n三退洪流\n三退热线\n三退破毒誓\n三陪\n三鱼比目\n上一届政府\n上任以来\n上份噐\n上分器\n上分机\n上分药水\n上半夜在赌\n上半年一人杀六警察\n上司就象阴道\n上坡下坡转弯都只用一档\n上将万连的孙子\n上届政府\n上届老贰\n上床就把你妈靠\n上日畜一头\n上海娘泡\n上海娘炮\n上海小瘪三\n上海市长\n上海房惠官\n上海滩将有大动作\n上海瘪三\n上级领导提倡的就是正确的\n上网发帖都要审查的国家\n上网文凭\n上网赚钱\n上访狗\n上门保健\n上门小姐\n上门按摩\n上门服务\n下一届政法委书记\n下一步改\n下半夜在嫖\n下半年六警察杀一人\n下岗工人八百万\n下岗工人挺难办\n下岗职工怀念毛主席\n下岗职工满街走\n下次有新歌把八荣八耻编进去\n下法轮\n下班插阴道\n下课插阴道\n下身开啤酒瓶盖\n下面夹着它\n下面的水\n不与其通婚\n不与猫匪苟同\n不予家奴\n不交钱不让出生\n不什和涛哥\n不会一连放三炮\n不会事前还吞壮阳药\n不作为奖\n不信它们是邪教徒\n不信耶稣的人会下地狱\n不做中国人\n不像负责任大国\n不分官黑勾结的官僚制度\n不判处一个死刑\n不去清真饭店吃饭\n不发不行\n不发死全家\n不吃不喝\n不呛喉\n不如反了吧\n不如被殖民强制改变来的\n不学无术擅长开会\n不少东西\n不就死了几个孩子\n不得不发\n不思四化\n不恨美国\n不想否认\n不愿跟我走的我让他跟你走\n不成却落马\n不政治\n不敢喘气\n不日是罪过\n不日麻屁为耻\n不是开窑子\n不是开赌场\n不是纸牌屋\n不是贩毒\n不朽尸王\n不朽尸王耄泽东\n不查他是公仆\n不查都是代表\n不查都是领导的脑子\n不畏强权\n不看新闻的20条理由\n不真心的请走开\n不能太cctv\n不能惹的国家\n不能说外一交\n不能说的日子\n不良少女日记\n不要到前线去充当抗日英雄\n不要战争赔款\n不要给组织丢脸\n不让换档\n不该不置私产\n不该严惩贪污\n不该冷淡亲友\n不该在列强面前骨头硬\n不该强调自力更生\n不该把工农兵捧上天\n不该抓阶级斗争\n不该政治挂帅\n不该有四大自由\n不购买清真食品\n不跟我走我就叫他们跟你走\n不辞辛劳\n不过既然这么问了\n不过是廉价劳动力\n不近平民\n不远不凸\n不闻爷儿叫春声\n与时俱尽\n与裙中同进出共性福\n与郭声琨远亲邻居有点生活过节\n专业上可圈可点之处太多\n专业代写\n专业代考\n专业办理\n专业助考\n专业坡解\n专业洗票\n专制\n专制封闭\n专制当局\n专家叫蛤蟆不叫\n专家座谈会\n专案维权\n专治乱了\n专治乱了无法治\n专用弩\n世事总有一些\n世界上万物\n世界上有三个国家\n世界人权宣言\n世界人权宣言60周年\n世界列强震惊了\n世界动乱的根源乃是鹅毛及其走\n世界大战\n世界局域网大会\n世界末日预言\n世界毒瘤\n世界第一\n世界维吾尔代表大会\n世界维吾尔大会\n世界维吾尔族人大会\n世界维吾尔青年代表大会\n世维会\n世维大会\n丙吡兰\n丙哌利定\n东亚病夫\n东亚病猪\n东伊运\n东北土狗\n东北大野驴\n东北撒比\n东北独立\n东北风情熟女之惑\n东哥你放心去吧\n东土耳其斯坦\n东山登山\n东方发出的闪电\n东方圣草\n东方闪电\n东村视频\n东海拔棒\n东突\n东突信息中心\n东突分子\n东突民族党\n东突解\n东英机生日\n东西德分开时\n丝丝诱惑\n丝情袜意\n丝袜youhuo\n丝袜you惑\n丝袜俱乐部\n丝袜按摩\n丝袜玉足\n丝袜秀\n丝袜窒息\n丝袜美腿\n丝袜诱惑\n丝袜足推\n丝足服务\n两个奶子有弹性\n两个弟弟和一个堂妹非正常死亡\n两乳之间\n两会又三\n两会新解\n两军对恃\n两大挡箭牌实为两块遮羞布\n两夫妻公款送礼\n两岸才子\n两年多的过往\n两性乐园\n两性屋\n两性淫乱\n两性狂情\n两性生活\n两性私语\n两性视频\n两次婚姻\n两湖贼匪\n两百元今晚我就是你的人\n两百名女技术强\n两腿一夹几百块\n两腿间劈了一刀\n两袖青风为耻\n两颗原子弹日德投降\n严惩贪腐\n严禁重庆人进京\n严轮字游\n个人奋斗的典范\n个人崇拜\n个农村退伍军人的下场\n丫与王益\n中gong将倒台\n中g将倒台\n中g灭亡\n中nan海\n中south海\n中亿商盟\n中公种养总书籍\n中共+倒台\n中共一党专制\n中共不亡\n中共不想说的历史\n中共不灭\n中共专制\n中共亵渎\n中共作恶\n中共党内斗争秘闻\n中共党魁\n中共利用\n中共卫队\n中共喉舌\n中共垃圾\n中共垮台\n中共头子\n中共将亡\n中共将倒台\n中共就能获救\n中共屠城\n中共当局\n中共当权\n中共必亡\n中共恶霸\n中共愚弄\n中共戕害\n中共政治分野\n中共政治迫害\n中共散毒\n中共是邪教\n中共暴力\n中共暴政\n中共未灭\n中共欺骗\n中共歪曲\n中共治下的中国\n中共治国术\n中共活摘器官\n中共流氓\n中共演戏\n中共灭口\n中共独权\n中共独枭\n中共的嘴脸\n中共的大堕落\n中共的恶戏\n中共的恶行\n中共的打手\n中共的教条\n中共的暴力\n中共的暴烈\n中共的流氓\n中共的烂疮\n中共的解体\n中共的谎言\n中共的谎话\n中共的迫害\n中共的迷魂\n中共的险恶\n中共维稳\n中共罪行\n中共自毁接班梯队\n中共装摸作样\n中共装阔\n中共谎言\n中共走狗\n中共迫害\n中共迷惑\n中共邪党\n中共邪恶\n中共邪灵\n中共镇压\n中共阴谋\n中共险恶\n中共非法\n中创互联\n中创网\n中办警卫局\n中功\n中华五千年的传统文化是太监文化\n中华复兴\n中华宝刀\n中华民国\n中华民族的希望\n中华淫民\n中南海事件\n中南海保镖\n中南海共产党在夹缝里\n中南海大总管\n中南海拼\n中南海红卡\n中南海零点计划\n中国+愚民\n中国+灭亡\n中国09年将面临更大的政治压力\n中国10亿人民的死亡\n中国10大悲情语句\n中国1978\n中国1978年以后的所谓理论\n中国1978年开始的所谓改革\n中国不存在上学难上学贵\n中国不强\n中国不强都不行\n中国之毁灭\n中国乱了\n中国人人手一枪\n中国人历来心术不正\n中国人喝牛奶结石了\n中国人就正常了\n中国人已成为地球公害和宇宙毒瘤\n中国人很能骂\n中国人必看\n中国人民党\n中国人的体质为何如此之差\n中国人真是可悲\n中国人类进步党\n中国人质被杀\n中国会有大地震\n中国元首\n中国公知派打\n中国六四真相\n中国共产党是英明的党\n中国共惨党\n中国共残党\n中国军情揭秘\n中国出了个习大大\n中国到底有没有法律\n中国卖淫合法\n中国即将灭亡\n中国反烟网\n中国反腐只是个形式\n中国反腐都是作秀\n中国只有一个邪教\n中国同胞\n中国和中华人民土匪国是两个概念\n中国四大底线已全部洞穿\n中国国家党\n中国外逃人员实况\n中国大陆无处不腐败\n中国女人坏时代\n中国奴隶\n中国嫖娼合法\n中国孩子\n中国完蛋\n中国官员喜欢作秀\n中国官方\n中国将是第二个朝鲜\n中国就是个毫无诚信的国家\n中国建国\n中国律师\n中国必乱\n中国必亡\n中国快垮了\n中国快灭亡\n中国怕美国\n中国总统\n中国政府\n中国政府拼\n中国救援队一直在路上\n中国新震荡\n中国无耻语录排行榜\n中国是一个道德沦丧的社会\n中国是不讲理\n中国是个处处谎言无耻贪婪的国家\n中国是个法制社会\n中国是法制社会\n中国最好的邻邦\n中国最强悍的陆战队\n中国最贵的商品是什么\n中国月光工人协会党\n中国有双矬子\n中国某位贪污一万亿之多\n中国梦+噩梦\n中国梦+恶梦\n中国梦+白日梦\n中国正腐\n中国民主党\n中国民主教育基金会\n中国民族社会主义工人党\n中国民运基金\n中国没救了\n中国没有任何的信仰自由\n中国没有民主\n中国没有生化部队一样\n中国法律就是一个笑话\n中国法律就是一坨\n中国法律就是个笑话\n中国法律就是笑话\n中国法律是给百姓定\n中国濒临绝种的动物清鹳\n中国灭亡\n中国版与日本版的静夜思\n中国留学生\n中国症腐\n中国的ccav\n中国的一道棋子\n中国的人格危机\n中国的十大贪官\n中国的宪法\n中国的憎恨\n中国的敌人\n中国的法律好笑\n中国的法律就是个笑\n中国的法律就是个笑话\n中国的法律就是笑话\n中国的法律特么是个笑话\n中国的法律真特么是个笑话\n中国的腐败\n中国真相基金会\n中国第一弟媳\n中国纳粹.中国的纳粹\n中国缺乏新闻自由\n中国网民党\n中国联邦主义\n中国股市胡紧套\n中国要完蛋\n中国警察就是一帮流氓\n中国警察就是一邦流氓\n中国警察最擅长于4件事\n中国走向富强的希望\n中国过度政府\n中国这样下去要亡\n中国革命党\n中国领导人\n中国领导人的子女\n中国领导人的生意与政治\n中国领导无能\n中国鬼子\n中国黄猫是全世界最无耻的民族\n中大学生报\n中央党校\n中央内斗\n中央军委\n中央发火了\n中央君萎\n中央大妓院\n中央政府的临时政府\n中央无能\n中央机关出上联\n中央特供\n中央纪律检查委员会大佬\n中央警卫团\n中央警卫局\n中央警卫局政变始末\n中央领导人之子\n中央高层\n中宣部运作\n中流砥柱\n中特\n中的班禅\n中秋节+敏感词\n中纪委黑暗的房间\n中组部长的人选\n中美互联网论坛\n中美论坛\n中苏国界东段协定\n中部偏南的海边\n中铝总经理孙兆学落马\n中间有个腐败城\n丰乳肥臀\n丰满坚挺\n丰满的双乳\n丰胸\n丰腴圆润\n丰韵少妇\n临听王\n临时性强奸\n丹凤朝阳\n为了伸张正义\n为了感谢日本人\n为人们服务+新版\n为人民服务\n为什么不带套\n为什么他们的日历上没有今天\n为什么你的制吅度会被全世界唾弃\n为什么外媒有猜测和天荆一样\n为什么封锁审核删贴\n为什么我是汉歼美豿\n为什么穷\n为什么网易上关于xi的新闻\n为什么记者采访前警察要拍他肩膀\n为保衙役之位\n为其全家脱罪\n为匪团谋利\n为哥哥服务\n为圈钱服务\n为奴65年\n为我们的子孙铺就奴役之路\n为无能的天朝感羞耻\n为有黑皮\n为毛的建国做出了不可磨灭的贡献\n为自己减罪\n为非作胡\n为鸡巴死为鸡巴奋斗一辈子\n为鸡巴生\n主席保镖\n主席是百姓之福\n主席涛公\n主席火葬场\n主席点阿扁\n主席病危\n主席的贴身保镖\n主席贴身保镖\n主席领袖群伦\n主新闻踩字就没有\n主有碧莲考斯\n主要因为蠢\n丽人己上马\n丽媛给公安部长打招呼\n举头望山月\n举杯一口干必定公安\n举着红旗反红旗\n举起伊能茎\n举阳入阴\n久战油\n义主民三\n义勇军进行曲\n义和团以及文革\n义教文集\n之毛太祖本纪\n之纳蠢辈\n之褪褪褪褪褪褪褪褪褪\n乌云部队\n乌伊会\n乌兹别克斯坦伊斯兰运动\n乌尔开希\n乌镇的维稳\n乌镇维稳\n乌鲁木齐\n乌黑阴毛两边露\n乎乃大虎也\n乐于给人做二奶\n乐众国际\n乐透码\n乔四\n乖乖把腿张开\n乘公交去高潮村办事\n乘坐砖机飞往太平洋\n乘飞机罢航了\n乙乙乙魉乙乙魉乙乙乙乙\n乙甲噻丁\n乙醚\n九.评\n九一评\n九个常委\n九二式手枪\n九十三运动\n九十减一年\n九十年前飞来祸\n九大乱象\n九大巨头\n九大长老\n九大长老的孙子\n九条老狗\n九肖\n九评\n九龙论坛\n也是团派\n习+下台\n习+两次婚姻\n习+二次婚姻\n习+大大\n习+婚姻史\n习+小团伙\n习+小圈子\n习+有几次婚姻\n习+柯小明\n习+柯零零\n习+离婚+柯小明\n习+肥+猪\n习boss\n习dada\n习jing平\n习主席上任以来的一系列举动\n习主席全国各族人民支持你\n习主席治国严治家更严的风格\n习他爸妈\n习以为常了\n习仲xun\n习党\n习参加g20\n习大包子\n习大大太英明了举双手双脚赞成\n习大大彭妈妈李岚清\n习大大接彭妈妈回家\n习大大接彭麻麻回家\n习宗书籍\n习家兄弟挑媳妇品味\n习家女人垂帘听政\n习小团伙\n习尔巴乔夫\n习就是头猪\n习就是条狗\n习巧未逢医拙手\n习应该是昏君\n习建平皇帝陛下\n习式政治\n习式讲话\n习性肠态\n习总书记\n习总的决策\n习总老江多次生死交锋\n习扛把子\n习政府\n习文练武有才干\n习日月氵\n习明泽+ab\n习明泽+黄晓明\n习明泽看上黄晓明\n习曾终有一战\n习权利大\n习条英机\n习武帝二年冬\n习武意谋反\n习氏夫妇\n习氏棋局\n习氏骗局\n习江之战\n习独裁\n习的亲信\n习的女儿\n习的新闻\n习的白日梦\n习索里尼\n习索里尼拼\n习老虎拼\n习近\n习近安\n习近平下台\n习近平不得好死\n习近平不是人\n习近平与访民对视了几秒钟\n习近平也太不是人了\n习近平二十年大战略\n习近平依赖王岐山\n习近平军委布局内幕\n习近平剥皮江泽民\n习近平危险\n习近平在危险节点上\n习近平大权麻烦多\n习近平家事\n习近平崩盘危机\n习近平布局十九大\n习近平必杀胡春华\n习近平怒斩周永康\n习近平拿下\n习近平撼动邓小平家族\n习近平改变世界\n习近平整死团派\n习近平权势升级版\n习近平权术史\n习近平江泽民新交易\n习近平清军换将行动\n习近平的政治试验\n习近平的方向\n习近平的王者霸气\n习近平美国打大老虎\n习近平自选接班人\n习近平草泥马\n习近平要动曾庆红一个亲戚\n习近平触礁\n习近平车队\n习近平选他到政法系统\n习近平透过车窗\n习近拼\n习连套餐\n习重用前秘书\n习重用同乡\n习重用同期同学\n习重用过往同事\n习镜瓶皇帝\n习阳无限好\n习魔李鬼\n习龘龘拼\n乡里干部忙赌博\n书记下台\n书记是个好书记\n买不起一辆校车\n买不起房\n买买提托乎提\n买了个三手航母\n买了器官\n买光全世界\n买卖枪支\n买器官\n买尸\n买春堂\n买的起房那是扯蛋\n买肾\n买通gov做靠山\n买通政府做靠山\n乱伦熟女\n乱华乱华乱华乱华\n乱华乱华乱华乱华坏\n乱我华夏匪患盛\n乱戴纱帽称提拔\n乱打针\n乱淫\n乳fan\n乳丰臀肥\n乳吻其阴\n乳房露在外\n乳晕\n乳球\n乳穿\n乳首\n乾坤棒\n乾隆下江南\n了了了快了了快了了了了\n了件渔袍\n争当已经把一个民族快整死\n事业象老罗一样干\n事实独立\n二+六宪章\n二乙噻丁\n二人转演员\n二元户口制度\n二六社论\n二分敷衍\n二十六年前的坦克\n二十六年前的枪声\n二十午年前\n二十周年\n二十年\n二十年前天安门\n二十年后腐败更猖\n二奶三奶他不管\n二奶上位\n二奶大奖\n二奶腐败\n二奸二假\n二姐在澳大利亚\n二战长跑冠军\n二次婚姻\n二甘醇超标\n二甲噻丁\n二的3次方宪章\n二的三次方宪章\n二老婆唱歌\n二肖\n二话不说插进来\n二龙戏珠\n云南暴乱\n云南省政府\n云南还没到呢\n互害社会\n互联网信息办\n互联网大会\n五一七宣言\n五中全会\n五中全会大决战\n五元一晚随你摸\n五六式普通弹\n五加一四\n五十六个男人一起操你娘\n五十六种精子\n五千个男人操妳m逼\n五四谈话\n五四运动\n五大常任理事国\n五大谎言\n五年一遇\n五年罢黜习近平阴谋\n五指油压\n五星宏辉\n五星洪辉\n五星红辉\n五月35\n五月三十五\n五月三十五日\n五月暴动\n五月麻古六月冰\n五牦搐生\n五百元我不管你今晚带的是不是人\n五肖\n五角狗的嘴脸\n亚太正悟网\n亚洲bt\n亚洲三大妓女\n亚洲图区\n亚洲某国\n亚洲自由之声\n亚洲色图\n亚生买买提\n亚甫泉\n亡儒林你的良心狗吃了\n亡党\n亡国之兆\n亡国前兆\n亡国的前兆\n亡必共中\n亡我之心不死\n亡易已经没有干净的地方\n亡谠\n亡道之国\n交世界上最多的税\n交合\n交奸\n交媾\n交换夫妻\n交欢\n交警同志挡天下\n交警罚款有蛮忙\n交警队站在马路吃社会\n交通警察象蚂蝗\n产傥\n产共倒打\n产谠\n产邪党\n享乐淫逸\n享年66岁\n享着败腐利益\n京城停尸间玻璃罩子\n京城血案的真相\n京要地震\n京都7位主事太监\n亮碧思\n亮穴\n亲jj\n亲吻蛋蛋\n亲在美国身在华\n亲密私聊\n亲秘私聊\n亲蛋蛋\n人为什么这么幸运呢\n人事安排\n人人人救人人救人人人人\n人人自残\n人人见官像滩泥\n人人都从后面上我\n人众人人众人人\n人体艺术\n人在云上\n人大会议结束\n人妖\n人妻小说\n人敏的挡\n人权\n人权不能完全保障\n人权保障\n人权律\n人权恶棍\n人权斗士\n人民一个清静\n人民共和国从来不是人民的\n人民共和国从来就不是人民的\n人民内情真相\n人民十四亿\n人民却喜欢毛\n人民在流泪\n人民大会堂里有人民吗\n人民大会里有人民吗\n人民尚未温加饱\n人民币废了\n人民币胜\n人民救星窑洞毛\n人民救星红烧肉\n人民教师黑社会\n人民日报日人民\n人民检查院不一定是人民\n人民的基儿\n人民的悲惨\n人民算个屁\n人民群众像羔羊\n人民群众的房子就让法院强制执行\n人民要下跪\n人民请龙哥代言中国\n人民需要反抗\n人治多于法制\n人治的社会\n人游行\n人神共愤\n人类救星数今朝\n人类癌症\n人类的毒瘤\n人类破坏力\n人肉烧烤\n人虽微胖\n人间地狱\n亻中员力爹\n亻共钅铲\n什么叫升官送呗\n什么叫政冶黑呗\n什么权利都没有\n仁和地产\n仆不怕饮\n仈氿学謿\n今上于美\n今上禧宗\n今后打炮花钱\n今年猪是疯狂的\n今年除夕为什么不放假\n今年雪灾又地震\n今日去共\n今有红星来救世\n今贼以八千万帮众\n仍张纸就打的我满脸是血\n仍然自己懵懵懂懂\n仍胸襟对枪\n从公家仓库偷了好多肉\n从寄生幸存到诡变\n从小到大没有见过一张选票\n从山上窑洞里流窜到城里\n从木耳中认识了硫酸铜\n从火腿里我们认识了敌敌畏\n从火锅里我们认识了福尔马林\n从票子到马\n从脑科学解构雨伞时代\n仕途萎靡\n他们在世界上抵抗着世界的威胁\n他们在后方窑洞和学生演员写日记\n他们在年轻的时候\n他们居然是抗日\n他们把金天屏蔽了\n他们消灭了黑社会\n他们用人民当家做主骗到国家权力\n他们的执政合法性在哪里\n他们说世界上有腥味的风带血的雨\n他们高喊反腐倡廉\n他妈的政府\n他姐癫狸第一母犬\n他拿着炝\n他的姓氏以江开头\n他跟你耍流氓\n代刻\n代办发票\n代办文凭\n代理体检\n代理发票\n代理开票\n代理票据\n代考\n代销违章\n令plan\n令匪计划\n令家兄弟与女人\n令狐计划\n令计划与郭伯雄\n令计划周永康薄熙来的女人\n令计划夫妇逃亡记\n令计划栽赃习近平\n以一党专政为耻\n以享乐淫逸为荣\n以十三亿奴役养千万猿\n以反贪的名义\n以吹啸为荣\n以多党治国为荣\n以官官相互为耻\n以尔虞我诈为荣\n以崇尚洗货为荣\n以捞取政绩为荣\n以搞反腐的名义\n以政治造假为耻\n以毫宅巨赌为荣\n以溜完想做爱为荣\n以溜点就拐为耻\n以茎制洞\n以血护法\n以财大气粗为荣\n以身护法\n以长江划界\n仲供是狗\n仲勋子夜袭山陵\n仲勋毁国体\n任于斯国\n任你淫\n任务赚钱\n任过多年公安局长\n仿牌香烟\n仿真人民币\n仿真抢\n仿真枪\n仿真烟\n仿真狗\n仿真震棒\n企业管理者\n伊吉拉特\n伊教非常低俗\n伊斯兰+毒瘤\n伊斯兰+邪教\n伊海涛\n伍猫狗全家死\n伐囵大法\n休假式治疗\n优昙婆罗圣花\n优昙婆罗花\n优秀技师\n优秀的技师\n优网\n会上床会收费\n会中国话就和你爷爷辩论\n会删除网易所有产品\n会忽悠会受贿\n会畏惧这样下去怎办\n会讨薪会下跪\n会阴\n伞下力量\n伞里伞外\n伟光正灵导\n伟光正领导\n伟哥\n伟大光荣正确的疯狗\n伟大的中国共产党必将统一全球\n伟大领袖\n伟大领袖这个野种\n伟大领袖那么风流\n传授吹萧神功\n传播与呐喊\n传播自由民主思想\n传销窝点\n伤天害理\n伦公\n伦功\n伦攻\n伪共党\n伪大的当\n伪法院\n伪科学\n伴游\n伶俩香蕉\n伸手摸姐冒毛湾\n伸缩转珠\n但人不傻\n但你可以上网评论\n但你必须尊重我的习惯\n但愿朝阳常照我土\n但闻床上男女爽歪歪\n住房环境\n住英国房\n体内一股暗流喷流通而出\n体制内的今天你沉默了\n体制是昏庸的\n体味激情童男\n体推\n体检代理\n体检枪手\n体透视镜\n何为做爱\n何烂侉子\n何谈国防\n余杰\n佛家大法\n佛恩先已预言早\n佛罗蒙香水\n作.弊.器\n作★弊★器\n作作秀骗骗善良的百姓\n作各种证\n作弊仪器\n作弊器\n作弊设备\n作恶无数\n作恶无法又无天\n作爱要从后面插\n作爱还要舌头舔\n作硝化甘\n作秀+胖子\n你三条腿还站不稳\n你不了解中国国情\n你也许不敢上街呐喊\n你买把水果刀就算凶器\n你们是个屁\n你们炕上日\n你们的二奶小蜜也很嚣张\n你们的吃喝有公款抵帐\n你们的处分不过是换个官当\n你删除的不是帖子\n你听见神的声音了吗\n你在非洲\n你多生一个\n你太奶奶英道\n你太婆英道\n你奶逼里能耍猴\n你妈b不日\n你妈了个逼\n你妈养汉真是行\n你妈卖逼上报纸\n你妈卖逼在北京\n你妈卖逼搞破鞋\n你妈卖逼能制富\n你妈卖逼行不行\n你妈啦bi\n你妈大比长肿瘤\n你妈天天去卖骚\n你妈天天让人配\n你妈奶子喂鸽子\n你妈屁眼淌月经\n你妈屁股纹朵花\n你妈性高潮\n你妈爱玩玻璃球\n你妈确实逼很紧\n你妈逼上有跟针\n你妈逼里好风流\n你妈逼里操金庸\n你妈逼里有红线\n你妈逼里点洋蜡\n你妈逼里练武功\n你妈阴蒂钓鱼\n你妹正在干死猪\n你姐逼里踢足球\n你姥逼里装铅\n你娘正在操海龟\n你就操警察他妈\n你想不交租吗\n你想不想入档\n你想分财主的东西吗\n你想发财吗\n你慰永康\n你我非不怕\n你曾陪伴着孤单的紫阳\n你母亲生蛆\n你演个jb\n你爷双腿全干瘸\n你爷太tm不是人\n你爷好象江折民\n你爸的鸡八肥\n你的爷爷茅择东也不是好货\n你的狗将咱局长的蛋子给咬下来了\n你的老婆叫野鸡\n你的胸膛\n你的西域\n你知道你们家属有多高兴吗\n你老爸当初怎么没把你射到墙上\n你能关闭所有新闻跟帖吗\n你还占我田亩\n你还拆我房屋\n你还自比雷锋\n你麻麻蓝币\n佰富国际\n佳阴\n佳静安定\n佳静安定片\n使下的有\n使出我的全柴动力\n使劲还能出骚味\n使用的统治手段\n供chandang\n供chan党\n供chan当\n供chan档\n供chan裆\n供chan谠\n供产dang\n供产主意\n供产傥\n供产党\n供产当\n供产挡\n供产档\n供产裆\n供产谠\n供傥\n供养了世界上最大的超级裆\n供厂党\n供惨dang\n供惨党\n供惨当\n供惨挡\n供惨档\n供惨裆\n供惨谠\n供掺dang\n供掺党\n供掺当\n供掺挡\n供掺档\n供掺裆\n供掺谠\n供残dang\n供残傥\n供残党\n供残挡\n供残档\n供残裆\n供残谠\n供谠\n供贪党\n供铲dang\n供铲当\n供铲挡\n供餐党\n依law至果\n依托利定\n依托尼秦\n依法治国就是个笑话\n侦探公司\n侦探器材\n侦探设备\n侯赛因江\n侵入她的西圣地\n侵略拉丁美洲\n便携系列\n促退队\n俄国人生性虚伪\n俄狗干儿子\n俄罗斯要跟世界说拜拜了\n俄罗斯轮盘\n保一次通过\n保三代富贵\n保健技师\n保先邪恶活动\n保准任职在政协\n保单仪器\n保单机\n保密渠道\n保底每天收入\n保护粤语粤港大行动\n保护郭声琨当公安部长\n保证是本人\n保过答案\n保钓\n保鲜专栏毒害世人\n信号拦截器\n信心比黄金还重要\n信接收器\n信访专班\n信马贼洗脑\n俪影蝎心\n修改宪法\n修改投注单\n修改法律\n修改注单\n修炼大法\n倍他罗定\n倒下的是临时楼\n倒习动员令\n倒了批文倒指标\n倒共救国\n倒共符号\n倒共风潮\n倒卖军火\n倒周审簿\n倒行逆施\n候德建\n借灾夸恶党\n借给我的\n借腐除异\n假公济私\n假冒香烟\n假币\n假币批发\n假庆陵拼\n假恶斗\n假烟\n假牌\n假硬币\n假钞\n假钱\n偏要推到胡\n偕花枝招展的老婆\n做ai\n做一次\n做人像吴官一样正\n做人的不如做狗的受宠\n做人的不如做狗的受宠爱\n做原子弹\n做官员的不一定是双规\n做官当道都腐败\n做官最喜得小恙\n做情爱\n做杠\n做爱不痛叫得出奇\n做爱不痛叫得奇\n做爱兴奋过度脱精而亡\n做爱夜当午\n做爱如此多招\n做爱实在真有劲\n做爱插得浅\n做爱插得浅生科学家\n做爱来啊啊叫\n做爱爽不爽\n做爱要从后面插\n做爱要带照相机\n做爱身体好\n做肛\n做要带套\n停止迫害法轮功\n健壮直男\n健慰器\n偶像的阴影\n偶可是战斗力四千万\n偶尔jz\n偶尔兼职\n偷窥软件\n偷荤2奶\n偷荤二奶\n催情水\n催情液\n催情物品\n催情用品\n催情药\n催泪枪\n催眠药\n催眠香水\n傻根把翠花取\n傻比河南\n像妓女上面老换人\n像寡妇睡觉上面没人\n像都教授\n僵尸遮民家堡\n僵贼\n僵贼民\n元亨真人\n元旦当天\n元旦没进乌鲁木齐\n兄弟二人在家打架争遗产\n兄弟全整\n兄弟数拾弒泽东\n充气人\n充气娃娃\n充气玩偶\n先帝病危\n先把我们从笼子里放出来不\n先烈纷纷\n光复中华民国\n光复华夏\n光复大陆\n光复大陆国土\n光子嫩肤\n光学真题\n光学瞄准器\n光想立马就作爱\n光腚总菊\n光腚肿菊\n光腚草拟吗啊\n光辉论\n光靛总菊\n光频溶脂\n克强经济\n免税香烟\n免责条款\n免费a片\n免费上网\n免除32个国家\n免除46个国家\n免除别人的贷款\n免除非洲债务\n兑现竞选支票\n党下台\n党中央\n党中央拼\n党亡\n党产共倒打\n党代会\n党仰荒亡殃\n党八股\n党共倒打\n党前干劲\n党匪\n党卑鄙\n党卫军\n党后萎\n党喝人血\n党国维稳第一线\n党土匪\n党在干社会\n党在搞社会\n党在玩社会\n党天外纵榨贪搞\n党太黑\n党妈妈的雨露阳光\n党就是黑社\n党徒\n党打死\n党收瓜光\n党政一家拼\n党文化制造的谎言\n党文化污染\n党是喝人血\n党校楼上吹过风\n党根本没有人权\n党欺骗\n党灭\n党灭亡\n党的官\n党的暴力\n党的暴政\n党的杀人历史\n党的流氓本性\n党的邪教\n党禁\n党继续掌权\n党蛊惑\n党走入坟墓\n党迫害\n党邪恶\n党都不会重用人才\n党震\n党风日下\n党黑\n全世界唾弃\n全国为官作风大奖赛\n全国二奶大奖赛\n全国已经19万多人控告蟾蜍\n全国车主统一鸣笛\n全套为你服务\n全套服务\n全套的服务\n全家中邪\n全家人在床上玩乱伦\n全家女人世代为娼\n全家火葬场\n全家灵车漂\n全新的赚钱方式\n全是tama黑社\n全是tama黑社会\n全村结扎\n全歼共军\n全民倒共\n全民团结争民主\n全民投票\n全民诉江\n全民起义\n全球公审\n全球公审江泽民\n全球纪念六四25周年网络大会\n全球记者招待会\n全球诉江\n全真文凭\n全能之父\n全能教申明\n全能神\n全脱舞蹈\n全裸自拍\n全裸视频\n全诳大妖\n全身油压\n全身瘦\n全部都是贪污犯\n全面把持\n八三四一部队\n八丸亣四\n八九20周年\n八九之后\n八九事件\n八九二十周年\n八九六四\n八九北京事件\n八九学生\n八九学生运动\n八九学运\n八九屠杀\n八九惨案\n八九政治\n八九政治风波\n八九暴乱\n八九柳丝\n八九民运\n八九纪念\n八九见证\n八九运动\n八九风波\n八亿人民都是批判家\n八八事件\n八八纪念日\n八八血案\n八十年代最后那一年\n八十年代邓小平\n八千万头魔鬼\n八千万支那贱民\n八国联军\n八大家族\n八尺协定\n八年抗战\n八的二次方\n八背飞凫\n八荣八耻全颠倒\n八荣八耻编成经\n八角亭新疆人打架\n八路军和新四军\n八路匪\n八路来了\n八酒六似\n公chandang\n公chan党\n公chan当\n公chan挡\n公chan档\n公chan裆\n公chan谠\n公主+哈佛\n公主+美国\n公产dang\n公产专制\n公产小丑\n公产当\n公产挡\n公产档\n公产王朝\n公产裆\n公产谠\n公仆总把主人欺\n公信洞穿\n公党执政万年红\n公共厕所的供\n公共场所敢作爱\n公共场所敢做爱\n公关小姐\n公关小姐变娘子\n公关招聘\n公务员\n公务员却在涨工资\n公务员打人\n公务员素描\n公务用枪\n公厕党\n公司丽人\n公司佳丽\n公器公用\n公娼贼裆\n公安不犯案\n公安局长\n公安恶人\n公安打死人\n公安把治安搞乱了\n公安把秩序搞乱\n公安系统大震荡\n公安经历\n公安网监\n公安部+主任\n公安部+办公厅\n公安部副部长\n公安部和习近平的冲突\n公安部就局\n公安部是在草蓿人命\n公安部长\n公安部长+公安经历\n公安部长+冤案\n公安部长+回学校学习\n公安部长+情人\n公安部长+替罪羊\n公安部长上任半年三度告急\n公安部长不宜升\n公安部长享乐\n公安部长离不开曾庆红\n公安部长谢罪自杀\n公安错打\n公审毛泽东\n公审江泽民\n公差党\n公开审理\n公开小姐\n公惨dang\n公惨主义\n公惨党\n公惨当\n公惨挡\n公惨档\n公惨裆\n公惨谠\n公排\n公掺dang\n公掺党\n公掺当\n公掺档\n公掺裆\n公掺谠\n公检法国地税\n公检法是流氓\n公款化为私票子\n公残dang\n公残党\n公残当\n公残挡\n公残档\n公残裆\n公残谠\n公民同城\n公民教育\n公狗操母狗\n公猪操母猪\n公祭六四\n公缠党\n公贪党\n公贪党万岁\n公铲dang\n公铲党\n公铲当\n公铲挡\n公铲档\n公铲裆\n公铲谠\n公颤党\n公馋党\n公鸡操母鸡\n六.四惨案\n六4\n六4事件\n六4学运\n六four\n六si\n六si死难\n六x事件\n六一○办公室\n六一一四\n六一四\n六一零办公室六一零\n六三后一天\n六九体位\n六九式\n六十六载暗夜中\n六十又四\n六十多年间竟已成禽兽之帮\n六司运动\n六合玄机\n六合皇\n六合网\n六合菜\n六合采\n六名暴恐分子\n六四20周年\n六四26周年致国内同学的公开信\n六四之后\n六四之役\n六四之殇\n六四事\n六四事件\n六四二十周年\n六四以来的中国政治思潮\n六四刽子手的辉煌人生\n六四动乱\n六四图片\n六四天安\n六四天安门\n六四始末\n六四学子爱国何罪\n六四学潮\n六四学运\n六四将至\n六四尾声\n六四屠城\n六四屠杀\n六四平反\n六四惨案\n六四掺案\n六四政变\n六四暴乱\n六四档案\n六四死难\n六四死难者\n六四母亲\n六四民运\n六四真相\n六四纪念\n六四纪念馆\n六四绝食书\n六四网络大会\n六四血案\n六四血腥\n六四诗集\n六四运动\n六四遇难\n六四镇压\n六四问答\n六四风波\n六大成绩\n六月四号\n六月四日\n六月寺号\n六月没在贵州瓮安\n六月第一个星期三\n六月联盟\n六月荷花\n六泗\n六祀事件\n六肆\n六肆余孽\n六肖\n六部口惨案\n兰州烧饼\n共+倒+台+退+防\n共.产.党\n共0产0党\n共0贪0党\n共chandang\n共chan党\n共chan当\n共chan挡\n共chan档\n共chan裆\n共chan谠\n共fei\n共一产一党\n共一党\n共不等于中\n共中灭天\n共也差不多\n共产.党\n共产dang\n共产主义+邪教\n共产主义拼\n共产主义歪理邪说\n共产党下台\n共产党不仅会偷还会\n共产党亡\n共产党倒台\n共产党屠城\n共产党必亡\n共产党快亡了\n共产党政府\n共产党无耻\n共产党是骗子\n共产党独裁\n共产党腐败\n共产党该倒台\n共产党邪教\n共产六十年\n共产当\n共产挡\n共产无赖\n共产极权\n共产档\n共产神教\n共产裆\n共产谠\n共产邪党\n共产邪恶\n共产邪教\n共产邪灵\n共党\n共党专政成兽禽\n共党倒台\n共党必亡\n共党拼\n共党是我国最大的黑社会\n共党没救了\n共党灭亡\n共党的腐败\n共党腐败\n共党要完蛋\n共军成了都市高楼里的看家狗\n共军背后偷袭国军\n共匪党\n共匪拼\n共匪邪恶政权\n共厂党\n共参党\n共同执政\n共同执政中国\n共奴\n共妻邪说\n共娼党\n共废要完\n共惨dang\n共惨党\n共惨当\n共惨挡\n共惨档\n共惨裆\n共惨谠\n共抢党\n共掺dang\n共掺党\n共掺当\n共掺挡\n共掺档\n共掺裆\n共掺谠\n共残dang\n共残当\n共残挡\n共残档\n共残谠\n共生东土\n共禅党\n共立丿尚儿\n共筑中共梦\n共蚕党\n共裆正腐\n共谗党\n共谗谠\n共贱和谐\n共踩党\n共钅产衤当\n共铲dang\n共铲党\n共铲当\n共铲挡\n共铲档\n共铲裆\n共铲谠\n共长党\n共青团也不是神马好鸟\n共非要灭亡\n共颤党\n共餐党\n共馋党\n兲朝必亡\n关押自由派\n关系密切\n关闭网易\n兴中心幼\n兴华党\n兴奋镇痛\n兴盛遍神州工厂变歌厅\n兵部侍郎也完蛋了\n其中就包括\n其双腿间缝隙的距离\n其女自幼与县令同宿\n其妻卫子夫能歌善舞\n其父统一250\n其美仁增\n养不起父母下岗\n养外国老大们\n养生会所\n养生会馆\n养身会所\n养身会馆\n兼职上门\n兼职不讲价\n兼职专职\n兼职公关\n兼职创业\n兼职女孩\n兼职女模\n兼职妹妹\n兼职少妇\n兼职服务\n兼职白领\n兼职的妹妹\n兼职美女\n兼职辣妹\n兼职靓女\n内人党\n内政三招\n内脏均被挖掉\n内蒙文革实录\n内部斗争\n再来壹炮\n再胡闹下去\n冒毛湾\n军中第一虎\n军事三招\n军事司法体制\n军事政变邓小丑\n军委多部门制\n军委改革\n军械所乐队\n军民冲突\n军民融合\n军用武器\n军痿猪席\n军的大老虎\n军警\n军警品\n军警殴打\n军警毒打\n军长发威\n军队向人民开枪\n军队国安大清洗内幕\n军队国家化\n军队屠城\n军队改革\n军队是属于某个政党\n军队有偿服务\n军队腐败\n农村腐败\n农民or农民工\n农民及农民政党是最可怕的一群人\n农民叫操比\n农民嫖妓\n农民市民股民家家难民\n农民焚烧秸秆他们不让\n冤民大同盟\n冰.麻\n冰在火上\n冰毒\n冰毒万岁\n冰毒粉\n冰火\n冰火九重\n冲击市委\n冲峰枪\n冲杯三鹿\n冲杯三鹿给谠喝\n冲浪赚钱\n冲突\n冲锋枪\n冲锋枪突突死\n准军事化的黑社会\n准备后事\n凝视着俄国人发明的镰刀斧头\n几万炮灰正步走\n几千万人\n几千万宣誓效忠的信徒\n凡凡阚凡凡阚阚阚阚阚阚凡\n凤反展翅\n凤啄水\n凤抬头\n凭六四洗脑营役\n凯托米酮\n凳+浆+糊\n出了个茅厕蹲\n出了事情有人保\n出了问题有人保\n出千技巧\n出卖大明山\n出售下列枪\n出售人民币\n出售发票\n出售处女\n出售处男\n出售枪支\n出售硬币\n出售银行卡\n出售香烟\n出国访问\n出成绩付\n出现404\n出肖\n出过轨勾引领导下过水\n出钱是恶党\n刀架保安\n刁jing\n刁jin平\n刁一不远不凹\n刁不远平\n刁丶斤辶干丶\n刁加一点不远不凸\n刁劲瓶拼\n刁多一点\n刁夫妇访美\n刁夫妇访美时候有国人拦车告御状\n刁夫妇访英\n刁夫妇访越\n刁字加一点\n刁开非死不可\n刁式幽默\n刁总书记\n刁月半子\n刁的女儿\n刁索里尼\n刁舔鹅腚\n刁辶斤一丷十\n刁远不平\n刁远并瓦\n刂刂刂刂诞刂刂诞刂刂刂\n分两炮精\n分分钟钟治你个\n分尸\n分权制衡\n分而治之\n分耲耲耲耲耲耲\n分配问题\n刑事判决荒唐案\n刑讯逼人死\n刑讯逼供办冤案\n刑责不用担\n刘世锦\n刘乐君\n刘云山曾庆红设计暗算习近平\n刘仁军\n刘婷婷\n刘少奇不抽烟\n刘晓波\n刘淑君\n刘牢出外甥\n刚出来做\n刚愎自用\n刚热\n创业团队\n创业手册\n初夜无红\n初夜无红老公闹\n删一条发一条\n判乱\n利用公款下饭店\n利用邪教吸引大家眼球\n别只顾自己饭馆就餐秀\n别忘了向历次政冶杀人运动\n别怪我搞台独\n别拿邪教说事儿\n别有用心的太阳\n别的派系\n别看我长个大肥脸\n别让台湾同胞深陷万劫不复的磨难\n刮财党\n到了东莞\n到处撒银子挥霍无度\n到处说环境差\n制作\n制作证件\n制服诱惑\n制止腐败\n制证定金\n制造那么大的冤案\n刺杀习辶\n刺杀刁辶斤平\n刺激器\n刺激套环\n刺胡事件\n前core\n前core病危\n前主席病危\n前例腺保养\n前列腺保健\n前列腺保养\n前前皇帝\n前前老大\n前妻有个儿子在美国读书\n前政治犯协会\n前朝皇帝\n前朝那九个长老\n前肖\n前门鸟进鸟出\n剩下的交给我们\n剪辑是个高人\n剿f不力\n剿共复国\n剿匪不利\n剿匪不力\n剿灭供匪\n劈开你妈两条腿\n力月西\n力骗中央\n办公厅+主任\n办各种证件\n办理各种\n办理各种证件\n办理各类证件\n办理学历\n办理文凭\n办理本科\n办理真实\n办理真实学历\n办理票据\n办理证书\n办理证件\n办理资格\n办真实学历\n办譪\n办证\n办证热线\n功chandang\n功chan当\n功chan挡\n功chan档\n功chan裆\n功chan谠\n功产dang\n功产党\n功产当\n功产挡\n功产档\n功产裆\n功产谠\n功友\n功惨dang\n功惨党\n功惨当\n功惨挡\n功惨档\n功惨裆\n功惨谠\n功掺dang\n功掺党\n功掺当\n功掺挡\n功掺档\n功掺裆\n功掺谠\n功残dang\n功残党\n功残当\n功残挡\n功残档\n功残裆\n功残谠\n功铲dang\n功铲党\n功铲当\n功铲档\n功铲裆\n功铲谠\n加分器\n加快牛肉让你搞\n加息本来无帮国\n加拿大籍\n加税救爹\n务员答案\n务员考试\n劣等民族到哪都是窝里斗\n劣等的汉族灭绝\n动乱\n动乱分子\n动乱的根源\n动物标本\n助勃\n助勃乳液\n助挺\n助考\n励志典范\n劲奸狂插\n劲得力\n劳动人民还当牛做马\n劳民伤财\n势力\n势力的狗\n势力社团\n势劦\n勃起\n勺瘨勺勺勺瘨瘨瘨瘨瘨瘨瘨勺勺\n勿忘64\n勿忘之士鲜血遍地\n勿忘八九\n勿忘六四\n勿忘阝击泗\n匀之斤平\n包你舒服\n包厢公主\n包哥哥满意\n包哥哥爽\n包子上台\n包子上市\n包子大帝\n包子战蛤蟆\n包子无能\n包子的女儿也在美国\n包子访美\n包子访英\n包干价格\n包您舒服\n包房公主\n包括误猫\n包皮\n包赢仪器\n化名也有效\n化学扫盲\n北京+胖子\n北京301医院\n北京之春\n北京事件\n北京人欠削\n北京人欠扁\n北京人欠抽\n北京人欠插\n北京停尸房\n北京公安\n北京公安内部有人狗胆包天\n北京公安局长\n北京公检法\n北京出庭\n北京副市长\n北京动乱\n北京哈巴\n北京工人自治联合会\n北京市公安局\n北京市公安局联合公开信\n北京市委\n北京市政府\n北京市长\n北京市高校学生自治联合会\n北京广场\n北京政局乱套\n北京政府\n北京整得凶了\n北京暗战\n北京独立\n北京猪猡\n北京电影学院\n北京电影学院彭妈妈\n北京电影学院彭麻麻\n北京看全国都是基层\n北京警察\n北京警察局长\n北京警方\n北京请愿\n北京频传江病危\n北京高校学生自治联合会\n北京鸡共匪畜\n北平屠城\n北海资本运作\n北电彭妈妈\n北电彭麻麻\n北省委门\n北美大湖区法会上讲法\n北美巡回讲法\n北美自由论坛\n北美讲法\n匪+共+将+倒+台\n匪gong\n匪党\n匪共灭消姓百\n匪出身的政\n匪患多灾\n匪患横行六十年\n匪警\n匹米诺定\n区乡干部忙赌博\n区的雷人\n医生心黑手辣\n医生看病\n医生见死不救\n医疗改革提前送终\n十七大幕\n十三亿中国人的一半在看着你呢\n十世班禅喇嘛传记\n十个人里九个骗\n十个江浙九个贱\n十个河南九个骗\n十个预言\n十临坛竹\n十九大七常委\n十九大三大战役\n十兄弓虽\n十八大大黑马\n十八山羊对树\n十八摸\n十几亿人口\n十几亿人都成了这个小集团的人质\n十口心思思钱思权思小蜜\n十周年\n十大元帅侍女生\n十大元帅侍妾生\n十大超富发家秘史\n十大雷人提案\n十年前就知道\n十年执政\n十操九射八式\n十景缎\n十月巨变\n十类人不\n千人成人俱乐部\n千变娱乐\n千古一帝大撒币\n千夫所指千夫所指千夫所指\n千夫所指无病自死\n千年灾星\n千年灾星毛啧栋\n千里朦胧\n卄一八匚非\n升天\n午夜激情\n半壁江山\n半壁江山藏红颜\n半夜别忘补一炮\n半根手指就塞满\n半波\n半羽浮岿+水边楼台+瓶分秋色\n半自动枪\n华为胡主席签了签名照\n华人妇女\n华南教会\n华夏民生艰\n卒于2015年1月\n单挑王\n单特\n卖b\n卖shen\n卖器官\n卖国\n卖国卖国卖国卖国\n卖地宰相\n卖地财政\n卖尸\n卖比\n卖比劈大腿\n卖淫的不一定是小姐\n卖肾\n卖逼无限红\n卖银行卡\n南京书记进北京\n南京软蛋都闭嘴\n南充事件\n南大自由论坛\n南帝薄熙来\n南方人真难看\n南方的小岛\n南方血灾和汶川地震\n南方雪灾和汶川地震\n南昌鬼子\n南望王师又一年\n南汇\n南湖+船\n南艺婊子有味道\n南荒地的姑娘操干\n博会暂停\n博园区伪\n博大书局\n博大出版社\n博客赚钱\n博彩公司\n博讯\n博讯网\n占岛为王\n占领中南海\n卡日阿吉\n卫星天线安装\n卫星定位\n卫星接收器\n卫星电视安装\n印尼共产党\n印尼华人\n印尼反华\n印尼屠杀\n印尼政府\n印尼暴乱\n印尼暴徒\n印尼杀你\n印尼猴子\n印度是个奇葩国\n印度肾疗\n危害祖国为荣\n即四反年党\n即时播报\n却在研究着你的退休\n卵巢保养\n卵蛋\n厄厄幽幽\n厅房公主\n历朝历代\n厉鬼\n压成了肉饼\n厚颜无耻地\n厞栱篨铲\n原一九五七\n原产地烟丝\n原厂丝\n原厂烟丝\n原味丝袜\n原味内裤\n原味玉足\n原子弹\n原来他更喜欢女仆\n去北朝鲜就行了\n去年土匪换班的时候我就说过\n去旅游暴乱了\n去留一念间朋友\n去眼袋\n县里干部忙吃喝\n叁退平安\n参与推墙\n参与迫害的中共\n参加者回忆录\n又是作秀到处亲密兵营\n又是河南\n又有钱贪污\n又糊又瘟\n又红又专的领路人\n又耳木卜\n又耳瘸子\n友好往来\n友朋遍布\n友赚网\n双10节\n双乳\n双凤游龙\n双大老虎\n双头\n双峰秀乳\n双胞胎在母亲肚子里聊天\n双腿叉开\n双腿间的禁地\n双飞\n双飞一次\n双飞包夜\n双龙至尊\n反gong\n反g复m\n反上10年\n反人类\n反作弊\n反党\n反党份子拼\n反公救国\n反共产\n反共复国\n反共复民\n反共复清\n反共救国\n反共热线\n反共联盟\n反华\n反华势力\n反华大暴动\n反华暴动\n反右练防骗\n反对假普选\n反对党\n反对共产党\n反对执政党就要坐牢\n反封锁\n反屏蔽\n反恐本来就是各国的较量场\n反抗共产党\n反攻大陆\n反正你横竖都是嘴\n反毛方阵\n反民众\n反汉复藏\n反测速雷\n反社会的\n反腐+作秀\n反腐+内部\n反腐+戏\n反腐+政治斗争\n反腐+洗牌\n反腐+演戏\n反腐+笑话\n反腐两年牺牲了一名上将\n反腐之际卸职惹关注\n反腐亡党\n反腐只是政治斗争\n反腐在前台\n反腐大王\n反腐才一年\n反腐背后不过是新政权的崛起罢了\n反腐败大概干不过朱元璋\n反腐败无能\n反腐败是笑谈\n反腐都是\n反腐除不尽\n反贪南征北战\n反贪方知无官正\n反贪最新动向\n反造来起家大\n反雷达测\n反革命\n反革命操丈母娘\n反革命暴乱\n发piao\n发人深省的故事\n发仑\n发伦\n发出强大正念\n发出正念\n发功\n发动文革\n发囵\n发工资都捐了\n发愣工\n发抡\n发抡功\n发正念\n发正念功法\n发沦\n发票代开\n发票代理\n发纶\n发缥\n发行自己印制的伪钞\n发言记录\n发论\n发财得行贿\n发轮\n发达国家送订单\n发骚\n叔安排侄\n取代江派色彩浓厚的现部长\n取名社会主义\n受世界上最重的剥削\n受外部势力\n受贿在后台\n变态帝制\n变成为魔鬼的帮凶\n变牌器\n变牌衣\n口及米青并瓦\n口及精并瓦\n口吹器\n口天丰阝国\n口技\n口是心非阳奉阴违\n口枷\n口沙\n口铰\n古典泰式\n古可叶\n古方迷香\n古月三昷\n古月金帛\n古月钅白巾氵寿\n古柯\n古死办劫\n古田会议\n另一个王朝\n只挣违民\n只是在做腑卧撑而已\n只是它们分属不同的pai\n只是用了一张床\n只是近黄昏\n只有中国没去\n只有美利坚才能救中国\n只要一天离不开共产主义\n只要和老百姓有关的都是恶意的\n只要组织还在\n只阚阚阚阚阚阚阚只只只只\n叫你讨债叫你上访\n叫声阿扁提防提防\n叫春声\n叫起床来像水牛\n可俺老婆还算给力\n可儿的秘密花园\n可卡因\n可叹吾草民人命比草贱\n可多克辛\n可待因\n可拉横幅于大街\n可是只有躯壳\n可笑的最新消息\n可能入局后转任人大副\n可能是哈尔滨警察\n可能是林大人\n可能是派出所\n可能没有下一个国庆了\n台下共中\n台倒谠供\n台北廖婉怡\n台湾+正统\n台湾中国的希望\n台湾大选告诉全体中国人\n台湾性虎\n台湾想要单干\n台湾放光明\n台湾政论区\n台湾最新d版\n台湾统一中国\n台湾统一大陆\n台湾自由联盟\n台湾轮盘\n台湾青年独立联盟\n台盟\n右丙氧芬\n右手拿的白奶罩\n右转是政\n右马拉胺\n叶倩彤\n号小灭公购\n号屏蔽器\n号码复制机\n号称第二聪明人种\n司司司司司司\n司机\n司法不独立\n司法独立\n司长期有\n叼包孓夶\n叼禁讠平\n吃了原告吃被告\n吃人的体制\n吃人的制度\n吃你白带\n吃喝嫖赌\n吃喝嫖赌样样都来活了103岁\n吃女婴\n吃婴\n吃饭基本靠党\n各尽所能\n各类文凭\n各类考试\n合双\n合成冰\n合数单\n合数双\n合法土匪\n合法的土匪\n吉瑟利努\n吉祥宝贝\n吉祥宝贝破解\n吊死鬼打粉插花\n同声哭泣\n同居社区\n同志交友\n同志作爱\n同志图片\n同志帅哥\n同志服务\n同志桑拿洗浴中心\n同志激情\n同志片\n同志电影\n同志网\n同志聊天室\n同志论坛\n同性恋吧\n同性服务\n名义上爱国\n名烟极品\n名烟系列批发\n名誉主席\n名誉会长\n后来乾隆驾崩\n后来武帝上台\n后肖\n后面插\n吐尔逊\n向学生开枪\n向隔壁苏大哥学的\n吗哌利定\n吗啡\n吗拉胺\n吗苯丁酯\n吗裂猪仪\n吗酰胺中间体\n君子会所\n君无戏言\n君猥副猪细\n含鸡鸡\n听二奶吟\n听天由命否极泰来\n听说三鹿奶是靖国神社指定牛奶\n听说天津网友全被屏蔽了\n启示录二千年前预言\n启靖\n吴学灿\n吴尔凯希\n吴百益\n吸大呆子\n吸毒青年和你为伍\n吸脂\n吸脂减肥\n吸舔\n吸龙珠口莎\n吹喇叭\n吹箫\n吹萧无节奏\n吾买尔江\n吾尔凯希\n吾尔开\n呆在家地震\n告别中共\n告诉你们什么是真正的卖国\n呋替定\n周yongka\n周yong康\n周师傅900亿\n周年病危\n周徐令进笼子\n周徐苏令\n周恩来只喝酒\n周恩来秽史揭秘\n周拥糠被查\n周晓春\n周永kang\n周永康令计划如何审\n周永康泄露的国家机密\n周永康狱中自辩书\n周永康自辩书真相\n周的案子\n周而复治\n周锋锁\n命根\n命运就像强奸\n命运就象强奸\n和=胡\n和你妈一起搞\n和奥巴马站在一起的大肥猪\n和她同时辞职的同事\n和尚把尼姑摁到地上强奸了尼姑\n和尚的鸡巴\n和平环境\n和平请愿\n和男晚抱\n和破四旧的宇宙裆们\n和羊有一毛钱关系吗\n和谐三年\n和谐你全家\n咖啡因\n咩龚就锅\n咱们长征的时候到过她们村\n咱们长征的时候去过她们村\n哄.铲.谠\n哄chandang\n哄chan党\n哄chan当\n哄chan挡\n哄chan裆\n哄chan谠\n哄产dang\n哄产党\n哄产当\n哄产挡\n哄产档\n哄产裆\n哄产谠\n哄惨dang\n哄惨党\n哄惨当\n哄惨挡\n哄惨裆\n哄惨谠\n哄掺dang\n哄掺党\n哄掺当\n哄掺挡\n哄掺档\n哄掺裆\n哄掺谠\n哄残dang\n哄残党\n哄残当\n哄残挡\n哄残档\n哄残裆\n哄残谠\n哄铲dang\n哄铲党\n哄铲当\n哄铲挡\n哄铲档\n哄铲裆\n哄铲谠\n哈克\n哈继铭\n哈药直销\n哌替啶\n哌替定\n哌酰胺\n哥哥光临我\n哥哥加我\n哥哥可以电话\n哥哥喜欢就电话\n哥哥您可以放心\n哥哥有诚意\n哥哥满意\n哥哥的鸡八粗又大\n哥的jj\n哪方高贵就在你的一票之间\n哪日灯头朝下时\n唆哈粉\n唐朝后面的那个朝代\n唐荆陵\n售一元硬\n售弹簧刀\n唯一影赚\n唯国人不晓\n唯有日属\n唯有鸡巴翘\n唱戏出身\n唱歌的名妓\n唱歌的妓\n唱歌老婆周游世界\n唾党妈\n商务伴游\n商务公关\n商务美女\n商务陪伴\n商务陪护\n啊厚挂了\n啊扁涛哥\n啤酒乐园\n啥叫两会\n啪啪啪啪啪\n喂奶门\n善.恶\n善恶有报\n喋血长安\n喘息\n喜欢就联系我\n喜欢我就给我电话\n喜欢我的加起\n喜欢我的朋友\n喜欢我给我打电话\n喜欢的人也会喜欢上你\n喜胖子这个杂中孙子\n喜贪赃\n喜金平拼\n喝坏党风喝坏胃\n喝我精子汤\n喝酒不用劝肯定在法院\n喝酒象喝水肯定在建委\n喷潮\n喷雾型\n喷雾迷幻\n喷雾迷昏\n喷麻麻拼\n嗑药\n嗨死总比枪毙强\n嘉兴+破船\n嘉兴南湖的游船\n嘉兴市委副书记\n嘉兴的厂停工\n嘉庆处死和珅\n嘉庆皇帝\n嘎玛巴\n嘠玛钯\n嘻弄春根\n嘿咻\n器官摘除\n器官活摘\n器宫活谪天地怒器宫活谪\n噶伦桑东\n噶玛巴\n囊帕拉\n四26社论\n四个全面\n四个国家去打\n四二二事件\n四六反平\n四六级\n四十个新疆人\n四十多个\n四处奔波\n四大怪事\n四大惹不起\n四大扯个\n四大文明古国\n四大虚\n四川独立\n四川猴子\n四川的武大郎中国人的儿子\n四川耗子\n四川阉耗子\n四意摧残\n四月二十六日社论\n四月圣火被搞怪\n四次入侵\n四海龙女\n四百元我要问问你今晚要带几个人\n四立方事件\n四维不张\n四老虎密事\n四肖\n回分器\n回大陆执政\n回封建时代\n回帖我脱给你看\n回帖脱衣给你看\n回忆六四\n回收香烟\n回民暴动\n回苹果铝当厂长吧\n因为天天可以日你\n团派的末日\n团结起来+高喊打倒\n园发生砍\n困官砸车\n围剿工匪\n围截铁路\n围攻\n围攻上海\n围殴\n围观的群众\n围观起哄\n国一九五七\n国之将亡\n国之将危\n国之将灭\n国公薄氏\n国内搜刮\n国内的禁闻\n国内说是报复社一会\n国军万岁\n国军千古\n国军威武\n国军欲血抗日\n国务院总理诸葛亮\n国务院拼\n国务院新闻办\n国嘉煮习\n国复共反\n国家150笔债务共计八百多亿\n国家不让你生的时候的\n国家主席\n国家主席李世民\n国家互联网信息办公室\n国家信访局\n国家变好\n国家吞得\n国家囚徒\n国家失踪了\n国家奴隶\n国家好不好\n国家好比汽车\n国家己经烂透\n国家必亡\n国家总掩盖真相\n国家机器\n国家没救\n国家的奴隶\n国家的钱\n国家的黑暗\n国家目前主要工作\n国家若绑架了\n国家规定+狗屁\n国家软弱\n国家领导人\n国家领导人的子女\n国将不国\n国将易主\n国已被贼窃\n国庆又是银河落九天\n国库拿来当私库\n国旗下的讲话\n国无希望\n国是谁的\n国民党反动派\n国民党打回来\n国民党来大陆统治\n国民素质太低\n国营腐败\n国防信息化\n国际声援西藏运动\n国际投注\n国际支持西藏网络\n国际西藏运动\n国际调查+记者+同盟\n国颜掉裆\n图匪本色\n图样图森破+大佬\n囿函团囿囡囚\n圆圆的潮水\n圆满\n圌圌圌圌圌圌\n土供吐肺\n土共独裁\n土制\n土匪党\n土匪当政\n土匪当时吹嘘它建政之后\n土匪控制流氓\n土匪控制社会\n土匪政权\n土匪的共产党\n土匪篡权以来\n土土土墓土土墓土土土土\n土土土崩土土崩土土土土\n圡匪治国\n圣战不息\n圣战培训班\n圣水\n圣灵向众教会说话\n圣灵所使用\n圣灵末世的工作\n在1215岁孩子书包里放安全套\n在51就不上传照片\n在~家~创~业~\n在一个批评不自由的国度里\n在中国各大城中村空投枪械\n在中国能找出个清廉的官\n在人间走天路\n在光中行走\n在唐朝就知道今年地震了\n在天巢已是癫\n在家兼职\n在家创业\n在家可以经营\n在家工作\n在家开店\n在家赚钱\n在线为您服务\n在线投注\n在线激情\n在线美女\n在线聊天\n在线赌钱\n在让别人去打\n在这里读懂中国\n在陕北老流氓\n地下先烈\n地下共党好奸诈\n地产之歌\n地产古\n地匹哌酮\n地区协调\n地县干部忙吃喝\n地域一时爽\n地平线上升起的f\n地恩丙胺\n地方势力\n地方政府蛮干\n地球未来的预言\n地球漫游\n地磅无线遥控\n地美庚醇\n地芬诺辛\n地芬诺酯\n地西泮\n地震专家不学无术\n地震来加菜\n均对到底是听档的还是国家的\n坐台公关\n坐台只点吕秀莲\n坐火车出轨了\n坐着收钱看操逼\n坐等碘伏的那一天\n坐脸\n坑朦拐骗利翻番\n坑蒙拐骗\n坚持先军政治\n坚挺丰满的双峰\n坚硬中国肾\n坟场新闻\n坦克压学生\n坦克车从学生们的身上辗过\n坦克车压伤\n坪1进1席\n垃圾中共\n埃托啡\n城乡不平等宪法化\n城乡平等\n城乡统筹\n城墙+照片\n城大月报\n城管大队长猝死在街头\n城管方队\n域疆坚决永固\n基本靠吼\n堂口\n塞闭人民\n增值税\n增大宝\n增大液\n士士士领士士士士领士士士\n士康事件\n壮阳啫喱\n壮阳喷剂\n壮阳增大胶囊\n壮阳软膏\n声优\n声援真普选\n声琨接替王岐山访美\n声琨背景简历\n壹玖捌玖年陆月肆日\n壹玖捌玖陆肆\n处处性骚扰\n处处有匪警\n处女\n处女地\n处女就是茅台酒\n处女穴\n处女膜\n处重红邪\n复兴中华民国\n复制注意把括弧内容删除\n复制银行卡\n复印件制\n复印件生\n复原辽阔是没错\n夏珠活佛\n夏米斯丁艾合麦提\n外+秀恩爱+狗男女\n外交三招\n外交最弱\n外围赌球\n外家新赐飞龙璧\n外来马教\n外透视镜\n外高联\n多党\n多妻养德\n多穴\n多维新闻社\n多里坤.艾沙\n多里坤艾沙\n多难兴邦\n夜场兼职\n夜场女模特\n夜场招聘\n夜场模特\n夜场直招\n夜夜笙歌里藏春\n夜夜箫歌里藏春\n夜店模特\n夜总会公关\n夜总会招聘\n夜总会模特\n夜晚服务\n夜袭珍珠港美人受惊\n够毒\n够鳋\n大boss\n大gi元\n大g元\n大ji元\n大一纪\n大中华理性诉求\n大人物+被抓\n大使馆被炸\n大傻+老婆\n大傻+送钱\n大傻与干爹签订\n大傻在美国\n大傻夫妻\n大内主管\n大内总管\n大势所趋丕极退则安\n大善大忍\n大喊大叫要人操\n大回报\n大圆满法\n大坝垮的省长都没戏了\n大大+两次婚姻\n大大+二次婚姻\n大大+婚姻史\n大大+强强\n大大+有几次婚姻\n大大+柯小明\n大大+柯零零\n大大+麻麻\n大大三年\n大大上台\n大大下台\n大大大难大大难大大大大\n大大威武\n大大家教好严\n大大家教真好\n大大的中国\n大奶mm\n大姐加x大guo籍\n大姐加拿大\n大姐在加拿大\n大季元\n大学动乱\n大学艳遇史\n大宋子民\n大宝法王\n大审判大审判大审判审\n大家快跑\n大家找我聊天\n大小爪牙一帮子\n大屠杀\n大己元\n大批贪官\n大救星习大大升起\n大日本帝国万岁\n大棒口里含\n大款的老婆领导的钱\n大比里头烧过柴\n大河南威武\n大法不可被利用\n大法义解\n大法之声\n大法修炼\n大法好\n大法学员\n大法弟子\n大法新闻社\n大法洪传时代\n大法的纯洁\n大法资料\n大法通行\n大法金刚永纯\n大海啸\n大湖区讲法\n大潮涌迂腐\n大烟\n大烟鬼戒烟网\n大牢唬洲泳糠\n大狙\n大祭司\n大纪元\n大纪园\n大胖子在粪堆上打苍蝇\n大腿内侧\n大航海时代你禁海\n大荷烂猪\n大虹桥规划\n大街操过b\n大规模叛乱\n大规模暗杀\n大规模骚乱\n大记元\n大送王朝\n大送皇帝\n大逼塞进你睾丸\n大逼里头有怪味\n大道忠郭宫惨当\n大陆之纳\n大陆回归台湾\n大陆放肆\n大陆没有互联世界\n大陆沦陷\n大陆的腐败\n大面积心肌梗死\n大饥荒时期\n大麻组合\n大黄钻\n大黑鹰\n天a门屠杀\n天一灭一中一共\n天上导弹不断南方洪水泛滥\n天下太平天下太平退\n天下必反\n天亡中一共\n天亡中共\n天人之路\n天佑台湾\n天兵天将下天廷\n天叫共党亡\n天国乐团\n天堂里看到股票上涨\n天大地大都是党的\n天大的笑话\n天天天遣天天遣天天天天\n天天挂代理yy跟它娘拍兽皇\n天天看见头条那个装碧犯\n天天绣恩爱\n天威唐鼓队\n天子有喜好\n天安门\n天安门之魂\n天安门事件\n天安门事变\n天安门前开口说\n天安门四君子\n天安门坦克碾压\n天安门城楼罚站\n天安门大学生事件\n天安门大屠杀\n天安门屠杀\n天安门屠杀事件\n天安门广场大屠杀\n天安门广场枪杀学生\n天安门广场民主运动\n天安门录影带\n天安门母亲\n天安门清场\n天安门的母亲\n天安门自焚伪案\n天安门被清场\n天官作共\n天忿地怒人怨警\n天怒人怨诉江\n天意天意天意之\n天意难违天意难违天意\n天推广歌\n天文三六共\n天曹69到来\n天朝+歌功颂德\n天朝+灭亡\n天朝9贼\n天朝zf\n天朝不亡\n天朝不灭天理\n天朝你去抗议\n天朝前戴眼镜\n天朝将亡\n天朝必亡\n天朝必灭\n天朝快完蛋\n天朝政府\n天朝政府拼\n天朝更落后更专制的制度\n天朝最高政法委老大周\n天朝末年\n天朝末路\n天朝棺腐垄断\n天朝气数将尽\n天朝气数已尽\n天朝灭亡\n天朝症腐\n天朝的法律就是个笑话\n天朝皇帝\n天朝老大\n天朝老大家的歌妓\n天朝要亡\n天朝覆灭\n天朝首相\n天津公安\n天津大爆炸内幕\n天津奥斯卡\n天津市市长\n天津市长\n天灭zhonggong\n天灭伊斯兰\n天灭共产党\n天灭在眼前\n天灭河蟹\n天灭终共\n天父真好\n天皇万岁\n天线宝宝\n天要亡供\n天要亡共\n天赚网\n天越来越黑\n天门事件\n天风地火一齐来\n天鹅之旅\n天龙t253\n太上皇与庆亲王\n太上皇江\n太上皇病危\n太毒\n太王四神\n太监媒体\n太阳代表光明\n太阳城\n太阳旗是光明\n夫人打伞\n夫人着衣秀\n夫妇乐园\n夫妻两口真和谐\n夫妻交换\n夫妻友论坛\n夫妻可以换着搞\n夫妻秀视频\n夭孽孽孽孽孽孽孽夭夭夭夭\n央官省官市官县官村镇官官官皆贪\n央视不差钱\n央视是变态\n央视自焚\n失业大军数百万\n失信天下习\n失意药\n失身\n头定挂墙头\n头条新闻\n夷裆砖至\n夹吸器\n夹夹子\n夹阴\n奇迹的黄\n奋力堵住阴道\n奔驰到处撞人\n奔驰宝马\n奖金就象阴毛\n套动\n套图\n奥斯卡+温\n奥运飞流直下三千尺\n女主持\n女人不卖淫对不起江泽民\n女人二十八叫你用力插\n女人和狗\n女人的胸男人为什么喜欢摸\n女人穴\n女人给别人睡的是穷人\n女任职名\n女儿+哈佛\n女儿在美\n女儿在美国\n女儿送国外\n女公关\n女友b的味道\n女基督\n女士按摩\n女奴\n女子交友\n女干过你太奶\n女干过你来老母\n女性青睐\n女技师\n女特服\n女王\n女用器具\n女的借b行凶\n女被人家搞\n奴才满庙堂\n奴隶是没有土地\n奴隶是没有政治权利\n奴隶的财产来自于奴隶主的分配\n奶头\n奶子不大肿得出期\n奶子不打肿得奇\n奶推\n奶盐浴\n奸二二奸奸奸奸奸奸奸二\n奸人妻女\n奸插局\n奸淫\n奸通奸奸通通通通通通通奸\n她的mm\n她的姓是唐朝后面的那个朝代\n好b都给狗日了\n好书推荐好书推荐好书\n好大喜功\n好支威有希\n好日子就要来了幸运\n好法大轮法\n好火费炭好女废汉\n好爽\n好紧\n好结石三鹿造\n如今不退受牵连\n如暗娼\n如果他的姐姐一个是加拿大籍华人\n如果你真杀了人千万不要惊慌\n如果你觉得政治与你无关\n如果团结可以赶走流氓\n如果当年给日本人治理\n妄想有一天中国变天了\n妓女乙队伍的标语口号\n妓女合法化\n妓女工作歌星干\n妓女时尚新潮\n妓女甲队伍的标语口号\n妓女罢工\n妓女随时可以上\n妓者\n妓院合法化\n妖妖孽孽\n妞妞基地\n妳家老爸鸡巴短\n妹为哥哥服务\n妹为您服务\n妹妹上门\n妹妹为哥哥的服务\n妹妹兼职\n妹妹好风骚\n妹妹既然出来做\n妹妹服务\n妹妹本人\n妹妹的屄\n妹子会做爱\n妹开苞\n妻妾全换\n妻子李京\n妻脱光倒立镜前\n姐夫跨小姨\n姐妹双飞\n姐姐外国籍\n姐姐是加拿大公民\n姐开苞\n姐的穴\n姐穴\n姓wen\n姓何的检察长\n姓何的监察长\n姓刁名镜瓶\n姓婤的出面\n姓张的衙内\n姓是唐朝后面的那个朝代\n姚明进去\n姜上来时\n姜仄敏在与怂卒赢握手时\n姜坐工行总行1把手15年\n姜氏干部\n姿不对死\n姿势任哥\n姿势认你摆\n姿势随便\n威客\n威尔刚\n威武窑\n娇吟\n娇喘\n娇声娇气催你快\n娇羞\n娘两腿之间\n娱乐会所\n娱乐城招聘\n娱乐城诚聘\n娱乐招聘\n娱乐透视\n娶不起没房没车谁嫁你\n娶了个唱歌的老婆\n娼妓业进程\n婚姻改革同居成风\n婚嫁业务\n婴儿被煮成汤\n媒体封锁\n媒体是下作的\n媛水救不了近火\n嫂子说你是贱人\n嫖妓安全\n嫖娼精英\n嫩b\n嫩嫩的阴阜\n嫩屄\n子子子麈子子麈子子\n孔布煮意\n存瑞是我和毛主席的好儿子\n孙中山模仿美国\n孙悟空也有人管他\n孟国中号\n孟国忠号\n学习就像嫖妓\n学习就象嫖妓\n学民双运捕蟾蜍\n学生动乱\n学生妹兼职\n学生运动\n学生问老师\n学自联\n学运\n学运民运捕蟾蜍\n宁予友邦\n宁做日本狗\n宁做美国狗不做中国人\n宁死都要坚强\n宁赠友邦不于家奴\n它们还要欺骗中国人到什么时候\n宇宙的特性是真善忍\n宇宙真理\n宇明网\n守口如瓶奖\n守在子宫门口\n守所死法\n安全套随身带\n安圆鼎逞强\n安局办公楼\n安局豪华\n安徽太和\n安徽草狗\n安徽鬼子来了\n安排某国进行全苠投票\n安排赵飞任天津公安局局长\n安排邓小平曾孙\n安眠酮\n安纳咖\n安邦设局清除高层\n安钠咖\n安静要和谐\n完全可以代替中国古代的李自成\n完全可以代替中国古代的满族\n宏志\n宏法\n宗教自由\n宗果领导人\n官v的避重就轻\n官也不容\n官僚精英\n官匪一家\n官匪勾结的重要原因\n官员不会当官\n官员代表答\n官员只有特权\n官员奸淫\n官员恶\n官员把群众整疯\n官员真是土匪\n官员靠吃政治饭\n官员黑手常伸\n官商勾结为荣\n官商联手\n官因发帖\n官场开始乱咬\n官场搞乱\n官场秘诀\n官场经济\n官场缺德\n官场腐败\n官官勾结\n官官相互\n官官相照\n官官相通\n官府忽悠百姓\n官网可查\n官网注册\n官腐民盗\n宙最高法\n定位仪\n定位器\n定罪量刑成冤案\n宝在甘肃修\n宝马娱乐城\n宝马进去自行车出来\n实学历文\n实干误国+空谈兴邦\n实惠安全\n实毕业证\n实现中华民族的伟大复兴\n实现复兴\n实际神\n审判ccp\n审判在神家起首\n审判江泽民\n审理妓女队伍\n宣传联播\n宣战江泽民\n宣称自己没有私利的集团\n宣统狗皇帝的大姐二姐\n宪路求索群\n宫喘主意\n宫庭粉推\n宫廷粉推\n宫残党\n宫雾猿和鹳狸猿\n害怕人民觉醒\n害怕言论自由\n害死8000万民\n家一样饱\n家国匪土个是国中\n家宝安全门\n家宝影帝\n家家不保户户掏尽\n家属被打\n家庭像贾春一样旺\n家庭基督教会\n家庭教会\n家畜\n家里有田\n宾馆服务\n宿命论\n寂寞妹妹\n寂寞少女\n寂寞少妇\n寂寞白领\n富可甲天下的政府\n富婆\n富婆包我\n富婆去夜总会找乐子\n富婆给废\n富平大肥猪\n富甲全中国\n富裕后秘书兼老婆\n富贵在天习近贫\n富起来我理所应当会过上\n对人民必须纂改历史\n对人民的恐惧\n对付人民\n对付老百姓\n对你无法监督\n对内坑害民众丧心病狂\n对内强力围吻\n对内搜刮屁民刮地皮三尺\n对内残酷欺压\n对外软弱\n对外送美元如丢废纸\n对天一朝\n对岸小马哥的母亲去世\n对日强硬\n对毛子不要纠缠历史\n对着你妈来一枪\n对鬼子不要忘记历史\n寻找逃荒妇女娃娃\n导人的最\n导爆索\n导的情人\n封杀网易\n封杀酱猪媳\n封锁中国\n封锁人民的嘴巴\n射乳\n射了姑娘一脊梁\n射你嘴里\n射你脸上\n射出来\n射出郭晶晶\n射的金连一裤裆\n射眼睛里\n射精大厦\n将物价推高\n尊爵粉推\n小b崽子\n小jj\n小修女对神父jj的描述\n小喷筒\n小妹扛枪\n小妹服务\n小姐上门\n小姐乞丐在徐州\n小姐代表答\n小姐你真骚\n小姐开博\n小姐把辈份搞乱\n小姐服务\n小姐说俺是第一次\n小姨子穴\n小孩杀死\n小孩被抢\n小官大官高官官官皆贪\n小屄\n小平同志很正经\n小平同志还挺正经\n小平率领小商贩\n小平领导小商贩\n小弟无骨硬得奇\n小心国家政策来捣鬼\n小投入\n小投资\n小支那\n小日本和那个什么痒滴\n小板凳家族\n小比崽子\n小江同志挺能干\n小江小胡\n小洞\n小猎王\n小胡和小温\n小逼崽子\n小雨伞小雨伞你是我们的希望\n小飞狼\n小飞虎\n小黑豹\n少喝酒多作爱\n少在这里瞎比比\n少女怕日以手遮阴\n少女迷情药\n少妇帐篷\n少妇是红酒\n少妇服务\n少妇白洁\n少妇穴\n少年混混出韶山\n少数民族\n少数民猪就是x档养的狗比\n少爷陪游\n尖鄙尖尖鄙鄙鄙鄙鄙鄙鄙尖\n尖阁列岛日\n尝你乾坤棒\n就不会有自由\n就业问题\n就会推翻暴政\n就去干\n就去播播\n就去爱\n就去色色\n就在厂里\n就在白帝城立三个铁人请罪\n就必须让日本人来当物业管理\n就是人民\n就是处女少\n就是整天跟着土\n就是精神病的理论\n就是连阿平都不敢说他敢搞\n就是马列主义都是假的\n就没有新满清\n就没有防盗门\n就爱色\n就算凶器\n就让你等全部当官\n就选了两个自认为可靠的\n尸体\n尸骨未寒\n尼可吗啡\n局域网大会\n局干部拿\n局长包养女主播\n局长孙宝东是帮凶关系\n屁穴\n屄儿\n屄友\n屄里\n居民聚居区\n屏蔽器\n屏蔽词档案\n展开我们的翅膀\n属于你的阳光\n屠光北京人\n屠华\n屠夫嫖妓被抓罚\n屠夫的职业\n屠宰场新上任的场长\n屠宰场新厂长上任\n屠宰场新厂长上任两年\n屠杀\n屠杀大学生\n屠杀学生\n履带下的共和国公民\n山东人和狗一样\n山东大叫驴\n山东大蠢驴\n山东大驴\n山东女婿\n山东威海复职案教育我们\n山东招远被毒打致死的女孩请愿\n山东毛驴\n山西儒林鼠鸡\n山西黑窑罢\n山锅怠标\n岂能正声\n岥解仪噐\n峨嵋密封圈\n峨嵋弹簧\n峨嵋皮碗\n州大批贪\n工chandang\n工chan党\n工chan当\n工chan挡\n工chan档\n工chan裆\n工chan谠\n工产dang\n工产当\n工产挡\n工产档\n工产裆\n工产谠\n工体开车撞人\n工作只要一张床\n工作就像lunjian\n工作就像嫖妓\n工作就象轮奸\n工农匪裆\n工商税务两条狼\n工字密封圈\n工字弹簧\n工字皮碗\n工惨dang\n工惨党\n工惨当\n工惨挡\n工惨档\n工惨裆\n工惨谠\n工掺党\n工掺当\n工掺档\n工掺裆\n工掺谠\n工残dang\n工残党\n工残当\n工残挡\n工残档\n工残裆\n工残谠\n工程吞得\n工程款\n工自联\n工费比王\n工资买得起房那是扯蛋\n工资好比眉毛短\n工资待遇\n工资日结\n工资翻了好几倍\n工铲dang\n工铲党\n工铲挡\n工铲档\n工铲裆\n工铲谠\n工长党\n工馋党\n左啡诺\n左手拿的避孕套\n左美沙芬\n左芬啡烷\n左转是政\n巩固统治\n已合了66年\n已喝了66年\n已婚女帐篷\n已婚女视频\n已经有美国和日本的资金进入中国\n已经过第二个本命年\n巴基斯坦杀人了\n巴掌拍的震山响\n巴新反华\n巴西人\n巴西预言\n市府办强势部门\n市民每个月买20块钱的生态基金\n市长书记一起睡\n布什和锦涛\n布什头痛的胡主席的姓\n布什妈的\n布什给美元\n布什问胡锦涛\n布假戏骗百姓\n布卖淫女\n布吉火车站\n布尔什维克\n布施外邦+劫夺聚敛\n师有回天力\n师涛\n希望死的都是中国人\n希望的田野\n希望载猪的飞机失事\n希望这些人回到自己的原住地\n希特勒的头像还挂\n希特勒的画像还挂在城楼\n帝国之梦\n帝王浪漫双飞\n帝王浴\n帝王游戏\n帝都公安\n帝阅水师于东海\n带根吊\n带着老婆作秀\n带着老婆瞎吉巴转\n带薪坐牢\n带蛋\n带领我们勇往直前\n席临终前\n席指着护\n席泽明步\n席索里尼\n帮主\n帮了我们的大忙\n帮内\n常委大老虎的荒淫\n常识革命\n幊党毕辋\n幕没有不\n干你姐\n干到高潮叫叫\n干扰器\n干扰大法\n干掉中共\n干材烈火\n干死共产党\n干的你妈流白带\n干的你爸直阳痿\n干的妳m\n干的妳m直流脓\n干部一大怪\n干部贪乡干部拿\n平凡不高考\n平反64\n平反八九\n平反六四\n平反六四一起撑\n平叫到床\n平台出租\n平台更重要\n平平+强强\n平时在家无聊\n平特\n平生万卷\n平码\n平肖\n年年反腐年年腐\n年经再起\n年老年少都得退\n年轻的雪主\n幼b\n幼幼诱女\n幼穴\n幼逼\n广东人很奇葩\n广东猩猩\n广东猴子\n广告赚钱\n广场上冤魂游荡\n广场上的共和国\n广场上的热血\n广场学生\n广场是我的坟墓\n广州食尸狗\n广电总局\n广电总菊\n广西土狗\n广西猴子\n广西贪腐\n庆丰三年\n庆丰三年旦\n庆丰二年秋\n庆丰包子\n庆丰大帝\n庆父不死\n庆谁的国\n床上功夫\n床上功夫传天下\n床上翻腾\n床上陪伴\n床前看月光\n库帑丰盈\n应召服务\n应诉申请书\n庙堂之上+朽木为官\n府集中领\n废叁十九\n废除害人的马列主义\n废除毒誓废除\n度冷丁\n度制义主产共的类人反\n庭审直播\n庭锋不堪回首芝逼中\n庵菊才是真正的黑社会\n康宝莱\n康师傅拼\n康庄大道\n康死无红\n康没有不\n康王的发豆腐渣\n延时丸\n延时乳液\n延时喷剂\n延时油\n延时液\n延时王\n延时胶囊\n延迟退休\n建国党\n建国门事件\n建国门枪战\n建筑老板若要富敢将工程变豆腐\n廿六年前那一夜\n廿周年\n开个网站就能赚钱\n开会就象乱伦\n开发区的领导最逍遥\n开发商若要富先用金钱铺好路\n开发豆腐渣\n开发身体养爹娘\n开国大典\n开奖号\n开奖结果\n开始做梦\n开展圣战\n开幕式含义新说法\n开心转\n开我小阴唇\n开放党禁\n开放报禁\n开特\n开腿卖b挣大钱\n开锁器\n开锁工具\n异域被杀+友邦赏花\n异常调动\n异性按摩\n弃欓\n弄死自己国家人\n弄穴\n弓弩\n弓箭\n弓藏党\n弓颤党\n弓馋党\n引发清明京师民\n引咎辞职\n引导评论帖文获得5支持\n引无数美女竞折腰\n弟大物勃\n弟子\n弟子的伟大\n张伯笠\n张含韵的卫生巾\n张宏堡\n张宏真\n张开双腿\n张新东\n张柏笠\n张磊律师\n张祖桦\n张立冬绝对有背景\n张绝对不是什么邪教成员\n张飞不是\n弥天大谎\n弥留之际\n弩中之王\n弩弓\n弹刺跳刀\n强j\n强制征地\n强制拆迁\n强制监视\n强制视频\n强制软件\n强力打压股市\n强奸后记得留些钱\n强奸无罪\n强奸朋友妻\n强奸粉\n强征土地\n强拆\n强摘器官\n强摘法轮功学员器官\n强权政府\n强烈声讨\n强烈要求司法独立\n强盗当政\n强硬发言\n强行征地\n强行拆迁\n强行拘留\n强行视频\n强迫信邪论洗脑发毒誓做牺牲供品\n当今圣上\n当今天子\n当今的国舅\n当今的媛\n当今皇后\n当今那位\n当代七整\n当你在山上\n当你在山上当土匪时\n当官在于\n当官的受贿数额越来越多\n当官的喜贪赃\n当官的贪污\n当官要精\n当官要精通哪四种语言\n当家作主搞起来\n当年mao害的\n当心华南虎\n当政者\n当朝7大长老\n当朝七大长老\n当朝大老板的大姐\n当朝长公主\n彡壴麻麻\n形相猥琐\n形象总与一副黑框眼\n形透视镜\n彩金狮王\n彭+女+爰\n彭丽媛干政\n彭丽援交\n彭元帅立马\n彭妈妈北京电影学院\n彭妈妈北电\n彭妈妈李岚清\n彭妈妈来学校看电影\n彭麻麻北京电影学院\n彭麻麻北电\n彭麻麻拼\n彭麻麻来学校看电影\n影帝家宝\n彻底斩杀\n征四海民饷\n待开发票\n徒务近功\n得法\n得谁跟谁cao\n得谁跟谁搞\n得谁跟谁睡\n循环商务\n循环电子商务\n微型摄像\n微电波拉皮\n德国俄国来的马\n德国妇女\n德国魔棒\n德盛祸国\n心里懦弱\n必中\n必杀\n必须要煽动反美\n志不愿跟\n志成之歌\n志成学子之歌\n忘供必80后\n忘记删除者一律开除\n快凯公司\n快办学历\n快害大千国\n快感喷剂\n快感热舞\n快速出手奖\n快餐小姐\n快餐美女\n快马加鞭\n快鹿弹簧\n忽悠屁民\n忽悠百姓\n忽视农民\n怋主制镀\n怎么每天都有个猪头在首页\n怎克强敌\n怒的志愿\n怕被女人强奸\n思想上压迫你禁锢\n思想情妇要养\n思想解放了都当小姐\n思钱思权思小蜜\n急忙掏出大炮\n急救急救急救急救急救退\n性专买店\n性专卖店\n性交大学\n性保健\n性友谊\n性器\n性开放俱乐部\n性开放的\n性感\n性感丝足\n性感内衣大全\n性推广歌\n性格和善黑吉辽\n性欲泛滥\n性欲较强\n性爱网\n性爱视频\n性生活基本靠手\n性用品\n性福无限\n性色社区\n性调节师\n性趣激发\n性霸2000\n总会美女\n总射击师\n总政上海帮\n总政治部\n总理的意思是5月份开始下跌\n总理的贴身保镖\n总理贴身保镖\n总理邮箱\n恋情像李长一样春\n恋足\n恐出头而遭官府打压\n恐怖事件\n恐怖份子不是吓大的\n恐怖气息\n恐怖组织\n恐怖袭击\n恢复三民主义\n恢复中华国\n恩典之光\n恭惨党\n恶习不除\n恶习好大喜功\n恶习该死\n恶习难改\n恶习难该\n恶习难除\n恶劣之罪非咫尺易网可罗列\n恶势力插\n恶势力操\n恶孽罪行录\n恶打\n恶政之下\n恶灵时代\n恶畜别说是送钱\n恶警\n恶谠\n恶邻居欺负了\n您可以决定是否回答\n您对全会提出依法治国怎么看\n悼念89\n悼念胡耀邦\n情妇\n情妇大奖赛\n情妇腐败\n情感陪护\n情戏玩具\n情报窃听\n情爱娇娃\n情聊天室\n情色一条龙\n情色五月天\n情色网\n情色论坛\n情趣游戏\n情趣玩具\n惜阿尔道夫功亏一篑\n惟有日属\n惟有美女权钱欲\n惠州火车站\n惨无人道\n惨痛教训\n想当年习刚上台\n想怎么冼脑就怎么冼脑\n想想广场的tank\n想杀谁就杀谁\n想研究唐朝就去日本\n想禁什么就禁什么\n想起交警欲断肠\n想轧警察就轧警察\n想违章就违章\n愈搓愈爽\n愚民政策\n愚民教育\n感谢政府为我解决了住房问题\n感谢炒蛋饭\n慈父斯大林万寿无疆\n慈禧的野种孙子习仲勋造反\n慧网\n戏子国母\n戏子老婆\n成为贵族\n成人bt\n成人保健品\n成人俱乐部\n成人午夜场\n成人卫星频道\n成人图库\n成人图片\n成人在线电影\n成人导航\n成人影视\n成人影院\n成人漫画\n成人用品\n成人社区\n成人站\n成人网\n成人聊天\n成人聊天室\n成人视频\n成人视频聊天\n成人配色\n成人频道\n成功克隆毛泽东\n成品冰\n我一直用1个档\n我为什么信耶稣\n我也得发\n我今天不睡觉了\n我们不能谈政一冶\n我们响应国家号召坚决不出门\n我们唱着洞房红\n我们宿舍\n我们已经老了\n我们挺你\n我们时代的英雄\n我们班有56个学生\n我们的冤屈已无处申张\n我们的希特勒\n我们的政府很无能干\n我们的民工象牲口一样\n我们要选票\n我们让日本人来当物业管理不好吗\n我们讲着春药的故事\n我党上市\n我军擅长意淫\n我去很远的地方看朋友并谈点事\n我去过西藏\n我只是混口饭吃\n我叫盆子\n我可以诅咒你死后下火狱\n我可是党书记\n我可是共党的书记\n我听很多老人说\n我和你妈搞破鞋\n我和你妈来通奸\n我和毛主席的儿子\n我国法律就是摆设\n我在你妈逼上走\n我在北京\n我姓邓\n我家世世代代\n我射她嘴里\n我就不是胡紧套\n我就操翻你妈比\n我希望中国分裂\n我恨警察\n我想带她回家去做爱\n我愿揭杆\n我打着伞走在路上\n我把你姐把夜包\n我搞台独\n我是一个寂寞的女人\n我是不是该学怎么换挡\n我是主子\n我有一个朋友特别爱吃包子\n我朝将亡\n我朝无将\n我朝法律就是笑话\n我来晚了\n我来说说事情的真相\n我现在的男人是通过投机取巧\n我的上师\n我的喇嘛\n我的壮丽青春\n我的女儿在美国\n我的尸体\n我的性启蒙老师\n我的服务\n我的民主历程\n我的真实照片\n我的西域\n我看还是不要报道两个会了\n我秀你射\n我立马把长江水喝干\n我给你妈逼干肿\n我自愿退出中国国籍\n我草不带套\n我草你吗不带套\n我要买by套\n我认为网易老板姓丁的这就在犯罪\n我让你挥手了吗\n我讲个笑话+法治社会\n我识条铁\n我跟你妈更厉害\n戒严令\n戒严指挥\n战争赔款不要了\n战堂\n战斗弹\n战马喷雾剂\n战马油\n截留公款称奖金\n戴眼镜的青蛙\n戴着一副黑框眼镜\n户口和人权在中国是奢饰品\n户户缰户缰缰缰缰缰缰缰户\n房产改革口袋掏空\n房价涨了\n房屋产权\n房贷给废\n所以我认为警务人员\n所以说网易是最大的地域者\n所有的反腐\n所谓人口红利\n手16年\n手下有全球\n手向外弯心最邪\n手拍肩\n手指虐\n手摸的舌舔的\n手机卡复制器\n手机复制\n手机定位\n手机注册\n手机跟踪\n手枪\n手枪出售\n手淫无档次\n手狗\n手表短信接收器\n手铐\n扌丁到供馋残\n才厚才薄又怎样\n才干是银牌\n才有新中国\n才知道只生\n才能救生\n才能有新中国\n扎人事件\n扎刺\n扎针\n扒开小逼使劲瞅\n扒衫射水吸舔取jing\n打人交警\n打人致死\n打伞新时尚\n打伤小贩\n打倒+政府\n打倒gcd\n打倒中国共产党\n打倒中国共产党拼\n打倒中国政府\n打倒中央\n打倒中央政府\n打倒习达林\n打倒习近平\n打倒公惨荡\n打倒共产党拼\n打倒共产蛋拼\n打倒共长党拼\n打倒共长蛋拼\n打倒共非\n打倒当前政府\n打倒政府\n打倒现政府\n打出一个\n打出一个新中国\n打击天朝\n打击警察\n打到+政府\n打到gcd\n打到中国\n打到中国政府\n打到中央\n打到中央政府\n打到共产党\n打到当前政府\n打到政府\n打到现政府\n打压异族\n打日本他在后方窑洞\n打杂抢烧\n打架结社黑社会\n打死人\n打死经过\n打毒针\n打炮\n打着反腐的口号收拢人\n打砸事件\n打砸办公\n打砸烧事件\n打粉插花\n打老虎遇阻内幕\n打针党\n打飞机\n打飞机专\n打黄扫非找鸡睡\n托江的关系\n托福枪手\n执政党\n执法何在\n执法犯法\n执法者\n执法者犯法\n扩大内需\n扫了爷爷\n扬刀跃马踏北京\n扬州籍的重要人物\n扬州老鳖\n批发假币\n批发硬币\n批发香烟\n批发黄领巾的生意\n批条画圈就来钱\n批评谠\n找个技术好的\n找心地好的哥哥\n找政法委副\n找枪手造舆论\n找点空闲\n找财喜\n找鸡\n技术侦查\n把你妈操残废\n把你母亲摁地上就是一顿草\n把全世界各国骂人语言加在一起\n把学生整\n把握鸡遇\n把日本人引进来\n把民意强奸\n把病人整\n把矬子扔进厕所\n把腿掰开\n把邓小平\n把那被窝捂起来\n把酒溜死\n抓了那么多贪官\n抓捕令计划内幕\n抓来打一炮\n投注网\n投胎至十岁\n抗暴\n抗美援朝\n抗议政府\n抗议镇压\n折腾死8000万民\n抠b\n抠逼\n抡功\n抢位之祸\n抢其火炬\n抢夺尸体\n抢小孩\n抢尸\n抢烧\n抢老人\n护士的穴\n护士门\n护尸\n护法\n报仇收帐\n报告淫长我方已经子弹耗尽\n报复执法\n抬抬女\n抵制共党\n抵制央视\n抵制政府\n抵制新闻联播\n抹上张学油\n抹黑falungong\n抽弄\n抽捣\n抽着大中\n抽着芙蓉\n抽送\n拆房揭瓦\n拆迁户\n拉开水晶\n拉开水晶棺\n拉拉用具\n拉拐子\n拉顿德通\n拍肩型\n拍肩神药\n拍肩粉\n拍马是一种高级艺术\n拒绝洗脑\n拔除痔肭傻鸡这棵毒瘤\n招募小姐\n招坐台小姐\n招坐台少爷\n招女ds\n招女模\n招奴\n招收小姐\n招聘av\n招聘公主\n招聘公关\n招聘兼职美女\n招聘商秘\n招聘坐台小姐\n招聘女模\n招聘小姐\n招聘技师\n招聘模特\n拥习挺b\n拥护什么\n拦截器\n拨开她的上海三毛\n拨开阴毛驾云雾\n拱.铲.谠\n拱.铲谠\n拱chandang\n拱chan党\n拱chan挡\n拱chan档\n拱chan裆\n拱chan谠\n拱产dang\n拱产党\n拱产当\n拱产挡\n拱产档\n拱产裆\n拱产谠\n拱傥\n拱惨党\n拱惨当\n拱惨挡\n拱惨档\n拱惨裆\n拱掺dang\n拱掺党\n拱掺当\n拱掺挡\n拱掺档\n拱掺裆\n拱掺谠\n拱残dang\n拱残党\n拱残当\n拱残档\n拱残裆\n拱残谠\n拱谠\n拱铲.谠\n拱铲dang\n拱铲党\n拱铲当\n拱铲档\n拱铲裆\n拱铲谠\n拱铲铛\n拳击的雹子\n拿下胡锦涛\n拿枪打人立过功\n拿着江泽民\n拿着自己的钱\n拿破仑1968\n拿起武器去反抗\n拿车那就是3年\n拿车那就是三年\n挂照片+城墙\n挂照片+敬仰\n挂牌\n挂牌出肖\n指向郭声琨\n指挥长温公\n指纹考勤\n按摩按到裸睡的\n按摩推油\n按桌子上狠狠草\n按需分配\n挑你母b\n挑拨离间\n挑逗\n挖掘死尸\n挖肃\n挡坦克的人\n挡坦克的男人\n挥发型\n挨了一炮\n振动按摩\n振臂一呼\n振蛋\n挺起古巨鸡\n挺趣蛋\n捅鸡局\n捆绑\n捎带着宣传自己爱吃包子拉面\n捏住脖子按下水\n捐款就像发情\n捕捕捕捕捕捕捕\n捕杀令完成\n损毁商铺\n损毁民房\n换党\n换届就是驴造出一茬换一茬\n据说全民\n据说天津\n掌握了权力\n掏子为组织和谐了腐败制度\n排华\n排除异己\n排除异已\n掠夺就是奴役\n探头狗\n探测狗\n接管中国\n控制人口奖\n控制在3000字以内\n控制舆论\n控告僵蟾蜍\n控诉世博\n推粉\n推翻+政府\n推翻gcd\n推翻中共\n推翻中国政府\n推翻亦因\n推翻供谠\n推翻共产党\n推翻剥削政府\n推翻当前政府\n推翻政府\n推翻现政府\n推翻鞋觉\n推荐朋友赚钱\n掰开屁眼往里搞\n掰证\n揉摸\n提供场所\n提前送终\n提着wy老总丁磊及小编狗头\n插bb\n插一半生干部\n插你的下面\n插入她的隧道股份\n插入宋祖阴\n插入穴\n插女\n插妳m\n插妳m的大阴道\n插妹妹\n插弄\n插死山东女人\n插爆\n插的好舒服\n插的好舒适\n插穴\n插肉\n插肛\n插进你下面\n插进你的下面\n插进咽喉深入\n插进妳m桃花深处\n插进来\n插进穴\n插进阴头\n握紧大印收贿赂\n揭揭揭揭揭揭\n揭杆而起\n揭竿起义\n揭露江泽民\n搂着小姐打炮\n搔穴\n搞个处女\n搞了一轮股权私募\n搞她几夜不撒尿\n搞完你妈草你姨\n搞得鸡巴起了泡\n搞洪宪帝制\n搞独立於大中华地区的其实是大陆\n搞破鞋\n搞计算机的出来接客\n摆平胡锦涛\n摆脱党文化\n摇头万岁\n摇头会更爽\n摇头没烦恼\n摘取人体器官\n摘取犯人器官\n摩根大通\n摩门教\n摸乳门\n摸其乳吻其阴\n摸奶视频\n摸奶门\n摸摸下面就流水\n摸胸门\n摸黑毛泽东\n摸齐乳\n摸ｊｊ爽\n撒币外交\n撒币大帝\n撒币夫妇\n撒旦魔教乱\n撒钱就行\n撞其火车\n撞其火车抢其火炬兮\n撞死百姓没啥事\n撤出新疆\n撤回革命\n撤消发改委\n操dabi\n操交警\n操交警他妈\n操他老祖宗\n操你妈就是猛\n操你瞎妈\n操入\n操到高潮不用防\n操地你妈满床滚\n操她\n操妳\n操妳m逼\n操妹妹\n操娘\n操完你妈操你姐\n操小逼\n操屄\n操干\n操死人逼\n操比\n操的你妈满床滚\n操破\n操穴\n操翻你妈比\n操过你妈小屁屁\n操这\n操逼喝酒象喝汤此人在工商\n操逼速度如闪电\n攀附权贵\n支台入联\n支持is\n支持上海独立\n支持东北独立\n支持习主席\n支持习大大访美支持两国合作\n支持习总书记\n支持云南独立\n支持令计划\n支持北京独立\n支持台湾独立\n支持广州独立\n支持新疆独立\n支持日本消灭中国\n支持李柱铭\n支持梁国雄\n支持河南独立\n支持浙江独立\n支持港独\n支持爱国民主运动联合会\n支持蕟哥\n支持西藏独立\n支持香港争取真普选\n支持香港回归英国\n支持香港独立\n支持黎智英\n支那\n支那人\n支那匪政权\n支那狗\n支那豚\n收复大陆\n收账\n收购shen\n收购肾\n收费视频\n改你媛的蛋\n改号软件\n改名为胡锦波\n改曹换待\n改脸型\n改行做成品油\n改革失去动力\n改革开放鸡婆泛滥\n改革是错误的\n攻产党\n攻官小姐\n攻长胆拼\n放光明电视\n放光明电视台\n放入春药\n放弃治疗\n放弃这么好的上场机会\n政令+中南海\n政令不出中南海\n政党自我吹嘘\n政匪\n政华同志\n政华局长\n政变\n政坛起家\n政府+下台\n政府+剥削\n政府+压榨\n政府+打倒\n政府+无能\n政府+烂到根\n政府+腐败\n政府不要脸\n政府交换被抓获\n政府吃屎\n政府垃圾\n政府太无能\n政府太贪\n政府太黑\n政府忽悠百姓\n政府忽悠百姓叫政策\n政府操\n政府无能\n政府是大爷\n政府是爷\n政府腐败\n政府靠得住\n政当匪土\n政息人亡\n政权必倒\n政治只有腐败\n政治地位\n政治垄断\n政治小丑\n政治小丑奖\n政治局常委\n政治恶棍\n政治报复\n政治斗争\n政治朝鲜化\n政治派系\n政治满清化\n政治牺牲品\n政治背景\n政治课堂上\n政治运动\n政治迫害\n政治道德钞票经济理论\n政法委老大周捞钱\n政纸改歌\n政绩就是神吹\n政绩把财政整空\n敌对势力想方设法欲遏制\n敏感案件辩护人\n敏感的政治纪念日\n救主早已驾云重归\n救化名化名\n教大家怎么有钱\n教练弹\n教育改革了于是马家爵杀人\n教育改革父母逼疯\n教育部是明抢\n敛财三千多万\n敢动中国\n敢将工程变豆腐\n散户们绝望的歌唱\n散财童子\n数千个恐怖分子家庭\n数疯流浊物\n数百家族共和\n数风流人物还看锦涛\n整天都是说一天的两国的友谊\n整形美容\n文刂日尧氵皮\n文刂目尧氵皮\n文化最烂\n文化部长\n文化革命干活要命\n文字沉默革命\n文艺女兵\n文革六四\n文革十年日记\n文革应该继续\n文革是中华民族文化的伟大创举\n料理店\n斯登姆\n新boss\n新一代江派\n新一届领导\n新上任的当家\n新上任的皇上\n新上任的皇帝\n新上台的贼子\n新二十四孝\n新君夕某\n新唐人电视\n新四人帮\n新四人帮政变内幕\n新帝登基\n新浪总裁可是观海听涛的女婿\n新生网\n新疆东突\n新疆事件\n新疆又暴动\n新疆恐怖分子\n新疆暴恐\n新疆暴恐分子\n新疆汉族\n新疆独立\n新疆独立运动\n新疆维族\n新疆自治区\n新疆鞑子\n新纳粹\n新贼更比旧贼恶\n新闻尽撒谎\n新闻管制\n新闻网\n新闻联播大结局\n新闻联播档中央\n新闻联播的惊人发现\n新闻联播里\n新黄+执政\n方丈正在打坐\n方怪方方怪方方\n施老师我看您面相挺老实的\n无乱九国\n无人有权沉默\n无公p公z\n无前搞医保\n无前搞射保\n无国界记者\n无官不贪\n无恶不作\n无意中闯入了我的世界\n无意中闯入我的世界\n无抵押\n无数淫雄竞折腰\n无无脑无脑脑脑脑脑脑脑无\n无权巡航\n无权投票\n无毒无马\n无界流览\n无病毒无木马\n无税香烟\n无线微型摄像机\n无线微型耳机\n无线监控系统\n无线远程监控\n无耻之徒以为皇帝坐稳了\n无耻作秀的国\n无耻国家\n无耻的国家\n无耻的政府\n无耻组织\n无耻语录\n无能政府\n无能的政府\n无能的正腐\n无能的温家宝\n无需抵押\n无风险\n既然是兄弟同胞\n既然认了洋祖宗\n日习他老娘\n日习他老母\n日出英花\n日后必有有关部门与你司约谈告诫\n日尧三皮\n日式指压\n日批\n日收入不低于\n日暮苍山兰舟小\n日本一天被炸掉\n日本亚洲的希望\n日本人当物业管理\n日本人来当物业管理\n日本人管理时\n日本人被赶走\n日本侵华有功\n日本和美国\n日本完整地保存了这首诗的原貌\n日本战犯的处理\n日本是发达国家\n日本是战胜国\n日本现在的和族\n日本的侵略\n日本皇军\n日本裕仁天皇\n日本首相\n日治时代\n日赚\n日遍大江南北\n日麻屁为荣\n旦旦旦撒旦旦撒旦旦旦旦\n早亡了早好\n早就已经不鸟cctv\n早就知道是黄局\n早泄克星\n早点灭亡\n旭光就连升\n时不我待时不我待速速速\n昂贵的服务\n昂首阔步奔高丽\n明hui\n明哲保身明哲保身活活\n明天就要大阅兵\n明慧周刊\n明慧周报\n明慧周末\n明慧图\n明慧广播\n明慧新闻\n明慧汇编\n明慧消息\n明慧编辑部\n明慧网\n明慧资料\n明星时常犯贱\n明毁网\n明泽公主\n星光伴我淫\n星条代表希望\n星条旗是希望\n春夏自由论坛\n春宫图\n春宵\n春水\n春水横溢\n春风欲度玉门关\n昨天我去算命\n昭君出塞\n是个敏感词\n是你的吗\n是共产党的天\n是否该分\n是快递曝乍\n是改革的高潮\n是谁弄明白了时\n是邓坑了中华民族\n晚上吊没事\n晚上娱乐打炮\n晚上有奶摸\n晚上有鸟耍\n晚上洞空空\n晚上球没事\n晚上睡前叫叫床\n晚上趴下就干\n晚上还去干你姐\n晚共末年\n晚年邓小平\n晚自习后\n普世价值缺失社会缺乏共识\n普京媛媛\n普布次仁仁波切\n普拉波沃?苏毕安托\n普罗庚嗪\n普通新闻赞的旁边有个踩\n景逸鸣\n晴空万里\n暗娼妓女借邓尸体\n暗灰讨饭\n暴乱\n暴力与谎言为挡治郭手段\n暴力事件\n暴力强摘器官\n暴力执政\n暴力执法\n暴力拆迁\n暴力拆迁打死人\n暴力犯罪\n暴力破解\n暴动\n暴君\n暴君毛泽东\n暴徒\n暴打\n暴政\n暴虐统治\n曲吗多\n曲马多\n更名为周永健\n更喜美穴温骚紧\n更好的朋友像伟哥\n曹长青\n曾q红\n曾国藩曾说\n曾大佬3年后不能发力\n曾大佬可能入局后转任人大副\n曾庆红向王岐山亮剑\n曾庆红废帝密谋\n曾庆红是郭声琨后台\n曾庆红老乡\n曾曾贾贾九常委\n曾玉梅\n曾的亲戚\n曾经有两个机会\n曾经有位外国人咨询\n曾经红人被抓\n替党说话\n替利定\n替考\n最不要脸的就是网易的评论审核员\n最坏的时代+最好的时代\n最大的妓女培训基地\n最大的流氓培训基\n最大的流氓是中国政府\n最大的涉黑组织\n最大的腐败培训基地\n最大的邪教\n最大的黑帮\n最大的黑社会\n最大贪污犯\n最引人注目的哥哥伟哥\n最恨怋紸\n最新地址\n最新网址\n最新网站\n最新黄站\n最昧心的是为人民服务\n最牛公安\n最终死在鸡巴上\n最能编造历史\n最难捉摸的官话研究研究\n最高指示\n最高身份奖\n月入上万\n月入过万\n月底可以拿到可以买一辆车的工资\n月收入万元\n月收入上万\n月收入几千\n月经来了也让搞\n月经来了都让搞\n月莫虫合\n月薪万元\n月薪过万\n月赚万元\n月赚上万\n月赚上千\n月赚千元\n月赚数万\n月赚过万\n有一个d\n有一个姓苏的也得过\n有个东西它已翘\n有个华莱士\n有个外来邪教\n有个天使进入一个魔鬼控制的村庄\n有个美丽的森林叫香岗\n有个蛆织\n有乌市出发的一百多名大学生\n有了权把子\n有事找大哥\n有人头一直歪着\n有你的臂膀跟我挽在一起\n有党性+没人性\n有关部门\n有兴趣的哥哥\n有几次婚姻\n有奶不一\n有幼女嫖\n有执照的流氓\n有批不日\n有效管理77名情人\n有时会是私法局\n有没有一个名词能把邪恶\n有码\n有色金属\n有诚意的哥哥\n有钱不捞白当官\n有钱就能有道理的地方\n有限选举\n有魏氏兄弟\n服务介绍\n服务价格\n服务工作者\n服务至佳\n服务费\n服务项目\n朝代毁灭\n朝代灭亡\n朝廷必欲收天才\n朝政混乱\n朝鲜和韩国\n朝鲜邓被打到\n期待2016美曰出兵开揍某傻\n期待大陆早日回归\n木兰裆裤湿\n木制条盒\n木子十兄弓虽\n木子月月\n木子月月加一鸟\n木子月月鸟\n木子朋鸟\n木子论坛\n木子颗弓虽\n未办酒席\n未来中国论坛\n未来会有挽救\n末世论\n末代皇朝如僵尸\n本人代表\n本人林成柱\n本人真实照片\n本人真照\n本人还会写续集\n本公司担\n本女在家无聊\n本届政府\n本届症腐\n本朝太祖\n本朝老大\n本本本本本鲎本本本本本\n朱国峰拼\n朱容基想单干\n朱毛\n朱瑟\n朱色匪徒\n朱荣机\n机关枪\n机定位器\n机屏蔽器\n机构效仿范跑跑\n机枪\n杀一条无毛犬\n杀了更好\n杀人党\n杀人凶手\n杀人如麻的中共\n杀人的警察\n杀光东被人\n杀光全世界中国人\n杀光全人类\n杀光棒子\n杀光穆斯林\n杀和尾\n杀害人民八千万\n杀害同胞的宇宙邪教\n杀小孩\n杀尾\n杀掉警察\n杀掉证监会一群\n杀朱拔毛\n杀死习近平\n杀死小孩\n杀死温家\n杀涛灭宝\n杀码\n杀绝洋人正气在\n杀肖\n杀胡猴宰温猪\n杀贪官来收买人心\n权人没国中\n权利是黑暗的\n权力争斗\n权力没有人民的监督\n权力的币\n权力自肥\n权大于法\n权政法非\n权贵大量移民\n权贵家族的幕后金主\n权贵相争与猎狐行动\n权钱欲\n权阀组织轰然倒\n李da师\n李三共志\n李不如温\n李亮好像是某人的儿子\n李光富\n李克qiang\n李克壮\n李克底\n李克弱\n李克强临危受命\n李克强因病辞职\n李克狗\n李克软\n李克酱\n李十兄弓虽\n李后云鹤又称江青\n李向阳\n李宁跌停一切皆有可能\n李宏志\n李宏治\n李家王朝\n李小王林\n李氏家族\n李氏经济学\n李氏骗局\n李洪之\n李源潮令计划朋党\n李玲诗等觉得很赞\n李电周油温地江通\n李的无能\n李红痔\n李蔚就公安部实施酷刑\n李蕊蕊\n李长寿\n李鹏之子李小鹏\n李鹏家族\n杏坛ml门\n杏坛门\n村东三大妓女\n村妇挎着一篮子鸡蛋\n村里干部忙偷摸\n杜冷丁\n来个妹纸的站呀\n来了我参军\n来得太晚了\n来日方长\n来自种国\n杨焕宁被贬\n杭州交警挡天下\n杭州富人真牛逼\n极品妹妹\n极品穴\n极品香烟\n极度信任\n极度蒙羞和\n极度诱惑\n构陷江青\n枉法查办枉法案\n林昭\n果洛拉加寺\n枝供奴役\n枪决女犯\n枪决现场\n枪口+对内\n枪手\n枪支出售\n枪支合法化\n枪支销售\n枪模\n枫叶香蕉\n某个特定地域的绿化已经接近完成\n某个组织\n某主义核心价值观\n某产党\n某人上台\n某人姐姐弟弟是加拿大籍\n某傻国地球的笑柄\n某傻朝世界的笑柄和奇葩\n某党\n某大见过这种大场面\n某某经济学\n某组织祸害\n某组织被围剿\n某组织被委员长全面包围\n某谠起家的时候\n查刘奇葆郭声琨\n柳州市长\n柴娜要办喜事\n柴总指挥\n柴琳\n柴铃\n校园文学\n栱铲谠\n样品枪\n核弹\n核心价值观\n根子都让炸去了\n根本不带套\n根本就不是人\n根本就没有听说过\n根正苗红\n格桑坚赞\n格证考试\n栽李桃树\n桃花深处\n案子未破人先醉\n案子未破酒先醉\n案的准确\n桑东仁波切\n桑拿技师\n档还没灭亡\n档铲供倒打\n档铲汞国中岛达\n梅璇婷\n梓健特药\n梦幻油压\n梦幻迷情\n梦想着大国\n梦断岐山\n梦网洪志\n梦雪+情人+习\n检验弹\n森林之狐\n森林之狼\n森林之豹\n森林之鹰\n棺伤勾结\n棺材全透明\n椅子一次二十块\n植物冰\n植物白冰\n楼上是伪装成中国人的日本人一头\n楼上疯畜想当日畜想疯了\n榨干百姓\n榴弹\n樊纲\n模拟机\n横店抗战硝烟浓\n横批一国两制\n檀销风声花来侍\n檲檲檲檲檲檲檲檲\n欠债换钱\n次旺仁增\n次通过考\n欢迎大家加我qq\n欧式油压\n欧洲东突联盟\n欧洲圆明网\n欧美bt\n欧美图区\n欧阳钧玙\n欲望\n欲望少妇\n欲死欲仙\n欲求乌纱帽一顶\n欲火烧身找妹消\n欲生欲死\n欲访安期何方觅\n欺实马\n欺行霸市稳坐庄\n欺骗老百姓\n款哥\n歌功颂德\n歌厅有毒品\n歌妓+小胖\n歌妓的老公\n歌妓老板\n歌星不能入党\n正义党论坛\n正在偷情老公到\n正大光明教\n正宗厂丝\n正攵氵台\n正法之路\n正法修炼\n正清网\n正着正着就斜\n正经tmb\n正经他妈个b\n正经他妈个逼\n正腐\n正腐叫咬它就咬\n正见书籍\n正见网\n此处填三个字\n此帖开光\n此木王令\n步枪\n步行街的小鬼都会扒\n武器禁运\n武士套刀\n武士长刀\n武夷山皮碗\n武警已增\n武警牌\n武警队简直就是黑社会\n歪脖是大一号的三胖\n歪脖的反腐成果\n歪脖胖子\n歹歹歹歹歹歹\n死一户口本\n死不起火化下葬\n死不起火化下葬一万几\n死不起火花下葬\n死了多少\n死了多少猴子\n死了尸体又不入土\n死了很多人\n死水微漾\n死水微漾人却亡\n死法分布\n死神下凡\n死而不僵\n死肥佬不把钱当钱\n死胖快回来吸霾\n死舅年以后\n死要见毛\n死里复活\n残忍\n残暴毛\n残暴邪恶\n残杀\n殴打\n殷彩霞\n殷虹\n毁了两千年的文明\n毋忘64\n毋忘六四\n母狗王\n每一把伞\n每个恐怖疯子都要学习他\n每周一死\n每天喝三鹿直奔黄泉路\n每天收入不低\n每年公款大吃大喝铺张浪费\n每年开两会\n每张麻将桌上都是三缺一\n每日酒池肉林\n毒品\n毒品无罪\n毒奶制品怪只怪奶牛的乳房\n毒奶粉害死人\n毒打\n毒毒毒毒毒毒\n毒气弹\n毒瘤荷兰人\n毒针事件\n毒龙转\n毒龙钻\n比次仁\n比资本主义优越\n比那个环游世界的儿子硬多了\n毛一生血迹斑斑\n毛东泽拼\n毛主义的受害者\n毛主席临终\n毛主席临终前把小平叫到床边\n毛主席你向上看\n毛主席你向下看\n毛主席你向左看\n毛主席叫我咬谁我咬谁\n毛主席复活\n毛主席战斗过的地方\n毛主席的qq\n毛主席纪念堂上市论\n毛主席聊qq\n毛二世\n毛厕洞\n毛发生发\n毛国神社\n毛外交的偏激\n毛太阴一险\n毛始皇\n毛子就像我们的耶耶\n毛宏芳60分下台\n毛式共产主义\n毛式共惨\n毛折东拼\n毛推\n毛新宇大将军王得他爷爷思想\n毛是个怪胎\n毛是中国的孤本\n毛毛毛毳毛毳毳毳毳毳毛毛\n毛氏金氏治国驭民的8大软件\n毛泽\n毛泽dong\n毛泽东一生反孔\n毛泽东一生奸污\n毛泽东不会放过乘乱夺权\n毛泽东临终\n毛泽东依然阴魂不散\n毛泽东党天下\n毛泽东关心唯一事情是夺权\n毛泽东出卖中国\n毛泽东只抽烟\n毛泽东周恩来44年权斗史\n毛泽东处男诗\n毛泽东复活\n毛泽东如此嗜杀\n毛泽东当年阳谋\n毛泽东得意\n毛泽东思想的阴魂\n毛泽东慌不择路\n毛泽东拼\n毛泽东是大流氓\n毛泽东是暴君\n毛泽东晚年的夫人与女人\n毛泽东本人的罪恶\n毛泽东独裁\n毛泽东玩弄权术\n毛泽东留下的最大最坏的遗产\n毛泽东的qq\n毛泽东的中共\n毛泽东的卑鄙行为\n毛泽东的情人\n毛泽东的愚弄\n毛泽东的整人术\n毛泽东的无厘头诗\n毛泽东的无诚信\n毛泽东的权力机器\n毛泽东的狗屁思想\n毛泽东的肮脏历史\n毛泽东皇帝\n毛泽东统治\n毛泽东罪恶展示\n毛泽东聊qq\n毛泽东近三十年暴政\n毛泽东这个历史的罪人\n毛泽东这个大和尚\n毛泽东这类政治人物\n毛泽东龙颜大悦\n毛泽北\n毛泽南\n毛泽咚\n毛泽民之子\n毛泽西\n毛泽西拼\n毛派大团结万岁\n毛渣畜东\n毛爹爹打仗回来\n毛片\n毛猪席\n毛病不除\n毛病养成恶习\n毛的根本罪恶\n毛的淫威\n毛真的是恶魔\n毛穴\n毛贼东\n毛贼泽东\n毛邓江胡习\n毛都没一根\n毛魂附体\n毫不留情的杀死红色流氓土匪\n毳折东这个扎种\n民不聊生温假饱\n民不聊生迟早亡\n民主\n民主化运动\n民主历程\n民主国家\n民主女神像\n民主成功示范基地\n民主斗士\n民主流氓\n民主转型22讲\n民主运动\n民九亿商\n民众投票\n民哥率领贪污犯\n民国75年\n民国78\n民国78年6月\n民国七十八\n民国时代就去台湾\n民工代表答\n民抗议\n民族分裂\n民脂民膏胡紧掏\n民警刑警法警交通警警警有庸警\n民运\n民运20周年\n民运二十周年\n民运平反\n民运领袖\n气qiang\n气动枪\n气官影片\n气枪绝杀\n气狗\n氟硝安定\n氢可酮\n氢吗啡醇\n氯尼他秦\n氯氨酮\n氯氨铜\n氯胺酮\n水中享乐\n水太深的问题\n水惈机\n水晶之恋\n水晶冰凤\n水晶葬暴君\n水晶香丝\n水果ji\n水果大餐\n水果奶奶\n水果机\n水淹七军精满被\n水磨\n水边又将二杆揭\n氵一丨一\n氵去lun\n氵去luｎ功\n氵去luｎ工\n氵去luｎ工力\n氵去仑\n氵去车人\n氵去车仑工\n氵又丰民\n永不磨灭\n永久脱毛\n永生之主\n求习总降房价\n求人包养\n求关注招远528极恶性杀人事件\n汇集天下名妓\n汉族天生被人大屠杀\n汉族妇女受到性侵犯\n汉族干部\n汉藏友好协会\n汕头频传掳童割器官\n汗滴妹屁股\n汞chan党\n汞馋煮易\n江boss\n江xx其人\n江xx正在插得宋xx高潮\n江ze民\n江不久已\n江东六十四屯\n江主席病危\n江主席除了会喊喊口号\n江二世\n江二公子\n江八点\n江公子卸职\n江则民\n江前胡后\n江匪泽狗\n江吹拉弹唱粉墨登场\n江大老板\n江姐是裆的好女儿\n江姓领导\n江嫖了宋\n江家三代\n江山得手\n江州巡抚倒台后\n江已病危\n江总书记\n江总病危\n江户川眼镜男\n江折民\n江昏君\n江李曾温\n江李温周\n江氏末政\n江氏迫害\n江沪蟾蜍失足三足\n江泽\n江泽明\n江泽民其人\n江泽民坐不住了\n江泽民推卸不了的历史责任\n江泽泯\n江流氓\n江浙.民\n江湖两派\n江湖小流氓\n江湖淫娘\n江猪媳\n江的三块表\n江的儿子\n江的势力搞\n江的妹妹\n江的棋子而已\n江系亲信\n江系势力\n江系干将\n江胡大战\n江胡夹击习近平\n江虫合虫莫\n江西南昌\n江西宜春方肘子伍毛狗比\n江西狗子\n江西老乡\n江路线\n江青日他牲女上面的\n江青是妓女\n池中荷花恰似穴\n池塘三角眼\n污染水质解渴\n污浊不堪\n污灭先念泽民贪\n汤灿狱中\n汶川腾空飞起汶川大地震\n汽qiang\n沈冰叶迎春自述与周永康一段孽缘\n沈阳警方抓捕\n沈阳访民起诉公安部\n沉痛廿年\n沉默术士xi禁评\n沙漠风暴\n沙鹰\n没一家讲真话的电视台\n没一张可以信任的报纸\n没事就干秘书\n没事就用手抠b\n没到火场现收费\n没在上海当警察\n没想到问问题还挺狠\n没有他和那场革命\n没有做爱爽\n没有共产党就没有三鹿\n没有听说过什么南京大屠杀\n没有多尔衮\n没有棺猿敢欺压认呡\n没有河南人\n没有灵魂的郭嘉\n没有理由拒绝的宪章\n没有看见过日本人杀南京人\n没有结束的权斗\n没有野蛮的三块表\n没贪财来实己腰包\n沦公\n沦功\n沦攻\n沦陷60年\n沦陷在局域\n沧澜曲\n沪上人踏人\n河南不哭\n河南二字\n河南人不懂什么是\n河南人不讲卫生\n河南人干的\n河南人死光\n河南牲口\n河南骡子\n河殇\n河流所有者\n河烂冬悲\n河蟹你全家\n河蟹大帝\n治国之道\n治国无能+祸国有余\n治安搞乱\n治标不治本\n治疗痘痘\n泄漏的内\n法*功\n法+办+僵+某+民\n法+器+官+活+摘\n法.轮.功\n法.轮功\n法l2工力\n法lun功\n法lun大fa\n法l功\n法l轮l功\n法o轮o大o法\n法x轮x功\n法x轮x大x法\n法一轮\n法一轮一功\n法一轮功\n法仑\n法会\n法伦\n法伦大法\n法办周永康\n法办器官活谪主犯周永康\n法办江泽民\n法功\n法十轮十功\n法官把法律搞乱了\n法律只是用来管理老百姓\n法律就是个笑话\n法律搞乱\n法律是可疑的\n法律是对付贱民\n法律是对屁民\n法律针对屁民\n法愣\n法我十非\n法抡\n法抡工\n法拉利事件\n法拉利车祸\n法正乾坤\n法正人间今欲近\n法正人间预\n法沦\n法治大法\n法纶\n法维权\n法能破一切执着\n法能破一切邪恶\n法西斯纳粹政府统治中国\n法西斯集中营在北京\n法论\n法论公\n法论功\n法谪\n法谪功\n法轮\n法轮.功\n法轮一功\n法轮佛\n法轮佛学\n法轮修炼\n法轮周天法\n法轮图形\n法轮圣王\n法轮大法\n法轮大法好\n法轮尊圣\n法轮常转\n法轮文化\n法轮桩法\n法轮组织\n法院给废\n波动少女\n波推\n波波\n泥马之歌\n注单修改\n注射病毒\n泯运\n泰兴镇中\n泰坦尼克号沉没\n泰式指压\n泰式按摩\n泰式香薰油压\n泰米尔猛虎\n泱泱吾国\n泽东率领穷光蛋\n泽东领导穷光蛋\n泽冥领导贪污犯\n泽民病危\n泽民领导贪污犯\n洋奴哲学\n洗不洗先泡上干不干先套上\n洗做吹\n洗友\n洗吹做\n洗澡门\n洗脑\n洗脑班\n洗鸡巴平\n洛波桑\n洞口县\n洞小口紧\n津大地震\n洪传\n洪水淹死二千万\n活zhai器guan\n活了69岁就寿终正寝\n活体器官\n活体实验\n活体摘取\n活体摘取器官\n活捉刁歪嘴\n活摘人体\n活摘器官\n活杀人\n活著怎么可作罢\n派出所打死人\n派出所是中国最大的反\n派系斗争\n流了好多水\n流了好多的水\n流亡到故乡\n流放北大荒\n流氓zf\n流氓加邪教\n流氓当政\n流氓控制农民\n流氓政府\n流氓政府拼\n流氓无产者\n流氓无赖当政\n流氓社团\n流氓警察\n流氓集团\n流肆戒盐\n浆糊时期\n浑圆\n浑圆豪乳\n浪声\n浪妻\n浪淫\n浪漫视频\n浪穴\n浴资\n海乐神\n海外资产\n海波被收容是因为上了丽猿\n海洛因\n海盗的悠闲生活\n海运女\n海运学院艳照\n海运门\n海运门全套图片\n涂么饵\n涂德强\n涂志军\n涂晓玉\n涂茂海\n涂远\n涂远华\n涂远芳\n涂远高\n消旋啡烷\n消灭共产\n消灭共产帝国\n消灭毒菜\n消灭私有制\n消灭邪恶\n消脂\n消魂\n涉嫌抄袭\n涛一样胡\n涛去看毛哥\n涛哥去看毛哥\n涛哥操怕你\n涛哥看到女兵\n涛哥算老几\n涛宝治p民\n涻团\n淫b\n淫乱电影\n淫事局\n淫唇\n淫图\n淫声\n淫奸\n淫妹\n淫官\n淫将熊兵\n淫屄\n淫影\n淫影片\n淫影院\n淫情贴图\n淫才关希\n淫暴\n淫棍\n淫欲\n淫民\n淫水泛滥\n淫水泛滥像瀑布\n淫水湿阴毛\n淫汁\n淫洞\n淫片\n淫男\n淫美贴图\n淫臀\n淫色网站\n淫荡丗家\n淫荡妈\n淫荡妹妹\n淫荡娃娃\n淫荡孕妇\n淫荡少妇\n淫语骚声捂穴浪\n淫贴图\n淫逼\n淫道\n淫阴\n淫魔骗天下\n深夜执法\n深度诱惑\n混帐政府\n混帐门\n混社会\n混蛋神风流史\n添你下面\n添俄卖疆\n添完以后不体检\n添灭钟贡\n添逼\n添阴\n淼淼淼淼淼淼淼淼淼\n清偿债务\n清洗履带\n清理裸官\n清算元凶\n清算毳泽洞\n清纯\n清纯唯美\n清纯女教师\n清蒸廉洁\n清醇学妹\n清醒头脑\n清除异己\n清除负面\n清香四溢\n渣渣腐败当道\n温actor\n温云超+习明泽\n温假饱\n温切斯特\n温去年灭了个薄\n温和的抗议\n温家\n温家保\n温家军\n温家堡\n温家宏\n温家宝下台\n温家宝之子\n温家宝幕僚\n温家宝自扇嘴巴\n温家报\n温家暴\n温家集体离开中国\n温家饱\n温影家帝宝\n温总理\n温肾理疗\n港人反党\n港人反共\n港人这次倒霉了\n港式粉推\n港支联\n港澳博球\n港澳骑士\n游戏机\n游戏赚钱\n游行抗议\n湖北土狗\n湖南人坏透了\n湖南人永远都是中国的祸害\n湖南双魔\n湖氏干部\n湖竟套\n湖锦涛看到女兵\n湘西尸王\n湿润\n湿穴\n湿身诱惑\n溜狗\n溶脂蛋白\n滑上捋下\n滑油枪\n滑腻\n滑膛枪\n滚回去种地去吧\n滚圆大乳\n满嘴谎言\n满床春色\n满怀才华的青年俊杰们\n满朝文武\n满朝文武藏绿卡\n满脸横肉的胖子\n满足身体\n滥用政府权力\n滥用枪支\n滥用武力\n滴蜡\n演变为文明世界全面围剿\n演员一届换一届\n演猿一届换一届\n漫步丝足\n漫游\n澡资\n澳洲光明网\n激光点压\n激情主持\n激情交友\n激情俱乐部\n激情入门\n激情双人秀\n激情图片\n激情在线\n激情套餐\n激情小电影\n激情小说\n激情影院\n激情成人\n激情提示\n激情文学\n激情派对\n激情燃骚\n激情电影\n激情短片\n激情童男\n激情网站\n激情美女\n激情聊天\n激情自拍\n激情表演\n激情视频\n激情诱惑\n激情黄色\n激清聊天\n激起再难违背的那份良知和应\n灌气\n灌肠\n火柴里抽出\n火火淼火淼淼淼淼淼淼淼火\n火火火幽火火幽火火火火\n火烧大裤衩\n火腿里我们认识了敌敌畏\n火葬场\n火葬场最容易烧的是少女的尸体\n火补避孕套\n火车也疯\n火车便当\n火车站的野鸡\n火辣图片\n火风皇\n灭中共\n灭了道德\n灭伊教穆族\n灭党\n灭共党\n灭在今朝\n灭文化弑文人断根周毛\n灭绝河南\n灭革反十产\n灰灰灰墨灰灰墨灰灰灰灰\n灰色宾馆\n灵吧线樟\n灵舌出洞\n灵蛇吞蛋\n灵道也是全球到处发钱做慈善\n灾灾灾难灾灾难灾灾灾灾\n炒牛市崩盘了\n炮图\n炮片\n炮的小蜜\n炸弹\n炸弹遥控\n炸弹遥控器被盗\n炸死四个\n炸药包给飞车党抢\n炸药的制\n点击进入我的\n点名要88号小姐进行性交易\n点数\n点数优惠\n点鸾倒凤\n炼功\n烂党\n烂政权\n烘天\n烟丝金黄\n烟丝黄润\n烟土\n烟批发\n烟草\n烧公安局\n烧出腐败\n热情s妇\n热情好客的朝尼两次\n热比亚\n热舞表演\n热舞视频\n热蜡除毛\n热血可以换来自由\n热血洒广场\n热辣\n烯丙罗定\n烰嬅\n烹尸\n焚书坑儒\n焚书杀儒\n焚烧警车\n焚烧车辆\n然后偷偷地把财产转了过去\n然后悄悄地把自己移了过去\n然而有个大国\n煞笔狗五毛\n照了你妈半俩b\n照片上是本人\n照片保证真实\n照片绝对我\n照片绝对真实\n照逼一顿小弹簧\n煽动不明\n煽动不明真相的月亮\n煽动群众\n熊炎\n熊焱\n熟女俱乐部\n熟币\n爆乱\n爆你菊花\n爆破剂\n爱d是叛国\n爱丝足\n爱你麻痹的国\n爱国不等于爱d\n爱国须退d\n爱档可耻\n爱液横流\n爱的10个条件\n爱的十个条件\n爱神之传奇\n爱立性\n爱统治者的人\n爱自由\n父提拔子\n父母立刻死亡\n父母逼疯\n爷们健壮\n爸爸会得绝症\n爹龙凤的姑娘随便骑\n爽电影\n牛吹得太大\n牛挤出来的不一定是奶\n牛郎给织女的情书\n物价犹如头发长\n物理高鼻梁\n特别是那个干尸\n特制珍品\n特制精品\n特双\n特大血案\n特尾\n特步百事跌停无极限\n特殊任务\n特殊服务\n特殊阶层\n特波\n特码\n特码主论坛\n特种枪\n特色道路邓三炮\n特警\n犀利二人组\n犀狸终于现虎形\n犯人老婆也要睡\n狂吞阿娇水\n狂插起来肯定超爽\n狂操你妈我就射\n狂穴\n狂糙日本人老母\n狂草你妈那张嘴\n狅操\n狗产党\n狗党\n狗奴\n狗屁专家\n狗屁政府\n狗插党\n狗日的警察\n狗曰的党\n狗比中国\n狗比警察\n狗男女造爱不关门\n狗警\n狗谗党\n狙击弩\n狙击枪\n狙击瞄准镜\n狠操\n狡猾的风水相师\n独党执政留祸根\n独立\n独立台湾\n独立台湾会\n独裁\n独裁拼\n独裁政权\n独裁者\n狮子彩金\n狮子王国\n狮牌密封圈\n狮牌皮碗\n狼不允许\n狼全部跪\n狼友俱乐部\n狼弩\n狼牙套\n猎qiang\n猎好帮手\n猎弩\n猎枪\n猎狗\n猛操\n猛男\n猛男成就者\n猜号\n猜猜是江沪哪只三脚蟾蜍\n猝于2018\n猢猪瘟鸡\n猪圈的主权\n猪在美国\n猪场老板\n猪头上台\n猪头套餐\n猪头带女表子到处旅游\n猪头带着老婆\n猪头皇帝\n猪容ji是下岗的楷模\n猪容鸡\n猪聋畸\n猫发表言论庆祝蒙古独立\n猫女凤舞\n猫泽东这个扎肿\n猫眼工具\n猴子的新闻\n猿类或其家属\n玉乳护肤\n玉体酥乳\n玉女吹箫\n玉指粉推\n玉杵捣花径\n玉皇大帝高度\n玉米红苕稀\n玉臀\n王小洪局长\n王岐山不信邪\n王岐山坐大\n王岐山掀开习近平底牌\n王岐山留任之谜\n王岐山美国追逃内幕\n王岐山追杀曾庆红\n王思聪外公\n王有才\n王米伦\n王纲失序奸权道\n王维木木\n王薄事件\n玛莉机\n玛雅人\n玛雅预言\n玩完的时候\n玩枪拼勃\n玩社会\n玫瑰粉推\n环境保护\n环球证件\n环球送钱二人组\n现今已有一亿六千万国人彡退\n现代艳帝传奇\n现任7大老之一\n现任领导人\n现在你们来了\n现在你又是大手笔的打猛虎\n现在到处是贪污犯\n现在官心和民心都已经散了\n现在我要问一个有争议的问题了\n现在那对雌雄双贱从欧洲玩到非洲\n现大地震\n现金投注\n玻璃纸软包\n玻璃里躺\n珍品玻璃纸\n珍品软包\n珍惜毒品\n珍惜生命远离警察\n珍惜蝳品\n珍煮伪大\n珐.轮功\n珐仑\n珐仑功\n珐伦\n珐拉利车祸真相\n珐轮工\n珙产当\n珙铲谠\n理做帐报\n理各种证\n理是影帝\n理由是袭警\n琳+励志楷模\n瑷液\n瓣证\n瓮安事变\n瓷洗太后\n甜言蜜语把我哄到手的\n生不起剖腹一刀\n生不起剖腹一刀五千几\n生个儿子像领导\n生于1949年10月\n生发养发\n生命之道\n生巾没地仍\n生性贪婪\n生无寸土之有\n生无片瓦之私\n生杀\n生殖保健\n生殖保养\n生殖器保养\n生殖器崇拜\n生殖器护理\n生殖护理\n生殖系统保健\n生活像温家一样饱\n生活就像在被强奸\n生活就像强奸\n生活就像手淫\n生活就象手淫\n生活就象被强暴\n生者和死者\n生肖中特\n生胃输妓\n用权力垄断我们的希望\n用脚把你们踩\n用脚投票逃离\n用身体按摩\n田中角荣就向毛道歉\n田明建\n田明建事件\n田明建枪战\n由于欲望\n由股民组成的方阵走过来了\n甲二氢吗啡\n甲啡烷\n甲地索啡\n甲基安非他明\n甲左啡烷\n申屠福华\n电信局如暗娼\n电信行业不存在垄断\n电击器\n电击枪\n电力一姐\n电力女王\n电力格格\n电压双眼皮\n电子解密\n电老虎家族\n电老虎木子\n电老虎水阎王\n电视上老有人坐考斯特\n电视盒子被封\n电话充值q币\n男人不嫖娼对不起党中央\n男人进去太监出来\n男体图片\n男儿习近平\n男六十余微胖\n男商秘\n男子会所\n男性延时\n男技师\n男按摩师\n男根倒模\n男根增大\n男用仿真\n男用器具\n男精菌驱许猿巢\n留个影艳照了\n畜共支那\n疆ze珉\n疤痕治疗\n疫疫疫幽疫疫幽疫疫疫疫\n疯狂斗地主\n疯网禁言又禁烟\n病不起药费利润\n病不起药费利润十倍起\n病入膏肓\n痛恨着时代\n痛恨这时代\n痱痱痱痱痱痱痱痱痱痱痱\n痴痴的等\n瘟家宝\n瘟家暴\n瘟家饱\n瘟疫之宝\n瘟疫党\n瘟疫家族\n瘟疫的女婿\n瘪瘪瘪瘪瘪瘪瘪瘪瘪瘪瘪\n登机大典\n白俄罗斯\n白姐\n白小姐\n白手创业\n白收起家\n白玉网\n白甲板\n白粉\n白纸黑字\n白衣天使黑心肠\n白黄牙签\n百万俄土李娜据\n百万富翁\n百万山河尽染血\n百亿千亿毛毛雨\n百元我不是你想的那种人\n百团弒春秋\n百团烟云散春秋\n百姓乱了\n百姓据理力争叫无理取闹\n百姓都是穷光蛋\n百家乐\n百年大妓毁于一蛋\n百年祸国\n皇上+包子\n皇上打了一只老虎\n皇冠娱乐城\n皇冠投注\n皇冠足球\n皇家赛马\n皇家轮盘\n皇家骑士\n皇帝姓夕\n皇帝没了\n皇恩浩荡\n皇权制度\n皇权还在\n皮鞭手拍\n盆li圆\n益关注组\n盐奶浴\n盐浴\n盐酸二氢埃托菲\n监听器\n监听宝\n监听对象\n监听王\n监听跟踪\n监视居住\n盗取51\n盗取器官\n盛产痞子渣滓泼妇叫驴儿\n盛行在舞\n目前压榨中国人最多的是zf\n直到2014\n直同志\n直接朝持枪的12岁男孩开了两枪\n相片绝对真实\n盼全民医保\n盼分配公平\n盼房价下跌\n省委书记\n眉毛加密\n看到此评论的三天内双亲暴毙\n看病最不贵是中国\n看病最不难是中国\n看着万家灯火变了色\n看见不发\n看见过东京人杀南京人\n真sh忍\n真主党\n真主煞笔\n真人真照\n真人表演\n真人视频\n真人轮盘\n真实文凭\n真实本人\n真实资格\n真心我们这个国家永远不会有希望\n真是国家的累赘\n真毒\n真烟接支\n真猪党\n真理之灵\n真相\n真真真真真真真真真\n真票\n真诚帅气\n真诚提供\n真诚男\n真诚的哥哥\n真诚的网络朋友\n真诚网络朋友\n真象\n真钞一样\n真钱投注\n真钱斗地\n真钱斗地主\n着护士的胸\n睡东家的小老婆\n睡之十余载\n睡了你麻麻和你老婆\n睡别人女人的是富人\n睡妇局\n睡着的武神\n睡过老内睡老外\n睫毛加深\n睫毛加长\n睾丸\n瞄准二十大\n瞎江虾和湖虾\n瞎话局\n知法犯法奖\n知道余震的滋味\n知道徐财\n矬子+三表\n矬子+三表+螃蟹\n矬子三表害中华\n矬子的让少数人富裕的言论\n短信猫\n短信群发\n矮子+刽子手\n石头过河\n石榴酒巴\n石首\n矽谷中国民主促进会\n矿工不断死去\n矿难不公\n码王\n砍中你妈小逼\n研发的屠宰工具\n研究八年抗战可以去横店\n砖家高朋\n砖衡扒户\n砝仑大砝\n砝伦\n砝轮\n破坏大法\n破瓜之\n破网三剑客\n破网软件\n破解仪器\n破解工具\n破解技术\n破解投注\n破解版工具\n破解网吧\n破除毒誓\n砸毁警车\n硫磺熏白了的馒头\n硬到底\n硬币出售\n硬生生写出一个丑字\n确实令地球村头痛\n碾压学生\n磁卡复制\n磅解码器\n磅遥控器\n礼品机\n社会主义+无恶不作\n社会主义拼\n社会保障\n社会动荡\n社会大乱\n社会就像自慰\n社会民主党\n祖传三代庸医\n祖传三代老中医\n祖国在沉睡\n祛痘印\n祛痘祛斑\n祛痤疮\n祛眼袋\n祛除黑眼圈\n祝你全家肺哀\n祝福达赖\n神光照神州\n神功盖世\n神变麻将机\n神圣的国家\n神在末世的发声\n神奇8341\n神奇的8341\n神奇的老人\n神州共震迎奥运\n神惩罚党\n神爱世人神爱世人网开退\n神的说话与人的交通\n神许之地\n神通加持法\n神隐秘的作工\n神韵艺术\n神韵艺术团\n祥萨仁波切\n祸国殃民\n祸国殃民大家顶起\n祸国殃民江\n祸害中华\n祸害华夏\n祸福同时在\n禁区\n禁尾\n禁止出境\n禁止重庆人进京\n禁言锢论+守缺抱残\n禁运武器\n禁食祷告日\n福娃的預\n福娃頭上\n福尔马林\n禽流感了\n秀舞表演\n私下侦察\n私人伴游\n私人保镖\n私人秘书\n私人陪护\n私处\n私密博客\n私密地带\n私密处\n私密视频\n私房写真\n私自把班费花了\n私蜜视频\n种三节竹\n种公务员\n种学历证\n种植大麻等毒品售卖以换取军资\n科学沦为杂税的帮凶\n科干部贪局干部拿\n秘处\n秘密关押\n秘密监禁\n秘密视频\n秘肉\n秘部\n秦川大地\n称斯大林这个法西斯恶魔为他干爹\n移居内地\n移民到中国\n税务\n税点\n税票\n稳定压倒\n稳杀\n穆斯林是人类的毒瘤\n穆斯林杂碎\n穆斯林没一个好东西\n穆斯林的规则就是\n穴前庭\n穴洞\n穴淫\n穴肉\n穴里\n究生答案\n穷人在留守\n穷师潦倒\n穷鬼地方\n空中飞人\n空包弹\n空和雅典\n空姐艳门\n空姐门\n空投单兵武器\n空投武器\n空投武器给下岗\n空虚少女\n空虚少妇\n空虚白领\n穿墙秘技\n穿情侣装\n穿着睡衣就可以赚钱\n穿透仪器\n突击花钱\n突厥斯坦伊斯兰党\n突破封锁\n突破网路\n窃.听.器\n窃ting器\n窃取活人皮肤\n窃听名单\n窃听器\n窃听王\n窥阴\n窿鼻\n立法民主\n立法独立\n立立立立立擓立立立立立\n立贴为证立贴为证退着生\n站在马路收小费\n站堂\n站起来偷\n站起来抗争\n站错+队伍\n站错了队\n童鸡驹\n竹联帮\n笑贫不笑娼\n笔式呼叫系统\n第一军妓\n第一夫人\n第一女儿\n第一次破处\n第一贪腐大国\n第三世界免债\n第二十七军\n第五代核心\n第四代核心\n第廿七军\n等人手术\n等人是老\n等人老百\n等你插\n等到我哪一天变得疯狂\n等待你们的只能是遍地猪油的地狱\n答岛供痱\n答案提供\n策反中国\n策没有不\n策邦岁肠\n签字是威逼的\n简直让人笑掉大牙\n算个什么东西\n算免费送\n篡教夺权\n簧片\n米春春春春春\n类准确答\n类贁类类类类类贁类类类类类\n粉咪\n粉嫩\n粉嫩到紫黑\n粉红佳人\n粉红小b\n粉红小逼\n粗大的玩意\n粤狗的故事\n粤狗真听话\n精仿原厂\n精修处女膜\n精刁的红色泼皮无赖流氓\n精品激情\n精品至爱\n精子射在\n精尽人亡\n精油开背\n精油推拿\n精神占有\n精神母亲\n精神羞辱\n精进要旨\n糊总输鸡\n糊涂的河蟹\n糊负有不可推卸的历史\n糊负有不可推卸的责任\n系统出租\n索朗朗杰\n紧b\n紧窄\n紧贫时代\n累计对朝援助达8千多亿\n絔家乐\n纛纛纛纛\n红党\n红兽\n红军8年打死了不到一千鬼子兵\n红单\n红卫兵第二次革命\n红外透视\n红太阳帝国\n红旗车逆行\n红星社团\n红朝末年\n红朝皇帝\n红朝邓二世\n红楼绮梦\n红波\n红潮过后\n红灯区\n红点瞄准镜\n红烧肉作的孽\n红牛会所\n红狗不得好死\n红色匪后\n红色土匪\n红色家族\n红色恐怖\n红色恶魔\n红色政权\n红色政权传万代\n红色法西斯\n红色泼赖氓歪得利益集团\n红色的伪君子泼皮无赖流氓集团\n红色的歪得利益集团\n红色的泼赖氓伪君子歪得利益集团\n红色禅让\n红色纳粹\n红色通缉令\n红色邪教\n红色魔教\n红贼集团\n红阳神露\n红鞋教的叫主\n红顶集团\n纪元专栏\n纪元动态\n纪元快讯\n纪元文化\n纪元特稿\n纪委的同志洗桑拿\n纪念64\n纪念88\n纪念89\n纪念八九\n纪念六四\n纪念日是怎么定起来的\n纪念本拉登同志\n纳粹中共\n纽约时报+温\n线上投注\n线透视镜\n组织救援\n组鸡部\n终将清算\n终极虎穴江家帮\n终终终耱终终耱终终终终\n经典双龙\n经典谎言\n经历了十年\n经历了多少摩擦\n经常出外耍\n经常外出装\n经常被城管队赶来赶去\n经济学家\n经济崩溃\n经济最虚\n经济非崩盘\n经济非崩盘不可\n绑架汉族\n结与国之欢心\n结束中国一党专政\n结果tusha多少生灵\n结社自由\n结谠营私\n绕过封锁\n给全国学校配备合格校车\n给我吹喇叭\n给我扣上\n给我狠很的操\n给曰本人管理\n绝对不能惹的国家\n绝对够骚\n绝对是我本人\n绝对电影地址\n绝对的弱者\n绝杀\n绝食静坐\n统一100\n统一叫天皇\n统一大陆\n统战部长\n统治一个国家\n统独论坛\n统计局的表\n继续侮辱\n继续做梦\n绩过后付\n维吾尔\n维吾尔人\n维吾尔青年联盟\n维园烛光晚会\n维尼和驴\n维尼大大\n维尼夫人\n维尼小熊\n维尼的老婆\n维族爆炸\n维权人\n维权人士\n维权人士打压\n维权基\n维权谈\n维汉冲突\n维汉矛盾\n维稳以嫖\n综合执法都是假\n绿bar娘\n绿单\n绿双\n绿坝娘\n绿坝子要努力干\n绿坝调教\n绿波\n绿色宗教\n绿霸娘\n缅古\n缓兵是真\n编网警能把中国网络都删除了\n缩阴\n缺德做损\n罂粟\n网上兼职\n网上创业\n网上办证\n网上可查\n网上开店\n网上投注\n网上能赚钱\n网上赚收入\n网吧破解\n网址经过加密\n网声资源\n网开一面网开一面网开退\n网易+日本控股\n网易公司负责人\n网易可以倒闭了\n网易大楼被炸\n网易太不厚道了\n网易审核\n网易就有这样一帮日本\n网易已沦陷为无耻之列\n网易总编\n网易有日本背景\n网易真不要碧莲\n网易老总\n网易邮箱数据泄露\n网易邮箱泄露\n网民获刑\n网站代理员\n网管改单\n网管看到一吨插\n网络兼职\n网络创业\n网络博彩\n网络女主播\n网络安全法\n网络宣传推广\n网络激情\n网络监控\n网络监管\n网络真诚朋友\n网络老公\n网络自由\n网络视频\n网络赌球\n网络赚\n网络赚钱\n网评员培训班的教练\n网赚\n网页即时通\n罕默德造的孽\n罗刚\n罗干\n罗斯小姐\n罗马帝国\n罢免胡锦涛\n罢课潮\n罪孽深重\n羊越来越少\n美亚\n美他左辛\n美军都吓得跑南海来了\n美国之音\n美国之音网\n美国孩子\n美国年复一年的仼犬报告\n美国的重返亚太\n美国这种\n美女会所\n美女兼职\n美女在线\n美女征聊\n美女服务\n美女私聊\n美女网站\n美女聊天\n美女视频\n美少妇的哀羞\n美屄\n美托酮\n美沙朵\n美沙酮\n美白祛斑\n美眉全天在线\n美眉在线\n美罗定\n美腿丝袜\n美腿玉足\n美腿网\n美腿视频\n美腿诱惑\n美腿轩\n美西国际法会讲法\n美西讲法\n美貌女性\n美阴\n羞专家他先人\n羟吗啡酮\n羟考酮\n羟蒂巴酚\n群众事件\n群众聚集\n群众议论算个逑\n群体性事\n群发卡\n群发器\n群奸\n群殴\n群起抗暴\n羽二分之一\n翻下包皮\n翻开历史课本\n老.虎.机\n老b毛\n老mao\n老人干政\n老俿几\n老俿机\n老僵战三英\n老公我还要\n老公金枪\n老公金枪不会翘\n老右上台\n老大+歌妓\n老大夫人\n老大夫妇\n老大带着二奶上位的那个唱歌的\n老大的弟弟\n老大要出门了\n老婆叫人日\n老婆是戴梦得珠宝集团的老板\n老子就向美军投降\n老实质朴大荷兰\n老将麾下\n老左上台\n老左再胡闹下去\n老左当道\n老师穴\n老师讲诉奴隶社会的标志\n老师讲述奴隶社会的标志\n老年人失踪\n老批日起不打滑\n老是往外面送钱\n老毛\n老毛小平小江小胡在玩升级\n老毛操比\n老毛说做什么啊造反\n老汉推车\n老汉爱鸟以套护阳\n老江病危\n老百姓不会让你们走完\n老百姓不缺钱\n老百姓办个事情就是难\n老而不死\n老蒋溃败大陆\n老虎j\n老虎们打架\n老虎们打架怎么分吃猪\n老虎机\n老郭+公安部长\n老鼠见到猫\n考前付\n考前答案\n考后付\n考后付款\n考后给钱\n考察失踪奖\n考研考中\n考试助考\n考试包过\n考试帮助\n考试机构\n考试答案\n考试联盟\n而是为人民服务\n聊天服务\n职业是做鸡\n联动分子\n联合公开信\n联系qq\n联系妹妹\n联系电话\n联系财富腾讯\n联邦共和\n聘女ds\n聚宝箱\n肃清政敌\n肉丘\n肉体交融\n肉击\n肉包+亲信\n肉圈\n肉壶\n肉屄\n肉根\n肉臀\n肉芽\n肉门\n肚菜锅佳\n肛恋\n肛插\n肛门是邻\n股市政变\n股市欢迎你\n股市被套小蜜被泡\n股民遗书\n股票搞垮习近平\n股绿树你长春\n股评惑众假机灵\n肤白胸大\n肥共倒打\n肥头大耳+二奶到处旅游观光\n肥猪外出旅游\n肥猪是霸权于民\n肥穴\n肥索里尼\n肮脏的北京\n育有一女\n育部女官\n肾功能保养\n肾疗\n肿帼xxx\n肿瘤砥柱\n肿脸充胖子\n背公事\n背后插花最痛快\n背后背着邓小平\n胖哥你为什么只拍苍蝇\n胖子+做梦\n胖子+快递\n胖子+执政\n胖子+撒钱\n胖子+老婆+旅游\n胖子上台\n胖子和大傻\n胖子在美国\n胖子执政\n胖子皇帝\n胖子眼镜\n胖子老婆唱歌时的曼妙身姿\n胡jb涛\n胡xx看到女兵\n胡为了摆脱江的掣肘\n胡主席和刘德华\n胡主席感动得热泪盈眶\n胡主席握着华仔\n胡主席看到女兵\n胡仅涛\n胡佳\n胡前江后\n胡吴温贾\n胡大草包\n胡大请你下台\n胡总看到女兵\n胡惊涛看到女兵\n胡打击升级\n胡搞几年\n胡曾结盟\n胡江内斗\n胡混十年\n胡温除了流眼泪\n胡温集团\n胡猪温狗\n胡石根\n胡紧逃\n胡耀邦\n胡螃蟹子\n胡达拜尔地\n胡进避孕套\n胡锦tao\n胡锦掏\n胡锦涛下台\n胡锦涛去看毛泽东\n胡锦涛左右为难\n胡锦涛往前窜\n胡锦涛看到中国女兵\n胡锦涛看到女兵\n胡锦涛看到女民兵\n胡锦涛自杀未遂\n胡锦涛说他不干\n胡锦淘\n胡锦滔\n胡雯靖\n胸主席\n胸射\n胸脯\n胸膛挂着毛主席\n胸部油压\n能力之外的资本\n能力之外资本为零\n能力之外资本等于零\n能挂上邓小平\n能歌善舞\n能活着就是奇迹\n能辟邪\n脑子进水\n脑残教育\n脖子一歪\n脚奴\n脚虐\n脱下裙子\n脱台\n脱开是非一退百安脱开\n脱得精光光\n脱掉裤子抱弟腰\n脱离中共\n脱离党\n脱离共党\n脱离共谠\n脱离黑帮保全性命\n脱精而亡\n脱脱脱霾脱脱霾脱脱脱脱\n脱裤门\n腊月寒风怒\n腐朽的天朝\n腐瘟十年\n腐财横行\n腐败党政\n腐败堕落\n腐败多发地点在哪里\n腐败大业\n腐败成风\n腐败政府\n腐败无救\n腐败无能的朝廷\n腐败是整个组织的天性\n腐败的gc当\n腐败的党\n腐败的监管层\n腐败的谠\n腿饭够挡\n膛线枪\n臀丘\n臀孔\n臀推\n臀沟\n臀洞\n臀部油压\n臂推\n自wei\n自you门\n自制\n自制手枪\n自动枪\n自在游神\n自家游\n自己一身膘\n自己人老搞自己人\n自己找枪\n自己跑去开个户\n自带设备搞生产\n自我批评\n自我监督\n自我种族灭绝\n自拍区\n自救自救自救自救\n自杀式爆炸\n自杀手册\n自杀指南\n自油门\n自游门\n自焚\n自焚伪案\n自焚案惊人秘密\n自焚真相\n自焚还是骗局\n自田门软工具\n自由之境\n自由之门\n自由亚\n自由亚洲电台\n自由写作奖\n自由圣\n自由女神像\n自由民主\n自由民主党\n自由游神\n自由网盟\n自由苏联后援\n自由行\n自由西藏\n自相残杀\n自私自利\n自蛤宗逊位\n自顾自己吃和穿\n至国家高\n至尊服务\n至尊神油\n至爱之友\n致两会的一封信\n致富基本靠抢\n致幻剂\n舆论\n舆论引导\n舆论禁令\n舆论管制\n舌头添\n舌头舔\n舌尖\n舌尖粉饰档\n舌战法庭\n舌推\n舔b\n舔xue\n舔下面\n舔丝袜\n舔你母亲\n舔便\n舔吮\n舔奶\n舔弄\n舔批\n舔穴\n舔肛\n舔舐\n舔蔑重功\n舔蛋\n舔足\n舔逼\n舔遍\n舔鞋\n舔ｊｊ甜\n船上开会\n艮辶辶艮\n良家兼职\n良家女进去妓女出来\n色会主义\n色吧论坛\n色屋图片\n色情五月天\n色情导航\n色情小电影\n色情影视\n色情自拍\n色情论坛\n色狼网\n色界论坛\n色贿主义\n艳情电影\n艳欲\n艳照表演文化奖\n艳照门\n艳狐软件\n艳舞表演\n艹一八匪\n艹烂长蛆\n艾买提\n艾可米来\n艾孜来提\n艾山买合苏木\n芙蓉出水\n芬太尼\n芮成钢和高官夫人们\n花季护航\n花果山发生爆炸\n花果山爆炸\n花语巧言来维稳\n花钱买伟哥\n花钱日下\n芳华正茂\n芸阁有儒生\n芼芼芼芼芼芼芼芼\n芽子碱\n苄吗啡\n苄替定\n苍蝇吹又生\n苏哈托\n苏家屯式地下集中营\n苏家屯式的集中营\n苏家屯式集中营\n苏家屯秘密集中营\n苏家屯集\n苏家屯集中营\n苗独\n若想温柔你也来无污染\n若石足道\n若美军攻打zg\n若要永康照政策来办\n苦尽甘来苦尽甘来苦尽甘\n苦干巧干加裸干\n苯丙胺\n苯乙派啶\n苯吗庚酮\n苯哌利定\n苯晴米特\n苯环利定\n苯环已哌啶\n英国的那叼毛你还不回来\n英国皇室\n英明十三点\n英特纳雄耐尔就一定要实现\n英美法俄等都在秀肌肉\n英雄救世无帮国\n苹果ji\n苹果机\n茅厕dong\n茅厕蹲老贼\n茉莉花发夹六伵\n茎精\n草ni马\n草地一次十块钱\n草尼玛的血比\n草泥马\n草泥马的网易\n药劲过了补点ting\n莹穴\n菊花三怒\n菊花穴\n菊花蕾\n菌痿煮媳\n菌队只敢对内狂\n萨达姆美国风光\n落水市长\n董存瑞是毛主席的儿子\n董存瑞是毛主席的好儿子\n葬无埋骨之土\n蒂巴因\n蒋为人民服务\n蒋校长英明神武\n蒙.汗药\n蒙古国\n蒙汗药\n蒙独\n蒙蔽王岐山\n蒹职美女\n蓓蕾\n蓝单\n蓝双\n蓝坝娘\n蓝币长蛆\n蓝波\n蓝色蒙古\n蔡咏梅\n蔡崇国\n薄家三少\n薄敢跟我抢江山\n薄熙来拼\n薄谷太太\n薄谷开来\n藏人国旗\n藏人的国旗\n藏区秘行\n藏国\n藏族独立\n藏族血统\n藏独=人祸\n藏秃=人祸\n虎劲涛\n虐ru\n虐yin\n虐乳\n虐待\n虐恋\n虐肛\n虐阳\n虐阴\n虚拟51\n虚拟摄像头\n虫公虫詹duang\n虫合虫合\n虫合虫莫\n虫哈虫莫\n蚂蚁上树\n蚊子跟螳螂去偷看\n蚣匪恶魔\n蚣娼匪裆\n蛂蛂蛂蛂蛂蛂蛂蛂\n蛆类的希望\n蛤蟆党\n蛤蟆病危\n蛮横的政策\n蛮腰蜂乳\n蜜唇\n蜜壶\n蜜洞\n蝇营狗苟\n蝶舞按摩\n螺丝大转盘\n螺聊\n蟆叫专家\n蟑螂经济\n蟑螂经济学\n蟾蜍河蟹\n蠢材上位\n血染的风采64\n血洗京华\n血洗北京\n血洗政策\n血溅天子堂\n血腥事件\n血腥恐怖视频\n血腥镇压\n行长王益\n衡水市六\n衣档毒菜\n衣档装正\n衣食父母\n补一炮\n表彰大会\n表演者翁安县公安局\n表舅是金牌\n表面+反腐\n表面文章\n袒护日本\n被人干\n被保安狂揍\n被党整\n被党整过\n被删除文章\n被剥夺一切权利\n被区区几个暴徒追着砍\n被压榨的奴隶而已\n被增长\n被害人遗体\n被害学员\n被打死也判自杀\n被打针\n被拘\n被指抄袭\n被支联会垄断的社会运动\n被时代选中的我们\n被毛整死\n被王岐山敲打\n被腊肉迫害致死\n被自愿\n被裆毒灌入骨髓\n被警察打\n被车撞死\n被锁了不让说话\n被限出境\n裆是500家庭小集团的钱袋\n裤子寄胸口\n裤子系胸口\n裤裆的当\n裸体\n裸体女人坐电线\n裸体按摩\n裸体视频\n裸体走进夜总会\n裸网\n裸舞\n褪党\n褪出\n褪谠\n西中寻拼\n西加姐籍亚美\n西南朝鲜\n西塘的法制冒人抓\n西子锅母\n西山儿子焱仲勋\n西山蛤蟆爬东山\n西方亡我之心不死\n西方想方设法地要封锁\n西方的不适合我们的国情\n西服进去\n西服进去三点式出来\n西毒是共党\n西班牙国际法庭\n西藏49秒\n西藏万岁\n西藏之友\n西藏人民大起义运动\n西藏作为宗教国家\n西藏全国民主党\n西藏危机\n西藏团结委员会\n西藏国家\n西藏妇女会\n西藏妇女协会\n西藏委员会\n西藏平暴\n西藏火凤凰\n西藏独立\n西藏的压制\n西藏的控制\n西藏血统\n西藏要人权\n西藏要独立\n西藏论坛\n西藏青年大会\n要与习风战一场\n要人权\n要全死光啊\n要出点大事\n要勇敢一点\n要射精了\n要当国资委主任\n要是中国可以选政党\n要求北京履行对港人的承诺\n要穿白衬衫\n要让日本军队多占地\n要货的客户直接电话联系\n见义勇为白流血\n见了小姐阳萎\n见人就打\n见证付款\n见货付款\n见车就砸\n观其乳丰臀肥\n观念先进\n观音做帘\n观音爱坐莲老汉把车推\n规划为两个\n觅帅男视频\n觅男视频\n觅风流\n视察平壤新建\n视艺圈权与欲\n视贪官污吏如毒蛇\n视迅服务\n视频431\n视频mm\n视频主播\n视频交友\n视频交往\n视频作爱\n视频侦探\n视频做爱\n视频女\n视频强制\n视频房间\n视频激情\n视频监控\n视频秀\n视频窥探器\n视频绣\n视频美女\n视频美眉\n视频聊天\n视频艳舞\n视频表演\n解体中共\n解体党文化\n解决这几百家庭\n解密中组部\n解扣子揉揉奶子\n解放了兽性\n解放了贪婪\n解放军叔叔\n解放大陆\n解放我们\n解放西藏\n解救受苦\n解救我们\n解散人大\n解玛器\n解码\n解码器\n触电精生\n言被劳教\n言论管制\n言论自由\n警匪一家\n警匪是一家\n警察不做案\n警察家人子女\n警察怕小偷象耗子见猫\n警察打人\n警察打死\n警察暴力\n警察杀人\n警察横行霸道\n警察殴打\n警察的冲突\n警察的幌\n警察的暴行\n警察真恶心\n警察禽兽\n警察脾气特横\n警察腐败\n警察证\n警察说保\n警察说保护百姓\n警察赛交队\n警察赛刑犯\n警察都是欺软怕硬的狗\n警方包庇\n警棍\n警民冲突\n警民对峙\n警犬部长狗声琨\n警用执法车\n警车\n警车被掀翻\n警车雷达\n譪件\n计划+谋杀藏族\n计划与习近平的两次较量\n计划生育祸国殃民\n计生断子绝孙\n认识中国军车牌\n让人们看到了\n让人民币给废了\n让你们活着就已经是国家的恩赐了\n让你的小鸟鸟永远打瞌睡\n让医疗费给废了\n让大家复制起来\n让日本多占地\n让法院给废了\n让车轧死\n让非洲老朋友继续毒菜\n让领导先走\n讯喜喜喜喜喜喜喜喜讯讯\n讲个笑话\n许多年前\n许多谣言并不\n许宪春\n许能带雨\n论一座大楼的倒掉\n论公\n论功\n论攻\n论街头政治\n设置路障\n访民截车\n证一次性\n证书办理\n证件办理\n证件集团\n证到付款\n证生成器\n证监会无能\n证监会更黑\n评价中国\n评评评评评评\n诅咒灵验\n识牌器\n诉讼集团\n译新网\n译新考试\n试嫖一月不收任何费用\n诚意做的哥哥\n诚意加q\n诚意加我\n诚意哥哥\n诚意玩的哥哥\n诛共匪\n诛赤义军\n话在肉身显现\n话说天下大势\n话说江核心\n诞诞诞诞诞诞诞诞诞诞\n该亡裆了\n语重心长\n误间度醒\n诱人双峰\n诱人身材\n诱惑\n诱惑电影\n诱惑视频\n说个笑话\n说股票是毒品\n说邪教的都是故意往偏引的\n请尽情的嘶叫\n请注意时间变动\n请示威\n请问各位大侠\n请问是否确有此事\n诺亚方舟\n诺匹哌酮\n读不起选个学校\n读不起选个学校三万起\n诽谤大法\n谁也不许给习总添乱呀\n谁会谋害习近平\n谁做了哑巴\n谁对他媳妇彭撸过\n谁愿做陪葬谁愿做陪葬生\n谁接习近平的班\n谁操我屁股眼\n谁改谁过好日子\n谁知道徐才\n谁言共肥度日\n谁谋杀了令谷\n调情\n调情器具\n调情震棒\n调教项目\n谓的和谐\n谗谗谗谗谗\n谠亡\n谠在玩设会\n谤罪获刑\n谨以此纪念中国收费公路\n谴责+公安部长\n谷丽萍自辩书\n象妓女睡觉\n象蚂蝗\n豪华轮盘\n貌似能暂时止痛\n贝壳网\n贡产组织\n贡傥\n贡噶札西\n贡缠党\n贡谠\n财产不公开\n财产保护\n财产移了过去\n财众科技\n财富第七波\n财政气粗是大爷\n财税改革\n财阀与高官的秘密交易\n败家子要送钱\n货到付款\n贩卖毒品\n贩毒\n贪官\n贪官不断\n贪官也辛\n贪官习近平\n贪官卖国\n贪官后宫奇闻\n贪官情妇二奶展\n贪官所贪数额越来越大\n贪官数世界第一\n贪官是层出的\n贪官狗急跳墙\n贪官越打越多\n贪官遍地\n贪污一摞子\n贪污两亿的副局长\n贪污犯\n贪污腐败垄断一切\n贪污腐败欺男霸女没关系\n贪污钱财去嫖妓\n贪淫\n贪腐党\n贪财好色婚外恋\n贫穷时老婆兼秘书\n贰十吾年前\n贱b当政的鸟郭嘉\n贵妃醉酒\n贵宾接待\n贺guoqiang\n贺一亿三千万人三退\n贺一亿两千多万三退勇士\n贺国强家族\n贼仔匪支那\n贼党\n贼眉鼠眼狂\n贾qinglin\n资本主义走的是邪路\n资本等于零\n资金外逃\n赌具\n赌博千药\n赌博器\n赌博技巧\n赌博机\n赌博游戏机\n赌博粉\n赌博练头脑\n赌博股市\n赌博隐形\n赌币机\n赏波赏穴赏菊花\n赚钱网址\n赚钱资料\n赛唓讽纭\n赛车风云\n赛马会\n赢钱技巧\n赤俄及其跟随者们\n赤党\n赤共六十多年犯下的滔天罪行\n赤色魔鬼\n赤贼滚下台\n赤鬼洗脑\n走光\n走向美好的未来\n走私车\n走阴道卡坏了\n赵总书记\n赵样不行\n赵紫阳\n赵紫阳回忆录\n赵维山\n赵长青\n赶一英一超一美\n赶走嫖客自己睡\n起来不愿做奴隶的人们\n起来反抗\n超常科学\n超级颜论\n越境失败\n越境杀人\n越是安全稳定的国家\n越是脆弱饭罪的国家\n足球改单\n足球玩法\n足球皇帝\n足球系统\n跑灯机\n跟到涛哥混口饭\n跟大大谈心\n跟我装b全干倒\n跟我走进夜总会\n跟着红军走\n跟贴用户自律公约\n跟踪仪器\n跟踪器\n路边的河里\n路过一村庄\n跳艳舞\n跳蛋\n跳蛋器具\n踢掉你妈老b毛\n踢翻小贩\n踢踏\n踩江后审江\n踩江镇江审江\n踩着我的头\n踩踏佛像\n蹴鞠兴本朝\n身份证生成器\n躺在床上玩小鸡\n躺在玻璃里的那个腌货\n车上我被挤得流了产\n车上我被挤得都怀了孕\n车主被钓鱼\n车仑工力\n车牌挂国徽\n车站卖比劈大腿\n转型正义\n转是政府\n转法轮\n转盘机\n转移视线\n转膛枪\n轮公\n轮功\n轮大\n轮攻\n轮流坐庄\n轮盘机\n轮盘源码\n软弱外交\n软弱的国\n软禁江泽民\n轻呼壮弟加油\n轻松赚钱\n轻轻一插就叫痛\n辩证\n辩词与梦\n辶斤丷干\n边喊反腐倡廉\n边抚摸边洗\n边说枪杆子里出政权\n达到蚣狒\n达明一派\n达毕业证\n达赖喇嘛\n达赖喇嘛流亡50周年\n达赖活佛\n达赖集团\n过夜\n迎接方式\n运动枪\n运气像曾庆一样红\n运水微漾人却震\n近朱者赤猿不老\n近看原来在性交\n还.看.锦.涛\n还会吹萧\n还做早操\n还我紫阳\n还有一人在训练\n还权\n还爱做梦\n还爱尼玛什么档\n还看锦涛\n这个分裂过程永远不会停止\n这个国家充满谎言已很可鄙\n这个国家已经病入膏肓了\n这个国家没希望了\n这个案子很有可能不了了之\n这个猪头整人有一套\n这些乌龟果真全部当了官\n这些堂口老大的压力大了\n这件事恰恰证明了不是\n这几句真理\n这国家烂到底了\n这就是我的华夏\n这就是现在的中国百姓\n这届政府\n这届症腐\n这届领导\n这才是权谋的最高境界\n这是一个国家还是监狱\n这是一种大无畏精神\n这是个什么郭嘉\n这条消息太毒\n这样无声无息的逝去\n这虫子跟河南人一样\n这风刮来的时候\n进京执掌公安部\n进入政府\n进出皆匪寇\n进平+两次婚姻\n进平+二次婚姻\n进平+婚姻史\n进平+有几次婚姻\n进平+柯小明\n进平+柯零零\n进来的罪\n远志明\n远离股海周永康\n远离苼命\n远程偷拍\n远程破解\n远程视频\n连主席都仰敬三分\n连线宝马\n连线机\n连缴税的资格都没有\n连营立炸十五地\n迪考谭凯\n迪里夏提\n迫g害致死的\n迫害伴奏曲\n迷幻情水\n迷幻水\n迷幻液\n迷幻粉\n迷幻蘑菇\n迷幻香水\n迷彩弩\n迷情少妇\n迷情液\n迷惑药\n迷昏水\n迷欲水\n迷歼药\n迷混药\n迷魂液\n迷魂烟\n迷魂粉\n追月\n追杀令计划\n追责+公安部长\n追踪仪器\n退+党+团+平安\n退.党\n退b器\n退dang\n退了平安\n退休+片场\n退休大佬倒习\n退傥\n退党\n退共\n退共党\n退出中共\n退出中国共产党\n退出了中共\n退出了共产党\n退出傥\n退出党\n退出共产\n退出共产党\n退出平安\n退出平安防清算\n退则生退则生退则生\n退团\n退币器\n退档\n退者生退者生者生\n退谠\n送了几十亿\n送财童子\n送货上门\n逃离中国\n逃逃逃逃逃逃逃逃逃\n逆我者嫖娼\n逆施倒行+除异固权\n逆贼毛匪泽东\n选个学校三万起\n选择善良\n选择性错误\n选择的反腐行动\n选霸就是干部\n透明扑克\n透视功能\n透视扑克\n透视牌九\n透视相机\n透视眼镜\n透视蔴将\n透视麻将\n逗乳\n逗肛\n逗逗小胡\n通奸通奸通奸通奸奸\n通钢总经\n速眠水\n造反派耶律仲勋\n逩驰寳马\n逮捕江泽民\n逼好痒\n逼嫩\n逼很紧\n逼无保鸟无套\n逼是好地方\n逼毛\n逼痒\n逼穴\n逼里也能吹喇叭\n逼里啥都有\n逼里好风流\n逼里有千秋\n逼里有口大黑锅\n逼里装宽带\n逼里说快板\n逼里跑轮船\n遇饥荒饿亡\n遍地皆骗\n道具自卫\n遗弃的恶土\n遛月寺日\n遥想当年春衫薄\n遥控麻将机\n遭人强暴就从了吧\n遵义选出ceo\n避凶之良策智者\n避孕套对卫生巾\n避孕药催大\n避难的方式零星迁徙到一个新地方\n邓儿\n邓先生的秦川大地公司\n邓六四\n邓小平即抽烟又喝酒活了93岁\n邓小平失算\n邓小平极其不耐烦\n邓小平的英语水平\n邓小平英语\n邓川猴子\n邓爷爷的语言\n邓爷爷的预言\n邓爷爷转\n邓爷爷转世\n邓的干部\n邓盗江寇\n邓矮\n邓笑贫\n邓颖超日记\n邢铮\n那个根本就是个阳痿货\n那为什么苏联没了\n那可汀\n那当着学生的面我也回答\n那灵在说话\n那话儿\n邦国殄瘁\n邪d气数已尽\n邪傥\n邪共党\n邪共党魁江恶首\n邪恶\n邪恶的党\n邪恶的共产党\n邪恶的组织\n邪恶组织\n邪挡\n邪教只是一个幌子\n邪教本质\n邪教特征\n邪教组织\n邪档\n邪的教育\n邪警\n邪谠\n郑姆斯特丹\n郑旭光\n部忙组阁\n部是这样\n部长下台\n郭保留国务委员虚衔\n郭升坤不得力啊\n郭嘉+灭亡\n郭声琨为升官谎报\n郭声琨发力\n郭声琨在广西犯罪\n郭声琨是广西腐败的总后台\n郭声琨秘书出身\n郭声琨结党营私\n郭声琨退位后\n郭徐老虎\n郭海峰\n都不如四个字最令人感到不知廉耻\n都在车上\n都当小姐\n都等着钱\n都进中央\n鄹鄹鄹鄹鄹鄹\n酐乐欣\n酒像喝汤\n酒池肉林\n酒象喝汤\n酥软振动\n酥麻\n酱猪媳\n酸羟亚胺\n醉妃粉\n醉警察\n醋托啡\n醋氢可待因\n醒觉醒觉醒觉醒觉醒觉快\n里蓝亲是教改的榜样\n重启政改\n重回天安门\n重庆市委\n重庆市委书记\n重庆模式\n重新评价毛泽东\n重肖\n重要原因是police待遇过低\n重评毛泽东\n野兽\n野汉不带\n野汉不带避孕套\n野肖\n量中华之物力\n量刑歧视\n金三胖子\n金三色\n金伯帆\n金元外交\n金刚喷雾剂\n金刚油\n金婷干\n金属波箱\n金属超标100倍的碧螺春茶\n金枪消魂\n金正日临终前把金正恩叫到床前\n金正日拉着儿子\n金正日拉着儿子的手\n金沙娱乐\n金牌\n金牛教\n金猫探险\n金连舔点尝一尝\n金钟村民的生活实践\n金钱把官场搞乱\n鉴定完毕\n钅帛氵寿\n针刺\n针孔摄像头\n针孔摄象头\n针对政治局常委家族的调查\n针扎\n针毒\n针灸减肥\n针状物\n针装毒药\n钓鱼列岛\n钓鱼台\n钓鱼岛是日本的\n钓鱼执法\n钟共\n钟央\n钢珠qiang\n钢珠手枪\n钢珠枪\n钢笔摄像机\n钢管舞视频\n钱三字经\n钱权交易称下海\n钻石冰\n钻跨\n铀235\n铁帽子王\n铁树开花\n铅弹\n铭记印尼\n铮铮铁骨\n铲车铲大学生是哪一年\n铲除共匪\n铲除恶习\n银子把官场搞乱了\n银河党\n银行卡复制器\n银行可以耍无赖\n银行有奶\n销售枪支\n销售香烟\n销魂\n销魂椅\n锍氓社团\n锡锋密封圈\n锡锋弹簧\n锡锋皮碗\n锤子和一把镰刀熔化\n锤子弯刀帮会组织\n锤子情调地上来五盘\n锦涛入套\n锦涛裸退\n锭位噐\n镆口镆镆镆镆镆\n镆合合镆镆镆镆镆镆镆合\n镇压\n镇压人民\n镇压学生事件\n镇压群众\n镇压老百姓\n镰刀斧头帮\n镰刀锤子\n镰刀锤子帮\n镶击镶击镶\n长城以北全送\n长安街逆向行驶\n长安街逆行\n长春解法\n长春讲法\n长期出售\n长期销售\n门徒会\n门朗塔庆\n问谁未发声\n闲着没事带根吊\n闵行倒钩门\n闷声发大财把资产转移海外\n闹事\n闻被控制\n闻齐阴\n阅nmlgb\n阅什么兵\n阅你吗的兵\n阅你麻痹兵\n阅兵仪式\n阉档砖全\n防卫器\n防卫电棍\n防护具\n防拍器\n防暴器\n防暴枪\n防泄膏\n防火墙高筑\n防电子眼\n防身器\n防身药水\n阳物\n阳物插入其羞处\n阳精\n阴chun\n阴dao\n阴di\n阴丘\n阴壁\n阴小湿大\n阴护\n阴毒举世公认\n阴毛不烫卷得奇\n阴毛不烫卷的出奇\n阴毛纺织厂\n阴毛都露出\n阴水\n阴穴\n阴道无油滑得出奇\n阴道无油滑的出奇\n阴部又开花\n阴部无油滑得奇\n阻挡军车\n阻碍人类的希望\n阿不都吉力力\n阿不都热合曼\n阿不都艾尼\n阿卜杜勒\n阿塔汗\n阿姨摸我小鸡鸡\n阿尼利定\n阿布都米吉提\n阿扁对小胡\n阿扁推翻\n阿扁涛哥\n阿托品\n阿拉丁神丹\n阿斗治国\n阿法罗定\n阿波罗新闻网\n阿芙蓉\n阿西尔白克\n阿里布达年代记\n陆月肆号\n陆月肆日\n陆肆事件\n陈冠希进去艳照门出来\n陈如彭\n陈姓男子\n陈子明\n陈巧文\n陈胜吴广何在\n陈道明的夫人一个是\n陈雄杰\n陈鸽\n限制出境\n限制片\n陕西人射的没那么早\n陕西歪脖子\n除夕+习\n除夕+圣上\n除夕皇帝\n除恶唯有剑\n除恶唯有剑出鞘\n除报禁\n除疤痕\n除皱\n除贪官来消除异己\n除退恶评\n陪人吃来陪人睡\n陪伴服务\n陪睡\n陪聊妹\n陷害老百姓\n隆胸\n隆鼻\n随身带着避孕套\n隐型耳机\n隐形喷剂\n隐私地带\n隐私部位\n隐蔽执法就是爽\n隐退的正义\n隔墙听\n难产的产\n难道习不是\n难道你兄弟过好点是错误的\n难道我们喜哥和膨姐\n雄风重振\n雅思枪手\n雅玛人\n集会自由\n集体失声\n集体强奸\n集体打砸\n集体摸胸\n集体腐败死到地\n雨伞人物图集\n雨伞运动\n雨伞运动之香港大撕裂\n雨伞运动的思考之旅\n雨夜送耀邦\n雨荷兼职\n雨荷网\n雪山狮子\n雪泥鸿爪话文革\n雪灾=天灾\n零8宪章\n零九宪章\n零八宪章\n零八宪章拼\n零八纲领\n零及其指\n零投资\n零风险\n雷人女官\n需要假币\n震其国土\n震动器\n震惊一个民\n震棒\n震死四川\n震荡器\n震蛋\n露出林心乳\n露出龟心\n露穴\n露逼\n霸王墙的风洞的弓\n霸王执法\n青春少女想做爱\n青春少男想做爱\n青藏达赖乱窜\n青蛙+国难\n青蛙和兴红\n青蛙己死\n靓妹兼职\n靓穴\n静偲兯\n静偲节\n静听花开的声音\n静坐人海\n静思节\n非共倒打\n非匚八一艹刂至亻丁扌\n非常好的朋友像避孕套\n非法关押\n非法判刑\n非法取缔\n非法器官移植\n非法抄家\n非法抓捕\n非法抓走\n非法拘留\n非法秘密判刑\n非法秘密抓捕\n非法镇压\n非电导爆系统\n非诺非烷\n非那佐辛\n靠党党腐败\n靠努力工作能升官那更是扯蛋\n靠政绩能升官发财那更是扯蛋\n靠老婆能满足性欲那也是扯蛋\n面瘫老大\n面瘫老板\n面貌与心灵\n面部整形\n鞋崇拜\n鞑战大克坦\n鞭尸毛鸡吧\n鞭走鞭爱\n韩式松骨\n韩式风情\n韬光养晦\n项圈脖套\n项王仁慈\n顺便撒纸钞\n顺我者昌\n顺着乳沟往下摸\n顿湿滔滔\n预言家\n领导+习\n领导人保镖\n领导人动手\n领导人贴身保镖\n领导人都是酒囊饭袋\n领导家的小配房\n领导小姐你先摸\n领导小蜜你乱摸\n领导就像阴道\n领导干部吃王八\n领导强词夺理叫坚持真理\n领导必定在人大\n领导忽悠百姓叫号召\n领导忽悠领导叫交易\n领导是个吊\n领导没有不重视的\n领导泡妞\n领导泡妞放哨站岗\n领导的亲属\n领导的亲属+股东\n领导私事你瞎说\n领导领导你真坏\n领袖伟大以人民愚蠢为代价\n题板是宋庆龄\n颠覆中国\n颠覆共党\n颤颤颤颤颤颤颤\n风云势力\n风洞的弓\n风险中的暴富\n风骚侍女\n风骚少妇\n风骚性感\n风骚的少妇\n飞机上做爱\n饿死了三千万居民\n饿死几千万人\n饿死整死八千万\n首先把硫磺放到汽水罐里\n首辅大人还是皖籍\n首都公安\n首都公安内部有人狗胆包天\n香港一直没有遗忘那一年\n香港一类\n香港回归晚会上\n香港回归没看见\n香港总彩\n香港支联会\n香港故事\n香港民主派\n香港民族论\n香港独立\n香港签证\n香港论坛\n香港赛马会\n香港雨伞运动的日与夜\n香港雨伞革命中的反抗\n香港马会\n香烟出售\n香烟回收\n香烟批发\n香烟销售\n香缸正发生伍肆晕动\n香舌\n马云+太祖爷\n马会\n马克思主义到底是什么\n马克思主义的画皮\n马列体制祸国殃民\n马列根本之邪\n马列毒瘤\n马列毛祸害中国\n马列毛邓\n马列毛邓三科梦\n马列邪恶斗争\n马列邪教拼\n马劣主义\n马劣猪蚁\n马恩列斯\n马恩裂死猫\n马拉不动\n马来种广西猴\n马贼洗脑发血誓\n驱尽邪魔传万代\n驱赶码咧奴\n驱赶码洌子孙\n驱逐德国邪教\n驱逐马列\n驱除赤魔\n驴和维尼\n驾驶证\n骂人歇后语\n骂咧子孙\n骂政府\n骆冰淫传\n验货付款\n验钞机包通过\n骑单车出\n骑马\n骑马射箭也不赖\n骗农民和学生\n骗我们一切以民为主\n骚乱\n骚妹\n骚姊姊\n骚姐姐\n骚婊\n骚痒\n骡子比主义指导下的奴隶社会\n高.智.晟\n高举4300万牌子\n高举裤衩歇会儿再来\n高价买朋友\n高价买石油\n高仿中华\n高仿真\n高仿香烟\n高利贷\n高压电击棍\n高就在政\n高层内幕\n高层利益\n高山流水\n高干\n高干子女\n高干子弟\n高干子弟心更贪\n高度重视\n高树三姐妹\n高档香烟\n高治联\n高潮喷水\n高潮的浪叫\n高管背后的情妇\n高级伴游\n高级服务\n高级服务生\n高耀杰回忆与随想\n高老庄的房子仍在继续拆迁\n高考落榜生\n高薪养廉\n高薪急聘\n高薪日结\n高薪服务人员\n高薪服务生\n高薪诚聘\n高贵水晶藏邪魂\n高跟\n鬤鬤鬤鬤鬤鬤鬤鬤鬤鬤鬤鬤鬤\n鬼畜\n魔女乖乖粉\n魔相从高墙滚出去\n魔鬼们对外熊包一堆\n魔鬼孟见柱\n鱼掉到粪坑里\n鲁迅公园绝食活动\n鲍彤\n鲍戈\n鲍朴\n鲎犬犬犬犬犬鲎犬犬犬犬犬\n鲜血洒广场\n鸟耍\n鸟进鸟出\n鸡八\n鸡头个个发\n鸡巴无骨硬得出奇\n鸡巴炸飞\n鸡巴都炸没了\n鸡犬不宁民不聊\n鸡那档杀死的鸡那人更多\n鸡鸡\n鸡鸡硬了我就干\n鸡鸡长在脸上\n鸦片\n鸭子\n鸳鸯欲\n鸳鸯浴\n鹅毛扶持\n鹅罗撕胡作非为\n鹏嫲麻帮我含吉粑\n鹏鹏是最大的老虎\n鹤喃井盖\n鹿鞭丸\n麦司卡林\n麦罗啡\n麦角乙二胺\n麦角酸二乙基酰胺\n麻古\n麻将像锦涛一样胡\n麻将透视器\n麻果\n麻醉qiang\n麻醉注射枪\n麻醉诱导\n麻醉迷幻\n麻醉钢枪\n麻醉香烟\n黄丝带与伞\n黄俄狗杂出卖领土给毛子\n黄冰\n黄小说\n黄恶野孙\n黄易是最没有道德的\n黄毒市场在买方\n黄泥巴裹鸡也可以\n黄海ci胡\n黄海事件\n黄海刺胡\n黄海刺虎\n黄海暗杀\n黄海谋刺\n黄爱性\n黄玉婷\n黄琦\n黄皮的玛咧奴\n黄种人的骄傲\n黄站\n黄色图片\n黄色小电影\n黄色小说\n黄色激情\n黄色照片\n黄色经济最可靠\n黄色网\n黄菊\n黄雀营救\n黑势力\n黑客改单\n黑帮\n黑心党\n黑恶公安\n黑掱党\n黑暗中的国家秘密\n黑暗吮吸术\n黑暗政府\n黑涩会\n黑火药的\n黑猴杂交\n黑白颠倒\n黑眼镜背带裤\n黑社会\n黑箱作业出卖国土\n黑红轮盘\n黑老大\n黑色之年\n黑蟒\n黑衙门\n黑衣人抗议\n黑车\n黑钞\n黑鬼罪行满天下\n黑龙江边境市县\n默一罕一默一德一就一是一杂一种\n默罕默德造的孽\n鼓动一些\n鼻吸剂\n齐奥塞斯库\n龙凤的人人性自慰\n龙村和龟庄是两个相邻的村子\n龙湾事件\n龙虎机\n龙虎豹\n龚灿党\n龚肥不亡天理难蓉\n龚菲不亡则中华亡\n龟缝";
let _brakeSWSet = null;
function brakeHasSensitive(name) {
  if (!_brakeSWSet) _brakeSWSet = new Set(BRAKE_SENSITIVE_WORDS.split('\n').map(function (w) { return w.toLowerCase(); }));
  const t = String(name || '').toLowerCase();
  for (const w of _brakeSWSet) { if (w && t.indexOf(w) !== -1) return true; }
  return false;
}

// ---------- 刹车站：全网统计 + 实时排行榜 ----------
// 存储设计：每局写入独立 key（brake_run_<时间戳>_<随机>_<s|f>_<设备>），append-only。
// 原因：KV 为最终一致性，旧的"读计数→+1→写回"在快速连玩时会被旧数据覆盖导致丢记录。
function brakeRunKey(ts, device, success) {
  const d = String(device || 'anon').replace(/[^a-zA-Z0-9]/g, '').slice(0, 20) || 'anon';
  const r = Math.random().toString(36).slice(2, 6);
  return 'brake_run_' + String(ts).padStart(13, '0') + '_' + r + '_' + (success ? 's' : 'f') + '_' + d;
}
async function listBrakeRunKeys(kv) {
  const keys = [];
  let cursor = undefined;
  do {
    const res = await kv.list({ prefix: 'brake_run_', cursor: cursor, limit: 1000 });
    for (const k of res.keys) keys.push(k.name);
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  return keys;
}
// 一次性迁移旧格式（brake_runs_v1 数组 / brake_stats_v1 计数器）
// 用确定性 key（_mig<序号>），重复执行只会覆盖，不会产生重复
async function migrateBrakeOld(kv) {
  if (!kv) return;
  try {
    const old = await kv.get('brake_runs_v1');
    if (old) {
      const arr = JSON.parse(old);
      if (Array.isArray(arr)) {
        let i = 0;
        for (const e of arr) {
          const t = e.t || Date.now();
          const d = String(e.d || 'anon').replace(/[^a-zA-Z0-9]/g, '').slice(0, 20) || 'anon';
          const key = 'brake_run_' + String(t).padStart(13, '0') + '_mig' + (i++) + '_' + (e.ok ? 's' : 'f') + '_' + d;
          await kv.put(key, JSON.stringify({ ip: e.ip || '', d: e.d || '', n: e.n || '无名车手', ok: !!e.ok, ms: e.ms | 0, r: e.r | 0, t: t }));
        }
      }
      await kv.delete('brake_runs_v1');
      await kv.delete('brake_stats_v1');
    }
  } catch (e) {}
}
// 去重：同一毫秒同一设备的重复 key 只保留一个（真实游玩不可能同毫秒提交两次）
async function dedupeBrakeRuns(kv, keys) {
  const seen = new Set();
  const dups = [];
  for (const k of keys) {
    const m = /^brake_run_(\d+)_[a-z0-9]+_([sf])_([A-Za-z0-9]+)$/.exec(k);
    if (!m) continue;
    const sig = m[1] + '_' + m[3] + '_' + m[4]; // 时间戳_结果_设备（忽略随机段）
    if (seen.has(sig)) dups.push(k);
    else seen.add(sig);
  }
  if (dups.length) {
    await Promise.all(dups.map(function (k) { return kv.delete(k); }));
  }
  return keys.filter(function (k) { return dups.indexOf(k) === -1; });
}
// 刹车上报限流：单个 IP 每分钟最多 20 局（正常游玩一局至少十几秒，20/分钟只拦刷子）
// 限流器自身故障时放行，不影响正常游玩
async function brakeRateLimit(kv, ip) {
  if (!kv || !ip) return true;
  try {
    const bucket = Math.floor(Date.now() / 60000);
    const key = 'brake_rl_' + bucket + '_' + ip.replace(/[^a-zA-Z0-9.:]/g, '').slice(0, 45);
    const raw = await kv.get(key);
    const n = (parseInt(raw || '0', 10) || 0) + 1;
    if (n > 20) return false;
    await kv.put(key, String(n), { expirationTtl: 75 });
    return true;
  } catch (e) { return true; }
}
async function handleBrakeResult(request, env) {
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: false, error: '未启用' }, 503);
  let b = {};
  try { b = await request.json(); } catch (e) {}
  const success = b.success === true;
  const ms = Math.round(Number(b.ms) || 0);
  const reaction = Math.min(Math.max(Math.round(Number(b.reaction) || 0), 0), 30000);
  let name = String(b.name || '').slice(0, 12) || '无名车手';
  if (brakeHasSensitive(name)) name = '无名车手';
  const device = String(b.device || '').slice(0, 64) || 'anon';
  if (success && !(ms >= 500 && ms <= 30000)) return json({ ok: false, error: '数据异常' }, 400);
  const now = Date.now();
  const ip = request.headers.get('cf-connecting-ip') || '';
  if (ip && !(await brakeRateLimit(kv, ip))) {
    return json({ ok: false, error: '手速太快了，歇一会儿再战' }, 429);
  }
  try {
    await kv.put(brakeRunKey(now, device, success), JSON.stringify({ ip: ip, d: device, n: name, ok: success, ms: success ? ms : 0, r: reaction, t: now }));
  } catch (e) {}
  if (success) {
    let board = [];
    try { const raw = await kv.get('brake_board_v1'); if (raw) board = JSON.parse(raw); } catch (e) {}
    if (!Array.isArray(board)) board = [];
    const ex = board.find(function (e) { return e.d === device; });
    if (ex) { if (ms < ex.ms) { ex.ms = ms; ex.n = name; ex.t = now; } }
    else board.push({ n: name, ms: ms, d: device, t: now });
    board.sort(function (a, b2) { return a.ms - b2.ms; });
    board = board.slice(0, 50);
    try { await kv.put('brake_board_v1', JSON.stringify(board)); } catch (e) {}
  }
  return json({ ok: true });
}
async function brakeStatsCount(kv) {
  let s = 0, f = 0;
  if (!kv) return { s: s, f: f };
  await migrateBrakeOld(kv);
  let keys = await listBrakeRunKeys(kv);
  try { keys = await dedupeBrakeRuns(kv, keys); } catch (e) {}
  for (const k of keys) {
    const seg = k.split('_');
    if (seg[4] === 's') s++; else if (seg[4] === 'f') f++;
  }
  return { s: s, f: f };
}
async function handleBrakeStats(request, env) {
  const kv = env.FEEDBACK_KV;
  let c = { s: 0, f: 0 };
  try { c = await brakeStatsCount(kv); } catch (e) {}
  return json({ ok: true, success: c.s, fail: c.f });
}
async function handleBrakeBoard(request, env) {
  const kv = env.FEEDBACK_KV;
  let board = [];
  try { const raw = kv && await kv.get('brake_board_v1'); if (raw) board = JSON.parse(raw); } catch (e) {}
  if (!Array.isArray(board)) board = [];
  const out = board.map(function (e) {
    return { n: String(e.n || '无名车手').slice(0, 12), ms: e.ms | 0, t: e.t | 0, d: String(e.d || '') };
  });
  return json({ ok: true, board: out });
}

// ---------- 刹车站昵称校验（改名时调用） ----------
async function handleBrakeCheckName(request, env) {
  let b = {};
  try { b = await request.json(); } catch (e) {}
  const name = String(b.name || '').trim().slice(0, 12);
  if (!name) return json({ ok: false, error: '名字不能为空' }, 400);
  if (brakeHasSensitive(name)) return json({ ok: false, error: '名字包含敏感词，换一个吧' }, 400);
  return json({ ok: true, name: name });
}

// ---------- 刹车站后台管理 ----------
async function handleAdminBrakeRuns(request, env) {
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  await migrateBrakeOld(kv);
  let runs = [];
  let keys = [];
  try {
    if (kv) {
      keys = await listBrakeRunKeys(kv);
      keys.sort().reverse();
      const latest = keys.slice(0, 200);
      const vals = await Promise.all(latest.map(function (k) { return kv.get(k); }));
      for (const v of vals) {
        if (!v) continue;
        try { runs.push(JSON.parse(v)); } catch (e) {}
      }
    }
  } catch (e) {}
  let c = { s: 0, f: 0 };
  try {
    for (const k of keys) {
      const seg = k.split('_');
      if (seg[4] === 's') c.s++; else if (seg[4] === 'f') c.f++;
    }
  } catch (e) {}
  return json({ ok: true, success: c.s, fail: c.f, runs: runs });
}
async function handleAdminBrakeDeleteEntry(request, env) {
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  let b = {};
  try { b = await request.json(); } catch (e) {}
  const device = String(b.device || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 20);
  if (!device) return json({ ok: false, error: '缺少设备' }, 400);
  try {
    if (kv) {
      const keys = await listBrakeRunKeys(kv);
      const mine = keys.filter(function (k) { return k.endsWith('_' + device); });
      await Promise.all(mine.map(function (k) { return kv.delete(k); }));
      let board = [];
      try { const raw = await kv.get('brake_board_v1'); if (raw) board = JSON.parse(raw); } catch (e) {}
      if (Array.isArray(board)) {
        const nb = board.filter(function (e) { return String(e.d || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 20) !== device; });
        if (nb.length !== board.length) await kv.put('brake_board_v1', JSON.stringify(nb));
      }
    }
  } catch (e) {}
  return json({ ok: true });
}
async function handleAdminBrakeReset(request, env) {
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  try {
    if (kv) {
      const keys = await listBrakeRunKeys(kv);
      await Promise.all(keys.map(function (k) { return kv.delete(k); }));
      await kv.delete('brake_board_v1');
      await kv.delete('brake_runs_v1');
      await kv.delete('brake_stats_v1');
    }
  } catch (e) {}
  return json({ ok: true });
}
async function handleFeedbackSubmit(request, env) {
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: false, error: '反馈功能暂未启用' }, 503);
  // 人机验证
  const tsSecret = (env.TURNSTILE_SECRET_KEY || '').trim();
  let text = '', contact = '', tsToken = '';
  let site = siteTag();
  let files = [];
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('multipart/form-data')) {
    const form = await request.formData();
    text = String(form.get('text') || '').slice(0, 2000);
    contact = String(form.get('contact') || '').slice(0, 200);
    tsToken = String(form.get('turnstile') || '');
    if (String(form.get('site') || '') === '[刹车站]') site = '[刹车站]';
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
      if (String(j.site || '') === '[刹车站]') site = '[刹车站]';
    } catch {}
  }
  if (!text.trim()) return json({ ok: false, error: '请填写反馈内容' }, 400);
  if (tsSecret && site !== '[刹车站]') { // 刹车站为跨域提交，跳过 Turnstile，IP 冷却仍生效
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
    site,
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

async function handleAdminFeedbacks(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const siteFilter = new URL(request.url).searchParams.get('site') || '';
  const out = [];
  try {
    let cursor = undefined;
    do {
      const res = await kv.list({ prefix: 'fb_', cursor });
      for (const k of res.keys) {
        try {
          const raw = await kv.get(k.name);
          if (!raw) continue;
          const it = JSON.parse(raw);
          if (siteFilter && it.site !== siteFilter) continue;
          out.push({ id: it.id, site: it.site, text: it.text||'', contact: it.contact||'', ip: it.ip||'', cc: it.cc||'', t: it.t||0, files: it.files||[] });
        } catch(e){}
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch(e){}
  out.sort(function(a,b){ return b.t - a.t; });
  return json({ ok: true, feedbacks: out.slice(0,100) });
}
// 批量删除反馈（含 R2 附件）
async function handleAdminFeedbackDelete(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
  const ids = Array.isArray(body.ids) ? body.ids.slice(0,100) : [];
  const kv = env.FEEDBACK_KV;
  const bucket = env.FEEDBACK_BUCKET;
  let n = 0;
  for (const rawId of ids) {
    const id = String(rawId || '');
    if (!/^fb_[0-9a-zA-Z_]+$/.test(id)) continue;
    try {
      const raw = await kv.get(id);
      if (raw && bucket) {
        try {
          const it = JSON.parse(raw);
          for (const f of (it.files || [])) {
            if (f.key) { try { await bucket.delete(f.key); } catch(e){} }
          }
        } catch(e){}
      }
      await kv.delete(id);
      n++;
    } catch(e){}
  }
  return json({ ok: true, deleted: n });
}

function getDeviceId(request){
  return (request.headers.get('x-device-id') || '').trim().slice(0,64);
}
async function handleAdminFeedbackFile(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const key = new URL(request.url).searchParams.get('k') || '';
  if (!key || key.includes('..')) return json({ ok: false, error: '参数错误' }, 400);
  const bucket = env.FEEDBACK_BUCKET;
  if (!bucket) return json({ ok: false, error: '未配置存储' }, 503);
  try {
    const obj = await bucket.get(key);
    if (!obj) return json({ ok: false, error: '文件不存在' }, 404);
    return new Response(obj.body, {
      headers: {
        'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
        'Content-Disposition': 'inline',
        'Cache-Control': 'public, max-age=86400',
      },
    });
  } catch(e){
    return json({ ok: false, error: '读取失败' }, 500);
  }
}
function blackMsg(bl){
  let m = '大肥鱼不喜欢你！你已被大肥鱼拉黑！🐳';
  if (bl && bl.reason) m += '（拉黑原因：' + bl.reason + '）';
  return m;
}
async function isBlacklisted(request, env){
  const kv = env.FEEDBACK_KV;
  if (!kv) return null;
  const ip = request.headers.get('cf-connecting-ip') || '';
  const dev = getDeviceId(request);
  const reasonOf = (b) => { try { return JSON.parse(b).reason || ''; } catch(e){ return ''; } };
  try {
    if (ip) {
      const b = await kv.get('blackip_' + ip);
      if (b) return { type: 'ip', value: ip, reason: reasonOf(b) };
    }
    if (dev) {
      const b = await kv.get('blackdev_' + dev);
      if (b) return { type: 'device', value: dev, reason: reasonOf(b) };
    }
  } catch(e){}
  return null;
}
function fmtBT(t){
  const d = new Date(t + 8*3600*1000);
  const p2 = (n) => String(n).padStart(2,'0');
  return d.getUTCFullYear()+'-'+(d.getUTCMonth()+1)+'-'+d.getUTCDate()+' '+p2(d.getUTCHours())+':'+p2(d.getUTCMinutes());
}
function banMsg(ban){
  let m = '大肥鱼把你关进小黑屋了！🐳封禁' + ban.days + '天，解封时间：' + fmtBT(ban.until);
  if (ban.reason) m += '（封禁理由：' + ban.reason + '）';
  return m;
}
async function checkBan(username, env){
  if (!username) return null;
  const kv = env.FEEDBACK_KV;
  if (!kv) return null;
  try {
    const raw = await kv.get('ban_' + username);
    if (!raw) return null;
    const d = JSON.parse(raw);
    if (d.until && d.until < Date.now()) { await kv.delete('ban_' + username); return null; }
    return d;
  } catch(e){ return null; }
}
async function handleAdminBans(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const out = [];
  try {
    const list = await kv.list({ prefix: 'ban_' });
    for (const k of list.keys) {
      try {
        const d = JSON.parse(await kv.get(k.name));
        if (d.until && d.until < Date.now()) { await kv.delete(k.name); continue; }
        out.push({ username: k.name.slice(4), days: d.days||0, reason: d.reason||'', until: d.until||0, t: d.t||0 });
      } catch(e){}
    }
  } catch(e){}
  out.sort((a,b) => b.t - a.t);
  return json({ ok: true, list: out });
}
async function handleAdminBan(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const method = request.method;
  if (method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
    const bans = Array.isArray(body.bans) ? body.bans.slice(0,100) : [{ username: body.username, days: body.days, reason: body.reason }];
    for (const b of bans) {
      const username = String(b.username || '').trim().slice(0,32);
      let days = parseInt(b.days) || 0;
      if (!username || ![1,3,5,30,365].includes(days)) continue;
      const reason = String(b.reason || '').trim().slice(0,100);
      const until = Date.now() + days * 86400000;
      await kv.put('ban_' + username, JSON.stringify({ days, reason, until, t: Date.now() }));
    }
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    let body = {};
    try { body = await request.json(); } catch(e){}
    const us = Array.isArray(body.usernames) ? body.usernames.slice(0,100) : (body.username ? [body.username] : []);
    for (const u of us) {
      const username = String(u || '').trim().slice(0,32);
      if (username) await kv.delete('ban_' + username);
    }
    return json({ ok: true });
  }
  return json({ ok: false, error: '方法错误' }, 405);
}
async function handleAdminBalance(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const apiKey = (env.DEEPSEEK_API_KEY || '').trim();
  if (!apiKey) return json({ ok: false, error: '未配置 DEEPSEEK_API_KEY' });
  try {
    const r = await fetch('https://api.deepseek.com/user/balance', {
      headers: { 'Authorization': 'Bearer ' + apiKey }
    });
    if (!r.ok) return json({ ok: false, error: '查询失败(' + r.status + ')' });
    const j = await r.json();
    const infos = Array.isArray(j.balance_infos) ? j.balance_infos : [];
    const out = infos.map(function(b){
      return { currency: b.currency || '', total: b.total_balance || '0', granted: b.granted_balance || '0', topped: b.topped_up_balance || '0' };
    });
    return json({ ok: true, is_available: !!j.is_available, balances: out });
  } catch(e){ return json({ ok: false, error: '网络错误' }); }
}
async function handleAdminSysprompt(request, env){
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  if (request.method === 'GET') {
    let v = '';
    try { v = await kv.get('sysprompt') || ''; } catch(e){}
    return json({ ok: true, prompt: v });
  }
  if (request.method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
    const v = String(body.prompt || '').trim().slice(0, 4000);
    try {
      if (v) await kv.put('sysprompt', v);
      else await kv.delete('sysprompt');
    } catch(e){ return json({ ok: false, error: '保存失败' }, 500); }
    return json({ ok: true });
  }
  return json({ ok: false, error: '方法错误' }, 405);
}
async function handleAdminBlacklist(request, env){  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  const method = request.method;
  if (method === 'GET') {
    const out = [];
    try {
      for (const prefix of ['blackip_', 'blackdev_']) {
        let cursor = undefined;
        do {
          const res = await kv.list({ prefix, cursor });
          for (const k of res.keys) {
            try {
              const raw = await kv.get(k.name);
              const it = raw ? JSON.parse(raw) : {};
              out.push({ type: prefix === 'blackip_' ? 'ip' : 'device', value: k.name.slice(prefix.length), username: it.username || '', reason: it.reason || '', t: it.t || 0 });
            } catch(e){}
          }
          cursor = res.list_complete ? undefined : res.cursor;
        } while (cursor);
      }
    } catch(e){}
    out.sort(function(a,b){ return b.t - a.t; });
    return json({ ok: true, list: out });
  }
  if (method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ ok: false, error: '格式错误' }, 400); }
    const items = Array.isArray(body.items) ? body.items.slice(0,100) : [{ type: body.type, value: body.value, username: body.username, reason: body.reason }];
    for (const it of items) {
      const type = it.type === 'device' ? 'device' : 'ip';
      const value = String(it.value || '').trim().slice(0,100);
      if (!value) continue;
      const key = (type === 'ip' ? 'blackip_' : 'blackdev_') + value;
      await kv.put(key, JSON.stringify({ username: String(it.username||''), reason: String(it.reason||''), t: Date.now() }));
    }
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    const url = new URL(request.url);
    let items = [];
    try {
      const body = await request.json();
      if (Array.isArray(body.items)) items = body.items.slice(0,100);
    } catch(e){}
    if (!items.length) {
      const type = url.searchParams.get('type') === 'device' ? 'device' : 'ip';
      const value = (url.searchParams.get('value') || '').trim().slice(0,100);
      if (value) items = [{ type, value }];
    }
    for (const it of items) {
      const type = it.type === 'device' ? 'device' : 'ip';
      const value = String(it.value || '').trim().slice(0,100);
      if (!value) continue;
      await kv.delete((type === 'ip' ? 'blackip_' : 'blackdev_') + value);
    }
    return json({ ok: true });
  }
  return json({ ok: false, error: '方法错误' }, 405);
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
    if (url.pathname === '/api/admin/feedbacks' && request.method === 'DELETE') return handleAdminFeedbackDelete(request, env);
    if (url.pathname === '/api/admin/feedbacks') return handleAdminFeedbacks(request, env);
    if (url.pathname === '/api/admin/blacklist') return handleAdminBlacklist(request, env);
    if (url.pathname === '/api/admin/bans') return handleAdminBans(request, env);
    if (url.pathname === '/api/admin/ban') return handleAdminBan(request, env);
    if (url.pathname === '/api/admin/sysprompt') return handleAdminSysprompt(request, env);
    if (url.pathname === '/api/admin/balance') return handleAdminBalance(request, env);
    if (url.pathname === '/api/admin/pricing') return handleAdminPricing(request, env);
    if (url.pathname === '/api/admin/feedback-file') return handleAdminFeedbackFile(request, env);
    if (url.pathname === '/admin') return adminPage(env);
    if (url.pathname === '/api/turnstile-key') {
      return json({ ok: true, siteKey: (env.TURNSTILE_SITE_KEY || '').trim() });
    }
    if (url.pathname === '/api/feedback' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      }});
    }
    if (url.pathname === '/api/feedback' && request.method === 'POST') {
      const fr = await handleFeedbackSubmit(request, env);
      const fh = new Headers(fr.headers);
      fh.set('Access-Control-Allow-Origin', '*');
      return new Response(fr.body, { status: fr.status, headers: fh });
    }
    if (url.pathname.startsWith('/api/brake/') && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      }});
    }
    if (url.pathname === '/api/brake/result' && request.method === 'POST') {
      const br = await handleBrakeResult(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/brake/stats' && request.method === 'GET') {
      const br = await handleBrakeStats(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/brake/check-name' && request.method === 'POST') {
      const br = await handleBrakeCheckName(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/brake/board' && request.method === 'GET') {
      const br = await handleBrakeBoard(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/admin/brake/runs' && request.method === 'GET') {
      const br = await handleAdminBrakeRuns(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/admin/brake/delete-entry' && request.method === 'POST') {
      const br = await handleAdminBrakeDeleteEntry(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/admin/brake/reset' && request.method === 'POST') {
      const br = await handleAdminBrakeReset(request, env);
      const bh = new Headers(br.headers);
      bh.set('Access-Control-Allow-Origin', '*');
      return new Response(br.body, { status: br.status, headers: bh });
    }
    if (url.pathname === '/api/feedback' && request.method === 'GET') return handleFeedbackList(request, env);
    if (url.pathname === '/api/feedback' && request.method === 'DELETE') return handleFeedbackDelete(request, env);
    if (url.pathname.startsWith('/api/fb-file/')) return handleFeedbackFile(request, env);
    return env.ASSETS.fetch(request);
  },
};
