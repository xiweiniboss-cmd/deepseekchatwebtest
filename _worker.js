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
const BRAKE_SENSITIVE_WORDS = "08xz\n08宪\n13亿傻逼纳税人\n17da\n18禁\n198964\n20和谐年\n2o年\n3P\n4事件\n4风\n5月35\n5毛党\n64式手枪出售\n64惨案\n64时期\n64运动\n6位qq\n7大军区\n8341部队\n89年春夏之交\n8的平方事件\n92式手枪出售\n99bb\n9学\n9风\nATOM弹制造\nBT\nC4塑胶炸药\nC4炸药\nC4炸药的成分\nDIY原子弹\nDIY核弹\nJS\nLY\nQQ\nSM\nTNT 炸弹的制作\nTNT炸弹制作\nZha药制造进程\na4u\na4y\nadult\namateur\nanal\nasshole\na扁\na片\nbaodong\nbaoluan\nbaozha\nbao炸\nba课\nbbc中文网\nbitch\nbjork\nboycott\ncao你\nchinesedemocracy\ndalai\nda案\nda选\ndick\ndizhi\ndi制\ndl喇嘛\nduli\nfenlie\nfuck\nfuck your mother\ngay片\ngc党\ngfw\ngong党\ngong和\ngoogleblogger\ng产\ng匪\ng点\ng片\nhardcore\nhjt\nhmtd\nhujintao\nh动漫\nh动画\nincest\njieyan\njie严\njing坐\njzm\nlasa\nla萨\nmayingjiu\nmin主\nmorphine\nnarcotic\nnmd\nporn\nqingzhen\nrenquan\nsb国务院\nsecom\nsexinsex\nshangfang\nshit\nsm女王\ntaidu\ntaiwan\ntibet\ntmd\ntnt炸药成分\ntnt炸药配方\ntokyohot\ntwdl\ntxt下载\nwikipedia\nxiao77\nxiao平\nxing伴侣\nxizang\nxi藏\nxjp\nxuechao\nx民党\nx藏\nyin荡\nyoutube\nyouxing\nyou行\nzangdu\nzang人\nzedong\nzemin\nze东\nze民\nzf大楼\nzhadan\nzhayao\nzha弹\nzha药\nzhengfu\nzz炸弹的制作方法\nz东\n「红烧兔子」大餐\n【手枪出售】联系电话\n一ye情\n一丝不挂\n一中一台\n一党专制\n一党专政\n一党执政\n一夜情\n一夜欢\n一本道\n一百块钱的上的那个二逼\n丁一平\n丁子霖\n七个杂种开玩会\n七大军区\n万人大签名\n万人骚动\n万润南\n三个呆婊\n三个婊\n三分钟教你原子弹\n三利达弓弩专卖网\n三利达弓弩军刀\n三利达弓弩直营\n三利达弓弩配件\n三呆婊\n三棱军刺专卖\n三步倒弩箭专卖\n三步倒捕狗药\n三步倒药箭批发\n三步倒麻醉弩箭销售\n三步倒麻醉箭\n三步倒麻醉箭专卖\n三硝基甲苯\n三箭气枪出售\n三级片\n三股势力\n上中央\n上海人缺操\n上海傻逼\n上海帮\n上海逼\n上访\n下体\n下硝化甘油的制作方法\n下贱\n下载速度\n不是黑社会便是和正负官员有亲属关系的败类\n专业代理\n专业弓弩网\n专制政权\n专制走狗\n世界日报\n东北人就这操行\n东北杂种\n东北贱人\n东北逼\n东北骚逼\n东森新闻网\n东森电视\n东突厥斯坦解放组织\n东突解放组织\n丝袜\n丝诱\n两岸战争\n严家其\n个qb\n中gong\n中共\n中共任用\n中共保命\n中共党文化\n中共封网\n中共封锁\n中共就是一群王八蛋\n中共帝国\n中共帮凶\n中共恐惧\n中共政治游戏\n中共是狗屎\n中共权力斗争\n中共洗脑\n中共独裁\n中共的罪恶\n中共的血旗\n中共的走狗拼\n中共腐败\n中共裁\n中共解体\n中共近期权力斗争\n中共退党\n中共邪教\n中共邪毒素\n中共黑\n中共黑帮\n中华局域网\n中华帝国\n中华联邦\n中南海\n中国jc就是一群废物\n中国zf\n中国人是垃圾\n中国人权\n中国复兴党\n中国弓弩专卖网\n中国弓弩狩猎网\n中国弓弩直销\n中国弓弩网\n中国弓驽网\n中国弩弓专卖\n中国当局\n中国战神军用弓弩\n中国户外刀具网\n中国政府就是一坨屎\n中国政府是婊子\n中国新民党\n中国时报\n中国最垃圾的地方\n中国的官员都是人神共愤的杂种\n中国的法律他妈是个笑话\n中国的法律真他妈是个笑话\n中国的陷阱\n中央zf\n中央领导\n中年美妇\n中珙\n丹增嘉措\n主席画像\n主权\n丽女爰是个女子逼\n丽女爰是女子逼\n乖乖粉\n九学\n九风\n习sb\n习二逼\n习仲勋\n习傻逼\n习大傻逼\n习太子\n习婊\n习屌\n习明泽\n习杂种\n习汉奸\n习畜生\n习近平\n习逼格逼格\n买卖54狗\n买卖64狗\n买卖军狗\n买卖军用枪支\n买卖警察枪支\n买小车\n买春\n乱交\n乱伦\n乱伦小\n乱伦类\n乱奸\n乳交\n乳头\n乳房\n乳方\n乳沟\n乳爆\n于幼军\n互联网审查\n五毛们\n五毛党\n五毛拿钱发帖死全家\n五毛死全家\n五毛畜牲\n亚情\n亡党亡国\n亢议\n产党共\n人quan\n人体炸弹\n人体炸弹制作流程\n人兽\n人妻\n人拳\n人木又\n人渣\n人肉炸弹\n仇共\n仓井空\n他妈的\n仙鹤气枪出售\n代孕妈妈\n代开发票\n代理\n代生孩子\n代购\n令计划\n仿品军刺出售\n仿品军刺网\n仿真枪QQ\n伊力哈木\n伊斯兰\n伊斯兰畜生\n伦理大\n伦理毛\n伦理片\n伦理电影\n位的qq\n低价出售\n低制\n体位\n体奸\n何清涟\n作爱\n你他妈\n你们他妈的开始扫黄净网了\n你办事我放心\n你吗b\n你妈个烂比\n你妈妈个大雪碧\n你妈烂了\n你妈的\n你妈血比\n你妈逼拼\n你怎么用土办法做武器\n你除了会操尼玛会认贼作令尊\n你麻痹\n供产\n供应三利达弓弩麻醉箭\n供应三步倒麻醉箭\n供应军用弓弩专卖\n供应军用弩折叠弩\n供应军用手枪\n供应弓弩\n供应弓弩麻醉箭\n供应弩捕狗箭\n供应弩用麻醉箭\n供应汽枪\n供应秦氏弓弩\n供应精品弓弩\n供应钢珠弓弩\n供应麻醉箭\n供应麻醉箭三步倒\n供应麻醉箭批发\n供铲党\n供铲裆\n供铲谠\n侯德健\n保钓组织\n俞正声\n信用卡提现\n信访\n借腹生子\n做爱\n偷拍\n偷欢\n傅锐\n傻b\n傻比\n傻逼\n傻逼政府\n傻逼杂狗\n光复民国\n光腚总局去死\n免费二级域名\n免费使用\n免费索取\n免费订购热线\n党产共\n党的喉舌\n党章\n入耳关\n入联\n全国鸡婆最多\n全套\n全家不得好死\n全家死光\n全家死绝\n全职\n全裸\n全金属仿真枪专卖\n全集在线\n八九年\n公产党\n公头\n公开信\n六位qq\n六合彩\n六和谐四\n六四\n六氟化铀\n六河蟹四\n六百度四\n兰州军区\n共c党\n共x党\n共产专制\n共产主义的幽灵\n共产党\n共产王朝\n共党就是汉奸\n共匪\n共惨\n共操蛋\n共残主义\n共残党\n共残裆\n共狗\n共贪党\n共铲\n关闭所有论坛\n兵力部署\n兼值\n兼职\n兽交\n兽奸\n兽性\n兽欲\n内射\n冒泽东这个杂种\n写的炸弹制作教程\n军事社\n军刀专 卖\n军刀专卖军刺\n军刀专卖刀具批发\n军刀价格军用刀具\n军刀军刺甩棍\n军刀军品网\n军刀匕首直销网\n军刀图片砍刀\n军刀甩棍销售\n军刀电棍销售\n军刀直刀专卖\n军刀直刀军品网\n军刀直销网\n军刀网\n军刀网军刀专卖\n军刺野营砍刀出售\n军品军刺网\n军用54出售\n军用77出售\n军用刀具军品网\n军用弓弩专卖店\n军用弓弩专卖网\n军用弓弩公司\n军用弓弩批发\n军用手枪钢珠枪\n军转\n农村逼\n冷钢刀具专卖\n冷钢刀具军品网\n冷钢刀具直销网\n凌辱\n几吧\n出售54式手枪\n出售:高仿真枪\n出售M1911\n出售三棱刀\n出售仿真枪\n出售军刀\n出售军刺\n出售军刺军刀\n出售军品军刀\n出售各类猎狗\n出售国产军用54手枪\n出售外国枪模\n出售开山刀军刺\n出售弹簧刀\n出售手枪\n出售手枪 QQ\n出售手枪 电话\n出售手枪=货到付款\n出售手狗\n出售步枪\n出售气枪\n出售气枪 QQ\n出售气枪 电话\n出售气狗\n出售汽枪\n出售火枪 –游戏\n出售炸药\n出售炸药 电话\n出售炸药QQ\n出售狙击枪\n出售猎枪\n出售猎枪 QQ\n出售猎枪 电话\n出售猎狗\n出售答案\n出售美军现役军刀\n出售袖珍手枪\n出售警用手铐|仿真枪\n出售跳刀\n出售进口金属枪模\n出售雷管\n出售雷管炸药\n出售麻醉枪免收任何定金\n出现暴动\n刀具直销网\n刁sb\n刁傻逼\n刁婊子\n刁杂种\n刁王八\n刁畜生\n刁逼带着戏子环球\n列确\n刘云山\n刘奇葆\n刘宾雁\n刘少奇\n刘延东\n刘志军\n刘明康\n刘晓竹\n刘永清\n刘瑞龙\n刘翔老婆逼很宽\n则民\n刚操完你娘\n别他吗\n别梦成灰\n到货\n制作性能优良的燃烧弹\n制作火药配方\n制作炸弹首先要\n制作硝化甘油\n制作简易弓弩\n刹笔\n刺刀专卖网\n刻章办\n前凸后翘\n加盟连锁\n劣等民族\n勃朗宁军刀\n募屎淋\n包二奶\n包夜\n匕首蝴蝶甩刀专卖\n北京人欠屌\n北京傻逼\n北京军区\n北京帮\n北京当局\n北京政权\n北京逼\n北京那群傻逼\n北京风波\n北方先锋军刀\n北高联\n十7大\n十七大\n华主席\n华国\n华建敏\n华盛顿邮报\n卖64手枪\n卖92手枪\n卖逼\n卖钢珠枪QQ\n南京军区\n南京逼\n南方军刀网\n南街村\n占领台湾\n卧槽\n卧艹\n印尼事件\n印尼屠华\n历史的伤口\n厕奴\n原味内衣\n原子弹 制作方法\n原子弹DIY教程\n原子弹制作\n原子弹制作 方法\n原子弹制作手册\n原子弹制作方法\n原子弹制作方法DIY\n原子弹制造完全手册\n原子弹配方\n原音铃声\n去中央\n去你的妈的法律\n双臀\n双规\n反party\n反共\n反分裂\n发情\n发浪\n发生关系\n发生暴动\n口交\n口射\n口暴\n口活\n口淫\n口爆\n叫床\n可塑炸弹制作\n可塑炸弹制作方法\n台du\n台wan\n台军\n台完\n台弯\n台毒\n台海危机\n台海大战\n台海局势\n台海战争\n台海统一\n台海问题\n台湾共和国\n台湾国\n台湾应该独立\n台湾有权独立\n台湾版假币\n台湾独立\n台湾问题\n台独\n台百度湾\n叶剑英\n司马仿真枪模型QQ\n司马璐\n吃精\n各式气枪出售\n各种炸药配方大全\n各类军用枪\n各类军用枪支\n后庭\n后穴\n吕祖善\n吞精\n启蒙派\n吴仪\n吴官正\n吴定富\n吴胜利\n吴邦国\n吸精\n吸金逼\n吾尔\n吾尔开希\n吾尔开西\n告全国同胞书\n周小川\n周建南\n周永康\n周生贤\n呻吟\n咪咪\n品香堂\n哒赖\n哪能买到真枪\n哪里有卖双管猎\n哪里有枪出售\n哪里有气枪卖\n哪里有真枪出售\n哪里有真枪卖买\n哪里有连发猎枪买卖\n哪里有钢珠枪\n哪里能买到自制手枪\n售手枪QQ\n售枪购买手枪\n售肾\n啦撒\n啦沙\n啦萨\n喝血社会\n喷精\n四事件\n四二六社论\n四海帮\n四风\n回回\n回复可见\n回教\n回族\n回民\n回良玉\n国wu院\n国产av\n国产汽狗专卖|气枪货\n国峰\n国民党\n国锋\n国际特赦\n土g\n土共\n土炸药成份\n圣战组织\n在家里做原子弹\n在线播放\n地下钱庄\n坦克压大学生\n垃圾a股一片绿色\n垃圾共产党\n垃圾制度\n垃圾国家\n垃圾政府\n垃圾政府拼\n垃圾正奸会\n垃圾治国\n垃圾煮易核心价值观\n垃圾网易\n垃圾郭家\n城管暴力执法\n基地组织\n基本配方是硝酸甘\n塑胶炸弹\n塔利班\n境外媒体\n墓屎淋\n处男\n夏川纯\n外地傻逼\n外地逼\n多人轮\n夜勤病栋\n大sb\n大乳\n大力抽送\n大波\n大赦国际\n大连人都是大傻逼\n大陆官方\n大陆当局\n天按门\n天灭中共\n太子党\n失身粉\n奈美\n套弄\n套牌车\n奚国华\n女优\n女干你麻麻\n奶子\n奸情\n好嫩\n如何制硝化甘油\n如何自制燃烧弹\n妈了个逼\n妈逼\n妓女\n妹上门\n妹按摩\n姚依林\n威胁论\n娘西皮\n娥眉气枪出售\n婊子\n婊子养的\n婊子嫖客领潮\n婊子戏子的几日游\n婊子政府\n婊子满世界扔钱\n婴儿汤\n媚外\n嫩女\n嫩穴\n嫩逼\n子弹货到付款\n孔丹\n孙家正\n孟建柱\n学chao\n学潮\n学生妹\n学百度潮\n安徽人都是垃圾\n安徽傻逼\n安徽杂种\n安徽畜生\n安徽自古出人渣\n安徽逼崽\n安拉\n宋平顺\n完全自杀手册\n官匪\n官商勾结\n官逼民反\n审帖的这种走狗\n客服\n宪政\n宪法法院\n宪章\n家里人天天在村里吹牛逼说我\n寂寞女\n寂寞男\n密穴\n对逼进行分类\n寻找林昭的灵魂\n封从德\n封锁消息\n封面女郎\n射满他妈老比\n射爽\n射精\n射逼里\n射颜\n小xue\n小口径秃鹰沙漠\n小型弓弩专卖店\n小姐\n小泽一郎\n小猎人弓弩网\n小穴\n小逼\n小额贷款\n少修正\n少年阿宾\n尚福林\n就去日\n尼泊尔军刀出售\n屁眼\n屄痒\n屌大瓶\n屌近平\n屎坑核心\n屎进瓶\n屠光绍\n山东畜牲驴\n山东畜生\n山东逼欠插\n崩盘\n工产党\n工字汽狗麻醉枪\n工字牌气枪出售专卖\n左翼联盟\n巨乳\n巨奶\n巨屌\n希葬\n希藏\n席二逼\n帮忙点一下\n帮忙点下\n常万全\n干你\n干你女马\n干你妈\n干你娘\n干死\n干死你\n干穴\n干过你妈\n平反\n平小邓\n平近习\n幼交\n幼女\n幼男\n广东傻逼\n广东婊子\n广东杂种\n广东逼\n广告代理\n广州军区\n广西傻逼\n广西畜生\n广西逼\n应召\n底制\n廖锡龙\n开山刀砍刀出售\n开苞\n异议人士\n弄机电两代汉奸\n弓单\n弓弩一百专卖店\n弓弩专卖\n弓弩专卖店\n弓弩专卖店网\n弓弩专卖网\n弓弩专卖网货到付款\n弓弩专卖货到付款\n弓弩专营\n弓弩亲兄弟货到付款\n弓弩免定金货到付款\n弓弩制作\n弓弩商城\n弓弩商城专卖\n弓弩图纸\n弓弩批发\n弓弩有限公司\n弓弩特许经销\n弓弩狩猎网\n弓弩直销\n弓弩网\n弓弩营销中心\n弓弩论坛\n弓弩销售\n弓弩麻醉箭\n弓弩麻醉镖\n引起暴动\n张培莉\n张定发\n张德江\n张志国\n张志新\n张立昌\n张筱雨\n张荣坤\n张高丽\n弹药制造方法\n弹药配方\n强jian\n强制拆除\n强制捐款\n强卫\n强奸\n强奸处女\n强暴\n当局严密封锁\n形式主义\n彭一定被习操过\n彭二逼\n彭婊\n彭婊子\n彭氏逼\n徐才厚\n徐明\n徐绍史\n微店\n快感\n怎么用土办法做武器\n怎么自制燃烧弹\n性交\n性交图片\n性交视频\n性伙伴\n性伴侣\n性奴\n性奴集中营\n性息\n性感妖娆\n性感少\n性感诱惑\n性技巧\n性服务\n性欲\n性爱\n性福情\n性虎\n性虐\n性饥渴\n恐怖份子\n恐怖分子\n恐怖分子傻瓜手册\n恐怖分子自己制造炸弹\n恶党\n悦逼\n情色\n情趣用品\n惹火身材\n慕屎淋\n戈博军刀\n成人dv\n成人卡通\n成人图\n成人小\n成人小说\n成人文\n成人文学\n成人游戏\n成人片\n成人电\n成人电影\n成人网站\n成人聊\n成人色情\n成人视\n成人论坛\n成都军区\n我严重怀疑这个国家被汉奸和敌对势力掌控了\n我咒你全家死光光\n我就色\n我干\n我操\n我日你\n我日你娘\n我等有王八蛋进贡\n我草\n戒yan\n戒严\n战术军刀出售\n截访\n戴秉国\n户外军刀出售\n户外军刀网\n手工猎刀专卖\n手工猎刀户外刀具\n手把手教你做炸弹\n手把手教你制作原子弹\n手教你做原子弹\n手教你制作原子弹\n手枪|阻击枪\n手枪式折叠三用弩\n手枪气* 枪猎\n手柄制作炸弹引爆器\n手槍买卖自制手枪\n手淫\n扌由插\n打倒中共\n打倒中国\n打倒共产主义\n打倒共产党\n打倒朱镕\n打倒李鹏\n打倒江主席\n打倒江泽民\n打倒温家宝\n打倒罗干\n打倒胡锦涛\n打台湾\n打狗弓弩三步倒\n打砸抢\n扣扣\n找个妈妈\n找个爸爸\n技师\n抓胸\n投公\n抗议\n折刀专卖网\n折刀砍刀专卖\n折刀砍刀军品网\n折叠狗QQ\n抵zhi\n抵制\n抵制中共\n抵制共产主义\n抵制共产党\n抵制朱镕基\n抵制李鹏\n抵制江主席\n抵制江泽民\n抵制温家宝\n抵制罗干\n抵制胡锦涛\n抽一插\n抽插\n抿主\n拉sa\n拉屎\n拉萨\n拔出来\n招妓\n招聘\n招鸡\n择民\n拱铲\n拳交\n拿钱发帖的杂种们\n按摩棒\n挡中央\n捏弄\n换妻俱乐部\n推油\n揉乳\n提供专业及时的气狗\n提供气狗专卖店\n插b\n插了尼玛的逼\n插你\n插我\n插暴\n插比\n插进\n插逼\n插阴\n援交\n援助交际\n援藏\n摇头丸\n摸奶\n摸胸\n操b专车\n操他妈\n操你\n操你全家\n操你大爷\n操你妈\n操你娘\n操你祖宗\n操我\n操死\n操泽东\n操烂\n操爆你\n操着江苏无锡口音的鸟\n操纵股票\n操肛门\n操过逼\n操逼\n操黑\n擦你妈\n支持zd\n支持台湾\n收复台湾\n改卷内幕\n改革历程\n攻占台湾\n放尿\n政f\n政zhi\n政付\n政俯\n政府\n政府+傻逼\n政府+去死\n政府+垃圾\n政治风波\n政腐\n敏主\n救市\n教你制作原子弹\n教你怎么用土办法做武器\n文做\n新僵杂种\n新疆逼\n新疆骚乱\n新闻封锁\n方励之\n无修正\n无官正\n无抵押贷款\n无界浏览\n无界网络\n无码\n无耻\n日你妈\n日本万岁\n日死你妈\n日烂\n日逼\n昝爱宗\n星岛日报\n春药\n暴乳\n暴奸\n暴干\n暴淫\n曹刚川\n曾培炎\n曾宪梓\n曾庆红\n曾荫权\n曾道人\n替考试\n最新销售汽狗\n最淫官员\n有军用枪支出售\n有意者\n期出售手枪气枪猎\n木仓\n木屎林\n本世纪最大的卖国贼是蟾蜍\n本店\n朱云来\n朱容基\n朱容鸡\n朱海仑\n朱镕基\n朱镕鸡\n杀b\n杀毙\n杂种\n杂种大手一挥\n杂种天朝\n杂种拼\n权贵集团\n李peng\n李先念\n李克强\n李天羽\n李学举\n李小琳\n李小鹏\n李岚清\n李干成\n李建国\n李德生\n李春城\n李月月鸟\n李沛瑶\n李洪志\n李源潮\n李瑞环\n李荣融\n李铁映\n李长春\n李鹏\n杜世成\n杜德印\n杨思敏\n杨洁篪\n杭州傻逼\n杭州逼\n松岛枫\n极端武力军品网\n极端武力折刀\n极端武力直销网\n林左鸣\n林文漪\n林树森\n林炎志\n柳斌杰\n柴玲\n标准炸弹教程\n栗智\n校鸡\n核弹制作方法\n核弹头的制造\n核蛋\n桑拿\n档中央\n梁光烈\n楼凤\n榨干你\n欠干\n欧广源\n欲仙欲死\n欲女\n欲火\n款到发货\n正品军刺出售\n正府\n步qiang\n死全家\n死逼\n殃视\n母奸\n母屎淋\n毒豺\n毒龙\n毛zd\n毛zx\n毛人渣\n毛傻逼\n毛大畜牲\n毛大畜生\n毛太祖\n毛杂种\n毛杂种拼\n毛泽东\n毛泽东+人渣\n毛渣东畜牲\n毛灾东这个大畜牲\n毛相\n民一主\n民主女神\n民泽江\n民猪\n民珠\n民竹\n民运人士\n民进党\n气枪\n气枪/出售/专卖网\n气枪/猎枪/钢珠枪\n气枪专卖网\n气枪价格 仿真气枪\n气枪价格，气枪专卖店\n气枪仿真枪出售\n气枪猎枪麻醉枪\n气枪看货加QQ\n气枪联系QQ\n气枪货到付款,汽狗出售\n气枪购买|气枪组装\n气枪迷魂药\n气狗 高压气枪\n气狗出售 进口气狗\n氢弹手工制作方法\n水浴法制TNT\n汉人\n汉维\n江core\n江x\n江zm\n江三婊子\n江三条腿\n江丑闻\n江主席\n江书记\n江人马\n江哥\n江大王八\n江太上\n江婊\n江嫡系\n江宰民\n江家帮\n江戏子\n江某某\n江核心\n江梳头\n江毒\n江氏家族\n江氏政治委员\n江氏政治局\n江氏集团\n江汉奸\n江沢民\n江泉集团\n江泽慧\n江泽民\n江派\n江派人马\n江派和胡派\n江浙民\n江浙闽\n江独裁\n江猪\n江祸心\n江系人\n江系人马\n江绵康\n江绵恒\n江胡\n江胡内斗\n江苏杂种叫喳喳\n江蛤蟆\n江败类\n江贼\n江贼民\n江黑心\n汤加丽\n汪东兴\n汪兆钧\n汽油三分之一白糖混合\n汽狗高压汽枪\n汽车炸弹制作\n沈彤\n沈跃跃\n沈阳军区\n沐屎淋\n沙比\n河南东北畜生\n河南人傻逼\n河南人全家死光\n河南杂种\n河南畜牲\n河南逼\n河蟹社会\n油行\n法轮功\n泽d\n洋垃圾也必须扔掉\n洗屌\n洗屌不吓台\n洗屌瓶\n流淫\n流血冲突\n济南军区\n浙江傻逼\n浪叫\n浪女\n浪妇\n浪逼\n液体炸药配方\n淘宝\n淘宝气枪货到付款\n淫书\n淫乱\n淫亵\n淫兽\n淫兽学\n淫兽学园\n淫叫\n淫声浪语\n淫女\n淫妇\n淫妻\n淫威\n淫娃\n淫媚\n淫情\n淫情女\n淫教师\n淫术炼金士\n淫样\n淫母\n淫水\n淫河\n淫浪\n淫液\n淫照\n淫电影\n淫穴\n淫糜\n淫肉\n淫色\n淫荡\n淫荡照片\n淫荡美女\n淫荡自慰器\n淫荡视频\n淫虐\n淫虫\n淫贱\n淫靡\n淫騷妹\n淫魔\n淫魔舞\n混蛋\n清zhen\n清华帮\n清真\n温jb\n温jia宝\n温x\n温云松\n温加保\n温加宝\n温加饱\n温如春\n温婊家子宝\n温宝宝\n温家宝\n游xing\n游行\n湖南出了一个杂种\n湖紧掏\n湾台\n满洲第三帝国\n满狗\n漏乳\n潮吹\n潮喷\n激情\n激流中国\n火乍\n火药制作简易炸弹\n火药原理\n火药的配方\n火药配方\n灭亡中国\n灭共\n炮友\n炸dan\n炸yao\n炸弹制作\n炸弹制作从入门\n炸弹制作从入门到精\n炸弹制作入门\n炸弹制作手册 硫酸\n炸弹配方\n炸药\n炸药出售\n炸药制造生产工艺\n炸药及其制造方法\n炸药的制作\n炸药的制作配方\n炸药的成分\n炸药的配方\n炸药硝酸甘油制法\n炸药配方\n炸药配方与制作\n烂屄\n烂逼\n热武器QQ\n热比娅\n焚烧中国国旗\n焦国标\n煞笔\n煞逼\n熟女\n熟妇\n熟母\n燃烧剂的简易制作\n燃烧剂的简易制备\n燃烧弹\n燃烧弹 制作\n燃烧弹制作\n燃烧弹的制作方\n燃烧弹的制作方法\n燃烧瓶制作\n燃烧瓶的制作方法\n爆zha\n爆乳\n爆你菊\n爆操\n爆破和杀伤燃烧弹\n爆草\n爱国者同盟\n爱女人\n爱液\n爽死我了\n爽片\n特供\n特共\n特贡\n狂插\n狂操\n狗产蛋\n狗娘养\n狗屎共产党\n狗屎国家\n狗屎政府\n狗屎的天朝法律\n狗操\n狗日的\n狗日的中国社会\n狗日的五毛\n狗日的党\n狗日的共产党\n狗日的制度\n狗日的国家\n狗日的政府\n狗日的毛泽东\n狗日的社会\n狗杂种\n狗草\n狗逼政府\n狩猎器材弓弩\n狩猎器材弓弩专卖\n狩猎弓弩专卖\n狩猎弓弩专卖网\n狩猎弓弩麻醉箭\n独夫民贼\n狼友\n猎枪|真枪\n猎枪专卖店\n猎枪仿真枪QQ\n猎枪出售/枪\n猎枪哪里有卖\n猎枪子弹底火专卖\n猎枪手枪买卖\n猎枪销售手枪销售气枪\n猎枪麻醉枪钢珠枪\n猫则东\n猫泽东\n猫贼洞\n玉乳\n玉女心经\n玉穴\n玉蒲团\n王东明\n王丹\n王乐泉\n王兆国\n王八们有何事上奏\n王八朝\n王八蛋\n王八蛋政府\n王八裆\n王冶坪\n王千源\n王太华\n王学军\n王岐山\n王振华\n王沪宁\n王洛林\n王炳章\n王维林\n王胜俊\n王超华\n王鸿举\n玛雅网\n用刀横向切腹\n用火药混合塑料\n用逼\n由喜贵\n电婊\n电脑传讯\n男公关\n男奴\n畜牲大手一挥\n畜牲毛\n畜生\n畜生习近平\n畜生治国\n畜生的国度\n疆独\n症腐\n瘟假逼\n登陆台湾\n白春礼\n白痴\n皮箱炸弹\n盗撮\n直刀匕首直销网\n相奸\n真主\n真他妈\n知道64\n石肖\n砍刀精品折刀专卖\n砲友\n硒藏\n硝酸甘油\n硝酸甘油制作\n硝酸甘油炸弹制作\n硝酸甘油炸弹制作方法\n硝酸甘油炸药制作\n硝酸铵的简便制取方法\n硝铵炸药配方\n示wei\n示威\n社会主义灭亡\n私人侦探\n私家侦探\n秃鹰气枪货到付款\n秘唇\n稀藏\n穆屎林\n穆屎淋\n穆斯林\n穆罕穆德\n穆罕默德\n穴口\n穴图\n第21集团军\n答an\n简易原子弹教程\n简易大威力炸弹\n简易导弹制作\n简易核弹头的制造\n简易炸弹\n简易炸药\n简易燃烧弹\n粉碎四人帮\n粉穴\n粟戎生\n精叉都在吃屎\n精子\n精液\n精神药品\n糊屌滔爷\n紫阳\n红色贵族\n纽约时报\n组织集体\n组装手枪\n统一台湾\n维吾\n维基百科\n维权\n维汉\n网易去死\n网易我操你妈\n网特\n网络\n网络封锁\n网络工作\n网络评论员\n网评员\n网购\n罗箭\n罢ke\n罢参\n罢吃\n罢学\n罢工\n罢教\n罢考\n罢课\n罢运\n罢食\n罢餐\n罢饭\n美乳\n美国军刀出售\n美国广播公司\n美女上门\n美女写真\n美女裸体\n美少妇\n美幼\n美穴\n美腿\n美艳少妇\n美逼\n群交\n群体事件\n群体性事件\n耀邦\n老j\n老习\n老共\n老娘的巨逼\n老江\n老猫子冬是仲果的败类\n老逼\n考中答案\n聊性\n联名上书\n肉具\n肉唇\n肉棍\n肉棒\n肉欲\n肉洞\n肉穴\n肉缝\n肉茎\n肉逼\n肏你\n肏死\n肛交\n肛门\n股市圈钱\n肥逼\n肿朝isis是行畜生道\n胡boss\n胡jintao\n胡jt\n胡j涛\n胡x\n胡主席\n胡平\n胡总\n胡惊涛\n胡春华\n胡景涛\n胡派\n胡海峰\n胡海清\n胡温\n胡狗屎\n胡王八\n胡紧套\n胡紧掏\n胡锦涛\n胸推\n脑子全是被d灌的屎\n脑残zf\n脑残患儿发病\n脚交\n脱光\n脱内裤\n腐败中国\n腾讯客服电话\n臧人\n臧独\n自制手弩\n自制手枪哪里买\n自制手枪哪里有卖\n自制炸药方法\n自制炸药配方\n自制燃烧弹\n自动跳刀专卖\n自慰\n自由亚洲\n自由时报\n自由门\n舔脚\n舔阴\n舞女\n色b\n色区\n色妹妹\n色小说\n色情图片\n色情小说\n色情影片\n色情服务\n色情片\n色情电影\n色情网站\n色情表演\n色欲\n色猫\n色电影\n色界\n色盟\n色色\n色视频\n色诱\n色逼\n艳情小说\n艹你\n花花公子\n苏晓康\n苏树林\n苏贞昌\n英国金融时报\n茳泽民\n草你\n草你丫\n草你全家\n草你吗\n草你妈网易\n草泥马大勺逼\n草逼\n荡女\n荡妇\n莫洛托夫燃烧弹\n莫洛托夫鸡尾酒的配方\n菊穴\n菊花洞\n菊门\n著名精品折刀出售\n董建华\n葬独\n蒋公纪念歌\n蒋彦永\n蒋捷连\n蒙古分裂分子\n蔡武\n蔡赴朝\n薄一波\n薄熙\n薄熙来\n藏du\n藏m\n藏人\n藏妇会\n藏字石\n藏春阁\n藏暴乱\n藏毒\n藏民\n藏独\n藏独立\n藏獨\n藏西\n藏青会\n虎骑\n蚁力神\n蜜液\n蜜穴\n血书\n血洗京城\n血葫芦逼\n袁纯清\n被干\n被插\n被操\n装b\n裆中央\n裙中性运动\n裤袜\n裸体写真\n裸照\n裸聊\n裸聊网\n裸舞视\n裸陪\n裸露\n裹本\n西z\n西奘\n西点军刀网\n西点军品军刀网\n西独\n西脏\n西臧\n西葬\n西藏\n要射了\n规模冲突\n视频来源\n解决台湾\n解放tw\n解放军\n解放台湾\n警匪\n警用刀具出售\n讨伐中宣部\n讨说法\n记者无疆界\n许其亮\n访民\n证监会\n详情请进入\n诱奸\n请命\n请愿\n请点击进入\n谁是新中国\n调教\n调查婚外情\n谐星习屌\n谜奸药\n谭作人\n豪乳\n贡挡\n败类\n败类改革\n质押贷款\n贪污腐败\n购买枪支QQ\n购买自爆材料\n贰拾周年\n贰拾年\n贱b\n贱人\n贱比\n贱货\n贵州人是杂种\n贵州穷逼\n贺卫方\n贺国强\n贺子珍\n贾庆林\n贾廷安\n资金周转\n资金短缺\n赖达\n赤裸\n赵氏弓弩专卖\n赵氏弓弩专卖店\n赵氏弓弩专卖网\n赵氏弓弩销售\n赵洪祝\n起爆器\n足交\n足球投注\n路甬祥\n转让 猎枪\n轮奸\n轮操\n轮暴\n轻型巡航导弹的制作\n辛灏年\n辛灝年\n达赖\n这群杂种每天还在控制新闻媒体\n进口气枪,气枪子弹\n进攻台湾\n连锁加盟\n迷奸\n迷奸粉\n迷奸药\n迷幻药\n迷幻藥\n迷情水\n迷情粉\n迷情药\n迷昏口\n迷昏药\n迷昏藥\n迷药\n迷藥\n迷魂药\n迷魂藥\n迷魂香\n追风弓弩麻醉箭专卖\n送qb\n选国家主席\n逼你交钱\n逼你做事\n逼养的\n逼奸\n逼死\n逼水\n逼近江泽民曾庆红\n邓xp\n邓小平\n邓晓平\n邓朴方\n邓榕\n邓王八\n邓败类\n邓质方\n邪党\n郑州弓弩专卖\n郭伯雄\n郭金龙\n酥痒\n酸甘油炸药\n醯进逼\n释欲\n里有汽枪出售\n里鹏\n野营军刀出售\n野营刀专卖\n野营刀具专卖\n野营刀具军品网\n野营开山刀军刺\n野营砍刀户外军刀\n金盾工程\n金鳞岂是池中物\n金麟岂是池中物\n针孔摄象\n钓鱼岛\n钢珠弓弩专卖店\n钢珠弓弩专卖网\n钢珠枪小口径步枪\n铁凝\n铃声\n铃木麻\n铅弹 上海工字气枪\n销售/专卖/买卖77式手枪\n销售小口径步枪\n销售气手狗\n销售热线\n销售电手狗\n销售运动步枪\n锋同志\n锡峰气枪出售\n锦涛\n长期出 售手枪\n门安天\n闹独立\n阅尼玛逼的兵\n阅逼\n阉割\n阎明复\n防卫刀具专卖\n防卫刀具军品网\n防卫刀具直销网\n防卫棍刀出售\n防卫棍刀户外刀具\n防卫甩棍出售\n防卫电棍出售\n防卫著名军刀出售\n防卫野营砍刀出售\n防身手枪QQ\n防身武器手枪\n阳具\n阳江军品军刀网\n阳江刀具专卖\n阳江刀具军品网\n阳江刀具批发网\n阳江刀具直销网\n阴b\n阴唇\n阴户\n阴核\n阴毛\n阴精\n阴茎\n阴茎助勃\n阴茎增大\n阴蒂\n阴道\n阴部\n阴间来电\n阴阜\n阻击枪/汽枪/高压气枪\n阿兰得龙野营刀具网\n阿兰德龙户外\n阿兰德龙野营刀\n阿共\n阿扁\n阿拉伯\n阿旺晋美\n阿波罗网\n陆四\n陆肆\n陈s扁\n陈一咨\n陈同海\n陈建国\n陈德铭\n陈水扁\n陈炳德\n陈绍基\n陈至立\n陈良宇\n陈随便\n限量\n陰唇\n陰戶\n陰道\n隐形耳机\n集会\n集体淫\n集合\n集团出售手枪\n集团出售手枪气枪\n集束炸弹制作\n雪山狮子旗\n雷管出售\n露b\n霸工\n霸课\n霸餐\n青天白日\n靖志远\n静zuo\n静坐\n鞑子\n韩国狗\n颜射\n颜色革命\n风月大陆\n风骚\n食屎减刑复读鸡\n食精\n马克屎\n马勒\n马屁精\n马恺\n马英九\n马飚\n驴操北京它妈的不管\n骚嘴\n骚女\n骚妇\n骚屄\n骚比\n骚水\n骚浪\n骚穴\n骚货\n骚逼\n骡屙屎\n高丽棒子\n高勤荣\n高压气枪,气枪子弹\n高压气枪|气枪货到付款\n高压气枪|电狗专卖\n高压气枪专卖店\n高压狗QQ\n高性能爆炸物质混合\n高智晟\n高清在线\n高潮\n高爆炸药基本配方\n高爆炸药的基本配方\n高自联\n魏京生\n鸡吧\n鸡奸\n鸡尾酒炸弹制作\n鸡巴\n麻将透\n麻果丸\n麻痹的\n麻醉弓弩专卖店\n麻醉弹\n麻醉枪\n麻醉枪出售可验货\n麻醉枪猎枪军用\n麻醉槍\n麻醉狗\n麻醉药\n麻醉藥\n黄丽满\n黄兴国\n黄华华\n黄敬\n黄易也开始装逼\n黄易就是典型的走狗奸臣\n黄片\n黄镇\n黑屄\n黑火药和硝酸钾农药混合\n黑火药比例\n黑火药的制作\n黑火药的成分\n黑火药的配方\n黑火药配方\n黑火药配方比例\n黑索金的制造过程\n黑逼\n默罕默德\n龙新民\n龟头";
let _brakeSWSet = null;
function brakeHasSensitive(name) {
  if (!_brakeSWSet) _brakeSWSet = new Set(BRAKE_SENSITIVE_WORDS.split('\n').map(function (w) { return w.toLowerCase(); }));
  const t = String(name || '').toLowerCase();
  for (const w of _brakeSWSet) { if (w && t.indexOf(w) !== -1) return true; }
  return false;
}

// ---------- 刹车站：全网成功/失败统计 + 实时排行榜 ----------
async function handleBrakeResult(request, env) {
  const kv = env.FEEDBACK_KV;
  if (!kv) return json({ ok: false, error: '未启用' }, 503);
  let b = {};
  try { b = await request.json(); } catch (e) {}
  const success = b.success === true;
  const ms = Math.round(Number(b.ms) || 0);
  let name = String(b.name || '').slice(0, 12) || '无名车手';
  if (brakeHasSensitive(name)) name = '无名车手';
  const device = String(b.device || '').slice(0, 64) || 'anon';
  if (success && !(ms >= 500 && ms <= 30000)) return json({ ok: false, error: '数据异常' }, 400);
  let stats = { s: 0, f: 0 };
  try { const raw = await kv.get('brake_stats_v1'); if (raw) stats = JSON.parse(raw); } catch (e) {}
  if (success) stats.s++; else stats.f++;
  try { await kv.put('brake_stats_v1', JSON.stringify(stats)); } catch (e) {}
  try {
    let runs = [];
    const rraw = await kv.get('brake_runs_v1');
    if (rraw) runs = JSON.parse(rraw);
    if (!Array.isArray(runs)) runs = [];
    runs.unshift({ ip: request.headers.get('cf-connecting-ip') || '', d: device, n: name, ok: success, ms: success ? ms : 0, t: Date.now() });
    runs = runs.slice(0, 200);
    await kv.put('brake_runs_v1', JSON.stringify(runs));
  } catch (e) {}
  if (success) {
    let board = [];
    try { const raw = await kv.get('brake_board_v1'); if (raw) board = JSON.parse(raw); } catch (e) {}
    if (!Array.isArray(board)) board = [];
    const now = Date.now();
    const ex = board.find(function (e) { return e.d === device; });
    if (ex) { if (ms < ex.ms) { ex.ms = ms; ex.n = name; ex.t = now; } }
    else board.push({ n: name, ms: ms, d: device, t: now });
    board.sort(function (a, b2) { return a.ms - b2.ms; });
    board = board.slice(0, 50);
    try { await kv.put('brake_board_v1', JSON.stringify(board)); } catch (e) {}
  }
  return json({ ok: true });
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
  let stats = { s: 0, f: 0 }, runs = [];
  try {
    const sraw = kv && await kv.get('brake_stats_v1');
    if (sraw) stats = JSON.parse(sraw);
    const rraw = kv && await kv.get('brake_runs_v1');
    if (rraw) runs = JSON.parse(rraw);
  } catch (e) {}
  if (!Array.isArray(runs)) runs = [];
  return json({ ok: true, success: stats.s | 0, fail: stats.f | 0, runs: runs.slice(0, 200) });
}
async function handleAdminBrakeReset(request, env) {
  if (!adminAuth(request, env)) return json({ ok: false, error: '无权' }, 403);
  const kv = env.FEEDBACK_KV;
  try {
    if (kv) {
      await kv.delete('brake_stats_v1');
      await kv.delete('brake_board_v1');
      await kv.delete('brake_runs_v1');
    }
  } catch (e) {}
  return json({ ok: true });
}

async function handleBrakeStats(request, env) {
  const kv = env.FEEDBACK_KV;
  let stats = { s: 0, f: 0 };
  try { const raw = kv && await kv.get('brake_stats_v1'); if (raw) stats = JSON.parse(raw); } catch (e) {}
  return json({ ok: true, success: stats.s | 0, fail: stats.f | 0 });
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
