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
  if (bl) return json({ ok: false, error: '账号已被限制访问' }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  const action = body.action === 'register' ? 'register' : 'login';
  const username = String(body.username || '').trim();
  const password = String(body.password || '').trim();
  if (!validUsername(username)) return json({ ok: false, error: '用户名为1-8个字母' }, 400);
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
  const thinkFlag = !!(body.think || (oldEntry && oldEntry.think));
  const webFlag = !!(body.web || (oldEntry && oldEntry.web));
  list = list.filter(function(c){ return c.id !== id; });
  list.unshift({ id, title, t: Date.now(), think: thinkFlag, web: webFlag });
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
  const html = "<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>可乐站·DeepSeek 后台</title><style>*{box-sizing:border-box}body{margin:0;background:#0b0b0f;color:#e8e8ec;font-family:-apple-system,sans-serif;padding:16px;max-width:720px;margin:0 auto}h1{font-size:20px}h2{font-size:16px;margin-top:24px}.card{background:#14141a;border:1px solid #2c2c36;border-radius:14px;padding:14px;margin-bottom:10px}.row{display:flex;justify-content:space-between;align-items:center;gap:8px}button{border:none;border-radius:10px;padding:9px 14px;font-size:14px;cursor:pointer}.bv{background:#2a2a34;color:#e8e8ec}.bd{background:#3a2028;color:#ff8ba0}.msg{border-left:3px solid #2c2c36;padding:8px 10px;margin:8px 0;font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word}.msg.user{border-color:#4a9eff}.msg.assistant{border-color:#22c55e}.rl{font-size:12px;color:#9a9aa3;margin-bottom:4px}#kb{text-align:center;margin-top:60px}.hd{display:none}input{background:#101016;border:1px solid #2c2c36;border-radius:10px;color:#e8e8ec;padding:12px;font-size:15px;width:220px;text-align:center}.sm{font-size:12px;color:#9a9aa3}.fb-txt.clamp{max-height:60px;overflow:hidden}.blue{color:#4a9eff;font-size:12px}.tg{background:#4a9eff22;color:#4a9eff;border-radius:6px;padding:2px 6px;font-size:11px}.tg2{background:#22c55e22;color:#22c55e;border-radius:6px;padding:2px 6px;font-size:11px}</style></head><body><div id=\"kb\"><h1>可乐站·DeepSeek 后台</h1><p class=\"sm\">请输入管理密码</p><input type=\"password\" id=\"ki\"><br><br><button class=\"bv\" id=\"goBtn\">进入</button><div id=\"lm\" style=\"margin-top:10px;min-height:20px\"></div></div><div id=\"mn\" class=\"hd\"><h1>用户管理</h1><button class=\"bv\" id=\"rfBtn\">刷新</button><div id=\"ul\"></div><h2 id=\"ct\" class=\"hd\"></h2><div id=\"cl\"></div><h2 id=\"mt\" class=\"hd\"></h2><div id=\"ml\"></div><h2 style=\"margin-top:30px\">🚫 黑名单</h2><button class=\"bv\" id=\"blBtn\">刷新黑名单</button><div id=\"bl\" style=\"margin-top:10px\"></div><h2 style=\"margin-top:30px\">💬 反馈记录</h2><button class=\"bv\" id=\"fbBtn\">加载反馈</button><div id=\"fl\" style=\"margin-top:10px\"></div></div><script>var K=\"\";function lm(t,c){var e=document.getElementById(\"lm\");if(e){e.textContent=t;e.style.color=c||\"#ff8ba0\";}}function esc(t){return String(t||\"\").replace(/&/g,\"&amp;\").replace(/</g,\"&lt;\").replace(/>/g,\"&gt;\");}function fmtT(t){var d=new Date(t);return d.getFullYear()+\"-\"+(d.getMonth()+1)+\"-\"+d.getDate()+\" \"+d.getHours()+\":\"+(\"0\"+d.getMinutes()).slice(-2);}function api(p){return fetch(p+(p.indexOf(\"?\")>=0?\"&\":\"?\")+\"key=\"+encodeURIComponent(K)).then(function(r){return r.text();}).then(function(t){try{return JSON.parse(t);}catch(e){return{ok:false,error:\"返回异常\"}}}).catch(function(e){return{ok:false,error:\"网络错误\"}});}async function doLogin(){lm(\"验证中…\",\"#9a9aa3\");K=document.getElementById(\"ki\").value.trim();if(!K){lm(\"请输入密码\");return;}var j=await api(\"/api/admin/users\");if(!j.ok){lm(j.error||\"密码错误\");return;}document.getElementById(\"kb\").style.display=\"none\";document.getElementById(\"mn\").classList.remove(\"hd\");showUsers(j.users);loadBlacklist();}function showUsers(us){var h=\"\";if(!us.length)h='<div class=\"card\">暂无用户</div>';for(var i=0;i<us.length;i++){var u=us[i];var tk=u.tokens?u.tokens.t.toLocaleString():\"0\";h+='<div class=\"card\"><div class=\"row\"><div><b>'+esc(u.username)+'</b> '+u.convs+'个对话<br><span class=\"sm\">'+esc(u.model||\"--\")+' | '+esc(u.ip||\"--\")+'</span><br><span class=\"sm\">最后活跃: '+(u.lastT?fmtT(u.lastT):\"--\")+'</span><br><span class=\"blue\">Tokens: '+tk+'</span></div><div><button class=\"bv\" data-u=\"'+esc(u.username)+'\" data-a=\"v\">查看</button> <button class=\"bd\" data-u=\"'+esc(u.username)+'\" data-a=\"d\">删除</button> <button class=\"bd\" data-u=\"'+esc(u.username)+'\" data-a=\"b\" data-ip=\"'+esc(u.ip||\"\")+'\" data-dev=\"'+esc(u.dev||\"\")+'\">拉黑</button></div></div></div>';}document.getElementById(\"ul\").innerHTML=h;var bs=document.getElementById(\"ul\").querySelectorAll(\"button[data-u]\");for(var i=0;i<bs.length;i++){bs[i].onclick=function(){var u=this.getAttribute(\"data-u\");var a=this.getAttribute(\"data-a\");if(a===\"v\")viewConvs(u);else if(a===\"b\")blockUser(u,this.getAttribute(\"data-ip\"),this.getAttribute(\"data-dev\"));else delUser(u);};}}async function viewConvs(u){var j=await api(\"/api/admin/user-convs?user=\"+encodeURIComponent(u));if(!j.ok){alert(\"失败\");return;}document.getElementById(\"ml\").innerHTML=\"\";var t=document.getElementById(\"ct\");t.classList.remove(\"hd\");t.textContent=u+\" 的对话\";var h=\"\";if(!j.convs.length)h='<div class=\"card\">无对话</div>';for(var i=0;i<j.convs.length;i++){var c=j.convs[i];var tags=(c.think?' <span class=\"tg\">🧠深度思考</span>':\"\")+(c.web?' <span class=\"tg2\">🌐联网</span>':\"\");h+='<div class=\"card\"><div class=\"row\"><div><b>'+esc(c.title)+'</b>'+tags+'<br><span class=\"sm\">'+(c.t?fmtT(c.t):\"--\")+'</span></div><button class=\"bv\" data-u=\"'+esc(u)+'\" data-c=\"'+c.id+'\">查看内容</button></div></div>';}var cl=document.getElementById(\"cl\");cl.innerHTML=h;var bs=cl.querySelectorAll(\"button[data-c]\");for(var k=0;k<bs.length;k++){bs[k].onclick=function(){viewMsgs(this.getAttribute(\"data-u\"),this.getAttribute(\"data-c\"));};}t.scrollIntoView();}async function viewMsgs(u,id){var j=await api(\"/api/admin/conv?user=\"+encodeURIComponent(u)+\"&id=\"+encodeURIComponent(id));if(!j.ok){alert(\"失败\");return;}var t=document.getElementById(\"mt\");t.classList.remove(\"hd\");t.textContent=\"对话内容\";var h=\"\";for(var i=0;i<j.messages.length;i++){var m=j.messages[i];var txt=Array.isArray(m.content)?m.content.map(function(p){return p.type===\"text\"?p.text:\"[图片]\";}).join(\"\"):String(m.content||\"\");h+='<div class=\"msg '+m.role+'\"><div class=\"rl\">'+(m.role===\"user\"?\"用户\":\"AI\")+(m.t?' <span>'+fmtT(m.t)+'</span>':\"\")+'</div>'+esc(txt).replace(/\\n/g,\"<br>\")+'</div>';}document.getElementById(\"ml\").innerHTML=h||'<div class=\"card\">空</div>';t.scrollIntoView();}async function delUser(u){if(!confirm(\"删除 \"+u+\" 及所有记录？不可恢复！\"))return;var r=await fetch(\"/api/admin/delete-user?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({user:u})});var j=await r.json();if(j.ok){doLogin();}else{alert(j.error||\"失败\");}}async function blockUser(u,ip,dev){if(!ip&&!dev){alert(\"该用户无IP/设备记录\");return;}if(!confirm(\"拉黑 \"+u+\"？\"))return;if(ip){await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({type:\"ip\",value:ip,username:u})});}if(dev){await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K),{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({type:\"device\",value:dev,username:u})});}alert(\"已拉黑\");loadBlacklist();}async function loadBlacklist(){var j=await api(\"/api/admin/blacklist\");if(!j.ok)return;var h=\"\";if(!j.list.length)h='<div class=\"card\">黑名单为空</div>';for(var i=0;i<j.list.length;i++){var b=j.list[i];h+='<div class=\"card\"><div class=\"row\"><div><b>'+(b.type===\"ip\"?\"IP\":\"设备\")+'</b> '+esc(b.value)+'<br><span class=\"sm\">'+esc(b.username||\"--\")+' | '+fmtT(b.t)+'</span></div><button class=\"bv\" data-t=\"'+b.type+'\" data-v=\"'+esc(b.value)+'\">解除</button></div></div>';}var el=document.getElementById(\"bl\");el.innerHTML=h;var bs=el.querySelectorAll(\"button[data-v]\");for(var k=0;k<bs.length;k++){bs[k].onclick=function(){unblock(this.getAttribute(\"data-t\"),this.getAttribute(\"data-v\"));};}}async function unblock(t,v){if(!confirm(\"解除拉黑 \"+v+\"？\"))return;var r=await fetch(\"/api/admin/blacklist?key=\"+encodeURIComponent(K)+\"&type=\"+t+\"&value=\"+encodeURIComponent(v),{method:\"DELETE\"});var j=await r.json();if(j.ok)loadBlacklist();else alert(\"失败\");}document.getElementById(\"goBtn\").onclick=doLogin;document.getElementById(\"rfBtn\").onclick=doLogin;document.getElementById(\"blBtn\").onclick=loadBlacklist;document.getElementById(\"ki\").addEventListener(\"keydown\",function(e){if(e.key===\"Enter\")doLogin();});function showFbFiles(i){\nvar fbs=window._fbs||[];var f=fbs[i];if(!f||!f.files||!f.files.length)return;\nvar el=document.getElementById(\"fbf\"+i);\nif(el.style.display!==\"none\"){el.style.display=\"none\";return;}\nvar h=\"\";\nfor(var k=0;k<f.files.length;k++){\nvar fl=f.files[k];\nvar url=\"/api/admin/feedback-file?key=\"+encodeURIComponent(K)+\"&k=\"+encodeURIComponent(fl.key);\nvar nm=esc(fl.name||\"附件\");\nif((fl.type||\"\").indexOf(\"image/\")===0){\nh+='<div style=\"margin-bottom:8px\"><img src=\"'+url+'\" style=\"max-width:100%;border-radius:8px\"><br><a href=\"'+url+'\" target=\"_blank\" class=\"blue\">'+nm+'</a></div>';\n}else if((fl.type||\"\").indexOf(\"video/\")===0){\nh+='<div style=\"margin-bottom:8px\"><video src=\"'+url+'\" controls style=\"max-width:100%;border-radius:8px\"></video><br><span class=\"sm\">'+nm+'</span></div>';\n}else{\nh+='<div><a href=\"'+url+'\" target=\"_blank\" class=\"blue\">附件: '+nm+'</a></div>';\n}\n}\nel.innerHTML=h;el.style.display=\"block\";\n}\ndocument.getElementById(\"fbBtn\").onclick=async function(){var j=await api(\"/api/admin/feedbacks?site=\"+encodeURIComponent(\"[DeepSeek站]\"));if(!j.ok){alert(\"失败\");return;}window._fbs=j.feedbacks;var h=\"\";if(!j.feedbacks.length)h='<div class=\"card\">暂无反馈</div>';for(var i=0;i<j.feedbacks.length;i++){var f=j.feedbacks[i];var txt=esc(f.text).replace(/\\n/g,\"<br>\");var short=txt.length>150;h+='<div class=\"card\"><div class=\"fb-txt'+(short?\" clamp\":\"\")+'\" id=\"fbt'+i+'\">'+txt+'</div>'+(short?'<a href=\"javascript:void(0)\" onclick=\"var e=document.getElementById(\\'fbt'+i+'\\');e.classList.toggle(\\'clamp\\');this.textContent=e.classList.contains(\\'clamp\\')?\\'展开全文\\':\\'收起\\'\" style=\"color:#4a9eff;font-size:12px\">展开全文</a>':\"\")+'<div class=\"sm\" style=\"margin-top:6px\">'+fmtT(f.t)+' | '+esc(f.ip||\"--\")+(f.contact?\" | \"+esc(f.contact):\"\")+(f.files&&f.files.length?\" | \"+f.files.length+\"个附件 <button class=\\\"bv\\\" style=\\\"padding:4px 10px;font-size:12px\\\" onclick=\\\"showFbFiles(\"+i+\")\\\">查看</button>\":\"\")+'</div><div id=\"fbf'+i+'\" style=\"display:none;margin-top:8px\"></div></div>';}document.getElementById(\"fl\").innerHTML=h;};</script></body></html>\n";
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
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
        let convCount = 0, lastT = 0;
        try {
          const raw = await kv.get('convs_' + uname);
          if (raw) { const l = JSON.parse(raw); if (Array.isArray(l)) { convCount = l.length; for (const c of l) if (c.t > lastT) lastT = c.t; } }
        } catch(e){}
        let regIp2='', lm='', tk=null, dev='';
        try { const ur=await kv.get(k.name); if(ur) { const uo=JSON.parse(ur); regIp2=uo.ip||''; dev=uo.dev||''; } } catch(e){}
        try { lm=await kv.get('umodel_'+uname)||''; } catch(e){}
        try { const tr=await kv.get('tokens_'+uname); if(tr) tk=JSON.parse(tr); } catch(e){}
        out.push({ username: uname, convs: convCount, ip: regIp2, model: lm, lastT: lastT, tokens: tk, dev: dev });
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
  const bl = await isBlacklisted(request, env);
  if (bl) return json({ ok: false, error: '账号已被限制访问' }, 403);
  const username = await getUserByToken(request, env);
  if (!username) return json({ ok: false, error: '请先登录' }, 401);

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
  const model = body.model === 'deepseek-v4-pro' ? 'deepseek-v4-pro' : 'deepseek-v4-flash';
  try { if (kv) await kv.put('umodel_' + username, model, { expirationTtl: 90*24*3600 }); } catch(e){}
  const messages = Array.isArray(body.messages) ? body.messages.slice(-30) : [];
  if (!messages.length || !messages.some(function(m){ return m.role === 'user'; }))
    return json({ ok: false, error: '消息为空' }, 400);
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

  try {
    const r = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({ model, messages: clean, stream: true, stream_options: { include_usage: true }, thinking: { type: 'enabled' } }),
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
                      let o = { p: 0, c: 0, t: 0 };
                      try { if (v) o = JSON.parse(v); } catch(e){}
                      o.p += pt; o.c += ct2; o.t += (pt + ct2);
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
async function isBlacklisted(request, env){
  const kv = env.FEEDBACK_KV;
  if (!kv) return null;
  const ip = request.headers.get('cf-connecting-ip') || '';
  const dev = getDeviceId(request);
  try {
    if (ip) {
      const b = await kv.get('blackip_' + ip);
      if (b) return { type: 'ip', value: ip };
    }
    if (dev) {
      const b = await kv.get('blackdev_' + dev);
      if (b) return { type: 'device', value: dev };
    }
  } catch(e){}
  return null;
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
    const type = body.type === 'device' ? 'device' : 'ip';
    const value = String(body.value || '').trim().slice(0,100);
    if (!value) return json({ ok: false, error: '参数错误' }, 400);
    const key = (type === 'ip' ? 'blackip_' : 'blackdev_') + value;
    await kv.put(key, JSON.stringify({ username: String(body.username||''), reason: String(body.reason||''), t: Date.now() }));
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    const url = new URL(request.url);
    const type = url.searchParams.get('type') === 'device' ? 'device' : 'ip';
    const value = (url.searchParams.get('value') || '').trim().slice(0,100);
    if (!value) return json({ ok: false, error: '参数错误' }, 400);
    await kv.delete((type === 'ip' ? 'blackip_' : 'blackdev_') + value);
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
    if (url.pathname === '/api/admin/feedbacks') return handleAdminFeedbacks(request, env);
    if (url.pathname === '/api/admin/blacklist') return handleAdminBlacklist(request, env);
    if (url.pathname === '/api/admin/feedback-file') return handleAdminFeedbackFile(request, env);
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
