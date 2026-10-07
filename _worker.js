// DeepSeek 网页聊天 - Worker 代理（API Key 放服务端环境变量，不暴露给前端）
function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function handleChat(request, env) {
  const apiKey = (env.DEEPSEEK_API_KEY || '').trim();
  if (!apiKey) return json({ ok: false, error: '未配置 DeepSeek API Key：请在 Cloudflare Pages → Settings → Environment variables 添加 DEEPSEEK_API_KEY（重新部署后生效）' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  const model = body.model === 'deepseek-reasoner' ? 'deepseek-reasoner' : 'deepseek-chat';
  const messages = Array.isArray(body.messages) ? body.messages.slice(-30) : [];
  if (!messages.length || !messages.some(function(m){ return m.role === 'user'; }))
    return json({ ok: false, error: '消息为空' }, 400);
  // 只保留 role/content，防止注入奇怪字段
  const clean = messages.map(function(m){
    return { role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content || '').slice(0, 20000) };
  });

  try {
    const r = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + apiKey,
      },
      body: JSON.stringify({ model, messages: clean, stream: true, temperature: 0.7 }),
    });
    if (!r.ok || !r.body) {
      const t = await r.text().catch(function(){ return ''; });
      let msg = 'DeepSeek 接口错误(' + r.status + ')';
      try {
        const j = JSON.parse(t);
        if (j.error && j.error.message) msg = j.error.message;
      } catch {}
      if (r.status === 401) msg = 'API Key 无效，请检查 DEEPSEEK_API_KEY';
      if (r.status === 402) msg = 'DeepSeek 账户余额不足，请去 platform.deepseek.com 充值';
      if (r.status === 429) msg = '请求太频繁，请稍后再试';
      return json({ ok: false, error: msg }, r.status);
    }
    // 流式透传 SSE
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/chat' && request.method === 'POST') return handleChat(request, env);
    return env.ASSETS.fetch(request);
  },
};
