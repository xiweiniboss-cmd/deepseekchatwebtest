// 反馈系统 / 后台登录加固测试：node --test tests/
// _worker.js 是 Pages 高级模式入口，这里复制成 .mjs 再导入（仓库根目录不放 package.json，避免影响 Pages 构建）
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dsk-')), 'worker.mjs');
fs.copyFileSync(path.join(here, '..', '_worker.js'), tmp);
const worker = (await import(pathToFileURL(tmp).href)).default;

const KEY = 'test-admin-key-not-real';
const SELF = 'https://deepseekchatkele.pages.dev';

function memKV(init = {}) {
  const m = new Map(Object.entries(init));
  const log = [];
  return {
    m, log, failPut: null,
    async get(k) { log.push(['get', k]); return m.has(k) ? m.get(k) : null; },
    async put(k, v, o) { log.push(['put', k, o]); if (this.failPut && this.failPut(k)) throw new Error('kv put fail'); m.set(k, String(v)); },
    async delete(k) { log.push(['delete', k]); m.delete(k); },
    async list({ prefix = '' } = {}) { log.push(['list', prefix]); return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).sort().map((name) => ({ name })), list_complete: true }; },
  };
}
function memR2(init = {}) {
  const m = new Map(Object.entries(init));
  return {
    m, puts: [], deleted: [], failPutAt: -1,
    async put(k, v, o) { if (this.puts.length === this.failPutAt) { this.puts.push(k); throw new Error('r2 fail'); } this.puts.push(k); m.set(k, { data: new Uint8Array(v), type: o && o.httpMetadata && o.httpMetadata.contentType }); },
    async get(k) { const o = m.get(k); return o ? { body: o.data, size: o.data.length, httpMetadata: { contentType: o.type } } : null; },
    async delete(k) { this.deleted.push(k); m.delete(k); },
  };
}
function makeEnv(extra = {}) {
  return {
    FEEDBACK_ADMIN_KEY: KEY,
    FEEDBACK_KV: memKV({
      tp0k_write_ok: '1',
      fb_1731000000000abc: JSON.stringify({ id: 'fb_1731000000000abc', site: '[DeepSeek站]', text: 'hi', files: [{ key: 'fb/1_a.svg', name: 'a.svg', type: 'image/svg+xml' }], t: 1731000000000 }),
      sess_secret: 'SESSION', conv_1: 'CHAT',
    }),
    FEEDBACK_BUCKET: memR2({
      'fb/1_a.svg': { data: new TextEncoder().encode('<svg onload=alert(1)>'), type: 'image/svg+xml' },
      'fb/2_b.png': { data: new Uint8Array([1, 2, 3]), type: 'image/png' },
      'other/secret.txt': { data: new Uint8Array([1]), type: 'text/plain' },
    }),
    ASSETS: { fetch: async () => new Response('asset', { status: 200 }) },
    ...extra,
  };
}
async function call(env, p, { method = 'GET', headers = {}, body, cookie, ip = '203.0.113.9' } = {}) {
  const h = new Headers({ 'cf-connecting-ip': ip, ...headers });
  if (cookie) h.set('cookie', cookie);
  let b = body;
  if (body !== undefined && !(body instanceof FormData) && typeof body !== 'string') { b = JSON.stringify(body); if (!h.has('content-type')) h.set('content-type', 'application/json'); }
  const req = new Request(SELF + p, { method, headers: h, body: b });
  return worker.fetch(req, env, { waitUntil() {} });
}
async function login(env) {
  const r = await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { origin: SELF } });
  assert.equal(r.status, 200);
  return r.headers.get('set-cookie').split(';')[0];
}

/* ---------- 登录 ---------- */
test('登录：JSON + 同源，下发 HttpOnly Secure SameSite=Strict 12 小时 Cookie', async () => {
  const env = makeEnv();
  assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: 'key=' + KEY, headers: { 'content-type': 'application/x-www-form-urlencoded' } })).status, 415);
  assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { origin: 'https://evil.example' } })).status, 403);
  assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  const r = await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { origin: SELF, 'sec-fetch-site': 'same-origin' } });
  assert.equal(r.status, 200);
  const sc = r.headers.get('set-cookie');
  for (const f of ['dsk_admin=', 'HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=43200', 'Path=/']) assert.ok(sc.includes(f), f);
  assert.ok(!sc.includes(KEY));
});

test('登录：同一 IP（IPv6 /64）错 10 次锁定，计数键带本站域名', async () => {
  const env = makeEnv();
  for (let i = 0; i < 10; i++) assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: { key: 'x' }, headers: { origin: SELF }, ip: '2001:db8:5:6::' + (i + 1) })).status, 403);
  assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { origin: SELF }, ip: '2001:db8:5:6::99' })).status, 429);
  assert.ok(env.FEEDBACK_KV.m.has('admfail_deepseekchatkele.pages.dev_2001:db8:5:6::/64'));
  assert.equal((await call(env, '/api/admin/login', { method: 'POST', body: { key: KEY }, headers: { origin: SELF }, ip: '198.51.100.1' })).status, 200);
});

test('后台接口：?key= 不再有效，只认 Cookie；写操作要求同源', async () => {
  const env = makeEnv();
  assert.equal((await call(env, '/api/admin/feedbacks?key=' + KEY)).status, 403);
  assert.equal((await call(env, '/api/admin/users?key=' + KEY)).status, 403);
  const cookie = await login(env);
  const r = await call(env, '/api/admin/feedbacks', { cookie });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).feedbacks.length, 1);
  assert.equal((await call(env, '/api/admin/feedbacks', { method: 'DELETE', cookie, body: { ids: ['fb_1731000000000abc'] }, headers: { origin: 'https://evil.example' } })).status, 403);
  assert.ok(env.FEEDBACK_KV.m.has('fb_1731000000000abc'));
  const d = await call(env, '/api/admin/feedbacks', { method: 'DELETE', cookie, body: { ids: ['fb_1731000000000abc', 'sess_secret'] }, headers: { origin: SELF } });
  assert.equal((await d.json()).deleted, 1);
  assert.ok(!env.FEEDBACK_KV.m.has('fb_1731000000000abc'));
  assert.ok(env.FEEDBACK_KV.m.has('sess_secret'), '非反馈键不能被删');
  assert.deepEqual(env.FEEDBACK_BUCKET.deleted, ['fb/1_a.svg']);
  // 伪造 / 过期 Cookie
  const exp = Math.floor(Date.now() / 1000) + 100;
  assert.equal((await call(env, '/api/admin/feedbacks', { cookie: 'dsk_admin=' + exp + '.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })).status, 403);
  assert.equal((await call(env, '/api/admin/feedbacks', { cookie: 'dsk_admin=' + (exp - 1000) + '.' + cookie.split('.')[1] })).status, 403);
});

test('小游戏后台（tp0k/zhijia/brake）跨站 ?key= 保持可用', async () => {
  const env = makeEnv();
  const r = await call(env, '/api/admin/zhijia/board?key=' + KEY, { headers: { origin: 'https://game.example' } });
  const j = await r.json().catch(() => ({}));
  assert.notEqual(j.error, '无权');
  const bad = await call(env, '/api/admin/zhijia/board?key=wrong', { headers: { origin: 'https://game.example' } });
  assert.equal((await bad.json()).error, '无权');
});

test('/admin：旧书签 ?key= 换 Cookie 并跳转去掉密码；跨站带来的不校验；页面不再拼 ?key=', async () => {
  const env = makeEnv();
  const ok = await call(env, '/admin?key=' + encodeURIComponent(KEY), { headers: { 'sec-fetch-site': 'none' } });
  assert.equal(ok.status, 302);
  assert.equal(ok.headers.get('location'), '/admin');
  assert.match(ok.headers.get('set-cookie'), /^dsk_admin=/);
  const cross = await call(env, '/admin?key=' + encodeURIComponent(KEY), { headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(cross.headers.get('location'), '/admin?err=cross');
  assert.equal(cross.headers.get('set-cookie'), null);
  const wrong = await call(env, '/admin?key=nope');
  assert.equal(wrong.headers.get('location'), '/admin?err=wrong');
  const page = await call(env, '/admin');
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(page.headers.get('cache-control'), 'no-store');
  const html = await page.text();
  assert.ok(!/encodeURIComponent\(K\)/.test(html));
  assert.ok(!/key=" *\+/.test(html));
  assert.ok(html.includes('/api/admin/login'));
});

test('退出登录清除 Cookie', async () => {
  const env = makeEnv();
  const r = await call(env, '/api/admin/logout', { method: 'POST', headers: { origin: SELF } });
  assert.match(r.headers.get('set-cookie'), /dsk_admin=; .*Max-Age=0/);
});

/* ---------- 附件 ---------- */
test('附件：白名单类型内联，SVG 强制下载；nosniff + sandbox + 私有缓存；只允许 fb/', async () => {
  const env = makeEnv();
  const cookie = await login(env);
  const png = await call(env, '/api/admin/feedback-file?k=' + encodeURIComponent('fb/2_b.png'), { cookie });
  assert.equal(png.headers.get('content-type'), 'image/png');
  assert.equal(png.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(png.headers.get('content-security-policy'), "default-src 'none'; sandbox");
  assert.equal(png.headers.get('cache-control'), 'private, max-age=3600');
  const svg = await call(env, '/api/admin/feedback-file?k=' + encodeURIComponent('fb/1_a.svg'), { cookie });
  assert.equal(svg.headers.get('content-type'), 'application/octet-stream');
  assert.match(svg.headers.get('content-disposition'), /^attachment/);
  assert.equal((await call(env, '/api/admin/feedback-file?k=' + encodeURIComponent('other/secret.txt'), { cookie })).status, 400);
  assert.equal((await call(env, '/api/admin/feedback-file?k=' + encodeURIComponent('fb/../other/secret.txt'), { cookie })).status, 400);
  assert.equal((await call(env, '/api/admin/feedback-file?key=' + KEY + '&k=fb/2_b.png')).status, 403);
  // 旧接口 /api/fb-file/
  assert.equal((await call(env, '/api/fb-file/fb/1_a.svg?key=' + KEY)).status, 403);
  const old = await call(env, '/api/fb-file/fb/1_a.svg', { cookie });
  assert.equal(old.headers.get('content-type'), 'application/octet-stream');
  assert.equal(old.headers.get('content-security-policy'), "default-src 'none'; sandbox");
  assert.equal(old.headers.get('cache-control'), 'private, max-age=3600');
  // 旧列表 / 删除接口
  assert.equal((await call(env, '/api/feedback?key=' + KEY)).status, 403);
  assert.equal((await call(env, '/api/feedback', { cookie })).status, 200);
  assert.equal((await call(env, '/api/feedback?id=fb_1731000000000abc', { method: 'DELETE', cookie, headers: { origin: 'https://evil.example' } })).status, 403);
});

/* ---------- 提交 ---------- */
const ZJ = 'https://zhijia-game.example';
test('智驾 / 刹车跨站提交仍然可用（未核实域名时默认放行游戏标签），回显 Origin 不用 *，并记录来源', async () => {
  const env = makeEnv();
  const pre = await call(env, '/api/feedback', { method: 'OPTIONS', headers: { origin: ZJ, 'access-control-request-method': 'POST' } });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), ZJ);
  const r = await call(env, '/api/feedback', { method: 'POST', body: { site: '[智驾站]', text: '【其他】测试' }, headers: { origin: ZJ } });
  assert.equal(r.status, 200, await r.clone().text());
  assert.equal(r.headers.get('access-control-allow-origin'), ZJ);
  const rec = [...env.FEEDBACK_KV.m.entries()].filter(([k]) => k.startsWith('fb_')).map(([, v]) => JSON.parse(v)).find((x) => x.site === '[智驾站]');
  assert.equal(rec.origin, ZJ);
  assert.equal(rec.text, '【其他】测试');
  const b = await call(env, '/api/feedback', { method: 'POST', body: { site: '[刹车站]', text: 'brake' }, headers: { origin: 'https://brake.example' }, ip: '198.51.100.7' });
  assert.equal(b.status, 200);
});

test('DeepSeek 站反馈只能来自本站页面；强制模式下未知来源被拒绝', async () => {
  const env = makeEnv();
  const r = await call(env, '/api/feedback', { method: 'POST', body: { text: 'x' }, headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://evil.example'); // 允许读到错误信息，但没写入
  assert.ok(![...env.FEEDBACK_KV.m.keys()].some((k) => k.startsWith('fb_') && k !== 'fb_1731000000000abc'));
  const env2 = makeEnv({ FEEDBACK_CORS_ENFORCE: '1', FEEDBACK_ALLOWED_ORIGINS: 'https://zhijia-ok.example' });
  const pre = await call(env2, '/api/feedback', { method: 'OPTIONS', headers: { origin: ZJ } });
  assert.equal(pre.status, 403);
  assert.equal(pre.headers.get('access-control-allow-origin'), null);
  const p2 = await call(env2, '/api/feedback', { method: 'POST', body: { site: '[智驾站]', text: 'x' }, headers: { origin: ZJ } });
  assert.equal(p2.status, 403);
  const ok = await call(env2, '/api/feedback', { method: 'POST', body: { site: '[智驾站]', text: 'x' }, headers: { origin: 'https://zhijia-ok.example' } });
  assert.equal(ok.status, 200);
  const prev = await call(env2, '/api/feedback', { method: 'OPTIONS', headers: { origin: 'https://abc123.deepseekchatkele.pages.dev' } });
  assert.equal(prev.headers.get('access-control-allow-origin'), 'https://abc123.deepseekchatkele.pages.dev');
  const same = await call(env2, '/api/feedback', { method: 'POST', body: { text: '本站' }, headers: { origin: SELF }, ip: '198.51.100.8' });
  assert.equal(same.status, 200);
});

test('提交：问题类型 / 链接单独存；来源页面只收 http/https', async () => {
  const env = makeEnv();
  await call(env, '/api/feedback', { method: 'POST', body: { text: 't', kind: '建议', link: 'https://x.example/1', page: 'javascript:alert(1)' }, headers: { origin: SELF } });
  await call(env, '/api/feedback', { method: 'POST', body: { text: 't2', kind: '<b>乱填</b>', page: 'https://deepseekchatkele.pages.dev/' }, headers: { origin: SELF }, ip: '198.51.100.20' });
  const recs = [...env.FEEDBACK_KV.m.entries()].filter(([k]) => k.startsWith('fb_') && k !== 'fb_1731000000000abc').map(([, v]) => JSON.parse(v));
  const a = recs.find((x) => x.text === 't'), b = recs.find((x) => x.text === 't2');
  assert.equal(a.kind, '建议'); assert.equal(a.link, 'https://x.example/1'); assert.equal(a.page, undefined);
  assert.equal(b.kind, undefined); assert.equal(b.page, 'https://deepseekchatkele.pages.dev/');
});

function fd(files, extra = {}) {
  const f = new FormData();
  f.append('text', '带附件'); for (const [k, v] of Object.entries(extra)) f.append(k, v);
  for (const [name, type, size] of files) f.append('files', new File([new Uint8Array(size)], name, { type }));
  return f;
}
test('附件上传前校验：类型白名单、单个 20MB、最多 3 个；不合格时一个都不上传', async () => {
  const env = makeEnv();
  let r = await call(env, '/api/feedback', { method: 'POST', body: fd([['a.png', 'image/png', 10], ['x.svg', 'image/svg+xml', 10]]), headers: { origin: SELF } });
  assert.equal(r.status, 400);
  r = await call(env, '/api/feedback', { method: 'POST', body: fd([['x.html', 'text/html', 10]]), headers: { origin: SELF } });
  assert.equal(r.status, 400);
  r = await call(env, '/api/feedback', { method: 'POST', body: fd([['big.mp4', 'video/mp4', 20 * 1024 * 1024 + 1]]), headers: { origin: SELF } });
  assert.equal(r.status, 400);
  r = await call(env, '/api/feedback', { method: 'POST', body: fd([['1.png', 'image/png', 1], ['2.png', 'image/png', 1], ['3.png', 'image/png', 1], ['4.png', 'image/png', 1]]), headers: { origin: SELF } });
  assert.equal(r.status, 400);
  assert.equal(env.FEEDBACK_BUCKET.puts.length, 0);
  // 没有类型的 HEIC 按扩展名识别
  r = await call(env, '/api/feedback', { method: 'POST', body: fd([['IMG_1.HEIC', '', 5], ['v.mp4', 'video/mp4', 5]]), headers: { origin: SELF } });
  assert.equal(r.status, 200);
  const types = [...env.FEEDBACK_BUCKET.m.entries()].filter(([k]) => /^fb\/\d/.test(k) && !k.startsWith('fb/1_') && !k.startsWith('fb/2_')).map(([, v]) => v.type).sort();
  assert.deepEqual(types, ['image/heic', 'video/mp4']);
});

test('上传 / 写入失败时回滚：删掉已上传附件，不留记录，不设冷却', async () => {
  const env = makeEnv();
  env.FEEDBACK_BUCKET.failPutAt = 1;
  let r = await call(env, '/api/feedback', { method: 'POST', body: fd([['1.png', 'image/png', 3], ['2.png', 'image/png', 3]]), headers: { origin: SELF } });
  assert.equal(r.status, 500);
  assert.equal(env.FEEDBACK_BUCKET.deleted.length, 1);
  assert.ok(!env.FEEDBACK_KV.m.has('cool_203.0.113.9'));
  const env2 = makeEnv();
  env2.FEEDBACK_KV.failPut = (k) => k.startsWith('fb_');
  r = await call(env2, '/api/feedback', { method: 'POST', body: fd([['1.png', 'image/png', 3]]), headers: { origin: SELF } });
  assert.equal(r.status, 500);
  assert.equal(env2.FEEDBACK_BUCKET.deleted.length, 1);
  assert.equal([...env2.FEEDBACK_BUCKET.m.keys()].filter((k) => /^fb\/\d{13}_/.test(k)).length, 0);
});

test('冷却：成功提交后 10 分钟内同一 IP 不能再提交', async () => {
  const env = makeEnv();
  assert.equal((await call(env, '/api/feedback', { method: 'POST', body: { text: 'a' }, headers: { origin: SELF } })).status, 200);
  assert.equal((await call(env, '/api/feedback', { method: 'POST', body: { text: 'b' }, headers: { origin: SELF } })).status, 429);
});

test('整个流程不碰账号 / 会话 / 聊天键', async () => {
  const env = makeEnv();
  const cookie = await login(env);
  await call(env, '/api/admin/feedbacks', { cookie });
  await call(env, '/api/feedback', { method: 'POST', body: { site: '[智驾站]', text: 'x' }, headers: { origin: ZJ } });
  const touched = env.FEEDBACK_KV.log.map((x) => x[1]).filter((k) => /^(sess_|conv_)/.test(k));
  assert.deepEqual(touched, []);
});
