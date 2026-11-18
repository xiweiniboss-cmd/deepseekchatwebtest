// 智驾成绩合理性校验 / 记录白名单 / 后台 X-Admin-Key 测试：node --test tests/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zjg-')), 'worker.mjs');
fs.copyFileSync(path.join(here, '..', '_worker.js'), tmp);
const worker = (await import(pathToFileURL(tmp).href)).default;

const KEY = 'test-admin-key-not-real';
const SELF = 'https://deepseekchatkele.pages.dev';
const ZJ = 'https://zhijiamoniqi.pages.dev';

function memKV() {
  const m = new Map();
  return {
    m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, String(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) { return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }; },
  };
}
// 极简 D1：记录写入的 SQL 和参数，够区分「写入了 / 被拒了」
function memDB() {
  const writes = [];
  return {
    writes,
    prepare(sql) {
      let args = [];
      const st = {
        bind(...a) { args = a; return st; },
        async run() { if (/^\s*(INSERT|DELETE)/i.test(sql)) writes.push({ sql, args }); return { meta: { changes: 1 } }; },
        async first() { return null; },
        async all() { return { results: [] }; },
      };
      return st;
    },
  };
}
function makeEnv() {
  return { FEEDBACK_ADMIN_KEY: KEY, FEEDBACK_KV: memKV(), DB: memDB(), ASSETS: { fetch: async () => new Response('asset') } };
}
let ipN = 0;
async function call(env, p, { method = 'GET', headers = {}, body, ip } = {}) {
  const h = new Headers({ 'cf-connecting-ip': ip || ('198.51.100.' + (++ipN % 250)), ...headers });
  let b = body;
  if (body !== undefined && typeof body !== 'string') { b = JSON.stringify(body); h.set('content-type', 'application/json'); }
  return worker.fetch(new Request(SELF + p, { method, headers: h, body: b }), env, { waitUntil() {} });
}
const s1 = (o) => Object.assign({ nickname: '测试', device: 'dev1', brakeTime: 2.4, margin: 174, reaction: 0.016 }, o);
const s2 = (o) => Object.assign({ nickname: '测试', device: 'dev2', escapeTime: 0.8, reaction: null }, o);

test('第一阶段：真实榜单上的合法成绩照常收（含按住刹车等失控的一帧反应）', async () => {
  const env = makeEnv();
  for (const o of [{}, { brakeTime: 2.1804, margin: 175.98, reaction: 0.0042 }, { brakeTime: 3.0031, margin: 163.87, reaction: 0.2931 }, { brakeTime: 29, margin: 100, reaction: 0.3 }, { reaction: 0.05 }, { reaction: 0.1 }]) {
    const r = await call(env, '/api/zhijia/score', { method: 'POST', body: s1(o) });
    assert.equal(r.status, 200, JSON.stringify(o));
    const j = await r.json();
    assert.equal(typeof j.score, 'number');
    assert.equal(typeof j.best, 'number');
  }
  const j = await (await call(env, '/api/zhijia/score', { method: 'POST', body: s1({ brakeTime: 2.5 }) })).json();
  assert.equal(j.score, 40000 + 1612);
});

test('第一阶段：不可能的数字一律 400', async () => {
  const env = makeEnv();
  const bad = [
    { brakeTime: 1.99 }, { brakeTime: 0.01 }, { brakeTime: 0 }, { brakeTime: -3 }, { brakeTime: 30.5 }, { brakeTime: '2.5' }, { brakeTime: null },
    { margin: -1 }, { margin: 185.1 }, { margin: 260 }, { margin: '100' },
    { reaction: null }, { reaction: 0 }, { reaction: -1 }, { reaction: 0.06 }, { reaction: 0.099 }, { reaction: 3 /* 晚于刹停 2.4 s */ }, { reaction: 'x' },
  ];
  for (const o of bad) {
    const r = await call(env, '/api/zhijia/score', { method: 'POST', body: s1(o) });
    assert.equal(r.status, 400, JSON.stringify(o));
    assert.deepEqual(await r.json(), { error: '数据异常' });
  }
  // NaN / Infinity 经 JSON 会变成 null；手写的 1e999 解析成 Infinity
  for (const raw of ['{"brakeTime":1e999,"margin":100,"reaction":0.3}', '{"brakeTime":2.5,"margin":1e999,"reaction":0.3}', '{"brakeTime":2.5,"margin":100,"reaction":1e999}']) {
    assert.equal((await call(env, '/api/zhijia/score', { method: 'POST', body: raw, headers: { 'content-type': 'application/json' } })).status, 400, raw);
  }
  assert.equal(env.DB.writes.length, 0);
});

test('第二阶段：escapeTime 0.3~3 秒，reaction 可为 null', async () => {
  const env = makeEnv();
  for (const o of [{}, { escapeTime: 0.3 }, { escapeTime: 2.999 }, { escapeTime: 0.792, reaction: 5.445 }, { reaction: 0.01 }]) {
    assert.equal((await call(env, '/api/zhijia/score2', { method: 'POST', body: s2(o) })).status, 200, JSON.stringify(o));
  }
  const j = await (await call(env, '/api/zhijia/score2', { method: 'POST', body: s2({ escapeTime: 0.3 }) })).json();
  assert.equal(j.score, 270000);
  for (const o of [{ escapeTime: 0.1 }, { escapeTime: 0.299 }, { escapeTime: 0 }, { escapeTime: 3.01 }, { escapeTime: '1' }, { escapeTime: null }, { reaction: 0.07 }, { reaction: -5 }, { reaction: 31 }, { reaction: 'a' }]) {
    assert.equal((await call(env, '/api/zhijia/score2', { method: 'POST', body: s2(o) })).status, 400, JSON.stringify(o));
  }
});

test('记录：result / mode 只收前端会发的值，昵称去掉 HTML 字符，数值夹紧', async () => {
  const env = makeEnv();
  const base = { nickname: 'ok', device: 'd1', mode: 'hard', result: 'win', brakeTime: 2.4, reaction: 0.3, maxForce: 1500, maxSpeed: 66, margin: 170, escapeTime: 0 };
  for (const result of ['win', 'snap', 'burned', 'news', 'survive']) {
    assert.equal((await call(env, '/api/zhijia/record', { method: 'POST', body: { ...base, result } })).status, 200, result);
  }
  for (const o of [{ result: '<img src=x onerror=alert(1)>' }, { result: 'WIN' }, { result: undefined }, { mode: 'god' }, { mode: undefined }]) {
    assert.equal((await call(env, '/api/zhijia/record', { method: 'POST', body: { ...base, ...o } })).status, 400, JSON.stringify(o));
  }
  const n0 = env.DB.writes.length;
  await call(env, '/api/zhijia/record', { method: 'POST', body: { ...base, nickname: '<b>x</b>"\'`&', device: 'a<b>', maxForce: 1e6, maxSpeed: 'fast', margin: Infinity, brakeTime: -1, reaction: 'x' } });
  const args = env.DB.writes[n0].args; // rkey, n, d, mode, result, t, r, f, v, m, ts, ip, et
  assert.equal(args[1], 'bx/b');
  assert.equal(args[2], 'ab');
  assert.deepEqual([args[5], args[6], args[7], args[8], args[9]], [0, -1, 0, 0, 0]);
});

test('智驾后台：X-Admin-Key 请求头可用（跨站预检放行该头），?key= 仍兼容，输错同样计入锁定', async () => {
  const env = makeEnv();
  const pre = await call(env, '/api/admin/zhijia/board', { method: 'OPTIONS', headers: { origin: ZJ, 'access-control-request-method': 'GET', 'access-control-request-headers': 'x-admin-key' } });
  assert.equal(pre.status, 204);
  assert.match(pre.headers.get('access-control-allow-headers'), /X-Admin-Key/i);
  const ok = await call(env, '/api/admin/zhijia/board', { headers: { origin: ZJ, 'X-Admin-Key': KEY } });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).ok, true);
  assert.equal(ok.headers.get('access-control-allow-origin'), ZJ);
  const q = await call(env, '/api/admin/zhijia/board?key=' + KEY, { headers: { origin: ZJ } });
  assert.equal(q.status, 200);
  const bad = await call(env, '/api/admin/zhijia/board', { headers: { origin: ZJ, 'X-Admin-Key': 'wrong' }, ip: '203.0.113.77' });
  assert.equal(bad.status, 403);
  assert.ok([...env.FEEDBACK_KV.m.keys()].some((k) => k.startsWith('admfail_')));
  // 请求头优先：头错、地址栏对 → 拒绝
  assert.equal((await call(env, '/api/admin/zhijia/board?key=' + KEY, { headers: { origin: ZJ, 'X-Admin-Key': 'wrong' } })).status, 403);
  // 没有任何密钥 → 拒绝
  assert.equal((await call(env, '/api/admin/zhijia/board', { headers: { origin: ZJ } })).status, 403);
});
