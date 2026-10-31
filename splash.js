/*!
 * splash.js — 启动动画（纯叠加层，自包含）
 * - 只在页面加载时盖一层 #ds-splash，播完后整个节点和样式一起移除，主界面 DOM/CSS 一点不改。
 * - 所有样式都以 #ds-splash 为前缀，keyframes 以 ds-sp- 为前缀，不会泄漏到主界面。
 * - 任何 JS 异常 → 立即移除自身；自动播放段各有硬性超时（MAX_TOTAL_MS）兜底，等待确认时最多 CONFIRM_WAIT_MS 后自动继续，永远不会挡住主界面。
 * - 第 1 步「需要访问许可」会暂停，等用户点「授权访问 AUTHORIZE」或按 Enter（这次点击同时解锁声音）；之后每一步自动推进并配语音；SKIP / Esc 任何时候都可直接跳过。
 * - 确认后播放英文系统语音：预渲染 /splash/voice/*.mp3（edge-tts en-US-JennyNeural + ffmpeg 处理），失败才用 speechSynthesis。
 * - 引入方式：index.html 的 <head> 里一行 <script src="/splash.js"></script>
 */
(function () {
  'use strict';

  /* ================= 可调参数（每项改一行即可） ================= */
  var WELCOME_NAME   = '博士';            // 欢迎语里的称呼：「欢迎 博士 访问」
  var PLAY_MODE      = 'daily';           // 'daily' 每天一次 | 'always' 每次都播 | 'off' 关闭
  var STORAGE_KEY    = 'ds_splash_day';   // localStorage 键，值为当天日期 YYYY-MM-DD
  var BRAND          = 'DEEPSEEK';
  var BRAND_SUB      = 'SYNTHESIZE INTELLIGENCE';
  var OS_NAME        = 'CHAT OS';         // 左上角第三行：「CHAT OS」
  var LOGO_TAGLINE   = 'DEEPSEEK · CHAT OS';
  var REV            = 'REV 0.1.0';
  var STEP_MS        = 1800;              // 每一步停留时长
  var LOGO_MS        = 3400;              // 开头黑屏 logo 段时长
  var WELCOME_MS     = 2400;              // 最后欢迎页停留时长
  var EXIT_MS        = 750;               // 退场动画时长
  var MAX_TOTAL_MS   = 17000;             // 硬性上限：确认前的自动段（logo + 第 1 步）不超过这个时长
  var POST_CLICK_MAX_MS = 25000;          // 硬性上限：点确认之后的自动段（6 句语音 + 每步最多多等 1.2s 也够用）
  var CONFIRM_ENABLED = true;             // 第 1 步「需要访问许可」是否暂停等用户点「授权访问 AUTHORIZE」
  var CONFIRM_WAIT_MS = 30000;            // 等待确认的安全上限：超时自动继续（不出声）
  /* 声音：浏览器禁止无用户手势自动出声，所以只在用户点「确认身份」（或按 Enter）之后才播放。
   * 优先播放预渲染语音（VOICE_BASE 下的 mp3，在等待确认时预加载，用 WebAudio 播放）；
   * 语音文件加载失败时才退回 speechSynthesis（en-US 女声，rate 1）；都不可用则静默。 */
  var VOICE_ENABLED  = true;
  var VOICE_BASE     = '/splash/voice/';
  var VOICE_FILES    = { 'Access permission required.': 'access-required.mp3', 'ID confirmed.': 'id-confirmed.mp3', 'Request received.': 'request-received.mp3',
                         'Start processing.': 'start-processing.mp3', 'Permission authorized.': 'permission-authorized.mp3',
                         'Welcome to DeepSeek Chat.': 'welcome.mp3' };
  var VOICE_GAP_MS   = 250;               // 两句之间至少留的间隔；上一句没说完，下一步会稍等，画面不会跑在声音前面
  var VOICE_WAIT_MAX = 1200;              // 每一步最多因声音多等这么久
  var VOICE_LOAD_WAIT_MS = 800;           // 点确认时若语音还没加载完，最多等这么久
  var VOICE_RATE     = 1;                 // 仅 speechSynthesis 兜底时使用
  /* =========================================================== */

  var root = null, styleEl = null, timers = [], done = false, exiting = false, voiceArmed = false;
  var capTimer = null, waiting = false, confirmed = false;
  var actx = null, clips = {}, clipsState = 'idle', clipsCb = [], sources = [], voiceFree = 0, voiceLate = 0; // voiceFree: 当前语音预计结束时刻(performance.now)

  function hardRemove() {
    done = true;
    for (var i = 0; i < timers.length; i++) clearTimeout(timers[i]);
    timers = [];
    try { clearTimeout(capTimer); } catch (e) {}
    try { document.removeEventListener('keydown', onKey, true); } catch (e) {}
    try { if (window.speechSynthesis) window.speechSynthesis.cancel(); } catch (e) {}
    stopAudio();
    try { if (root && root.hidePopover && root.matches(':popover-open')) root.hidePopover(); } catch (e) {}
    try { if (root && root.parentNode) root.parentNode.removeChild(root); } catch (e) {}
    try { if (styleEl && styleEl.parentNode) styleEl.parentNode.removeChild(styleEl); } catch (e) {}
    root = null; styleEl = null;
  }
  // 所有回调都包一层：出错就立刻移除自身
  function safe(fn) {
    return function () { if (done) return; try { return fn.apply(this, arguments); } catch (e) { hardRemove(); } };
  }
  function later(fn, ms) { timers.push(setTimeout(safe(fn), ms)); }

  function today() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function shouldPlay() {
    var q = '';
    try { q = (location.search.match(/[?&]splash=([^&]*)/) || [])[1] || ''; } catch (e) {}
    if (q === '1') return true;    // ?splash=1 强制播放（预览用）
    if (q === '0') return false;   // ?splash=0 强制不播
    if (PLAY_MODE === 'off') return false;
    if (PLAY_MODE === 'always') return true;
    try {
      if (localStorage.getItem(STORAGE_KEY) === today()) return false;
      localStorage.setItem(STORAGE_KEY, today());
    } catch (e) {}
    return true;
  }
  function reducedMotion() {
    try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // 官方 DeepSeek 鲸鱼标志：取自 https://www.deepseek.com/ 首页页眉 logo（<svg viewBox="0 0 143 23"> 中的鲸鱼 path，形状原样未改，仅用 currentColor 着色）
  var WHALE = '<svg class="ds-sp-whale" viewBox="0 1.5 27 20.1" aria-hidden="true"><path fill="currentColor" d="M26.5174 3.39471C26.235 3.2567 26.1137 3.52006 25.9487 3.65346C25.8923 3.69659 25.8446 3.75294 25.7969 3.80469C25.3846 4.24516 24.9027 4.53439 24.2737 4.49989C23.3536 4.44814 22.5682 4.73737 21.8735 5.44119C21.7258 4.57349 21.2353 4.0554 20.4889 3.72304C20.0985 3.55054 19.7034 3.37746 19.4297 3.00197C19.2388 2.73459 19.1865 2.43673 19.091 2.14289C19.0301 1.96579 18.9697 1.78466 18.7656 1.75418C18.5442 1.71968 18.4574 1.90541 18.3705 2.06067C18.0232 2.69549 17.8887 3.39471 17.9019 4.10313C17.9324 5.6965 18.6051 6.96556 19.9421 7.86834C20.0939 7.97184 20.133 8.07535 20.0852 8.22658C19.9938 8.53766 19.8857 8.83955 19.7903 9.15063C19.7293 9.34901 19.6384 9.39271 19.4257 9.30588C18.692 8.9994 18.0583 8.54571 17.4982 7.99772C16.5477 7.07827 15.6881 6.06336 14.6162 5.26869C14.3644 5.08296 14.1125 4.91045 13.8521 4.746C12.7584 3.68394 13.9952 2.81164 14.2816 2.70814C14.5812 2.60003 14.3857 2.22857 13.4179 2.23317C12.4502 2.2372 11.5646 2.56151 10.4359 2.99335C10.2708 3.05832 10.0972 3.10547 9.91951 3.14457C8.8954 2.95022 7.83162 2.90709 6.72069 3.03245C4.62877 3.26533 2.95777 4.25436 1.72954 5.94261C0.254043 7.97184 -0.0932678 10.2777 0.33167 12.6824C0.778458 15.2171 2.07225 17.3153 4.06008 18.9558C6.12152 20.6567 8.49577 21.4905 11.2047 21.3306C12.8498 21.2358 14.6812 21.0155 16.7473 19.2669C17.2682 19.5262 17.8151 19.6297 18.7219 19.7074C19.4205 19.7723 20.0933 19.6729 20.6143 19.5648C21.4302 19.3923 21.3739 18.6367 21.0789 18.4981C18.6874 17.3843 19.2124 17.8374 18.7351 17.4706C19.9501 16.033 21.8063 13.4776 22.379 9.99821C22.4353 9.61409 22.5072 9.073 22.4986 8.76192C22.494 8.57216 22.5377 8.49856 22.7545 8.47671C23.3536 8.40771 23.935 8.24383 24.4692 7.94999C26.0188 7.10357 26.6439 5.71318 26.7911 4.04678C26.8129 3.79204 26.7865 3.52869 26.5174 3.39471ZM13.0143 18.3946C10.6964 16.5724 9.5722 15.9726 9.10816 15.9985C8.67402 16.0244 8.75222 16.5212 8.84768 16.8449C8.94773 17.1646 9.07768 17.3849 9.25996 17.6655C9.38589 17.8512 9.47272 18.1272 9.13404 18.3348C8.38766 18.7965 7.08985 18.1796 7.0289 18.1491C5.51833 17.2595 4.25559 16.0853 3.36546 14.4793C2.50581 12.9337 2.0067 11.2753 1.92447 9.50542C1.90262 9.07818 2.02855 8.92695 2.45406 8.84932C3.01413 8.74582 3.59144 8.72397 4.15093 8.80619C6.51656 9.15178 8.53027 10.2092 10.2185 11.8848C11.1822 12.8388 11.9114 13.979 12.6623 15.0929C13.461 16.2757 14.3201 17.4027 15.4144 18.3268C15.8008 18.6505 16.109 18.8966 16.404 19.0783C15.5144 19.1778 14.0297 19.1991 13.0143 18.3958V18.3946ZM14.1252 11.2489C14.1252 11.0591 14.277 10.9079 14.4679 10.9079C14.511 10.9079 14.5501 10.9165 14.5852 10.9292C14.6329 10.9464 14.6766 10.9723 14.7111 11.0114C14.7721 11.0718 14.8066 11.158 14.8066 11.2489C14.8066 11.4386 14.6548 11.5899 14.4639 11.5899C14.273 11.5899 14.1252 11.4386 14.1252 11.2489ZM17.5759 13.0188C17.3545 13.1096 17.1331 13.1873 16.9203 13.1959C16.5903 13.2131 16.2303 13.0791 16.0348 12.9153C15.7312 12.6605 15.5139 12.5179 15.423 12.0734C15.3839 11.8837 15.4057 11.5899 15.4402 11.4214C15.5185 11.0585 15.4316 10.8257 15.1757 10.614C14.9676 10.4415 14.7025 10.3938 14.4115 10.3938C14.3029 10.3938 14.2034 10.3461 14.1292 10.3076C14.0079 10.2472 13.9078 10.096 14.0033 9.91023C14.0338 9.84985 14.1815 9.70322 14.216 9.67734C14.6111 9.45251 15.0665 9.52612 15.488 9.6946C15.8784 9.85445 16.174 10.1477 16.5989 10.5623C17.033 11.0631 17.1112 11.2011 17.3585 11.5772C17.554 11.871 17.7317 12.1729 17.8536 12.5185C17.9272 12.7341 17.8317 12.9107 17.5759 13.0188Z"/></svg>';

  function chars(s) { // 逐字出现
    var out = '', a = Array.from ? Array.from(s) : s.split('');
    for (var i = 0; i < a.length; i++) out += '<span style="animation-delay:' + (i * 70) + 'ms">' + (a[i] === ' ' ? '&nbsp;' : esc(a[i])) + '</span>';
    return out;
  }
  function hexGrid() {
    var h = '0123456789ABCDEF', out = '';
    for (var r = 0; r < 9; r++) {
      var row = [];
      for (var c = 0; c < 10; c++) row.push(h[(Math.random() * 16) | 0] + h[(Math.random() * 16) | 0]);
      out += '<div style="animation-delay:' + (r * 90) + 'ms">' + row.join(' ') + '</div>';
    }
    return out;
  }
  function userId() {
    var u = '';
    try { u = localStorage.getItem('ds_user') || ''; } catch (e) {}
    return u ? u.toUpperCase() : 'GUEST';
  }

  var STEPS = [
    { zh: '需要访问许可', en: 'ACCESS PERMISSION REQUIRED', tag: 'AUTHORIZATION', subZh: '等待用户授权…', subEn: 'AWAITING OPERATOR CONSENT', say: 'Access permission required.', extra: 'auth' },
    { zh: '身份资料确认', en: 'IDENTITY VERIFICATION', tag: 'IDENTITY', subZh: '核对身份资料…', subEn: 'MATCHING OPERATOR RECORD', say: 'ID confirmed.', sayAt: 900, extra: 'card' },
    { zh: '接收访问需求', en: 'ACCESS REQUEST RECEIVED', tag: 'REQUEST', subZh: '访问需求已接收', subEn: 'REQUEST QUEUED', say: 'Request received.', extra: 'whale' },
    { zh: '开始读取权限', en: 'PERMISSION READ STARTED', tag: 'READ', subZh: '开始读取权限，索引工作区与会话…', subEn: 'READING PERMISSION SET', say: 'Start processing.', extra: 'read' },
    { zh: '读取完毕·核验通过', en: 'READ COMPLETE · VERIFIED', tag: 'VERIFY', subZh: '读取完毕，核验通过，权限已授予', subEn: 'PERMISSION AUTHORIZED', say: 'Permission authorized.', extra: 'ring' },
    { welcome: true, tag: 'WELCOME', subZh: '身份验证完成，会话已建立', subEn: 'IDENTITY VERIFIED · SESSION ESTABLISHED', say: 'Welcome to DeepSeek Chat.' }
  ];

  function stepHTML(s, i) {
    var h = '<div class="ds-sp-step" data-i="' + i + '">';
    if (s.welcome) {
      h += '<div class="ds-sp-wel1">WELCOME</div>' +
           '<div class="ds-sp-wel2">' + esc(BRAND + ' ' + OS_NAME) + '</div>' +
           '<div class="ds-sp-wwhale">' + WHALE + '</div>' +
           '<div class="ds-sp-spaced">' + esc(BRAND) + ' · ' + esc(OS_NAME) + '</div>' +
           '<div class="ds-sp-wel3">欢迎 ' + esc(WELCOME_NAME) + ' 访问</div>';
    } else {
      if (s.extra === 'ring') {
        h += '<div class="ds-sp-ring"><svg viewBox="0 0 200 200" aria-hidden="true">' +
             '<circle class="ds-sp-r1" cx="100" cy="100" r="92"/>' +
             '<circle class="ds-sp-r2" cx="100" cy="100" r="66"/>' +
             '<circle class="ds-sp-r3" cx="100" cy="100" r="40"/>' +
             '<g class="ds-sp-orb"><circle class="ds-sp-dot" cx="100" cy="34" r="3.2"/><circle class="ds-sp-dot" cx="146.7" cy="146.7" r="2.6"/></g>' +
             '<g class="ds-sp-orb2"><circle class="ds-sp-head" cx="100" cy="8" r="5"/></g>' +
             '</svg></div>';
      }
      h += '<div class="ds-sp-title">' + chars(s.zh) + '</div>' +
           '<div class="ds-sp-en">' + esc(s.en) + '</div>';
      if (s.extra === 'card') {
        h += '<div class="ds-sp-card"><div class="ds-sp-ava">' + WHALE + '</div><div class="ds-sp-cinfo">' +
             '<div><b>NAME</b><span>' + esc(WELCOME_NAME) + '</span></div>' +
             '<div><b>ID</b><span>' + esc(userId()) + '</span></div>' +
             '<div><b>CLEARANCE</b><span class="ds-sp-or">LEVEL 5</span></div>' +
             '<div><b>STATUS</b><span class="ds-sp-cst">PENDING</span></div>' +
             '<div class="ds-sp-bar"><i></i></div></div></div>';
      }
      if (s.extra === 'auth' && CONFIRM_ENABLED) {
        h += '<button type="button" class="ds-sp-confirm ds-sp-mono" aria-label="授权访问"><span class="ds-sp-cz">授权访问</span><span class="ds-sp-ce">AUTHORIZE</span><span class="ds-sp-ca">&rsaquo;</span></button>' +
             '<div class="ds-sp-chint ds-sp-mono">CLICK OR PRESS ENTER</div>';
      }
      if (s.extra === 'whale' || s.extra === 'read') {
        h += '<div class="ds-sp-mwhale">' + WHALE + '<div class="ds-sp-spaced">' + esc(BRAND) + '</div><div class="ds-sp-dash">- - - - - - - -</div></div>';
      }
      if (s.extra === 'read') h += '<div class="ds-sp-hex" aria-hidden="true">' + hexGrid() + '</div>';
    }
    return h + '</div>';
  }

  var CSS = [
    '#ds-splash{position:fixed;inset:0;left:0;top:0;width:100vw;height:100vh;height:100dvh;max-width:none;max-height:none;margin:0;padding:0;border:0;outline:0;overflow:hidden;z-index:2147483647;background:#000;color:#151515;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Noto Sans CJK SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased;user-select:none;-webkit-user-select:none;cursor:default;opacity:1;transition:opacity ' + EXIT_MS + 'ms ease,transform ' + EXIT_MS + 'ms cubic-bezier(.6,0,.3,1),filter ' + EXIT_MS + 'ms ease}',
    '#ds-splash::backdrop{background:transparent}',
    '#ds-splash *,#ds-splash *::before,#ds-splash *::after{box-sizing:border-box;margin:0;padding:0}',
    '#ds-splash.ds-sp-exit{opacity:0;transform:translateY(-4%) scale(1.02);filter:blur(6px);pointer-events:none}',
    '#ds-splash.ds-sp-exit-fast{transition-duration:280ms}',
    '#ds-splash .ds-sp-mono{font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,"Noto Sans Mono CJK SC",monospace}',
    '#ds-splash .ds-sp-whale{display:block;width:100%;height:auto}',
    /* —— 黑屏 logo 段 —— */
    '#ds-splash .ds-sp-logo{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#000;color:#fff;opacity:0;animation:ds-sp-fadein 1.2s ease .25s forwards}',
    '#ds-splash .ds-sp-logo .ds-sp-whale{width:84px;color:#fff;margin-bottom:18px}',
    '#ds-splash .ds-sp-logo .ds-sp-l1{font-size:26px;font-weight:700;letter-spacing:.32em;text-indent:.32em}',
    '#ds-splash .ds-sp-logo .ds-sp-l2{font-size:21px;font-weight:700;letter-spacing:.2em;text-indent:.2em;margin-top:4px}',
    '#ds-splash .ds-sp-logo .ds-sp-l3{font-size:9px;letter-spacing:.42em;text-indent:.42em;color:#8a8a8a;margin-top:10px}',
    '#ds-splash .ds-sp-logo::after{content:"";position:absolute;top:0;right:0;width:28%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.05) 60%,rgba(255,255,255,.02));pointer-events:none}',
    '#ds-splash.ds-sp-os .ds-sp-logo{display:none}',
    /* —— 系统终端段 —— */
    '#ds-splash .ds-sp-os{position:absolute;inset:0;display:none;background:linear-gradient(180deg,#f3f3f2 0%,#ebebea 100%);color:#151515}',
    '#ds-splash.ds-sp-os .ds-sp-os{display:block}',
    '#ds-splash .ds-sp-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(0,0,0,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,0,0,.022) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}',
    '#ds-splash .ds-sp-panel{position:absolute;top:2%;bottom:2%;border:1px solid rgba(0,0,0,.06);background:linear-gradient(180deg,rgba(255,255,255,.55),rgba(255,255,255,.15));pointer-events:none;animation:ds-sp-panel 1.2s ease both}',
    '#ds-splash .ds-sp-p1{left:5%;width:10%;bottom:48%}',
    '#ds-splash .ds-sp-p2{left:60%;width:16%;animation-delay:.1s}',
    '#ds-splash .ds-sp-p3{left:78%;width:16%;animation-delay:.2s}',
    '#ds-splash .ds-sp-crn{position:absolute;width:14px;height:14px;border:1px solid rgba(0,0,0,.35)}',
    '#ds-splash .ds-sp-c1{left:18px;top:18px;border-right:0;border-bottom:0}',
    '#ds-splash .ds-sp-c2{right:18px;top:18px;border-left:0;border-bottom:0}',
    '#ds-splash .ds-sp-c3{left:18px;bottom:18px;border-right:0;border-top:0}',
    '#ds-splash .ds-sp-c4{right:18px;bottom:18px;border-left:0;border-top:0}',
    '#ds-splash .ds-sp-hd{position:absolute;left:38px;top:34px;animation:ds-sp-slide .6s ease both}',
    '#ds-splash .ds-sp-hd .ds-sp-b1{font-size:22px;font-weight:800;letter-spacing:.04em;line-height:1.1}',
    '#ds-splash .ds-sp-hd .ds-sp-b2{font-size:10.5px;font-weight:700;letter-spacing:.06em;margin-top:2px}',
    '#ds-splash .ds-sp-hd .ds-sp-b3{font-size:22px;font-weight:800;letter-spacing:.04em;line-height:1.15}',
    '#ds-splash .ds-sp-hd .ds-sp-b3 span{font-weight:400}',
    '#ds-splash .ds-sp-tel{margin-top:38px;font-size:8.5px;letter-spacing:.18em;color:#8b8b8b}',
    '#ds-splash .ds-sp-or{color:#f07a1a}',
    '#ds-splash .ds-sp-segs{display:flex;gap:4px;margin-top:9px}',
    '#ds-splash .ds-sp-segs i{display:block;width:16px;height:2px;background:#c9c9c9;transition:background .3s,width .3s}',
    '#ds-splash .ds-sp-segs i.ds-on{background:#f07a1a;width:26px}',
    '#ds-splash .ds-sp-skip{position:absolute;right:34px;top:34px;font:inherit;font-size:10px;letter-spacing:.24em;color:#6f6f6f;background:transparent;border:0;padding:8px 6px;cursor:pointer;appearance:none;-webkit-appearance:none;border-radius:0;box-shadow:none;line-height:1;z-index:3}',
    '#ds-splash .ds-sp-skip:hover,#ds-splash .ds-sp-skip:focus-visible{color:#111;outline:1px solid rgba(0,0,0,.25)}',
    '#ds-splash .ds-sp-skipdark{color:#888}',
    '#ds-splash .ds-sp-bl{position:absolute;left:38px;bottom:34px;font-size:9px;letter-spacing:.2em;color:#777}',
    '#ds-splash .ds-sp-eq{display:flex;gap:2px;align-items:flex-end;height:12px;margin-bottom:18px}',
    '#ds-splash .ds-sp-eq i{display:block;width:2px;background:#f07a1a;animation:ds-sp-eq .9s ease-in-out infinite alternate}',
    '#ds-splash .ds-sp-br{position:absolute;right:38px;bottom:34px;text-align:right;font-size:9px;letter-spacing:.2em;color:#444}',
    '#ds-splash .ds-sp-br .ds-sp-pw{margin-top:22px;font-weight:700;color:#222}',
    '#ds-splash .ds-sp-br .ds-sp-pw::after{content:"";display:inline-block;width:20px;height:5px;background:#111;margin-left:8px;vertical-align:middle}',
    '#ds-splash .ds-sp-bc{position:absolute;left:50%;bottom:36px;transform:translateX(-50%);text-align:center;width:min(70vw,520px)}',
    '#ds-splash .ds-sp-sz{font-size:13px;color:#333;letter-spacing:.06em;min-height:1.4em}',
    '#ds-splash .ds-sp-se{font-size:8.5px;letter-spacing:.28em;color:#9a9a9a;margin-top:6px;min-height:1.2em}',
    '#ds-splash .ds-sp-prog{position:absolute;left:50%;bottom:8px;width:min(46vw,330px);height:3px;transform:translateX(-50%);background:rgba(0,0,0,.08)}',
    '#ds-splash .ds-sp-prog i{display:block;height:100%;width:0;background:#111;transition:width .9s ease}',
    '#ds-splash .ds-sp-prog i::after{content:"";position:absolute;top:0;width:6px;height:100%;background:#f07a1a;margin-left:-3px}',
    /* —— 中央步骤 —— */
    '#ds-splash .ds-sp-center{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:min(92vw,560px);height:min(80vh,560px)}',
    '#ds-splash .ds-sp-step{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;text-align:center}',
    '#ds-splash .ds-sp-step.ds-on{display:flex;animation:ds-sp-fadein .35s ease both}',
    '#ds-splash .ds-sp-title{position:relative;z-index:2;font-size:clamp(24px,4.6vw,34px);letter-spacing:.42em;text-indent:.42em;font-weight:400;color:#111;white-space:nowrap}',
    '#ds-splash .ds-sp-title span{display:inline-block;opacity:0;animation:ds-sp-char .45s ease forwards}',
    '#ds-splash .ds-sp-en{position:relative;z-index:2;font-size:clamp(8px,1.6vw,10px);letter-spacing:.62em;text-indent:.62em;color:#555;margin-top:6px;padding-bottom:4px;border-bottom:1px solid rgba(0,0,0,.18);width:100%;max-width:430px;white-space:nowrap;animation:ds-sp-fadein .8s ease .25s both}',
    '#ds-splash .ds-sp-card{display:flex;gap:14px;align-items:center;margin-top:26px;padding:12px 16px;border:1px solid rgba(0,0,0,.14);background:rgba(255,255,255,.6);text-align:left;animation:ds-sp-up .5s ease .35s both}',
    '#ds-splash .ds-sp-confirm{position:relative;display:inline-flex;align-items:center;gap:12px;margin-top:22px;padding:12px 22px 12px 26px;min-height:44px;background:#111;color:#fff;border:1px solid #111;border-left:4px solid #f07a1a;border-radius:0;font:inherit;font-size:12px;letter-spacing:.22em;line-height:1;cursor:pointer;appearance:none;-webkit-appearance:none;box-shadow:0 6px 18px rgba(0,0,0,.18);clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,0 100%);opacity:0;pointer-events:none;transition:background .2s,transform .15s}',
    '#ds-splash .ds-sp-step.ds-on .ds-sp-confirm{animation:ds-sp-up .5s ease .9s both,ds-sp-glow 1.6s ease-in-out 1.4s infinite}',
    '#ds-splash.ds-sp-wait .ds-sp-confirm{pointer-events:auto}',
    '#ds-splash .ds-sp-confirm:hover,#ds-splash .ds-sp-confirm:focus-visible{background:#000;outline:0;box-shadow:inset 0 0 0 1px #f07a1a,0 6px 22px rgba(240,122,26,.4)}',
    '#ds-splash .ds-sp-confirm:active{transform:scale(.97)}',
    '#ds-splash .ds-sp-confirm .ds-sp-cz{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Noto Sans CJK SC","Microsoft YaHei",sans-serif;font-size:14px;font-weight:700;letter-spacing:.3em}',
    '#ds-splash .ds-sp-confirm .ds-sp-ce{color:#f07a1a;font-weight:700}',
    '#ds-splash .ds-sp-confirm .ds-sp-ca{color:#f07a1a;font-size:16px;animation:ds-sp-nudge 1s ease-in-out infinite}',
    '#ds-splash .ds-sp-confirm.ds-sp-ok{background:#f07a1a;border-color:#f07a1a;color:#111}',
    '#ds-splash .ds-sp-confirm.ds-sp-ok .ds-sp-ce,#ds-splash .ds-sp-confirm.ds-sp-ok .ds-sp-ca{color:#111}',
    '#ds-splash .ds-sp-cst{color:#999;animation:ds-sp-blink 1s steps(2) infinite}',
    '#ds-splash .ds-sp-cst.ds-sp-cok{color:#f07a1a;animation:none}',
    '#ds-splash .ds-sp-chint{margin-top:10px;font-size:8px;letter-spacing:.32em;color:#777;opacity:0}',
    '#ds-splash.ds-sp-wait .ds-sp-chint{animation:ds-sp-blink 1.2s steps(2) infinite}',
    '#ds-splash .ds-sp-ava{width:52px;height:52px;border:1px solid rgba(0,0,0,.2);display:flex;align-items:center;justify-content:center;padding:8px;color:#111;background:#fafafa}',
    '#ds-splash .ds-sp-cinfo{font-size:10px;letter-spacing:.14em;color:#333;min-width:170px}',
    '#ds-splash .ds-sp-cinfo>div{display:flex;justify-content:space-between;gap:16px;line-height:1.75}',
    '#ds-splash .ds-sp-cinfo b{font-weight:400;color:#999}',
    '#ds-splash .ds-sp-cinfo span{font-weight:700;color:#111;letter-spacing:.1em}',
    '#ds-splash .ds-sp-cinfo span.ds-sp-or{color:#f07a1a}',
    '#ds-splash .ds-sp-bar{height:3px;background:rgba(0,0,0,.08);margin-top:6px}',
    '#ds-splash .ds-sp-bar i{display:block;height:100%;width:0;background:#f07a1a;animation:ds-sp-fill 1.2s ease .5s forwards}',
    '#ds-splash .ds-sp-mwhale{margin-top:22px;display:flex;flex-direction:column;align-items:center;color:#111;animation:ds-sp-up .5s ease .3s both}',
    '#ds-splash .ds-sp-mwhale .ds-sp-whale{width:64px}',
    '#ds-splash .ds-sp-spaced{font-size:8.5px;letter-spacing:.7em;text-indent:.7em;color:#555;margin-top:12px}',
    '#ds-splash .ds-sp-dash{font-size:9px;letter-spacing:.1em;color:#777;margin-top:10px}',
    '#ds-splash .ds-sp-hex{position:absolute;right:-42%;top:6%;font-size:8.5px;line-height:1.75;letter-spacing:.12em;color:#b9b9b9;text-align:left;white-space:nowrap;pointer-events:none}',
    '#ds-splash .ds-sp-hex div{opacity:0;animation:ds-sp-fadein .3s ease forwards}',
    '#ds-splash .ds-sp-ring{position:absolute;left:50%;top:50%;width:min(84vw,430px);height:min(84vw,430px);transform:translate(-50%,-50%);z-index:1}',
    '#ds-splash .ds-sp-ring svg{width:100%;height:100%;overflow:visible}',
    '#ds-splash .ds-sp-ring circle{fill:none}',
    '#ds-splash .ds-sp-r1{stroke:#111;stroke-width:4;stroke-linecap:round;stroke-dasharray:578;stroke-dashoffset:578;transform-origin:100px 100px;transform:rotate(-100deg);animation:ds-sp-draw 1.4s cubic-bezier(.5,0,.2,1) forwards}',
    '#ds-splash .ds-sp-r2{stroke:#fff;stroke-width:2.5;opacity:.95}',
    '#ds-splash .ds-sp-r3{stroke:#222;stroke-width:1.4}',
    '#ds-splash .ds-sp-ring .ds-sp-dot{fill:#f07a1a}',
    '#ds-splash .ds-sp-ring .ds-sp-head{fill:#111}',
    '#ds-splash .ds-sp-orb{transform-origin:100px 100px;animation:ds-sp-spin 3.2s linear infinite}',
    '#ds-splash .ds-sp-orb2{transform-origin:100px 100px;animation:ds-sp-spin2 1.4s cubic-bezier(.5,0,.2,1) forwards}',
    '#ds-splash .ds-sp-wel1{font-size:clamp(30px,6vw,44px);font-weight:800;letter-spacing:.14em;text-indent:.14em;color:#2f74c8;text-shadow:0 0 18px rgba(47,116,200,.35);animation:ds-sp-up .5s ease both}',
    '#ds-splash .ds-sp-wel2{margin-top:6px;background:#111;color:#fff;font-size:clamp(15px,3vw,21px);font-weight:800;letter-spacing:.08em;padding:3px 10px;animation:ds-sp-wipe .6s ease .2s both}',
    '#ds-splash .ds-sp-wwhale{width:62px;margin-top:22px;color:#111;animation:ds-sp-up .5s ease .4s both}',
    '#ds-splash .ds-sp-wel3{margin-top:8px;font-size:14px;letter-spacing:.24em;text-indent:.24em;color:#2f74c8;animation:ds-sp-fadein .6s ease .6s both}',
    '@keyframes ds-sp-glow{0%,100%{box-shadow:0 6px 18px rgba(0,0,0,.18)}50%{box-shadow:0 6px 22px rgba(240,122,26,.45)}}',
    '@keyframes ds-sp-nudge{0%,100%{transform:none}50%{transform:translateX(3px)}}',
    '@keyframes ds-sp-blink{0%{opacity:.9}100%{opacity:.2}}',
    '@keyframes ds-sp-fadein{from{opacity:0}to{opacity:1}}',
    '@keyframes ds-sp-char{from{opacity:0;filter:blur(4px)}to{opacity:1;filter:none}}',
    '@keyframes ds-sp-up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}',
    '@keyframes ds-sp-slide{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:none}}',
    '@keyframes ds-sp-panel{from{opacity:0;transform:scaleY(.9)}to{opacity:1;transform:none}}',
    '@keyframes ds-sp-fill{to{width:100%}}',
    '@keyframes ds-sp-eq{from{height:3px}to{height:12px}}',
    '@keyframes ds-sp-draw{to{stroke-dashoffset:150}}',
    '@keyframes ds-sp-spin{to{transform:rotate(360deg)}}',
    '@keyframes ds-sp-spin2{from{transform:rotate(-10deg)}to{transform:rotate(256.6deg)}}',
    '@keyframes ds-sp-wipe{from{clip-path:inset(0 100% 0 0)}to{clip-path:inset(0 0 0 0)}}',
    /* 手机 */
    '@media (max-width:600px){#ds-splash .ds-sp-hd{left:22px;top:24px}#ds-splash .ds-sp-hd .ds-sp-b1,#ds-splash .ds-sp-hd .ds-sp-b3{font-size:17px}#ds-splash .ds-sp-hd .ds-sp-b2{font-size:8.5px}#ds-splash .ds-sp-tel{margin-top:18px}#ds-splash .ds-sp-skip{right:16px;top:22px}#ds-splash .ds-sp-bl{left:22px;bottom:70px}#ds-splash .ds-sp-br{right:22px;bottom:70px}#ds-splash .ds-sp-br .ds-sp-id{display:none}#ds-splash .ds-sp-bc{bottom:20px;width:90vw}#ds-splash .ds-sp-title{letter-spacing:.24em;text-indent:.24em}#ds-splash .ds-sp-en{letter-spacing:.3em;text-indent:.3em}#ds-splash .ds-sp-hex{display:none}#ds-splash .ds-sp-p1{display:none}#ds-splash .ds-sp-p2{left:52%;width:20%}#ds-splash .ds-sp-p3{left:76%;width:20%}}',
    /* 减少动态效果：所有动画瞬时完成 */
    '#ds-splash.ds-sp-rm,#ds-splash.ds-sp-rm *{animation-duration:1ms!important;animation-delay:0ms!important;transition-duration:200ms!important}'
  ].join('\n');

  function build(rm) {
    styleEl = document.createElement('style');
    styleEl.id = 'ds-splash-style';
    styleEl.textContent = CSS;
    (document.head || document.documentElement).appendChild(styleEl);

    root = document.createElement('div');
    root.id = 'ds-splash';
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-label', '启动动画');
    if (rm) root.className = 'ds-sp-rm';

    var segs = '', eq = '', steps = '';
    for (var i = 0; i < STEPS.length; i++) { segs += '<i></i>'; steps += stepHTML(STEPS[i], i); }
    for (var k = 0; k < 6; k++) eq += '<i style="animation-delay:' + (k * 120) + 'ms"></i>';

    root.innerHTML =
      '<div class="ds-sp-logo">' + WHALE +
        '<div class="ds-sp-l1">深度求索</div><div class="ds-sp-l2">' + esc(BRAND) + '</div>' +
        '<div class="ds-sp-l3">' + esc(LOGO_TAGLINE) + '</div></div>' +
      '<div class="ds-sp-os">' +
        '<div class="ds-sp-grid"></div><div class="ds-sp-panel ds-sp-p1"></div><div class="ds-sp-panel ds-sp-p2"></div><div class="ds-sp-panel ds-sp-p3"></div>' +
        '<i class="ds-sp-crn ds-sp-c1"></i><i class="ds-sp-crn ds-sp-c2"></i><i class="ds-sp-crn ds-sp-c3"></i><i class="ds-sp-crn ds-sp-c4"></i>' +
        '<div class="ds-sp-hd"><div class="ds-sp-b1">' + esc(BRAND) + '</div><div class="ds-sp-b2">' + esc(BRAND_SUB) + '</div>' +
          '<div class="ds-sp-b3">' + esc(OS_NAME.replace(/\s*OS$/, '')) + ' <span>OS</span></div>' +
          '<div class="ds-sp-tel ds-sp-mono">' + esc(REV) + ' · WEB PROFILE <span class="ds-sp-or ds-sp-clock"></span></div>' +
          '<div class="ds-sp-segs">' + segs + '</div></div>' +
        '<div class="ds-sp-center">' + steps + '</div>' +
        '<div class="ds-sp-bl ds-sp-mono"><div class="ds-sp-eq">' + eq + '</div><div class="ds-sp-cnt"></div></div>' +
        '<div class="ds-sp-br ds-sp-mono"><div class="ds-sp-id">· <span class="ds-sp-idl">ID PENDING</span> : <span class="ds-sp-idn"></span></div><div class="ds-sp-pw">POWERED BY ' + esc(BRAND) + '</div></div>' +
        '<div class="ds-sp-bc"><div class="ds-sp-sz"></div><div class="ds-sp-se ds-sp-mono"></div></div>' +
        '<div class="ds-sp-prog"><i></i></div>' +
      '</div>' +
      '<button type="button" class="ds-sp-skip ds-sp-mono ds-sp-skipdark" aria-label="跳过启动动画">SKIP &rsaquo;</button>';

    // 放在 <html> 下（不进 <body>），主界面 body 的子节点完全不受影响
    document.documentElement.appendChild(root);
    // 用 popover 顶层渲染，盖过主界面 body::after 等任何 z-index；不支持时退回 z-index 最大值
    try { root.setAttribute('popover', 'manual'); root.showPopover(); } catch (e) { root.removeAttribute('popover'); }

    var skip = root.querySelector('.ds-sp-skip');
    skip.addEventListener('click', safe(function (ev) { ev.stopPropagation(); exit(true); }));
    var cbtn = root.querySelector('.ds-sp-confirm');
    if (cbtn) cbtn.addEventListener('click', safe(function (ev) { ev.stopPropagation(); confirmId(); }));
    document.addEventListener('keydown', onKey, true);
  }

  function onKey(e) {
    if (done) return;
    if (e.key === 'Escape' || e.key === 'Esc') { try { e.preventDefault(); e.stopPropagation(); } catch (x) {} safe(function () { exit(true); })(); }
    else if (waiting && e.key === 'Enter') { try { e.preventDefault(); e.stopPropagation(); } catch (x) {} safe(confirmId)(); }
  }

  /* ---- 声音（仅在用户点确认之后；任何异常都静默） ---- */
  function armVoice() { if (VOICE_ENABLED) voiceArmed = true; }
  function pickVoice() {
    try {
      var vs = window.speechSynthesis.getVoices() || [], en = [], i;
      for (i = 0; i < vs.length; i++) if (/^en[-_]US/i.test(vs[i].lang)) en.push(vs[i]);
      for (i = 0; i < en.length; i++) if (/female|samantha|zira|aria|jenny|ava|allison|susan|karen|victoria|google us english/i.test(en[i].name)) return en[i];
      return en[0] || null;
    } catch (e) { return null; }
  }
  function now() { return (window.performance && performance.now) ? performance.now() : +new Date(); }
  /* 预加载：等待确认时 fetch + decode 全部语音；任何一个失败就整体退回 speechSynthesis */
  function preloadVoice() {
    if (!VOICE_ENABLED || clipsState !== 'idle') return;
    clipsState = 'loading';
    try {
      var AC = window.AudioContext || window.webkitAudioContext;
      if (!AC || !window.fetch) throw 0;
      actx = new AC();
      var names = [], k, left;
      for (k in VOICE_FILES) names.push(k);
      left = names.length;
      var fail = function () { if (clipsState === 'loading') { clipsState = 'failed'; flushClips(); } };
      names.forEach(function (t) {
        fetch(VOICE_BASE + VOICE_FILES[t]).then(function (r) { if (!r.ok) throw 0; return r.arrayBuffer(); }).then(function (ab) {
          if (done) return;
          actx.decodeAudioData(ab, function (buf) {   // 回调写法兼容老 Safari
            clips[t] = buf;
            if (--left === 0 && clipsState === 'loading') { clipsState = 'ready'; flushClips(); }
          }, fail);
        })['catch'](fail);
      });
    } catch (e) { clipsState = 'failed'; }
  }
  function flushClips() { var cb = clipsCb; clipsCb = []; for (var i = 0; i < cb.length; i++) { try { cb[i](); } catch (e) {} } }
  // 语音就绪（或失败、或超时）后再继续
  function whenVoice(fn, maxMs) {
    if (clipsState !== 'loading') { fn(); return; }
    var fired = false, go = safe(function () { if (!fired) { fired = true; fn(); } });
    clipsCb.push(go); later(go, maxMs);
  }
  function unlockAudio() {   // 必须在点击/按键的同步调用栈里执行
    try { if (actx && actx.state === 'suspended') actx.resume(); } catch (e) {}
    try {   // iOS：在手势里播一段静音缓冲以解锁
      if (actx) { var b = actx.createBuffer(1, 1, 22050), s = actx.createBufferSource(); s.buffer = b; s.connect(actx.destination); s.start(0); }
    } catch (e) {}
  }
  function stopAudio() {
    for (var i = 0; i < sources.length; i++) { try { sources[i].stop(0); } catch (e) {} }
    sources = [];
    try { if (actx && actx.close) actx.close(); } catch (e) {}
    actx = null;
  }
  // 返回这句话预计的时长（ms），用于让下一步等它说完；0 = 未出声
  function say(text) {
    if (!VOICE_ENABLED || !voiceArmed || !text) return 0;
    var buf = clips[text];
    if (buf && actx) {
      try {
        var src = actx.createBufferSource(); src.buffer = buf; src.connect(actx.destination); src.start(0);
        sources.push(src);
        var ms = Math.round(buf.duration * 1000);
        voiceFree = now() + ms;
        try { root && root.setAttribute('data-voice', text + '@' + Math.round(now())); } catch (e) {}
        return ms;
      } catch (e) {}
    }
    if (clipsState !== 'failed') return 0;   // 文件可用但单句失败：静默
    try {
      var u = new SpeechSynthesisUtterance(text), v = pickVoice();
      u.lang = 'en-US'; u.rate = VOICE_RATE; if (v) u.voice = v;
      window.speechSynthesis.speak(u);   // 兜底：排队播放，不打断上一句
    } catch (e) {}
    return 0;
  }
  // 距离当前语音说完还要等多久（ms，含间隔，封顶）
  // voiceLate: 本步语音比本步画面晚开始的毫秒数（身份卡那一步是 sayAt），上限顺延同样时长，保证 +1.2s 是相对语音开始算的，长语音也不会被下一句盖住
  function voiceWait() { return Math.max(0, Math.min(VOICE_WAIT_MAX + voiceLate, voiceFree + VOICE_GAP_MS - now())); }

  function q(sel) { return root ? root.querySelector(sel) : null; }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function tickClock() {
    var el = q('.ds-sp-clock'); if (!el) return;
    var d = new Date(); el.textContent = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    later(tickClock, 1000);
  }

  function showStep(i) {
    var s = STEPS[i], all = root.querySelectorAll('.ds-sp-step'), segs = root.querySelectorAll('.ds-sp-segs i');
    voiceLate = 0;
    for (var k = 0; k < all.length; k++) all[k].className = 'ds-sp-step' + (k === i ? ' ds-on' : '');
    for (var j = 0; j < segs.length; j++) segs[j].className = j === i ? 'ds-on' : '';
    q('.ds-sp-cnt').textContent = '[ ' + pad2(i + 1) + ' / ' + pad2(STEPS.length) + ' ]  ' + s.tag;
    q('.ds-sp-sz').textContent = s.subZh;
    q('.ds-sp-se').textContent = s.subEn;
    q('.ds-sp-prog i').style.width = Math.round((i + 1) / STEPS.length * 100) + '%';
    root.setAttribute('data-step', String(i + 1));
    if (s.extra === 'card') {   // 身份卡：先显示 PENDING，片刻后自己变成 CONFIRMED，同时读出 'ID confirmed.'
      later(function () {
        var c = q('.ds-sp-cst'); if (c) { c.textContent = 'CONFIRMED'; c.className = 'ds-sp-cst ds-sp-cok'; }
        var l = q('.ds-sp-idl'); if (l) l.textContent = 'ID CONFIRMED';
        voiceLate = s.sayAt || 0;
        say(s.say);
      }, s.sayAt || 0);
    } else if (i > 0) say(s.say);   // 第 1 步的语音在点击时播放
  }

  function exit(fast) {
    if (exiting || done || !root) return;
    exiting = true;
    if (fast) root.className += ' ds-sp-exit-fast';
    root.className += ' ds-sp-exit';
    later(hardRemove, fast ? 320 : EXIT_MS + 50);
  }

  // 硬性兜底（不经过 safe()）：每段自动播放重新计时
  function startCap(ms) { try { clearTimeout(capTimer); } catch (e) {} capTimer = setTimeout(hardRemove, ms || MAX_TOTAL_MS); }
  function stopCap() { try { clearTimeout(capTimer); } catch (e) {} capTimer = null; }

  function pauseForConfirm() {
    waiting = true;
    stopCap();                                   // 等用户期间不计入 17s 上限
    root.className += ' ds-sp-wait';
    root.setAttribute('data-wait', '1');
    var l = q('.ds-sp-idl'); if (l) l.textContent = 'ID PENDING';
    preloadVoice();                              // 用户看授权按钮时预加载语音
    later(function () { if (waiting) resume(false); }, CONFIRM_WAIT_MS);   // 安全自动继续
  }
  function confirmId() {
    if (!waiting || confirmed) return;
    confirmed = true;
    armVoice();
    unlockAudio();
    var b = q('.ds-sp-confirm'); if (b) b.className += ' ds-sp-ok';
    whenVoice(function () { say(STEPS[0].say); resume(true); }, VOICE_LOAD_WAIT_MS);
  }
  function resume(byUser) {
    if (!waiting) return;
    waiting = false;
    root.className = root.className.replace(/\s*ds-sp-wait/g, '');
    root.removeAttribute('data-wait');
    root.setAttribute('data-confirmed', byUser ? 'user' : 'timeout');
    startCap(POST_CLICK_MAX_MS);
    // 依次推进：每一步至少间隔 STEP_MS；若上一句语音还没说完，就再等到它说完（+间隔，最多 VOICE_WAIT_MAX）
    var i = 1;
    function next() {
      showStep(i);
      if (i === STEPS.length - 1) {
        later(function () { later(function () { exit(false); }, voiceWait()); }, WELCOME_MS);   // 结束前等最后一句说完
        return;
      }
      i++;
      later(function () { later(next, voiceWait()); }, STEP_MS);
    }
    // 点击 = 第 1 步语音开始：和其它步一样，至少 STEP_MS 后再进第 2 步（超时自动继续时无语音，直接进）
    later(function () { later(next, voiceWait()); }, byUser ? STEP_MS : 200);
  }

  function run() {
    if (!shouldPlay()) return;
    var rm = reducedMotion();
    build(rm);
    startCap();
    root.setAttribute('data-step', '0');

    if (rm) { // 减少动态：只显示欢迎页，快速淡出
      root.className += ' ds-sp-os';
      var l0 = q('.ds-sp-idl'); if (l0) l0.textContent = 'ID CONFIRMED';
      showStep(STEPS.length - 1);
      later(function () { exit(false); }, 1200);
      return;
    }
    q('.ds-sp-idn').textContent = ('000' + ((Math.random() * 9999) | 0)).slice(-4);
    later(function () {           // 硬切到白色终端
      root.className += ' ds-sp-os';
      q('.ds-sp-skip').className = 'ds-sp-skip ds-sp-mono';
      tickClock();
      if (CONFIRM_ENABLED) {           // 第 1 步「需要访问许可」出现后暂停，等授权
        later(function () { showStep(0); }, 200);
        later(pauseForConfirm, 200 + 900);
      } else {
        for (var i = 0; i < STEPS.length; i++) (function (i) { later(function () { showStep(i); }, 200 + i * STEP_MS); })(i);
        later(function () { exit(false); }, 200 + (STEPS.length - 1) * STEP_MS + WELCOME_MS);
      }
    }, LOGO_MS);
  }

  try { run(); } catch (e) { hardRemove(); }
})();
