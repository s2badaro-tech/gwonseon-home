// 권선 작업실 공통 로그인 v4 (2026-11-27, Supabase) — 대문·작업기록·코일 관리·설정방이 함께 씀
// 이름 + PIN을 한 번 넣으면 Supabase 서버에서 출입증 하나를 받아, 세 방이 같은 출입증을 씀.
// PIN 자체는 저장하지 않습니다.
(function () {
  var API = 'https://difrlthubqaoeqyprhhj.supabase.co/functions/v1/api';
  var K = { wlTok: 'wr_token', wlName: 'wr_name', wlCfg: 'wr_cfg', coTok: 'coilinv_token', coName: 'coilinv_name', coSnap: 'coilinv_snap', stTok: 'st_token', stSup: 'st_sup' };
  function ls(k, v) {
    try { if (v === undefined) return localStorage.getItem(k); if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); }
    catch (e) { return null; }
  }
  function post(app, fn, args) {
    return fetch(API, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ app: app, fn: fn, args: args || [] }) })
      .then(function (r) { return r.json(); }, function () { throw new Error('인터넷 연결을 확인해 주세요.'); })
      .then(function (j) { if (j && j.ok) return j.v; throw new Error(String((j && j.e) || '서버 응답이 이상합니다').replace(/^(Exception|Error):\s*/, '').replace('[로그인]', '').trim()); });
  }
  // 출입증 하나를 세 방 자리에 모두 저장
  function saveAll(token, name, sup) {
    ls(K.wlCfg, null); ls(K.coSnap, null);
    ls(K.wlTok, token); ls(K.wlName, name); ls(K.coTok, token); ls(K.coName, name); ls(K.stTok, token);
    if (sup !== undefined) ls(K.stSup, sup ? 'Y' : null);
  }
  // Supabase로 옮긴 뒤 처음 한 번: 작업기록 출입증은 새 서버로 옮겨져 있으므로 코일·설정방도 같은 출입증을 씀
  if (ls('gw_sb1') !== '1') {
    var t = ls(K.wlTok);
    if (t) saveAll(t, ls(K.wlName) || ls(K.coName) || ''); else { ls(K.coTok, null); ls(K.stTok, null); }
    ls('gw_sb1', '1');
  }
  var GW = {
    name: function () { return ls(K.wlName) || ls(K.coName) || ''; },
    isSup: function () { return ls(K.stSup) === 'Y'; }, // 운영자
    stToken: function () { return ls(K.stTok) || ''; },
    stPost: function (fn, args) { return post('st', fn, args); },
    // 등급 이름 (운영자 > 관리자 > 팀원). 작업기록 설정을 기억해 둔 게 없으면 한 번 받아 옴
    role: function () {
      var c = null; try { c = JSON.parse(ls(K.wlCfg) || 'null'); } catch (e) {}
      if (!c || !c.me || String(c.me.name).replace(/\s/g, '') !== String(GW.name()).replace(/\s/g, '')) return '';
      return c.me.owner ? '운영자' : c.me.admin ? '관리자' : '팀원';
    },
    fetchRole: function () {
      var r = GW.role(), t = ls(K.wlTok); if (r || !t) return Promise.resolve(r);
      return post('wl', 'getConfig', [t]).then(function (c) { if (c && c.me && !c.login) ls(K.wlCfg, JSON.stringify(c)); return GW.role(); }, function () { return ''; });
    },
    loggedIn: function () { return !!(ls(K.wlTok) && ls(K.coTok) && ls(K.wlName) === ls(K.coName)); },
    // 로그인 → { name, mustChange }
    login: function (name, pin) {
      return post('wl', 'login', [name, pin]).then(function (r) { saveAll(r.token, r.name, r.sup); return { name: r.name, mustChange: !!r.mustChange }; });
    },
    // 한쪽 방에서 로그인했을 때: 그 방 출입증을 다른 방에도 그대로 씀 (서버에 다시 안 감)
    alsoLogin: function (which) {
      var t = which === 'wl' ? ls(K.coTok) : ls(K.wlTok), n = which === 'wl' ? ls(K.coName) : ls(K.wlName);
      if (t) saveAll(t, n);
      if (t) post('st', 'getAll', [t]).then(function (a) { ls(K.stSup, a && a.me && a.me.sup ? 'Y' : null); }, function () {});
      return Promise.resolve();
    },
    // PIN 바꾸기: 명단이 하나라 한 번 바꾸면 모든 방이 새 PIN. 지금 출입증은 그대로 씀
    changePin: function (name, oldPin, newPin) {
      var t = ls(K.wlTok) || ls(K.coTok);
      return post('wl', 'changePin', [t, oldPin, newPin]).then(function () { ls(K.wlCfg, null); });
    },
    logout: function () {
      var t = ls(K.wlTok) || ls(K.coTok) || ls(K.stTok);
      ls(K.wlTok, null); ls(K.coTok, null); ls(K.wlCfg, null); ls(K.coSnap, null); ls(K.stTok, null); ls(K.stSup, null);
      if (t) post('wl', 'logout', [t]).catch(function () {});
    }
  };
  window.GW = GW;
})();
