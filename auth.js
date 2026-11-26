// 권선 작업실 공통 로그인 (대문·작업기록·코일 관리가 함께 씀)
// 이름 + PIN을 한 번 넣으면 작업기록 서버와 코일 서버 양쪽에 들어가 출입증 두 개를 이 휴대폰에 저장합니다.
// 세 화면이 같은 주소(깃허브) 아래라 저장한 출입증을 같이 씁니다. PIN 자체는 저장하지 않습니다.
(function () {
  var WL = 'https://script.google.com/macros/s/AKfycbyd0RPsssmkYegAsfN5EQFJYO3R0e44egM7moJNYQs_L1tfu1fod5QeRUK8j7rHe80/exec';
  var CO = 'https://script.google.com/macros/s/AKfycbzkBCcsgRhWZK3SGpM0MP1HwDYyZLvzNSZkOdCogANwlLe3Gg9_K7e8mFJuHvIVzChJ/exec';
  var K = { wlTok: 'wr_token', wlName: 'wr_name', wlCfg: 'wr_cfg', coTok: 'coilinv_token', coName: 'coilinv_name', coSnap: 'coilinv_snap' };
  function ls(k, v) {
    try { if (v === undefined) return localStorage.getItem(k); if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); }
    catch (e) { return null; }
  }
  function post(url, fn, args) {
    return fetch(url, { method: 'POST', redirect: 'follow', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ fn: fn, args: args || [] }) })
      .then(function (r) { return r.json(); }, function () { throw new Error('인터넷 연결을 확인해 주세요.'); })
      .then(function (j) { if (j && j.ok) return j.v; throw new Error(String((j && j.e) || '서버 응답이 이상합니다').replace(/^(Exception|Error):\s*/, '').replace('[로그인]', '').trim()); });
  }
  function saveWl(r) { ls(K.wlCfg, null); ls(K.wlTok, r.token); ls(K.wlName, r.name); }
  function saveCo(r) { ls(K.coSnap, null); ls(K.coTok, r.token); ls(K.coName, r.name); }
  var GW = {
    name: function () { return ls(K.wlName) || ls(K.coName) || ''; },
    loggedIn: function () { return !!(ls(K.wlTok) && ls(K.coTok) && ls(K.wlName) === ls(K.coName)); },
    // 두 서버에 함께 들어가기 → { name, mustChange }
    login: function (name, pin) {
      return Promise.all([post(WL, 'login', [name, pin]), post(CO, 'login', [name, pin])]).then(function (a) {
        saveWl(a[0]); saveCo(a[1]);
        return { name: a[0].name, mustChange: !!(a[0].mustChange || a[1].mustChange) };
      });
    },
    // 한쪽 방에서 로그인했을 때 다른 쪽도 조용히 들어가 둠 (실패해도 그 방은 그대로 씀)
    alsoLogin: function (which, name, pin) {
      if (which === 'wl') return post(WL, 'login', [name, pin]).then(saveWl).catch(function () {});
      return post(CO, 'login', [name, pin]).then(saveCo).catch(function () {});
    },
    // PIN 바꾸기: 명단은 하나라 한 번 바꾸면 두 앱 모두 새 PIN. 바꾼 뒤 두 출입증을 새 PIN으로 다시 받아 둠.
    // 코일 서버로 바꾸면 코일 출입증이 바로 새것으로 바뀌고, 작업기록은 새 PIN으로 다시 들어가 기억을 새로 고침.
    changePin: function (name, oldPin, newPin) {
      // 코일 출입증이 같은 사람 것일 때만 코일 서버로 바꿈 (한 휴대폰을 여러 사람이 쓸 때 대비)
      var same = String(ls(K.coName) || '').replace(/\s/g, '') === String(name || '').replace(/\s/g, '');
      var co = same ? ls(K.coTok) : null, wl = ls(K.wlTok);
      var step = co ? post(CO, 'changePin', [co, oldPin, newPin])
        : post(WL, 'changePin', [wl, oldPin, newPin]);
      return step.then(function () {
        var oldWl = ls(K.wlTok);
        return Promise.all([
          post(WL, 'login', [name, newPin]).then(function (r) { saveWl(r); if (oldWl && oldWl !== r.token) post(WL, 'logout', [oldWl]).catch(function () {}); }).catch(function () {}),
          co ? null : post(CO, 'login', [name, newPin]).then(saveCo).catch(function () {})
        ]);
      });
    },
    // 로그아웃: 두 앱 모두
    logout: function () {
      var wl = ls(K.wlTok), co = ls(K.coTok);
      ls(K.wlTok, null); ls(K.coTok, null); ls(K.wlCfg, null); ls(K.coSnap, null);
      if (wl) post(WL, 'logout', [wl]).catch(function () {});
      if (co) post(CO, 'logout', [co]).catch(function () {});
    }
  };
  window.GW = GW;
})();
