// 권선 작업실 서버 (Supabase Edge Function 'api') v1 — 2026-11-27
// 구글 Apps Script 세 개(작업기록 v30 · 코일 관리 v34 · ⚙ 설정방 v3)가 하던 일을 그대로 옮김.
// 화면은 지금처럼 { app, fn, args } 를 보내고 { ok, v } 또는 { ok:false, e } 를 받음.
//   app: 'wl' = 작업기록, 'co' = 코일 관리, 'st' = 설정방, 'sys' = 구글 도우미(비밀 열쇠 필요)
// 보안: 표는 모두 RLS가 켜져 있고 정책이 없어 공개 키로는 못 읽음. 여기서만 서비스 키(환경변수)로 다룸.
//       서비스 키는 Supabase가 이 함수에 넣어 주는 환경변수에만 있고, 코드·깃허브에는 없음.
// 권선 기록·코일 이력은 지우는 기능이 없음 (취소도 되돌림 줄을 더함).
import { createClient } from 'jsr:@supabase/supabase-js@2';

const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });
const VERSION = 'sb1';
const LOGIN_MARK = '[로그인]';
const TEMP_PIN = '2027';
const TOKEN_DAYS = 30;
const DAY = 86400000;

// ───────────────── 공통 도구 ─────────────────
function kst(ms?: number) { return new Date((ms ?? Date.now()) + 9 * 3600000).toISOString(); }
function nowStr() { const k = kst(); return k.slice(0, 10) + ' ' + k.slice(11, 16); }
function today() { return kst().slice(0, 10); }
function dayStr(ms: number) { return kst(ms).slice(0, 10); }
function normName(s: any) { return String(s ?? '').replace(/\s+/g, ''); }
function num(v: any) { const n = parseFloat(String(v ?? '').replace(/[^0-9.\-]/g, '')); return isFinite(n) ? n : NaN; }
function r2(n: number) { return Math.round(n * 100) / 100; }
function txt(v: any) { const s = String(v ?? '').trim(); return /^[=+\-@]/.test(s) ? "'" + s : s; }
async function sha256hex(s: string) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function pinHash(salt: string, pin: string) { return 'h' + await sha256hex(String(salt) + String(pin)); }
function randHex(n = 32) { const a = new Uint8Array(n); crypto.getRandomValues(a); return [...a].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function uuid() { return crypto.randomUUID(); }
function err(m: string): never { throw new Error(m); }
async function q(p: PromiseLike<any>): Promise<any> {
  const { data, error } = await p;
  if (error) throw new Error('저장소 오류: ' + (error.message || error));
  return data;
}
async function getSetting(key: string, def: any) {
  const r = await q(db.from('app_settings').select('value').eq('key', key).maybeSingle());
  return r ? (r as any).value : def;
}
async function putSetting(key: string, value: any) {
  await q(db.from('app_settings').upsert({ key, value, updated_at: new Date().toISOString() }));
}
async function secret(key: string) {
  const r: any = await q(db.from('app_secrets').select('value').eq('key', key).maybeSingle());
  return r ? String(r.value) : '';
}
// 구글 도우미(Apps Script)에게 일 시키기: 사진 저장, 메일, 백업 파일 쓰기
async function google(op: string, data: any) {
  const url = await secret('gas_url'), key = await secret('gas_key');
  if (!url || !key) err('구글 도우미 주소가 아직 설정되지 않았습니다.');
  const r = await fetch(url, { method: 'POST', redirect: 'follow', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ fn: 'bridge', args: [key, op, data] }) });
  const j = await r.json().catch(() => null);
  if (!j || !j.ok) err('구글 도우미 오류: ' + ((j && j.e) || r.status));
  return j.v;
}
function bg(p: Promise<any>) { // 응답을 먼저 보내고 뒤에서 마저 함
  const er = (globalThis as any).EdgeRuntime;
  if (er && er.waitUntil) er.waitUntil(p.catch(() => {})); else p.catch(() => {});
}

// ───────────────── 사람 명단 · 로그인 (세 방이 같이 씀) ─────────────────
type Person = { id: number; name: string; wl_admin: boolean; owner: boolean; coil_admin: boolean; off: boolean; salt: string; pin_hash: string; temp: boolean; reg_at: string; last_seen: string };
async function people(): Promise<Person[]> {
  return (await q(db.from('people').select('*').order('sort').order('id'))) as any;
}
// 등급: 운영자(전체관리 Y) > 관리자 > 팀원. 운영자가 아무도 없으면 작업기록 관리자가 운영자 (예전 규칙, 잠김 방지)
function roles(P: Person[], p: Person) {
  const anyOwner = P.some((x) => x.owner && !x.off);
  const owner = p.owner || (!anyOwner && p.wl_admin);
  const anyCoil = P.some((x) => x.coil_admin);
  return {
    owner,
    wlAdmin: owner || p.wl_admin,
    coilAdmin: owner || p.coil_admin || (!anyCoil && p.wl_admin),
  };
}
function findP(P: Person[], name: any) { const n = normName(name); return P.find((u) => normName(u.name) === n); }

async function login(app: string, name: string, pin: string) {
  const key = normName(name), now = Date.now();
  const f: any = await q(db.from('login_fails').select('*').eq('name_key', key).maybeSingle());
  const fails = f && f.until_ms > now ? f.fails : 0;
  if (fails >= 5) err('PIN을 5번 틀려서 10분 동안 잠겼습니다. 잠시 뒤에 다시 해보세요.');
  const P = await people(), u = findP(P, name);
  if (!u || u.off || !u.salt || (await pinHash(u.salt, String(pin ?? '').trim())) !== u.pin_hash) {
    await q(db.from('login_fails').upsert({ name_key: key, fails: fails + 1, until_ms: now + 600000 }));
    const left = 4 - fails;
    err('이름 또는 PIN이 맞지 않습니다.' + (left <= 0 ? ' 10분 동안 잠깁니다.' : left <= 2 ? ' (' + left + '번 더 틀리면 10분 잠김)' : '') + (app === 'co' ? ' 등록은 관리자에게 부탁하세요.' : ''));
  }
  await q(db.from('login_fails').delete().eq('name_key', key));
  const token = randHex(32);
  await q(db.from('sessions').insert({ token_hash: await sha256hex(token), person_id: u.id, created_ms: now, last_ms: now }));
  await q(db.from('people').update({ last_seen: nowStr() }).eq('id', u.id));
  // 30일 넘게 안 쓴 출입증 정리
  bg(q(db.from('sessions').delete().lt('last_ms', now - TOKEN_DAYS * DAY)));
  const R = roles(P, u);
  return { token, name: u.name, admin: app === 'co' ? R.coilAdmin : R.wlAdmin, owner: R.owner, sup: R.owner, mustChange: u.temp };
}
type Me = { id: number; name: string; admin: boolean; owner: boolean; wlAdmin: boolean; coilAdmin: boolean; mustChange: boolean; token: string; P: Person[]; p: Person };
async function me(token: any, app: string): Promise<Me> {
  if (!token) err(LOGIN_MARK + ' 다시 로그인해 주세요.');
  const th = await sha256hex(String(token));
  const s: any = await q(db.from('sessions').select('*').eq('token_hash', th).maybeSingle());
  if (!s) err(LOGIN_MARK + ' 다시 로그인해 주세요.');
  const P = await people(), u = P.find((x) => x.id === s.person_id);
  if (!u || u.off || !u.pin_hash) { await q(db.from('sessions').delete().eq('token_hash', th)); err(LOGIN_MARK + ' PIN이 바뀌었거나 명단에서 빠졌습니다. 다시 로그인해 주세요.'); }
  const now = Date.now();
  if (now - s.last_ms > TOKEN_DAYS * DAY) { await q(db.from('sessions').delete().eq('token_hash', th)); err(LOGIN_MARK + ' ' + TOKEN_DAYS + '일 넘게 안 써서 로그인이 끝났습니다. 다시 로그인해 주세요.'); }
  if (now - s.last_ms > 3600000) bg(Promise.all([q(db.from('sessions').update({ last_ms: now }).eq('token_hash', th)), q(db.from('people').update({ last_seen: nowStr() }).eq('id', u.id))]));
  const R = roles(P, u);
  return { id: u.id, name: u.name, admin: app === 'co' ? R.coilAdmin : R.wlAdmin, owner: R.owner, wlAdmin: R.wlAdmin, coilAdmin: R.coilAdmin, mustChange: u.temp, token: String(token), P, p: u };
}
async function logout(token: any) {
  if (token) await q(db.from('sessions').delete().eq('token_hash', await sha256hex(String(token))));
  return { ok: true };
}
async function changePin(app: string, token: any, oldPin: any, newPin: any) {
  const m = await me(token, app);
  newPin = String(newPin ?? '').trim();
  if (!/^\d{4,8}$/.test(newPin)) err('새 PIN은 숫자 4~8자리로 정해주세요.');
  if (newPin === TEMP_PIN) err(TEMP_PIN + '은 임시 PIN이라 쓸 수 없습니다. 다른 숫자로 정해주세요.');
  if ((await pinHash(m.p.salt, String(oldPin ?? '').trim())) !== m.p.pin_hash) err('지금 PIN이 맞지 않습니다.');
  const salt = uuid();
  await q(db.from('people').update({ salt, pin_hash: await pinHash(salt, newPin), temp: false }).eq('id', m.id));
  // 다른 휴대폰 출입증은 끝냄 (지금 이 휴대폰은 그대로)
  const th = await sha256hex(m.token);
  await q(db.from('sessions').delete().eq('person_id', m.id).neq('token_hash', th));
  if (app === 'st') await stLog(m.name, '내 PIN 바꿈', m.name, '', '');
  return { ok: true };
}
async function resetPinRow(u: Person) {
  const salt = uuid();
  await q(db.from('people').update({ salt, pin_hash: await pinHash(salt, TEMP_PIN), temp: true }).eq('id', u.id));
  await q(db.from('sessions').delete().eq('person_id', u.id)); // 그 사람 휴대폰은 다시 로그인
}
async function stLog(who: string, what: string, target: string, before: any, after: any) {
  await q(db.from('settings_log').insert({ at: nowStr(), who, what, target, before: String(before ?? ''), after: String(after ?? '') }));
}

// ═════════════════ 작업기록 앱 (wl) ═════════════════
const KINDS: any = {
  motor: { sheet: '모터재권선', title: '모터 재권선', fields: [
    ['ledgerNo', '작업번호', 'text'], ['customer', '고객·설비', 'text'], ['maker', '제조사', 'text'],
    ['target', '권선 대상', 'pick', ['고정자', '회전자']], ['kw', '출력(kW)', 'num'],
    ['poles', '극수', 'list', ['2', '4', '6', '8', '10', '12']], ['volt', '전압(V)', 'list', ['220', '380', '440', '3300', '6600']],
    ['hz', '주파수(Hz)', 'list', ['60', '50']], ['rpm', '회전수(rpm)', 'num'], ['slots', '슬롯수', 'num'],
    ['windType', '권선형식(2층 중첩권, 단층 중첩권/동심권)', 'pick', ['2층 중첩권', '단층 중첩권', '단층 동심권']],
    ['wire', '코일선경(mm)', 'wire', ['0.7', '0.75', '0.8', '0.85', '0.9', '0.95', '1.0', '1.1', '1.2', '1.3', '1.4']],
    ['strands', '가닥수', 'num'], ['turns', '코일턴수', 'num'], ['series', '직렬수', 'text'], ['parallel', '병렬수', 'text'],
    ['pitch', '피치', 'text'], ['conn', '결선', 'pick', ['1Y', '2Y', '3Y', '4Y', '1Δ', '2Δ', '3Δ', '4Δ', '1Y-Δ', '2Y-Δ', '3Y-Δ', '4Y-Δ']],
    ['leads', '리드수', 'num'], ['coilKg', '코일무게(kg)', 'num'], ['memo', '메모', 'area'],
  ] },
  coil: { sheet: '마그네틱코일', title: '마그네틱 코일', fields: [
    ['ledgerNo', '작업번호', 'text'], ['maker', '제조사', 'text'], ['model', '모델명', 'text'],
    ['size', '코일 배치 타입', 'select', ['단일 코일형', '다극코일형', '기타']],
    ['ringID', '보빈 내경(mm)', 'num', [], { when: 'size', is: '단일 코일형' }], ['ringOD', '보빈 외경(mm)', 'num', [], { when: 'size', is: '단일 코일형' }],
    ['ringH', '보빈 높이(mm)', 'num', [], { when: 'size', is: '단일 코일형' }],
    ['coilPoles', '극편 개수', 'select', ['2', '4', '6', '8', '12'], { when: 'size', is: '다극코일형' }],
    ['mpID', '내경 ID(mm)', 'num', [], { when: 'size', is: '다극코일형' }], ['mpOD', '코어 외경 OD(mm)', 'num', [], { when: 'size', is: '다극코일형' }],
    ['mpH', '극편 높이 H(mm)', 'num', [], { when: 'size', is: '다극코일형' }],
    ['coilVolt', '코일전압(V)', 'list', ['24', '110', '220', '380', '440']], ['acdc', 'AC/DC', 'list', ['AC', 'DC']],
    ['hz', '주파수(Hz)', 'list', ['60', '50', '50/60']], ['turns', '코일턴수', 'num'],
    ['wire', '코일선경(mm)', 'wire', ['0.7', '0.75', '0.8', '0.85', '0.9', '0.95', '1.0', '1.1', '1.2', '1.3', '1.4']],
    ['ohm', '코일저항(Ω)', 'num'], ['bobbin', '보빈치수(내경, 외경, 높이)', 'text', [], { when: 'size', is: '기타' }],
    ['coilG', '코일무게(g)', 'num'], ['memo', '메모', 'area'],
  ] },
};
const RANGES = {
  motor: { kw: [0.1, 2000], rpm: [100, 3600], slots: [6, 200], strands: [1, 40], turns: [1, 300], leads: [3, 12], coilKg: [0.05, 1000], wire: [0.1, 3.0] },
  coil: { turns: [10, 30000], ohm: [0.01, 10000], wire: [0.05, 3.0], coilG: [1, 100000], ringID: [1, 1000], ringOD: [1, 1500], ringH: [1, 1000], mpID: [1, 1000], mpOD: [1, 1500], mpH: [1, 1000] },
};
const ADMIN_LITE = ['stats'];
const GUIDE_URL: any = { mp: 'https://s2badaro-tech.github.io/gwonseon-home/worklog/guide_mp.jpg' };
function kindDef(k: string) { const d = KINDS[k]; if (!d) err('알 수 없는 종류: ' + k); return d; }
function cellTxt(v: any) { const s = String(v ?? ''); return /^[=+\-@]/.test(s) ? "'" + s : s; }
function vget(r: any, key: string) { const v = r.vals ? r.vals[key] : undefined; return v === undefined || v === null ? '' : String(v); }
function sizeFix(v: string) { return v === '링형' ? '단일 코일형' : v; }

async function wlKinds() {
  const hidden: string[] = await getSetting('wl.hidden', []);
  const lists: any = await getSetting('wl.lists', {});
  const H: any = {}; hidden.forEach((t) => { t = String(t).replace(/\s*:\s*/, ':').trim(); if (t) H[t] = 1; });
  const out: any = {};
  Object.keys(KINDS).forEach((k) => {
    const tag = k === 'motor' ? '모터:' : '코일:';
    out[k] = { title: KINDS[k].title, fields: KINDS[k].fields.filter((f: any) => !H[f[1]] && !H[tag + f[1]]).map((f: any) => {
      const l = lists[tag + f[1]] || lists[f[1]]; const g = f.slice(); if (l && l.length) g[3] = l; return g;
    }) };
  });
  return out;
}
async function getConfig(token: any) {
  let m: Me;
  try { m = await me(token, 'wl'); } catch (_e) { return { login: true }; }
  return { kinds: await wlKinds(), me: { name: m.name, admin: m.admin, owner: m.owner, mustChange: m.mustChange }, opts: { editOwnOnly: (await getSetting('wl.editOwnOnly', false)) === true }, ranges: RANGES };
}
async function findSame(kind: string, key: string, value: any, token: any) {
  await me(token, 'wl');
  const def = kindDef(kind), f = def.fields.find((x: any) => x[0] === key);
  const want = String(value ?? '').replace(/\s+/g, '').toLowerCase();
  if (!f || !want) return [];
  let rows: any[];
  if (key === 'ledgerNo') rows = await q(db.from('work_records').select('*').eq('kind', kind).ilike('ledger_no', '%' + String(value).trim().replace(/[%_]/g, '') + '%').order('seq').limit(200));
  else rows = await q(db.from('work_records').select('*').eq('kind', kind).order('seq'));
  const sumKeys = kind === 'motor' ? ['target', 'kw', 'poles'] : ['size', 'turns', 'wire'];
  return rows.filter((r) => vget(r, key).replace(/\s+/g, '').toLowerCase() === want).slice(0, 20)
    .map((r) => ({ id: r.record_id, date: r.recorded_at, author: r.author, sum: sumKeys.map((k) => vget(r, k)).filter(String).join(' ') }));
}
// v2 (2단계 오프라인 저장): 휴대폰이 같은 저장을 두 번 보내도(신호가 끊겨 대답을 못 받은 경우) 한 번만 처리.
// 요청ID를 먼저 선점하고, 끝나면 결과를 남겨 둠. 같은 ID가 또 오면 남겨 둔 결과를 그대로 돌려줌.
async function onceReq(reqId: any, fn: () => Promise<any>): Promise<any> {
  const id = String(reqId || '').slice(0, 80);
  if (!id) return fn();
  const { error } = await db.from('req_claims').insert({ req_id: id });
  if (error) {
    if (!/duplicate|unique/i.test(error.message)) err('저장소 오류: ' + error.message);
    for (let i = 0; i < 10; i++) {
      const r: any = await q(db.from('req_claims').select('result').eq('req_id', id).maybeSingle());
      if (r && r.result) return Object.assign({}, r.result, { dup: true });
      await new Promise((ok) => setTimeout(ok, 500));
    }
    err('응답 없음 (같은 기록을 저장하는 중입니다)');
  }
  try {
    const out = await fn();
    await db.from('req_claims').update({ result: out ?? { ok: true } }).eq('req_id', id);
    return out;
  } catch (e) {
    await db.from('req_claims').delete().eq('req_id', id);
    throw e;
  }
}
async function saveRecord(rec: any, token: any) {
  const m = await me(token, 'wl');
  rec = rec || {};
  const kind = rec.kind, def = kindDef(kind), now = nowStr();
  const old: any = rec.id ? await q(db.from('work_records').select('*').eq('record_id', String(rec.id)).maybeSingle()) : null;
  if (old && old.kind !== kind) err('기록 종류가 맞지 않습니다.');
  if (old && (await getSetting('wl.editOwnOnly', false)) === true && !m.admin && normName(old.author) !== normName(m.name)) err('[권한] 남의 기록은 관리자만 고칠 수 있습니다. 관리자에게 말해 주세요.');
  const vals: any = Object.assign({}, old ? old.vals : {});
  def.fields.forEach((f: any) => {
    if (!rec.values || rec.values[f[0]] === undefined) return; // 화면에서 숨긴 칸은 그대로 둠
    let v: any = String(rec.values[f[0]]).trim();
    if (f[2] === 'num' && v !== '' && !isNaN(Number(v))) v = String(Number(v));
    vals[f[0]] = v;
  });
  let photo = old ? old.photo : '';
  if (rec.photo && rec.photo.data) {
    const id = String(rec.id || old?.record_id || 'R' + Date.now());
    const url = await google('uploadPhoto', { name: rec.photo.name || id + '.jpg', type: rec.photo.type || 'image/jpeg', data: rec.photo.data });
    photo = (photo ? photo + '\n' : '') + url;
  }
  if (old) {
    await q(db.from('work_records').update({ vals, photo, ledger_no: vals.ledgerNo || '', edited_at: now, editor: m.name }).eq('record_id', old.record_id));
    const logs: any[] = [];
    def.fields.concat([[null, '사진']]).forEach((f: any) => {
      const a = f[0] ? cellTxt(vget(old, f[0])) : cellTxt(old.photo), b = f[0] ? cellTxt(vals[f[0]] ?? '') : cellTxt(photo);
      if (a !== b) logs.push({ at: now, who: m.name, kind_title: def.title, record_id: old.record_id, ledger_no: cellTxt(vals.ledgerNo || ''), field: f[1], before: a, after: f[1] === '사진' ? '(사진 추가) ' + b : b });
    });
    if (logs.length) await q(db.from('work_edits').insert(logs));
    return { ok: true, id: old.record_id };
  }
  const id = String(rec.id || 'R' + Date.now());
  // v2: 신호가 없어 늦게 올라온 기록은 휴대폰에서 실제로 저장한 시각으로 남김
  await q(db.from('work_records').insert({ record_id: id, kind, recorded_at: usedAt(rec.ts) || now, author: m.name, ledger_no: vals.ledgerNo || '', vals, photo }));
  return { ok: true, id };
}
async function recordHistory(token: any, id: any) {
  await me(token, 'wl');
  const r: any[] = await q(db.from('work_edits').select('*').eq('record_id', String(id)).order('id', { ascending: false }).limit(100));
  return r.map((x) => ({ when: x.at, who: x.who, field: x.field, from: x.before, to: x.after }));
}
async function getGuide(token: any, key: any) { await me(token, 'wl'); const u = GUIDE_URL[key]; if (!u) err('그림이 없습니다'); return u; }
function recLabel(k: string, r: any, withExtra: boolean) {
  const g = (x: string) => vget(r, x);
  if (k === 'motor') return [g('target'), g('kw') && g('kw') + 'kW', g('poles') && g('poles') + 'P', withExtra ? g('customer') : ''].filter(String).join(withExtra ? ' · ' : ' ');
  return [sizeFix(g('size')), withExtra && g('coilPoles') ? g('coilPoles') + '극' : '', g('turns') && g('turns') + '턴', withExtra ? g('maker') : ''].filter(String).join(withExtra ? ' · ' : ' ');
}
async function recentRecords(token: any, days: any) {
  await me(token, 'wl');
  days = Math.min(Math.max(parseInt(days, 10) || 30, 1), 400);
  const from = dayStr(Date.now() - (days - 1) * DAY);
  const rows: any[] = await q(db.from('work_records').select('*').or('recorded_at.gte.' + from + ',edited_at.gte.' + from).limit(5000));
  const list: any[] = [];
  rows.forEach((r) => {
    const base = { id: r.record_id, kind: r.kind, title: KINDS[r.kind].title, no: vget(r, 'ledgerNo'), label: recLabel(r.kind, r, true), photo: !!r.photo };
    if (r.recorded_at && r.recorded_at.slice(0, 10) >= from) list.push(Object.assign({ when: r.recorded_at, type: '새 기록', who: r.author }, base));
    if (r.edited_at && r.edited_at.slice(0, 10) >= from) list.push(Object.assign({ when: r.edited_at, type: '수정', who: r.editor }, base));
  });
  list.sort((a, b) => (a.when < b.when ? 1 : a.when > b.when ? -1 : 0));
  return list.slice(0, 500);
}
function recOut(def: any, r: any) {
  const v: any = {}; def.fields.forEach((f: any) => { v[f[0]] = vget(r, f[0]); });
  if (v.size !== undefined) v.size = sizeFix(v.size);
  return { id: r.record_id, date: r.recorded_at, author: r.author, photo: r.photo || '', edited: r.edited_at || '', values: v };
}
async function allRecords(kind: string) {
  const out: any[] = [];
  for (let from = 0; ; from += 1000) {
    const r: any[] = await q(db.from('work_records').select('*').eq('kind', kind).order('seq', { ascending: false }).range(from, from + 999));
    out.push(...r); if (r.length < 1000) break;
  }
  return out;
}
async function listRecords(kind: string, token: any) {
  await me(token, 'wl'); const def = kindDef(kind);
  return (await allRecords(kind)).map((r) => recOut(def, r));
}
async function listRecordsPage(kind: string, token: any, start: any, count: any) {
  await me(token, 'wl'); const def = kindDef(kind);
  const keys = def.fields.map((f: any) => f[0]);
  start = Math.max(0, parseInt(start, 10) || 0);
  count = Math.min(Math.max(parseInt(count, 10) || 300, 1), 1000);
  const { count: total, error } = await db.from('work_records').select('record_id', { count: 'exact', head: true }).eq('kind', kind);
  if (error) err('저장소 오류: ' + error.message);
  if (start >= (total || 0)) return { total: total || 0, keys, rows: [] };
  const rows: any[] = await q(db.from('work_records').select('*').eq('kind', kind).order('seq', { ascending: false }).range(start, start + count - 1));
  return { total: total || 0, keys, rows: rows.map((r) => [r.record_id, r.recorded_at, r.author, r.photo || '', r.edited_at || ''].concat(keys.map((k: string) => k === 'size' ? sizeFix(vget(r, k)) : vget(r, k)))) };
}
async function wlStats() {
  const month = today().slice(0, 7), P = await people();
  const kinds = [];
  for (const k of Object.keys(KINDS)) {
    const x: any = { title: KINDS[k].title, total: 0, month: 0, edited: 0, authors: {} };
    for (let from = 0; ; from += 1000) {
      const r: any[] = await q(db.from('work_records').select('recorded_at,author,edited_at').eq('kind', k).order('seq').range(from, from + 999));
      r.forEach((y) => { x.total++; if (String(y.recorded_at).indexOf(month) === 0) x.month++; if (y.edited_at) x.edited++; const w = y.author || '이름없음'; x.authors[w] = (x.authors[w] || 0) + 1; });
      if (r.length < 1000) break;
    }
    x.authors = Object.keys(x.authors).map((w) => [w, x.authors[w]]).sort((p: any, q2: any) => q2[1] - p[1]);
    kinds.push(x);
  }
  return { month, users: P.length, kinds };
}
// 엑셀로 내려받기용: 시트와 같은 칸 순서
async function wlExport() {
  const out: any = {};
  for (const k of Object.keys(KINDS)) {
    const def = KINDS[k], extraKeys: string[] = [];
    const rows = (await allRecords(k)).reverse();
    rows.forEach((r) => Object.keys(r.extra || {}).forEach((h) => { if (extraKeys.indexOf(h) < 0) extraKeys.push(h); }));
    const head = ['기록ID', '기록일시', '작성자'].concat(def.fields.map((f: any) => f[1]), extraKeys, ['사진', '수정일시', '수정자']);
    out[k] = { name: def.sheet, head, rows: rows.map((r) => [r.record_id, r.recorded_at, r.author].concat(def.fields.map((f: any) => vget(r, f[0])), extraKeys.map((h) => String((r.extra || {})[h] ?? '')), [r.photo, r.edited_at, r.editor])) };
  }
  const ed: any[] = await q(db.from('work_edits').select('*').order('id'));
  out.edits = { name: '수정기록', head: ['수정일시', '수정자', '종류', '기록ID', '작업번호', '칸', '바꾸기 전', '바꾼 후'], rows: ed.map((e) => [e.at, e.who, e.kind_title, e.record_id, e.ledger_no, e.field, e.before, e.after]) };
  return out;
}
const WL_ADMIN: any = {
  listUsers: async (m: Me) => m.P.map((u) => { const R = roles(m.P, u); return { name: u.name, admin: R.wlAdmin, owner: R.owner, temp: u.temp, reg: u.reg_at, last: u.last_seen }; }),
  addUser: async (m: Me, a: any) => {
    const name = String(a.name || '').trim().replace(/^[=+\-@']+/, '');
    if (!name) err('이름을 적어주세요.'); if (name.length > 20) err('이름이 너무 깁니다.');
    if (findP(m.P, name)) err(name + " 님은 이미 등록되어 있습니다. (PIN을 잊었으면 'PIN 초기화')");
    const salt = uuid();
    await q(db.from('people').insert({ name, wl_admin: !!a.admin, salt, pin_hash: await pinHash(salt, TEMP_PIN), temp: true, reg_at: nowStr(), sort: m.P.length + 1 }));
    return { name, pin: TEMP_PIN, site: 'https://s2badaro-tech.github.io/gwonseon-home/' };
  },
  deleteUser: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('없는 사용자입니다: ' + a.name);
    if (normName(u.name) === normName(m.name)) err('자기 자신은 지울 수 없습니다.');
    if (roles(m.P, u).owner) err('운영자는 여기서 바꾸거나 지울 수 없습니다.');
    if (roles(m.P, u).wlAdmin && m.P.filter((x) => roles(m.P, x).wlAdmin).length <= 1) err('관리자가 한 명은 있어야 합니다.');
    // 기록은 이름으로 남아 있으므로 그대로. 명단에서만 '사용 안 함'으로 (줄을 지우지 않음)
    await q(db.from('people').update({ off: true, salt: '', pin_hash: '' }).eq('id', u.id));
    await q(db.from('sessions').delete().eq('person_id', u.id));
    await stLog(m.name, '사용 안 함 (작업기록 관리에서 삭제)', u.name, '사용', '사용 안 함');
    return { ok: true };
  },
  resetPin: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('없는 사용자입니다: ' + a.name);
    if (normName(u.name) === normName(m.name)) err("내 PIN은 위쪽 '내 정보' → PIN 바꾸기에서 바꿔주세요.");
    await resetPinRow(u);
    return { name: u.name, pin: TEMP_PIN, site: 'https://s2badaro-tech.github.io/gwonseon-home/' };
  },
  setRole: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('없는 사용자입니다: ' + a.name);
    if (normName(u.name) === normName(m.name)) err('자기 역할은 바꿀 수 없습니다.');
    if (roles(m.P, u).owner) err('운영자는 여기서 바꾸거나 지울 수 없습니다.');
    await q(db.from('people').update({ wl_admin: !!a.admin }).eq('id', u.id));
    return { ok: true };
  },
  stats: async () => wlStats(),
  statsNow: async () => wlStats(),
  recent: async () => {
    const rows: any[] = await q(db.from('work_records').select('*').order('seq', { ascending: false }).limit(300));
    const list: any[] = [];
    rows.forEach((r) => {
      const label = (vget(r, 'ledgerNo') ? '#' + vget(r, 'ledgerNo') + ' ' : '') + recLabel(r.kind, r, false);
      list.push({ when: r.recorded_at, type: '새 기록', who: r.author, kind: KINDS[r.kind].title, label });
      if (r.edited_at) list.push({ when: r.edited_at, type: '수정', who: r.editor, kind: KINDS[r.kind].title, label });
    });
    list.sort((a, b) => (a.when < b.when ? 1 : a.when > b.when ? -1 : 0));
    return list.slice(0, 30);
  },
  links: async () => ({ sheet: '', photos: await getSetting('wl.photoFolder', ''), site: 'https://s2badaro-tech.github.io/gwonseon-home/worklog/', excel: true }),
  exportAll: async () => wlExport(),
  refreshCache: async () => ({ ok: true }),
  getOpts: async () => ({ editOwnOnly: (await getSetting('wl.editOwnOnly', false)) === true }),
  setOpt: async (_m: Me, a: any) => { if (a.key === 'editOwnOnly') await putSetting('wl.editOwnOnly', !!a.on); return { editOwnOnly: (await getSetting('wl.editOwnOnly', false)) === true }; },
  // 숨길 칸 · 선택목록 (예전 시트 '설정' 탭 D·F·G열)
  getLists: async () => ({ hidden: await getSetting('wl.hidden', []), lists: await getSetting('wl.lists', {}) }),
  setLists: async (m: Me, a: any) => {
    const hidden = String(a.hidden || '').split(/\n/).map((x) => x.trim()).filter(String);
    const lists: any = {};
    String(a.lists || '').split(/\n/).forEach((line) => {
      const i = line.indexOf('='); if (i < 0) return;
      const t = line.slice(0, i).replace(/\s*:\s*/, ':').trim(), items = line.slice(i + 1).split(/[,，、]/).map((x) => x.trim()).filter(String);
      if (t && items.length) lists[t] = items;
    });
    const oldH = await getSetting('wl.hidden', []), oldL = await getSetting('wl.lists', {});
    await putSetting('wl.hidden', hidden); await putSetting('wl.lists', lists);
    await q(db.from('work_edits').insert({ at: nowStr(), who: m.name, kind_title: '(설정)', record_id: '', ledger_no: '', field: '숨길 칸·선택목록', before: JSON.stringify({ hidden: oldH, lists: oldL }).slice(0, 5000), after: JSON.stringify({ hidden, lists }).slice(0, 5000) }));
    return { hidden, lists };
  },
  changeLog: async () => {
    const r: any[] = await q(db.from('work_edits').select('*').order('id', { ascending: false }).limit(80));
    return r.map((x) => ({ when: x.at, who: x.who, kind: x.kind_title, id: x.record_id, no: x.ledger_no, field: x.field, from: x.before, to: x.after }));
  },
  backupInfo: async () => backupInfo(),
  backupNow: async () => backupNow(),
};
async function wlAdmin(token: any, action: string, args: any) {
  const m = await me(token, 'wl');
  if (!m.admin) err('관리자만 쓸 수 있는 기능입니다.');
  if (!m.owner && ADMIN_LITE.indexOf(action) < 0) err('운영자만 쓸 수 있는 기능입니다.');
  const fn = WL_ADMIN[action]; if (!fn) err('없는 기능입니다: ' + action);
  return fn(m, args || {});
}

// ═════════════════ 코일 관리 앱 (co) ═════════════════
const ST_USE = '사용중', ST_EMPTY = '소진', TYPE_DEF = '일반 환선';
const TYPES = ['출고', '입고', '실사조정'];
// v3 (3단계): 인롤 종류는 coil_types 표의 spec(규격)·unit(1대당 무게)로 정함. 관리 화면에서 이름·규격·1대당 무게를 고칠 수 있음.
const TYPE_ALIAS: any = { 'in-roll 환선': '인롤 4.5 환선', 'in-roll 나각선': '인롤 3.5×7 평각선', 'in-roll 4.0 환선': '인롤 4.5 환선', 'in-roll 3.0×7.3 나각선': '인롤 3.5×7 평각선' };
// 코일 선종(종류) 기본값: AIW가 주력. 규격 목록은 선종마다 따로 (2026-11-05 재고표 기준, 관리 화면에서 고침)
const KIND_DEF = ['AIW', '인버터', '인롤'];
const SPECS_DEF: any = {
  AIW: ['0.1', '0.12', '0.15', '0.18', '0.2', '0.23', '0.25', '0.28', '0.3', '0.32', '0.35', '0.37', '0.4', '0.45', '0.5', '0.55', '0.6', '0.65', '0.7', '0.75', '0.8', '0.85', '0.9', '0.95', '1.0', '1.05', '1.1', '1.15', '1.2', '1.25', '1.3', '1.35', '1.4', '1.45', '1.5', '1.6', '1.7', '1.8', '1.9', '2.0', '2.1', '2.2', '2.3', '2.4'],
  '인버터': ['0.8', '0.9', '1.1', '1.2', '1.3', '1.4'],
};
const CO_VERSION = 'v53';
const QR_APP_URL = 'https://s2badaro-tech.github.io/gwonseon-home/coil/';
const COIL_DEF = { safety: 50, mail: '', kinds: KIND_DEF, specsBy: SPECS_DEF, locs: [], specs: [], prefix: 'C-', emptyKg: 0.2, defTare: 1, bobbinTxt: '' };
async function coSet() {
  const s = Object.assign({}, COIL_DEF, await getSetting('coil.settings', {}));
  return Object.assign(s, { bobbins: [] as any[] });
}
function specTxt(spec: any) { const s = String(spec ?? '').trim(); return /^\d*\.?\d+$/.test(s) ? String(Number(s)) : s.replace(/\s*[xX*×]\s*/g, '×'); }
function specKey(spec: any, kind: any, type: any) {
  type = String(type || '').trim();
  return String(spec || '').trim() + '|' + String(kind || '').trim().toUpperCase() + (type && type !== TYPE_DEF ? '|' + type : '');
}
function normNo(s: any, S: any) {
  s = String(s || '').trim().toUpperCase().replace(/\s+/g, '');
  if (!s) return '';
  const pre = String(S.prefix || 'C-').toUpperCase(), m = s.match(/(\d+)$/);
  if (!m) return s;
  return pre + ('000' + Number(m[1])).slice(-Math.max(3, String(Number(m[1])).length));
}
async function coTypes() {
  const S = await coSet();
  const rows: any[] = await q(db.from('coil_types').select('*').order('sort').order('name'));
  const out: any[] = [];
  rows.forEach((r) => {
    const name = TYPE_ALIAS[r.name] || r.name; if (out.some((x) => x.name === name)) return;
    out.push({ name, tare: r.tare === null || r.tare === undefined ? null : Number(r.tare), alert: r.alert !== null && Number(r.alert) > 0 ? Number(r.alert) : null,
      spec: name === TYPE_DEF ? '' : specTxt(r.spec || ''), unit: Number(r.unit) > 0 ? Number(r.unit) : null });
  });
  if (!out.some((x) => x.name === TYPE_DEF)) out.unshift({ name: TYPE_DEF, tare: S.defTare, alert: S.safety, spec: '', unit: null });
  return out;
}
function typeOf(T: any[], name: any) {
  name = String(name || '').trim() || TYPE_DEF; name = TYPE_ALIAS[name] || name;
  return T.find((x) => x.name === name) || T.find((x) => x.name === TYPE_DEF);
}
async function readCoils(T?: any[]) {
  T = T || await coTypes();
  const out: any[] = [];
  for (let from = 0; ; from += 1000) {
    const r: any[] = await q(db.from('coils').select('*').order('seq').range(from, from + 999));
    r.forEach((c) => {
      const t = typeOf(T!, c.ctype), t0 = c.tare === null || c.tare === undefined ? NaN : Number(c.tare);
      const noTare = t.tare != null && (!isFinite(t0) || (t0 <= 0 && t.tare > 0)), tare = noTare ? t.tare : isFinite(t0) ? t0 : 0;
      out.push({ no: String(c.no).toUpperCase(), spec: specTxt(c.spec), kind: c.kind, maker: c.maker, type: t.name, tare, tareSet: true, tareDef: noTare,
        rem: Number(c.rem) || 0, loc: c.loc, status: c.status || ST_USE, reg: c.reg_at, changed: c.changed_at, memo: c.memo });
    });
    if (r.length < 1000) break;
  }
  return out;
}
function coilOut(c: any) { return { no: c.no, spec: c.spec, kind: c.kind, type: c.type, maker: c.maker, tare: c.tare, tareSet: c.tareSet, rem: r2(c.rem), loc: c.loc, status: c.status, reg: c.reg, changed: c.changed, memo: c.memo }; }
async function readSpecs() {
  const r: any[] = await q(db.from('coil_specs').select('*'));
  const m: any = {}; r.forEach((x) => { m[x.key] = { safety: x.safety === null ? NaN : Number(x.safety), order: x.order_state, orderAt: x.order_at, orderMemo: x.order_memo }; });
  return m;
}
async function stockCalc() {
  const T = await coTypes(), C = await readCoils(T), P = await readSpecs(), g: any = {};
  C.forEach((c) => {
    const k = specKey(c.spec, c.kind, c.type);
    if (!g[k]) g[k] = { spec: c.spec, kind: c.kind, type: c.type, total: 0, count: 0, coils: [] };
    if (c.status !== ST_EMPTY) { g[k].total += c.rem; g[k].count++; }
    g[k].coils.push(coilOut(c));
  });
  Object.keys(P).forEach((k) => { if (!g[k] && P[k].order) { const p = k.split('|'); g[k] = { spec: p[0], kind: p[1], type: p[2] || TYPE_DEF, total: 0, count: 0, coils: [] }; } });
  return Object.keys(g).map((k) => {
    const x = g[k], p = P[k] || {};
    x.total = r2(x.total);
    const tt = typeOf(T, x.type); x.safety = tt.alert; x.unit = tt.unit || null;
    if (x.unit) x.units = Math.floor(x.total / x.unit + 1e-9);
    x.order = p.order || ''; x.orderAt = p.orderAt || ''; x.orderMemo = p.orderMemo || '';
    x.low = x.safety != null && x.total < x.safety;
    x.coils.sort((a: any, b: any) => (a.no < b.no ? -1 : 1));
    return x;
  }).sort((a, b) => (b.low - a.low) || (num(a.spec) - num(b.spec)) || (a.kind < b.kind ? -1 : 1));
}
async function coInit(token: any) {
  const m = await me(token, 'co'), S = await coSet();
  return { me: { name: m.name, admin: m.admin, owner: m.owner, mustChange: m.mustChange }, version: CO_VERSION, users: m.P.filter((u) => !u.off).map((u) => u.name),
    worklogSite: 'https://s2badaro-tech.github.io/gwonseon-home/worklog/', sheetUrl: '', excel: m.admin,
    appUrl: QR_APP_URL, kinds: S.kinds, specsBy: S.specsBy, mail: m.admin ? S.mail : '', locs: S.locs, specs: S.specs, prefix: S.prefix, bobbins: [], bobbinTxt: S.bobbinTxt, defTare: S.defTare, types: await coTypes(),
    targets: await targets(), stock: await stockCalc() };
}
// 작업기록 앱의 최근 작업 (오늘 + 지난 2일)
async function recentJobs() {
  const to = today(), from = dayStr(Date.now() - 2 * DAY), byNo: any = {};
  const rows: any[] = await q(db.from('work_records').select('*').gte('recorded_at', from).order('seq', { ascending: false }).limit(800));
  rows.forEach((r) => {
    const no = vget(r, 'ledgerNo').trim(); if (!no) return;
    const at = r.recorded_at, day = at.slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}/.test(at) || day < from || day > to) return;
    const motor = r.kind === 'motor';
    const x = { no, src: motor ? '모터' : '코일', at, today: day === to, who: r.author,
      desc: (motor ? ['customer', 'target'] : ['maker', 'model']).map((k) => vget(r, k).trim()).filter(String).join(' '),
      kw: motor ? vget(r, 'kw').trim() : '', wire: vget(r, 'wire').trim() };
    if (!byNo[no] || byNo[no].at < at) byNo[no] = x;
  });
  return Object.keys(byNo).map((k) => byNo[k]).sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 60);
}
async function targets() {
  const out: string[] = [], seen: any = {};
  const add = (t: any) => { t = String(t || '').trim(); if (t && !seen[t]) { seen[t] = 1; out.push(t); } };
  const mv: any[] = await q(db.from('coil_moves').select('target').neq('target', '').order('seq', { ascending: false }).limit(300));
  mv.forEach((r) => add(r.target));
  const wr: any[] = await q(db.from('work_records').select('*').order('seq', { ascending: false }).limit(120));
  wr.forEach((r) => {
    const no = vget(r, 'ledgerNo').trim(); if (!no) return;
    const extra = (r.kind === 'motor' ? ['customer', 'target'] : ['maker', 'model']).map((k) => vget(r, k).trim()).filter(String).join(' ');
    add(no + (extra ? ' ' + extra : ''));
  });
  return out.slice(0, 80);
}
function moveOut(r: any, cancelled: boolean) {
  return { id: r.id, at: r.at, no: r.no, type: r.type, spec: specTxt(r.spec), kind: r.kind, worker: r.worker, target: r.target, mode: r.mode,
    gross: r.gross === null ? '' : Number(r.gross), delta: r.delta === null ? '' : Number(r.delta), before: r.before === null ? '' : Number(r.before), after: r.after === null ? '' : Number(r.after),
    by: r.by, memo: r.memo, kw: r.kw, cancelled, seq: r.seq, edits: Array.isArray(r.edits) ? r.edits : [] };
}
// f = {no, worker, target, from, to, type, id, before(seq: 이보다 옛날 것), limit}
async function history(f: any, limit: number, S?: any) {
  S = S || await coSet();
  let qy = db.from('coil_moves').select('*').order('seq', { ascending: false }).limit(Math.min(limit, 5000));
  if (f.id) qy = qy.eq('id', String(f.id));
  if (f.no) qy = qy.eq('no', normNo(f.no, S));
  if (f.worker) qy = qy.eq('worker', String(f.worker));
  if (f.type) qy = qy.eq('type', String(f.type));
  if (f.target) qy = qy.ilike('target', '%' + String(f.target).replace(/[%_]/g, '') + '%');
  if (f.from) qy = qy.gte('at', String(f.from).slice(0, 10));
  if (f.to) qy = qy.lt('at', String(f.to).slice(0, 10) + '~');
  if (f.before) qy = qy.lt('seq', Number(f.before));
  const rows: any[] = await q(qy);
  const ids = rows.map((r) => r.id), cancelled: any = {};
  for (let i = 0; i < ids.length; i += 300) {
    const c: any[] = await q(db.from('coil_moves').select('cancel_of').in('cancel_of', ids.slice(i, i + 300)));
    c.forEach((x) => { cancelled[x.cancel_of] = 1; });
  }
  return rows.map((r) => moveOut(r, !!cancelled[r.id]));
}
// v5 (4-3): 작업마다 '원래 선경×가닥 → 실제로 감은 조합 · 단면적 %'를 남김 (가닥 수 기준, 찍은 보빈 수가 아님)
async function savePlan(job: string, p: any, who: string) {
  const row = { job, orig: txt(p.orig), actual: txt(p.actual), ratio: isFinite(num(p.ratio)) ? num(p.ratio) : null, kind: txt(p.kind), by: who, at: nowStr() };
  if (!row.orig) return;
  await q(db.from('job_plans').upsert(row));
}
async function plansFor(jobs: string[]) {
  const L = Array.from(new Set(jobs.filter(String))); if (!L.length) return {};
  const out: any = {};
  for (let i = 0; i < L.length; i += 200) (await q(db.from('job_plans').select('*').in('job', L.slice(i, i + 200)))).forEach((r: any) => { out[r.job] = { orig: r.orig, actual: r.actual, ratio: r.ratio === null ? null : Number(r.ratio), kind: r.kind }; });
  return out;
}
async function getHistory(token: any, f: any) {
  await me(token, 'co');
  f = f || {};
  const lim = Math.min(Math.max(parseInt(f.limit, 10) || 300, 1), 1000);
  const rows = await history(f, lim + 1);
  const more = rows.length > lim; if (more) rows.pop();
  const sum: any = {}, by: any = {};
  rows.forEach((r) => {
    if (r.type !== '출고' || r.cancelled) return;
    const k = r.spec + 'mm ' + r.kind;
    sum[k] = r2((sum[k] || 0) - num(r.delta));
    by[r.worker || '-'] = r2((by[r.worker || '-'] || 0) - num(r.delta));
  });
  return { rows, used: sum, usedBy: by, more: more ? rows[rows.length - 1].seq : 0, plans: await plansFor(rows.map((r) => String(r.target || ''))) };
}
async function getCoil(token: any, no: any) {
  await me(token, 'co');
  const S = await coSet(); no = normNo(no, S);
  const T = await coTypes();
  const r: any = await q(db.from('coils').select('*').eq('no', no).maybeSingle());
  if (!r) err(no + ' 번 타래를 찾지 못했습니다. 번호를 다시 확인하고, 그래도 안 되면 관리자에게 알려 주세요.');
  const c = (await readCoilRow(r, T));
  return { coil: coilOut(c), history: await history({ no }, 15, S) };
}
async function readCoilRow(c: any, T: any[]) {
  const t = typeOf(T, c.ctype), t0 = c.tare === null || c.tare === undefined ? NaN : Number(c.tare);
  const noTare = t.tare != null && (!isFinite(t0) || (t0 <= 0 && t.tare > 0)), tare = noTare ? t.tare : isFinite(t0) ? t0 : 0;
  return { no: String(c.no).toUpperCase(), spec: specTxt(c.spec), kind: c.kind, maker: c.maker, type: t.name, tare, tareSet: true, tareDef: noTare,
    rem: Number(c.rem) || 0, loc: c.loc, status: c.status || ST_USE, reg: c.reg_at, changed: c.changed_at, memo: c.memo };
}
async function findReq(reqId: any) {
  if (!reqId) return null;
  const r: any = (await q(db.from('coil_moves').select('*').eq('req_id', String(reqId)).order('seq', { ascending: false }).limit(1)))[0];
  if (!r) return null;
  return { id: r.id, no: r.no, before: Number(r.before), after: Number(r.after), delta: Number(r.delta), rem: Number(r.after), dup: true, low: '' };
}
function usedAt(ts: any) {
  const t = Number(ts), now = Date.now();
  if (!isFinite(t) || t <= 0) return '';
  if (now - t < 3 * 60000 || now - t > 7 * DAY) return '';
  const k = kst(t); return k.slice(0, 10) + ' ' + k.slice(11, 16);
}
function newMoveId() { const k = kst(); return 'L' + k.slice(2, 4) + k.slice(5, 7) + k.slice(8, 10) + k.slice(11, 13) + k.slice(14, 16) + k.slice(17, 19) + Math.floor(Math.random() * 90 + 10); }
async function logRow(o: any) {
  let id = newMoveId();
  for (let i = 0; i < 5; i++) {
    const { error } = await db.from('coil_moves').insert({ id, at: o.at || nowStr(), no: o.no, type: o.type, spec: o.spec, kind: o.kind, worker: txt(o.worker), target: txt(o.target), mode: o.mode || '',
      gross: o.gross === '' || o.gross === undefined ? null : o.gross, delta: o.delta, before: o.before, after: o.after, by: o.by, memo: txt(o.memo), req_id: o.reqId || '', kw: o.kw == null ? '' : txt(o.kw), cancel_of: o.cancelOf || '' });
    if (!error) return id;
    if (!/duplicate|unique/i.test(error.message)) err('저장소 오류: ' + error.message);
    id = newMoveId() + i;
  }
  err('기록 번호를 만들지 못했습니다. 다시 해 주세요.');
}
// 같은 타래를 두 사람이 동시에 저장할 때 숫자가 꼬이지 않게: 잔량이 그대로일 때만 바꿈
async function setRem(no: string, before: number, after: number, status: string, extra: any = {}) {
  const r: any[] = await q(db.from('coils').update(Object.assign({ rem: after, status, changed_at: nowStr() }, extra)).eq('no', no).eq('rem', before).select('no'));
  if (!r.length) err('방금 다른 사람이 이 타래를 저장했습니다. 타래를 다시 열고 한 번 더 해 주세요.');
}
async function saveMove(token: any, a: any) {
  const m = await me(token, 'co');
  a = a || {};
  if (TYPES.indexOf(a.type) < 0) err('쓰기·추가·무게 맞추기 중에서 하나를 골라주세요.');
  if (!m.admin && a.type !== '출고') err('코일 추가와 무게 맞추기는 관리자만 할 수 있습니다.');
  if (!m.admin) a.worker = m.name;
  const v = num(a.value);
  if (!isFinite(v) || v < 0) err('무게(kg)를 숫자로 넣어주세요.');
  if (a.type === '출고' && !String(a.target || '').trim()) err('작업번호를 넣어주세요.');
  if (String(a.kw ?? '').trim() !== '') {
    const k = num(a.kw);
    if (!isFinite(k) || k <= 0 || k > 5000 || !/\d/.test(String(a.kw))) err('kW는 숫자로 넣어주세요 (예: 37). 지금: ' + String(a.kw).slice(0, 20));
    a.kw = String(r2(k));
  }
  const at = usedAt(a.ts);
  const dup = await findReq(a.reqId); if (dup) return dup;
  const S = await coSet(), T = await coTypes(), no = normNo(a.no, S);
  const row: any = await q(db.from('coils').select('*').eq('no', no).maybeSingle());
  if (!row) err(no + ' 번 타래가 없습니다.');
  const c = await readCoilRow(row, T);
  const before = r2(c.rem), gross = a.mode === 'gross';
  let after: number, tareMsg = '';
  if (gross) {
    if (v < c.tare) err('저울 무게(' + v + 'kg)가 빈 보빈 무게(' + c.tare + 'kg)보다 작습니다. 보빈째 저울에 올렸는지 다시 확인해 주세요.');
    after = r2(v - c.tare);
    if (a.type === '입고' && after < before) err('코일을 추가했는데 무게가 줄었습니다. 저울을 다시 확인하세요. 무게를 바로잡으려면 ‘무게 맞추기’를 쓰세요.');
  } else {
    after = a.type === '출고' ? r2(before - v) : a.type === '입고' ? r2(before + v) : r2(v);
  }
  if (after < 0) err('남은 코일이 ' + before + 'kg인데 ' + v + 'kg를 쓰면 0보다 작아집니다. 타래를 저울에 올려 ‘무게 맞추기’로 바로잡아 주세요.');
  if (a.type === '출고' && after > before) err('지난번보다 무게가 늘었습니다 (' + r2(before + c.tare) + 'kg → ' + v + 'kg, 보빈 포함). 저울을 다시 확인하거나 관리자에게 무게 맞추기를 부탁하세요.');
  const delta = r2(after - before), status = after <= S.emptyKg ? ST_EMPTY : ST_USE;
  await setRem(no, Number(row.rem), after, status, c.tareDef ? { tare: c.tare } : {});
  const id = await logRow({ no, type: a.type, spec: c.spec, kind: c.kind, worker: a.worker || m.name, target: a.target, mode: gross ? '저울 총무게' : '무게 직접', gross: gross ? v : '',
    delta, before, after, by: m.name, memo: [tareMsg, String(a.memo || '').trim(), at ? '늦게 보냄: ' + nowStr() : ''].filter(String).join(' / '), reqId: a.reqId, kw: a.kw, at });
  if (a.type === '입고') await clearOrder(c.spec, c.kind, c.type);
  if (a.type === '출고' && a.plan && txt(a.target)) await savePlan(txt(a.target), a.plan, m.name);
  const low = await checkLow(c.spec, c.kind, c.type);
  return { id, no, before, after, delta, status, low, tare: c.tare, tareMsg };
}
async function checkLow(spec: string, kind: string, type: string) {
  const all = await stockCalc(), x = all.find((s) => specKey(s.spec, s.kind, s.type) === specKey(spec, kind, type));
  if (!x || !x.low) return '';
  const dae = (kg: number) => x.unit ? Math.floor(kg / x.unit + 1e-9) + '대분 · ' : '';
  const msg = spec + 'mm ' + (kind || '') + (x.type && x.type !== TYPE_DEF ? ' ' + x.type : '') + ' 재고 ' + dae(x.total) + x.total + 'kg — 알림 기준 ' + dae(x.safety) + x.safety + 'kg 아래입니다.' + (x.order ? ' (발주완료 ' + x.orderAt + ')' : '');
  if (x.order) return msg;
  const S = await coSet(), k = specKey(spec, kind, type), sent = await getSetting('coil.mailed', {});
  if (S.mail && !(sent[k] && Date.now() - sent[k] < 6 * 3600000)) {
    sent[k] = Date.now(); await putSetting('coil.mailed', sent);
    bg(google('mail', { to: String(S.mail).split(/[,;\s]+/).filter(String).join(','), subject: '[코일 재고 부족] ' + spec + 'mm ' + (kind || '') + (x.type && x.type !== TYPE_DEF ? ' ' + x.type : ''),
      body: msg + '\n\n보유 타래 ' + x.count + '개\n' + x.coils.filter((t: any) => t.status !== ST_EMPTY).map((t: any) => ' ' + t.no + ' : ' + t.rem + 'kg ' + t.loc).join('\n') +
        '\n\n발주했으면 앱 재고 현황에서 ‘발주완료’를 눌러 주세요.\n' + QR_APP_URL }));
  }
  return msg;
}
async function addCoil(token: any, a: any) {
  const m = await me(token, 'co');
  if (!m.admin) err('코일 등록은 관리자만 할 수 있습니다.');
  a = a || {};
  const spec = specTxt(a.spec); if (!spec) err('규격(선경 mm)을 넣어주세요.');
  const S = await coSet(), T = await coTypes(), t = typeOf(T, a.ctype), ctype = t.name;
  const t0 = String(a.tare ?? '').trim() === '' ? NaN : num(a.tare), tare = isFinite(t0) && t0 >= 0 ? r2(t0) : t.tare;
  if (tare == null) err(ctype + '은(는) 빈 보빈 무게를 직접 넣어 주세요 (kg).');
  const v = num(a.value); if (!isFinite(v) || v < 0) err('코일 무게(kg)를 숫자로 넣어주세요.');
  const rem = a.mode === 'gross' ? r2(v - tare) : r2(v);
  if (rem < 0) err('저울 무게가 빈 보빈 무게보다 작습니다. 보빈째 저울에 올렸는지 확인해 주세요.');
  const dup = await findReq(a.reqId); if (dup) return dup;
  if (!txt(a.loc)) err('보관위치(선반)를 골라 주세요.');
  let no = a.no ? normNo(a.no, S) : await nextNo(S);
  const kind = (txt(a.kind) || (t.spec ? '인롤' : 'AIW')).toUpperCase();
  for (let i = 0; ; i++) {
    const { error } = await db.from('coils').insert({ no, spec, kind, maker: txt(a.maker), tare, ctype, rem, loc: txt(a.loc), status: rem <= S.emptyKg ? ST_EMPTY : ST_USE, reg_at: nowStr(), reg_by: m.name, changed_at: nowStr(), memo: txt(a.memo) });
    if (!error) break;
    if (!/duplicate|unique/i.test(error.message)) err('저장소 오류: ' + error.message);
    if (a.no || i > 5) err(no + ' 번은 벌써 다른 타래가 쓰고 있습니다. 번호 칸을 비워 두면 새 번호를 알아서 붙여 줍니다.');
    no = await nextNo(S);
  }
  await logRow({ no, type: '신규등록', spec, kind, worker: m.name, target: '', mode: a.mode === 'gross' ? '저울 총무게' : '라벨 순수무게', gross: a.mode === 'gross' ? v : '', delta: rem, before: 0, after: rem, by: m.name, memo: a.memo, reqId: a.reqId });
  await clearOrder(spec, kind, ctype);
  return { no, rem, tare };
}
async function nextNo(S: any) {
  const pre = String(S.prefix || 'C-').toUpperCase();
  const r: any[] = await q(db.from('coils').select('no').ilike('no', pre + '%'));
  let max = 0; r.forEach((x) => { const mm = String(x.no).match(/(\d+)$/); if (mm) max = Math.max(max, Number(mm[1])); });
  return pre + ('000' + (max + 1)).slice(-3);
}
async function editCoil(token: any, no: any, a: any) {
  const m = await me(token, 'co');
  if (!m.admin) err('타래 정보 수정은 관리자만 할 수 있습니다.');
  const S = await coSet(), T = await coTypes(); no = normNo(no, S); a = a || {};
  const row: any = await q(db.from('coils').select('*').eq('no', no).maybeSingle());
  if (!row) err(no + ' 번 타래가 없습니다.');
  const c: any = await readCoilRow(row, T);
  const map: any = { spec: ['규격(mm)', 'spec', 'spec'], kind: ['선종', 'kind', 'kind'], maker: ['제조사', 'maker', 'maker'], tare: ['공타래(kg)', 'tare', 'tare'], ctype: ['코일종류', 'type', 'ctype'], loc: ['보관위치', 'loc', 'loc'], status: ['상태', 'status', 'status'], memo: ['메모', 'memo', 'memo'] };
  const set: any = {}, diff: string[] = [], logs: any[] = [], now = nowStr();
  Object.keys(map).forEach((k) => {
    if (a[k] === undefined) return;
    let nv: any = k === 'tare' ? num(a[k]) : String(a[k]).trim();
    if (k === 'ctype') nv = typeOf(T, nv).name;
    if (k === 'tare' && !isFinite(nv)) return;
    if (k === 'spec') nv = specTxt(nv);
    if (k === 'kind') nv = nv.toUpperCase();
    if (String(nv) === String(c[map[k][1]])) return;
    set[map[k][2]] = k === 'tare' ? nv : txt(nv);
    diff.push(map[k][0] + ': ' + c[map[k][1]] + ' → ' + nv);
    logs.push({ at: now, who: m.name, no, field: map[k][0], before: txt(c[map[k][1]]), after: String(set[map[k][2]]) });
  });
  if (!diff.length) return { ok: true, changed: 0 };
  await q(db.from('coil_edits').insert(logs));
  set.changed_at = now;
  await q(db.from('coils').update(set).eq('no', no));
  await logRow({ no, type: '정보수정', spec: set.spec || c.spec, kind: set.kind || c.kind, worker: m.name, target: '', mode: '', gross: '', delta: 0, before: r2(c.rem), after: r2(c.rem), by: m.name, memo: diff.join(' / ') });
  return { ok: true, changed: diff.length };
}
function monthsBack(k: number) {
  const out: string[] = [], d = today().slice(0, 7); let y = Number(d.slice(0, 4)), mo = Number(d.slice(5, 7));
  for (let i = 0; i < k; i++) { out.push(y + '-' + ('0' + mo).slice(-2)); mo--; if (!mo) { mo = 12; y--; } }
  return out;
}
async function getMonthly(token: any) {
  await me(token, 'co');
  const months = monthsBack(6), want: any = {}; months.forEach((x) => { want[x] = 1; });
  const tot: any = {}; months.forEach((x) => { tot[x] = { used: 0, inn: 0, adj: 0, jobs: 0 }; });
  const agg: any[] = await q(db.rpc('coil_monthly', { p_from: months[months.length - 1] + '-01' }));
  const g: any = {};
  agg.forEach((o) => {
    if (!want[o.month]) return;
    const spec = specTxt(o.spec), k = spec + '|' + o.kind;
    const x = g[k] = g[k] || { spec, kind: o.kind, m: {} };
    const y = x.m[o.month] = x.m[o.month] || { used: 0, inn: 0, adj: 0 };
    y.used = r2(y.used + Number(o.used)); y.inn = r2(y.inn + Number(o.inn)); y.adj = r2(y.adj + Number(o.adj));
    tot[o.month].used = r2(tot[o.month].used + Number(o.used)); tot[o.month].inn = r2(tot[o.month].inn + Number(o.inn)); tot[o.month].adj = r2(tot[o.month].adj + Number(o.adj));
  });
  // 작업 수 = 그 달 출고에 나온 작업번호 수 (규격이 달라도 한 번)
  const jobs: any[] = await q(db.from('coil_moves').select('at,target,id').eq('type', '출고').neq('target', '').gte('at', months[months.length - 1] + '-01').limit(100000));
  const J: any = {}; jobs.forEach((r) => { J[r.at.slice(0, 7) + '|' + r.target] = 1; });
  Object.keys(J).forEach((k) => { const mo = k.slice(0, 7); if (tot[mo]) tot[mo].jobs++; });
  const stock: any = {};
  (await stockCalc()).forEach((s) => { const k = s.spec + '|' + s.kind; stock[k] = r2((stock[k] || 0) + num(s.total)); if (!g[k]) g[k] = { spec: s.spec, kind: s.kind, m: {} }; });
  const rows = Object.keys(g).map((k) => {
    const x = g[k]; x.stock = stock[k] || 0;
    let s3 = 0; for (let i = 1; i <= 3; i++) s3 += ((x.m[months[i]] || {}).used || 0);
    x.avg = r2(s3 / 3); x.cover = x.avg > 0 ? Math.round(x.stock / x.avg * 10) / 10 : null;
    return x;
  }).sort((a, b) => (num(a.spec) - num(b.spec)) || (a.kind < b.kind ? -1 : 1));
  return { months, rows, total: tot };
}
// v6 (4-6): 재고조사 '있는지만 확인' — QR만 찍으면 이번 달 확인됨 (관리자, 휴대폰 보관 후 늦게 올려도 됨)
async function stkSeen(token: any, a: any) {
  const m = await me(token, 'co');
  if (!m.admin) err('재고조사는 관리자만 할 수 있습니다.');
  a = a || {};
  const S = await coSet(), no = normNo(a.no, S);
  const c: any = await q(db.from('coils').select('no').eq('no', no).maybeSingle());
  if (!c) err(no + ' 번 타래를 찾지 못했습니다.');
  const at = usedAt(a.ts) || nowStr(), month = (at.slice(0, 7));
  const { error } = await db.from('stk_checks').insert({ month, no, at, by: m.name, req_id: txt(a.reqId) });
  if (error && !/duplicate|unique/i.test(error.message)) err('저장소 오류: ' + error.message);
  return { no, at, dup: !!error };
}
async function cancelMove(token: any, id: any) {
  const m = await me(token, 'co');
  const o = (await history({ id }, 1))[0];
  if (!o) err('그 기록을 찾지 못했습니다.');
  if (o.cancelled) err('이미 취소된 기록입니다.');
  if (TYPES.indexOf(o.type) < 0) err(o.type + ' 기록은 취소할 수 없습니다. 타래 정보가 틀렸으면 ‘정보 수정’으로 고치세요.');
  if (!m.admin && o.by !== m.name) err('내가 넣은 기록만 취소할 수 있습니다. (관리자는 모두 가능)');
  const S = await coSet(), T = await coTypes();
  const row: any = await q(db.from('coils').select('*').eq('no', o.no).maybeSingle());
  if (!row) err('타래를 찾지 못했습니다.');
  const c = await readCoilRow(row, T);
  const d = num(o.delta), before = r2(c.rem), after = r2(before - d);
  if (after < 0) err('이 기록을 취소하면 남은 무게가 0보다 작아집니다. 타래를 저울에 올려 ‘무게 맞추기’로 바로잡아 주세요.');
  await setRem(o.no, Number(row.rem), after, after <= S.emptyKg ? ST_EMPTY : ST_USE);
  const nid = await logRow({ no: o.no, type: '취소', spec: c.spec, kind: c.kind, worker: o.worker, target: o.target, kw: o.kw, mode: '', gross: '', delta: r2(-d), before, after, by: m.name, memo: '[취소] ' + id + ' (' + o.type + ' ' + o.at + ')', cancelOf: String(id) });
  return { id: nid, after };
}
async function setOrder(token: any, spec: any, kind: any, done: any, memo: any, type: any) {
  const m = await me(token, 'co');
  const k = specKey(spec, kind, type);
  const v = { order_state: done ? '발주완료' : '', order_at: done ? nowStr() : '', order_memo: done ? txt((memo || '') + ' (' + m.name + ')') : '' };
  const ex: any = await q(db.from('coil_specs').select('key').eq('key', k).maybeSingle());
  if (ex) await q(db.from('coil_specs').update(v).eq('key', k));
  else await q(db.from('coil_specs').insert(Object.assign({ key: k, spec: String(spec), kind: String(kind || ''), ctype: type && type !== TYPE_DEF ? String(type) : '' }, v)));
  return { ok: true };
}
async function clearOrder(spec: string, kind: string, type: string) {
  const k = specKey(spec, kind, type);
  const p: any = await q(db.from('coil_specs').select('*').eq('key', k).maybeSingle());
  if (p && p.order_state) await q(db.from('coil_specs').update({ order_state: '', order_memo: (p.order_memo + ' → 입고 ' + nowStr()).trim() }).eq('key', k));
}
async function setSafety(token: any, spec: any, kind: any, kg: any) {
  const m = await me(token, 'co');
  if (!m.admin) err('안전재고는 관리자만 바꿀 수 있습니다.');
  const n = num(kg); if (!isFinite(n) || n < 0) err('kg를 숫자로 넣어주세요.');
  const k = specKey(spec, kind, '');
  const ex: any = await q(db.from('coil_specs').select('key').eq('key', k).maybeSingle());
  if (ex) await q(db.from('coil_specs').update({ safety: n }).eq('key', k));
  else await q(db.from('coil_specs').insert({ key: k, spec: String(spec), kind: String(kind || ''), safety: n }));
  return { ok: true };
}
async function labelData(token: any, nos: any) {
  await me(token, 'co');
  const S = await coSet();
  const want = String(nos || '').split(/[,\s]+/).map((x) => normNo(x, S)).filter(String);
  if (!want.length) err('라벨을 뽑을 타래 번호를 넣어 주세요.');
  const C = await readCoils();
  return { appUrl: QR_APP_URL, rows: want.map((no) => C.find((c) => c.no === no)).filter(Boolean).map((c: any) => ({ no: c.no, spec: c.spec, kind: c.kind, type: c.type, loc: c.loc, maker: c.maker, w: Math.round(c.rem * 10) / 10 })) };
}
async function clientLog(token: any, msg: any) {
  let m: Me; try { m = await me(token, 'co'); } catch (_e) { return false; }
  await q(db.from('diag_log').insert({ at: kst().slice(0, 10) + ' ' + kst().slice(11, 19), who: m.name, msg: String(msg || '').slice(0, 500) }));
  return true;
}
async function coilMailSet(who: string, mail: any) {
  const list = String(mail || '').split(/[,;\s]+/).map((x) => x.trim()).filter(String);
  list.forEach((x) => { if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x)) err(x + ' 은(는) 메일 주소 모양이 아닙니다.'); });
  const s = await getSetting('coil.settings', {}), old = s.mail || '';
  s.mail = list.join(', '); await putSetting('coil.settings', s);
  await q(db.from('coil_edits').insert({ at: nowStr(), who, no: '(설정)', field: '부족 알림 메일', before: txt(old), after: txt(s.mail) }));
  return { mail: s.mail };
}
const CO_ADMIN: any = {
  // 엑셀로 내려받기: 규격별 합계 + 타래별 목록 (화면에서 엑셀 파일로 만듦)
  stockExport: async (m: Me) => {
    const G = await stockCalc(), C = await readCoils();
    C.sort((a, b) => (a.no < b.no ? -1 : a.no > b.no ? 1 : 0));
    return { at: nowStr(), who: m.name,
      groups: G.map((g) => [g.spec, g.kind, g.type, g.count, g.total, g.safety == null ? '' : g.safety, g.low ? '부족' : '', g.order ? g.order + (g.orderAt ? ' (' + g.orderAt + ')' : '') : '']),
      coils: C.map((x) => [x.no, x.spec, x.kind, x.type, x.maker, x.loc, r2(x.rem), x.tareDef ? '' : x.tare, x.status, x.reg, x.changed, x.memo]) };
  },
  users: async (m: Me) => m.P.filter((u) => !u.off).map((u) => { const R = roles(m.P, u); return { name: u.name, admin: R.coilAdmin, owner: R.owner, wlAdmin: R.wlAdmin, temp: u.temp }; }),
  setCoilAdmins: async (m: Me, a: any) => {
    const want = (a.names || []).map(normName);
    const pick = m.P.filter((u) => !u.off && (roles(m.P, u).owner || want.indexOf(normName(u.name)) >= 0));
    if (!pick.some((u) => u.id === m.id)) err('나 자신은 코일 관리자에서 뺄 수 없습니다. 다른 사람을 관리자로 정한 뒤, 그 사람이 빼 주세요.');
    const old = m.P.filter((u) => roles(m.P, u).coilAdmin).map((u) => u.name).join(', ');
    for (const u of m.P) await q(db.from('people').update({ coil_admin: pick.some((x) => x.id === u.id) }).eq('id', u.id));
    const txtNow = pick.map((u) => u.name).join(', ');
    await q(db.from('coil_edits').insert({ at: nowStr(), who: m.name, no: '(설정)', field: '코일 관리자', before: txt(old), after: txt(txtNow) }));
    return { names: pick.map((u) => u.name) };
  },
  backupInfo: async () => backupInfo(),
  backupNow: async () => backupNow(),
  logoutAll: async (m: Me) => {
    const th = await sha256hex(m.token);
    const r: any[] = await q(db.from('sessions').delete().neq('token_hash', th).select('token_hash'));
    await q(db.from('coil_edits').insert({ at: nowStr(), who: m.name, no: '(로그인)', field: '모든 휴대폰 로그아웃', before: r.length + '대', after: '0대' }));
    return { count: r.length };
  },
  // v6 (4-6): 두 갈래 재고조사. '무게 잴 타래' = 이번 달 쓴 타래(전체 실사면 모두), '있는지만 확인' = 나머지 (QR만 찍으면 확인됨)
  stocktake: async (_m: Me, a: any) => {
    const month = today().slice(0, 7), tag = '재고조사 ' + month, done: any = {}, used: any = {}, full = !!(a && a.full);
    (await history({ type: '실사조정', from: month + '-01' }, 5000)).forEach((o) => {
      if (o.cancelled || o.target !== tag) return;
      if (!done[o.no]) done[o.no] = { at: o.at, diff: 0, by: o.by };
      done[o.no].diff = r2(done[o.no].diff + num(o.delta));
    });
    (await history({ type: '출고', from: month + '-01' }, 5000)).forEach((o) => { if (!o.cancelled) used[o.no] = 1; });
    const seen: any = {};
    (await q(db.from('stk_checks').select('no,at,by').eq('month', month).limit(5000))).forEach((r: any) => { seen[r.no] = r; });
    const items: any[] = [];
    (await readCoils()).forEach((c) => {
      if (!c.no) return;
      const w = done[c.no], sn = seen[c.no];
      if (c.status === ST_EMPTY && !w && !sn) return;
      const g = full || used[c.no] ? 'w' : 'c';
      const x: any = { no: c.no, spec: c.spec, kind: c.kind, type: c.type, loc: c.loc || '', rem: r2(c.rem), tare: c.tare, tareSet: c.tareSet, g };
      if (w) { x.done = 'w'; x.at = w.at; x.diff = w.diff; x.by = w.by; } else if (sn && g === 'c') { x.done = 'c'; x.at = sn.at; x.by = sn.by; }
      items.push(x);
    });
    items.sort((p, o) => (String(p.loc) < String(o.loc) ? -1 : String(p.loc) > String(o.loc) ? 1 : 0) || (p.no < o.no ? -1 : 1));
    return { month, tag, full, items };
  },
  // v3: 코일 종류(일반 환선·인롤…) — 알림 무게, 인롤은 이름·규격·1대당 무게도 고침 (이름을 바꾸면 그 종류 타래도 같이 바뀜)
  setTypes: async (m: Me, a: any) => {
    const cur: any[] = await q(db.from('coil_types').select('*'));
    const now = nowStr(), logs: any[] = [];
    for (const r of (a.rows || [])) {
      const oldName = String(r.old || r.name || '').trim(); let name = String(r.name || '').trim(); if (!name) name = oldName; if (!name) continue;
      const old = cur.find((x) => x.name === oldName) || cur.find((x) => (TYPE_ALIAS[x.name] || x.name) === oldName);
      if (r.tare === undefined && old) r.tare = old.tare === null ? '' : old.tare;
      const blank = String(r.tare ?? '').trim() === '', t = blank ? null : num(r.tare), al = num(r.alert);
      if (!blank && (!isFinite(t as number) || (t as number) < 0 || (t as number) > 30)) err(name + ': 빈 보빈 무게를 0~30kg 숫자로 넣거나 비워 두세요 (비우면 등록 때 직접 씀).');
      const alv = isFinite(al) && al > 0 ? al : null, alTxt = alv === null ? '알림 없음' : String(alv);
      const isDef = name === TYPE_DEF || oldName === TYPE_DEF;
      const spec = isDef ? '' : (r.spec === undefined ? (old ? old.spec || '' : '') : specTxt(r.spec));
      const un = num(r.unit), unit = isDef ? null : (r.unit === undefined ? (old ? old.unit : null) : (isFinite(un) && un > 0 ? un : null));
      if (isDef && name !== TYPE_DEF) err('일반 환선은 이름을 바꿀 수 없습니다.');
      if (name !== oldName && cur.some((x) => x.name === name)) err(name + ' 은(는) 이미 있는 종류 이름입니다.');
      const desc = (o: any) => (o.tare ?? '') + 'kg / ' + (o.alert === null || o.alert === undefined ? '알림 없음' : o.alert) + (o.spec ? ' / 규격 ' + o.spec : '') + (o.unit ? ' / 1대 ' + o.unit + 'kg' : '');
      const nv = { tare: t, alert: alv, spec, unit };
      if (!old) { await q(db.from('coil_types').insert(Object.assign({ name, sort: cur.length + 1 }, nv))); logs.push({ at: now, who: m.name, no: '(코일종류)', field: name, before: '(새로)', after: desc(nv) }); continue; }
      const same = old.name === name && String(old.tare ?? '') === String(t ?? '') && String(old.alert ?? '') === String(alv ?? '') && String(old.spec ?? '') === String(spec) && String(old.unit ?? '') === String(unit ?? '');
      if (same) continue;
      await q(db.from('coil_types').update(Object.assign({ name }, nv)).eq('name', old.name));
      if (old.name !== name) {
        const cs: any[] = await q(db.from('coils').select('no,spec').eq('ctype', old.name));
        await q(db.from('coils').update({ ctype: name, changed_at: now }).eq('ctype', old.name));
        const sp: any[] = await q(db.from('coil_specs').select('*').eq('ctype', old.name));
        for (const x of sp) { await q(db.from('coil_specs').delete().eq('key', x.key)); await q(db.from('coil_specs').upsert(Object.assign({}, x, { ctype: name, key: specKey(x.spec, x.kind, name) }))); }
        cs.forEach((c) => logs.push({ at: now, who: m.name, no: c.no, field: '코일종류', before: old.name, after: name }));
      }
      logs.push({ at: now, who: m.name, no: '(코일종류)', field: name, before: (old.name !== name ? old.name + ' / ' : '') + desc(old), after: desc(nv) });
    }
    if (logs.length) await q(db.from('coil_edits').insert(logs));
    return coTypes();
  },
  // v3: 선종(AIW·인버터·인롤…) 이름과 선종별 규격 목록. 이름을 바꾸면 그 선종 타래도 같이 바뀜 (지난 이력은 그대로)
  setKinds: async (m: Me, a: any) => {
    const s = await getSetting('coil.settings', {}), S = await coSet(), now = nowStr(), logs: any[] = [];
    const rows = (a.rows || []).map((r: any) => ({ old: String(r.old || '').trim(), name: String(r.name || '').trim().toUpperCase(), specs: String(r.specs || '').split(/[,，\s]+/).map((x: string) => specTxt(x)).filter(String) })).filter((r: any) => r.name);
    if (!rows.length) err('선종을 하나 이상 넣어 주세요.');
    const names = rows.map((r: any) => r.name); if (new Set(names).size !== names.length) err('같은 선종 이름이 두 번 있습니다.');
    const specsBy: any = {};
    for (const r of rows) {
      specsBy[r.name] = r.specs.map((x: string) => (/^\d+$/.test(x) ? x + '.0' : x));
      if (r.old && r.old !== r.name) {
        const cs: any[] = await q(db.from('coils').select('no').eq('kind', r.old));
        if (cs.length) await q(db.from('coils').update({ kind: r.name, changed_at: now }).eq('kind', r.old));
        const sp: any[] = await q(db.from('coil_specs').select('*').eq('kind', r.old));
        for (const x of sp) { await q(db.from('coil_specs').delete().eq('key', x.key)); await q(db.from('coil_specs').upsert(Object.assign({}, x, { kind: r.name, key: specKey(x.spec, r.name, x.ctype) }))); }
        logs.push({ at: now, who: m.name, no: '(선종)', field: '이름', before: r.old, after: r.name + ' (타래 ' + cs.length + '개)' });
      }
    }
    const beforeTxt = (S.kinds || []).map((k: string) => k + ':' + ((S.specsBy || {})[k] || []).length).join(', '), afterTxt = names.map((k: string) => k + ':' + specsBy[k].length).join(', ');
    if (beforeTxt !== afterTxt) logs.push({ at: now, who: m.name, no: '(선종)', field: '선종·규격 목록', before: beforeTxt, after: afterTxt });
    s.kinds = names; s.specsBy = specsBy; await putSetting('coil.settings', s);
    if (logs.length) await q(db.from('coil_edits').insert(logs));
    return { kinds: names, specsBy };
  },
  // v4 (4-1): 보관위치(선반) 버튼 목록
  setLocs: async (m: Me, a: any) => {
    const list = String(a.text || '').split(/[,，\n]/).map((x) => x.trim()).filter(String);
    if (!list.length) err('선반을 하나 이상 넣어 주세요.');
    const s = await getSetting('coil.settings', {}), old = (s.locs || []).join(', ');
    s.locs = list; await putSetting('coil.settings', s);
    await q(db.from('coil_edits').insert({ at: nowStr(), who: m.name, no: '(설정)', field: '보관위치 목록', before: txt(old), after: txt(list.join(', ')) }));
    return { locs: list };
  },
  // v3: 부족 알림 메일 받는 사람 (쉼표로 여러 명) — 설정방에서도 같은 칸
  setMail: async (m: Me, a: any) => coilMailSet(m.name, a.mail),
  setBobbins: async (m: Me, a: any) => {
    const list = String(a.text || '').split(/[,，\n]/).map((x) => { const mm = x.trim().match(/^(.*?)[\s:=]*(\d+(?:\.\d+)?)\s*(?:kg)?$/i); return mm && Number(mm[2]) > 0 ? { name: mm[1].trim() || mm[2] + 'kg', kg: Number(mm[2]) } : null; }).filter(Boolean) as any[];
    const t = list.map((b) => b.name + ' ' + b.kg).join(', ');
    const s = await getSetting('coil.settings', {}), old = s.bobbinTxt || '';
    s.bobbinTxt = t; await putSetting('coil.settings', s);
    await q(db.from('coil_edits').insert({ at: nowStr(), who: m.name, no: '(설정)', field: '보빈 종류', before: txt(old), after: txt(t) }));
    return { bobbins: list, text: t };
  },
  tareMissing: async () => [],
  setTares: async () => ({ count: 0, nos: [] }),
  editLog: async () => {
    const r: any[] = await q(db.from('coil_edits').select('*').order('id', { ascending: false }).limit(60));
    return r.map((x) => [x.at, x.who, x.no, x.field, x.before, x.after]);
  },
};
async function coAdmin(token: any, action: string, args: any) {
  const m = await me(token, 'co');
  if (!m.admin) err('관리자만 쓸 수 있는 기능입니다.');
  const fn = CO_ADMIN[action]; if (!fn) err('앱이 옛날 화면입니다. 새로고침한 뒤 다시 해보세요. (' + action + ')');
  return fn(m, args || {});
}

// ═════════════════ ⚙ 설정방 (st) ═════════════════
const SITES = { worklog: 'https://s2badaro-tech.github.io/gwonseon-home/worklog/', coil: 'https://s2badaro-tech.github.io/gwonseon-home/coil/', home: 'https://s2badaro-tech.github.io/gwonseon-home/' };
function stView(P: Person[]) {
  return P.map((u) => { const R = roles(P, u); return { name: u.name, wl: u.wl_admin, coil: R.coilAdmin, sup: R.owner, off: u.off, temp: u.temp, reg: u.reg_at, last: u.last_seen }; })
    .sort((a, b) => (Number(a.off) - Number(b.off)) || a.name.localeCompare(b.name, 'ko'));
}
async function stGetAll(token: any) {
  const m = await me(token, 'st');
  return { me: { name: m.name, mustChange: m.mustChange, token: m.token, sup: m.owner }, version: 'sb1', sites: SITES, tempPin: TEMP_PIN, users: m.owner ? stView(m.P) : [], coilMail: m.owner ? String((await coSet()).mail || '') : '' };
}
const ST_ACT: any = {
  setCoilMail: async (m: Me, a: any) => { const r = await coilMailSet(m.name, a.mail); return { coilMail: r.mail, msg: r.mail ? '코일 부족 알림 메일: ' + r.mail : '코일 부족 알림 메일을 껐습니다.' }; },
  addUser: async (m: Me, a: any) => {
    const name = String(a.name || '').trim().replace(/^[=+\-@']+/, '');
    if (!name) err('이름을 적어주세요.'); if (name.length > 20) err('이름이 너무 깁니다.');
    const old = findP(m.P, name);
    if (old) err(old.off ? name + " 님은 '사용 안 함' 상태입니다. 명단에서 '다시 사용'을 눌러주세요." : name + ' 님은 이미 등록되어 있습니다.');
    const salt = uuid();
    await q(db.from('people').insert({ name, salt, pin_hash: await pinHash(salt, TEMP_PIN), temp: true, reg_at: nowStr(), sort: m.P.length + 1 }));
    await stLog(m.name, '사람 등록', name, '', '팀원, 임시 PIN');
    return { msg: name + ' 님을 등록했습니다. 임시 PIN ' + TEMP_PIN + ' (처음 들어갈 때 바꾸게 됩니다)' };
  },
  resetPin: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('명단에 없는 사람입니다: ' + a.name);
    if (u.id === m.id) err("내 PIN은 위쪽 '내 PIN 바꾸기'에서 바꿔 주세요.");
    if (u.off) err("사용 안 함 상태입니다. 먼저 '다시 사용'을 눌러주세요.");
    await resetPinRow(u); await stLog(m.name, 'PIN 초기화', u.name, '', '임시 PIN');
    return { msg: u.name + ' 님 PIN을 ' + TEMP_PIN + '로 초기화했습니다. 휴대폰에서 다시 로그인하면 새 PIN을 정하게 됩니다.' };
  },
  setOff: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('명단에 없는 사람입니다: ' + a.name);
    if (a.off) {
      if (u.id === m.id) err('나 자신은 사용 안 함으로 바꿀 수 없습니다.');
      if (u.owner && m.P.filter((x) => x.owner && !x.off).length <= 1) err('운영자가 한 명은 있어야 합니다.');
      await q(db.from('people').update({ off: true, salt: '', pin_hash: '' }).eq('id', u.id));
      await q(db.from('sessions').delete().eq('person_id', u.id));
      await stLog(m.name, '사용 안 함', u.name, '사용', '사용 안 함');
      return { msg: u.name + ' 님을 사용 안 함으로 바꿨습니다. 그동안의 기록은 그대로 남아 있습니다.' };
    }
    await q(db.from('people').update({ off: false }).eq('id', u.id));
    await resetPinRow(u); await stLog(m.name, '다시 사용', u.name, '사용 안 함', '사용, 임시 PIN');
    return { msg: u.name + ' 님을 다시 사용하게 했습니다. 임시 PIN ' + TEMP_PIN };
  },
  setWorklogAdmin: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('명단에 없는 사람입니다: ' + a.name);
    if (!a.on && u.wl_admin && m.P.filter((x) => x.wl_admin && !x.off).length <= 1) err('작업기록 관리자가 한 명은 있어야 합니다.');
    await q(db.from('people').update({ wl_admin: !!a.on }).eq('id', u.id));
    await stLog(m.name, '작업기록 관리자', u.name, u.wl_admin ? '관리자' : '팀원', a.on ? '관리자' : '팀원');
    return {};
  },
  setCoilAdmin: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('명단에 없는 사람입니다: ' + a.name);
    const cur = m.P.filter((x) => roles(m.P, x).coilAdmin).map((x) => x.name);
    const next = cur.filter((n) => normName(n) !== normName(u.name)); if (a.on) next.push(u.name);
    if (!next.length) err('코일 관리자가 한 명은 있어야 합니다.');
    for (const x of m.P) await q(db.from('people').update({ coil_admin: next.some((n) => normName(n) === normName(x.name)) }).eq('id', x.id));
    await stLog(m.name, '코일 관리자', u.name, cur.join(', '), next.join(', '));
    return { note: '코일 앱에 바로 반영됩니다.' };
  },
  setSuper: async (m: Me, a: any) => {
    const u = findP(m.P, a.name); if (!u) err('명단에 없는 사람입니다: ' + a.name);
    if (!a.on && u.id === m.id) err('나 자신은 운영자에서 뺄 수 없습니다.');
    if (a.on && u.off) err('사용 안 함 상태인 사람은 운영자로 정할 수 없습니다.');
    await q(db.from('people').update({ owner: !!a.on }).eq('id', u.id));
    await stLog(m.name, '운영자', u.name, u.owner ? 'Y' : '', a.on ? 'Y' : '');
    return {};
  },
};
async function stAct(token: any, action: string, a: any) {
  const m = await me(token, 'st');
  if (!m.owner) err('이 기능은 운영자만 할 수 있습니다.');
  if (m.mustChange) err('먼저 내 PIN을 바꿔 주세요.');
  const fn = ST_ACT[action]; if (!fn) err('없는 기능입니다: ' + action);
  const out = (await fn(m, a || {})) || {};
  out.users = stView(await people());
  return out;
}

// ═════════════════ 백업 · 이전 (구글 도우미와 비밀 열쇠로만) ═════════════════
async function sysCheck(key: any) { const k = await secret('gas_key'); if (!k || String(key) !== k) err('열쇠가 맞지 않습니다.'); }
async function allRows(table: string, order: string) {
  const out: any[] = [];
  for (let from = 0; ; from += 1000) {
    const r: any[] = await q(db.from(table).select('*').order(order).range(from, from + 999));
    out.push(...r); if (r.length < 1000) break;
  }
  return out;
}
// 백업용 표 (시트와 같은 제목줄)
async function dump() {
  const W = await wlExport();
  const coils = await allRows('coils', 'seq'), moves = await allRows('coil_moves', 'seq');
  const specs = await allRows('coil_specs', 'key'), types = await allRows('coil_types', 'sort'), cedits = await allRows('coil_edits', 'id');
  const P = await people(), slog = await allRows('settings_log', 'id'), plans = await allRows('job_plans', 'job'), stks = await allRows('stk_checks', 'id');
  const N = (v: any) => (v === null || v === undefined ? '' : v);
  return [
    { file: W.motor.name, head: W.motor.head, rows: W.motor.rows },
    { file: W.coil.name, head: W.coil.head, rows: W.coil.rows },
    { file: '수정기록', head: W.edits.head, rows: W.edits.rows },
    { file: '사용자', head: ['이름', '작업기록 관리자', '운영자', '코일 관리자', '상태', '임시', '등록일', '마지막접속'], rows: P.map((u) => [u.name, u.wl_admin ? '관리자' : '팀원', u.owner ? 'Y' : '', u.coil_admin ? 'Y' : '', u.off ? '사용안함' : '', u.temp ? 'Y' : '', u.reg_at, u.last_seen]) },
    { file: '설정방기록', head: ['일시', '누가', '무엇', '대상', '전', '후'], rows: slog.map((x) => [x.at, x.who, x.what, x.target, x.before, x.after]) },
    { file: '코일재고_코일목록', head: ['번호', '규격(mm)', '선종', '제조사', '공타래(kg)', '현재잔량(kg)', '보관위치', '상태', '등록일', '등록자', '최종변경', '메모', '코일종류'], rows: coils.map((c) => [c.no, c.spec, c.kind, c.maker, N(c.tare), N(c.rem), c.loc, c.status, c.reg_at, c.reg_by, c.changed_at, c.memo, c.ctype]) },
    { file: '코일재고_입출고이력', head: ['이력ID', '일시', '번호', '구분', '규격(mm)', '선종', '작업자', '작업대상', '입력방식', '저울총무게(kg)', '변동량(kg)', '변동전(kg)', '변동후(kg)', '기록자', '메모', '요청ID', 'kW', '수정내역'], rows: moves.map((r) => [r.id, r.at, r.no, r.type, r.spec, r.kind, r.worker, r.target, r.mode, N(r.gross), N(r.delta), N(r.before), N(r.after), r.by, r.memo, r.req_id, r.kw, r.edits && r.edits.length ? JSON.stringify(r.edits) : '']) },
    { file: '코일재고_작업별조합', head: ['작업번호', '원래', '실제', '단면적%', '선종', '기록자', '일시'], rows: plans.map((x) => [x.job, x.orig, x.actual, N(x.ratio), x.kind, x.by, x.at]) },
    { file: '코일재고_재고조사확인', head: ['월', '번호', '일시', '확인자'], rows: stks.map((x) => [x.month, x.no, x.at, x.by]) },
    { file: '코일재고_규격기준', head: ['규격(mm)', '선종', '안전재고(kg)', '발주상태', '발주일', '발주메모', '코일종류'], rows: specs.map((s) => [s.spec, s.kind, N(s.safety), s.order_state, s.order_at, s.order_memo, s.ctype]) },
    { file: '코일재고_코일종류', head: ['코일종류', '빈 보빈(kg)', '부족 알림(kg)', '메모'], rows: types.map((t) => [t.name, N(t.tare), t.alert === null ? '알림 없음' : t.alert, t.memo]) },
    { file: '코일재고_수정기록', head: ['일시', '수정자', '번호', '칸', '전', '후'], rows: cedits.map((x) => [x.at, x.who, x.no, x.field, x.before, x.after]) },
  ];
}
async function backupInfo() {
  const b = await getSetting('backup.last', {});
  return { last: b.info || '', url: b.url || '', list: b.list || [], count: (b.list || []).length };
}
async function backupNow() {
  const r = await google('backupNow', {}); // 구글 도우미가 dump를 받아 드라이브 '백업' 폴더에 씀
  await putSetting('backup.last', r);
  return { info: r.info, url: r.url };
}
// 시트 → Supabase 한꺼번에 옮기기 (구글 도우미가 시트를 읽어 보냄). 같은 내용을 두 번 보내도 덮어쓰기라 안전
async function importData(part: string, rows: any[], opts: any) {
  opts = opts || {};
  const chunk = async (table: string, list: any[], onConflict: string) => {
    for (let i = 0; i < list.length; i += 500) await q(db.from(table).upsert(list.slice(i, i + 500), { onConflict }));
  };
  if (opts.wipe) { // 처음 옮길 때만: 그 표를 비우고 다시 (시트 원본은 그대로)
    const del: any = { work_records: 'record_id', work_edits: 'id', settings_log: 'id', coils: 'no', coil_moves: 'id', coil_specs: 'key', coil_types: 'name', coil_edits: 'id', diag_log: 'id' };
    if (del[part]) await q(db.from(part).delete().not(del[part], 'is', null));
  }
  if (part === 'people') {
    // name_key는 자동 계산 칸이라 upsert 기준으로 못 씀 → 이름으로 찾아 고치거나 새로 넣음
    const P = await people();
    for (const r of rows) { const u = findP(P, r.name); if (u) await q(db.from('people').update(r).eq('id', u.id)); else await q(db.from('people').insert(r)); }
  }
  else if (part === 'sessions_by_name') {
    const P = await people(), now = Date.now(), list: any[] = [];
    rows.forEach((r: any) => { const u = findP(P, r.name); if (u && r.token_hash) list.push({ token_hash: r.token_hash, person_id: u.id, created_ms: now, last_ms: now }); });
    if (opts.wipe) await q(db.from('sessions').delete().not('token_hash', 'is', null));
    await chunk('sessions', list, 'token_hash');
  }
  else if (part === 'work_records') await chunk('work_records', rows, 'record_id');
  else if (part === 'coils') await chunk('coils', rows, 'no');
  else if (part === 'coil_moves') await chunk('coil_moves', rows, 'id');
  else if (part === 'coil_specs') await chunk('coil_specs', rows, 'key');
  else if (part === 'coil_types') await chunk('coil_types', rows, 'name');
  else if (['work_edits', 'settings_log', 'coil_edits', 'diag_log'].indexOf(part) >= 0) { for (let i = 0; i < rows.length; i += 500) await q(db.from(part).insert(rows.slice(i, i + 500))); }
  else if (part === 'settings') { for (const k of Object.keys(rows as any)) await putSetting(k, (rows as any)[k]); }
  else err('모르는 표: ' + part);
  await q(db.from('migration_log').insert({ what: 'import ' + part, info: { rows: Array.isArray(rows) ? rows.length : Object.keys(rows || {}).length, wipe: !!opts.wipe } }));
  return { part, rows: Array.isArray(rows) ? rows.length : 0 };
}
// 이전 확인: 표마다 줄 수 + 규격별 재고 합계 + 타래마다 이력 합 = 잔량인지
async function verify() {
  const cnt = async (t: string) => { const { count } = await db.from(t).select('*', { count: 'exact', head: true }); return count || 0; };
  const tables = ['people', 'work_records', 'work_edits', 'settings_log', 'coils', 'coil_moves', 'coil_specs', 'coil_types', 'coil_edits', 'diag_log'];
  const counts: any = {}; for (const t of tables) counts[t] = await cnt(t);
  const stock = (await stockCalc()).map((g) => ({ key: specKey(g.spec, g.kind, g.type), total: g.total, count: g.count }));
  const chk: any[] = await q(db.rpc('coil_check'));
  const bad = chk.filter((c) => Math.abs(Number(c.rem) - Number(c.sum_delta)) > 0.011 || (c.last_after !== null && Math.abs(Number(c.rem) - Number(c.last_after)) > 0.011));
  return { counts, stock, coilsChecked: chk.length, mismatch: bad.slice(0, 50), mismatchCount: bad.length };
}

// ═════════════════ 창구 ═════════════════
const API: any = {
  wl: {
    login: (n: any, p: any) => login('wl', n, p), changePin: (t: any, o: any, n: any) => changePin('wl', t, o, n), logout, adminCall: wlAdmin,
    recordHistory, getConfig, findSame, saveRecord: (rec: any, t: any) => onceReq(rec && rec.qid, () => saveRecord(rec, t)), getGuide, recentRecords, listRecords, listRecordsPage,
    // 구글 도우미가 사진 저장 전에 출입증을 확인할 때
  },
  co: {
    login: (n: any, p: any) => login('co', n, p), logout, changePin: (t: any, o: any, n: any) => changePin('co', t, o, n),
    saveMove: async (t: any, a: any) => { const d = await findReq(a && a.reqId); return d || onceReq(a && a.reqId, () => saveMove(t, a)); },
    addCoil: async (t: any, a: any) => { const d = await findReq(a && a.reqId); return d || onceReq(a && a.reqId, () => addCoil(t, a)); },
    editCoil, cancelMove, setOrder, setSafety, assignNumbers: async () => ({ count: 0, nos: [] }), adminCall: coAdmin,
    getInit: coInit, getJobs: async (t: any) => { await me(t, 'co'); return recentJobs(); }, getStock: async (t: any) => { await me(t, 'co'); return stockCalc(); },
    getCoil, getHistory, getMonthly, labelData, clientLog, stkSeen,
  },
  st: {
    login: async (n: any, p: any) => { const r = await login('st', n, p); return { token: r.token, name: r.name, mustChange: r.mustChange, sup: r.sup }; },
    logout, changePin: (t: any, o: any, n: any) => changePin('st', t, o, n), getAll: stGetAll, act: stAct,
  },
  sys: {
    ping: async () => { const { count } = await db.from('people').select('id', { count: 'exact', head: true }); return { ok: true, at: nowStr(), people: count }; },
    dump: async (k: any) => { await sysCheck(k); return dump(); },
    import: async (k: any, part: string, rows: any[], opts: any) => { await sysCheck(k); return importData(part, rows, opts); },
    verify: async (k: any) => { await sysCheck(k); return verify(); },
    setBackupInfo: async (k: any, info: any) => { await sysCheck(k); await putSetting('backup.last', info); return true; },
  },
};

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'content-type, authorization, apikey, x-client-info' };
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  let out: any;
  try {
    if (req.method !== 'POST') err('POST만 받습니다.');
    const body = JSON.parse(await req.text() || '{}');
    const box = API[String(body.app || '')];
    const f = box && Object.prototype.hasOwnProperty.call(box, body.fn) ? box[body.fn] : null;
    if (!f) err('없는 기능입니다: ' + body.app + '.' + body.fn);
    const v = await f(...(Array.isArray(body.args) ? body.args : []));
    out = { ok: true, v: v === undefined ? null : v };
  } catch (e) {
    out = { ok: false, e: String((e as any)?.message ?? e) };
  }
  return new Response(JSON.stringify(out), { headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS) });
});
