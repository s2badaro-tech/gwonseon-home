-- 권선 작업실 Supabase 표 설계 v1 (2026-11-27)
-- 두 앱(작업기록·코일 관리)과 ⚙ 설정방이 같이 쓰는 데이터베이스.
-- 보안: 모든 표에 RLS를 켜고 정책(policy)을 하나도 만들지 않음 → 공개 키(anon)로는 아무것도 읽고 쓸 수 없음.
--       화면은 Edge Function 'api' 하나만 부르고, 그 안에서 이름+PIN 출입증을 확인한 뒤 서비스 키로 표를 다룸.
-- 원칙: 권선 기록·코일 이력은 지우지 않음 (삭제 기능 없음). 수정은 수정기록 표에 전→후로 남김.

create extension if not exists pgcrypto;

-- ───── 사람 명단 (하나를 두 앱이 같이 씀) ─────
create table if not exists people (
  id          bigserial primary key,
  name        text not null,
  name_key    text generated always as (regexp_replace(name, '\s+', '', 'g')) stored unique,
  wl_admin    boolean not null default false,   -- 작업기록 '관리자' (시트 역할 칸)
  owner       boolean not null default false,   -- 운영자 (시트 '전체관리' Y)
  coil_admin  boolean not null default false,   -- 코일 관리자 (코일 시트 설정 10행)
  off         boolean not null default false,   -- 사용 안 함
  salt        text not null default '',
  pin_hash    text not null default '',         -- 'h' + sha256hex(salt + pin)  (시트와 같은 방식, PIN 숫자는 저장 안 함)
  temp        boolean not null default false,   -- 임시 PIN (첫 로그인 때 바꿔야 함)
  reg_at      text not null default '',
  last_seen   text not null default '',
  sort        int not null default 0
);

-- 출입증 (휴대폰마다 하나). 토큰은 sha256으로만 저장
create table if not exists sessions (
  token_hash  text primary key,
  person_id   bigint not null references people(id) on delete cascade,
  created_ms  bigint not null,
  last_ms     bigint not null
);
create index if not exists sessions_person on sessions(person_id);

-- PIN 5번 틀리면 10분 잠금
create table if not exists login_fails (
  name_key    text primary key,
  fails       int not null default 0,
  until_ms    bigint not null default 0
);

-- 설정방 변경 기록
create table if not exists settings_log (
  id bigserial primary key, at text not null, who text, what text, target text, before text, after text
);

-- 앱 설정 (키-값). wl.hidden / wl.lists / wl.editOwnOnly / coil.settings / backup 정보 등
create table if not exists app_settings (
  key text primary key, value jsonb not null, updated_at timestamptz not null default now()
);

-- ───── 작업기록 앱 ─────
-- kind: 'motor' = 모터재권선 탭, 'coil' = 마그네틱코일 탭(화면 이름 전자브레이크)
create table if not exists work_records (
  record_id   text primary key,
  kind        text not null check (kind in ('motor', 'coil')),
  recorded_at text not null default '',   -- 'yyyy-MM-dd HH:mm' (한국 시각, 시트와 같은 글자)
  author      text not null default '',
  ledger_no   text not null default '',   -- 작업번호 (찾기 빠르게 따로 둠, vals에도 있음)
  vals        jsonb not null default '{}', -- 칸 키 → 값 (ledgerNo, customer, kw, …)
  extra       jsonb not null default '{}', -- 시트에만 있던 그 밖의 칸 (제목 → 값), 잃지 않게
  photo       text not null default '',   -- 구글 드라이브 사진 주소 (여러 장은 줄바꿈)
  edited_at   text not null default '',
  editor      text not null default '',
  seq         bigserial                   -- 시트 줄 순서 (최근 것부터 보여 줄 때)
);
create index if not exists work_records_kind_seq on work_records(kind, seq desc);
create index if not exists work_records_ledger on work_records(lower(regexp_replace(ledger_no, '\s+', '', 'g')));
create index if not exists work_records_at on work_records(recorded_at);
create index if not exists work_records_edit on work_records(edited_at);

create table if not exists work_edits (
  id bigserial primary key, at text not null, who text, kind_title text, record_id text, ledger_no text,
  field text, before text, after text
);
create index if not exists work_edits_rec on work_edits(record_id);

-- ───── 코일 관리 앱 ─────
create table if not exists coils (
  no          text primary key,           -- C-001
  spec        text not null default '',   -- 규격(mm)
  kind        text not null default '',   -- 선종
  maker       text not null default '',
  tare        numeric,                    -- 공타래(kg), 비면 종류별 기본
  rem         numeric not null default 0, -- 현재잔량(kg)
  loc         text not null default '',
  status      text not null default '사용중',
  reg_at      text not null default '',
  reg_by      text not null default '',
  changed_at  text not null default '',
  memo        text not null default '',
  ctype       text not null default '',   -- 코일종류
  seq         bigserial
);

create table if not exists coil_moves (
  id          text primary key,           -- 이력ID L2611...
  at          text not null default '',   -- 일시 'yyyy-MM-dd HH:mm'
  no          text not null default '',
  type        text not null default '',   -- 출고/입고/실사조정/신규등록/정보수정/취소
  spec        text not null default '',
  kind        text not null default '',
  worker      text not null default '',
  target      text not null default '',   -- 작업대상(작업번호)
  mode        text not null default '',
  gross       numeric,
  delta       numeric,
  before      numeric,
  after       numeric,
  by          text not null default '',
  memo        text not null default '',
  req_id      text not null default '',
  kw          text not null default '',
  cancel_of   text not null default '',   -- 이 줄이 취소한 이력ID (메모 '[취소] L…'에서)
  seq         bigserial
);
create index if not exists coil_moves_seq on coil_moves(seq desc);
create index if not exists coil_moves_no on coil_moves(no, seq desc);
create index if not exists coil_moves_at on coil_moves(at);
create index if not exists coil_moves_req on coil_moves(req_id) where req_id <> '';
create index if not exists coil_moves_cancel on coil_moves(cancel_of) where cancel_of <> '';

create table if not exists coil_specs (       -- 규격기준
  key         text primary key,               -- spec|KIND(|type)
  spec text not null default '', kind text not null default '', ctype text not null default '',
  safety numeric, order_state text not null default '', order_at text not null default '', order_memo text not null default ''
);

create table if not exists coil_types (       -- 코일종류
  name text primary key, tare numeric, alert numeric, memo text not null default '', sort int not null default 0
);

create table if not exists coil_edits (       -- 코일 수정기록
  id bigserial primary key, at text not null, who text, no text, field text, before text, after text
);

create table if not exists diag_log (         -- 휴대폰 QR 진단기록
  id bigserial primary key, at text not null, who text, msg text
);

-- 이전할 때 쓴 표 (어느 시트에서 몇 줄 옮겼는지)
create table if not exists migration_log (
  id bigserial primary key, at timestamptz not null default now(), what text, info jsonb
);

-- 비밀값 (구글 도우미와 주고받는 열쇠). 서비스 키로만 읽힘
create table if not exists app_secrets (key text primary key, value text not null);

-- ───── 보안: 모든 표 RLS 켜기 (정책 없음 = 공개 키로 접근 불가) ─────
do $$
declare t text;
begin
  for t in select tablename from pg_tables where schemaname = 'public' loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
  end loop;
end $$;
revoke all on all sequences in schema public from anon, authenticated;

-- ───── 요약 계산 (서버 함수에서만 부름) ─────
-- 월별 사용량: 취소된 줄과 '취소' 줄은 뺌
create or replace function coil_monthly(p_from text)
returns table(month text, spec text, kind text, type text, used numeric, inn numeric, adj numeric, jobs bigint)
language sql stable security definer set search_path = public as $$
  select substr(m.at, 1, 7) as month, m.spec, m.kind, m.type,
         sum(case when m.type = '출고' then -m.delta else 0 end) as used,
         sum(case when m.type in ('입고', '신규등록') then m.delta else 0 end) as inn,
         sum(case when m.type = '실사조정' then m.delta else 0 end) as adj,
         count(distinct case when m.type = '출고' and m.target <> '' then m.target end) as jobs
  from coil_moves m
  where m.at >= p_from and m.type <> '취소'
    and not exists (select 1 from coil_moves c where c.cancel_of = m.id)
  group by 1, 2, 3, 4;
$$;
revoke all on function coil_monthly(text) from public, anon, authenticated;

-- 검증: 타래마다 (이력 변동량 합계)와 (현재잔량)이 같은지
create or replace function coil_check()
returns table(no text, rem numeric, sum_delta numeric, last_after numeric, moves bigint)
language sql stable security definer set search_path = public as $$
  select c.no, c.rem,
         coalesce((select sum(m.delta) from coil_moves m where m.no = c.no and m.type <> '정보수정'), 0),
         (select m.after from coil_moves m where m.no = c.no and m.type <> '정보수정' order by m.seq desc limit 1),
         (select count(*) from coil_moves m where m.no = c.no)
  from coils c;
$$;
revoke all on function coil_check() from public, anon, authenticated;

grant execute on function coil_monthly(text) to service_role;
grant execute on function coil_check() to service_role;
-- 앞으로 새로 만드는 표도 공개 키로는 못 쓰게
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from anon, authenticated, public;
