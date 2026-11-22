-- Questionnaire avec pass : schéma Supabase
-- À coller en entier dans Supabase > SQL Editor, puis "Run".
-- Rejouable sans risque : ne touche pas aux données déjà présentes.

create extension if not exists pgcrypto with schema extensions;

-- ============ Tables (inaccessibles directement : tout passe par les fonctions plus bas) ============
create table if not exists settings (key text primary key, value text not null);

create table if not exists groups (
  role text primary key check (role in ('visiteur', 'intervenant')),
  questions jsonb not null default '[]',
  active boolean not null default false,
  video text not null default ''
);
insert into groups (role) values ('visiteur'), ('intervenant') on conflict do nothing;

create table if not exists answers (
  id bigserial primary key,
  code text not null unique,
  at timestamptz not null default now(),
  role text not null check (role in ('visiteur', 'intervenant')),
  first text not null, last text not null, company text not null,
  phone text not null, email text not null,
  tries int not null default 1,
  r jsonb not null default '{}'
);

create table if not exists counters (ym text primary key, n int not null);

create table if not exists saved (
  id text primary key,
  name text not null,
  at timestamptz not null default now(),
  groups jsonb not null,
  answers jsonb not null
);

create table if not exists auth_fail (at timestamptz not null default now());

alter table settings enable row level security;
alter table groups enable row level security;
alter table answers enable row level security;
alter table counters enable row level security;
alter table saved enable row level security;
alter table auth_fail enable row level security;
revoke all on settings, groups, answers, counters, saved, auth_fail from anon, authenticated;

-- ============ Aides internes ============
create or replace function _norm(t text) returns text language sql immutable as $$
  select regexp_replace(lower(btrim(coalesce(t, ''))), '\s+', ' ', 'g')
$$;

-- Mot de passe admin : vrai si correct. Après 10 échecs en 10 minutes, tout est refusé.
create or replace function _admin_ok(p_pwd text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare h text;
begin
  if (select count(*) from auth_fail where at > now() - interval '10 minutes') >= 10 then return false; end if;
  select value into h from settings where key = 'admin_hash';
  if h is not null and crypt(coalesce(p_pwd, ''), h) = h then return true; end if;
  insert into auth_fail default values;
  delete from auth_fail where at < now() - interval '1 day';
  return false;
end $$;

create or replace function _find_answer(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c text := upper(regexp_replace(coalesce(p_code, ''), '[\s-]', '', 'g')); r jsonb;
begin
  select to_jsonb(a) - 'id' into r from answers a where upper(a.code) = c;
  if r is not null then return r || '{"source":""}'; end if;
  select a || jsonb_build_object('source', s.name) into r
    from saved s, jsonb_array_elements(s.answers) a where upper(a->>'code') = c limit 1;
  return r;
end $$;

create or replace function _answer_view(a jsonb) returns jsonb language sql stable as $$
  select a || jsonb_build_object(
    'expires', (a->>'at')::timestamptz + interval '6 months',
    'expired', (a->>'at')::timestamptz + interval '6 months' <= now())
$$;

-- ============ Fonctions publiques (participants) ============
create or replace function public_state() returns jsonb
language sql security definer set search_path = public as $$
  select jsonb_build_object('active', jsonb_object_agg(role, active)) from groups
$$;

create or replace function public_group(p_role text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare g groups;
begin
  select * into g from groups where role = p_role;
  if not found or not g.active then return jsonb_build_object('active', false, 'questions', '[]'::jsonb, 'video', ''); end if;
  return jsonb_build_object('active', true, 'video', g.video,
    'questions', coalesce((select jsonb_agg(q - 'correct') from jsonb_array_elements(g.questions) q), '[]'::jsonb));
end $$;

create or replace function submit_answers(
  p_role text, p_company text, p_last text, p_first text, p_phone text, p_email text,
  p_responses jsonb, p_tries int default 1
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
  g groups; q jsonb; qid text; qtype text; nopts int; correct jsonb; v jsonb; val text; arr jsonb;
  graded boolean; missing boolean; is_ok boolean; wrong jsonb := '[]'; clean jsonb := '{}';
  v_phone text; v_ym text; v_n int; v_code text; a answers;
begin
  if p_role not in ('visiteur', 'intervenant') then return jsonb_build_object('error', 'Rôle inconnu'); end if;
  if btrim(coalesce(p_company, '')) = '' or btrim(coalesce(p_last, '')) = '' or btrim(coalesce(p_first, '')) = ''
     or length(p_company) > 100 or length(p_last) > 100 or length(p_first) > 100 then
    return jsonb_build_object('error', 'Entreprise, nom et prénom obligatoires');
  end if;
  if btrim(coalesce(p_email, '')) !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' or length(p_email) > 200 then
    return jsonb_build_object('error', 'Adresse e-mail invalide');
  end if;
  v_phone := regexp_replace(coalesce(p_phone, ''), '[ .\-()/]', '', 'g');
  if v_phone !~ '^(0|\+33|0033)[1-9][0-9]{8}$' then
    return jsonb_build_object('error', 'Numéro de téléphone invalide (10 chiffres)');
  end if;
  select * into g from groups where role = p_role;
  if not g.active then return jsonb_build_object('error', 'closed'); end if;
  p_responses := coalesce(p_responses, '{}');

  for q in select * from jsonb_array_elements(g.questions) loop
    qid := q->>'id'; qtype := q->>'type';
    nopts := coalesce(jsonb_array_length(q->'options'), 0);
    correct := coalesce(q->'correct', '[]');
    graded := jsonb_array_length(correct) > 0;
    v := p_responses->qid;
    missing := false;
    if qtype = 'text' then
      val := left(btrim(coalesce(v #>> '{}', '')), 2000);
      missing := val = '';
      v := to_jsonb(val);
    elsif qtype = 'multi' then
      select coalesce(jsonb_agg(x), '[]') into arr
        from jsonb_array_elements(case when jsonb_typeof(v) = 'array' then v else '[]'::jsonb end) x
        where jsonb_typeof(x) = 'number' and x::text ~ '^[0-9]+$' and (x::text)::int < nopts;
      v := arr;
    else
      missing := v is null or jsonb_typeof(v) <> 'number' or v::text !~ '^[0-9]+$' or (v::text)::int >= nopts;
    end if;
    if missing and not graded then return jsonb_build_object('error', 'Réponse manquante'); end if;
    if missing then is_ok := false;
    elsif not graded then is_ok := true;
    elsif qtype = 'text' then
      is_ok := exists (select 1 from jsonb_array_elements_text(correct) c where _norm(c) = _norm(val));
    elsif qtype = 'multi' then is_ok := v @> correct and correct @> v;
    else is_ok := correct @> v;
    end if;
    if not is_ok then wrong := wrong || to_jsonb(qid); end if;
    clean := clean || jsonb_build_object(qid, case when missing then null else v end);
  end loop;

  if jsonb_array_length(wrong) > 0 then return jsonb_build_object('ok', false, 'wrong', wrong); end if;

  v_ym := to_char(now() at time zone 'Europe/Paris', 'YYMM');
  insert into counters (ym, n) values (v_ym, 1) on conflict (ym) do update set n = counters.n + 1 returning counters.n into v_n;
  if v_n > 9999 then raise exception 'Limite de 9999 participants atteinte pour ce mois'; end if;
  v_code := (case when p_role = 'intervenant' then 'I' else 'V' end) || v_ym || lpad(v_n::text, 4, '0');
  insert into answers (code, role, first, last, company, phone, email, tries, r)
    values (v_code, p_role, btrim(p_first), btrim(p_last), btrim(p_company), v_phone, btrim(p_email),
            greatest(1, least(coalesce(p_tries, 1), 1000)), clean)
    returning * into a;
  return jsonb_build_object('ok', true, 'code', v_code, 'role', p_role, 'first', a.first, 'last', a.last,
    'company', a.company, 'at', a.at, 'expires', a.at + interval '6 months');
end $$;

-- Ce que montre le QR code : valable, périmé ou inconnu. Peu d'informations (les codes se suivent).
create or replace function pass_status(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a jsonb; v jsonb;
begin
  a := _find_answer(p_code);
  if a is null then return jsonb_build_object('valid', false, 'state', 'unknown'); end if;
  v := _answer_view(a);
  return jsonb_build_object('valid', not (v->>'expired')::boolean,
    'state', case when (v->>'expired')::boolean then 'expired' else 'valid' end,
    'expires', v->'expires', 'role', a->>'role',
    'name', btrim((a->>'first') || ' ' || left(coalesce(a->>'last', ''), 1) || '.'));
end $$;

-- ============ Fonctions admin (mot de passe demandé à chaque appel) ============
create or replace function admin_state(p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  return jsonb_build_object(
    'groups', (select jsonb_object_agg(role, jsonb_build_object('questions', questions, 'active', active, 'video', video)) from groups),
    'answers', coalesce((select jsonb_agg(_answer_view(to_jsonb(a) - 'id') order by a.at, a.id) from answers a), '[]'::jsonb),
    'name', coalesce((select value from settings where key = 'name'), ''));
end $$;

create or replace function admin_save_group(p_pwd text, p_role text, p_questions jsonb, p_active boolean, p_video text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  if p_role not in ('visiteur', 'intervenant') then return jsonb_build_object('error', 'Rôle inconnu'); end if;
  if jsonb_typeof(p_questions) <> 'array' or jsonb_array_length(p_questions) > 100 then
    return jsonb_build_object('error', 'Questions invalides');
  end if;
  if p_active and jsonb_array_length(p_questions) = 0 then return jsonb_build_object('error', 'Aucune question'); end if;
  if coalesce(p_video, '') !~ '^(https?://\S+)?$' or length(coalesce(p_video, '')) > 500 then
    return jsonb_build_object('error', 'Le lien de la vidéo doit commencer par http:// ou https://');
  end if;
  update groups set questions = p_questions, active = p_active, video = coalesce(p_video, '') where role = p_role;
  return jsonb_build_object('ok', true);
end $$;

create or replace function admin_verify(p_pwd text, p_code text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a jsonb; v jsonb;
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  a := _find_answer(p_code);
  if a is null then return jsonb_build_object('found', false); end if;
  v := _answer_view(a);
  return jsonb_build_object('found', true, 'name', (a->>'first') || ' ' || (a->>'last'), 'company', a->>'company',
    'role', a->>'role', 'email', a->>'email', 'phone', a->>'phone', 'at', a->'at', 'tries', a->'tries',
    'expires', v->'expires', 'expired', v->'expired', 'source', a->>'source', 'code', a->>'code');
end $$;

create or replace function admin_clear_answers(p_pwd text, p_role text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  delete from answers where role = p_role;
  return jsonb_build_object('ok', true);
end $$;

-- ---- Questionnaires enregistrés ----
create or replace function _saved_list() returns jsonb language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', id, 'name', name, 'at', at,
    'questions', (select coalesce(sum(jsonb_array_length(g->'questions')), 0) from jsonb_each(groups) e(k, g)),
    'answers', jsonb_array_length(answers),
    'video', exists (select 1 from jsonb_each(groups) e(k, g) where coalesce(g->>'video', '') <> '')) order by at desc), '[]'::jsonb)
  from saved
$$;

create or replace function _snapshot_into(p_id text, p_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into saved (id, name, at, groups, answers)
  values (p_id, p_name, now(),
    (select jsonb_object_agg(role, jsonb_build_object('questions', questions, 'video', video)) from groups),
    coalesce((select jsonb_agg(to_jsonb(a) - 'id' order by a.at) from answers a), '[]'::jsonb))
  on conflict (id) do update set name = excluded.name, at = excluded.at, groups = excluded.groups, answers = excluded.answers;
end $$;

create or replace function admin_saved_list(p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  return _saved_list();
end $$;

create or replace function admin_save_current(p_pwd text, p_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); sid text;
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  if nm = '' or length(nm) > 80 then return jsonb_build_object('error', 'Donne un nom au questionnaire'); end if;
  select id into sid from saved where lower(name) = lower(nm) and id <> 'auto';
  perform _snapshot_into(coalesce(sid, encode(extensions.gen_random_bytes(4), 'hex')), nm);
  insert into settings (key, value) values ('name', nm) on conflict (key) do update set value = excluded.value;
  return _saved_list();
end $$;

create or replace function admin_open_saved(p_pwd text, p_sid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare s saved; role_ text;
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  select * into s from saved where id = p_sid;
  if not found then return jsonb_build_object('error', 'Questionnaire introuvable'); end if;
  if exists (select 1 from answers) or exists (select 1 from groups where jsonb_array_length(questions) > 0 or video <> '') then
    perform _snapshot_into('auto', 'Sauvegarde automatique (avant ouverture)');
    if p_sid <> 'auto' then select * into s from saved where id = p_sid; end if;
  end if;
  for role_ in select unnest(array['visiteur', 'intervenant']) loop
    update groups set questions = coalesce(s.groups->role_->'questions', '[]'), active = false,
      video = coalesce(s.groups->role_->>'video', '') where role = role_;
  end loop;
  delete from answers;
  insert into answers (code, at, role, first, last, company, phone, email, tries, r)
    select a->>'code', (a->>'at')::timestamptz, a->>'role', a->>'first', a->>'last', a->>'company',
           a->>'phone', a->>'email', coalesce((a->>'tries')::int, 1), coalesce(a->'r', '{}')
    from jsonb_array_elements(s.answers) a;
  insert into settings (key, value) values ('name', case when p_sid = 'auto' then '' else s.name end)
    on conflict (key) do update set value = excluded.value;
  return jsonb_build_object('ok', true);
end $$;

create or replace function admin_delete_saved(p_pwd text, p_sid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _admin_ok(p_pwd) then return jsonb_build_object('error', 'auth'); end if;
  delete from saved where id = p_sid;
  return _saved_list();
end $$;

-- Les fonctions internes (préfixe _) ne sont pas appelables depuis le site.
revoke execute on function _admin_ok(text), _find_answer(text), _answer_view(jsonb), _saved_list(), _snapshot_into(text, text) from public, anon, authenticated;

-- Droits explicites : seules ces fonctions sont appelables depuis le site (clé anon), quels que soient
-- les réglages "Data API" du projet. Les tables, elles, ne sont pas accessibles directement.
grant usage on schema public to anon;
grant execute on function
  public_state(), public_group(text),
  submit_answers(text, text, text, text, text, text, jsonb, int),
  pass_status(text),
  admin_state(text), admin_save_group(text, text, jsonb, boolean, text), admin_verify(text, text),
  admin_clear_answers(text, text), admin_saved_list(text), admin_save_current(text, text),
  admin_open_saved(text, text), admin_delete_saved(text, text)
to anon;
