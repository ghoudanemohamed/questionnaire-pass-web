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
  first text not null, last text not null, company text,
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

-- Journal des tentatives : une ligne par question et par envoi (juste ou faux). Sert aux statistiques.
create table if not exists attempt_log (
  at timestamptz not null default now(),
  role text not null,
  q_id text not null,
  ok boolean not null
);

alter table attempt_log enable row level security;
revoke all on attempt_log from anon, authenticated;

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

-- Administrateurs supplémentaires (en plus du mot de passe principal, stocké dans settings).
-- perms : ce que chacun a le droit de faire (edit, view, remove, library, verify).
create table if not exists admins (
  name text primary key,
  hash text not null,
  at timestamptz not null default now()
);
alter table admins add column if not exists perms jsonb not null
  default '{"edit":true,"view":true,"remove":true,"library":true,"verify":true}';
alter table admins enable row level security;
revoke all on admins from anon, authenticated;

-- Qui est-ce ? {"level":"main"}, {"level":"sub","name":..,"perms":{..}} ou null (refusé).
-- Après 10 échecs en 10 minutes, tout est refusé.
create or replace function _admin_who(p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare h text; mu text; r record; u text := ''; pw text; i int;
begin
  if (select count(*) from auth_fail where at > now() - interval '10 minutes') >= 10 then return null; end if;
  -- p_pwd = "identifiant:mot de passe" (l'identifiant ne contient pas de « : »)
  p_pwd := coalesce(p_pwd, '');
  i := position(':' in p_pwd);
  if i > 0 then u := lower(btrim(left(p_pwd, i - 1))); pw := substr(p_pwd, i + 1); else pw := p_pwd; end if;
  select value into h from settings where key = 'admin_hash';
  select value into mu from settings where key = 'admin_user';
  mu := lower(coalesce(mu, 'admin'));
  if u <> '' then
    if u = mu then
      if h is not null and crypt(pw, h) = h then return jsonb_build_object('level', 'main'); end if;
    else
      select name, hash, perms into r from admins where lower(name) = u;
      if found and crypt(pw, r.hash) = r.hash then
        return jsonb_build_object('level', 'sub', 'name', r.name, 'perms', r.perms);
      end if;
    end if;
  end if;
  -- Compatibilité (sauvegarde automatique, scripts) : le mot de passe principal seul est accepté.
  if h is not null and crypt(p_pwd, h) = h then return jsonb_build_object('level', 'main'); end if;
  insert into auth_fail default values;
  delete from auth_fail where at < now() - interval '1 day';
  return null;
end $$;

create or replace function _admin_level(p_pwd text) returns text
language sql security definer set search_path = public, extensions as $$
  select _admin_who(p_pwd)->>'level'
$$;

create or replace function _admin_ok(p_pwd text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select _admin_who(p_pwd) is not null
$$;

-- Contrôle d'une autorisation : null si permis, sinon l'erreur à renvoyer.
create or replace function _admin_deny(p_pwd text, p_perm text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare w jsonb := _admin_who(p_pwd);
begin
  if w is null then return jsonb_build_object('error', 'auth'); end if;
  if w->>'level' = 'main' then return null; end if;
  if coalesce((w->'perms'->>p_perm)::boolean, false) then return null; end if;
  return jsonb_build_object('error', 'Ton compte n''a pas cette autorisation');
end $$;

-- Nettoie une liste d'autorisations : seules les 5 clés connues, en vrai/faux.
create or replace function _clean_perms(p jsonb) returns jsonb language sql immutable as $$
  select jsonb_build_object(
    'edit', coalesce((p->>'edit')::boolean, false), 'view', coalesce((p->>'view')::boolean, false),
    'remove', coalesce((p->>'remove')::boolean, false), 'library', coalesce((p->>'library')::boolean, false),
    'verify', coalesce((p->>'verify')::boolean, false))
$$;

-- Conservation des données : 12 mois après le test (6 mois de validité du pass + 6 mois).
create or replace function _purge() returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from answers where at < now() - interval '12 months';
  update saved set answers = coalesce(
    (select jsonb_agg(a) from jsonb_array_elements(answers) a
      where (a->>'at')::timestamptz >= now() - interval '12 months'), '[]'::jsonb)
  where exists (select 1 from jsonb_array_elements(answers) a
      where (a->>'at')::timestamptz < now() - interval '12 months');
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
  graded boolean; missing boolean; is_ok boolean; wrong jsonb := '[]'; clean jsonb := '{}'; evals jsonb := '[]';
  v_phone text; v_ym text; v_n int; v_code text; a answers;
begin
  if p_role not in ('visiteur', 'intervenant') then return jsonb_build_object('error', 'Rôle inconnu'); end if;
  if btrim(coalesce(p_last, '')) = '' or btrim(coalesce(p_first, '')) = ''
     or length(coalesce(p_company, '')) > 100 or length(p_last) > 100 or length(p_first) > 100 then
    return jsonb_build_object('error', 'Nom et prénom obligatoires');
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
    evals := evals || jsonb_build_object('q', qid, 'ok', is_ok);
    clean := clean || jsonb_build_object(qid, case when missing then null else v end);
  end loop;

  insert into attempt_log (role, q_id, ok)
    select p_role, e->>'q', (e->>'ok')::boolean from jsonb_array_elements(evals) e;

  if jsonb_array_length(wrong) > 0 then return jsonb_build_object('ok', false, 'wrong', wrong); end if;

  perform _purge();
  v_ym := to_char(now() at time zone 'Europe/Paris', 'YYMM');
  insert into counters (ym, n) values (v_ym, 1) on conflict (ym) do update set n = counters.n + 1 returning counters.n into v_n;
  if v_n > 9999 then raise exception 'Limite de 9999 participants atteinte pour ce mois'; end if;
  v_code := (case when p_role = 'intervenant' then 'I' else 'V' end) || v_ym || lpad(v_n::text, 4, '0');
  insert into answers (code, role, first, last, company, phone, email, tries, r)
    values (v_code, p_role, btrim(p_first), btrim(p_last), nullif(btrim(coalesce(p_company, '')), ''), v_phone, btrim(p_email),
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
declare who_ jsonb := _admin_who(p_pwd); main_ boolean; seeing boolean;
begin
  if who_ is null then return jsonb_build_object('error', 'auth'); end if;
  main_ := who_->>'level' = 'main';
  seeing := main_ or coalesce((who_->'perms'->>'view')::boolean, false);
  perform _purge();
  return jsonb_build_object(
    'main', main_,
    'requests', case when main_ then (select count(*) from admin_requests) else 0 end,
    'perms', case when main_ then '{"edit":true,"view":true,"remove":true,"library":true,"verify":true}'::jsonb else _clean_perms(who_->'perms') end,
    'groups', (select jsonb_object_agg(role, jsonb_build_object('questions', questions, 'active', active, 'video', video)) from groups),
    'answers', case when seeing then coalesce((select jsonb_agg(_answer_view(to_jsonb(a) - 'id') order by a.at, a.id) from answers a), '[]'::jsonb) else '[]'::jsonb end,
    'name', coalesce((select value from settings where key = 'name'), ''),
    'qstats', case when not seeing then '{}'::jsonb else coalesce((
      select jsonb_object_agg(role, per) from (
        select role, jsonb_object_agg(q_id, jsonb_build_object('n', n, 'wrong', w)) per from (
          select role, q_id, count(*) n, count(*) filter (where not ok) w from attempt_log group by role, q_id
        ) s group by role
      ) t), '{}'::jsonb) end);
end $$;

create or replace function admin_save_group(p_pwd text, p_role text, p_questions jsonb, p_active boolean, p_video text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb;
begin
  d := _admin_deny(p_pwd, 'edit'); if d is not null then return d; end if;
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
declare d jsonb; a jsonb; v jsonb;
begin
  d := _admin_deny(p_pwd, 'verify'); if d is not null then return d; end if;
  a := _find_answer(p_code);
  if a is null then return jsonb_build_object('found', false); end if;
  v := _answer_view(a);
  return jsonb_build_object('found', true, 'name', (a->>'first') || ' ' || (a->>'last'), 'company', a->>'company',
    'role', a->>'role', 'email', a->>'email', 'phone', a->>'phone', 'at', a->'at', 'tries', a->'tries',
    'expires', v->'expires', 'expired', v->'expired', 'source', a->>'source', 'code', a->>'code');
end $$;

create or replace function admin_clear_answers(p_pwd text, p_role text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb;
begin
  d := _admin_deny(p_pwd, 'remove'); if d is not null then return d; end if;
  delete from answers where role = p_role;
  delete from attempt_log where role = p_role;
  return jsonb_build_object('ok', true);
end $$;

-- Retire un participant : son pass devient inconnu (le QR ne le reconnaît plus). Il devra repasser le test.
create or replace function admin_revoke(p_pwd text, p_code text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb; c text := upper(regexp_replace(coalesce(p_code, ''), '[\s-]', '', 'g'));
begin
  d := _admin_deny(p_pwd, 'remove'); if d is not null then return d; end if;
  delete from answers where upper(code) = c;
  update saved set answers = coalesce(
    (select jsonb_agg(a) from jsonb_array_elements(answers) a where upper(a->>'code') <> c), '[]'::jsonb)
  where exists (select 1 from jsonb_array_elements(answers) a where upper(a->>'code') = c);
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
declare d jsonb;
begin
  d := _admin_deny(p_pwd, 'library'); if d is not null then return d; end if;
  return _saved_list();
end $$;

create or replace function admin_save_current(p_pwd text, p_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb; nm text := btrim(coalesce(p_name, '')); sid text;
begin
  d := _admin_deny(p_pwd, 'library'); if d is not null then return d; end if;
  if nm = '' or length(nm) > 80 then return jsonb_build_object('error', 'Donne un nom au questionnaire'); end if;
  select id into sid from saved where lower(name) = lower(nm) and id <> 'auto';
  perform _snapshot_into(coalesce(sid, encode(extensions.gen_random_bytes(4), 'hex')), nm);
  insert into settings (key, value) values ('name', nm) on conflict (key) do update set value = excluded.value;
  return _saved_list();
end $$;

create or replace function admin_open_saved(p_pwd text, p_sid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb; s saved; role_ text;
begin
  d := _admin_deny(p_pwd, 'library'); if d is not null then return d; end if;
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
  delete from attempt_log;
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
declare d jsonb;
begin
  d := _admin_deny(p_pwd, 'library'); if d is not null then return d; end if;
  delete from saved where id = p_sid;
  return _saved_list();
end $$;

-- ---- Administrateurs (réservé au mot de passe principal) ----
create or replace function _admins_list() returns jsonb language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('name', name, 'at', at, 'perms', _clean_perms(perms)) order by at), '[]'::jsonb) from admins
$$;

create or replace function admin_list_admins(p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd);
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  return _admins_list();
end $$;

drop function if exists admin_add_admin(text, text, text);
create or replace function admin_add_admin(p_pwd text, p_name text, p_new text, p_perms jsonb default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd); nm text := btrim(coalesce(p_name, '')); h text; r record;
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  if nm !~ '^[A-Za-z0-9._@-]{3,40}$' then
    return jsonb_build_object('error', 'Identifiant : 3 à 40 caractères (lettres, chiffres, . _ - @)');
  end if;
  if lower(nm) = lower(coalesce((select value from settings where key = 'admin_user'), 'admin'))
     or exists (select 1 from admin_requests where lower(name) = lower(nm)) then
    return jsonb_build_object('error', 'Cet identifiant existe déjà');
  end if;
  if length(coalesce(p_new, '')) < 8 or length(p_new) > 200 then
    return jsonb_build_object('error', 'Mot de passe : 8 caractères minimum');
  end if;
  if exists (select 1 from admins where lower(name) = lower(nm)) then
    return jsonb_build_object('error', 'Ce nom existe déjà');
  end if;
  select value into h from settings where key = 'admin_hash';
  if h is not null and crypt(p_new, h) = h then return jsonb_build_object('error', 'Choisis un autre mot de passe'); end if;
  for r in select hash from admins loop
    if crypt(p_new, r.hash) = r.hash then return jsonb_build_object('error', 'Choisis un autre mot de passe'); end if;
  end loop;
  insert into admins (name, hash, perms)
    values (nm, crypt(p_new, gen_salt('bf')), _clean_perms(coalesce(p_perms, '{"edit":true,"view":true,"verify":true}'::jsonb)));
  return _admins_list();
end $$;

create or replace function admin_set_perms(p_pwd text, p_name text, p_perms jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd);
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  update admins set perms = _clean_perms(p_perms) where name = p_name;
  return _admins_list();
end $$;

create or replace function admin_remove_admin(p_pwd text, p_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd);
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  delete from admins where name = p_name;
  return _admins_list();
end $$;

-- ---- Demandes de compte administrateur : créées par la personne, activées seulement si le principal valide ----
create table if not exists admin_requests (
  name text primary key,
  hash text not null,
  at timestamptz not null default now()
);
alter table admin_requests enable row level security;
revoke all on admin_requests from anon, authenticated;

create or replace function _requests_list() returns jsonb language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('name', name, 'at', at) order by at), '[]'::jsonb) from admin_requests
$$;

-- Ouverte à tous : la personne choisit un identifiant et un mot de passe. Rien n'est actif tant que le principal n'a pas validé.
create or replace function admin_request_account(p_name text, p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, ''));
begin
  if nm !~ '^[A-Za-z0-9._@-]{3,40}$' then
    return jsonb_build_object('error', 'Identifiant : 3 à 40 caractères (lettres, chiffres, . _ - @)');
  end if;
  if length(coalesce(p_pwd, '')) < 8 or length(p_pwd) > 200 then
    return jsonb_build_object('error', 'Mot de passe : 8 caractères minimum');
  end if;
  delete from admin_requests where at < now() - interval '30 days';
  if lower(nm) = lower(coalesce((select value from settings where key = 'admin_user'), 'admin'))
     or exists (select 1 from admins where lower(name) = lower(nm))
     or exists (select 1 from admin_requests where lower(name) = lower(nm)) then
    return jsonb_build_object('error', 'Cet identifiant est déjà pris');
  end if;
  if (select count(*) from admin_requests) >= 20 then
    return jsonb_build_object('error', 'Trop de demandes en attente, réessaie plus tard');
  end if;
  insert into admin_requests (name, hash) values (nm, crypt(p_pwd, gen_salt('bf')));
  return jsonb_build_object('ok', true);
end $$;

-- Pour dire à la personne que son compte attend la validation (le mot de passe doit être le bon).
create or replace function admin_request_status(p_name text, p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r admin_requests;
begin
  select * into r from admin_requests where lower(name) = lower(btrim(coalesce(p_name, '')));
  if not found then return jsonb_build_object('state', 'none'); end if;
  if crypt(coalesce(p_pwd, ''), r.hash) = r.hash then return jsonb_build_object('state', 'pending'); end if;
  insert into auth_fail default values;
  return jsonb_build_object('state', 'none');
end $$;

create or replace function admin_list_requests(p_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd);
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  return _requests_list();
end $$;

create or replace function admin_approve_request(p_pwd text, p_name text, p_perms jsonb default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd); r admin_requests;
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  select * into r from admin_requests where name = p_name;
  if not found then return jsonb_build_object('error', 'Demande introuvable'); end if;
  if exists (select 1 from admins where lower(name) = lower(r.name)) then
    return jsonb_build_object('error', 'Cet identifiant existe déjà');
  end if;
  insert into admins (name, hash, perms)
    values (r.name, r.hash, _clean_perms(coalesce(p_perms, '{"edit":true,"view":true,"verify":true}'::jsonb)));
  delete from admin_requests where name = r.name;
  return _requests_list();
end $$;

create or replace function admin_reject_request(p_pwd text, p_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare lvl text := _admin_level(p_pwd);
begin
  if lvl is null then return jsonb_build_object('error', 'auth'); end if;
  if lvl <> 'main' then return jsonb_build_object('error', 'Réservé à l''administrateur principal'); end if;
  delete from admin_requests where name = p_name;
  return _requests_list();
end $$;

-- Chacun (principal ou non) change son propre identifiant et/ou son mot de passe.
-- Il faut redonner le mot de passe actuel. Un champ vide = on ne change pas.
create or replace function admin_change_account(p_pwd text, p_current text, p_new_name text, p_new_pwd text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare w jsonb := _admin_who(p_pwd); nm text := btrim(coalesce(p_new_name, '')); np text := coalesce(p_new_pwd, '');
        h text; cur text; r record; main_ boolean; me text;
begin
  if w is null then return jsonb_build_object('error', 'auth'); end if;
  main_ := w->>'level' = 'main';
  if (select count(*) from auth_fail where at > now() - interval '10 minutes') >= 10 then
    return jsonb_build_object('error', 'auth');
  end if;
  if main_ then
    select value into h from settings where key = 'admin_hash';
    me := coalesce((select value from settings where key = 'admin_user'), 'admin');
  else
    me := w->>'name';
    select hash into h from admins where name = me;
  end if;
  if h is null or crypt(coalesce(p_current, ''), h) <> h then
    insert into auth_fail default values;
    return jsonb_build_object('error', 'Mot de passe actuel incorrect');
  end if;
  if nm = '' and np = '' then return jsonb_build_object('error', 'Rien à changer'); end if;
  if nm <> '' and lower(nm) <> lower(me) then
    if nm !~ '^[A-Za-z0-9._@-]{3,40}$' then
      return jsonb_build_object('error', 'Identifiant : 3 à 40 caractères (lettres, chiffres, . _ - @)');
    end if;
    if lower(nm) = lower(coalesce((select value from settings where key = 'admin_user'), 'admin'))
       or exists (select 1 from admins where lower(name) = lower(nm))
       or exists (select 1 from admin_requests where lower(name) = lower(nm)) then
      return jsonb_build_object('error', 'Cet identifiant est déjà pris');
    end if;
  else
    nm := me;
  end if;
  if np <> '' and (length(np) < 8 or length(np) > 200) then
    return jsonb_build_object('error', 'Mot de passe : 8 caractères minimum');
  end if;
  if main_ then
    insert into settings (key, value) values ('admin_user', nm)
      on conflict (key) do update set value = excluded.value;
    if np <> '' then
      update settings set value = crypt(np, gen_salt('bf')) where key = 'admin_hash';
    end if;
  else
    update admins set name = nm, hash = case when np <> '' then crypt(np, gen_salt('bf')) else hash end
      where name = me;
  end if;
  return jsonb_build_object('ok', true, 'name', nm);
end $$;

-- ---- RGPD : la personne supprime elle-même ses données (code + e-mail du pass) ----
create or replace function delete_my_data(p_code text, p_email text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c text := upper(regexp_replace(coalesce(p_code, ''), '[\s-]', '', 'g')); a jsonb;
begin
  a := _find_answer(c);
  if a is null or lower(btrim(coalesce(a->>'email', ''))) <> lower(btrim(coalesce(p_email, ''))) then
    return jsonb_build_object('ok', false);
  end if;
  delete from answers where upper(code) = c;
  update saved set answers = coalesce(
    (select jsonb_agg(x) from jsonb_array_elements(answers) x where upper(x->>'code') <> c), '[]'::jsonb)
  where exists (select 1 from jsonb_array_elements(answers) x where upper(x->>'code') = c);
  return jsonb_build_object('ok', true);
end $$;

-- Les fonctions internes (préfixe _) ne sont pas appelables depuis le site.
revoke execute on function _requests_list(), _admin_who(text), _admin_deny(text, text), _clean_perms(jsonb), _admin_level(text), _admin_ok(text), _purge(), _admins_list(), _find_answer(text), _answer_view(jsonb), _saved_list(), _snapshot_into(text, text) from public, anon, authenticated;

-- Droits explicites : seules ces fonctions sont appelables depuis le site (clé anon), quels que soient
-- les réglages "Data API" du projet. Les tables, elles, ne sont pas accessibles directement.
grant usage on schema public to anon;
grant execute on function
  public_state(), public_group(text),
  submit_answers(text, text, text, text, text, text, jsonb, int),
  pass_status(text),
  admin_state(text), admin_save_group(text, text, jsonb, boolean, text), admin_verify(text, text),
  admin_clear_answers(text, text), admin_revoke(text, text), admin_saved_list(text), admin_save_current(text, text),
  admin_open_saved(text, text), admin_delete_saved(text, text),
  admin_list_admins(text), admin_add_admin(text, text, text, jsonb), admin_set_perms(text, text, jsonb), admin_remove_admin(text, text),
  admin_request_account(text, text), admin_request_status(text, text), admin_list_requests(text),
  admin_approve_request(text, text, jsonb), admin_reject_request(text, text),
  admin_change_account(text, text, text, text),
  delete_my_data(text, text)
to anon;
