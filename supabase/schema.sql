-- Sanam: companies, users with Dragon-style permissions, and company-scoped records.
-- Every rule is enforced here with row level security, not only hidden in the app.

create table public.sanam_companies (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'شركتي',
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now()
);

create table public.sanam_members (
  company_id uuid not null references public.sanam_companies(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  username text not null,
  is_admin boolean not null default false,
  active boolean not null default true,
  requires_approval boolean not null default false,
  -- {"<tab>": {"view": bool, "edit": bool, "delete": bool}}
  permissions jsonb not null default '{}'::jsonb,
  -- null = every project, otherwise an array of project ids
  allowed_projects jsonb,
  created_at timestamptz not null default now(),
  primary key (company_id, user_id),
  unique (user_id)
);

-- helpers live outside the API schema so they can't be called over REST
create schema if not exists sanam_private;

create or replace function sanam_private.me()
returns public.sanam_members language sql stable security definer set search_path = '' as $$
  select m.* from public.sanam_members m where m.user_id = auth.uid() and m.active
$$;

create or replace function sanam_private.company()
returns uuid language sql stable security definer set search_path = '' as $$
  select m.company_id from public.sanam_members m where m.user_id = auth.uid() and m.active
$$;

-- which permission tab a record belongs to
create or replace function sanam_private.tab(col text, d jsonb)
returns text language sql immutable set search_path = '' as $$
  select case
    when col = 'txns' then case d->>'kind'
      when 'invoice' then 'invoice' when 'expense' then 'expense'
      when 'statement' then 'statement' when 'collection' then 'statement'
      when 'subwork' then 'subwork' when 'payment' then 'subwork'
      when 'transfer' then 'transfer'
      when 'salary' then 'payroll' when 'advance' then 'payroll'
      else 'daily' end
    when col = 'reports' then 'site'
    else col end
$$;

create or replace function sanam_private.can(t text, act text)
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select m.is_admin or coalesce((m.permissions->t->>act)::boolean, false)
    from public.sanam_members m where m.user_id = auth.uid() and m.active), false)
$$;

-- project restriction: rows tied to a project must be in the member's allowed list
create or replace function sanam_private.project_ok(col text, rid text, d jsonb)
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((
    select m.is_admin or m.allowed_projects is null
      or (case when col = 'projects' then m.allowed_projects ? rid
               when coalesce(d->>'projectId', '') = '' then true
               else m.allowed_projects ? (d->>'projectId') end)
    from public.sanam_members m where m.user_id = auth.uid() and m.active), false)
$$;

create or replace function sanam_private.needs_approval()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select not m.is_admin and m.requires_approval from public.sanam_members m
    where m.user_id = auth.uid() and m.active), false)
$$;

-- policies run as the signed-in user, so they need to reach the helpers (the schema isn't exposed over REST)
grant usage on schema sanam_private to authenticated;
grant execute on all functions in schema sanam_private to authenticated;

create table public.sanam_data (
  company_id uuid not null default sanam_private.company() references public.sanam_companies(id) on delete cascade,
  collection text not null,
  id text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid(),
  primary key (company_id, collection, id)
);

-- entries from members who need approval are stored as pending, whatever the app sends
create or replace function sanam_private.stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  if new.collection in ('txns', 'reports') and sanam_private.needs_approval() then
    new.data := new.data || jsonb_build_object('pending', true, 'byUser', auth.uid());
  end if;
  return new;
end $$;
grant execute on function sanam_private.stamp() to authenticated;
create trigger sanam_data_stamp before insert or update on public.sanam_data
  for each row execute function sanam_private.stamp();

alter table public.sanam_companies enable row level security;
alter table public.sanam_members enable row level security;
alter table public.sanam_data enable row level security;

create policy "members see their company" on public.sanam_companies for select to authenticated
  using (id = sanam_private.company());
create policy "admin renames company" on public.sanam_companies for update to authenticated
  using (id = sanam_private.company() and (sanam_private.me()).is_admin);

create policy "members see colleagues" on public.sanam_members for select to authenticated
  using (company_id = sanam_private.company() or user_id = auth.uid());
create policy "admin edits members" on public.sanam_members for update to authenticated
  using (company_id = sanam_private.company() and (sanam_private.me()).is_admin and user_id <> auth.uid())
  with check (company_id = sanam_private.company());

-- lists (projects, parties, accounts, employees) are readable by every member so forms can show names;
-- everything else needs "view" on its tab
create policy "read" on public.sanam_data for select to authenticated using (
  company_id = sanam_private.company()
  and (collection in ('projects', 'parties', 'accounts', 'employees') or sanam_private.can(sanam_private.tab(collection, data), 'view'))
  and sanam_private.project_ok(collection, id, data));
create policy "add" on public.sanam_data for insert to authenticated with check (
  company_id = sanam_private.company()
  and sanam_private.can(sanam_private.tab(collection, data), 'edit')
  and sanam_private.project_ok(collection, id, data));
create policy "edit" on public.sanam_data for update to authenticated
  using (company_id = sanam_private.company()
    and sanam_private.can(sanam_private.tab(collection, data), 'edit')
    and sanam_private.project_ok(collection, id, data)
    and (not sanam_private.needs_approval() or coalesce((data->>'pending')::boolean, false)))
  with check (company_id = sanam_private.company()
    and sanam_private.can(sanam_private.tab(collection, data), 'edit')
    and sanam_private.project_ok(collection, id, data));
create policy "delete" on public.sanam_data for delete to authenticated using (
  company_id = sanam_private.company()
  and sanam_private.can(sanam_private.tab(collection, data), 'delete')
  and sanam_private.project_ok(collection, id, data)
  and (not sanam_private.needs_approval() or coalesce((data->>'pending')::boolean, false)));

alter table public.sanam_data replica identity full;
do $$ begin
  alter publication supabase_realtime add table public.sanam_data;
exception when duplicate_object then null; end $$;

-- first sign-in: a person with no company gets their own and becomes its admin
create or replace function public.sanam_session()
returns jsonb language plpgsql security definer set search_path = '' as $$
declare m public.sanam_members; c public.sanam_companies;
begin
  if auth.uid() is null then return null; end if;
  select * into m from public.sanam_members where user_id = auth.uid();
  if not found then
    insert into public.sanam_companies (name, created_by) values ('شركتي', auth.uid()) returning * into c;
    insert into public.sanam_members (company_id, user_id, username, is_admin, permissions)
      values (c.id, auth.uid(), coalesce((select email from auth.users where id = auth.uid()), 'admin'), true, '{}')
      returning * into m;
  end if;
  select * into c from public.sanam_companies where id = m.company_id;
  return jsonb_build_object('company_id', m.company_id, 'company_name', c.name, 'username', m.username,
    'is_admin', m.is_admin, 'active', m.active, 'requires_approval', m.requires_approval,
    'permissions', m.permissions, 'allowed_projects', m.allowed_projects);
end $$;
revoke all on function public.sanam_session() from public, anon;
grant execute on function public.sanam_session() to authenticated;

-- admin approves or rejects a pending entry
create or replace function public.sanam_approve(p_collection text, p_id text, p_ok boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not coalesce((sanam_private.me()).is_admin, false) then raise exception 'not admin'; end if;
  if p_ok then
    update public.sanam_data set data = data - 'pending'
      where company_id = sanam_private.company() and collection = p_collection and id = p_id;
  else
    delete from public.sanam_data
      where company_id = sanam_private.company() and collection = p_collection and id = p_id;
  end if;
end $$;
revoke all on function public.sanam_approve(text, text, boolean) from public, anon;
grant execute on function public.sanam_approve(text, text, boolean) to authenticated;

-- site photos live under the company's folder
insert into storage.buckets (id, name, public) values ('sanam-photos', 'sanam-photos', true) on conflict (id) do nothing;
create policy "sanam_photos_company_upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'sanam-photos' and (storage.foldername(name))[1] = sanam_private.company()::text);
