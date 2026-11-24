-- Stock Khata: database setup for Supabase. Paste all of this in Supabase > SQL Editor > New query > Run.
-- Safe to run again.

create extension if not exists pgcrypto;

-- ---------- tables ----------
create table if not exists public.businesses(
  id uuid primary key default gen_random_uuid(),
  name text not null,
  address text not null default '',
  phone text not null default '',
  gstin text not null default '',
  active boolean not null default true,
  bill_seq integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.members(
  user_id uuid primary key references auth.users(id) on delete cascade,
  business_id uuid not null references public.businesses(id) on delete cascade,
  role text not null check (role in ('owner','cashier')),
  login_id text not null default '',
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.invites(
  code text primary key,
  role text not null check (role in ('owner','cashier')),
  business_id uuid references public.businesses(id) on delete cascade,
  label text not null default '',
  used boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.platform_admins(
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- every vendor's records (products, sales, purchases ...) live here, always tagged with the vendor
create table if not exists public.docs(
  business_id uuid not null references public.businesses(id) on delete cascade,
  col text not null,
  id text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (business_id, col, id)
);

-- shared list of barcode -> product name (no prices, no stock, nothing about any vendor)
create table if not exists public.catalogue(
  barcode text primary key,
  name text not null,
  unit text not null default 'pcs',
  created_at timestamptz not null default now()
);

alter table public.businesses enable row level security;
alter table public.members enable row level security;
alter table public.invites enable row level security;
alter table public.platform_admins enable row level security;
alter table public.docs enable row level security;
alter table public.catalogue enable row level security;

-- ---------- who am I ----------
create or replace function public.my_business() returns uuid
language sql stable security definer set search_path = public as $$
  select m.business_id from public.members m
  join public.businesses b on b.id = m.business_id
  where m.user_id = auth.uid() and m.active and b.active
  limit 1
$$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select m.role from public.members m
  join public.businesses b on b.id = m.business_id
  where m.user_id = auth.uid() and m.active and b.active
  limit 1
$$;

create or replace function public.is_platform_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.platform_admins where user_id = auth.uid())
$$;

-- ---------- access rules ----------
-- owner: everything of own business. cashier: can read products and sales, and add sales. Nothing else.
drop policy if exists docs_select on public.docs;
create policy docs_select on public.docs for select to authenticated
  using (business_id = public.my_business()
         and (public.my_role() = 'owner' or col in ('products','sales')));

drop policy if exists docs_insert on public.docs;
create policy docs_insert on public.docs for insert to authenticated
  with check (business_id = public.my_business()
              and (public.my_role() = 'owner' or (public.my_role() = 'cashier' and col = 'sales')));

drop policy if exists docs_update on public.docs;
create policy docs_update on public.docs for update to authenticated
  using (business_id = public.my_business() and public.my_role() = 'owner')
  with check (business_id = public.my_business() and public.my_role() = 'owner');

drop policy if exists docs_delete on public.docs;
create policy docs_delete on public.docs for delete to authenticated
  using (business_id = public.my_business() and public.my_role() = 'owner');

drop policy if exists catalogue_select on public.catalogue;
create policy catalogue_select on public.catalogue for select to authenticated
  using (public.my_business() is not null);

drop policy if exists catalogue_insert on public.catalogue;
create policy catalogue_insert on public.catalogue for insert to authenticated
  with check (public.my_role() = 'owner');

-- businesses, members, invites, platform_admins have no direct access: only the functions below touch them.

-- ---------- functions the app calls ----------
create or replace function public.my_context() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r jsonb;
begin
  if auth.uid() is null then return null; end if;
  select jsonb_build_object(
      'business_id', b.id, 'role', m.role, 'login_id', m.login_id,
      'member_active', m.active, 'business_active', b.active,
      'name', b.name, 'address', b.address, 'phone', b.phone, 'gstin', b.gstin)
    into r
    from public.members m join public.businesses b on b.id = m.business_id
    where m.user_id = auth.uid();
  return jsonb_build_object('member', r, 'is_admin', public.is_platform_admin(), 'user_id', auth.uid());
end $$;

-- lets the sign up screen check a code before creating the account
create or replace function public.check_invite(p_code text) returns text
language sql stable security definer set search_path = public as $$
  select role from public.invites where code = upper(trim(p_code)) and not used
$$;

create or replace function public.claim_invite(p_code text, p_name text, p_login text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare inv public.invites%rowtype; bid uuid; nm text := trim(coalesce(p_name,''));
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  if exists(select 1 from public.members where user_id = auth.uid()) then raise exception 'already_member'; end if;
  select * into inv from public.invites where code = upper(trim(p_code)) and not used for update;
  if not found then raise exception 'bad_code'; end if;
  if inv.role = 'owner' then
    if nm = '' then raise exception 'name_required'; end if;
    insert into public.businesses(name) values (left(nm, 80)) returning id into bid;
  else
    bid := inv.business_id;
  end if;
  insert into public.members(user_id, business_id, role, login_id)
    values (auth.uid(), bid, inv.role, left(coalesce(p_login,''), 40));
  update public.invites set used = true where code = inv.code;
  return jsonb_build_object('ok', true, 'role', inv.role);
end $$;

create or replace function public.create_staff_invite() returns text
language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if public.my_role() is distinct from 'owner' then raise exception 'not_allowed'; end if;
  c := upper(encode(gen_random_bytes(4), 'hex'));
  insert into public.invites(code, role, business_id, label) values (c, 'cashier', public.my_business(), 'cashier');
  return c;
end $$;

create or replace function public.list_staff() returns table(user_id uuid, login_id text, role text, active boolean)
language plpgsql stable security definer set search_path = public as $$
begin
  if public.my_role() is distinct from 'owner' then raise exception 'not_allowed'; end if;
  return query select m.user_id, m.login_id, m.role, m.active from public.members m
    where m.business_id = public.my_business() order by m.role desc, m.created_at;
end $$;

create or replace function public.set_staff_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_role() is distinct from 'owner' then raise exception 'not_allowed'; end if;
  update public.members set active = p_active
    where user_id = p_user and business_id = public.my_business() and role = 'cashier';
end $$;

create or replace function public.update_business(p_name text, p_address text, p_phone text, p_gstin text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_role() is distinct from 'owner' then raise exception 'not_allowed'; end if;
  if trim(coalesce(p_name,'')) = '' then raise exception 'name_required'; end if;
  update public.businesses set name = left(trim(p_name), 80), address = left(coalesce(p_address,''), 200),
    phone = left(coalesce(p_phone,''), 20), gstin = left(upper(coalesce(p_gstin,'')), 20)
    where id = public.my_business();
end $$;

create or replace function public.next_bill_no() returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if public.my_business() is null then raise exception 'not_allowed'; end if;
  update public.businesses set bill_seq = bill_seq + 1 where id = public.my_business() returning bill_seq into n;
  return n;
end $$;

-- platform owner (you) only
create or replace function public.admin_create_vendor_invite(p_label text) returns text
language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if not public.is_platform_admin() then raise exception 'not_allowed'; end if;
  c := upper(encode(gen_random_bytes(4), 'hex'));
  insert into public.invites(code, role, label) values (c, 'owner', left(coalesce(p_label,''), 60));
  return c;
end $$;

create or replace function public.admin_list_invites() returns table(code text, label text, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform_admin() then raise exception 'not_allowed'; end if;
  return query select i.code, i.label, i.created_at from public.invites i
    where i.role = 'owner' and not i.used order by i.created_at desc;
end $$;

create or replace function public.admin_list_businesses() returns table(id uuid, name text, active boolean, created_at timestamptz, owner_login text, staff integer)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform_admin() then raise exception 'not_allowed'; end if;
  return query select b.id, b.name, b.active, b.created_at,
      coalesce((select m.login_id from public.members m where m.business_id = b.id and m.role = 'owner' limit 1), ''),
      (select count(*)::integer from public.members m where m.business_id = b.id and m.role = 'cashier')
    from public.businesses b order by b.created_at desc;
end $$;

create or replace function public.admin_set_business_active(p_id uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_platform_admin() then raise exception 'not_allowed'; end if;
  update public.businesses set active = p_active where id = p_id;
end $$;

-- ---------- bill PDFs (public link, hard to guess) ----------
insert into storage.buckets(id, name, public) values ('bills', 'bills', true) on conflict (id) do nothing;

drop policy if exists bills_insert on storage.objects;
create policy bills_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'bills' and (storage.foldername(name))[1] = public.my_business()::text);

-- ---------- live updates ----------
do $$ begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null;
          when undefined_object then null;
end $$;
