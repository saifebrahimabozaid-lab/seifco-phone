-- Seifco Phone shared backend schema (Supabase / PostgreSQL)
-- Run this in Supabase SQL Editor. Never put the service_role key in the browser.
create extension if not exists pgcrypto;

create table if not exists public.shops (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'سيفكو فون',
  owner_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  shop_id uuid references public.shops(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'admin' check (role in ('admin','employee')),
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_seifco_user()
returns trigger language plpgsql security definer set search_path = public
as $$
declare new_shop uuid;
begin
  insert into public.shops(name, owner_id)
  values ('سيفكو فون', new.id)
  returning id into new_shop;
  insert into public.profiles(id, shop_id, display_name, role)
  values (new.id, new_shop, coalesce(new.raw_user_meta_data->>'display_name','مدير المحل'), 'admin');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_seifco on auth.users;
create trigger on_auth_user_created_seifco
after insert on auth.users
for each row execute procedure public.handle_new_seifco_user();

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null, code text, price numeric(12,2) not null default 0 check(price >= 0),
  cost numeric(12,2) not null default 0 check(cost >= 0), qty integer not null default 0 check(qty >= 0),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique(shop_id, code)
);
create table if not exists public.sales (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  invoice_no text, items jsonb not null default '[]'::jsonb, subtotal numeric(12,2) not null default 0,
  discount numeric(12,2) not null default 0, total numeric(12,2) not null default 0,
  customer_id uuid, created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.expenses (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  note text not null, amount numeric(12,2) not null check(amount > 0),
  created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.purchases (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  supplier_id uuid, product_id uuid, name text not null, code text, cost numeric(12,2) not null default 0,
  qty integer not null check(qty > 0), total numeric(12,2) not null default 0,
  created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.customers (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null, phone text, notes text, created_at timestamptz not null default now()
);
create table if not exists public.suppliers (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null, phone text, notes text, created_at timestamptz not null default now()
);
create table if not exists public.maintenance (
  id uuid primary key default gen_random_uuid(), shop_id uuid not null references public.shops(id) on delete cascade,
  customer text not null, phone text, device text not null, issue text not null,
  status text not null default 'قيد الاستلام', cost numeric(12,2) not null default 0,
  notes text, created_by uuid references auth.users(id), created_at timestamptz not null default now()
);

create index if not exists products_shop_idx on public.products(shop_id);
create index if not exists sales_shop_date_idx on public.sales(shop_id, created_at desc);
create index if not exists expenses_shop_date_idx on public.expenses(shop_id, created_at desc);
create index if not exists purchases_shop_date_idx on public.purchases(shop_id, created_at desc);
create index if not exists customers_shop_idx on public.customers(shop_id);
create index if not exists suppliers_shop_idx on public.suppliers(shop_id);
create index if not exists maintenance_shop_date_idx on public.maintenance(shop_id, created_at desc);

create or replace function public.current_shop_id()
returns uuid language sql stable security definer set search_path = public
as $$ select shop_id from public.profiles where id = auth.uid() $$;
create or replace function public.is_shop_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin') $$;

alter table public.shops enable row level security;
alter table public.profiles enable row level security;
do $$
declare t text;
begin
 foreach t in array array['products','sales','expenses','purchases','customers','suppliers','maintenance'] loop
   execute format('alter table public.%I enable row level security', t);
 end loop;
end $$;

drop policy if exists "shop members read own shop" on public.shops;
create policy "shop members read own shop" on public.shops for select to authenticated
using (id = public.current_shop_id());
drop policy if exists "profile members read own shop" on public.profiles;
create policy "profile members read own shop" on public.profiles for select to authenticated
using (shop_id = public.current_shop_id());
drop policy if exists "admin manage profiles" on public.profiles;
create policy "admin manage profiles" on public.profiles for all to authenticated
using (shop_id = public.current_shop_id() and public.is_shop_admin())
with check (shop_id = public.current_shop_id() and public.is_shop_admin());

-- Members can read shop records. Employees may create sales/expenses; only admins
-- may change or delete records and manage stock, purchases, contacts and maintenance.
do $$
declare t text;
begin
 foreach t in array array['products','sales','expenses','purchases','customers','suppliers','maintenance'] loop
   execute format('drop policy if exists "read own shop %1$s" on public.%1$I', t);
   execute format('create policy "read own shop %1$s" on public.%1$I for select to authenticated using (shop_id = public.current_shop_id())', t);
 end loop;
end $$;

drop policy if exists "admin manage products" on public.products;
create policy "admin manage products" on public.products for all to authenticated
using (shop_id=public.current_shop_id() and public.is_shop_admin())
with check (shop_id=public.current_shop_id() and public.is_shop_admin());

drop policy if exists "staff create sales" on public.sales;
create policy "staff create sales" on public.sales for insert to authenticated
with check (shop_id=public.current_shop_id() and created_by=auth.uid());
drop policy if exists "admin manage sales" on public.sales;
create policy "admin manage sales" on public.sales for all to authenticated
using (shop_id=public.current_shop_id() and public.is_shop_admin())
with check (shop_id=public.current_shop_id() and public.is_shop_admin());

drop policy if exists "staff create expenses" on public.expenses;
create policy "staff create expenses" on public.expenses for insert to authenticated
with check (shop_id=public.current_shop_id() and created_by=auth.uid());
drop policy if exists "admin manage expenses" on public.expenses;
create policy "admin manage expenses" on public.expenses for all to authenticated
using (shop_id=public.current_shop_id() and public.is_shop_admin())
with check (shop_id=public.current_shop_id() and public.is_shop_admin());

do $$
declare t text;
begin
 foreach t in array array['purchases','customers','suppliers','maintenance'] loop
   execute format('drop policy if exists "admin manage %1$s" on public.%1$I', t);
   execute format('create policy "admin manage %1$s" on public.%1$I for all to authenticated using (shop_id=public.current_shop_id() and public.is_shop_admin()) with check (shop_id=public.current_shop_id() and public.is_shop_admin())', t);
 end loop;
end $$;

-- Employee account creation/deletion must be performed by a trusted server function
-- using the Supabase service role. Do not expose service_role credentials to app.js.
