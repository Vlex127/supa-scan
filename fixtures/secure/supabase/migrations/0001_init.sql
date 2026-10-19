-- Secure fixture: every construct the v1 rules inspect, written the safe way.
-- The engine MUST report zero findings here; if this ever lights up, either a
-- rule has regressed to a false positive or a fix has drifted.

create table public.todos (
  id bigint generated always as identity primary key,
  title text not null,
  user_id uuid references auth.users (id)
);

alter table public.todos enable row level security;

create policy "select own" on public.todos
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy "insert own" on public.todos
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

-- Deliberately kept: a public-read policy with USING (true) is the legitimate
-- "reference data" pattern, not a vulnerability. The scanner must NOT flag a
-- constant-TRUE predicate on a read-only policy.
create policy "read_public" on public.todos
  for select
  to public
  using (true);

create view public.todo_summary
  with (security_invoker = true)
as
  select user_id, count(*) as n
  from public.todos
  group by user_id;

create function public.touch_updated() returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  return new;
end;
$$;
