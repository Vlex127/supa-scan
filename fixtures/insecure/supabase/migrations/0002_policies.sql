-- Insecure fixture, part 2 (applied after 0001_init.sql). Exercises the
-- cross-file, ordered schema state: todos gets RLS here while audit_log (from
-- the previous migration) stays unprotected.

alter table public.todos enable row level security;

-- POLICY_PERMISSIVE (medium): a constant-TRUE write predicate guarded only by a
-- valid session (authenticated), so severity is medium, not high.
create policy "todos_update_all" on public.todos
  for update
  to authenticated
  using (true)
  with check (true);

-- POLICY_ANON_WRITE + POLICY_PERMISSIVE (high): anonymous writes gated only by TRUE.
create policy "todos_anon_write" on public.todos
  for insert
  to anon
  with check (true);

-- VIEW_NO_SECURITY_INVOKER: defaults to the owner, bypassing the table's RLS.
create view public.open_todos as
  select id, title from public.todos;

-- SECDEF_NO_SEARCH_PATH: runs as owner with an unfixed search_path.
create function public.helper() returns int
language plpgsql
security definer
as $$
begin
  return 1;
end;
$$;
