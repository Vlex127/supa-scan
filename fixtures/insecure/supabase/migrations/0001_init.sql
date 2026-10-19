-- Insecure fixture: deliberately bad patterns. The scanner must flag every one
-- of these. Keep this file free of anything that should be clean, so a future
-- rule regression is obvious.

-- Two tables, neither protected yet.
create table public.todos (
  id bigint generated always as identity primary key,
  title text not null,
  user_id uuid
);

create table public.audit_log (
  id bigint generated always as identity primary key,
  message text
);
