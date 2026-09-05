-- Fixtures + 200 queued scan_jobs for the claim_next_scan_job() concurrency
-- test. Uses a fixed, clearly-marked test UUID and ON CONFLICT upserts so
-- it never truncates real data -- safe to run against a real Supabase
-- project (it only adds one test user/target/200 jobs of its own).
--
-- WARNING: this is a synthetic UUID chosen for testing only. If you run
-- this against a project with real users, do not reuse this UUID for
-- anything else, and clean up the test rows afterwards (see bottom).

insert into auth.users (id, email)
values ('00000000-0000-0000-0000-000000000001', 'concurrency-tester@smart-sec.local')
on conflict (id) do nothing;

insert into public.profiles (id, full_name, role)
values ('00000000-0000-0000-0000-000000000001', 'Concurrency Tester', 'admin')
on conflict (id) do update set full_name = excluded.full_name, role = excluded.role;

insert into public.scan_targets (id, owner_id, url, program_name, is_authorized)
values (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'https://concurrency-test.local',
  'Concurrency Test Target',
  true
)
on conflict (owner_id, url) do nothing;

insert into public.scan_jobs (owner_id, target_id, status)
select
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000002',
  'queued'
from generate_series(1, 200);

select count(*) as total_queued_jobs
from public.scan_jobs
where status = 'queued' and owner_id = '00000000-0000-0000-0000-000000000001';

-- Cleanup after the test (run manually once done):
--   delete from public.scan_jobs where owner_id = '00000000-0000-0000-0000-000000000001';
--   delete from public.scan_targets where id = '00000000-0000-0000-0000-000000000002';
--   delete from public.profiles where id = '00000000-0000-0000-0000-000000000001';
--   delete from auth.users where id = '00000000-0000-0000-0000-000000000001';
