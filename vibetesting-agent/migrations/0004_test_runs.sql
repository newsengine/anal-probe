-- #32 — run-ledger: every test run + its sub-tests (keyed by VTA number).
CREATE TABLE IF NOT EXISTS test_runs (
  id TEXT PRIMARY KEY,
  scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  run_number INTEGER,
  target TEXT NOT NULL,
  actor TEXT NOT NULL,
  trigger TEXT,
  priority TEXT NOT NULL,
  passed INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  fail_high INTEGER NOT NULL DEFAULT 0,
  fail_medium INTEGER NOT NULL DEFAULT 0,
  fail_low INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER,
  finished_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS test_runs_user_idx ON test_runs(user_id);
CREATE INDEX IF NOT EXISTS test_runs_target_idx ON test_runs(target, run_number);
CREATE INDEX IF NOT EXISTS test_runs_project_idx ON test_runs(project_id);

CREATE TABLE IF NOT EXISTS test_results (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  vta_number INTEGER,
  check_id TEXT NOT NULL,
  category TEXT,
  severity TEXT,
  pass INTEGER NOT NULL,
  detail TEXT,
  atlas TEXT
);
CREATE INDEX IF NOT EXISTS test_results_run_idx ON test_results(run_id);
CREATE INDEX IF NOT EXISTS test_results_check_idx ON test_results(check_id);
CREATE INDEX IF NOT EXISTS test_results_vta_idx ON test_results(vta_number);
