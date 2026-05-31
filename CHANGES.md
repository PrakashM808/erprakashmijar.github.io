# Changes in this build

This build is the existing PM::OFFSEC project with the following bugs fixed.
No features were removed and no files were regenerated from scratch — only the
specific defects below were changed. Both test suites pass.

## 1. Admin portal: three tabs threw a ReferenceError (blank/broken tabs)
`admin/index.html`

`ap()` called `renderSMTP()`, `renderApiKeys()` and `renderAISettings()` on tab
open, but those functions were never defined. Opening **SMTP**, **API Keys** or
**AI Settings** threw `ReferenceError` and broke the tab. The three functions are
now defined; SMTP and AI Settings hydrate their form fields from the same
`localStorage` keys their Save handlers already write to (`pm_smtp_config`,
`pm_ai_config`), and API Keys is a safe no-op (its table is static).

Result: 0 of 26 admin tabs broken (was 3 of 26).

## 2. Admin & client could not reach the Scanner Dashboard
`dashboard/assets/js/01-app-core.js`, `admin/index.html`, `client/index.html`,
`business/index.html`

The dashboard's role guard bounces an admin back to the admin portal, and a
client/employee back to the client portal, unless the URL carries `?stay=1`.
The "Scanner Dashboard" buttons and most inline links did not add `?stay=1`, so
clicking them sent the user straight back. Individual clients had no `?stay=1`
exception at all, so the scanner was unreachable for them.

Fixes:
- `?stay=1` added to every "open scanner dashboard" link/button across the
  admin, client and business portals.
- The dashboard guard now honors `?stay=1` for all roles (single early return).
  Normal login-time role routing is otherwise unchanged.

Verified: admin, individual client, employee and business client all land on and
stay at the scan dashboard when they click through; without `?stay=1`,
login-time routing is unchanged.

## 3. Frontend smoke test: stale assertion
`tests/test_frontend_smoke.py`

The test expected the client role badge to read `CLIENT`, but the app
intentionally groups `user`/`client`/`employee` into the "PERSONAL" portal and
renders `PERSONAL`. Updated the assertion to match the app's actual (and
documented) behavior.

## Running the tests
```bash
pip install -r backend/requirements.txt pytest
python3 -m pytest tests/test_backend.py -q          # 18 passed

pip install playwright && python3 -m playwright install chromium
python3 tests/test_frontend_smoke.py                # SMOKE TEST PASSED
```
