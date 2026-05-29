# Tests

Automated regression tests for PM::OFFSEC. These run in CI on every push and
block deploy if anything fails.

## Backend — `test_backend.py` (pytest)

Boots the FastAPI app in in-memory mode with `TestClient` and checks:
- app imports and registers routes (catches the missing-import class of bug)
- `/api/health` works
- auth register/login return valid JWTs; bad passwords are rejected
- protected endpoints (`/api/camera/scan`) return 401 without a token and 200 with one
- the real camera scanner runs end to end
- the Lemon Squeezy webhook never 500s on bad input
- a smoke pass confirms no GET endpoint returns 5xx

```bash
pip install -r backend/requirements.txt pytest
python3 -m pytest tests/test_backend.py -q
```

## Frontend — `test_frontend_smoke.py` (Playwright)

Loads `dashboard/index.html` headless with an injected session and asserts:
- zero JavaScript page errors on load and after navigation
  (this is what catches the infinite-recursion / broken-handler class of bug)
- the external CSS loaded
- all key global functions are defined
- the scan modal opens
- every page renders visibly with no content leaking across pages

```bash
pip install playwright && python3 -m playwright install chromium
python3 tests/test_frontend_smoke.py
```

Exit code 0 = pass, non-zero = fail (CI fails the build).

## Why these specific tests

Every check here maps to a real bug that occurred during development:
recursion that killed the scan button, an orphaned block leaking the MSP
dashboard onto every page, a missing `timedelta` import that 500'd login, and
protected endpoints that didn't actually authenticate from the UI. The tests
exist so those classes of regression can't silently come back.
