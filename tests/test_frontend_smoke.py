"""
Frontend smoke test for the PM::OFFSEC dashboard.

This catches the exact class of bugs we hit in development:
  - JS errors that halt script execution (the infinite-recursion overrides)
  - missing global functions (broken inline onclick handlers)
  - pages that fail to render or leak content across pages (the MSP leak)
  - the scan modal not opening

It loads dashboard/index.html in headless Chromium with an injected session,
then asserts there are zero page errors and every key page/function works.

Run:  python tests/test_frontend_smoke.py
Exit code 0 = pass, 1 = fail.  (CI fails the build on non-zero.)
"""
import json
import pathlib
import sys

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = ROOT / "dashboard" / "index.html"

SESSION = {"id": "smoke", "email": "smoke@test.local", "name": "Smoke",
           "role": "admin", "plan": "pro", "loginAt": 9999999999999}

KEY_FUNCTIONS = [
    "openScanModal", "nav", "scanCameras", "runDarkWebScan", "renderDarkWeb",
    "runRemoteScan", "renderCompliance", "apiGet", "apiPost", "ensureBackendToken",
]

PAGES = [
    "dashboard", "devices", "scan", "webscan", "darkweb", "attacksurface",
    "incidents", "compliance", "msp", "atm", "vending", "fleet", "cameras",
]

FAILURES = []


def check(label, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append((label, detail))


def main():
    url = "file://" + str(INDEX) + "?stay=1"  # ?stay=1 lets the admin session view the dashboard without role-redirect
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
        ctx = browser.new_context(viewport={"width": 1440, "height": 1000})
        ctx.add_init_script(
            "sessionStorage.setItem('pm_session_v2', '%s');" % json.dumps(SESSION)
        )
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(url, wait_until="domcontentloaded", timeout=20000)
        page.wait_for_timeout(2000)

        print("Frontend smoke test")
        # 1) no fatal page errors during load
        check("no page errors on load", not errors, "; ".join(errors[:3]))

        # 2) external CSS applied
        g = page.evaluate(
            "getComputedStyle(document.documentElement).getPropertyValue('--g').trim()"
        )
        check("external CSS loaded", bool(g), f"--g='{g}'")

        # 3) key global functions defined
        missing = [f for f in KEY_FUNCTIONS
                   if page.evaluate("typeof window['" + f + "']") != "function"]
        check("all key functions defined", not missing, f"missing: {missing}")

        # 4) scan modal opens
        page.click("#scanBtn")
        page.wait_for_timeout(400)
        disp = page.evaluate(
            "getComputedStyle(document.getElementById('scanModal')).display"
        )
        check("scan modal opens", disp == "flex", f"display={disp}")

        # 5) every page renders visibly, no MSP leak onto non-MSP pages
        for pid in PAGES:
            page.evaluate("(p)=>nav(p)", pid)
            page.wait_for_timeout(120)
            res = page.evaluate(
                "(pid)=>{const e=document.getElementById('page-'+pid);"
                "if(!e)return 'MISSING';"
                "const r=e.getBoundingClientRect();"
                "const vis=getComputedStyle(e).display!=='none'&&r.width>100;"
                "const leak=(pid!=='msp')&&(e.innerText||'').includes('Total Clients');"
                "return vis?(leak?'LEAK':'OK'):'HIDDEN';}", pid)
            check(f"page '{pid}' renders cleanly", res == "OK", res)

        # 6) no errors accumulated during navigation
        check("no page errors after navigation", not errors, "; ".join(errors[:3]))

        # 7) client portal scoping: switching SESSION.role to client and
        #    re-applying the portal must hide admin/SOC/SIEM sections.
        client_view = page.evaluate(
            "()=>{ if(typeof SESSION==='undefined'||typeof applyRolePortal!=='function') return {skip:true};"
            "SESSION.role='client'; document.getElementById('adminSection').style.display='none';"
            "applyRolePortal();"
            "const shown=(sel)=>{const e=document.querySelector(sel);return e?getComputedStyle(e).display!=='none':false;};"
            "return {admin:shown('#adminSection'), soc:shown('.sb-section[data-sec=soc]'),"
            "siem:shown('.sb-section[data-sec=siem]'), badge:(document.getElementById('hdrRole')||{}).textContent};}"
        )
        if client_view.get("skip"):
            check("client portal (SESSION/applyRolePortal available)", False, "globals missing")
        else:
            check("client portal hides admin section", client_view["admin"] is False, str(client_view))
            check("client portal hides SOC section", client_view["soc"] is False, str(client_view))
            check("client portal hides SIEM section", client_view["siem"] is False, str(client_view))
            check("client role badge shows CLIENT", client_view["badge"] == "CLIENT", str(client_view))

        browser.close()

    print()
    if FAILURES:
        print(f"SMOKE TEST FAILED — {len(FAILURES)} issue(s)")
        sys.exit(1)
    print("SMOKE TEST PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
