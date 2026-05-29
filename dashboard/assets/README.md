# Dashboard Assets

The dashboard was refactored from a single 11.9k-line `index.html` into a markup
file plus separated CSS and JavaScript. `index.html` now contains only HTML
markup (~2k lines); all styling and behavior live here.

## Structure

```
dashboard/
  index.html              HTML markup only (pages, modals, header, sidebar)
  assets/
    css/
      dashboard.css        All dashboard styles (merged from 6 inline <style> blocks)
    js/                     Loaded in order as classic scripts (shared global scope)
      00-sanitize.js        escHtml / safeName helpers
      01-app-core.js        Auth guard, state, API layer, scanning, devices, nav,
                            init, plan system, SOC stores, OSINT, threat intel,
                            incidents, IOC, MITRE, playbooks, Wazuh, Splunk,
                            theme, AI remediation, learning center, auto-logout
      02-pwa-install.js     PWA install banner
      03-misc-a.js          Small helpers
      04-modals-soc.js      Modal HTML wiring + SOC interactions
      05-features-ext.js    Extended feature functions
      06-physical-fleet.js  ATM / vending / device fleet / SOAR
      07-init-hardening.js  IP validation, disclaimers, security helpers
      08-patches.js         Function patches (scan/render/compliance wrappers)
      09-final.js           Final launch fixes and missing handlers
```

## Important: load order and global scope

The JS files are loaded as **classic scripts** (not ES modules) in the order
listed above. This is deliberate: the markup uses inline `onclick="fn()"`
handlers throughout, which require functions to be on the global scope.
Converting to ES modules would require either replacing every inline handler
or adding a build step.

**Do not reorder the script tags** — later files patch functions defined in
earlier ones (e.g. the scan/dark-web wrappers in `08-patches.js` depend on
`01-app-core.js` having run first).

## Next refactor step (optional, future)

To move to true ES modules / components, add a build tool (Vite) and either:
1. Replace inline `onclick` handlers with `addEventListener`, or
2. Keep handlers but explicitly attach functions to `window` in each module.

This was intentionally deferred — the current split is a zero-behavior-change
improvement that makes the code navigable and testable first.
