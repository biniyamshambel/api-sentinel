# Screenshots

These are real captures of the running application, not mockups. They were captured with
headless Chromium through Selenium against the local demo servers started by
`./scripts/run_demo.sh`.

| File | View |
| --- | --- |
| `dashboard.png` | Initial warm white and coffee dashboard at 1440 px width, empty state, exports disabled |
| `report.png` | Sample report loaded via **Load sample report**, scrolled to the assessment, score, and findings |
| `mobile.png` | Initial responsive layout at 390 px width, no horizontal overflow |

The report capture uses the deterministic sample report (`GET /api/demo`): HTTP transport,
missing CSP, and missing `Referrer-Policy`. The score is `40` / **High**, using the project's
additive rubric. No outbound request is made when loading it.

Both export buttons are enabled only after a report exists. The PDF button sends that same
report to `POST /api/report/pdf`; the JSON button serializes the same object in the browser.

To reproduce locally:

1. Start both servers with `./scripts/run_demo.sh`.
2. Open <http://127.0.0.1:8000>.
3. Capture the initial empty state.
4. Click **Load sample report**.
5. Scroll to **Assessment complete** and capture the viewport, or download the PDF/JSON to
   verify exports.
6. Resize to 390 px width for the mobile capture. The page should not scroll horizontally.

Browser checks used in this project also covered keyboard focus, severity filtering, both
real downloads, console errors, and widths of 1440, 980, 760, 520, and 390 px.
