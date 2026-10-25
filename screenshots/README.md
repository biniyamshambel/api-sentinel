# Screenshots

These are real captures of the running application, not mockups.

| File | View |
| --- | --- |
| `dashboard.png` | Initial dashboard at 1440 px width, service health online |
| `report.png` | Sample report loaded via **Load sample report**, scrolled to findings |
| `mobile.png` | Responsive layout at 390 px width |

The report capture shows the intentional configuration findings from the deterministic
sample report (`GET /api/demo`): HTTP transport, missing CSP, and missing `Referrer-Policy`.
The risk score is `40` / **High**, using the project's additive rubric.

To reproduce the report screenshot locally:

1. Start the app with `.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000`.
2. Open <http://127.0.0.1:8000>.
3. Click **Load sample report**.
4. Scroll to **Assessment complete** and capture the viewport.
