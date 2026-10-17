# Setup and safety notes

This repository is a **local-only SOC training demonstration** with synthetic data. It is not a production deployment.

## Requirements

- Python 3.10 or newer
- Python virtual environment support
- Flask 3.x (see `requirements.txt`)

## Start the dashboard

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 tests/smoke_test.py
python3 dashboard/app.py
```

Visit http://127.0.0.1:5000/ in a browser. Stop the development server with Ctrl+C.

## Important limitations

- Keep the app bound to `127.0.0.1`. Do not expose port 5000 publicly.
- The demo case-update forms do not implement authentication or CSRF protection.
- Flask's built-in development server is not suitable for production.
- The included SQLite databases are **synthetic demonstration data**, intentionally committed for repeatable exercises.
- The dashboard saves analyst case changes to local SQLite files. To reset, restore the demo database files from Git **only if you do not need to keep your local edits**.
- Never commit tokens, passwords, personal information, or real incident evidence to this repository.

The smoke test checks selected routes and sample alerts. It is not a full security or end-to-end verification.
