# ContractShield

ContractShield is a small web app for reviewing Solidity source. It sends a selected
`.sol` file or pasted source to a FastAPI service, checks the source against the
implemented rules, and returns findings with source lines and remediation guidance.

## Run locally

Requirements: Node.js 20+ and Python 3.11+.

### API

From the repository root in PowerShell:

```powershell
cd apps/api
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The API runs at <http://localhost:8000>; its health check is
<http://localhost:8000/api/v1/health>. API documentation is at
<http://localhost:8000/docs>.

### Web app

In a second PowerShell window:

```powershell
cd apps/web
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open <http://localhost:3000>. The web app calls
`NEXT_PUBLIC_API_BASE_URL` from `apps/web/.env.local`, which defaults to
`http://localhost:8000/api/v1`.

### Tests and build

```powershell
cd apps/api
.\.venv\Scripts\python.exe -m pytest

cd ..\web
npm run lint
npm run build
```

## Current analysis scope

The API currently checks Solidity source for:

- `tx.origin` authorization
- `delegatecall`
- `selfdestruct` and the legacy `suicide` alias
- A low-level `.call` followed by a later assignment in the same function, as a
  possible reentrancy pattern (suppressed when the function declares
  `nonReentrant`)

Each match includes a line, rationale, severity, and a recommendation. The
analysis endpoint accepts `.sol` source up to 200,000
characters. It analyzes the request in memory; it does not save scan history.

This is a limited, rule-based source-pattern screen—not an AI model, Solidity
compiler, or complete security audit. It can miss issues, and some findings need
manual review. “No known patterns found” means only that these implemented checks
did not match; it is not a claim that a contract is safe. Analysis does not
currently include imported dependencies, inherited project files, deployed
bytecode, or contract-specific business logic.

User accounts, Supabase persistence, historical dashboards, and scan storage are
not currently connected. The active source-review flow does not require Supabase
credentials.
