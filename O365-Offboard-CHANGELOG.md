# O365 Offboard PowerShell — Changelog

**Script:** `O365-Offboard.ps1` (also `O365-Offboard-Jeremy-hardened.ps1`)  
**Author base:** Jeremy · **Hardened:** Zeus for Michael Menor (Tactical IT)  
**Version:** 1.1.0 · **Date:** 2026-10-01  

Complementary to on-prem `AD.html`. Does **not** merge AD logic. Never deletes the user object or purges a mailbox. **Do not** run against a live tenant without intent.

## 1.1.0 — 2026-10-01 — Zeus harden for Michael

### Required bug fixes
1. Fixed group list loop: `i++` → `$i++`.
2. `Select-User`: initialize `$validSelection = $false` before the do/while so multi-match selection works.
3. Implemented missing `Set-MailSettings` (menu 4): show current type/forwarding/GAL/LitigationHold; actions Hide from GAL, Clear forwarding, Set AutoReply (optional); confirm each change; catch hybrid errors. Litigation Hold left alone.
4. Implemented missing `Remove-UserLicenses` (menu 5): list assigned SKUs via Graph, interactive select (incl. Select All), confirm, before/after.
5. `Remove-Groups` **A: Select All** implemented (was stub).
6. Exit (7) and `try/finally` around main loop always disconnect EXO + Graph (covers Ctrl+C / terminating errors).
7. Typos: `grups` → `groups`; header `.PENDINGFUNCTIONS` updated (Remove-Groups / licenses / mail settings done; mailbox Full Access / Send As still pending).
8. `Disable-UserSignIn`: before/after `AccountEnabled`, confirm, clear hybrid/AD-synced error message.
9. `Convert-ToSharedMailbox`: confirm, before/after `RecipientTypeDetails`, hybrid failure guidance.
10. Actions 1–5 require a selected user (`Test-UserSelected`); offers prompt to select if null.

### Hardening
- Version **1.1.0**, date **2026-10-01**, history note *Zeus harden for Michael*.
- `#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, ExchangeOnlineManagement` (install via `Install-Module` if missing — see script comment).
- `Ensure-CloudConnections`: check Graph/EXO and reconnect if needed.
- Detect `onPremisesSyncEnabled`; warn and guide to AD term + sync before cloud-only mutations.
- `Remove-Groups`: warn/skip-attempt messaging for dynamic, role-assignable, and well-known groups (`All Users` / `All Company`); no Domain Users in cloud.
- Consistent `Write-Host` colors; no secrets logged.
- Indentation normalized to spaces; interactive menu style preserved.

### Intentionally left pending
- Set mailbox permissions (Full Access / Send As / Send on Behalf) — listed under `.PENDINGFUNCTIONS`.
- No live `Connect-MgGraph` / `Connect-ExchangeOnline` validation in this deliverable (no tenant run by design).

## Prior
- **1.0.1** — 2026-08-24 — Implement Remove-Groups  
- **1.0.0** — 2026-08-17 — Initial script (Jeremy)
