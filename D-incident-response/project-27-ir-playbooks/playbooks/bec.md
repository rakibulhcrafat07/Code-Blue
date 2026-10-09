# Playbook 3 — Business Email Compromise

**Trigger:** a suspicious payment/bank-change request, or a reported odd mailbox behaviour / login.
**Default severity:** SEV-2 (SEV-1 if funds moved or many mailboxes affected).

![BEC flowchart](../images/04-pb-bec.png)

## Steps
1. **Preserve** the triggering message (full headers) and the invoice/payment details.
2. **Pull sign-in logs + mailbox rules** for the mailbox (M365 UAL / Workspace / Zimbra-Carbonio).
3. **Decide — takeover vs spoof** — headers: `pass` from the **real** domain + an unfamiliar sign-in IP = **account takeover**; `pass` from a **look-alike** domain = **impersonation** (no mailbox to clean, go to awareness + blocking).
4. **Find the hidden rule** — the BEC signature: an inbox/forwarding rule that moves invoice/payment mail to RSS/Archive or forwards it externally. Document it.
5. **Contain** — reset password, **revoke all sessions/tokens**, disable **legacy auth**, remove the malicious rule and any OAuth grants.
6. **Scope** — any other mailboxes with external forwarding; the attacker IP across all users.
7. **Act on the fraud** — notify finance + the real vendor **out-of-band**; contact the bank fraud desk to **freeze/recall** — speed matters most here.

## Runs for real in
[Project 20 — Business Email Compromise](../../project-20-business-email-compromise/)
