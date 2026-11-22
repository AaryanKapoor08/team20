# Before / after screenshots

Taken 18 November 2026 on Windows 11, Python 3.11, Chrome. Four images: the same attack,
run twice, once against the system **before** our solution and once **after**.

The attack is `attacks/vpn_attacker.py`: an attacker who already has Alice's correct
password and logs in through a VPN in her own country. Nothing about the password is
wrong — this is exactly the "the password is already stolen" case the project is about.

"Before" = `SECURITY_PROFILE=BASELINE`: per-IP rate limit and account lockout only, which
is what most sites do. "After" = `ADAPTIVE`: the same app with the risk check and step-up
turned on. Same code, same database schema, same attack, one setting different.

---

## 01-before-baseline-dashboard.png

**What it shows:** the admin dashboard straight after the attack, with the app in BASELINE.

Read the Recent logins table: `alice@example.com` from **185.199.84.7, CA, Firefox on
Linux**, result **logged in**, risk column **-**. The row above it is the admin opening the
dashboard. The rows below, from `24.70.15.5, Chrome on Windows`, are Alice's own earlier
logins, which the attack script creates first so there is a history to compare against.

The point for the report: the attacker's login sits in the log next to Alice's real ones
and is indistinguishable from them. The stat tiles read Low 0 / Medium 0 / High 0 and the
Risk levels panel says *"No scored logins yet. Logins are scored only in the ADAPTIVE
profile"* — nothing scored it, because in BASELINE nothing is looking. The rate limit and
the lockout never fire, because the attacker never gets a password wrong.

## 03-before-baseline-attacker-view.png

**What it shows:** the same moment from the attacker's side — the home page of Alice's
account, "Logged in as alice@example.com". The attacker is inside. This is the "before"
state in one image.

## 02-after-adaptive-dashboard.png

**What it shows:** the dashboard after the identical attack, with the app in ADAPTIVE.

The same login — `alice@example.com`, **185.199.84.7, CA, Firefox on Linux** — now reads
result **refused**, risk **medium**, and the Reasons column spells out why: *new IP address
for this user; new network (ASN) for this user; new browser for this user; new operating
system for this user*. Alice's own logins in the rows below are still **logged in** at
**low** risk, from the same database and the same engine, which is the other half of the
claim: the check refuses the attacker without punishing the real user.

The stat tiles now read Low 4 / Medium 1 / High 0 and the Risk levels chart has bars,
because logins are being scored at all.

## 04-after-adaptive-attacker-view.png

**What it shows:** the same moment from the attacker's side. Instead of Alice's account
they get the login page with *"This login looks unusual and was blocked. Try again from
your usual device."* The correct password was not enough.

Note the wording: it does not say which signal failed, so an attacker cannot tune their
next attempt against it. The detail only exists on the admin dashboard.

---

## How to reproduce all four

From the project root, with nothing else on port 8000. Move `team20.db` aside first if you
want to keep your own data; each run below starts from a fresh database.

```
# before
del team20.db
python run.py --baseline --lab
#   in a second terminal:
.venv\Scripts\python attacks\vpn_attacker.py      # prints: GOT IN with the stolen password
#   then log in at http://localhost:8000 as admin@example.com / admin-demo-pass
#   and open /admin                                -> screenshot 01
#   the attacker's own view is screenshot 03

# after
del team20.db
python run.py --lab
.venv\Scripts\python attacks\vpn_attacker.py      # prints: stopped by risk block
#   log in as admin and open /admin                -> screenshot 02
#   the attacker's own view is screenshot 04
```

The two script lines above are the evidence in text form, if the report wants to quote them:

```
vpn_attacker: GOT IN with the stolen password (risk check did not fire)
vpn_attacker: stopped by risk block: login refused as too risky
```

## Honest notes, in case a marker asks

- The attacker's IP, country, network and browser are faked through the `X-Lab-Client`
  header, which the app reads **only** when started with `--lab`. With lab mode off the
  header is ignored completely, and `tests/test_client_context.py` checks that. Without it
  every login on one laptop would look identical and no risk check could be demonstrated.
- The two runs use separate fresh databases, so neither run can affect the other.
- This is one attacker of five. `attacks/targeted_attacker.py`, who copies Alice's country,
  network, browser *and* device, still gets in under ADAPTIVE — see E2 in `results/`. That
  is the limit of context-based risk scoring and the reason passkeys are in the project;
  E7 is the experiment that answers it. Say this in the report rather than letting a marker
  find it.
