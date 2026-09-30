# Risk-Based Authentication

**Protecting accounts even after a password is stolen.**

CS2413 Information Security, University of New Brunswick, Fall 2026. Team 20.

> **Status:** in progress. The app and experiments are being built and will be complete by Nov 15, 2026.

## How to run

You only need Python 3.11 or newer. No Docker, no database setup, no config files.

```
git clone https://github.com/AaryanKapoor08/team20.git
cd team20
python run.py
```

On a Mac, use `python3 run.py`. Then open **http://localhost:8000** in your browser.

The first run installs everything and creates the demo accounts. Later runs just start the app. Demo logins will be listed here once the app is ready.

## The problem

Passwords get stolen all the time: fake login pages, malware on someone's laptop, and leaked databases. Once an attacker has the right password, a normal login page cannot tell them apart from the real user.

This project asks: **can we still protect an account after its password is stolen?**

## What the app does

Every login is checked for more than just the password. The app looks at *how* the login is happening: where it comes from, what browser and device it uses, and whether lots of failed logins are happening at the same time. It gives each login a risk level:

| Risk | What happens |
|---|---|
| Low (looks like the usual user) | Logs in normally |
| Medium (something is unusual) | Must also enter a 6-digit code from an authenticator app |
| High (very unusual) | Must use a passkey (fingerprint, face or device PIN), or is blocked |

Other protections:

- **Safe password storage.** Passwords are scrambled with a slow, one-way method, plus a secret key kept outside the database. A stolen database alone is not enough to recover them.
- **Encrypted app codes.** The secrets behind the 6-digit codes are stored locked (encrypted).
- **Logins tied to the device.** If someone copies a logged-in user's cookie to another computer, the session is ended.
- **A log that can't be secretly edited.** Every security event is recorded, and each entry is linked to the one before it, so changing any entry is detected.
- **Admin dashboard.** Shows recent logins, why each one got its risk level, blocked addresses, and whether the log is intact.
- **Firewall rules.** Addresses that behave like attackers get blocked, and the admin page only opens from allowed addresses.

## Tech stack

| Tool | What we use it for |
|---|---|
| Python + Flask | The web app |
| SQLite | The database (a single file, built into Python) |
| Plain HTML and CSS | The web pages |
| Argon2 | Storing passwords safely |
| cryptography (AES) | Encrypting the secrets behind the 6-digit codes |
| pyotp + qrcode | 6-digit authenticator codes and the QR code to set them up |
| webauthn | Passkeys |
| Chart.js | Charts on the admin dashboard |
| pytest | Automated tests |
| matplotlib | Charts for the experiment results |
| hashcat | Password-cracking tool, used only in one experiment |
| Nginx + Docker | Optional second way to run the app, with an extra firewall in front |

Everything installs with Python's normal package installer and works the same on Windows and Mac.

## How we test it

We attack our own app, on our own computer only, with scripts that act like real attackers:

| Attacker | What they try |
|---|---|
| Botnet | Tries leaked passwords from many different addresses and countries |
| VPN attacker | Has the password and pretends to be in the user's country |
| Targeted attacker | Copies the user's country, network and browser, and tricks them into giving up a 6-digit code |
| Malware thief | Has the password and a copied login cookie |
| Lockout abuser | Fails logins on purpose to lock real users out |

We run each attacker against two versions of the app:

- **Baseline:** what most websites do (password, limit on failed attempts, account lockout).
- **Adaptive:** everything described above.

Experiments:

| # | Question |
|---|---|
| E1 | How fast can stolen password databases be cracked with different storage methods? |
| E2 | Which attackers get in, and which protection stops each one? |
| E3 | How often would real users be asked for an extra check by mistake? (using a public dataset of real logins) |
| E4 | Does tying logins to the device stop a stolen cookie? |
| E5 | Can an attacker lock real users out, and does the risk check help? |
| E6 | Is editing the security log detected? |
| E7 | Do passkeys stop an attacker who tricked the user into giving up a code? |

Results, charts and the experiment setup will be added to this README and the `results/` folder.

## Repository layout

| Folder | What is in it | Course section |
|---|---|---|
| `app/` | The web app | A. Implementation |
| `nginx/` | Optional firewall settings | A. Implementation |
| (this README) | How the experiments were set up | B. Experimental setup |
| `attacks/`, `experiments/` | Attack scripts and experiment scripts | C. Experiments |
| `results/` | Data, charts and findings | D. Results |
| `tests/` | Automated tests | |
| `run.py` | Sets everything up and starts the app | |

## Ground rules

All attacks run only against our own app on our own computers. No real users, no real websites.
