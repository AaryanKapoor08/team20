# Risk-Based Authentication

CS2413 Information Security, University of New Brunswick, Fall 2026. Team 20.

## The problem

Passwords get stolen through phishing, malware and database leaks. Once an attacker has the right password, a normal login page cannot tell them apart from the real user. This project asks a simple question: can we still protect an account after its password is stolen?

## What we are building

A Flask web app with a login system that looks at more than the password. Every login attempt is scored by a risk engine based on its context: IP address, country, network (ASN), browser and how many failed attempts are happening.

- Low risk: the user logs in normally.
- Medium risk: the user must enter a TOTP code from an authenticator app.
- High risk: the user must use a passkey, or the attempt is blocked.

Other defenses include Argon2id password hashing with a pepper, encrypted TOTP secrets, sessions tied to the device that created them, a tamper-evident audit log, an admin dashboard, and Nginx as a firewall in front of the app.

## How we test it

We attack our own system on localhost with simulated attackers: a credential stuffing botnet, a VPN attacker, a targeted attacker with a phished code, an infostealer with a stolen session cookie, and someone trying to lock real users out. We compare a baseline setup (password, rate limiting, lockout) against the full adaptive setup and record which defense stops which attacker.

We also measure how many real logins would be flagged by mistake, using a public login dataset.

## Repository layout

| Folder | Contents |
|---|---|
| `app/` | A. Implementation |
| `nginx/` | A. Firewall config |
| `docs/` | B. Experimental setup, proposal and threat analysis |
| `simulator/`, `experiments/` | C. Attacker scripts and experiments |
| `results/` | D. Data, charts and findings |

Setup instructions will be added once the app is running.
