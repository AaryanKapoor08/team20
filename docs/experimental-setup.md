# Experimental setup (README section B, draft)

A running list of the hardware, versions, thresholds and sample sizes used for the
experiments. Add to it as each experiment runs. This file is local-only (it is a
`.md` and under `docs/`, both excluded from git); the final version is copied into
the README section B when the experiments are done.

## Machine

- Laptop: Windows 11 Home (10.0.26300)
- CPU: AMD Ryzen 7 8845HS (8 cores / 16 threads)
- GPU: NVIDIA GeForce RTX 4050 Laptop GPU (not used yet; needed for hashcat in E1 step 16.3)
- Python: 3.11.15 (the project's `.venv`)

## Package versions (relevant to experiments)

- flask 3.1.3
- argon2-cffi 25.1.0 (Argon2id)
- cryptography 50.0.2
- bcrypt 5.0.0
- matplotlib 3.11.2
- pyotp 2.10.0

## Password-hashing settings (used by the app and measured in E1)

- Argon2id: library defaults — time_cost 3, memory_cost 65536 KiB (64 MiB), parallelism 4
- bcrypt: cost factor (rounds) 12
- MD5, SHA-256: plain single-pass hashes (shown as the weak baseline)

## E1 — Hash cracking

- Script: `experiments/e1_hash_cracking.py`, output `results/e1_hash_cracking.csv` + `.png`
- Speed sample: hash one password repeatedly for up to 2 s per algorithm, report guesses/second.
- Dictionary attack: a 4000-entry stand-in wordlist with 5 weak passwords placed at the end,
  8 target hashes (5 weak + 3 strong), 1.5 s budget per target hash.
- `seconds_for_rockyou` scales the measured speed to the real rockyou.txt size (14,344,391 lines).
- Result (this machine): MD5 ~1.38M guesses/s, SHA-256 ~1.19M/s, bcrypt ~5/s, Argon2id ~16/s.
  MD5/SHA-256 crack all 5 weak passwords; bcrypt and Argon2id crack 0 within the budget.
- hashcat (step 16.3): **not installed on this machine.** The script detects this and uses the
  Python dictionary attack above, which makes the same point and is fully reproducible. To run
  the real hashcat step later: install hashcat, keep the wordlist in `wordlists/` (gitignored),
  and record GPU hashes/second and % cracked per hash type here.

## E2 — Attacker detection

- Script: `experiments/e2_attacker_detection.py`, output `results/e2_attacker_detection.csv` + `.png`
- Helpers: `experiments/lab_server.py` (starts the app on a fresh temp DB per run) and
  `experiments/_serve.py` (the server entry point). Lab mode on, port 8000.
- Attackers 1 to 3 (`naive_botnet`, `vpn_attacker`, `targeted_attacker`) run against
  `SECURITY_PROFILE=BASELINE` then `ADAPTIVE`. Each run uses its own empty database.
- Result:
  - naive_botnet: stopped under both (all guesses are wrong passwords).
  - vpn_attacker: **gets in under BASELINE**, **blocked by the risk check under ADAPTIVE**.
  - targeted_attacker: **gets in under both** — it copies the victim's whole context, so the
    risk check sees a normal login. This is the case only a passkey stops (see E7).

## E3 — False positives

- Script: `experiments/e3_false_positives.py`, output `results/e3_false_positives.csv` + `.png`
- Replays honest logins through the real risk engine (`app/risk.py`) and counts how many would
  be asked for an extra check at several score thresholds.
- **Dataset note (plan change):** the public RBA dataset (Wiefling et al., `das-group/rba-dataset`,
  CC BY 4.0) is ~15 GB and is not downloaded or committed. Instead E3 uses a generated population
  of ordinary users (stable home device + network, with occasional honest changes: a new phone,
  a browser update, a trip abroad). It models the same question and runs anywhere. If a file
  `data/rba_sample.csv` is dropped in later, `load_rows` can be pointed at it; `data/` is gitignored.
- Sample size: 1000 users, 12 history logins each, 6 test logins each = 6000 honest logins scored,
  against a fixed background of 1000 common logins. Fixed random seed 20, so the result repeats.
- Thresholds tested: 2, 3, 4, 5, 6, 7. The app uses RISK_MEDIUM = 3.
- Result (this machine): at threshold 3, ~4.6% of honest logins get an extra check; dropping to 2
  jumps to ~21%; raising to 7 reaches 0%. Lower threshold = more attackers caught but more real
  users nagged.

## Where nothing committed must go

- Wordlists (rockyou etc.): `wordlists/` — gitignored.
- Datasets (RBA sample): `data/` — gitignored.
- Checked after Phase 16 (step 16.7): only `experiments/*.py` and `results/*.csv`/`*.png` are
  committed; no wordlist, dataset, or temp database is tracked.
