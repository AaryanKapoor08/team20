"""E1: how hard is it to crack a password hash?

We hash the same passwords with four algorithms and compare them two ways:

1. Speed: how many hashes one CPU core can make per second. A fast hash (MD5,
   SHA-256) lets an attacker try billions of guesses; a slow hash (bcrypt,
   Argon2id) is slow on purpose, so the same guessing takes far longer.
2. A small dictionary attack: with a fixed time budget, how many weak passwords
   each hash type lets the attacker crack.

This is why the app stores passwords with Argon2id (see app/passwords.py), not a
plain fast hash. hashcat (step 16.3) is the real cracking tool, but it needs a GPU
build and a separate install; if it is not on PATH we report that and keep the
Python measurement, which makes the same point and runs anywhere.

Run from the project root:  python experiments/e1_hash_cracking.py
"""

import csv
import hashlib
import shutil
import sys
import time
from pathlib import Path

# Running the file directly puts experiments/ on the path, not the project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import bcrypt
import matplotlib

# Draw to a file, not a window, so the script runs with no screen attached
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from argon2 import PasswordHasher

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e1_hash_cracking.csv"
CHART_PATH = RESULTS_DIR / "e1_hash_cracking.png"

# A guess an attacker would make. We hash this over and over to measure speed.
SAMPLE_PASSWORD = "correct horse battery"

# The same settings the app uses, so the numbers match our real password storage
ARGON2 = PasswordHasher()
BCRYPT_ROUNDS = 12

# The five weak passwords we pretend the stolen database holds. A wordlist attack
# finds these; the three strong ones below never appear in any list.
WEAK_PASSWORDS = ["123456", "password", "qwerty", "letmein", "welcome"]
STRONG_PASSWORDS = ["S7!xQ2#mLp", "9z$Vr8@Tn4", "Hk3^Wd6&Bq"]
TARGET_PASSWORDS = WEAK_PASSWORDS + STRONG_PASSWORDS


def build_wordlist() -> list:
    """Return a stand-in leaked-password list (rockyou has ~14 million lines).

    Thousands of filler entries come first and the weak targets sit at the very
    end, so the attacker must try the whole list before cracking one. A fast hash
    races through it; a slow hash runs out of time first. That is the whole point.
    """
    filler = []
    for number in range(WORDLIST_FILLER):
        filler.append(f"guess{number}")
    return filler + WEAK_PASSWORDS


# How many never-matching entries the attacker wades through before the weak ones
WORDLIST_FILLER = 4000

# How long the attacker is allowed to spend on each target hash
CRACK_BUDGET_SECONDS = 1.5

WORDLIST = build_wordlist()

# A real leaked list to put the speed in context (rockyou.txt line count)
ROCKYOU_SIZE = 14_344_391


def md5_hex(text: str) -> str:
    """Return the MD5 hash of a password (a deliberately weak, fast hash)."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha256_hex(text: str) -> str:
    """Return the SHA-256 hash of a password (fast, so weak for passwords)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bcrypt_hash(text: str) -> bytes:
    """Return a bcrypt hash of a password (slow on purpose)."""
    return bcrypt.hashpw(text.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


def argon2_hash(text: str) -> str:
    """Return an Argon2id hash of a password (slow and memory-hard, what the app uses)."""
    return ARGON2.hash(text)


def measure_speed(hash_once, max_seconds: float = 2.0, max_count: int = 500_000) -> float:
    """Return how many hashes per second this algorithm makes on one core."""
    count = 0
    start = time.perf_counter()
    # Keep hashing until either the time budget or the count cap is reached
    while True:
        hash_once(SAMPLE_PASSWORD)
        count += 1
        elapsed = time.perf_counter() - start
        if elapsed >= max_seconds or count >= max_count:
            break
    return count / elapsed


def crack_target(target_hash, verify, budget_seconds: float) -> bool:
    """Try every wordlist entry against one hash until it matches or time runs out."""
    start = time.perf_counter()
    for guess in WORDLIST:
        if verify(guess, target_hash):
            return True
        if time.perf_counter() - start >= budget_seconds:
            return False
    return False


def run_dictionary_attack(make_hash, verify) -> int:
    """Hash every target, then crack each one, and return how many were cracked."""
    target_hashes = []
    for password in TARGET_PASSWORDS:
        target_hashes.append(make_hash(password))

    cracked = 0
    for target_hash in target_hashes:
        if crack_target(target_hash, verify, CRACK_BUDGET_SECONDS):
            cracked += 1
    return cracked


# Each algorithm as (name, hash function, verify function) so one loop handles all four
def match_plain(guess: str, target: str, make_hash) -> bool:
    """Verify a guess for a plain hash by hashing it and comparing the text."""
    return make_hash(guess) == target


ALGORITHMS = [
    ("MD5", md5_hex, lambda g, t: match_plain(g, t, md5_hex)),
    ("SHA-256", sha256_hex, lambda g, t: match_plain(g, t, sha256_hex)),
    ("bcrypt", bcrypt_hash, lambda g, t: bcrypt.checkpw(g.encode("utf-8"), t)),
    ("Argon2id", argon2_hash, lambda g, t: verify_argon2(g, t)),
]


def verify_argon2(guess: str, target_hash: str) -> bool:
    """Verify a guess against an Argon2id hash, returning False on a mismatch."""
    try:
        return ARGON2.verify(target_hash, guess)
    except Exception:
        return False


def seconds_for_rockyou(hashes_per_second: float) -> float:
    """How long it would take to try the whole rockyou list once at this speed."""
    return ROCKYOU_SIZE / hashes_per_second


def collect_rows() -> list:
    """Measure every algorithm and return one result row per algorithm."""
    rows = []
    for name, make_hash, verify in ALGORITHMS:
        print(f"  measuring {name} ...")
        speed = measure_speed(make_hash)
        cracked = run_dictionary_attack(make_hash, verify)
        rows.append({
            "algorithm": name,
            "hashes_per_second": round(speed, 2),
            "seconds_for_rockyou": round(seconds_for_rockyou(speed), 2),
            "cracked": cracked,
            "targets": len(TARGET_PASSWORDS),
            "percent_cracked": round(100 * cracked / len(TARGET_PASSWORDS), 1),
            "crack_budget_seconds": CRACK_BUDGET_SECONDS,
        })
    return rows


def write_csv(rows: list) -> None:
    """Save the result rows to the E1 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw two bars per algorithm: guesses per second (log) and percent cracked."""
    names = [row["algorithm"] for row in rows]
    speeds = [row["hashes_per_second"] for row in rows]
    percents = [row["percent_cracked"] for row in rows]

    figure, (left, right) = plt.subplots(1, 2, figsize=(11, 4.5))

    left.bar(names, speeds, color="#c0392b")
    left.set_yscale("log")
    left.set_ylabel("guesses per second (log scale)")
    left.set_title("Hashing speed: lower is safer")

    right.bar(names, percents, color="#2980b9")
    right.set_ylim(0, 100)
    right.set_ylabel("weak passwords cracked (%)")
    right.set_title(f"Cracked in a {CRACK_BUDGET_SECONDS:g} s dictionary attack")

    figure.suptitle("E1: fast hashes crack passwords, slow hashes resist")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def report_hashcat() -> None:
    """Say whether the real hashcat tool is available (step 16.3)."""
    if shutil.which("hashcat") is None:
        print("hashcat not found on PATH: using the Python dictionary attack above.")
        print("To run step 16.3, install hashcat and point it at a wordlist kept in wordlists/.")
    else:
        print("hashcat is installed. The Python measurement still runs for a like-for-like table.")


def run() -> None:
    """Measure all four hash types, save the CSV and chart, and print a summary."""
    print("E1: comparing MD5, SHA-256, bcrypt and Argon2id")
    rows = collect_rows()
    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        print(
            f"  {row['algorithm']:>9}: {row['hashes_per_second']:>14,.0f} guesses/s, "
            f"cracked {row['cracked']}/{row['targets']} weak"
        )
    print()
    report_hashcat()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
