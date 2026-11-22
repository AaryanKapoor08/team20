"""E1: how hard is it to crack a stolen password hash?

Hashes the same passwords with MD5, SHA-256, bcrypt and Argon2id, measures guesses per
second, then runs a small dictionary attack with a time limit.
Run from the project root:  python experiments/e1_hash_cracking.py
"""

import csv
import hashlib
import time
from pathlib import Path

import bcrypt
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "results" / "e1_hash_cracking.csv"
CHART_PATH = ROOT / "results" / "e1_hash_cracking.png"

ARGON2 = PasswordHasher()
BCRYPT_ROUNDS = 12
SAMPLE_PASSWORD = "correct horse battery"
CRACK_SECONDS = 1.5
ROCKYOU_SIZE = 14344391

WEAK = ["123456", "password", "qwerty", "letmein", "welcome"]
STRONG = ["S7!xQ2#mLp", "9z$Vr8@Tn4", "Hk3^Wd6&Bq"]
TARGETS = WEAK + STRONG

# 4000 wrong guesses first, then the weak passwords at the very end
WORDLIST = []
for number in range(4000):
    WORDLIST.append("guess" + str(number))
WORDLIST = WORDLIST + WEAK


def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()


def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


def hash_argon2(password):
    return ARGON2.hash(password)


def check_md5(guess, target):
    return hash_md5(guess) == target


def check_sha256(guess, target):
    return hash_sha256(guess) == target


def check_bcrypt(guess, target):
    return bcrypt.checkpw(guess.encode(), target)


def check_argon2(guess, target):
    try:
        return ARGON2.verify(target, guess)
    except VerificationError:
        return False


# name, how to hash, how to check a guess
ALGORITHMS = [
    ("MD5", hash_md5, check_md5),
    ("SHA-256", hash_sha256, check_sha256),
    ("bcrypt", hash_bcrypt, check_bcrypt),
    ("Argon2id", hash_argon2, check_argon2),
]


def guesses_per_second(make_hash):
    """Hash the sample password for up to 2 seconds and return the speed."""
    count = 0
    start = time.perf_counter()
    while True:
        make_hash(SAMPLE_PASSWORD)
        count += 1
        elapsed = time.perf_counter() - start
        if elapsed >= 2.0 or count >= 500000:
            return count / elapsed


def crack(target, check):
    """Try the wordlist on one hash. Return True if found before time runs out."""
    start = time.perf_counter()
    for guess in WORDLIST:
        if check(guess, target):
            return True
        if time.perf_counter() - start >= CRACK_SECONDS:
            return False
    return False


def main():
    """Measure all four, save the CSV and chart, print the result."""
    rows = []
    for name, make_hash, check in ALGORITHMS:
        print("measuring", name, "...")
        speed = guesses_per_second(make_hash)
        cracked = 0
        for password in TARGETS:
            if crack(make_hash(password), check):
                cracked += 1
        rows.append({
            "algorithm": name,
            "hashes_per_second": round(speed, 2),
            "seconds_for_rockyou": round(ROCKYOU_SIZE / speed, 2),
            "cracked": cracked,
            "targets": len(TARGETS),
            "percent_cracked": round(100 * cracked / len(TARGETS), 1),
            "crack_budget_seconds": CRACK_SECONDS,
        })

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    names = []
    speeds = []
    percents = []
    for row in rows:
        names.append(row["algorithm"])
        speeds.append(row["hashes_per_second"])
        percents.append(row["percent_cracked"])
    figure, (left, right) = plt.subplots(1, 2, figsize=(11, 4.5))
    left.bar(names, speeds, color="grey", edgecolor="black")
    left.set_yscale("log")
    left.set_title("Guesses per second (lower is safer)")
    right.bar(names, percents, color="black")
    right.set_ylim(0, 100)
    right.set_title("Passwords cracked in 1.5 s (%)")
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)

    for row in rows:
        print(row["algorithm"], ":", round(row["hashes_per_second"]), "guesses/s, cracked", row["cracked"], "of", row["targets"])


if __name__ == "__main__":
    main()
