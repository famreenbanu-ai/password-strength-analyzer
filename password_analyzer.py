"""
Password Strength Analyzer & Secure Password Generator
IBM Cybersecurity Bootcamp Project

Features:
  1. Scores a password (0-100) using length, character variety, entropy,
     common-password check, and pattern checks (repeats, sequences, keyboard walks).
  2. Estimates brute-force crack time from entropy.
  3. Generates cryptographically secure passwords/passphrases using `secrets`.

Usage:
  python password_analyzer.py analyze            (prompts securely, input hidden)
  python password_analyzer.py generate --length 16
  python password_analyzer.py passphrase --words 5
"""
import argparse
import getpass
import math
import re
import secrets
import string

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "superman",
    "1qaz2wsx", "7777777", "welcome", "admin", "login", "passw0rd", "iloveyou",
    "princess", "admin123", "password1", "password123", "qwerty123", "india123",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

WORDLIST = [
    "anchor", "bridge", "candle", "dolphin", "ember", "falcon", "garden",
    "harbor", "island", "jungle", "kettle", "lantern", "meadow", "nebula",
    "orchid", "pepper", "quartz", "river", "saddle", "timber", "umbrella",
    "valley", "willow", "yonder", "zephyr", "copper", "marble", "thunder",
    "velvet", "whisper", "crystal", "horizon", "pioneer", "voyage", "sunrise",
    "granite", "monsoon", "lotus", "temple", "coconut", "jasmine", "cinnamon",
]


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 32
    return size


def entropy_bits(password):
    size = charset_size(password)
    return len(password) * math.log2(size) if size else 0.0


def has_sequence(password, n=3):
    p = password.lower()
    for i in range(len(p) - n + 1):
        chunk = p[i:i + n]
        if chunk.isalnum() or chunk.isdigit():
            codes = [ord(c) for c in chunk]
            if all(codes[j + 1] - codes[j] == 1 for j in range(n - 1)):
                return True
            if all(codes[j] - codes[j + 1] == 1 for j in range(n - 1)):
                return True
    return False


def has_keyboard_walk(password, n=4):
    p = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - n + 1):
            seg = row[i:i + n]
            if seg in p or seg[::-1] in p:
                return True
    return False


def has_repeats(password, n=3):
    return re.search(r"(.)\1{%d,}" % (n - 1), password) is not None


def format_time(seconds):
    units = [("years", 31536000), ("days", 86400), ("hours", 3600),
             ("minutes", 60), ("seconds", 1)]
    if seconds < 1:
        return "instantly"
    if seconds > 31536000 * 1e9:
        return "billions of years+"
    for name, sec in units:
        if seconds >= sec:
            return f"{seconds / sec:,.1f} {name}"
    return "instantly"


def analyze(password):
    feedback = []
    score = 0
    length = len(password)

    # Length (up to 40 pts)
    score += min(length, 20) * 2
    if length < 8:
        feedback.append("Use at least 8 characters (12+ recommended).")
    elif length < 12:
        feedback.append("Longer is stronger: aim for 12+ characters.")

    # Variety (up to 28 pts)
    checks = {
        "lowercase letters": r"[a-z]",
        "uppercase letters": r"[A-Z]",
        "digits": r"\d",
        "special characters": r"[^A-Za-z0-9]",
    }
    for label, pattern in checks.items():
        if re.search(pattern, password):
            score += 7
        else:
            feedback.append(f"Add {label}.")

    # Entropy bonus (up to 32 pts)
    bits = entropy_bits(password)
    score += min(int(bits / 80 * 32), 32)

    # Penalties
    common = password.lower() in COMMON_PASSWORDS
    if common:
        score = min(score, 5)
        feedback.append("This is a very common password. Never use it.")
    if has_repeats(password):
        score -= 10
        feedback.append("Avoid repeated characters (e.g. 'aaa').")
    if has_sequence(password):
        score -= 10
        feedback.append("Avoid sequences like 'abc' or '123'.")
    if has_keyboard_walk(password):
        score -= 10
        feedback.append("Avoid keyboard patterns like 'qwerty'.")

    score = max(0, min(100, score))
    if score < 30:
        rating = "Very Weak"
    elif score < 50:
        rating = "Weak"
    elif score < 70:
        rating = "Medium"
    elif score < 85:
        rating = "Strong"
    else:
        rating = "Very Strong"

    # Assume attacker makes 10 billion guesses/second (offline, fast hash)
    guesses = 2 ** bits if bits else 1
    crack_seconds = guesses / 2 / 1e10
    if common:
        crack_seconds = 0

    if not feedback:
        feedback.append("Great password! Store it in a password manager.")

    return {
        "score": score,
        "rating": rating,
        "entropy_bits": round(bits, 1),
        "crack_time": format_time(crack_seconds),
        "feedback": feedback,
    }


def generate_password(length=16, symbols=True):
    length = max(length, 8)
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    alphabet = "".join(pools)
    # Guarantee at least one char from each pool
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=5, sep="-"):
    words = max(words, 4)
    picked = [secrets.choice(WORDLIST) for _ in range(words)]
    return sep.join(picked) + sep + str(secrets.randbelow(900) + 100)


def print_report(result):
    print("\n===== Password Analysis =====")
    print(f"Score        : {result['score']}/100  ({result['rating']})")
    print(f"Entropy      : {result['entropy_bits']} bits")
    print(f"Est. crack   : {result['crack_time']}")
    print("Suggestions  :")
    for item in result["feedback"]:
        print(f"  - {item}")
    print("=============================\n")


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer & Generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("analyze", help="Analyze a password (hidden input)")

    g = sub.add_parser("generate", help="Generate a secure random password")
    g.add_argument("--length", type=int, default=16)
    g.add_argument("--no-symbols", action="store_true")

    ph = sub.add_parser("passphrase", help="Generate a passphrase")
    ph.add_argument("--words", type=int, default=5)

    args = parser.parse_args()

    if args.cmd == "analyze":
        pwd = getpass.getpass("Enter password to analyze (hidden): ")
        print_report(analyze(pwd))
    elif args.cmd == "generate":
        pwd = generate_password(args.length, not args.no_symbols)
        print(f"Generated password: {pwd}")
        print_report(analyze(pwd))
    elif args.cmd == "passphrase":
        pp = generate_passphrase(args.words)
        print(f"Generated passphrase: {pp}")
        true_bits = args.words * math.log2(len(WORDLIST)) + math.log2(900)
        print(f"True passphrase entropy (word-based): {true_bits:.1f} bits")
        print("Note: use more words for stronger passphrases (small demo wordlist).")


if __name__ == "__main__":
    main()
