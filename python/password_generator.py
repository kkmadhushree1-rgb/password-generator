"""Secure password generator.

Uses the `secrets` module (OS-level CSPRNG), never `random`.

Usage as a module:
    from password_generator import generate_password
    pw = generate_password(20)

Usage as a CLI:
    python password_generator.py                 # one 16-char password
    python password_generator.py -l 24 -n 5      # five 24-char passwords
    python password_generator.py --no-symbols    # letters + digits only
    python password_generator.py --no-ambiguous  # skip look-alikes (0/O, 1/l/I)
"""

import argparse
import math
import secrets
import string

MIN_LENGTH = 8
AMBIGUOUS = set("0O1lI|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"


def _build_pools(use_lower, use_upper, use_digits, use_symbols, no_ambiguous):
    candidates = [
        (use_lower, string.ascii_lowercase),
        (use_upper, string.ascii_uppercase),
        (use_digits, string.digits),
        (use_symbols, SYMBOLS),
    ]
    pools = []
    for enabled, chars in candidates:
        if not enabled:
            continue
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        if chars:
            pools.append(chars)
    return pools


def generate_password(
    length=16,
    use_lower=True,
    use_upper=True,
    use_digits=True,
    use_symbols=True,
    no_ambiguous=False,
):
    """Return a cryptographically secure random password.

    Guarantees at least one character from every enabled character set.
    """
    pools = _build_pools(use_lower, use_upper, use_digits, use_symbols, no_ambiguous)
    if not pools:
        raise ValueError("Enable at least one character set.")
    if length < max(MIN_LENGTH, len(pools)):
        raise ValueError(f"Length must be at least {max(MIN_LENGTH, len(pools))}.")

    # One guaranteed character from each pool, the rest from the combined pool.
    all_chars = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]

    # Cryptographically secure shuffle so guaranteed chars aren't predictable.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def entropy_bits(length, pool_size):
    """Approximate entropy (bits) of a uniformly random password."""
    return length * math.log2(pool_size)


def main():
    p = argparse.ArgumentParser(description="Secure password generator")
    p.add_argument("-l", "--length", type=int, default=16)
    p.add_argument("-n", "--count", type=int, default=1)
    p.add_argument("--no-lower", action="store_true")
    p.add_argument("--no-upper", action="store_true")
    p.add_argument("--no-digits", action="store_true")
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--no-ambiguous", action="store_true")
    args = p.parse_args()

    opts = dict(
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        no_ambiguous=args.no_ambiguous,
    )
    try:
        pool_size = len("".join(_build_pools(**opts)))
        for _ in range(args.count):
            print(generate_password(args.length, **opts))
    except ValueError as e:
        p.error(str(e))

    print(f"\n~{entropy_bits(args.length, pool_size):.0f} bits of entropy per password")


if __name__ == "__main__":
    main()
