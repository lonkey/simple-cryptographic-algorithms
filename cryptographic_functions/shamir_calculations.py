#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from tabulate import tabulate
import random

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Shamir three-pass keypair generation
def keypair_generation(p, a=None, b=None, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['Shamir’s No-Key Schlüsselerzeugung']], tablefmt='fancy_grid'))

    # Choose an integer p that is a prime number
    if not shared_functions.is_prime(p):
        print(f'Die Variable p = {p} muss eine Primzahl sein.')
        return -1

    # Choose an integer a such that 1 ≤ a < p
    if a is None:
        a = random.randrange(1, p)

    # Choose an integer b such that 1 ≤ b < p and a != b
    if b is None:
        b = a
        while b == a:
            b = random.randrange(1, p)

    # Choose an integer b such that a != b
    if a == b:
        print(f'Die Variablen a = {a} und b = {b} dürfen nicht identisch sein.')
        return -1

    # Choose an integer a such that 1 ≤ a < p
    if a not in range(1, p):
        print(f'Für die Variable a = {a} muss gelten 1 ≤ {a} < {p}.')
        return -1

    # Choose an integer b such that 1 ≤ b < p
    if b not in range(1, p):
        print(f'Für die Variable b = {b} muss gelten 1 ≤ {b} < {p}.')
        return -1

    # Secret generation
    a_i = modulo_inverse_multiplicative.mim(p - 1, a, print_matrix, print_linear_factorization, 1)
    b_i = modulo_inverse_multiplicative.mim(p - 1, b, print_matrix, print_linear_factorization, 2)

    # Calculation path output
    print(
        f'A und B vereinbaren öffentlich eine Primzahl p = {p}.', end='\n\n')
    print(
        f'(A) Wähle: a = {a} ist gültig, da gilt:\n'
        f'1 ≤ {a} < {p}\n'
        f'(B) Wähle: b = {b} ist gültig, da gilt:\n'
        f'1 ≤ {b} < {p}', end='\n\n')
    print(
        f'(A) Berechne: a^-1 = a mod (p - 1) = {a} mod {p - 1} = {a_i}\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'(B) Berechne: b^-1 = b mod (p - 1) = {b} mod {p - 1} = {b_i}\n'
        f'<AUXILIARY 2>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 2>', end='\n\n')
    print(
        f'Der Schlüssel K(A) = {{a, a^-1, p}} entspricht somit K(A) = {{{a}, {a_i}, {p}}} und der Schlüssel K(B) = {{'
        f'b, b^-1, p}} folglich K(B) = {{{b}, {b_i}, {p}}}.', end='\n\n')
    return (a, a_i, p), (b, b_i, p)


# Shamir three-pass key exchange
def key_exchange(key_a, key_b, k=None):
    print(tabulate([['Shamir’s No-Key Schlüsselaustausch']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    a, a_i, p = key_a
    b, b_i, b_p = key_b

    # The value of p must be identical in both keys
    if p != b_p:
        print(f'Die Variablen a_p = {p} und b_p = {b_p} müssen identisch sein.')
        return -1

    # Choose an integer k such that 1 ≤ k < p
    if k is None:
        k = random.randrange(1, p)

    # Choose an integer k such that 1 ≤ k < p
    if k not in range(1, p):
        print(f'Für die Variable k = {k} muss gelten 1 ≤ {k} < {p}.')
        return -1

    # Key exchange
    a_y1 = (k ** a) % p
    b_y1 = (a_y1 ** b) % p
    a_y2 = (b_y1 ** a_i) % p
    b_y2 = (a_y2 ** b_i) % p

    if not k == b_y2:
        print(f'Bei der Generierung des gemeinsamen Schlüssels ist ein Fehler aufgetreten, da das Ergebnis für '
              f'k = {k} und b_y2 = {b_y2} nicht identisch ist.')
        return -1

    # Calculation path output
    print(
        f'Der Schlüsselaustausch am Beispiel von K(A) = {{a, a^-1, p}} = {{{a}, {a_i}, {p}}} sowie K(B) = {{b, b^-1, '
        f'p}} = {{{b}, {b_i}, {p}}}.', end='\n\n')
    print(
        f'(A) Wähle: Sitzungsschlüssel k = {k} ist gültig, da gilt:\n'
        f'1 ≤ {k} < {p}', end='\n\n')
    print(
        f'(A) Berechne: a_y1 = k^a mod p = {k}^{a} mod {p} = {a_y1}\n'
        f'A teilt B öffentlich den Wert von a_y1 = {a_y1} mit.', end='\n\n')
    print(
        f'(B) Berechne: b_y1 = a_y1^b mod p = {a_y1}^{b} mod {p} = {b_y1}\n'
        f'B teilt A öffentlich den Wert von b_y1 = {b_y1} mit.', end='\n\n')
    print(
        f'(A) Berechne: a_y2 = b_y1^a_i mod p = {b_y1}^{a_i} mod {p} = {a_y2}\n'
        f'A teilt B öffentlich den Wert von a_y2 = {a_y2} mit.', end='\n\n')
    print(
        f'(B) Berechne: b_y2 = a_y2^b_i mod p = {a_y2}^{b_i} mod {p} = {b_y2}\n'
        f'B erhält den Sitzungsschlüssel k = b_y2 = {k}.', end='\n\n')
    print(
        f'Verifikation 1: k = k^(a * a^-1) mod p = {(k ** (a * a_i)) % p}\n'
        f'Verifikation 2: k = k^(b * b^-1) mod p = {(k ** (b * b_i)) % p}', end='\n\n')
    return k
