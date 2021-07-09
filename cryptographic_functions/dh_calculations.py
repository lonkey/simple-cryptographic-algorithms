#!/usr/bin/env python3

from cryptographic_functions import shared_functions
from tabulate import tabulate
import random

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Diffie–Hellman key exchange
def key_exchange(p, g, a=None, b=None):
    print(tabulate([['Diffie-Hellman-Schlüsselaustausch']], tablefmt='fancy_grid'))

    # Choose an integer p that is a prime number
    if not shared_functions.is_prime(p):
        print(f'Die Variable p = {p} muss eine Primzahl sein.')
        return -1

    # Choose an integer g such that 1 < g < p
    if g not in range(2, p):
        print(f'Für die Variable g = {g} muss gelten 1 < {g} < {p}.')
        return -1

    # Choose an integer a such that 1 < a < p
    if a is None:
        a = random.randrange(2, p)

    # Choose an integer b such that 1 < b < p and a != b
    if b is None:
        b = a
        while b == a:
            b = random.randrange(2, p)

    # Choose an integer b such that a != b
    if a == b:
        print(f'Die Variablen a = {a} und b = {b} dürfen nicht identisch sein.')
        return -1

    # Choose an integer a such that 1 < a < p
    if a not in range(2, p):
        print(f'Für die Variable a = {a} muss gelten 1 < {a} < {p}.')
        return -1

    # Choose an integer b such that 1 < b < p
    if b not in range(2, p):
        print(f'Für die Variable b = {b} muss gelten 1 < {b} < {p}.')
        return -1

    # Secret generation
    a_secret = (g ** a) % p
    b_secret = (g ** b) % p
    a_shared_key = (b_secret ** a) % p
    b_shared_key = (a_secret ** b) % p

    if not a_shared_key == b_shared_key:
        print(f'Bei der Generierung des gemeinsamen Schlüssels ist ein Fehler aufgetreten, da das Ergebnis für '
              f'K_A = {a_shared_key} und K_B = {b_shared_key} nicht identisch ist.')
        return -1

    # Calculation path output
    print(
        f'A und B vereinbaren öffentlich für den Schlüsselaustausch eine Primzahl p = {p} und eine Basis '
        f'g = {g} aus dem Galois-Körper GF({p}).', end='\n\n')
    print(
        f'(A) Wähle: a = {a} ist gültig, da gilt:\n'
        f'1 < {a} < {p}\n'
        f'(B) Wähle: b = {b} ist gültig, da gilt:\n'
        f'1 < {b} < {p}', end='\n\n')
    print(
        f'(A) Berechne: α = g^a mod p = {g}^{a} mod {p} = {a_secret}\n'
        f'(B) Berechne: β = g^b mod p = {g}^{b} mod {p} = {b_secret}', end='\n\n')
    print(
        f'A und B teilen sich öffentlich gegenseitig die Werte von α = {a_secret} und β = {b_secret} mit.', end='\n\n')
    print(
        f'(A) Berechne: K = β^a mod p = {b_secret}^{a} mod {p} = {a_shared_key}\n'
        f'(B) Berechne: K = α^b mod p = {a_secret}^{b} mod {p} = {b_shared_key}', end='\n\n')
    print(
        f'Verifikation: K = g^(a * b) mod p = {g}^({a} * {b}) mod {p} = {g ** (a * b) % p}', end='\n\n')
    return a_shared_key
