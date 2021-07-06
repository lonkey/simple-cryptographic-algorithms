#!/usr/bin/env python

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from tabulate import tabulate
import random

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# ElGamal keypair generation
def keypair_generation(p, g, d=None):
    print(tabulate([['ElGamal Schlüsselerzeugung']], tablefmt='fancy_grid'))

    # Choose an integer p that is a prime number
    if not shared_functions.is_prime(p):
        print(f'Die Variable p = {p} muss eine Primzahl sein.')
        return -1

    # Choose an integer g such that 1 ≤ g < p
    if g not in range(1, p):
        print(f'Für die Variable g = {g} muss gelten 1 ≤ {g} < {p}.')
        return -1

    # Choose an integer d such that 1 ≤ d < (p - 1)
    if d is None:
        d = random.randrange(1, p - 1)

    if d not in range(1, p - 1):
        print(f'Für die Variable d = {d} muss gelten 1 ≤ {d} < {p - 1}.')
        return -1

    # Secret generation
    e = (g ** d) % p

    # Calculation path output
    print(
        f'Es wird öffentlich für die Schlüsselerzeugung eine Primzahl p = {p} und eine Basis g = {g} aus dem '
        f'Galois-Körper GF({p}) vereinbart.', end='\n\n')
    print(
        f'Wähle: d = {d} ist gültig, da gilt:\n'
        f'1 ≤ {d} < {p - 1}', end='\n\n')
    print(
        f'(A) Berechne: e = g^d mod p = {g}^{d} mod {p} = {e}', end='\n\n')
    print(
        f'Der öffentliche Schlüssel K(pub) = {{p, g, e}} entspricht somit K(pub) = {{{p}, {g}, {e}}} und der private '
        f'Schlüssel K(priv) = {{p, d}} folglich K(priv) = {{{p}, {d}}}.', end='\n\n')
    return (p, g, e), (p, d)


# ElGamal encryption
def encryption(public_key, m, k=None):
    print(tabulate([['ElGamal Verschlüsselung']], tablefmt='fancy_grid'))

    # Unpack the private key into its components
    p, g, e = public_key

    # Choose an integer m such that 1 ≤ m < p
    if m not in range(1, p):
        print(f'Für die Variable m = {m} muss gelten 1 ≤ {m} < {p}.')
        return -1

    # Choose an integer k such that 1 ≤ k < p - 1 and such that k and p - 1 are coprime
    if k is None:
        k = random.randrange(1, p - 1)
        while shared_functions.gcd(k, p - 1) != 1:
            k = random.randrange(1, p - 1)
    else:
        if shared_functions.gcd(k, p - 1) != 1:
            print(f'Das selbstgewählte k = {k} ist nicht teilerfremd zu (p - 1) = {p - 1}, da ggT({k},{p - 1}) = '
                  f'{shared_functions.gcd(k, p - 1)}.')
            return -1

    # Choose an integer k such that 1 ≤ k < p - 1
    if k not in range(1, p - 1):
        print(f'Für die Variable k = {k} muss gelten 1 ≤ {k} < {p - 1}.')
        return -1

    # Encryption
    a = (g ** k) % p
    b = ((e ** k) * m) % p

    # Calculation path output
    print(
        f'Wähle: k = {k} ist gültig, da gilt:\n'
        f'1 ≤ {k} < {p - 1} und ggT({k},{p - 1}) = {shared_functions.gcd(k, p - 1)}', end='\n\n')
    print(
        f'Die Verschlüsselung am Beispiel von K(pub) = {{{p}, {g}, {e}}} für den Klartext m = {m} ergibt den '
        f'Geheimtext a = {a} sowie b = {b}, da gilt:\n'
        f'a = g^k mod p\n'
        f'a = {g}^{k} mod {p}\n'
        f'a = {a}\n'
        f'b = e^k ⊙ m mod p\n'
        f'b = {e}^{k} ⊙ {m} mod {p}\n'
        f'b = {b}', end='\n\n')
    print(
        f'K = e^k = {e}^{k} = {(e ** k) % p} mod {p}', end='\n\n')
    return a, b


# ElGamal decryption
def decryption(private_key, c, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['ElGamal Entschlüsselung']], tablefmt='fancy_grid'))

    # Unpack the private key into its components
    p, d = private_key

    # Unpack the ciphertext into its components
    a, b = c

    # Choose an integer a such that 1 ≤ a < p
    if a not in range(1, p):
        print(f'Für die Variable a = {a} muss gelten 1 ≤ {a} < {p}.')
        return -1

    # Choose an integer b such that 1 ≤ b < p
    if b not in range(1, p):
        print(f'Für die Variable b = {b} muss gelten 1 ≤ {b} < {p}.')
        return -1

    # Decryption
    a_d = (a ** d) % p
    a_i = modulo_inverse_multiplicative.mim(p, a_d, print_matrix, print_linear_factorization, 1)
    m = (a_i * b) % p

    # Calculation path output
    print(
        f'Die Entschlüsselung am Beispiel von K(priv) = {{{p}, {d}}} für den Geheimtext a = {a} und b = {b} '
        f'ergibt den Klartext m = {m}, da gilt:\n'
        f'a^d ⊙ m = b mod p\n'
        f'{a}^{d} ⊙ m = {b} mod {p}\n'
        f'{a ** d} ⊙ m = {b} mod {p}\n'
        f'{a_d} ⊙ m = {b} mod {p}', end='\n\n')
    print(
        f'K = a^d = {a}^{d} = {a_d} mod {p}', end='\n\n')
    print(
        f'Daraus folgt:\n'
        f'm = {a_d}^-1 ⊙ {b} mod {p}\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'm = {a_i} ⊙ {b} mod {p}\n'
        f'm = {a_i * b} mod {p}\n'
        f'm = {m}', end='\n\n')
    return m
