#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from tabulate import tabulate
import random

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# RSA keypair generation
def keypair_generation(p, q, e=None, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['RSA Schlüsselerzeugung']], tablefmt='fancy_grid'))

    # Choose an integer p that is a prime number
    if not shared_functions.is_prime(p):
        print(f'Die Variable p = {p} muss eine Primzahl sein.')
        return -1

    # Choose an integer q that is a prime number
    if not shared_functions.is_prime(q):
        print(f'Die Variable q = {q} muss eine Primzahl sein.')
        return -1

    # Choose an integer p such that p != q
    if p == q:
        print(f'Die Variablen p = {p} und q = {q} dürfen nicht identisch sein.')
        return -1

    # Calculation of n
    n = p * q

    # Calculation of phi_n (phi_n is the totient of n)
    phi_n = (p - 1) * (q - 1)

    # Choose an integer e such that 1 ≤ e < phi_n and e and phi_n are coprime
    if e is None:
        e = random.randrange(1, phi_n)
    else:
        # Choose an integer e such that 1 ≤ e < phi_n
        if e not in range(1, phi_n):
            print(f'Für die Variable e = {e} muss gelten 1 ≤ {e} < {phi_n}.')
            return -1

        # Choose an integer e such that e and phi_n are coprime
        if shared_functions.gcd(e, phi_n) != 1:
            print(f'Das selbstgewählte e = {e} ist nicht teilerfremd zu Φ(n) = (p - 1) * (q - 1) = ({p} - 1) * '
                  f'({q} - 1) = {p - 1} * {q - 1} = {phi_n}.', end='\n\n')
            return -1

    # Choose an integer e such that 1 ≤ e < phi_n and e and phi_n are coprime
    g = shared_functions.gcd(e, phi_n)
    while g != 1:
        e = random.randrange(1, phi_n)
        g = shared_functions.gcd(e, phi_n)

    # Use Extended Euclid's Algorithm to generate the private key (d is the multiplicative inverse of e in GF(phi_n))
    d = modulo_inverse_multiplicative.mim(phi_n, e, print_matrix, print_linear_factorization, 1)

    # Calculation path output
    if d != -1:
        print(
            f'Berechne: n = p * q = {p} * {q} = {n}', end='\n\n')
        print(
            f'Berechne: Φ(n) = (p - 1) * (q - 1) = ({p} - 1) * ({q} - 1) = {p - 1} * {q - 1} = {phi_n}', end='\n\n')
        print(
            f'Wähle: e = {e} ist gültig, da gilt:\n'
            f'1 ≤ {e} < {phi_n} und ggT({e},{phi_n}) = {g}', end='\n\n')
        print(
            f'Berechne: d = e^-1 mod Φ(n) = {d}\n'
            f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
            f'Verifikation 1: d * e = {d} * {e} = {d * e} = {(d * e) // phi_n} * {phi_n} + {(d * e) % phi_n}\n'
            f'Verifikation 2: d ⊙ e = {d} ⊙ {e} = {(d * e) % phi_n} mod {phi_n}', end='\n\n')
        print(
            f'Der öffentliche Schlüssel K(pub) = {{e, n}} entspricht somit K(pub) = {{{e}, {n}}} und der private '
            f'Schlüssel K(priv) = {{d, n}} folglich K(priv) = {{{d}, {n}}}.', end='\n\n')
        return (e, n), (d, n)
    else:
        print(
            f'Das in modulo phi_n = {phi_n} multiplikativ inverse Element zu e = {e} kann folglich nicht bestimmt '
            f'werden, da phi_n und e nicht teilerfremd sind.', end='\n\n')
        return -1


# RSA encryption
def encryption(public_key, p):
    print(tabulate([['RSA Verschlüsselung']], tablefmt='fancy_grid'))

    # Unpack the public key into its components
    e, n = public_key

    # Choose an integer p such that 0 ≤ p < n
    if p not in range(n):
        print(f'Für die Variable p = {p} muss gelten 0 ≤ {p} < {n}.')
        return -1

    # Encryption
    c = (p ** e) % n

    # Calculation path output
    print(
        f'Die Verschlüsselung am Beispiel von K(pub) = {{{e}, {n}}} für den Klartext p = {p} ergibt den Geheimtext '
        f'c = {c}, da gilt:\n'
        f'c = p^d mod n\n'
        f'c = {p}^{e} mod {n}\n'
        f'c = {c}', end='\n\n')
    return c


# RSA decryption
def decryption(private_key, c):
    print(tabulate([['RSA Entschlüsselung']], tablefmt='fancy_grid'))

    # Unpack the private key into its components
    d, n = private_key

    # Choose an integer c such that 0 ≤ c < n
    if c not in range(n):
        print(f'Für die Variable c = {c} muss gelten 0 ≤ {c} < {n}.')
        return -1

    # Decryption
    p = (c ** d) % n

    # Calculation path output
    print(
        f'Die Entschlüsselung am Beispiel von K(priv) = {{{d}, {n}}} für den Geheimtext c = {c} ergibt den Klartext '
        f'p = {p}, da gilt:\n'
        f'p = c^e mod n\n'
        f'p = {c}^{d} mod {n}\n'
        f'p = {p}', end='\n\n')
    return p


# RSA Pollard's rho algorithm
def pollard_rho(n, x=None, c=23):
    print(tabulate([['RSA Pollard-Rho-Methode']], tablefmt='fancy_grid'))

    # Choose an integer n such that n < 2
    if n < 2:
        print(f'Das Modul n = {n} muss größer 2 sein.')
        return -1

    # Choose an integer n that is not a prime number
    if shared_functions.is_prime(n):
        print(f'Das Modul n = {n} darf für eine Faktorisierung keine Primzahl sein.')
        return -1

    # Choose an integer x and y such that 1 ≤ {x, y} < n
    x = x_0 = y = random.randrange(1, n) if x is None else x

    list_x = []
    list_y = []
    list_d = []
    while list_x.count(x) != 2:
        x = (x * x + c) % n
        list_x.append(x)
        y = (y * y + c) % n
        y = (y * y + c) % n
        list_y.append(y)
        list_d.append(shared_functions.gcd(x - y, n))

    print(f'Faktorisierungstabelle nach Pollard-Rho für n = {n}:')
    print(tabulate(zip(*(range(1, len(list_x) + 1), list_x, list_y, list_d)),
                   headers=['i', 'x_i = f(x_i - 1)', 'y_i = x_2i = f(f(y_i − 1))', 'ggT(x_i - x_2i, n)'],
                   tablefmt='pretty'), end='\n\n')

    p = q = -1
    for d in list_d:
        if d == 1 or d == n:
            continue
        if not shared_functions.is_prime(n / d):
            continue
        if n / d * d == n:
            if shared_functions.is_prime(d):
                p = int(n / d)
                q = int(d)
            else:
                print(f'In diesem speziellen Fall ist der gefundene Faktor mit dem Wert {d} keine Primzahl. Dieser '
                      f'kann jedoch durch die Wiederholung der Funktion mit n = {d} weiter faktorisiert werden.')
                return -1
            break

    # Try again with a different c
    if p == -1 or q == -1 or p * q != n:
        print(f'Für den Zyklus c = {c} war die Faktorisierung nicht erfolgreich. Wiederhole den Versuch mit einem '
              f'anderen Wert für c.')
        return -1

    # Calculation path output
    print(
        f'Aus der Faktorisierungstabelle ergibt sich für die Funktion f(x) = x^2 + c mit c = {c} und x_0 = {x_0}:\n'
        f'p = {p}\n'
        f'q = {q}', end='\n\n')
    print(
        f'Verifikation:\n'
        f'p * q = {p} * {q} = {n}', end='\n\n')
    return p, q
