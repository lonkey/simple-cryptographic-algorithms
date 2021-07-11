#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from tabulate import tabulate
import random

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Fiat-Shamir keypair generation
def keypair_generation(p, q, s=None, v=None):
    print(tabulate([['Fiat-Shamir-Protokoll Schlüsselerzeugung']], tablefmt='fancy_grid'))

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

    # Choose an integer s such that 1 < s < n and s and n are coprime
    if s is None:
        s = random.randrange(2, n)
    else:
        # Choose an integer s such that 1 < s < n
        if s not in range(2, n):
            print(f'Für die Variable s = {s} muss gelten 1 < {s} < {n}.')
            return -1

        # Choose an integer s such that s and n are coprime
        if shared_functions.gcd(s, n) != 1:
            print(f'Das selbstgewählte s = {s} ist nicht teilerfremd zu n = p * q = {n}.')
            return -1

    # Choose an integer s such that 1 < s < n and s and n are coprime
    t = shared_functions.gcd(s, n)
    while t != 1:
        s = random.randrange(2, n)
        t = shared_functions.gcd(s, n)

    # Calculation of v
    v = (s ** 2) % n

    # Verification of v
    v_v = (s ** 2) * v % n

    # Calculation path output
    if v_v == 1:
        print(
            f'Aus den Primzahlen p = {p} und q = {q} wird das öffentliche Modul n = p * q = {n} berechnet.', end='\n\n')
        print(
            f'(A) Wähle: s = {s} ist gültig, da gilt:\n'
            f'1 < {s} < {n} und ggT({s},{n}) = {t}', end='\n\n')
        print(
            f'(A) Berechne: v = s^2 mod n = {s}^2 mod {n} = {v}\n'
            f'Der Wert von v ist gültig, da die Bedingung {s}^2 * {v} = {v_v} mod {n} erfüllt ist.', end='\n\n')
        print(
            f'Der öffentliche Schlüssel K(pub) = {{v, n}} entspricht somit K(pub) = {{{v}, {n}}} und der private '
            f'Schlüssel K(priv) = {{s, n}} folglich K(priv) = {{{s}, {n}}}.', end='\n\n')
        return (v, n), (s, n)
    else:
        print(
            f'Das gewählte Schlüsselpaar K = (v, s) = ({v}, {s}) aus Modulo {n} mit dem öffentlichen Schlüssel '
            f'K(pub) = ({v}, {n}) und dem privaten Schlüssel K(priv) = ({s}, {n}) ist ungültg, da die Bedingung '
            f'{s}^2 * {v} = {t} mod {n} nicht erfüllt ist, sondern {v_v} mod {n} entspricht.')
        return -1


# Fiat-Shamir verification
def verification(key_a, key_b, k=None, b=None, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['Fiat-Shamir-Protokoll Verifikation']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    v, n = key_a
    s, n_v = key_b

    # The value of n must be identical in both keys
    if n != n_v:
        print(f'Die Variablen a_n = {n} und b_n = {n_v} müssen identisch sein.')
        return -1

    # Choose an integer k such that 1 < k < n and k and n are coprime
    if k is None:
        k = random.randrange(2, n)
    else:
        # Choose an integer k such that 1 < k < n
        if k not in range(2, n):
            print(f'Für die Variable k = {k} muss gelten 1 < {k} < {n}.')
            return -1

        # Choose an integer k such that k and n are coprime
        if shared_functions.gcd(k, n) != 1:
            print(f'Das selbstgewählte k = {k} ist nicht teilerfremd zu n = {n}.')
            return -1

    # Choose an integer k such that 1 < k < n and k and n are coprime
    l = shared_functions.gcd(k, n)
    while l != 1:
        k = random.randrange(2, n)
        l = shared_functions.gcd(k, n)

    # Choose an integer b such that b ∈ {0, 1}
    if b is None:
        b = random.randrange(0, 2)
    else:
        # Choose an integer b such that b ∈ {0, 1}
        if b not in range(0, 2):
            print(f'Für die Variable b = {b} muss gelten b ∈ {{0, 1}}.')
            return -1

    # Calculation of v_i
    v_i = modulo_inverse_multiplicative.mim(n, v, print_matrix, print_linear_factorization, 1)

    # Calculation of x
    x = (k ** 2) % n

    # Calculation of y
    y = k if b == 0 else (k * s) % n

    # Calculation of y_v
    y_v = x % n if b == 0 else (x * v_i) % n

    # Calculation path output
    print(
        f'Die Authentizitätsprüfung am Beispiel von K(A) = {{v, n}} = {{{v}, {n}}} sowie '
        f'K(B) = {{s, n}} = {{{s}, {n}}}.', end='\n\n')
    print(
        f'Commitment:\n'
        f'(B) Wähle: Zufallszahl k = {k} ist gültig, da gilt:\n'
        f'1 < {k} < {n} und ggT({k},{n}) = {l}\n'
        f'(B) Berechne: x = k^2 mod n = {k}^{2} mod {n} = {x}\n'
        f'B teilt A öffentlich den Wert von x = {x} mit.', end='\n\n')
    print(
        f'Challenge:\n'
        f'(A) Wähle: Zufallsbit b ∈ {{0, 1}} = {b}\n'
        f'A teilt B öffentlich den Wert von b = {b} mit.', end='\n\n')
    if b == 0:
        print(
            f'Response:\n'
            f'(B) Berechne: y = k mod n = {k} mod {n} = {y}\n'
            f'B teilt A öffentlich den Wert von y = {y} mit.', end='\n\n')
        print(
            f'Verifikation:\n'
            f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
            f'(A) Berechne: y_v = x mod n = {x} mod {n} = {y_v}\n'
            f'(A) Verifikation: y_v ≡ y^2 mod {n} = {y_v} ≡ {(y ** 2) % n}', end='\n\n')
    else:
        print(
            f'Response:\n'
            f'(B) Berechne: y = k * s mod n = {k} * {s} mod {n} = {y}\n'
            f'B teilt A öffentlich den Wert von y = {y} mit.', end='\n\n')
        print(
            f'Verifikation:\n'
            f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
            f'(A) Berechne: y_v = x * v^-1 mod n = {x} * {v_i} mod {n} = {y_v}\n'
            f'(A) Verifikation: y_v ≡ y^2 mod {n} = {y_v} ≡ {(y ** 2) % n}', end='\n\n')
    return y_v


# Fiat-Shamir attack
def attack_scheme(key_a, y=None, b=None, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['Fiat-Shamir-Protokoll Angriffsmuster']], tablefmt='fancy_grid'))

    # Unpack the public key into its components
    v, n = key_a

    # Choose an integer y such that 1 < y < n
    if y is None:
        y = random.randrange(2, n)
    else:
        # Choose an integer k such that 1 < k < n
        if y not in range(2, n):
            print(f'Für die Variable y = {y} muss gelten 1 < {y} < {n}.')
            return -1

    # Choose an integer b such that b ∈ {0, 1}
    if b is None:
        b = random.randrange(0, 2)
    else:
        # Choose an integer b such that b ∈ {0, 1}
        if b not in range(0, 2):
            print(f'Für die Variable b = {b} muss gelten b ∈ {{0, 1}}.')
            return -1

    # Calculation of v_i
    v_i = modulo_inverse_multiplicative.mim(n, v, print_matrix, print_linear_factorization, 1)

    # Calculation of x
    x = (y ** 2) % n if b == 0 else ((y ** 2) * v) % n

    # Calculation of y_v
    y_v = x % n if b == 0 else (x * v_i) % n

    # Calculation path output
    print(
        f'Die Angriffsmuster am Beispiel von K(A) = {{v, n}} = {{{v}, {n}}}.', end='\n\n')
    print(
        f'(B) Wähle: Zufallszahl y = {y} ist gültig, da gilt:\n'
        f'1 < {y} < {n}', end='\n\n')
    if b == 0:
        print(
            f'Commitment:\n'
            f'(B) Berechne: x = y^2 mod n = {y}^{2} mod {n} = {x} für die Annahme b = {b}\n'
            f'B teilt A öffentlich den Wert von x = {x} mit.', end='\n\n')
    else:
        print(
            f'Commitment:\n'
            f'(B) Berechne: x = y^2 * v mod n = {y}^{2} * {v} mod {n} = {x} für die Annahme b = {b}\n'
            f'B teilt A öffentlich den Wert von x = {x} mit.', end='\n\n')
    print(
        f'Challenge:\n'
        f'(A) Wähle: Zufallsbit b ∈ {{0, 1}} = {b}\n'
        f'A teilt B öffentlich den Wert von b = {b} mit.', end='\n\n')
    print(
        f'Response:\n'
        f'B teilt A öffentlich den Wert von y = {y} mit.', end='\n\n')
    if b == 0:
        print(
            f'Verifikation:\n'
            f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
            f'(A) Berechne: y_v = x mod n = {x} mod {n} = {y_v}\n'
            f'(A) Verifikation: y_v ≡ y^2 mod {n} = {y_v} ≡ {(y ** 2) % n}', end='\n\n')
        print(
            f'Response-Problem:\n'
            f'Die erfolgreiche Verifizierung hängt vollständig davon ab, dass Alice im Challenge-Teilschritt '
            f'tatsächlich den Wert von b = {b} anfordert, der zuvor im Commitment angenommen wurde. Ist dies jedoch '
            f'nicht der Fall, d. h. Alice wählt stattdessen b = {b + 1}, so kann der korrekte Wert für y nicht mehr '
            f'bestimmt werden.\n'
            f'(B) Berechne: y = √(x * v^-1) ist bei ausreichend großem Modul n mit vorgegebenem x nicht ermittelbar.',
            end='\n\n')
    else:
        print(
            f'Verifikation:\n'
            f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
            f'(A) Berechne: y_v = x * v^-1 mod n = {x} * {v_i} mod {n} = {y_v}\n'
            f'(A) Verifikation: y_v ≡ y^2 mod {n} = {y_v} ≡ {(y ** 2) % n}', end='\n\n')
        print(
            f'Response-Problem:\n'
            f'Die erfolgreiche Verifizierung hängt vollständig davon ab, dass Alice im Challenge-Teilschritt '
            f'tatsächlich den Wert von b = {b} anfordert, der zuvor im Commitment angenommen wurde. Ist dies jedoch '
            f'nicht der Fall, d. h. Alice wählt stattdessen b = {b - 1}, so kann der korrekte Wert für y nicht mehr '
            f'bestimmt werden.\n'
            f'(B) Berechne: y = √(x) mod n ist im endlichen Zahlenkörper bei ausreichend großen Schlüssellängen nicht '
            f'effizient ermittelbar.', end='\n\n')
    return y_v
