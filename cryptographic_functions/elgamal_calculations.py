#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from math import ceil, sqrt
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

    # Unpack the public key into its components
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


# ElGamal signature signing
def sign(public_key, private_key, m, r=None, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['ElGamal Signierung']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    p, g, e = public_key
    p_v, d = private_key

    # The value of p must be identical in both keys
    if p != p_v:
        print(f'Die Variablen p = {p} und p_v = {p_v} müssen identisch sein.')
        return -1

    # Choose an integer m such that 1 ≤ m < p
    if m not in range(1, p):
        print(f'Für die Variable m = {m} muss gelten 1 ≤ {m} < {p}.')
        return -1

    # Choose an integer r such that 1 ≤ r < p - 1 and such that r and p - 1 are coprime
    if r is None:
        r = random.randrange(1, p - 1)
        while shared_functions.gcd(r, p - 1) != 1:
            r = random.randrange(1, p - 1)
    else:
        if shared_functions.gcd(r, p - 1) != 1:
            print(f'Das selbstgewählte r = {r} ist nicht teilerfremd zu (p - 1) = {p - 1}, da ggT({r},{p - 1}) = '
                  f'{shared_functions.gcd(r, p - 1)}.')
            return -1

    # Choose an integer r such that 1 ≤ r < p - 1
    if r not in range(1, p - 1):
        print(f'Für die Variable r = {r} muss gelten 1 ≤ {r} < {p - 1}.')
        return -1

    # Calculation of r_i
    r_i = modulo_inverse_multiplicative.mim(p - 1, r, print_matrix, print_linear_factorization, 1)

    # Signing
    p_nb = (g ** r) % p
    s = ((m - d * p_nb) * r_i) % (p - 1)

    # Calculation path output
    print(
        f'Die Signierung für die Nachricht m = {m} mittels K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} und K(priv) = '
        f'{{p, d}} = {{{p_v}, {d}}}.', end='\n\n')
    print(
        f'Die Zufallszahl r = {r} ist gültig, da gilt:\n'
        f'r ∈ {{1, p − 1}} ∈ {{1, {p - 1}}} und ggT(r, p - 1) = ggT({r}, {p - 1}) = {shared_functions.gcd(r, p - 1)}\n'
        f'Von der Zufallszahl r wird nun das multiplikativ inverse Element r^-1 = {r_i} berechnet.\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>', end='\n\n')
    print(
        f'Nun wird der Nachrichtenbezeichner p_nb berechnet:\n'
        f'p_nb = g^r mod p\n'
        f'p_nb = {g}^{r} mod {p}\n'
        f'p_nb = {g ** r} mod {p}\n'
        f'p_nb = {p_nb}', end='\n\n')
    print(
        f'Das Signaturelement s, welches Teil der digitalen Signatur ist, kann nun mittels des Nachrichtenelementes '
        f'm = {m} wie folgt berechnet werden:\n'
        f's = (m - d * p_nb) * r^-1 mod (p - 1)\n'
        f's = ({m} - {d} * {p_nb}) * {r_i} mod {p - 1}\n'
        f's = ({m} - {d * p_nb}) * {r_i} mod {p - 1}\n'
        f's = ({m - d * p_nb}) * {r_i} mod {p - 1}\n'
        f's = ({(m - d * p_nb) % (p - 1)}) * {r_i} mod {p - 1}\n'
        f's = {s}', end='\n\n')
    print(
        f'Die signierte Nachricht m_s = {{m, p_nb, s}} = {{{m}, {p_nb}, {s}}} setzt sich aus dem Klartext, dem '
        f'Nachrichtenbezeichner und dem Signaturelement zusammen.', end='\n\n')
    return m, p_nb, s


# ElGamal signature verifying
def verify(public_key, signed_message):
    print(tabulate([['ElGamal Verifizierung']], tablefmt='fancy_grid'))

    # Unpack the public key into its components
    p, g, e = public_key

    # Unpack the signed message into its components
    m, p_nb, s = signed_message

    # Calculation of a and b
    a = (g ** m) % p
    b = (e ** p_nb) * (p_nb ** s) % p

    # Calculation path output
    print(
        f'Zur Verifizierung für die signierte Nachricht m = {{m, p_nb, s}} = {{{m}, {p_nb}, {s}}} mittels K(pub) = '
        f'{{p, g, e}} = {{{p}, {g}, {e}}} muss der Ausdruck g^m = e^p_n * p_n^s mod p bestätigt werden.', end='\n\n')
    print(
        f'a = g^m mod p\n'
        f'a = {g}^{m} mod {p}\n'
        f'a = {a}', end='\n\n')
    print(
        f'b = e^p_n * p_n^s mod p\n'
        f'b = {e}^{p_nb} * {p_nb}^{s} mod {p}\n'
        f'b = {(e ** p_nb) % p} * {(p_nb ** s) % p} mod {p}\n'
        f'b = {b}', end='\n\n')
    if a == b:
        print(
            f'Aufgrund der Kongruenz von a = {a} und b = {b} kann die Integrität der signierten Nachricht bestätigt '
            f'werden.', end='\n\n')
    else:
        print(
            f'Aufgrund der Inkongruenz von a = {a} und b = {b} kann die Integrität der signierten Nachricht nicht '
            f'bestätigt werden.', end='\n\n')
    return a, b


# ElGamal homomorphic multiplicative scheme
def homomorphic_multiplicative_scheme(public_key, private_key, c_1, c_2, print_matrix=False,
                                      print_linear_factorization=True):
    print(tabulate([['Homomorphes multiplikatives Schema']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    p, g, e = public_key
    p_v, d = private_key

    # Unpack both ciphertexts into its components
    a_1, b_1 = c_1
    a_2, b_2 = c_2

    # The value of p must be identical in both keys
    if p != p_v:
        print(f'Die Variablen p = {p} und p_v = {p_v} müssen identisch sein.')
        return -1

    # Calculation of m
    a_1_a_2 = ((a_1 * a_2) ** d) % p
    a_i = modulo_inverse_multiplicative.mim(p, a_1_a_2, print_matrix, print_linear_factorization, 1)
    m = (a_i * (b_1 * b_2)) % p

    # Calculation path output
    print(
        f'Gegeben sind K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} und K(priv) = {{p, d}} = {{{p_v}, {d}}} mit den '
        f'Geheimtexten c_1 = {{a_1, b_1}} = {{{a_1}, {b_1}}} und c_2 = {{a_2, b_2}} = {{{a_2}, {b_2}}}.', end='\n\n')
    print(
        f'Aufgrund der Eigenschaft des multiplikativen Homomorphismus gilt:\n'
        f'(a, b) = (a_1 * a_2, b_1 * b_2) mod p\n'
        f'(a, b) = ({a_1} * {a_2}, {b_1} * {b_2}) mod {p}\n'
        f'(a, b) = ({(a_1 * a_2) % p}, {(b_1 * b_2) % p})', end='\n\n')
    print(
        f'Der zum Geheimtext (a, b) gehörende Klartext m = m_1 * m_2 ergibt sich aus der Gleichung a^d * m = b mod p '
        f'zu:\n'
        f'(a_1 * a_2)^d * m = (b_1 * b_2) mod p\n'
        f'({a_1} * {a_2})^{d} * m = ({b_1} * {b_2}) mod {p}\n'
        f'{(a_1 * a_2) % p}^{d} * m = {(b_1 * b_2) % p}\n'
        f'{((a_1 * a_2) ** d) % p} * m = {(b_1 * b_2) % p}\n'
        f'm = {((a_1 * a_2) ** d) % p}^-1 * {(b_1 * b_2) % p}\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'm = {a_i} * {(b_1 * b_2) % p}\n'
        f'm = {m}', end='\n\n')
    return m


# ElGamal homomorphic ciphertext extension
def homomorphic_ciphertext_extension(public_key, private_key, m_1, a_b, print_matrix=False,
                                     print_linear_factorization=True):
    print(tabulate([['Homomorphe Erweiterung des Geheimtextes']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    p, g, e = public_key
    p_v, d = private_key

    # Unpack the combined ciphertext into its components
    a, b = a_b

    # The value of p must be identical in both keys
    if p != p_v:
        print(f'Die Variablen p = {p} und p_v = {p_v} müssen identisch sein.')
        return -1

    # Calculation of m
    a_d = (a ** d) % p
    a_i = modulo_inverse_multiplicative.mim(p, a_d, print_matrix, print_linear_factorization, 1)
    m = (a_i * b) % p

    # Calculation of m_2
    m_1_i = modulo_inverse_multiplicative.mim(p, m_1, print_matrix, print_linear_factorization, 2)
    m_2 = (m * m_1_i) % p

    # Calculation path output
    print(
        f'Gegeben sind K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} und K(priv) = {{p, d}} = {{{p_v}, {d}}} mit dem aus '
        f'Geheimtext 1 und 2 erweiterten Geheimtext a_b = {{a, b}} = {{{a}, {b}}}. Ebenfalls bekannt ist der zu '
        f'Geheimtext 1 zugehörige Klartext m_1 = {m_1}. Durch die Umkehrung der Geheimtext-Erweiterung soll nun der '
        f'Klartext m_2 ermittelt werden.', end='\n\n')
    print(
        f'Der zum erweiterten Geheimtext (a, b) gehörende Klartext m ergibt sich aus der Gleichung a^d * m = b mod p '
        f'zu:\n'
        f'm = b * (a^d)^-1 mod p\n'
        f'm = {b} * ({a}^{d})^-1 mod {p}\n'
        f'm = {b} * {a_d}^-1 mod {p}\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'm = {b} * {a_i} mod {p}\n'
        f'm = {m}', end='\n\n')
    print(
        f'Der Klartext m_2, welcher zur Erweiterung des Klartexts m_1 verwendet wurde, ergibt sich aus:\n'
        f'm_2 = m * m_1^-1 mod p\n'
        f'm_2 = {m} * {m_1}^-1 mod {p}\n'
        f'<AUXILIARY 2>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 2>\n'
        f'm_2 = {m} * {m_1_i} mod {p}\n'
        f'm_2 = {m_2}', end='\n\n')
    print(
        f'Verifikation:\n'
        f'm = m_1 * m_2 mod p\n'
        f'{m} = {m_1} * {m_2} mod {p}\n'
        f'{m} = {(m_1 * m_2) % p}', end='\n\n')
    return m_2


# ElGamal homomorphic multiplicative decryption
def homomorphic_multiplicative_decryption(public_key, private_key, m_1, c_1, c_2, print_matrix=False,
                                          print_linear_factorization=True):
    print(tabulate([['Homomorphe multiplikative Entschlüsselung']], tablefmt='fancy_grid'))

    # Unpack both keys into its components
    p, g, e = public_key
    p_v, d = private_key

    # Unpack both ciphertexts into its components
    a_1, b_1 = c_1
    a_2, b_2 = c_2

    # The value of p must be identical in both keys
    if p != p_v:
        print(f'Die Variablen p = {p} und p_v = {p_v} müssen identisch sein.')
        return -1

    # Calculation of m
    a_1_a_2 = ((a_1 * a_2) ** d) % p
    a_i = modulo_inverse_multiplicative.mim(p, a_1_a_2, print_matrix, print_linear_factorization, 1)
    m = (a_i * (b_1 * b_2)) % p

    # Calculation of m_2
    m_1_i = modulo_inverse_multiplicative.mim(p, m_1, print_matrix, print_linear_factorization, 2)
    m_2 = (m * m_1_i) % p

    # Calculation path output
    print(
        f'Gegeben sind K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} und K(priv) = {{p, d}} = {{{p_v}, {d}}} mit den '
        f'Geheimtexten c_1 = {{a_1, b_1}} = {{{a_1}, {b_1}}} und c_2 = {{a_2, b_2}} = {{{a_2}, {b_2}}}. Ebenfalls '
        f'bekannt ist der zu c_1 zugehörige Klartext m_1 = {m_1}. Unter Ausnutzung der Eigenschaft des multiplikativen '
        f'Homomorphismus soll nun der Klartext m_2 des Geheimtextes c_2 ermittelt werden.', end='\n\n')
    print(
        f'Aufgrund der Eigenschaft des multiplikativen Homomorphismus gilt:\n'
        f'(a, b) = (a_1 * a_2, b_1 * b_2) mod p\n'
        f'(a, b) = ({a_1} * {a_2}, {b_1} * {b_2}) mod {p}\n'
        f'(a, b) = ({(a_1 * a_2) % p}, {(b_1 * b_2) % p})', end='\n\n')
    print(
        f'Der zum Geheimtext (a, b) gehörende Klartext m = m_1 * m_2 ergibt sich aus der Gleichung a^d * m = b mod p '
        f'zu:\n'
        f'(a_1 * a_2)^d * m = (b_1 * b_2) mod p\n'
        f'({a_1} * {a_2})^{d} * m = ({b_1} * {b_2}) mod {p}\n'
        f'{(a_1 * a_2) % p}^{d} * m = {(b_1 * b_2) % p}\n'
        f'{((a_1 * a_2) ** d) % p} * m = {(b_1 * b_2) % p}\n'
        f'm = {((a_1 * a_2) ** d) % p}^-1 * {(b_1 * b_2) % p}\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'm = {a_i} * {(b_1 * b_2) % p}\n'
        f'm = {m}', end='\n\n')
    print(
        f'Der zum Geheimtext c_2 gehörende Klartext m_2 ergibt sich aus:\n'
        f'm_2 = m * m_1^-1 mod p\n'
        f'm_2 = {m} * {m_1}^-1 mod {p}\n'
        f'<AUXILIARY 2>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 2>\n'
        f'm_2 = {m_2}', end='\n\n')
    print(
        f'Verifikation:\n'
        f'm = m_1 * m_2 mod p\n'
        f'{m} = {m_1} * {m_2} mod {p}\n'
        f'{m} = {(m_1 * m_2) % p}', end='\n\n')
    return m_2


# ElGamal homomorphic multiplicative decryption with identical random value
def homomorphic_multiplicative_decryption_k(public_key, m_1, c_1, c_2, print_matrix=False,
                                            print_linear_factorization=True):
    print(tabulate([['Homomorphe multiplikative Entschlüsselung mit identischem Zufallswert']], tablefmt='fancy_grid'))

    # Unpack the public key into its components
    p, g, e = public_key

    # Unpack both ciphertexts into its components
    a_1, b_1 = c_1
    a_2, b_2 = c_2

    # Calculation of m_2 assuming that the random numbers of both ciphertexts are identical
    b_1_i = modulo_inverse_multiplicative.mim(p, b_1, print_matrix, print_linear_factorization, 1)
    m_2 = (b_1_i * b_2 * m_1) % p

    # Calculation of m_1_i
    m_1_i = modulo_inverse_multiplicative.mim(p, m_1, print_matrix, print_linear_factorization, 2)

    # Calculation path output
    print(
        f'Gegeben sind K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} mit den Geheimtexten c_1 = {{a_1, b_1}} = '
        f'{{{a_1}, {b_1}}} und c_2 = {{a_2, b_2}} = {{{a_2}, {b_2}}}. Ebenfalls bekannt ist der zu c_1 zugehörige '
        f'Klartext m_1 = {m_1}. Unter Ausnutzung des Zugriffs auf die Verschlüsselungsfunktion mit einem identischen '
        f'Zufallswert k für die Berechnung der Geheimtexte kann nun der Klartext m_2 des Geheimtextes c_2 ermittelt '
        f'werden.', end='\n\n')
    print(
        f'Der zum Geheimtext c_2 gehörende Klartext m_2 ergibt sich aus:\n'
        f'm_2 = b_1^-1 * b_2 * m_1 mod p\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'm_2 = {b_1_i} * {b_2} * {m_1} mod {p}\n'
        f'm_2 = {b_1_i * b_2 * m_1} mod {p}\n'
        f'm_2 = {m_2}', end='\n\n')
    print(
        f'Verifikation:\n'
        f'b_1^-1 * b_2 = m_1^-1 * m_2 mod p\n'
        f'<AUXILIARY 2>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 2>\n'
        f'{b_1_i} * {b_2} = {m_1_i} * {m_2} mod {p}\n'
        f'{(b_1_i * b_2) % p} = {(m_1_i * m_2) % p}', end='\n\n')
    return m_2


# ElGamal baby-step giant-step
def bsgs(public_key, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['ElGamal Babystep-Giantstep-Algorithmus']], tablefmt='fancy_grid'))

    # Unpack the public key into its components
    p, g, e = public_key

    # Print calculation message
    print('Berechnung, bitte warten...', end='\r')

    # Calculation of m
    m = ceil(sqrt(p - 1))

    # Calculation of g^{0...(m-1)} mod p (baby-step)
    tab = {(g ** r) % p: r for r in range(m)}

    # Calculation of y
    y = (g ** (m * (p - 2))) % p

    # Find match in table (giant-step)
    for q in range(m):
        z = (e * (y ** q)) % p
        if z in tab:
            d = q * m + tab[z]
            break

    # Removal of the calculation message
    print(' ' * len('Berechnung, bitte warten...'), end='\r')

    # Calculation of g_i
    g_i = modulo_inverse_multiplicative.mim(p, g, print_matrix, print_linear_factorization, 1)

    # Check the local existence of d
    if not 'd' in locals():
        print(f'Der zum öffentlichen Schlüssel K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}} zugehörige private Schlüssel '
              f'K(priv) = {{p, d}} konnte nicht mittels des Babystep-Giantstep-Algorithmus bestimmt werden.')
        return -1

    # Calculation path output
    print(
        f'Gegeben ist der öffentliche Schlüssel K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}}. Unter Verwendung des '
        f'Babystep-Giantstep-Algorithmus zur Berechnung des diskreten Logarithmus im endlichen Zahlenkörper wird '
        f'nachfolgend der private Schlüssel K(priv) = {{p, d}} bestimmt.', end='\n\n')
    print(
        f'Zunächst ist die Menge der Paare M = {{(e * g^-r, r) | 0 ≤ r < m}} mod p zu bestimmen.\n'
        f'm = ⌈√(p - 1)⌉\n'
        f'm = ⌈√({p - 1})⌉\n'
        f'm = ⌈{sqrt(p - 1)}⌉\n'
        f'm = {m}', end='\n\n')
    print(
        f'Dabei ergibt sich die folgende Menge der Paare über (e * g^-r, r) mod p\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'({e} * {g}^-{0}, {0}) = ({e} * {g_i ** 0}, {0}) = ({(e * (g_i ** 0)) % p}, {0}) mod {p}\n'
        f'[...]\n'
        f'({e} * {g}^-{d - 1}, {d - 1}) = ({e} * ({g}^-1)^{d - 1}, {d - 1}) = ({e} * {g_i}^{d - 1}, {d - 1}) = '
        f'({(e * (g_i ** (d - 1))) % p}, {d - 1}) mod {p}\n'
        f'({e} * {g}^-{d}, {d}) = ({e} * ({g}^-1)^{d}, {d}) = ({e} * {g_i}^{d}, {d}) = ({(e * (g_i ** d)) % p}, {d}) '
        f'mod {p}', end='\n\n')
    print(
        f'Dabei ist zu erkennen, dass das Paar ({(e * (g_i ** d)) % p}, {d}) die Lösung für den diskreten Logarithmus '
        f'darstellt. Folglich entspricht der private Schlüssel K(priv) = {{p, d}} = {{{p}, {d}}}.', end='\n\n')
    print(
        f'Verifikation mit K(pub) = {{p, g, e}} = {{{p}, {g}, {e}}}:\n'
        f'e = g^d mod p\n'
        f'e = {g}^{d} mod {p}\n'
        f'e = {(g ** d) % p}\n'
        f'{e} = {(g ** d) % p}', end='\n\n')
    return d
