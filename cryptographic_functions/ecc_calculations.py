#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import shared_functions
from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Extended elliptic curve point verification
def on_curve(curve, p, print_header=None):
    if not print_header:
        print(tabulate([['Verifikation eines Punktes auf der elliptischen Kurve']], tablefmt='fancy_grid'))
    else:
        print(tabulate([[f'<AUXILIARY {print_header}>Verifikation eines Punktes auf der elliptischen Kurve']],
                       tablefmt='fancy_grid'))

    # Unpack all curve parameters and the point into its components
    a, b, n = curve
    x_p, y_p = p

    v_p = (y_p ** 2) % n == ((x_p ** 3) + (a * x_p) + b) % n

    # Calculation path output
    print(
        f'Durch das Einsetzen des Punktes P = (x_p|y_p) = ({x_p}|{y_p}) in die elliptischen Kurve y^2 = x^3 + a * x + '
        f'b im GF({n}) wird berechnet:\n'
        f'{y_p}^2 = {x_p}^3 + {a} * {x_p} + {b} mod {n}\n'
        f'{y_p ** 2} = {x_p ** 3} + {a * x_p} + {b} mod {n}\n'
        f'{y_p ** 2} = {(x_p ** 3) + (a * x_p) + b} mod {n}\n'
        f'{(y_p ** 2) % n} = {((x_p ** 3) + (a * x_p) + b) % n}', end='\n\n')
    if v_p:
        print(f'Folglich liegt der Punkt P auf der elliptischen Kurve, da {(y_p ** 2) % n} = '
              f'{((x_p ** 3) + (a * x_p) + b) % n}.')
    else:
        print(f'Folglich liegt der Punkt P nicht auf der elliptischen Kurve, da {(y_p ** 2) % n} != '
              f'{((x_p ** 3) + (a * x_p) + b) % n}.')
    shared_functions.print_auxiliary(print_header)
    return v_p


# Elliptic curve point addition
def addition(curve, p, q, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['Addition von Punkten auf der elliptischen Kurve']], tablefmt='fancy_grid'))

    # Unpack all curve parameters and both points into its components
    a, b, n = curve
    x_p, y_p = p
    x_q, y_q = q

    # Choose a point p that lies on the elliptic curve
    if not on_curve(curve, p, 1):
        print(f'Der Punkt P = ({x_p}|{y_p}) muss auf der elliptischen Kurve liegen.')
        return -1

    # Choose a point q that lies on the elliptic curve
    if not on_curve(curve, q, 2):
        print(f'Der Punkt Q = ({x_q}|{y_q}) muss auf der elliptischen Kurve liegen.')
        return -1

    # Calculation of m
    m_n = (y_p - y_q) % n
    m_d = modulo_inverse_multiplicative.mim(n, (x_p - x_q) % n, print_matrix, print_linear_factorization, 3)
    m = (m_n * m_d) % n

    # Calculation of x_r, y_r and y_r_i
    x_r = ((m ** 2) - x_p - x_q) % n
    y_r = (y_p - m * (x_p - x_r)) % n
    y_r_i = -y_r % n

    # Choose a point r that lies on the elliptic curve
    if not on_curve(curve, (x_r, y_r_i), 4):
        print(f'Der Punkt R = ({x_r}|{y_r_i}) muss auf der elliptischen Kurve liegen.')
        return -1

    # Calculation path output
    print(
        f'Im endlichen Zahlenkörper GF({n}) sollen auf Basis der Kurve y^2 = x^3 + {a} * x + {b} die Punkte '
        f'P = ({x_p}|{y_p}) und Q = ({x_q}|{y_q}) additiv verknüpft werden, um den Punkt R zu bestimmen.',
        end='\n\n')
    print(
        f'(1) Verifiziere, dass P = ({x_p}|{y_p}) auf der elliptischen Kurve liegt:\n'
        f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
        f'(2) Verifiziere, dass Q = ({x_q}|{y_q}) auf der elliptischen Kurve liegt:\n'
        f'<AUXILIARY 2>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 2>', end='\n\n')
    print(
        f'Für die additive Verknüpfung der beiden Punkte wird nun die Steigung m in GF({n}) berechnet:\n'
        f'm = (y_p - y_q) / (x_p - x_q) % n\n'
        f'm = (y_p - y_q) * (x_p - x_q)^-1 % n\n'
        f'm = ({y_p} - {y_q}) * ({x_p} - {x_q})^-1 % {n}\n'
        f'm = {m_n} * {x_p - x_q}^-1 % {n}\n'
        f'<AUXILIARY 3>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 3>\n'
        f'm = {m_n} * {m_d} % {n}\n'
        f'm = {m}', end='\n\n')
    print(
        f'Daraus folgt für die Berechnung von -R = (x_r|y_r):\n'
        f'x_r = ((m ** 2) - x_p - x_q) % n\n'
        f'x_r = (({m} ** 2) - {x_p} - {x_q}) % {n}\n'
        f'x_r = {(m ** 2) - x_p - x_q} % {n}\n'
        f'x_r = {x_r}\n'
        f'y_r = (y_p - m * (x_p - x_r)) % n\n'
        f'y_r = ({y_p} - {m} * ({x_p} - {x_r})) % {n}\n'
        f'y_r = {y_p - m * (x_p - x_r)} % {n}\n'
        f'y_r = {y_r}', end='\n\n')
    print(
        f'Aus dem Punkt -R = ({x_r}|{y_r}) kann nun mittels Punktnegation für y_r der Punkt R = ({x_r}|{y_r_i}) '
        f'berechnet werden:\n'
        f'y_r_i = -(y_r) % n\n'
        f'y_r_i = {-y_r} % {n}\n'
        f'y_r_i = {y_r_i}', end='\n\n')
    print(
        f'(3) Verifiziere, dass R = ({x_r}|{y_r_i}) auf der elliptischen Kurve liegt:\n'
        f'<AUXILIARY 4>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 4>', end='\n\n')
    return x_r, y_r_i
