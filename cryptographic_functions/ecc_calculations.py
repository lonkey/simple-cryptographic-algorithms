#!/usr/bin/env python3

from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Elliptic curve point verification
def on_curve(curve, p):
    print(tabulate([['Verifikation eines Punktes auf der elliptischen Kurve']], tablefmt='fancy_grid'))

    # Unpack all curve parameters and the point into its components
    a, b, n = curve
    x_p, y_p = p

    v_p = True if (y_p ** 2) % n == ((x_p ** 3) + (a * x_p) + b) % n else False

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
              f'{((x_p ** 3) + (a * x_p) + b) % n}.', end='\n\n')
    else:
        print(f'Folglich liegt der Punkt P nicht auf der elliptischen Kurve, da {(y_p ** 2) % n} != '
              f'{((x_p ** 3) + (a * x_p) + b) % n}.', end='\n\n')
    return v_p


# Elliptic curve point addition
def addition(curve, p, q):
    print(tabulate([['Addition von Punkten auf der elliptischen Kurve']], tablefmt='fancy_grid'))

    # Unpack all curve parameters and both points into its components
    a, b, n = curve
    x_p, y_p = p
    x_q, y_q = q

    v_p = True if (y_p ** 2) % n == ((x_p ** 3) + (a * x_p) + b) % n else False
    v_q = True if (y_q ** 2) % n == ((y_p ** 3) + (a * y_p) + b) % n else False

    print(f'v_p = {v_p}\tv_q = {v_q}')


# Elliptic curve double-and-add
def double_and_add(curve, p):
    print(tabulate([['Punktverdoppelung auf der elliptischen Kurve']], tablefmt='fancy_grid'))

    # Unpack all curve parameters and the point into its components
    a, b, n = curve
    x_p, y_p = p
