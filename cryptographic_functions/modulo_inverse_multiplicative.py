#!/usr/bin/env python3

from cryptographic_functions import shared_functions
from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Multiplicative inverse element in finite sets
def mim(m, a, print_matrix=False, print_linear_factorization=True, print_header=None):
    if not print_header:
        print(tabulate([['Multiplikativ inverses Element in endlichen Mengen']], tablefmt='fancy_grid'))
    else:
        print(tabulate([[f'<AUXILIARY {print_header}>Multiplikativ inverses Element']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    if m < 2:
        print(f'Die Variable m = {m} muss größer gleich 2 sein.')
        return -1

    if a not in range(1, m):
        print(f'Die Variable a = {a} muss zwischen 1 und {m - 1} liegen.')
        return -1

    if print_matrix:
        # Table calculation
        table = [list(range(m)), [0] * m]
        for x in range(1, m):
            table.append([0] + [(x * y) % m for y in range(1, m)])

        # Table matrix output
        print(f'modulo-{m}-Multiplikationstabelle:')
        print(tabulate(zip(*table), headers=tuple(['⊙'] + list(range(m))), tablefmt='pretty'), end='\n\n')

    list_m, list_a, list_q, list_r, list_x, list_y_calc, list_y = \
        shared_functions.linear_factorization(*shared_functions.gcd_extended(m, a))

    # Linear factorization output
    if print_linear_factorization:
        print(f'ggT- und Linearfaktorzerlegungstabelle für m = {m} und a = {a}:')
        print(tabulate(zip(*(range(1, len(list_m) + 1), list_m, list_a, list_q, list_r, list_x, list_y_calc, list_y)),
                       headers=['i', 'm', 'a', 'q', 'r', 'x', 'y_calc', 'y'], tablefmt='pretty'))
        print('Die Berechnungstabelle des erweiterten euklidschen Algorithmus entspricht dem Muster m = a * q + r.',
              end='\n\n')

    # Correction of the gcd in very small finite fields
    if len(list_r) < 2:
        gcd = a
    else:
        gcd = list_r[-2]

    # Calculation path output
    print(
        f'Aus den Ergebnissen der ggT- und Linearfaktorzerlegungstabelle folgt somit:\n'
        f'ggT({m},{a}) = {gcd} = m1 * (x1) + a1 * (y1) = {list_m[0]} * ({list_x[0]}) + {list_a[0]} * ({list_y[0]})',
        end='\n\n')
    if gcd == 1:
        if list_y[0] < 0:
            print(f'Da nach der Linearfaktorzerlegung das multiplikativ inverse Element a^-1 = {list_y[0]} negativ '
                  f'ist, entspricht dessen tatsächlicher Wert a^-1 = a^-1 + m = {list_y[0]} + {m} = {list_y[0] + m}.')
            list_y[0] = list_y[0] + m
        print(
            f'Das in modulo m = {m} multiplikativ inverse Element zu a = {a} ist a^-1 = {list_y[0]}, da gilt:\n'
            f'a ⊙ a^-1 = {list_y[0]} ⊙ {a} = {list_y[0] * a} mod {m} = {(list_y[0] * a) % m}')
        shared_functions.print_auxiliary(print_header)
        return list_y[0]
    else:
        print(
            f'Das in modulo m = {m} multiplikativ inverse Element zu a = {a} kann folglich nicht bestimmt werden, da m '
            f'und a nicht teilerfremd sind.')
        shared_functions.print_auxiliary(print_header)
        return -1
