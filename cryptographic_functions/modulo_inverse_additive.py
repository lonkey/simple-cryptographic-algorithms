#!/usr/bin/env python3

from cryptographic_functions import shared_functions
from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Additive inverse element in finite sets
def mia(m, a, print_matrix=False, print_header=None):
    if not print_header:
        print(tabulate([['Additives inverses Element in endlichen Mengen']], tablefmt='fancy_grid'))
    else:
        print(tabulate([[f'<AUXILIARY {print_header}>Additives inverses Element']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    if m < 2:
        print(f'Die Variable m = {m} muss größer gleich 2 sein.')
        return -1

    if a not in range(m):
        print(f'Die Variable a = {a} muss zwischen 0 und {m - 1} liegen.')
        return -1

    if print_matrix:
        # Table calculation
        table = [list(range(m))]
        for x in range(m):
            table.append([(x + y) % m for y in range(m)])

        # Table matrix output
        print(f'modulo-{m}-Additionstabelle:')
        print(tabulate(zip(*table), headers=tuple(['⊕'] + list(range(m))), tablefmt='pretty'), end='\n\n')

    i = m - a
    q = (a + i) // m
    r = (a + i) % m

    # Calculation path output
    print(
        f'Das in modulo m = {m} additiv inverse Element zu a = {a} ist (-a) = {i}, da gilt:\n'
        f'({a} + {i}) / {m} = {q} + ({r} / {m})\n'
        f'{a} + {i} = {m} = {q} * {m} + {r}\n'
        f'Daraus folgt: a ⊕ (-a) = {a} ⊕ ({m} - {a}) = {a} ⊕ {i} = 0')
    shared_functions.print_auxiliary(print_header)
    return i
