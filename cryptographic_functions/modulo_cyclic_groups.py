#!/usr/bin/env python3

from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Cyclic groups
def mcg(m, print_matrix=False):
    print(tabulate([['Primitive und nicht-primitive Elemente in zyklischen Gruppen']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    if m < 2:
        print(f'Die Variable m = {m} muss größer gleich 2 sein.')
        return -1

    # Table calculation
    table = [list(range(1, m))]
    for y in range(1, m):
        table.append([(x ** y) % m for x in range(1, m)])

    # Table matrix output
    if print_matrix:
        print(f'modulo-{m}-Zyklustabelle:')
        print(tabulate(zip(*table), headers=tuple(['z'] + ['z' + str(z) for z in range(1, m)]), tablefmt='pretty'),
              end='\n\n')

    p = []
    n = []

    # Identify the primitive and non-primitive elements
    for i, x in enumerate([sorted(z) for z in zip(*table[1:])], start=1):
        if x == list(range(1, m)):
            p.append(i)
        else:
            n.append(i)

    # Calculation path output
    if len(p) > 0:
        print(
            f'Die Elemente g = {{{", ".join(map(str, p))}}} sind primitive Elemente der zyklischen Gruppe der Ordnung '
            f'm = {m}.', end='\n\n')
    else:
        print(f'Für die zyklische Gruppe der Ordnung m = {m} konnten keine primitiven Elemente ermittelt werden.',
              end='\n\n')
        p = -1
    if len(n) > 0:
        print(
            f'Die Elemente g = {{{", ".join(map(str, n))}}} sind nicht-primitive Elemente der zyklischen Gruppe der '
            f'Ordnung m = {m}.', end='\n\n')
    else:
        print(f'Für die zyklische Gruppe der Ordnung m = {m} konnten keine nicht-primitiven Elemente ermittelt werden.',
              end='\n\n')
        n = -1
    return p, n
