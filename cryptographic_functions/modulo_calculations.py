#!/usr/bin/env python3

from cryptographic_functions import modulo_inverse_additive
from cryptographic_functions import modulo_inverse_multiplicative
from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Addition in finite sets
def addition(m, a, b):
    print(tabulate([['Addition in endlichen Mengen']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    if m < 2:
        print(f'Die Variable m = {m} muss größer gleich 2 sein.')
        return -1

    if a not in range(m):
        print(f'Die Variable a = {a} muss zwischen 0 und {m - 1} liegen.')
        return -1

    if b not in range(m):
        print(f'Die Variable b = {b} muss zwischen 0 und {m - 1} liegen.')
        return -1

    q = (a + b) // m
    r = (a + b) % m

    # Calculation path output
    print(f'Die modulo m = {m} Addition von {a} ⊕ {b} = {r}, da gilt:\n'
          f'({a} + {b}) / {m} = {q} + ({r} / {m})\n'
          f'{a} + {b} = {q} * {m} + {r}\n'
          f'Daraus folgt: {a} ⊕ {b} = {r}', end='\n\n')
    return r


# Subtraction in finite sets
def subtraction(m, a, b, print_matrix=False):
    print(tabulate([['Subtraktion in endlichen Mengen']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    i = modulo_inverse_additive.mia(m, b, print_matrix, 1)

    q = (a + i) // m
    r = (a + i) % m

    # Calculation path output
    if i != -1:
        print(f'Die modulo m = {m} Subtraktion von {a} ⊖ {b} = {r}, da gilt:\n'
              f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
              f'({a} + {i}) / {m} = {q} + ({r} / {m})\n'
              f'{a} + {i} = {q} * {m} + {r}\n'
              f'Daraus folgt: {a} ⊖ {b} = {a} ⊕ ({-a}) = {a} ⊕ {i} = {r}', end='\n\n')
        return r
    else:
        print(
            f'Die modulo m = {m} Subtraktion von {a} ⊖ {b} kann nicht durchgeführt werden, da das additiv inverse '
            f'Element für m und b nicht definiert ist.', end='\n\n')
        return -1


# Multiplication in finite sets
def multiplication(m, a, b):
    print(tabulate([['Multiplikation in endlichen Mengen']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    if m < 2:
        print(f'Die Variable m = {m} muss größer gleich 2 sein.')
        return -1

    if a not in range(1, m):
        print(f'Die Variable a = {a} muss zwischen 1 und {m - 1} liegen.')
        return -1

    if b not in range(1, m):
        print(f'Die Variable b = {b} muss zwischen 1 und {m - 1} liegen.')
        return -1

    q = (a * b) // m
    r = (a * b) % m

    # Calculation path output
    print(f'Die modulo m = {m} Multiplikation von {a} ⊙ {b} = {r}, da gilt:\n'
          f'({a} * {b}) / {m} = {q} + ({r} / {m})\n'
          f'{a} * {b} = {q} * {m} + {r}\n'
          f'Daraus folgt: {a} ⊙ {b} = {r}', end='\n\n')
    return r


# Division in finite sets
def division(m, a, b, print_matrix=False, print_linear_factorization=True):
    print(tabulate([['Division in endlichen Mengen']], tablefmt='fancy_grid'))

    # Checking whether requirements are met
    i = modulo_inverse_multiplicative.mim(m, b, print_matrix, print_linear_factorization, 1)

    q = (a * i) // m
    r = (a * i) % m

    # Calculation path output
    if i != -1:
        print(f'Die modulo m = {m} Division von {a} ⊘ {b} = {r}, da gilt:\n'
              f'<AUXILIARY 1>Achtung: Die Namen der Variablen können abweichen!</AUXILIARY 1>\n'
              f'({a} * {i}) / {m} = {q} + ({r} / {m})\n'
              f'{a} * {i} = {q} * {m} + {r}\n'
              f'Daraus folgt: {a} ⊘ {b} = {a} ⊙ {b}^-1 = {a} ⊙ {i} = {r}', end='\n\n')
        return r
    else:
        print(
            f'Die modulo m = {m} Division von {a} ⊘ {b} kann nicht durchgeführt werden, da m und b nicht teilerfremd '
            f'sind und folglich das multiplikativ inverse Element nicht definiert ist.', end='\n\n')
        return -1
