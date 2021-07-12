#!/usr/bin/env python3

from cryptographic_functions import shared_functions
from tabulate import tabulate
import math

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Fermat's factorization
def factorization(n):
    print(tabulate([['Faktorisierungsmethode von Fermat']], tablefmt='fancy_grid'))

    # Choose an integer n that is not a prime number
    if shared_functions.is_prime(n):
        print(f'Das Modul n = {n} darf für eine Faktorisierung keine Primzahl sein.')
        return -1

    # Calculate an integer x such that x > √(x)
    x = math.ceil(math.sqrt(n))

    # Calculation of y
    y = (x ** 2) - n

    # Save all intermediate results
    list_x = [x]
    list_q_x = [f'{y} = {x}^2 - {n}']
    list_y_2 = [f'{int(math.sqrt(y))}^2' if math.sqrt(y).is_integer() else '-']

    while not math.sqrt(y).is_integer():
        x += 1
        list_x.append(x)
        y = x ** 2 - n
        list_q_x.append(f'{y} = {x}^2 - {n}')
        list_y_2.append(f'{int(math.sqrt(y))}^2' if math.sqrt(y).is_integer() else '-')

    print(f'Faktorisierungstabelle nach Fermat für n = {n}:')
    print(tabulate(zip(*(list_x, list_q_x, list_y_2)),
                   headers=['x', 'q(x) = x^2 - n', 'y^2'], tablefmt='pretty'), end='\n\n')

    # Calculation path output
    print(
        f'Gemäß der Faktorisierungstabelle lässt sich q(x) für x = {list_x[-1]} somit als Quadratzahl darstellen:\n'
        f'q({list_x[-1]}) = {list_q_x[-1]} = {list_y_2[-1]}', end='\n\n')
    print(
        f'Daraus folgt:\n'
        f'(1): x^2 - n = y^2\n'
        f'(1): {list_x[-1]}^2 - {n} = {list_y_2[-1]}\n'
        f'(1): {list_x[-1] ** 2} - {n} = {y}\n\n'
        f'(2): x^2 - y^2 = n\n'
        f'(2): {list_x[-1]}^2 - {list_y_2[-1]} = {n}\n'
        f'(2): {list_x[-1] ** 2} - {y} = {n}', end='\n\n')
    print(
        f'Damit lassen sich nun die Faktoren von p und q bestimmen:\n'
        f'x^2 - y^2 = (x + y) * (x - y) = p * q = n\n'
        f'{list_x[-1]}^2 - {int(math.sqrt(y))}^2 = ({list_x[-1]} + {int(math.sqrt(y))}) * ({list_x[-1]} - '
        f'{int(math.sqrt(y))}) = {list_x[-1] + int(math.sqrt(y))} * {list_x[-1] - int(math.sqrt(y))} = {n}', end='\n\n')
    print(
        f'Daraus folgt p = {list_x[-1] + int(math.sqrt(y))} und q = {list_x[-1] - int(math.sqrt(y))}.', end='\n\n')
    return list_x[-1] + int(math.sqrt(y)), list_x[-1] - int(math.sqrt(y))
