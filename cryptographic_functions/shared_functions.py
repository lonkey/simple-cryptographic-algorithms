#!/usr/bin/env python3

from tabulate import tabulate

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"


# Simple gcd calculation
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Extended gcd calculation
def gcd_extended(m, a):
    list_m = []
    list_a = []
    list_q = []
    list_r = []
    q = None
    r = None

    while r != 0:
        q = m // a
        r = m % a
        list_m.append(m)
        list_a.append(a)
        list_q.append(q)
        list_r.append(r)
        m = a
        a = r
    return list_m, list_a, list_q, list_r


# Simple primality test
def is_prime(n):
    # Corner cases
    if n <= 1:
        return False
    if n <= 3:
        return True

    # This is checked so that we can skip middle five numbers in below loop
    if n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i = i + 6
    return True


# Extended linear factorization calculation
def linear_factorization(list_m, list_a, list_q, list_r):
    x = 0
    y = 1
    list_x = [x]
    list_y = [y]
    list_y_calc = [str(y)]

    for i, (m, a, q, r) in enumerate(zip(list_m[::-1], list_a[::-1], list_q[::-1], list_r[::-1]), start=1):
        if i == 1:
            continue
        list_x.append(y)
        y = x - q * list_x[-1]
        list_y_calc.append(f'{x} - {q} * ({list_x[-1]}) = {y}')
        list_y.append(y)
        x = list_x[-1]
    return list_m, list_a, list_q, list_r, list_x[::-1], list_y_calc[::-1], list_y[::-1]


def print_auxiliary(print_header):
    if not print_header:
        print('', end='\n\n')
    else:
        print(tabulate([[f'</AUXILIARY {print_header}>']], tablefmt='fancy_grid'), end='\n\n')
