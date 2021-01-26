# Simple Cryptographic Algorithms

Python library for demonstrating the functionality of common cryptographic algorithms.

## Requirements

Python 3.7.9 or later including pip for installing the following requirements:

```shell
pip install -r requirements.txt
```

## Usage

To use, simply uncomment the corresponding function in `main.py` and adjust the sample values if necessary.

## To Do

- Include a brute force function for flexible cracking of all included algorithms in the lower prime range
    - Enhance the time complexity of the existing RSA `rsa_calculations.brute_force_by_key()` function from its current 2<sup>O(n)</sup>
- Unify output of mathematical conditions
- Add an English translation
