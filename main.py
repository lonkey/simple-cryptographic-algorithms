#!/usr/bin/env python3

from cryptographic_functions import dh_calculations
from cryptographic_functions import ecc_calculations
from cryptographic_functions import elgamal_calculations
from cryptographic_functions import fermat_calculations
from cryptographic_functions import fiat_shamir_calculations
from cryptographic_functions import modulo_calculations
from cryptographic_functions import modulo_cyclic_groups
from cryptographic_functions import modulo_inverse_additive
from cryptographic_functions import modulo_inverse_multiplicative
from cryptographic_functions import rsa_calculations
from cryptographic_functions import shamir_calculations

__author__ = "Lukas Zorn"
__copyright__ = "Copyright 2021 Lukas Zorn"
__license__ = "GNU GPLv3"

if __name__ == '__main__':
    #########################
    # Global initial values #
    #########################
    print_matrix = False  # Optional argument
    print_linear_factorization = True  # Optional argument

    #########################
    # Modulo initial values #
    #########################
    modulo_m = 13
    modulo_a = 7
    modulo_b = 9

    # modulo_calculations.addition(modulo_m, modulo_a, modulo_b)
    # modulo_calculations.subtraction(modulo_m, modulo_a, modulo_b, print_matrix)
    # modulo_calculations.multiplication(modulo_m, modulo_a, modulo_b)
    # modulo_calculations.division(modulo_m, modulo_a, modulo_b, print_matrix, print_linear_factorization)
    # modulo_cyclic_groups.mcg(modulo_m, print_matrix)
    # modulo_inverse_additive.mia(modulo_m, modulo_a, print_matrix)
    # modulo_inverse_multiplicative.mim(modulo_m, modulo_a, print_matrix, print_linear_factorization)

    ######################
    # RSA initial values #
    ######################
    rsa_p = 3
    rsa_q = 11
    rsa_n = 33
    rsa_e = 3  # Optional argument
    rsa_d = 7
    rsa_public_key = (rsa_e, rsa_n)
    rsa_private_key = (rsa_d, rsa_n)
    rsa_plaintext = 4
    rsa_ciphertext = 31
    rsa_x = 1  # Optional argument
    rsa_c = 23  # Optional argument

    # rsa_calculations.keypair_generation(rsa_p, rsa_q, rsa_e, print_matrix, print_linear_factorization)
    # rsa_calculations.encryption(rsa_public_key, rsa_plaintext)
    # rsa_calculations.decryption(rsa_private_key, rsa_ciphertext)
    # rsa_calculations.pollard_rho(rsa_n, rsa_x, rsa_c)

    #################################
    # Diffie–Hellman initial values #
    #################################
    dh_p = 23
    dh_g = 5
    dh_a = 6  # Optional argument
    dh_b = 15  # Optional argument

    # dh_calculations.key_exchange(dh_p, dh_g, dh_a, dh_b)

    #############################################
    # Shamir three-pass protocol initial values #
    #############################################
    shamir_p = 23
    shamir_a = 3  # Optional argument
    shamir_a_i = 15
    shamir_b = 5  # Optional argument
    shamir_b_i = 9
    shamir_k = 2  # Optional argument
    shamir_key_a = (shamir_a, shamir_a_i, shamir_p)
    shamir_key_b = (shamir_b, shamir_b_i, shamir_p)

    # shamir_calculations.keypair_generation(shamir_p, shamir_a, shamir_b, print_matrix, print_linear_factorization)
    # shamir_calculations.key_exchange(shamir_key_a, shamir_key_b, shamir_k)

    ##########################
    # ElGamal initial values #
    ##########################
    elgamal_p = 7
    elgamal_g = 5
    elgamal_d = 4  # Optional argument
    elgamal_e = 2
    elgamal_k = 3  # Optional argument
    elgamal_public_key = (elgamal_p, elgamal_g, elgamal_e)
    elgamal_private_key = (elgamal_p, elgamal_d)
    elgamal_plaintext = 3
    elgamal_ciphertext = (20, 12)
    elgamal_r = 7  # Optional argument
    elgamal_p_n = 3
    elgamal_s = 7
    elgamal_signed_message = (elgamal_plaintext, elgamal_p_n, elgamal_s)
    elgamal_homomorphic_c_1 = (3, 3)
    elgamal_homomorphic_c_2 = (6, 3)

    # elgamal_calculations.keypair_generation(elgamal_p, elgamal_g, elgamal_d)
    # elgamal_calculations.encryption(elgamal_public_key, elgamal_plaintext, elgamal_k)
    # elgamal_calculations.decryption(elgamal_private_key, elgamal_ciphertext, print_matrix, print_linear_factorization)
    # elgamal_calculations.sign(elgamal_public_key, elgamal_private_key, elgamal_plaintext, elgamal_r, print_matrix,
    #                           print_linear_factorization)
    # elgamal_calculations.verify(elgamal_public_key, elgamal_signed_message)
    # elgamal_calculations.homomorphic_multiplicative_scheme(elgamal_public_key, elgamal_private_key,
    #                                                        elgamal_homomorphic_c_1, elgamal_homomorphic_c_2,
    #                                                        print_matrix, print_linear_factorization)

    #########################################
    # Fermat's factorization initial values #
    #########################################
    fermat_n = 33

    # fermat_calculations.factorization(fermat_n)

    #################################
    # Elliptic curve initial values #
    #################################
    # y^2 = x^3 + ecc_a * x + ecc_b (mod ecc_n)
    ecc_a = 1
    ecc_b = 7
    ecc_n = 17
    ecc_curve = (ecc_a, ecc_b, ecc_n)
    ecc_p = (2, 0)
    ecc_q = (1, 3)

    # ecc_calculations.on_curve(ecc_curve, ecc_p)
    # ecc_calculations.addition(ecc_curve, ecc_p, ecc_q, print_matrix, print_linear_factorization)

    ####################################################
    # Fiat-Shamir identification scheme initial values #
    ####################################################
    fiat_shamir_p = 5
    fiat_shamir_q = 3
    fiat_shamir_n = fiat_shamir_p * fiat_shamir_q
    fiat_shamir_s = 7  # Optional argument
    fiat_shamir_v = 4  # Optional argument
    fiat_shamir_public_key = (fiat_shamir_v, fiat_shamir_n)
    fiat_shamir_private_key = (fiat_shamir_s, fiat_shamir_n)
    fiat_shamir_k = 13  # Optional argument
    fiat_shamir_b = 1  # Optional argument
    fiat_shamir_y = 3  # Optional argument

    # fiat_shamir_calculations.keypair_generation(fiat_shamir_p, fiat_shamir_q, fiat_shamir_s, fiat_shamir_v)
    # fiat_shamir_calculations.verification(fiat_shamir_public_key, fiat_shamir_private_key, fiat_shamir_k,
    #                                       fiat_shamir_b, print_matrix, print_linear_factorization)
    # fiat_shamir_calculations.attack_scheme(fiat_shamir_public_key, fiat_shamir_y, fiat_shamir_b, print_matrix,
    #                                        print_linear_factorization)
