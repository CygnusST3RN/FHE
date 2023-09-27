import numpy as np
from numpy.polynomial import polynomial as poly

def gen_binary_poly(size):
    """Generates a polynomial with coeffecients in [0, 1]
     """
    return np.random.randint(0, 2, size, dtype=np.int64)


def gen_uniform_poly(size, modulus):
    """Generates a polynomial with coeffecients being integers in Z_modulus
    """
    return np.random.randint(0, modulus, size, dtype=np.int64)


def gen_normal_poly(size):
    """Generates a polynomial with coeffecients in a normal distribution
    of mean 0 and a standard deviation of 2, then discretize it.
    """
    return np.int64(np.random.normal(0,2, size=size))


# Functions for polynomial evaluation in Z_q[X]/(X^N + 1)

def polymul(x, y, modulus, poly_mod):
    """Multiply two polynomials
    """
    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) %
                              modulus, poly_mod)[1] % modulus)
    )


def polyadd(x, y, modulus, poly_mod):
    """Add two polynomials
    """
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(x, y) %
                              modulus, poly_mod)[1] % modulus)
    )


# Functions for keygen, encryption and decryption

def keygen(size, modulus, poly_mod):
    """Generate a public and secret keys
    """
    s = gen_binary_poly(size)
    a = gen_uniform_poly(size, modulus)
    e = gen_normal_poly(size)
    b = polyadd(polymul(-a, s, modulus, poly_mod), -e, modulus, poly_mod)

    return (b, a), s


def encrypt(pk, size, q, t, poly_mod, pt):
    """Encrypt an integer.
    """
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    ct0 = polyadd(
        polyadd(
            polymul(pk[0], u, q, poly_mod),
            e1, q, poly_mod),
        scaled_m, q, poly_mod
    )
    ct1 = polyadd(
        polymul(pk[1], u, q, poly_mod),
        e2, q, poly_mod
    )
    return (ct0, ct1)


def decrypt(sk, size, q, t, poly_mod, ct):
    """Decrypt a ciphertext
    """
    scaled_pt = polyadd(
        polymul(ct[1], sk, q, poly_mod),
        ct[0], q, poly_mod
    )
    delta = q // t
    decrypted_poly = np.round(scaled_pt / delta) % t
    return int(decrypted_poly[0])


# Function for adding and multiplying encrypted values

def addPlain(ct, pt, q, t, poly_mod):
    """Add a ciphertext and a plaintext.
    """
    size = len(poly_mod) - 1
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m
    new_ct0 = polyadd(ct[0], scaled_m, q, poly_mod)
    return (new_ct0, ct[1])


def addCipher(ct1, ct2, q, poly_mod):
    """Add a ciphertext and a ciphertext.
    """
    new_ct0 = polyadd(ct1[0], ct2[0], q, poly_mod)
    new_ct1 = polyadd(ct1[1], ct2[1], q, poly_mod)
    return (new_ct0, new_ct1)


def mulPlain(ct, pt, q, t, poly_mod):
    """Multiply a ciphertext and a plaintext.
    """
    size = len(poly_mod) - 1
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    new_c0 = polymul(ct[0], m, q, poly_mod)
    new_c1 = polymul(ct[1], m, q, poly_mod)
    return (new_c0, new_c1)



if __name__ == "__main__":

    # polynomial modulus degree
    n = 2**5
  
    # ciphertext modulus
    q = 2**60
  
    # plaintext modulus
    t = 2**30
  
    # polynomial modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])

    # Keygen
    pk, sk = keygen(n, q, poly_mod)

    # Encryption
    #sample integers
    pt1, pt2 = 849, 403
    cst1, cst2 = 7, 5

    ct1 = encrypt(pk, n, q, t, poly_mod, pt1)
    ct2 = encrypt(pk, n, q, t, poly_mod, pt2)
    print(f"The decrypted value of ct1 is {decrypt(sk , n , q , t ,poly_mod , ct1)}")
    print("[+] Ciphertext ct1({}):".format(pt1))
    print("")
    print("\t ct1_0:", ct1[0])
    print("\t ct1_1:", ct1[1])
    print("")
    print("[+] Ciphertext ct2({}):".format(pt2))
    print("")
    print("\t ct2_0:", ct2[0])
    print("\t ct2_1:", ct2[1])
    print("")

    # Evaluation
    ct3 = addPlain(ct1, cst1, q, t, poly_mod)
    ct4 = mulPlain(ct2, cst2, q, t, poly_mod)
    print(f"ct3_0 : {ct3[0]} ,\n ct3_1 : {ct3[1]}")
    print(f"ct4_0 : {ct3[0]} ,\n ct4_1 : {ct3[1]}")

    # ct5 = ct1 + 7 + 3 * ct2
    ct5 = addCipher(ct3, ct4, q, poly_mod)
    ct6 = addCipher(ct1 , ct2 , q , poly_mod)
    # Decryption
    decrypted_ct3 = decrypt(sk, n, q, t, poly_mod, ct3)
    decrypted_ct4 = decrypt(sk, n, q, t, poly_mod, ct4)
    decrypted_ct5 = decrypt(sk, n, q, t, poly_mod, ct5)
    dct6 = decrypt(sk , n , q , t , poly_mod , ct6)
    print("[+] Decrypted ct3(ct1 + {}): {}".format(cst1, decrypted_ct3))
    print("[+] Decrypted ct4(ct2 * {}): {}".format(cst2, decrypted_ct4))
    print("[+] Decrypted ct5(ct1 + {} + {} * ct2): {}".format(cst1, cst2, decrypted_ct5))
    print(f"ct6 = {ct6}")
    print(f"dct6 = {dct6}")
