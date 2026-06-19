from __future__ import annotations

_PRIMITIVE_POLY = 0x11D

EXP_TABLE = [0] * 256
LOG_TABLE = [0] * 256

_x = 1
for i in range(256):
    EXP_TABLE[i] = _x
    LOG_TABLE[_x] = i
    _x <<= 1
    if _x >= 256:
        _x ^= _PRIMITIVE_POLY
del _x


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b]) % 255]


def gf_pow(a: int, n: int) -> int:
    if a == 0:
        return 0
    return EXP_TABLE[(LOG_TABLE[a] * n) % 255]


def gf_poly_eval(poly: list[int], x: int) -> int:
    result = poly[0]
    for coeff in poly[1:]:
        result = gf_mul(result, x) ^ coeff
    return result


def gf_poly_mul(p: list[int], q: list[int]) -> list[int]:
    result = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            result[i + j] ^= gf_mul(a, b)
    return result


def gf_poly_scale(poly: list[int], scalar: int) -> list[int]:
    return [gf_mul(coeff, scalar) for coeff in poly]


def gf_poly_add(p: list[int], q: list[int]) -> list[int]:
    result = [0] * max(len(p), len(q))
    for i, coeff in enumerate(p):
        result[i + len(result) - len(p)] = coeff
    for i, coeff in enumerate(q):
        result[i + len(result) - len(q)] ^= coeff
    return result


def rs_calc_syndromes(
    data: bytes | bytearray | memoryview,
    nsym: int,
) -> list[int]:
    return [gf_poly_eval(list(data), gf_pow(2, i)) for i in range(nsym)]


def rs_find_error_locator(syndromes: list[int], nsym: int) -> list[int]:
    error_locator = [1]
    old_locator = [1]
    for i in range(nsym):
        delta = syndromes[i]
        for j in range(1, len(error_locator)):
            delta ^= gf_mul(error_locator[-(j + 1)], syndromes[i - j])
        old_locator.append(0)
        if delta != 0:
            if len(old_locator) > len(error_locator):
                new_locator = gf_poly_scale(old_locator, delta)
                old_locator = gf_poly_scale(error_locator, gf_div(1, delta))
                error_locator = new_locator
            error_locator = gf_poly_add(
                error_locator, gf_poly_scale(old_locator, delta))
    return error_locator


def rs_find_errors(error_locator: list[int], n: int) -> list[int]:
    errs = len(error_locator) - 1
    positions = []
    for i in range(n):
        if gf_poly_eval(error_locator, gf_pow(2, i)) == 0:
            positions.append(n - 1 - i)
    if len(positions) != errs:
        raise ValueError(
            F'found {len(positions)} error positions but expected {errs}')
    return positions


def rs_correct(
    data: bytes | bytearray | memoryview,
    nsym: int,
) -> bytearray:
    """
    Perform Reed-Solomon error correction on the given data block.
    The last `nsym` bytes of `data` are the EC codewords.
    Returns the corrected data (without EC codewords) as a bytearray.
    """
    output = bytearray(data)
    if nsym <= 0:
        return output
    syndromes = rs_calc_syndromes(output, nsym)
    if max(syndromes) == 0:
        return bytearray(output[:len(output) - nsym])
    error_locator = rs_find_error_locator(syndromes, nsym)
    reversed_locator = error_locator[::-1]
    positions = rs_find_errors(reversed_locator, len(output))
    error_evaluator = gf_poly_mul(syndromes, reversed_locator)[:nsym]
    x_list = [gf_pow(2, len(output) - 1 - p) for p in positions]
    for i, xi in enumerate(x_list):
        xi_inv = gf_div(1, xi)
        error_eval = gf_poly_eval(
            list(reversed(error_evaluator)), xi_inv)
        locator_prime = 1
        for j, xj in enumerate(x_list):
            if j != i:
                locator_prime = gf_mul(
                    locator_prime, 1 ^ gf_mul(xi_inv, xj))
        if locator_prime == 0:
            raise ValueError('could not correct errors')
        magnitude = gf_div(error_eval, locator_prime)
        output[positions[i]] ^= magnitude
    corrected_syndromes = rs_calc_syndromes(output, nsym)
    if max(corrected_syndromes) != 0:
        raise ValueError('error correction failed: residual syndrome')
    return bytearray(output[:len(output) - nsym])
