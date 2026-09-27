from libc.stdint cimport uint8_t, uint64_t
from libc.stdlib cimport realloc


cdef extern from 'Python.h':
    const Py_ssize_t PY_SSIZE_T_MAX


cdef inline int reserve(uint8_t **buf, Py_ssize_t *cap, Py_ssize_t used, uint64_t count) except -1 nogil:
    cdef Py_ssize_t needed, grown
    cdef uint8_t *tmp
    if count > <uint64_t>(PY_SSIZE_T_MAX - used):
        with gil:
            raise MemoryError
    needed = used + <Py_ssize_t>count
    if needed <= cap[0]:
        return 0
    grown = cap[0] * 2 if cap[0] <= PY_SSIZE_T_MAX // 2 else needed
    if grown < needed:
        grown = needed
    tmp = <uint8_t *>realloc(buf[0], <size_t>grown)
    if tmp == NULL:
        with gil:
            raise MemoryError
    buf[0] = tmp
    cap[0] = grown
    return 0
