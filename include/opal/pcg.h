#ifndef _OPAL_PCG_H
#define _OPAL_PCG_H


#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>


typedef struct pcg32 {
    uint64_t state;
    uint64_t inc;
} pcg32;


// URANDOM Functions

/**
 * @return A random number between [0 and UINT32_MAX].
 */
uint32_t urandom_rand32(void);


/**
 * @return A random number between [0 and UINT64_MAX].
 */
uint64_t urandom_rand64(void);


// PCG Functions


/**
 * Allocates and returns a new pcg32 generator seeded with
 * bytes from /dev/urandom.
 */
pcg32 *pcg32_new(void);


/**
 * Frees a generator allocated with pcg32_new().
 */
void pcg32_free(pcg32 *generator);


/**
 * Seeds a generator with a given seed and stream id.
 */
void pcg32_seed(pcg32 *generator, uint64_t seed, uint64_t stream);


/**
 * @return A random number between [0 and UINT32_MAX].
 */
uint32_t pcg32_rand(pcg32 *generator);


/**
 * @return A random number between [0 and UINT64_MAX].
 */
uint64_t pcg32_rand64(pcg32 *generator);


/**
 * @return A random number between [0 and max).
 */
uint32_t pcg32_randbelow(pcg32 *generator, uint32_t max);


/**
 * @return A random number between [min and max).
 */
uint32_t pcg32_randbetween(pcg32 *generator, uint32_t min, uint32_t max);


/**
 * @return A random float between [0.0 and 1.0].
 */
float pcg32_randfloat(pcg32 *generator);


/**
 * @return A random double between [0.0 and 1.0].
 */
double pcg32_randdouble(pcg32 *generator);


/**
 * Fill a given buffer with random bytes.
 */
void pcg32_randbytes(pcg32 *generator, void *buffer, size_t bytes);


/**
 * @return True or false at random.
 */
bool pcg32_randbool(pcg32 *generator);

#endif
