#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include "opal/pcg.h"


/**
 * Allocates and returns a new pcg32 generator seeded with
 * bytes from /dev/urandom.
 */
pcg32 *pcg32_new(void)
{
    pcg32 *generator = malloc(sizeof(pcg32));
    if (generator == NULL)
    {
        return NULL;
    }
    pcg32_seed(generator, urandom_rand64(), urandom_rand64());
    return generator;
}


/**
 * Frees a generator allocated with pcg32_new().
 */
void pcg32_free(pcg32 *generator)
{
    free(generator);
}


/**
 * @return A random number between [0 and UINT32_MAX].
 */
uint32_t urandom_rand32(void)
{
    uint32_t result = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &result, sizeof result);
    close(fd);
    return result;
}


/**
 * @return A random number between [0 and UINT64_MAX].
 */
uint64_t urandom_rand64(void)
{
    uint64_t result = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &result, sizeof result);
    close(fd);
    return result;
}


/**
 * @return A random number between [0 and UINT32_MAX].
 */
uint32_t pcg32_rand(pcg32 *generator)
{
    uint64_t oldstate = generator->state;
    generator->state = oldstate * 6364136223846793005ULL + generator->inc;
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}


uint64_t pcg32_rand64(pcg32 *generator)
{
    union {
        uint64_t total;
        struct {
            uint32_t front_half;
            uint32_t back_half;
        };
    } value;

    value.front_half = pcg32_rand(generator);
    value.back_half = pcg32_rand(generator);
    return value.total;
}


/**
 * @return A random 32 bit number between [0 and max).
 */
uint32_t pcg32_randbelow(pcg32 *generator, uint32_t max)
{
    if (max == 0)
    {
        return 0;
    }

    uint32_t threshold = -max % max;

    for (;;) {
        uint32_t value = pcg32_rand(generator);
        if (value >= threshold) {
            return value % max;
        }
    }
}


/**
 * @return A random 64 bit number between [0 and max).
 */
uint64_t pcg32_randbelow64(pcg32 *generator, uint64_t max)
{
    if (max == 0)
    {
        return 0;
    }

    uint64_t threshold = -max % max;

    for (;;) {
        uint64_t value = pcg32_rand64(generator);
        if (value >= threshold) {
            return value % max;
        }
    }
}


/**
 * @return A random 32 bit number between [min and max).
 */
uint32_t pcg32_randbetween(pcg32 *generator, uint32_t min, uint32_t max)
{
    return min + pcg32_randbelow(generator, max - min);
}


/**
 * @return A random 64 bit number between [min and max).
 */
uint64_t pcg32_randbetween64(pcg32 *generator, uint64_t min, uint64_t max)
{
    return min + pcg32_randbelow64(generator, max - min);
}


/**
 * @return A random float between [0.0 and 1.0].
 */
float pcg32_randfloat(pcg32 *generator)
{
    return pcg32_rand(generator) / (float)UINT32_MAX;
}


/**
 * @return A random double between [0.0 and 1.0].
 */
double pcg32_randdouble(pcg32 *generator)
{
    return pcg32_rand64(generator) / (double)UINT64_MAX;
}


/**
 * Fill a given buffer with random bytes.
 */
void pcg32_randbytes(pcg32 *generator, void *buffer, size_t bytes)
{
    uint8_t *ptr = buffer;
    while (bytes)
    {
        uint32_t value = pcg32_rand(generator);
        size_t chunk_size = (bytes < sizeof value ? bytes : sizeof value);
        memcpy(ptr, &value, chunk_size);
        bytes -= chunk_size;
        ptr += chunk_size;
    }
}


/**
 * @return True or false at random.
 */
bool pcg32_randbool(pcg32 *generator)
{
    return pcg32_randbelow(generator, 2) != 0;
}


/**
 * Seeds a generator with a given seed and stream id.
 */
void pcg32_seed(pcg32 *generator, uint64_t seed, uint64_t stream)
{
    generator->state = 0U;
    generator->inc = (stream << 1u) | 1u;
    pcg32_rand(generator);
    generator->state += seed;
    pcg32_rand(generator);
}
