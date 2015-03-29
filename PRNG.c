#include <openssl/rand.h>
#include <stdio.h>

int RAND_load_file(const char * filename, long bytes);
int RAND_write_file(const char * filename);

int main(void) {
    printf("start\n");
    // read 1024 bytes from /dev/random and seed the PRNG with it
    RAND_load_file("/dev/urandom", 1024);
    printf("loaded\n");

    // write a seed file
    RAND_write_file("prngseed.dat");
    printf("written\n");

    // read the seed file in its entirety and print the number of bytes
    int nb = RAND_load_file("prngseed.dat", -1);
    printf("Seeded the PRNG with %d byte(s) of data from prngseed.dat.\n", nb);
    
    return 0;
}