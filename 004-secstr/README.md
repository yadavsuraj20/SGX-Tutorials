# To lower case: A secure string processing facility

Subtle side-channel vulnerabilities may arise in unexpected places.  In this
exercise we will explore how a seemingly harmless side-channel in one part of
the program, may compromise an unrelated secret in entirely another part of the
program.

## Your task

Consider the following enclave function that securely transforms a provided
input string to lower case characters.

```C
void ecall_to_lowercase(char *s)
{
    int i; char c;

    /* First ensure the _untrusted_ string lies outside the enclave */
    if (!sgx_is_outside_enclave(s, strlen(s)))
        return;

    /* Now transform the string character per character */
    for (i=0; i < strlen(s); i++)
        s[i] = to_lower(s[i]);
}
```

The above program is functionally correct. Go over the program line per line,
can you spot the subtle side-channel vulnerability?

The test enclave provides an `ecall_set_secret` entry point that places a
supposedly secret input value at a specific location `secret_pt` inside the
"enclave" (`victim.c`).  However, since the secret is _never_ explicitly used
inside the enclave, it should not be possible for the attacker to obtain its
value.

**Do it yourself.** Modify the untrusted main function to obtain the secret
value by observing side-effects of the `ecall_to_lowercase` enclave function.

Some guidance notes:

* Modern Intel processors feature a memory page size of 4096 (0x1000) bytes.
* You can make use of the
    [mprotect](http://man7.org/linux/man-pages/man2/mprotect.2.html) library
    function to alter page-granular access rights.
* The provided skeleton program already takes care to redirect any page faults
    to the `fault_handler` function.
* Make sure to test both with an input `s=1` and `s=0` to make sure your attack
    proplerly handles both cases.

### Launching the attack on real SGX hardware

Now you have the proof-of-concept attack working in an _unprotected_
application on your own laptop, proceed to the `../004-sgx-secstr` program
to try and port your attack to a real Intel x86 SGX processor.


## Solution and Explanation
Check `main.c` file for implementation.

After some experiments (and checking the original solution, in this case), I figured out the solution.

If we check the `array` and `secret_pt`, `secret_pt` points to middle element of the `array` and is the last byte on that memory page. The element just after `secret_pt` resides in a different memory page.

Now, the main concept is that if the value stored at `secret_pt` is 0, it means that the string(char*) starting at address `secret_pt` has length 0, as `\0` reperesents the end of string. And if the value is 1, it means that the string has length 1 as the next element is `\0`.

The main vulnerability is the function `strlen(s)`, which accesses the string elements starting at address `s` until it reaches the character `\0`.

So, if we call `ecall_to_lowercase(secret_pt)` with secret value 0, `strlen(secret_pt)` will only access that particular element, but if the secret value is 1, `strlen(secret_pt)` will also access the next element which is on a different page.

So, mark the next page (`page_pt = secret_pt + 1`) as NOT_ACCESSIBLE (`PROT_NONE`) and call `ecall_to_lowercase(secret_pt)`. If the secret value is 0, it will not result in page fault, and if it is 1, it will result in page fault.

We only need to call `strlen(s)` function inside `ecall_to_lowercase`, and that's sufficient for this attack.

**Note:** For better understanding, try the following:
> Mark the page where `secret` is stored (`secret_pt + 1 - 0x1000`) as NOT_ACCESSIBLE and you'll see that it results in a page fault everytime, as we need to access `secret_pt` always to check the string length.

> Instead of `*secret_pt = b`, do `*(secret_pt+1) = b;` and you'll see that it does not result in page fault with both secret values because `secret_pt` is always `\0` and `strlen` will not access next elements.

> You can also print `strlen(s)` and check the answer for both cases.