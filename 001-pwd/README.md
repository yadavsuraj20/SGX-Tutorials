# A hands-on guide to execution timing attacks

As a warm-up exercise, we will start by explaining the concept of a timing
side-channel by attacking a rudimentary example program. The program compares a
user-provided input against an unknown secret PIN code to decide access.
Your task is to infer the secret PIN code, without modifying any of the code.
For this, you will have to cleverly provide inputs to the program, and
carefully observe the associated execution timings being printed.

## Your task

Try to understand what the passwd program is doing by examining its source code
(`passwd.c`). However, make sure to not yet open the `secret.h` file at this
point, or you'll miss out on all the fun! ;-)

**Note.** This program does not yet require Intel SGX support, but can only be
executed on a (recent) Intel/AMD x86 processor, which is most likely what's in
your laptop (if you don't get any error messages).

### Identifying the timing channel

After running and/or examining the program, you will have noticed that the only
way to get access is to provide the unknown PIN code.  However, besides
printing an "access denied" message, the program also prints a timing
measurement. More specifically, it prints the amount of CPU cycles needed to
execute the `check_pwd` function below (expressed as the median over 100,000
repeated runs):

```C
int check_pwd(char *user, int user_len, char *secret, int secret_len)
{
    int i;

    /* reject if incorrect length */
    if (user_len != secret_len)
        return 0;

    /* reject on first byte mismatch */
    for (i=0; i < user_len; i++)
    {
        if (user[i] != secret[i])
            return 0;
    }

    /* user password passed all the tests */
    return 1;
}
```

**Note.** The above code is somewhat simplified. The real C program includes
additional dummy `delay` function calls to artificially delay the
program, with the purpose of amplifying the timing channel for educational
purposes.

**Do it yourself.** Explain why the execution timings being printed are not not
always exactly the same when repeatedly providing the exact same input.  Why is
it a good idea to print the median instead of the average?

> Execution time non-determinism in modern processors is caused by a wide range
> of microarchitectural optimizations including (instruction+data) caching,
> pipelining, branch prediction, dynamic frequency scaling, etc.  Ultimately, a
> single execution timing measurement may be unreliable, and it's better to
> aggregate over multiple measurements.  **We compute the the median, since a
> single outlier (e.g., due to an operating system context switch or interrupt)
> may strongly affect the average.**

The `check_pwd` function performs the actual password comparison, and only returns
1 if the password string pointed to by the `user` argument
exactly matches a `secret` string. Otherwise a return value of zero is returned.
While this is clearly functionally correct behavior, `check_pwd` does not
always execute the same instructions for every input.

### Exploiting the timing channel

Keep in mind that you only control the `user` and `user_len`
arguments (by providing inputs to the program), while `secret` and `secret_len`
remain fixed unknown values.

**Do it yourself.** Try to come up with a way to iteratively provide inputs and
learn something useful from the associated timings. First infer `secret_len`,
before finally inferring all the `secret` bytes.  You can assume the secret PIN
code uses only numeric digits (0-9).

## Solution and Explanation

As we can clearly see that the function first check if the length is correct of not, and then iteratively checks the password(secret) one-by-one byte.

**Note: There is an additional delay(to help us with good results) after checking the length, and after each character.** This means if our length is correct, or if any additional charater is correct, the program will take more time(due to additional delay) as compared to wrong ones.

So, we should first try passwords like 1, 11, 111, 1111, 11111, ... to check how much time the program takes.
```
Enter super secret password ('q' to exit): 1
time (med clock cycles): 146
Enter super secret password ('q' to exit): 11
time (med clock cycles): 145
Enter super secret password ('q' to exit): 111
time (med clock cycles): 641
Enter super secret password ('q' to exit): 1111
time (med clock cycles): 145
Enter super secret password ('q' to exit): 11111
time (med clock cycles): 147
```

We can clearly see that time taken for length=3 is significantly larger than others, and this means that **the password length is 3**.

Now, we should iteratively try different digits at first place, then at 2nd place, and so on..

```
Enter super secret password ('q' to exit): 111
time (med clock cycles): 639
Enter super secret password ('q' to exit): 211
time (med clock cycles): 654
Enter super secret password ('q' to exit): 311
time (med clock cycles): 655
Enter super secret password ('q' to exit): 411
time (med clock cycles): 639
Enter super secret password ('q' to exit): 511
time (med clock cycles): 1159
Enter super secret password ('q' to exit): 611
time (med clock cycles): 641
```

511 took a large time, which means that **1st digit is 5**.

```
Enter super secret password ('q' to exit): 511
time (med clock cycles): 1142
Enter super secret password ('q' to exit): 521
time (med clock cycles): 1667
Enter super secret password ('q' to exit): 531
time (med clock cycles): 1139
```

521 took a large time, which means that **2nd digit is 2**.

```
Enter super secret password ('q' to exit): 521
time (med clock cycles): 1661
Enter super secret password ('q' to exit): 522
time (med clock cycles): 1664
Enter super secret password ('q' to exit): 523
time (med clock cycles): 1664
Enter super secret password ('q' to exit): 524
time (med clock cycles): 2178
Enter super secret password ('q' to exit): 525
time (med clock cycles): 1674
```

524 took a large time, which means that **3rd digit is 4**.

**Hence, the password(secret) is 524.**