# PIN code verifier: your  first enclave program

## Application overview

The purpose of this application is to develop a first elementary SGX enclave
program that verifies untrusted user input. Particularly, we assume that the
enclave has previously already been securely provisioned with a 4-digit PIN
code and an application-level secret. The enclave's sole job is to enforce
access control on the application secret by querying the untrusted world for
the PIN code, destroying the secret after three successive failed comparison
attempts, or returning it on success.

**Note.** This application only serves demonstration purposes and does not aim
to be a fully tamper-proof security solution. Notable enclave concepts that are
missing include _secure I/O_, _secret provisioning_, _sealing_ for persistent
storage, and _state continuity_ to protect against roll-back attacks.

## Your task

Developing an SGX enclave application roughly falls down in three phases,
outlined below.

### Extending enclave public interface (`Enclave/encl.edl`)

In the enclaved execution paradigm, the programmer splits off a small trusted
application part (the "enclave") that is shielded by the CPU from the remainder
of the application. Since enclaves are designed to operate in an untrusted,
potentially hostile, environment, they should enforce a strict public software
interface. Generally, enclaves can interact with their untrusted environment in
two distinct ways:

- **ECALL:** Function call performed by the untrusted world to enter an
  enclave, passing some arguments and/or expecting a return value.
- **OCALL:** Function call performed by the enclave to call back to the
  untrusted world, passing some arguments and/or expecting a return value.

The Intel SGX SDK features a small domain-specific [Enclave Definition Language
(EDL)](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax)
to unambiguously define the enclave's ECALL/OCALL interaction with the
untrusted world. Pointer arguments should be explicitly marked with `[in]` and
`[out]` attributes to indicate whether they represent input and/or output for
the enclave (in case of an ECALL), or untrusted world (in case of an OCALL).
Based on this description, the SDK automatically generates trusted and
untrusted bridge code that securely transfers control to/from the untrusted
environment.

**Do it yourself.** The PIN code verifier application will feature an ECALL
entry point to try and request the application secret by verifying an untrusted
PIN code from the end user. You will thus have to:

- Extend `Enclave/encl.edl` with a trusted `ecall_get_secret` ECALL entry point
  that takes an `int*` and a `char*` pointer arguments and returns an `int`,
  indicating whether or not PIN code verification succeeded and the application
  secret was written to the pointer argument.

### Extending enclave implementation (`Enclave/encl.c`)

After defining the enclave's interface, you will have to implement the required
ECALL functionality. Implement the `int ecall_get_secret(int *secret_pt)`
function by making use of the `int ocall_get_pin(char *)` untrusted helper
function. Take care to ensure that:

- The enclave only writes `super_secret_constant` to `secret_pt` when the
  untrusted user-provided PIN code exactly matches `SECRET_PIN` of length
  `SECRET_LEN`.

### Extending untrusted runtime (`main.c`)

Finally, after finishing the trusted enclave's implementation, you have to
extend the untrusted runtime support system. We already provided the enclave
creation code, `ocall_get_pin` function, and an example `ecall_dummy()` enclave
function call. Now, add the `ecall_get_secret()` enclave function call, and
print out the return value and secret returned by the trusted enclave.

## Building and running

Simply execute:

```bash
$ make run
```

**Explain.** Do you succeed in reproducing the timing side-channel attack of
the untrusted program in an enclave setting. Explain why (not)? What does this
tell you about the _signal-to-noise_ ratio for timing enclave programs? 

## Solution and Explanation
For code implementation, check the respective files.

**Note:** If you get an error `make[1]: sgx_edger8r: Command not found`, source the sgx environment path(`source /opt/intel/sgxsdk/environment`).

After running the program for different inputs, we observe that the time values are not good enough to differentiate between correct and incorrect lengths. The program takes almost similar time for all the inputs.

This means that the external factors are dominant in this case as compared to the actual password checking algorithm.

**Ex.** If the SECRET_PIN is "592" (SECRET_LEN=3)
```
Enter super secret password ('q' to exit): 1
Return value: 0, Secret: 0x0
time (med clock cycles): 102039
Enter super secret password ('q' to exit): 11
Return value: 0, Secret: 0x0
time (med clock cycles): 112304
Enter super secret password ('q' to exit): 111
Return value: 0, Secret: 0x0
time (med clock cycles): 102104
Enter super secret password ('q' to exit): 1111
Return value: 0, Secret: 0x0
time (med clock cycles): 101955
Enter super secret password ('q' to exit): 11111
Return value: 0, Secret: 0x0
time (med clock cycles): 102580
```

In fact, we can sometimes see very different results for the same inputs. These may be due to context switches, AEXs and other factors.
```
Enter super secret password ('q' to exit): 11111
Return value: 0, Secret: 0x0
time (med clock cycles): 54520
```

For the correct pwd input, we can see that the return value is 1 and the secret is written correctly.
```
Enter super secret password ('q' to exit): 592
Return value: 1, Secret: 0xdeadbeef
time (med clock cycles): 113304
```

**Final Results:** We are **NOT** able to perform the timing side-channel attack in the enclave setting.

This means that the **_signal-to-noise_ ratio is very low** due to large noise.