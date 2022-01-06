

# TODO
## Remove all dependencies
If you're using extrasafe to provide extra security, it then becomes a target for vulnerabilities, including supply-chain attacks.

### this-error
Relatively easy to remove: just generate the code from the proc macros and commit it directly to the repository.

### seccomp
This is the hardest part to remove as we'd have to either rewrite the bpf generator, or record the output of libseccomp for our specific use-cases and commit it to the repository. For cases like allowing lists of fds to be read from/written to, we'd have to do some additional work to template the generated bpf code, which is essentially what libseccomp is already doing.

### syscalls
Relatively easy to remove by copying directly into the repository, but comes with a maintenance burden of having to update the lists when new syscalls are created.
