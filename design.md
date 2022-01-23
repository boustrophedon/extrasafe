# Overview

extrasafe starts from a default-deny state and allows you to add groups of filters via the RuleSet trait.

The basic parts are:


- SafetyContext
This is the entry point. You create a SafetyContext, in which you gather rules via RuleSets, which are then used to generate seccomp rules. The seccomp filter is instantiated when `load()` is called, and cannot be removed once loaded. If the SafetyContext is created with `all_threads` instead of `this_thread()`, the `SECCOMP_FILTER_FLAG_TSYNC` attr is set, which synchronizes all threads in the process to have the same seccomp filters.
- RuleSet
A trait that provides a collection of simple and conditional rules. You can think of this as a facet of a security policy, like allowing IO, network, or clock access. There are implementors provided by extrasafe and you can also define your own.
- Rule
A syscall and an optional number of conditions on the syscall's arguments. You can make comparisons on the arguments of the syscall, but the conditions can't dereference pointers so you can't do e.g. string comparisons on file paths.

The comparisons are such that when the comparison returns **true**, the syscall is allowed.

A single Rule may contain multiple conditions, which are anded together by libseccomp, that is, they all must be true for the syscall to be allowed. If multiple rules are loaded, the syscall is allowed if any of the rules allow it.


One thing to note is that libseccomp will silently override conditional rules on a syscall if an unconditional one is added (in the context of extrasafe, where all filters are allow-based). extrasafe catches this and provides an error with the conflicting syscall and the names of the RuleSets that provided the rules.

# What extrasafe actually does

Not really that much: We create a seccomp context that's default-deny (returns EPERM on all syscalls), and then when you call `.enable(RuleSet)` we gather the rules from that ruleset and add them to a list, checking that they don't override each other. Then when you call `.load()` we shove all the rules into seccomp and load the context.

The value provided is mostly via the logical framework of default-deny and grouping syscalls into logical sets so they can be mixed and matched per the needs of your application, so you don't have to learn about how seccomp works. Originally I was going to call the library ez-seccomp. Also I wanted to call it libchristie and its logo would be like a bridge with a stop sign with the tagline "I'm taking syscalls but only on-topic syscalls. No off-topic syscalls. Permission denied. You have been stopped."

# Cross-platform

extrasafe is linux-only, but it's possible to cfg-define the RuleSet trait per-platform and have it work in an entirely different way, defining a new `SafetyContext::enable` for each platform.

I don't really think that's a good idea because it would be too easy to misuse due to different semantics on different platforms.

# Notes on built-in contexts

## The write syscall

It's unfortunate but also kind of a good thing that the write syscall is used to write to both files and sockets.

It means we can't enable writing both to specific files and specific socket, which is good in the sense it encourages us to split out the parts that talk to the network and the parts that do file IO, but unfortunate in that it would be nice if we could just say "only write to these files and sockets and nothing else"

### Sidebar: how sockets work
TODO


