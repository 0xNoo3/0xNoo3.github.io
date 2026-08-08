---
title: Binary Deobfuscation 101 🐍
description: taming real world malware obfuscations
date: 2026-08-08 
categories: [Deobfuscation]
media_subpath: /assets/posts/2026-08-08-taming-obfuscation/
tags: [deobfuscation, symbolic-execution, miasm, virtual machine obfuscation, cff, opaque-predicates, indirect jump, indirect calls]
toc: True
---

# Introduction

When it comes to reverse engineering of real world malware samples, we are not provided with a clean binary which is just one F5 away 😅 . Instead we get somewhat [obfuscated](https://en.wikipedia.org/wiki/Obfuscation_(software)) samples which is a major hinderence in binary analysis/reverse engineering. Well to deal with this, we are left with only one option which is you guessed it right Deobfuscation. So here you will read about most well known obfuscation techniques and how to deal with them using [miasm](https://miasm.re/blog/) a free and open source (GPLv2) reverse engineering framework. As I was learning miasm by reading it [source](https://github.com/cea-sec/miasm/tree/master/miasm) (pain) because it has poorly managed documentation and less examples. Even there official blog is outdated somehow wrtten in 2016-2019. So i saw a perfect opportunity to write about miasm, after all its a great framework.


## Who is this post for?
If you are getting your hands dirty in binary deobfuscation this is for you, as i will go from basic concepts to advance (kind of).
You can read about [Advance Binrary Deobfuscations](https://github.com/malrev/ABD/blob/master/Advanced-Binary-Deobfuscation.pdf) here.
I will discuss the solutions of **ABD** Exercises that I have done from getting started and giving basic overview of miasm
After that we will do deobfuscation of read world malware samples Which included Multiple Obfuscations Such as:
> Opaque predicates, Virtual Machine Based Obfuscation, Indirect Jumps, Indirect Calls and Control Flow Flattening.

For the basic examples i am using [src](https://github.com/malrev/ABD/tree/master/hands-on1) from ABD

## Dead Code Removal

Original Source:
```c
#include <stdio.h>

unsigned int target_function(int n)
{
    int a,b,c,r;

    a = 12;
    b = 56;
    c = 127;

    r = a + b + c + n;

    return r;
}

int main(int argc, char* argv[])
{
    unsigned int n = target_function(argc);

    printf("n=%u\n", n);

    return 0;
}
```

Disassembly:

![](2026-08-08-20-01-37.png)

Here we can clearly see that these three values are added the the function argument.


But even a very simple example, nothing but addition, when obfuscated with ollvm sub pass.
it becomes like this:

![](2026-08-08-20-04-15.png)

It may not seem very complicated but just to give you the idea that simple addition and there are junk code some constants that we didn't even had in our binary and additional instructions which are nothing but junk, if done this iteratively it becomes massive problem.

To deal with this we will perform some [Data Flow Analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) which is a fundamental part of [Compiler Optimizations Techniques](https://en.wikipedia.org/wiki/Optimizing_compiler) by lifting the [x86](https://en.wikipedia.org/wiki/X86) architecture to miasm's [Intermediate Representation](https://en.wikipedia.org/wiki/Intermediate_representation).

```py
file = 'test-add-sub.bin'
addr = 0x1190

# these are miasm inits
loc_db = LocationDB() # for managing locations and addreses 
container = Container.from_stream(open(file, 'rb'), loc_db=loc_db) # Init Binary Container
machine = Machine(container.arch) # architecture-specific toolkit
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db) # disassembly engine
asmcfg = mdis.dis_multiblock(addr) # whole assembly control flow graph 
lifter = machine.lifter_model_call(loc_db=loc_db) # initialization of the lifter 
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg=asmcfg) # lifting x86 asmcfg to miasm's own IR-CFG
```
> These are the initialization stage of miasm (almost) every time we will do this so i might skip later

```py
open('asmcfg.dot', 'w').write(asmcfg.dot()); open('ircfg', 'w').write(ircfg.dot())
```

we can also view the asmcfg and ircfg like this

the asmcfg is similar as you saw as it is x86 assembly

![](2026-08-08-21-32-28.png)

But [Miasm's IR](https://miasm.re/blog/2019/01/16/miasm_ir_getting_higher.html) is a lil complicated you can say:


![](2026-08-08-21-40-09.png)

You will later see in this blog that Hexrays IR also has Explicit semantics for EFLAGS after each computation instruction.This is Because the IR needs to be a complete, self-contained semantic model of the instruction — including side effects so that later analysis (symbolic execution, optimization) is correct without needing hidden/implicit CPU behavior.

So we will do [Dead Removal](https://en.wikipedia.org/wiki/Dead-code_elimination) and [Constant Propagation](https://www.geeksforgeeks.org/compiler-design/constant-propagation-in-complier-design/) using miasm.

```py
deadrm = DeadRemoval(lifter=lifter)  # create dead-code elimination pass for this lifter
entry_points = set([mdis.loc_db.get_offset_location(addr)])  # get LocKey used as CFG entry point
init_infos = lifter.arch.regs.regs_init  # initial symbolic values for all registers

# runs constant propagation over the IR CFG starting from addr with the given initial register state, folding known constant values through expressions.
cst_propag_link = propagate_cst_expr(lifter, ircfg, addr, init_infos)

modified = True
while modified:  # keep optimizing until no more changes occur
    modified = False
    modified |= deadrm.do_dead_removal(ircfg=ircfg)      # remove unused/dead IR assignments
    modified |= remove_empty_assignblks(ircfg)           # remove blocks left empty after dead removal
    modified |= merge_blocks(ircfg, entry_points)         # merge mergeable blocks to simplify CFG


open(f'ircfg_simplified.dot', 'w').write(ircfg.dot()) # constant propagated, clean unobfuscated ir

```
Here is the IRCFG now !

![](2026-08-08-21-55-05.png)

So now on this basic example the dead code is removed and optimized

> Unfortunately Miasm IR is not backword compatible to x86, so we can't just recompile the clean binary, tho it "had" conversion to LLVM IR but this is also broken in latest Miasm versions due to the use of depreciated LLVM-Lite APIs
{:.prompt-info}

The full script can be found [here](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-01_dead_code_elim-py)

## Opaque Predicates

In computer programming, an opaque predicate is a predicate, an expression that evaluates to either "true" or "false", for which the outcome is known by the programmer a priori, but which, for a variety of reasons, still needs to be evaluated at run time.

> from wiki

so its just having multiple Basic Blocks that are never executed because the 
