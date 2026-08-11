---
title: Binary Deobfuscation 101 🐍
description: Taming real world malware obfuscations
date: 2026-08-11 
categories: [Deobfuscation]
media_subpath: /assets/posts/2026-08-08-taming-obfuscation/
tags: [deobfuscation, symbolic execution, miasm, virtual machine obfuscation, cff, opaque-predicates, indirect jump, indirect calls]
toc: True
---

# Introduction

When it comes to reverse engineering of real world malware samples, we are not provided with a clean binary which is just one F5 away 😅 . Instead we get somewhat [obfuscated](https://en.wikipedia.org/wiki/Obfuscation_(software)) samples which is a major hinderence in binary analysis/reverse engineering. Well to deal with this, we are left with only one option which is you guessed it right Deobfuscation. So here you will read about most well known obfuscation techniques and how to deal with them using [miasm](https://miasm.re/blog/) a free and open source (GPLv2) reverse engineering framework. As I was learning miasm by reading it [source](https://github.com/cea-sec/miasm/tree/master/miasm) (pain) because it has poorly managed documentation and less examples. Even there official blog is outdated somehow wrtten in 2016-2019. So i saw a perfect opportunity to write about miasm, after all its a great framework.


## Who is this post for?
If you are getting your hands dirty in binary deobfuscation this is for you, as i will go from basic concepts to advance (kind of).
You can read about [Advance Binrary Deobfuscations](https://github.com/malrev/ABD/blob/master/Advanced-Binary-Deobfuscation.pdf).
I will discuss the solutions of **ABD** Exercises that I have done from getting started and giving basic overview of miasm
After that we will do deobfuscation of real world malware samples Which included Multiple Obfuscations Such as:
> Opaque predicates, Virtual Machine Based Obfuscation, Indirect Jumps, Indirect Calls and Control Flow Flattening.

For the basic examples i am using [src](https://github.com/malrev/ABD/tree/master/hands-on1) from ABD

> These will be simple dummy examples so you can skip to malware obfuscation if you are well aware of the basics
{:.prompt-info}

![](2026-08-08-22-31-24.png)

Because of this fact i cannot pick a single source so the source will be changing during basic deobfuscation examples :p

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

### Data Flow Analysis & Constant Propagation
To deal with this we will perform some [Data Flow Analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) which is a fundamental part of [Compiler Optimizations Techniques](https://en.wikipedia.org/wiki/Optimizing_compiler) by lifting the [x86](https://en.wikipedia.org/wiki/X86) architecture to miasm's [Intermediate Representation](https://en.wikipedia.org/wiki/Intermediate_representation).

```py
# these are miasm inits
loc_db = LocationDB() # for managing locations and addreses 
container = Container.from_stream(open(file, 'rb'), loc_db=loc_db) # Init Binary Container
machine = Machine(container.arch) # architecture-specific toolkit
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db) # disassembly engine
asmcfg = mdis.dis_multiblock(addr) # whole assembly control flow graph of the target address
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

so its just having multiple Basic Blocks that are never executed, Which results in increase number of basic blocks and function sizes are increased. 

![](2026-08-08-22-13-42.png)
_Classic Opaque Predicates_

i never thought of deobfuscating hello world lol. We are choosing this example now because it has ollvm bcf.

Source:
```c
#include <stdio.h>

void target_function(void)
{
    char* msg = "hello world";
    printf("%s\n", msg);
}

int main(int argc, char* argv[])
{
    target_function();
    return 0;
}
```

Disassembly:

![](2026-08-08-22-37-48.png)

Well a hello world can't have those many basic blocks 😂 

### General Heuristic to deal with Opaque Predicates

we will execute each basic block via [Symbolic Execution](https://en.wikipedia.org/wiki/Symbolic_execution) and check if the result is an Condition then, if it is we will convert the miasm expression to [z3](https://en.wikipedia.org/wiki/Z3_Theorem_Prover) IR. and check is anyof the branch from the condition is unsat, If it is then we know that it is an opaque branch and thus will never be executed.

```py
# here 'l' is the branch 1 and the 'r' is the branch 2 of the basic block possible condition
def is_opaque(l, r): 
    s = z3.Solver()
    t = TranslatorZ3() # converting miasm expression to z3 IR
    s.add(t.from_expr(l) == t.from_expr(r)) # adding to the z3 solver
    return s.check() == z3.unsat # returns true if unsat/opaque branch
```

Iterating though each basic block in the asmcfg and execute it symbolically.

```py 
[...]
for bb in asmcfg.blocks:
    # init sybolic execution 
    sb = SymbolicExecutionEngine(lifter=lifter) 
    # symbolic execution of bb
    r = sb.run_block_at(ircfg=ircfg, addr=bb.lines[0].offset) 
    if not isinstance(r, ExprCond): 
        continue
    vaddr = bb.lines[-1].offset 
    # cond? jump: fall
    jcc = is_opaque(r, r.src1); fall = is_opaque(r, r.src2)
    # print('jcc ', jcc, 'fall ', fall) # debug
    if jcc: # jcc is opaque so it won't jmp
        # patch the jcc with nops, so it just falls
        print('Patched NOP: ', hex(vaddr)) # not hitting in this example
    elif fall: # fall is opaque so it won't fall 
        # convert jcc to jmp
        print('Replace jcc', hex(vaddr))
    else:
        print(f'Skip valid conditional at: {hex(offset)}')
```

patching to nop is very trivial, just see the jcc size and patch to *b'\x90' * instruction_size*. But patching jcc to jmp we have to take care of the relative address. in this example the jcc are 6 bytes as they are rel32 jumps you check more on [x86 conditional jumps](https://www.felixcloutier.com/x86/jcc) 

So in this case we will read 4 bytes (skipping the 2 jcc default bytes) and because the formula is *rel32 = address to jump - (address of jmp instruction + instruction_size)* as the jcc was 6 bytes so reading and +1 becomes the new-rel32.

```py
    # helper functions
    p32 = lambda d: struct.pack('<I', d)
    u32 = lambda d, i: struct.unpack('<I', d[i:i+4])[0]
    [...]
    elif fall: # fall is opaque so it won't fall 
        # replace with direct jump
        print('Replace jcc', hex(vaddr)) # debug
        new_rel32 = u32(binary, offset+2) + 1 # read 4 bytes of rel & as jmp has 1 less byte size than jcc +1 so new_rel = oldrel + 1
        binary[offset: offset + 6] = b'\xE9' + p32(new_rel32) + b'\x90'
```

The Whole script is can be found [here](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-02_remove_opaque_predicates-py)


## Stack VM

Its a simple stack VM. This example will is VM Obfuscation with [Tigress](https://tigress.wtf/)
And by this you will see how a very simple example becomes when VM obfuscation is applied to it.

Source:
```c
#include <stdio.h>

int target_function(int n)
{
    int a, b;

    a = 0xdeadbeef;
    b = 0x8badf00d;

    int c = a + b;
    int d = a - b;
    int e = c + d + n;

    if(e % 2 == 0){
        return 0;
    }else{
        return 1;
    }
}

int main(int argc, char* argv[])
{
  int n = target_function(argc);
  printf("n=%d\n", n);
  return n;
}
```

After obfuscation:

```c
/* Generated by CIL v. 1.7.0 */
/* print_CIL_Input is false */

union _1_target_function_$node;
struct _IO_FILE;
enum _1_target_function_$op;
struct timeval;
extern int gettimeofday(struct timeval *tv , void *tz ) ;
extern int pthread_cond_broadcast(int *cond ) ;
char **_global_argv  =    (char **)0;
extern int posix_memalign(void **memptr , unsigned long alignment , unsigned long size ) ;
extern int getpagesize() ;
extern int pthread_join(void *thread , void **value_ptr ) ;
extern unsigned long strlen(char const   *s ) ;
extern int open(char const   *filename , int oflag  , ...) ;
extern int pthread_barrier_destroy(int *barrier ) ;
extern int pthread_mutex_init(int *mutex , int *attr ) ;
extern int strncmp(char const   *s1 , char const   *s2 , unsigned long maxlen ) ;
extern int printf(char const   * __restrict  __format  , ...) ;
int _global_argc  =    0;
extern int pthread_cond_signal(int *cond ) ;
extern int pthread_barrier_init(int *barrier , int *attr , unsigned int count ) ;
extern int raise(int sig ) ;
extern int scanf(char const   *format  , ...) ;
char **_global_envp  =    (char **)0;
extern int unlink(char const   *filename ) ;
extern double difftime(long tv1 , long tv0 ) ;
extern int pthread_barrier_wait(int *barrier ) ;
extern int pthread_mutex_lock(int *mutex ) ;
extern void *memcpy(void *s1 , void const   *s2 , unsigned long size ) ;
extern int gethostname(char *name , unsigned long namelen ) ;
extern void *dlsym(void *handle , char *symbol ) ;
char const   *_1_target_function_$strings  =    "";
extern void abort() ;
extern unsigned long strtoul(char const   *str , char const   *endptr , int base ) ;
extern void free(void *ptr ) ;
extern int fprintf(struct _IO_FILE *stream , char const   *format  , ...) ;
int main(int argc , char **argv , char **_formal_envp ) ;
extern void exit(int status ) ;
extern void signal(int sig , void *func ) ;
typedef struct _IO_FILE FILE;
extern int mprotect(void *addr , unsigned long len , int prot ) ;
extern int close(int filedes ) ;
extern double strtod(char const   *str , char const   *endptr ) ;
extern double log(double x ) ;
extern double ceil(double x ) ;
union _1_target_function_$node {
   char _char ;
   unsigned int _unsigned_int ;
   unsigned char _unsigned_char ;
   long _long ;
   unsigned long _unsigned_long ;
   void *_void_star ;
   unsigned short _unsigned_short ;
   unsigned long long _unsigned_long_long ;
   signed char _signed_char ;
   long long _long_long ;
   int _int ;
   short _short ;
};
extern int fclose(void *stream ) ;
extern int fcntl(int filedes , int cmd  , ...) ;
enum _1_target_function_$op {
    _1_target_function__return_int$expr_STA_0 = 11,
    _1_target_function__local$result_STA_0$value_LIT_0 = 181,
    _1_target_function__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1 = 242,
    _1_target_function__store_int$right_STA_0$left_STA_1 = 161,
    _1_target_function__constant_int$result_STA_0$value_LIT_0 = 175,
    _1_target_function__load_int$left_STA_0$result_STA_0 = 254,
    _1_target_function__formal$result_STA_0$value_LIT_0 = 32,
    _1_target_function__goto$label_LAB_0 = 9,
    _1_target_function__Mod_int_int2int$left_STA_0$result_STA_0$right_STA_1 = 184,
    _1_target_function__MinusA_int_int2int$left_STA_0$result_STA_0$right_STA_1 = 150,
    _1_target_function__Eq_int_int2int$left_STA_0$result_STA_0$right_STA_1 = 194,
    _1_target_function__branchIfTrue$expr_STA_0$label_LAB_0 = 42
} ;
unsigned char _1_target_function_$array[1][168]  = { {        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)4,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__constant_int$result_STA_0$value_LIT_0,        (unsigned char)239,        (unsigned char)190, 
            (unsigned char)173,        (unsigned char)222,        _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__local$result_STA_0$value_LIT_0, 
            (unsigned char)8,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__constant_int$result_STA_0$value_LIT_0,        (unsigned char)13,        (unsigned char)240,        (unsigned char)173, 
            (unsigned char)139,        _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)12, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0, 
            (unsigned char)4,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)8,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1, 
            _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)16,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)8, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0, 
            _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)4,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__MinusA_int_int2int$left_STA_0$result_STA_0$right_STA_1,        _1_target_function__store_int$right_STA_0$left_STA_1, 
            _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)20,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)12,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__local$result_STA_0$value_LIT_0, 
            (unsigned char)16,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1,        _1_target_function__formal$result_STA_0$value_LIT_0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0, 
            _1_target_function__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1,        _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__goto$label_LAB_0,        (unsigned char)4, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__constant_int$result_STA_0$value_LIT_0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__constant_int$result_STA_0$value_LIT_0,        (unsigned char)2,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)20,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__Mod_int_int2int$left_STA_0$result_STA_0$right_STA_1, 
            _1_target_function__Eq_int_int2int$left_STA_0$result_STA_0$right_STA_1,        _1_target_function__branchIfTrue$expr_STA_0$label_LAB_0,        (unsigned char)9,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__goto$label_LAB_0,        (unsigned char)25, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0, 
            (unsigned char)24,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__constant_int$result_STA_0$value_LIT_0,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__goto$label_LAB_0,        (unsigned char)4, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_target_function__goto$label_LAB_0, 
            (unsigned char)25,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__constant_int$result_STA_0$value_LIT_0,        (unsigned char)1,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__store_int$right_STA_0$left_STA_1,        _1_target_function__goto$label_LAB_0, 
            (unsigned char)4,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_target_function__goto$label_LAB_0,        (unsigned char)4,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_target_function__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_target_function__load_int$left_STA_0$result_STA_0,        _1_target_function__return_int$expr_STA_0}};
int target_function(int n ) ;
extern int pthread_cond_wait(int *cond , int *mutex ) ;
extern void perror(char const   *str ) ;
extern int pthread_cond_init(int *cond , int *attr ) ;
extern long write(int filedes , void *buf , unsigned long nbyte ) ;
extern int ptrace(int request , void *pid , void *addr , int data ) ;
extern float strtof(char const   *str , char const   *endptr ) ;
extern unsigned long strnlen(char const   *s , unsigned long maxlen ) ;
struct timeval {
   long tv_sec ;
   int tv_usec ;
};
extern void qsort(void *base , unsigned long nel , unsigned long width , int (*compar)(void *a ,
                                                                                       void *b ) ) ;
extern long clock(void) ;
extern long time(long *tloc ) ;
extern long read(int filedes , void *buf , unsigned long nbyte ) ;
extern int rand() ;
extern int strcmp(char const   *a , char const   *b ) ;
extern void *fopen(char const   *filename , char const   *mode ) ;
extern double sqrt(double x ) ;
extern long strtol(char const   *str , char const   *endptr , int base ) ;
extern int snprintf(char *str , unsigned long size , char const   *format  , ...) ;
extern void *malloc(unsigned long size ) ;
extern int nanosleep(int *rqtp , int *rmtp ) ;
extern int pthread_mutex_unlock(int *mutex ) ;
extern int atoi(char const   *s ) ;
extern int pthread_create(void *thread , void *attr , void *start_routine , void *arg ) ;
extern int fscanf(struct _IO_FILE *stream , char const   *format  , ...) ;
extern int fseek(struct _IO_FILE *stream , long offs , int whence ) ;
void megaInit(void) ;
void megaInit(void) 
{ 


  {

}
}
int main(int argc , char **argv , char **_formal_envp ) 
{ 
  int n ;
  int tmp ;
  int _BARRIER_0 ;

  {
  megaInit();
  _global_argc = argc;
  _global_argv = argv;
  _global_envp = _formal_envp;
  _BARRIER_0 = 1;
  tmp = target_function(argc);
  n = tmp;
  printf((char const   */* __restrict  */)"n=%d\n", n);
  return (n);
}
}
int target_function(int n ) 
{ 
  char _1_target_function_$locals[28] ;
  union _1_target_function_$node _1_target_function_$stack[1][32] ;
  union _1_target_function_$node *_1_target_function_$sp[1] ;
  unsigned char *_1_target_function_$pc[1] ;

  {
  _1_target_function_$sp[0] = _1_target_function_$stack[0];
  _1_target_function_$pc[0] = _1_target_function_$array[0];
  while (1) {
    switch (*(_1_target_function_$pc[0])) {
    case _1_target_function__Mod_int_int2int$left_STA_0$result_STA_0$right_STA_1: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + -1)->_int = (_1_target_function_$sp[0] + 0)->_int % (_1_target_function_$sp[0] + -1)->_int;
    (_1_target_function_$sp[0]) --;
    break;
    case _1_target_function__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + -1)->_int = (_1_target_function_$sp[0] + -1)->_int + (_1_target_function_$sp[0] + 0)->_int;
    (_1_target_function_$sp[0]) --;
    break;
    case _1_target_function__load_int$left_STA_0$result_STA_0: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + 0)->_int = *((int *)(_1_target_function_$sp[0] + 0)->_void_star);
    break;
    case _1_target_function__return_int$expr_STA_0: 
    (_1_target_function_$pc[0]) ++;
    return ((_1_target_function_$sp[0] + 0)->_int);
    break;
    case _1_target_function__local$result_STA_0$value_LIT_0: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + 1)->_void_star = (void *)(_1_target_function_$locals + *((int *)_1_target_function_$pc[0]));
    (_1_target_function_$sp[0]) ++;
    _1_target_function_$pc[0] += 4;
    break;
    case _1_target_function__formal$result_STA_0$value_LIT_0: 
    (_1_target_function_$pc[0]) ++;
    switch (*((int *)_1_target_function_$pc[0])) {
    case 0: 
    (_1_target_function_$sp[0] + 1)->_void_star = (void *)(& n);
    break;
    }
    (_1_target_function_$sp[0]) ++;
    _1_target_function_$pc[0] += 4;
    break;
    case _1_target_function__Eq_int_int2int$left_STA_0$result_STA_0$right_STA_1: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + -1)->_int = (_1_target_function_$sp[0] + 0)->_int == (_1_target_function_$sp[0] + -1)->_int;
    (_1_target_function_$sp[0]) --;
    break;
    case _1_target_function__MinusA_int_int2int$left_STA_0$result_STA_0$right_STA_1: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + -1)->_int = (_1_target_function_$sp[0] + 0)->_int - (_1_target_function_$sp[0] + -1)->_int;
    (_1_target_function_$sp[0]) --;
    break;
    case _1_target_function__constant_int$result_STA_0$value_LIT_0: 
    (_1_target_function_$pc[0]) ++;
    (_1_target_function_$sp[0] + 1)->_int = *((int *)_1_target_function_$pc[0]);
    (_1_target_function_$sp[0]) ++;
    _1_target_function_$pc[0] += 4;
    break;
    case _1_target_function__goto$label_LAB_0: 
    (_1_target_function_$pc[0]) ++;
    _1_target_function_$pc[0] += *((int *)_1_target_function_$pc[0]);
    break;
    case _1_target_function__store_int$right_STA_0$left_STA_1: 
    (_1_target_function_$pc[0]) ++;
    *((int *)(_1_target_function_$sp[0] + -1)->_void_star) = (_1_target_function_$sp[0] + 0)->_int;
    _1_target_function_$sp[0] += -2;
    break;
    case _1_target_function__branchIfTrue$expr_STA_0$label_LAB_0: 
    (_1_target_function_$pc[0]) ++;
    if ((_1_target_function_$sp[0] + 0)->_int) {
      _1_target_function_$pc[0] += *((int *)_1_target_function_$pc[0]);
    } else {
      _1_target_function_$pc[0] += 4;
    }
    (_1_target_function_$sp[0]) --;
    break;
    }
  }
}
}
```

So now we are starting to deal with something interesting, Opening it to IDA:

![](2026-08-09-00-25-09.png)
_VM Function_

![](2026-08-09-01-24-42.png)
_VM Bytecode_

IDA decompilation results:

![](2026-08-09-00-27-32.png)

### VM Tracing

Our first step is to make a working Symbolic Execution Engine which traces the vm with concerete bytecode values. for that we can insert the vm bytecode into the sybolic execution symbols dictonary.

```py
[...]
def read_bytecode():
    # here i have embedded the address of the bytecode and its size
    bytecode_addr = 0x804A060; sz = 0x804A107 - 0x804A060 + 1 # is 0xA8
    sym_bytecode_addr = ExprMem(ExprInt(bytecode_addr, 32), sz * 8) # symbolic memory
    byte_code = container.bin_stream.getbytes(bytecode_addr, sz) # bytecode from the file
    sym_bytecode = ExprInt(int.from_bytes(byte_code, byteorder='little'), sz * 8)
    return sym_bytecode_addr, sym_bytecode

sb = SymbolicExecutionEngine(lifter=lifter)
sym_bytecode_addr, sym_bytecode = read_bytecode()
sb.symbols[sym_bytecode_addr] = sym_bytecode # fixed the bytecode in the symbolic symbols
[...]
```

when ever Symbolic execution is performed than bytecode will be treated as concerete value instead of symbolic.

```py
[...]

sb.run_block_at(ircfg=ircfg, addr=vm_entry) # initialized all the stack varible etc


q = deque([ExprInt(vm_dispatcher, 32)])
while q:
    bb = q.popleft()
    # print(f'current: {block}')
    r = sb.run_block_at(ircfg=ircfg, addr=bb)
    print(r)
    if r.is_loc() or r.is_int():
        q.append(r)
```

After some tracing it stopped !
```
[...]
0x804856C
0x804858E
0x8048595
0x80485A0
0x8048724
0x80488A8
0x8048509
0x8048520
0x8048527
0x8048530
0x804854C
0x8048856
smod((@32[ESP + 0x4] + 0xBD5B7DDE)[31:32]?({@32[ESP + 0x4] + 0xBD5B7DDE 0 32, 0xFFFFFFFF 32 64},{@32[ESP + 0x4] + 0xBD5B7DDE 0 32, 0x0 32 64}), 0x2)[0:32]?(0x8048889,0x8048871)
```

The last basic block was 0x8048856 so we analyze that and see why the next didn't resolved.

![](2026-08-09-01-42-25.png)

We can see that it reads an address from the virtual stack pointer and dereference it and check if its zero or not, so it takes a path depending on the vstack_ptr. if we look at the miasm expression condition **@32[ESP + 0x4] + 0xBD5B7DDE)[31:32]?** [ESP + 0x4] is a symbolic value which we haven't defined in the symbolic execution symbols dictonary.


the arg variable is [EBP-0x8] which is basically [ESP + 0x4] its the function argument. So we just have to make the function argument concerete.

```py
# initiallizing before running the symbolic exectution of vm entry
sb.symbols[ExprId('ESP', 32)] = ExprInt(0x1000, 32) # arbitrary address 

arg = ExprMem(expr_simp(sb.symbols[ExprId('ESP', 32)] + ExprInt(4, 32)), 32) # the stack address where the argument resides
sb.symbols[arg] = ExprInt(0, 32) # set concrete value for arg

sb.run_block_at(ircfg=ircfg, addr=vm_entry) 
[...]
```

```
[...]
0x80488A8
0x8048509
0x8048520
0x8048527
0x8048530
0x8048535
0x804853E
0x804865F
0x80488B2
@32[0x1000]
```

Thats it, as it was a simple vm our tracer is complete :)

```py
# tracer
file = 'test-mod2-add-virtualized.bin'
addr = 0x80484DE

loc_db = LocationDB()
container = Container.from_stream(open(file, 'rb'), loc_db=loc_db)
machine = Machine(container.arch)
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
lifter = machine.lifter_model_call(loc_db=loc_db)
sb = SymbolicExecutionEngine(lifter=lifter)
asmcfg = mdis.dis_multiblock(addr)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg=asmcfg)
vm_entry = addr; vm_dispatcher = 0x8048509

def read_bytecode():
    bytecode_addr = 0x804A060; sz = 0x804A107 - 0x804A060 + 1 
    sym_bytecode_addr = ExprMem(ExprInt(bytecode_addr, 32), sz * 8) # symbolic memory
    byte_code = container.bin_stream.getbytes(bytecode_addr, sz) # bytecode from the file
    sym_bytecode = ExprInt(int.from_bytes(byte_code, byteorder='little'), sz * 8)
    return sym_bytecode_addr, sym_bytecode

sym_bytecode_addr, sym_bytecode = read_bytecode()
sb.symbols[sym_bytecode_addr] = sym_bytecode # fixed the bytecode in the symbolic symbols

sb.symbols[ExprId('ESP', 32)] = ExprInt(0x1000, 32)

arg = ExprMem(expr_simp(sb.symbols[ExprId('ESP', 32)] + ExprInt(4, 32)), 32)
sb.symbols[arg] = ExprInt(0, 32) # set concrete value for arg

sb.run_block_at(ircfg=ircfg, addr=vm_entry) 

q = deque([ExprInt(vm_dispatcher, 32)])
while q:
    bb = q.popleft()
    # print(f'current: {block}')
    r = sb.run_block_at(ircfg=ircfg, addr=bb)
    print(r)
    if r.is_loc() or r.is_int():
        q.append(r)

```

### VM Disassembler
When the tracer is ready, We are ready to write a disassembler. As its just a simple VM its handlers are only 1 liner, so you can just analyze it in 5 mins, because to write a full disasembler of this VM we do need to understand the handlers semantics a little bit so we can add information in our disassembler the symbolic execution just helps us to avoid writing each handler semantic implementation but still we should know what each handler.

```c
// Short manaual analysis of the simple stack base vm, i have renamed variables and commented what handler does
int __cdecl vm(char arg)
{
  int vip; // eax
  _DWORD *vstack_ptr; // [esp+8h] [ebp-130h]
  char *vbytecode; // [esp+Ch] [ebp-12Ch]
  _BYTE vstack[284]; // [esp+10h] [ebp-128h] BYREF
  unsigned int canary; // [esp+12Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  vstack_ptr = vstack;
  vbytecode = ::vbytecode;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              vip = (unsigned __int8)*vbytecode;
              if ( vip != 0xA1 )
                break;
              ++vbytecode;
              *(_DWORD *)vstack_ptr[-2u] = *vstack_ptr;// store
              vstack_ptr -= 4;
            }
            if ( (unsigned __int8)*vbytecode <= 0xA1u )
              break;
            if ( vip == 0xB8 )
            {
              ++vbytecode;
              *(vstack_ptr - 2) = *vstack_ptr % *(vstack_ptr - 2);// mod and load
              vstack_ptr -= 2;
            }
            else if ( (unsigned __int8)*vbytecode > 0xB8u )
            {
              switch ( vip )
              {
                case 0xF2:
                  ++vbytecode;
                  *(vstack_ptr - 2) += *vstack_ptr;// add
                  vstack_ptr -= 2;
                  break;
                case 0xFE:
                  ++vbytecode;
                  *vstack_ptr = *(_DWORD *)*vstack_ptr;// store
                  break;
                case 0xC2:
                  ++vbytecode;
                  *(vstack_ptr - 2) = *vstack_ptr == *(vstack_ptr - 2);// sete
                  vstack_ptr -= 2;
                  break;
              }
            }
            else if ( vip == 0xAF )
            {
              vstack_ptr[2] = *(_DWORD *)++vbytecode;// push imm
              vstack_ptr += 2;
              vbytecode += 4;
            }
            else if ( vip == 0xB5 )
            {
              vstack_ptr[2] = &vstack[*(_DWORD *)++vbytecode + 0x100];// mov vtack, [mem]
              vstack_ptr += 2;
              vbytecode += 4;
            }
          }
          if ( vip != 0x20 )
            break;
          if ( !*(_DWORD *)++vbytecode )
            vstack_ptr[2] = &arg;               // mov stack, value (load)
          vstack_ptr += 2;
          vbytecode += 4;
        }
        if ( (unsigned __int8)*vbytecode <= 0x20u )
          break;
        if ( vip == 0x2A )
        {
          ++vbytecode;
          if ( *vstack_ptr )                    // jnz
            vbytecode += *(_DWORD *)vbytecode;
          else
            vbytecode += 4;
          vstack_ptr -= 2;
        }
        else if ( vip == 0x96 )
        {
          ++vbytecode;
          *(vstack_ptr - 2) = *vstack_ptr - *(vstack_ptr - 2);// sub
          vstack_ptr -= 2;
        }
      }
      if ( vip != 9 )
        break;
      ++vbytecode;
      vbytecode += *(_DWORD *)vbytecode;        // jmp
    }
  }
  while ( vip != 0xB );
  ++vbytecode;
  return *vstack_ptr;
}
```

So we will just now symbolically execute the vm and check after each block that if this address is one of the vm handlers, and if it is, we will print the what ever the semantics of that handler are, and thats how we get out vm disassembler.

```py
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.analysis.simplifier import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprMem, ExprInt, ExprId
from collections import deque

file = 'test-mod2-add-virtualized.bin'
addr = 0x80484DE

loc_db = LocationDB()
container = Container.from_stream(open(file, 'rb'), loc_db=loc_db)
machine = Machine(container.arch)
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
lifter = machine.lifter_model_call(loc_db=loc_db)
sb = SymbolicExecutionEngine(lifter=lifter)
asmcfg = mdis.dis_multiblock(addr)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg=asmcfg)
vm_entry = addr; vm_dispatcher = 0x8048509

def read_bytecode():
    bytecode_addr = 0x804A060; sz = 0x804A107 - 0x804A060 + 1 # is 0xA8
    sym_bytecode_addr = ExprMem(ExprInt(bytecode_addr, 32), sz * 8) # symbolic memory
    byte_code = container.bin_stream.getbytes(bytecode_addr, sz) # bytecode from the file
    sym_bytecode = ExprInt(int.from_bytes(byte_code, byteorder='little'), sz * 8)
    return sym_bytecode_addr, sym_bytecode

def resolve_addr(r):
    if r.is_int():
        return int(r)
    if r.is_loc():
        return loc_db.get_location_offset(r.loc_key)
    return None

HANDLERS = {
    0x8048821: 'STORE',
    0x80485B0: 'MOD',
    0x80485F6: 'ADD',
    0x8048639: 'DEREF',
    0x8048724: 'SETE',
    0x80487B2: 'PUSH',
    0x804868B: 'LOAD, [MEM]',
    0x80486D7: 'LOAD INPUT',
    0x8048856: 'JNZ',
    0x804876D: 'SUB',
    0x80487F7: 'JMP',
    0x804865F: 'HALT'
}

# the disassembler (this vm is so simple that we don't need miasm, but to give you the idea that all the internals of vm like pushing/popping stack values are all done by miasm)
def disassemble(sb, r, vstack, vstack_addr, vip):
    global EBP
    mnem = HANDLERS[r]
    # always expr_simp the address before building the ExprMem key
    mem = lambda addr:expr_simp(sb.eval_expr(ExprMem(expr_simp(addr), 32)))

    tos    = vstack                             # @32[P]      top of vstack
    second = mem(vstack_addr - ExprInt(8, 32))  # @32[P - 8]  next slot down
    imm    = mem(vip + ExprInt(1, 32))          # imm32 of the 5-byte opcodes

    if mnem == 'STORE':          # *(vstack[-2]) = vstack[0]; vsp -= 4 dwords
        print(f'{vip}  {mnem} [{second}] = {tos}')
    elif mnem == 'MOD':          # vstack[-2] = vstack[0] % vstack[-2]; vsp -= 2
        print(f'{vip}  {mnem}   {tos} % {second}')
    elif mnem == 'ADD':          # vstack[-2] += vstack[0]; vsp -= 2
        print(f'{vip}  {mnem}   {second}, {tos}')
    elif mnem == 'SUB':          # vstack[-2] = vstack[0] - vstack[-2]; vsp -= 2
        print(f'{vip}  {mnem}   {tos} - {second}')
    elif mnem == 'SETE':         # vstack[-2] = (vstack[0] == vstack[-2]); vsp -= 2
        print(f'{vip}  {mnem}  {tos} == {second}')
    elif mnem == 'DEREF':          # vstack[0] = *(vstack[0])   -- deref in place
        print(f'{vip}  {mnem} [{tos}] -> {mem(tos)}')
    elif mnem == 'PUSH':         # push imm32
        print(f'{vip}  {mnem}  {imm}')
    elif mnem == 'LOAD, [MEM]':   # push &vstack[imm + 0x100]
        slot = expr_simp(ExprInt(0x100, 32) + imm + expr_simp(EBP - ExprInt(0x128, 32))) # &vstack= byte ptr -128h
        print(f'{vip}  LOAD  &vstack[{imm} + 0x100]  (= {slot})')
    elif mnem == 'LOAD INPUT':   # if (imm == 0) push &arg    (arg is at EBP+8)
        if imm.is_int() and int(imm) == 0:
            print(f'{vip}  CMOVZ {mnem}  input={sb.eval_expr(ExprMem(expr_simp(EBP + ExprInt(8, 32)), 32))}; !zf:{imm}')
    elif mnem == 'JNZ':       # ++vip; if (vstack[0]) vip += disp else vip += 4; vsp -= 2
        print(f'{vip}  {mnem}  {expr_simp(vip + ExprInt(1, 32) + imm)}  ; !zf = {tos}')
    elif mnem == 'JMP':          # ++vip; vip += disp
        print(f'{vip}  {mnem}   {expr_simp(vip + ExprInt(1, 32) + imm)}')
    elif mnem == 'HALT':
        print(f'{vip}  {mnem}  ; ret = {tos}')


sym_bytecode_addr, sym_bytecode = read_bytecode()
sb.symbols[sym_bytecode_addr] = sym_bytecode # fixed the bytecode in the symbolic symbols

sb.symbols[ExprId('ESP', 32)] = ExprInt(0x1000, 32) # arbitrary address
arg = ExprMem(expr_simp(sb.symbols[ExprId('ESP', 32)] + ExprInt(4, 32)), 32)
sb.symbols[arg] = ExprInt(0, 32) # set concrete value for arg

sb.run_block_at(ircfg=ircfg, addr=vm_entry) # initialized all the stack varible etc

EBP = sb.symbols[ExprId('EBP', 32)]
arg = ExprMem(expr_simp(EBP + ExprInt(8, 32)), 32)
sb.symbols[arg] = ExprInt(0, 32) # set concrete value for arg

# we needed vip and vstack to print the information we needed for each handler
vip_local = sb.symbols[ExprMem(EBP - ExprInt(0x12C, 32), 32)]
vstack_local = sb.symbols[ExprMem(EBP - ExprInt(0x130, 32), 32)] # local variables

q = deque([ExprInt(vm_dispatcher, 32)])
while q:
    bb = q.popleft()
    r = sb.run_block_at(ircfg=ircfg, addr=bb)

    vstack_addr = sb.eval_expr(vstack_local); vstack = sb.eval_expr(ExprMem(vstack_local, 32))
    hd = resolve_addr(r)
    if hd in HANDLERS:
        disassemble(sb, hd, vstack=vstack, vstack_addr=vstack_addr, vip=sb.eval_expr(vip_local))


    if r.is_loc() or r.is_int():
        q.append(r)
    # print(r) # tracer

```

This gives us clean disassembly which you can see [here](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-04_deob_vm-py-L126)

## Tigress CFF

This example has [Control Flow Flattening](https://tigress.cs.arizona.edu/transformPage/docs/flatten/index.html). I thought to change the dummy/simple src to a little bit larget dummy example.
Its nothing serious its just [180 LOC](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-06_testing_cff-c) and its obfuscated version is [520 LOC](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-06_testing_cff-c-L190)

![](2026-08-09-03-09-19.png)
_Flattened function CFG 🫠_

![](2026-08-10-23-15-40.png)
_Dispatcher_

Its a jump table based CFF obfuscator. if we disassemble it via miasm asmcfg then the view is:

![](2026-08-11-00-18-07.png)

We can only see the entry and the dispatcher, it just ends on indirect jump, So we merge the asmcfg with the addresses in jmp table, and we will get the whole asmcfg.

```py

jt = {}
for s in range(jt_count):
    idx = va(jt_base + 4 * s) # va is a helper function which uses lief to convert address to raw offset 
    jt[s] = struct.unpack('<I', raw[idx:idx+4])[0]

state_and_addr = {s: h for s, h in jt.items() if h != disp_addr} # to avoid the loopback branches

asmcfg = mdis.dis_multiblock(target_addr) # incomplete asmcfg (just the dispatcher)

for h in set(state_and_addr.values()): # getting all the state addreses
    asmcfg.merge(mdis.dis_multiblock(h)) # merging them on existing incomplete AsmCFG

open('asmcfg.dot', 'w').write(asmcfg.dot()) # we have a full asm cfg now

```

![](2026-08-11-11-14-31.png)
_Final AsmCFG_

One thing to note about miasm asm blocks that they split on calls, Forexample:

![](2026-08-11-11-43-44.png)
_Basic Block of a case_

![](2026-08-11-11-52-15.png)
_Same Basic Block in miasm. Its split on each call_

### General Approach 

So we have an initial state at the start of dispatcher block, that state determines which jump to perform from the jump table. After each case execution at the tail state value is updated, but some cases have conditional jumps which can have two distinct state values. Thus effecting the execution flow via a condition. 

![](2026-08-10-23-07-20.png)
_A simple example of how a single case determines the other state by jcc, fall through will get executed which will have fall state_

![](2026-08-10-23-07-51.png)
_This is simple case, one state corresponds the other state. Just the whole OBB chain as its unconditional_


To deobfuscate this, We will again use the power of Symbolic execution engine. We will extract all splited basic blocks (as miasm basic blocks are splited on call instruction too) as single original basic block. If we encounter any jcc at the any of the case block it means that there is a conditional control flow here, to extract the info we will chain the fall case leaving the jcc case for later recovery. After that we have the full chain of the case statement (if its a jcc then last chain block is the fall case). We iterate through each of the cases and perform symbolic exection on each case by extracting there jcc case too and the last chain value (which is the fall case). So by this we will have the entire chain of execution in uncondtional jmp blocks and both jcc state and fall state if it was an conditional jump block, Which we store as `state to state mapping` where we know this state can have two possible further states depending upon the jcc and then we do have `state to address mapping` too. 

As miasm treats global data reads as symbolic, We do need to set the jump table to be concerete so that, it resolves to some jump address rather than some symbolic vector.


![](2026-08-10-23-58-29.png)
_Jump Table_

The jump table lives in the *.rodata*, We can also just read the jump table directly from binary but i opted [lief](https://lief.re/doc/latest/) as it will work for whole sections in the binary. 

```py
concreteSymbols = {} # we will use that as the argument of add_data

def add_data(concrete, offset, data):
    # fill every overlapping qword/dword with concrete values from data 
    for i in range(0, len(data)-7, 8):
        concrete[ExprMem(ExprInt(offset + i, 64), 64)] = ExprInt(u64(data, i), 64)
    for i in range(0, len(data)-3, 4):
        concrete[ExprMem(ExprInt(offset + i, 32), 32)] = ExprInt(u32(data, i), 32)

def simpExprMemCallBack(expr):
    if isinstance(expr, ExprMem):
        if expr in concreteSymbols:
            return expr.replace_expr({expr: concreteSymbols[expr]}) 
    return None

def simpExprMem(_, expr):
    # https://github.com/cea-sec/miasm/blob/master/miasm/expression/expression.py#L614 
    visitor = ExprVisitorCallbackTopToBottom(simpExprMemCallBack) 
    return visitor.visit(expr)
```

> The functions that we want, that initialize the data.

```py

rodata = elf.get_section('.rodata') # getting the .rodata of the binary via lief 

# This function initilizes all the .rodata in concreteSymbols dict. (tho we need just the jmp table) 
add_data(concreteSymbols, rodata.virtual_address, bytes(rodata.content)) # rodata virtuall address as offset

# Custom simplification pass
custom_simp = ExpressionSimplifier() 
custom_simp.enable_passes(ExpressionSimplifier.PASS_COMMONS)
custom_simp.enable_passes(ExpressionSimplifier.PASS_HIGH_TO_EXPLICIT)
custom_simp.enable_passes({ExprMem: [simpExprMem]})

```

> Custom simplification pass which contains the concerete data we need, we just need to pass it to symbolic execution engine


```py
def case_chain(case_loc):
    chain = [case_loc]
    cur = case_loc 
    while True:
        bb = asmcfg.loc_key_to_block(cur) 
        if bb.lines[-1].name in ('JMP', 'RET'):
            break 
        succs = asmcfg.successors(cur)
        if bb.lines[-1].name.startswith('J') and len(succs) == 2: # if we get a jcc (then we have 2 successors)
            cur = fall_through(bb, succs) # than we append the fall case in our chain.
        else:
            cur = succs[0]

        if cur in DISPATCHER_LOCS:
            break 

        chain.append(cur) # append all the block in the chain (and fall in case of jcc)
    return chain

def fall_through(bb, succs): # succ is a lockey 
    tgt = bb.lines[-1].args[0] # getting path to jcc location
    if isinstance(tgt, ExprLoc): tgt_loc = tgt.loc_key 
    else: tgt_loc = tgt
    others = [s for s in succs if s != tgt_loc] # the successors which isn't the jcc
    assert len(others) == 1 
    return others[0] # returning the fall case

```
Now as we have discussed how we will connect the OBB via chaining and how to fall through works, Now we will just pick the state variable and see how we will perform symbolic execution on each case.

```s
.text:080486C3 dispatcher:             ; switch 33 cases
.text:080486C3 cmp     [ebp+state], 20h ; [ebp - 0x38]
.text:080486C7 ja      short dispatcher 
```

```py
disp_addr = 0x80486C3

dispatch_loc = loc_db.get_offset_location(disp_addr) # our state variable read is from this block is in this block
disp_block = asmcfg.loc_key_to_block(dispatch_loc)
state_variable = disp_block.lines[0].get_args_expr()[0] # as the state cmp is at first line of dispatcher, and its first expr
print('STATE VAR:', state_variable) 
```
> We get the correct state

```shell
STATE VAR: @32[EBP + 0xFFFFFFC8]
```

```py
# performed on each case
def discover_case(case_loc, chain):
    case_block = asmcfg.loc_key_to_block(case_loc)
    last = case_block.lines[-1] 
    if last.name.startswith('J') and len(chain) == 2: # as the jcc cases only had 2 chains.
        # passing our custom simplification pass for concerete data
        sb = SymbolicExecutionEngine(lifter, init_symbols, sb_expr_simp=custom_simp) 
        jcc_target_loc = to_loc_key(last.args[0]) # getting the jcc target location
        side_state = symb_exe_to_state(sb, jcc_target_loc) # next state value after the jcc case
        fall_state = symb_exe_to_state(sb, chain[-1]) # next state value after the fall case
        return [fall_state], {jcc_target_loc: side_state} # the fall state is the next state and along side we have also calculated the jcc

    sb = SymbolicExecutionEngine(lifter, init_symbols, sb_expr_simp=custom_simp)  # if the case was simple unconditional jmp (fixed state conversion)
    nxt = symb_exe_to_state(sb, chain[-1]) # direct unconditional state update
    if nxt is not None:
        return [nxt], {} # just the nxt because it has no jcc case
    else:
        return [], {} # no next as its a return block 

def symb_exe_to_state(sb, loc):
    r = sb.run_block_at(ircfg=ircfg, addr=loc) # perform symbolic execution of the a basic block of location
    r = to_loc_key(r)
    if r in DISPATCHER_LOCS: # if dispatcher and pre-dispathcer
        v = sb.eval_expr(state_variable) # get the state value which is updated during symbolic execution
        return int(v) if isinstance(v, ExprInt) else None 
    if r == ret_loc: # whent he next basic block is the return block
        return None 
    return symb_exe_to_state(sb, r) # repeat the process to process multichain blocks

```

These are peformed on each jump table location getting information on each of the case block on where it falls and where it jumps. Then we do have all necessary information to delete the irrelevant basic block and only keep the Original Basic Blocks which is union of only the prologue block, case blocks and return block. All the irrelevant Basic blocks will be removed

```py
def remove_irrelevant_BB(original_BB):
    irrelevant_locations = []
    for bb in asmcfg.blocks:
        if bb.loc_key not in original_BB:
            irrelevant_locations.append(bb.loc_key)
    for loc in irrelevant_locations:
        asmcfg.del_block(asmcfg.loc_key_to_block(loc))
```

Each iteration of the symbolic execution on each individial case block stores the info in three python dictonary, I have modified the [ollvm-unflattener binrewriter](https://github.com/cdong1012/ollvm-unflattener/blob/master/unflattener/binrewrite.py) to make this tigress cff unflattener work which you can see [here](https://gist.github.com/0xNoo3/c879a676e19d8f2a879f89165424a781#file-06_writers-py-L1), Now if we just run our deobfuscator we get a fully unflattened function 

![](2026-08-11-13-29-19.png)
_CFG Before Deobfuscation_

![](2026-08-11-13-31-14.png)
_CFG After Deobfuscation_

> This is the whole deobfuscation script

```py
from miasm.core.locationdb import LocationDB, LocKey
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.simplifications import ExpressionSimplifier, expr_simp
from miasm.expression.expression import ExprInt, ExprMem, ExprLoc, ExprVisitorCallbackTopToBottom
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.x86.regs import all_regs_ids, all_regs_ids_init
from collections import defaultdict
from binrewrite_t import TBinaryRewriter
import struct 
import lief 

file = 'testing-flatten.bin' 
target_addr = 0x80486B6         
disp_addr = 0x80486C3 
pre_disp_addr = 0x8048B57  
ret_addr = 0x8048B5C  
jt_base = 0x8048F20 
jt_count =  0x21

ENTRY_STATE = -2
EXIT_STATE = -1

elf = lief.ELF.parse(file)
loc_db = LocationDB()
container = Container.from_stream(open(file, 'rb'), loc_db=loc_db) 
machine = Machine(container.arch) 
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db) 
lifter = machine.lifter_model_call(loc_db=loc_db) 

va = lambda addr: elf.virtual_address_to_offset(addr) 

raw = open(file, 'rb').read() 
jt = {}
for s in range(jt_count):
    idx = va(jt_base + 4 * s)
    jt[s] = struct.unpack('<I', raw[idx:idx+4])[0]

state_and_addr = {s: h for s, h in jt.items() if h != disp_addr}

asmcfg = mdis.dis_multiblock(target_addr) 

for h in set(state_and_addr.values()):
    asmcfg.merge(mdis.dis_multiblock(h))

ircfg = lifter.new_ircfg_from_asmcfg(asmcfg=asmcfg) # lifting the full asmcfg to full ircfg

def u64(data, i):
    return struct.unpack('<Q', data[i:i + 8])[0] 
def u32(data, i):
    return struct.unpack('<I', data[i:i + 4])[0] 

concreteSymbols = {} 
def add_data(symb, offset, data):
    # fill every overlapping qword/dword with concrete values from data 
    for i in range(0, len(data)-7, 8):
        symb[ExprMem(ExprInt(offset + i, 64), 64)] = ExprInt(u64(data, i), 64) 
    for i in range(0, len(data)-3, 4):
        symb[ExprMem(ExprInt(offset + i, 32), 32)] = ExprInt(u32(data, i), 32) 

def simpExprMemCallBack(expr):
    if isinstance(expr, ExprMem):
        if expr in concreteSymbols:
            return expr.replace_expr({expr: concreteSymbols[expr]}) 
    return None 

def simpExprMem(_, expr):
    # https://github.com/cea-sec/miasm/blob/master/miasm/expression/expression.py#L614 
    visitor = ExprVisitorCallbackTopToBottom(simpExprMemCallBack) 
    return visitor.visit(expr)

def to_loc_key(expr):
    if isinstance(expr, LocKey):  return expr
    if isinstance(expr, ExprLoc): return expr.loc_key
    if isinstance(expr, int):     return loc_db.get_offset_location(expr)
    if isinstance(expr, ExprInt): return loc_db.get_offset_location(int(expr))
    return None

rodata = elf.get_section('.rodata') 

add_data(concreteSymbols, rodata.virtual_address, bytes(rodata.content))

custom_simp = ExpressionSimplifier()
custom_simp.enable_passes(ExpressionSimplifier.PASS_COMMONS)
custom_simp.enable_passes(ExpressionSimplifier.PASS_HIGH_TO_EXPLICIT)
custom_simp.enable_passes({ExprMem: [simpExprMem]})

pre_disp_loc = loc_db.get_offset_location(pre_disp_addr)
dispatch_loc = loc_db.get_offset_location(disp_addr)
ret_loc = loc_db.get_offset_location(ret_addr)
DISPATCHER_LOCS = {dispatch_loc, pre_disp_loc}

disp_block = asmcfg.loc_key_to_block(dispatch_loc)
state_variable = disp_block.lines[0].get_args_expr()[0]
print('STATE VAR:', state_variable) 

init_symbols = {}
for i, r in enumerate(all_regs_ids):
    init_symbols[r] = all_regs_ids_init[i]

def remove_irrelevant_BB(original_BB):
    irrelevant_locations = []
    for bb in asmcfg.blocks:
        if bb.loc_key not in original_BB:
            irrelevant_locations.append(bb.loc_key)
    for loc in irrelevant_locations:
        asmcfg.del_block(asmcfg.loc_key_to_block(loc))

def fall_through(bb, succs): # succ is a lockey 
    tgt = bb.lines[-1].args[0] # getting path to jcc location 
    if isinstance(tgt, ExprLoc): tgt_loc = tgt.loc_key 
    else: tgt_loc = tgt 
    others = [s for s in succs if s != tgt_loc] # the successors which isn't the jcc 
    assert len(others) == 1 
    return others[0] # returning the fall case 

def case_chain(case_loc):
    chain = [case_loc]
    cur = case_loc 
    while True:
        bb = asmcfg.loc_key_to_block(cur) 
        if bb.lines[-1].name in ('JMP', 'RET'):
            break 
        succs = asmcfg.successors(cur)
        if bb.lines[-1].name.startswith('J') and len(succs) == 2: # if we get a jcc (then we have 2 successors)
            cur = fall_through(bb, succs) # than we append the fall case in our chain.
        else:
            cur = succs[0]
        if cur in DISPATCHER_LOCS:
            break 
        chain.append(cur) # append all the block in the chain (and fall in case of jcc)
    return chain

def symb_exe_to_state(sb, loc):
    r = sb.run_block_at(ircfg=ircfg, addr=loc)
    r = to_loc_key(r) 
    if r in DISPATCHER_LOCS:
        v = sb.eval_expr(state_variable) 
        return int(v) if isinstance(v, ExprInt) else None 
    if r == ret_loc:
        return None 
    return symb_exe_to_state(sb, r) 

def discover_case(case_loc, chain):
    case_block = asmcfg.loc_key_to_block(case_loc)
    last = case_block.lines[-1] 
    if last.name.startswith('J') and len(chain) == 2: # as the jcc cases only had 2 chains.
        sb = SymbolicExecutionEngine(lifter, init_symbols, sb_expr_simp=custom_simp) 
        jcc_target_loc = to_loc_key(last.args[0]) # getting the jcc target location
        side_state = symb_exe_to_state(sb, jcc_target_loc) # jcc state
        fall_state = symb_exe_to_state(sb, chain[-1]) # fall state from the last chain
        return [fall_state], {jcc_target_loc: side_state} # the fall state is the next state and along side we have also calculated the jcc

    sb = SymbolicExecutionEngine(lifter, init_symbols, sb_expr_simp=custom_simp)  # if the case was simple unconditional jmp (fixed state conversion)
    nxt = symb_exe_to_state(sb, chain[-1]) # direct unconditional state update
    if nxt is not None:
        return [nxt], {} # just the nxt because it has no jcc case
    else:
        return [], {} # no next as its a return block 

state_to_state_map = defaultdict(list)
state_to_addr_map = defaultdict(list)
jcc_targets_map = defaultdict(dict)

# entry/prologue pseudo-state: run the entry block -> first dispatched state 
entry_loc = loc_db.get_offset_location(target_addr) 
state_to_addr_map[ENTRY_STATE] = case_chain(entry_loc) 
sb0 = SymbolicExecutionEngine(lifter, init_symbols, sb_expr_simp=custom_simp) 
first_state_val = symb_exe_to_state(sb0, entry_loc) 

assert first_state_val is not None
state_to_state_map[ENTRY_STATE].append(first_state_val) 

print('entry chain:', [hex(loc_db.get_location_offset(x)) for x in state_to_addr_map[ENTRY_STATE]], '-> first state', hex(first_state_val)) 

for state_val, case_addr in sorted(state_and_addr.items()):
    case_loc = loc_db.get_offset_location(case_addr) 
    chain = case_chain(case_loc) 
    state_to_addr_map[state_val] = chain # containes a whole block and only fall if the the block splits into conditional
    nexts, jcc = discover_case(case_loc, chain) 
    state_to_state_map[state_val] = nexts 
    if jcc:
        jcc_targets_map[state_val] = jcc 
    print('state {:2d} chain={} -> fall={} jcc={}'.format( # debug/info print
        state_val,
        [hex(loc_db.get_location_offset(x)) for x in chain],
        nexts,
        {hex(loc_db.get_location_offset(k)): v for k, v in jcc.items()} if jcc else None)) 

# exit pseudo-state: the ret block.  Terminal cases jump straight to it 
# (no state store involved), so it cannot be a jump-table state.
state_to_addr_map[EXIT_STATE] = [ret_loc] 
state_to_state_map[EXIT_STATE] = [] # as there is no next state

for s, ns in state_to_state_map.items():
    if not ns and s != EXIT_STATE: # if there is no next state and current state is not an exit state, make that state and exit state. 
        state_to_state_map[s] = [EXIT_STATE] 

# OBB = union of all case chains (+ prologue, + ret block) 
OBB = [] 
for locations in state_to_addr_map.values():
    OBB.extend(locations) 
print('OBB blocks:', len(OBB), 'of', len(asmcfg.blocks)) 

remove_irrelevant_BB(original_BB=OBB) 

# Patch 
rewriter = TBinaryRewriter(container.arch, file, va_function_lief=va) 
rewriter.patch_binary(asmcfg, target_addr, state_to_state_map,state_to_addr_map, jcc_targets_map,ENTRY_STATE, EXIT_STATE, sb0, file + '.deob',state_variable=state_variable) 

```

## Range Dividers

Sometimes to increase the function size and the CFG, There is range-dividers obfuscations. which is basically replicating the basic block functionality. Hence we perform Equivalence checking.

> A method to determine if two given BB have the same behavior via Syntactically-equivalent & Semantically-equivalent.

### Approach

We will iterate through each basic block, And for each basic block we will check all the other basic block of that function that are they Syntactically-equivalent or Semantically-equivalent Hence the Basic blocks are equivalent. 

> First check the Syntax-equivalence 

```py
def syntax_cmp(src_asmbb, dst_asmbb):
    if len(src_asmbb.lines) != len(dst_asmbb.lines):
        return False
    for src_l, dst_l in zip(src_asmbb.lines, dst_asmbb.lines):

        if str(src_l).startswith('J') and str(dst_l).startswith('J'): # if its jmp instruction
            if str(src_l).split(' ')[0] != str(dst_l).split(' ')[0]: # don't care about the jmp location
                return False
            
        elif str(src_l) != str(dst_l): # if the instructions are not jmp or jcc and they are not same 
            return False
    return True # all passed hence same instructions
```

If the syntax_cmp returns False, We check semantic equivalence, We will have two lifter to lift each block, because we want two different IRCFG. We will perform symbolic execution on each IR Block. and check if they are sat.


```py
def semantic_cmp(src_asmbb, dst_asmbb, lifter_s, lifter_d):
    src_ircfg = IRCFG(None, src_asmbb.loc_key)
    lifter_s.add_asmblock_to_ircfg(block=src_asmbb, ircfg=src_ircfg)
    dst_ircfg = IRCFG(None, dst_asmbb.loc_key)
    lifter_d.add_asmblock_to_ircfg(block=dst_asmbb, ircfg=dst_ircfg)
    src_irbb = src_ircfg.blocks[next(iter(src_ircfg.blocks))] # get the source IR basic block
    dst_irbb = dst_ircfg.blocks[next(iter(dst_ircfg.blocks))] # get the destination IR basic block

    # Ready for Symbolic Execution
    src_symbols = {}; dst_symbols = {}

    # regs
    for i, r in enumerate(all_regs_ids):
        src_symbols[r] = all_regs_ids_init[i]; dst_symbols[r] = all_regs_ids_init[i] # init symbols for both blocks

    src_sb = SymbolicExecutionEngine(lifter_s, src_symbols)

    for assignblk in src_irbb:
        assign = True
        for dst in assignblk:
            if str(dst) in ['EIP', 'IRDst']:
                assign = False
        if assign:
            src_sb.eval_updt_assignblk(assignblk)

    dst_sb = SymbolicExecutionEngine(lifter_d, dst_symbols)

    for assignblk in dst_irbb:
        assign = True
        for dst in assignblk:
            if str(dst) in ['EIP', 'IRDst']:
                assign = False
        if assign:
            dst_sb.eval_updt_assignblk(assignblk)

    src_sb.del_mem_above_stack(lifter_s.sp)
    dst_sb.del_mem_above_stack(lifter_d.sp)

    all_memory_ids  = [k for k, v in dst_sb.symbols.memory()] + [k for k, v in src_sb.symbols.memory()]

    for k in all_regs_ids + all_memory_ids:

        if str(k) == 'EIP' or k in [zf, nf, pf, of, cf, af, df, tf]:
            continue

        v0 = src_sb.symbols[k] # source symbol value
        v1 = dst_sb.symbols[k] # destination symbol value

        if v0 == v1:
            continue

        s = z3.Solver() 
        t = TranslatorZ3() 
        try:
            r = t.from_expr(v0); l = t.from_expr(v1)
        except NotImplementedError:
            return False

        s.add(z3.Not(r == l)) # in no such case r == l
        if s.check() == z3.unsat: # means that r == l in all cases not only one
            continue
        else:
            return False 
    # all symbols and memory has been iterated and every case was unsat for r != l, it means that both are equal in both cases.
    return True 
```

![](2026-08-11-15-56-32.png)
_Before Equivalence checking_

![](2026-08-11-16-00-23.png)
_After Equivalence checking_

## Zeus VM Devirtualization 

I picked that sample because its famous and well know. I will cover its string deobfuscation and write a functional disassembler which yields some usefull information. 

### String Decryption

during analysis we see this function frequently

![](2026-08-11-16-56-03.png)

If we look inside

![](2026-08-11-16-57-20.png)
_String decryption function_

The string encrypted table has 4 bytes of key, size of the encrypted string and the address to the encrypted string bytes.


![](2026-08-11-17-02-10.png)
_encrypted string table_

Setting the struct in IDA

```c
struct enc
{
  _DWORD key;
  _DWORD size;
  _BYTE *string;
};
```

![](2026-08-11-17-09-41.png)
_after applying the enc struct_

> For testing that it works i did the first manually.

```py
k = bytes.fromhex('6001BE89')
sz = 9
enc = bytes.fromhex('606E6C6C7C6968737A00')

dec = []
for i in range(sz):
    dec.append(i ^ enc[i] ^ k[sz & 3])
print(''.join(map(chr, dec))) 
```

```shell
$ python string_dec.py 
anonymous
```

```py
# translation in ida python

def decrypt_string(off):
    enc_struct = 0x4019E0 + 12 * off
    k = ida_bytes.get_bytes(enc_struct, 4); size = idc.get_wide_dword(enc_struct+4); enc_addr = idc.get_wide_dword(enc_struct+8)
    enc = ida_bytes.get_bytes(enc_addr, size=size)
    key = k[size & 3]; dec = []
    for i in range(size):
        dec.append(i ^ enc[i] ^ key)
    return bytes(dec).decode()
```

as the encrypted string table is referenced in two function means both are string decryption functions, we will use ida python and get the first argument from all of the xrefs and after that we can perform string decryption in ida and convert them into a enum, So we will have the decrypted string at each function argument.

> Full string decryption to enum script

```py

import idc
import ida_bytes
import ida_funcs 
import idautils
import ida_hexrays
import re 

def get_first_arg(call_ea):
    func = ida_funcs.get_func(call_ea) 
    cfunc = ida_hexrays.decompile(func)      
    class ArgFinder(ida_hexrays.ctree_visitor_t):  # custom visitor to walk the ctree
        def __init__(self): 
            ida_hexrays.ctree_visitor_t.init(self, ida_hexrays.CV_FAST)  # faster traversal
            self.result = None                    # will hold the first arg's value if found

        def visit_expr(self, e):
            # look for a call expression whose address matches our target call_ea
            if e.op == ida_hexrays.cot_call and e.ea == call_ea:
                if e.a.size() > 0:                # e.a is the call's argument list (carglist_t)
                    arg0 = e.a[0]                  # first arg
                    if arg0.op == ida_hexrays.cot_num:  # if its a constant
                        self.result = arg0.numval() 
                return 1   # stop traversal 
            return 0       # continue traversal

    af = ArgFinder()
    af.apply_to(cfunc.body, None)   # run the visitor over the whole function body
    return af.result                 # return the found constant, or None if not found/not a constant

xrefs = [ref.frm for ref in idautils.XrefsTo(0x416951)] + [ref.frm for ref in idautils.XrefsTo(0x416901)] 

def decrypt_string(off, xref):
    if xref == 0x41c73d: return None # some junk byte
    # print(hex(xref)) # debug print
    enc_struct = 0x4019E0 + 12 * off
    k = ida_bytes.get_bytes(enc_struct, 4); size = idc.get_wide_dword(enc_struct+4); enc_addr = idc.get_wide_dword(enc_struct+8)
    enc = ida_bytes.get_bytes(enc_addr, size=size)
    key = k[size & 3]; dec = []
    for i in range(size):
        dec.append(i ^ enc[i] ^ key)
    return bytes(dec).decode()

enum_dict = {}
def string_decryptor():
    for xref in xrefs:
        offset = get_first_arg(xref)
        if not offset or offset in enum_dict:
            # print(hex(xref), offset)
            continue
        decrypted = decrypt_string(offset, xref)
        if decrypted:
            enum_dict[offset] = decrypted
    
    dict_to_enum(enum_dict)

def dict_to_enum(d, enum_name="zeus_string_dec"):

    used = set()
    lines = [f"enum {enum_name}", "{"]

    for key in sorted(d):
        s = d[key]
        # Uppercase
        name = s.upper()
        # Common replacements
        replacements = {
            "%S": "FMT_S",
            "%U": "FMT_U",
            "%D": "FMT_D",
            "%X": "FMT_X",
            "%08X": "FMT_08X",
            "%02X": "FMT_02X",
            "%C": "FMT_C",
            "%P": "FMT_P",
            "*": "STAR",
            "\\": "_",
            "/": "_",
            ".": "_",
            ":": "_",
            "-": "_",
            " ": "_",
            "\t": "_",
            "\r": "_",
            "\n": "_",
            '"': "",
            "'": "",
            "(": "",
            ")": "",
            "[": "",
            "]": "",
            "{": "",
            "}": "",
            ",": "_",
            ";": "_",
            "=": "_",
            "+": "_",
            "&": "_AND_",
            "|": "_OR_",
            "?": "_",
            "!": "_",
            "@": "AT",
        }

        for old, new in replacements.items():
            name = name.replace(old, new)
        # Remove anything still invalid
        name = re.sub(r'[^A-Z0-9_]', '_', name)
        # Collapse repeated underscores
        name = re.sub(r'_+', '_', name).strip("_")
        # Cannot start with digit
        if name[0].isdigit():
            name = "_" + name

        # Ensure uniqueness
        base = name
        i = 2
        while name in used:
            name = f"{base}_{i}"
            i += 1
        used.add(name)
        lines.append(f"    {name} = 0x{key:X},")

    lines.append("};")

    with open(enum_name+'.c', 'w') as f:
        f.write("\n".join(lines))

string_decryptor()
```

> After setting the first argument type to the decrypted enum, we will have all the string decrypted in the argument :)

<video src="/assets/posts/2026-08-08-taming-obfuscation/zeus_string.webm" controls style="max-width: 100%; height: auto;"></video>

### De-Virt

After some analysis we encounter the vm function.

![](2026-08-11-18-04-45.png)
_vm function_

![](2026-08-11-18-05-15.png)
_function table as vm handlers_

some analysis yields the vm struct

```c
struct vm
{
  _BYTE *vpc;
  _BYTE *mem;
  _DWORD flag;
  _DWORD reg[16];
};
```

![](2026-08-11-18-06-29.png)
_After applying vm struct_

As the vm context is going to the function argument of the dispatcher hence all the handlers function arg should be the vm ctx

```py
import idc

table = 0x427018
functions = [idc.get_wide_dword(table + i * 4) for i in range(69)] # getting all the handlers 

for f in functions:
    idc.SetType(f, 'char __thiscall function(vm *this)') # set a function type
```

The handlers are simple, nothing complicated, each handler decryptes the bytecode at runtime with a custom key, So symbolic execution is our way to go. We need to set the bytecode and memcode as concerete values. As all of the handlers access the bytecode and memcode via the vm struct, so we will set struct in miasm at a arbitrary address, and initialize the member of struct as they were initialized in the vm entry.

> This is the basic miasm setup we need for zeus vm. 

```py

VM_CTX = 0x10000000      # arbitrary address
VIP, MEM, FLAG, REG = 0x00, 0x04, 0x08, 0x0C # struct offsets
BYTECODE = 0x403368
MEMCODE = 0x4030E0

sb = SymbolicExecutionEngine(lifter=lifter)


def write_address(addr, val, size=32): # write address on a member of struct 
    sb.symbols[ExprMem(ExprInt(addr, 32), size)] = ExprInt(val, size)

ctx = lambda off: expr_simp(sb.eval_expr(ExprMem(ExprInt(VM_CTX + off, 32), 32))) # access the member address of the vm context
read_value_n = lambda addr_expr, size=8: expr_simp(sb.eval_expr(ExprMem(expr_simp(addr_expr), size))) # derence the member

# init bytecode, memcode, flags in the vm ctx
write_address(VM_CTX + VIP,  BYTECODE); write_address(VM_CTX + MEM,  MEMCODE); write_address(VM_CTX + FLAG, 0)
# 16 flags
for i in range(16):
    write_address(VM_CTX + REG + i * 4, 0, size=32)

# populating the bytecode addr with concerete bytecode
data = container.bin_stream.getbytes(BYTECODE, 0x1000)
for i, b in enumerate(data):
    sb.symbols[ExprMem(ExprInt(BYTECODE + i, 32), 8)] = ExprInt(b, 8)

# populating the memcode addr with concerete memcode
data = container.bin_stream.getbytes(MEMCODE, 0x288)
for i, b in enumerate(data):
    sb.symbols[ExprMem(ExprInt(MEMCODE + i, 32), 8)] = ExprInt(b, 8)

```

> The reason why we initialize this at a byte granulity because miasm will read the dword/word or any reference automatically as long each address should have concerete byte value, also we didn't use the tigress CFF method of concerete values because  we will use only one Symbolic execution engine through out. If we had multiple symbolic execution engines this would fail. 
{:.prompt-tip}

While analysis of handlers to understand some semantics of handlers so we can write a disassembler. All the handlers are simple/simmilar enough, one handler was a little of so lets see that that is.

![](2026-08-11-19-12-53.png)

```c
int __userpurge sub_409281@<eax>(int result@<eax>, int a2, __int16 a3)
{
  int n0x100; // ecx
  _BYTE *v4; // esi
  char *v5; // esi
  int n256; // edi
  char v7; // dl
  unsigned __int8 v8; // [esp+Eh] [ebp-2h]
  unsigned __int8 v9; // [esp+Fh] [ebp-1h]

  n0x100 = 0;
  v9 = 0;
  v8 = 0;
  *(_WORD *)(result + 256) = 0;
  v4 = (_BYTE *)result;
  do
    *v4++ = n0x100++;
  while ( (unsigned __int16)n0x100 < 0x100u );
  v5 = (char *)result;
  n256 = 256;
  do
  {
    v7 = *v5;
    v8 += *v5 + *(_BYTE *)(v9++ + a2);
    *v5 = *(_BYTE *)(v8 + result);
    *(_BYTE *)(v8 + result) = v7;
    if ( v9 == a3 )
      v9 = 0;
    ++v5;
    --n256;
  }
  while ( n256 );
  return result;
}

int __userpurge sub_4092E4@<eax>(int result@<eax>, int a2, unsigned int a3)
{
  unsigned int v3; // edi
  char v4; // dl
  unsigned __int8 i; // [esp+6h] [ebp-2h]
  unsigned __int8 v6; // [esp+7h] [ebp-1h]

  v6 = *(_BYTE *)(result + 256);
  v3 = 0;
  for ( i = *(_BYTE *)(result + 257); v3 < a3; ++v3 )
  {
    v4 = *(_BYTE *)(++v6 + result);
    i += v4;
    *(_BYTE *)(v6 + result) = *(_BYTE *)(i + result);
    *(_BYTE *)(i + result) = v4;
    *(_BYTE *)(a2 + v3) ^= *(_BYTE *)((unsigned __int8)(v4 + *(_BYTE *)(v6 + result)) + result);
  }
  *(_BYTE *)(result + 256) = v6;
  *(_BYTE *)(result + 257) = i;
  return result;
}

```

