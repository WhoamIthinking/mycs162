#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;
  write(1, "Hello\n", 6); // 直接调用 write，不依赖 printf
  return 0;

  //for (i = 0; i < argc; i++)
    //printf ("%s ", argv[i]);
  //printf ("\n");

  //return EXIT_SUCCESS;
}
