#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "cycle.h"

FILE *fd;
pthread_mutex_t m;

extern unsigned zebu_entry_instru(char *);
extern unsigned zebu_exit_instru(char *);

/*
  This is elegance at its most.
  I doubt anybody thought of it.  
*/
void zebu_start() __attribute__((constructor));
void zebu_final() __attribute__((destructor)) ;

ticks a, b;
unsigned call_count;

//Initialize counter & open the dump file !
void zebu_start()
{
  call_count = 0;
  fd = fopen("prof.zebu", "wb");
}

//Cleanup !
void zebu_final()
{ fclose(fd); }

//
unsigned zebu_entry_instru(char *fname)
{
  pthread_mutex_lock(&m); 
 
  b = getticks();

  call_count++;  
  
  return 0;
}

//
unsigned zebu_exit_instru(char *fname)
{ 
  a = getticks();
  
  fprintf(fd, "Call n° %d to function \t '%s' took \t\t %.0lf \t\t cycles (%.0lf, %.0lf).\n", 
	  call_count, 
	  fname, 
	  elapsed(a, b),
	  (double)b,
	  (double)a);

  pthread_mutex_unlock(&m);
  
  return 0; 
}
