#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define N 100

#pragma instrument function add, mul, reduce

//
void *reduce(void *p)
{
  int *t = (int *)p, x = 0;
  
  for (int i = 0; i < N; i++)
    x += t[i];
}

//
void print(int *v, int n)
{
  printf("[ ");

  if (n <= 16 && n > 0)
    for (int i = 0; i < n; i++)
      printf("%d ", v[i]);
  else
    printf("... ");
  
  printf("]\n");

}

//
void zeroup(int *r, int n)
{ memset(r, 0, sizeof(int) * n); }

//
void add(int *v1, int *v2, int *r, int n)
{
  for (int i = 0; i < n; i++)
    r[i] = v1[i] + v2[i];
}

//
int mul(int *v1, int *v2, int n)
{
  register int r = 0;
  
  for (int i = 0; i < n; i++)
    r += v1[i] * v2[i];

  return r;
}

//
int main(int argc, char **argv)
{
  int n = 1024 * 1024, r;
  int *v1 = (int *)malloc(sizeof(int) * n),
      *v2 = (int *)malloc(sizeof(int) * n),
      *v3 = (int *)malloc(sizeof(int) * n);
  
  pthread_t t1, t2;
  
  zeroup(v1, n);
  zeroup(v2, n);
  
  add(v1, v2, v3, n);
  r = mul(v1, v2, n);
  
  pthread_create(&t1, NULL, reduce, v1);
  pthread_create(&t2, NULL, reduce, v2);
  
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  
  free(v1);
  free(v2);
  free(v3);
  
  return 0;
}

