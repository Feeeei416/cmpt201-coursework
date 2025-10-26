#define _POSIX_C_SOURCE_200809
#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void *foo(void *arg) {
  char *message = arg;
  printf("Inside a thread!\n");
  printf("Message is: %s\n", message);
  pid_t tid = gettid();
  printf("ID: %d\n", tid);
  return (void *)strlen(message);
}

int main(void) {
  pthread_t thread_id = 0;
  pthread_attr_t *attr = NULL;
  void *arg = "Hello Thread";
  int result = pthread_create(&thread_id, attr, foo, arg);
  if (result != 0) {
    return 0;
  }
  void *r = 0;
  pthread_join(thread_id, &r);
  long long len = (long long)r;
  printf("Done: answer is %lld. \n", len);
  return 0;
}
