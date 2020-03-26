#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

void vuln_func(char *buf)
{
  unsigned int i;
  char *ptr;

  if (!(ptr = malloc(8)))
    return;

  for (i = 0; i < 8; i++){
    char c = 0;
    while(c < buf[i]) c++;
    ptr[i] = c;
  }

  printf(ptr);
  free(ptr);
}

int
open_socket(const char *node, const char *service)
{
  struct addrinfo hints, *res;
  int sockfd;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_PASSIVE;
  if(getaddrinfo(NULL, "9999", &hints, &res) != 0) {
    return -1;
  }

  if((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
    return -1;
  }
  if(bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
    return -1;
  }

  return sockfd;
}


int main(int ac, char **av)
{
  int  fd1, fd2, fd3, fd4;
  char *buf1, *buf2, *buf3, *buf4;
  
  char socket_buf[8];
  socklen_t addrlen;
  struct sockaddr_storage addr;

  if (!(buf1 = malloc(8)))
    return -1;
  if (!(buf2 = malloc(8)))
    return -1;
  if (!(buf3 = malloc(8)))
    return -1;
  if (!(buf4 = malloc(8)))
    return -1;
  
  fd1 = open("/home/binary/code/chapter11/ese/1.txt", O_RDONLY);
  read(fd1, buf1, 8);

  fd2 = open("/home/binary/code/chapter11/ese/2.txt", O_RDONLY);
  read(fd2, buf2, 8);

  fd3 = open("/home/binary/code/chapter11/ese/3.txt", O_RDONLY);
  read(fd3, buf3, 8);

  fd4 = open("/home/binary/code/chapter11/ese/4.txt", O_RDONLY);
  read(fd4, buf4, 8);

  int sockfd = open_socket("localhost", "9999");
  
  if(sockfd < 0) {
    fprintf(stderr, "failed to open socket\n");
    return 1;
  }

  addrlen = sizeof(addr);
  if(recvfrom(sockfd, socket_buf, sizeof(socket_buf), 0, (struct sockaddr*)&addr, &addrlen) < 0) {
    fprintf(stderr, "(dta-formatstring_test) recvfrom failed\n");
    return 1;
  }

  //printf("%d\n%d\n%d\n%d\n%d\n", fd1,fd2,fd3,fd4,sockfd);
  
  close(fd1);
  close(fd2);
  close(fd3);
  close(fd4);
  close(sockfd);

  //vuln_func(buf3);
  vuln_func(socket_buf);
  
  free(buf1);
  free(buf2);
  free(buf3);
  free(buf4);
}
