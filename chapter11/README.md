# Detecting Format String vuln via DTA

The exercise on this chapter is done on the VM provided in the book because compiling
the pintools requires older version of gcc and glibc. 

Download the VM from: https://practicalbinaryanalysis.com 

To test this exercise, copy Makefile and the ese/ folder inside /home/binary/code/chapter11/ in the VM, then run:


```
$ cd /home/binary/code/chapter11/
$ make dta-formatstring_test
$ make dta-formatstring.o
$ make dta-formatstring.so

$ cd ~/libdft/pin-2.13-61206-gcc.4.4.7-linux
$ ./pin.sh -follow_execv -t ~/code/chapter11/ese/dta-formatstring.so -- ~/code/chapter11/ese/dta-formatstring_test &


```

## Open another shell, then run:

```
nc -u localhost 9999
%s
```
