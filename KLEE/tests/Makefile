

compile:
	clang -I . -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone mydriver.c

klee:
	klee --libc=uclibc  --posix-runtime  --external-calls=all mydriver.bc

build:
	gcc -I ../../include -L /home/klee/klee_build/lib/ mydriver.c -lkleeRuntest

test:
	KTEST_FILE=klee-last/test000001.ktest ./a.out

.PHONY:
	compile build runtest klee-last
