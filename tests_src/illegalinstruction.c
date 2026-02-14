#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>

#define SIZE 4096
int main() {
#if defined(__arm64__)
	// arm64 macOS enforces W^X: write first, then make executable
	char * scode = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (scode == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	// UDF #0 (encoding 0x00000000) is permanently undefined on arm64
	for (int i = 0; i < SIZE/4; i++) ((uint32_t*)scode)[i] = 0x00000000;
	if (mprotect(scode, SIZE, PROT_READ | PROT_EXEC)) {
		perror("mprotect");
		return 1;
	}
#else
	char * scode = valloc(SIZE);
	//make scode executable on 64-bit
	if (mprotect((void*)scode,  sizeof(scode), PROT_READ | PROT_WRITE | PROT_EXEC)) {
		perror("mprotect");
	}
	//0xffff is an illegal instruction on both PPC and Intel.
	memset((void*)scode,0xff,SIZE);
#endif
	void  (*fp)() = (void(*)())scode;
	(*fp) ();
}
