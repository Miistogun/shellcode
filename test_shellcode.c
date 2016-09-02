#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// compile with gcc flags -fno-stack-protector, -z execstack
// eg. gcc -o test_shellcode -fno-stack-protector -z execstack test_shellcode.c

int main(int argc, char** argv) {
	char *code;
	void (*fp)(void);

	if (argc != 2) {
		printf("Usage: %s <shellcode>\n", argv[0]);
		return 0;
	}

	code = malloc(strlen(argv[1]));
	strcpy(code, argv[1]);
	printf("Trying %lu bytes long shellcode ..\n", strlen(code));

	fp = (void *)code;
	fp();

	return 0;
}
