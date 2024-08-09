.code

; Function to set up the syscall number
; RCX: syscall number
setup_syscall_number PROC
    mov eax, ecx
    ret
setup_syscall_number ENDP

; Function to execute a direct syscall
; RAX: syscall number (set by setup_syscall_number)
; RCX, RDX, R8, R9: first four arguments
; [RSP+28h], [RSP+30h], ...: additional arguments
execute_syscall PROC
    mov r10, rcx  ; Windows syscall calling convention
    syscall
    ret
execute_syscall ENDP

PUBLIC setup_syscall_number
PUBLIC execute_syscall

END