extern runCode
global alignstack

segment ._TEXT

alignstack:
    push rdi
    mov rdi, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, byte +0x20
    call runCode
    mov rsp, rdi
    pop rdi
    ret