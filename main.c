#include <stdio.h>
#include <windows.h>

/* lot of structs taken from LoudSunRun, makes life easier */
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

typedef struct _FRAME_INFO {
    DWORD64 frameSize;
    PVOID returnAddress;
} FRAME_INFO, * PFRAME_INFO;

/* https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#unwind-operation-code */
DWORD64 findUnwindInfoStackImpact(PUNWIND_INFO pUnwindInfo) {

    DWORD64 stackFrameSize = 0;
    
    for (int i=0;i < pUnwindInfo->CountOfCodes; i++) {

        PUNWIND_CODE currentUnwindCode = &pUnwindInfo->UnwindCode[i];
        UNWIND_CODE_OPS currentUnwindOp = (UNWIND_CODE_OPS)currentUnwindCode->UnwindOp;
        BYTE currentOpInfo = currentUnwindCode->OpInfo;

        DWORD addedSize = 0;
        switch (currentUnwindOp) {

            case UWOP_PUSH_NONVOL:                
                addedSize += 8;
                break;
            
            case UWOP_ALLOC_SMALL:
                addedSize += (currentOpInfo * 8) + 8;
                break;

            case UWOP_ALLOC_LARGE:
            
                if (!currentOpInfo) {
                    i++;
                    currentUnwindCode = &pUnwindInfo->UnwindCode[i];
                    addedSize += (currentUnwindCode->FrameOffset * 8);
                }

                else if (currentOpInfo == 1) {
                    i++;
                    currentUnwindCode = &pUnwindInfo->UnwindCode[i];
                    addedSize += currentUnwindCode->FrameOffset;
                    
                    i++;
                    currentUnwindCode = &pUnwindInfo->UnwindCode[i];
                    addedSize += currentUnwindCode->FrameOffset << 16;
                }

                break;

            case UWOP_SAVE_NONVOL:
                i++;
                break;

            case UWOP_PUSH_MACHFRAME:

                if (currentOpInfo) {
                    addedSize += 0x40;
                } 

                else {
                    addedSize += 0x48;
                }
                
                break;
        }

        stackFrameSize += addedSize;
    }

    return stackFrameSize;
}

void populateFrames(PFRAME_INFO frames[]) {

    HANDLE hNtdll = GetModuleHandle("ntdll.dll");
    DWORD64 ntdllImageBase = 0;
    HANDLE hKernel32 = GetModuleHandle("kernel32.dll");
    DWORD64 kernel32ImageBase = 0;

    PVOID RUTS28 = (PBYTE)GetProcAddress(hNtdll, "RtlUserThreadStart") + 0x28;
    PRUNTIME_FUNCTION pRUTS28ActiveRuntimeFunctionTable = RtlLookupFunctionEntry((DWORD64)RUTS28, &ntdllImageBase, NULL);
    PUNWIND_INFO pRUTS28UnwindInfo = (PUNWIND_INFO)(pRUTS28ActiveRuntimeFunctionTable->UnwindData + ntdllImageBase);
    DWORD64 RUTS28StackImpact = findUnwindInfoStackImpact(pRUTS28UnwindInfo);

    PVOID BTIT1D = (PBYTE)GetProcAddress(hKernel32, "BaseThreadInitThunk") + 0x1D;
    PRUNTIME_FUNCTION pBTIT1DActiveRuntimeFunctionTable = RtlLookupFunctionEntry((DWORD64)BTIT1D, &kernel32ImageBase, NULL);
    PUNWIND_INFO pBTIT1DUnwindInfo = (PUNWIND_INFO)(pBTIT1DActiveRuntimeFunctionTable->UnwindData + kernel32ImageBase);
    DWORD64 BTIT1DStackImpact = findUnwindInfoStackImpact(pBTIT1DUnwindInfo);

    frames[0]->frameSize        = RUTS28StackImpact;
    frames[0]->returnAddress    = RUTS28;
    frames[1]->frameSize        = BTIT1DStackImpact;
    frames[1]->returnAddress    = BTIT1D;
   
    return;
}

/* basic architecture of a spoofer */
__attribute__((naked)) PVOID fourArgAsmCall(
    DWORD64 arg1,                           // [rsp + 0x00]
    DWORD64 arg2,                           // [rsp + 0x08]
    DWORD64 arg3,                           // [rsp + 0x10]
    DWORD64 arg4,                           // [rsp + 0x18]
    DWORD64 functionPointer,                // [rsp + 0x20]
    PFRAME_INFO frameInfo                   // [rsp + 0x28]

) {
    asm(
        // we need to save r14, r15, rdi, and the original stack pointer
        "push r14\n" 	   // save r14
        "push r15\n" 	   // save r15
        "push rdi\n" 	   // save rdi	  
        "mov rdi, rsp\n"   // save original rsp
        
        // bring rsp back to before we pushed 3 regs on it
        "add rsp, 0x18\n" 
        "pop rax\n"
        
        // ---  
        
        "mov r10, rsp\n"    // hold spoofed rsp in r10 so we can still use rsp to access arguments
        "sub r10, 0x3000\n" // make tons of space for frames
        
        // truncate the stack
        "xor r11, r11\n"
        "mov [r10], r11\n"
        
        // ---
        
        "mov r11, [rsp + 0x28]\n" // make r11 to point to PFRAME_INFO	
        "mov r11, [r11]\n" // dereference makes it point to FRAME_INFO array
        
        // create frame space
        "sub r10, [r11]\n"
        "sub r10, 0x8\n"
        
        // move r11 to point to address of return address
        "add r11, 0x8\n"
        
        // move the return address onto our fake stack
        "mov r14, [r11]\n"
        "mov [r10], r14\n"
        
        // ---
        
        // move r11 to point to size of next stack frame
        "add r11, 0x8\n"
        
        // create frame space	
        "sub r10, [r11]\n"
        "sub r10, 0x8\n"
        
        // move r11 to point to address of return address of stack frame
        "add r11, 0x8\n"
        
        // move the return address onto our fake stack
        "mov r14, [r11]\n"
        "mov [r10], r14\n"
        
        // ---
        
        "mov r15, [rsp + 0x20]\n" // grab location to jump to before clobbering rsp
        "mov rsp, r10\n" // use spoofed stack
        "jmp r15\n" // execute
    );
}

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    
    /*
    mov rsp, rdi
    pop rdi
    pop r15
    pop r14
    ret
    */

    printf("[+] exception raised\n");

    PCONTEXT context = pExceptionInfo->ContextRecord;

    // 1. mov rsp, rdi
    context->Rsp = context->Rdi;

    // 2. pop rdi
    context->Rdi = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 3. pop r15
    context->R15 = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 4. pop r14
    context->R14 = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 5. ret
    context->Rip = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    printf("[+] stack spoofing undone\n");
    printf("[+] continuing execution\n");

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {

    printf("[+] starting...\n");

    PVOID handler = AddVectoredExceptionHandler(1, VectoredHandler);
    
    if (!handler) {
        printf("[-] failed to add VEH\n");
        return 1;
    }

    printf("[+] added VEH\n");

    FRAME_INFO framesData[2] = { {0}, {0} };
    PFRAME_INFO frames[2] = { &framesData[0], &framesData[1] };
    populateFrames(frames);
    
    printf("[+] frame return address: %p\n", frames[1]->returnAddress);

    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = (DWORD64)frames[1]->returnAddress;
    context.Dr7 |= 1;            // Enable local breakpoint 0 (DR0)
    context.Dr7 &= ~(3 << 16);   // R/W0 = 00b -> execution
    context.Dr7 &= ~(3 << 18);   // LEN0 = 00b -> 1 byte (ignored for execution)

    HANDLE hCurrentThread = GetCurrentThread();
    if (!SetThreadContext(hCurrentThread, &context)) {
        printf("[-] failed applying hwbp\n");
        return 1;
    }

    printf("[+] applied hwbp at: %p\n", frames[1]->returnAddress);

    HANDLE hKernel32 = GetModuleHandle("kernel32.dll");
    PVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");

    printf("[+] starting spoofed function call\n");
    PVOID ptr = fourArgAsmCall(
        (DWORD64)0x0,                      
        (DWORD64)0x1000,                     
        (DWORD64)MEM_COMMIT | MEM_RESERVE,  
        (DWORD64)PAGE_EXECUTE_READWRITE,            
        (DWORD64)pVirtualAlloc,
        (PFRAME_INFO)frames
    );

    printf("[*] completed spoofed function call\n");
    printf("ptr: %p\n", ptr);

    // just wait to exit
    char buf[64];
    gets(buf);
    
    return 0;
}
