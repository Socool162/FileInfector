;Compile:       ml /c /Zd /coff findFiles_Demo.asm 
;       link findFiles_Demo.obj /subsystem:console
;           Run:        findFiles_Demo.exe

.386
.MODEL flat, stdcall
OPTION CASEMAP:NONE

; Thêm các file .inc để sử dụng các hằng số và cấu trúc
INCLUDE windows.inc
INCLUDE kernel32.inc
INCLUDE user32.inc
INCLUDE shlwapi.inc ; Cần cho hàm PathFindFileName

; Thêm các file .lib để linker tự động tìm
INCLUDELIB kernel32.lib
INCLUDELIB user32.lib
INCLUDELIB shlwapi.lib


.data
    search_path     db "L:\test\*.*", 0
    base_path       db "L:\test\", 0
    newline         db 0Dh, 0Ah
    hConsoleOut     HANDLE ?
    bytesWritten    DWORD ?

.data? ; Uninitialized data section
    find_data       WIN32_FIND_DATA <>
    full_path       db MAX_PATH dup(?)

.code
start:
    ; Lay handle cua console
    push    STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     hConsoleOut, eax

    ; Bat dau tim file
    lea     eax, find_data
    push    eax
    push    offset search_path
    call    FindFirstFileA

    cmp     eax, INVALID_HANDLE_VALUE
    je      _exit
    mov     esi, eax ; Luu find handle

find_loop:
    ; Xay dung duong dan day du
    lea     edi, full_path
    push    offset base_path
    push    edi
    call    lstrcpyA

    lea     eax, find_data.cFileName
    push    eax
    push    edi
    call    lstrcatA

    ; In ra man hinh
    push    offset bytesWritten
    push    0
    ; Tinh toan do dai chuoi de in cho chinh xac
    push    edi ; Dia chi buffer
    call    lstrlenA ; EAX = do dai chuoi
    
    lea     edi, full_path
    push    eax ; So byte can in
    push    edi ; Con tro den chuoi
    push    hConsoleOut
    call    WriteConsoleA

    ; In them ky tu xuong dong
    push    offset bytesWritten
    push    0
    push    SIZEOF newline
    push    offset newline
    push    hConsoleOut
    call    WriteConsoleA

    ; Tim file tiep theo
    lea     eax, find_data
    push    eax
    push    esi
    call    FindNextFileA
    test    eax, eax
    jnz     find_loop

    ; Dong find handle
    push    esi
    call    CloseHandle

_exit:
    push    0
    call    ExitProcess

End start