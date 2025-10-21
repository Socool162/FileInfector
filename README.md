Folder 1: B3_FileInfect_Lamvd have code virus (infectFile_Success.asm) and file virus compiled (infectFile_Success.exe). 

Folder 2: test just have file 32bit infected that I tested before. You can check their sections (.infect) in CFF Explorer. 

Folder 3: test1 have clean original file (.exe) that I use to test. In CFF Explorer, their files have not .inject section.

Note:

- I custome " search_path     db "L:\test\*.*",0  and base_path       db "L:\test\",0 "... So if you test in C:\test, just change L to C.
- Dont test while openning file "fileInfect_Success.exe" in x32dbg (breakpoint will cause error)
