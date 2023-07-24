val = 0x1505
APIstrings = ["NtGetContextThread", "RtlAddVectoredExceptionHandler", "NtAllocateVirtualMemory", "DbgUIRemoteBreakIn", "LdrLoadDll", "DbgBreakPoint", "EnumWindows", "NtSetInformationThread", "ZwSetInformationThread", "TerminateProcess", "ExitProcess", "NtSetContextThread", "NtWriteVirtualMemory", "NtCreateSection", "NtMapViewOfSection", "NtOpenFile", "NtSetInformationProcess", "NtClose",
             "NtResumeThread", "NtProtectVirtualMemory", "CreateProcessInternal", "GetLongPathNameW", "Sleep", "NtCreateThreadEx", "WaitForSingleObject", "TerminateThread", "CreateFileW", "WriteFile","ReadFile","ShellExecuteW",
             "RegCreateKeyExA","RegSetValueExA", "NtQueryInformationProcess", "InternetOpenA", "InternetSetOptionA", "InternetOpenUrlA", "InternetReadFile", "InternetCloseHandle"]

for APIstring in APIstrings:
    val  = 0x1505
    for ch in instring:
        val += ((val <<5))
        val &= 0xFFFFFFFF
        val += ord(ch)
        val &= 0xFFFFFFFF
        val ^= 0x8131A1
    print(APIstring+" :  "+hex(val))


    
            
