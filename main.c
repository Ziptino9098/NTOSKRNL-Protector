#include <ntifs.h>

// Prototypes
NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING* ImageName);
NTSYSCALLAPI NTSTATUS NTAPI ZwLoadKey(POBJECT_ATTRIBUTES KeyAttributes, POBJECT_ATTRIBUTES FileAttributes);

// Global Handles
HANDLE g_NtosHandle = NULL;
HANDLE g_HalHandle = NULL;
BOOLEAN g_TerminateThread = FALSE;

// Helper to read QWORD (64-bit)
ULONGLONG ReadConfigQword(PCWSTR ValueName) {
    UNICODE_STRING keyPath, valName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hKey;
    ULONGLONG result = 0;

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\KERNELCONFIG\\Drivers\\SystemProtector");
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_READ, &objAttr))) {
        RtlInitUnicodeString(&valName, ValueName);
        PKEY_VALUE_PARTIAL_INFORMATION kvpi;
        ULONG size = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONGLONG);
        kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, size, 'regt');

        if (kvpi) {
            if (NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvpi, size, &size))) {
                if (kvpi->Type == REG_QWORD) result = *(PULONGLONG)kvpi->Data;
            }
            ExFreePool(kvpi);
        }
        ZwClose(hKey);
    }
    return result;
}

// Heartbeat Thread: Manages Locks in Real-Time
void HeartbeatThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    while (!g_TerminateThread) {
        LARGE_INTEGER interval;
        interval.QuadPart = -50000000; // 5 seconds

        // Toggle NTOS Lock
        if (ReadConfigQword(L"LockNtoskrnl.exe") == 1 && g_NtosHandle == NULL) {
            UNICODE_STRING path;
            OBJECT_ATTRIBUTES attr;
            IO_STATUS_BLOCK io;
            RtlInitUnicodeString(&path, L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe");
            InitializeObjectAttributes(&attr, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            ZwCreateFile(&g_NtosHandle, GENERIC_READ, &attr, &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
        }
        else if (ReadConfigQword(L"LockNtoskrnl.exe") == 0 && g_NtosHandle != NULL) {
            ZwClose(g_NtosHandle);
            g_NtosHandle = NULL;
        }

        // Toggle HAL Lock
        if (ReadConfigQword(L"LockHal.dll") == 1 && g_HalHandle == NULL) {
            UNICODE_STRING path;
            OBJECT_ATTRIBUTES attr;
            IO_STATUS_BLOCK io;
            RtlInitUnicodeString(&path, L"\\??\\C:\\Windows\\System32\\hal.dll");
            InitializeObjectAttributes(&attr, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            ZwCreateFile(&g_HalHandle, GENERIC_READ, &attr, &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
        }
        else if (ReadConfigQword(L"LockHal.dll") == 0 && g_HalHandle != NULL) {
            ZwClose(g_HalHandle);
            g_HalHandle = NULL;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo == NULL) {
        PUNICODE_STRING procName = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(Process, &procName))) {
            if (procName->Buffer != NULL) {
                if (wcsstr(procName->Buffer, L"lsass.exe") && ReadConfigQword(L"CrashOnLSATermination") == 1) KeBugCheck(0xEF);
                if (wcsstr(procName->Buffer, L"winlogon.exe") && ReadConfigQword(L"CrashOnWinlogonTermination") == 1) KeBugCheck(0xEF);
                if (wcsstr(procName->Buffer, L"explorer.exe") && ReadConfigQword(L"CrashOnExplorerTermination") == 1) KeBugCheck(0xEF);
            }
            if (procName) ExFreePool(procName);
        }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = NULL; // Keep it unstoppable

    HANDLE hThread;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, HeartbeatThread, NULL);
    ZwClose(hThread);

    return PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
}
