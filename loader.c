#define _AMD64_
#include <ddk/ntifs.h>

// Manually define the prototype so GCC knows how to call it
NTSYSCALLAPI NTSTATUS NTAPI ZwLoadKey(
    _In_ POBJECT_ATTRIBUTES KeyAttributes,
    _In_ POBJECT_ATTRIBUTES FileAttributes
);

NTSTATUS MountCustomHive() {
    OBJECT_ATTRIBUTES destKey;
    OBJECT_ATTRIBUTES sourceFile;
    UNICODE_STRING destPath;
    UNICODE_STRING filePath;

    RtlInitUnicodeString(&destPath, L"\\Registry\\Machine\\KERNELCONFIG");
    InitializeObjectAttributes(&destKey, &destPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    RtlInitUnicodeString(&filePath, L"\\??\\C:\\Windows\\System32\\KERNELCONFIG");
    InitializeObjectAttributes(&sourceFile, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwLoadKey(&destKey, &sourceFile);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = MountCustomHive();

    // Success / Already Loaded
    if (NT_SUCCESS(status) || status == (NTSTATUS)0xC000010E || status == (NTSTATUS)0xC0000035) {
        return STATUS_SUCCESS;
    }

    // Not Found (0xC000000F) -> REGISTRY_ERROR (0x51)
    if (status == (NTSTATUS)0xC000000F || status == (NTSTATUS)0xC000003A) {
        KeBugCheckEx(0x51, 1, 0, 0, 0);
    }

    // Locked/Access Denied (0xC0000022) -> CRITICAL_PROCESS_DIED (0xEF)
    if (status == (NTSTATUS)0xC0000022 || status == (NTSTATUS)0xC0000043) {
        KeBugCheckEx(0xEF, 2, 0, 0, 0);
    }

    // Fallback BSOD
    KeBugCheckEx(0x51, 3, (ULONG_PTR)status, 0, 0);

    return status;
}
