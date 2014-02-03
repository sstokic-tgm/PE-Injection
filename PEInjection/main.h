#ifndef __MAIN_H__
#define __MAIN_H__

#define NT_SUCCESS(x) ((x) >= 0)

/* The CLIENT_ID structure contains identifiers of a process and a thread */
typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID,*PCLIENT_ID;

/* The UNICODE_STRING structure is used to pass Unicode strings */
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* MSDN-Quote:
   The OBJECT_ATTRIBUTES structure specifies attributes that can be applied to objects or object handles by routines 
   that create objects and/or return handles to objects.
   Use the InitializeObjectAttributes macro to initialize the members of the OBJECT_ATTRIBUTES structure. 
   Note that InitializeObjectAttributes initializes the SecurityQualityOfService member to NULL. If you must specify a non-NULL value, 
   set the SecurityQualityOfService member after initialization */
typedef struct _OBJECT_ATTRIBUTES 
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS (NTAPI *_RtlCreateUserThread)(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PCLIENT_ID ClientID);
typedef PIMAGE_NT_HEADERS (NTAPI *_RtlImageNtHeader)(PVOID ModuleAddress);
typedef NTSTATUS (NTAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS (NTAPI *_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
typedef NTSTATUS (NTAPI *_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS (NTAPI *_NtClose)(HANDLE ObjectHandle);
typedef NTSTATUS (NTAPI *_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

/* Returns the process id of the specified process name */
DWORD GetProcID(std::string ProcName);
/* Function we gonna inject in a process */
DWORD WINAPI FuncThread(LPVOID unused);
/* Check if the specified process is running/existing */
BOOL ProcessExists(std::string process);
/* Returns the address of the specified library */
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
///----------------------------------------------------------------------///

#endif