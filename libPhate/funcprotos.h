/**
typedefs for all the functions we are getting using GetProcAddress
taken from MSDN
**/
typedef HMODULE (WINAPI *LoadLibraryEx_t)(LPCWSTR, HANDLE,DWORD);
typedef HANDLE (WINAPI *OpenProcess_t)(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId);
typedef BOOL (WINAPI *EnumProcesses_t)(DWORD *pProcessIds, DWORD cb,DWORD *pBytesReturned);
typedef DWORD (WINAPI *GetProcessImageFileName_t)( _In_   HANDLE hProcess,  _Out_  LPWSTR lpImageFileName,  _In_   DWORD nSize);
typedef DWORD (WINAPI *GetNamedSecurityInfo_t)(
  _In_       LPWSTR pObjectName,
  _In_       SE_OBJECT_TYPE ObjectType,
  _In_       SECURITY_INFORMATION SecurityInfo,
  _Out_opt_  PSID *ppsidOwner,
  _Out_opt_  PSID *ppsidGroup,
  _Out_opt_  PACL *ppDacl,
  _Out_opt_  PACL *ppSacl,
  _Out_opt_  PSECURITY_DESCRIPTOR *ppSecurityDescriptor
);

typedef BOOL (WINAPI *MakeAbsoluteSD_t)(
  _In_       PSECURITY_DESCRIPTOR pSelfRelativeSD,
  _Out_opt_  PSECURITY_DESCRIPTOR pAbsoluteSD,
  _Inout_    LPDWORD lpdwAbsoluteSDSize,
  _Out_opt_  PACL pDacl,
  _Inout_    LPDWORD lpdwDaclSize,
  _Out_opt_  PACL pSacl,
  _Inout_    LPDWORD lpdwSaclSize,
  _Out_opt_  PSID pOwner,
  _Inout_    LPDWORD lpdwOwnerSize,
  _Out_opt_  PSID pPrimaryGroup,
  _Inout_    LPDWORD lpdwPrimaryGroupSize
);

typedef BOOL (WINAPI *AddAccessAllowedAce_t)(
  _Inout_  PACL pAcl,
  _In_     DWORD dwAceRevision,
  _In_     DWORD AccessMask,
  _In_     PSID pSid
);

typedef BOOL (WINAPI *ConvertStringSidToSid_t)(
  _In_   LPCSTR StringSid,
  _Out_  PSID *Sid
);

typedef BOOL (WINAPI *LookupAccountName_t)(
  _In_opt_   LPCTSTR lpSystemName,
  _In_       LPCTSTR lpAccountName,
  _Out_opt_  PSID Sid,
  _Inout_    LPDWORD cbSid,
  _Out_opt_  LPTSTR ReferencedDomainName,
  _Inout_    LPDWORD cchReferencedDomainName,
  _Out_      PSID_NAME_USE peUse
);

typedef DWORD (WINAPI *SetNamedSecurityInfo_t)(
  _In_      LPTSTR pObjectName,
  _In_      SE_OBJECT_TYPE ObjectType,
  _In_      SECURITY_INFORMATION SecurityInfo,
  _In_opt_  PSID psidOwner,
  _In_opt_  PSID psidGroup,
  _In_opt_  PACL pDacl,
  _In_opt_  PACL pSacl
);


typedef LONG (WINAPI *RegGetKeySecurity_t)(
  _In_       HKEY hKey,
  _In_       SECURITY_INFORMATION SecurityInformation,
  _Out_opt_  PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _Inout_    LPDWORD lpcbSecurityDescriptor
);

typedef BOOL (WINAPI *GetSecurityDescriptorDacl_t)(
  _In_   PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _Out_  LPBOOL lpbDaclPresent,
  _Out_  PACL *pDacl,
  _Out_  LPBOOL lpbDaclDefaulted
);

typedef DWORD (WINAPI *GetExplicitEntriesFromAcl_t)(
  _In_   PACL pacl,
  _Out_  PULONG pcCountOfExplicitEntries,
  _Out_  PEXPLICIT_ACCESS *pListOfExplicitEntries
);

typedef HLOCAL (WINAPI *LocalFree_t)(
  _In_  HLOCAL hMem
);

typedef HANDLE (WINAPI *FindFirstFile_t)(_In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATA lpFindFileData);
typedef BOOL (WINAPI *FindNextFile_t)( _In_   HANDLE hFindFile, _Out_  LPWIN32_FIND_DATA lpFindFileData);
typedef BOOL (WINAPI *FindClose_t)(_Inout_  HANDLE hFindFile);

typedef DWORD (WINAPI *GetCurrentDirectory_t)(  _In_   DWORD nBufferLength, _Out_  LPWSTR lpBuffer);
typedef bool (WINAPI *SetCurrentDirectory_t)( _In_  LPCWSTR lpPathName);


typedef NTSTATUS (__stdcall *RtlGetAce_t)(
  _In_   PACL Acl,
  _In_   ULONG AceIndex,
  _Out_  PVOID *Ace
);

typedef BOOL (__stdcall *ConvertSidToStringSid_t)(
  _In_   PSID Sid,
  _Out_  LPSTR *StringSid
);

typedef BOOL (WINAPI *LookupAccountSid_t)(
  _In_opt_   LPCWSTR lpSystemName,
  _In_       PSID lpSid,
  _Out_opt_  LPWSTR lpName,
  _Inout_    LPDWORD cchName,
  _Out_opt_  LPWSTR lpReferencedDomainName,
  _Inout_    LPDWORD cchReferencedDomainName,
  _Out_      PSID_NAME_USE peUse
);

typedef BOOL (WINAPI *CreateProcess_t)(
  _In_opt_     LPCWSTR lpApplicationName,
  _Inout_opt_  LPWSTR lpCommandLine,
  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_         BOOL bInheritHandles,
  _In_         DWORD dwCreationFlags,
  _In_opt_     LPVOID lpEnvironment,
  _In_opt_     LPCWSTR lpCurrentDirectory,
  _In_         LPSTARTUPINFO lpStartupInfo,
  _Out_        LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOLEAN (WINAPI *CreateSymbolicLink_t)(
  _In_  LPTSTR lpSymlinkFileName,
  _In_  LPTSTR lpTargetFileName,
  _In_  DWORD dwFlags
);

typedef DWORD (WINAPI *GetLogicalDriveStrings_t)(
  _In_   DWORD nBufferLength,
  _Out_  LPTSTR lpBuffer
);


//tower of typedefs, used for rundll
#define MAX_ARGS 12
typedef void* (*nullary_t) (void);
typedef void* (*unary_t) (void*);
typedef void* (*binary_t) (void*, void*);
typedef void* (*ternary_t) (void*, void*, void*);
typedef void* (*quaternary_t) (void*, void*, void*, void*);
typedef void* (*quinary_t) (void*, void*, void*, void*, void*);
typedef void* (*senary_t) (void*, void*, void*, void*, void*, void*);
typedef void* (*septenary_t) (void*, void*, void*, void*, void*, void*, void*);
typedef void* (*octonary_t) (void*, void*, void*, void*, void*, void*, void*, void*);
typedef void* (*novenary_t) (void*, void*, void*, void*, void*, void*, void*, void*, void*);
typedef void* (*denary_t) (void*, void*, void*, void*, void*, void*, void*, void*, void*, void*);
typedef void* (*undenary_t) (void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*);
typedef void* (*duodenary_t) (void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*);

typedef HANDLE (*RegisterEventSource_t)(
  _In_  LPCWSTR lpUNCServerName,
  _In_  LPCWSTR lpSourceName
);
typedef BOOL (*GetEventLogInformation_t)(
  _In_   HANDLE hEventLog,
  _In_   DWORD dwInfoLevel,
  _Out_  LPVOID lpBuffer,
  _In_   DWORD cbBufSize,
  _Out_  LPDWORD pcbBytesNeeded
);
typedef BOOL (*DeregisterEventSource_t)(
  _Inout_  HANDLE hEventLog
);

typedef BOOL (WINAPI *OpenProcessToken_t)(
  _In_   HANDLE ProcessHandle,
  _In_   DWORD DesiredAccess,
  _Out_  PHANDLE TokenHandle
);

typedef BOOL (WINAPI *GetTokenInformation_t)(
  _In_       HANDLE TokenHandle,
  _In_       TOKEN_INFORMATION_CLASS TokenInformationClass,
  _Out_opt_  LPVOID TokenInformation,
  _In_       DWORD TokenInformationLength,
  _Out_      PDWORD ReturnLength
);

typedef BOOL (WINAPI *LookupPrivilegeName_t)(
  _In_opt_   LPCWSTR lpSystemName,
  _In_       PLUID lpLuid,
  _Out_opt_  LPWSTR lpName,
  _Inout_    LPDWORD cchName
);

typedef BOOL (WINAPI *VirtualFree_t)(
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD dwFreeType
);

typedef LPVOID (WINAPI *VirtualAlloc_t)(
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
);

typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
  _In_       ULONG SystemInformationClass, //changed from SYSTEM_INFORMATION_CLASS to ULONG
  _Inout_    PVOID SystemInformation,
  _In_       ULONG SystemInformationLength,
  _Out_opt_  PULONG ReturnLength
);


typedef HANDLE (WINAPI *OpenProcess_t)(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  DWORD dwProcessId
);


typedef NTSTATUS (NTAPI *NtDuplicateObject_t)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS (NTAPI *NtQueryObject_t)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );
 
typedef BOOL (WINAPI *GetProcessMitigationPolicy_t)(
  _In_   HANDLE hProcess,
  _In_   PROCESS_MITIGATION_POLICY MitigationPolicy,
  _Out_  PVOID lpBuffer,
  _In_   SIZE_T dwLength
);

typedef SIZE_T (WINAPI *VirtualQueryEx_t)(
  _In_      HANDLE hProcess,
  _In_opt_  LPCVOID lpAddress,
  _Out_     PMEMORY_BASIC_INFORMATION lpBuffer,
  _In_      SIZE_T dwLength
);

typedef LONG (WINAPI *RegGetValue_t)(
  _In_         HKEY hkey,
  _In_opt_     LPCTSTR lpSubKey,
  _In_opt_     LPCTSTR lpValue,
  _In_opt_     DWORD dwFlags,
  _Out_opt_    LPDWORD pdwType,
  _Out_opt_    PVOID pvData,
  _Inout_opt_  LPDWORD pcbData
);


typedef LONG (WINAPI *RegOpenKeyEx_t)(
  _In_        HKEY hKey,
  _In_opt_    LPCTSTR lpSubKey,
  _Reserved_  DWORD ulOptions,
  _In_        REGSAM samDesired,
  _Out_       PHKEY phkResult
);


typedef LONG (WINAPI *RegSetValueEx_t)(
  _In_        HKEY hKey,
  _In_opt_    LPCTSTR lpValueName,
  _Reserved_  DWORD Reserved,
  _In_        DWORD dwType,
  _In_        const BYTE *lpData,
  _In_        DWORD cbData
);


typedef LONG (WINAPI *RegCloseKey_t)(
  _In_  HKEY hKey
);

typedef LONG (WINAPI *RegDeleteValue_t)(
  _In_      HKEY hKey,
  _In_opt_  LPCTSTR lpValueName
);

typedef LONG (WINAPI *RegDeleteTree_t)(
  _In_      HKEY hKey,
  _In_opt_  LPCTSTR lpSubKey
);

typedef LONG (WINAPI *RegDeleteKey_t)(
  _In_  HKEY hKey,
  _In_  LPCTSTR lpSubKey
);

typedef LONG (WINAPI *RegCreateKeyEx_t)(
  _In_        HKEY hKey,
  _In_        LPCTSTR lpSubKey,
  _Reserved_  DWORD Reserved,
  _In_opt_    LPTSTR lpClass,
  _In_        DWORD dwOptions,
  _In_        REGSAM samDesired,
  _In_opt_    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _Out_       PHKEY phkResult,
  _Out_opt_   LPDWORD lpdwDisposition
);

typedef LONG (WINAPI *RegQueryInfoKey_t)(
  _In_         HKEY hKey,
  _Out_opt_    LPTSTR lpClass,
  _Inout_opt_  LPDWORD lpcClass,
  _Reserved_   LPDWORD lpReserved,
  _Out_opt_    LPDWORD lpcSubKeys,
  _Out_opt_    LPDWORD lpcMaxSubKeyLen,
  _Out_opt_    LPDWORD lpcMaxClassLen,
  _Out_opt_    LPDWORD lpcValues,
  _Out_opt_    LPDWORD lpcMaxValueNameLen,
  _Out_opt_    LPDWORD lpcMaxValueLen,
  _Out_opt_    LPDWORD lpcbSecurityDescriptor,
  _Out_opt_    PFILETIME lpftLastWriteTime
);

typedef LONG (WINAPI *RegEnumValue_t)(
  _In_         HKEY hKey,
  _In_         DWORD dwIndex,
  _Out_        LPTSTR lpValueName,
  _Inout_      LPDWORD lpcchValueName,
  _Reserved_   LPDWORD lpReserved,
  _Out_opt_    LPDWORD lpType,
  _Out_opt_    LPBYTE lpData,
  _Inout_opt_  LPDWORD lpcbData
);

typedef LONG (WINAPI *RegEnumKeyEx_t)(
  _In_         HKEY hKey,
  _In_         DWORD dwIndex,
  _Out_        LPTSTR lpName,
  _Inout_      LPDWORD lpcName,
  _Reserved_   LPDWORD lpReserved,
  _Inout_      LPTSTR lpClass,
  _Inout_opt_  LPDWORD lpcClass,
  _Out_opt_    PFILETIME lpftLastWriteTime
);

typedef BOOL (WINAPI *TerminateProcess_t)(
  _In_  HANDLE hProcess,
  _In_  UINT uExitCode
);

typedef LPTSTR (WINAPI *GetCommandLine_t)(void);

typedef DWORD (WINAPI *GetEnvironmentVariable_t)(
  _In_opt_   LPCTSTR lpName,
  _Out_opt_  LPTSTR lpBuffer,
  _In_       DWORD nSize
);

typedef BOOL (WINAPI *SetEnvironmentVariable_t)(
  _In_      LPCTSTR lpName,
  _In_opt_  LPCTSTR lpValue
);