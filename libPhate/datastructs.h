/**
various data types and structs

mostly copied from MSDN
some are copied from windows header files

**/


//from msdn
typedef enum _SE_OBJECT_TYPE { 
  SE_UNKNOWN_OBJECT_TYPE      = 0,
  SE_FILE_OBJECT,
  SE_SERVICE,
  SE_PRINTER,
  SE_REGISTRY_KEY,
  SE_LMSHARE,
  SE_KERNEL_OBJECT,
  SE_WINDOW_OBJECT,
  SE_DS_OBJECT,
  SE_DS_OBJECT_ALL,
  SE_PROVIDER_DEFINED_OBJECT,
  SE_WMIGUID_OBJECT,
  SE_REGISTRY_WOW64_32KEY
} SE_OBJECT_TYPE;

typedef enum _ACCESS_MODE { 
  NOT_USED_ACCESS    = 0,
  GRANT_ACCESS,
  SET_ACCESS,
  DENY_ACCESS,
  REVOKE_ACCESS,
  SET_AUDIT_SUCCESS,
  SET_AUDIT_FAILURE
} ACCESS_MODE;

typedef enum _TRUSTEE_FORM { 
  TRUSTEE_IS_SID,
  TRUSTEE_IS_NAME,
  TRUSTEE_BAD_FORM,
  TRUSTEE_IS_OBJECTS_AND_SID,
  TRUSTEE_IS_OBJECTS_AND_NAME
} TRUSTEE_FORM;

typedef enum _MULTIPLE_TRUSTEE_OPERATION { 
  NO_MULTIPLE_TRUSTEE,
  TRUSTEE_IS_IMPERSONATE
} MULTIPLE_TRUSTEE_OPERATION;

typedef enum _TRUSTEE_TYPE { 
  TRUSTEE_IS_UNKNOWN,
  TRUSTEE_IS_USER,
  TRUSTEE_IS_GROUP,
  TRUSTEE_IS_DOMAIN,
  TRUSTEE_IS_ALIAS,
  TRUSTEE_IS_WELL_KNOWN_GROUP,
  TRUSTEE_IS_DELETED,
  TRUSTEE_IS_INVALID,
  TRUSTEE_IS_COMPUTER
} TRUSTEE_TYPE;


typedef struct _TRUSTEE {
  struct _TRUSTEE*           pMultipleTrustee;
  MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
  TRUSTEE_FORM               TrusteeForm;
  TRUSTEE_TYPE               TrusteeType;
  LPTSTR                     ptstrName;
} TRUSTEE, *PTRUSTEE;


typedef struct _EXPLICIT_ACCESS {
  DWORD       grfAccessPermissions;
  ACCESS_MODE grfAccessMode;
  DWORD       grfInheritance;
  TRUSTEE     Trustee;
} EXPLICIT_ACCESS, *PEXPLICIT_ACCESS;



//from processsthreadsapi.h (because of ifdefs prevent them being included)
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _STARTUPINFOA {
    DWORD   cb;
    LPSTR   lpReserved;
    LPSTR   lpDesktop;
    LPSTR   lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _STARTUPINFOW {
    DWORD   cb;
    LPWSTR  lpReserved;
    LPWSTR  lpDesktop;
    LPWSTR  lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

#ifdef UNICODE
typedef STARTUPINFOW STARTUPINFO;
typedef LPSTARTUPINFOW LPSTARTUPINFO;
#else
typedef STARTUPINFOA STARTUPINFO;
typedef LPSTARTUPINFOA LPSTARTUPINFO;
#endif // UNICODE

// Changed to signed int32, so that the NT_SUCCESS macro works.
typedef  int32 NTSTATUS;

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
 
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
const PWSTR GarbageData = (PWSTR)0xcdcdcdcd;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
 
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
 
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
 
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

//from winnt.h (typedefs prevent them from being included)
#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400     

#define RRF_RT_REG_BINARY 0x00000008
#define RRF_RT_REG_MULTI_SZ 0x00000020
#define RRF_RT_DWORD 0x00000018
#define RRF_RT_REG_SZ 0x00000002
#define RRF_RT_ANY 0x0000ffff
#define RRF_RT_QWORD 0x00000048

#define HKEY_CLASSES_ROOT	((HKEY)0x80000000)
#define HKEY_CURRENT_USER	((HKEY)0x80000001)
#define HKEY_LOCAL_MACHINE	((HKEY)0x80000002)
#define HKEY_USERS	((HKEY)0x80000003)
#define HKEY_PERFORMANCE_DATA	((HKEY)0x80000004)
#define HKEY_CURRENT_CONFIG	((HKEY)0x80000005)
#define HKEY_DYN_DATA	((HKEY)0x80000006)

extern PCWSTR REG_ROOTS[];
typedef long LSTATUS; //XXX: shoud this be ULONG?
typedef ULONG REGSAM; 
#define RootName(KEY) (REG_ROOTS[((uint32)KEY) & 0xF])

enum RegCreateOrOpenKey
{
	RCOOK_DONT_CARE,
	RCOOK_CREATE_NEW,
	RCOOK_OPEN_EXISTING
};

enum class RegistryType
{
	None = REG_NONE,
	String = REG_SZ,
	VariableString = REG_EXPAND_SZ,
	Binary = REG_BINARY,
	Integer = REG_DWORD,
	IntegerBigEndian = REG_DWORD_BIG_ENDIAN,
	SymbolicLink = REG_LINK,
	MultiString = REG_MULTI_SZ,
	ResourceList = REG_RESOURCE_LIST,
	HardwareResourceLIst = REG_FULL_RESOURCE_DESCRIPTOR,
	ResourceRequirement = REG_RESOURCE_REQUIREMENTS_LIST,
	Long = REG_QWORD
};

enum class RegistryHive
{
	HKCR = (int) HKEY_CLASSES_ROOT,
	HKCU = (int) HKEY_CURRENT_USER,
	HKLM = (int) HKEY_LOCAL_MACHINE,
	HKU = (int) HKEY_USERS,
	HKPD = (int) HKEY_PERFORMANCE_DATA,
	HKCC = (int) HKEY_CURRENT_CONFIG
};

