#pragma once
#include <windows.h>
#include <string>
#include <collection.h>



#define BUF_SIZE 1024
#define BIG_BUFFER_SIZE 1024 * 1024




PCWSTR REG_ROOTS[] = {
		L"HKEY_CLASSES_ROOT",
		L"HKEY_CURRENT_USER",
		L"HKEY_LOCAL_MACHINE",
		L"HKEY_USERS",
		L"HKEY_PERFORMANCE_DATA",
		L"HKEY_CURRENT_CONFIG"};


//code from GoodDayToDie's project

ref class RegistryKey sealed
{
private:
	static RegistryKey ^HKCR;
	static RegistryKey ^HKCU;
	static RegistryKey ^HKLM;
	static RegistryKey ^HKU;
	static RegistryKey ^HKPD;
	static RegistryKey ^HKCC;
	HKEY _root;
	Platform::String ^_path;
	Platform::String ^_name;
	Platform::String ^_fullname;
	RegistryKey (HKEY hkey, Platform::String ^path, Platform::String ^name);
	static RegistryKey^ GetRootKey (RegistryHive hive);
	RegistryKey (RegistryHive hive, Platform::String ^path);

public:
	//  Public properties
	property Platform::String^ Name { Platform::String^ get (); }
	property Platform::String^ Path { Platform::String^ get (); }
	property Platform::String^ FullName { Platform::String^ get (); }
	// Static readonly root keys
	static property RegistryKey ^HKeyClassesRoot { RegistryKey ^get(); }
	static property RegistryKey ^HKeyCurrentUser { RegistryKey ^get(); }
	static property RegistryKey ^HKeyLocalMachine { RegistryKey ^get(); }
	static property RegistryKey ^HKeyUsers { RegistryKey ^get(); }
	static property RegistryKey ^HKeyPerformanceData { RegistryKey ^get(); }
	static property RegistryKey ^HKeyCurrentConfig { RegistryKey ^get(); }
};

ref class RegistryValue sealed
{
	Platform::String ^_name;
	Platform::String ^_fullpath;
	RegistryKey ^_key;
	RegistryType _type;
	Object ^_data;
};

enum class MoveFlags : uint32
{
		None = 0,
		ReplaceExisting = MOVEFILE_REPLACE_EXISTING,
		AcrossVolumes = MOVEFILE_COPY_ALLOWED,
		DelayUntilReboot = MOVEFILE_DELAY_UNTIL_REBOOT,
		WriteThroughBeforeReturn = MOVEFILE_WRITE_THROUGH,
		FailIfDestinationLosesLinks = MOVEFILE_FAIL_IF_NOT_TRACKABLE
};

#define STDREGARGS Platform::String^ sHive, Platform::String ^path, Platform::String ^value

#define HIVECONVERT RegistryHive hive = stringToRegistryHive(sHive);

//end code from GoodDayToDie


namespace Phate
{
	



    public ref class libPhate sealed
	{
	public:

		static bool Initialize();
		static Platform::String^ AceFlagsToString(unsigned int flags);
		static Platform::String^ AccessMaskToString(unsigned int mask);
		static uint64 GetProcAddress(uint64 module, Platform::String^ proc);
		static uint64 LoadLibrary(Platform::String^ libname, uint32 flags);
		static uint64 GetCurrentProcessId();
		static uint64 OpenProcess(uint64 id, uint64 access_desired);
		static Windows::Foundation::Collections::IVector<uint64> ^ ListProcesses();
		static Platform::String ^ GetProcessName(uint64 hproc);
		static uint64 OpenFile(Platform::String^ name, Platform::String^ mode);
		static Platform::String ^ GetCurrentDirectory();
		static Platform::String ^ ChangeDirectory(Platform::String^ path);
		static Platform::String ^ ListDirectory(Platform::String^ path, unsigned int flags);
		static int64 CreateProcess(Platform::String^ commandLine);
		static int64 libPhate::RunDLL(Platform::String^ lib, Platform::String^ func, const Platform::Array<Platform::String^>^ values, const Platform::Array<Platform::String^>^ types, int count);
		static Platform::String^ GetFilePerms(Platform::String^ path);
		static Platform::String^ libPhate::GetRegPerms(Platform::String^ path);
		static Platform::String^ libPhate::GetPerms(Platform::String^ path, int ObjectType);
		static uint64 LoadLibrary(Platform::String^ libname);
		static bool CloseFile(uint64 ptr);
		static Platform::String ^ SidToName(unsigned long long pSid);
		static uint64 OpenProcessToken(uint64 process_handle, uint64 access_desired);
		static int GetCurrentUserInfo(int flags);
		static Platform::String^ GetCurrentUserPrivileges();
		static Platform::String^ PrintCurrentUserInfo(int flags);
		static Platform::String^ GetCurrentUserGroups();
		static Platform::String^ ReadFile(Platform::String^ name, unsigned int linewrap);
		static bool BurnFree(int type, unsigned long long resource);
		static unsigned long long Burn(int type, unsigned int resource_count);
		static Platform::String^ LaunchUri(Platform::String^ target);
		static Platform::String^ LaunchFile(Platform::String^ target);
		static Platform::String^ EnumerateHandles(Platform::String^ pid);
		static Platform::String^ ProcessMitigationInfo(Platform::String^ param);
		static bool TerminateProcess(uint32 processID);
		static bool SetEnvironmentVariable(Platform::String ^name, Platform::String ^value);
		static Platform::String^ GetCommandLine();
		static Platform::String^ GetEnvironmentVariable (Platform::String ^name);
		static Platform::String^ MemoryRegions(Platform::String^ param);
		static Platform::Array<uint8>^ ReadFile (Platform::String ^path, int64 offset, uint32 length);
		static bool WriteFile (Platform::String ^path, int64 offset, const Platform::Array<uint8> ^data);
		static bool CopyFile (Platform::String ^sourceName, Platform::String ^destName);
		static bool DeleteFile (Platform::String ^path);
		static bool CreateDirectory (Platform::String ^fullpath);
		static bool DeleteDirectory (Platform::String ^fullpath);
		static bool CreateSymbolicLink (Platform::String ^target, Platform::String ^linkname, bool directory);
		static Platform::String^ ChangeOwner(Platform::String^ path, int objectType, Platform::String^ newOwner);
		static Platform::Array<Platform::String^>^ GetDriveLetters();
		static Platform::String^ ReadDWORD (STDREGARGS);
		static Platform::String^ ReadString (STDREGARGS);
		static Platform::String^ ReadMultiString (STDREGARGS);
		static Platform::String^ ReadBinary (STDREGARGS);
		static Platform::String^ ReadQWORD (STDREGARGS);
		static Platform::String^ WriteDWORD (STDREGARGS, uint32 data);
		static Platform::String^ WriteString (STDREGARGS, Platform::String ^data);
		static Platform::String^ WriteMultiString (STDREGARGS, const Platform::Array<Platform::String^> ^data);
		static Platform::String^ WriteBinary (STDREGARGS, const Platform::Array<uint8> ^data);
		static Platform::String^ WriteQWORD (STDREGARGS, uint64 data);
		static Platform::String^ DeleteValue (STDREGARGS);
		static Platform::String^ DeleteKey (Platform::String^ sHive, Platform::String ^path, bool recursive);
		static Platform::String^ CreateKey (Platform::String^ sHive, Platform::String ^path);
		static Platform::String^ GetSubKeyNames (Platform::String^ sHive, Platform::String ^path);
		static Platform::String^ GetValues (Platform::String^ sHive, Platform::String ^path);
		static Platform::String^ CanWrite (STDREGARGS);
		static Platform::String^ EnumRegKey (Platform::String^ sHive, Platform::String ^path);
		static Platform::String^ errorToString(unsigned int errcode); 
		static Platform::String^ ChangeGroup(Platform::String^ path, int objectType, Platform::String^ newGroup);
		static Platform::String^ ChangePerms(Platform::String^ path, int objectType, Platform::String^ newPerms);




	private:

		static HKEY GetHKey (HKEY base, PCWSTR path, REGSAM permission, RegCreateOrOpenKey disposition);
		static bool EnumSubKeys (HKEY key, PWSTR *names, DWORD count, DWORD maxlen); 		// Gets the names of the subkeys. Maxlen includes null terminator.
		static bool EnumValues (HKEY key, DWORD count, PWSTR *names,DWORD names_maxlen, PBYTE *vals,DWORD vals_maxlen, DWORD * types, DWORD * value_lens); 		// Gets the names of the values. Maxlen includes null terminator.
		static Platform::String^ SecurityDescriptorToString(PACL dacl, PACL sacl, PSID owner, PSID group);
		static Platform::String^ registryValueToString(PBYTE value, DWORD type, DWORD len);
		static Platform::String^ registryTypeToString(DWORD type);
		static RegistryHive stringToRegistryHive(Platform::String^ hive);
		static Platform::String^ setPerms(Platform::String^ path, int objectType, SECURITY_INFORMATION securityInformation, PSID owner, PSID group, PACL dacl, PACL sacl);
		static bool MoveFile (Platform::String ^sourceName, Platform::String ^destName, MoveFlags flags);
		static bool s_isInitialized;
		static bool LoadNeededPointers();
		static Platform::String ^ crackTokenGroupAttributes(unsigned int attrs);
		static Platform::String^ libPhate::stateToString(DWORD state);
		static Platform::String^ libPhate::typeToString(DWORD type);
		static Platform::String^ libPhate::protectToString(DWORD protect);

		
		/**** function pointers ****/ 
		/**WHEN ADDING ONE HERE, DONT FORGET TO ADD THE DECLARATION TO libPhate.cpp AS WELL**/
		static ConvertSidToStringSid_t		pConvertSidToStringSid;
		static ConvertStringSidToSid_t		pConvertStringSidToSid;
		static AddAccessAllowedAce_t		pAddAccessAllowedAce;
		static CreateProcess_t				pCreateProcess;
		static DeregisterEventSource_t		pDeregisterEventSource;
		static EnumProcesses_t				pEnumProcesses;
		static FindClose_t					pFindClose;
		static FindFirstFile_t				pFindFirstFile;
		static FindNextFile_t				pFindNextFile;
		static GetCurrentDirectory_t		pGetCurrentDirectory;
		static GetEventLogInformation_t		pGetEventLogInformation;
		static GetExplicitEntriesFromAcl_t	pGetExplicitEntriesFromAcl;
		static GetNamedSecurityInfo_t		pGetNamedSecurityInfo;
		static GetProcessImageFileName_t	pGetProcessImageFileName;
		static GetProcessMitigationPolicy_t	pGetProcessMitigationPolicy;
		static GetSecurityDescriptorDacl_t	pGetSecurityDescriptorDacl;
		static GetTokenInformation_t		pGetTokenInformation;
		static LoadLibraryEx_t				pLoadLibraryEx;
		static LocalFree_t					pLocalFree;
		static LookupAccountSid_t			pLookupAccountSid;
		static LookupAccountName_t			pLookupAccountName;
		static LookupPrivilegeName_t		pLookupPrivilegeName;
		static MakeAbsoluteSD_t				pMakeAbsoluteSD;
		static NtDuplicateObject_t			pNtDuplicateObject;
		static NtQueryObject_t				pNtQueryObject;
		static NtQuerySystemInformation_t	pNtQuerySystemInformation;
		static OpenProcess_t				pOpenProcess;
		static OpenProcessToken_t			pOpenProcessToken;
		static RegisterEventSource_t		pRegisterEventSource;
		static RtlGetAce_t					pRtlGetAce;
		static SetCurrentDirectory_t		pSetCurrentDirectory;
		static SetNamedSecurityInfo_t		pSetNamedSecurityInfo;
		static VirtualAlloc_t				pVirtualAlloc;
		static VirtualFree_t				pVirtualFree;
		static VirtualQueryEx_t				pVirtualQueryEx;

		static RegGetValue_t				pRegGetValue;
		static RegGetKeySecurity_t			pRegGetKeySecurity;
		static RegOpenKeyEx_t				pRegOpenKeyEx;
		static RegSetValueEx_t				pRegSetValueEx;
		static RegCloseKey_t				pRegCloseKey;
		static RegDeleteValue_t				pRegDeleteValue;
		static RegDeleteTree_t				pRegDeleteTree;
		static RegDeleteKey_t				pRegDeleteKey;
		static RegCreateKeyEx_t				pRegCreateKeyEx;
		static RegQueryInfoKey_t			pRegQueryInfoKey;
		static RegEnumValue_t				pRegEnumValue;
		static RegEnumKeyEx_t				pRegEnumKeyEx;

		static TerminateProcess_t			pTerminateProcess;
		static GetCommandLine_t				pGetCommandLine;
		static GetEnvironmentVariable_t		pGetEnvironmentVariable;
		static SetEnvironmentVariable_t		pSetEnvironmentVariable;

		static CreateSymbolicLink_t			pCreateSymbolicLink;
		static GetLogicalDriveStrings_t		pGetLogicalDriveStrings;


		//private enums
		enum LS_FLAGS
		{
			GET_SEC_INFO = 1,
			IS_SINGLE_FILE = 0x80000000
		};

		enum BURN_TYPES
		{
			MEM_PAGES = 1
		};

	
	};
}

