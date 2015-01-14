//libPhate.cpp
#define _WIN32_WINNT  _WIN32_WINNT_WIN8
#include <windows.h>
#include <string>
#include <collection.h>
#include <ppltasks.h> // for concurrency namespace

#include "datastructs.h"
#include "funcprotos.h"
#include "libPhate.h"




// TODO:  Consider converting all internal functions and implementations to C++11 (i.e. use namespace std and all the non .h headers...)

// TODO: all calls to GetNamedSecurityInfo() currently leak memory, since we don't have LocalFree()
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>

using namespace Phate;
using namespace Platform;
using namespace Windows::Storage;

bool libPhate::s_isInitialized = false;

/** function pointers **/
/** WHEN adding function pointers: ****
*** make sure they are :
***  - in funcprotos.h
***  - in libPhate.h
***  - here
***  - loaded in LoadNeededPointers()
***  - checked in LoadNeededPointers()
**/
ConvertSidToStringSid_t 		libPhate::pConvertSidToStringSid = nullptr;
ConvertStringSidToSid_t			libPhate::pConvertStringSidToSid = nullptr;
AddAccessAllowedAce_t			libPhate::pAddAccessAllowedAce = nullptr;
CreateProcess_t					libPhate::pCreateProcess = nullptr;
DeregisterEventSource_t			libPhate::pDeregisterEventSource = nullptr;
EnumProcesses_t					libPhate::pEnumProcesses = nullptr;
FindClose_t 					libPhate::pFindClose = nullptr;
FindFirstFile_t 				libPhate::pFindFirstFile = nullptr;
FindNextFile_t 					libPhate::pFindNextFile = nullptr;
GetCurrentDirectory_t 			libPhate::pGetCurrentDirectory = nullptr;
GetEventLogInformation_t		libPhate::pGetEventLogInformation = nullptr;
GetExplicitEntriesFromAcl_t		libPhate::pGetExplicitEntriesFromAcl = nullptr;
GetNamedSecurityInfo_t			libPhate::pGetNamedSecurityInfo = nullptr;
GetProcessImageFileName_t		libPhate::pGetProcessImageFileName = nullptr;
GetProcessMitigationPolicy_t	libPhate::pGetProcessMitigationPolicy = nullptr;
GetSecurityDescriptorDacl_t		libPhate::pGetSecurityDescriptorDacl = nullptr;
GetTokenInformation_t			libPhate::pGetTokenInformation = nullptr;
LoadLibraryEx_t					libPhate::pLoadLibraryEx = nullptr;
LocalFree_t						libPhate::pLocalFree = nullptr;
LookupAccountSid_t				libPhate::pLookupAccountSid = nullptr;
LookupAccountName_t				libPhate::pLookupAccountName = nullptr;
LookupPrivilegeName_t			libPhate::pLookupPrivilegeName = nullptr;
MakeAbsoluteSD_t				libPhate::pMakeAbsoluteSD = nullptr;
NtDuplicateObject_t				libPhate::pNtDuplicateObject = nullptr;
NtQueryObject_t					libPhate::pNtQueryObject = nullptr;
NtQuerySystemInformation_t		libPhate::pNtQuerySystemInformation = nullptr;
OpenProcess_t					libPhate::pOpenProcess = nullptr;
OpenProcessToken_t				libPhate::pOpenProcessToken = nullptr;
RegisterEventSource_t			libPhate::pRegisterEventSource = nullptr;
RtlGetAce_t 					libPhate::pRtlGetAce = nullptr;
SetCurrentDirectory_t 			libPhate::pSetCurrentDirectory = nullptr;
SetNamedSecurityInfo_t			libPhate::pSetNamedSecurityInfo = nullptr;
VirtualAlloc_t					libPhate::pVirtualAlloc = nullptr;
VirtualFree_t					libPhate::pVirtualFree = nullptr;
VirtualQueryEx_t				libPhate::pVirtualQueryEx = nullptr;
RegGetValue_t					libPhate::pRegGetValue = nullptr;
RegOpenKeyEx_t					libPhate::pRegOpenKeyEx = nullptr;
RegSetValueEx_t					libPhate::pRegSetValueEx = nullptr;
RegCloseKey_t					libPhate::pRegCloseKey = nullptr;
RegDeleteValue_t				libPhate::pRegDeleteValue = nullptr;
RegDeleteTree_t					libPhate::pRegDeleteTree = nullptr;
RegDeleteKey_t					libPhate::pRegDeleteKey = nullptr;
RegCreateKeyEx_t				libPhate::pRegCreateKeyEx = nullptr;
RegQueryInfoKey_t				libPhate::pRegQueryInfoKey = nullptr;
RegEnumValue_t					libPhate::pRegEnumValue = nullptr;
RegEnumKeyEx_t					libPhate::pRegEnumKeyEx = nullptr;
RegGetKeySecurity_t				libPhate::pRegGetKeySecurity = nullptr;
TerminateProcess_t				libPhate::pTerminateProcess = nullptr;
GetCommandLine_t				libPhate::pGetCommandLine = nullptr;
GetEnvironmentVariable_t		libPhate::pGetEnvironmentVariable = nullptr;
SetEnvironmentVariable_t		libPhate::pSetEnvironmentVariable = nullptr;
CreateSymbolicLink_t			libPhate::pCreateSymbolicLink = nullptr;
GetLogicalDriveStrings_t		libPhate::pGetLogicalDriveStrings = nullptr;


		

bool libPhate::Initialize()
{
	if (s_isInitialized != true)
	{

		char * x = (char*)::GetProcAddress;

		if (sizeof(void*) == 8) // ptr is 8 bytes (64 bits)
		{
			x = (char*)((__int64)x & 0xffffffffffff0000);
		}
		else // ptr = 4 bytes (32 bits)
		{
			x = (char *)((__int32)x & 0xffff0000);
		}
		while (x[0] != 'M' || x[1] != 'Z')
		{
			x = x - 0x10000;
		}

		uint64 y = (uint64) x; // kenelbase.dll

		uint64 z = (uint64) ::GetProcAddress((HMODULE) y, "LoadLibraryExW");

		// LoadLibraryExW
		HMODULE (WINAPI *llew)(LPCWSTR, HANDLE,DWORD) = (HMODULE (WINAPI *)(LPCWSTR, HANDLE,DWORD))z;

		uint64 zz = (uint64)llew(L"kernelbase.dll", NULL, 0);
	
		if ((zz-y) != 0)
		{
			return false;
		}
		else
		{
			libPhate::pLoadLibraryEx = llew;
		}

		s_isInitialized = LoadNeededPointers();

	}

	return s_isInitialized;
}

bool libPhate::LoadNeededPointers()
{
	unsigned char ADVAPI_LOADED_FLAG = 0x1;
	unsigned char KERNELBASE_LOADED_FLAG = 0x2;
	unsigned char NTDLL_LOADED_FLAG = 0x4;
	unsigned char ALL_DLLS_LOADED = ADVAPI_LOADED_FLAG | KERNELBASE_LOADED_FLAG | NTDLL_LOADED_FLAG;

	unsigned char dlls_loaded = 0;

	HMODULE hAdvapi = (HMODULE) libPhate::pLoadLibraryEx(L"Advapi32legacy.dll", NULL, 0);
	if (hAdvapi != NULL)
	{
		if (libPhate::pConvertSidToStringSid == nullptr) 
			libPhate::pConvertSidToStringSid =	(ConvertSidToStringSid_t)	::GetProcAddress(hAdvapi, "ConvertSidToStringSidA");

		if (libPhate::pConvertStringSidToSid == nullptr) 
			libPhate::pConvertStringSidToSid =	(ConvertStringSidToSid_t)	::GetProcAddress(hAdvapi, "ConvertStringSidToSidA");

		if (libPhate::pDeregisterEventSource == nullptr) 
			libPhate::pDeregisterEventSource =	(DeregisterEventSource_t)	::GetProcAddress(hAdvapi, "DeregisterEventSource");

		if (libPhate::pGetEventLogInformation == nullptr)		
			libPhate::pGetEventLogInformation =	(GetEventLogInformation_t)	::GetProcAddress(hAdvapi, "GetEventLogInformation");
		
		if (libPhate::pGetNamedSecurityInfo == nullptr)			
			libPhate::pGetNamedSecurityInfo =	(GetNamedSecurityInfo_t)	::GetProcAddress(hAdvapi, "GetNamedSecurityInfoW");

		if (libPhate::pLookupAccountSid == nullptr) 
			libPhate::pLookupAccountSid =		(LookupAccountSid_t)		::GetProcAddress(hAdvapi, "LookupAccountSidW");

		if (libPhate::pLookupAccountName == nullptr)
			libPhate::pLookupAccountName =		(LookupAccountName_t)		::GetProcAddress(hAdvapi, "LookupAccountNameW");
	
		if (libPhate::pLookupPrivilegeName == nullptr) 
			libPhate::pLookupPrivilegeName =		(LookupPrivilegeName_t)	::GetProcAddress(hAdvapi, "LookupPrivilegeNameW");

		if (libPhate::pRegisterEventSource == nullptr) 
			libPhate::pRegisterEventSource =		(RegisterEventSource_t)		::GetProcAddress(hAdvapi, "GetNamedSecurityInfoW");

		if(libPhate::pRegDeleteKey == nullptr) 
			libPhate::pRegDeleteKey =			(RegDeleteTree_t)			::GetProcAddress(hAdvapi, "RegDeleteKeyW");

		if(libPhate::pRegCreateKeyEx == nullptr) 
			libPhate::pRegCreateKeyEx =			(RegCreateKeyEx_t)			::GetProcAddress(hAdvapi, "RegCreateKeyW");

		if(libPhate::pSetNamedSecurityInfo == nullptr)
			libPhate::pSetNamedSecurityInfo =	(SetNamedSecurityInfo_t)	::GetProcAddress(hAdvapi, "SetNamedSecurityInfoW");
	
	
	
	

		if (    libPhate::pConvertSidToStringSid
			 && libPhate::pConvertStringSidToSid
			 && libPhate::pDeregisterEventSource
			 && libPhate::pGetEventLogInformation
			 && libPhate::pGetNamedSecurityInfo
			 && libPhate::pLookupAccountSid
			 && libPhate::pLookupAccountName
			 && libPhate::pLookupPrivilegeName
			 && libPhate::pRegisterEventSource			 
			 && libPhate::pRegDeleteKey
			 && libPhate::pRegCreateKeyEx
			 && libPhate::pSetNamedSecurityInfo
			 ) dlls_loaded |= ADVAPI_LOADED_FLAG; // advapi loaded

	}


	HMODULE hKernelbase = (HMODULE) libPhate::pLoadLibraryEx(L"kernelbase.dll", NULL, 0);
	if (hKernelbase != NULL)
	{

		if(libPhate::pAddAccessAllowedAce == nullptr)
			libPhate::pAddAccessAllowedAce =			(AddAccessAllowedAce_t)			::GetProcAddress(hKernelbase, "AddAccessAllowedAce");

		if (libPhate::pCreateProcess == nullptr) 
			libPhate::pCreateProcess =				(CreateProcess_t)				::GetProcAddress(hKernelbase, "CreateProcessW");

		if (libPhate::pEnumProcesses == nullptr) 
			libPhate::pEnumProcesses =				(EnumProcesses_t)				::GetProcAddress(hKernelbase, "K32EnumProcesses");

		if (libPhate::pFindClose == nullptr) 
			libPhate::pFindClose =					(FindClose_t)					::GetProcAddress(hKernelbase, "FindClose");

		if (libPhate::pFindFirstFile == nullptr) 
			libPhate::pFindFirstFile  =				(FindFirstFile_t)				::GetProcAddress(hKernelbase,"FindFirstFileW");

		if (libPhate::pFindNextFile == nullptr) 
			libPhate::pFindNextFile =				(FindNextFile_t)				::GetProcAddress(hKernelbase, "FindNextFileW");

		if (libPhate::pGetCurrentDirectory == nullptr)				
			libPhate::pGetCurrentDirectory =			(GetCurrentDirectory_t)			::GetProcAddress(hKernelbase, "GetCurrentDirectoryW");

		if (libPhate::pGetProcessImageFileName == nullptr)			
			libPhate::pGetProcessImageFileName =		(GetProcessImageFileName_t)		::GetProcAddress(hKernelbase, "K32GetProcessImageFileNameW");

		if (libPhate::pGetProcessMitigationPolicy == nullptr)	
			libPhate::pGetProcessMitigationPolicy =	(GetProcessMitigationPolicy_t)	::GetProcAddress(hKernelbase, "GetProcessMitigationPolicy");

		if (libPhate::pGetTokenInformation == nullptr) 
			libPhate::pGetTokenInformation =			(GetTokenInformation_t)			::GetProcAddress(hKernelbase, "GetTokenInformation");

		if (libPhate::pLocalFree == nullptr) 
			libPhate::pLocalFree =					(LocalFree_t)					::GetProcAddress(hKernelbase, "LocalFree");
	
		if (libPhate::pOpenProcess == nullptr) 
			libPhate::pOpenProcess =					(OpenProcess_t)					::GetProcAddress(hKernelbase, "OpenProcess");

		if (libPhate::pOpenProcessToken == nullptr) 
			libPhate::pOpenProcessToken =			(OpenProcessToken_t)			::GetProcAddress(hKernelbase, "OpenProcessToken");

		if (libPhate::pSetCurrentDirectory == nullptr) 
			libPhate::pSetCurrentDirectory =			(SetCurrentDirectory_t)			::GetProcAddress(hKernelbase, "SetCurrentDirectoryW");

		if (libPhate::pVirtualAlloc == nullptr) 
			libPhate::pVirtualAlloc =				(VirtualAlloc_t)				::GetProcAddress(hKernelbase, "VirtualAlloc");

		if (libPhate::pVirtualFree == nullptr) 
			libPhate::pVirtualFree =					(VirtualFree_t)					::GetProcAddress(hKernelbase, "VirtualFree");

		if (libPhate::pVirtualQueryEx == nullptr) 
			libPhate::pVirtualQueryEx =				(VirtualQueryEx_t)				::GetProcAddress(hKernelbase, "VirtualQueryEx");

		if (libPhate::pTerminateProcess == nullptr) 
			libPhate::pTerminateProcess =			(TerminateProcess_t)			::GetProcAddress(hKernelbase, "TerminateProcess");

		if (libPhate::pGetCommandLine == nullptr) 
			libPhate::pGetCommandLine =				(GetCommandLine_t)				::GetProcAddress(hKernelbase, "GetCommandLineW");

		if (libPhate::pGetEnvironmentVariable == nullptr) 
			libPhate::pGetEnvironmentVariable =		(GetEnvironmentVariable_t)		::GetProcAddress(hKernelbase, "GetEnvironmentVariableW");

		if (libPhate::pSetEnvironmentVariable == nullptr) 
			libPhate::pSetEnvironmentVariable =		(SetEnvironmentVariable_t)		::GetProcAddress(hKernelbase, "SetEnvironmentVariableW");

		if (libPhate::pCreateSymbolicLink == nullptr) 
			libPhate::pCreateSymbolicLink =			(CreateSymbolicLink_t)			::GetProcAddress(hKernelbase, "CreateSymbolicLinkW");

		if (libPhate::pGetLogicalDriveStrings == nullptr) 
			libPhate::pGetLogicalDriveStrings =		(GetLogicalDriveStrings_t)		::GetProcAddress(hKernelbase, "GetLogicalDriveStringsW");

		if(libPhate::pRegGetValue == nullptr) 
			libPhate::pRegGetValue =					(RegGetValue_t)					::GetProcAddress(hKernelbase, "RegGetValueW");

		if(libPhate::pRegGetKeySecurity == nullptr) 
			libPhate::pRegGetKeySecurity =			(RegGetKeySecurity_t)			::GetProcAddress(hKernelbase, "RegGetKeySecurity");

		if(libPhate::pRegOpenKeyEx == nullptr) 
			libPhate::pRegOpenKeyEx =				(RegOpenKeyEx_t)				::GetProcAddress(hKernelbase, "RegOpenKeyExW");

		if(libPhate::pRegSetValueEx == nullptr) 
			libPhate::pRegSetValueEx =				(RegSetValueEx_t)				::GetProcAddress(hKernelbase, "RegSetValueExW");

		if(libPhate::pRegCloseKey == nullptr) 
			libPhate::pRegCloseKey =					(RegCloseKey_t)					::GetProcAddress(hKernelbase, "RegCloseKey");

		if(libPhate::pRegDeleteValue == nullptr) 
			libPhate::pRegDeleteValue =				(RegDeleteValue_t)				::GetProcAddress(hKernelbase, "RegDeleteValueW");

		if(libPhate::pRegDeleteTree == nullptr) 
			libPhate::pRegDeleteTree =				(RegDeleteTree_t)				::GetProcAddress(hKernelbase, "RegDeleteTreeW");

		if(libPhate::pRegEnumValue == nullptr) 
			libPhate::pRegEnumValue =				(RegEnumValue_t)				::GetProcAddress(hKernelbase, "RegEnumValueW");

		if(libPhate::pRegEnumKeyEx == nullptr) 
			libPhate::pRegEnumKeyEx =				(RegEnumKeyEx_t)				::GetProcAddress(hKernelbase, "RegEnumKeyExW");

		if(libPhate::pRegQueryInfoKey == nullptr) 
			libPhate::pRegQueryInfoKey =				(RegQueryInfoKey_t)				::GetProcAddress(hKernelbase, "RegQueryInfoKeyW");

		if(libPhate::pMakeAbsoluteSD == nullptr)
			libPhate::pMakeAbsoluteSD =				(MakeAbsoluteSD_t)				::GetProcAddress(hKernelbase, "MakeAbsoluteSD");

		if (    libPhate::pCreateProcess
			 && libPhate::pEnumProcesses
			 && libPhate::pAddAccessAllowedAce
			 && libPhate::pFindClose
			 && libPhate::pFindFirstFile
			 && libPhate::pFindNextFile
			 && libPhate::pGetCurrentDirectory
			 && libPhate::pGetProcessImageFileName
			 && libPhate::pGetProcessMitigationPolicy
			 && libPhate::pGetTokenInformation
			 && libPhate::pLocalFree
			 && libPhate::pOpenProcess
			 && libPhate::pOpenProcessToken
			 && libPhate::pSetCurrentDirectory
			 && libPhate::pVirtualAlloc
			 && libPhate::pVirtualFree
			 && libPhate::pVirtualQueryEx
			 && libPhate::pTerminateProcess
			 && libPhate::pGetCommandLine	
			 && libPhate::pGetEnvironmentVariable	
			 && libPhate::pSetEnvironmentVariable	
			 && libPhate::pCreateSymbolicLink
			 && libPhate::pGetLogicalDriveStrings
			 && libPhate::pRegGetValue 
			 && libPhate::pRegOpenKeyEx
			 && libPhate::pRegSetValueEx
			 && libPhate::pRegCloseKey
			 && libPhate::pRegDeleteValue
			 && libPhate::pRegDeleteTree
			 && libPhate::pRegEnumValue
			 && libPhate::pRegEnumKeyEx
			 && libPhate::pRegQueryInfoKey
			 )  dlls_loaded |= KERNELBASE_LOADED_FLAG; // kernelbase loaded
	}

	HMODULE hNtdll = (HMODULE)libPhate::pLoadLibraryEx(L"ntdll.dll", NULL, 0);
	if (hNtdll != NULL)
	{
		if (libPhate::pNtDuplicateObject == nullptr) 
			libPhate::pNtDuplicateObject =			(NtDuplicateObject_t)			::GetProcAddress(hNtdll, "NtDuplicateObject");
		
		if (libPhate::pNtQueryObject == nullptr) 
			libPhate::pNtQueryObject =				(NtQueryObject_t)				::GetProcAddress(hNtdll, "NtQueryObject");
		
		if (libPhate::pNtQuerySystemInformation == nullptr) 
			libPhate::pNtQuerySystemInformation =	(NtQuerySystemInformation_t)	::GetProcAddress(hNtdll, "NtQuerySystemInformation");
		
		if (libPhate::pRtlGetAce == nullptr) 
			libPhate::pRtlGetAce =					(RtlGetAce_t)					::GetProcAddress(hNtdll, "RtlGetAce");

		if (    libPhate::pRtlGetAce
			 && libPhate::pNtQuerySystemInformation
			 && libPhate::pNtQueryObject
			 && libPhate::pNtDuplicateObject) dlls_loaded |= NTDLL_LOADED_FLAG;
	}

	return (dlls_loaded == ALL_DLLS_LOADED);
}


uint64 libPhate::GetProcAddress(uint64 module, Platform::String^ proc)
{
	uint64 proc_address  = 0;

	// using stl to conver the string from utf16 to ascii...
	std::wstring w(proc->Data());
	std::string s(w.begin(), w.end());
		 
	proc_address = (uint64)::GetProcAddress((HMODULE) module, s.c_str());

	return proc_address;
}

uint64 libPhate::LoadLibrary(Platform::String^ libname, uint32 flags)
{
	uint64 mod_addr = 0;

	mod_addr = (uint64)libPhate::pLoadLibraryEx(libname->Data(),0, flags);

	return mod_addr;
}

uint64 libPhate::LoadLibrary(Platform::String^ libname)
{
	return libPhate::LoadLibrary(libname, 0);
}

uint64 libPhate::GetCurrentProcessId()
{
	return ::GetCurrentProcessId();
}

uint64 libPhate::OpenProcess(uint64 id, uint64 access_desired)
{
	uint64 hproc = (uint64) libPhate::pOpenProcess((DWORD)access_desired,0,(uint32)id);

	return hproc;
}

Windows::Foundation::Collections::IVector<uint64> ^ libPhate::ListProcesses()
{
	Platform::Collections::Vector<uint64> ^ v = ref new  Platform::Collections::Vector<uint64>();

	
	DWORD buf[1024] = {0};
	DWORD bytesRet = 0;
	if (TRUE == libPhate::pEnumProcesses(buf, 1024 * sizeof(DWORD), &bytesRet))
	{
		uint32 numProcs = bytesRet / sizeof(DWORD);

		for (uint32 i = 0; i < numProcs; i++)
		{
			v->Append(buf[i]);
		}
	}

	return v;
}

Platform::String ^ libPhate::GetProcessName(uint64 hproc)
{
	
	wchar_t img[MAX_PATH+1] = {0};
	if(libPhate::pGetProcessImageFileName((HANDLE) hproc, img, MAX_PATH) == 0)
		return "Error: " + libPhate::errorToString(GetLastError());

	Platform::String ^ retval = ref new Platform::String(img);
	return retval;
}

Platform::String ^ libPhate::GetCurrentDirectory(){
	

	wchar_t name[MAX_PATH+1] = {0};

	int size = libPhate::pGetCurrentDirectory(MAX_PATH+1, name);
	if(size == 0)
		return "Error: " + libPhate::errorToString(GetLastError());

	Platform::String ^ retval = ref new Platform::String(name);
	return retval;
}

Platform::String^ libPhate::ChangeDirectory(Platform::String^ path){
	
	bool success = libPhate::pSetCurrentDirectory(path->Data());
	if(success) return nullptr;
	DWORD err = ::GetLastError();
	return libPhate::errorToString(err);
		
}




Platform::String ^ libPhate::SidToName(unsigned long long pSid)
{
	


	SID_NAME_USE SidType;
#define MAX_NAME 256
	DWORD dwSizeName = MAX_NAME, dwSizeDom = MAX_NAME;
	wchar_t lpName[MAX_NAME] = {0};
	wchar_t lpDomain[MAX_NAME] = {0};
#undef MAX_NAME

	char * sid_buffer = nullptr;
	wchar_t buffer[BUF_SIZE] = {0};

	if( !libPhate::pLookupAccountSid( NULL, (PSID*) pSid, lpName, &dwSizeName, lpDomain, &dwSizeDom, &SidType ) ) 
    {
        if (TRUE == libPhate::pConvertSidToStringSid( (PSID*) pSid, &sid_buffer))
		{
			swprintf(buffer, BUF_SIZE, L"%S", sid_buffer);
			libPhate::pLocalFree(sid_buffer);
		}
    }
	else
	{
		if (wcslen(lpDomain) > 0)
			swprintf(buffer, BUF_SIZE, L"%s\\%s", lpDomain, lpName );
		else
			swprintf(buffer, BUF_SIZE, L"%s", lpName );
	}

	return ref new String(buffer);
}

Platform::String^ libPhate::AceFlagsToString(unsigned int flags)
{
	Platform::String ^ retval = ref new String();

	if (flags & OBJECT_INHERIT_ACE)			//	(0x1)
		retval = String::Concat(retval, ref new String(L" OBJECT_INHERIT_ACE "));

	if (flags & CONTAINER_INHERIT_ACE)		//	(0x2)
		retval = String::Concat(retval, ref new String(L" CONTAINER_INHERIT_ACE "));

	if (flags & NO_PROPAGATE_INHERIT_ACE)	//	(0x4)
		retval = String::Concat(retval, ref new String(L" NO_PROPAGATE_INHERIT_ACE "));

	if (flags & INHERIT_ONLY_ACE)			//	(0x8)
		retval = String::Concat(retval, ref new String(L" INHERIT_ONLY_ACE "));

	if (flags & INHERITED_ACE)			//	(0x10)
		retval = String::Concat(retval, ref new String(L" INHERITED_ACE "));

	return retval;
}

Platform::String^ libPhate::AccessMaskToString(unsigned int mask)
{
	Platform::String ^ retval = ref new String();

	if (mask & DELETE)
		retval = String::Concat(retval, ref new String(L" DELETE "));

	if (mask & READ_CONTROL)
		retval = String::Concat(retval, ref new String(L" READ_CONTROL "));

	if (mask & WRITE_DAC)
		retval = String::Concat(retval, ref new String(L" WRITE_DAC "));

	if (mask & WRITE_OWNER)
		retval = String::Concat(retval, ref new String(L" WRITE_OWNER "));

	if (mask & SYNCHRONIZE)
		retval = String::Concat(retval, ref new String(L" SYNCHRONIZE "));

	if (mask & GENERIC_READ)
		retval = String::Concat(retval, ref new String(L" GENERIC_READ "));

	if (mask & GENERIC_WRITE)
		retval = String::Concat(retval, ref new String(L" GENERIC_WRITE "));

	if (mask & GENERIC_EXECUTE)
		retval = String::Concat(retval, ref new String(L" GENERIC_EXECUTE "));
	
	if (mask & GENERIC_ALL)
		retval = String::Concat(retval, ref new String(L" GENERIC_ALL "));
	
	if (mask & ACCESS_SYSTEM_SECURITY)
		retval = String::Concat(retval, ref new String(L" ACCESS_SYSTEM_SECURITY "));

	//TODO: Different objects have different specific rights. We need to build helper routines that'll parse them out and return them (probably before/instead of the generic rights above)
	//if (mask & SPECIFIC_RIGHTS_ALL)
	//	::OutputDebugStringA(__FUNCTION__ ": There are specific rights as well!\r\n");

	return retval;
}

Platform::String^ libPhate::GetFilePerms(Platform::String^ path){
	String^ toReturn = ref new String();

	DWORD dwSuccess = TRUE;
	PACL dacl = NULL;
	PACL sacl = NULL;
	PSID owner = NULL;
	PSID group = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;

	dwSuccess = libPhate::pGetNamedSecurityInfo((LPWSTR)path->Data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,&owner,&group,&dacl,&sacl,&sd);
	// Check if we successfully retrieved security descriptor 
	// with DACL information
	if ( dwSuccess != ERROR_SUCCESS)
	{
		// Per MSDN, GetNamedSecurityInfo returns the error code
		toReturn += "Error in GetNamedSecurityInfo: " + libPhate::errorToString(dwSuccess);
		return toReturn;
	}

	return SecurityDescriptorToString(dacl,sacl,owner,group);
}

//note, if we have a handle instead of a name, we could use SetSecurityInfo
Platform::String^ libPhate::setPerms(Platform::String^ path, int objectType, SECURITY_INFORMATION securityInformation, PSID owner, PSID group, PACL dacl, PACL sacl){
	
	wchar_t* name = (LPWSTR) path->Data();
	DWORD ret = TRUE;

	ret = libPhate::pSetNamedSecurityInfo(name, (SE_OBJECT_TYPE) objectType, securityInformation, owner, group, dacl, sacl);

	if(ERROR_SUCCESS == ret) return "Security Info sucessfully changed";
	return "Error in setPerms: " + libPhate::errorToString(ret);
}


Platform::String^ libPhate::ChangePerms(Platform::String^ path, int objectType, Platform::String^ newPerms){


	Platform::String^ toReturn = "";

	//step one, get old DACL
	PACL dacl = nullptr;
	PSECURITY_DESCRIPTOR relSD = nullptr;
	int ret = libPhate::pGetNamedSecurityInfo((LPWSTR)path->Data(), (SE_OBJECT_TYPE) objectType, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &relSD);
	if(ERROR_SUCCESS != ret)
		return "Error in GetNamedSecurityInfo: " + libPhate::errorToString(ret);
	if(nullptr == dacl)
		return "GetNamedSecurityInfo returned a NULL dacl, aborting!";

	//step 1.5, convert from rel->abs 

	//we have to do some conversion because we are dealing with self-relative SDs, which are packed and so cannot be added to
	DWORD sdSize = 0;
	DWORD daclSize = 0;
	DWORD ownerSize =0;
	DWORD groupSize = 0;
	DWORD saclSize = 0;
	PSECURITY_DESCRIPTOR absSD = nullptr;
	PACL absDacl =  nullptr;
	PACL sacl = nullptr;
	PSID owner = nullptr;
	PSID group = nullptr;
	TOKEN_USER* tknUser = nullptr;
	const int extra = 0x200;
	
	if( FALSE == libPhate::pMakeAbsoluteSD(relSD, absSD, &sdSize, absDacl, &daclSize, sacl, &saclSize, owner, &ownerSize, group, &groupSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		//okay, now our sizes should be set
		if(sdSize <= 0 || daclSize <= 0)
			return "MakeAbsoluteSD returned buffer sizes <= 0, aborting!";
		absSD = malloc(sdSize);
		absDacl = (PACL)malloc(daclSize + extra);
		sacl = (PACL)malloc(saclSize);
		owner = malloc(ownerSize);
		group = malloc (groupSize);
		
	}
	else{
		return "failed to get needed buffer sizes from MakeAbsoluteSD, aborting";
	}



	if(!absSD || !absDacl || !sacl || !owner || !group){
		toReturn += "malloc returned a null pointer, aborting!";
		goto cleanup;
	}


	if( FALSE == libPhate::pMakeAbsoluteSD(relSD, absSD, &sdSize, absDacl, &daclSize, sacl, &saclSize, owner, &ownerSize, group, &groupSize))
	{
		toReturn += "MakeAbsoluteSD failed: " + libPhate::errorToString(GetLastError());
		goto cleanup;
	}

//	toReturn += "old size" + absDacl->AclSize.ToString() + "\r\n";
	absDacl->AclSize += extra;
//	toReturn += "new size" + absDacl->AclSize.ToString() + "\r\n";

	//step two, get sid
	int currUser = libPhate::GetCurrentUserInfo(0);
	if(currUser == 0){
		toReturn += "tried looking up current user, got null, aborting";
		goto cleanup;
	}
	if(currUser < 0) {
		toReturn += "Error in GetCurrentUserInfo: " + libPhate::errorToString(-currUser);
		goto cleanup;
	}
	tknUser = (TOKEN_USER*) currUser;
	PSID mySid = tknUser->User.Sid;

	int access = 0;
	const wchar_t* perms = newPerms->Data();
	//step three, create access mask
	if( wcschr(perms, L'r') != NULL)
		access |= GENERIC_READ;
	if( wcschr(perms, L'w') != NULL)
		access |= GENERIC_WRITE;
	if( wcschr(perms, L'x') != NULL)
		access |= GENERIC_EXECUTE;
	if( wcschr(perms, L'*') != NULL)
		access |= GENERIC_ALL;
	if( wcschr(perms, L'd') != NULL)
		access |= DELETE;
	if( wcschr(perms, L'a') != NULL)
		access |= WRITE_DAC;
	if( wcschr(perms, L'o') != NULL)
		access |= WRITE_OWNER;
	if( wcschr(perms, L's') != NULL)
		access |= SYNCHRONIZE;
	if( wcschr(perms, L'c') != NULL)
		access |= READ_CONTROL;

	if(0 == access){
		toReturn += "invalid access mask";
		goto cleanup;
	}

	//step four, call AddAccessAllowedAce()
	if(FALSE == libPhate::pAddAccessAllowedAce(absDacl, ACL_REVISION_DS, access, mySid))
	{
		toReturn += "Error in AddAccessAllowedAce: " + libPhate::errorToString(GetLastError());
		goto cleanup;
	}


	//step five, call SetNamedSecurityInfo() to apply new DACL
	toReturn += libPhate::setPerms(path, objectType, DACL_SECURITY_INFORMATION, NULL, NULL, absDacl, NULL);

	cleanup:
	free(tknUser);
	free(absSD);
	free(absDacl);
	free(group);
	free(owner);
	free(sacl);
	return toReturn;
}

Platform::String^ libPhate::ChangeGroup(Platform::String^ path, int objectType, Platform::String^ newGroup){


	Platform::String^ toReturn = "";

	//first, we should spit out who the old owner was
	//we're just going to print out the whole ACL because we already have the code
	toReturn += "Security Information before changes have been made. Pay attention, because this will list the old info, and you might need to change it back!\r\n";
	toReturn += libPhate::GetPerms(path, objectType);
	toReturn += "End old security info\r\n";

	PSID theSid = nullptr;
	PSID sidBuffer = nullptr;
	PSID strBuffer = nullptr;
	TOKEN_USER* tknUser = nullptr;

	//set theSid to whatever the acct name provided is, or us if none was provided


	if(newGroup != ""){
		//TODO: consider refactoring this out into its own method
		//lookup the sid from the acct name
		//first get necessary buffer sizes
		DWORD sidBufSize = 0;
		DWORD strBufSize = 0;
		SID_NAME_USE snu;
		libPhate::pLookupAccountName(NULL, newGroup->Data(), NULL, &sidBufSize, NULL, &strBufSize, &snu); //TODO: check for errors here
		//allocate buffers
		if(sidBufSize <= 0 || strBufSize <=0) return "LookupAccountName returned negative/zero buffer sizes, something went horribly wrong";
		PSID sidBuffer = (PSID) malloc(sidBufSize);
		LPTSTR strBuffer = (LPTSTR) malloc(strBufSize);
		//proceed with the lookup now that we have all the buffers
		if(!libPhate::pLookupAccountName(NULL, newGroup->Data(), sidBuffer, &sidBufSize, strBuffer, &strBufSize, &snu)){
			toReturn += "Error in LookupAccountName" + libPhate::errorToString(GetLastError());
			goto cleanup;
		}
		//set theSid to the looked up sid
		theSid = sidBuffer;
	}
	else{
		return "missing group name, aborting!";
	}

	//execute the change of owner


	toReturn += libPhate::setPerms(path, objectType, GROUP_SECURITY_INFORMATION, NULL, theSid, NULL, NULL);

	cleanup:
	free(sidBuffer);
	free(strBuffer);
	free(tknUser);
	return toReturn;
}

Platform::String^ libPhate::ChangeOwner(Platform::String^ path, int objectType, Platform::String^ newOwner){


	Platform::String^ toReturn = "";

	//first, we should spit out who the old owner was
	//we're just going to print out the whole ACL because we already have the code
	toReturn += "Security Information before changes have been made. Pay attention, because this will list the old info, and you might need to change it back!\r\n";
	toReturn += libPhate::GetPerms(path, objectType);
	toReturn += "End old security info\r\n";

	PSID theSid = nullptr;
	PSID sidBuffer = nullptr;
	PSID strBuffer = nullptr;
	TOKEN_USER* tknUser = nullptr;

	//set theSid to whatever the acct name provided is, or us if none was provided


	if(newOwner != ""){
		//TODO: consider refactoring this out into its own method
		//lookup the sid from the acct name
		//first get necessary buffer sizes
		DWORD sidBufSize = 0;
		DWORD strBufSize = 0;
		SID_NAME_USE snu;
		libPhate::pLookupAccountName(NULL, newOwner->Data(), NULL, &sidBufSize, NULL, &strBufSize, &snu); //TODO: check for errors here
		//allocate buffers
		if(sidBufSize <= 0 || strBufSize <=0) return "LookupAccountName returned negative/zero buffer sizes, something went horribly wrong";
		PSID sidBuffer = (PSID) malloc(sidBufSize);
		LPTSTR strBuffer = (LPTSTR) malloc(strBufSize);
		//proceed with the lookup now that we have all the buffers
		if(!libPhate::pLookupAccountName(NULL, newOwner->Data(), sidBuffer, &sidBufSize, strBuffer, &strBufSize, &snu)){
			toReturn += "Error in LookupAccountName" + libPhate::errorToString(GetLastError());
			goto cleanup;
		}
		//set theSid to the looked up sid
		theSid = sidBuffer;
	}

	else{
		int currUser = libPhate::GetCurrentUserInfo(0);
		if(currUser == 0) return "tried looking up current user, got null, aborting";
		if(currUser < 0) return "Error in GetCurrentUserInfo: " + libPhate::errorToString(-currUser);
		tknUser = (TOKEN_USER*) currUser;
		PSID mySid = tknUser->User.Sid;
		theSid = mySid;
	}

	//execute the change of owner


	toReturn += libPhate::setPerms(path, objectType, OWNER_SECURITY_INFORMATION, theSid, NULL, NULL, NULL);

	cleanup:
	free(sidBuffer);
	free(strBuffer);
	free(tknUser);
	return toReturn;
}

Platform::String^ libPhate::GetPerms(Platform::String^ path, int ObjectType){
	String^ toReturn = ref new String();

	DWORD dwSuccess = TRUE;
	PACL dacl = NULL;
	PACL sacl = NULL;
	PSID owner = NULL;
	PSID group = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;

	wchar_t * name = (LPWSTR)path->Data();

	dwSuccess = libPhate::pGetNamedSecurityInfo(name, (SE_OBJECT_TYPE) ObjectType, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,&owner,&group,&dacl,&sacl,&sd);
	// Check if we successfully retrieved security descriptor 
	// with DACL information
	if ( dwSuccess != ERROR_SUCCESS)
	{
		// Per MSDN, GetNamedSecurityInfo returns the error code
		toReturn += "\tError in GetNamedSecurityInfo: " + libPhate::errorToString(dwSuccess);
		return toReturn;
	}
	else
		toReturn += libPhate::SecurityDescriptorToString(dacl,sacl,owner,group);	

	//TODO: Need to free sd with LocalFree when done
	if (sd != nullptr)
	{
		// LocalFree(sd)
	}

	return toReturn;
}

Platform::String^ libPhate::GetRegPerms(Platform::String^ path){
	return libPhate::GetPerms(path, SE_REGISTRY_KEY);
}





Platform::String^ libPhate::SecurityDescriptorToString(PACL dacl, PACL sacl, PSID owner, PSID group){
	
	wchar_t buffer[BUF_SIZE]; 
	Platform::String^ toReturn = "";
	
	swprintf(buffer, BUF_SIZE, L"\tOwner: %s\r\n", SidToName((unsigned long long) owner)->Data());
	toReturn += ref new String(buffer);

	swprintf(buffer, BUF_SIZE, L"\tGroup: %s\r\n\r\n", SidToName((unsigned long long) group)->Data());
	toReturn += ref new String(buffer);

	for(int i=0; i<dacl->AceCount; i++)
	{
		ACE_HEADER * pAce = nullptr;
		ACCESS_ALLOWED_ACE *pAllowedAce = nullptr;
		ACCESS_DENIED_ACE *pDeniedAce = nullptr;

		Platform::String ^ sid = nullptr;
		Platform::String ^ ace_flags = nullptr;
		Platform::String ^ access_mask = nullptr;

		if (/*STATUS_SUCCESS*/ 0 == libPhate::pRtlGetAce(dacl, i, (void**)&pAce))
		{
			switch(pAce->AceType)
			{
			
				case ACCESS_ALLOWED_ACE_TYPE:					//	(0x0)
				{
					pAllowedAce = (ACCESS_ALLOWED_ACE*)pAce;
					sid = libPhate::SidToName((unsigned long long) &pAllowedAce->SidStart);
					ace_flags = libPhate::AceFlagsToString(pAllowedAce->Header.AceFlags);
					access_mask = libPhate::AccessMaskToString(pAllowedAce->Mask);

					swprintf(buffer, BUF_SIZE, L"\tAllowed: %s\r\n\tFlags:   %s\r\n\tAccess:  %s\r\n\r\n", sid->Data(), ace_flags->Data(), access_mask->Data());
					break;
				}
				case ACCESS_DENIED_ACE_TYPE:					//	(0x1)
				{
					pDeniedAce = (ACCESS_DENIED_ACE*)pAce;
					sid = libPhate::SidToName((unsigned long long) &pDeniedAce->SidStart);
					ace_flags = libPhate::AceFlagsToString(pDeniedAce->Header.AceFlags) + ref new Platform::String(L"\r\n\t\t");
					access_mask = libPhate::AccessMaskToString(pDeniedAce->Mask) + ref new Platform::String(L"\r\n\t\t");

					swprintf(buffer, BUF_SIZE, L"\tDenied:  %s\r\n\tFlags:   %s\r\n\tAccess:  %s\r\n\r\n", sid->Data(), ace_flags->Data(), access_mask->Data());
					break;
				}
				case SYSTEM_AUDIT_ACE_TYPE:						//	(0x2)
				{
					//break;
				}
				case SYSTEM_ALARM_ACE_TYPE:						//	(0x3)
				{
					//break;
				}
				case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:			//	(0x4)
				{
					//break;
				}
				case ACCESS_ALLOWED_OBJECT_ACE_TYPE:			//	(0x5)
				{
					//break;
				}
				case ACCESS_DENIED_OBJECT_ACE_TYPE:				//	(0x6)
				{
					//break;
				}
				case SYSTEM_AUDIT_OBJECT_ACE_TYPE:				//	(0x7)
				{
					//break;
				}
				case SYSTEM_ALARM_OBJECT_ACE_TYPE:				//	(0x8)
				{
					//break;
				}
				case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:			//	(0x9)
				{
					//break;
				}
				case ACCESS_DENIED_CALLBACK_ACE_TYPE:			//	(0xA)
				{
					//break;
				}
				case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:	//	(0xB)
				{
					//break;
				}
				case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:	//	(0xC)
				{
					//break;
				}
				case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:			//	(0xD)
				{
					//break;
				}
				case SYSTEM_ALARM_CALLBACK_ACE_TYPE:			//	(0xE)
				{
					//break;
				}
				case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:		//	(0xF)
				{
					//break;
				}
				case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:		//	(0x10)
				{
					//break;
				}
				case SYSTEM_MANDATORY_LABEL_ACE_TYPE:			//	(0x11)
				{
					//break;
				}
				case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:		//	(0x12)
				{
					//break;
				}
				case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:			//	(0x13)
				{
					//break;
				}
				default:
				{
					swprintf(buffer, BUF_SIZE, L"\tUnknown ACE type:  0x%02x\r\n\tFlags:   %s\r\n\tAccess:  %s\r\n\r\n", pAce->AceType, L"n/a", L"n/a");
					break;
				}
			}

			toReturn += ref new Platform::String(buffer);
			
		}
	}
	
	toReturn += "\r\n";
	return toReturn;

}



Platform::String ^ libPhate::ListDirectory(Platform::String^ path, unsigned int flags){

	if(path->Length() == 0)
	{
		// no param, use cwd instead
		// also clear the is_file flag, if set
		path = libPhate::GetCurrentDirectory();

		if (flags & LS_FLAGS::IS_SINGLE_FILE)
			flags &= ~LS_FLAGS::IS_SINGLE_FILE;
	} //okay now our path should be stable

	// TODO: There's a bug in storing the path in orig for the sec checks.  
	// If there are wild cards embedded in it, the sec checks are going to fail when we try to
	// concatenate the file name with orig. 

	Platform::String ^ orig = path; // needed for security queries
		
	if ( (wcschr(path->Data(), L'*') != 0) || (wcschr(path->Data(), L'?') != 0))
	{
		// path already contains a wildcard, don't add any more
		// also, it's not a single file, so clear the bit
		if (flags & LS_FLAGS::IS_SINGLE_FILE)
			flags &= ~LS_FLAGS::IS_SINGLE_FILE;
	}
	else if ((flags & LS_FLAGS::IS_SINGLE_FILE) == 0)
	{
		// no wild cards and not a single file
		// check to make sure there isn't an ending slash
		// then add the appropriate end
		if (path->Data()[path->Length() - 1] == L'\\')
		{
			// only add the wildcard
			path += "*";
		}
		else
		{
			// add the end slash and the wild card
			path += "\\*";
		}
	}

	
	
	WIN32_FIND_DATA result;
	wchar_t buffer[BUF_SIZE+1] = {0};
	LARGE_INTEGER filesize;
	DWORD dwError=0;
	HANDLE h = INVALID_HANDLE_VALUE;

	
	Platform::String ^ toReturn = "";

	if (flags & LS_FLAGS::IS_SINGLE_FILE) 
	{
		// this is a file, not a directory
		// get the info needed to keep going
		WIN32_FILE_ATTRIBUTE_DATA w32fad = {0};

		swprintf(result.cFileName, MAX_PATH, L"%s", path->Data());;

		if (FALSE == ::GetFileAttributesEx(path->Data(), GetFileExInfoStandard, &w32fad))
		{
			result.dwFileAttributes = 0;
			filesize.QuadPart = 0;
		}
		else
		{
			result.dwFileAttributes = w32fad.dwFileAttributes;
			result.nFileSizeHigh = w32fad.nFileSizeHigh;
			result.nFileSizeLow = w32fad.nFileSizeLow;
			result.ftCreationTime = w32fad.ftCreationTime;
			result.ftLastAccessTime = w32fad.ftLastAccessTime;
			result.ftLastWriteTime = w32fad.ftLastWriteTime;
		}

	}
	else
	{
		// open the search handle
		h = libPhate::pFindFirstFile(path->Data(), &result);

		if(h == INVALID_HANDLE_VALUE)
			return "Error: " + errorToString(GetLastError());
	}
	
	do
   {
	  if (result.cFileName[0] == L'.'){ // for . and ..
		  if(result.cFileName[1] == L'\0' || (result.cFileName[1] == L'.' && result.cFileName[2] == L'\0')){
			 swprintf(buffer, BUF_SIZE, L"dir:  \t%s\r\n", result.cFileName);
			 toReturn += ref new Platform::String(buffer);
		  }
      }
      else
      {
		  if (result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		  {
			 swprintf(buffer, BUF_SIZE, L"dir:  \t%s\r\n", result.cFileName);
		  }
		  else
		  {

			 filesize.LowPart = result.nFileSizeLow;
			 filesize.HighPart = result.nFileSizeHigh;

			 swprintf(buffer, BUF_SIZE, L"file: \t%-16s\t%ld B\r\n", result.cFileName, filesize.QuadPart);
			 
		  }
	
		  toReturn += ref new Platform::String(buffer); 

		 //okay lets do perms here
		  if (flags & LS_FLAGS::GET_SEC_INFO)
		  {
			  if (flags & LS_FLAGS::IS_SINGLE_FILE)
				toReturn += libPhate::GetFilePerms(orig);
			  else
				  toReturn += libPhate::GetFilePerms(orig + "\\" + ref new Platform::String(result.cFileName));
		  }
	  }
   }
   while ((libPhate::pFindNextFile(h, &result) != 0) && !(flags & LS_FLAGS::IS_SINGLE_FILE) /*short circuit for single file case*/ );
 
   dwError = ::GetLastError();
   if (dwError != ERROR_NO_MORE_FILES && dwError != ERROR_INVALID_HANDLE ) 
   {
	   toReturn += "error occured: " + errorToString(dwError);
   }

  if( libPhate::pFindClose(h) == 0)
	  toReturn += "error occured in FindClose: " + errorToString(GetLastError());
   return toReturn;



}

//@return pid on success
//@return -err on error
int64 libPhate::CreateProcess(Platform::String^ commandLine){
	
	size_t len = commandLine->Length() + 1;
	PWSTR cmd = new WCHAR[len];
	wcscpy_s(cmd, len, commandLine->Data());
	STARTUPINFO si;
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;

	BOOL ret = libPhate::pCreateProcess(NULL, cmd, NULL, NULL, FALSE, 0x0, NULL, NULL, &si, &pi);

	delete[] cmd;
	if (ret)
	{
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return pi.dwProcessId;
	}
	else
	{
		DWORD err = ::GetLastError();
		//::OutputDebugStringW(ErrorToString(err)->Data());
		return -1 * ((int64) err);
	}
}

uint64 libPhate::OpenFile(Platform::String^ name, Platform::String^ mode)
{
	FILE * fp = nullptr;
	const wchar_t*  n = name->Data();
	const wchar_t* m = mode->Data();
	
	try
	{
		_wfopen_s(&fp, n, m);
	}
	catch(...)
	{
		fp = nullptr;
	}

	return (uint64) fp;
}

 int64 libPhate::RunDLL(Platform::String^ lib, Platform::String^ func, const Platform::Array<Platform::String^>^ values, const Platform::Array<Platform::String^>^ types, int count){

	 // load lib
	 uint64 libBase = libPhate::LoadLibrary(lib);

	 // getprocaddr func
	 uint64 funcPtr = libPhate::GetProcAddress(libBase, func );

	 // prepare args
	 void* args[MAX_ARGS] = {0};

	 for(int i=0; i < count; i++){
		 if(types->get(i) == "int"){ //64 bit signed int
			std::wstring ws( values->get(i)->Data());
			std::wstringstream conv;
			int64 tmp;
			conv << ws;
			conv >> tmp;
			args[i] = (void*)tmp;
		 }
		 if(types->get(i) == "uint"){ //64 bit unsigned int
			std::wstring ws( values->get(i)->Data());
			std::wstringstream conv;
			uint64 tmp;
			conv << ws;
			conv >> tmp;
			args[i] = (void*)tmp;
		 }
		 if(types->get(i) == "str"){ //unicode string
			const wchar_t* tmp = values->get(i)->Data();
			args[i] = (void*) tmp;
		 }
		 if(types->get(i) == "astr"){ //ascii string
			 std::wstring w(values->get(i)->Data());
			 std::string s(w.begin(), w.end());
			 const char* cs = s.c_str();
			 args[i] = (void*) cs;
		 }
	 }


	 // find correct prototype, cast, call
	 if(count==0){
		 auto f = (nullary_t)funcPtr;
		 return (int64) f();
	 }
	 if(count==1){
		 auto f = (unary_t)funcPtr;
		 return (int64) f(args[0]);
	 }
	 if(count==2){
		 auto f = (binary_t)funcPtr;
		 return (int64) f(args[0], args[1]);
	 }
	 if(count==3){
		 auto f = (ternary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2]);
	 }
	 if(count==4){
		 auto f = (quaternary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3]);
	 }
	 if(count==5){
		 auto f = (quinary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4]);
	 }
	 if(count==6){
		 auto f = (senary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5]);
	 }
	 if(count==7){
		 auto f = (septenary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
	 }
	 if(count==8){
		 auto f = (octonary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	 }
	 if(count==9){
		 auto f = (novenary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
	 }
	 if(count==10){
		 auto f = (denary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	 }
	 if(count==11){
		 auto f = (undenary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]);
	 }
	 if(count==12){
		 auto f = (duodenary_t)funcPtr;
		 return (int64) f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
	 }
	 
	 return 0;
 }

bool libPhate::CloseFile(uint64 ptr)
{
	return (0 == fclose((FILE *)ptr));
}


// Note: There are issues with LocalFree and LocalAlloc. See the commented code below
/*
	typedef HLOCAL (WINAPI *LocalAlloc_t)(
	  _In_  UINT uFlags,
	  _In_  SIZE_T uBytes
	);

	LocalAlloc_t LocalAlloc = nullptr;
    // Retrieve the system error message for the last-error code

	if (LocalAlloc == nullptr) (LocalAlloc_t)GetProcAddress((HMODULE)s_kernelbase_base, "LocalAlloc");

	// TODO: Figure out which functions can't be found in the dlls, and why not
	// Ex. LocalAlloc, which I can see in the exports and in memory, but GPA() fails
	// Until then, here's a hardcoded offset :(
	if (!LocalAlloc) LocalAlloc = (LocalAlloc_t)(s_kernelbase_base + 0xC439);
*/


//now we are using malloc/free, so we don't need LocalFree()
Platform::String^ libPhate::errorToString(unsigned int errcode) 
{ 

	wchar_t * lpMsgBuf = (wchar_t*) malloc(BUF_SIZE);
 
    ::FormatMessageW( 
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errcode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)lpMsgBuf,
        BUF_SIZE, NULL );

    // Return the error
	Platform::String^ toRet = ref new String(lpMsgBuf);
	free(lpMsgBuf);
	return toRet;

}

//note: caller should check for errors
uint64 libPhate::OpenProcessToken(uint64 process_handle, uint64 access_desired)
{
	HANDLE retval = INVALID_HANDLE_VALUE;
	
	libPhate::pOpenProcessToken((HANDLE)process_handle, (DWORD)access_desired, &retval);

	return (uint64)retval;


}

//useful little macro for when you want to return a pointer or an error
int errReturn(int err){
	if(err > 0) return -err;
	return err;
}

// TODO: Refactor the various GetCurrent* methods to be more consistent in style and to make sure they don't leak memory


/**
refactored so that there can be code reuse
@return:
0 if it received a null token
-err if an error occured
ptr to TOKEN_USER if suceeded

remember to FREE the TOKEN_USER after you are done with it!
**/
int libPhate::GetCurrentUserInfo(int flags)
{
	HANDLE token_handle = INVALID_HANDLE_VALUE;
	TOKEN_USER *output = nullptr;
	unsigned char * input = nullptr;
	DWORD output_len = 0;

	int err = libPhate::pOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle);
	if( FALSE == err)
		return errReturn(GetLastError());

	if (FALSE == libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenUser, input, 0, &output_len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{ 
		//allocate memory
		int bufLen = sizeof(TOKEN_USER)+output_len;
		input = (unsigned char *) malloc(bufLen);
		if (input == nullptr || FALSE == libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenUser,input, bufLen, &output_len))
		{
			free(input);
			if(input == nullptr) return NULL;
			return errReturn(GetLastError());
		}
	}
	
	
	if (output_len == 0) // it failed to write any output XXX: changing this from getLastError() because i don't think that it sets getLastError() to ERROR_SUCCESS when it succeeds
	{
		free(input);
		return errReturn(GetLastError());
	}

	
	output = (TOKEN_USER*)input;
	return (int)output;
}


Platform::String^ libPhate::PrintCurrentUserInfo(int flags)
{

	int info = libPhate::GetCurrentUserInfo(flags);

	if(info < 0)
		return libPhate::errorToString(-info);

	if(info == 0)
		return "received a null TOKEN_USER";

	TOKEN_USER* output = (TOKEN_USER*) info;

	Platform::String^ retstr;

	//if (flags & 1) // User Name
		retstr = libPhate::SidToName((unsigned long long)output->User.Sid) + "\r\n";

	if (flags & 1) // User Groups
		retstr += libPhate::GetCurrentUserGroups() + "\r\n";

	if (flags & 2) // User Privs
		retstr += libPhate::GetCurrentUserPrivileges() + "\r\n";

	free(output);
	return retstr;

}

Platform::String^ libPhate::GetCurrentUserPrivileges()
{
	

	HANDLE token_handle = INVALID_HANDLE_VALUE;
	unsigned char buf[256] = {0};
	TOKEN_PRIVILEGES *output = nullptr;
	unsigned char * input = (unsigned char *)buf;
	DWORD output_len = 0;

	if (FALSE == libPhate::pOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle))
		return errorToString(GetLastError());

	if (FALSE == libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenPrivileges, input, sizeof(buf), &output_len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		// try again, but allocate enough memory
		input = (unsigned char *) malloc((sizeof(TOKEN_USER)+output_len) * sizeof(unsigned char));
		if (input == nullptr && FALSE == libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenPrivileges,input, output_len, &output_len))
		{
			if (input != nullptr) free(input);
			return libPhate::errorToString(GetLastError());
		}
	}
	
	
	if (output_len == 0 || GetLastError() != 0) // it failed to write any output
	{
		if (input != (unsigned char *)&buf && input != nullptr) free(input);
		return libPhate::errorToString(GetLastError());
	}

	
	output = (TOKEN_PRIVILEGES*)input;

	Platform::String ^ retval = ref new Platform::String();

	for (unsigned int i = 0; i < output->PrivilegeCount; i++)
	{
		wchar_t* name = nullptr;
		DWORD name_len = 0;

		libPhate::pLookupPrivilegeName(NULL, &(output->Privileges[i].Luid), name, &name_len);
		name = (wchar_t*)malloc((name_len+1) * sizeof(wchar_t));
		libPhate::pLookupPrivilegeName(NULL, &(output->Privileges[i].Luid), name, &name_len);

		retval += "\r\n" + ref new Platform::String(name); 

		free(name);
	}

	return retval;

}

Platform::String ^ libPhate::crackTokenGroupAttributes(unsigned int attrs)
{
	Platform::String ^ retval = ref new Platform::String();

	if (attrs & SE_GROUP_MANDATORY  )
		retval += "Mandatory ";

	if (attrs & SE_GROUP_ENABLED)
		retval += "Enabled ";
	
	if (attrs & SE_GROUP_ENABLED_BY_DEFAULT)
		retval += "default ";

	if (attrs & SE_GROUP_INTEGRITY)
		retval += "Integrity ";
	 
	if (attrs & SE_GROUP_INTEGRITY_ENABLED )
		retval += "enabled ";

	if (attrs & SE_GROUP_LOGON_ID )
		retval += "Logon "; 

	if (attrs & SE_GROUP_OWNER )
		retval += "Owner "; 

	if (attrs & SE_GROUP_RESOURCE  )
		retval += "Domain-Local "; 

	if (attrs & SE_GROUP_USE_FOR_DENY_ONLY  )
		retval += "Deny-Only "; 

	return retval;

}

Platform::String^ libPhate::GetCurrentUserGroups()
{


	HANDLE token_handle = INVALID_HANDLE_VALUE;
	unsigned char buf[256] = {0};
	TOKEN_GROUPS *output = nullptr;
	unsigned char * input = (unsigned char *)buf;
	DWORD output_len = sizeof(buf);

	if (FALSE == libPhate::pOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle))
		return libPhate::errorToString(GetLastError());

	if (FALSE == libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenGroups, input, output_len, &output_len))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return libPhate::errorToString(GetLastError());

		// try again, but allocate enough memory
		input = nullptr;
		unsigned int mem_to_alloc = 0;
		BOOL result;

		do
		{
			::SetLastError(0);

			mem_to_alloc += output_len;

			input = (unsigned char *) realloc(input, mem_to_alloc);
		
			if (input == nullptr)
			{
				return libPhate::errorToString(GetLastError());
			}

			result = libPhate::pGetTokenInformation(token_handle, _TOKEN_INFORMATION_CLASS::TokenGroups, input, mem_to_alloc, &output_len);

		} while (result == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
	}
	
	
	if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER && GetLastError() != 0) 
	{
		if (input != (unsigned char *)&buf && input != nullptr) free(input);
		return libPhate::errorToString(GetLastError());
	}

	
	output = (TOKEN_GROUPS*)input;

	Platform::String ^ retval = ref new Platform::String();

	for (unsigned int i = 0; i < output->GroupCount; i++)
	{
		retval += "\r\n" + libPhate::SidToName((unsigned long long)output->Groups[i].Sid) + "( " + libPhate::crackTokenGroupAttributes(output->Groups[i].Attributes) + ")";
	}

	if (input != (unsigned char *)&buf && input != nullptr) free(input);

	return retval;

}

// TODO: handle NULL bytes in the file terminating swprintf() early
Platform::String^ libPhate::ReadFile(Platform::String^ name, unsigned int linenum)
{
	std::ifstream file(name->Data());

	if (false == file.is_open())
		return "Error: Unable to open file";

	std::stringstream str;

	str << file.rdbuf();

	file.close();

	std::string s = str.str();

	wchar_t * ws = (wchar_t*)calloc(s.length() +1, sizeof(wchar_t));

	swprintf(ws, s.length(), L"%S", s.c_str());

	Platform::String ^ ret = ref new Platform::String(ws);

	free(ws);

	return ret; 

}

bool libPhate::BurnFree(int type, unsigned long long resource)
{
	switch((BURN_TYPES) type)
	{
		case BURN_TYPES::MEM_PAGES:
		{
			


			if (resource == 0)
				return true; // if you ask to free nothing, then nothing is freed

			if (TRUE == libPhate::pVirtualFree((void*)resource, 0, MEM_RELEASE))
				return true;
			else
				return false;

		}
		break;
		default:
			return false;
	}
}

unsigned long long libPhate::Burn(int type, unsigned int resource_count)
{
	switch((BURN_TYPES) type)
	{
		case BURN_TYPES::MEM_PAGES:
		{
			


			if (resource_count == 0)
				return 0;

			// TODO: Use api to get the page size for the platform, rather than assuming pageSize == 4096
			return (unsigned long long) libPhate::pVirtualAlloc(0, 4096 * resource_count, MEM_COMMIT, PAGE_READWRITE);

		}
		break;
		default:
			return 0;
	}

}


// http://msdn.microsoft.com/en-us/library/windowsphone/develop/jj206987(v=vs.105).aspx
// http://msdn.microsoft.com/en-us/library/windowsphone/develop/jj207065%28v=vs.105%29.aspx#BKMK_Reservedprotocolnames
// http://developer.nokia.com/Community/Wiki/URI_Association_Schemes_List

Platform::String^ libPhate::LaunchUri(Platform::String^ target)
{
	Platform::String ^ retval = nullptr;

	Windows::Foundation::Uri ^ uri = ref new Windows::Foundation::Uri(target);

	try
	{
		concurrency::task<bool> launchUriOperation(Windows::System::Launcher::LaunchUriAsync(uri));
		retval = launchUriOperation.then([](bool success)
		{
			if (success)
				return ref new Platform::String(L"LaunchUri succeeded");
			else
				return ref new Platform::String(L"LaunchUri failed");
		}).get();
	}
	catch(Exception ^ e)
	{
		retval =  "Error: " + e->ToString();
	}

	return retval;
}

Platform::String^ libPhate::LaunchFile(Platform::String^ target)
{
	
	Platform::String ^ retval = nullptr;
	
	
	// TODO: This compiles, but the cast shouldn't be necessary (see launchuri above), but I don't think
	// that concurrency::task has a specialization for  Windows::Storage::StorageFile^, even though all the examples in MSDN
	// show the below without a cast. 
	// See: http://msdn.microsoft.com/en-us/library/windows/apps/windows.storage.applicationdata.localfolder.aspx?cs-save-lang=1&cs-lang=cpp#code-snippet-1

	try
	{
		concurrency::task< Windows::Storage::StorageFile^> fileOperation = (concurrency::task<StorageFile^>)
		   ((ApplicationData::Current)->LocalFolder)->CreateFileAsync(target, Windows::Storage::CreationCollisionOption::OpenIfExists);
		
		fileOperation.then([  ](Windows::Storage::StorageFile^ file)
		{
			if (file != nullptr)
			{
				// Launch the file
				concurrency::task<bool> launchFileOperation(Windows::System::Launcher::LaunchFileAsync(file));
				launchFileOperation.then([](bool success)
				{
					if (success)
						return ref new Platform::String(L"LaunchFile succeeded");
					else
						return ref new Platform::String(L"LaunchFile failed");
				} );
			}
			else
			{
				//file not found
			}
		});
	}
	catch(Exception ^ e)
	{
		
		retval =  "Error: " + e->ToString();
	}

	return retval;
}

Platform::String^ libPhate::EnumerateHandles(Platform::String^ param)
{
	
	
	NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    ULONG i;
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
 
    // NtQuerySystemInformation won't give us the correct buffer size,
    //  so we guess by doubling the buffer size.
    while ((status = libPhate::pNtQuerySystemInformation(SystemHandleInformation,handleInfo,handleInfoSize,NULL)) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
 
    // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
    if (!NT_SUCCESS(status)) {
        return("NtQuerySystemInformation failed!");
    }
	 
	int targetPid = -1;
	

	std::wstring ws( param->Data());
	std::wstringstream conv;
	conv << ws;
	conv >> targetPid;
	

	unsigned int flags = targetPid & 0x03; // mask out the flag bits

	targetPid = targetPid & 0xFFFFFFFC; // and clear them
	
	if (targetPid == 0)
	{
		// It's not likely (currently) to have someone request the idle process to enumerate
		// so assume that the user wanted to enumerate all processes
		targetPid = -1;
	}
	
	Platform::String^ toReturn = "";

	int lastPid = -1;

	unsigned long ourProcessId = (unsigned long) libPhate::GetCurrentProcessId();
	
	
	HANDLE dupHandle = NULL;
	
	HANDLE processHandle = NULL;
	bool clearHandle = false;
    
	for (i = 0; i < handleInfo->HandleCount; i++) 
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		POBJECT_TYPE_INFORMATION objectTypeInfo = nullptr;
		PVOID objectNameInfo = nullptr;
		UNICODE_STRING objectName ={0};
		ULONG returnLength = 0;
        
		// Check if this handle belongs to the PID the user specified
        if (targetPid >= 0 && handle.ProcessId != targetPid)
            continue;
		
		// Check to see if we've changed process handle tables so we can add a message to that effect
		if(handle.ProcessId != lastPid){
			toReturn += "Doing handles for pid# " + handle.ProcessId.ToString() + "\t-\t";
			HANDLE h_temp = libPhate::pOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, handle.ProcessId);
			if (h_temp != NULL)
			{
				toReturn += libPhate::GetProcessName((unsigned long long)h_temp) + "\r\n";
				CloseHandle(h_temp);
			}
			else
			{
				toReturn += "<unknown>\r\n";
			}

			lastPid = handle.ProcessId;
			if (processHandle != NULL)
			{
				::CloseHandle(processHandle); // Close the handle to the prior process
				processHandle = NULL;
			}
		}

		// if the process we're querying is not our process, we need to open that process and duplicate the handle
		if (handle.ProcessId != ourProcessId)
		{
			if (!(processHandle = libPhate::pOpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId))) {
				if ((flags & 1) == 0) // if flags bit 1 is set, do not display handles to unnamed objects
					toReturn += "Could not open handle for pid# " + handle.ProcessId.ToString() + "\r\n";
				continue;
			}

			if (clearHandle)
			{
				// a stale handle from another process is hanging around
				// close it
				::CloseHandle(dupHandle);
				clearHandle = false;
			}

			// Duplicate the handle so we can query it.
			if (!  NT_SUCCESS(libPhate::pNtDuplicateObject(processHandle,(void*) handle.Handle,GetCurrentProcess(),&dupHandle,0,0,0))){
				if ((flags & 1) == 0) // if flags bit 1 is set, do not display handles to unnamed objects
					toReturn += "Error duplicating handle " + handle.Handle.ToString() + " \r\n";
				continue;
			}
			else
				clearHandle = true;
		}
		else
		{
			// this is one of our process' handles, so no need to dup it into our process space
			dupHandle = (HANDLE) handle.Handle;
			clearHandle = false; // wouldn't want to close all of our handles!
		}
 
        // Query the object type.
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);

		// Wrap attempted access to query an object in try/catch because in the time between the snapshot
		// and the query, the process could have closed the handle (I'm guessing), which causes an access
		// violation that crashes the app. Only has happened while debugging, so far (although the catch hasn't
		// caught it)
		try
		{
			NTSTATUS stat = libPhate::pNtQueryObject(dupHandle,ObjectTypeInformation,objectTypeInfo,0x1000,NULL);
			if (!  NT_SUCCESS(stat)) {
				if ((flags & 1) == 0) // if flags bit 1 is set, do not display handles to unnamed objects
					toReturn += "Error querying handle " + handle.Handle.ToString() + " \r\n";
				free(objectTypeInfo);
				if (handle.ProcessId != ourProcessId) CloseHandle(dupHandle);
				continue;
			}

			// Query the object name (unless it has an access of 0x0012019f, on which NtQueryObject could hang.
			// Note: it seems that this has been fixed as of Win 7
			//http://forum.sysinternals.com/discussion-howto-enumerate-handles_topic19403_post105939.html#105939
 
			objectNameInfo = malloc(0x1000);

			if (!  NT_SUCCESS(libPhate::pNtQueryObject( dupHandle,ObjectNameInformation, objectNameInfo, 0x1000, &returnLength ))) {
				// Reallocate the buffer and try again.
				objectNameInfo = realloc(objectNameInfo, returnLength);
				if (!  NT_SUCCESS(libPhate::pNtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,returnLength,NULL))) {
					// We have the type name, so just display that.
					if ((flags & 1) == 0) // if flags bit 1 is set, do not display handles to unnamed objects
						toReturn += "\tHandle #" + handle.Handle.ToString() + "\ttype name:"  + ref new Platform::String(objectTypeInfo->Name.Buffer) + "\tcan't get name\r\n";
					free(objectTypeInfo);
					free(objectNameInfo);
					if (handle.ProcessId != ourProcessId) CloseHandle(dupHandle);
					continue;
				}
			}
		}
		catch(...)
		{
			if ((flags & 1) == 0)
				toReturn += "Error querying handle " + handle.Handle.ToString() + " \r\n";
		}
 
        // Cast our buffer into an UNICODE_STRING.
        objectName = *(PUNICODE_STRING)objectNameInfo;
 
        // Print the information!
        if (objectName.Length)
        {
            // The object has a name.
			if ((flags & 1) == 1)
				toReturn += "\tHandle #" + handle.Handle.ToString() + "\ttypeName:"  + ref new Platform::String(objectTypeInfo->Name.Buffer) + "\tname:" + ref new Platform::String(objectName.Buffer) + "\r\n";
        }
        else {
			if ((flags & 1) == 0) // if flags bit 1 is set, do not display handles to unnamed objects
				toReturn += "\tHandle #" + handle.Handle.ToString() + "\ttypeName:"  + ref new Platform::String(objectTypeInfo->Name.Buffer) + "\tname: unnamed\r\n";
        }
 
        free(objectTypeInfo);
        free(objectNameInfo);
		if (handle.ProcessId != ourProcessId)
		{
			// clean up the handle
			CloseHandle(dupHandle);
			clearHandle = false;
		}

		
    }
 
    free(handleInfo);

	return toReturn;
}

Platform::String^ libPhate::ProcessMitigationInfo(Platform::String^ param){
	


	int targetPid = -1;
	if(param == "") return "missing pid parameter\r\n";
	std::wstring ws( param->Data());
	std::wstringstream conv;
	conv << ws;
	conv >> targetPid;

	//open a handle to the target process

	HANDLE processHandle = libPhate::pOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);

	if(processHandle == NULL){
		return "failed to open process handle, error#" + GetLastError().ToString() + "\r\n";
	}

	Platform::String^ toReturn = "";
	//got handle, let's go through and look at every one of the policies we can
	PROCESS_MITIGATION_DEP_POLICY depBuffer = {0};

	// TODO: Trace this down...regardless of what parameters I send, this fails.  Looking at working samples on the Win 8 Desktop programs
	// My parameters look ok, and I tried with a handle that has PROCESS_ALL_ACCESS.
	// I'm debating whether DEP is even enabled ? It seems to be - I can't just jump to a random bunch of bytes I declare on the stack through a function pointer...
	if(!libPhate::pGetProcessMitigationPolicy(processHandle, ProcessDEPPolicy, &depBuffer, sizeof(PROCESS_MITIGATION_DEP_POLICY)))
		toReturn += "Error: Failed to lookup DEP policy, " + errorToString( GetLastError()) + "\r\n";
	else
		toReturn += "Dep Enabled:" + depBuffer.Enable.ToString() + "\r\nATLThunkEmulation Disabled:" + depBuffer.DisableAtlThunkEmulation.ToString() + "\r\nDep Permanent:" + depBuffer.Permanent.ToString() + "\r\n";


	PROCESS_MITIGATION_ASLR_POLICY aslrBuffer;
	if(!libPhate::pGetProcessMitigationPolicy(processHandle,ProcessASLRPolicy, &aslrBuffer, sizeof(aslrBuffer)))
		toReturn += "failed to lookup aslr policy, " + errorToString( GetLastError()) + "\r\n";
	else
		toReturn += "BottomUpRandomization Enabled:" + aslrBuffer.EnableBottomUpRandomization.ToString() + "\r\nForceRelocateImages Enabled:" + aslrBuffer.EnableForceRelocateImages.ToString() + "\r\nHighEntropyASLR Enabled:" + aslrBuffer.EnableHighEntropy.ToString() + "\nDisallowStrippedImages:" + aslrBuffer.DisallowStrippedImages.ToString() + "\r\n";

	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictBuffer;
	if(!libPhate::pGetProcessMitigationPolicy(processHandle,ProcessStrictHandleCheckPolicy, &strictBuffer, sizeof(strictBuffer)))
		toReturn += "failed to lookup strict handle check policy," + errorToString( GetLastError()) + "\r\n";
	else
		toReturn += "RaiseExceptionOnInvalidHandleReference:" + strictBuffer.RaiseExceptionOnInvalidHandleReference.ToString() + "\r\nHandleExceptionsPermanentlyEnabled:" + strictBuffer.HandleExceptionsPermanentlyEnabled.ToString() + "\r\n";

	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY sysCallBuffer;
	if(!libPhate::pGetProcessMitigationPolicy(processHandle,ProcessSystemCallDisablePolicy, &sysCallBuffer, sizeof(sysCallBuffer)))
		toReturn += "failed to lookup syscall disable policy, " + errorToString( GetLastError()) + "\r\n";
	else
		toReturn += "DisallowWin32KSysCalls:" + sysCallBuffer.DisallowWin32kSystemCalls.ToString() + "\r\n";

	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionBuffer;
	if(!libPhate::pGetProcessMitigationPolicy(processHandle,ProcessExtensionPointDisablePolicy, &extensionBuffer, sizeof(extensionBuffer)))
		toReturn += "failed to lookup extension point disable policy, " + errorToString( GetLastError()) + "\r\n";
	else
		toReturn += "ExtensionPointsDisabled:" + extensionBuffer.DisableExtensionPoints.ToString() + "\r\n";

	CloseHandle(processHandle);
	return toReturn;

}

Platform::String^ libPhate::stateToString(DWORD state){
	switch(state){
		case MEM_COMMIT: return "MEM_COMMIT";
		case MEM_FREE: return "MEM_FREE";
		case MEM_RESERVE: return "MEM_RESERVE";
		default: return "UNKNOWN";
	}
}

Platform::String^ libPhate::registryTypeToString(DWORD type){
	switch(type){
		case REG_BINARY: return "REG_BINARY";
		case REG_DWORD: return "REG_DWORD";
		case REG_QWORD: return "REG_QWORD";
		case REG_SZ: return "REG_SZ";
		case REG_MULTI_SZ: return "REG_MULTI_SZ";
		case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
		case REG_LINK:  return "REG_LINK";
		case REG_NONE:
		default:
			return "REG_NONE";
	}
}


Platform::String^ libPhate::registryValueToString(PBYTE value, DWORD type, DWORD len){
	std::vector<String^> strings;
	wchar_t str[17] = {0};
	String^ toReturn = "";
	PWSTR strptr = (PWSTR) value;
	size_t chars = len / sizeof(WCHAR);
	String ^curstr;

	if (len == 0)
		return ref new Platform::String();

	switch(type){
		case REG_DWORD: 
			swprintf(str, 17, L"%x", *(unsigned int*)value); 
			return ref new Platform::String(str);
		case REG_QWORD:
			swprintf(str, 17, L"%I64x", *(unsigned long long*) value); 
			return ref new Platform::String(str);
		case REG_EXPAND_SZ: 
		case REG_LINK: 
		case REG_SZ: 
			return ref new Platform::String(strptr);
		case REG_MULTI_SZ: 	
			curstr = ref new String(strptr);
			while (curstr->Length() > 0)
			{
				strings.push_back(curstr);
				strptr += (curstr->Length() + 1);
				if (strptr < (PWSTR)(value + chars))
				{
					curstr = ref new String(strptr);
				}
				else
				{
					break;
				}
			}
			for(String^ s : strings)
				toReturn += s;
			return toReturn;
		case REG_NONE:
		case REG_BINARY:  // ascii-hex encoded
		default:
			for(unsigned int i=0; i < len; i++){
				swprintf(str, 3, L"%02x", value[i]); 
				toReturn += ref new String(str);
			}
			return toReturn;	
	}
}

Platform::String^ libPhate::typeToString(DWORD type){
	switch(type){
		case MEM_IMAGE: return "MEM_IMAGE";
		case MEM_MAPPED: return "MEM_MAPPED";
		case MEM_PRIVATE: return "MEM_PRIVATE";
		default: return "UNKNOWN";
	}
}

Platform::String^ libPhate::protectToString(DWORD protect){
	Platform::String^ toReturn = "";
	//base types
	if(protect & PAGE_EXECUTE) toReturn += "PAGE_EXECUTE";
	if(protect & PAGE_EXECUTE_READ) toReturn += "PAGE_EXECUTE_READ";
	if(protect & PAGE_EXECUTE_READWRITE) toReturn += "PAGE_EXECUTE_READWRITE";
	if(protect & PAGE_EXECUTE_WRITECOPY) toReturn += "PAGE_EXECUTE_WRITECOPY";
	if(protect & PAGE_NOACCESS) toReturn += "PAGE_NOACCESS";
	if(protect & PAGE_READONLY) toReturn += "PAGE_READONLY";
	if(protect & PAGE_READWRITE) toReturn += "PAGE_READWRITE";
	if(protect & PAGE_WRITECOPY) toReturn += "PAGE_WRITECOPY";
	//modifiers
	if(protect & PAGE_GUARD) toReturn += " & PAGE_GUARD";
	if(protect & PAGE_NOCACHE) toReturn += "& PAGE_NOCACHE";
	if(protect & PAGE_WRITECOMBINE) toReturn += "& PAGE_WRITECOMBINE";

	return toReturn;
}

Platform::String^ libPhate::MemoryRegions(Platform::String^ param){
	


	int targetPid = -1;
	if(param == "") return "missing pid parameter\r\n";
	std::wstring ws( param->Data());
	std::wstringstream conv;
	conv << ws;
	conv >> targetPid;

	//open a handle to the target process

	HANDLE processHandle = libPhate::pOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);

	if(processHandle == NULL){
		return "failed to open process handle, error:" + errorToString(GetLastError()) + "\r\n";
	}
	Platform::String^ toReturn = "";
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID lpMem = 0;
	
	while (libPhate::pVirtualQueryEx(processHandle, lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0) {
        //printout info about the region
		wchar_t str[17] = {0};
		swprintf(str, 17, L"%p", mbi.BaseAddress);
		toReturn += "*** Memory Region @" + ref new Platform::String(str) + ":\r\n";
		swprintf(str, 17, L"%p", mbi.AllocationBase);
		toReturn += "Allocation Base @" + ref new Platform::String(str) + "\r\n";
		swprintf(str, 17, L"%x", mbi.RegionSize);
		toReturn += "Size: " + ref new Platform::String(str) + "\r\n";
		toReturn += "State: " + stateToString(mbi.State) + "\r\n";
		toReturn += "Type: " + typeToString(mbi.Type) + "\r\n";
		toReturn += "Protections: " + protectToString(mbi.Protect) + "\r\n";
		toReturn += "Allocation Protections: " + protectToString(mbi.AllocationProtect) + "\r\n";
		toReturn += "*** \r\n";
        /* increment lpMem to next region of memory */
        lpMem = (LPVOID)((DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize);
}

	return toReturn;
}

//TODO: refactor this to be case independent
RegistryHive libPhate::stringToRegistryHive(Platform::String^ hive){
	if(hive == "HKEY_CLASSES_ROOT" || hive == "hkcr" || hive == "HKCR") return RegistryHive::HKCR;
	if(hive == "HKEY_CURRENT_USER" || hive == "hkcu" || hive == "HKCU") return RegistryHive::HKCU;
	if(hive == "HKEY_LOCAL_MACHINE" || hive == "hklm" || hive == "HKLM") return RegistryHive::HKLM;
	if(hive == "HKEY_USERS" || hive == "hku" || hive == "HKU") return RegistryHive::HKU;
	if(hive == "HKEY_PERFORMANCE_DATA" || hive == "hkpd" || hive == "HKPD") return RegistryHive::HKPD;
	if(hive == "HKEY_CURRENT_CONFIG" || hive == "hkcc" || hive == "HKCC") return RegistryHive::HKCC;

	return RegistryHive::HKCU; //arbitrary default
}


Platform::String^ libPhate::ReadDWORD (STDREGARGS)
{
	HIVECONVERT
	DWORD data;
	DWORD bytes = sizeof(data);
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : NULL;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegGetValue(
		(HKEY)hive, key, val, RRF_RT_DWORD, NULL, &data,&bytes);
	if (ERROR_SUCCESS == err)
	{
		wchar_t str[17] = {0};
		swprintf(str, 17, L"%x", data); 
		return "Read DWORD: "+ ref new Platform::String(str) + "\r\n";
	}
	else
	{
		return "Error reading: " + errorToString(err) + "\r\n";
	}
}

Platform::String^ libPhate::ReadString(Platform::String^ sHive, Platform::String ^path, Platform::String ^value)
{
	HIVECONVERT
	DWORD bytes = 0;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : NULL;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegGetValue((HKEY)hive, key, val, RRF_RT_REG_SZ, NULL, NULL, &bytes);
	Platform::String^ toReturn = "";
	if (ERROR_SUCCESS == err)
	{
		// Got the length...
		PWSTR str = new WCHAR[bytes];
		err = libPhate::pRegGetValue(
			(HKEY)hive, path->Data(), value->Data(), RRF_RT_REG_SZ, NULL, str, &bytes);
		if (ERROR_SUCCESS == err)
		{
			toReturn += "Read String: " + ref new String(str) + "\r\n";
			delete[] str;
			return toReturn;
		}
		else
		{
			delete[] str;
			return "Error reading: " + errorToString(err) + "\r\n";
		}
	}
	// Can't get here without something going wrong...
	return "Error reading: " + errorToString(err) + "\r\n";
}

String^ libPhate::ReadMultiString (STDREGARGS)
{
	HIVECONVERT
	std::vector<String^> strings;
	DWORD bytes = 0;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : NULL;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegGetValue((HKEY)hive, key, val, RRF_RT_REG_MULTI_SZ, NULL, NULL, &bytes);
	if (ERROR_SUCCESS == err)
	{
		// Got the length...
		size_t chars = bytes / sizeof(WCHAR);
		PWSTR strbuf = new WCHAR[chars];
		PWSTR strptr = strbuf;
		err = libPhate::pRegGetValue((HKEY)hive, path->Data(), value->Data(), RRF_RT_REG_MULTI_SZ, NULL, strbuf, &bytes);
		if (ERROR_SUCCESS == err)
		{
			String ^curstr = ref new String(strptr);
			while (curstr->Length() > 0)
			{
				strings.push_back(curstr);
				strptr += (curstr->Length() + 1);
				if (strptr < (strbuf + chars))
				{
					curstr = ref new String(strptr);
				}
				else
				{
					break;
				}
			}
			String^ toReturn = "";
			for(String^ s : strings)
				toReturn += "Read String: " + s + "\r\n";
			return toReturn;
		}
		else
		{
			delete[] strbuf;
		}
	}
	return "Error reading: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::ReadBinary (STDREGARGS)
{
	HIVECONVERT
	DWORD bytes = 0;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : NULL;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err =libPhate::pRegGetValue((HKEY)hive, key, val, RRF_RT_REG_BINARY, NULL, NULL, &bytes);
	if (ERROR_SUCCESS == err)
	{
		// Got the length...
		PBYTE buf = new BYTE[bytes];
		err = libPhate::pRegGetValue((HKEY)hive, path->Data(), value->Data(), RRF_RT_ANY, NULL, buf, &bytes);
		if (ERROR_SUCCESS == err)
		{
			String^ toReturn = "Read Bytes: ";
			wchar_t str[3] = {0};
			for(unsigned int i=0; i < bytes; i++){
				swprintf(str, 3, L"%02x", buf[i]); 
				toReturn += ref new String(str);
			}
			delete[] buf;
			return toReturn;
		}
		delete[] buf;
	}
	return "Error reading: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::ReadQWORD (STDREGARGS)
{
	HIVECONVERT
	int64_t data;
	DWORD bytes = sizeof(data);
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : NULL;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegGetValue(
		(HKEY)hive, key, val, RRF_RT_QWORD, NULL, &data, &bytes);
	if (ERROR_SUCCESS == err)
	{
		wchar_t str[17] = {0};
		swprintf(str, 17, L"%x", data); 
		return "Read QWORD: "+ ref new Platform::String(str) + "\r\n";
	}
	return "Error reading: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::WriteDWORD (STDREGARGS, uint32 data)
{
	HIVECONVERT
	

	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "Error opening key: " + errorToString(err) + "\r\n";
	}
	err = libPhate::pRegSetValueEx(hkey, val, 0x0, REG_DWORD, (PBYTE)(&data), sizeof(data));
	libPhate::pRegCloseKey(hkey);
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error setting value: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::WriteString (STDREGARGS, String ^data)
{
	HIVECONVERT
	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "Error opening key: " + errorToString(err) + "\r\n";
	}
	err = libPhate::pRegSetValueEx(hkey, val, 0x0, REG_SZ, (PBYTE)(data->Data()), ((data->Length() + 1) * (sizeof(WCHAR))));
	libPhate::pRegCloseKey(hkey);
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error setting value: " + errorToString(err) + "\r\n";

}

Platform::String^ libPhate::WriteMultiString (STDREGARGS, const Array<String^> ^data)
{
	HIVECONVERT
	// Build the buffer
	size_t chars = 0x0;
	for (String ^*str = data->begin(); str != data->end(); str++)
	{
		chars += (*str)->Length();
		chars++;	// For the null byte
	}
	PWCHAR buffer = new WCHAR[++chars];
	int index = 0;
	for (String ^*str = data->begin(); str != data->end(); str++)
	{
		// Copy this string, including its terminating null
		memcpy(buffer + index, (*str)->Data(), (((*str)->Length() + 1) * sizeof(WCHAR)));
		index += ((*str)->Length() + 1);
	}
	buffer[chars - 1] = L'\0';

	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "Error opening key: " + errorToString(err) + "\r\n";
	}
	err = libPhate::pRegSetValueEx(hkey, val, 0x0, REG_MULTI_SZ, (PBYTE)(buffer), (chars * (sizeof(WCHAR))));
	libPhate::pRegCloseKey(hkey);
	delete[] buffer;
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error setting value: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::WriteBinary (STDREGARGS, const Array<uint8> ^data)
{
	HIVECONVERT
	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "Error opening key: " + errorToString(err) + "\r\n";

	}
	err = libPhate::pRegSetValueEx(hkey, val, 0x0, REG_BINARY, data->Data, data->Length);
	libPhate::pRegCloseKey(hkey);
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error setting value: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::WriteQWORD (STDREGARGS, uint64 data)
{
	HIVECONVERT
	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "Error opening key: " + errorToString(err) + "\r\n";
	}
	err = libPhate::pRegSetValueEx(hkey, val, 0x0, REG_QWORD, (PBYTE)(&data), sizeof(data));
	libPhate::pRegCloseKey(hkey);
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error setting value: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::DeleteValue (STDREGARGS)
{
	HIVECONVERT
	// Key or value name can be null; in that case, use the default value and/or the specified key
	HKEY hkey = (HKEY)hive;
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err;
	if ((nullptr != path) && (path->Length() > 0))
	{
		// Need to open a sub-key
		err = libPhate::pRegOpenKeyEx((HKEY)hive, path->Data(), 0x0, KEY_SET_VALUE, &hkey);
		if (err != ERROR_SUCCESS)
		{
			return "Error opening key: " + errorToString(err) + "\r\n";
		}
	}
	err = libPhate::pRegDeleteValue(hkey, val);
	if (path && path->Length())
	{
		libPhate::pRegCloseKey(hkey);
	}
	if (ERROR_SUCCESS == err)
	{
		return "Success! \r\n";
	}
	return "Error deleting: " + errorToString(err) + "\r\n";

}

Platform::String^ libPhate::DeleteKey (Platform::String^ sHive, String ^path, bool recursive)
{
	HIVECONVERT
	LSTATUS err;
	if (recursive)
	{
		err = libPhate::pRegDeleteTree((HKEY)hive, path->Data());
		if (err != ERROR_SUCCESS)
		{
			return "Error opening key: " + errorToString(err) + "\r\n";
		}
	}
	err = libPhate::pRegDeleteKey((HKEY)hive, path->Data());
	if (err != ERROR_SUCCESS)
	{
		return "Success! \r\n";

	}
	return "Error deleting: " + errorToString(err) + "\r\n";
}

Platform::String^ libPhate::CreateKey (Platform::String^ sHive, String ^path)
{
	HIVECONVERT
	HKEY hk = NULL;
	LSTATUS err = libPhate::pRegCreateKeyEx((HKEY)hive, path->Data(), 0x0, NULL, 0x0, KEY_READ | KEY_WRITE, NULL, &hk, NULL);
	if (ERROR_SUCCESS != err)
	{
		return "Error creating key: " + errorToString(err) + "\r\n";
	}
	libPhate::pRegCloseKey(hk);
	return "Success! \r\n";
}

Platform::String^ libPhate::EnumRegKey (Platform::String^ sHive, String ^path)
{
	HIVECONVERT

	HKEY hk;
	if (ERROR_SUCCESS != libPhate::pRegOpenKeyEx((HKEY)hive, NULL, 0,  KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE ,&hk))
		return "Error: unable to open key";

	DWORD subkey_count = 0x0, values_count = 0x00;
	DWORD subkey_maxlen = 0x0, values_name_maxlen = 0x00, values_val_maxlen = 0x00;
	DWORD secdesc_bytelen = 0x00;

	
	LSTATUS err = ERROR_SUCCESS;
	PWSTR * pnames = NULL;
	PWSTR * values_names = NULL;
	PBYTE * values_values = NULL;
	DWORD * types = NULL;
	DWORD * value_lens = NULL;

	Platform::String ^ name;
	unsigned char * sd_raw = NULL;

	int i;
	Platform::String^ toReturn = "";

	// Get the key we're querying on
	if ((nullptr != path) && (!path->IsEmpty()))
	{
		hk = GetHKey(hk, path->Data(), KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, RCOOK_OPEN_EXISTING);
	}

	if (hk)
	{
		// Get the info needed for the enumeration
		err = libPhate::pRegQueryInfoKey(hk, NULL, NULL, NULL, &subkey_count, &subkey_maxlen, NULL, &values_count, &values_name_maxlen, &values_val_maxlen, &secdesc_bytelen, NULL);
		subkey_maxlen++; // for the null terminator
		values_name_maxlen++;	// for the null terminator
		values_val_maxlen++;	// for the null terminator


	}
	else
	{
		toReturn += "Error querying Registry key";
		goto Cleanup;
	}

	if (ERROR_SUCCESS != err)
	{
		toReturn = "error in QueryInfoKey: " + errorToString(err) + "\r\n";
		goto Cleanup;
	}
	
	toReturn += sHive + "\\" + path + "\r\n";

	/******************* SUBKEYS *******************/
	// Create an array of C wstrings to hold the names
	pnames = new PWSTR[subkey_count];
	if (nullptr == pnames)
	{
		toReturn = "out of memory! \r\n";
		goto Cleanup;
	}
	// Populate the array of names
	for (i = 0; i < (int)subkey_count; i++)
	{
		pnames[i] = new WCHAR[subkey_maxlen];
		if (nullptr == pnames[i])
		{
			toReturn = "out of memory! \r\n";
			goto Cleanup;
		}
	}
	if (!libPhate::EnumSubKeys(hk, pnames, subkey_count, subkey_maxlen))
	{
		toReturn = "enum sub keys failed with error: " + errorToString(GetLastError()) + "\r\n";
		goto Cleanup;
	}

	/******************* VALUES *******************/
	values_names = new PWSTR[values_count]();
	values_values = new PBYTE[values_count]();
	types = new DWORD[values_count]();
	value_lens = new DWORD[values_count]();
	if (nullptr == values_names || nullptr == values_values || types == nullptr || value_lens == nullptr)
	{
		toReturn = "out of memory! \r\n";
		goto Cleanup;
	}

	// Populate the array of names
	for (i = 0; i < (int)values_count; i++)
	{
		values_names[i] = new WCHAR[values_name_maxlen](); 
		values_values[i] = new BYTE[values_val_maxlen]();
		if (nullptr == values_names[i] || nullptr == values_values[i])
		{
			toReturn = "out of memory! \r\n";
			goto Cleanup;
		}
	}
	if (! (err = libPhate::EnumValues(hk, values_count, values_names, values_name_maxlen, values_values, values_val_maxlen, types, value_lens)))
	{
		toReturn = "enum values failed with error: " + errorToString(GetLastError()) + "\r\n";
		goto Cleanup;
	}

	// Get the Security Descriptor and print it out
	/******************* SD *******************/
	
	if (sHive == "HKEY_CURRENT_USER" || sHive == "hkcu") 
		name = "CURRENT_USER\\";
	else if (sHive == "HKEY_LOCAL_MACHINE" || sHive == "hklm")
		name = "MACHINE\\";
	else if (sHive == "HKEY_USERS" || sHive == "hku")
		name = "USERS\\";
	else if (sHive == "HKEY_CLASSES_ROOT"|| sHive == "hkcr")
		name = "CLASSES_ROOT\\";
	else
		name = "";

	if (name != "")
		toReturn += libPhate::GetRegPerms(name+path);
	else
		toReturn += "\tNo Security Information available\r\n\r\n";

	toReturn += "Subkeys:\r\n\r\n";

	/**************** Return Values **********/
	//	OK, should be ready to create the return value
	for (unsigned j = 0; j < subkey_count; j++)
	{
		toReturn += "\t" + ref new Platform::String(pnames[j]) + "\r\n";

	}

	toReturn += "\r\nValues:\r\n\r\n";

	for (unsigned j = 0; j < values_count; j++)
	{
		if (wcscmp(values_names[j], L"") == 0)
			toReturn += "\t(default)";
		else
			toReturn += "\t" + ref new Platform::String(values_names[j]);
		
		toReturn +=  " [";
		toReturn += registryTypeToString(types[j]) + "]: ";

		toReturn += registryValueToString(values_values[j], types[j], value_lens[j]) + "\r\n";

	}



Cleanup:
	if (pnames)
	{
		for (unsigned i=0; i < subkey_count; i++)
			delete[] pnames[i];
		delete[] pnames;
	}
	if (values_names)
	{
		for(unsigned i=0; i < values_count; i++)
			delete[] values_names[i];
		delete[] values_names;
	}
	if (values_values)
	{
		for(unsigned i=0; i < values_count; i++)
			delete[] values_values[i];
		delete[] values_values;
	}
	delete[] types;
	delete[] value_lens;
	if (hk && (hk != (HKEY)hive))
	{
		libPhate::pRegCloseKey(hk);
	}

	return toReturn;
}

Platform::String^ libPhate::GetSubKeyNames (Platform::String^ sHive, String ^path)
{
	HIVECONVERT
	DWORD count = 0x0;
	DWORD maxlen = 0x0;
	HKEY hk = (HKEY)hive;
	LSTATUS err = ERROR_SUCCESS;
	PWSTR *pnames = NULL;
	int i;
	Platform::String^ toReturn = "";

	// Get the key we're querying on
	if ((nullptr != path) && (!path->IsEmpty()))
	{
		hk = GetHKey(hk, path->Data(), KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, RCOOK_OPEN_EXISTING);
	}
	if (hk)
	{
		// Get the info needed for the enumeration
		err = libPhate::pRegQueryInfoKey(hk, NULL, NULL, NULL, &count, &maxlen, NULL, NULL, NULL, NULL, NULL, NULL);
		maxlen++;
	}
	else
	{
		goto Cleanup;
	}
	if (ERROR_SUCCESS != err)
	{
		toReturn = "error in QueryInfoKey: " + errorToString(err) + "\r\n";
		goto Cleanup;
	}
	
	// Create an array of C wstrings to hold the names
	pnames = new PWSTR[count];
	if (nullptr == pnames)
	{
		toReturn = "out of memory! \r\n";
		goto Cleanup;
	}
	// Populate the array of names
	for (i = 0; i < (int)count; i++)
	{
		pnames[i] = new WCHAR[maxlen];
		if (nullptr == pnames[i])
		{
			toReturn = "out of memory! \r\n";
			goto Cleanup;
		}
	}
	if (!libPhate::EnumSubKeys(hk, pnames, count, maxlen))
	{
		toReturn = "enum sub keys failed \r\n";
		goto Cleanup;
	}

	//	OK, should be ready to create the return value
	for (unsigned j = 0; j < count; j++)
	{ 		//print each of the pnames
		toReturn += "SubKeyName: " + ref new Platform::String(pnames[j]) + "\r\n";
	}

Cleanup:
	if (pnames)
	{
		// Free all allocations so far
		for (i--; i >= 0; i--)
		{
			delete[] pnames[i];
		}
		delete[] pnames;
	}
	if (hk && (hk != (HKEY)hive))
	{
		libPhate::pRegCloseKey(hk);
	}

	return toReturn;
}

Platform::String^ libPhate::GetValues (Platform::String^ sHive, String ^path)
{
	HIVECONVERT
	DWORD count = 0x0;
	DWORD maxlen = 0x0;
	DWORD length = 0x0;
	PWSTR name = NULL;
	HKEY hk = (HKEY)hive;
	LSTATUS err = ERROR_SUCCESS;
	Platform::String^ toReturn = "";
	bool unexpected = false;
	int i;

	// Get the key we're querying on
	if ((nullptr != path) && (!path->IsEmpty()))
	{
		hk = GetHKey(hk, path->Data(), KEY_QUERY_VALUE, RCOOK_OPEN_EXISTING);
	}
	if (hk)
	{
		// Get the info needed for the enumeration
		err = libPhate::pRegQueryInfoKey(hk, NULL, NULL, NULL, NULL, NULL, NULL, &count, &maxlen, NULL, NULL, NULL);
		maxlen++;	// For the NULL character
	}
	else
	{
		toReturn += "Error in GetHKey: " + errorToString(err) + "\r\n";
		goto Cleanup;
	}
	if (ERROR_SUCCESS != err)
	{
		toReturn += "Error in RegQueryInfoKey: " + errorToString(err) + "\r\n";
		goto Cleanup;
	}
	
	// Populate the values
	name = new WCHAR[maxlen];
	if (nullptr == name)
	{
		toReturn += "Out of memory! \r\n";
		goto Cleanup;
	}
	for (i = 0; i < (int)count; i++)
	{
		length = maxlen;
		//value info
		String ^Name;
		RegistryType Type;
		uint32 Length;
		err = libPhate::pRegEnumValue(hk, i, name, &length, NULL, (LPDWORD)&Type, NULL, (LPDWORD)&Length);
		if (err != ERROR_SUCCESS)
		{
			if (ERROR_NO_MORE_ITEMS == err)
			{
				// Unexpected, but handle it by shortening the returned array
				count = i;
				break;
			}
			else if (ERROR_MORE_DATA == err && !unexpected)
			{
				// name length too short
				maxlen = length + 1;
				delete[] name;
				name = new WCHAR[maxlen];
				i--;
				unexpected = true;
			}
			else
			{
				toReturn += "Error in RegEnumValue: " + errorToString(err) + "\r\n";
				goto Cleanup;
			}
		}
		else
		{
			// Enum for this val succeeded
			unexpected = false;
			toReturn += "Value: " + ref new String(name) + "\r\n";
		}
	}


Cleanup:
	if (name) delete[] name;
	if (hk && (hk != (HKEY)hive))
	{
		libPhate::pRegCloseKey(hk);
	}

	return toReturn;
}

Platform::String^ libPhate::CanWrite (STDREGARGS)
{
	HIVECONVERT
	HKEY hkey = NULL;
	// Key or value name can be null; in that case, use the default value and/or the specified key
	PCWSTR key = path ? path->Data() : L"";
	PCWSTR val = value ? value->Data() : NULL;
	LSTATUS err = libPhate::pRegOpenKeyEx((HKEY)hive, key, 0x0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &hkey);
	if (err != ERROR_SUCCESS)
	{
		return "cannot write / error opening key: " + errorToString(err) + "\r\n";
	}
	// Open succeeded, so clean up
	libPhate::pRegCloseKey(hkey);
	return "can write! \r\n";
}


HKEY libPhate::GetHKey (HKEY base, PCWSTR path, REGSAM permission, RegCreateOrOpenKey disposition)
{
	HKEY ret = nullptr;
	LSTATUS err;
	DWORD disp = 0x0;
	if (RCOOK_OPEN_EXISTING == disposition)
	{
		err = libPhate::pRegOpenKeyEx(base, path, 0x0, permission, &ret);
	}
	else
	{
		err = libPhate::pRegCreateKeyEx(base, path, 0x0, NULL, 0x0, permission, NULL, &ret, (PDWORD)&disp);
	}
	if (err != ERROR_SUCCESS)
	{
		SetLastError(err);
		ret = nullptr;
	}
	if ((RCOOK_CREATE_NEW == disposition) && (REG_CREATED_NEW_KEY != disp))
	{
		SetLastError(ERROR_FILE_EXISTS);
		ret = nullptr;
	}
	return ret;
}

bool libPhate::EnumSubKeys (HKEY key, PWSTR *names, DWORD count, DWORD maxlen)
{
	LSTATUS err = ERROR_SUCCESS;
	DWORD length = maxlen;
	for (DWORD i = 0x0; i < count; i++)
	{
		err = libPhate::pRegEnumKeyEx(key, i, names[i], &length, NULL, NULL, NULL, NULL);
		if (err != ERROR_SUCCESS)
		{
			if (ERROR_NO_MORE_ITEMS == err)
			{
				// End of the key... might be unexpected, but handle anyhow
				for (; i < count; i++)
				{
					// empty-string the rest of the values
					names[i][0] = L'\0';
				}
				break;
			}
			else
			{
				// An actual error occurred
				SetLastError(err);
				return false;
			}
		}
		length = maxlen;
	}
	return true;
}

bool libPhate::EnumValues (HKEY key, DWORD count, PWSTR *names,DWORD names_maxlen, PBYTE *vals,DWORD vals_maxlen, DWORD * types, DWORD * val_lens)
{
	LSTATUS err = ERROR_SUCCESS;
	DWORD name_length = names_maxlen;
	DWORD val_length = vals_maxlen;

	for (DWORD i = 0x0; i < count; i++)
	{
		err = libPhate::pRegEnumValue(key, i, names[i], &name_length, NULL, &types[i], vals[i], &val_length);
		val_lens[i] = val_length;
		if (err != ERROR_SUCCESS)
		{
			if (ERROR_NO_MORE_ITEMS == err)
			{
				// End of the key... might be unexpected, but handle anyhow
				for (; i < count; i++)
				{
					// empty-string the rest of the values
					names[i][0] = L'\0';
					types[i] = REG_NONE;
					vals[i][0] = '\0';
					val_lens[i] = 0;
				}
				break;
			}
			else
			{
				// An actual error occurred
				SetLastError(err);
				return false;
			}
		}
		
		name_length = names_maxlen;
		val_length = vals_maxlen;
	}
	return true;
}


// processes stuff from GoodDayToDie
// TODO: write C# bindings to integrate more of this into Phate
bool libPhate::TerminateProcess (uint32 processID)
{
	HANDLE proc =  libPhate::pOpenProcess(PROCESS_TERMINATE, FALSE, processID);
	BOOL ret = FALSE;
	if (NULL != proc)
	{
		ret =  libPhate::pTerminateProcess(proc, 0x0);
		CloseHandle(proc);
	}
	return !!ret;
}

Platform::String^ libPhate::GetCommandLine()
{
	

	return ref new String(libPhate::pGetCommandLine());
}





Platform::String^ libPhate::GetEnvironmentVariable (String ^name)
{
	
	PCWSTR n = name->Data();
	DWORD size = 0x0;
	DWORD size2 = 0x1;
	PWSTR buf = NULL;
	while (size2 >= size)
	{
		if (buf != NULL)
		{
			delete[] buf;
		}
		size = libPhate::pGetEnvironmentVariable(n, NULL, 0);
		if (size > 0)
		{
			buf = new WCHAR[size];
			size2 = libPhate::pGetEnvironmentVariable(n, buf, size);
		}
	}
	if (size2 > 0)
	{
		// Function succeeded
		String ^ret = ref new String(buf);
		delete[] buf;
		return ret;
	}
	else
	{
		delete[] buf;
		return nullptr;
	}
}




bool libPhate::SetEnvironmentVariable (String ^name, String ^value)
{
	
	return !!libPhate::pSetEnvironmentVariable(name->Data(), value->Data());
}


Array<uint8>^ libPhate::ReadFile (String ^path, int64 offset, uint32 length)
{
	HANDLE file = ::CreateFile2(path->Data(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, NULL);
	if (INVALID_HANDLE_VALUE == file) return nullptr;
	FILE_STANDARD_INFO info;
	if (!::GetFileInformationByHandleEx(file, FileStandardInfo, &info, sizeof(FILE_STANDARD_INFO)))
	{
		::CloseHandle(file);
		return nullptr;
	}
	if (info.EndOfFile.QuadPart < offset)
	{
		::SetLastError(ERROR_BAD_ARGUMENTS);
		return nullptr;
	}
	uint32 len = ((info.EndOfFile.QuadPart - offset) > length) ? 
		length	// There's at least length bytes remaining
		: (uint32)(info.EndOfFile.QuadPart - offset);
	Array<uint8> ^ret = ref new Array<uint8>(len);
	DWORD bytes = 0;
	LARGE_INTEGER li; li.QuadPart = offset;
	if (!(::SetFilePointerEx(file, li, NULL, FILE_BEGIN) && 
		::ReadFile(file, ret->Data, len, &bytes, NULL)))
	{
		::CloseHandle(file);
		return nullptr;
	}
	::CloseHandle(file);
	return ret;
}


bool libPhate::WriteFile (String ^path, int64 offset, const Array<uint8> ^data)
{
	HANDLE file = ::CreateFile2(path->Data(), GENERIC_WRITE, 0, CREATE_ALWAYS, NULL);
	if (INVALID_HANDLE_VALUE == file) return false;
	if (data && data->Length)
	{
		DWORD bytes = 0;
		LARGE_INTEGER li; li.QuadPart = offset;
		if (!(::SetFilePointerEx(file, li, NULL, FILE_BEGIN) && 
			::WriteFile(file, data->Data, data->Length, &bytes, NULL)))
		{
			::CloseHandle(file);
			return false;
		}
	}
	::CloseHandle(file);
	return true;
}

bool libPhate::CopyFile (String ^sourceName, String ^destName)
{
	HRESULT h = ::CopyFile2(sourceName->Data(), destName->Data(), NULL);
	return SUCCEEDED(h);
}


bool libPhate::MoveFile (String ^sourceName, String ^destName, MoveFlags flags)
{
	return !!::MoveFileEx(sourceName->Data(), destName->Data(), (DWORD)flags);
}

bool libPhate::DeleteFile (String ^path)
{
	return (0 != ::DeleteFileW(path->Data()));
}

bool libPhate::CreateDirectory (String ^fullpath)
{
	return !!::CreateDirectoryW(fullpath->Data(), NULL);
}

bool libPhate::DeleteDirectory (String ^fullpath)
{
	return !!::RemoveDirectory(fullpath->Data());
}

bool libPhate::CreateSymbolicLink (String ^target, String ^linkname, bool directory)
{
	PWCHAR t = new WCHAR[target->Length() + 1];
	PWCHAR n = new WCHAR[linkname->Length() + 1];
	wcscpy_s(t, target->Length() + 1, target->Data());
	wcscpy_s(n, linkname->Length() + 1, linkname->Data());
	bool ret = !!pCreateSymbolicLink(n, t, directory ? 1 : 0);
	delete[] t;
	delete[] n;
	return ret;
}

Array<String^>^ libPhate::GetDriveLetters ()
{
	PWSTR buf = NULL;
	// Get the required buffer length, then get the strings
	DWORD len = pGetLogicalDriveStrings(0, NULL);
	if (!len) return nullptr;
	buf = new WCHAR[len + 1];
	buf[0] = L'\0';
	if (! pGetLogicalDriveStrings(len, buf))
	{
		delete[] buf;
		return nullptr;
	}
	// Ok, we now have a multi-string array; parse it
	std::vector<String^> vec;
	PWSTR cur = buf;
	DWORD curlen = 0x0;
	while ( (curlen = ::wcslen(cur)) )
	{
		vec.push_back(ref new String(cur));
		cur += (curlen + 1);
	}
	// Clean up and return
	delete[] buf;
	return ref new Array<String^>(vec.data(), vec.size());
}
