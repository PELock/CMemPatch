//////////////////////////////////////////////////////////////////////
//
// CMemPatch class by Bartosz Wójcik
//
// http://www.pelock.com
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "mempatch.h"

//////////////////////////////////////////////////////////////////////
// 
// constructor
//
//////////////////////////////////////////////////////////////////////

CMemPatch::CMemPatch() : pbFileImage(NULL), bLoaded(FALSE)
{
	memset(lpszFile, 0, MAX_PATH);
}

CMemPatch::CMemPatch(char *lpszFilename, BOOL bLoadSuspended)
{
	pbFileImage = NULL;

	if (lpszFilename != NULL)
	{
		// copy original file name
		strncpy(lpszFile, lpszFilename, MAX_PATH);

		// load file
		LoadFile(bLoadSuspended);
	}
	else
	{
		memset(lpszFile, 0, MAX_PATH);
		bLoaded = FALSE;
	}
}

//////////////////////////////////////////////////////////////////////
// 
// destructor
//
//////////////////////////////////////////////////////////////////////

CMemPatch::~CMemPatch()
{
	if (IsLoaded() == FALSE) return;

	// release buffer
	delete [] pbFileImage;
	pbFileImage = NULL;

	// close process handles
	::CloseHandle(piProcessInfo.hThread);
	::CloseHandle(piProcessInfo.hProcess);
}

//////////////////////////////////////////////////////////////////////////
//
// is the image properly loaded
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::IsLoaded()
{
	return bLoaded;
}

//////////////////////////////////////////////////////////////////////////
//
// terminate loaded process with given exit code
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::Terminate(unsigned int dwExitCode)
{
	if (IsLoaded() == FALSE) return FALSE;
	
	// terminate process
	if (::TerminateProcess(piProcessInfo.hProcess, dwExitCode) != TRUE) return FALSE;

	// close process handles
	::CloseHandle(piProcessInfo.hThread);
	::CloseHandle(piProcessInfo.hProcess);

	// release memory
	if (pbFileImage != NULL)
	{
		delete[] pbFileImage;

		pbFileImage = NULL;
	}

	bLoaded = FALSE;

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// resume suspended process
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::Resume()
{
	if (IsLoaded() == FALSE) return FALSE;

	if (::ResumeThread(piProcessInfo.hThread) != -1)
	{
		return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// verify PE file, and read default image base, image size
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::IsValidPE(DWORD *dwProcessSize, DWORD *dwPrefferedBase)
{
	DWORD dwRead = 0, dwSignature = 0;

	// read IMAGE_DOS_HEADER
	if (ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)hModule, &lpDosHeader, sizeof(IMAGE_DOS_HEADER), &dwRead) == 0) return FALSE;

	// verify ms-dos header (check MZ signature)
	if (lpDosHeader.e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

	// read PE header signature (PE,0,0 bytes)
	if (ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)(hModule + lpDosHeader.e_lfanew), &dwSignature, 4, &dwRead) == 0) return FALSE;

	// verify PE signature
	if (dwSignature != IMAGE_NT_SIGNATURE) return FALSE;

	// read IMAGE_FILE_HEADER header
	if (ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)(hModule + lpDosHeader.e_lfanew + 4), &lpFileHeader, sizeof(IMAGE_FILE_HEADER), &dwRead) == 0) return FALSE;

	// read IMAGE_OPTIONAL_HEADER header
	if (ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)(hModule + lpDosHeader.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)), &lpNtHeader, lpFileHeader.SizeOfOptionalHeader, &dwRead) == 0) return FALSE;

	// read image size and image base
	if ( (lpNtHeader.SizeOfImage != 0) && (dwProcessSize != NULL) && (dwPrefferedBase != NULL))
	{
		*dwProcessSize = lpNtHeader.SizeOfImage;
		*dwPrefferedBase = lpNtHeader.ImageBase;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//
// read or reload whole process memory
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::ReadFile()
{
	if (IsLoaded() == FALSE) return FALSE;

	if (pbFileImage == NULL)
	{
		pbFileImage = new BYTE[dwFileImage];

		// check allocated memory pointer
		if (pbFileImage == NULL)
		{
			return FALSE;
		}

		return ::ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)hModule, (LPVOID)pbFileImage, dwFileImage, &dwRead);
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// read memory from the VA (Virtual Address) address
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::ReadFromVA(LPCVOID lpAddress, LPVOID lpBuffer, DWORD nSize)
{
	if (IsLoaded() == FALSE) return FALSE;
	
	if ( (lpBuffer != NULL) && (nSize != 0) && (nSize <= dwFileImage) )
	{
		return (::ReadProcessMemory(piProcessInfo.hProcess, lpAddress, lpBuffer, nSize, &dwRead));
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// read memory from the RVA (Relative Virtual Address) address
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::ReadFromRVA(LPCVOID lpAddress, LPVOID lpBuffer, DWORD nSize)
{
	if (IsLoaded() == FALSE) return FALSE;

	if ( (lpBuffer != NULL) && (nSize != 0) && (nSize <= dwFileImage) )
	{
		return (::ReadProcessMemory(piProcessInfo.hProcess, (LPCVOID)( (DWORD)lpAddress + hModule), lpBuffer, nSize, &dwRead));
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// write memory buffer to the RVA address
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::WriteToRVA(LPVOID lpAddress, LPVOID lpBuffer, DWORD nSize)
{
	if (IsLoaded() == FALSE) return FALSE;

	if ( (nSize != 0) && (lpBuffer != NULL) && (nSize <= dwFileImage) )
	{
		return (::WriteProcessMemory(piProcessInfo.hProcess, (LPVOID)( (DWORD)lpAddress + hModule), lpBuffer, nSize, &dwWritten));
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//
// load executable file
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::LoadFile(BOOL bLoadSuspended)
{
	MODULEENTRY32 meModuleEntry;
	HANDLE hSnapshot = NULL;
	BOOL bModuleDone = FALSE;

	// file already loaded
	if (IsLoaded() == TRUE) return FALSE;
	
	memset(&siStartupInfo, 0, sizeof(STARTUPINFO));
	memset(&piProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	siStartupInfo.cb = sizeof(STARTUPINFO);

	// create new process
	bLoaded = ::CreateProcess(NULL, lpszFile, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | (bLoadSuspended ? CREATE_SUSPENDED : 0), NULL, NULL, &siStartupInfo, &piProcessInfo);

	if (bLoaded == FALSE) return FALSE;

	// set default image base for executable files (if we can't find anything else)
	hModule = 0x400000;

	// enumerate loaded process list to get current image base
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, piProcessInfo.dwProcessId );

	meModuleEntry.dwSize = sizeof(MODULEENTRY32); 
			
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Module32First(hSnapshot, &meModuleEntry) == TRUE)
		{
			do 
			{
				if ( strnicmp(lpszFile, meModuleEntry.szExePath, MAX_PATH) == 0 )
				{
					hModule = (DWORD)meModuleEntry.modBaseAddr;
					bModuleDone = TRUE;
					break;
				}
			}
			while (Module32Next(hSnapshot, &meModuleEntry) == TRUE);
		}

		CloseHandle(hSnapshot);
	}

	// verify PE file
	if (IsValidPE(&dwFileImage, &dwPrefferedBase) == TRUE)
	{
		if (bModuleDone == FALSE)
		{
			hModule = dwPrefferedBase;
		}
	}
	else
	{
		Terminate();
	}

	return bLoaded;
}

//////////////////////////////////////////////////////////////////////////
//
// select executable file to load
//
//////////////////////////////////////////////////////////////////////////

BOOL CMemPatch::SelectFile(const char *lpszDialogCaption, const char *lpszFileMask)
{
	// fill ofn structure with 0
	memset(&ofnOpenFileSelect, 0, sizeof(OPENFILENAME));

	ofnOpenFileSelect.lStructSize = sizeof(OPENFILENAME);
	ofnOpenFileSelect.hwndOwner = NULL;
	ofnOpenFileSelect.nMaxFile = MAX_PATH;
	ofnOpenFileSelect.lpstrFile = lpszFile;
	ofnOpenFileSelect.lpstrTitle = lpszDialogCaption;
	ofnOpenFileSelect.Flags = OFN_HIDEREADONLY | OFN_FILEMUSTEXIST;
	ofnOpenFileSelect.lpstrFilter = lpszFileMask;

	return (GetOpenFileName(&ofnOpenFileSelect) != 0 ? TRUE : FALSE);
}
