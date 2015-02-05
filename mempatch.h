//////////////////////////////////////////////////////////////////////
//
// CMemPatch class by Bartosz Wójcik
//
// http://www.pelock.com
//
//////////////////////////////////////////////////////////////////////

#include <Tlhelp32.h>

#if !defined(__MEMPATCH__)
#define __MEMPATCH__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


class CMemPatch
{
public:
	CMemPatch();
	CMemPatch(char *lpszFilename, BOOL bLoadSuspended = FALSE);
	virtual ~CMemPatch();

public:
	
	BOOL LoadFile(BOOL bLoadSuspended = FALSE);
	BOOL IsLoaded();
	BOOL Resume();
	BOOL Terminate(unsigned int dwExitCode = EXIT_SUCCESS);

	BOOL ReadFile();
	BOOL ReadFromVA(LPCVOID lpAddress, LPVOID lpBuffer, DWORD nSize);
	BOOL ReadFromRVA(LPCVOID lpAddress, LPVOID lpBuffer, DWORD nSize);
	BOOL WriteToVA(LPVOID lpAddress, LPVOID lpBuffer, DWORD nSize);
	BOOL WriteToRVA(LPVOID lpAddress, LPVOID lpBuffer, DWORD nSize);
	BOOL SelectFile(const char *lpszDialogCaption = "Select file to load", const char *szFileMask = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0");

	char lpszFile[MAX_PATH];
	BYTE *pbFileImage;
	DWORD dwFileImage;
	DWORD hModule;

private:

	BOOL IsValidPE(DWORD *dwImageSize, DWORD *dwPrefferedBase);

	OPENFILENAME ofnOpenFileSelect;
	STARTUPINFO siStartupInfo;
	PROCESS_INFORMATION piProcessInfo;

	IMAGE_DOS_HEADER lpDosHeader;
	IMAGE_FILE_HEADER lpFileHeader;
	IMAGE_OPTIONAL_HEADER lpNtHeader;

	DWORD dwPrefferedBase;
	DWORD dwRead, dwWritten;
	BOOL bLoaded;
};

#endif
