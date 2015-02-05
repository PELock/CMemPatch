//////////////////////////////////////////////////////////////////////
//
// CMemPatch class usage example by Bartosz Wójcik
//
// This is a decryptor for the HUGI e-zines.
//
// You can find it at http://www.hugi.scene.org/
//
// E-zine engine is based od Chris Dragan's work.
//
// 1. The e-zine executable is run
// 2. The decryption keys for the data package is read
// 3. Data package is decrypted and stored on disk
//
// http://www.pelock.com
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"

int main(int argc, char *argv[])
{
	CMemPatch myPatch;
	unsigned int i, dwSize, dwKeys[256], dwBuffer[256];
	LPCVOID lpMagic;
	FILE *hInput, *hOutput;
	WIN32_FIND_DATA wfFindData;

	// select file to load
	if ( myPatch.SelectFile() )
	{
		// run selected file
		if ( myPatch.LoadFile() )
		{
			MessageBox(NULL, "Make sure zine is running (after configuration), then press OK", "Waiting", MB_ICONINFORMATION);

			// read whole process memory
			if (myPatch.ReadFile())
			{
				// search for bytes
				// mov     dword_4391E0[ecx], eax
				// imul    eax, 8088405h
				for (i = 0; i < myPatch.dwFileImage; i++)
				{
					if (myPatch.pbFileImage[i] == 0x89 && myPatch.pbFileImage[i+1] == 0x81 && myPatch.pbFileImage[i+6] == 0x69 && myPatch.pbFileImage[i+9] == 0x84)
					{
						// get an offset from the "mov dword_4391E0[ecx], eax"
						lpMagic = *(LPCVOID *)&myPatch.pbFileImage[i+2];

						// read encryption keys
						if (myPatch.ReadFromVA(lpMagic, &dwKeys, 1024))
						{
							*(strrchr(myPatch.lpszFile, '\\') + 1) = '\0';
							strcat(myPatch.lpszFile,"*.dat");

							if ( FindFirstFile(myPatch.lpszFile, &wfFindData) != 0 )
							{
								hInput = fopen(wfFindData.cFileName,"rb");

								if (hInput != NULL)
								{
									hOutput = fopen("decrypted.rar","wb");

									if (hOutput != NULL)
									{

										fseek(hInput, 0, FILE_END);

										fseek(hInput,0, FILE_BEGIN);
										
										dwSize = fread(&dwBuffer, 1, 1024, hInput);

										while ( dwSize != 0 )
										{
											for (i = 0; i < 256 ; i++ )
											{
												dwBuffer[i] ^= dwKeys[i];
											}

											fwrite(&dwBuffer, dwSize, 1, hOutput);

											dwSize = fread(&dwBuffer, 1, 1024, hInput);
										}

										fclose(hOutput);

										printf("File successfully decrypted!\n");
									}
									else
									{
										printf("Cannot create output file!\n");
									}

									fclose(hInput);

								}
								else
								{
									printf("Cannot open file %s!\n",wfFindData.cFileName);
								}
							}
							else
							{
								printf("Couldnt find *.dat file!\n");
							}
						}
						else
						{
							printf("Cannot read encryption keys from the memory!\n");
						}

						// terminate process
						myPatch.Terminate();

						break;
					}
				}
			}
			else
			{
				printf("Cannot read from the process memory!\n");
			}
		}
		else
		{
			printf("Cannot load file %s!\n", myPatch.lpszFile);
		}
	}

	return 0;
}