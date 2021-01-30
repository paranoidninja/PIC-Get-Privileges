#include "addresshunter.h"
#include <stdio.h>
#include <inttypes.h>

// kernel32.dll exports
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)();

// advapi32.dll exports
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* GETTOKENINFORMATION)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI* LOOKUPPRIVILEGENAMEW)(LPCWSTR,  PLUID, LPWSTR, LPDWORD);

// msvcrt.dll exports
typedef int(WINAPI* WPRINTF)(const wchar_t* format, ...);
typedef void*(WINAPI* CALLOC)(size_t num, size_t size);

void getprivs() {
    //dlls to dynamically load during runtime
    UINT64 kernel32dll, msvcrtdll, advapi32dll;
    //symbols to dynamically resolve from dll during runtime
    UINT64 LoadLibraryAFunc, CloseHandleFunc,
        OpenProcessTokenFunc, GetCurrentProcessFunc, GetTokenInformationFunc, LookupPrivilegeNameWFunc,
        callocFunc, wprintfFunc;

    // kernel32.dll exports
    kernel32dll = GetKernel32();

    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);

    CHAR getcurrentprocess_c[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    GetCurrentProcessFunc = GetSymbolAddress((HANDLE)kernel32dll, getcurrentprocess_c);

    CHAR closehandle_c[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    CloseHandleFunc = GetSymbolAddress((HANDLE)kernel32dll, closehandle_c);

    // advapi32.dll exports
    CHAR advapi32_c[] = {'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0};
    advapi32dll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(advapi32_c);
    CHAR openprocesstoken_c[] = {'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', 0};
    OpenProcessTokenFunc = GetSymbolAddress((HANDLE)advapi32dll, openprocesstoken_c);
    CHAR gettokeninformation_c[] = { 'G', 'e', 't', 'T', 'o', 'k', 'e', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0 };
    GetTokenInformationFunc = GetSymbolAddress((HANDLE)advapi32dll, gettokeninformation_c);
    CHAR lookupprivilegenamew_c[] = {'L', 'o', 'o', 'k', 'u', 'p', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'N', 'a', 'm', 'e', 'W', 0};
    LookupPrivilegeNameWFunc = GetSymbolAddress((HANDLE)advapi32dll, lookupprivilegenamew_c);

    // msvcrt.dll exports
    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0};
    msvcrtdll = (UINT64) ((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR calloc_c[] = {'c', 'a', 'l', 'l', 'o', 'c', 0};
    callocFunc = GetSymbolAddress((HANDLE)msvcrtdll, calloc_c);
    CHAR wprintf_c[] = {'w', 'p', 'r', 'i', 'n', 't', 'f', 0};
    wprintfFunc = GetSymbolAddress((HANDLE)msvcrtdll, wprintf_c);

    DWORD cbSize = sizeof(TOKEN_ELEVATION), tpSize, length;
	HANDLE hToken = NULL;
    TOKEN_ELEVATION Elevation;
    PTOKEN_PRIVILEGES tPrivs = NULL;
    WCHAR name[256];
    WCHAR priv_enabled[] =  { L'[', L'+', L']', L' ', L'%', L'-', L'5', L'0', L'l', L's', L' ', L'E', L'n', L'a', L'b', L'l', L'e', L'd', L' ', L'(', L'D', L'e', L'f', L'a', L'u', L'l', L't', L')', L'\n', 0 };
    WCHAR priv_adjusted[] = { L'[', L'+', L']', L' ', L'%', L'-', L'5', L'0', L'l', L's', L' ', L'E', L'n', L'a', L'b', L'l', L'e', L'd', L' ', L'(', L'D', L'e', L'f', L'a', L'u', L'l', L't', L')', L'\n', 0 };
    WCHAR priv_disabled[] = { L'[', L'+', L']', L' ', L'%', L'-', L'5', L'0', L'l', L's', L' ', L'E', L'n', L'a', L'b', L'l', L'e', L'd', L' ', L'(', L'D', L'e', L'f', L'a', L'u', L'l', L't', L')', L'\n', 0 };
    WCHAR priv_elevated[] =   {L'[', L'+', L']', L' ', L'E', L'l', L'e', L'v', L'a', L't', L'e', L'd', 0};
    WCHAR priv_restricted[] = {L'[', L'+', L']', L' ', L'R', L'e', L's', L't', L'r', L'i', L'c', L't', L'e', L'd', 0};

	if (((OPENPROCESSTOKEN)OpenProcessTokenFunc)(((GETCURRENTPROCESS)GetCurrentProcessFunc)(), TOKEN_QUERY, &hToken)) {
        ((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenPrivileges, tPrivs, 0, &tpSize);
        tPrivs = (PTOKEN_PRIVILEGES)((CALLOC)callocFunc)(tpSize+1, sizeof(TOKEN_PRIVILEGES));

        if (tPrivs) {
            if (((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenPrivileges, tPrivs, tpSize, &tpSize)) {
                for(int i=0; i<tPrivs->PrivilegeCount; i++){
                    length=256;
                    ((LOOKUPPRIVILEGENAMEW)LookupPrivilegeNameWFunc)(NULL, &tPrivs->Privileges[i].Luid, name, &length);
                    if (tPrivs->Privileges[i].Attributes == 3) {
                        ((WPRINTF)wprintfFunc)(priv_enabled, name);
                    } else if (tPrivs->Privileges[i].Attributes == 2) {
                        ((WPRINTF)wprintfFunc)(priv_adjusted, name);
                    } else if (tPrivs->Privileges[i].Attributes == 0) {
                        ((WPRINTF)wprintfFunc)(priv_disabled, name);
                    }
                }
            }
        }

		if (((GETTOKENINFORMATION)GetTokenInformationFunc)(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            if (Elevation.TokenIsElevated) {
                ((WPRINTF)wprintfFunc)(priv_elevated);
            } else {
                ((WPRINTF)wprintfFunc)(priv_restricted);
            }
		}
        ((CLOSEHANDLE)CloseHandleFunc)(hToken);
	}
}
