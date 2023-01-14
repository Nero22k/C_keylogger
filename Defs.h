#pragma once

typedef int (WINAPI *TypeMessageBoxA)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
);

typedef HHOOK (WINAPI *TypeSetWindowsHookExA)(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
);

typedef BOOL (WINAPI *TypeGetMessageA)(
	LPMSG lpMsg,
	HWND  hWnd,
	UINT  wMsgFilterMin,
	UINT  wMsgFilterMax
);

typedef BOOL (WINAPI *TypeTranslateMessage)(
	const MSG* lpMsg
);

typedef LRESULT (WINAPI *TypeDispatchMessageA)(
	const MSG* lpMsg
);

typedef BOOL (WINAPI *TypeUnhookWindowsHookEx)(
	HHOOK hhk
);

typedef LRESULT (WINAPI *TypeCallNextHookEx)(
	HHOOK  hhk,
	int    nCode,
	WPARAM wParam,
	LPARAM lParam
);

typedef SHORT (WINAPI *TypeGetAsyncKeyState)(
	int vKey
);

typedef struct _UNICODE_STRING {
     USHORT Length;
     USHORT MaximumLength;
     PWSTR  Buffer;
 } UNICODE_STRING;
 typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks; /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
    LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
    PVOID BaseAddress; /* 0x18 */
    PVOID EntryPoint; /* 0x1C */
    ULONG SizeOfImage; /* 0x20 */
    UNICODE_STRING FullDllName; /* 0x24 */
    UNICODE_STRING BaseDllName; /* 0x2C */
    ULONG Flags; /* 0x34 */
    union {
        UCHAR FlagGroup [4];
        ULONG Flag;
        struct {
            /*  bit fields, see below  */
        };  
    };
    WORD LoadCount; /* 0x38 */
    WORD TlsIndex; /* 0x3A */
    union /* 0x3C */
    {
         LIST_ENTRY HashLinks;
         struct
         {
              PVOID SectionPointer;
              ULONG CheckSum;
         };
    };
    union
    {
         ULONG TimeDateStamp;
         PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;