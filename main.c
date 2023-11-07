#include <windows.h>
#include <stdio.h>

//use <stdbool.h>, my winsdk install doesnt include it
#ifndef bool
#define bool _Bool
#define true 1
#define false 0
#endif


bool GetValidFilePath(wchar_t* out, int maxlen) {
    wchar_t buff[512];

    bool correct = false;
    do {
        printf("file: ");
        fgetws(buff, maxlen, stdin);
        buff[lstrlenW(buff) - 1] = '\0';
        putchar('\n');
        DWORD attrib = GetFileAttributesW(buff);
        if ((attrib != INVALID_FILE_ATTRIBUTES) && !(attrib & FILE_ATTRIBUTE_DIRECTORY) && !(attrib & FILE_ATTRIBUTE_DEVICE)) {
            correct = true;

        }
        else {
            fprintf(stderr, "Invalid file '%ls'.\n", buff);
        }

    } while (correct == false);
    if (lstrcpynW(out, buff, maxlen) == NULL) {
        return false;

    }
    
    return true;
    



}
void PrintErr() {
    wchar_t buf[256];
    DWORD le = GetLastError();
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, le, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
    fprintf(stderr,"Error: %ls (%lu)", buf, le);

}

int main() {
    wchar_t buff[512];
    bool r = GetValidFilePath(buff, 512);
    if (r == NULL) {
        fprintf(stderr, "lstrcpynW() failed, NULL returned\n");
        PrintErr();
        return 1;
    }
    printf("%ls\n", buff);
    
    

    

   
    HMODULE hModule = LoadLibraryW(buff);

    if (hModule == NULL) {
        fprintf(stderr,"Failed to load the PE file.\n");
        PrintErr();
        return 1;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        char* moduleName = (char*)((BYTE*)hModule + importDesc->Name);
        printf("Imported Module: %s\n", moduleName);

        IMAGE_THUNK_DATA* importThunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->OriginalFirstThunk);
        while (importThunk->u1.AddressOfData) {
            if (importThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("\tOrdinal: %u\n", IMAGE_ORDINAL(importThunk->u1.Ordinal));
            }
            else {
                IMAGE_IMPORT_BY_NAME* importData = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + importThunk->u1.AddressOfData);
                printf("\tFunction Name: %s\n", importData->Name);
            }
            importThunk++;
        }

        importDesc++;
    }

    if (!FreeLibrary(hModule)) {
        fprintf(stderr,"Failed to unload module\n");
        PrintErr();
        return 1;
    }



    (void)getchar();
    return 0;
}