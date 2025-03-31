#include <windows.h>

int main()
{
    int msgboxID = MessageBoxW(
        NULL,
        (LPCWSTR)L"Learning about the Windows API.",
        (LPCWSTR)L"Learning C Journey",
        MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
    );
}
