#include<Windows.h> 
#include<time.h> 
typedef void (*MYPROC)(char *,const char *);

int main()
{  
    ULONGLONG uptime = GetTickCount();
    Sleep(5000);
    ULONGLONG uptimeBis = GetTickCount();
    if ((uptimeBis - uptime) < 5000 || IsDebuggerPresent())
    {
        MessageBox(NULL, TEXT("Hello world !"), "", MB_OK);
    }
    else
    {
        char message[20] = "";
        HINSTANCE hlib = LoadLibrary("msvcrt.dll");
        MYPROC func = (MYPROC) GetProcAddress(hlib,"strcat");
        (func)(message, "I'm ");
        (func)(message, "evil !!");
        MessageBox(NULL, message, "", MB_OK); 
    }
    exit(0);  
} 