#include "Logger.h"
#include <fstream>
#include <mutex>
#include <stdarg.h>
#include <windows.h>

static bool isInit = false;
std::ofstream logFile;

inline __declspec(align(0x1000)) static char sBuffer[1024] = { 0 };
inline __declspec(align(0x1000)) static wchar_t wBuffer[1024] = { 0 };

std::mutex logMutex;

void Logger::Log(const char* format, ...) {
    std::lock_guard<std::mutex> guard(logMutex);
    va_list args;
    va_start(args, format);
    vsprintf_s(sBuffer, format, args);
    va_end(args);

    printf("[TID:%08x]  %s", GetCurrentThreadId(), sBuffer);
    logFile << "[TID: " << std::hex << GetCurrentThreadId() << "]  " << sBuffer << std::endl;
    fflush(stdout);
}

void Logger::Log(wchar_t* format, ...) {
    std::lock_guard<std::mutex> guard(logMutex);
    va_list args;
    va_start(args, format);
    vswprintf_s(wBuffer, format, args);
    va_end(args);

    printf("[TID:%08x]  %ls", GetCurrentThreadId(), wBuffer);

    std::wstring wstr(wBuffer);
    std::string str(wstr.begin(), wstr.end());

    logFile << "[TID: " << std::hex << GetCurrentThreadId() << "]  " << str << std::endl;
    fflush(stdout);
}

void Logger::InitializeLogFile(const char* fileName) {
    if (!isInit) {
        logFile.open(fileName, std::ios::out | std::ios::trunc);
        isInit = true;
    }
}

void Logger::CloseLogFile() {
    if (isInit) {
        logFile.close();
        isInit = false;
    }
}