#include <windows.h>
#include <iostream>

#include "util.hpp"

std::wstring util::ExpandEnvironmentVariables(const std::wstring& input) {
    size_t pos = input.find(L"\\SystemRoot\\");
    std::wstring modifiedInput = input;
    if (pos != std::wstring::npos) {
        modifiedInput.replace(pos, 12, L"%SystemRoot%\\"); // 12 is the length of "\\SystemRoot\\"
    }
    
    // First, get the required buffer size
    DWORD requiredSize = ExpandEnvironmentStrings(modifiedInput.c_str(), NULL, 0);
    if (requiredSize == 0) {
        // Handle error. You might want to throw an exception or return the original input
        return input;
    }

    // Allocate buffer and expand the string
    std::vector<wchar_t> buffer(requiredSize);
    DWORD expandedSize = ExpandEnvironmentStrings(modifiedInput.c_str(), buffer.data(), requiredSize);
    if (expandedSize == 0 || expandedSize > requiredSize) {
        // Handle error
        return input;
    }

    // Create a string from the buffer and return it
    return std::wstring(buffer.begin(), buffer.begin() + expandedSize - 1); // -1 to remove the null terminator
}