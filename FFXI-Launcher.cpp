#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <string>
#include <map>
#include <ctime>
#include <vector>
#include <sstream>
#include <array>
#include <cstring>
#include <stdint.h>
#include "sha1.h"
#include <cctype>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "httplib.h"
#include <process.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <mutex>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

// Debug flag - set to true to enable key press logging
bool DEBUG_KEY_PRESSES = false;

// Helper function to get key name from virtual key code
std::string getKeyName(WORD vk) {
    switch (vk) {
        case VK_RETURN: return "ENTER";
        case VK_ESCAPE: return "ESC";
        case VK_UP: return "UP";
        case VK_DOWN: return "DOWN";
        case VK_SHIFT: return "SHIFT";
        case VK_MENU: return "ALT";
        default: return "*";  // Mask all other keys
    }
}

// Helper function to log key presses
void logKeyPress(WORD vk, bool isKeyUp = false) {
    if (!DEBUG_KEY_PRESSES) return;
    
    std::string action = isKeyUp ? "Released" : "Pressed";
    std::string keyName = getKeyName(vk);
    std::cout << "[Key] " << action << " " << keyName << std::endl;
}

struct AccountConfig {
    std::string name;
    std::string password;
    std::string totpSecret;
    int slot;
    std::string args;
};

struct GlobalConfig {
    int delay;
    bool POLProxy;
    std::string clientRegion; // "US" or "JP" or "EU"
    std::vector<AccountConfig> accounts;
};

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20

std::string base32_decode(const std::string& input) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> output;
    int buffer = 0, bitsLeft = 0;
    for (char c : input) {
        if (c == '=' || c == ' ') break;
        const char* p = strchr(alphabet, toupper(c));
        if (!p) continue;
        buffer <<= 5;
        buffer |= (p - alphabet);
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            output.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    return std::string(output.begin(), output.end());
}

// SHA1 implementation public domain (Steve Reid, others)
void sha1(const uint8_t* data, size_t len, uint8_t* out);

void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t output[20]) {
    const size_t blockSize = 64;
    const size_t hashSize = 20;
    uint8_t k_ipad[blockSize] = { 0 };
    uint8_t k_opad[blockSize] = { 0 };
    uint8_t tk[hashSize] = { 0 };

    if (key_len > blockSize) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = hashSize;
    }

    uint8_t k0[blockSize] = { 0 };
    memcpy(k0, key, key_len);

    for (size_t i = 0; i < blockSize; ++i) {
        k_ipad[i] = k0[i] ^ 0x36;
        k_opad[i] = k0[i] ^ 0x5c;
    }

    std::vector<uint8_t> inner_data;
    inner_data.insert(inner_data.end(), k_ipad, k_ipad + blockSize);
    inner_data.insert(inner_data.end(), data, data + data_len);

    uint8_t inner_hash[hashSize];
    sha1(inner_data.data(), inner_data.size(), inner_hash);

    std::vector<uint8_t> outer_data;
    outer_data.insert(outer_data.end(), k_opad, k_opad + blockSize);
    outer_data.insert(outer_data.end(), inner_hash, inner_hash + hashSize);

    sha1(outer_data.data(), outer_data.size(), output);
}

std::string generate_totp(const std::string& secret_base32) {
    std::string key = base32_decode(secret_base32);
    uint64_t timestep = time(nullptr) / 30;
    uint8_t msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = timestep & 0xFF;
        timestep >>= 8;
    }

    uint8_t hash[20];
    hmac_sha1((uint8_t*)key.data(), key.size(), msg, 8, hash);

    int offset = hash[19] & 0x0F;
    int binary =
        ((hash[offset] & 0x7F) << 24) |
        ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) |
        (hash[offset + 3] & 0xFF);

    int code = binary % 1000000;
    char buf[7];
    snprintf(buf, sizeof(buf), "%06d", code);
    return std::string(buf);
}

void simulateKey(WORD vk, bool shift = false) {
    INPUT inputs[4] = {};
    int count = 0;
    if (shift) {
        inputs[count].type = INPUT_KEYBOARD;
        inputs[count].ki.wVk = VK_SHIFT;
        logKeyPress(VK_SHIFT);
        count++;
    }
    inputs[count].type = INPUT_KEYBOARD;
    inputs[count].ki.wVk = vk;
    logKeyPress(vk);
    count++;
    inputs[count].type = INPUT_KEYBOARD;
    inputs[count].ki.wVk = vk;
    inputs[count].ki.dwFlags = KEYEVENTF_KEYUP;
    logKeyPress(vk, true);
    count++;
    if (shift) {
        inputs[count].type = INPUT_KEYBOARD;
        inputs[count].ki.wVk = VK_SHIFT;
        inputs[count].ki.dwFlags = KEYEVENTF_KEYUP;
        logKeyPress(VK_SHIFT, true);
        count++;
    }
    SendInput(count, inputs, sizeof(INPUT));
    Sleep(30);
}

void copyAndPasteText(HWND hwnd, const std::string& text) {
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Clipboard] Copying and pasting: " << std::string(text.length(), '*') << std::endl;
    }
    
    // Save current clipboard content
    std::string originalClipboard;
    if (OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData != NULL) {
            char* pszText = static_cast<char*>(GlobalLock(hData));
            if (pszText != NULL) {
                originalClipboard = pszText;
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
    
    // Set text to clipboard
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hGlob = GlobalAlloc(GMEM_FIXED, text.length() + 1);
        if (hGlob != NULL) {
            strcpy_s(static_cast<char*>(hGlob), text.length() + 1, text.c_str());
            SetClipboardData(CF_TEXT, hGlob);
        }
        CloseClipboard();
    }
    
    // Focus window
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    BringWindowToTop(hwnd);
    
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Timing] Waiting 50ms for window focus..." << std::endl;
    }
    Sleep(50); // Give window time to focus
    
    // Try PostMessage first (asynchronous)
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Paste] Sending PostMessage WM_PASTE" << std::endl;
    }
    PostMessage(hwnd, WM_PASTE, 0, 0);
    
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Timing] Waiting 200ms after PostMessage..." << std::endl;
    }
    Sleep(200);
    
    // Try SendMessage (synchronous)
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Paste] Sending SendMessage WM_PASTE" << std::endl;
    }
    SendMessage(hwnd, WM_PASTE, 0, 0);
    
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Timing] Waiting 200ms after SendMessage..." << std::endl;
    }
    Sleep(200);
    
    // If WM_PASTE didn't work, try keybd_event
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Key] Pressed CTRL (keybd_event)" << std::endl;
        std::cout << "[Key] Pressed V (keybd_event)" << std::endl;
    }
    
    keybd_event(VK_CONTROL, 0, 0, 0);
    Sleep(10);
    keybd_event('V', 0, 0, 0);
    Sleep(10);
    keybd_event('V', 0, KEYEVENTF_KEYUP, 0);
    Sleep(10);
    keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
    
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Key] Released V (keybd_event)" << std::endl;
        std::cout << "[Key] Released CTRL (keybd_event)" << std::endl;
        std::cout << "[Timing] Waiting 500ms after paste..." << std::endl;
    }
    
    Sleep(500);
}

void sendText(HWND hwnd, const std::string& text, int delay = 50) {
    if (DEBUG_KEY_PRESSES) {
        std::cout << "[Text] Sending " << text.length() << " characters: " << std::string(text.length(), '*') << std::endl;
    }
    for (char c : text) {
        SHORT vk = VkKeyScanA(c);
        if (vk == -1) continue;
        bool shift = (vk & 0x0100) != 0;
        WORD vkCode = vk & 0xFF;
        SetForegroundWindow(hwnd);
        simulateKey(vkCode, shift);
        Sleep(delay);
    }
}

// Forward declarations
void removeHostsEntry();

// Global flag to track if hosts entry was added (so we know to clean it up)
std::atomic<bool> hostsEntryAdded(false);

// Add back the addHostsEntry function
void addHostsEntry(const std::string& ip) {
    std::ifstream in("C:\\Windows\\System32\\drivers\\etc\\hosts");
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("wh000.pol.com") != std::string::npos && line.find("#ffxi-autologin") != std::string::npos)
            return; // Entry already exists
    }
    in.close();

    std::ofstream out("C:\\Windows\\System32\\drivers\\etc\\hosts", std::ios::app);
    out << "\n" << ip << " wh000.pol.com #ffxi-autologin\n";
}

// Define a struct for passing data to EnumWindowsProc
struct WindowSearchData {
    const std::wstring* username;
    HWND* foundHwnd;
};

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    wchar_t title[256];
    GetWindowTextW(hWnd, title, sizeof(title) / sizeof(wchar_t));
    if (wcsncmp(title, L"PlayOnline Viewer", 17) == 0) {
        WindowSearchData* data = reinterpret_cast<WindowSearchData*>(lParam);
        // Create a new title with username only
        std::wstring newTitle = L"PlayOnline Viewer - ";
        newTitle += *(data->username);
        SetWindowTextW(hWnd, newTitle.c_str());
        // Bring this window to the front and focus it
        SetForegroundWindow(hWnd);
        SetActiveWindow(hWnd);
        SetFocus(hWnd);
        BringWindowToTop(hWnd);
        *(data->foundHwnd) = hWnd;
        return FALSE;
    }
    return TRUE;
}

std::string readConfigFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void writeConfigFile(const std::string& path, const GlobalConfig& config) {
    json j;
    j["delay"] = config.delay;
    j["clientRegion"] = config.clientRegion;
    json accounts = json::array();
    for (const auto& account : config.accounts) {
        json acc;
        acc["name"] = account.name;
        acc["password"] = account.password;
        acc["totpSecret"] = account.totpSecret;
        acc["slot"] = account.slot;
        acc["args"] = account.args;
        accounts.push_back(acc);
    }
    j["accounts"] = accounts;
    std::ofstream file(path);
    file << j.dump(4);
}

GlobalConfig loadConfig(const std::string& path) {
    GlobalConfig config;
    std::string content = readConfigFile(path);
    if (content.empty()) {
        config.clientRegion = "US"; // Default to US
        return config;
    }
    try {
        json j = json::parse(content);
        config.delay = j.value("delay", 3000);
        config.POLProxy = true;
        config.clientRegion = j.value("clientRegion", "US"); // Default to US if not set
        if (j.contains("accounts")) {
            for (const auto& acc : j["accounts"]) {
                AccountConfig account;
                account.name = acc.value("name", "");
                account.password = acc["password"];
                account.totpSecret = acc["totpSecret"];
                account.slot = acc["slot"];
                account.args = acc.value("args", "");
                config.accounts.push_back(account);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        config.clientRegion = "US"; // Default to US on error
    }
    return config;
}

void setupConfig(GlobalConfig& config) {
    std::cout << "Setting up FFXI autoPOL configuration\n";
    std::string input;
    
    // Client region selection
    while (true) {
        std::cout << "Client region (US/JP/EU, default US): ";
        std::getline(std::cin, input);
        if (input.empty()) {
            config.clientRegion = "US";
            break;
        }
        std::transform(input.begin(), input.end(), input.begin(), ::toupper);
        if (input == "US" || input == "JP" || input == "EU") {
            config.clientRegion = input;
            break;
        }
        std::cout << "Please enter 'US' or 'JP' or 'EU'.\n";
    }
    
    std::cout << "Delay before input starts (in seconds, default 3): ";
    std::getline(std::cin, input);
    if (input.empty()) {
        config.delay = 3000; // Default to 3 seconds if nothing entered
    } else if (std::all_of(input.begin(), input.end(), ::isdigit)) {
        int val = std::stoi(input);
        if (val >= 1 && val <= 20) config.delay = val * 1000;
    }
    int numAccounts = 0;
    while (true) {
        std::cout << "How many characters do you want to set up? ";
        std::getline(std::cin, input);
        if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
            numAccounts = std::stoi(input);
            if (numAccounts > 0) break;
        }
        std::cout << "Please enter a valid number greater than 0.\n";
    }
    for (int i = 0; i < numAccounts; i++) {
        std::cout << "\nSetting up character " << (i + 1) << ":\n";
        AccountConfig account;
        // Name (no spaces)
        while (true) {
            std::cout << "Character name (no spaces, unique): ";
            std::getline(std::cin, account.name);
            if (account.name.find(' ') != std::string::npos || account.name.empty()) {
                std::cout << "Name cannot contain spaces or be empty. Try again.\n";
                continue;
            }
            bool duplicate = false;
            for (const auto& acc : config.accounts) {
                if (_stricmp(acc.name.c_str(), account.name.c_str()) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                std::cout << "Name must be unique. Try again.\n";
                continue;
            }
            break;
        }
        std::cout << "Password: ";
        std::getline(std::cin, account.password);
        std::cout << "TOTP Secret (leave empty if not using): ";
        std::getline(std::cin, account.totpSecret);
        // Slot (1-4)
        while (true) {
            std::cout << "POL Slot number (1-20): ";
            std::cout << "Slots 5-20 requires Windower.";
            std::getline(std::cin, input);
            if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                int slot = std::stoi(input);
                if (slot >= 1 && slot <= 20) {
                    account.slot = slot;
                    break;
                }
            }
            std::cout << "POL Slot must be 1 - 20. Try again.\n";
        }
        std::cout << "Windower arguments (e.g. -p=\"ProfileName\" leave empty for none) ";
        std::getline(std::cin, account.args);
        config.accounts.push_back(account);
    }
}

int getLoginWValue(const std::string& polPath) {
    std::string loginWPath = polPath + "\\usr\\all\\login_w.bin";
    std::ifstream file(loginWPath, std::ios::binary);
    if (!file) {
        std::cerr << "Could not open login_w.bin at: " << loginWPath << "\n";
        return -1;
    }

    // Seek to offset 0x64
    file.seekg(0x64);
    if (file.fail()) {
        std::cerr << "Failed to seek to offset 0x64 in login_w.bin\n";
        return -1;
    }

    // Read the byte at that offset
    unsigned char value;
    file.read(reinterpret_cast<char*>(&value), 1);
    if (file.fail()) {
        std::cerr << "Failed to read value from login_w.bin\n";
        return -1;
    }

    return value;
}

std::string getPOLPath(DWORD processId) {
    //std::cout << "Looking for POL.exe in process " << processId << "\n";
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "";
    }

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(moduleEntry);
    if (!Module32FirstW(snapshot, &moduleEntry)) {
        std::cerr << "Module32First failed with error: " << GetLastError() << "\n";
        CloseHandle(snapshot);
        return "";
    }

    std::string polPath;
    do {
        std::wstring moduleName = moduleEntry.szModule;
        
        if (_wcsicmp(moduleName.c_str(), L"pol.exe") == 0) {
            // Convert wide string to narrow string
            int size = WideCharToMultiByte(CP_UTF8, 0, moduleEntry.szExePath, -1, NULL, 0, NULL, NULL);
            std::string path(size, 0);
            WideCharToMultiByte(CP_UTF8, 0, moduleEntry.szExePath, -1, &path[0], size, NULL, NULL);
            polPath = path;
            //std::cout << "Found POL.exe at: " << polPath << "\n";
            break;
        }
    } while (Module32NextW(snapshot, &moduleEntry));

    if (polPath.empty()) {
        std::cerr << "POL.exe not found.\n";
    }

    CloseHandle(snapshot);
    return polPath;
}

// Helper to defocus any existing PlayOnline Viewer window
void defocusExistingPOL() {
    HWND fg = GetForegroundWindow();
    wchar_t title[256];
    if (fg && GetWindowTextW(fg, title, 256)) {
        if (wcsncmp(title, L"PlayOnline Viewer", 17) == 0 ||
            wcsncmp(title, L"Final Fantasy XI", 16) == 0) {
            // Set focus to desktop
            HWND desktop = GetDesktopWindow();
            SetForegroundWindow(desktop);
            Sleep(100);
        }
    }
}

void launchAccount(const AccountConfig& account, const GlobalConfig& config) {
    // Determine port based on client region
    int port = [&]() {
        if (config.clientRegion == "JP") return 51300;
        if (config.clientRegion == "EU") return 51302;
        return 51304; // default (US)
        }();

    // Check if the port can be opened
    SOCKET testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bool portAvailable = false;
    if (testSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket for port check.\n";
    } else {
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
        serverAddr.sin_port = htons(port);
        
        // Set socket options before bind
        int opt = 1;
        if (setsockopt(testSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
            std::cerr << "setsockopt SO_REUSEADDR failed\n";
        } else {
            // Try to set SO_EXCLUSIVEADDRUSE to false
            opt = 0;
            if (setsockopt(testSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&opt, sizeof(opt)) < 0) {
                std::cerr << "setsockopt SO_EXCLUSIVEADDRUSE failed\n";
            } else {
                if (bind(testSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                    DWORD error = WSAGetLastError();
                    std::cerr << "POL Redirect won't work: Port " << port << " is already in use (Error: " << error << ")\n";
                } else {
                    portAvailable = true;
                    if (config.POLProxy) {
                        addHostsEntry("127.0.0.1");
                        hostsEntryAdded = true;
                    }
                }
            }
        }
        closesocket(testSocket); // Make sure to close the test socket
    }

    std::cout << "Launching character: " << account.name << std::endl;

    // Defocus any existing POL window before launching new one
    defocusExistingPOL();

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string baseDir = exePath;

    std::string exe = baseDir + "\\Windower.exe";
    bool isWindower = true;
    if (GetFileAttributesA(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        exe = baseDir + "\\pol.exe";
        isWindower = false;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    std::string cmdline = exe;
    if (isWindower && !account.args.empty()) {
        cmdline += " " + account.args;
    }

    if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to launch, try running as admin.\n";
        return;
    }

    // Convert username to wide string for window title
    std::wstring wUsername(account.name.begin(), account.name.end());
    HWND hwnd = nullptr;
    WindowSearchData searchData = { &wUsername, &hwnd };
    for (int i = 0; i < 60 && !hwnd; ++i) {
        EnumWindows(EnumWindowsProc, (LPARAM)&searchData);
        if (!hwnd) Sleep(500);
    }

    if (!hwnd) {
        std::cerr << "Could not find POL window\n";
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    // Get the actual POL.exe path from the running process
    std::string polPath = getPOLPath(pi.dwProcessId);
    if (polPath.empty()) {
        // Try getting the path from the window
        char windowPath[MAX_PATH];
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            if (GetModuleFileNameExA(hProcess, NULL, windowPath, MAX_PATH)) {
                polPath = windowPath;
            }
            CloseHandle(hProcess);
        }
    }

    if (polPath.empty()) {
        std::cerr << "Could not find POL.exe path\n";
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    // Get the directory containing POL.exe
    size_t lastSlash = polPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        polPath = polPath.substr(0, lastSlash);
    }

    // Read login_w.bin value
    int loginWValue = getLoginWValue(polPath);
    if (loginWValue == -1) {
        std::cerr << "Failed to read login_w.bin, using default slot selection\n";
    }

    // Wait for the window to have a title bar (WS_CAPTION)
    int waitTitleBar = 0;
    while (!(GetWindowLong(hwnd, GWL_STYLE) & WS_CAPTION) && waitTitleBar < 100) { // up to 10s
        Sleep(100);
        waitTitleBar++;
    }

    // Logging before BlockInput(TRUE)
    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);
    wchar_t winTitle[256] = {0};
    GetWindowTextW(hwnd, winTitle, 256);

    BlockInput(TRUE);

    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    BringWindowToTop(hwnd);
    // Send VK_MENU (Alt) to help force focus
    keybd_event(VK_MENU, 0, 0, 0);
    keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);

    Sleep(config.delay);
    // Extra focus before input
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    BringWindowToTop(hwnd);

    // Check for auto-login status
    std::ifstream loginWFile(polPath + "\\usr\\all\\login_w.bin", std::ios::binary);
    bool autoLoginEnabled = false;
    if (loginWFile) {
        loginWFile.seekg(0x6F);
        unsigned char autoLoginValue;
        loginWFile.read(reinterpret_cast<char*>(&autoLoginValue), 1);
        autoLoginEnabled = (autoLoginValue != 0x00);
        
        // If auto-login is enabled, check if the slot matches
        if (autoLoginEnabled && loginWValue != -1 && loginWValue != account.slot) {
            std::cout << "\nWARNING: Auto-login is enabled for slot " << loginWValue 
                      << " but you selected slot " << account.slot << ".\n  It's recommended to disable auto-login in POL.\n";

            autoLoginEnabled = false;

            // Press ESC to cancel auto-login
            simulateKey(VK_ESCAPE);
            Sleep(1300);
 
        }
    }

    // Adjust slot selection based on login_w.bin value
    if (loginWValue != -1) {
        int targetSlot = account.slot;
        if (targetSlot < loginWValue) {
            // If we want a lower slot than what's in the file, we need to press UP
            int upPresses = loginWValue - targetSlot;
            for (int i = 0; i < upPresses; ++i) {
                simulateKey(VK_UP);
                Sleep(200);
            }
        } else if (targetSlot > loginWValue) {
            // If we want a higher slot than what's in the file, we need to press DOWN
            int downPresses = targetSlot - loginWValue;
            for (int i = 0; i < downPresses; ++i) {
                simulateKey(VK_DOWN);
                Sleep(200);
            }
        }
    } else {
        // Fallback to original slot selection if we couldn't read login_w.bin
        if (account.slot > 1) {
            for (int i = 1; i < account.slot; ++i) {
                simulateKey(VK_DOWN);
                Sleep(200);
            }
        }
    }

    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    BringWindowToTop(hwnd);

    // Skip these returns if auto-login is enabled
    if (!autoLoginEnabled) {
    Sleep(200);
    simulateKey(VK_RETURN);
    Sleep(200);
    simulateKey(VK_RETURN);
    Sleep(300);
    simulateKey(VK_RETURN);
    }

    Sleep(200);
    simulateKey(VK_RETURN);
    Sleep(200);
    simulateKey(VK_RETURN);
    Sleep(300);
    simulateKey(VK_RETURN);
    Sleep(500);
    simulateKey(VK_RETURN);
    Sleep(500);

    // send some backspace keys just incase we press enter a few times on the 0 key
    simulateKey(VK_BACK);
    Sleep(25);
    simulateKey(VK_BACK);
    Sleep(25);
    simulateKey(VK_BACK);
    Sleep(25);
    simulateKey(VK_BACK);
    Sleep(25);

    sendText(hwnd, "a", 5);
    Sleep(25);
    simulateKey(VK_BACK);

    //sendText(hwnd, account.password, 5);
    copyAndPasteText(hwnd, account.password);

    Sleep(300);

    simulateKey(VK_RETURN);
    Sleep(500);
    simulateKey(VK_DOWN);
    Sleep(300);

    if (!account.totpSecret.empty()) {
        simulateKey(VK_RETURN);
        std::string totp = generate_totp(account.totpSecret);
        sendText(hwnd, totp, 5);
        simulateKey(VK_ESCAPE);
        Sleep(100);
        simulateKey(VK_DOWN);
        Sleep(100);
    }

    simulateKey(VK_RETURN);
    Sleep(50);

    simulateKey(VK_RETURN);
    Sleep(500);

    BlockInput(FALSE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

std::atomic<bool> shouldExit(false);

// Global variable to store the port for the proxy server
std::atomic<int> proxyPort(51304);

// Console control handler for cleanup on termination (Ctrl+C, window close, etc.)
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT || 
        dwCtrlType == CTRL_BREAK_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT || 
        dwCtrlType == CTRL_SHUTDOWN_EVENT) {
        shouldExit = true;
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        return TRUE;
    }
    return FALSE;
}

void startProxyServer() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Server failed to start\n";
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Port creation failed\n";
        WSACleanup();
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    // Set socket options before bind
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt SO_REUSEADDR failed\n";
        closesocket(serverSocket);
        WSACleanup();
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    // Try to set SO_EXCLUSIVEADDRUSE to false
    opt = 0;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt SO_EXCLUSIVEADDRUSE failed\n";
        closesocket(serverSocket);
        WSACleanup();
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
    serverAddr.sin_port = htons(proxyPort.load());

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        DWORD error = WSAGetLastError();
        std::cerr << "Bind failed with error: " << error << " (";
        switch (error) {
            case WSAEADDRINUSE:
                std::cerr << "Port Address already in use";
                break;
            case WSAEACCES:
                std::cerr << "Port Access denied";
                break;
            case WSAEINVAL:
                std::cerr << "Port Invalid argument";
                break;
            default:
                std::cerr << "Port Unknown error";
        }
        std::cerr << ")\n";
        closesocket(serverSocket);
        WSACleanup();
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed with error: " << WSAGetLastError() << "\n";
        closesocket(serverSocket);
        WSACleanup();
        // Clean up hosts entry if proxy fails to start
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        shouldExit = true; // Signal main thread to exit
        return;
    }

    while (!shouldExit) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed with error: " << WSAGetLastError() << "\n";
            continue;
        }
        char buffer[4096];
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            if (strstr(buffer, "GET /pml/main/index.pml") != nullptr) {
                std::string response = "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: text/x-playonline-pml;charset=UTF-8\r\n"
                                     "Content-Length: 123\r\n"
                                     "Connection: close\r\n"
                                     "\r\n"
                                     "<pml><head><meta http-equiv=\"Content-Type\" content=\"text/x-playonline-pml;charset=UTF-8\"><title>Fast</title></head><body><timer name=\"fast\" href=\"gameto:1\" enable=\"1\" delay=\"0\"></body></pml>";
                send(clientSocket, response.c_str(), response.length(), 0);
                shouldExit = true;
            } else {
                std::string response = "HTTP/1.1 404 Not Found\r\n"
                                     "Content-Type: text/plain\r\n"
                                     "Content-Length: 13\r\n"
                                     "Connection: close\r\n"
                                     "\r\n"
                                     "Not Found";
                send(clientSocket, response.c_str(), response.length(), 0);
            }
        }
        closesocket(clientSocket);
    }
    closesocket(serverSocket);
    WSACleanup();
    
    // Clean up hosts entry when proxy server exits
    if (hostsEntryAdded.load()) {
        removeHostsEntry();
        hostsEntryAdded = false;
    }
}

bool editConfig(GlobalConfig& config) {
    std::string input;
    while (true) {
        std::cout << "\nEdit Configuration Menu:\n";
        std::cout << "  [E] Edit existing character\n";
        std::cout << "  [A] Add new character\n";
        std::cout << "  [D] Delete character\n";
        std::cout << "  [C] Modify timeout\n";
        std::cout << "  [R] Change client region (US/JP)\n";
        std::cout << "  [X] Exit to selection screen\n";
        std::cout << "Enter option: ";
        std::getline(std::cin, input);
        // Convert input to lowercase
        std::transform(input.begin(), input.end(), input.begin(), ::tolower);
        if (input == "e") {
            if (config.accounts.empty()) {
                std::cout << "No characters to edit.\n";
                continue;
            }
            std::cout << "\nSelect a character to edit:\n";
            for (size_t i = 0; i < config.accounts.size(); ++i) {
                std::cout << "  [" << (i + 1) << "] " << config.accounts[i].name << " (slot " << config.accounts[i].slot << ")\n";
            }
            std::cout << "Enter number (1-" << config.accounts.size() << "): ";
            std::getline(std::cin, input);
            if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                int choice = std::stoi(input);
                if (choice >= 1 && (size_t)choice <= config.accounts.size()) {
                    AccountConfig& acc = config.accounts[choice - 1];
                    std::cout << "Editing character: " << acc.name << "\n";
                    std::cout << "Current name: " << acc.name << "\n";
                    std::cout << "New name (leave empty to keep current): ";
                    std::getline(std::cin, input);
                    if (!input.empty()) {
                        acc.name = input;
                    }
                    std::cout << "Current password: " << acc.password << "\n";
                    std::cout << "New password (leave empty to keep current): ";
                    std::getline(std::cin, input);
                    if (!input.empty()) {
                        acc.password = input;
                    }
                    std::cout << "Current TOTP secret: " << acc.totpSecret << "\n";
                    std::cout << "New TOTP secret (leave empty to keep current): ";
                    std::getline(std::cin, input);
                    if (!input.empty()) {
                        acc.totpSecret = input;
                    }
                    std::cout << "Current slot: " << acc.slot << "\n";
                    std::cout << "New slot (1-4, leave empty to keep current): ";
                    std::getline(std::cin, input);
                    if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                        int slot = std::stoi(input);
                        if (slot >= 1 && slot <= 4) {
                            acc.slot = slot;
                        }
                    }
                    std::cout << "Current Windower arguments: " << acc.args << "\n";
                    std::cout << "New Windower arguments (leave empty to keep current): ";
                    std::getline(std::cin, input);
                    if (!input.empty()) {
                        acc.args = input;
                    }
                    std::cout << "Character updated.\n";
                }
            }
        } else if (input == "a") {
            AccountConfig newAcc;
            std::cout << "\nAdding new character:\n";
            std::cout << "Character name (no spaces, unique): ";
            std::getline(std::cin, newAcc.name);
            std::cout << "Password: ";
            std::getline(std::cin, newAcc.password);
            std::cout << "TOTP Secret (leave empty if not using): ";
            std::getline(std::cin, newAcc.totpSecret);
            std::cout << "POL Slot number (1-4): ";
            std::getline(std::cin, input);
            if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                int slot = std::stoi(input);
                if (slot >= 1 && slot <= 4) {
                    newAcc.slot = slot;
                }
            }
            std::cout << "Windower arguments (e.g. -p=\"ProfileName\" leave empty for none): ";
            std::getline(std::cin, newAcc.args);
            config.accounts.push_back(newAcc);
            std::cout << "New character added.\n";
        } else if (input == "d") {
            if (config.accounts.empty()) {
                std::cout << "No characters to delete.\n";
                continue;
            }
            std::cout << "\nSelect a character to delete:\n";
            for (size_t i = 0; i < config.accounts.size(); ++i) {
                std::cout << "  [" << (i + 1) << "] " << config.accounts[i].name << " (slot " << config.accounts[i].slot << ")\n";
            }
            std::cout << "Enter number (1-" << config.accounts.size() << "): ";
            std::getline(std::cin, input);
            if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                int choice = std::stoi(input);
                if (choice >= 1 && (size_t)choice <= config.accounts.size()) {
                    std::cout << "Are you sure you want to delete " << config.accounts[choice - 1].name << "? (y/n): ";
                    std::getline(std::cin, input);
                    if (input == "y" || input == "Y") {
                        config.accounts.erase(config.accounts.begin() + choice - 1);
                        std::cout << "Character deleted.\n";
                    }
                }
            }
        } else if (input == "c") {
            std::cout << "Current timeout: " << config.delay / 1000 << " seconds\n";
            std::cout << "New timeout (in seconds, 1-20): ";
            std::getline(std::cin, input);
            if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                int val = std::stoi(input);
                if (val >= 1 && val <= 20) {
                    config.delay = val * 1000;
                    std::cout << "Timeout updated.\n";
                }
            }
        } else if (input == "r") {
            std::cout << "Current client region: " << config.clientRegion << "\n";
            std::cout << "New client region (US/JP): ";
            std::getline(std::cin, input);
            std::transform(input.begin(), input.end(), input.begin(), ::toupper);
            if (input == "US" || input == "JP") {
                config.clientRegion = input;
                std::cout << "Client region updated to " << config.clientRegion << ".\n";
            } else {
                std::cout << "Invalid region. Please enter 'US' or 'JP'.\n";
            }
        } else if (input == "x") {
            return false; // Return to selection screen
        } else {
            std::cout << "Invalid option. Try again.\n";
        }
    }
    return true; // Exit the app
}

// Add back the removeHostsEntry function
void removeHostsEntry() {
    const char* path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    const char* tmpPath = "C:\\Windows\\System32\\drivers\\etc\\hosts.tmp";

    std::ifstream in(path);
    std::ofstream out(tmpPath);

    std::string line;
    while (std::getline(in, line)) {
        // Trim leading/trailing whitespace
        std::string trimmed = line;
        trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
        trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

        // Skip blank or matching lines
        if (trimmed.empty() || trimmed.find("#ffxi-autologin") != std::string::npos)
            continue;

        out << line << "\n";
    }

    in.close();
    out.close();

    DeleteFileA(path);
    MoveFileA(tmpPath, path);
}

// Update main to remove hosts entry before exiting
int main(int argc, char* argv[]) {
    std::cout << "Created by: jaku | https://twitter.com/jaku\n";
    std::cout << "Version: 0.0.23  | https://github.com/jaku/FFXI-autoPOL\n";
    DEBUG_KEY_PRESSES = false;
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--debug-keys") {
            DEBUG_KEY_PRESSES = true;
            std::cout << "Key press logging enabled\n";
        }
    }
    
    // Clean up any existing hosts file entries at startup
    removeHostsEntry();
    
    // Register console control handler to clean up on termination
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string baseDir = exePath;
    std::string configPath = baseDir + "\\config.json";
    GlobalConfig config = loadConfig(configPath);
    bool setupMode = false;
    bool editMode = false;
    std::string characterName;
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--setup") {
            setupMode = true;
        } else if (arg == "--edit") {
            editMode = true;
        } else if (arg == "--character" && i + 1 < argc) {
            characterName = argv[++i];
        } else if (arg == "--windower-arg" && i + 1 < argc) {
            for (auto& acc : config.accounts) {
                if (_stricmp(acc.name.c_str(), characterName.c_str()) == 0) {
                    acc.args = argv[++i];
                    break;
                }
            }
        }
    }
    if (setupMode || config.accounts.empty()) {
        setupConfig(config);
        writeConfigFile(configPath, config);
        std::cout << "Setup complete. Exiting.\n";
        return 0;
    }
    if (editMode) {
        std::cout << "Editing configuration...\n";
        editConfig(config);
        writeConfigFile(configPath, config);
        std::cout << "Configuration updated. Exiting.\n";
        return 0;
    }
    if (config.accounts.empty()) {
        std::cout << "No accounts configured. Please run with --setup to configure accounts.\n";
        return 1;
    }
    // Main loop for character selection and editing
    while (true) {
        // If more than one account and no character specified, prompt user
        if (characterName.empty() && config.accounts.size() > 1) {
            std::cout << "\nSelect a character to log in with:\n";
            for (size_t i = 0; i < config.accounts.size(); ++i) {
                std::cout << "  [" << (i + 1) << "] " << config.accounts[i].name << " (slot " << config.accounts[i].slot << ")\n";
            }
            std::cout << "  [E] Edit configuration\n";
            std::string input;
            int choice = 0;
            while (true) {
                std::cout << "Enter number (1-" << config.accounts.size() << ") or 'E' to edit configuration: ";
                std::getline(std::cin, input);
                std::string lowerInput = input;
                std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
                if (lowerInput == "e") {
                    if (!editConfig(config)) {
                        writeConfigFile(configPath, config);
                        // After editing, reload config and restart selection
                        config = loadConfig(configPath);
                        break; // break inner while, return to selection
                    } else {
                        writeConfigFile(configPath, config);
                        std::cout << "Configuration updated. Exiting.\n";
                        return 0;
                    }
                }
                if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
                    choice = std::stoi(input);
                    if (choice >= 1 && (size_t)choice <= config.accounts.size()) {
                        characterName = config.accounts[choice - 1].name;
                        break;
                    }
                }
                std::cout << "Invalid choice. Try again.\n";
            }
            if (characterName.empty()) {
                continue; // Go back to selection if editConfig returned
            }
        }
        // Set proxy port based on client region
        proxyPort = (config.clientRegion == "JP") ? 51300 : 51304;
        
        // Always start proxy server
        std::thread proxyThread(startProxyServer);
        // Find the account to launch
        AccountConfig* toLaunch = nullptr;
        if (characterName.empty()) {
            // If only one account exists, use it regardless of slot
            if (config.accounts.size() == 1) {
                toLaunch = &config.accounts[0];
            } else {
                // If multiple accounts, we should have already prompted for selection
                // This is just a fallback
                std::cout << "No account selected. Please specify a character name.\n";
                return 1;
            }
        } else {
            for (auto& acc : config.accounts) {
                if (_stricmp(acc.name.c_str(), characterName.c_str()) == 0) { toLaunch = &acc; break; }
            }
        }
        if (!toLaunch) {
            std::cout << "No account found for requested character name.\n";
            return 1;
        }
        launchAccount(*toLaunch, config);
        // Wait for a request, then exit
        while (!shouldExit) { Sleep(100); }
        proxyThread.join();
        // Remove hosts entry before exiting (cleanup is also done in proxy thread and handler, but this ensures it)
        if (hostsEntryAdded.load()) {
            removeHostsEntry();
            hostsEntryAdded = false;
        }
        return 0;
    }
    return 0;
}
