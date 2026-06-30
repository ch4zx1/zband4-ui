#include "UIAccessManager.h"

#include "../../Utils/ReleaseTestLogger.hpp"

#include <TlHelp32.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace Haze::Overlay
{
    namespace
    {
        constexpr wchar_t kUIAccessMethodArgumentW[] = L"--haze-overlay-method=uiaccess";
        constexpr char kUIAccessMethodArgumentA[] = "--haze-overlay-method=uiaccess";

        DWORD g_LastUIAccessError = ERROR_SUCCESS;

        void SetLastUIAccessError(DWORD errorCode)
        {
            g_LastUIAccessError = errorCode;
        }

        std::string ToLowerAscii(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        std::wstring ToLowerWide(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
                return static_cast<wchar_t>(std::towlower(c));
            });
            return value;
        }

        bool ContainsTextInsensitive(const std::wstring& text, const std::wstring& needle)
        {
            return ToLowerWide(text).find(ToLowerWide(needle)) != std::wstring::npos;
        }

        bool QueryCurrentProcessUIAccess(bool& outEnabled, DWORD& outError)
        {
            outEnabled = false;
            outError = ERROR_SUCCESS;

            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            {
                outError = GetLastError();
                return false;
            }

            DWORD uiAccess = 0;
            DWORD returnLength = 0;
            const BOOL ok = GetTokenInformation(
                token,
                TokenUIAccess,
                &uiAccess,
                sizeof(uiAccess),
                &returnLength);
            if (!ok)
                outError = GetLastError();

            CloseHandle(token);
            outEnabled = uiAccess != 0;
            return ok != FALSE;
        }

        bool IsCurrentProcessElevated(DWORD& outError)
        {
            outError = ERROR_SUCCESS;

            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            {
                outError = GetLastError();
                return false;
            }

            TOKEN_ELEVATION elevation{};
            DWORD returnLength = 0;
            const BOOL ok = GetTokenInformation(
                token,
                TokenElevation,
                &elevation,
                sizeof(elevation),
                &returnLength);
            if (!ok)
                outError = GetLastError();

            CloseHandle(token);
            return ok != FALSE && elevation.TokenIsElevated != 0;
        }

        DWORD DuplicateWinlogonToken(DWORD sessionId, DWORD desiredAccess, HANDLE* outToken)
        {
            if (outToken == nullptr)
                return ERROR_INVALID_PARAMETER;

            *outToken = nullptr;

            PRIVILEGE_SET privilegeSet{};
            privilegeSet.PrivilegeCount = 1;
            privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;

            if (!LookupPrivilegeValueW(nullptr, SE_TCB_NAME, &privilegeSet.Privilege[0].Luid))
                return GetLastError();

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return GetLastError();

            DWORD errorCode = ERROR_NOT_FOUND;
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            for (BOOL keepGoing = Process32FirstW(snapshot, &entry);
                keepGoing;
                keepGoing = Process32NextW(snapshot, &entry))
            {
                if (_wcsicmp(entry.szExeFile, L"winlogon.exe") != 0)
                    continue;

                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                if (process == nullptr)
                    continue;

                HANDLE token = nullptr;
                if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token))
                {
                    BOOL hasTcb = FALSE;
                    DWORD tokenSessionId = 0;
                    DWORD returnLength = 0;

                    if (PrivilegeCheck(token, &privilegeSet, &hasTcb) &&
                        hasTcb &&
                        GetTokenInformation(token, TokenSessionId, &tokenSessionId, sizeof(tokenSessionId), &returnLength) &&
                        tokenSessionId == sessionId)
                    {
                        if (DuplicateTokenEx(token, desiredAccess, nullptr, SecurityImpersonation, TokenImpersonation, outToken))
                            errorCode = ERROR_SUCCESS;
                        else
                            errorCode = GetLastError();

                        CloseHandle(token);
                        CloseHandle(process);
                        break;
                    }

                    CloseHandle(token);
                }

                CloseHandle(process);
            }

            CloseHandle(snapshot);
            return errorCode;
        }

        DWORD CreateUIAccessToken(HANDLE* outToken)
        {
            if (outToken == nullptr)
                return ERROR_INVALID_PARAMETER;

            *outToken = nullptr;

            HANDLE selfToken = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &selfToken))
                return GetLastError();

            DWORD errorCode = ERROR_SUCCESS;
            DWORD sessionId = 0;
            DWORD returnLength = 0;
            if (!GetTokenInformation(selfToken, TokenSessionId, &sessionId, sizeof(sessionId), &returnLength))
            {
                errorCode = GetLastError();
                CloseHandle(selfToken);
                return errorCode;
            }

            HANDLE systemToken = nullptr;
            errorCode = DuplicateWinlogonToken(sessionId, TOKEN_IMPERSONATE, &systemToken);
            if (errorCode != ERROR_SUCCESS)
            {
                CloseHandle(selfToken);
                return errorCode;
            }

            if (SetThreadToken(nullptr, systemToken))
            {
                constexpr DWORD desiredAccess =
                    TOKEN_QUERY |
                    TOKEN_DUPLICATE |
                    TOKEN_ASSIGN_PRIMARY |
                    TOKEN_ADJUST_DEFAULT |
                    TOKEN_ADJUST_SESSIONID;

                if (DuplicateTokenEx(selfToken, desiredAccess, nullptr, SecurityAnonymous, TokenPrimary, outToken))
                {
                    BOOL uiAccess = TRUE;
                    if (!SetTokenInformation(*outToken, TokenUIAccess, &uiAccess, sizeof(uiAccess)))
                    {
                        errorCode = GetLastError();
                        CloseHandle(*outToken);
                        *outToken = nullptr;
                    }
                }
                else
                {
                    errorCode = GetLastError();
                }

                RevertToSelf();
            }
            else
            {
                errorCode = GetLastError();
            }

            CloseHandle(systemToken);
            CloseHandle(selfToken);
            return errorCode;
        }

        std::wstring BuildCommandLineForUIAccessRelaunch()
        {
            std::wstring commandLine = GetCommandLineW();
            if (!ContainsTextInsensitive(commandLine, kUIAccessMethodArgumentW))
            {
                if (!commandLine.empty() && !std::iswspace(commandLine.back()))
                    commandLine += L' ';
                commandLine += kUIAccessMethodArgumentW;
            }
            return commandLine;
        }

        DWORD RelaunchCurrentProcessWithUIAccess(bool& outRelaunched)
        {
            outRelaunched = false;

            HANDLE uiAccessToken = nullptr;
            DWORD errorCode = CreateUIAccessToken(&uiAccessToken);
            if (errorCode != ERROR_SUCCESS)
                return errorCode;

            STARTUPINFOW startupInfo{};
            GetStartupInfoW(&startupInfo);
            startupInfo.cb = sizeof(startupInfo);

            PROCESS_INFORMATION processInfo{};
            std::wstring commandLine = BuildCommandLineForUIAccessRelaunch();
            std::vector<wchar_t> commandLineBuffer(commandLine.begin(), commandLine.end());
            commandLineBuffer.push_back(L'\0');

            wchar_t currentDirectory[MAX_PATH]{};
            LPCWSTR currentDirectoryPtr = nullptr;
            if (GetCurrentDirectoryW(MAX_PATH, currentDirectory) != 0)
                currentDirectoryPtr = currentDirectory;

            const BOOL created = CreateProcessAsUserW(
                uiAccessToken,
                nullptr,
                commandLineBuffer.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                currentDirectoryPtr,
                &startupInfo,
                &processInfo);

            if (created)
            {
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
                outRelaunched = true;
                errorCode = ERROR_SUCCESS;
            }
            else
            {
                errorCode = GetLastError();
            }

            CloseHandle(uiAccessToken);
            return errorCode;
        }

        bool IsPermissionError(DWORD errorCode)
        {
            return errorCode == ERROR_ELEVATION_REQUIRED ||
                errorCode == ERROR_ACCESS_DENIED ||
                errorCode == ERROR_PRIVILEGE_NOT_HELD ||
                errorCode == ERROR_NOT_FOUND;
        }

        std::string BuildUIAccessFailureMessage(DWORD errorCode)
        {
            if (IsPermissionError(errorCode))
                return "O Metodo 2 requer permissao de administrador para iniciar corretamente.";
            return "Nao foi possivel iniciar usando o Metodo 2. Tente o Metodo 1 ou Modo Janela.";
        }
    }

    const char* OverlayStartupMethodName(OverlayStartupMethod method)
    {
        switch (method)
        {
        case OverlayStartupMethod::FullscreenMethod1:
            return "FullscreenMethod1";
        case OverlayStartupMethod::FullscreenMethod2_UIAccess:
            return "FullscreenMethod2_UIAccess";
        case OverlayStartupMethod::WindowedMethod3:
            return "WindowedMethod3";
        default:
            return "Unknown";
        }
    }

    bool IsUIAccessAvailable()
    {
        bool uiAccessEnabled = false;
        DWORD errorCode = ERROR_SUCCESS;
        if (!QueryCurrentProcessUIAccess(uiAccessEnabled, errorCode))
        {
            SetLastUIAccessError(errorCode);
            return false;
        }

        if (uiAccessEnabled)
        {
            SetLastUIAccessError(ERROR_SUCCESS);
            return true;
        }

        if (!IsCurrentProcessElevated(errorCode))
        {
            SetLastUIAccessError(errorCode != ERROR_SUCCESS ? errorCode : ERROR_ELEVATION_REQUIRED);
            return false;
        }

        SetLastUIAccessError(ERROR_SUCCESS);
        return true;
    }

    bool IsRunningWithUIAccess()
    {
        bool uiAccessEnabled = false;
        DWORD errorCode = ERROR_SUCCESS;
        if (!QueryCurrentProcessUIAccess(uiAccessEnabled, errorCode))
        {
            SetLastUIAccessError(errorCode);
            return false;
        }

        SetLastUIAccessError(ERROR_SUCCESS);
        return uiAccessEnabled;
    }

    DWORD PrepareUIAccessForCurrentProcess()
    {
        bool uiAccessEnabled = false;
        DWORD errorCode = ERROR_SUCCESS;
        if (!QueryCurrentProcessUIAccess(uiAccessEnabled, errorCode))
        {
            SetLastUIAccessError(errorCode);
            return errorCode;
        }

        if (uiAccessEnabled)
        {
            SetLastUIAccessError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (!IsCurrentProcessElevated(errorCode))
        {
            errorCode = errorCode != ERROR_SUCCESS ? errorCode : ERROR_ELEVATION_REQUIRED;
            SetLastUIAccessError(errorCode);
            return errorCode;
        }

        bool relaunched = false;
        errorCode = RelaunchCurrentProcessWithUIAccess(relaunched);
        SetLastUIAccessError(errorCode);
        if (errorCode == ERROR_SUCCESS && relaunched)
        {
            ReleaseTestLogger::Flush();
            ExitProcess(0);
        }

        return errorCode;
    }

    DWORD GetLastUIAccessError()
    {
        return g_LastUIAccessError;
    }

    UIAccessInitResult InitializeUIAccessOverlayMode()
    {
        UIAccessInitResult result{};

        HZ_LOG_STEP("uiaccess_requested");

        bool uiAccessEnabled = false;
        DWORD errorCode = ERROR_SUCCESS;
        if (!QueryCurrentProcessUIAccess(uiAccessEnabled, errorCode))
        {
            result.errorCode = errorCode;
            result.message = BuildUIAccessFailureMessage(errorCode);
            SetLastUIAccessError(errorCode);
            HZ_LOG_WARN("uiaccess_error_code=" << errorCode);
            return result;
        }

        if (uiAccessEnabled)
        {
            result.success = true;
            result.alreadyEnabled = true;
            result.message = "Metodo 2 iniciado com sucesso.";
            SetLastUIAccessError(ERROR_SUCCESS);
            HZ_LOG_INFO("uiaccess_already_enabled");
            return result;
        }

        if (!IsCurrentProcessElevated(errorCode))
        {
            errorCode = errorCode != ERROR_SUCCESS ? errorCode : ERROR_ELEVATION_REQUIRED;
            result.errorCode = errorCode;
            result.message = BuildUIAccessFailureMessage(errorCode);
            SetLastUIAccessError(errorCode);
            HZ_LOG_WARN("uiaccess_error_code=" << errorCode);
            return result;
        }

        bool relaunched = false;
        errorCode = RelaunchCurrentProcessWithUIAccess(relaunched);
        result.errorCode = errorCode;
        result.relaunched = relaunched;
        SetLastUIAccessError(errorCode);

        HZ_LOG_INFO("uiaccess_prepare_result=" << (errorCode == ERROR_SUCCESS ? "success" : "failed") <<
            " | uiaccess_error_code=" << errorCode <<
            " | relaunched=" << ReleaseTestLogger::Bool(relaunched));

        if (errorCode == ERROR_SUCCESS)
        {
            result.success = true;
            result.message = "Metodo 2 iniciado com sucesso.";
            if (relaunched)
            {
                ReleaseTestLogger::Flush();
                ExitProcess(0);
            }
            return result;
        }

        result.message = BuildUIAccessFailureMessage(errorCode);
        return result;
    }

    bool IsUIAccessMethodArgument(const char* argument)
    {
        if (argument == nullptr)
            return false;
        return ToLowerAscii(argument) == kUIAccessMethodArgumentA;
    }

    bool TryResolveOverlayStartupMethodFromArguments(int argc, char* argv[], OverlayStartupMethod& outMethod)
    {
        for (int index = 1; index < argc; ++index)
        {
            if (argv == nullptr || argv[index] == nullptr)
                continue;

            const std::string argument = ToLowerAscii(argv[index]);
            if (argument == kUIAccessMethodArgumentA ||
                argument == "--overlay-method=uiaccess" ||
                argument == "--uiaccess-overlay")
            {
                outMethod = OverlayStartupMethod::FullscreenMethod2_UIAccess;
                return true;
            }

            if (argument == "--haze-overlay-method=fullscreen1" ||
                argument == "--overlay-method=fullscreen1" ||
                argument == "--overlay-method=band4")
            {
                outMethod = OverlayStartupMethod::FullscreenMethod1;
                return true;
            }

            if (argument == "--haze-overlay-method=windowed3" ||
                argument == "--overlay-method=windowed3" ||
                argument == "--overlay-method=windowed")
            {
                outMethod = OverlayStartupMethod::WindowedMethod3;
                return true;
            }
        }

        return false;
    }
}
