#pragma once

#include <Windows.h>

#include <string>

namespace Haze::Overlay
{
    enum class OverlayStartupMethod
    {
        FullscreenMethod1,
        FullscreenMethod2_UIAccess,
        WindowedMethod3
    };

    struct UIAccessInitResult
    {
        bool success = false;
        bool alreadyEnabled = false;
        bool relaunched = false;
        DWORD errorCode = ERROR_SUCCESS;
        std::string message;
    };

    const char* OverlayStartupMethodName(OverlayStartupMethod method);

    bool IsUIAccessAvailable();
    bool IsRunningWithUIAccess();
    DWORD PrepareUIAccessForCurrentProcess();
    DWORD GetLastUIAccessError();
    UIAccessInitResult InitializeUIAccessOverlayMode();

    bool IsUIAccessMethodArgument(const char* argument);
    bool TryResolveOverlayStartupMethodFromArguments(int argc, char* argv[], OverlayStartupMethod& outMethod);
}
