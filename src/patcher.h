#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

#define IDR_HOOK_DLL 101
#define IDI_APP_ICON 200

bool IsInstalled();
bool IsPatchInMemory();
DWORD FindNvContainer();
bool AnyNvContainerRunning();
std::wstring ExtractDll();
bool DoInject(DWORD pid, const wchar_t *dll);
bool DoEject(DWORD pid);
bool DoInstallRunKey();
bool DoUninstallRunKey();

