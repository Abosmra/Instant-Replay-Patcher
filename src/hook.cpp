/*
 * hook.cpp — Instant Replay anti-disable hook DLL
 *
 * Injected into nvcontainer.exe (SPUser instance).
 * Applies three patches:
 *   1. Hooks GetWindowDisplayAffinity -> always WDA_NONE
 *   2. Hooks Module32FirstW           -> always FALSE
 *   3. Hooks LoadLibraryExW           -> patches nvd3dumx.dll on load
 *   4. Byte-patches nvd3dumx.dll if already loaded
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>

static constexpr int kWatcherTicks = 300;
static constexpr DWORD kWatcherSleepMs = 1'000;

static void Log(const char *fmt, ...)
{
  wchar_t tmp[MAX_PATH];
  GetTempPathW(MAX_PATH, tmp);
  wchar_t path[MAX_PATH];
  swprintf_s(path, L"%sir_hook_log.txt", tmp);
  FILE *f = nullptr;
  _wfopen_s(&f, path, L"a");
  if (!f)
    return;
  va_list va;
  va_start(va, fmt);
  vfprintf(f, fmt, va);
  va_end(va);
  fclose(f);
}

#pragma comment(lib, "psapi.lib")

/* -----------------------------------------------------------------------
 * nvd3dumx.dll byte patches (Widevine L1 flag bypass)
 * --------------------------------------------------------------------- */
static BYTE g_orig1[] = {0x44, 0x8B, 0x82, 0x70, 0x01, 0x00, 0x00, 0x45, 0x85, 0xC0};
static BYTE g_patch1[] = {0x45, 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x45, 0x85, 0xC0};
static BYTE g_orig2[] = {0x8B, 0x88, 0x70, 0x01, 0x00, 0x00, 0x85, 0xC9};
static BYTE g_patch2[] = {0x31, 0xC9, 0x90, 0x90, 0x90, 0x90, 0x85, 0xC9};

struct PatternPair
{
  BYTE *search;
  BYTE *replace;
  size_t len;
};

static void ApplyPatterns(HMODULE hMod, PatternPair *pairs, int count)
{
  if (!hMod)
    return;
  MODULEINFO mi = {};
  if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
    return;

  BYTE *base = static_cast<BYTE *>(mi.lpBaseOfDll);
  SIZE_T size = mi.SizeOfImage;

  for (int i = 0; i < count; ++i)
  {
    PatternPair &p = pairs[i];
    bool found = false;
    for (SIZE_T j = 0; j + p.len <= size; ++j)
    {
      if (memcmp(base + j, p.search, p.len) == 0)
      {
        DWORD old;
        if (VirtualProtect(base + j, p.len, PAGE_EXECUTE_READWRITE, &old))
        {
          memcpy(base + j, p.replace, p.len);
          VirtualProtect(base + j, p.len, old, &old);
          Log("  pattern %d: PATCHED at offset 0x%zx\n", i, j);
        }
        else
        {
          Log("  pattern %d: found but VirtualProtect FAILED\n", i);
        }
        found = true;
        break;
      }
    }
    if (!found)
      Log("  pattern %d: NOT FOUND\n", i);
  }
}

static void PatchNvd3dumx(HMODULE hMod)
{
  PatternPair pairs[] = {
      {g_orig1, g_patch1, sizeof(g_orig1)},
      {g_orig2, g_patch2, sizeof(g_orig2)},
  };
  ApplyPatterns(hMod, pairs, 2);
}

static void UnpatchNvd3dumx(HMODULE hMod)
{
  PatternPair pairs[] = {
      {g_patch1, g_orig1, sizeof(g_patch1)},
      {g_patch2, g_orig2, sizeof(g_patch2)},
  };
  ApplyPatterns(hMod, pairs, 2);
}

/* -----------------------------------------------------------------------
 * API hooks
 * --------------------------------------------------------------------- */
static decltype(&GetWindowDisplayAffinity) Real_GetWindowDisplayAffinity = GetWindowDisplayAffinity;
static BOOL WINAPI Hook_GetWindowDisplayAffinity(HWND, DWORD *p)
{
  *p = WDA_NONE;
  return TRUE;
}

static decltype(&Module32FirstW) Real_Module32FirstW = Module32FirstW;
static BOOL WINAPI Hook_Module32FirstW(HANDLE, LPMODULEENTRY32W) { return FALSE; }

static decltype(&LoadLibraryExW) Real_LoadLibraryExW = LoadLibraryExW;
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE f, DWORD flags)
{
  HMODULE h = Real_LoadLibraryExW(name, f, flags);
  if (h && name)
  {
    const wchar_t *t = L"nvd3dumx.dll";
    size_t nl = wcslen(name), tl = wcslen(t);
    if (nl >= tl && _wcsicmp(name + nl - tl, t) == 0)
    {
      Log("nvd3dumx.dll loaded via LoadLibraryExW — patching\n");
      PatchNvd3dumx(h);
    }
  }
  return h;
}

static void InstallHooks()
{
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach((void **)&Real_GetWindowDisplayAffinity, (void *)Hook_GetWindowDisplayAffinity);
  DetourAttach((void **)&Real_Module32FirstW, (void *)Hook_Module32FirstW);
  DetourAttach((void **)&Real_LoadLibraryExW, (void *)Hook_LoadLibraryExW);
  DetourTransactionCommit();
}

static void RemoveHooks()
{
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach((void **)&Real_GetWindowDisplayAffinity, (void *)Hook_GetWindowDisplayAffinity);
  DetourDetach((void **)&Real_Module32FirstW, (void *)Hook_Module32FirstW);
  DetourDetach((void **)&Real_LoadLibraryExW, (void *)Hook_LoadLibraryExW);
  DetourTransactionCommit();
}

/* -----------------------------------------------------------------------
 * DllMain
 * --------------------------------------------------------------------- */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hInst);
    Log("=== ir_hook DllMain ATTACH ===\n");
    InstallHooks();
    Log("Detours hooks installed\n");
    HMODULE hNvd = GetModuleHandleW(L"nvd3dumx.dll");
    if (hNvd)
    {
      Log("nvd3dumx.dll already loaded — patching now\n");
      PatchNvd3dumx(hNvd);
    }
    else
    {
      Log("nvd3dumx.dll not yet loaded — starting watcher thread\n");
      CreateThread(nullptr, 0, [](LPVOID) -> DWORD
                   {
                for (int i = 0; i < kWatcherTicks; ++i) {
                    Sleep(kWatcherSleepMs);
                    HMODULE h = GetModuleHandleW(L"nvd3dumx.dll");
                    if (h) {
                        Log("nvd3dumx.dll appeared after %ds — patching\n", i + 1);
                        PatchNvd3dumx(h);
                        return 0;
                    }
                }
                Log("nvd3dumx.dll never appeared\n");
                return 0; }, nullptr, 0, nullptr);
    }
  }
  else if (reason == DLL_PROCESS_DETACH)
  {
    RemoveHooks();
    HMODULE hNvd = GetModuleHandleW(L"nvd3dumx.dll");
    if (hNvd)
      UnpatchNvd3dumx(hNvd);
  }
  return TRUE;
}
