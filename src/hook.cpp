/*
 * hook.cpp — Instant Replay anti-disable hook DLL
 *
 * Injected into nvcontainer.exe (SPUser instance).
 * Applies:
 *   1. Hooks GetWindowDisplayAffinity -> always WDA_NONE
 *   2. Hooks Module32First/Next (W & A) -> always FALSE (blocks Widevine detection)
 *   3. Hooks LoadLibrary(Ex) (W & A) -> patches nvd3dumx.dll on dynamic load
 *   4. Byte-patches nvd3dumx.dll if already loaded (using fast PE executable section scan)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>

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

  SYSTEMTIME st;
  GetLocalTime(&st);
  fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

  va_list va;
  va_start(va, fmt);
  vfprintf(f, fmt, va);
  va_end(va);
  fclose(f);
}

/* -----------------------------------------------------------------------
 * nvd3dumx.dll byte patches (Widevine L1 flag bypass)
 * --------------------------------------------------------------------- */
static BYTE g_orig1[]  = {0x44, 0x8B, 0x82, 0x70, 0x01, 0x00, 0x00, 0x45, 0x85, 0xC0};
static BYTE g_patch1[] = {0x45, 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x45, 0x85, 0xC0};
static BYTE g_orig2[]  = {0x8B, 0x88, 0x70, 0x01, 0x00, 0x00, 0x85, 0xC9};
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

  auto modBase = reinterpret_cast<BYTE *>(reinterpret_cast<ULONG_PTR>(hMod) & ~3ULL);
  auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(modBase);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
  {
    Log("ApplyPatterns: Invalid DOS header\n");
    return;
  }

  auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(
      modBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
  {
    Log("ApplyPatterns: Invalid NT header\n");
    return;
  }

  auto section = IMAGE_FIRST_SECTION(nt);

  for (int i = 0; i < count; ++i)
  {
    PatternPair &p = pairs[i];
    bool found = false;

    // Scan only executable code sections to avoid access violations and reduce scan time to ~5ms
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections && !found; ++s)
    {
      if (!(section[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
        continue;

      BYTE *secBase = modBase + section[s].VirtualAddress;
      DWORD secSize = section[s].Misc.VirtualSize;
      if (secSize == 0)
        secSize = section[s].SizeOfRawData;

      for (DWORD j = 0; j + p.len <= secSize; ++j)
      {
        // First-byte filter before invoking memcmp
        if (secBase[j] == p.search[0] && memcmp(secBase + j, p.search, p.len) == 0)
        {
          DWORD oldProtect = 0;
          if (VirtualProtect(secBase + j, p.len, PAGE_EXECUTE_READWRITE, &oldProtect))
          {
            memcpy(secBase + j, p.replace, p.len);
            VirtualProtect(secBase + j, p.len, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), secBase + j, p.len);
            Log("  pattern %d: PATCHED at RVA 0x%lx (section %.8s)\n",
                i, (DWORD)(section[s].VirtualAddress + j), section[s].Name);
          }
          else
          {
            Log("  pattern %d: found at RVA 0x%lx but VirtualProtect failed (err: %lu)\n",
                i, (DWORD)(section[s].VirtualAddress + j), GetLastError());
          }
          found = true;
          break;
        }
        else if (secBase[j] == p.replace[0] && memcmp(secBase + j, p.replace, p.len) == 0)
        {
          Log("  pattern %d: ALREADY in target state at RVA 0x%lx (section %.8s)\n",
              i, (DWORD)(section[s].VirtualAddress + j), section[s].Name);
          found = true;
          break;
        }
      }
    }

    if (!found)
    {
      Log("  pattern %d: NOT FOUND in any executable section\n", i);
    }
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

// 1. GetWindowDisplayAffinity — spoof WDA_NONE so protected windows aren't flagged
static decltype(&GetWindowDisplayAffinity) Real_GetWindowDisplayAffinity = GetWindowDisplayAffinity;
static BOOL WINAPI Hook_GetWindowDisplayAffinity(HWND, DWORD *p)
{
  if (!p)
  {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  *p = WDA_NONE;
  return TRUE;
}

// 2. Module enumeration — return ERROR_NO_MORE_FILES so browser Widevine checks fail immediately
static decltype(&Module32FirstW) Real_Module32FirstW = Module32FirstW;
static BOOL WINAPI Hook_Module32FirstW(HANDLE, LPMODULEENTRY32W)
{
  SetLastError(ERROR_NO_MORE_FILES);
  return FALSE;
}

static decltype(&Module32NextW) Real_Module32NextW = Module32NextW;
static BOOL WINAPI Hook_Module32NextW(HANDLE, LPMODULEENTRY32W)
{
  SetLastError(ERROR_NO_MORE_FILES);
  return FALSE;
}

static decltype(&Module32First) Real_Module32First = Module32First;
static BOOL WINAPI Hook_Module32First(HANDLE, LPMODULEENTRY32)
{
  SetLastError(ERROR_NO_MORE_FILES);
  return FALSE;
}

static decltype(&Module32Next) Real_Module32Next = Module32Next;
static BOOL WINAPI Hook_Module32Next(HANDLE, LPMODULEENTRY32)
{
  SetLastError(ERROR_NO_MORE_FILES);
  return FALSE;
}

// 3. Dynamic loading — catch nvd3dumx.dll regardless of which loader function is called
static bool IsNvd3dumx(LPCWSTR name)
{
  if (!name)
    return false;
  const wchar_t *t = L"nvd3dumx.dll";
  size_t nl = wcslen(name), tl = wcslen(t);
  return (nl >= tl && _wcsicmp(name + nl - tl, t) == 0);
}

static bool IsNvd3dumxA(LPCSTR name)
{
  if (!name)
    return false;
  const char *t = "nvd3dumx.dll";
  size_t nl = strlen(name), tl = strlen(t);
  return (nl >= tl && _stricmp(name + nl - tl, t) == 0);
}

static decltype(&LoadLibraryW) Real_LoadLibraryW = LoadLibraryW;
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name)
{
  HMODULE h = Real_LoadLibraryW(name);
  if (h && IsNvd3dumx(name))
  {
    Log("nvd3dumx.dll loaded via LoadLibraryW — patching\n");
    PatchNvd3dumx(h);
  }
  return h;
}

static decltype(&LoadLibraryExW) Real_LoadLibraryExW = LoadLibraryExW;
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE f, DWORD flags)
{
  HMODULE h = Real_LoadLibraryExW(name, f, flags);
  if (h && IsNvd3dumx(name))
  {
    Log("nvd3dumx.dll loaded via LoadLibraryExW — patching\n");
    PatchNvd3dumx(h);
  }
  return h;
}

static decltype(&LoadLibraryA) Real_LoadLibraryA = LoadLibraryA;
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR name)
{
  HMODULE h = Real_LoadLibraryA(name);
  if (h && IsNvd3dumxA(name))
  {
    Log("nvd3dumx.dll loaded via LoadLibraryA — patching\n");
    PatchNvd3dumx(h);
  }
  return h;
}

static decltype(&LoadLibraryExA) Real_LoadLibraryExA = LoadLibraryExA;
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR name, HANDLE f, DWORD flags)
{
  HMODULE h = Real_LoadLibraryExA(name, f, flags);
  if (h && IsNvd3dumxA(name))
  {
    Log("nvd3dumx.dll loaded via LoadLibraryExA — patching\n");
    PatchNvd3dumx(h);
  }
  return h;
}

static void InstallHooks()
{
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach((void **)&Real_GetWindowDisplayAffinity, (void *)Hook_GetWindowDisplayAffinity);
  DetourAttach((void **)&Real_Module32FirstW, (void *)Hook_Module32FirstW);
  DetourAttach((void **)&Real_Module32NextW, (void *)Hook_Module32NextW);
  DetourAttach((void **)&Real_Module32First, (void *)Hook_Module32First);
  DetourAttach((void **)&Real_Module32Next, (void *)Hook_Module32Next);
  DetourAttach((void **)&Real_LoadLibraryW, (void *)Hook_LoadLibraryW);
  DetourAttach((void **)&Real_LoadLibraryExW, (void *)Hook_LoadLibraryExW);
  DetourAttach((void **)&Real_LoadLibraryA, (void *)Hook_LoadLibraryA);
  DetourAttach((void **)&Real_LoadLibraryExA, (void *)Hook_LoadLibraryExA);
  LONG err = DetourTransactionCommit();
  if (err != NO_ERROR)
    Log("DetourTransactionCommit (install) failed with error %ld\n", err);
}

static void RemoveHooks()
{
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach((void **)&Real_GetWindowDisplayAffinity, (void *)Hook_GetWindowDisplayAffinity);
  DetourDetach((void **)&Real_Module32FirstW, (void *)Hook_Module32FirstW);
  DetourDetach((void **)&Real_Module32NextW, (void *)Hook_Module32NextW);
  DetourDetach((void **)&Real_Module32First, (void *)Hook_Module32First);
  DetourDetach((void **)&Real_Module32Next, (void *)Hook_Module32Next);
  DetourDetach((void **)&Real_LoadLibraryW, (void *)Hook_LoadLibraryW);
  DetourDetach((void **)&Real_LoadLibraryExW, (void *)Hook_LoadLibraryExW);
  DetourDetach((void **)&Real_LoadLibraryA, (void *)Hook_LoadLibraryA);
  DetourDetach((void **)&Real_LoadLibraryExA, (void *)Hook_LoadLibraryExA);
  LONG err = DetourTransactionCommit();
  if (err != NO_ERROR)
    Log("DetourTransactionCommit (remove) failed with error %ld\n", err);
}

/* -----------------------------------------------------------------------
 * DllMain
 * --------------------------------------------------------------------- */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID lpReserved)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hInst);
    Log("=== ir_hook DllMain ATTACH (PID: %lu) ===\n", GetCurrentProcessId());
    InstallHooks();
    Log("Detours hooks installed\n");
    HMODULE hNvd = GetModuleHandleW(L"nvd3dumx.dll");
    if (hNvd)
    {
      Log("nvd3dumx.dll already loaded — patching now\n");
      PatchNvd3dumx(hNvd);
    }
  }
  else if (reason == DLL_PROCESS_DETACH)
  {
    Log("=== ir_hook DllMain DETACH (lpReserved: %p) ===\n", lpReserved);
    // Only safely unhook during explicit FreeLibrary (lpReserved == nullptr),
    // avoid touching memory during process termination.
    if (!lpReserved)
    {
      RemoveHooks();
      HMODULE hNvd = GetModuleHandleW(L"nvd3dumx.dll");
      if (hNvd)
        UnpatchNvd3dumx(hNvd);
      Log("Detours hooks removed and driver unpatched\n");
    }
  }
  return TRUE;
}
