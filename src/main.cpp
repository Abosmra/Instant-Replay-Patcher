/*
 * main.cpp — Instant Replay Patcher
 *
 * Runs with Administrator privileges (required for process injection).
 *
 * Arguments:
 *   (none)        show interactive control dialog
 *   --silent      inject silently on login (registered via Scheduled Task)
 */

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>
#include "patcher.h"
#include "gui.h"

static constexpr DWORD kCmdTimeoutMs = 15'000;
static constexpr DWORD kInjectTimeoutMs = 5'000;
static constexpr DWORD kPollIntervalMs = 2'000;
static constexpr DWORD kStartupDelayMs = 3'000;
static constexpr int kPollAttempts = 150;

/* -----------------------------------------------------------------------
 * Admin check
 * --------------------------------------------------------------------- */
static bool IsRunningAsAdmin()
{
  BOOL admin = FALSE;
  PSID sid = nullptr;
  SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&auth, 2,
                               SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                               0, 0, 0, 0, 0, 0, &sid))
  {
    CheckTokenMembership(nullptr, sid, &admin);
    FreeSid(sid);
  }
  return admin == TRUE;
}

/* -----------------------------------------------------------------------
 * Task Scheduler / service helpers
 * --------------------------------------------------------------------- */
static int RunCommand(const wchar_t *cmd)
{
  wchar_t buf[2048];
  wcsncpy_s(buf, cmd, _TRUNCATE);
  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {};
  if (!CreateProcessW(nullptr, buf, nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    return -1;
  WaitForSingleObject(pi.hProcess, kCmdTimeoutMs);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return (int)code;
}

bool IsInstalled()
{
  return GetFileAttributesW(L"C:\\Windows\\System32\\Tasks\\InstantReplayPatcher") != INVALID_FILE_ATTRIBUTES;
}

bool DoInstallRunKey()
{
  wchar_t exe[MAX_PATH];
  GetModuleFileNameW(nullptr, exe, MAX_PATH);
  wchar_t user[256];
  DWORD n = 256;
  GetUserNameW(user, &n);
  wchar_t cmd[2048];
  swprintf_s(cmd,
             L"schtasks /Create /F /RU \"%s\" /RL HIGHEST /SC ONLOGON "
             L"/TN \"InstantReplayPatcher\" "
             L"/TR \"\\\"%s\\\" --silent\"",
             user, exe);
  return RunCommand(cmd) == 0;
}

bool DoUninstallRunKey()
{
  return RunCommand(L"schtasks /Delete /F /TN \"InstantReplayPatcher\"") == 0;
}

/* -----------------------------------------------------------------------
 * Extract hook.dll from resource to %TEMP%\ir_hook.dll
 * --------------------------------------------------------------------- */
std::wstring ExtractDll()
{
  HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_HOOK_DLL), reinterpret_cast<LPCWSTR>(RT_RCDATA));
  if (!hRes)
    return L"";
  HGLOBAL hGlob = LoadResource(nullptr, hRes);
  if (!hGlob)
    return L"";
  void *data = LockResource(hGlob);
  DWORD size = SizeofResource(nullptr, hRes);
  if (!data || !size)
    return L"";

  wchar_t tmp[MAX_PATH], path[MAX_PATH];
  GetTempPathW(MAX_PATH, tmp);
  swprintf_s(path, L"%sir_hook.dll", tmp);
  DeleteFileW(path);

  HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hf == INVALID_HANDLE_VALUE)
    return L"";
  DWORD written = 0;
  WriteFile(hf, data, size, &written, nullptr);
  CloseHandle(hf);
  if (written != size)
  {
    DeleteFileW(path);
    return L"";
  }
  return path;
}

/* -----------------------------------------------------------------------
 * Process helpers
 * --------------------------------------------------------------------- */
typedef LONG(WINAPI *NtQIP_t)(HANDLE, UINT, PVOID, ULONG, PULONG);

static std::wstring ReadCmdLineFromHandle(HANDLE h)
{
  auto fn = reinterpret_cast<NtQIP_t>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  if (!fn)
    return L"";

  struct
  {
    PVOID r1, Peb, r2[2];
    ULONG_PTR Pid;
    PVOID r3;
  } pbi = {};
  if (fn(h, 0, &pbi, sizeof(pbi), nullptr) != 0)
    return L"";

  BYTE peb[0x100] = {};
  SIZE_T rd = 0;
  if (!ReadProcessMemory(h, pbi.Peb, peb, sizeof(peb), &rd))
    return L"";

  PVOID ppa = *reinterpret_cast<PVOID *>(peb + 0x20);
  BYTE pp[0x200] = {};
  if (!ReadProcessMemory(h, ppa, pp, sizeof(pp), &rd))
    return L"";

  USHORT len = *reinterpret_cast<USHORT *>(pp + 0x70);
  PVOID buf = *reinterpret_cast<PVOID *>(pp + 0x78);
  if (len == 0 || len >= 4096)
    return L"";

  std::wstring s(len / sizeof(wchar_t), L'\0');
  if (!ReadProcessMemory(h, buf, static_cast<LPVOID>(const_cast<wchar_t *>(s.data())), len, &rd))
    return L"";
  return s;
}

static std::wstring GetProcCmdLine(DWORD pid)
{
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!h)
    return L"";
  std::wstring result = ReadCmdLineFromHandle(h);
  CloseHandle(h);
  return result;
}

bool AnyNvContainerRunning()
{
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  PROCESSENTRY32W pe = {sizeof(pe)};
  bool found = false;
  if (Process32FirstW(snap, &pe))
  {
    do
    {
      if (_wcsicmp(pe.szExeFile, L"nvcontainer.exe") == 0)
      {
        found = true;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found;
}

DWORD FindNvContainer()
{
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe = {sizeof(pe)};
  DWORD pid = 0;
  if (Process32FirstW(snap, &pe))
  {
    do
    {
      if (_wcsicmp(pe.szExeFile, L"nvcontainer.exe") == 0)
      {
        if (GetProcCmdLine(pe.th32ProcessID).find(L"SPUser") != std::wstring::npos)
        {
          pid = pe.th32ProcessID;
          break;
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pid;
}

static DWORD WaitForNvContainer()
{
  for (int i = 0; i < kPollAttempts; ++i)
  {
    DWORD pid = FindNvContainer();
    if (pid)
      return pid;
    Sleep(kPollIntervalMs);
  }
  return 0;
}

bool IsPatchInMemory()
{
  DWORD pid = FindNvContainer();
  if (!pid)
    return false;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  MODULEENTRY32W me = {sizeof(me)};
  bool found = false;
  if (Module32FirstW(snap, &me))
  {
    do
    {
      if (_wcsnicmp(me.szModule, L"ir_hook", 7) == 0)
      {
        found = true;
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
}

/* -----------------------------------------------------------------------
 * Inject / Eject
 * --------------------------------------------------------------------- */
bool DoInject(DWORD pid, const wchar_t *dll)
{
  HANDLE hp = OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
      FALSE, pid);
  if (!hp)
    return false;
  size_t bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
  void *remote = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote)
  {
    CloseHandle(hp);
    return false;
  }
  if (!WriteProcessMemory(hp, remote, dll, bytes, nullptr))
  {
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    CloseHandle(hp);
    return false;
  }
  auto fn = reinterpret_cast<LPTHREAD_START_ROUTINE>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
  HANDLE ht = CreateRemoteThread(hp, nullptr, 0, fn, remote, 0, nullptr);
  if (!ht)
  {
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    CloseHandle(hp);
    return false;
  }
  WaitForSingleObject(ht, kInjectTimeoutMs);
  DWORD code = 0;
  GetExitCodeThread(ht, &code);
  CloseHandle(ht);
  VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
  CloseHandle(hp);
  return code != 0;
}

bool DoEject(DWORD pid)
{
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  MODULEENTRY32W me = {sizeof(me)};
  HMODULE hMod = nullptr;
  wchar_t loadedDllPath[MAX_PATH] = {};
  if (Module32FirstW(snap, &me))
  {
    do
    {
      if (_wcsnicmp(me.szModule, L"ir_hook", 7) == 0)
      {
        hMod = me.hModule;
        wcsncpy_s(loadedDllPath, me.szExePath, _TRUNCATE);
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  if (!hMod)
    return false;
  HANDLE hp = OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
      FALSE, pid);
  if (!hp)
    return false;
  auto fn = reinterpret_cast<LPTHREAD_START_ROUTINE>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary"));
  HANDLE ht = CreateRemoteThread(hp, nullptr, 0, fn, hMod, 0, nullptr);
  if (!ht)
  {
    CloseHandle(hp);
    return false;
  }
  WaitForSingleObject(ht, kInjectTimeoutMs);
  DWORD code = 0;
  GetExitCodeThread(ht, &code);
  CloseHandle(ht);
  CloseHandle(hp);
  if (loadedDllPath[0])
  {
    Sleep(100);
    DeleteFileW(loadedDllPath);
  }
  return code != 0;
}

static void EnableDebugPriv()
{
  HANDLE ht;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ht))
    return;
  TOKEN_PRIVILEGES tp = {};
  LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(ht, FALSE, &tp, sizeof(tp), nullptr, nullptr);
  CloseHandle(ht);
}

/* -----------------------------------------------------------------------
 * Silent mode — used by Task Scheduler on login (no UAC, no UI)
 * --------------------------------------------------------------------- */
static int RunSilent()
{
  EnableDebugPriv();
  DWORD pid = WaitForNvContainer();
  if (!pid)
    return 1;
  Sleep(kStartupDelayMs);
  std::wstring dll = ExtractDll();
  if (dll.empty())
    return 1;
  DoInject(pid, dll.c_str());
  return 0;
}

/* -----------------------------------------------------------------------
 * wWinMain
 * --------------------------------------------------------------------- */
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmd, int)
{
  if (lpCmd && wcsstr(lpCmd, L"--silent"))
    return RunSilent();

  HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"IRPatcher_Instance");
  if (GetLastError() == ERROR_ALREADY_EXISTS)
  {
    HWND existing = FindWindowW(L"IRPatcherWindow", nullptr);
    if (existing)
    {
      if (IsIconic(existing))
        ShowWindow(existing, SW_RESTORE);
      SetForegroundWindow(existing);
    }
    CloseHandle(hMutex);
    return 0;
  }

  if (!IsRunningAsAdmin())
  {
    MessageBoxW(nullptr,
                L"This application requires administrator privileges.\n"
                L"Right-click IRPatcher.exe and select \"Run as administrator\".",
                L"Administrator Required", MB_OK | MB_ICONERROR);
    return 1;
  }

  EnableDebugPriv();
  ShowDialog();
  return 0;
}
