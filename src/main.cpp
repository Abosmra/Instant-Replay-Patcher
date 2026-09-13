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
#include <vector>
#include <dwmapi.h>
#include <objbase.h>
#include <gdiplus.h>

#define IDR_HOOK_DLL 101
#define IDI_APP_ICON 200

static constexpr DWORD kCmdTimeoutMs = 15'000;
static constexpr DWORD kInjectTimeoutMs = 5'000;
static constexpr DWORD kPollIntervalMs = 2'000;
static constexpr DWORD kStartupDelayMs = 3'000;
static constexpr int kPollAttempts = 150;

static constexpr int kDlgW = 460;
static constexpr int kDlgH = 296;

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

static bool IsInstalled()
{
  return GetFileAttributesW(L"C:\\Windows\\System32\\Tasks\\InstantReplayPatcher") != INVALID_FILE_ATTRIBUTES;
}

static bool DoInstallRunKey()
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

static bool DoUninstallRunKey()
{
  return RunCommand(L"schtasks /Delete /F /TN \"InstantReplayPatcher\"") == 0;
}

/* -----------------------------------------------------------------------
 * Extract hook.dll from resource to %TEMP%\ir_hook.dll
 * --------------------------------------------------------------------- */
static std::wstring ExtractDll()
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

static bool AnyNvContainerRunning()
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

static DWORD FindNvContainer()
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

static bool IsPatchInMemory()
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
static bool DoInject(DWORD pid, const wchar_t *dll)
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

static bool DoEject(DWORD pid)
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
 * Silent mode \u2014 used by HKCU Run entry on login (no UAC, no UI)
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
 * Dialog & UI State (GDI+ Modern Dashboard)
 * --------------------------------------------------------------------- */
enum class BtnId
{
  None,
  Apply,
  Eject,
  Install,
  Uninstall
};
enum class ToastType
{
  None,
  Success,
  Warning,
  Info,
  Error
};

static BtnId g_hoverBtn = BtnId::None;
static BtnId g_pressedBtn = BtnId::None;
static HWND g_hwnd = nullptr;
static bool g_stInstall = false;
static bool g_stPatch = false;
static int g_dpi = 96;

static std::wstring g_toastMsg = L"Ready to patch";
static ToastType g_toastType = ToastType::None;
static ULONGLONG g_toastTime = 0;

static void SetToast(const std::wstring &msg, ToastType type)
{
  g_toastMsg = msg;
  g_toastType = type;
  g_toastTime = GetTickCount64();
  if (g_hwnd)
    InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void RefreshStatus(HWND hwnd)
{
  g_stInstall = IsInstalled();
  g_stPatch = IsPatchInMemory();
  InvalidateRect(hwnd, nullptr, FALSE);
}

static void ActionApplyNow()
{
  DWORD pid = FindNvContainer();
  if (!pid)
  {
    if (AnyNvContainerRunning())
      SetToast(L"Turn ON Instant Replay in NVIDIA App first", ToastType::Warning);
    else
      SetToast(L"NVIDIA App is not running", ToastType::Warning);
    return;
  }
  if (IsPatchInMemory())
  {
    SetToast(L"Patch is already active in memory", ToastType::Info);
    return;
  }
  std::wstring dll = ExtractDll();
  if (dll.empty())
  {
    SetToast(L"Could not extract hook DLL to %TEMP%", ToastType::Error);
    return;
  }
  if (DoInject(pid, dll.c_str()))
    SetToast(L"Patch applied! Active for this session", ToastType::Success);
  else
    SetToast(L"Injection failed. Ensure Instant Replay is active", ToastType::Error);
}

static void ActionRemove()
{
  DWORD pid = FindNvContainer();
  if (!pid || !IsPatchInMemory())
  {
    SetToast(L"No active patch found in memory", ToastType::Info);
    return;
  }
  if (DoEject(pid))
    SetToast(L"Patch successfully ejected from memory", ToastType::Success);
  else
    SetToast(L"Failed to eject patch from memory", ToastType::Error);
}

static void ActionInstall()
{
  if (IsInstalled())
  {
    SetToast(L"Startup task is already registered", ToastType::Info);
    return;
  }
  DWORD pid = FindNvContainer();
  if (pid && !IsPatchInMemory())
  {
    std::wstring dll = ExtractDll();
    if (!dll.empty())
      DoInject(pid, dll.c_str());
  }
  if (DoInstallRunKey())
    SetToast(L"Installed! Auto-applies on every login", ToastType::Success);
  else
    SetToast(L"Failed to register scheduled task", ToastType::Error);
}

static void ActionUninstall()
{
  if (!IsInstalled())
  {
    SetToast(L"Startup task is not registered", ToastType::Info);
    return;
  }
  DWORD pid = FindNvContainer();
  if (pid)
    DoEject(pid);
  if (DoUninstallRunKey())
    SetToast(L"Uninstalled. Startup task removed", ToastType::Success);
  else
    SetToast(L"Failed to remove scheduled task", ToastType::Error);
}

static bool IsButtonEnabled(BtnId id)
{
  switch (id)
  {
  case BtnId::Apply:
    return !g_stPatch;
  case BtnId::Eject:
    return g_stPatch;
  case BtnId::Install:
    return !g_stInstall;
  case BtnId::Uninstall:
    return g_stInstall;
  default:
    return false;
  }
}

static BtnId HitTestButton(float x, float y, float width, float s)
{
  float card1X = 18.0f * s;
  float card1Y = 18.0f * s;
  float card2X = 18.0f * s;
  float card2Y = 128.0f * s;
  float cardW = width - 36.0f * s;
  float btnW = (cardW - 44.0f * s) / 2.0f;
  float btnH = 34.0f * s;

  Gdiplus::RectF btnApply(card1X + 16.0f * s, card1Y + 54.0f * s, btnW, btnH);
  Gdiplus::RectF btnEject(card1X + 28.0f * s + btnW, card1Y + 54.0f * s, btnW, btnH);
  Gdiplus::RectF btnInstall(card2X + 16.0f * s, card2Y + 54.0f * s, btnW, btnH);
  Gdiplus::RectF btnUninstall(card2X + 28.0f * s + btnW, card2Y + 54.0f * s, btnW, btnH);

  if (btnApply.Contains(x, y))
    return BtnId::Apply;
  if (btnEject.Contains(x, y))
    return BtnId::Eject;
  if (btnInstall.Contains(x, y))
    return BtnId::Install;
  if (btnUninstall.Contains(x, y))
    return BtnId::Uninstall;

  return BtnId::None;
}

static void AddRoundedRect(Gdiplus::GraphicsPath &path, const Gdiplus::RectF &rect, float radius)
{
  float d = radius * 2.0f;
  if (d > rect.Width)
    d = rect.Width;
  if (d > rect.Height)
    d = rect.Height;

  path.Reset();
  path.AddArc(rect.X, rect.Y, d, d, 180.0f, 90.0f);
  path.AddArc(rect.X + rect.Width - d, rect.Y, d, d, 270.0f, 90.0f);
  path.AddArc(rect.X + rect.Width - d, rect.Y + rect.Height - d, d, d, 0.0f, 90.0f);
  path.AddArc(rect.X, rect.Y + rect.Height - d, d, d, 90.0f, 90.0f);
  path.CloseFigure();
}

static void DrawStatusPill(
    Gdiplus::Graphics &g,
    const Gdiplus::RectF &rect,
    const wchar_t *text,
    bool active,
    float s,
    Gdiplus::Font &font)
{
  Gdiplus::GraphicsPath path;
  AddRoundedRect(path, rect, rect.Height / 2.0f);

  Gdiplus::Color bgClr = active ? Gdiplus::Color(255, 22, 45, 14) : Gdiplus::Color(255, 30, 33, 39);
  Gdiplus::Color borderClr = active ? Gdiplus::Color(255, 45, 90, 20) : Gdiplus::Color(255, 46, 52, 62);
  Gdiplus::Color textClr = active ? Gdiplus::Color(255, 118, 185, 0) : Gdiplus::Color(255, 138, 145, 158);
  Gdiplus::SolidBrush bgBr(bgClr);
  g.FillPath(&bgBr, &path);

  Gdiplus::Pen pen(borderClr, 1.0f);
  g.DrawPath(&pen, &path);

  Gdiplus::StringFormat sf;
  sf.SetAlignment(Gdiplus::StringAlignmentCenter);
  sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
  Gdiplus::SolidBrush textBr(textClr);
  g.DrawString(text, -1, &font, rect, &sf, &textBr);
}

static void DrawCustomButton(
    Gdiplus::Graphics &g,
    const Gdiplus::RectF &rect,
    const wchar_t *text,
    bool enabled,
    bool hovered,
    bool pressed,
    bool isPrimary,
    float s,
    Gdiplus::Font &font)
{
  Gdiplus::GraphicsPath path;
  AddRoundedRect(path, rect, 6.0f * s);

  Gdiplus::Color bgClr, borderClr, textClr;
  if (!enabled)
  {
    bgClr = Gdiplus::Color(255, 20, 22, 26);
    borderClr = Gdiplus::Color(255, 34, 37, 44);
    textClr = Gdiplus::Color(255, 80, 86, 98);
  }
  else if (pressed)
  {
    bgClr = isPrimary ? Gdiplus::Color(255, 18, 38, 12) : Gdiplus::Color(255, 18, 20, 24);
    borderClr = isPrimary ? Gdiplus::Color(255, 118, 185, 0) : Gdiplus::Color(255, 60, 66, 78);
    textClr = Gdiplus::Color(255, 240, 242, 245);
  }
  else if (hovered)
  {
    bgClr = isPrimary ? Gdiplus::Color(255, 28, 58, 18) : Gdiplus::Color(255, 40, 45, 54);
    borderClr = isPrimary ? Gdiplus::Color(255, 138, 210, 0) : Gdiplus::Color(255, 85, 95, 112);
    textClr = Gdiplus::Color(255, 255, 255, 255);
  }
  else
  {
    bgClr = isPrimary ? Gdiplus::Color(255, 24, 46, 16) : Gdiplus::Color(255, 30, 34, 40);
    borderClr = isPrimary ? Gdiplus::Color(255, 118, 185, 0) : Gdiplus::Color(255, 48, 54, 64);
    textClr = isPrimary ? Gdiplus::Color(255, 240, 242, 245) : Gdiplus::Color(255, 215, 220, 228);
  }

  Gdiplus::SolidBrush br(bgClr);
  g.FillPath(&br, &path);

  Gdiplus::Pen pen(borderClr, 1.0f);
  g.DrawPath(&pen, &path);

  Gdiplus::SolidBrush textBr(textClr);
  Gdiplus::StringFormat sf;
  sf.SetAlignment(Gdiplus::StringAlignmentCenter);
  sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
  g.DrawString(text, -1, &font, rect, &sf, &textBr);
}

static void DrawToast(
    Gdiplus::Graphics &g,
    const Gdiplus::RectF &rect,
    const std::wstring &msg,
    ToastType type,
    float s,
    Gdiplus::Font &font)
{
  Gdiplus::GraphicsPath path;
  AddRoundedRect(path, rect, 8.0f * s);

  Gdiplus::Color borderClr;
  Gdiplus::Color accentClr;
  const wchar_t *prefix = L"";

  switch (type)
  {
  case ToastType::Success:
    borderClr = Gdiplus::Color(255, 45, 90, 20);
    accentClr = Gdiplus::Color(255, 118, 185, 0);
    prefix = L"✓  ";
    break;
  case ToastType::Warning:
    borderClr = Gdiplus::Color(255, 120, 80, 16);
    accentClr = Gdiplus::Color(255, 245, 166, 35);
    prefix = L"▲  ";
    break;
  case ToastType::Error:
    borderClr = Gdiplus::Color(255, 120, 35, 45);
    accentClr = Gdiplus::Color(255, 255, 85, 95);
    prefix = L"✕  ";
    break;
  case ToastType::Info:
    borderClr = Gdiplus::Color(255, 40, 70, 120);
    accentClr = Gdiplus::Color(255, 100, 150, 255);
    prefix = L"ℹ  ";
    break;
  case ToastType::None:
  default:
    borderClr = Gdiplus::Color(255, 42, 47, 56);
    accentClr = Gdiplus::Color(255, 138, 145, 158);
    prefix = L"";
    break;
  }

  Gdiplus::SolidBrush bgBr(Gdiplus::Color(255, 23, 26, 31));
  g.FillPath(&bgBr, &path);

  Gdiplus::Pen pen(borderClr, 1.0f);
  g.DrawPath(&pen, &path);

  // Text (centered, no left vertical pill, no leading dot)
  std::wstring display = std::wstring(prefix) + msg;
  Gdiplus::RectF textRect(rect.X + 8.0f * s, rect.Y, rect.Width - 16.0f * s, rect.Height);
  Gdiplus::SolidBrush textBr(accentClr);
  Gdiplus::StringFormat sf;
  sf.SetAlignment(Gdiplus::StringAlignmentCenter);
  sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
  sf.SetTrimming(Gdiplus::StringTrimmingEllipsisCharacter);
  g.DrawString(display.c_str(), -1, &font, textRect, &sf, &textBr);
}

static void RenderUI(Gdiplus::Graphics &g, int width, int height)
{
  float s = g_dpi / 96.0f;

  // Background
  Gdiplus::SolidBrush bgBrush(Gdiplus::Color(255, 18, 20, 23));
  g.FillRectangle(&bgBrush, 0, 0, width, height);

  Gdiplus::FontFamily fontFam(L"Segoe UI");
  Gdiplus::Font fontCardTitle(&fontFam, 13.0f * s, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
  Gdiplus::Font fontCardDesc(&fontFam, 11.0f * s, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
  Gdiplus::Font fontPill(&fontFam, 9.5f * s, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
  Gdiplus::Font fontBtn(&fontFam, 11.5f * s, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
  Gdiplus::Font fontToast(&fontFam, 11.5f * s, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);

  Gdiplus::StringFormat sfNear;
  sfNear.SetAlignment(Gdiplus::StringAlignmentNear);
  sfNear.SetLineAlignment(Gdiplus::StringAlignmentCenter);

  // Card 1: Live Session Patch
  float card1X = 18.0f * s;
  float card1Y = 18.0f * s;
  float cardW = static_cast<float>(width) - 36.0f * s;
  float cardH = 100.0f * s;

  Gdiplus::GraphicsPath card1Path;
  Gdiplus::RectF card1Rect(card1X, card1Y, cardW, cardH);
  AddRoundedRect(card1Path, card1Rect, 8.0f * s);

  Gdiplus::SolidBrush cardBgBr(Gdiplus::Color(255, 26, 29, 34));
  g.FillPath(&cardBgBr, &card1Path);
  Gdiplus::Pen cardBorderPen(Gdiplus::Color(255, 42, 47, 56), 1.0f);
  g.DrawPath(&cardBorderPen, &card1Path);

  Gdiplus::RectF card1TitleRect(card1X + 16.0f * s, card1Y + 12.0f * s, 260.0f * s, 20.0f * s);
  Gdiplus::SolidBrush cardTitleBr(Gdiplus::Color(255, 240, 242, 245));
  g.DrawString(L"Live Session Patch", -1, &fontCardTitle, card1TitleRect, &sfNear, &cardTitleBr);

  float pillW = 82.0f * s;
  Gdiplus::RectF pill1Rect(card1X + cardW - pillW - 16.0f * s, card1Y + 11.0f * s, pillW, 20.0f * s);
  DrawStatusPill(g, pill1Rect, g_stPatch ? L"ACTIVE" : L"INACTIVE", g_stPatch, s, fontPill);

  Gdiplus::RectF card1DescRect(card1X + 16.0f * s, card1Y + 32.0f * s, cardW - 32.0f * s, 16.0f * s);
  Gdiplus::SolidBrush cardDescBr(Gdiplus::Color(255, 138, 145, 158));
  g.DrawString(L"Hooks nvcontainer in memory. Resets when PC reboots.", -1, &fontCardDesc, card1DescRect, &sfNear, &cardDescBr);

  float btnW = (cardW - 44.0f * s) / 2.0f;
  float btnH = 34.0f * s;
  Gdiplus::RectF btn1Rect(card1X + 16.0f * s, card1Y + 54.0f * s, btnW, btnH);
  Gdiplus::RectF btn2Rect(card1X + 28.0f * s + btnW, card1Y + 54.0f * s, btnW, btnH);

  bool btn1En = IsButtonEnabled(BtnId::Apply);
  bool btn1Hov = (g_hoverBtn == BtnId::Apply) && btn1En;
  bool btn1Prs = (g_pressedBtn == BtnId::Apply) && btn1En;
  DrawCustomButton(g, btn1Rect, g_stPatch ? L"✓ Patch Active" : L"Apply Patch",
                   btn1En, btn1Hov, btn1Prs, !g_stPatch, s, fontBtn);

  bool btn2En = IsButtonEnabled(BtnId::Eject);
  bool btn2Hov = (g_hoverBtn == BtnId::Eject) && btn2En;
  bool btn2Prs = (g_pressedBtn == BtnId::Eject) && btn2En;
  DrawCustomButton(g, btn2Rect, L"Eject from Memory",
                   btn2En, btn2Hov, btn2Prs, false, s, fontBtn);

  // Card 2: Logon Startup Service
  float card2X = 18.0f * s;
  float card2Y = 128.0f * s;

  Gdiplus::GraphicsPath card2Path;
  Gdiplus::RectF card2Rect(card2X, card2Y, cardW, cardH);
  AddRoundedRect(card2Path, card2Rect, 8.0f * s);
  g.FillPath(&cardBgBr, &card2Path);
  g.DrawPath(&cardBorderPen, &card2Path);

  Gdiplus::RectF card2TitleRect(card2X + 16.0f * s, card2Y + 12.0f * s, 260.0f * s, 20.0f * s);
  g.DrawString(L"Logon Startup Service", -1, &fontCardTitle, card2TitleRect, &sfNear, &cardTitleBr);

  Gdiplus::RectF pill2Rect(card2X + cardW - pillW - 16.0f * s, card2Y + 11.0f * s, pillW, 20.0f * s);
  DrawStatusPill(g, pill2Rect, g_stInstall ? L"INSTALLED" : L"DISABLED", g_stInstall, s, fontPill);

  Gdiplus::RectF card2DescRect(card2X + 16.0f * s, card2Y + 32.0f * s, cardW - 32.0f * s, 16.0f * s);
  g.DrawString(L"Silently applies patch at logon via Scheduled Task.", -1, &fontCardDesc, card2DescRect, &sfNear, &cardDescBr);

  Gdiplus::RectF btn3Rect(card2X + 16.0f * s, card2Y + 54.0f * s, btnW, btnH);
  Gdiplus::RectF btn4Rect(card2X + 28.0f * s + btnW, card2Y + 54.0f * s, btnW, btnH);

  bool btn3En = IsButtonEnabled(BtnId::Install);
  bool btn3Hov = (g_hoverBtn == BtnId::Install) && btn3En;
  bool btn3Prs = (g_pressedBtn == BtnId::Install) && btn3En;
  DrawCustomButton(g, btn3Rect, g_stInstall ? L"✓ Auto-Start Active" : L"Enable Auto-Start",
                   btn3En, btn3Hov, btn3Prs, !g_stInstall, s, fontBtn);

  bool btn4En = IsButtonEnabled(BtnId::Uninstall);
  bool btn4Hov = (g_hoverBtn == BtnId::Uninstall) && btn4En;
  bool btn4Prs = (g_pressedBtn == BtnId::Uninstall) && btn4En;
  DrawCustomButton(g, btn4Rect, L"Remove Task",
                   btn4En, btn4Hov, btn4Prs, false, s, fontBtn);

  // Toast / Bottom Status
  float toastX = 18.0f * s;
  float toastY = 238.0f * s;
  Gdiplus::RectF toastRect(toastX, toastY, cardW, 40.0f * s);
  DrawToast(g, toastRect, g_toastMsg, g_toastType, s, fontToast);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
  switch (m)
  {
  case WM_PAINT:
  {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(h, &ps);
    RECT cr;
    GetClientRect(h, &cr);
    int width = cr.right - cr.left;
    int height = cr.bottom - cr.top;

    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBmp = CreateCompatibleBitmap(hdc, width, height);
    HGDIOBJ oldBmp = SelectObject(memDC, memBmp);

    {
      Gdiplus::Graphics g(memDC);
      g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
      g.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);
      g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
      RenderUI(g, width, height);
    }

    BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);
    SelectObject(memDC, oldBmp);
    DeleteObject(memBmp);
    DeleteDC(memDC);

    EndPaint(h, &ps);
    return 0;
  }

  case WM_ERASEBKGND:
    return 1;

  case WM_MOUSEMOVE:
  {
    float s = g_dpi / 96.0f;
    RECT cr;
    GetClientRect(h, &cr);
    float width = static_cast<float>(cr.right - cr.left);

    float x = static_cast<float>(LOWORD(l));
    float y = static_cast<float>(HIWORD(l));
    BtnId hit = HitTestButton(x, y, width, s);
    if (!IsButtonEnabled(hit))
      hit = BtnId::None;

    if (hit != g_hoverBtn)
    {
      g_hoverBtn = hit;
      InvalidateRect(h, nullptr, FALSE);
    }

    TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE, h, 0};
    TrackMouseEvent(&tme);
    return 0;
  }

  case WM_MOUSELEAVE:
    if (g_hoverBtn != BtnId::None || g_pressedBtn != BtnId::None)
    {
      g_hoverBtn = BtnId::None;
      g_pressedBtn = BtnId::None;
      InvalidateRect(h, nullptr, FALSE);
    }
    return 0;

  case WM_SETCURSOR:
    if (LOWORD(l) == HTCLIENT && g_hoverBtn != BtnId::None)
    {
      SetCursor(LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_HAND)));
      return TRUE;
    }
    return DefWindowProcW(h, m, w, l);

  case WM_LBUTTONDOWN:
  {
    float s = g_dpi / 96.0f;
    RECT cr;
    GetClientRect(h, &cr);
    float width = static_cast<float>(cr.right - cr.left);

    float x = static_cast<float>(LOWORD(l));
    float y = static_cast<float>(HIWORD(l));
    BtnId hit = HitTestButton(x, y, width, s);
    if (IsButtonEnabled(hit))
    {
      g_pressedBtn = hit;
      SetCapture(h);
      InvalidateRect(h, nullptr, FALSE);
    }
    return 0;
  }

  case WM_LBUTTONUP:
  {
    if (GetCapture() == h)
      ReleaseCapture();

    if (g_pressedBtn != BtnId::None)
    {
      float s = g_dpi / 96.0f;
      RECT cr;
      GetClientRect(h, &cr);
      float width = static_cast<float>(cr.right - cr.left);

      float x = static_cast<float>(LOWORD(l));
      float y = static_cast<float>(HIWORD(l));
      BtnId hit = HitTestButton(x, y, width, s);

      BtnId fired = (hit == g_pressedBtn) ? g_pressedBtn : BtnId::None;
      g_pressedBtn = BtnId::None;
      g_hoverBtn = IsButtonEnabled(hit) ? hit : BtnId::None;
      InvalidateRect(h, nullptr, FALSE);

      if (fired == BtnId::Apply)
      {
        ActionApplyNow();
        RefreshStatus(h);
      }
      else if (fired == BtnId::Eject)
      {
        ActionRemove();
        RefreshStatus(h);
      }
      else if (fired == BtnId::Install)
      {
        ActionInstall();
        RefreshStatus(h);
      }
      else if (fired == BtnId::Uninstall)
      {
        ActionUninstall();
        RefreshStatus(h);
      }
    }
    return 0;
  }

  case WM_TIMER:
    if (w == 1)
    {
      if (g_toastType != ToastType::None && (GetTickCount64() - g_toastTime > 5000))
      {
        g_toastType = ToastType::None;
        g_toastMsg = L"Ready to patch";
        InvalidateRect(h, nullptr, FALSE);
      }
      RefreshStatus(h);
    }
    return 0;

  case WM_CLOSE:
    DestroyWindow(h);
    return 0;

  case WM_DESTROY:
    KillTimer(h, 1);
    PostQuitMessage(0);
    return 0;
  }

  return DefWindowProcW(h, m, w, l);
}

static void CenterWindow(HWND hwnd)
{
  RECT rc;
  GetWindowRect(hwnd, &rc);
  SetWindowPos(hwnd, HWND_TOP,
               (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2,
               (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2,
               0, 0, SWP_NOSIZE);
}

static void ShowDialog()
{
  Gdiplus::GdiplusStartupInput gdiInput;
  ULONG_PTR gdiToken = 0;
  Gdiplus::GdiplusStartup(&gdiToken, &gdiInput, nullptr);

  HDC tmpDC = GetDC(nullptr);
  g_dpi = GetDeviceCaps(tmpDC, LOGPIXELSY);
  ReleaseDC(nullptr, tmpDC);

  HICON hAppIcon = static_cast<HICON>(LoadImageW(
      GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON),
      IMAGE_ICON, MulDiv(32, g_dpi, 96), MulDiv(32, g_dpi, 96), LR_SHARED));

  WNDCLASSEXW wc = {sizeof(wc)};
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hbrBackground = nullptr;
  wc.lpszClassName = L"IRPatcherWindow";
  wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
  wc.hIcon = hAppIcon;
  wc.hIconSm = hAppIcon;
  RegisterClassExW(&wc);

  constexpr DWORD kStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
  constexpr DWORD kExStyle = WS_EX_APPWINDOW;

  int scaledW = MulDiv(kDlgW, g_dpi, 96);
  int scaledH = MulDiv(kDlgH, g_dpi, 96);
  RECT wr = {0, 0, scaledW, scaledH};
  AdjustWindowRectEx(&wr, kStyle, FALSE, kExStyle);

  HWND hwnd = CreateWindowExW(
      kExStyle,
      L"IRPatcherWindow", L"Instant Replay Patcher",
      kStyle,
      CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top,
      nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);

  BOOL dark = TRUE;
  DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
  g_hwnd = hwnd;

  RefreshStatus(hwnd);
  SetTimer(hwnd, 1, 1500, nullptr);

  CenterWindow(hwnd);
  ShowWindow(hwnd, SW_SHOW);
  UpdateWindow(hwnd);

  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0))
  {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  g_hwnd = nullptr;
  Gdiplus::GdiplusShutdown(gdiToken);
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
