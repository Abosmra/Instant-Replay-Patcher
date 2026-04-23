/*
 * main.cpp \u2014 Instant Replay Patcher
 *
 * Runs as a normal user (no forced UAC).
 * Self-elevates via ShellExecuteW runas ONLY for Install/Uninstall.
 *
 * Arguments:
 *   (none)        show dialog
 *   --silent      inject silently at startup (added by Run key)
 *   --install     install Run key (called elevated)
 *   --uninstall   remove Run key (called elevated)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

#define IDR_HOOK_DLL 101
#define IDI_APP_ICON 200

static constexpr DWORD kCmdTimeoutMs = 15'000;
static constexpr DWORD kInjectTimeoutMs = 5'000;
static constexpr DWORD kPollIntervalMs = 2'000;
static constexpr DWORD kStartupDelayMs = 3'000;
static constexpr int kPollAttempts = 150;

static constexpr int kDlgW = 420;
static constexpr int kDlgH = 324;
static constexpr int kBtnW = 380;
static constexpr int kBtnH = 46;
static constexpr int kBtnX = 20;
static constexpr int kBtnY0 = 78;
static constexpr int kBtnGap = 8;

static constexpr COLORREF kClrBg = RGB(18, 18, 25);
static constexpr COLORREF kClrBtnNorm = RGB(30, 30, 44);
static constexpr COLORREF kClrBtnHov = RGB(46, 46, 66);
static constexpr COLORREF kClrBtnPrs = RGB(58, 58, 82);
static constexpr COLORREF kClrBorder = RGB(52, 52, 72);
static constexpr COLORREF kClrAccent = RGB(100, 149, 255);
static constexpr COLORREF kClrText = RGB(222, 222, 234);
static constexpr COLORREF kClrDim = RGB(100, 100, 120);
static constexpr COLORREF kClrGreen = RGB(72, 199, 116);

#define ID_BTN_ONCE 101
#define ID_BTN_INSTALL 102
#define ID_BTN_UNINSTALL 103
#define ID_BTN_REMOVE 104

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
  return RunCommand(L"schtasks /Query /TN \"InstantReplayPatcher\"") == 0 || RunCommand(L"sc query InstantReplayPatcher") == 0;
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
  RunCommand(L"sc stop InstantReplayPatcher");
  RunCommand(L"sc delete InstantReplayPatcher");

  bool deleted = RunCommand(L"schtasks /Delete /F /TN InstantReplayPatcher") == 0 || RunCommand(L"schtasks /Delete /F /TN \"InstantReplayPatcher\"") == 0;

  HKEY hk;
  if (RegOpenKeyExW(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS)
  {
    RegDeleteValueW(hk, L"InstantReplayPatcher");
    RegCloseKey(hk);
  }

  return deleted || RunCommand(L"sc query InstantReplayPatcher") != 0;
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
  swprintf_s(path, L"%sir_hook_%lu.dll", tmp, GetCurrentProcessId());
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

static DWORD FindNvContainer()
{
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  PROCESSENTRY32W pe = {sizeof(pe)};
  DWORD pid = 0, fallback = 0;
  if (Process32FirstW(snap, &pe))
  {
    do
    {
      if (_wcsicmp(pe.szExeFile, L"nvcontainer.exe") == 0)
      {
        if (!fallback)
          fallback = pe.th32ProcessID;
        if (GetProcCmdLine(pe.th32ProcessID).find(L"SPUser") != std::wstring::npos)
        {
          pid = pe.th32ProcessID;
          break;
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pid ? pid : fallback;
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
  if (Module32FirstW(snap, &me))
  {
    do
    {
      if (_wcsnicmp(me.szModule, L"ir_hook", 7) == 0)
      {
        hMod = me.hModule;
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
  wchar_t tmp[MAX_PATH], path[MAX_PATH];
  GetTempPathW(MAX_PATH, tmp);
  swprintf_s(path, L"%sir_hook.dll", tmp);
  DeleteFileW(path);
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
 * Dialog
 * --------------------------------------------------------------------- */
static HFONT g_uiFont = nullptr;
static HFONT g_uiFontBold = nullptr;
static HWND g_hoverBtn = nullptr;
static HWND g_hwnd = nullptr;
static HWND g_lblStart = nullptr;
static HWND g_lblPatch = nullptr;
static bool g_stInstall = false;
static bool g_stPatch = false;
static int g_dpi = 96;

static int SC(int v) { return MulDiv(v, g_dpi, 96); }

static void RefreshStatus(HWND hwnd)
{
  g_stInstall = IsInstalled();
  g_stPatch = IsPatchInMemory();
  wchar_t s1[64], s2[64];
  swprintf_s(s1, L"Startup:  %ls", g_stInstall ? L"Installed" : L"Not installed");
  swprintf_s(s2, L"Patch:  %ls", g_stPatch ? L"Active" : L"Inactive");
  SetWindowTextW(g_lblStart, s1);
  SetWindowTextW(g_lblPatch, s2);
  InvalidateRect(hwnd, nullptr, TRUE);
  UpdateWindow(hwnd);
}

static void ActionApplyNow()
{
  DWORD pid = FindNvContainer();
  if (!pid)
  {
    MessageBoxW(g_hwnd, L"NVIDIA App is not running. Start it and try again.",
                L"Not Running", MB_OK | MB_ICONWARNING);
    return;
  }
  if (IsPatchInMemory())
  {
    MessageBoxW(g_hwnd, L"Patch is already active in memory.",
                L"Already Patched", MB_OK | MB_ICONINFORMATION);
    return;
  }
  std::wstring dll = ExtractDll();
  if (dll.empty())
  {
    MessageBoxW(g_hwnd, L"Could not extract the hook. Check write access to the temp folder.",
                L"Extraction Failed", MB_OK | MB_ICONERROR);
    return;
  }
  if (DoInject(pid, dll.c_str()))
    MessageBoxW(g_hwnd, L"Patch applied successfully. It will reset on the next reboot.",
                L"Patch Applied", MB_OK | MB_ICONINFORMATION);
  else
    MessageBoxW(g_hwnd, L"Injection failed.", L"Injection Failed", MB_OK | MB_ICONERROR);
}

static void ActionRemove()
{
  DWORD pid = FindNvContainer();
  if (pid && DoEject(pid))
    MessageBoxW(g_hwnd, L"Patch removed from memory. Startup entry is unchanged.",
                L"Patch Removed", MB_OK | MB_ICONINFORMATION);
  else
    MessageBoxW(g_hwnd, L"No active patch found in memory. It may not have been applied.",
                L"Nothing to Remove", MB_OK | MB_ICONWARNING);
}

static void ActionInstall()
{
  if (IsInstalled())
  {
    MessageBoxW(g_hwnd, L"Startup entry is already installed.",
                L"Already Installed", MB_OK | MB_ICONINFORMATION);
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
    MessageBoxW(g_hwnd, L"Instant Replay will now be patched automatically on every login.",
                L"Installed", MB_OK | MB_ICONINFORMATION);
  else
    MessageBoxW(g_hwnd, L"Could not register the startup task.",
                L"Install Failed", MB_OK | MB_ICONERROR);
}

static void ActionUninstall()
{
  if (!IsInstalled())
  {
    MessageBoxW(g_hwnd, L"No startup entry found - it may have already been removed.",
                L"Not Installed", MB_OK | MB_ICONWARNING);
    return;
  }
  DWORD pid = FindNvContainer();
  if (pid)
    DoEject(pid);
  if (DoUninstallRunKey())
    MessageBoxW(g_hwnd, L"Startup entry removed. The patch will no longer apply on login.",
                L"Uninstalled", MB_OK | MB_ICONINFORMATION);
  else
    MessageBoxW(g_hwnd, L"Failed to remove the startup entry.",
                L"Uninstall Failed", MB_OK | MB_ICONERROR);
}

static LRESULT CALLBACK BtnSubclassProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
  auto orig = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_MOUSEMOVE && g_hoverBtn != hwnd)
  {
    HWND prev = g_hoverBtn;
    g_hoverBtn = hwnd;
    TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE, hwnd, 0};
    TrackMouseEvent(&tme);
    if (prev)
      InvalidateRect(prev, nullptr, FALSE);
    InvalidateRect(hwnd, nullptr, FALSE);
  }
  else if (msg == WM_MOUSELEAVE && g_hoverBtn == hwnd)
  {
    g_hoverBtn = nullptr;
    InvalidateRect(hwnd, nullptr, FALSE);
  }
  return CallWindowProcW(orig, hwnd, msg, w, l);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
  if (m == WM_COMMAND)
  {
    int id = LOWORD(w);
    switch (id)
    {
    case ID_BTN_ONCE:
      ActionApplyNow();
      RefreshStatus(h);
      break;
    case ID_BTN_REMOVE:
      ActionRemove();
      RefreshStatus(h);
      break;
    case ID_BTN_INSTALL:
      ActionInstall();
      RefreshStatus(h);
      break;
    case ID_BTN_UNINSTALL:
      ActionUninstall();
      RefreshStatus(h);
      break;
    }
    return 0;
  }
  if (m == WM_DESTROY)
  {
    PostQuitMessage(0);
    return 0;
  }
  if (m == WM_CLOSE)
  {
    DestroyWindow(h);
    return 0;
  }

  if (m == WM_ERASEBKGND)
  {
    RECT rc;
    GetClientRect(h, &rc);
    HBRUSH br = CreateSolidBrush(kClrBg);
    FillRect(reinterpret_cast<HDC>(w), &rc, br);
    DeleteObject(br);
    return 1;
  }
  if (m == WM_PAINT)
  {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(h, &ps);
    HPEN pen = CreatePen(PS_SOLID, 1, kClrBorder);
    HPEN old = static_cast<HPEN>(SelectObject(hdc, pen));
    MoveToEx(hdc, SC(kBtnX + 20), SC(64), nullptr);
    LineTo(hdc, SC(kBtnX + kBtnW - 20), SC(64));
    int mid = SC(kBtnY0) + 2 * (SC(kBtnH) + SC(kBtnGap)) + SC(5);
    MoveToEx(hdc, SC(kBtnX + 20), mid, nullptr);
    LineTo(hdc, SC(kBtnX + kBtnW - 20), mid);
    SelectObject(hdc, old);
    DeleteObject(pen);
    EndPaint(h, &ps);
    return 0;
  }
  if (m == WM_CTLCOLORSTATIC)
  {
    HDC hdc = reinterpret_cast<HDC>(w);
    HWND ctrl = reinterpret_cast<HWND>(l);
    SetBkMode(hdc, TRANSPARENT);
    if (ctrl == g_lblStart)
      SetTextColor(hdc, g_stInstall ? kClrGreen : kClrDim);
    else if (ctrl == g_lblPatch)
      SetTextColor(hdc, g_stPatch ? kClrGreen : kClrDim);
    else
      SetTextColor(hdc, kClrDim);
    return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
  }
  if (m == WM_DRAWITEM)
  {
    auto *dis = reinterpret_cast<DRAWITEMSTRUCT *>(l);
    if (dis->CtlType != ODT_BUTTON)
      return DefWindowProcW(h, m, w, l);
    bool hov = dis->hwndItem == g_hoverBtn;
    bool prs = (dis->itemState & ODS_SELECTED) != 0;
    HBRUSH br = CreateSolidBrush(prs ? kClrBtnPrs : hov ? kClrBtnHov
                                                        : kClrBtnNorm);
    FillRect(dis->hDC, &dis->rcItem, br);
    DeleteObject(br);
    RECT rc = dis->rcItem;
    --rc.right;
    --rc.bottom;
    HPEN pen = CreatePen(PS_SOLID, 1, hov ? kClrAccent : kClrBorder);
    HPEN oldP = static_cast<HPEN>(SelectObject(dis->hDC, pen));
    MoveToEx(dis->hDC, rc.left, rc.top, nullptr);
    LineTo(dis->hDC, rc.right, rc.top);
    LineTo(dis->hDC, rc.right, rc.bottom);
    LineTo(dis->hDC, rc.left, rc.bottom);
    LineTo(dis->hDC, rc.left, rc.top);
    SelectObject(dis->hDC, oldP);
    DeleteObject(pen);
    if (hov)
    {
      HPEN ap = CreatePen(PS_SOLID, 3, kClrAccent);
      oldP = static_cast<HPEN>(SelectObject(dis->hDC, ap));
      MoveToEx(dis->hDC, rc.left + 2, rc.top, nullptr);
      LineTo(dis->hDC, rc.left + 2, rc.bottom + 1);
      SelectObject(dis->hDC, oldP);
      DeleteObject(ap);
    }
    // "Label|Description" format — bold top line, dim bottom line
    wchar_t text[256];
    GetWindowTextW(dis->hwndItem, text, 256);
    SetBkMode(dis->hDC, TRANSPARENT);
    wchar_t *sep = wcschr(text, L'|');
    if (sep)
    {
      *sep = L'\0';
      const wchar_t *desc = sep + 1;
      int mid = (dis->rcItem.top + dis->rcItem.bottom) / 2;
      RECT rTop = {dis->rcItem.left + SC(18), dis->rcItem.top, dis->rcItem.right - SC(8), mid};
      RECT rBot = {dis->rcItem.left + SC(18), mid, dis->rcItem.right - SC(8), dis->rcItem.bottom};
      if (g_uiFontBold)
        SelectObject(dis->hDC, g_uiFontBold);
      SetTextColor(dis->hDC, kClrText);
      DrawTextW(dis->hDC, text, -1, &rTop, DT_LEFT | DT_BOTTOM | DT_SINGLELINE);
      if (g_uiFont)
        SelectObject(dis->hDC, g_uiFont);
      SetTextColor(dis->hDC, kClrDim);
      DrawTextW(dis->hDC, desc, -1, &rBot, DT_LEFT | DT_TOP | DT_SINGLELINE);
    }
    else
    {
      if (g_uiFont)
        SelectObject(dis->hDC, g_uiFont);
      SetTextColor(dis->hDC, kClrText);
      RECT tr = dis->rcItem;
      tr.left += SC(18);
      DrawTextW(dis->hDC, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    if (dis->itemState & ODS_FOCUS)
    {
      RECT fr = dis->rcItem;
      InflateRect(&fr, -3, -3);
      DrawFocusRect(dis->hDC, &fr);
    }
    return TRUE;
  }
  return DefWindowProcW(h, m, w, l);
}

static void RegisterDlgClass()
{
  HICON hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON));
  WNDCLASSEXW wc = {sizeof(wc)};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(NULL_BRUSH));
  wc.lpszClassName = L"IRDlg";
  wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
  wc.hIcon = hIcon;
  wc.hIconSm = hIcon;
  RegisterClassExW(&wc);
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
  g_stInstall = IsInstalled();
  g_stPatch = IsPatchInMemory();

  HDC tmpDC = GetDC(nullptr);
  g_dpi = GetDeviceCaps(tmpDC, LOGPIXELSY);
  ReleaseDC(nullptr, tmpDC);

  RegisterDlgClass();

  constexpr DWORD kStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
  constexpr DWORD kExStyle = WS_EX_DLGMODALFRAME | WS_EX_TOPMOST;
  RECT wr = {0, 0, SC(kDlgW), SC(kDlgH)};
  AdjustWindowRectEx(&wr, kStyle, FALSE, kExStyle);

  HWND hwnd = CreateWindowExW(
      kExStyle,
      L"IRDlg", L"Instant Replay Patcher",
      kStyle,
      CW_USEDEFAULT, CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top,
      nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);

  BOOL dark = TRUE;
  DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
  g_hwnd = hwnd;

  g_uiFont = CreateFontW(
      -MulDiv(10, g_dpi, 96),
      0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
      CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, nullptr);
  g_uiFontBold = CreateFontW(
      -MulDiv(12, g_dpi, 96),
      0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
      CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, nullptr);

  wchar_t s1[64], s2[64];
  swprintf_s(s1, L"Startup:  %ls", g_stInstall ? L"Installed" : L"Not installed");
  swprintf_s(s2, L"Patch:  %ls", g_stPatch ? L"Active" : L"Inactive");
  g_lblStart = CreateWindowExW(0, L"STATIC", s1, WS_CHILD | WS_VISIBLE | SS_LEFT,
                               SC(kBtnX), SC(21), SC(kBtnW / 2 - 10), SC(22),
                               hwnd, nullptr, nullptr, nullptr);
  g_lblPatch = CreateWindowExW(0, L"STATIC", s2, WS_CHILD | WS_VISIBLE | SS_LEFT,
                               SC(kBtnX + kBtnW / 2 + 10), SC(21), SC(kBtnW / 2 - 10), SC(22),
                               hwnd, nullptr, nullptr, nullptr);
  SendMessageW(g_lblStart, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFontBold), TRUE);
  SendMessageW(g_lblPatch, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFontBold), TRUE);

  int BY = SC(kBtnY0);
  auto Btn = [&](int id, const wchar_t *text)
  {
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                             SC(kBtnX), BY, SC(kBtnW), SC(kBtnH), hwnd,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
    SetWindowLongPtrW(b, GWLP_USERDATA, GetWindowLongPtrW(b, GWLP_WNDPROC));
    SetWindowLongPtrW(b, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(BtnSubclassProc));
    BY += SC(kBtnH) + SC(kBtnGap);
  };

  Btn(ID_BTN_ONCE, L"Apply Now|Patches this session only - resets on reboot");
  Btn(ID_BTN_REMOVE, L"Remove|Ejects patch from memory, startup entry unchanged");
  BY += SC(18);
  Btn(ID_BTN_INSTALL, L"Install|Patches now and auto-applies on every login");
  Btn(ID_BTN_UNINSTALL, L"Uninstall|Removes patch from memory and clears startup entry");

  CenterWindow(hwnd);
  ShowWindow(hwnd, SW_SHOW);
  UpdateWindow(hwnd);

  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0))
  {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  if (g_uiFont)
  {
    DeleteObject(g_uiFont);
    g_uiFont = nullptr;
  }
  if (g_uiFontBold)
  {
    DeleteObject(g_uiFontBold);
    g_uiFontBold = nullptr;
  }
  g_hwnd = g_lblStart = g_lblPatch = nullptr;
}
/* -----------------------------------------------------------------------
 * wWinMain
 * --------------------------------------------------------------------- */
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmd, int)
{
  HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"IRPatcher_Instance");
  if (GetLastError() == ERROR_ALREADY_EXISTS)
  {
    HWND existing = FindWindowW(L"IRDlg", nullptr);
    if (existing) {
      if (IsIconic(existing)) ShowWindow(existing, SW_RESTORE);
      SetForegroundWindow(existing);
    }
    CloseHandle(hMutex);
    return 0;
  }

  if (lpCmd && wcsstr(lpCmd, L"--silent"))
    return RunSilent();

  if (!IsRunningAsAdmin())
  {
    MessageBoxW(g_hwnd,
                L"This application requires administrator privileges.\n"
                L"Right-click IRPatcher.exe and select \"Run as administrator\".",
                L"Administrator Required", MB_OK | MB_ICONERROR);
    return 1;
  }

  EnableDebugPriv();
  ShowDialog();
  return 0;
}
