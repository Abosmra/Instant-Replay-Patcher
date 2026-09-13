#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <objbase.h>
#include <gdiplus.h>
#include <string>
#include "gui.h"
#include "patcher.h"

static constexpr int kDlgW = 360;
static constexpr int kDlgH = 296;

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

static std::wstring g_toastMsg = L"Ready";
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
    SetToast(L"Fix is already active", ToastType::Info);
    return;
  }
  std::wstring dll = ExtractDll();
  if (dll.empty())
  {
    SetToast(L"Failed to prepare patch files", ToastType::Error);
    return;
  }
  if (DoInject(pid, dll.c_str()))
    SetToast(L"Fix applied! Instant Replay is now active", ToastType::Success);
  else
    SetToast(L"Failed to apply fix. Make sure Instant Replay is on", ToastType::Error);
}

static void ActionRemove()
{
  DWORD pid = FindNvContainer();
  if (!pid || !IsPatchInMemory())
  {
    SetToast(L"Fix is not currently active", ToastType::Info);
    return;
  }
  if (DoEject(pid))
    SetToast(L"Fix turned off for this session", ToastType::Success);
  else
    SetToast(L"Failed to turn off the fix", ToastType::Error);
}

static void ActionInstall()
{
  if (IsInstalled())
  {
    SetToast(L"Auto-start is already enabled", ToastType::Info);
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
    SetToast(L"Enabled! Fix will run automatically on startup", ToastType::Success);
  else
    SetToast(L"Failed to enable auto-start", ToastType::Error);
}

static void ActionUninstall()
{
  if (!IsInstalled())
  {
    SetToast(L"Auto-start is not enabled", ToastType::Info);
    return;
  }
  DWORD pid = FindNvContainer();
  if (pid)
    DoEject(pid);
  if (DoUninstallRunKey())
    SetToast(L"Auto-start disabled", ToastType::Success);
  else
    SetToast(L"Failed to disable auto-start", ToastType::Error);
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
  float card1X = 16.0f * s;
  float card1Y = 15.0f * s;
  float card2X = 16.0f * s;
  float card2Y = 127.0f * s;
  float cardW = width - 32.0f * s;
  float btnW = (cardW - 40.0f * s) / 2.0f;
  float btnH = 32.0f * s;

  Gdiplus::RectF btnApply(card1X + 16.0f * s, card1Y + 59.0f * s, btnW, btnH);
  Gdiplus::RectF btnEject(card1X + 24.0f * s + btnW, card1Y + 59.0f * s, btnW, btnH);
  Gdiplus::RectF btnInstall(card2X + 16.0f * s, card2Y + 59.0f * s, btnW, btnH);
  Gdiplus::RectF btnUninstall(card2X + 24.0f * s + btnW, card2Y + 59.0f * s, btnW, btnH);

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
  (void)s;
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

static void DrawToast(
    Gdiplus::Graphics &g,
    const Gdiplus::RectF &rect,
    const std::wstring &msg,
    ToastType type,
    float s,
    Gdiplus::Font &font)
{
  Gdiplus::GraphicsPath path;
  AddRoundedRect(path, rect, 6.0f * s);

  Gdiplus::Color bgClr, borderClr, textClr;
  switch (type)
  {
  case ToastType::Success:
    bgClr = Gdiplus::Color(255, 16, 36, 12);
    borderClr = Gdiplus::Color(255, 35, 75, 20);
    textClr = Gdiplus::Color(255, 118, 185, 0);
    break;
  case ToastType::Warning:
    bgClr = Gdiplus::Color(255, 40, 32, 10);
    borderClr = Gdiplus::Color(255, 85, 65, 15);
    textClr = Gdiplus::Color(255, 245, 180, 40);
    break;
  case ToastType::Error:
    bgClr = Gdiplus::Color(255, 40, 14, 14);
    borderClr = Gdiplus::Color(255, 80, 25, 25);
    textClr = Gdiplus::Color(255, 245, 80, 80);
    break;
  case ToastType::Info:
    bgClr = Gdiplus::Color(255, 14, 28, 45);
    borderClr = Gdiplus::Color(255, 25, 55, 90);
    textClr = Gdiplus::Color(255, 80, 160, 245);
    break;
  default:
    bgClr = Gdiplus::Color(255, 20, 23, 27);
    borderClr = Gdiplus::Color(255, 34, 38, 45);
    textClr = Gdiplus::Color(255, 110, 116, 128);
    break;
  }

  Gdiplus::SolidBrush bgBr(bgClr);
  g.FillPath(&bgBr, &path);

  Gdiplus::Pen pen(borderClr, 1.0f);
  g.DrawPath(&pen, &path);

  Gdiplus::RectF textRect = rect;
  Gdiplus::SolidBrush textBr(textClr);
  Gdiplus::StringFormat sf;
  sf.SetAlignment(Gdiplus::StringAlignmentCenter);
  sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
  g.DrawString(msg.c_str(), -1, &font, textRect, &sf, &textBr);
}

static void RenderDashboard(Gdiplus::Graphics &g, int width, int height, float s)
{
  (void)height;
  Gdiplus::SolidBrush bgBrush(Gdiplus::Color(255, 18, 20, 23));
  g.FillRectangle(&bgBrush, 0, 0, width, height);

  // Smart font detection: Use modern Segoe UI Variable on Win11, fallback to Segoe UI on Win10/older
  static const wchar_t *kMainFont = []() {
    Gdiplus::FontFamily fam(L"Segoe UI Variable Text");
    return (fam.GetLastStatus() == Gdiplus::Ok) ? L"Segoe UI Variable Text" : L"Segoe UI";
  }();

  static const wchar_t *kSmallFont = []() {
    Gdiplus::FontFamily fam(L"Segoe UI Variable Small");
    return (fam.GetLastStatus() == Gdiplus::Ok) ? L"Segoe UI Variable Small" : kMainFont;
  }();

  static const wchar_t *kSemiboldFont = []() {
    Gdiplus::FontFamily fam(L"Segoe UI Variable Text Semibold");
    if (fam.GetLastStatus() == Gdiplus::Ok)
      return L"Segoe UI Variable Text Semibold";
    Gdiplus::FontFamily fam2(L"Segoe UI Semibold");
    if (fam2.GetLastStatus() == Gdiplus::Ok)
      return L"Segoe UI Semibold";
    return L"";
  }();

  Gdiplus::FontFamily fontFam(kMainFont);
  const Gdiplus::FontFamily *pFam = (fontFam.GetLastStatus() == Gdiplus::Ok)
                                      ? &fontFam
                                      : Gdiplus::FontFamily::GenericSansSerif();

  Gdiplus::FontFamily fontFamSmall(kSmallFont);
  const Gdiplus::FontFamily *pFamSmall = (fontFamSmall.GetLastStatus() == Gdiplus::Ok)
                                           ? &fontFamSmall
                                           : pFam;

  Gdiplus::FontFamily fontFamSemi(kSemiboldFont[0] ? kSemiboldFont : kMainFont);
  bool hasSemi = (kSemiboldFont[0] != L'\0' && fontFamSemi.GetLastStatus() == Gdiplus::Ok);
  const Gdiplus::FontFamily *pSemiFam = hasSemi ? &fontFamSemi : pFam;
  INT semiStyle = hasSemi ? Gdiplus::FontStyleRegular : Gdiplus::FontStyleBold;

  // Font sizes matching Windows 11 File Explorer / Fluent Type Ramp:
  // Card Titles: 15px Semibold (Explorer section headers)
  // Card Desc:   12px Regular  (Explorer metadata / secondary text)
  // Pills:       10.5px Bold   (Explorer badges / tag pills)
  // Buttons:     13.5px Semib  (Explorer / WinUI standard action buttons)
  // Toast:       12.5px Regular(Explorer status / info text)
  Gdiplus::Font fontCardTitle(pSemiFam, 15.0f * s, semiStyle, Gdiplus::UnitPixel);
  Gdiplus::Font fontCardDesc(pFam, 12.0f * s, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
  Gdiplus::Font fontPill(pFamSmall, 10.5f * s, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
  Gdiplus::Font fontBtn(pSemiFam, 13.5f * s, semiStyle, Gdiplus::UnitPixel);
  Gdiplus::Font fontToast(pFam, 12.5f * s, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);

  Gdiplus::StringFormat sfNear;
  sfNear.SetAlignment(Gdiplus::StringAlignmentNear);
  sfNear.SetLineAlignment(Gdiplus::StringAlignmentCenter);

  // Card 1
  float card1X = 16.0f * s;
  float card1Y = 15.0f * s;
  float cardW = static_cast<float>(width) - 32.0f * s;
  float cardH = 104.0f * s;

  Gdiplus::GraphicsPath card1Path;
  Gdiplus::RectF card1Rect(card1X, card1Y, cardW, cardH);
  AddRoundedRect(card1Path, card1Rect, 8.0f * s);

  Gdiplus::SolidBrush cardBgBr(Gdiplus::Color(255, 26, 29, 34));
  g.FillPath(&cardBgBr, &card1Path);
  Gdiplus::Pen cardBorderPen(Gdiplus::Color(255, 42, 47, 56), 1.0f);
  g.DrawPath(&cardBorderPen, &card1Path);

  Gdiplus::RectF card1TitleRect(card1X + 16.0f * s, card1Y + 12.0f * s, 240.0f * s, 20.0f * s);
  Gdiplus::SolidBrush cardTitleBr(Gdiplus::Color(255, 240, 242, 245));
  g.DrawString(L"Current Session", -1, &fontCardTitle, card1TitleRect, &sfNear, &cardTitleBr);

  float pillW = 82.0f * s;
  float pillH = 20.0f * s;
  Gdiplus::RectF pill1Rect(card1X + cardW - pillW - 16.0f * s, card1Y + 12.0f * s, pillW, pillH);
  DrawStatusPill(g, pill1Rect, g_stPatch ? L"ACTIVE" : L"INACTIVE", g_stPatch, s, fontPill);

  Gdiplus::RectF card1DescRect(card1X + 16.0f * s, card1Y + 36.0f * s, cardW - 32.0f * s, 16.0f * s);
  Gdiplus::SolidBrush cardDescBr(Gdiplus::Color(255, 138, 145, 158));
  g.DrawString(L"Fixes Instant Replay now. Resets when you restart.", -1, &fontCardDesc, card1DescRect, &sfNear, &cardDescBr);

  float btnW = (cardW - 40.0f * s) / 2.0f;
  float btnH = 32.0f * s;
  Gdiplus::RectF btn1Rect(card1X + 16.0f * s, card1Y + 59.0f * s, btnW, btnH);
  Gdiplus::RectF btn2Rect(card1X + 24.0f * s + btnW, card1Y + 59.0f * s, btnW, btnH);

  bool btn1En = IsButtonEnabled(BtnId::Apply);
  bool btn1Hov = (g_hoverBtn == BtnId::Apply) && btn1En;
  bool btn1Prs = (g_pressedBtn == BtnId::Apply) && btn1En;
  DrawCustomButton(g, btn1Rect, g_stPatch ? L"✓ Active" : L"Enable Fix",
                   btn1En, btn1Hov, btn1Prs, !g_stPatch, s, fontBtn);

  bool btn2En = IsButtonEnabled(BtnId::Eject);
  bool btn2Hov = (g_hoverBtn == BtnId::Eject) && btn2En;
  bool btn2Prs = (g_pressedBtn == BtnId::Eject) && btn2En;
  DrawCustomButton(g, btn2Rect, L"Disable Fix",
                   btn2En, btn2Hov, btn2Prs, false, s, fontBtn);

  // Card 2: Start with Windows
  float card2X = 16.0f * s;
  float card2Y = 127.0f * s;

  Gdiplus::GraphicsPath card2Path;
  Gdiplus::RectF card2Rect(card2X, card2Y, cardW, cardH);
  AddRoundedRect(card2Path, card2Rect, 8.0f * s);
  g.FillPath(&cardBgBr, &card2Path);
  g.DrawPath(&cardBorderPen, &card2Path);

  Gdiplus::RectF card2TitleRect(card2X + 16.0f * s, card2Y + 12.0f * s, 240.0f * s, 20.0f * s);
  g.DrawString(L"Start with Windows", -1, &fontCardTitle, card2TitleRect, &sfNear, &cardTitleBr);

  Gdiplus::RectF pill2Rect(card2X + cardW - pillW - 16.0f * s, card2Y + 12.0f * s, pillW, pillH);
  DrawStatusPill(g, pill2Rect, g_stInstall ? L"ENABLED" : L"DISABLED", g_stInstall, s, fontPill);

  Gdiplus::RectF card2DescRect(card2X + 16.0f * s, card2Y + 36.0f * s, cardW - 32.0f * s, 16.0f * s);
  g.DrawString(L"Fixes Instant Replay automatically on startup.", -1, &fontCardDesc, card2DescRect, &sfNear, &cardDescBr);

  Gdiplus::RectF btn3Rect(card2X + 16.0f * s, card2Y + 59.0f * s, btnW, btnH);
  Gdiplus::RectF btn4Rect(card2X + 24.0f * s + btnW, card2Y + 59.0f * s, btnW, btnH);

  bool btn3En = IsButtonEnabled(BtnId::Install);
  bool btn3Hov = (g_hoverBtn == BtnId::Install) && btn3En;
  bool btn3Prs = (g_pressedBtn == BtnId::Install) && btn3En;
  DrawCustomButton(g, btn3Rect, g_stInstall ? L"✓ Enabled" : L"Enable Auto-Start",
                   btn3En, btn3Hov, btn3Prs, !g_stInstall, s, fontBtn);

  bool btn4En = IsButtonEnabled(BtnId::Uninstall);
  bool btn4Hov = (g_hoverBtn == BtnId::Uninstall) && btn4En;
  bool btn4Prs = (g_pressedBtn == BtnId::Uninstall) && btn4En;
  DrawCustomButton(g, btn4Rect, L"Disable",
                   btn4En, btn4Hov, btn4Prs, false, s, fontBtn);

  // Toast / Bottom Status
  float toastX = 16.0f * s;
  float toastY = 240.0f * s;
  float toastH = 36.0f * s;
  Gdiplus::RectF toastRect(toastX, toastY, cardW, toastH);
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
      float s = g_dpi / 96.0f;
      RenderDashboard(g, width, height, s);
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
        g_toastMsg = L"Ready";
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

void ShowDialog()
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

