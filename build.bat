@echo off
:: build.bat — Instant Replay Patcher
:: Run from a Visual Studio x64 Developer Command Prompt (as Administrator).

set DETOURS_DIR=%~dp0Detours
set DETOURS_INC=%DETOURS_DIR%\include
set DETOURS_LIB=%DETOURS_DIR%\lib.X64\detours.lib

if not exist bin mkdir bin

echo === Building hook.dll ===
cl /nologo /LD /O2 /W3 /MT /I"%DETOURS_INC%" src\hook.cpp ^
   /Fo"bin\\" ^
   /link "%DETOURS_LIB%" psapi.lib user32.lib advapi32.lib ^
   /out:bin\hook.dll
if errorlevel 1 ( echo [!] hook.dll FAILED & exit /b 1 )

echo === Embedding hook.dll into resource ===
rc /nologo /fo bin\hook.res res\hook.rc
if errorlevel 1 ( echo [!] rc FAILED & exit /b 1 )

echo === Building IRPatcher.exe ===
cl /nologo /O2 /W3 src\main.cpp bin\hook.res ^
   /Fo"bin\\" ^
   /link advapi32.lib user32.lib gdi32.lib shell32.lib ^
   /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /MANIFEST:NO ^
   /out:bin\IRPatcher.exe
if errorlevel 1 ( echo [!] exe FAILED & exit /b 1 )

echo === Embedding admin manifest ===
mt.exe -nologo -manifest res\app.manifest -outputresource:bin\IRPatcher.exe;1
if errorlevel 1 ( echo [!] manifest FAILED & exit /b 1 )

echo.
echo === Done: bin\IRPatcher.exe ===
