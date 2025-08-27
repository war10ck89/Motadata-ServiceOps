@echo off
setlocal EnableExtensions
title Python 3.13 Silent Install (script folder base, robust detection)

REM ===== Base = folder where THIS .bat resides =====
set "BASEDIR=%~dp0"
if not "%BASEDIR:~-1%"=="\" set "BASEDIR=%BASEDIR%\"

echo.
echo ==== Python Silent Installer ^& PIP Bootstrap ====
echo   Base (script folder): "%BASEDIR%"
echo.

REM ===== Locate installer in script folder (prefer fixed name, else first python-*.exe) =====
set "INSTALLER="
if exist "%BASEDIR%python-installer.exe" set "INSTALLER=%BASEDIR%python-installer.exe"

if not defined INSTALLER (
  >"%TEMP%\_pyinst.lst" 2>nul dir /b /a:-d "%BASEDIR%python-3*.exe" "%BASEDIR%python*.exe"
  if exist "%TEMP%\_pyinst.lst" (
    set /p _rel=<"%TEMP%\_pyinst.lst"
    del "%TEMP%\_pyinst.lst" >nul 2>&1
    if defined _rel set "INSTALLER=%BASEDIR%%_rel%"
  )
)

if not defined INSTALLER (
  echo [ERROR] No Python installer EXE found in "%BASEDIR%".
  echo         Put e.g. "python-3.13.7-amd64.exe" here or rename it to "python-installer.exe".
  exit /b 1
)
echo   Installer: "%INSTALLER%"

REM ===== Require admin for All Users install to Program Files (matches your UI) =====
net session >nul 2>&1 && (set "ALLUSERS=1") || (set "ALLUSERS=0")
if "%ALLUSERS%"=="0" (
  echo [ERROR] This preset installs for ALL users into "C:\Program Files\Python313\".
  echo         Right-click CMD ^> Run as administrator, then re-run this script.
  exit /b 2
)

set "TARGETDIR=C:\Program Files\Python313\"
echo   TargetDir: "%TARGETDIR%"

REM ===== Build installer args to mirror your screenshots =====
REM Docs: official "Installing without UI" properties
set "ARGS=/quiet"
set "ARGS=%ARGS% InstallAllUsers=1"
set "ARGS=%ARGS% TargetDir=""%TARGETDIR%"""
set "ARGS=%ARGS% AssociateFiles=1"
set "ARGS=%ARGS% Shortcuts=1"
set "ARGS=%ARGS% PrependPath=1"
set "ARGS=%ARGS% CompileAll=1"
set "ARGS=%ARGS% Include_doc=0"
set "ARGS=%ARGS% Include_test=0"
set "ARGS=%ARGS% Include_tcltk=0"
set "ARGS=%ARGS% Include_pip=1"
set "ARGS=%ARGS% Include_launcher=1"
set "ARGS=%ARGS% InstallLauncherAllUsers=1"
set "ARGS=%ARGS% Include_symbols=1"
set "ARGS=%ARGS% Include_debug=1"
set "ARGS=%ARGS% Include_freethreaded=1"
set "ARGS=%ARGS% /log ""%BASEDIR%python_install.log"""

echo.
echo ==== Running silent install (see log if any error) ====
start /wait "" "%INSTALLER%" %ARGS%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo [ERROR] Installer failed with code %RC%.
  echo         Log file: "%BASEDIR%python_install.log"
  exit /b %RC%
)
echo   Python installation completed.

REM ===== Resolve the ACTUAL installed Python path (don't assume TargetDir) =====
set "PYEXE="
REM Prefer the launcher (will point to the default 3.x; works for free-threaded too)
py -3 -c "import sys,os;open(r'%TEMP%\_pyexe.txt','w').write(sys.executable)" >nul 2>&1
if exist "%TEMP%\_pyexe.txt" (
  set /p PYEXE=<"%TEMP%\_pyexe.txt"
  del "%TEMP%\_pyexe.txt" >nul 2>&1
)

REM Fallback: look for python.exe on PATH
if not defined PYEXE (
  cmd /c where python > "%TEMP%\_pywhere.txt" 2>nul
  if exist "%TEMP%\_pywhere.txt" (
    set /p PYEXE=<"%TEMP%\_pywhere.txt"
    del "%TEMP%\_pywhere.txt" >nul 2>&1
  )
)

REM Last-resort: try the expected TargetDir anyway
if not defined PYEXE if exist "%TARGETDIR%python.exe" set "PYEXE=%TARGETDIR%python.exe"

if not defined PYEXE (
  echo [ERROR] Could not locate the newly installed Python executable.
  echo         Check "%BASEDIR%python_install.log" and confirm installation.
  exit /b 3
)

echo   Resolved Python: "%PYEXE%"

REM ===== Add to PATH for THIS session =====
for %%D in ("%PYEXE%") do set "PYDIR=%%~dpD"
set "PATH=%PYDIR%;%PYDIR%Scripts;%PATH%"

echo.
echo ==== Verifying python and pip ====
"%PYEXE%" -V
"%PYEXE%" -m pip -V

REM ===== Ensure pip is present and current =====
"%PYEXE%" -m ensurepip --upgrade 1>nul 2>nul
"%PYEXE%" -m pip install --upgrade pip

REM ===== Optional: install packages from packages.txt (same folder as script) =====
set "PKGLIST=%BASEDIR%packages.txt"
echo.
if exist "%PKGLIST%" (
  echo ==== Installing packages from "%PKGLIST%" (prefer wheels) ====
  "%PYEXE%" -m pip install --prefer-binary -r "%PKGLIST%"
  if errorlevel 1 (
    echo [WARN] Some packages failed to install. Review errors above.
  ) else (
    echo   Packages installed successfully.
  )
) else (
  echo [INFO] No packages.txt found; skipping package install.
)

echo.
echo ==== Done. New terminals will inherit the persistent PATH. ====
exit /b 0
