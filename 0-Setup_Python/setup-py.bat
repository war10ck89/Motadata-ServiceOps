@echo off
setlocal EnableExtensions
title Python Silent Install + PIP + Packages

REM === Script folder ===
set "BASEDIR=%~dp0"

echo.
echo ==== Python Silent Installer ^& PIP Bootstrap ====
echo   Script directory: "%BASEDIR%"
echo.

REM === Prefer a fixed name to avoid wildcard parsing issues ===
set "INSTALLER=%BASEDIR%python-installer.exe"

REM If not found, pick the first python-*.exe or Python*.exe in this folder (no FOR loops)
if not exist "%INSTALLER%" (
  >"%TEMP%\_pyinst.lst" 2>nul dir /b /a:-d "%BASEDIR%python-*.exe" "%BASEDIR%Python*.exe"
  if exist "%TEMP%\_pyinst.lst" (
    set /p _rel=<"%TEMP%\_pyinst.lst"
    del "%TEMP%\_pyinst.lst" >nul 2>&1
    if defined _rel set "INSTALLER=%BASEDIR%%_rel%"
  )
)

if not exist "%INSTALLER%" (
  echo [ERROR] No Python installer found here.
  echo         Put the official Python EXE in this folder and EITHER rename it to:
  echo           python-installer.exe
  echo         OR ensure its name matches python-*.exe.
  exit /b 1
)

echo   Using installer: "%INSTALLER%"

REM === Admin check: install for all users if admin, else current user ===
net session >nul 2>&1 && (set "ALLUSERS=1" & echo   Admin detected: All Users install) || (set "ALLUSERS=0" & echo   Non-admin: Current User install)

REM === Silent install; also add PATH persistently ===
set "ARGS=/quiet InstallAllUsers=%ALLUSERS% PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1"
echo.
echo   Running installer silently...
start /wait "" "%INSTALLER%" %ARGS%
if errorlevel 1 (
  echo [ERROR] Python installer failed with code %errorlevel%.
  exit /b %errorlevel%
)
echo   Python installation completed.

REM === Pick a Python runner without FOR/F parsing ===
set "PYRUN="
py -3 -V >nul 2>&1 && set "PYRUN=py -3"
if not defined PYRUN (
  python -V >nul 2>&1 && set "PYRUN=python"
)

if not defined PYRUN (
  echo [WARN] Python not on PATH in this session yet.
  echo       Open a NEW terminal and run this script again if package install is needed now.
  goto :maybe_packages
) else (
  echo   Using Python runner: %PYRUN%
)

REM === Ensure pip exists and is current ===
echo.
echo   Ensuring pip is available and up-to-date...
%PYRUN% -m ensurepip --upgrade >nul 2>&1
%PYRUN% -m pip install --upgrade pip
if errorlevel 1 echo [WARN] pip upgrade reported an issue; continuing.

:maybe_packages
REM === Install packages from packages.txt if present ===
set "PKGLIST=%BASEDIR%packages.txt"
echo.
if exist "%PKGLIST%" (
  echo   Installing packages from "%PKGLIST%"...
  if defined PYRUN (
    %PYRUN% -m pip install -r "%PKGLIST%"
    if errorlevel 1 (
      echo [ERROR] pip encountered errors. Exit code %errorlevel%.
      exit /b %errorlevel%
    )
    echo   Packages installed successfully.
  ) else (
    echo [INFO] Skipping package install because Python isn't on PATH in this session yet.
  )
) else (
  echo   [INFO] No packages.txt found. Skipping package install.
)

echo.
echo ==== All done. Open a NEW terminal to see PATH changes globally. ====
exit /b 0
