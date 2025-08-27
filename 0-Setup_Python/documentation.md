# setup-py.bat — Silent Python Installer + Pip Bootstrap

> This document explains how to use and customize the silent Windows installer batch script.
It installs Python 3.13 with GUI-equivalent options, bootstraps pip, and (optionally) installs packages from packages.txt.

## Overview

* ***Base folder:*** the script uses its own folder (%~dp0) as the working base.
    *  It only looks for files next to the BAT, not the directory you launched from.
*  ***Installer discovery:*** looks for python-installer.exe, else the first python-3*.exe / python*.exe in the script folder.
* Silent install options (GUI-equivalent):
    * Install for all users (admin required)
    * Target: C:\Program Files\Python313\
    * Add Python to PATH (persistent)
    * Associate .py files; create Start Menu shortcuts
    * Include pip, include py launcher for all users
    * Precompile stdlib
    * Docs, test suite, Tk/IDLE disabled
    * Debug symbols, debug binaries, free-threaded binaries enabled
    * Installer log written as python_install.log beside the BAT
* ***Post-install detection:*** resolves the actual Python path via py -3 (or where python) — no hard-coded path assumptions.
* ***Session PATH:*** adds …\Python and …\Python\Scripts to the current CMD session so pip runs immediately.
* ***Optional packages:*** installs from packages.txt if present.

## Folder Layout

Place these files together:
```
setup-py.bat
python-3.13.7-amd64.exe   (or any “python-3*.exe”; you may rename to python-installer.exe)
packages.txt              (optional)
```
## How to Run

1. Open Command Prompt as Administrator (required for All-Users install to Program Files).
2. Execute the script (it uses its own folder as base):
D:\7-CODE\motadata-serviceops\0-Setup_Python> setup-py.bat
3. You should see messages like:
* Python installation completed.
* ***Resolved Python:*** "C:\Program Files\Python313\python.exe" (or the discovered path)
* pip upgrade output and any package installations (if packages.txt exists)
> Open a new terminal afterward to inherit the persistent PATH.

## Installer Switches Used
| Property                  | Value                         | Purpose                                |
| ------------------------- | ----------------------------- | -------------------------------------- |
| `/quiet`                  | —                             | Fully silent install                   |
| `InstallAllUsers`         | `1`                           | Install for all users (admin required) |
| `TargetDir`               | `C:\Program Files\Python313\` | Installation path                      |
| `AssociateFiles`          | `1`                           | Associate `.py` with Python            |
| `Shortcuts`               | `1`                           | Create Start Menu shortcuts            |
| `PrependPath`             | `1`                           | Add Python to the system PATH          |
| `CompileAll`              | `1`                           | Precompile the standard library        |
| `Include_doc`             | `0`                           | Skip docs                              |
| `Include_test`            | `0`                           | Skip test suite                        |
| `Include_tcltk`           | `0`                           | Skip Tk/IDLE                           |
| `Include_pip`             | `1`                           | Install pip                            |
| `Include_launcher`        | `1`                           | Install the `py` launcher              |
| `InstallLauncherAllUsers` | `1`                           | Make launcher available to all users   |
| `Include_symbols`         | `1`                           | Download debugging symbols             |
| `Include_debug`           | `1`                           | Download debug binaries                |
| `Include_freethreaded`    | `1`                           | Install free-threaded binaries (3.13+) |
| `/log`                    | `python_install.log`          | Save installer log beside the BAT      |

> Prefer a lean install? Set Include_symbols=0, Include_debug=0, Include_freethreaded=0.

## packages.txt Templates
### Minimal
* numpy
* pandas
### Robust for CPython 3.13 on Windows (prefer wheels, force PyPI)
--index-url https://pypi.org/simple
--only-binary :all:
--prefer-binary
numpy>=2.3,<3
pandas>=2.3,<2.4

## Troubleshooting
### [ERROR] No Python installer EXE found
* Ensure the installer EXE is in the script’s folder.
* Name it python-installer.exe or any python-3*.exe.
* The script prints the base folder at start: Base (script folder): "…".
### [ERROR] This preset installs for ALL users…
* Run Command Prompt as Administrator and re-run the BAT.
### [ERROR] Could not locate the newly installed Python
* Check python_install.log for MSI errors.
* The script auto-discovers the interpreter via py -3 or where python; re-run if needed.
### Pip: “No matching distribution found”
Typically a mirror index missing a wheel. Put the lines shown in the Robust packages.txt to force PyPI and wheels.
### Download failures (symbols/debug/free-threaded)
* Those options download extra payloads. For a fully offline install:
    1. On an online machine, stage a layout:
    > python-3.13.7-amd64.exe /layout "C:\temp\py313_layout"
    2. Copy that folder next to your BAT and run the BAT (same switches work).
## Verify After Install
Open a new Command Prompt and run:
```
python -V
py -3 -V
pip -V
where python
where pip
```

You should see Python 3.13, pip under C:\Program Files\Python313\Lib\site-packages\pip, and the py launcher available.
## Quick Customization
Install path: edit
set "TARGETDIR=C:\Program Files\Python313\"
Enable IDLE/Tk: set Include_tcltk=1
Skip symbols/debug/FTB: set Include_symbols=0, Include_debug=0, Include_freethreaded=0
Skip persistent PATH: set PrependPath=0
(the script still updates PATH for the current session so pip can run)
Different package list file: change
set "PKGLIST=%BASEDIR%packages.txt"
## Exit Codes
* 1 — Installer EXE not found in the script folder
* 2 — Not running as admin for an All-Users install
* 3 — Python executable not found after install (check python_install.log)
* Other — Return code from the Python installer