@echo off
chcp 65001 >nul 2>&1
title C2 Remote Control Console - WebShell Demo

cd /d "%~dp0"

set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo.
echo ==================================================
echo   C2 Remote Control Server (Windows Host)
echo ==================================================
echo.

set "PYTHON_CMD="

py -3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=py -3"
    goto :found
)

python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python"
    goto :found
)

python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python3"
    goto :found
)

echo [!] Python 3 not found. Please install Python 3.8+ and add it to PATH.
echo     Download: https://www.python.org/downloads/
pause
exit /b 1

:found
echo [*] Python: %PYTHON_CMD%
%PYTHON_CMD% --version
echo [*] Working dir: %CD%
echo [*] Listening port: 4444 (all interfaces)
echo.
echo [*] Make sure Windows Firewall allows TCP 4444
echo     Run as Admin: netsh advfirewall firewall add rule name="C2-4444" dir=in action=allow protocol=TCP localport=4444
echo.
echo ==================================================
echo   Starting C2 console...
echo ==================================================
echo.

%PYTHON_CMD% c2_console.py

echo.
echo [*] C2 console exited.
pause
