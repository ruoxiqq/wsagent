@echo off
REM ============================================================
REM  LLM Brain Launcher for Multi-Agent Defense
REM  Runs on Windows host, serves a local LLM to CentOS defense agents
REM  Mirrors the C2 topology: CentOS calls 192.168.163.1:11434
REM ============================================================
setlocal

set OLLAMA_MODEL=qwen2.5:7b
set OLLAMA_PORT=11434

echo ============================================================
echo  LLM Brain Launcher (Ollama)
echo ============================================================
echo.

REM Check ollama installed
where ollama >nul 2>nul
if errorlevel 1 (
    echo [!] Ollama not found. Install from https://ollama.com first.
    echo     After install, rerun this script.
    pause
    exit /b 1
)

echo [1/4] Configuring Ollama to listen on all interfaces (LAN access)...
REM Bind to 0.0.0.0 so CentOS VM can reach it across the VMware network
set OLLAMA_HOST=0.0.0.0:%OLLAMA_PORT%

echo [2/4] Pulling model %OLLAMA_MODEL% (first run downloads ~4.7GB)...
ollama pull %OLLAMA_MODEL%

echo [3/4] Opening Windows Firewall for TCP %OLLAMA_PORT% (admin required)...
netsh advfirewall firewall show rule name="Ollama-LLM" >nul 2>nul
if errorlevel 1 (
    netsh advfirewall firewall add rule name="Ollama-LLM" dir=in action=allow protocol=TCP localport=%OLLAMA_PORT%
) else (
    echo     Rule "Ollama-LLM" already exists.
)

echo [4/4] Starting Ollama server on 0.0.0.0:%OLLAMA_PORT% ...
echo.
echo  CentOS defense agent will call: http://192.168.163.1:%OLLAMA_PORT%
echo  Keep this window open while the defense system runs.
echo  Press Ctrl+C to stop the LLM brain.
echo ============================================================
echo.

ollama serve
endlocal
