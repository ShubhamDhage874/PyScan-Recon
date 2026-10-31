@echo off
setlocal

:: 1. Check direct Python39 path in LocalAppData
if exist "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" "%~dp0pyscan.py" %*
    goto end
)

:: 2. Check if python is working in PATH
python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python "%~dp0pyscan.py" %*
    goto end
)

:: 3. Check py launcher
py -3 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py -3 "%~dp0pyscan.py" %*
    goto end
)

echo [!] Python executable was not found. Please install Python 3.8+ or add it to your PATH.
pause

:end
endlocal
