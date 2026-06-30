@echo off
echo Killing all Python processes...
taskkill /F /IM python.exe 2>nul
timeout /t 3 /nobreak >nul

echo Checking for leftover processes...
netstat -ano | findstr ":8080" | findstr LISTENING
if %errorlevel% == 0 (
    echo Port 8080 still in use, killing by PID...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080" ^| findstr LISTENING') do (
        taskkill /F /PID %%a 2>nul
    )
    timeout /t 2 /nobreak >nul
)

echo Starting TempMail Dashboard...
cd /d %~dp0
python tempmail_dashboard.py
