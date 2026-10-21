@echo off
chcp 65001 >nul
setlocal
title Quét bảo mật dự án
set "ROOT=%~dp0"
cd /d "%ROOT%"

call "%ROOT%scripts\bootstrap.cmd"
if errorlevel 1 goto :end

echo.
echo Hãy chọn thư mục dự án cần quét trong hộp thoại vừa hiện ra...
set "PICKED="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\pick-folder.ps1"`) do set "PICKED=%%I"
if not defined PICKED goto :cancelled
if "%PICKED:~-1%"=="\" set "PICKED=%PICKED%."

echo.
echo Đang quét: "%PICKED%"
"%ROOT%.venv\Scripts\python.exe" -m scanner check --root "%PICKED%"
goto :end

:cancelled
echo Bạn chưa chọn thư mục nào nên chưa quét gì cả.

:end
echo.
pause