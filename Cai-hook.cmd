@echo off
chcp 65001 >nul
setlocal
title Cài kiểm tra trước khi push
set "ROOT=%~dp0"
pushd "%ROOT%"

call "%ROOT%scripts\bootstrap.cmd"
if errorlevel 1 goto :end

echo.
echo Hãy chọn thư mục dự án (đã có git) trong hộp thoại vừa hiện ra...
set "PICKED="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\pick-folder.ps1" ^|^| echo __PICKFAIL__`) do set "PICKED=%%I"
if "%PICKED%"=="__PICKFAIL__" goto :pickfail
if not defined PICKED goto :cancelled
if "%PICKED:~-1%"=="\" set "PICKED=%PICKED%."

set "ACTION=install"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; $r = [System.Windows.Forms.MessageBox]::Show('Có: CÀI kiểm tra trước khi push.' + [Environment]::NewLine + 'Không: GỠ kiểm tra đã cài.' + [Environment]::NewLine + 'Hủy: không làm gì.', 'Kiểm tra trước khi push', 'YesNoCancel', 'Question'); if ($r -eq 'Yes') { exit 0 } elseif ($r -eq 'No') { exit 1 } else { exit 2 }"
if errorlevel 2 goto :cancelled2
if errorlevel 1 set "ACTION=uninstall"

echo.
echo Dự án: "%PICKED%"
"%ROOT%.venv\Scripts\python.exe" -m scanner hook %ACTION% --root "%PICKED%"
goto :end

:pickfail
echo Không mở được hộp thoại chọn thư mục.
goto :end

:cancelled2
echo Bạn đã huỷ nên chưa thay đổi gì.
goto :end

:cancelled
echo Bạn chưa chọn thư mục nào nên chưa thay đổi gì.

:end
echo.
pause
popd
