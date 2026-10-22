@echo off
chcp 65001 >nul
setlocal
title Kiểm tra repo lạ trước khi tải
set "ROOT=%~dp0"
pushd "%ROOT%"

call "%ROOT%scripts\bootstrap.cmd"
if errorlevel 1 goto :end

rem Link repo là chữ do người dùng dán (có thể độc hại): KHÔNG bao giờ đưa vào dòng lệnh cmd.
rem ask-repo.ps1 ghi link vào file tạm, python đọc file đó (vet --source-file).
set "LINKFILE=%TEMP%\kiem-tra-repo-%RANDOM%%RANDOM%.txt"
if exist "%LINKFILE%" del "%LINKFILE%"

echo.
echo Hãy dán link repo cần kiểm tra vào hộp thoại vừa hiện ra...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\ask-repo.ps1" -OutFile "%LINKFILE%"
if errorlevel 1 goto :askfail
if not exist "%LINKFILE%" goto :cancelled

echo.
echo Đang kiểm tra repo trong môi trường cô lập, có thể mất vài phút...
"%ROOT%.venv\Scripts\python.exe" -m scanner vet --source-file "%LINKFILE%"
goto :end

:askfail
echo Không mở được hộp thoại nhập link.
goto :end

:cancelled
echo Bạn chưa nhập link nào nên chưa kiểm tra gì cả.

:end
if defined LINKFILE if exist "%LINKFILE%" del "%LINKFILE%"
echo.
pause
popd