@echo off
rem Chuẩn bị môi trường lần đầu: tạo .venv và cài thư viện. Trả về 0 nếu sẵn sàng, 1 nếu lỗi.
chcp 65001 >nul
setlocal
set "ROOT=%~dp0..\"
set "VENV=%ROOT%.venv"
set "MARK=%VENV%\.deps-ok"

if exist "%VENV%\Scripts\python.exe" if exist "%MARK%" exit /b 0

echo Đang chuẩn bị lần đầu... (chỉ làm một lần, có thể mất vài phút)

set "PYEXE="
call :try py -3
if not defined PYEXE call :try python
if not defined PYEXE goto :nopython

if exist "%VENV%\Scripts\python.exe" goto :install
%PYEXE% -m venv "%VENV%"
if errorlevel 1 goto :fail
:install
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check -r "%ROOT%requirements.txt"
if errorlevel 1 goto :fail
echo ok> "%MARK%"
echo Đã chuẩn bị xong.
exit /b 0

:try
%* -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if not errorlevel 1 set "PYEXE=%*"
exit /b 0

:nopython
echo.
echo Máy chưa có Python 3.11 trở lên nên chưa chạy được.
echo Trang tải Python sẽ được mở. Hãy cài đặt, nhớ tích "Add python.exe to PATH", rồi nhấp đúp lại file này.
start "" "https://www.python.org/downloads/"
exit /b 1

:fail
echo.
echo Chuẩn bị môi trường không thành công. Hãy kiểm tra kết nối mạng rồi nhấp đúp lại file này.
exit /b 1