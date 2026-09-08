@echo off
echo ==================================================
echo  SMART-SEC ^| Starting OWASP ZAP Daemon Mode
echo  Host: 127.0.0.1 ^| Port: 8080 ^| API Key: skripsi123
echo ==================================================

rem zap.bat resolves its own jar file relative to the current directory,
rem so we must cd into ZAP's own install folder before calling it --
rem otherwise it fails with "Unable to access jarfile zap-x.y.z.jar"
rem when invoked from anywhere else (e.g. via PATH from the project root).
set "ZAP_BAT_DIR="
for /f "delims=" %%i in ('where zap.bat 2^>nul') do if not defined ZAP_BAT_DIR set "ZAP_BAT_DIR=%%~dpi"

if not defined ZAP_BAT_DIR (
    echo ERROR: zap.bat tidak ditemukan di PATH.
    echo Tambahkan folder instalasi ZAP ^(mis. "C:\Program Files\ZAP\Zed Attack Proxy"^) ke PATH terlebih dahulu.
    exit /b 1
)

pushd "%ZAP_BAT_DIR%"
call zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.key=skripsi123
popd
