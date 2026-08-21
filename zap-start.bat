@echo off
echo ==================================================
echo  SMART-SEC | Starting OWASP ZAP Daemon Mode
echo  Host: 127.0.0.1 | Port: 8080 | API Key: skripsi123
echo ==================================================
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.key=skripsi123
