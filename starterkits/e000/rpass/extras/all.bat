@echo off
REM Remove old all.txt if it exists
if exist all.txt del all.txt

REM Copy Cargo.toml into all.txt
type Cargo.toml >> all.txt

REM Add divider
echo. >> all.txt
echo ======================================== >> all.txt
echo ============== main.rs ================= >> all.txt
echo ======================================== >> all.txt
echo. >> all.txt

REM Copy src\main.rs into all.txt
type src\main.rs >> all.txt

echo Done! Contents saved to all.txt
pause
