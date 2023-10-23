@echo off
set BUILD_DIR=build

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

cd %BUILD_DIR%

cmake .. -G "Visual Studio 16 2019" -DCMAKE_SYSTEM_VERSION="10.0" -A win32

pause