@echo off
setlocal EnableExtensions DisableDelayedExpansion
title KotoPizdelka - Windows installer build

rem Keep paths quoted and delayed expansion disabled for spaces, Unicode and !.
pushd "%~dp0"
if errorlevel 1 goto root_failed

echo KotoPizdelka - Windows installer build
echo.
echo This builds an x64 Windows installer from the locked source dependencies.
echo The first build can take several minutes and needs Internet access.
echo Existing Cargo build caches and application profiles are kept.
echo.

if not exist "apps\desktop\package-lock.json" goto source_missing
if not exist "apps\desktop\frontend\package-lock.json" goto source_missing
if not exist "Cargo.lock" goto source_missing

where /q node.exe
if errorlevel 1 goto node_missing
where /q npm.cmd
if errorlevel 1 goto node_missing
where /q cargo.exe
if errorlevel 1 goto rust_missing
where /q rustc.exe
if errorlevel 1 goto rust_missing

node.exe -e "const [major, minor] = process.versions.node.split('.').map(Number); process.exit(major > 22 || (major === 22 && minor >= 12) ? 0 : 1);"
if errorlevel 1 goto node_old
rustc.exe -vV | findstr.exe /x /c:"host: x86_64-pc-windows-msvc" >nul
if errorlevel 1 goto rust_wrong_host

echo Tool versions:
node.exe --version
call npm.cmd --version
cargo.exe --version
rustc.exe --version
echo.

set "BUILD_STEP=installing the desktop tools"
echo [1/3] Installing desktop tools from package-lock.json...
call npm.cmd --prefix apps\desktop ci
if errorlevel 1 goto command_failed

set "BUILD_STEP=installing the interface dependencies"
echo.
echo [2/3] Installing interface dependencies from package-lock.json...
call npm.cmd --prefix apps\desktop\frontend ci
if errorlevel 1 goto command_failed

set "BUILD_STEP=building the Windows application and installer"
echo.
echo [3/3] Building the Windows application and installer...
call npm.cmd --prefix apps\desktop run build -- --target x86_64-pc-windows-msvc -- --locked
if errorlevel 1 goto command_failed

set "INSTALLER_DIR=%CD%\target\x86_64-pc-windows-msvc\release\bundle\nsis"
if not exist "%INSTALLER_DIR%\*.exe" goto installer_missing
echo.
echo SUCCESS. Installer files:
for %%I in ("%INSTALLER_DIR%\*.exe") do echo   "%%~fI"
echo.
echo Run the installer, then open KotoPizdelka from its shortcut.
echo PowerShell, Node.js and a development server are not needed to run it.
start "" explorer.exe "%INSTALLER_DIR%"
set "BUILD_EXIT_CODE=0"
goto finish

:source_missing
echo ERROR: Source files are missing. Extract the full project archive first.
set "BUILD_EXIT_CODE=1"
goto finish

:node_missing
echo ERROR: Node.js and npm were not found in PATH.
echo Install Node.js 24 LTS, then close this window and try again.
set "BUILD_EXIT_CODE=1"
goto finish

:node_old
echo ERROR: The interface needs Node.js 22.12 or newer.
echo Install Node.js 24 LTS, then close this window and try again.
set "BUILD_EXIT_CODE=1"
goto finish

:rust_missing
echo ERROR: Rust was not found in PATH.
echo Install Rust with rustup and the MSVC Windows toolchain.
echo Also install Visual Studio Build Tools: Desktop development with C++.
echo Then close this window and try again.
set "BUILD_EXIT_CODE=1"
goto finish

:rust_wrong_host
echo ERROR: The active Rust toolchain must be x86_64-pc-windows-msvc.
echo This script builds on native x64 Windows with MSVC and the Windows SDK.
echo Check the active toolchain with: rustup show
set "BUILD_EXIT_CODE=1"
goto finish

:command_failed
set "BUILD_EXIT_CODE=%ERRORLEVEL%"
echo.
echo ERROR: Failed while %BUILD_STEP%.
echo The compiler or npm error is printed above. No application data was removed.
goto finish

:installer_missing
echo ERROR: The build finished, but no NSIS installer was found.
echo Expected folder: "%INSTALLER_DIR%"
set "BUILD_EXIT_CODE=1"
goto finish

:finish
echo.
echo Press any key to close this window.
pause >nul
popd
endlocal & exit /b %BUILD_EXIT_CODE%

:root_failed
echo ERROR: Could not open the project folder.
pause
endlocal & exit /b 1
