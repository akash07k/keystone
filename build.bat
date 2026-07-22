@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
	echo Error: "uv" was not found on PATH.
	exit /b 1
)

set "specialTarget="
set "cleanRequested="
set "wrapperClean="
set "arguments= %* "
if not "!arguments: clean =!"=="!arguments!" set "cleanRequested=1"
if not "!arguments: clean =!"=="!arguments!" set "wrapperClean=1"
if not "!arguments: -c =!"=="!arguments!" set "cleanRequested=1"
if not "!arguments: --clean =!"=="!arguments!" set "cleanRequested=1"
if not "!arguments: --remove =!"=="!arguments!" set "cleanRequested=1"
if not "!arguments: pot =!"=="!arguments!" set "specialTarget=pot"
if not "!arguments: mergePot =!"=="!arguments!" set "specialTarget=mergePot"
if defined wrapperClean (
	call uv run scons -c
	set "buildResult=!errorlevel!"
	if exist "dist" rmdir /s /q "dist"
	exit /b !buildResult!
)

if defined cleanRequested (
	call uv run scons %*
	set "buildResult=!errorlevel!"
	if exist "dist" rmdir /s /q "dist"
	exit /b !buildResult!
)

if defined specialTarget (
	call uv run scons %*
	exit /b !errorlevel!
)

if exist "dist\*.nvda-addon" del /q "dist\*.nvda-addon" >nul 2>nul
if exist "dist\*.nvda-addon" (
	echo Error: could not remove stale archives from dist.
	exit /b 1
)

call uv run scons %*
set "buildResult=!errorlevel!"
if not "!buildResult!"=="0" exit /b !buildResult!

set /a "archiveCount=0"
set "builtAddon="
for %%F in (dist\*.nvda-addon) do (
	set /a "archiveCount+=1"
	set "builtAddon=%%~nxF"
)

if "!archiveCount!"=="0" (
	echo Error: build completed but produced no .nvda-addon archive.
	exit /b 1
)

if not "!archiveCount!"=="1" (
	echo Error: build produced multiple .nvda-addon archives.
	del /q "dist\*.nvda-addon" >nul 2>nul
	exit /b 1
)

echo Built dist\!builtAddon!
exit /b 0
