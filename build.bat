@echo off
rem Build Loupe with MSVC. Finds Visual Studio through vswhere, so it works
rem from any shell, not only a Developer Command Prompt.
rem
rem   build            release build            build\loupe.exe
rem   build debug      debug build              build\debug\loupe.exe
rem   build asan       AddressSanitizer build   build\asan\loupe.exe
rem   build test       unit tests under ASan    build\test\test_loupe.exe, then runs them
rem   build fuzz       libFuzzer target         build\fuzz\fuzz_loupe.exe
rem   build mutate     mutation fuzzer (ASan)   build\fuzz\mutate.exe
rem   build clean
setlocal enableextensions
cd /d "%~dp0"

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=release"
if /i "%TARGET%"=="clean" goto :clean

where cl >nul 2>nul
if not errorlevel 1 goto :have_cl
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :no_vs
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto :no_vs
for %%d in ("%VSWHERE%") do set "PATH=%PATH%;%%~dpd"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
where cl >nul 2>nul
if errorlevel 1 goto :no_vs
:have_cl

set "LIB_SRC=src\image.c src\mem.c src\out.c src\inspect.c src\pe.c src\elf.c src\term.c"
set "COMMON=/nologo /std:c11 /W4 /WX /Isrc /guard:cf"
set "HARDEN=/guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT"
rem UTF-8 process code page, so non-ASCII paths survive argv and fopen.
set "MANIFEST=/MANIFEST:EMBED /MANIFESTINPUT:res\loupe.manifest"

for %%t in (release debug asan test fuzz mutate) do if /i "%TARGET%"=="%%t" goto :t_%%t
echo build: unknown target "%TARGET%"
exit /b 1

:t_release
if not exist build mkdir build
cl %COMMON% /O2 /Fo:build\ %LIB_SRC% src\main.c /Fe:build\loupe.exe /link %HARDEN% %MANIFEST%
exit /b %errorlevel%

:t_debug
if not exist build\debug mkdir build\debug
cl %COMMON% /Od /Zi /Fo:build\debug\ /Fd:build\debug\ %LIB_SRC% src\main.c /Fe:build\debug\loupe.exe /link /DEBUG %HARDEN% %MANIFEST%
exit /b %errorlevel%

:t_asan
if not exist build\asan mkdir build\asan
cl %COMMON% /Od /Zi /fsanitize=address /Fo:build\asan\ /Fd:build\asan\ %LIB_SRC% src\main.c /Fe:build\asan\loupe.exe /link /DEBUG %MANIFEST%
if errorlevel 1 exit /b 1
call :asan_runtime build\asan
exit /b 0

:t_test
if not exist build\test mkdir build\test
cl %COMMON% /Od /Zi /fsanitize=address /Fo:build\test\ /Fd:build\test\ %LIB_SRC% tests\test_loupe.c /Fe:build\test\test_loupe.exe /link /DEBUG
if errorlevel 1 exit /b 1
call :asan_runtime build\test
build\test\test_loupe.exe
exit /b %errorlevel%

:t_fuzz
if not exist build\fuzz mkdir build\fuzz
cl %COMMON% /Od /Zi /fsanitize=address /fsanitize=fuzzer /Fo:build\fuzz\ /Fd:build\fuzz\ %LIB_SRC% fuzz\fuzz_loupe.c /Fe:build\fuzz\fuzz_loupe.exe /link /DEBUG
if errorlevel 1 exit /b 1
call :asan_runtime build\fuzz
exit /b 0

:t_mutate
if not exist build\fuzz mkdir build\fuzz
cl %COMMON% /O1 /Zi /fsanitize=address /Fo:build\fuzz\ /Fd:build\fuzz\ %LIB_SRC% fuzz\mutate.c /Fe:build\fuzz\mutate.exe /link /DEBUG
if errorlevel 1 exit /b 1
call :asan_runtime build\fuzz
exit /b 0

:clean
if exist build rmdir /s /q build
exit /b 0

:no_vs
echo build: MSVC not found. Install Visual Studio with the "Desktop development with C++" workload.
exit /b 1

rem The ASan runtime is a DLL that ships with MSVC. Copy it next to the exe
rem so the sanitized builds run from any prompt.
:asan_runtime
copy /y "%VCToolsInstallDir%bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll" "%~1\" >nul
exit /b 0
