@echo off
@rem Copyright (c) 2026, Keishin Senzaki. All rights reserved.
@rem SPDX-License-Identifier: BSD-2-Clause-Patent

setlocal EnableExtensions

set "REPO=%~dp0.."
for %%I in ("%REPO%") do set "REPO=%%~fI"
set "EDK2=%REPO%\third_party\edk2"
set "BUILD_TARGET=%~1"
if not defined BUILD_TARGET set "BUILD_TARGET=DEBUG"
if not defined SOURCE_DATE_EPOCH set "SOURCE_DATE_EPOCH=1788220800"
if /i not "%BUILD_TARGET%"=="DEBUG" if /i not "%BUILD_TARGET%"=="RELEASE" (
  echo Usage: Build-Preloader.cmd [DEBUG^|RELEASE]
  exit /b 2
)

if not exist "%EDK2%\edksetup.bat" (
  echo EDK2 is missing. Run tools\Initialize-Repository.ps1 first.
  exit /b 1
)

if exist "%REPO%\.cache\venv\Scripts\python.exe" (
  set "PYTHON_COMMAND=%REPO%\.cache\venv\Scripts\python.exe"
) else (
  echo The Python environment is missing. Run tools\Initialize-Repository.ps1 first.
  exit /b 1
)

if not defined VSWHERE set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Build Tools were not found. Set VSWHERE to vswhere.exe.
  exit /b 1
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL (
  echo Visual C++ build tools were not found.
  exit /b 1
)

rem EDK2 BaseTools are Win32 host utilities even when the firmware target is X64.
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x86
if errorlevel 1 exit /b %errorlevel%

if not defined NASM_PREFIX (
  for /f "usebackq delims=" %%I in (`where nasm.exe 2^>nul`) do if not defined NASM_EXE set "NASM_EXE=%%I"
  if defined NASM_EXE for %%I in ("%NASM_EXE%") do set "NASM_PREFIX=%%~dpI"
)
if not defined NASM_PREFIX if exist "%ProgramFiles%\NASM\nasm.exe" set "NASM_PREFIX=%ProgramFiles%\NASM\"
if not exist "%NASM_PREFIX%nasm.exe" (
  echo NASM was not found. Add it to PATH or set NASM_PREFIX.
  exit /b 1
)
set "PATH=%NASM_PREFIX%;%PATH%"
set "WORKSPACE=%EDK2%"
set "EVB_PACKAGE_ALIASES=%REPO%\.cache\packages"
if not exist "%EVB_PACKAGE_ALIASES%" mkdir "%EVB_PACKAGE_ALIASES%"
if not exist "%EVB_PACKAGE_ALIASES%\DcsPkg" (
  mklink /J "%EVB_PACKAGE_ALIASES%\DcsPkg" "%REPO%\third_party\VeraCrypt-DCS" >nul
  if errorlevel 1 exit /b %errorlevel%
)
if not exist "%REPO%\third_party\VeraCrypt-DCS\Library\VeraCryptLib\common\Crypto.c" (
  call "%REPO%\third_party\VeraCrypt-DCS\Library\VeraCryptLib\mklinks_src.bat" auto "%REPO%\third_party\VeraCrypt\src"
  if errorlevel 1 exit /b %errorlevel%
)
set "PACKAGES_PATH=%REPO%;%EDK2%;%EVB_PACKAGE_ALIASES%"
set "EDK_TOOLS_BIN=%EDK2%\BaseTools\Bin\Win32"

pushd "%EDK2%"
if exist "%EDK2%\BaseTools\Bin\Win32\GenFw.exe" (
  call edksetup.bat
) else (
  call edksetup.bat Rebuild
)
if errorlevel 1 goto :error

call build -a X64 -t VS2022 -b %BUILD_TARGET% -p EvbPkg\EvbPkg.dsc
if errorlevel 1 goto :error

if not exist "%REPO%\artifacts" mkdir "%REPO%\artifacts"
"%EDK_TOOLS_BIN%\GenFw.exe" -z -o "%REPO%\artifacts\EncryptedVhdBoot.efi" "%EDK2%\Build\Evb\%BUILD_TARGET%_VS2022\X64\EvbPreloader.efi"
if errorlevel 1 goto :error

popd
echo Built: %REPO%\artifacts\EncryptedVhdBoot.efi
exit /b 0

:error
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
