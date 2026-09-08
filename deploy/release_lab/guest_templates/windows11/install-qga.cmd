@echo off
setlocal EnableExtensions
rem The controller attaches a verified virtio-win stable ISO as a second CD.
rem SATA/e1000 remain the Windows install devices; only this signed VirtIO
rem serial driver is added so QEMU Guest Agent can use the private QGA socket.
set "FOUND="
for %%D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if exist "%%D:\guest-agent\qemu-ga-x86_64.msi" if exist "%%D:\vioserial\w11\amd64\*.inf" (
    pnputil.exe /add-driver "%%D:\vioserial\w11\amd64\*.inf" /install
    if errorlevel 1 exit /b 21
    msiexec.exe /i "%%D:\guest-agent\qemu-ga-x86_64.msi" /qn /norestart
    if errorlevel 1 exit /b 22
    sc.exe query qemu-ga >nul 2>&1 || exit /b 23
    sc.exe start qemu-ga >nul 2>&1
    timeout /t 3 /nobreak >nul
    sc.exe query qemu-ga | findstr /i RUNNING >nul || exit /b 24
    set "FOUND=1"
    goto :done
  )
)
:done
if not defined FOUND exit /b 20
exit /b 0
