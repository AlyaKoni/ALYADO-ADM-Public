cd /d %~dp0

msiexec.exe /i MicrosoftEdgeEnterpriseX64.msi TRANSFORMS="MicrosoftEdgeEnterpriseX64.mst" /L*v %temp%\msedgeenterprise_installer.log

pause
