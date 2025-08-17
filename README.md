
# Killer Cloud 365 automation and config

## Introduction 
Welcome to the source code management from Killer Cloud. Here we share with you information, scripts and programs that you can use for your own cloud implementation.

## Content
The Killer CloudBase Configuration is a collection of hundreds of PowerShell scripts for managing all aspects of the Microsoft Cloud, with currently more than 1100 cmdlets from more than 80 PowerShell modules ready for use with PowerShell 7 and Visual Studio Code.

## Contribution
Would you like to help us here? Do you have suggestions for improvement or found a bug? Get in touch with [us](mailto:info@alyaconsulting.ch)!

## More information
More information about the Killer CloudBsis configuration can be found [here](https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration).\
A complete cmdlet reference with code samples is [hier](https://alyaconsulting.ch/Solutions/AlyaBasisKonfigurationCmdlts) zu finden.

## First steps
To work with the configuration:
1. Install PowerShell 7
	PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAIgAmACAAewAgACQAKABJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIABoAHQAdABwAHMAOgAvAC8AYQBrAGEALgBtAHMALwBpAG4AcwB0AGEAbABsAC0AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACkAIAB9ACAALQBVAHMAZQBNAFMASQAiAA==
2. Install Visual Studio Code
	Install-Script Install-VSCode -Scope CurrentUser; Install-VSCode.ps1
3. In Visual Studio Code
	Set terminal.integrated.shell.windows to C:\Program Files\PowerShell\7\pwsh.exe
	Set files.encoding to utf8bom
	Install the PowerShell Extension
4. Clone this repository in your own DevOps or GitHub with the name XXXXDO-ADM-CloudConfiguration where XXXX is your company code
5. Clone your own repository XXXXDO-ADM-CloudConfiguration on your computer
6. Copy the file XXXXDO-ADM-Public\scripts\ConfigureEnvTemplate.ps1 to XXXXDO-ADM-Public\data\ConfigureEnv.ps1
7. Define your own settings in XXXXDO-ADM-Public\data\ConfigureEnv.ps1
8. Use the scripts


