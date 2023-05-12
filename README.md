[Deutsch](#Einleitung)
[English](#Introduction)

# Einleitung 
Willkommen auf der öffentlichen Source Code Verwaltung von Alya Consulting. In diesem Bereich teilen wir mit Euch Informationen, Skripte und Programme, die Ihr für Eure eigene Cloud Implementierung verwenden könnt.

# Inhalt
Die Alya Basis Konfiguration ist eine Sammlung hunderter PowerShell-Skripte zur Verwaltung aller Aspekte der Microsoft Cloud mit aktuell mehr als 1100 Cmdlets aus mehr als 80 PowerShell-Modulen, die für die Verwendung mit PowerShell 7 und Visual Studio Code bereit sind.

# Mithelfen
Möchtest Du uns hier mithelfen? Hast Du Verbesserungsvorschläge oder einen Fehler gefunden? Melde Dich bei [uns](mailto:info@alyaconsulting.ch)!

# Mehr Informationen
Mehr Informationen über die Alya Bsis Konfiguration findest Du [hier](https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration).
Eine komplette Cmdlet Referenz mit Code Besipielen ist [hier](https://alyaconsulting.ch/Solutions/AlyaBasisKonfigurationCmdlts) zu finden.

# Erste Schritte
Um mit der Konfiguration zu arbeiten:
1. Installiere PowerShell 7
	PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAIgAmACAAewAgACQAKABJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIABoAHQAdABwAHMAOgAvAC8AYQBrAGEALgBtAHMALwBpAG4AcwB0AGEAbABsAC0AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACkAIAB9ACAALQBVAHMAZQBNAFMASQAiAA==
2. Installiere Visual Studio Code
	Install-Script Install-VSCode -Scope CurrentUser; Install-VSCode.ps1
3. In Visual Studio Code
	Setze terminal.integrated.shell.windows auf C:\Program Files\PowerShell\7\pwsh.exe
	Installiere die PowerShell Extension
4. Klone dieses Repository in Deinem eigenen DevOps oder GitHub mit dem Namen XXXXDO-ADM-CloudKonfiguration wobei XXXX Dein Firmenkürzel ist
5. Klone Dein eigenes Repository XXXXDO-ADM-CloudKonfiguration auf Deinen Rechner
6. Kopiere die Datei XXXXDO-ADM-Public\scripts\ConfigureEnvTemplate.ps1 nach  XXXXDO-ADM-Public\data\ConfigureEnv.ps1
7. Definiere in XXXXDO-ADM-Public\data\ConfigureEnv.ps1 Deine eigenen Einstellungen
8. Nutze die Skripte

# Introduction 
Welcome to the public source code management of Alya Consulting. Here we share with you information, scripts and programs that you can use for your own cloud implementation.

# Content
The Alya Base Configuration is a collection of hundreds of PowerShell scripts for managing all aspects of the Microsoft Cloud, with currently more than 1100 cmdlets from more than 80 PowerShell modules ready for use with PowerShell 7 and Visual Studio Code.

# Contribution
Would you like to help us here? Do you have suggestions for improvement or found a bug? Get in touch with [us](mailto:info@alyaconsulting.ch)!

# More information
More information about the Alya Bsis configuration can be found [here](https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration).
A complete cmdlet reference with code samples is [hier](https://alyaconsulting.ch/Solutions/AlyaBasisKonfigurationCmdlts) zu finden.

# First steps
To work with the configuration:
1. Install PowerShell 7
	PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAIgAmACAAewAgACQAKABJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIABoAHQAdABwAHMAOgAvAC8AYQBrAGEALgBtAHMALwBpAG4AcwB0AGEAbABsAC0AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACkAIAB9ACAALQBVAHMAZQBNAFMASQAiAA==
2. Install Visual Studio Code
	Install-Script Install-VSCode -Scope CurrentUser; Install-VSCode.ps1
3. In Visual Studio Code
	Set terminal.integrated.shell.windows to C:\Program Files\PowerShell\7\pwsh.exe
	Install the PowerShell Extension
4. Clone this repository in your own DevOps or GitHub with the name XXXXDO-ADM-CloudConfiguration where XXXX is your company code
5. Clone your own repository XXXXDO-ADM-CloudConfiguration on your computer
6. Copy the file XXXXDO-ADM-Public\scripts\ConfigureEnvTemplate.ps1 to XXXXDO-ADM-Public\data\ConfigureEnv.ps1
7. Define your own settings in XXXXDO-ADM-Public\data\ConfigureEnv.ps1
8. Use the scripts
