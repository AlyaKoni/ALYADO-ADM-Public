#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


#>

<#
FROM: https://www.alkanesolutions.co.uk/2021/01/16/launch-microsoft-teams-minimised-in-the-system-tray/
#>

$ErrorActionPreference = "Stop"

Try {

    #Open in the background
    $openAsHidden=$true

    #Open after login
    $openAtLogin=$true

    #Keep running in background when we 'close' teams
    $runningOnClose=$true

    $jsonFile = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft', 'Teams', 'desktop-config.json')
      
    if (Test-Path -Path $jsonFile) {   
    
        #Get Teams Configuration
        $jsonContent = Get-Content -Path $jsonFile -Raw
   
        #Convert file content from JSON format to PowerShell object
        $jsonObject = ConvertFrom-Json -InputObject $jsonContent
   
        #Update Object settings
        
        if ([bool]($jsonObject.appPreferenceSettings -match "OpenAsHidden")) {
            $jsonObject.appPreferenceSettings.OpenAsHidden = $openAsHidden
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name OpenAsHidden -Value $openAsHidden -MemberType NoteProperty
        }
    
        if ([bool]($jsonObject.appPreferenceSettings -match "OpenAtLogin")) {
            $jsonObject.appPreferenceSettings.OpenAtLogin = $openAtLogin
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name OpenAtLogin -Value $openAtLogin -MemberType NoteProperty
        }
                
        if ([bool]($jsonObject.appPreferenceSettings -match "RunningOnClose")) {
            $jsonObject.appPreferenceSettings.RunningOnClose = $runningOnClose
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name RunningOnClose -Value $runningOnClose -MemberType NoteProperty
        }
           
        #Terminate Teams if it is running
        $teamsProcess = Get-Process Teams -ErrorAction SilentlyContinue
	    If ($teamsProcess) {

			    #Close Teams Window
  			    $teamsProcess.CloseMainWindow() | Out-Null
			    Sleep 5
		
           	    #Close Teams 
			    Stop-Process -Name "Teams" -Force -ErrorAction SilentlyContinue

	    }

        #Update configuration
        $jsonObject | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonFile -Force
         
        #Define Teams Update.exe paths      
        $userTeams = [System.IO.Path]::Combine("$env:LOCALAPPDATA", "Microsoft", "Teams", "current", "Teams.exe")
        $machineTeamsX86 = [System.IO.Path]::Combine("$env:PROGRAMFILES (X86)", "Microsoft", "Teams", "current", "Teams.exe")
        $machineTeamsX64 = [System.IO.Path]::Combine("$env:PROGRAMFILES", "Microsoft", "Teams", "current", "Teams.exe")
        
        #Define arguments
        $args = @("-process-start-args","""--system-initiated""")

        #Launch Teams
        if (Test-Path -Path $userTeams) {
            Start-Process -FilePath $userTeams -ArgumentList $args
        } elseif (Test-Path -Path $machineTeamsX86) {
            Start-Process -FilePath $machineTeamsX86 -ArgumentList $args
        } elseif (Test-Path -Path $machineTeamsX64) {
            Start-Process -FilePath $machineTeamsX64 -ArgumentList $args
        }

    }

} catch {
    Write-Error $_.Exception
    throw
}
