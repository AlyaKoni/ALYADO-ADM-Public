#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author     Description
    ---------- -------------------- ----------------------------
    25.03.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]

Param  
(
)

#Exporting dynamic module
New-Module -Script {

    #Reading configuration
    . $PSScriptRoot\..\01_ConfigureEnv.ps1

    #Starting Transscript
    Start-Transcript -Path "$($AlyaLogs)\scripts\Configure-Log4Net-$($AlyaTimeString).log" | Out-Null

    # Getting log4net if not already present
    Install-PackageIfNotInstalled "log4net"
    Add-Type -Path "$($AlyaTools)\Packages\log4net\lib\net45\log4net.dll"

    # Functions
    function Reset-LogConfiguration
    {
        [log4net.LogManager]::ResetConfiguration()
    }

    function Configure-FileAppender
    {
        [CmdletBinding()]
        Param  
        (
            [Parameter(Mandatory=$true)]
            [string]$logFile,
            [Parameter(Mandatory=$false)]
            [string]$logPattern = "[%date{yyyy-MM-dd HH:mm:ss.fff} (%utcdate{yyyy-MM-dd HH:mm:ss.fff})] [%level] [%message]%n",
            [Parameter(Mandatory=$false)]
            [ValidateSet("All","Alert","Critical","Debug","Error","Fatal","Info","Trace","Verbose","Warn")] 
            [string]$logThreshold = "All"
        )
        $FileApndr = New-Object log4net.Appender.FileAppender(([log4net.Layout.ILayout](New-Object log4net.Layout.PatternLayout($logPattern)),$logFile,$true))
        $FileApndr.Threshold = [log4net.Core.Level]::$logThreshold
        [log4net.Config.BasicConfigurator]::Configure($FileApndr)
    }

    function Configure-ConsoleAppender
    {
        [CmdletBinding()]
        Param  
        (
            [Parameter(Mandatory=$false)]
            [string]$logPattern = "[%date{yyyy-MM-dd HH:mm:ss.fff}] [%level] [%message]%n",
            [Parameter(Mandatory=$false)]
            [ValidateSet("All","Alert","Critical","Debug","Error","Fatal","Info","Trace","Verbose","Warn")] 
            [string]$logThreshold = "All"
        )
        $debugColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::$debugColor
        if (-Not $debugColorlog4net) { $debugColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::White }
        $informationColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::$informationColor
        if (-Not $informationColorlog4net) { $informationColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::Cyan }
        $warningColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::$warningColor
        if (-Not $warningColorlog4net) { $warningColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::Yellow }
        $errorColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::$errorColor
        if (-Not $errorColorlog4net) { $errorColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::Red }
        $bckgrndColorlog4net = [log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColor
        $ColConsApndr = new-object log4net.Appender.ColoredConsoleAppender(([log4net.Layout.ILayout](new-object log4net.Layout.PatternLayout($logPattern))));
        $ColConsApndrDebugCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors
        $ColConsApndrDebugCollorScheme.Level=[log4net.Core.Level]::Debug
        $ColConsApndrDebugCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::$debugColorlog4net)
        if ($bckgrndColorlog4net) { $ColConsApndrDebugCollorScheme.BackColor=[log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColorlog4net }
        $ColConsApndr.AddMapping($ColConsApndrDebugCollorScheme)
        $ColConsApndrInfoCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors
        $ColConsApndrInfoCollorScheme.level=[log4net.Core.Level]::Info
        $ColConsApndrInfoCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::$informationColorlog4net)
        if ($bckgrndColorlog4net) { $ColConsApndrInfoCollorScheme.BackColor=[log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColorlog4net }
        $ColConsApndr.AddMapping($ColConsApndrInfoCollorScheme)
        $ColConsApndrWarnCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors
        $ColConsApndrWarnCollorScheme.level=[log4net.Core.Level]::Warn
        $ColConsApndrWarnCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::$warningColorlog4net)
        if ($bckgrndColorlog4net) { $ColConsApndrWarnCollorScheme.BackColor=[log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColorlog4net }
        $ColConsApndr.AddMapping($ColConsApndrWarnCollorScheme)
        $ColConsApndrErrorCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors
        $ColConsApndrErrorCollorScheme.level=[log4net.Core.Level]::Error
        $ColConsApndrErrorCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::$errorColorlog4net)
        if ($bckgrndColorlog4net) { $ColConsApndrErrorCollorScheme.BackColor=[log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColorlog4net }
        $ColConsApndr.AddMapping($ColConsApndrErrorCollorScheme)
        $ColConsApndrFatalCollorScheme=new-object log4net.Appender.ColoredConsoleAppender+LevelColors
        $ColConsApndrFatalCollorScheme.level=[log4net.Core.Level]::Fatal
        $ColConsApndrFatalCollorScheme.ForeColor=([log4net.Appender.ColoredConsoleAppender+Colors]::HighIntensity -bxor [log4net.Appender.ColoredConsoleAppender+Colors]::$errorColorlog4net)
        if ($bckgrndColorlog4net) { $ColConsApndrFatalCollorScheme.BackColor=[log4net.Appender.ColoredConsoleAppender+Colors]::$bckgrndColorlog4net }
        $ColConsApndr.AddMapping($ColConsApndrFatalCollorScheme)
        $ColConsApndr.ActivateOptions()
        $ColConsApndr.Threshold = [log4net.Core.Level]::$logThreshold
        [log4net.Config.BasicConfigurator]::Configure($ColConsApndr)
    }

    function Get-Logger
    {
        [CmdletBinding()]
        Param  
        (
            [Parameter(Mandatory=$false)]
            [string]$loggerName = "root"
        )
        $Log = [log4net.LogManager]::GetLogger($loggerName)
        return $Log
    }

    # Exports
    Export-ModuleMember -Function Reset-LogConfiguration | Out-Null
    Export-ModuleMember -Function Configure-FileAppender | Out-Null
    Export-ModuleMember -Function Configure-ConsoleAppender | Out-Null
    Export-ModuleMember -Function Get-Logger | Out-Null
    
    #Stopping Transscript
    Stop-Transcript

} | Out-Null

Reset-LogConfiguration
Configure-ConsoleAppender
$Log = Get-Logger
$Log.Info("Logger is configured, use it with `$Log = Get-Logger")
