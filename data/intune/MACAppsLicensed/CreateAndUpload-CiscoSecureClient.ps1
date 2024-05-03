#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    THIS FILE IS **NOT** PART OF THE ALYA BASE CONFIGURATION!	
    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    DIESE DATEI IST **NICHT** BESTANDTEIL DER ALYA BASIS KONFIGURATION!
    Dieses unveröffentlichte Material ist Eigentum von Alya Consulting.
    Alle Rechte vorbehalten. Die beschriebenen Methoden und Techniken
    werden hierin als Geschäftsgeheimnisse und/oder vertraulich betrachtet. 
    Die Reproduktion oder Verteilung, ganz oder teilweise, ist 
    verboten, ausser mit ausdrücklicher schriftlicher Genehmigung von Alya Consulting.


#>

. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

& "$($AlyaScripts)\intune\Create-IntuneMACPackages.ps1" -AppsPath "MACAppsLicensed" -CreateOnlyAppWithName "CiscoSecureClient"
& "$($AlyaScripts)\intune\Upload-IntuneMACPackages.ps1" -AppsPath "MACAppsLicensed" -UploadOnlyAppWithName "CiscoSecureClient"
& "$($AlyaScripts)\intune\Configure-IntuneMACPackages.ps1" -AppsPath "MACAppsLicensed" -ConfigureOnlyAppWithName "CiscoSecureClient"
