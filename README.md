# Einleitung 
Willkommen auf der öffentlichen Source Code Verwaltung der Alya Consulting. In diesem Bereich teilen wir mit Euch Informationen, Skripte und Programme, die Ihr für Eure eigene Cloud Implementierung verwenden könnt.

# Inhalt
Wir sind aktuell noch im Aufbau unserer Cloud Konfiguration. Es wird hier also des öftern Änderungen geben. Schaut einfach von Zeit zu Zeit wieder einmal rein. Aktuell gibt es hier:

# Mithelfen
Möchtest Du uns hier mithelfen? Hast Du Verbesserungsvorschläge oder einen Fehler gefunden? Melde Dich bei [uns](mailto:info@alyaconsulting.ch)!

# Erste Schritte
Um mit der Konfiguration zu arbeiten:
0. Klone dieses Repository in Deinem eigenen DevOps mit dem Namen XXXXDO-ADM-CloudKonfiguration wobei XXXX Dein Firmenkürzel ist
1. Erzeuge auf Deinem Rechner ein Verzeichnis XXXXDO-ADM-CloudKonfiguration
2. Kopiere folgende 3 Dateien in das Verzeichnis: 00_SetExecutionPolicy.cmd, 01_ConfigureEnv.ps1, 02_GitClone.ps1
3. Führe als Administrator 00_SetExecutionPolicy.cmd
4. Führe 02_GitClone.ps1 aus
5. Führe 03_StartMenu.ps1 aus und wähle den Menupunkt "ed-Edit Configuration"
