﻿#Requires -Version 2.0
#TODO #Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2020

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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]]$directoriesToAnalyse = @("C:\Users"),
    [string[]]$urlsToDocLibs = @("/sites/example/DocLib1")
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Analyse-Dir4Migration-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"

#Compiling helper
Write-Host "Compiling helper" -ForegroundColor $CommandInfo
$TypeDefinition = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SharePointFileShareMigrationAnalysis
{
    public class Helper
    {
        internal static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        internal static int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        internal const int MAX_PATH = 260;

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILETIME
        {
            internal uint dwLowDateTime;
            internal uint dwHighDateTime;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WIN32_FIND_DATA
        {
            internal FileAttributes dwFileAttributes;
            internal FILETIME ftCreationTime;
            internal FILETIME ftLastAccessTime;
            internal FILETIME ftLastWriteTime;
            internal int nFileSizeHigh;
            internal int nFileSizeLow;
            internal int dwReserved0;
            internal int dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string cFileName;
            // not using this
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            internal string cAlternate;
        }

        [Flags]
        internal enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,
        }

        [Flags]
        internal enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004,
        }

        internal enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5,
        }

        [Flags]
        internal enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFile(string lpFileName, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern bool FindNextFile(IntPtr hFindFile, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindClose(IntPtr hFindFile);

        internal class DirInfo
        {
            public long Size { get; set; }
            public long Files { get; set; }
        }

        internal static long byteToGb = 1024 * 1024 * 1024;
        internal static string[] notAllowedNames = new string[] {
            ".Lock",
            "con",
            "PRN",
            "aux",
            "NUL",
            "_vti_",
            "desktop.ini",
            "COM0",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "lpt0",
            "lpt1",
            "lpt2",
            "lpt3",
            "lpt4",
            "lpt5",
            "lpt6",
            "lpt7",
            "lpt8",
            "lpt9" };

        internal static string GetName(string di)
        {
            while (di.EndsWith("\\")) { di.TrimEnd("\\".ToCharArray()); }
            if (di.IndexOf("\\") == -1) return di;
            return di.Substring(di.LastIndexOf("\\") + 1);
        }

        internal static long GetFileSize(string filePath)
        {
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(filePath, out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                return (long)findData.nFileSizeLow + (long)findData.nFileSizeHigh * 4294967296;
            }
            else
            {
                return 0;
            }
        }

        internal static List<string> GetDirectories(string dirName)
        {
            List<string> results = new List<string>();
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(dirName + @"\*", out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                bool found;
                do
                {
                    string currentFileName = findData.cFileName;
                    if (((int)findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                        currentFileName != "." && currentFileName != "..")
                    {
                        results.Add(Path.Combine(dirName, currentFileName));
                    }
                    found = FindNextFile(findHandle, out findData);
                }
                while (found);
            }
            FindClose(findHandle);
            return results;
        }

        internal static List<string> GetFiles(string dirName)
        {
            List<string> results = new List<string>();
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(dirName + @"\*", out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                bool found;
                do
                {
                    string currentFileName = findData.cFileName;
                    if (((int)findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        results.Add(Path.Combine(dirName, currentFileName));
                    }
                    found = FindNextFile(findHandle, out findData);
                }
                while (found);
            }
            FindClose(findHandle);
            return results;
        }

        internal static DirInfo GetInfo(string root, string di, string path, StreamWriter ffi, StreamWriter cfi, StreamWriter efi, Dictionary<string, DirInfo> typeInfo)
        {
            string name = GetName(di);
            int dirTotLength = di.Length - root.Length + path.Length;
            if (name.IndexOfAny("\\/:*?\"<>|".ToCharArray()) > -1)
                lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "Not allowed character found: \\ / : * ? \" < > |" }); }
            if (name.Trim() != name)
                lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "Not allowed leading or trailing space found" }); }
            if (name.ToCharArray()[0] == '~')
                lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "A name starting with ~ is not allowed" }); }
            foreach (string notAllowedName in notAllowedNames)
            {
                if (name.ToLower() == notAllowedName.ToLower())
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "The name " + notAllowedName + " is not allowed" }); }
            }
            if (root == di && name == "forms")
                lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "A name forms is in root not allowed" }); }
            if (dirTotLength > 400)
                efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "Full folder path can have up to 400 characters" });
            if (name.Length > 255)
                efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "Folder name can have up to 255 characters" });
            List<string> files = GetFiles(di);
            List<string> subDirs = GetDirectories(di);
            long allFilesSize = 0;
            long subDirsSize = 0;
            long subDirsFilesCount = files.Count;
            if ((files.Count + subDirs.Count) > 5000)
                lock (efi) { efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { di, "Dir", "Directory has more than 5000 elements" }); }
            long subDirsDirsCount = subDirs.Count;
            int maxPathLength = dirTotLength;
            Parallel.ForEach(files, new ParallelOptions {
                MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                (fi) =>
            {
                long fileSize = GetFileSize(fi);
                if (fileSize == 0)
                    lock (efi) { efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "Zero length" }); }
                allFilesSize += fileSize;
                string fname = GetName(fi);
                int fileTotLength = dirTotLength + 1 + fname.Length;
                string fext = "";
                if (fname.IndexOf(".") > -1) fext = fname.Substring(fname.LastIndexOf("."));
                lock (typeInfo)
                {
                    if (!typeInfo.ContainsKey(fext)) typeInfo.Add(fext, new DirInfo());
                    typeInfo[fext].Files += 1;
                    typeInfo[fext].Size += fileSize;
                }
                //TODO SpecialCharactersStateInFileFolderNames for # and %
                if (fname.IndexOfAny("\\/:*?\"<>|".ToCharArray()) > -1)
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "Not allowed character found: \\ / : * ? \" < > |" }); }
                if (fname.Trim() != fname)
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "Not allowed leading or trailing space found" }); }
                foreach (string notAllowedName in notAllowedNames)
                {
                    if (fname.ToLower() == notAllowedName.ToLower())
                        lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "The name " + notAllowedName + " is not allowed" }); }
                }
                if (fname.ToCharArray()[0] == '~')
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "A name starting with ~ is not allowed" }); }
                if (fname.ToCharArray()[0] == '$')
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "A name starting with $ is not allowed" }); }
                if (fname.Contains("_vti_"))
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "File name should not contain _vti_" }); }
                if ((fileSize / byteToGb) > 100)
                    lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "Too big. only 100GB allowed" }); }
                if (fileTotLength > 400)
                    lock (efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "Folder name and file name combinations can have up to 400 characters" }); }
                if (fname.Length > 255)
                    efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, "File", "File name can have up to 255 characters" });
                if (fileTotLength > maxPathLength)
                    maxPathLength = fileTotLength;
                lock(ffi){ ffi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { fi, fileSize, fileTotLength }); }
            });
            Parallel.ForEach(subDirs, new ParallelOptions {
                MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                (sdi) =>
            {
                DirInfo subinfo = GetInfo(root, sdi, path, ffi, cfi, efi, typeInfo);
                lock (subDirs)
                {
                    subDirsSize += subinfo.Size;
                    subDirsFilesCount += subinfo.Files;
                }
            });
            lock(cfi){ cfi.WriteLine("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\"", new object[] { di, files.Count, subDirs.Count, allFilesSize, (allFilesSize + subDirsSize), subDirsFilesCount, maxPathLength }); }
            DirInfo info = new DirInfo();
            info.Size = allFilesSize + subDirsSize;
            info.Files = subDirsFilesCount;
            return info;
        }

        public static void Analyse(string[] dirs, string[] urls, string csvLocation)
        {
            try
            {
                using (StreamWriter ffi = new FileInfo(csvLocation+"\\SPShareAnalysis_Files.csv").CreateText())
                {
                    ffi.AutoFlush = true;
                    lock(ffi){ ffi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { "Path", "Size [Bytes]", "PathLength" }); }
                    using (StreamWriter cfi = new FileInfo(csvLocation+"\\SPShareAnalysis_Dirs.csv").CreateText())
                    {
                        cfi.AutoFlush = true;
                        lock(cfi){ cfi.WriteLine("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\"", new object[] { "Path", "#Files", "#Dirs", "Size [Bytes]", "TotalSize [Bytes]", "#FilesTotal", "MaxPathLength" }); }
                        using (StreamWriter efi = new FileInfo(csvLocation+"\\SPShareAnalysis_Errors.csv").CreateText())
                        {
                            efi.AutoFlush = true;
                            lock(efi){ efi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { "Path", "Type", "Error" }); }
                            using (StreamWriter tfi = new FileInfo(csvLocation+"\\SPShareAnalysis_Types.csv").CreateText())
                            {
                                tfi.AutoFlush = true;
                                lock(tfi){ tfi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { "Type", "Count", "Total Size [Bytes]" }); }
                                Dictionary<string, DirInfo> typeInfo = new Dictionary<string, DirInfo>();
                                Parallel.ForEach(dirs, new ParallelOptions {
                                    MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1 }, 
                                    (currentDir) =>
                                {
                                    string currentUrl = urls[Array.IndexOf(dirs, currentDir)];
                                    currentUrl = currentUrl.TrimEnd("/\\".ToCharArray()) + "/";
                                    GetInfo(currentDir, currentDir, currentUrl, ffi, cfi, efi, typeInfo);
                                });
                                foreach (KeyValuePair<string, DirInfo> type in typeInfo)
                                    lock(tfi){ tfi.WriteLine("\"{0}\",\"{1}\",\"{2}\"", new object[] { type.Key, type.Value.Files, type.Value.Size }); }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lock(Console.Error){ Console.Error.WriteLine("An exception happended: " + ex.GetType().ToString()); }
                lock(Console.Error){ Console.Error.WriteLine(ex.Message); }
                lock(Console.Error){ Console.Error.WriteLine(ex.StackTrace); }
            }
        }
        
    }
}
"@

$ReferencedAssemblies = 
@(
    'System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    'Microsoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    'System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    'System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    'System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
)

$addTypeCommand = Get-Command -Name 'Add-Type'
$addTypeCommandInstance = [Activator]::CreateInstance($addTypeCommand.ImplementingType)
$resolveAssemblyMethod = $addTypeCommand.ImplementingType.GetMethod('ResolveReferencedAssembly', [Reflection.BindingFlags]'NonPublic, Instance')
$compilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
$compilerParameters.CompilerOptions = '/debug-'

foreach ($reference in $ReferencedAssemblies)
{
    $resolvedAssembly = $resolveAssemblyMethod.Invoke($addTypeCommandInstance, $reference)
    $tmp = $compilerParameters.ReferencedAssemblies.Add($resolvedAssembly)
}

$compilerParameters.IncludeDebugInformation = $true
Add-Type -TypeDefinition $TypeDefinition -CompilerParameters $compilerParameters

# =============================================================
# LOCAL stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Analyse-Dir4Migration | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if (-Not (Test-Path $AlyaTemp))
{
    $tmp = New-Item -Path $AlyaTemp -ItemType Directory -Force
}

Write-Host "Analysing directories" -ForegroundColor $CommandInfo
[SharePointFileShareMigrationAnalysis.Helper]::Analyse($directoriesToAnalyse, $urlsToDocLibs, $AlyaTemp)

Write-Host "Exporting excel file:" -ForegroundColor $CommandInfo
$outputFile = "$($AlyaData)\sharepoint\FileSystemAnalysis4Migration.xlsx"
Write-Host "$outputFile" -ForegroundColor $CommandInfo
$SPShareAnalysisFiles = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Files.csv"
$SPShareAnalysisDirs = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv"
$SPShareAnalysisErrors = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Errors.csv"
$SPShareAnalysisTypes = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Types.csv"

$excel = $SPShareAnalysisFiles | Export-Excel -Path $outputFile -WorksheetName "Files" -TableName "Files" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet
$excel = $SPShareAnalysisDirs | Export-Excel -Path $outputFile -WorksheetName "Dirs" -TableName "Dirs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet
$excel = $SPShareAnalysisErrors | Export-Excel -Path $outputFile -WorksheetName "Errors" -TableName "Errors" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet
$excel = $SPShareAnalysisTypes | Export-Excel -Path $outputFile -WorksheetName "Types" -TableName "Types" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet

Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Files.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Errors.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Types.csv" -Force

#Stopping Transscript
Stop-Transcript