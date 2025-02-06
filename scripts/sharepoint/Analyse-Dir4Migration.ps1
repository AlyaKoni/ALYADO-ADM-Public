#Requires -Version 2.0
#TODO #Requires -RunAsAdministrator

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.10.2020 Konrad Brunner       Initial Version
    02.09.2024 Konrad Brunner       Checking OneDrive sync path

#>

[CmdletBinding()]
Param(
    [string[]]$directoriesToAnalyse = @("C:\Users"),
    [string[]]$urlsToDocLibs = @("sites/XXXXSP-ADM-Daten/Freigegebene Dokumente"),
    [string]$maxOneDriveSyncPath = "C:\Users\maxprename.maxlastname\EntraIdTenantNameInProperties\maxSiteName - maxLibTitle",
    [string]$delemitter = ","
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
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Text;

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
            internal uint nFileSizeHigh;
            internal uint nFileSizeLow;
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

        // Limitations
        internal static long byteToGb = 1024 * 1024 * 1024;
        internal static long fileSizeLimit = 250;
        internal static int fullPathLimit = 400;
        internal static int oneDrivePathLimit = 256;
        internal static int fileFolderNameLimit = 255;
        internal static int numFilesLimit = 300000;
        internal static string notAllowedChars = "\\/:*?\"<>|";
        internal static string notAllowedCharsODL = "~#%&{}\\/:*?\"<>|";
        internal static string notAllowedLeadingAndTrailingChars = " ";
        internal static string notAllowedFileNameStarting = "~$";
        internal static string notAllowedFolderNameInRootDir = "forms";
        internal static string notAllowedInFileNames = "_vti_";
        internal static string[] notAllowedNames = new string[] {
            ".lock",
            "con",
            "prn",
            "aux",
            "nul",
            "_vti_",
            "desktop.ini",
            "com0",
            "com1",
            "com2",
            "com3",
            "com4",
            "com5",
            "com6",
            "com7",
            "com8",
            "com9",
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
                return (long)findData.nFileSizeLow + (long)findData.nFileSizeHigh * ((long)uint.MaxValue+1);
            }
            else
            {
                return -1;
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

        internal static bool IsFolderReadable(string directoryPath)
        {
            FileSystemRights accessType = FileSystemRights.ListDirectory;
            bool hasAccess = true;
            try
            {
                AuthorizationRuleCollection collection = Directory.
                                            GetAccessControl(directoryPath)
                                            .GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
                foreach (FileSystemAccessRule rule in collection)
                {
                    if ((rule.FileSystemRights & accessType) > 0)
                    {
                        return hasAccess;
                    }
                }
            }
            catch (Exception)
            {
                hasAccess = false;
            }
            return hasAccess;
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

        internal static DirInfo GetInfo(string root, string di, string path, int oneDrivePathTotLength, string delemitter, StreamWriter ffi, StreamWriter cfi, StreamWriter efi, Dictionary<string, DirInfo> typeInfo)
        {
            string name = GetName(di);
            if (!IsFolderReadable(di))
            {
                lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "No access" }); }
                DirInfo info = new DirInfo();
                info.Size = 0;
                info.Files = 0;
                return info;
            }
            else
            {
                int dirTotLength = di.Length - root.Length + path.Length;
                int oneDriveDirTotLength = di.Length - root.Length + oneDrivePathTotLength;
                if (name.IndexOfAny(notAllowedChars.ToCharArray()) > -1)
                    lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Not allowed character found: " + notAllowedChars }); }
                if (name.Trim() != name)
                    lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Not allowed leading or trailing space found" }); }
                foreach (string notAllowedName in notAllowedNames)
                {
                    if (name.ToLower() == notAllowedName.ToLower())
                        lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "The name " + notAllowedName + " is not allowed" }); }
                }
                if (root == di && name == notAllowedFolderNameInRootDir)
                    lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "A name forms is in root not allowed" }); }
                if (dirTotLength > fullPathLimit)
                    efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Full folder path can have up to " + fullPathLimit + " characters" });
                if (oneDriveDirTotLength > oneDrivePathLimit)
                    efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "OneDrive client full folder path can have up to " + oneDrivePathLimit + " characters" });
                if (name.Length > fileFolderNameLimit)
                    efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Folder name can have up to " + fileFolderNameLimit + " characters" });
                List<string> files = GetFiles(di);
                List<string> subDirs = GetDirectories(di);
                long allFilesSize = 0;
                long subDirsSize = 0;
                long subDirsFilesCount = files.Count;
                if ((files.Count + subDirs.Count) > 5000)
                    lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Directory has more than 5000 elements (only SharePoint)" }); }
                long subDirsDirsCount = subDirs.Count;
                int maxPathLength = dirTotLength;
                Parallel.ForEach(files, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1
                },
                    (fi) =>
                    {
                        long fileSize = GetFileSize(fi);
                        if (fileSize < 0)
                        {
                            try {
                                FileInfo finf = new FileInfo(fi);
                                fileSize = finf.Length;
                            } catch (Exception) {}
                        }
                        if (fileSize < 0)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Error getting file size" }); }
                        if (fileSize == 0)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Zero length" }); }
                        allFilesSize += fileSize;
                        string fname = GetName(fi);
                        int fileTotLength = dirTotLength + 1 + fname.Length;
                        int oneDriveFileTotLength = oneDriveDirTotLength + 1 + fname.Length;
                        string fext = "";
                        if (fname.IndexOf(".") > -1) fext = fname.Substring(fname.LastIndexOf("."));
                        lock (typeInfo)
                        {
                            if (!typeInfo.ContainsKey(fext)) typeInfo.Add(fext, new DirInfo());
                            typeInfo[fext].Files += 1;
                            typeInfo[fext].Size += fileSize;
                        }
                        //TODO SpecialCharactersStateInFileFolderNames for # and %
                        if (fname.IndexOfAny(notAllowedChars.ToCharArray()) > -1)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Not allowed character found: \\ / : * ? \" < > |" }); }
                        if (fname.Trim() != fname)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Not allowed leading or trailing space found" }); }
                        foreach (string notAllowedName in notAllowedNames)
                        {
                            if (fname.ToLower() == notAllowedName.ToLower())
                                lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "The name " + notAllowedName + " is not allowed" }); }
                        }
                        if (fname.StartsWith(notAllowedFileNameStarting))
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "A name starting with " + notAllowedFileNameStarting + " is not allowed" }); }
                        if (fname.Contains(notAllowedInFileNames))
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "File name should not contain _vti_" }); }
                        if ((fileSize / byteToGb) > fileSizeLimit)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Too big. only " + fileSizeLimit + "GB allowed" }); }
                        if (fileTotLength > fullPathLimit)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "Folder name and file name combinations can have up to " + fullPathLimit + " characters" }); }
                        if (oneDriveFileTotLength > oneDrivePathLimit)
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "OneDrive client folder name and file name combinations can have up to " + oneDrivePathLimit + " characters" }); }
                        if (fname.Length > fileFolderNameLimit)
                            efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, "File", "File name can have up to 255 characters" });
                        if (fileTotLength > maxPathLength)
                            maxPathLength = fileTotLength;
                        lock (ffi) { ffi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { fi, fileSize, fileTotLength }); }
                    });
                Parallel.ForEach(subDirs, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1
                },
                    (sdi) =>
                    {
                        DirInfo subinfo = GetInfo(root, sdi, path, oneDrivePathTotLength, delemitter, ffi, cfi, efi, typeInfo);
                        lock (subDirs)
                        {
                            subDirsSize += subinfo.Size;
                            subDirsFilesCount += subinfo.Files;
                        }
                    });
                if (root != di && subDirsFilesCount > numFilesLimit)
                {
                    efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "Too much files for sync. Should not have more than " + numFilesLimit });
                }
                lock (cfi) { cfi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"" + delemitter + "\"{3}\"" + delemitter + "\"{4}\"" + delemitter + "\"{5}\"" + delemitter + "\"{6}\"", new object[] { di, files.Count, subDirs.Count, allFilesSize, (allFilesSize + subDirsSize), subDirsFilesCount, maxPathLength }); }
                DirInfo info = new DirInfo();
                info.Size = allFilesSize + subDirsSize;
                info.Files = subDirsFilesCount;
                return info;
            }
        }

        public static void Analyse(string[] dirs, string[] urls, int oneDrivePathTotLength, string csvLocation, string delemitter)
        {
            try
            {
                using (StreamWriter ffi = new StreamWriter(File.Open(csvLocation + "\\SPShareAnalysis_Files.csv", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None), Encoding.UTF8))
                {
                    ffi.AutoFlush = true;
                    lock (ffi) { ffi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { "Path", "Size [Bytes]", "PathLength" }); }
                    using (StreamWriter cfi = new StreamWriter(File.Open(csvLocation + "\\SPShareAnalysis_Dirs.csv", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None), Encoding.UTF8))
                    {
                        cfi.AutoFlush = true;
                        lock (cfi) { cfi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"" + delemitter + "\"{3}\"" + delemitter + "\"{4}\"" + delemitter + "\"{5}\"" + delemitter + "\"{6}\"", new object[] { "Path", "#Files", "#Dirs", "Size [Bytes]", "TotalSize [Bytes]", "#FilesTotal", "MaxPathLength" }); }
                        using (StreamWriter efi = new StreamWriter(File.Open(csvLocation + "\\SPShareAnalysis_Errors.csv", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None), Encoding.UTF8))
                        {
                            efi.AutoFlush = true;
                            lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { "Path", "Type", "Error" }); }
                            using (StreamWriter tfi = new StreamWriter(File.Open(csvLocation + "\\SPShareAnalysis_Types.csv", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None), Encoding.UTF8))
                            {
                                tfi.AutoFlush = true;
                                lock (tfi) { tfi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { "Type", "Count", "Total Size [Bytes]" }); }
                                Dictionary<string, DirInfo> typeInfo = new Dictionary<string, DirInfo>();
                                Parallel.ForEach(dirs, new ParallelOptions
                                {
                                    MaxDegreeOfParallelism = Environment.ProcessorCount > 1 ? Environment.ProcessorCount - 1 : 1
                                },
                                (currentDir) =>
                                {
                                    string currentUrl = urls[Array.IndexOf(dirs, currentDir)];
                                    currentUrl = currentUrl.TrimEnd("/\\".ToCharArray()) + "/";
                                    GetInfo(currentDir, currentDir, currentUrl, oneDrivePathTotLength, delemitter, ffi, cfi, efi, typeInfo);
                                });
                                foreach (KeyValuePair<string, DirInfo> type in typeInfo)
                                    lock (tfi) { tfi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { type.Key, type.Value.Files, type.Value.Size }); }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                lock (Console.Error) { Console.Error.WriteLine("An exception happended: " + ex.GetType().ToString()); }
                lock (Console.Error) { Console.Error.WriteLine(ex.Message); }
                lock (Console.Error) { Console.Error.WriteLine(ex.StackTrace); }
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
    $null = $compilerParameters.ReferencedAssemblies.Add($resolvedAssembly)
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
    $null = New-Item -Path $AlyaTemp -ItemType Directory -Force
}

Write-Host "Analysing directories" -ForegroundColor $CommandInfo
[SharePointFileShareMigrationAnalysis.Helper]::Analyse($directoriesToAnalyse, $urlsToDocLibs, $maxOneDriveSyncPath.Length, $AlyaTemp, $delemitter)

Write-Host "Exporting excel file:" -ForegroundColor $CommandInfo
$outputFile = "$($AlyaData)\sharepoint\FileSystemAnalysis4Migration.xlsx"
Write-Host "$outputFile" -ForegroundColor $CommandInfo
$SPShareAnalysisFiles = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Files.csv"
$SPShareAnalysisDirs = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv"
$SPShareAnalysisErrors = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Errors.csv"
$SPShareAnalysisTypes = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Types.csv"
$SPShareAnalysisDirsCount = ($SPShareAnalysisDirs | Measure-Object).Count
$SPShareAnalysisErrorsCount = ($SPShareAnalysisErrors | Measure-Object).Count
$SPShareAnalysisTypesCount = ($SPShareAnalysisTypes | Measure-Object).Count
$SPShareAnalysisFilesCount = ($SPShareAnalysisFiles | Measure-Object).Count
if ($SPShareAnalysisFilesCount -gt 999999)
{
    Write-Warning "Too much file rows. Truncated to 1 million and saved csv instead"
    $SPShareAnalysisFiles = $SPShareAnalysisFiles | Select-Object -First 999999
    Copy-Item -Path "$AlyaTemp\SPShareAnalysis_Files.csv" -Destination "$($AlyaData)\sharepoint\SPShareAnalysis_Files.csv" -Force
}
if ($SPShareAnalysisDirsCount -gt 999999)
{
    Write-Warning "Too much dir rows. Truncated to 1 million and saved csv instead"
    $SPShareAnalysisDirs = $SPShareAnalysisDirs | Select-Object -First 999999
    Copy-Item -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv" -Destination "$($AlyaData)\sharepoint\SPShareAnalysis_Dirs.csv" -Force
}
if ($SPShareAnalysisTypesCount -gt 999999)
{
    Write-Warning "Too much type rows. Truncated to 1 million and saved csv instead"
    $SPShareAnalysisTypes = $SPShareAnalysisTypes | Select-Object -First 999999
    Copy-Item -Path "$AlyaTemp\SPShareAnalysis_Types.csv" -Destination "$($AlyaData)\sharepoint\SPShareAnalysis_Types.csv" -Force
}
if ($SPShareAnalysisErrorsCount -gt 999999)
{
    Write-Warning "Too much error rows. Truncated to 1 million and saved csv instead"
    $SPShareAnalysisErrors = $SPShareAnalysisErrors | Select-Object -First 999999
    Copy-Item -Path "$AlyaTemp\SPShareAnalysis_Errors.csv" -Destination "$($AlyaData)\sharepoint\SPShareAnalysis_Errors.csv" -Force
}
$excel = $SPShareAnalysisErrors | Export-Excel -Path $outputFile -WorksheetName "Errors" -TableName "Errors" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisTypes | Export-Excel -Path $outputFile -WorksheetName "Types" -TableName "Types" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisDirs | Export-Excel -Path $outputFile -WorksheetName "Dirs" -TableName "Dirs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisFiles | Export-Excel -Path $outputFile -WorksheetName "Files" -TableName "Files" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel -Show

Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Files.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Errors.csv" -Force
Remove-Item -Path "$AlyaTemp\SPShareAnalysis_Types.csv" -Force

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAh1q+yLgnhJu/p
# EbW/W0+LlPSaP7kZ1fojh3btDezfZKCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMhk6yxw
# HTTsY14h0cxdLel2pg6SboGJOiY/96tf3ZOEMA0GCSqGSIb3DQEBAQUABIICAFgA
# kUIGMV70RqYUPMCdVOynGfGYtdXSfhIA0fbRT5WfwDm4XhqcjHwmq943lDK0WKe0
# xEzjGjlC8QFozTl65k+wvR7TxT0d6xIZjT50PIGTtCeen7NnxeJ7S9FtLIJiQ9p5
# EgV4WK+rNTLGG+h6zYysgiHQi3RfH4Dkwn/WZi/Lo84lbr0CstrWDmHBo8SNQZ7w
# 5n2dwh9fZbRYmoMznCPX2b2SPWbu0GOLOgzuzNbkC4yLrBKnviqKUaBKAx2foQLJ
# skStM4AA5la3VaDBQp50kHR4m31EaSwPamDlmKc4WqAwwKTNz8onetVncYEE/fYn
# PkVtMMBhAmPJIymffkIHsm2EIlInLyokLnxqnc9m+nGALaOLjXh5sx+S7udWnQOX
# QXoTbfKRahDEEgUd90D3W2ErQ0O1eWuA2Hr8KfNy7oKVAGsS0j181Rq/bjBXxprF
# 83TyrLM35CgaKfdZRLOCAXkPYDcFPDiQH1EIgBjB1cq6PGv74gBZQTEmdL/Z6cPy
# zOj+BsFGv3mdfYT7tsZR0Mjns2b/+J1a5iDh2s1xxJa9eim4skagqSgUZ44oJGZt
# IaoCNtLIF35eXCroc/o81yO0k1y1lnJemwxIT52lXXt71J5KO2kQ2+U5kiiygN+Z
# RtEE9siK/3Ao/bnfxKlBdYm5O9stTGqQcerqtRMgoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCD/0iW//D29Ynb8EvDQ4OUORjTEbs0L1yjKZQR+HrQNdgIUSMS1
# SlARvHyr1NOql3w4bHBCzQEYDzIwMjUwMjA2MTkzMTUxWjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIPCpSVdZRE0kEqIuHDB/S4+TcaLnAWOZ
# U6z97+i8tgDOMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGAdbRshDdxRpr3d5+dEVu9h2YXTvSdxMItGDGEw12hFBjz
# 7IVLdtIriJ519zR8V1OUOMxDcnXv084qXc+CQUdMSuLdI410tnvCoZKP9LWRxCjp
# Kh4mz1AnvWrcFnFNd0YRos8lm3QlNJdNWM1YPq2DKtWlMBBiT8GyES7V3QFEMgdG
# 0kZgLKnS0QyDXnYOMOsLHPPfNtLVZo94iKZaOBlFMfxbw/sBson4JBkOENUxddYX
# wjooVPPT5zqqdKoNtRWwyzhTKo+w181nOzd5kbAwZs7bBQ5MvqftWR100WimQ87m
# a9C/+5jVOr7258xRXp3xyapJA7WnrqdxgnTOT2T7sq08bcx7LyzhV56M4y/jRNSS
# N0LYa65DvL6I0/D9YF1LkOLyhwddJKcmAnDSPFgQIOFB7XJqp0jurigEIPCx2gcA
# SzsSEvGsnKimOCfBjgOJUgtt6UeWhYxL+h/n2lscr5mYBQ7ww/xPhB4qXgd8RXl1
# 5mQJe+CqcB1f3NgoWOj9
# SIG # End signature block
