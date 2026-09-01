#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    18.07.2024 Konrad Brunner       Initial Version
    02.09.2024 Konrad Brunner       Checking OneDrive sync path
    03.03.2025 Konrad Brunner       PowerShell 7
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Analyses local directories to identify potential compatibility or migration issues for SharePoint and OneDrive environments and exports the results to CSV and Excel reports.

.DESCRIPTION
The Analyse-Dir4MigrationStandalone.ps1 script performs a comprehensive scan of specified directories to assess their readiness for migration to SharePoint or OneDrive. It checks for issues such as long paths, invalid characters, large files, and excessive file counts. The script compiles results into multiple CSV files and consolidates them into an Excel workbook for reporting purposes. It leverages .NET assemblies and the ImportExcel module for reporting and performs the analysis in parallel for efficiency.

.PARAMETER directoriesToAnalyse
Specifies one or more local directories to analyse. Defaults to C:\Alya.

.PARAMETER urlsToDocLibs
Specifies corresponding SharePoint document library URLs for the directories being analysed. The order corresponds to the directories specified in directoriesToAnalyse.

.PARAMETER maxOneDriveSyncPath
Defines the maximum OneDrive sync path used for measuring path lengths against OneDrive constraints.

.PARAMETER delemitter
Defines the delimiter used in generated CSV output files. Defaults to a comma (,).

.INPUTS
None. Data is provided via parameters.

.OUTPUTS
The script generates the following files in the script directory:
SPShareAnalysis_Files.csv
SPShareAnalysis_Dirs.csv
SPShareAnalysis_Errors.csv
SPShareAnalysis_Types.csv
FileSystemAnalysis4Migration.xlsx

.EXAMPLE
PS> .\Analyse-Dir4MigrationStandalone.ps1 -directoriesToAnalyse "C:\Projects", "D:\Data" -urlsToDocLibs "sites/Projects/Documents", "sites/Data/Documents" -maxOneDriveSyncPath "C:\Users\User\Company\Projects - Documents"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string[]]$directoriesToAnalyse = @("C:\Alya"),
    [string[]]$urlsToDocLibs = @("sites/XXXXSP-ADM-Daten/Freigegebene Dokumente"),
    [string]$maxOneDriveSyncPath = "C:\Users\maxprename.maxlastname\EntraIdTenantNameInProperties\maxSiteName - maxLibTitle",
    [string]$delemitter = ","
)

# Starting Transcript
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
Start-Transcript -Path "$($PSScriptRoot)\Analyse-Dir4MigrationStandalone-$($AlyaTimeString).log" | Out-Null

#Members
$CommandInfo = "Cyan"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-Module -Name "ImportExcel" -Force -Scope CurrentUser
Import-Module "ImportExcel"

#Compiling helper
Write-Host "Compiling helper" -ForegroundColor $CommandInfo
$TypeDefinition = @"
using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Versioning;

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
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            internal int bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFile(string lpFileName, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindNextFile(IntPtr hFindFile, out
                WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(
            IntPtr handle
        );

        internal enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }
        internal enum SECURITY_INFORMATION
        {
            OWNER_SECURITY_INFORMATION = 1,
            GROUP_SECURITY_INFORMATION = 2,
            DACL_SECURITY_INFORMATION = 4,
            SACL_SECURITY_INFORMATION = 8,
        }

        [DllImport("Advapi32.dll", SetLastError = true)]
        internal static extern uint GetSecurityInfo(
            IntPtr hFindFile,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr pSidOwner,
            out IntPtr pSidGroup,
            out IntPtr pDacl,
            out IntPtr pSacl,
            out IntPtr pSecurityDescriptor
        );

        [DllImport("Advapi32.dll", SetLastError = true)]
        internal static extern uint GetNamedSecurityInfo(
            string fileOrDirName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr pSidOwner,
            out IntPtr pSidGroup,
            out IntPtr pDacl,
            out IntPtr pSacl,
            out IntPtr pSecurityDescriptor
        );

        [DllImport("advapi32.dll")]
        internal static extern Int32 GetSecurityDescriptorLength(
            IntPtr pSecurityDescriptor
        );

        [DllImport(
           "advapi32.dll",
           EntryPoint = "ConvertSidToStringSidW",
           CallingConvention = CallingConvention.Winapi,
           SetLastError = true,
           ExactSpelling = true,
           CharSet = CharSet.Unicode)]
        [ResourceExposure(ResourceScope.None)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertSidToStringSid(
            IntPtr Sid,
            ref IntPtr StringSid
        );

        [DllImport(
             "advapi32.dll",
             EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        [ResourceExposure(ResourceScope.None)]
        internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr securityDescriptor,
            /* DWORD */ uint requestedRevision,
            SECURITY_INFORMATION securityInformation,
            out IntPtr resultString,
            ref ulong resultStringLength
        );

        internal class DirInfo
        {
            internal long Size { get; set; }
            internal long Files { get; set; }
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
                return (long)findData.nFileSizeLow + (long)findData.nFileSizeHigh * ((long)uint.MaxValue + 1);
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
            bool hasAccess = true;
            WIN32_FIND_DATA findData;
            IntPtr findHandle = FindFirstFile(directoryPath, out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                IntPtr securityDescriptor = IntPtr.Zero;
                try
                {
                    IntPtr ownerSid;
                    IntPtr groupSid;
                    IntPtr dacl;
                    IntPtr sacl;

                    uint returnValue = GetNamedSecurityInfo(directoryPath,
                        SE_OBJECT_TYPE.SE_FILE_OBJECT,
                        SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                        out ownerSid, out groupSid, out dacl, out sacl, out securityDescriptor);

                    IntPtr sidString = IntPtr.Zero;
                    bool success = ConvertSidToStringSid(ownerSid, ref sidString);
                    string sidStringLoc = Marshal.PtrToStringAuto(sidString);

                    IntPtr daclString = IntPtr.Zero;
                    ulong resultStringLength = 0;
                    uint SDDL_REVISION_1 = 1;
                    success = ConvertSecurityDescriptorToStringSecurityDescriptor(
                        securityDescriptor,
                        SDDL_REVISION_1,
                        SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                        out daclString,
                        ref resultStringLength);
                    string daclStringLoc = Marshal.PtrToStringAuto(daclString);

                    if (daclString != IntPtr.Zero && sidString != IntPtr.Zero && daclStringLoc.Contains(sidStringLoc))
                    {
                        // we are able to read security decriptor so expecting read access
                        hasAccess = true;
                    }
                    else
                    {
                        hasAccess = false;
                    }

                    LocalFree(sidString);
                    LocalFree(daclString);
                }
                finally
                {
                    LocalFree(securityDescriptor);
                }

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
                lock (efi) { efi.WriteLine("\"{0}\"" + delemitter + "\"{1}\"" + delemitter + "\"{2}\"", new object[] { di, "Dir", "No access or not readable" }); }
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
                            try
                            {
                                FileInfo finf = new FileInfo(fi);
                                fileSize = finf.Length;
                            }
                            catch (Exception) { }
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
if (($PSVersionTable).PSEdition -eq "Core")
{
    $ReferencedAssemblies = 
    @(
    )
    $compilerParameters = @("-debug","-optimize","-nologo")
    foreach ($reference in $ReferencedAssemblies)
    {
        $compilerParameters += "-reference:`"$reference`""
    }

    Add-Type -TypeDefinition $TypeDefinition -CompilerOptions $compilerParameters
}
else
{
    $ReferencedAssemblies = 
    @(
        'System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        'Microsoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
        'System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        'System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
        'System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    )

    $addTypeCommand = Get-Command -Name "Add-Type"
    $addTypeCommandInstance = [Activator]::CreateInstance($addTypeCommand.ImplementingType)
    $resolveAssemblyMethod = $addTypeCommand.ImplementingType.GetMethod("ResolveReferencedAssembly", [Reflection.BindingFlags]"NonPublic, Instance")
    $compilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
    $compilerParameters.CompilerOptions = "/debug-"
    
    foreach ($reference in $ReferencedAssemblies)
    {
        $resolvedAssembly = $resolveAssemblyMethod.Invoke($addTypeCommandInstance, $reference)
        $null = $compilerParameters.ReferencedAssemblies.Add($resolvedAssembly)
    }
    
    $compilerParameters.IncludeDebugInformation = $true
    Add-Type -TypeDefinition $TypeDefinition -CompilerParameters $compilerParameters
}

# =============================================================
# LOCAL stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Analyse-Dir4Migration | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Analysing directories" -ForegroundColor $CommandInfo
[SharePointFileShareMigrationAnalysis.Helper]::Analyse($directoriesToAnalyse, $urlsToDocLibs, $PSScriptRoot, $delemitter)

Write-Host "Exporting excel file:" -ForegroundColor $CommandInfo
$outputFile = "$PSScriptRoot\FileSystemAnalysis4Migration.xlsx"
Write-Host "$outputFile" -ForegroundColor $CommandInfo
$SPShareAnalysisFiles = Import-Csv -Path "$PSScriptRoot\SPShareAnalysis_Files.csv" -Delimiter $delemitter
$SPShareAnalysisDirs = Import-Csv -Path "$PSScriptRoot\SPShareAnalysis_Dirs.csv" -Delimiter $delemitter
$SPShareAnalysisErrors = Import-Csv -Path "$PSScriptRoot\SPShareAnalysis_Errors.csv" -Delimiter $delemitter
$SPShareAnalysisTypes = Import-Csv -Path "$PSScriptRoot\SPShareAnalysis_Types.csv" -Delimiter $delemitter
$SPShareAnalysisDirsCount = ($SPShareAnalysisDirs | Measure-Object).Count
$SPShareAnalysisErrorsCount = ($SPShareAnalysisErrors | Measure-Object).Count
$SPShareAnalysisTypesCount = ($SPShareAnalysisTypes | Measure-Object).Count
$SPShareAnalysisFilesCount = ($SPShareAnalysisFiles | Measure-Object).Count
if ($SPShareAnalysisFilesCount -gt 999999)
{
    Write-Warning "Too much file rows. Truncated to 1 million. Csv has all rows!"
    $SPShareAnalysisFiles = $SPShareAnalysisFiles | Select-Object -First 999999
}
if ($SPShareAnalysisDirsCount -gt 999999)
{
    Write-Warning "Too much dir rows. Truncated to 1 million. Csv has all rows!"
    $SPShareAnalysisDirs = $SPShareAnalysisDirs | Select-Object -First 999999
}
if ($SPShareAnalysisTypesCount -gt 999999)
{
    Write-Warning "Too much type rows. Truncated to 1 million. Csv has all rows!"
    $SPShareAnalysisTypes = $SPShareAnalysisTypes | Select-Object -First 999999
}
if ($SPShareAnalysisErrorsCount -gt 999999)
{
    Write-Warning "Too much error rows. Truncated to 1 million. Csv has all rows!"
    $SPShareAnalysisErrors = $SPShareAnalysisErrors | Select-Object -First 999999
}
$excel = $SPShareAnalysisErrors | Export-Excel -Path $outputFile -WorksheetName "Errors" -TableName "Errors" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisTypes | Export-Excel -Path $outputFile -WorksheetName "Types" -TableName "Types" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisDirs | Export-Excel -Path $outputFile -WorksheetName "Dirs" -TableName "Dirs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $SPShareAnalysisFiles | Export-Excel -Path $outputFile -WorksheetName "Files" -TableName "Files" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel -Show

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDq07xLv1sPQPZ6
# MDsCpjTyJEAb93w2Eb+4+lfgHFijnqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP2y7835
# VngtYgaEzDGjitd/xqpEd7CfETddj69eCT5AMA0GCSqGSIb3DQEBAQUABIICAJfT
# 8IRGTPXVCkGF3u3K8VpLDucEbE4qoWtJ/Fzq4rCOtQVRGnm/2MLxBKZwRC9rp6uJ
# DIwI0X04695fDsgHEHCtn+OWjsSW5vPt8gbqZZckpLrPx0HgJ2dcKCj/QloMTmKR
# OVfkL4YjVMjPCWVwMZt4waIpenv/BZyrZl7b1WTNzHnQ8a5/GW8Iu6f75IbqnDND
# 8QSyE/cqqDT0mw2OXswGIAsiIF95pspArRBGYMb13aSr/vaFHzQFKsMKtTpeljk7
# GyV0LXMQ2yRUnooCs5yavAJ1/4b0Lff/rU/iRIreuKWxJTcL9r964JKO5szgLH6N
# GsLibZZ8CF83o7y6tZHowrBBIGq288S6O7EoPTPHgz4HUx0mcU2r1zTuGm+bTmjM
# xqhnVYTvwvMHLxaPAL3AV4djd41ZG29hVjy8lsDHMJzV8UyEQqBh3IEH6fGE+7rF
# UQQSObugzh1h7Nqm/QsfxuAgMZjxBUhNEtGfR6ES+uUA1YbOHMbS/Ta7eVkRGhq/
# /RcSgtGfmvRvSTdTQ7PWFZleeC8WMz60zbEQMWpo5UfX7aUN5scDVuA01EVccABL
# 5WX4dIQgLBIQ13gnN7nmU9wfITssil12el1077IjiFMAtp0pHqPluwxY0k+UEW5W
# FrtcbqRATGuRjSb01M74t9t/h0eVOjQf5Qlj+1sLoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCDSw9cXh2M9bpZBSFCmFSssSWUfh5fxHGUgOmZzSV+XpQIUdquM
# l3ooXsfzQ9nLVKNWxdk0JKYYDzIwMjYwODI5MTUzMjQxWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDCPflYV2FgMiauvKqAScHbi0SQXjsx1Mydc4u6uX6dwuYYwYK0rUy8LCSsR
# e/kSHt0wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAGtOpyU3pd8QqhfR+0qs5U/udhRXXk+EgEZzygnArMIIZ
# HEv9fiHlhBKsMiJwR26TVcjtrUhr6HkzJObFzkYUmtvirQ+uM3CfDFWaKqKLCfaF
# VGL4bGnmyA8bb2nszrBr2q2g71h+Hwud4JG+pF4y6fnerxJztSNV/W5ANjhG5xBe
# v7KJmfjD9qrLwLIxtk0BRKTNwCnud7wH0hc6yiIe0uGHOv0NVS8Auwwkb8mBRsx1
# +AZ/9RUFd9nmSXykhqXC5VuuL+emYtJMFM+fafz5U28F1t7+G0XicCSUzzeqRZZT
# U4cmkAyP8fMZT0GxYTCqPAtgx20xT4cQAY5llamZUvg0wcwe1gIT+XMKNEsm8g5D
# rJufHZecT/MsqznoqEqzgpmraKueJnT2e8Awf/EdYDt+n7MuCTU/768WQA1F8F89
# Jllv01o+lDPCezltHdXgjFQfncQO2MJIVIge9daOwWm86/QBw1Yo9JDa3nSBZgYo
# 5/j+RPqWCqnLnoeBRWNE
# SIG # End signature block
