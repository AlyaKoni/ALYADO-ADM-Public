#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    03.03.2025 Konrad Brunner       PowerShell 7

#>

[CmdletBinding()]
Param(
    [string[]]$directoriesToAnalyse = @("C:\Users\konrad.brunner\OneDrive - Alya Consulting Inh. Konrad Brunner"),
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
if ($AlyaIsPsCore)
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

if (-Not (Test-Path $AlyaTemp))
{
    $null = New-Item -Path $AlyaTemp -ItemType Directory -Force
}

Write-Host "Analysing directories" -ForegroundColor $CommandInfo
[SharePointFileShareMigrationAnalysis.Helper]::Analyse($directoriesToAnalyse, $urlsToDocLibs, $maxOneDriveSyncPath.Length, $AlyaTemp, $delemitter)

Write-Host "Exporting excel file:" -ForegroundColor $CommandInfo
$outputFile = "$($AlyaData)\sharepoint\FileSystemAnalysis4Migration.xlsx"
Write-Host "$outputFile" -ForegroundColor $CommandInfo
$SPShareAnalysisFiles = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Files.csv" -Delimiter $delemitter
$SPShareAnalysisDirs = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Dirs.csv" -Delimiter $delemitter
$SPShareAnalysisErrors = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Errors.csv" -Delimiter $delemitter
$SPShareAnalysisTypes = Import-Csv -Path "$AlyaTemp\SPShareAnalysis_Types.csv" -Delimiter $delemitter
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
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB77Vb9dSrCGV+L
# U/mG8y6H7xXGe4+5Uj4d24q2oTlNK6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGcdouSScBYszotG
# 8EEPirQrOsw61UGY6akjHh8sKeYWMA0GCSqGSIb3DQEBAQUABIICAIGTi2GbR2af
# we3JrAoY/6KCARRyZF9td3tEmhHtGsjgQrwvKHi07MzHPvnbvpnGZi0EhKBCOPdL
# H0beJeBDwOHDceXNDjrvhoUTQGfWNKOb1VTPXXrUSUpFEkGK7sIU9XyOmIhLAKUx
# qAnCV709KZhaTr0UpdpJt29H+89tUhIs/iPpTm0HMWfsiB5i95YB77gdcPkVCKC+
# FGDOsrRQT8422sS3O8Jv/6dW9M4QuVhDztDmvBuOSHAmcJ0Q9eotDwR/cO+iJ+Py
# y8rgMtBYKbPVKPSTwoboqXXjmA0q9ENEQXZyv/F8HfkGnJRExi6ZI55UZTQ+WQdM
# zCLLQk5Md4UeXgmy4rMteych0Oc3NIrH1ISbuz1LaJnsZyqoKcg4BcSpHgvErp+Y
# FJ9/tgKpVRTZ0hp1baTJfGMl8MYqnlP23GDJ0YDP9XzYi1n62MckvClGxUwBTQJx
# ORxGDWLChrrH+YBx5JAnUK9cAPYe/ev+2I9CL8UN1EOyL6zp74rvGyn3LReuw5i6
# TluZx9/Jhs7m5nYWs21ASGLIrMZbZD46+3+qWE6ps2fndMc944IV5ubbs1Ny1bze
# aPyy+pjqvlw7kZTeUz8hb2vAlZ/7rHdkyHgoP6+hlmW6uuQnXum2kmR3vobROJAh
# P8Dz6tjBYpVY1lIT2Ftc8fJiBS/CcVQmoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBzwPFDYpNRO3BC/Rd+2ktcaJ0wQEQocCy6otuJiNmUCgIUf/axt3weX4la
# ufS6796ei33AdJ4YDzIwMjYwMTIwMTAwMzQyWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IESt/GnYJ1LSrSY0KSisGWDa5rlesButIZe0/VAg+gAfMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAVmHtYxrY4heE
# jV4tecS4Ec8zI1rdb7DG5CMfMRvak8cuZUcIv8If3Dy8Z2ZtctfpvVp1sGbomPXa
# txQRfL28cg/yWZp7Tzly43rxuwh0AVjGFG7kOOYZEYkAfYwsP676uKGUrk6rT4e5
# +kJJIpV2pLWNXncSTtWE9jn+1pkHgMVW9dQnxFAjgF+uc1nUTD4Heyq1rIdpuDLh
# T6k87+Y/i2Zswz4NJC4sLwkIvmfRA31SHOTvD//PBORJdqzNcGJIX8NdvrFzmXdB
# Aoqiyn7w8GBaQdIroCUZLOLjZefHL3o8bJgoRfBCiRRDvl22bioDORNNXwxF0uIu
# 6EnVAUsfuS/OJ4t6pefoZ5lxtOAyQjoKlwfb/33QMH7CaNQC7SrLCS9Lrp/e+npg
# H+0fj5VsBhzEZxxIUQItZvkm2M9rv7yT5hwSYEvozh7WmpvaMTFcSIRG6gkq/NM4
# YwZVBsdOXt0aIqcBgw+FnFKIL+jo5u/ZfgBy0+50hEY0u2NacUOl
# SIG # End signature block
