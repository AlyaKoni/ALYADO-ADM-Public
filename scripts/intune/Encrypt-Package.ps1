#Requires -Version 2.0

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
    20.03.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param (
    [string]$sourceFile,
    [string]$targetFile
)

$TypeDefinition = @"
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace AlyaConsulting.Intune.MAC
{

    // Credits to: https://github.com/svrooij/ContentPrep/blob/6aeb51efdef41f98f23226ec0fe175d14f9a1f0d/src/SvR.ContentPrep/Models/FileEncryptionInfo.cs

    /// <summary>
    /// File encryption info.
    /// </summary>
    [XmlRoot("EncryptionInfo")]
    [Serializable]
    public class FileEncryptionInfo
    {
        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        public string EncryptionKey { get; set; }

        /// <summary>
        /// Gets or sets the mac key.
        /// </summary>
        public string MacKey { get; set; }

        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public string InitializationVector { get; set; }

        /// <summary>
        /// Gets or sets the mac.
        /// </summary>
        public string Mac { get; set; }

        /// <summary>
        /// Gets or sets the profile identifier.
        /// </summary>
        public string ProfileIdentifier { get; set; }

        /// <summary>
        /// Gets or sets the file digest.
        /// </summary>
        public string FileDigest { get; set; }

        /// <summary>
        /// Gets or sets the file digest algorithm.
        /// </summary>
        public string FileDigestAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the file size in bytes.
        /// </summary>
        public long SizeInBytes { get; set; }

        /// <summary>
        /// Gets or sets the encrypted file size in bytes.
        /// </summary>
        public long SizeEncryptedInBytes { get; set; }

    }

    public static class Encryptor
    {
        private const string ProfileIdentifier = "ProfileVersion1";
        private const string FileDigestAlgorithm = "SHA256";
        public static FileEncryptionInfo EncryptFile(string sourceFile, string targetFile)
        {
            byte[] encryptionKey = CreateAesKey();
            byte[] hmacKey = CreateAesKey();
            byte[] iv = GenerateAesIV();
            byte[] encryptedFileHash = EncryptFileWithIV(sourceFile, targetFile, encryptionKey, hmacKey, iv);

            byte[] fileHash;
            using (SHA256 hasher = SHA256.Create())
            using (FileStream fileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize: 4096))
            {
                fileHash = hasher.ComputeHash(fileStream);
                fileStream.Close();
            }

            FileInfo sourceFi = new FileInfo(sourceFile);
            FileInfo targetFi = new FileInfo(targetFile);

            FileEncryptionInfo fileEncryptionInfo = new FileEncryptionInfo
            {
                EncryptionKey = Convert.ToBase64String(encryptionKey),
                MacKey = Convert.ToBase64String(hmacKey),
                InitializationVector = Convert.ToBase64String(iv),
                Mac = Convert.ToBase64String(encryptedFileHash),
                ProfileIdentifier = ProfileIdentifier,
                FileDigest = Convert.ToBase64String(fileHash),
                FileDigestAlgorithm = FileDigestAlgorithm,
                SizeInBytes = sourceFi.Length,
                SizeEncryptedInBytes = targetFi.Length
            };
            return fileEncryptionInfo;
        }

        private static byte[] CreateAesKey()
        {
            AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider();
            cryptoServiceProvider.GenerateKey();
            return cryptoServiceProvider.Key;
        }

        private static byte[] GenerateAesIV()
        {
            Aes aes = Aes.Create();
            return aes.IV;
        }

        private static byte[] EncryptFileWithIV(
            string sourceFile,
            string targetFile,
            byte[] encryptionKey,
            byte[] hmacKey,
            byte[] initializationVector)
        {
            byte[] encryptedFileHash;
            Aes aes = Aes.Create();
            HMACSHA256 hmac = new HMACSHA256(hmacKey);
            FileStream targetFileStream = new FileStream(targetFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None, bufferSize: 4096);
            int offset = hmac.HashSize / 8;
            //byte[] buffer = new byte[2097152];
            // Create an empty buffer for a specific length
            byte[] buffer = new byte[offset + initializationVector.Length];
            // Write the empty IV to the targetFileStream
            targetFileStream.Write(buffer, 0, offset + initializationVector.Length);
            using (ICryptoTransform cryptoTransform = aes.CreateEncryptor(encryptionKey, initializationVector))
            using (FileStream inputFileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize: 4096))
            using (CryptoStream cryptoStream = new CryptoStream(targetFileStream, cryptoTransform, CryptoStreamMode.Write))
            {
                inputFileStream.CopyTo(cryptoStream, 2097152);
                cryptoStream.FlushFinalBlock();
            }

            // Re-open the file to write the hash and the IV
            using (FileStream encryptedFileStream = new FileStream(targetFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None, bufferSize: 4096))
            {
                encryptedFileStream.Seek(offset, SeekOrigin.Begin);
                encryptedFileStream.Write(initializationVector, 0, initializationVector.Length);
                encryptedFileStream.Seek(offset, SeekOrigin.Begin);
                byte[] hash = hmac.ComputeHash(encryptedFileStream);
                encryptedFileHash = hash;
                encryptedFileStream.Seek(0L, SeekOrigin.Begin);
                encryptedFileStream.Write(hash, 0, hash.Length);
                encryptedFileStream.Close();
            }

            return encryptedFileHash;
        }

        internal static Stream DecryptFile(Stream inputStream, string encryptionKey, string hmacKey)
        {
            var resultStream = new MemoryStream();
            var encryptionKeyBytes = Convert.FromBase64String(encryptionKey);
            var hmacKeyBytes = Convert.FromBase64String(hmacKey);
            Aes aes = Aes.Create();
            HMACSHA256 hmac = new HMACSHA256(hmacKeyBytes);
            int offset = hmac.HashSize / 8;
            byte[] buffer = new byte[offset];
            inputStream.Read(buffer, 0, offset);
            byte[] hash = hmac.ComputeHash(inputStream);

            if (!buffer.CompareHashes(hash))
            {
                throw new InvalidDataException("Hashes do not match");
            }
            inputStream.Seek(offset, SeekOrigin.Begin);
            byte[] iv = new byte[aes.IV.Length];
            inputStream.Read(iv, 0, iv.Length);

            ICryptoTransform cryptoTransform = aes.CreateDecryptor(encryptionKeyBytes, iv);
            CryptoStream cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read);
            cryptoStream.CopyTo(resultStream, 2097152);

            resultStream.Seek(0, SeekOrigin.Begin);
            return resultStream;
        }
    }

    internal static class HashAlgorithmExtensions
    {
        internal static byte[] ComputeHash(this HashAlgorithm hashAlgorithm, Stream stream)
        {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                hashAlgorithm.TransformBlock(buffer, 0, bytesRead, null, 0);
            }
            hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
            return hashAlgorithm.Hash;
        }

        internal static bool CompareHashes(this byte[] input, byte[] compareTo)
        {
            if (input.Length != compareTo.Length)
            {
                return false;
            }

            return !input.Where((t, i) => t != compareTo[i]).Any();
        }
    }
}
"@

$ReferencedAssemblies = 
@(
    'System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
    'System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
    'Microsoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
    'System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
    'System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
    'System.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
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
$encryptedInfo = [AlyaConsulting.Intune.MAC.Encryptor]::EncryptFile($sourceFile, $targetFile)
$encryptedInfo | ConvertTo-Json

<#
Usage from ps 7:
$encInfo = powershell -File "C:\UntuneMacEncryptor.ps1" -sourceFile "C:\Content\Firefox Setup 124.0.dmg" -targetFile "C:\Package\Firefox Setup 124.0.dmg" | ConvertFrom-Json
$encInfo | fl
#>