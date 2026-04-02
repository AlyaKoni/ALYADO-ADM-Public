using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace AlyaConsulting.Intune.MAC
{
    // Credits to: https://github.com/svrooij/ContentPrep/blob/6aeb51efdef41f98f23226ec0fe175d14f9a1f0d/src/SvR.ContentPrep/Models/FileEncryptionInfo.cs

    internal class Program
    {
        static void Main(string[] args)
        {
            string? sourceFile = null;
            string? targetFile = null;
            if (args != null && args.Length > 0) sourceFile = args[0];
            if (args != null && args.Length > 1) targetFile = args[1];
            if (sourceFile != null && targetFile != null)
            {
                var info = Encryptor.EncryptFile(sourceFile, targetFile);
                targetFile = targetFile + ".xml";
                var seri = new XmlSerializer(info.GetType());
                using (TextWriter writer = new StreamWriter(targetFile, false, Encoding.UTF8))
                {
                    seri.Serialize(writer, info);
                    writer.Close();
                }
                var memoryStream = new MemoryStream();
                var streamWriter = new StreamWriter(memoryStream, Encoding.UTF8);
                seri.Serialize(streamWriter, info);
                byte[] utf8EncodedXml = memoryStream.ToArray();
                var str = UTF8Encoding.UTF8.GetString(utf8EncodedXml);
                Console.WriteLine(str);
            }
            else
            {
                throw new ArgumentException("usage: encryptPackage sourceFile targetFile");
            }
        }

    }

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
        public string? EncryptionKey { get; set; }

        /// <summary>
        /// Gets or sets the mac key.
        /// </summary>
        public string? MacKey { get; set; }

        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public string? InitializationVector { get; set; }

        /// <summary>
        /// Gets or sets the mac.
        /// </summary>
        public string? Mac { get; set; }

        /// <summary>
        /// Gets or sets the profile identifier.
        /// </summary>
        public string? ProfileIdentifier { get; set; }

        /// <summary>
        /// Gets or sets the file digest.
        /// </summary>
        public string? FileDigest { get; set; }

        /// <summary>
        /// Gets or sets the file digest algorithm.
        /// </summary>
        public string? FileDigestAlgorithm { get; set; }

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
            var cryptoServiceProvider = Aes.Create();
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
            byte[] buffer = new byte[offset + initializationVector.Length];
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
        internal static byte[]? ComputeHash(this HashAlgorithm hashAlgorithm, Stream stream)
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
