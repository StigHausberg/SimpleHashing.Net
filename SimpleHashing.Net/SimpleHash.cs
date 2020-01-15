using System;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;

namespace SimpleHashing.Net
{
    public class SimpleHash : ISimpleHash
    {
        private const int MSaltSize = 16;
        private const int MHashSize = 32;
        private const int MIterations = 50000;

        public string Compute(string password)
        {
            return Compute(password, MIterations);
        }

        public string Compute(string password, int iterations)
        {
            using (var bytes = new Rfc2898DeriveBytes(password, MSaltSize, iterations))
            {
                var hash = bytes.GetBytes(MHashSize);

                return CreateHashString(hash, bytes.Salt, iterations);
            }
        }

        private string ComputeHash(string password, string salt, int iterations, int hashSize)
        {
            var saltBytes = Convert.FromBase64String(salt);

            using (var bytes = new Rfc2898DeriveBytes(password, saltBytes, iterations))
            {
                var hash = bytes.GetBytes(hashSize);

                return Convert.ToBase64String(hash);
            }
        }

        public bool Verify(string password, string passwordHashString)
        {
            var parameters = new SimpleHashParameters(passwordHashString);

            var hashSize = Convert.FromBase64String(parameters.PasswordHash).Length;

            var newPasswordHash = ComputeHash(password, parameters.Salt, parameters.Iterations, hashSize);

            return parameters.PasswordHash == newPasswordHash;
        }

        private string CreateHashString(byte[] hash, byte[] salt, int iterations)
        {
            var saltString = Convert.ToBase64String(salt);
            var hashStringPart = Convert.ToBase64String(hash);

            return string.Join
                (
                    Constants.Splitter.ToString(),
                    Constants.Algorithm,
                    iterations.ToString(CultureInfo.InvariantCulture),
                    saltString,
                    hashStringPart
                );
        }

        public TimeSpan Estimate(string password, int iterations)
        {
            var watch = new Stopwatch();
            watch.Start();
            Compute(password, iterations);
            watch.Stop();
            return watch.Elapsed;
        }
    }
}