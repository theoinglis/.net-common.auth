using System.Security.Cryptography;
using System.Text;

namespace Common.Auth.Hashing
{
    public class MD5HashService : IHashService
    {
        public string HashText(string text)
        {
            var cryptoProvider = new MD5CryptoServiceProvider();
            byte[] data = Encoding.ASCII.GetBytes(text);
            data = cryptoProvider.ComputeHash(data);
            return Encoding.ASCII.GetString(data);
        }
    }
}
