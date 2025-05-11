using DataSecurityProject.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;

namespace DataSecurityProject.Controllers
{
    public class EncryptionController : Controller
    {
        public IActionResult Encrypt() => View();

        [HttpPost]
        public IActionResult Encrypt(string plainText)
        {
            if (!HttpContext.Session.TryGetValue("user", out byte[] userBytes))
                return RedirectToAction("Login", "Authentication");

            string email = Encoding.UTF8.GetString(userBytes);
            var (cipher, key, iv) = EncryptText(plainText);

            var data = new TextData { EncryptedText = cipher, Key = key, IV = iv };
            string filePath = $"UserData/{email}_data.json";

            if (!Directory.Exists("UserData"))
                Directory.CreateDirectory("UserData");

            System.IO.File.WriteAllText(filePath, JsonSerializer.Serialize(data));

            ViewBag.EncryptedText = cipher;
            return View();
        }

        public IActionResult Decrypt()
        {
            if (!HttpContext.Session.TryGetValue("user", out byte[] userBytes))
                return RedirectToAction("Login", "Authentication");

            string email = Encoding.UTF8.GetString(userBytes);
            string filePath = $"UserData/{email}_data.json";
            if (!System.IO.File.Exists(filePath)) return View("NoData");

            var data = JsonSerializer.Deserialize<TextData>(System.IO.File.ReadAllText(filePath));

            string decrypted = DecryptText(data.EncryptedText, data.Key, data.IV);
            ViewBag.DecryptedText = decrypted;
            return View();
        }

        private static (string EncryptedText, string Key, string IV) EncryptText(string plainText)
        {
            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }

            return (
                Convert.ToBase64String(ms.ToArray()),
                Convert.ToBase64String(aes.Key),
                Convert.ToBase64String(aes.IV)
            );
        }

        private static string DecryptText(string cipherText, string key, string iv)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.IV = Convert.FromBase64String(iv);

            using var ms = new MemoryStream(cipherBytes);
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }
}
