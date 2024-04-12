using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using System;
using System.IO;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.Dynamic;
using System.ComponentModel.DataAnnotations;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.IO.Enumeration;
using Newtonsoft.Json.Bson;
//using Newtonsoft.Json;
//Author: Nathaniel Shah
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
#pragma warning disable CS8602 // Dereference of a possibly null reference.

namespace Messenger
{
    /// <summary>
    /// Key class to hold the key value for json serialization
    /// </summary>
    class KeyStorage
    {
        public string email { get; set; }
        public required string key { get; set; }
    }
    /// <summary>
    /// Key class to hold the key value for json serialization
    /// </summary>
    class PrivateKeyStorage
    {
        public string[] email { get; set; }
        public required string key { get; set; }
    }
    /// <summary>
    /// Key class to hold real values of a key
    /// </summary>
    class KeyClass
    {
        public int e { get; set; }
        public int n { get; set; }
        public BigInteger E { get; set; }
        public BigInteger N { get; set; }
    }
    class MsgClass
    {
        public string email { get; set; }
        public string content { get; set; }
        public DateTime messageTime { get; set; }
    }

    /// <summary>
    /// Class handling the creation, serliazation and sending/receiving of keys
    /// </summary>
    class Messenger
    {
        static readonly HttpClient client = new HttpClient();
        static string email;
        static string KURI = "http://voyager.cs.rit.edu:5050/Key/"; //They key uri
        static string MURI = "http://voyager.cs.rit.edu:5050/Message/"; //The message uri
        static void Main(string[] args)
        {
            email = "toivcs@rit.edu";

            KeyClass key = new KeyClass();
            Task task = getKey(key);
            task.Wait();
            Console.WriteLine(key.e);
            Console.WriteLine(key.E);
            Console.WriteLine(key.n);
            Console.WriteLine(key.N);

            MsgClass msg = new MsgClass();
            task = getMsg(msg);
            task.Wait();

        }

        static async Task getKey(KeyClass key)
        {
            try
            {
                KeyStorage? publicKey = await client.GetFromJsonAsync<KeyStorage>(KURI + email);

                string fileName = String.Format(@"{0}\" + email + ".key", Environment.CurrentDirectory);
                using (StreamWriter outputFile = new(fileName))
                {
                    outputFile.WriteLine(publicKey.key);
                }
                keySolver(key, publicKey.key);
                
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (NullReferenceException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch
            {
                Console.WriteLine("There was an error storing the key");
            }

        }

        public static void keySolver(KeyClass key, string b64key)
        {
            byte[] raw = Convert.FromBase64String(b64key);

            byte[] nBytes = new byte[4];
            byte[] eBytes = new byte[4];

            Array.Copy(raw, 0, eBytes, 0, 4);
            Array.Reverse(eBytes);
            int e = BitConverter.ToInt32(eBytes);

            byte[] EBytes = new byte[e];
            Array.Copy(raw, 4, EBytes, 0, e);
            BigInteger E = new(EBytes);

            Array.Copy(raw, e + 4, nBytes, 0, 4);
            Array.Reverse(nBytes);
            int n = BitConverter.ToInt32(nBytes);

            byte[] NBytes = new byte[n];
            Array.Copy(raw, 8 + e, NBytes, 0, n);
            BigInteger N = new(NBytes);
            key.e = e;
            key.n = n;
            key.N = N;
            key.E = E;
        }

        public void genKey()
        {
            Random rnd = new Random();

            int p_bytes = rnd.Next(384, 640);
            int q_bytes = 1024 - p_bytes;

            BigInteger p = NumberGen.primeGen(p_bytes, 1);
            BigInteger q = NumberGen.primeGen(q_bytes, 1);
            BigInteger n = p * q;
            BigInteger t = (p - 1) * (q - 1);

            int e1 = rnd.Next(64, 256);
            BigInteger e = NumberGen.primeGen(e1, 1);
            BigInteger d = modInverse(e, t);

            byte[] bPubKey = new byte[e.GetByteCount() + n.GetByteCount() + 8];
            byte[] bPrKey = new byte[d.GetByteCount() + n.GetByteCount() + 8];

            byte[] bE = e.ToByteArray();
            byte[] bD = d.ToByteArray();
            byte[] bN = n.ToByteArray();

            int ce = e.GetByteCount();
            int cd = d.GetByteCount();
            int cn = n.GetByteCount();

            byte[] be = BitConverter.GetBytes(ce);
            byte[] bd = BitConverter.GetBytes(cd);
            byte[] bn = BitConverter.GetBytes(cn);

            Array.Reverse(be);
            Array.Reverse(bd);
            Array.Reverse(bn);

            Array.Copy(bd, 0, bPrKey, 0, 4);
            Array.Copy(bD, 0, bPrKey, 4, cd);
            Array.Copy(bn, 0, bPrKey, 4 + cd, 4);
            Array.Copy(bN, 0, bPrKey, 8 + cd, cn);

            Array.Copy(be, 0, bPubKey, 0, 4);
            Array.Copy(bE, 0, bPubKey, 4, ce);
            Array.Copy(bn, 0, bPubKey, 4 + ce, 4);
            Array.Copy(bN, 0, bPubKey, 8 + ce, cn);

            PrivateKeyStorage prkey = new PrivateKeyStorage
            {
                key = Convert.ToBase64String(bPrKey)
            };

            KeyStorage pubkey = new KeyStorage
            {
                key = Convert.ToBase64String(bPubKey)
            };

            string privateKey = JsonSerializer.Serialize(prkey);
            string publicKey = JsonSerializer.Serialize(pubkey);


            string fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory);
            using (StreamWriter outputFile = new(fileName))
            {
                outputFile.WriteLine(privateKey);
            }

            fileName = String.Format(@"{0}\public.key", Environment.CurrentDirectory);
            using (StreamWriter outputFile = new(fileName))
            {
                outputFile.WriteLine(publicKey);
            }

        }

        static async Task getMsg(MsgClass msg)
        {
            MsgClass? MSG = await client.GetFromJsonAsync<MsgClass>(MURI + email);

            string b64key = checkEmails(msg.email);
            if (b64key != "False")
            {
                byte[] bmsg = Convert.FromBase64String(MSG.content);
                KeyClass keyC = new KeyClass();
                keySolver(keyC, b64key);
                string Message = RSA(keyC.E, keyC.N, bmsg);
                Console.WriteLine(Message);
            }
            else
            {
                Console.WriteLine("This message can't be decoded.");
            }
        }

        static string checkEmails(string email)
        {
            try
            {
                string fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory);
                using (StreamReader sr = new(fileName))
                {
                    string json = sr.ReadToEnd();
                    PrivateKeyStorage? priv = JsonSerializer.Deserialize<PrivateKeyStorage>(json);
                    string[] emails = priv.email;
                    foreach (string s in emails)
                    {
                        if (s.Equals(email))
                            return priv.key;
                    }
                    return "False";
                }
            }
            catch(FileNotFoundException)
            {
                Console.WriteLine("private.key does not exist. Please create a private key first");
                return "False";
            }
        }

        static async void sendKey()
        {
            string fileName = String.Format(@"{0}\public.key", Environment.CurrentDirectory);
            using (StreamReader sr = new(fileName))
            {
                string json = sr.ReadToEnd();
                KeyStorage? pubKey = JsonSerializer.Deserialize<KeyStorage>(json);
                pubKey.email = email;
                await client.PutAsJsonAsync<KeyStorage>(KURI + email, pubKey);
            }
            fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory);
            using (StreamReader sr = new(fileName))
            {
                string json = sr.ReadToEnd();
                PrivateKeyStorage? privKey = JsonSerializer.Deserialize<PrivateKeyStorage>(json);
                privKey.email.Append(email);
                json = JsonSerializer.Serialize<PrivateKeyStorage>(privKey);
                using (StreamWriter sw = new(fileName))
                {
                    sw.WriteLine(json);
                }
            }
        }

        static async void sendMsg(string msg)
        {
            string fileName = String.Format(@"{0}\" + email + ".key", Environment.CurrentDirectory);
            if (File.Exists(fileName))
            {
                using (StreamReader sr = new(fileName))
                {
                    string json = sr.ReadToEnd();
                    KeyStorage? keyC = JsonSerializer.Deserialize<KeyStorage>(json);
                    string key = keyC.key;
                    KeyClass keyClass = new KeyClass();
                    keySolver(keyClass, key);
                    byte[] bmsg = Encoding.UTF8.GetBytes(msg);
                    string b64msg = RSA(keyClass.E, keyClass.N, bmsg);
                    MsgClass MSG = new MsgClass()
                    {
                        email = email,
                        content = b64msg
                    };
                    await client.PutAsJsonAsync<MsgClass>(MURI + email, MSG);
                }
            }
            else
            {
                Console.WriteLine("please download the user's public key first");
            }
        }

        // author: toivcs@rit.edu
        static BigInteger modInverse(BigInteger a, BigInteger b)
        {
            BigInteger i = b, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger z = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - z * x;
                v = x;
            }
            v %= b;
            if (v < 0) v = (v + b) % b;
            return v;
        }

        static string RSA(BigInteger e, BigInteger n, byte[] bmsg)
        {
            BigInteger MSG = new(bmsg);
            MSG = BigInteger.ModPow(MSG, e, n);
            bmsg = MSG.ToByteArray();
            string msg = BitConverter.ToString(bmsg);
            return msg;
        }
    }

    class NumberGen
    {
        private static readonly object ConsoleLock = new object();

        static public BigInteger generator(int bits)
        {
            Byte[] bytes = RandomNumberGenerator.GetBytes(bits / 8);
            BigInteger num = new BigInteger(bytes);
            while (num % 2 == 0 | num < 0)
            {
                num = new BigInteger(RandomNumberGenerator.GetBytes(bits / 8));
            }
            return num;
        }
        static public BigInteger primeGen(int bits, int count)
        {
            BigInteger num = generator(bits);
            Boolean prime = num.IsProbablyPrime();
            while (!prime)
            {
                num = generator(bits);
                prime = num.IsProbablyPrime();
            }
            return num;
        }
    }

    public static class MyExtension
    {
        public static Boolean IsProbablyPrime(this BigInteger value, int k = 10)
        {
            BigInteger r;
            BigInteger d;
            (r, d) = nbull(value);
            for (int i = 0; i < k; i++)
            {
                BigInteger a = aCalc(value);
                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == BigInteger.One | x == value - 1) continue;
                for (int j = 0; j < r - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == value - 1) continue;
                }
                return false;
            }
            return true;
        }
        static private BigInteger aCalc(BigInteger value)
        {
            BigInteger a;
            a = NumberGen.generator(value.GetByteCount() - 1);
            return a;
        }
        static private (BigInteger, BigInteger) nbull(BigInteger value)
        {
            value--;
            BigInteger num = value;
            BigInteger counter = 0;
            while (num % 1 != 0)
            {
                counter++;
                value = num;
                num = num / 2;
            }
            return (counter, value);
        }
    }
}

    ///The following is debunct code i want to use as reference later


    ///This part is from main
    /// //string publicKey = getBaseString(e, n);
    //string privateKey = getBaseString(d, n);
    //var publickey = new Key
    //{
    //    BaseKey = publicKey
    //};
    //var privatekey = new Key
    //{
    //    BaseKey = privateKey
    //};
    ////            byte[] publicBytes = Encoding.UTF8.GetBytes(Publickey);
    ////return Convert.ToBase64String(publicBytes);
    //string jsonString = JsonSerializer.Serialize(privatekey);
    //byte[] privatebytes = Encoding.UTF8.GetBytes(jsonString);
    //string b64String = Convert.ToBase64String(privatebytes);

    //string fileName = String.Format(@"{0}\privateKey.txt", Environment.CurrentDirectory);
    //using (StreamWriter outputFile = new StreamWriter(fileName))
    //{
    //    outputFile.WriteLine(b64String);
    //}
    //KeyReader prkey = new KeyReader();
    //StreamReader sr = new StreamReader(fileName);
    //string b64json = sr.ReadLine();
    //byte[] privatebytes2 = Convert.FromBase64String(b64String);
    //string jsonString2 = Encoding.UTF8.GetString(privatebytes2);
    //Key? privkey = JsonSerializer.Deserialize<Key>(jsonString2);
    //prkey.Read(privkey.BaseKey);
    //Console.WriteLine(prkey.E.ToString(), prkey.N.ToString(), prkey.eSize, prkey.nSize);

    ///// <summary>
    ///// KeyReader is a class to read the deserialized json values
    ///// </summary>
    //class KeyReader
    //{
    //    public int eSize { get; set; }
    //    public int nSize { get; set; }
    //    public BigInteger E { get; set; }
    //    public BigInteger N { get; set; }
    //    public void Read(string s)
    //    {
    //        byte[] bytes = Encoding.UTF8.GetBytes(s);
    //        byte[] temp = new byte[2048];
    //        byte[] t = new byte[4];
    //        byte[] t2 = new byte[4];
    //        Array.Copy(bytes, 0, t, 0, 4);
    //        Array.Reverse(t);
    //        eSize = BitConverter.ToInt32(t);
    //        Array.Copy(bytes, 4, temp, 0, eSize);
    //        E = new BigInteger(temp);
    //        Array.Copy(bytes, 4 + eSize, t2, 0, 4);
    //        Array.Reverse(t2);
    //        nSize = BitConverter.ToInt32(t2);
    //        Console.WriteLine(eSize.ToString() + " " + nSize.ToString() + " " + 8);
    //        Console.WriteLine(bytes.Length);
    //        Array.Copy(bytes, 8 + eSize, temp, 0, nSize);
    //        N = new BigInteger(temp);
    //        //string temp = s.Substring(0, 4);
    //        //Console.WriteLine(temp.Length);
    //        //byte[] t = Convert.FromBase64String(temp);
    //        //Array.Reverse(t);
    //        //eSize = BitConverter.ToInt32(t);
    //        //temp = s.Substring(4, eSize);
    //        //E = new BigInteger(Convert.FromBase64String(temp));
    //        //temp = s.Substring(4 + eSize, 4);
    //        //t = Convert.FromBase64String(temp);
    //        //Array.Reverse(t);
    //        //nSize = BitConverter.ToInt32(t);
    //        //temp = s.Substring(8 + eSize, nSize);
    //        //N = new BigInteger(Convert.FromBase64String(temp));
    //    }
    //}
    //static String getBaseString(BigInteger e, BigInteger n)
    //{
    //    int eSize = e.GetByteCount();
    //    int nSize = n.GetByteCount();
    //    byte[] Base = new byte[8 + eSize + nSize];
    //    byte[] es = BitConverter.GetBytes(eSize);
    //    byte[] ns = BitConverter.GetBytes(nSize);
    //    Console.WriteLine(BitConverter.ToInt32(es).ToString());
    //    Array.Reverse(es);
    //    Array.Reverse(ns);
    //    Array.Copy(es, 0, Base, 0, 4);
    //    es = e.ToByteArray();
    //    Array.Copy(es, 0, Base, 4, eSize);
    //    Array.Copy(ns, 0, Base, 4 + eSize, 4);
    //    ns = n.ToByteArray();
    //    Array.Copy(ns, 0, Base, 8 + eSize, nSize);
    //    return Encoding.UTF8.GetString(Base);
    //    //byte[] temp = BitConverter.GetBytes(eSize);
    //    //Array.Reverse(temp); //makes it big endian
    //    //String Publickey = temp.ToString();
    //    //temp = e.ToByteArray();
    //    //Publickey += temp.ToString();
    //    //temp = BitConverter.GetBytes(nSize);
    //    //Array.Reverse(temp); //makes it big endian
    //    //Publickey += temp.ToString();
    //    //temp = n.ToByteArray();
    //    //Publickey += temp.ToString();
    //    //return Publickey;
    //}