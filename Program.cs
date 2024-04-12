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
    /// <summary>
    /// Message class to hold the contents of a message
    /// </summary>
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
        static string help = "dotnet run <option> <other arguments>" + Environment.NewLine +
            "- option - the task to perform, keyGen, sendKey, getKey, sendMsg, getMsg" + Environment.NewLine +
            "   keyGen takes the number of bits to use in the key" + Environment.NewLine +
            "   sendKey requires your email as the other argument" + Environment.NewLine +
            "   getKey requires an email as the other argument, and saves the public key of the email given" + Environment.NewLine +
            "   sendMsg requires the email to send to, THEN the message to send. ie. 'dotnet run sendMsg bob@mail.com 'Hello bob!''" + Environment.NewLine +
            "   getMsg requires an email and gets the message associated with that email address" + Environment.NewLine +
            "- other arguments - the email and/or message, the requirements of this option are dictated above" + Environment.NewLine;
        static readonly HttpClient client = new HttpClient();
        static string email;
        static string KURI = "http://voyager.cs.rit.edu:5050/Key/"; //The key uri
        static string MURI = "http://voyager.cs.rit.edu:5050/Message/"; //The message uri
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine(help);
                return;
            }
            string task = args[0];
            if (args.Length > 1)
                email = args[1];

            if(task == "keyGen")
            {
                if (args.Length != 2)
                {
                    Console.WriteLine(help);
                }
                else
                {
                    int bits = int.Parse(args[1]);
                    genKey(bits);
                }
            }
            else if(task == "sendKey")
            {
                if (args.Length != 2)
                {
                    Console.WriteLine(help);
                }
                else
                {
                    Task act = sendKey();
                    act.Wait();
                }
            }
            else if(task == "getKey")
            {
                if (args.Length != 2)
                {
                    Console.WriteLine(help);
                }
                else
                {
                    Task act = getKey();
                    act.Wait();
                }
            }
            else if(task == "sendMsg")
            {
                if (args.Length != 3)
                {
                    Console.WriteLine(help);
                }
                else
                {
                    string msg = args[2];
                    Task act = sendMsg(msg);
                    act.Wait();
                }
            }
            else if (task == "getMsg")
            {
                if (args.Length != 2)
                {
                    Console.WriteLine(help);
                }
                else
                {
                    Task act = getMsg();
                    act.Wait();
                }
            }
        }

        /// <summary>
        /// getKey will grab the public key for the provided email and save it to a local file titled {email}.key
        /// </summary>
        static async Task getKey()
        {
            KeyClass key = new KeyClass();
            try
            {
                KeyStorage? publicKey = await client.GetFromJsonAsync<KeyStorage>(KURI + email); //gets the key json file

                string fileName = String.Format(@"{0}\" + email + ".key", Environment.CurrentDirectory); //the file to write to
                using (StreamWriter outputFile = new(fileName))
                {
                    outputFile.Write(JsonSerializer.Serialize(publicKey)); //write the json to the file
                }
                
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

        /// <summary>
        /// keySovlver is a helper method that takes a base64 endoded key string, and breaks it down to it's components, e/d and n
        /// </summary>
        /// <param name="key"> a KeyClass object that should be empty, but will be used to store the paramaters that b64key breaks down into</param>
        /// <param name="b64key"> a base64 encoded key to handle </param>
        public static void keySolver(KeyClass key, string b64key)
        {
            byte[] raw = Convert.FromBase64String(b64key); //gets the raw bytes for the key

            byte[] nBytes = new byte[4]; //creates empty arrays to be filled later
            byte[] eBytes = new byte[4];

            Array.Copy(raw, 0, eBytes, 0, 4); //fills the empty array with the bytes comprising e
            Array.Reverse(eBytes); //reverses the array to match the little endianness of machines
            int e = BitConverter.ToInt32(eBytes); //translates the bytes to an int

            byte[] EBytes = new byte[e]; //creates empty array to be filled later of size e
            Array.Copy(raw, 4, EBytes, 0, e); //fills array with e bytes comprising of E
            BigInteger E = new(EBytes); //translates the bytes to an int

            Array.Copy(raw, e + 4, nBytes, 0, 4);
            Array.Reverse(nBytes);
            int n = BitConverter.ToInt32(nBytes);

            byte[] NBytes = new byte[n];
            Array.Copy(raw, 8 + e, NBytes, 0, n);
            BigInteger N = new(NBytes);

            key.e = e; //stores the components calculated into the KeyClass object provided
            key.n = n;
            key.N = N;
            key.E = E;
        }

        /// <summary>
        /// given a number of bits to use, will generate a public and private key, and store those into local files private.key and public.key
        /// </summary>
        /// <param name="bits"> the number of bits to comprise the key </param>
        static void genKey(int bits)
        {
            Random rnd = new Random();
            int lower = Convert.ToInt32((bits/2) * 0.75); // ensures that p is +/- 25% of 1/2 of n
            int higher = Convert.ToInt32(bits * 1.25); 
            int p_bytes = rnd.Next(lower, higher); 
            int q_bytes = 1024 - p_bytes; //ensures that p + q = bits

            BigInteger p = NumberGen.primeGen(p_bytes); //generates p and q
            BigInteger q = NumberGen.primeGen(q_bytes);
            BigInteger n = p * q;
            BigInteger t = (p - 1) * (q - 1);

            int e1 = rnd.Next(64, 256); //generates a random relatively small prime
            BigInteger e = NumberGen.primeGen(e1);
            BigInteger d = modInverse(e, t); //generates the inverse of the prime

            byte[] bPubKey = new byte[e.GetByteCount() + n.GetByteCount() + 8]; //creates empty arrays to be filled later
            byte[] bPrKey = new byte[d.GetByteCount() + n.GetByteCount() + 8];

            byte[] bE = e.ToByteArray(); //filles byte arrays with their associated bigint values
            byte[] bD = d.ToByteArray();
            byte[] bN = n.ToByteArray();

            int ce = e.GetByteCount(); //gets the length of the bigint values
            int cd = d.GetByteCount();
            int cn = n.GetByteCount();

            byte[] be = BitConverter.GetBytes(ce); //gets the byte[] version of the length of the bigint values
            byte[] bd = BitConverter.GetBytes(cd);
            byte[] bn = BitConverter.GetBytes(cn);

            Array.Reverse(be); //makes the lengths big endian for some god forsaken reason. Seriously. Why?
            Array.Reverse(bd);
            Array.Reverse(bn);

            Array.Copy(bd, 0, bPrKey, 0, 4); //filles the private key byte array with appropriate values
            Array.Copy(bD, 0, bPrKey, 4, cd);
            Array.Copy(bn, 0, bPrKey, 4 + cd, 4);
            Array.Copy(bN, 0, bPrKey, 8 + cd, cn);

            Array.Copy(be, 0, bPubKey, 0, 4); //fills the public key byte array with appropriate values
            Array.Copy(bE, 0, bPubKey, 4, ce);
            Array.Copy(bn, 0, bPubKey, 4 + ce, 4);
            Array.Copy(bN, 0, bPubKey, 8 + ce, cn);

            PrivateKeyStorage prkey = new PrivateKeyStorage //creates a new private key class object to store the generated values
            {
                key = Convert.ToBase64String(bPrKey)
            };

            KeyStorage pubkey = new KeyStorage //creates a new public key class object to store the generated values
            {
                key = Convert.ToBase64String(bPubKey)
            };

            string privateKey = JsonSerializer.Serialize(prkey); //serializes the objects into json format for storage
            string publicKey = JsonSerializer.Serialize(pubkey);


            string fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory); //the file to write to
            using (StreamWriter outputFile = new(fileName))
            {
                outputFile.WriteLine(privateKey); //writes the json into the file
            }

            fileName = String.Format(@"{0}\public.key", Environment.CurrentDirectory); //the file to write to
            using (StreamWriter outputFile = new(fileName))
            {
                outputFile.WriteLine(publicKey); //writes the json into the file
            }

        }

        /// <summary>
        /// gets a message for the given email address
        /// </summary>
        static async Task getMsg()
        {
            MsgClass? MSG = await client.GetFromJsonAsync<MsgClass>(MURI + email); //gets the message object from the server

            string b64key = checkEmails(email); //checks to see if the use has the appropriate private key
            if (b64key != "False")
            {
                byte[] bmsg = Convert.FromBase64String(MSG.content); //converts the message from base 64 string to a byte array for further use
                KeyClass keyC = new KeyClass();
                keySolver(keyC, b64key); //solves the key so it can be used
                string Message = RSA(keyC.E, keyC.N, bmsg); //decodes the message
                Console.WriteLine(Encoding.UTF8.GetString(bmsg)); //prints the message
            }
            else
            {
                Console.WriteLine("This message can't be decoded.");
            }
        }

        /// <summary>
        /// helper function to check if the user has the given email as a private key to use
        /// </summary>
        /// <param name="email"> the email to check for</param>
        /// <returns> the private key if it exists, and 'False' otherwise </returns>
        static string checkEmails(string email)
        {
            try
            {
                string fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory); //the file to check
                using (StreamReader sr = new(fileName))
                {
                    string json = sr.ReadToEnd(); //grabs the json from the file
                    PrivateKeyStorage? priv = JsonSerializer.Deserialize<PrivateKeyStorage>(json); //turns the json into a private key storage class for use
                    string[] emails = priv.email; //checks all of the emails saved to see if there is a match
                    foreach (string s in emails)
                    {
                        if (s.Equals(email)) //if there is a match, return the private key
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

        /// <summary>
        /// sendKey sends the generated key from genKey to the server with the user's given email, then updates the private.key file to show that the email is one that the user has
        /// </summary>
        static async Task sendKey()
        {
            PrivateKeyStorage privateKey; //creates an empty object so we can keep our progress between steps

            string fileName = String.Format(@"{0}\public.key", Environment.CurrentDirectory); //the file to send
            using (StreamReader sr = new(fileName))
            {
                string json = sr.ReadToEnd(); //grabs the json for use

                KeyStorage? pubKey = JsonSerializer.Deserialize<KeyStorage>(json); //turns the json into a key storage class so we can add the email to it
                pubKey.email = email; //adds the users email to the object to send

                await client.PutAsJsonAsync<KeyStorage>(KURI + email, pubKey); //sends the key file to the server
            }

            fileName = String.Format(@"{0}\private.key", Environment.CurrentDirectory); //the file to update the emails for
            using (StreamReader sr = new(fileName))
            {
                string json = sr.ReadToEnd(); //grabs the json for use

                PrivateKeyStorage? privKey = JsonSerializer.Deserialize<PrivateKeyStorage>(json); //turns the json into a private key class

                if (privKey.email is not null) {
                    privKey.email.Append(email); // if there is already an email there, appends the new one to the list
                }
                
                else
                {
                    string[] emails = new string[1]; //if there isn't an email already there, then we add add one
                    emails[0] = email;
                    privKey.email = emails;
                }

                privateKey = privKey; //updates our object with our current progress of an updated name
            }

            string Js = JsonSerializer.Serialize<PrivateKeyStorage>(privateKey); //the file to update
            using (StreamWriter sw = new(fileName))
            {
                sw.WriteLine(Js); //writes our new json object into the file
            }

            Console.WriteLine("Key saved");
        }

        /// <summary>
        /// sendMsg sends an encrypted base 64 message to the server
        /// </summary>
        /// <param name="msg"> the messaage to send </param>
        static async Task sendMsg(string msg)
        {
            string fileName = String.Format(@"{0}\" + email + ".key", Environment.CurrentDirectory); //the file where we can find the public key
            if (File.Exists(fileName)) //if the file doesn't exist, then we don't have the public key to use, so end
            {
                using (StreamReader sr = new(fileName))
                {
                    string json = sr.ReadToEnd(); //grabs the json

                    KeyStorage? keyC = JsonSerializer.Deserialize<KeyStorage>(json); //puts the json into a key storage object

                    string key = keyC.key; //grabs the key for easy access
                    KeyClass keyClass = new KeyClass(); //creates an empty keyClass for keySolver
                    keySolver(keyClass, key); //solves the key

                    byte[] bmsg = Encoding.UTF8.GetBytes(msg); //grabs the bytes from the message
                    string pmsg = RSA(keyClass.E, keyClass.N, bmsg); //encodes the message
                    byte[] bpmsg = Encoding.UTF8.GetBytes(msg); //grabs the bytes from the encoded message
                    string b64msg = Convert.ToBase64String(bmsg); //encodes the encoded message in base 64

                    MsgClass MSG = new MsgClass() //creates a message object to send tot he server
                    {
                        email = email,
                        content = b64msg
                    };

                    var response = await client.PutAsJsonAsync<MsgClass>(MURI + email, MSG); //sends the message to the server

                    if (response.IsSuccessStatusCode) //if the server accepts the message let the user know
                    {
                        Console.WriteLine("Message written");
                    }
                    else //if the server rejects the message, inform the user
                    {
                        Console.WriteLine("The server returned a error");
                    }
                }
            }
            else
            {
                Console.WriteLine("Key does not exist for " + email);
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

        /// <summary>
        /// does RSA encryption on a byte array and returns a plaintext message
        /// </summary>
        /// <param name="e"> the e/d value for use in RSA </param>
        /// <param name="n"> the n value for use in RSA </param>
        /// <param name="bmsg"> the message to en/decrypt </param>
        /// <returns> a plaintext en/decrypted message </returns>
        static string RSA(BigInteger e, BigInteger n, byte[] bmsg)
        {
            BigInteger MSG = new(bmsg); //creates a big int from the message

            MSG = BigInteger.ModPow(MSG, e, n); //RSA encryption

            bmsg = MSG.ToByteArray(); // turns the encrypted big int into a byte array

            string msg = BitConverter.ToString(bmsg); //turns that byte array into a plaintext string

            return msg;
        }
    }

    /// <summary>
    /// a random number generator class for use in creating prime numbers
    /// </summary>
    class NumberGen
    {
        private static readonly object ConsoleLock = new object();

        /// <summary>
        /// generates a random number for big ints
        /// </summary>
        /// <param name="bits"> the number of bits to use</param>
        /// <returns> the new big int </returns>
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
        /// <summary>
        /// generates a prime number using big ints
        /// </summary>
        /// <param name="bits"> the number of bits to use </param>
        /// <returns> the big integer created </returns>
        static public BigInteger primeGen(int bits)
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
        /// <summary>
        /// checks if a number is prime
        /// </summary>
        /// <param name="value"> the number to check </param>
        /// <param name="k"> the number of passes to do </param>
        /// <returns> true if it is prime, false if not </returns>
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
        /// <summary>
        /// a helper function to calculate a
        /// </summary>
        /// <param name="value"> the value to calculate a for</param>
        /// <returns> a </returns>
        static private BigInteger aCalc(BigInteger value)
        {
            BigInteger a;
            a = NumberGen.generator(value.GetByteCount() - 1);
            return a;
        }
        /// <summary>
        /// a helper function to calculate n
        /// </summary>
        /// <param name="value"> the number to calculate n for </param>
        /// <returns> the r and d values </returns>
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