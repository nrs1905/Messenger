using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using Newtonsoft.Json;
//Author: Nathaniel Shah

class KeyFile
{ 
    public int eSize { get; set; }
    public byte[] E { get; set; }
    public int n { get; set; }
    public byte[] N { get; set; }
}

class Messenger
{
    static void main(string[] args)
    {
        Random rnd = new Random();
        int p_bytes = rnd.Next(384, 640);
        int q_bytes = 1024 - p_bytes;
        BigInteger p = NumberGen.primeGen(p_bytes, 1);
        BigInteger q = NumberGen.primeGen(q_bytes, 1);
        BigInteger t = (p -1) * (q -1);
        int e1 = rnd.Next(1, 16); // 1 to 2**16 -1
        BigInteger e = NumberGen.primeGen(e1, 1);
        BigInteger d = modInverse(e, t);
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