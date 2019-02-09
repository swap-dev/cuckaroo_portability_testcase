﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

class Program
{
	static void Main(string[] args)
	{
		byte[] packedSolution = new byte[128] { 
			0x1D,0xEF,0x7B,0x00,0x1C,0xCC,0xD8,0x00,0x14,0xDD,0x3E,0x04,0x4D,0x36,0x33,0x05,0xCF,0xB5,0x06,0x06,0x2B,
			0x5E,0x9C,0x06,0xA2,0xA6,0x14,0x09,0x72,0xC9,0x9B,0x09,0x9B,0xB9,0x6E,0x0A,0x93,0xDC,0xA9,0x0B,0xDC,0x45,
			0xFF,0x0B,0xF3,0xDB,0x85,0x0C,0xD3,0xBF,0xB2,0x12,0x60,0x07,0x24,0x13,0xC7,0x7A,0x69,0x13,0x8E,0x0D,0x6B,
			0x13,0xE4,0x56,0xC5,0x13,0x02,0xE6,0xF7,0x13,0x37,0xA0,0x90,0x15,0xAA,0x7E,0xD8,0x15,0x74,0xF5,0xA0,0x16,
			0x9D,0x35,0x21,0x17,0x77,0xD0,0xAF,0x17,0x6F,0xE3,0xD2,0x17,0xD2,0x89,0x14,0x18,0x74,0xF8,0x48,0x18,0x9D,
			0xDD,0xFF,0x19,0xDA,0x32,0x32,0x1A,0xCC,0xA3,0x79,0x1C,0xE3,0x93,0x0C,0x1E,0x27,0x3E,0x67,0x1E,0x34,0x4C,0x5D,0x1F
		};
		Console.Write(BitConverter.ToString(packedSolution));
		Console.WriteLine();
		Console.WriteLine();



		var hash = new Crypto.Blake2B(256);

		var hashedBytes = hash.ComputeHash(packedSolution).Reverse().ToArray();

		Console.Write(BitConverter.ToString(hashedBytes));
		Console.WriteLine();

		Environment.Exit(0);
	}
}