all: cuckaroo cyclehash cyclehash.exe

cuckaroo: cuckaroo.c blake2b-ref.c
	gcc cuckaroo.c blake2b-ref.c -o cuckaroo
cyclehash: cyclehash.c blake2b-ref.c 
	gcc cyclehash.c blake2b-ref.c -o cyclehash
cyclehash.exe: cyclehash.cs Blake2B.cs
	mcs cyclehash.cs Blake2B.cs
