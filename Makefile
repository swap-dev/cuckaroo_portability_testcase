all: cuckaroo cyclehash

cuckaroo:
	gcc cuckaroo.c blake2b-ref.c -o cuckaroo
cyclehash:
	gcc cyclehash.c blake2b-ref.c -o cyclehash
