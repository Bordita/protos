COMPILER = gcc

COMPILERFLAGS=-Wall -pedantic

DEBUGFLAGS=-Wall -pedantic -std=c11 -fsanitize=address -g -lrt -pthread -Wno-pointer-airth

LDFLAGS=