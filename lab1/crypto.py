#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: 631
Name: <Erdei Julia Annegret>
SUNet: <ejam0390>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    titkos_szoveg  = ""
    for karakter in plaintext:
        if karakter.isalpha():
            eltolas = ord(karakter) - ord('A') + 3
            ujkar = chr((eltolas % 26) + ord('A'))
            titkos_szoveg += ujkar
        else:
            titkos_szoveg += karakter
    return titkos_szoveg


def decrypt_caesar(ciphertext):
    eredeti_szoveg  = ""

    for karakter in ciphertext:
        if karakter.isalpha():
            eltolas = ord(karakter) - ord('A') - 3
            ujkar = chr((eltolas % 26) + ord('A'))
            eredeti_szoveg += ujkar
        else:
            eredeti_szoveg += karakter

    return eredeti_szoveg



# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    titkos_szoveg = ""
    kulcshossza = len(keyword)

    for i, karakter in enumerate(plaintext):
        e_ertek = ord(karakter) - ord('A')
        k_ertek = ord(keyword[i % kulcshossza]) - ord('A')

        ujkar = (e_ertek + k_ertek) % 26
        titkos_szoveg += chr(ujkar + ord('A'))

    return titkos_szoveg

def decrypt_vigenere(ciphertext, keyword):
    eredeti_szoveg = ""
    kulcshossza = len(keyword)

    for i, karakter in enumerate(ciphertext):
        t_ertek = ord(karakter) - ord('A')
        k_ertek = ord(keyword[i % kulcshossza]) - ord('A')

        ujkar = (t_ertek - k_ertek) % 26
        eredeti_szoveg += chr(ujkar + ord('A'))

    return eredeti_szoveg



# Scytale Cipher

def encrypt_scytale(plaintext, circumference):
    titkos_szoveg = ""
    hossz = len(plaintext)
    oszlopok = hossz// circumference  
    for i in range(circumference):
        for j in range(oszlopok + 1):
            index = i + j * circumference
            if index < hossz:
                titkos_szoveg += plaintext[index]

    return titkos_szoveg
    
def decrypt_scytale(ciphertext, circumference): 
    eredeti_szoveg = ""
    hossz = len(ciphertext)
    oszlopok = hossz// circumference

    plaintext = [''] * hossz
    k = 0
    for i in range(circumference):
        for j in range(oszlopok + 1):
            index = i + j * circumference
            if index < hossz:
                plaintext[index] = ciphertext[k]
                k += 1

    eredeti_szoveg = ''.join(plaintext)
    return eredeti_szoveg


# Railfence Cipher

def encrypt_railfence(plaintext, num_sin):
    sinek = [""] * num_sin
    index = 0
    lefelé = True

    for betu in plaintext:
        sinek[index] += betu

        if index == 0:
            lefelé = True
        elif index == num_sin - 1:
            lefelé = False

        if lefelé:
            index += 1
        else:
            index -= 1

    titkos_szoveg = "".join(sinek)
    return titkos_szoveg

def decrypt_railfence(ciphertext, num_sin):
    hossz = len(ciphertext)
    sin_hosszak = [0] * num_sin
    index = 0
    lefelé = True

    for i in range(hossz):
        sin_hosszak[index] += 1
        
        if index == 0:
            lefelé = True
        elif index == num_sin - 1:
            lefelé = False
            
        if lefelé:
            index += 1
        else:
            index -= 1
    
    sinek = []
    aktualis_pozicio = 0
    for sin_hossz in sin_hosszak:
        sinek.append(ciphertext[aktualis_pozicio:aktualis_pozicio + sin_hossz])
        aktualis_pozicio += sin_hossz

    eredeti_szoveg = ""
    sin_poziciok = [0] * num_sin
    index = 0
    lefelé = True
    
    for i in range(hossz):
        eredeti_szoveg += sinek[index][sin_poziciok[index]]
        sin_poziciok[index] += 1
        
        if index == 0:
            lefelé = True
        elif index == num_sin - 1:
            lefelé = False
            
        if lefelé:
            index += 1
        else:
            index -= 1
            
    return eredeti_szoveg


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):    
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    raise NotImplementedError  # Your implementation here

def encrypt_mh(message, public_key):
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    raise NotImplementedError  # Your implementation here


if __name__ == "__main__":
    # 1. Caesar teszt
    print("\nCaesar teszt:")
    eredeti = "HELLO WORLDX!  100"
    titkos = encrypt_caesar(eredeti)
    visszafejtett = decrypt_caesar(titkos)
    print(f"Eredeti szöveg: {eredeti}")
    print(f"Titkosított szöveg: {titkos}")
    print(f"Visszafejtett szöveg: {visszafejtett}")
    
    # 2. Vigenere teszt
    print("\nVigenere teszt:")
    eredeti = "ERDEIJULIAANNEGRET"
    kulcs = "KEY"
    titkos = encrypt_vigenere(eredeti, kulcs)
    visszafejtett = decrypt_vigenere(titkos, kulcs)
    print(f"Eredeti szöveg: {eredeti}")
    print(f"Kulcsszó: {kulcs}")
    print(f"Titkosított szöveg: {titkos}")
    print(f"Visszafejtett szöveg: {visszafejtett}")

    # 3. Scytale teszt
    print("\nScytale teszt:")
    eredeti = "MINDENHOLJODELEGJOBBOTTHON"  # 26 karakter hosszú
    #eredeti = "EDDMEGABANANT" 
    kerulet = 5
    titkos = encrypt_scytale(eredeti, kerulet)
    visszafejtett = decrypt_scytale(titkos, kerulet)
    print(f"Eredeti szöveg: {eredeti}")
    print(f"Titkosított szöveg: {titkos}")
    print(f"Visszafejtett szöveg: {visszafejtett}")

    # 4. Railfence teszt
    print("\nRailfence teszt:")
    eredeti = "EDDMEGABANANT"
    num_sin = 4
    titkos = encrypt_railfence(eredeti, num_sin)
    visszafejtett = decrypt_railfence(titkos, num_sin)
    print(f"Eredeti szöveg: {eredeti}")
    print(f"Titkosított szöveg: {titkos}")
    print(f"Visszafejtett szöveg: {visszafejtett}") 
    
