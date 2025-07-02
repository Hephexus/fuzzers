## File Creation for Fuzzing Script
## Version 1.0

## Standard Imports
import sys, os, time, threading, random
from random import randbytes

## Custom Imports
import rich

##	------------------------------------------------------------------------------------------------
##	"Magic Bytes" for File Types
##	Executable Binaries 		Mnemonic 		Signature
##	------------------------------------------------------------------------------------------------
##	DOS Executable			"MZ"			0x4D 0x5A
##	PE32 Executable			"MZ"...."PE.."		0x4D 0x5A ... 0x50 0x45 0x00 0x00
##	Mach-O Executable (32 bit)	"FEEDFACE"		0xFE 0xED 0xFA 0xCE
##	Mach-O Executable (64 bit)	"FEEDFACF"		0xFE 0xED 0xFA 0xCF
##	ELF Executable			".ELF"			0x7F 0x45 0x4C 0x46
##	------------------------------------------------------------------------------------------------
##	Compressed Archives 		Mnemonic 		Signature
##	------------------------------------------------------------------------------------------------
##	Zip Archive			"PK.."			0x50 0x4B 0x03 0x04
##	Rar Archive			"Rar!...."		0x52 0x61 0x72 0x21 0x1A 0x07 0x01 0x00
##	Ogg Container			"OggS"			0x4F 0x67 0x67 0x53
##	Matroska/EBML Container		N/A			0x45 0x1A 0xA3 0xDF
##	------------------------------------------------------------------------------------------------
##	Image File Formats 		Mnemonic 		Signature
##	------------------------------------------------------------------------------------------------
##	PNG Image			".PNG...."		0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
##	BMP Image			"BM"			0x42 0x4D
##	GIF Image			"GIF87a"		0x47 0x49 0x46 0x38 0x37 0x61
##					"GIF89a"		0x47 0x49 0x46 0x38 0x39 0x61
##	------------------------------------------------------------------------------------------------

## Magic Bytes for different File Types
magic_dos_start = b"\x4D\x5A"
magic_p32_start = b"\x4D\x5A"
magic_p32_end = b"\x50\x45\x00\x00"
magic_mach_o_32 = b"\xFE\xED\xFA\xCE"
magic_mach_o_64 = b"\xFE\xED\xFA\xCF"
magic_elf_start = b"\x7F\x45\x4C\x46"
magic_zip_start = b"\x50\x4B\x03\x04"
magic_rar_start = b"\x52\x61\x72\x21\x1A\x07\x07\x01\x00"
magic_ogg_start = b"\x4F\x67\x67\x53"
magic_EBML_start = b"\x45\x1A\xA3\xDF"
magic_png_start = b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
magic_png_end = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"
magic_bmp_start = b"\x42\x4D"
magic_gif_87_start = b"\x47\x49\x46\x38\x37\x61"
magic_gif_89_start = b"\x47\x49\x46\x38\x39\x61"

## Random Byte Payloads
payload_bytes_1 = randbytes(4)
payload_bytes_2 = randbytes(8)
payload_bytes_3 = randbytes(16)

## Unicode Payloads
# Payload 0001: Control Characters: '\u0001\u0002\u0003\u0003\u0004\u0005\u0006\u0007\u0008\u0009'
# Payload 0002: Arabic Characters: '\u0610\u0611\u0612\u0613\u0614\u0615'
# Payload 0003: Thai Characters: '\u1714\u1734\u1772\u1773'
# Payload 0004: Limbu Characters: '\u1927\u1928\u1929\u1930\u1931\u1932\u1933\u1934\u1934\u1935\u1936\u1937'
# Payload 0005: Cyrillic Characters: '\u0483\u0484\u0485\u0486\u0487\u0488\u0489'
payload_unicode_start = "\n"
#payload_unicode_overflow = "A" * 1024
payload_unicode_overflow = '\u0610\u0611\u0612\u0613\u0614\u0615' * 1024
payload_unicode_full = (payload_unicode_start + payload_unicode_overflow)
payload_unicode_name = "Example Payload 001"

##	File Operations
##	Mode	Description			
##	r	Open a file for reading. (default)		
##	w	Open a file for writing. Creates a new file if it does not exist or truncates the file if it exists.			
##	x	Open a file for exclusive creation. If the file already exists, the operation fails.			
##	a	Open a file for appending at the end of the file without truncating it. Creates a new file if it does not exist.			
##	t	Open in text mode. (default)			
##	b	Open in binary mode.			
##	+	Open a file for updating (reading and writing)


def create_file():

	print("[+] Creating .PNG File...")
	file_bytes = open("test.png", "wb")
	file_bytes.write(magic_png_start)
	file_bytes.write(b"\n")
	file_bytes.write(payload_bytes_1)
	file_bytes.write(b"\n")
	file_bytes.write(payload_bytes_2)
	file_bytes.write(b"\n")
	file_bytes.write(payload_bytes_3)
	file_bytes.write(b"\n")
	file_bytes.write(magic_png_end)
	file_bytes.close()
	print("[+] Success!!!")

def inject_payload():

	file = open("test.png", "a")
	time.sleep(0.2)
	print("[+] Injecting Payload...")
	file.write("\n")
	file.write("\u0610\u0611\u0612\u0613\u0614\u0615")
	file.write("\n")
	file.write(payload_unicode_overflow)
	file.close()
	print("[+] Success!!!")

def menu_exploit_filetypes():
	print("[+] File Fuzzer V1 Now Starting...")
	create_file()
	inject_payload()
	print("[!] Now quitting...")	
	
	
menu_exploit_filetypes()
