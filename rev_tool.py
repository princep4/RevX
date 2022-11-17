from ciphey import decrypt
from ciphey.iface import Config
# for creating process and for calculating time
from multiprocessing import Process
import time
import subprocess

# Timeout setup handler
#import signal
import sys

#bring out all the strings from the exe
def read_file():
    strings_file=open("strings.txt", "w")
    subprocess.call(["strings","-n","8",sys.argv[1]], stdout=strings_file)
    strings_file.close()

    stringsread=open("strings.txt",'r')
    lines=stringsread.readlines()
    count = 0

    try:
        for line in lines:
            action_process = Process(target=decrypt_text, args=(line,)) # line is  passed to the function
            action_process.start()
            action_process.join(timeout=5)
            action_process.terminate()      
    except:
        print("exception")
    #print(count)


#function to decrypt the text
def decrypt_text(line):
    #print("hello")
    print("Encrypted word:",line)
        # print(count)
        #signal.alarm(10)
    res = decrypt(
        Config().library_default().complete_config(),
        line,
    )
    print("Decrypted word: ",res)
 
#Yara rules checking code   
def yara():
    print("print yara")



# Ask for choice 1. find encoded values and decode it  2. YARA rules check
# ---------- MAIN START -------------------

print("Enter your choice")
print("1. find encoded values and decode it")
print("2. YARA rules check")
x=input("choice: ")

if x=='1':
    # call the read file and run decrypt function
    read_file()
elif x=='2':
    yara()
    





