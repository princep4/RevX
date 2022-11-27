from ciphey import decrypt
from ciphey.iface import Config
# for creating process and for calculating time
from multiprocessing import Process
import time
import subprocess

from colorama import init
from termcolor import colored
 
init()
 
#print(colored('Hello, World!', 'green', 'on_red'))

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
    print("\033[0;31m Encrypted word:"+line+"\033[1;37m")
        # print(count)
        #signal.alarm(10)
    res = decrypt(
        Config().library_default().complete_config(),
        line,
    )
    print(" \033[0;32m Decrypted word: "+res+"\033[1;37m")
    
    
 
#Yara rules checking code   
def yara():
    print("print yara")
    yara_rule_path=input("Enter the path of the yara rules files : ")
    
    import yara
    from os import listdir
    from os.path import isfile, join
    onlyfiles = [f for f in listdir(yara_rule_path) if isfile(join(yara_rule_path, f))]

    from os import walk

    f = []
    for (dirpath, dirnames, filenames) in walk(yara_rule_path):
        f.extend(filenames)
        break

    # downlaod all the yara rules in one folder
    print("We found some malicious matches: \U0001F479\U0001F479\U0001F479")
    for i in f:
        s=yara_rule_path+'/'+i
        rules = yara.compile(s)
    # print(rules) 
        matches = rules.match(sys.argv[1])
        print(" \U000F27A1",matches)
    
# Evaluate the hash of file on VT    
def vt_check():
    
    print("the hash of the file")
    import sys
    import hashlib

    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(sys.argv[1], 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
    file_md5=md5.hexdigest()
    #print(file_md5)
    #print("MD5: {0}".format(file_md5))
    #print("SHA1: {0}".format(sha1.hexdigest()))
    
    params = {'apikey': 'df8fb7e710b729ebf276b1017340c8f478a3e56a5c1c01e79e22c227232935e8', 'resource':'34f8a7bf720bbfcee7a5c25c79dc9bfa'}
    headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
    response_dict={}
    try:
        response_dict = requests.get('https://www.virustotal.com/vtapi/v2/file/report', 
        params=params).json()

    except Exception as e:
            print(e)

    sample_info={}
    #print(response_dict)
    #hash_of_file=''
    if response_dict.get("response_code") != None and response_dict.get("response_code") > 0:
        # Hashes
        sample_info["md5"] = response_dict.get("md5")
        # AV matches
        #hash_of_file=sample_info["md5"]
        sample_info["positives"] = response_dict.get("positives")
        sample_info["total"] = response_dict.get("total")
        print(sample_info["md5"]+" Positives: "+str(sample_info["positives"])+"Total "+str(sample_info["total"]))
    else:
        print("Not Found in VT")
        print("The Hash of the file is: "+file_md5)
        print("I think Its secure \U0001F606")





# Ask for choice 1. find encoded values and decode it  2. YARA rules check
# ---------- MAIN START -------------------


# Make a loop asking the choices again and again
i=True
print(''' 
      
██████╗░███████╗██╗░░░██╗██╗░░██╗
██╔══██╗██╔════╝██║░░░██║╚██╗██╔╝
██████╔╝█████╗░░╚██╗░██╔╝░╚███╔╝░
██╔══██╗██╔══╝░░░╚████╔╝░░██╔██╗░
██║░░██║███████╗░░╚██╔╝░░██╔╝╚██╗
╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝ 

    By: 
    Prince Prafull \U0001F4AA| Aditya Nattu \U0001F4AA| Neeraj Uikey \U0001F4AA \n ''')
while(i):
    print("\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680\U0001F680")
    print("Enter your choice")
    print("1. find encoded values and decode it")
    print("2. YARA rules check")
    print("3. Virustotal check on the File's hash")
    print("Press n / No to exit")
    x=input("choice: ")

    if x=='1':
        # call the read file and run decrypt function
        read_file()
    elif x=='2':
        yara()
        #yara
    elif x=='3':
        vt_check()
    elif x=='n' or x=='no' or x=='No' or x=='NO':
        exit()




