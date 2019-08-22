#to create virtualenv
#pip install virtualenv
#to create to a virtualenv
#virtualenv <virtualenvname>
#activate virtualenv
# for windows: envname\scripts\activate
# for linux: source envname\bin\activate
from telethon import TelegramClient, events, sync, errors
from telethon import utils
from telethon.tl.types import InputPeerChat
import hashlib
import random
import sqlite3
import os
#from _winreg import *
import errno, os
#import winreg
import getpass
#import telegram-messages-dump
import subprocess as sp
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
def log_this(filename,message):
    fp = open(os.getcwd() + "/" + filename,'a',encoding="utf-8")
    fp.write(message+"\n")
    fp.close()
'''
Grab your API ID and API HASH at https://my.telegram.org/auth
'''
#????????????????????????????????????????????????????////////////////////////////////////////////////////////////////////////////////////////////
def try2():
    import time as t
    t#.sleep(100) # to avoid to much frequent login
    x=input("Enter the name of the chat")
    y=input("enter the phone number using extension code")
    #z=("mss.txt".format(x))
    #os.system("python -m telegram_messages_dump -c x -p y -o z")
    sp.call(["sudo","telegram-messages-dump","-c",x,"-p",y,"-o","chat.txt"])
#?????????????????????????????????////////////////////////////////////////////////////////////////////////////////////////////////////////////////
z=0
def web():
    api_id = 705019 # INSERT YOUR API ID HERE
    api_hash = 'ef7626a98a33f955da8b317f8f580065' # INSERT YOUR API HASH HERE
    session_name = input("[i] Enter any previous session name or press enter to create a new session: ")
    if not session_name:
        session_name = hashlib.md5(str(random.randint(100000,999999)).encode()).hexdigest()
    fname = session_name+".txt"
    fp = open(os.getcwd() + "/" + fname,'w',encoding="utf-8")
    fp.close()
    print()
    client = TelegramClient(session_name, api_id, api_hash)
    client.start()
    print("[i] SESSION NAME:",session_name)
    print()
    global z
    while True:
        try:
            if z==2:
                print("#"*60)
                try2()
                break
            else:
                z+=1
                print("z",z)
                for dialog in client.get_dialogs():
                    contact_name = str(utils.get_display_name(dialog.entity))
                    print("[i] Extracting chats from {}..".format(contact_name),end="")
                    log_this(fname,"\n-----------------------------------------------------")
                    log_this(fname,contact_name+"\n-----------------------------------------------------")
                    chat_id = client.get_entity(utils.get_display_name(dialog.entity)).id
                    for msg in client.iter_messages(chat_id, reverse=True):
                        if msg.message:
                            temp = str(utils.get_display_name(msg.sender)+" => "+msg.message)
                            log_this(fname,temp)
                        else:
                            temp = str(utils.get_display_name(msg.sender)+" => None")
                            log_this(fname,temp)
                    log_this(fname,"\n-----------------------------------------------------")
                    print("DONE !!")
                #break
        except Exception as e:
            print(e)
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# def regis():
#     import errno, os, winreg
#     proc_arch = os.environ['PROCESSOR_ARCHITECTURE'].lower()
#     proc_arch64 = os.environ['PROCESSOR_ARCHITEW6432'].lower()

#     if proc_arch == 'x86' and not proc_arch64:
#         arch_keys = {0}
#     elif proc_arch == 'x86' or proc_arch == 'amd64':
#         arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
#     else:
#         raise Exception("Unhandled arch: %s" % proc_arch)

#     for arch_key in arch_keys:
#         key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | arch_key)
#         for i in range(0, winreg.QueryInfoKey(key)[0]):
#             skey_name = winreg.EnumKey(key, i)
#             skey = winreg.OpenKey(key, skey_name)
#             try:
#                 return (winreg.QueryValueEx(skey, 'DisplayName')[0])
#             except OSError as e:
#                 if e.errno == errno.ENOENT:
#                     # DisplayName doesn't exist in this skey
#                     pass
#             finally:
#                 skey.Close()
def local():
    
    #aReg=winreg.connectKey(None,HKEY_LOCAL_MACHINE)
    a=0
    username = getpass.getuser()
    try:
        c=os.listdir((r'C:\Users\{}\AppData\Roaming\Telegram Desktop\tdata\dumps').format(username))
        # default istallade location
        a=len(os.listdir((r'C:\Users\{}\AppData\Roaming\Telegram Desktop\tdata\dumps').format(username)))
        if len(os.listdir((r'C:\Users\{}\AppData\Roaming\Telegram Desktop\tdata\dumps').format(username)))==0:
            print("Directory is empty,trying in other Directory>>>>>>>>>>>")
        else:
            print("got saved data....file name are {}".format(c))
    except:
        return 0
    finally:
        if a==0:
            print("no saved data found")
            print("going to get data from server")
            y=input("data encryption complete ........ press 1 to get data from server")
            if y=="1":
                xz=input("enter 1 for all chat and enter 2 spefic chat")
                if xz==1:
                    web()
                else:
                    try2()
            else:
                quit()
        # if regis()!=0:
        #     print("got some data",regis)
if __name__ == '__main__':
    local()