#!/usr/bin/env python3

import sys, os, subprocess

def convert_private_keys():
    
    # Parse the entire folder
    for source_file in os.listdir("."):

            # Check for all keys
            if source_file.endswith(".key"):

                 # Convert the key using OpenSSL.exe
                 target_file = os.path.splitext(source_file)[0] + ".txt"
                 print("%s --> %s" % (source_file, target_file))
                 subprocess.Popen(["openssl.exe", "rsa", "-inform", "MS\\PRIVATEKEYBLOB", "-in", source_file, "-outform", "PEM", "-out", target_file, "-traditional"])


if __name__ == '__main__':

    save_folder = os.path.abspath(".")
    folder_list = os.listdir(save_folder)
    for folder_name in folder_list:
        full_path = os.path.join(".", folder_name)
        full_path = os.path.abspath(full_path)
        if os.path.isdir(full_path):
            os.chdir(full_path)
            convert_private_keys()
            os.chdir(save_folder)
