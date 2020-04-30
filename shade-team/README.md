We are the team which created a trojan-encryptor mostly known as Shade, Troldesh or Encoder.858.
In fact, we stopped its distribution in the end of 2019.
Now we made a decision to put the last point in this story and to publish all the decryption keys we have (over 750 thousands at all).
We are also publishing our decryption soft; we also hope that, having the keys, antivirus companies will issue their own more user-friendly decryption tools.
All other data related to our activity (including the source codes of the trojan) was irrevocably destroyed.
We apologize to all the victims of the trojan and hope that the keys we published will help them to recover their data.



MIRRORS FOR DOWNLOADING:

* https://yadi.sk/d/36uVFJ6bUBrdpQ					(all the keys separately; all the keys in a zip; software)
* https://cloud.mail.ru/public/5gy6/4UMfYqAp4     			(all the keys separately; all the keys in a zip; software)
* https://drive.google.com/open?id=1iA2KquslytIE83mwzlXPcL3u8Z0yoqat	(all the keys in a zip; software)
* https://github.com/shade-team/keys 					(all the keys separately)
* https://github.com/shade-binary/bin 					(software)



DECRYPTION INSTRUSTIONS:

Note: Some of the published software is detected by some antiviruses because it uses common code blocks with the encryptor.
To avoid the deletion of them all the exe files were zipped with the same password: 123454321

If your encrypted files have one of the following extensions then you will need "main" subfolder from "keys" folder during the further steps:
* xtbl
* ytbl
* breaking_bad
* heisenberg
* better_call_saul
* los_pollos
* da_vinci_code
* magic_software_syndicate
* windows10
* windows8
* no_more_ransom
* tyson
* crypted000007
* crypted000078
* rsa3072
* decrypt_it

If your encrypted files have one of the following extensions then you will need "alt" subfolder from "keys" folder during the further steps:
* dexter
* miami_california

The subfolder which you need is denoted as &lt;dir&gt; in the following.
The "master" subfolder is for some antivirus companies, they were already instructed about it.

0. It's highly recommended to close all the programs (including antivirus ones) on your computer and avoid of performing any other actions during the decryption process.
If you have your computer's ID go to paragraph 1. Otherwise go to paragraph 2.
This ID is a 20-symbol string containing upper-case letters and digits (e. g. AABBCCDDEEFF00112233) and was saved in README.txt files on the desktop and in the root folders of all disks.
ID was also added after the file's name in the latter versions of the encryption software.

1. If the code from README.txt file contains zero after the vertical bar (e. g. AABBCCDDEEFF00112233|0), proceed with paragraph 1.1.
If the code from README.txt file contains three vertical bars (e. g. AABBCCDDEEFF00112233|765|8|1), proceed with paragraph 1.2.

1.1 Enter /keys/&lt;dir&gt;/dynamic/&lt;letter&gt;/ folder where &lt;letter&gt; is the first symbol of your code (A in our example).
/keys/alt/dynamic/ folder contains all the files together without the division by codes' first letters.
Find the .txt file which name contains your ID and download it (if there is more than one such file download all of them and repeat the whole decryption procedure with each of them).
You can use the search on the web page (Ctrl+F combination in your browser) to speed up the search process.
If the file(s) was found, proceed with paragraph 3.

1.2 Enter /keys/&lt;dir&gt;/static/ folder and find the file which name is the number after the first vertical bar of your code (765 in our example).
Download it and proceed with paragraph 3.

2. Download and execute /bin/getid.exe program. It will show you the ID, then you should go to paragraph 1 with it.
If it does not help try to perform the instructions from 2.1 paragraph.

2.1 Create a folder on your computer which path contains only english letters or digits (c:\1\ in the further instructions).
Download the file /bin/decrypt_bruteforce.exe, save it to this folder and create the folder "keys" there.
Then download all the files from /keys/&lt;dir&gt;/static/ folder and place them inside "keys" folder.
Take any of your encrypted files and place it into c:\1\ folder.
Run decrypt_bruteforce.exe and wait for the end of its work. If the key was found its filename would be shown in the window. Take the key file and proceed with paragraph 3.

3.  Create a folder on your computer which path contains only english letters or digits (c:\decrypt\ in the further instructions).
Download /bin/decrypt.exe file and save it to this folder.
You can also use /bin/decrypt_nolog.exe program instead (the only difference is that it shows less detailed information about the decryption process).
Then take a file with the key which you got during the previous steps and place it in this directory with "key.txt" name (or just "key" if your system does not display file extensions).
If the encrypted files are located on your computer then just run decrypt.exe.
If the encrypted files are located on the external drive then connect it, press Start-&gt;Execute-&gt;(input) cmd.exe and press Enter.
Type the following command in the window which opened and press Enter:
cd c:\decrypt\ && decrypt.exe &lt;path&gt;
where &lt;path&gt; is the root directory of the device you connected (e. g. S:\).
Wait until the end of the decryption process.
If you find the file with the name RENAME.txt in the folder with the decryptor then download /bin/rename.exe, place it into this folder, run it and wait until the end of its work.


If you have any difficulties we advice you to wait until the antivirus companies release more convenient utilities for the decryption.
Or you can ask for the free help on one of the thematic forums.
