import wget
import time
import os
for line in open("all.txt","r").readlines():
    wget.download("https://amad3us47.github.io/data/"+line)
    print("using "+line+"template")
    os.system("nuclei -u flipkart.com -o bugs.txt -t "+line)
    directory=os.getcwd()
    line=line.rstrip('\n')
    os.remove(directory+"/"+line)
