import subprocess
import time

subprocess.Popen(["python", "Groupscanbot.py"])
subprocess.Popen(["python", "Mainscan.py"])

while True:
    time.sleep(60)
