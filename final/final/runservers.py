import subprocess

subprocess.call(['python3 ecdsaserver.py &'], shell=True)
subprocess.call(['python3 rsaserver.py &'], shell=True)
subprocess.call(['python3 eddsaserver.py &'], shell=True)
subprocess.call(['python3 dssserver.py &'], shell=True)

