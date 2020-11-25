import subprocess

subprocess.call(['python3 rsaclient.py &'], shell=True)
subprocess.call(['python3 dssclient.py &'], shell=True)
subprocess.call(['python3 ecdsaclient.py &'], shell=True)
subprocess.call(['python3 eddsaclient.py &'], shell=True)


