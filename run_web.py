#!/usr/bin/python
import os
import subprocess


cwd = os.getcwd()
build = 'docker build . -f Dockerfile_web'
run = 'docker run -p "8000:8000" -v {}:/code {}'
kill = 'docker kill {}'

image = subprocess.check_output(build, shell=True).strip().split('\n')[-1].split()[-1]
print(image)
try:
    subprocess.call(run.format(cwd, image), shell=True)
except KeyboardInterrupt:
    print("\nKeyboardInterrupt")
    container = [group.split()[0]
                 for group in subprocess.check_output('docker ps', shell=True).strip().split('\n')[1:]
                 if group.split()[1] == image][0]
    subprocess.call(kill.format(container), shell=True, stdout=open('/dev/null'))
    print("Terminated {}".format(container))
