#!/usr/bin/python
import subprocess


build = 'docker build . -f Dockerfile_proxy'
run = 'docker run -p "80:80" -p "443:443" --dns="8.8.4.4" --dns "8.8.8.8" {}'
kill = 'docker kill {}'

image = subprocess.check_output(build, shell=True).strip().split('\n')[-1].split()[-1]
print(image)
try:
    subprocess.call(run.format(image), shell=True)
except KeyboardInterrupt:
    print("\nKeyboardInterrupt")
    container = [group.split()[0]
                 for group in subprocess.check_output('docker ps', shell=True).strip().split('\n')[1:]
                 if group.split()[1] == image][0]
    subprocess.call(kill.format(container), shell=True, stdout=open('/dev/null'))
    print("Terminated {}".format(container))
