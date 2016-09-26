#!/usr/bin/python
import subprocess


build = 'docker build . -f Dockerfile_web'
# http://stackoverflow.com/questions/36489696/cannot-link-to-a-running-container-started-by-docker-compose
run = 'docker run -p "8000:8000" --link "dnsserver_postgresql_1:postgresql" --volumes-from "dnsserver_postgresql_1" ' \
      '--net dnsserver_default {}'
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
