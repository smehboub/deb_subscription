# deb_subscription

>It's a tool for to add katello repositories to debian host and to register debian host to katello"    
>This tool work with python2 or python3   
>Tested with Python 2.7.13 and Python 3.5.3 on Debian 9   

## Installation and Use
```
apt update   
apt install -y apt-transport-https gnupg  
apt install python-pip 

# add to /etc/hosts
# <ip_katello> <fqdn_katello>

pip install deb-subscription   

deb_subscription --fqdn katello.domain.tld --organization ORG --location LOC --activation_key ACT_KEY --username admin --password xxxxxxxx   
```
