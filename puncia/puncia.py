import requests
import sys
import json
import time

def main():
    try:
        print("Panthera(P.)uncia [v0.12]\nSubdomain & Exploit Hunter powered by AI\n---------")
        if len(sys.argv)<2:
            sys.exit('additional command required (subdomain/exploit)')
        if len(sys.argv)<3:
            sys.exit('additional input required')
        if len(sys.argv)>4:
            sys.exit('refer usage at - https://github.com/ARPSyndicate/puncia#usage')
        time.sleep(2)
        if sys.argv[1] == 'subdomain':
            response = requests.get("http://api.subdomain.center/?domain="+sys.argv[2]).json()
            result = "\n".join(response)
            print(result)
            if len(sys.argv)==4:
                with open(sys.argv[3], "w") as f:
                    f.write(result)
        elif sys.argv[1] == 'exploit':
            response = requests.get("http://api.exploit.observer/?keyword="+sys.argv[2]).json()
            if 'entries' in response:
                result = "\n".join(response['entries'])
            else:
                sys.exit("Null Response")
            print(result)
            if len(sys.argv)==4:
                with open(sys.argv[3], "w") as f:
                    f.write(result)
        else:
            sys.exit('refer usage at - https://github.com/ARPSyndicate/puncia#usage')
    except Exception as exception:
        sys.exit(exception.__class__.__name__ + ": " + str(exception))