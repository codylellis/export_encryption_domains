from datetime import datetime
import traceback
import subprocess
import os 
import sys
import json
import time
import csv
import logging
import argparse
from argparse import RawTextHelpFormatter

###Global Variables###
# bash scripting
global shell
shell = '#!/bin/bash'
global cpprofile
cpprofile = '''source /etc/profile.d/CP.sh
source /etc/profile.d/vsenv.sh
source $MDSDIR/scripts/MDSprofile.sh
source $MDS_SYSTEM/shared/mds_environment_utils.sh
source $MDS_SYSTEM/shared/sh_utilities.sh
'''
# timestamp 
global now
nowtmp = datetime.now()
now = nowtmp.strftime("%m-%d-%y_%H-%M-%S")
# filepaths
global gwpath, gwbin, gwout
gwpath = os.path.dirname(os.path.abspath(__file__))
gwbin = f'{gwpath}/scripts'
gwout = f'{gwpath}/output'

logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
            datefmt='%a, %d %b %Y %H:%M:%S',
            filename=f'{gwpath}/log.log',
            filemode='w')

class Log:
    @classmethod
    def debug(cls, msg):
        logging.debug(msg)

    @classmethod
    def info(cls, msg):
        logging.info(msg)

    @classmethod
    def error(cls, msg):
        logging.error(msg)

###Debugging Functions###
# pause script, take any input to continue 
def pause_debug():
    input("[ DEBUG ] Press any key to continue...\n\n")   

# script exit 
def end(): 
    sys.exit(0)
    
def args(): 
    parser = argparse.ArgumentParser(add_help=False,
        formatter_class=RawTextHelpFormatter,
        prog=f'python3 {os.path.basename(__file__)}',
        description='Collect Gateway Encryption Domains',
        epilog=f'''
[ Notes ] 
None. 

[ Scope ] 
For MDM environment only. 

[ Description ]
Collect networks/hosts of each encryption domain. 

[ Folders ]
Main Path: {gwpath}
script and log

Output: {gwout} 
encryption_domains.csv and .json '''
)

    parser.add_argument('-d', '--debug', action='store_true') # enable debugging in logs
    
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='')

    a = vars(parser.parse_args())
    
    global debug
    if a['debug'] is True: 
        debug = 1
    else: 
        debug = 0 


# make log directory / clear old log files
def mkdir():

    Log.info(f'[ mkdir | {gwpath} | {gwbin} | {gwout}]\n')

    if os.path.isdir(gwpath) and os.path.isdir(gwbin) and os.path.isdir(gwout):
        Log.info(f'... Exists!\n')
    else:
        Log.info(f'... Does not exist\n')
        os.system(f'mkdir -v {gwpath}')
        os.system(f'mkdir -v {gwbin}')
        os.system(f'mkdir -v {gwout}')


# create bash scripts
def runcmd(cmd, script):
    
    script = f'{gwbin}/{script}'

    bash=f"""{shell} 
{cpprofile} 
{cmd} 
exit 0
"""

    if debug == 1:
        Log.debug(f'''[runcmd]\n-----\n{bash}\n [ script]\n{script}\n-----''')

    with open(script, 'w') as f: 
        f.write(bash)

    os.system(f"chmod +x {script}")
    
    try:
        response = subprocess.check_output(script, shell=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as e:
        Log.error(traceback.print_exc())
        Log.error(f"[runcmd] : Error : {e}")

    if debug == 1: 
        Log.debug(f"[runcmd]\n-----\n{response}\n-----\n")
    
    return response


# make list of CMA IP Addresses
def domains():
    
    global domain_ips, domain_names, domain_map
    cmd = "mdsstat | grep -i cma | awk '{print $6}' | grep -v 138.108.2.29"
    domain_ips = runcmd(cmd, 'domains_ips.sh').split()
    if debug == 1:
        Log.debug(f"[ DOMAIN LIST ]\n{domain_ips}\n")
        
    cmd = "mdsstat | grep -i cma | awk '{print $4}' | grep -v TCS"
    domain_names = runcmd(cmd, 'domain_names').split()
    
    domain_map = {}
    for x,y in zip(domain_ips,domain_names): 
        domain_map[x] = y
    
    Log.info(f'Domain Mapping : {domain_map}')
        

def vpndomains(): 
    global vpngws
    vpngws = {}

    for domain in domain_ips: 
        Log.info(f'[vpndomains] : {domain_map[domain]}')
        vpngws[domain_map[domain]] = {}
        cmds = {
            'simclu' : f'mgmt_cli -r true -d {domain} show simple-clusters details-level full limit 500 --format json', 
            'simgw' : f'mgmt_cli -r true -d {domain} show simple-gateways details-level full limit 500 --format json'
        }
        for dev,cmd in cmds.items(): 
            Log.info(f'[vpndomains] : {dev}')
            gws = json.loads(runcmd(cmd, f'show_simple_{dev}_{domain}.sh'))
            if gws.get('code') == 'generic_error':
                Log.info(f'Generic Error : {domain} : {dev} : ignoring...') 
                pass
            else:
                try:
                    for gw in gws['objects']: 
                        Log.info(f"[Gateway] : {gw['name']}")
                        if gw.get('vpn') == False or gw.get('externally-managed') == True or gw.get('vpn-settings').get('vpn-domain') == None: 
                            Log.info(f'Externally Managed or no vpn-domain')
                            pass
                        else: 
                            devices = show_group(gw['vpn-settings']['vpn-domain']['name'], domain) 
                            vpngws[domain_map[domain]].update({gw['name'] : devices})
                except KeyError as e: 
                    Log.error(traceback.print_exc())
                    Log.error(f"[runcmd] : Error : {domain} : {gw['name']} {e}")
                    pass

# get json object from mgmt api
def show_group(groupName, domain):
    Log.info(f'[show_group] : {groupName}')
    groups = []
    cmd = f"mgmt_cli -r true -d {domain} show group name {groupName} details-level full --format json"
    result = runcmd(cmd, f'show_{groupName}.sh')
    groupjson = json.loads(result)
    parsed = parser(groupjson, domain)
    return parsed

# parse json object
def parser(data, domain): 
    Log.info(f'[parser] : {domain}')
    if debug == 1: 
        Log.debug(f'-----\n\n{data}\n\n-----')
        pause_debug()
    global hosts,ranges,networks
    hosts = {}
    ranges = {}
    networks = {}
    cluster = {}
    clustermember = {}
    groups = {} 
    cphost = {}

    try:
        for ip in data['members']: 
            if ip['type'] == 'host':
                hosts[ip['name']] = ip['ipv4-address']
            elif ip['type'] == 'address-range':
                ranges[ip['name']] = str(ip['ipv4-address-first']) + '-' + str(ip['ipv4-address-last'])
            elif ip['type'] == 'network':
                networks[ip['name']] = ip['subnet4'] + '/' + str(ip['mask-length4'])
            elif ip['type'] == 'cluster-member': 
                clustermember[ip['name']] = ip['ip-address']
            elif ip['type'] == 'simple-cluster': 
                for clumem in ip['cluster-members']: 
                    cluster[clumem['name']] = clumem['ip-address']
            elif ip['type'] == 'checkpoint-host': 
                cphost[ip['name']] = ip['ipv4-address']
            elif ip['type'] == 'group': 
                groups[ip['name']] = show_group(ip['name'], domain)
            else:
                Log.error(f"[parser] {domain} : Mising Object Type: {ip['name']} : {ip['type']}\n")
                Log.error(f"[parser] Screenshot and RFE to Cody Ellis\n")
    except Exception as e:
        print(f"[parser] Error: {e}\n{domain} : {ip['name']} : {ip['type']}")
        print(traceback.format_exc())
        
    pout = {} 
    for x in hosts, networks, ranges, cluster, clustermember, cphost, groups: 
        pout.update(x)
        
    return pout
    


def output(dict, fn): 
    
    fn = f'{gwout}/{fn}'
    
    # gateway command output
    with open(f'{fn}.json', 'w') as f:
        f.write(json.dumps(dict, indent=4, sort_keys=False))  
    
    # make csv of stdout information 
    fcsv = f'{fn}.csv'
    with open(fcsv, 'w') as f:
        w = csv.writer(f)
        w.writerows(dict.items())


def cleanup():
    # remove undeleted tmp scripts
    os.system(f"rm {gwbin}/*")


def main(): 
    
    # Help Menu and configuration
    args()
    
    # create direcotries
    mkdir() 
    
    # get domains list 
    domains()
    
    # get list of gateways from domains
    vpndomains()
    
    # create file
    output(vpngws, 'vpn_gateways_encryption_domain_names')


if __name__ == "__main__": 
    
    try:
        #time start
        starttime = time.time()
        Log.info(f"Start Time: {starttime}")
        cleanup() 
        main()
    except Exception as e:
        Log.error(f"[main] : Error : {e}\n")
        Log.error(traceback.print_exc())
    finally:
        end()