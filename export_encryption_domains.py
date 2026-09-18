import subprocess
import time
from datetime import timedelta
from os import path, makedirs
import json
import csv
import logging
import argparse
from argparse import RawTextHelpFormatter
from textwrap import dedent
from multiprocessing import Pool, cpu_count, Manager

cwd = path.dirname(path.abspath(__file__))
out = f'{cwd}/out'

def runcmd(cmd, timeout=600):
    try:
        shell_cmd = f'source /etc/profile.d/CP.sh 2>/dev/null; {cmd}'
        cmd = ['/bin/bash', '-c', shell_cmd]
        result = subprocess.run(
            cmd, text=True, timeout=timeout, capture_output=True,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        if result.returncode != 0:
            logger.error(f'[runcmd] rc={result.returncode}\n{cmd}\n{result.stderr}')
        logger.info(f'[runcmd-stdout]{result.stdout}\n')
        return result.stdout
    except subprocess.TimeoutExpired as e:
        os.killpg(e.pid if hasattr(e, "pid") else 0, signal.SIGKILL) if False else None
        logger.exception(f'[runcmd] timeout\n{cmd}')
        return None
    except Exception:
        logger.exception(f'[runcmd]\n{cmd}')
        return None


def mp(func, items):
    """Run func(item, shared) for every item in a Pool.

    ``shared`` is a Manager dict proxy that every worker can write to.
    Returns a plain dict copy of the shared results.
    """
    with Manager() as manager:
        shared = manager.dict()
        with Pool(processes=max(1, cpu_count() // 2)) as pool:
            pool.starmap(func, [(item, shared) for item in items])
        return dict(shared)  # copy out before the manager shuts down


def create_logger():
    logger = logging.getLogger('exencdom')
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(\
        '[%(asctime)s| %(levelname)s| %(processName)s] %(message)s')
    logfile = f'{cwd}/workday.log'
    # handler = RotatingFileHandler(logfile, maxBytes=50000000, backupCount=5)
    handler = logging.FileHandler(f'{cwd}/log.log')
    handler.setFormatter(formatter)

    # this bit will make sure you won't have 
    # duplicated messages in the output
    if not len(logger.handlers):
        logger.addHandler(handler)
    return logger


# module-level logger used by runcmd() and main(); safe in workers because
# create_logger() only attaches a handler once per process
logger = create_logger()



class EXENCDOM: 
    
    def __init__(self): 
        
        makedirs(out, exist_ok=True)
        self.args()
        self.domains()
        self.vpngws = mp(self.vpndomains, self.domain_ips)
        self.output(self.vpngws, 'vpn_gateways_encryption_domain_names')
    
    def args(self): 
        parser = argparse.ArgumentParser(add_help=False,
            formatter_class=RawTextHelpFormatter,
            prog=f'python3 {path.basename(__file__)}',
            description='Collect Gateway Encryption Domains',
            epilog=dedent(f'''\
                [ Scope ] 
                Check Point Management

                [ Description ]
                Collect networks/hosts of each encryption domain. 

                [ Folders ]
                Script and Log: {cwd}
                Output: {out} 
                ''')
        )

        parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='')
        vars(parser.parse_args())





    # make list of CMA IP Addresses
    def domains(self):
        logger = create_logger()

        cmd = "mdsstat | grep -i cma | awk '{print $6}' | grep -v 138.108.2.29"
        self.domain_ips = runcmd(cmd).split()
            
        cmd = "mdsstat | grep -i cma | awk '{print $4}' | grep -v TCS"
        self.domain_names = runcmd(cmd).split()
        
        self.domain_map = {}
        for x,y in zip(self.domain_ips,self.domain_names): 
            self.domain_map[x] = y
        
        logger.info(f'Domain Mapping : {self.domain_map}')
        

    def vpndomains(self, domain, shared):
        """Worker: collect encryption domains for one CMA and store them in shared[name]."""
        logger = create_logger()
        name = self.domain_map[domain]
        logger.info(f'[vpndomains] : {name}')
        result = {}  # built locally; nested writes to a Manager dict do not propagate
        cmds = {
            'simclu' : f'mgmt_cli -r true -d {domain} show simple-clusters details-level full limit 500 --format json', 
            'simgw' : f'mgmt_cli -r true -d {domain} show simple-gateways details-level full limit 500 --format json',
            'ints' : f'mgmt_cli -r true -d {domain} show interoperable-devices details-level full --format json'
        }
        for dev,cmd in cmds.items(): 
            logger.info(f'[vpndomains] : {name} : {dev}')
            output = runcmd(cmd)
            if output is None: 
                logger.error(f'[vpndomains] {name} : {dev} : no output')
                continue
            gws = json.loads(output)
            if gws.get('code') == 'generic_error':
                logger.info(f'Generic Error : {domain} : {dev} : ignoring...') 
                continue
            try:
                for gw in gws.get('objects', []):
                    if gw is None:
                        continue
                    logger.info(f"[Gateway] : {gw['name']}")

                    devices = None
                    vpn_settings = gw.get('vpn-settings') or {}
                    vpn_domain = vpn_settings.get('vpn-domain')

                    if gw.get('type') == 'interoperable-device' and vpn_domain is not None:
                        logger.info('Interoperable')
                        devices = self.show_enc_dom(None, vpn_domain, domain)

                    elif gw.get('externally-managed') and vpn_domain is not None:
                        logger.info('Externally Managed')
                        devices = self.show_enc_dom(vpn_domain['type'], vpn_domain['name'], domain)

                    elif gw.get('vpn') is False or vpn_domain is None:
                        logger.info('No VPN')

                    else:
                        # Internally managed gateway/cluster with a VPN domain
                        devices = self.show_enc_dom(vpn_domain['type'], vpn_domain['name'], domain)

                    if devices:
                        result[gw['name']] = devices

            except KeyError as e:
                logger.exception(f'[vpndomains] : {domain} : {e}')

        shared[name] = result  # single assignment so the Manager sees it
        logger.info(f'[vpndomains] {name} : {len(result)} gateways')

    # get json object from mgmt api
    def show_enc_dom(self, TYPE, NAME, domain):
        logger = create_logger()
        logger.info(f'[show_enc_dom] : {TYPE} : {NAME}')
        
        if TYPE is None: 
            types = ['network', 'group', 'group-with-exclusion']
            try: 
                for t in types: 
                    cmd = f"mgmt_cli -r true -d {domain} show {t} name {NAME} details-level full --format json"
                    result = runcmd(cmd)
                    result = json.loads(result)
                    if result is not None: 
                        if result.get('code') != 'generic_err_object_not_found':
                            return self.parser(result,domain)
            except Exception: 
                logger.exception('[show_enc_dom interoperable]')            
        
        else: 
            cmd = f"mgmt_cli -r true -d {domain} show {TYPE} name {NAME} details-level full --format json"
            result = runcmd(cmd)
            if result is not None: 
                result = json.loads(result) 
                if result.get('code') != 'generic_err_object_not_found':
                    return self.parser(result, domain)

    # parse json object
    def parser(self, data, domain): 
        logger = create_logger()
        logger.info(f'[parser data {domain}]\n{data}')

        hosts = {}
        ranges = {}
        networks = {}
        cluster = {}
        clustermember = {}
        groups = {} 
        groupswe = {}
        cphost = {}
        

        try:
            if data['type'] == 'network':
                networks[data['name']] = data['subnet4'] + '/' + str(data['mask-length4'])
            if data['type'] == 'group-with-exclusion': 
                groupswe[data['name']] = f"NESTED GROUP : {data['include']['name']}"
            if data['type'] == 'group': 
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
                        groups[ip['name']] = 'Nested Groups'
                    else:
                        logger.error(f"[parser] {domain} : Mising Object Type: {ip['name']} : {ip['type']}\n")
                        logger.error(f"[parser] Screenshot and RFE to Cody Ellis\n")
        except Exception:
            logger.exception(f"[parser]")
            
            
        pout = {} 
        for x in hosts, networks, ranges, cluster, clustermember, cphost, groups, groupswe: 
            pout.update(x)
            
        return pout
            
    

    def output(self, dict, fn): 
        
        fn = f'{out}/{fn}'
        
        # gateway command output
        with open(f'{fn}.json', 'w') as f:
            f.write(json.dumps(dict, indent=4, sort_keys=False))  
        
        # make csv of stdout information 
        fcsv = f'{fn}.csv'
        with open(fcsv, 'w') as f:
            w = csv.writer(f)
            w.writerows(dict.items())


def main():
    start = time.perf_counter()
    try:
        EXENCDOM()
    finally:
        elapsed = timedelta(seconds=round(time.perf_counter() - start))
        logger.info(f'[main] total runtime {elapsed}')
        print(f'Total runtime: {elapsed}')



if __name__ == "__main__": 
    try:
        main()
    except Exception:
        logger.exception(f"[main]")