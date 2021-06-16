import json
import sys
import argparse

from colorama import init
init(strip=not sys.stdout.isatty())
from termcolor import cprint
from pyfiglet import figlet_format

# Variables
udump_path = "domain_users.json"
out_path = "out.txt"

# Put all the paramaters you want in here
# Make sure to use &= for every condition, that way we start w true and if any of the &= are false then its done.
def check_user(user,args):
    ret = True # Start at true, that way if any of the paramaters are false, it becomes false regardless.
    attributes = user['attributes']
    # Example: IF there is a comma in the 'cn' paramater Doing .get(param,[None]) allows the [0] to parse to None
    # ret &= "," in user['attributes'].get('cn', [None])[0]
    if args.das:
        ret &= attributes.get('memberOf',None) != None and any("CN=Domain Admins" in member for member in user['attributes']['memberOf'])
    
    if args.eas:
        ret &= attributes.get('memberOf',None) != None and any("CN=Enterprise Admins" in member for member in user['attributes']['memberOf'])
    
    if args.en_user:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] in [512,66048] # Enabled, enabled + pw never expires
    
    if args.no_exp:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] in [66050,66048] # pw never expires

    return ret

# Gets the sAMAccountname of the user, you can parse this into users.txt
def get_sam(user):
    return user['attributes'].get('sAMAccountName', [None])[0]

def get_desc(user):
    return user['attributes'].get('description', [None])[0]

def get_upn(user):
    return user['attributes'].get('userPrincipalName', [None])[0]

def get_pwd(user):
    pwdPfx = ['password:','pw:','pwd:']
    #print(user)
    for attribute in user['attributes']:
        value = str(user['attributes'][attribute][0])
        for pfx in pwdPfx:
            if pfx in value.lower():
                #print(f'{pfx} found in {value}')
                idx = value.lower().index(pfx)
                return value[idx:].split(' ')[1]
    return None


def check_all_users(users, out, args): 
    for user in users:
        if check_user(user,args):
            val = args.req_fun(user)
            if val != None:
                if args.pair:
                    out.write(f"{get_sam(user)}:")    
                out.write(f"{val}\n")
                if args.echo or args.verbose:
                    if args.pair:
                        print(f"{get_sam(user)}:",end='')
                    print(f"{val}")

def setup(args):
    # cprint(figlet_format("AD Dump Parser", font='slant'), 'red', attrs=['bold'])
    print(f'Loading {udump_path}...')
    try:
        users = json.loads(open(args.load_path,"r").read())
    except:
        users = None
    try:
        out = open(args.out_path,'w')
    except:
        out = None

    return users,out

def argp_init():
    parser = argparse.ArgumentParser(description='Quickly process AD output created by ldapdomaindump.py')
    parser.add_argument('-o','--output-file', dest='out_path', default='out.txt',
                        help='sets a custom output path (default out.txt)')
    parser.add_argument('-l','--load-path', dest='load_path', default='domain_users.json',
                        help='loads the user json table from a custom path (default domain_users.json)')

    requests = parser.add_argument_group(title='Request Options',description='Determines what options to list, note that these are mutually exclusive.')
    req_mxg = requests.add_mutually_exclusive_group()
    req_mxg.add_argument('-desc','--description', dest='req_fun', action='store_const', const=get_desc,
                        help='dump a list of descritions')
    req_mxg.add_argument('-upn', '--user-principal-name', dest='req_fun', action='store_const', const=get_upn,
                        help='dump a list of descritions')
    req_mxg.add_argument('-pwd', '--passwords', dest='req_fun', action='store_const', const=get_pwd,
                        help='attempt to enumerate passwords from varios attribute fields (description etc.)')
    req_mxg.add_argument('-sam','--sam-account-name', dest='req_fun', action='store_const', const=get_sam,
                        help='dump a list of sAMAccountName values, usable as a username list')

    filters = parser.add_argument_group(title='AD Filter Options', description='Enable or disable specific filters. Not mutually exclusive, as many filters as you want can be applied.')                  
    filters.add_argument('-da', '--domain-admins', dest='das', action='store_true',
                        help='filters by domain admins')
    filters.add_argument('-ea', '--enterprise-admins', dest='eas', action='store_true',
                        help='filters by enterprise admins')
    filters.add_argument('-eu', '--enabled-users', dest='en_user', action='store_true',
                        help='filters by users who are enabled')
    filters.add_argument('-ne', '--no-expiry',dest='no_exp',action='store_true',
                        help='filters by users with no password expiry (enabled or disabled)')

    parser.add_argument('-a','--all', dest='run_all', action='store_true', 
                        help='Runs all enumerations (sam, upn, pwd etc). Overrides [desc|upn|...]')

    # TODO Maybe remove -e           
    parser.add_argument('-e','--echo', dest='echo', action='store_true', 
                        help='echoes the found results back in stdout')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', 
                        help='turns on verbose mode')
    parser.add_argument('-c','--custom', action='store_true',
                        help='runs the custom code in custom() and exits. Arguments are passed into custom()')
    parser.add_argument('-p','--pair', dest='pair', action='store_true',
                        help='attaches the sAMAccountname to every value, useful for data that isnt identifying')
    return parser

def custom(args):
    
    users, out = setup(args)
    for user in users:
        if user['attributes'].get('userPrincipalName',None) is None:
            out.write(get_sam(user) + "\n")
    '''
        out.write('Attribute, Count\n')
        tot_dict = {}
        for user in users:
            attributes = user['attributes'].keys()
            for key in attributes:
                if key not in tot_dict:
                    tot_dict[key] = 0
                tot_dict[key] += 1

        for item in [(k,v) for k, v in sorted(tot_dict.items(), key=lambda x : x[1],reverse=True)]:
            out.write(f'{item[0]},{item[1]}\n')
        #out.write(str(tot_dict))
        print(len(users))
    '''

def main():
    cprint(figlet_format("AD Dump Parser", font='slant'), 'red', attrs=['bold'])
    parser = argp_init()
    args = parser.parse_args()
    if args.req_fun == None:
        args.req_fun = get_sam
    if args.custom:
        custom(args)
        return

    users, out = setup(args)
    if users == None or out == None:
        print(f'Error: users({users == None}) or output file({out == None}) is Nonexistant')
    
    check_all_users(users,out,args)
    out.close()

if __name__ == '__main__':
    main()