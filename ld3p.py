import json, argparse, re
import sys, os
from datetime import datetime as dt

from colorama import init
init(strip=not sys.stdout.isatty())
from termcolor import cprint
from pyfiglet import figlet_format

VERSION = "1.1.0"

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

    if args.sas:
        ret &= attributes.get('memberOf',None) != None and any("CN=Schema Admins" in member for member in user['attributes']['memberOf'])

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

# TODO Enumerate this with "reversedphonenumber" if this doesnt exist
def get_phone(user):
    val = user['attributes'].get('telephoneNumber',[None])[0]
    return None if val == None else re.sub('[()\- ]','',val)

def get_group_count(user):
    val = user['attributes'].get('memberOf',None)
    return None if val == None else len(val)
# Not added in the request dict, unneccesary but potentially interesting.
def get_phone_diff(user):
    if user['attributes'].get('telephoneNumber',[None])[0] != None and user['attributes'].get('msExchUMDtmfMap',None) != None:
        pn1 = get_phone(user)
        exchMap = user['attributes']['msExchUMDtmfMap']
        for v in exchMap:
            pn2 = v.split(':')[1][::-1] if v.startswith('reversedPhone') else None
            if pn2 != None:
                break
        if pn1 != pn2 and pn1 != None and pn2 != None:
            return f"{pn1},{pn2}"
    return None

# TODO, Return as integer
def get_last_logon(user):

    # I can twoline this but it would be disgusting. Basically this is just getting the logon timestamps and formatting them in a way we can understand
    a = user['attributes']
    l1 = a.get('lastLogon',[None])[0]
    l2 = a.get('lastLogonTimestamp',[None])[0]
    l1 = l1.split('+')[0].split('.')[0] if l1 != None else None
    l2 = l2.split('+')[0].split('.')[0] if l2 != None else None

    if l1 != None and l2 != None:
        t1 = dt.strptime(l1, "%Y-%m-%d %H:%M:%S")
        t2 = dt.strptime(l2, "%Y-%m-%d %H:%M:%S")
        return l1 if t1 >= t2 else l2
    else:
        return l1 if l1 != None else l2

# This is just the text file names along with the function that cooresponds with it (for when you open the new files)
request_dict = {'sAMAccountNames':get_sam,'descriptions':get_desc,"userPrincipalNames":get_upn,"passwords":get_pwd,"phoneNumbers":get_phone,"lastLogon":get_last_logon}

def enumerate_all(args):
    try:
        users = json.loads(open(args.load_path,"r").read())
    except:
        print(f"Error: Failed to load {args.load_path}")

    dirTitle = args.out_path if args.out_path != None else "out"
    os.mkdir(dirTitle)
    for req in request_dict:
        args.req_fun = request_dict[req]
        out = open(f"{dirTitle}/{req}.{args.data_format}","w")
        check_all_users(users,out,args)
        out.close()

def check_all_users(users, out, args): 
    s_res = []
    wr_count = 0
    for user in users:
        if check_user(user,args):
            val = args.req_fun(user)
            if val != None or (val == None and args.inc_none):
                if args.sort_data:
                    s_res.append((user,val))
                else:
                    write(out,val,args,user=user)
                wr_count += 1
    # If we be sortin the data innit
    if args.sort_data:
        s_res.sort(key=lambda x : x[1], reverse=True)
        for user,v in s_res:
            write(out,v,args,user=user)
    return wr_count
        

def setup(args):
    # cprint(figlet_format("AD Dump Parser", font='slant'), 'red', attrs=['bold'])
    print(f'Loading {args.load_path}...')
    try:
        users = json.loads(open(args.load_path,"r").read())
        print(f'Success, loaded {len(users)} users')
    except:
        users = None
    try:
        out = open(args.out_path,'w')
    except:
        out = None

    return users,out

def write(out,val,args,user=None):
    try:
        if args.pair:
            if args.data_format == 'txt':
                out.write(f'{get_sam(user)}:{val}\n')
            elif args.data_format == 'csv':
                val = f'"{val}"' if args.req_fun == get_desc else val # This line covers for descriptions that have comma's in them.
                out.write(f'{get_sam(user)},{val}\n')
            elif args.data_format == 'json':
                out[get_sam(user)] = val
        else:
            out.write(f"{val}\n") # TODO  maybe do some special formatting for csv
        if args.echo or args.verbose:
            if args.pair:
                print(f"{get_sam(user)}:",end='')
            print(f"{val}")
    except Exception as e:
            print("Error:" + str(e))

def argp_init():
    parser = argparse.ArgumentParser(description='ld3p (LDap Domain Dump Parser) is a tool that quickly parses and processes AD output created by ldapdomaindump.py')
    parser.add_argument('-o','--output-file', dest='out_path', default='out.txt',
                        help='sets a custom output path (default out.txt)')
    parser.add_argument('-l','--load-path', dest='load_path', default='domain_users.json',
                        help='loads the user json table from a custom path (default domain_users.json)')
    parser.add_argument('-f','--data_format', dest='data_format', default='txt',
                        help='determines data format. Current options are "txt,csv,json"')
    
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
    req_mxg.add_argument('-phn','--phone-numbers', dest='req_fun', action='store_const', const=get_phone,
                        help='dumps all phone numbers')
    req_mxg.add_argument('-pnd','--phone-number-diff',dest='req_fun', action='store_const', const=get_phone_diff,
                        help='gets the diff between the phone numbers in the "telephoneNumber" attribute and in "msExchUMDtmfMap"')
    req_mxg.add_argument('-lon','--last-logon', dest='req_fun', action='store_const', const=get_last_logon,
                        help='gets the most recent logon time of this account (compares lastLogon and lastLogonTimestamp)')
    req_mxg.add_argument('-grc','--group-count', dest='req_fun', action='store_const', const=get_group_count,
                        help='gets the number of groups for the selected accounts')

    filters = parser.add_argument_group(title='AD Filter Options', description='Enable or disable specific filters. Not mutually exclusive, as many filters as you want can be applied.')                  
    filters.add_argument('-da', '--domain-admins', dest='das', action='store_true',
                        help='filters by domain admins')
    filters.add_argument('-ea', '--enterprise-admins', dest='eas', action='store_true',
                        help='filters by enterprise admins')
    filters.add_argument('-sa', '--schema-admins', dest='sas', action='store_true',
                        help='filters by schema admins')
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
    parser.add_argument('-in', '--include-none', dest='inc_none', action='store_true', 
                        help='Includes nonevalues, valuable if you need a full list')
    parser.add_argument('-s','--sort',dest='sort_data',action='store_true',
                        help='sorts all of the data alphabetically / by value while enumerating it.')
    parser.add_argument('-sF','--sort-function',dest='sort_func',default='value',
                        help='Sets the sort function to be used default is by text sort.')
    return parser

def custom(args):
    users, out = setup(args)  

def main():
    cprint(figlet_format("ld3p", font='slant'), 'red', attrs=['bold'])
    parser = argp_init()
    args = parser.parse_args()
    if args.req_fun == None:
        args.req_fun = get_sam

    if args.custom:
        custom(args)
        return

    if args.run_all:
        enumerate_all(args)
        return

    users, out = setup(args)
    if users == None or out == None:
        print(f'Error: users({users == None}) or output file({out == None}) is Nonexistant')
    

    wr_count = check_all_users(users,out,args)
    out.close()
    print(f'Enumeration complete, wrote {wr_count} datapoints to {args.out_path}')

if __name__ == '__main__':
    main()