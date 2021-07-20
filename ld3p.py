import json, argparse, re
import sys, os
from datetime import datetime as dt
import pandas as pd
import numpy as np

from colorama import init
init(strip=not sys.stdout.isatty())
from termcolor import cprint
from pyfiglet import figlet_format

VERSION = "1.3.0"

dumpsec_map = {
    "UserName": "sAMAccountName",
    "Groups": "memberOf",
    "LastLogonTime": "lastLogon",
    "FullName":"name",
    "PswdLastSetTime":"pwdLastSet",
    "AcctExpiresTime":"accountExpires",
    "Comment":"description"
}

dumpsec_uac = {
    "AcctDisabled": {'cond':['Yes'],'value':2}, # YES TO INCLUDE
    "PswdRequired": {'cond':['No','No '],'value':32}, # MUST BE NO TO ADD
    "PswdCanBeChanged": {'cond':['No','No '],'value':64}, # Must be NO to add
    "PswdExpires": {'cond':['No','No '],'value':65536}, # Must be NO to add value
    "AcctLockedOut": {'cond':['Yes'],'value':16}, # Must be yes to include
    "AccountType": {'cond':['User'],'value':2}
}


dumpsec_ignore = ["Sid","LastLogonServer","HomeDir","HomeDrive","LogonScript","Workstations"]

t_vals = ('yes','true','t','y','1')
f_vals = ('no','false','f','n','0')

# Put all the paramaters you want in here
# Make sure to use &= for every condition, that way we start w true and if any of the &= are false then its done.
def check_user(user,args):
    ret = True # Start at true, that way if any of the paramaters are false, it becomes false regardless.
    attributes = user['attributes']

    # Example: IF there is a comma in the 'cn' paramater Doing .get(param,[None]) allows the [0] to parse to None
    # ret &= "," in user['attributes'].get('cn', [None])[0]
    if args.das:
        ret &= attributes.get('memberOf',None) != None and any("CN=Domain Admins" in member for member in attributes['memberOf'])
    
    if args.eas:
        ret &= attributes.get('memberOf',None) != None and any("CN=Enterprise Admins" in member for member in attributes['memberOf'])

    if args.sas:
        ret &= attributes.get('memberOf',None) != None and any("CN=Schema Admins" in member for member in attributes['memberOf'])

    if args.any_admin:
        ret &= attributes.get('memberOf',None) != None and any("admin" in member.lower() for member in attributes['memberOf'])

    # TODO Optimize this to make it some wizard looping stuff, ALSO throw error if not either t_vals, f_vals, 
    if args.en_user.lower() in t_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 2 == 0 # Enabled users
    elif args.en_user.lower() in f_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 2 == 2 # Disabled users
    
    if args.lkd_out.lower() in t_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 16 == 16
    elif args.lkd_out.lower() in f_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 16 == 0

    if args.pw_exp.lower() in t_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 65536 == 0 # pw never expires
    elif args.pw_exp.lower() in f_vals:
        ret &= attributes.get('userAccountControl',None) != None and attributes['userAccountControl'][0] & 65536 == 65536

    if args.cust_filter != None: #Currently only handles == and not 'in' beause I am NOT about to waste my time doing that
        if '=' not in args.cust_filter:
            print(f"Error: Invalid Custom Filter \"{args.cust_filter}\"")
            exit()

        var = args.cust_filter.split('=')[0]
        val = args.cust_filter.split('=')[1]
        if var == 'memberOf':
            ret &= attributes.get('memberOf',None) != None and any(val in member for member in user['attributes']['memberOf'])
        else:
            ret &= attributes.get(var,None) != None and str(attributes[var][0]).lower() == str(val).lower()
            
    return ret

# Gets the sAMAccountname of the user, you can parse this into users.txt
def get_sam(user):
    return user['attributes'].get('sAMAccountName', [None])[0]

def get_desc(user):
    return user['attributes'].get('description', [None])[0]

def get_upn(user):
    return user['attributes'].get('userPrincipalName', [None])[0]

def get_name(user):
    return user['attributes'].get('Name', [None])[0]

def get_pwd(user):
    pwdPfx = ['password:','pw:','pwd:']
    for attribute in user['attributes']:
        value = str(user['attributes'][attribute][0])
        for pfx in pwdPfx:
            if pfx in value.lower():
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

# This filters by just the CN names
def get_group_list(user):
    val = user['attributes'].get('memberOf',None)
    if val != None:
        mapped = list(map(lambda x:x.split(',')[0].split('=')[1],val))
        mapped.sort()
    return None if val == None else ",".join(mapped)

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

def get_pw_lastset(user):

    # I can twoline this but it would be disgusting. Basically this is just getting the logon timestamps and formatting them in a way we can understand
    a = user['attributes']
    l1 = a.get('pwdLastSet',[None])[0]
    l1 = l1.split('+')[0].split('.')[0] if l1 != None else None
    return None if l1 == None else dt.strptime(l1, "%Y-%m-%d %H:%M:%S")

def get_custom_attribute(user,attribute):
    return user['attributes'].get(attribute, [None])[0]

# This is just the text file names along with the function that cooresponds with it (for when you open the new files)
request_dict = {'sAMAccountNames':get_sam,'descriptions':get_desc,"userPrincipalNames":get_upn,"passwords":get_pwd,"phoneNumbers":get_phone,"lastLogons":get_last_logon,"names":get_name}

def enumerate_all(users, args):
    dirTitle = args.out_path if args.out_path != None else "out"
    os.mkdir(dirTitle)
    for req in request_dict:
        args.req_fun = request_dict[req]
        out = open(f"{dirTitle}/{req}.{args.output_format}","w")
        check_all_users(users,out,args)
        out.close()

def check_all_users(users, out, args): 
    s_res = []
    wr_count = 0
    for user in users:
        if check_user(user,args):
            
            if args.cust_attrib != None:
                val = get_custom_attribute(user,args.cust_attrib)
            else:
                val = args.req_fun(user)

            if val != None or (val == None and args.inc_none):
                if args.sort_data:
                    s_res.append((user,val))
                else:
                    write(out,val,args,user=user)
                wr_count += 1
    # If we be sortin the data innit
    if args.sort_data:
        s_res.sort(key=lambda x : x[1], reverse=((args.sort_func in ["r","v","value","number-high","num-high"]) and (args.sort_func not in  ['a','nr','alphabetical','alpha','number-low','num-low'])))
        for user,v in s_res:
            write(out,v,args,user=user)
    return wr_count

def get_user(users, sam_name):
    # TODO Oneline this
    for user in users:
        if user['attributes']['sAMAccountName'] == sam_name:
            return user
    return None

def not_nan(x):
    return x == x

def parse_dumpsec(args):
    users = []
    df = None
    print("Parsing DumpSec document...")
    if args.input_format in ['txt','text']:
        df = pd.read_csv(args.input_path, sep='\t', header=1)
    elif args.input_format in ['csv']:
        df = pd.read_csv(args.input_path)
    elif args.input_format in ['xls','xlsx']:
        df = pd.read_excel(args.input_path,sheet_name = None,header=1)
        df = list(df.values())[0]
    print(f"Dumpsec file found {str(len(df.keys()))} keys") # I refuse to concatenate sheets unless it is consistently built into dumpsec
    
    for row in df.iterrows():
        row = row[1].to_dict()
        if row.get('UserName',None) == None:
            print("Minor Error: Null Username...")
            continue

        user = [x for x in users if x['attributes'].get('sAMAccountName',[None])[0] != None and row.get('UserName') == x['attributes'].get('sAMAccountName')[0]]
        
        usr_exists = user != []
        user = {} if user == [] else user[0]
        # Handle Groups Right away
        if not 'memberOf' in user.keys() and not usr_exists:
            user['memberOf'] = []
        g_str = "CN="
        if not_nan(row['Groups']):
            g_str += f"{row['Groups']}"
        if not_nan(row['GroupComment']):
            g_str += f",CMT={row['GroupComment']}"
        if not_nan(row['GroupType']):
            g_str +=f",TYP={row['GroupType']}"
        
        if usr_exists:
            user['attributes']['memberOf'].append(g_str)
            continue
        else:
            user['memberOf'].append(g_str)
        
        usrAccCtrl= 0
        for attrib in row.keys():
            # Handle Groups, NaN values, and ignored values (respectively by or)
            if attrib in ['Groups','GroupComment','GroupType'] or row[attrib] != row[attrib] or attrib in dumpsec_ignore:
                continue
            if attrib in dumpsec_uac.keys() and not args.no_parse:
                usrAccCtrl += dumpsec_uac[attrib]['value'] if row[attrib] in dumpsec_uac[attrib]['cond'] else 0
                user['userAccountControl'] = [usrAccCtrl]
            elif attrib in dumpsec_map.keys() and not args.no_parse:
                user[dumpsec_map[attrib]] = [row[attrib]] if type(row[attrib]) in [int,str,float] else [str(row[attrib])]
            elif not args.no_parse and attrib not in dumpsec_ignore or args.no_parse:
                # If we arent ignoring it, or we straightup are just not parsing, then just set the exact value
                # Note, this overwrites every other variable (groups)... Unintended feature but was what I wanted to do.
                user[attrib] = [row[attrib]] if type(row[attrib]) in [int,str,float] else [str(row[attrib])]

                # This exists to fix a stupid bug with dumpsec and I HATE THAT I HAVE TO DO THIS SO MUCH, its supposed to be NO-PARSE but unfortunately it is PARSING!!!!!!!!!!!!
                #if row[attrib] == 'No ':
                #    user[attrib] = ['No']
            else:
                print("DumpSec Error: Invalid configuration, exiting...")
                exit()
        if user != {}:
            users.append({"attributes":user})
    return users

def setup(args):
    print(f'Loading {args.input_path}...')
    try:
        users = []
        if args.input_format == 'json':
            users = json.loads(open(args.input_path,"r").read())
        elif args.input_format in ['txt','text','xls','xlsx']: # Designed to handle dumpsec
            users = parse_dumpsec(args)
            
        if users == None or len(users) == 0:
            print("Error loading users, check paramaters and try again")
            exit()
        print(f'Success, loaded {len(users)} users')
    except Exception as e:
        users = None
        print(f"--==Setup Error==--\nLine Num: {sys.exc_info()[-1].tb_lineno}\nType: {type(e)}\nError Msg: {e}")
    try:
        if not args.run_all:
            out = open(args.out_path,'w')
        else:
            out = None
    except:
        out = None

    return users,out

def write(out,val,args,user=None):
    try:
        if args.pair:
            if args.output_format == 'txt':
                out.write(f'{get_sam(user)}:{val}\n')
            elif args.output_format == 'csv':
                val = f'"{val}"' if args.req_fun == get_desc else val # This line covers for descriptions that have comma's in them.
                out.write(f'{get_sam(user)},{val}\n')
            elif args.output_format == 'json':
                out[get_sam(user)] = val
        else:
            out.write(f"{val}\n") # TODO  maybe do some special formatting for csv
        if args.echo or args.verbose:
            if args.pair:
                print(f"{get_sam(user)}:",end='')
            print(f"{val}")
    except Exception as e:
            print("Write Error:" + str(e))

def argp_init():
    parser = argparse.ArgumentParser(description='ld3p (LDap Domain Dump Parser) is a tool that quickly parses and processes AD output created by ldapdomaindump.py')
    parser.add_argument('-o','--output-path', dest='out_path', default='out.txt',
                        help='sets a custom output path (default out.txt)')
    parser.add_argument('-i', '--input-path','-l','--load-path', dest='input_path', default='domain_users.json',
                        help='loads the user json table from a custom path (default domain_users.json)')
    parser.add_argument('-of','--output-format', dest='output_format', default='txt',
                        help='determines output data format. Current options are "txt,csv,json"')
    parser.add_argument('-if','--input-format', dest='input_format', default='json',
                        help='determines input data format. Current options are "txt,csv,json,xlsx"')
    parser.add_argument('-np','--no-parse', dest='no_parse', action='store_true',
                        help='if enabled, data from DumpSec is not parsed mapped to AD attributes') # TODO finish later

    requests = parser.add_argument_group(title='Request Options',description='Determines what options to list, note that these are mutually exclusive.\nCompatible with [A] All\n[U] Users\n[C] Computers\n[G] Groups')
    req_mxg = requests.add_mutually_exclusive_group()
    req_mxg.add_argument('-desc','--description', dest='req_fun', action='store_const', const=get_desc,
                        help='[U,G] Dump a list of descritions')
    req_mxg.add_argument('-upn', '--user-principal-name', dest='req_fun', action='store_const', const=get_upn,
                        help='[U] Dump a list of user principal names')
    req_mxg.add_argument('-pwd', '--passwords', dest='req_fun', action='store_const', const=get_pwd,
                        help='[A] Attempt to enumerate passwords from varios attribute fields (description etc.)')
    req_mxg.add_argument('-sam','--sam-account-name', dest='req_fun', action='store_const', const=get_sam,
                        help='[U,G] Dump a list of sAMAccountName values, usable as a username list')
    req_mxg.add_argument('-nam','--name',dest='req_fun',action='store_const',const=get_name,
                        help='[U] Dumps a list of full names (from the "name" attribute)')
    req_mxg.add_argument('-phn','--phone-numbers', dest='req_fun', action='store_const', const=get_phone,
                        help='[U] Dumps all phone numbers')
    req_mxg.add_argument('-pnd','--phone-number-diff',dest='req_fun', action='store_const', const=get_phone_diff,
                        help='[U] gets the diff between the phone numbers in the "telephoneNumber" attribute and in "msExchUMDtmfMap"')
    req_mxg.add_argument('-lon','--last-logon', dest='req_fun', action='store_const', const=get_last_logon,
                        help='[U,C] gets the most recent logon time of this account (compares lastLogon and lastLogonTimestamp)')
    req_mxg.add_argument('-pls','--password-last-set', dest='req_fun', action='store_const', const=get_pw_lastset,
                        help='[U,C] gets when the password is last set for this account.')
    req_mxg.add_argument('-grc','--group-count', dest='req_fun', action='store_const', const=get_group_count,
                        help='[U] gets the number of groups for the selected accounts')
    req_mxg.add_argument('-grl','--group-list', dest='req_fun', action='store_const', const=get_group_list,
                        help='[U] gets the number of groups for the selected accounts')
    req_mxg.add_argument('-cA','--custom-attribute', dest='cust_attrib',default=None,
                        help='[A] Gets a custom attribute.')
    
    filters = parser.add_argument_group(title='AD Filter Options', description='Enable or disable specific filters. Not mutually exclusive, as many filters as you want can be applied.')                  
    filters.add_argument('-da', '--domain-admins', dest='das', action='store_true',
                        help='[U] filters by domain admins')
    filters.add_argument('-ea', '--enterprise-admins', dest='eas', action='store_true',
                        help='[U] filters by enterprise admins')
    filters.add_argument('-sa', '--schema-admins', dest='sas', action='store_true',
                        help='[U] filters by schema admins')
    filters.add_argument('-eu', '--enabled-users', dest='en_user',default='Unfilled',
                        help='[U] filters by users who are enabled')
    filters.add_argument('-lo', '--locked-out',dest='lkd_out',default='Unfilled',
                        help='[U] filters by users who are locked out')
    filters.add_argument('-pe', '--password-expires',dest='pw_exp',default='Unfilled',
                        help='[U] filters by users with no password expiry (enabled or disabled)')
    filters.add_argument('-aa', '--any-admin', dest='any_admin', action='store_true',
                        help='[U] filters by users who have the phrase \'Admin\' in any of their groups')
    filters.add_argument('-cF','--custom-filter', dest='cust_filter', default=None, 
                        help='[A] Runs a custom filter paramaterized by "VARIABLE=VALUE". Sometimes just doesn\'t work')

    parser.add_argument('-a','--all', dest='run_all', action='store_true', 
                        help='Runs all common enumerations (sam, upn, pwd etc). Overrides [desc|upn|...]')

    # TODO Maybe remove -e           
    parser.add_argument('-e','--echo', dest='echo', action='store_true', 
                        help='echoes the found results back in stdout')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', 
                        help='turns on verbose mode')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='turns on debug mode for self inserted code.')
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
    parser.add_argument('-dl','--dump-loaded',dest='dump_loaded',action='store_true',
                        help='dumps the loaded users table to the output file')
    return parser

def custom(args):
    pass

def main():
    cprint(figlet_format("ld3p", font='slant'), 'red', attrs=['bold'])
    parser = argp_init()
    args = parser.parse_args()
    if args.req_fun == None:
        args.req_fun = get_sam

    if args.custom:
        custom(args)
        return

    users, out = setup(args)
    if users == None or (out == None and not args.run_all):
        print(f'Error: users({users == None}) or output file({out == None}) is Nonexistant')
        exit()

    if args.run_all:
        enumerate_all(users, args)
        return

    if args.dump_loaded:
        json.dump(users,open(args.out_path,"w"))
        return

    wr_count = check_all_users(users,out,args)
    out.close()
    print(f'Enumeration complete, wrote {wr_count} datapoints to {args.out_path}')

if __name__ == '__main__':
    main()