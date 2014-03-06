#!/usr/bin/python
import logging, sys, re, getpass, argparse
from pysphere import MORTypes, VIServer, VITask, VIProperty, VIMor, VIException
from pysphere.vi_virtual_machine import VIVirtualMachine
    
def find_vm(name, con):
  try:
    vm = con.get_vm_by_name(name)
    return vm
  except VIException:
    return None

def find_host(name, server):
  try:
    t_hs = [k for k, v in server.get_hosts().items() if v == name]
    if len(t_hs) > 0:
      return t_hs[0]
    else:
      return None
  except VIException, e:
    logger.error(e)
    return None
        
def find_datastore(name, server):
  try:
    t_ds = [k for k, v in server.get_datastores().items() if v == name]
    if len(t_ds) > 0:
      return t_ds[0]
    else:
      return None
  except VIException, e:
    logger.error(e)
    return None

def migrate_vm(vm, thost, server):
  try:
    vm_name = vm.get_property('name')
    logger.info("Migrating %s to %s: " %(vm_name, thost))
    logger.debug("Validating whether the host %s exists" % thost)
    hid = find_host(thost, server)

    if hid:
      logger.debug("Found %s. It has host id %s" % (thost, hid))
      logger.info('Initializing migration of %s to %s (%s)' %(vm_name, thost, hid))
      vm.migrate(vm, host=hid)
      logger.info("Successfully migrated %s to %s" %(vm_name, thost))
    else:
      logger.error("Host not found. Verify hostname and try again.")   
  except VIException as inst:
    logger.error(inst)

def relocate_vm(vm, tds, thost, server):
  try:
    vm_name = vm.get_property('name')
    logger.info("Migrating %s to %s: " %(vm_name, tds ))
    logger.debug("Validating whether the datastore %s exists" % tds)
    did = find_datastore(tds, server)

    if did:
      logger.debug("Found %s. It has datastire id %s" % (tds, did))
      if thost:
        logger.debug ("Validating whether the host %s exists" % thost)
        hid = find_host(thost, server)
        if hid:
          logger.debug("Found %s. It has host id %s" % (thost, hid))
          logger.info("Initilizing relocation of %s to %s & %s" %(vm_name, tds, thost))
          vm.relocate(vm, datastore=did, host=hid)
          logger.info("Successfully relocated %s to %s %s" %(vm_name, tds, thost ))
        else:
          logger.error("Host not found. Verify hostname and try again.")
      else:
        logger.info("Initilizing relocation of %s to %s" %(vm_name, tds ))
        vm.relocate(vm, datastore=did)
        logger.info("Successfully relocated %s to %s: " %(vm_name, tds ))
    else:
      logger.error("Datastore not found. Verify datastore name and try again.")
  except VIException as inst:
    logger.error(inst)

def get_args():
  # Creating the argument parser
  parser = argparse.ArgumentParser(description="Migrate or Relocate VMs (vMotion & svMotion)")
  parser.add_argument('-s', '--server', nargs=1, required=True, help='The vCenter or ESXi server to connect to', dest='server', type=str)
  parser.add_argument('-u', '--user', nargs=1, required=True, help='The username with which to connect to the server', dest='username', type=str)
  parser.add_argument('-p', '--password', nargs=1, required=False, help='The password with which to connect to the host. If not specified, the user is prompted at runtime for a password', dest='password', type=str)
  parser.add_argument('-m', '--vm', nargs=1, required=True, help='The virtual machine (VM) to migrate or relocate', dest='vmname', type=str)
  parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
  parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
  parser.add_argument('-l', '--log-file', nargs=1, required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
  parser.add_argument('-V', '--version', action='version', version="%(prog)s (version 0.1)")
  
  # configuring subparsers for actions
  subparsers = parser.add_subparsers(help='commands')

  # migrate command
  migrate_parser = subparsers.add_parser('migrate', help='Migrate VM to a target host')
  migrate_parser.add_argument('-th', '--targethost', required=True, action='store', help='Target host', dest='thost', type=str)

  # relocate command
  relocate_parser = subparsers.add_parser('relocate', help='Relocate VM to a target datastore and/or host')
  relocate_parser.add_argument('-td', '--targetds', required=True, action='store', help='Target datastore.', dest='tds', type=str)
  relocate_parser.add_argument('-th', '--targethost', required=False, action='store', help='Target host.', dest='tdh', type=str)
  
  args = parser.parse_args()
  return args

# Parsing values
args     = get_args()
argsdict = vars(args)
server   = args.server[0]
username = args.username[0]
vmname   = args.vmname[0]
verbose  = args.verbose
debug    = args.debug
log_file = None
password = None
thost    = None
tds      = None

if args.password:
  password = args.password[0]

if args.logfile:
  log_file = args.logfile[0]

if hasattr(args, 'thost'):
  thost = args.thost

if hasattr(args,'tds'):
  tds = args.tds

if hasattr(args, 'tdh'):
  tdh = args.tdh

# Logging settings
if debug:
  log_level = logging.DEBUG
elif verbose:
  log_level = logging.INFO
else:
  log_level = logging.WARNING

# Initializing logger
if log_file:
  logging.basicConfig(filename=log_file,format='%(asctime)s %(levelname)s %(message)s',level=log_level)
else:
  logging.basicConfig(filename=log_file,format='%(asctime)s %(levelname)s %(message)s',level=log_level)
  logger = logging.getLogger(__name__)
logger.debug('Logger initialized')

# Asking Users password for server
if password is None:
  logger.debug('No command line password received, requesting password from user')
  password = getpass.getpass(prompt='Enter password for vCenter %s for user %s: ' % (server, username))

# Connecting to server
logger.info('Connecting to server %s with username %s' % (server,username))

con = VIServer()
try:
  logger.debug('Trying to connect with provided credentials')
  con.connect(server,username,password)
  logger.info('Connected to server %s' % server)
  logger.debug('Server type: %s' % con.get_server_type())
  logger.debug('API version: %s' % con.get_api_version())
except VIException as ins:
  logger.error(ins)
  logger.debug('Loggin error. Program will exit now.')
  sys.exit()
# Finding the VM
logger.debug('Searching virtual machine %s.' % vmname)
vm = find_vm(vmname, con)

if vm is None:
  logger.error('Could not find %s, please verify VMs name and try again.' % vmname)
  con.disconnect()
  sys.exit()

logger.info('Successfully found %s in %s' % (vm.get_property('name'), vm.get_property('path')))

if thost is not None:
    migrate_vm (vm, thost, con)
    con.disconnect()
    sys.exit()
elif tds is not None:
    if tdh is not None:
       relocate_vm (vm, tds, tdh, con)
    relocate_vm (vm, tds, thost, con)
    con.disconnect()
    sys.exit()

con.disconnect()
