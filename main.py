#!/usr/bin/python3

import os, sys, subprocess, json, logging, argparse
from uuid import uuid4

parser = argparse.ArgumentParser(description='Extracts NTLMv2 tokens from pcaps \
and creates files ready to be consumed by hashcat')
parser.add_argument('--tshark_path', 
                    type=str, 
                    help='full path to tshark executable', 
                    required=True)
parser.add_argument('--pcap_file', 
                    type=str, 
                    help='full path to pcap file', 
                    required=True)

args = parser.parse_args()
tshark_path = args.tshark_path
pcap_file = args.pcap_file

# Change the value below based on your system paths, it is set for *nix type systems
tmp = '/tmp'
# Set temporary directory and log file names
scr_dir = 'nocashvalue_ntlmv2-' + uuid4().__str__()[:8]
tmp_scr_dir = tmp + '/' + scr_dir
log_file = 'nocashvalue.log'

# Create script tmp directory
os.mkdir(tmp_scr_dir)

# Setup logger
logger = logging.getLogger('nocashvalue')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(tmp_scr_dir+'/'+log_file)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)

logger.info('Logger initialized')

challenge_filter_str = "'ntlmssp.identifier == NTLMSSP and ntlmssp.messagetype == 0x00000002'"
blob_filter_str = "'ntlmssp.identifier == NTLMSSP and ntlmssp.messagetype == 0x00000003'"

challenge_str_cmd = "{} -r {} -Y{} -Tjson -e ntlmssp.auth.username \
-e ntlmssp.auth.domain -e ntlmssp.ntlmserverchallenge -e ntlmssp.ntlmv2_response.ntproofstr \
-e ntlmssp.ntlmv2_response".format(tshark_path, pcap_file, challenge_filter_str)

blob_str_cmd = "{} -r {} -Y{} -Tjson -e ntlmssp.auth.username -e ntlmssp.auth.domain \
-e ntlmssp.ntlmserverchallenge -e ntlmssp.ntlmv2_response.ntproofstr \
-e ntlmssp.ntlmv2_response".format(tshark_path, pcap_file, blob_filter_str)

logger.info('Executing "{}" in a subprocess shell'.format(challenge_str_cmd))
pipe1 = subprocess.Popen(challenge_str_cmd, stdout=subprocess.PIPE, shell=True)
logger.info('Child process pid is {} and it exited with {}'.format(pipe1.pid, pipe1.returncode))

logger.info('Executing "{}" in a subprocess shell'.format(blob_str_cmd))
pipe2 = subprocess.Popen(blob_str_cmd, stdout=subprocess.PIPE, shell=True)
logger.info('Child process pid is {} and it exited with {}'.format(pipe2.pid, pipe2.returncode))

challenge_str_output = pipe1.stdout.read()
blob_str_output = pipe2.stdout.read()

# This is a list of dictionaries
challenge_str_json = json.loads(challenge_str_output.decode('UTF-8'))
logger.info(json.dumps(challenge_str_json, indent=2))

blob_str_json = json.loads(blob_str_output.decode('UTF-8'))
logger.info(json.dumps(blob_str_json, indent=2))

# Log the fact that the number of server challenge packets 
# are different than the number of ntlmv2_response packets and exit
if (len(challenge_str_json) != len(blob_str_json)): 
    sys.stdout.write('Number of SMB2 packets containing NTLM Server Challenge tokens \
are different than the number of packets containing NTLMv2 responses. See {} \
for details.'.format(tmp_scr_dir+'/'+log_file))
    exit()

packets = []

# Merge server challenge tokens with the rest of the ntlmv2_response details
# Caveat: We assume that the packets are received in chronological order such that
# the packet which contains server_challenge token appears right before the packet 
# that contains NTLMv2_response it is associated with
for i, blob_pkt in enumerate(blob_str_json):
    username, domain, server_challenge, ntproofstr, ntlmv2_response = ['', '', '', '', '']
    if (len(blob_pkt['_source']['layers']) > 0 and 
        'ntlmssp.auth.username' in blob_pkt['_source']['layers']):
        username = blob_pkt['_source']['layers']['ntlmssp.auth.username'][0]
    if (len(blob_pkt['_source']['layers']) > 0 
        and 'ntlmssp.auth.domain' in blob_pkt['_source']['layers']):
        domain = blob_pkt['_source']['layers']['ntlmssp.auth.domain'][0]
    if (len(challenge_str_json[i]['_source']['layers']) > 0 
        and 'ntlmssp.ntlmserverchallenge' in challenge_str_json[i]['_source']['layers']):
        server_challenge = challenge_str_json[i]['_source']['layers']['ntlmssp.ntlmserverchallenge'][0]
    if (len(blob_pkt['_source']['layers']) > 0 
        and 'ntlmssp.ntlmv2_response.ntproofstr' in blob_pkt['_source']['layers']):
        ntproofstr = blob_pkt['_source']['layers']['ntlmssp.ntlmv2_response.ntproofstr'][0]
    if (len(blob_pkt['_source']['layers']) > 0 
        and 'ntlmssp.ntlmv2_response' in blob_pkt['_source']['layers']):
        ntlmv2_response = blob_pkt['_source']['layers']['ntlmssp.ntlmv2_response'][0]
        if len(ntlmv2_response) > 0:
            ntlmv2_response = ntlmv2_response[31:]
    packets.insert(i, {'username': username, 
                       'domain': domain, 
                       'server_challenge': server_challenge, 
                       'ntproofstr': ntproofstr, 
                       'ntlmv2_response': ntlmv2_response})

# Hashcat NTLMv2 file format
# username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response
for packet in packets:
    file_name = (tmp_scr_dir 
                    + '/' + packet['username'] + '_' + packet['domain'] 
                    + '-' + uuid4().__str__()[:8] + '.txt')
    with open(file_name, 'w', encoding="UTF-8") as file:
        blob = packet['username'] + '::' + packet['domain'] + ':' + packet['server_challenge'] 
        blob += ':' + packet['ntproofstr'] + ':' + packet['ntlmv2_response']
        file.write(blob)

sys.stdout.write('{} files created. See {} for details.'.format(len(packets),tmp_scr_dir))