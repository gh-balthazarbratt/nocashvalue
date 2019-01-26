## Background
In late Dec 2018 I saw a really cool blogpost by [@kimberMuffin](https://twitter.com/kimberMuffin/status/1075073687538171904) that explains how to 
extract and crack NTLMv2 hashes from a pcap file using Wireshark. While I'm very 
familiar with Wireshark and enjoy the GUI features I wondered if I could automate 
this process. Many other tools exist that does similar things but I wanted to 
make my own so here it is.

After a few painful misfires I settled on this command line script written in 
Python that parses a pcap file using `tshark` found on the host. Script outputs 
all `user::hash` combinations it can extract from the pcap into an individual file ready for cracking. 

It is a very crude first pass and I'm sure it could've been written more elegantly
but this will do for now. Putting this out here in hopes that it will help someone
on a pentest/redteam engagement.

Shout-out to @dontlook for coming up with the name for this repository. 

Issues/PRs welcome.  


**Note**: I only had a chance to test this script with the only pcap file I had access
 to which can be found on [Wireshark website](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=smb-on-windows-10.pcapng). Please test with your own pcaps and report back any issues.

## Dependencies
* `tshark` 
* `python3`

## How to use the script

Check the `python3` path in `#!` at the top of `main.py`. Should run fine in any *nix system. Did not test this on a Windows system.
 
```
$ ./main.py -h
usage: main.py [-h] --tshark_path TSHARK_PATH --pcap_file PCAP_FILE

Extracts NTLMv2 tokens from pcaps and creates files ready to be consumed by
hashcat

optional arguments:
  -h, --help            show this help message and exit
  --tshark_path TSHARK_PATH
                        full path to tshark executable
  --pcap_file PCAP_FILE
                        full path to pcap file
```

```
$ ./main.py --tshark_path /usr/local/bin/tshark --pcap_file smb-on-windows-10.pcapng
7 files created. See /tmp/nocashvalue_ntlmv2-75282e00 for details.
```

## License

MIT License
