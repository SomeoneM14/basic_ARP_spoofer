# basic_ARP_spoofer

### For educational use only

## this arp spoofer has 2 functionalities:

### shut down an entire network (via t argument)

### dns mitm tool

Both functionalities were tested (with permission) and work on a lot of networks (some networks are more secure than others)

to use spoofer (s argument):
- you need to be on the same network as the target
- you need to know the target's gateway
- you need to know the target's ip address

ARP packets are sent directly to the gateway and to the target to execute 2 way mitm
change the spoof_url variable to your needs
whenever client inquires the ip address of the target url you will be notified and the target will be sent your local ip instead of the real one
all other traffic goes through fine

usage:
`arp_spoofer.py <target ip> <gateway ip> s`

usage example:
> python arp_spoofer.py 10.0.0.9 10.0.0.1 s

to use destroyer:
- you need to be in the target network
- you need to know the target network's gateway

ARP packets will be sent associating the the gateway ip with a junk mac address
no traffic will be able to go through the gateway (if it works)

usage:
`arp_spoofer.py <network prefix + 255.255 (change according to subnet mask)> <gateway ip> t`

usage example:
> python arp_spoofer.py 10.0.255.255 10.0.0.1 t
