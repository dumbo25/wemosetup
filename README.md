# vadim
vadim.py is derived from: https://github.com/vadimkantorov/wemosetup

The primary use of this script is to find WeMos that lost connection or are
not responding to discover on Amazon Alexa App. However, this script does a
lot more. It is based on a python script written by Vadim Kantorov.

Vadim's python script using the discover command gives the most consistent
results for WeMo devices on my home network. I run the script on a MacBook
running OS X 11.4.

I was late to the WeMo party, and I hunted for a script that could do what I
needed. Vadim's script out perfoms nmap, arp and various python and bash scripts
on my network. With nmap and arp, only ~1/2 of my WeMo devices are found. My
assumption is this caused by the various network segments in my home network. 
This script consistently finds all or most of my WeMo devices. Sometimes it 
misses one or two.

In addition, the script helped me debug several issues with my network and my
WeMo configurations.

My network has two switches and two Wi-Fi access points directly connected to an
AT&T fiber gateway (Gb). Each WeMo connected to a secondary switch or Wi-Fi AP.
So, my network has multiple network segments. A network segment makes it a bit
harder to consistently find all the devices running scripts or commands from my 
MacBook.

During the setup process, every WeMo switch has the same IP Address 10.22.22.1
I am not certain, but I believe Vadim's script was developed to setup a WeMo
device from a linux command line. I tried not to break the original commands.

I use the WeMo app and not the vadim script to setup new, or to setup after
reboot or after factory reset. Vadim's script also supports WeMo bridges, which
I don't have.

So, I am modifying Vadim's script to meet my needs. Hopefully, without breaking
his features.

vadim can discover, track, control (on or off), set up and report on WeMo 
devices on a home LAN.

I started by making a few minor changes to Vadim's script. The code was beautiful 
and I wanted to learn from it, but the code is badly butchered now. 

After reading through the code and running various commands, I realized Vadim's 
script was much more powerful than it appeared. So, I started to add even more
features.

The initial changes included improving the help output, and changes to allow it 
to run under python3 on a MacBook.

I changed the command discover to work on my LAN rather than on a WeMo bridge, 
and moved the old discover command to one called bridge.

I added several commands: data, bridge, display, mac, off, on, toggle, status, 
and so on.

One of the more useful changes to discover is it will detect rogue APs, which 
caused my WeMo devices to lose connection or become unctrollable via the WeMo 
app, Alexa or Voice control via Echo.

vadim also attaches to an sqlite3 database and stores the Friendly Name, MAC 
Address, IP Address, port, serial number, HW Version, and setup code. 

vadim.py imports
   mylog.py
   wemo_db.py

Run using:

   python3 vadim.py command [options]

or

   python3 vadim.py
   
to get help on all of its features
