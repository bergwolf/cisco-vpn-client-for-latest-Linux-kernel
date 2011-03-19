12 May 2009

This is an *UNOFFICIAL* patch for Cisco VPN Client on AMD Phenom
CPUs.

The original binaries misdetect the installed CPU, and with 
AMD Phenom tried to use Intel-specific routines for MDA and SHA,
thus crashing the application itself.

Here you will find the same binaries patched to work with new AMD
CPUs, so if your Cisco VPN Client running on your AMD segfaults
try this patched binaries.

______
Usage |
-----------------------------------------------------
You can simply copy them in the right dirs by hand, or run 
install.sh script, that will backup original binaries and then
copy the patched one.

There are three binaries (vpnclient, cvpnd, cisco_cert_mgr) and
one library (libvpnapi.so), usually installed in:
/opt/cisco-vpnclient/bin/   (binaries)
/opt/cisco-vpnclient/lib/   (library) 

If you have not-standard install you must simply replace original
files with the supplied ones in this package.

The binaries are a modified version of the ones i found in:

vpnclient-linux-x86_64-4.8.01.0640-k9.tar.gz

The patched files worked for me, but you are ecnouraged to
consider this patch *UNOFFICIAL*, *UNSTABLE*, *UNTESTED*.

If they work for you, write me some feedback about:
- your client version;
- your kernel Version (uname -a);
- your CPU version  (cat /proc/cpuinfo); 

Have fun!
t3x@alkolizzati.org

This patched version has been downloaded from http://projects.tuxx-home.at/,
please check for updates there and if you experience any problems, visit
the support forum http://forum.tuxx-home.at/.
