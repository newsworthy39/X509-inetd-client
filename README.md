# X509-inetd-client
The x509-client that goes with the https://github.com/newsworthy39/x509-inetd-superserver

The x509 inetd-like client. The inetd-superserver, takes simple init-style sysv-scripts, and executes them, outputting any result via echo, printf back to the client. Since its a TLS-1.2 (tls1.1-compatible) TCP server, listening on a specific-port, you may use whatever protocol as you see fint. The same does the inetd-client.

# Arguments:
 -h(ost to connecto, default= "0.0.0.0"),
 
 -p(ort, default="5001"),
 
 -d(irectory to look for scripts, to execute when called, default="/etc/etherclient.d")
 
 -c(ertificate X509 pki-bundle, default="mycrt.pem")  
 
 -n(o run scripts, default off)
 
# Compile:
 git clone https://github.com/newsworthy39/X509-inetd-client
 
 cd X509-inetd-client
 
 RELEASE="Release"
 
 cd $RELEASE && make
