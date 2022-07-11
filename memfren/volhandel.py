import re
import sys
import hashlib
import subprocess
from  .config import *
from .errorhandel import ErrorHandler

class VolatiltyHandler():
    def __init__(self):
        self._volatility_handler = ""
        self._is_vol_okay = 0
        self._error_handler = ErrorHandler()
        # Analysis structure
        self._image_type = ""
        self._image_location = ""
        self._volname = vol_path
        self._all_processes = ""
        self._md5sum = ""
        self._imagesize = ""
        self._hives = []
        self._creds = []
        self._connections_udp = []
        self._connections_tcp = []
        self._startup_keys = []
        self._drivers = []

    def regex_search(self, data, regex):
        """
        This function runs regex search on data given
        and returns output.
        :data the data to run through the filter
        :regex the regex query
        :return the filtered result of the search
        """
        results = re.search(regex, data)
        return results

    def get_image_info(self, imagelocation):
        '''
        This function will try to get the image_type of the memory image
        If the imagetype is not successfully extracted an exception will occur.
        The imagetype will be returned to class var self._imagetype

        Other functions depend on this function to create the parent attribute of the file name.

        This function will also match the complete image path in to the class var self._image_location
        :param imagelocation: The file location of the image to be analyzed
        :return: Will return a 1 in case of an error
        '''

        self._error_handler.error_log(1, "Getting image type...")

        self._image_location = str(imagelocation)
        print(vol_path)
        print(self._volname)
        command = "python " + self._volname + " -f " + str(imagelocation) + " windows.info"
        status, output = subprocess.getstatusoutput(command)
        if status == 0:
           print(status, output)
        else:
            self._error_handler.error_log(4, "Did not detect the information.")

    def get_process_list(self):
        '''
        This function will extract all processes listed in memory image using
        psscan method in vol.py
        '''

        # Function vars
        class vol_proc(object):
            def __init__(self):
                pass

        self._error_handler.error_log(1, "Getting all processes from file using 'psscan'")

        regi1 = "([0x].........)\s(.+.exe)\s+(\d+)\s+(\d+)\s+([0x].........)\s+(............................)"
        regi = "(\d+)\s+(\d+)\s+(.+\.exe)\s+([0x]\w+)\s+(\d*)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"
        all_processes = []

        # Execute command
        command = "python " + self._volname + " -f " + self._image_location + " windows.pslist"
        print(command)
        status, output = subprocess.getstatusoutput(command)

        output = output.split('\n')
        print(output)
        # Check if there is any output from command
        if len(output) == 0:
            self._error_handler.error_log(3, "Finding process command returned 0 results")
            return 1

        for proc in output:
            temp = self.regex_search(proc, regi)
            try:
                temp = temp.groups()
                process = vol_proc()
                process.pid = temp[0]
                process.ppid = temp[1]
                process.name = temp[2]
                process.offset = temp[3]
                process.create_time = temp[8]
                all_processes.append(process)
            except:
                # no matches found
                pass
        self._error_handler.error_log(0, "Got " + str(len(all_processes)) + " processes using 'psscan'")
        self._all_processes = all_processes


    def hive_list(self):
        '''
        This function will extract all hives listed in memory image using
        hivelist method in vol.py
        '''

        class hive(object):
            def __init__(self):
                pass

        self._error_handler.error_log(1, "Starting hivelist harvesting")

        #regi = "(0x........)\s(0x........)\s(.+)"
        regi = "(0x\w+)\s+(.+)\s+"
        hives = []

        command = "python " + self._volname + " -f " + self._image_location + " windows.registry.hivelis"
        status, output = subprocess.getstatusoutput(command)

        output = output.split('\n')
        print(output)
        if len(output) == 0:
            self._error_handler.error_log(1, "Finding hivelist returned 0 results")
            return 1

        for hive_i in output:
            temp = self.regex_search(hive_i, regi)
            try:
                temp = temp.groups()

                current_hive = hive()
                current_hive.offset = temp[0]
                current_hive.name = temp[1]
                hives.append(current_hive)
            except:
                # no matches found
                pass

        self._error_handler.error_log(0, "Got " + str(len(hives)) + " hives using 'hivelist'")
        self._hives = hives


    def find_hashes(self):
        '''
        This function will find hashes in memory. After that it will build an object
        of credentials for each credentials found and turn it into a global object.
        '''

        class hash(object):
            def __init__(self):
                pass

        self._error_handler.error_log(1, "Starting hash harvesting")

        all_creds = []

        sam_offset = ""
        sys_offset = ""

        regi = "(\w+)\s+(\d+)\s+(.{32})\s+(.{32})"


        command = "python " + self._volname + " -f " + self._image_location + " windows.hashdump"
        status, output = subprocess.getstatusoutput(command)

        output = output.split('\n')
        print(output)
        output = output[1:]

        if len(output) == 0:
            self._error_handler.error_log(1, "Found 0 users.")
            return 1

        for creds in output:
            temp = self.regex_search(creds, regi)
            try:
                temp = temp.groups()
                print(temp)
                current_creds = hash()
                current_creds.username = temp[0]
                current_creds.rid = temp[1]
                current_creds.lmhash = temp[2]
                current_creds.nthash = temp[3]
                all_creds.append(current_creds)
            except:
                # no matches found
                pass

        self._creds = all_creds
        self._error_handler.error_log(0, "Found %s hashes in memory" % len(all_creds))

    def get_network_connections(self):
        '''
        DO NOT start reading or changing this function!
        There is some black magic regex voodoo here and it's not nice.
        Basically it will give you a list of network connections splitted by TCP
        and by UDP but i don't think you want to go into this...
        '''

        self._error_handler.error_log(1, "Getting network traffic information'")

        class net_socket(object):
            def __init__(self):
                pass

        tcp_array = []
        udp_array = []

        #tcp_regex = "(0x........)\s(TCPv\d)\s+(.+):(\d{1,5})\s+(.+):(\d{1,5})\s+(LISTENING | ESTABLISHED | CLOSED | CLOSE_WAIT)\s+([0-9-]+)\s+(.+)"
        tcp_regex = "(0x.+)\s+(TCPv\d)\s+(::|\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(::|\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(LISTENING|ESTABLISHED|CLOSED|CLOSE_WAIT)\s+(\d+)\s+(\w+)\s+(.+)"
        udp_regex = "(0x.+)\s(UDPv\d)\s+(.+):(\d{1,5})\s+[*:]{3}\s+([0-9-]+)\s+([a-zA-Z.-]+)\s+([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC[0-9+]+)"

        xp = self._image_type.find("WinXP")
        sev = self._image_type.find("Win7")

        command = "python " + self._volname + " -f " + self._image_location + " windows.netscan.NetScan"
        status, output = subprocess.getstatusoutput(command)
        output = output.split('\n')

        print(output)
        if len(output) == 0:
            self._error_handler.error_log(3, "Can not get the net information!")
            return 1

        for connection in output:
            tcp = connection.find("TCP")
            udp = connection.find("UDP")

            if udp == 11:
                try:
                    # This is a UDP Connection
                    temp = self.regex_search(connection, udp_regex)
                    temp = temp.groups()
                    current_conn = net_socket()
                    current_conn.offset = temp[0]
                    current_conn.ver = temp[1]
                    current_conn.bind_add = temp[2]
                    current_conn.bind_port = temp[3]
                    current_conn.pid = temp[4]
                    current_conn.p_name = temp[5]
                    current_conn.time = temp[6]
                    udp_array.append(current_conn)
                except:
                    continue

            elif tcp == 11:
                # This is a TCP Connection
                try:
                    print("tcp")
                    print(connection)
                    temp = self.regex_search(connection, tcp_regex)
                    temp = temp.groups()
                    print(temp)
                    current_conn = net_socket()
                    current_conn.offset = temp[0]
                    current_conn.ver = temp[1]
                    current_conn.bind_add = temp[2]
                    current_conn.bind_port = temp[3]
                    current_conn.remote_addr = temp[4]
                    current_conn.remote_port = temp[5]
                    current_conn.state = temp[6]
                    current_conn.pid = temp[7]
                    tcp_array.append(current_conn)
                except:
                    continue

            else:
                # Item matched nothing
                pass

        self._connections_tcp = tcp_array
        self._connections_udp = udp_array
        self._error_handler.error_log(0, "Found %s UDP Connections" % len(udp_array))
        self._error_handler.error_log(0, "Found %s TCP Connections" % len(tcp_array))