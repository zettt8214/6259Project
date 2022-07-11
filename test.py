import virtualbox
from virtualbox.library import FileCopyFlag
import os
import time

host_path = os.getcwd()
vm_path = "C:"
# vbox = virtualbox.VirtualBox()
# print([m.name for m in vbox.machines])
# machine = vbox.find_machine("Project Win7")
#
#
#mgr = virtualbox.Manager()
#session2 = mgr.get_session()
#machine.lock_machine(session2,virtualbox.library.LockType.shared)
# sample_path = "\\Sample\\test.txt"
# src =  host_path + sample_path
# dst = vm_path + sample_path
# print(src)
# print(dst)
# guest_session = session2.console.guest.create_session("Administrator", "vv")
# guest_session.execute("C:\\\\Windows\\System32\\cmd.exe", ["/C", "C:\\startexe.bat C:\\sample1.exe"])
# guest_session.process_create("C:\\Users\\Administrator\\Desktop\\ProcessMonitor\\Procmon.exe", ["/Terminate"],[],[],0)
# guest_session.directory_exists("C:\\Windows")
# guest_session.file_copy_to_guest(source = host_path + "\\Sample\\sample1.exe", destination = vm_path+"\\sample1.exe",  flags = [FileCopyFlag(0)])
#guest_session.file_copy_from_guest(source = vm_path + "\\eventlog.xml", destination = host_path + "\\Result\eventlog.xml",  flags = [FileCopyFlag(0)])

# proc, stdout, stderr = guest_session.execute("C:\\\\Windows\\System32\\cmd.exe", ["/C", "WEVTUtil query-events \"Microsoft-Windows-Sysmon/Operational\" /format:xml /e:sysmonview > C:\\\\Users\\Administrator\\Desktop\\Sysmon\\eventlog.xml"])
# print(stdout)

# Get memory dump
#session2.console.debugger.dump_guest_core("dump.img","")
#
# def read_snapshot(m_name, s_name):
#     start = time.time()
#     name = "read_snapshot"
#     vb = virtualbox.VirtualBox()
#     session = virtualbox.Session()
#
#     try:
#         vm = vb.find_machine(m_name)
#         snap = vm.find_snapshot(s_name)
#         vm.create_session(session=session)
#     except virtualbox.library.VBoxError as e:
#         return print(name, "failed", e.msg, True)
#     except Exception as e:
#         return print(name, "failed", str(e), True)
#
#     restoring = session.machine.restore_snapshot(snap)
#
#     while restoring.operation_percent < 100:
#         time.sleep(0.5)
#
#     session.unlock_machine()
#     if restoring.completed == 1:
#         return print(name, "success", "restoring completed in {:>.4} sec".format(str(time.time() - start)), False)
#     else:
#         return print(name, "failed", "restoring not completed", True)
#
#
# import base64
#
#
# def _base64_encode_command( command):
#     """using base64 encoded commands solves issues with quoting in the
#     VirtualBox execute function, needed as a workaround, for pythons
#     base64 function not inserting \x00 after each char
#     """
#
#     blank_command = ""
#     command = command.decode("utf-8")
#     for char in command:
#         blank_command += char + "\x00"
#
#     command = blank_command.encode("utf-8")
#     command = base64.b64encode(command)
#     return command.decode("utf-8")
#
#


# def run_shell_cmd(vb, command, cmd=False, stop_ps=False):
#     """runs a command inside the default shell of the user or in the legacy
#         cmd.exe, needs properly split arguments for cmd=True
#
#         Arguments:
#             command - command which will be executed
#             cmd - run inside a cmd or powershell
#             stop_ps - kill the powershell window after running the command
#     """
#     term = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
#     command = _base64_encode_command(command)
#     return vb.run_process(command=term,
#                                          arguments=["-OutputFormat", "Text",
#                                                     "-inputformat", "none",
#                                                     "-EncodedCommand", command])
#
#
# command = b"C:\\startexe.bat C:\\sample1.exe"
# print(_base64_encode_command(command))


from memfren import *

vol = volhandel.VolatiltyHandler()
vol.get_image_info("D:/Share/test.elf")
vol.get_network_connections()
# import re
# c = "0x7e0b3340	TCPv4	0.0.0.0	49153	0.0.0.0	0	LISTENING	776	svchost.exe	-"
# r = "(0x.+)\s+(TCPv\d)\s+(::|\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(::|\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(LISTENING|ESTABLISHED|CLOSED|CLOSE_WAIT)\s+(\d+)\s+(\w+)\s+(.+)"
#
# results = re.search(r, c)
# print(results.groups())