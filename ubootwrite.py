#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import division #1/2 = float, 1//2 = integer, python 3.0 behaviour in 2.6, to make future port to 3 easier.
from __future__ import print_function
from optparse import OptionParser
import os
import struct
import sys
import zlib
import time
import serial
import subprocess

# The maximum size to transfer if we can determinate the size of the file (if input data comes from stdin).
MAX_SIZE = 2 ** 30
LINE_FEED = "\n"

def check_serial_port_available(port, verbose):
        """Check if serial port is available and not in use by another process"""
        if verbose:
                print(f"Checking if {port} is available...")
        
        # First check if the port file exists
        if not os.path.exists(port):
                return False, f"Port {port} does not exist"
        
        # Check if any process is using the port using lsof
        process_info = find_process_using_port(port)
        if process_info and "Unknown process" not in process_info:
                return False, process_info
        
        # Try to open the port to see if it's available
        try:
                test_ser = serial.Serial(port, 115200, timeout=1)
                test_ser.close()
                if verbose:
                        print(f"{port} is available")
                return True, None
        except serial.SerialException as e:
                error_msg = str(e)
                if "Permission denied" in error_msg or "device reports readiness" in error_msg:
                        # Port is in use, but lsof didn't find it, try again
                        process_info = find_process_using_port(port)
                        if process_info and "Unknown process" not in process_info:
                                return False, process_info
                        else:
                                return False, f"Port is in use: {error_msg}"
                else:
                        # Other error (port doesn't exist, etc.)
                        return False, error_msg
        except Exception as e:
                return False, str(e)

def find_process_using_port(port):
        """Find which process is using the serial port"""
        try:
                # Use lsof to find processes using the port
                result = subprocess.run(['lsof', port], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                        # Parse the output to get process info
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:  # Skip header line
                                process_line = lines[1]  # First process
                                parts = process_line.split()
                                if len(parts) >= 2:
                                        process_name = parts[0]
                                        pid = parts[1]
                                        return f"Process '{process_name}' (PID {pid})"
                        return "Unknown process"
                else:
                        # Try alternative method using fuser
                        try:
                                result = subprocess.run(['fuser', port], capture_output=True, text=True, timeout=5)
                                if result.returncode == 0 and result.stdout.strip():
                                        pids = result.stdout.strip().split()
                                        if pids:
                                                # Try to get process name for the first PID
                                                try:
                                                        with open(f'/proc/{pids[0]}/comm', 'r') as f:
                                                                process_name = f.read().strip()
                                                        return f"Process '{process_name}' (PID {pids[0]})"
                                                except:
                                                        return f"Process (PID {pids[0]})"
                        except:
                                pass
                        return "Unknown process (lsof returned no results)"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                return "Unknown process (could not run lsof)"
        except Exception:
                return "Unknown process"

# Wait for the prompt
def getprompt(ser, verbose):

        # Flush receive buffer
        while ser.read(256):
                pass
        
        # Send a linefeed to get the prompt
        ser.write(str.encode(LINE_FEED))
        # Read the response
        buf = ser.read(256);
        if (buf.endswith(b"> ") or buf.endswith(b"# ")):
                # Extract just the last line (the prompt)
                lines = buf.decode().replace('\r', '\n').split('\n')
                prompt = lines[-1].encode()
                if verbose:
                        print("Prompt is '" + prompt.decode() + "'")
                return prompt
        else:
                print("Error: Could not get U-Boot prompt")
                sys.exit(1)

# Send command, verify echo, wait for prompt and return result
def send_command(ser, command, prompt, verbose):

        # Write the command and a line feed
        ser.write(str.encode(command + LINE_FEED))
        
        # Read and verify echo
        buf = ser.read(len(command))
        if (buf.decode() != command):
                if verbose:
                        print("Echo mismatch. Expected '{0}', got '{1}'".format(command, buf.decode()))
                return None

        # Read response byte by byte until we find the prompt
        buf = b''
        while True:
                byte = ser.read(1)
                if not byte:  # Timeout or no more data
                        break
                buf += byte
                # Check if we have the prompt at the end
                if buf.endswith(prompt):
                        if verbose:
                                print("Command completed successfully")
                        # Return everything except the prompt
                        return buf[:-len(prompt)]
        
        if verbose:
                print("Prompt not received. Instead received '" + buf.decode() + "'")
        return None

# Wait for the prompt and return True if received or False otherwise 
def writecommand(ser, command, prompt, verbose):

        result = send_command(ser, command, prompt, verbose)
        return result is not None



def get_uboot_crc32(ser, start_addr, size, verbose, prompt):
        """Get CRC32 from U-Boot using crc32 command"""
        if verbose:
                print("Getting CRC32 from U-Boot...")
        
        # Run U-Boot crc32 command
        crc_cmd = "crc32 {0:08x} {1:08x}".format(start_addr, size)
        if verbose:
                print("Running:", crc_cmd)
        
        # Send command and get response
        buf = send_command(ser, crc_cmd, prompt, verbose)
        if buf is None:
                return None
        
        # Parse the CRC32 value from U-Boot response
        # Response format is typically: "crc32 for 0xaddr ... 0xaddr+size ==> 0x12345678"
        try:
                response_str = buf.decode()
                if verbose:
                        print("Full CRC32 response: '{0}'".format(repr(response_str)))
                # Look for the CRC32 value (8 hex digits after "==>")
                if "==>" in response_str:
                        crc_part = response_str.split("==>")[1]
                        if verbose:
                                print("CRC part after '==>': '{0}'".format(repr(crc_part)))
                        # Clean up the CRC value - remove whitespace, carriage returns, and prompt
                        crc_hex = crc_part.split()[0].strip()  # Take first word, remove whitespace
                        if verbose:
                                print("Extracted CRC hex: '{0}'".format(crc_hex))
                        # Extract the hex value
                        crc_val = int(crc_hex, 16)
                        return crc_val
                else:
                        print("Unexpected CRC32 response format:", response_str)
                        return None
        except Exception as e:
                print("Error parsing CRC32 response:", e)
                return None

def memwrite(ser, path, size, start_addr, verbose, big_endian):
        
        prompt = getprompt(ser, verbose)
        
        if (path == "-"):
                fd = sys.stdin
                if (size <= 0):
                        size = MAX_SIZE 
        else:
                fd = open(path,"rb")
                if (size <= 0):
                        # Get the size of the file
                        fd.seek(0, os.SEEK_END);
                        size = fd.tell();
                        fd.seek(0, os.SEEK_SET);

        addr = start_addr
        bytes_read = 0
        crc32_checksum = 0
        startTime = time.time();
        bytesLastSecond = 0
        
        while (bytes_read < size):
                if ((size - bytes_read) > 4):           
                        read_bytes = fd.read(4);
                else:
                        read_bytes = fd.read(size - bytes_read);

                if (len(read_bytes) == 0):
                        if (path == "-"):
                                size = bytes_read
                        break

                bytesLastSecond += len(read_bytes)
                bytes_read += len(read_bytes)
                crc32_checksum = zlib.crc32(read_bytes, crc32_checksum) & 0xFFFFFFFF
                
                while (len(read_bytes) < 4):
                        read_bytes += b'\x00'

                if big_endian:
                        (val, ) = struct.unpack(">L", read_bytes)
                else:
                        (val, ) = struct.unpack("<L", read_bytes)

                str_to_write = "mw {0:08x} {1:08x}".format(addr, val)
                if verbose:
                        print("Writing:" + str_to_write + "at:", "0x{0:08x}".format(addr))

                if not writecommand(ser, str_to_write, prompt, verbose):
                        print("Found an error at address 0x{0:08x}, so aborting".format(addr))
                        fd.close()
                        return
                
                # Print progress
                currentTime = time.time();
                if ((currentTime - startTime) > 1):
                        print("\rProgress {:2.1f}%".format((bytes_read * 100) / size), end = '')
                        print(", {:3.1f}kb/s".format(bytesLastSecond / (currentTime - startTime) / 1024), end = '')
                        print(", ETA {0}s   ".format(round((size - bytes_read) / bytesLastSecond / (currentTime - startTime))), end = '')
                        bytesLastSecond = 0
                        startTime = time.time();

                # Increment address
                addr += 4

        if (bytes_read != size):
                print("Error while reading file '", fd.name, "' at offset " + bytes_read)
        else:
                totalTime = time.time() - startTime;
                print("\rProgress 100%", end = '')
                print(", {:3.1f}kb/s".format(bytes_read / totalTime / 1024), end = '')
                print(", Total time {0}s   ".format(round(totalTime)))
                # Automatically verify CRC using U-Boot command
                uboot_crc = get_uboot_crc32(ser, start_addr, bytes_read, verbose, prompt)
                if uboot_crc is not None:
                        if uboot_crc == crc32_checksum:
                                print("File successfully written. CRC32 verification PASSED: {0:08x}".format(uboot_crc))
                        else:
                                print("File successfully written. CRC32 verification FAILED!")
                                print("Expected: {0:08x}".format(crc32_checksum))
                                print("Got:      {0:08x}".format(uboot_crc))
                else:
                        print("File successfully written. CRC32 verification failed - could not get CRC from U-Boot")

        fd.close()
        return

def main():
        optparser = OptionParser("usage: %prog [options]", version = "%prog 0.3")
        optparser.add_option("--verbose", action = "store_true", dest = "verbose", help = "be verbose", default = False)
        optparser.add_option("--serial", dest = "serial", help = "specify serial port", default = "/dev/ttyUSB0", metavar = "dev")
        optparser.add_option("--write", dest = "write", help = "write mem from file", metavar = "path")
        optparser.add_option("--addr", dest = "addr", help = "mem address", default = "0x80500000", metavar = "addr")
        optparser.add_option("--size", dest = "size", help = "# bytes to write", default = "0", metavar = "size")
        optparser.add_option("--big", action = "store_true", dest = "big_endian", help = "target is big-endian (default little-endian)", default = False)
        optparser.add_option("--speed", dest = "speed", help = "serial port speed (default 115200)", default = "115200", metavar = "speed")
        optparser.add_option("--skip-check", action = "store_true", dest = "skip_check", help = "skip serial port availability check", default = False)
        (options, args) = optparser.parse_args()
        if (len(args) != 0):
                optparser.error("incorrect number of arguments")

        # Check if serial port is available before trying to open it (unless --skip-check is used)
        if not options.skip_check:
                port_available, process_info = check_serial_port_available(options.serial, options.verbose)
                if not port_available:
                        print(f"Error: Serial port {options.serial} is not available.")
                        if process_info and "Unknown process" not in process_info:
                                print(f"Port is being used by: {process_info}")
                                print("Please close the other application or kill the process and try again.")
                                print("Or use --skip-check to override this check.")
                        else:
                                print(f"Error details: {process_info}")
                                print("Use --skip-check to override this check.")
                        sys.exit(1)
        else:
                if options.verbose:
                        print("Skipping port availability check (--skip-check specified)")

        ser = serial.Serial(options.serial, int(options.speed), timeout=0.1)
        
        # Send Ctrl+C to clear any pending input and ensure a clean prompt
        ser.write(b'\x03')
        time.sleep(0.2)  # Give U-Boot a moment to process Ctrl+C
        # Send extra newlines to ensure prompt is ready
        ser.write(str.encode(LINE_FEED))
        ser.write(str.encode(LINE_FEED))
        time.sleep(0.2)
        
        if options.write:
                memwrite(ser, options.write, int(options.size, 0), int(options.addr, 0), options.verbose, options.big_endian)
        return

if __name__ == '__main__':
        main()
