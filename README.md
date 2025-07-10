ubootwrite
========
Is a simple python tool that uploads binary images to the RAM of linux systems running the U-Boot bootloader (e.g. for OpenWRT) via the serial port. It works in cases where no transfer via alternate methods (XMODEM/TFTP/BOOTM/etc.) can be made. ubootwrite has a high overhead, as the binary file is converted to ASCII and sent in 32Bit chunks, so transferring larger amounts of data can be really slow.

The original author is "pgid69" and the original source is the [OpenWRT forum](https://forum.openwrt.org/viewtopic.php?pid=183315#p183315). The initial commit is the original version found in the forum and "pgid69" states the tool is based on [brntool](https://github.com/rvalles/brntool).

License
========
[GPLv3](http://opensource.org/licenses/GPL-3.0). See [LICENSE.md](LICENSE.md).

Dependencies
========
python(3)  
python(3)-pyserial

Installation
========
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ubootwrite
   ```

2. The script is executable, so you can run it directly:
   ```bash
   ./ubootwrite.py [OPTIONS]
   ```

   Or with Python explicitly:
   ```bash
   python3 ubootwrite.py [OPTIONS]
   ```

Overview
========
Use Python (preferably 3.0+) to run the tool: ```./ubootwrite.py [OPTIONS]``` or ```python ubootwrite.py [OPTIONS]```.  

**Options:**  
* ```--verbose``` - Be verbose and show detailed progress information (very noisy).  
* ```--serial``` - The serial port to write to, e.g. ```--serial=/dev/ttyUSB2```. It will open it with 8 data bits, one stop bit.  
* ```--speed``` - The serial port speed, e.g. ```--speed=9600``` (default 115200).  
* ```--write``` - The file to transfer to RAM, e.g. ```--write=openwrt-squashfs.image```.  
* ```--addr``` - The RAM start address to write to, e.g. ```--addr=0x80050000```.  
* ```--size``` - The number of bytes to transfer, e.g. ```--size=12345```. Omit to transfer the whole file.  
* ```--big``` - Target is big-endian (default little-endian).  
* ```--skip-check``` - Skip serial port availability check (use with caution).  

**An example for a full command line could be:**  
```bash
./ubootwrite.py --serial=/dev/ttyUSB6 --write=openwrt-squashfs.image --addr=0x80050000
```

This can take a looong time. Be patient. The script will show progress information including transfer speed and estimated time remaining.

Once you have the data in RAM you can copy it to flash. **Note: The following commands are examples and are device-dependent. Consult your device's documentation for the correct flash commands:**
Unprotecting flash: ```protect off all```  
Erasing the sectors: ```erase [ADDRESS_IN_FLASH] +[SIZE_OF_DATA]``` (all in hex)  
Copying the data to flash: ```cp.b [RAM_ADRESS] [ADDRESS_IN_FLASH] [SIZE_OF_DATA]``` (all in hex)

Troubleshooting
========
**Q:** I'm on linux and I can not access the serial port somehow...  
**A:** You might need to add your USERNAME to the dialout group: ```sudo usermod -a -G dialout USERNAME``` or use sudo.  

**Q:** The script says the serial port is already in use...  
**A:** The script automatically detects when another application (like screen, minicom, gtkterm, etc.) is using the serial port. Close the other application first, or use the `--skip-check` option to override this check (use with caution).

**Q:** The script fails to get the U-Boot prompt...  
**A:** Make sure U-Boot is running and responding on the serial port. Use `--verbose` for debugging if needed.

**Q:** The transfer is very slow...  
**A:** This is normal for this tool as it sends data in 32-bit chunks via U-Boot commands. For faster transfers, consider using U-Boot's built-in XMODEM, TFTP, or other transfer methods if available.

I found a bug or have a suggestion
========
The best way to report a bug or suggest something is to post an issue on GitHub. Try to make it simple, but descriptive and add ALL the information needed to REPRODUCE the bug. **"Does not work" is not enough!** You can also submit a pull request if you have a fix or improvement.
