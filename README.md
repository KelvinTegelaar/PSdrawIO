# PSDrawIO

This is the CyberDrain PowerShell wrapper for draw.io.
  

# Installation instructions

This module has been published to the PowerShell Gallery. Use the following command to install:  

    install-module PsdrawIO


# Usage

  
**Examples:**
outputs a scan of the network 192.168.15.1/24 and prints the resulting CSV to the console
```powershell
New-Networkmap -Network 192.168.15.1/24 -Layout organic
```
outputs a scan of the network 192.168.15.1/24 and prints the resulting CSV to a file
```powershell
 New-Networkmap -Network 192.168.15.1/24 -Layout organic | out-file "C:\Temp\Example.csv"
```
outputs a scan of all connected networks to this device, and prints the resulting CSV to a file

```powershell
 New-Networkmap -Layout organic | out-file "C:\Temp\Example.csv"
```

You can import the CSV file via insert -> advanced -> CSV file

# Example

Example screenshot

![Example](Example.png)

# Contributions

Feel free to send pull requests or fill out issues when you encounter them. I'm also completely open to adding direct maintainers/contributors and working together! :)

# Future plans

- [x] Make basic network map
- [ ] Automatic Import to Draw.io
- [ ] LLDP support to find network topology
- [ ] Create Application map of current device
- [ ] Create configuration scan of current device
