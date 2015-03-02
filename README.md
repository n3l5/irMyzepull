
IR Memoryze pull (irMyzepull)

DESCRIPTION:

irMyzepull is a PowerShell script utilized to pull artifacts from a live system over the network. (testing Win 8 still) 

It utilizes the Mandiant Memoryze tool to "audit and collect all running processes and drivers from memory, file system metadata, registry data, event logs, network information, services, tasks, and web history" (if configured via .xml config file)

To build a custom .xml file download Mandiant Redline.
		
NOTEs: 
- All testing done on PowerShell v4
- Requires MAgent.exe (x86 & x64)
- Requires a Memoryze audit .xml file (specified manually in script)
- Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
Assumed Directories:
- c:\windows\temp\IR - Where the work will be done (no need to create)
		
***As expected: Must be ran a user that will have Admin creds on the remote system. The assumption is that the target system is part of a domain.
	
LINKs:  
	
irMyzepull main - https://github.com/n3l5/irMyzepull
	
Links to required tools:
- Magent.exe - via Mandiant Redline collector package - https://www.mandiant.com/resources/download/redline
- 7za.exe - Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
	
Various tools for analysis of the artifacts:
- Mandiant Redline - https://www.mandiant.com/resources/download/redline
