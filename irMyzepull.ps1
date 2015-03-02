<#  
.SYNOPSIS  
    IR Memoryze pull (irMyzepull)

.DESCRIPTION
irMyzepul is a PowerShell script utilized to pull dump memory from a live WinXP-Win7 system on your network. It DOES NOT utilize WinRM capabilities.

Utilizes the Mandiant's Memoryze memory dumping tool to dump artficats. When done collecting the artifacts, it will 7zip the data and pull the info off the box for offline analysis. 

.PARAMETER Target
    This is the target computer where you will be collecting artifacts from.

.PARAMETER ToolsDir
	This the file path location of the tools on the analysis system.

.PARAMETER DumpDir
	This is the file path location you want the memory dumped. (On analysis system or other location like UNC path to server share)

.PARAMETER 7zpass
	This is the password for the compressed & password protected file that the artifacts will be put into.

.NOTEs:  
    
	All testing done on PowerShell v4
	
	Requires magent.exe (x86 & x64) for memory acquisition.
	Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
	Assumed Directories:
	c:\windows\temp\IR - Where the work will be done/copied temporarily
		
	Must be ran as a user that will have Admin creds on the remote system.
	
    LINKs:  
	
	
	Links to required tools:
	
	7-Zip commandline - Part of the 7-Zip archiver - can be downloaded from: http://www.7-zip.org/
		
	Mandian Redline for analysis of the irMyzepull dump:
	
	Mandiant Redline - https://www.mandiant.com/resources/download/redline
	
#>
#>
Param(
  [Parameter(Mandatory=$True,Position=0)]
   [string]$target,
   
   [Parameter(Mandatory=$True)]
   [string]$toolsDir,
   
   [Parameter(Mandatory=$True)]
   [string]$dumpDir,
   
   [Parameter(Mandatory=$True)]
   [string]$7zpass
     
    )
   
echo "=============================================="
echo "=============================================="
Write-Host -Fore Magenta "


  _      __  __                           _ _ 
 (_)    |  \/  |                         | | |
  _ _ __| \  / |_   _ _______ _ __  _   _| | |
 | | '__| |\/| | | | |_  / _ \ '_ \| | | | | |
 | | |  | |  | | |_| |/ /  __/ |_) | |_| | | |
 |_|_|  |_|  |_|\__, /___\___| .__/ \__,_|_|_|
                 __/ |       | |              
                |___/        |_|              


 "
echo ""
echo "=============================================="
Write-Host -Fore Yellow "Run as administrator/elevated privileges!!!"
echo "=============================================="
echo ""

Write-Host -Fore Cyan ">>>>> Press a key to begin...."
[void][System.Console]::ReadKey($TRUE)
echo ""
echo ""
$userDom = Read-Host "Enter your target DOMAIN (if any)..."
$username = Read-Host "Enter you UserID..."
$domCred = "$userDom" + "\$username"
$compCred = "$target" + "\$username"
#Fill credentials based on whether domain or remote system credentials used 
if (!($userDom)){
	$cred = Get-Credential $compCred
	}
else {
	$cred = Get-Credential $domCred
	}
echo ""

#Test if the box is up and running

Write-Host -Fore Yellow ">>>>> Testing connection to $target...."
echo ""
if ((!(Test-Connection -Cn $target -BufferSize 16 -Count 1 -ea 0 -quiet)) -OR (!($socket = New-Object net.sockets.tcpclient("$target",445)))) {
	Write-Host -Foreground Magenta "$target appears to be down"
	}

################
#Target is up start the collection
################

else {

#Determine if Mail Alert is wanted ask for particulars
if ($mail -like "Y*") {
	$mailTo = Read-Host "Enter alert TO: email address...multiples should separated with a comma"
	$mailFrom = Read-Host "Enter alert FROM: email address..."
	$smtpServer = Read-Host "Enter SMTP relay server..."
	}
elseif ((!($mail)) -OR ($mail -like "N*")) {
	Write-Host -Foregroundcolor Cyan "  -Mail notification off-"
	}

#Get system info
	$targetName = Get-WMIObject -class Win32_ComputerSystem -ComputerName $target -Credential $cred | ForEach-Object Name
	$targetIP = Get-WMIObject -class Win32_NetworkAdapterConfiguration -ComputerName $target -Credential $cred -Filter "IPEnabled='TRUE'" | Where {$_.IPAddress} | Select -ExpandProperty IPAddress | Where{$_ -notlike "*:*"}
	$mem = Get-WMIObject -class Win32_PhysicalMemory -ComputerName $target -Credential $cred | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)} 
	$mfg = Get-WmiObject -class Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty manufacturer
	$model = Get-WmiObject Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty model
	$pctype = Get-WmiObject Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty PCSystemType
	$sernum = Get-wmiobject Win32_Bios -ComputerName $target -Credential $cred | select -ExpandProperty SerialNumber
	$tmzn = Get-WmiObject -class Win32_TimeZone -Computer $target -Credential $cred | select -ExpandProperty caption

#Display logged in user info (if any)	
	if ($expproc = gwmi win32_process -computer $target -Credential $cred -Filter "Name = 'explorer.exe'") {
		$exuser = ($expproc.GetOwner()).user
		$exdom = ($expproc.GetOwner()).domain
		$currUser = "$exdom" + "\$exuser" }
	else { 
		$currUser = "NONE" 
	}

echo ""
echo "=============================================="
Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"

$arch = Get-WmiObject -Class Win32_Processor -ComputerName $target -Credential $cred | foreach {$_.AddressWidth}

#Determine XP or Win7
$OSvers = Get-WMIObject -Class Win32_OperatingSystem -ComputerName $target -Credential $cred | foreach {$_.Version}

Write-Host -ForegroundColor Magenta "==[ Host OS: $OSvers x$arch"
Write-Host -ForegroundColor Magenta "==[ Total memory size: $mem GB"
Write-Host -ForegroundColor Magenta "==[ Manufacturer: $mfg"
Write-Host -ForegroundColor Magenta "==[ Model: $model"
Write-Host -ForegroundColor Magenta "==[ System Type: $pctype"
Write-Host -ForegroundColor Magenta "==[ Serial Number: $sernum"
Write-Host -ForegroundColor Magenta "==[ Timezone: $tmzn"
Write-Host -ForegroundColor Magenta "==[ Current logged on user: $currUser"
	
echo "=============================================="
echo ""

################
##Set up environment on remote system. IR folder for memtools and art folder for memory.##
################
##For consistency, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator system.
##Tools will stored directly in the "IR" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.

##Set up PSDrive mapping to remote drive
	New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$ -Credential $cred | Out-Null
    
	$remoteMEMfold = "x:\windows\Temp\IR"
	New-Item -Path $remoteMEMfold -ItemType Directory | Out-Null
	$irFolder = "C:\windows\Temp\IR"
	$date = Get-Date -format yyyy-MM-dd_HHmm_

#######
#Run Memoryze remote
#######

#Copy mAgent base on arch

	if ($arch -like "32") 
	{
		Copy-Item $toolsDir\x86\mAgent.exe $remoteMEMfold -recurse
	}
	if ($arch -like "64") 
	{
		Copy-Item $toolsDir\x64\mAgent.exe $remoteMEMfold -recurse
	}

#Copy Audit script & 7za
	Copy-Item $toolsDir\*.xml $remoteMEMfold
	Copy-Item $toolsDir\7za.exe $remoteMEMfold

#Set up environment	
	$memName = $date + $targetName + "_myzedump"
	$dumpPath = $irFolder+"\"+$memName
		
#Setup commands
	$myzeargs = "-o $dumpPath -script myzeComprehensive.xml -encoding none"
	$myzedump = "cmd /c $irFolder\mAgent.exe $myzeargs" 
		
#Send command to capture remotely	
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $myzedump -ComputerName $target -Credential $cred | Out-Null
	
	echo "=============================================="
	Write-Host -ForegroundColor Magenta ">>>[Memory acquisition started]<<<"
	echo "=============================================="
	echo ""
	$time1 = (Get-Date).ToShortTimeString()
	Write-host -Foregroundcolor Cyan "-[ Start time: $time1 ]-"
	
#Monitor the Winpmem process
	do {(Write-Host -ForegroundColor Yellow "   >> Memoryze dumping info..."),(Start-Sleep -Seconds 180)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='mAgent.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "mAgent.exe"}).ProcessID -eq $null)
	Write-Host -ForegroundColor Green " [done]"

#Setup compress command
	
	$7z = "cmd /c $irFolder\7za.exe a $dumpPath.7z -p$7zpass -mmt -mhe $dumpPath"

#Start memory capture compress
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target -Credential $cred | Out-Null

#Monitor the 7za process
	do {(Write-Host -ForegroundColor Yellow "   >> compressing image..."),(Start-Sleep -Seconds 180)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='7za.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "7za.exe"}).ProcessID -eq $null)
	Write-Host -ForegroundColor Green " [done]"

#Time conversion
	$time2 = (Get-Date).ToShortTimeString()
	Write-host -Foregroundcolor Cyan "-[ End time: $time2 ]-"
	
	$timeDiff = NEW-TIMESPAN –Start $time1 –End $time2
	Write-Host "Memory dump process time $timeDiff minutes"
	
#################
##Package pull
###################
echo ""
echo "=============================================="
Write-Host -Fore Magenta ">>>[Transferring the image...]<<<"
echo "=============================================="
echo ""

##size it up
$remDumppath = $remoteMEMfold+"\"+$memName+".7z"

$7zsize = "{0:N2}" -f ((Get-ChildItem $remDumppath | Measure-Object -property length -sum ).Sum / 1GB) + " GB"
Write-Host -ForegroundColor Cyan "  Image size: $7zsize "

Write-Host -Fore Green "Transfering the image...."
if (!(Test-Path -Path $irFolder -PathType Container)){
	New-Item -Path $irFolder -ItemType Directory  | Out-Null
}

Move-Item $remDumppath $dumpDir
Write-Host -Fore Yellow "  [done]"

###Delete the remote IR folder 7 tools##
Write-Host -Fore Green "Removing the remote working environment...."
Remove-Item $remoteMEMfold -Recurse -Force 

##Disconnect the PSDrive X mapping##
Remove-PSDrive X

##Ending##
$endTime = Get-Date -format yyyy-MM-dd_HHmm
Write-Host -Foregroundcolor Cyan "-[ End time: $endTime ]-"
echo "=============================================="
Write-Host -ForegroundColor Magenta ">>>>>>>>>>[ irMemPull complete ]<<<<<<<<<<<"
echo "=============================================="
}