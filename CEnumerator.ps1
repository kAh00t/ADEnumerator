# CEnumerator - Grab version information and other fun stuff 
# Version : 0.2 (use at own risk)
# Created by: David Manuel
# Date: 21/06/2021 
# Description: Windows AD connected/domain joined endpoint enumerator. Output of cme needs filters (commands below) and use : for delimeter in Excel to go over data. 

# Useage: 
# Launch command directly in memory, requires outbound 443, might trigger AV lol 
# powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kAh00t/ADEnumerator/main/CEnumerator.ps1')"
# OR
# crackmapexec smb 192.168.123.0/24 -u 'USERNAME' -p 'PASSWORD' -x "powershell.exe -exec Bypass -C \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kAh00t/ADEnumerator/main/CEnumerator.ps1')\"" | tee cmeoutput.txt

# OR

# crackmapexec smb alive-windowsmachines.txt -u 'username' -p 'password' -X "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kAh00t/ADEnumerator/main/CEnumerator.ps1')" | tee output.txt

# Parse and remove weird encoding string issue I've not worked out 
# cat cmeoutput.txt | grep ">>>" | cut -d ">" -f 4 | sed -e 's/\[0m//' >> excel-parsed.csv


# sed -i '1s/^/    CME    windowsVersion        windowsEdition  ipAddress       CurrentDomain   computerName    defaultGateway  osSupported     LastGPOAppliedTime    lastSecurityUpdate    LocalGuestAccountEnabled    LocalAdmins    FirewallServiceRunning    firewallStatusDomain    firewallStatusPrivate    firewallStatusPublic    ChromeInstalled    chromeVersion    FirefoxInstalled    firefoxVersion    EdgeInstalled    msedgeVersion    IEInstalled    ieVersion    AVEnabled2    AVOnAccess    AVRealTimeProtectionEnabled    AVSignatureAge    /' output.txt
# Open the parsed file, remember to choose : as delimeter. 
# libreoffice excel-parsed.csv 


# Table Columns:    CME    windowsVersion    windowsEdition    ipAddress    CurrentDomain    computerName    defaultGateway    osSupported    LastGPOAppliedTime    lastSecurityUpdate    LocalGuestAccountEnabled    LocalAdmins    FirewallServiceRunning    firewallStatusDomain    firewallStatusPrivate    firewallStatusPublic    ChromeInstalled    chromeVersion    FirefoxInstalled    firefoxVersion    EdgeInstalled    msedgeVersion    IEInstalled    ieVersion    AVEnabled2    AVOnAccess    AVRealTimeProtectionEnabled    AVSignatureAge    

# Function to write out variables to console
function DisplayOutput {
	    param([String]$grouping,[String]$category,[String]$output) 
       # Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:${grouping}:${category}:${output}"
} 


function DisplayOutputAlt {
    # Write-Host "+++ windowsVersion^windowsEdition^ipAddress^CurrentDomain^computerName^defaultGateway^osSupported^LastGPOAppliedTime^lastSecurityUpdate^LocalGuestAccountEnabled^LocalAdmins^FirewallServiceRunning^firewallStatusDomain^firewallStatusPrivate^firewallStatusPublic^ChromeInstalled^chromeVersion^FirefoxInstalled^firefoxVersion^EdgeInstalled^msedgeVersion^IEInstalled^ieVersion^AVEnabled2^AVOnAccess^AVRealTimeProtectionEnabled^AVSignatureAge"    
    Write-Host "`t+++`tcomputerName`twindowsVersion`twindowsEdition`tipAddress`tCurrentDomain`t defaultGateway`t osSupported`t LastGPOAppliedTime`t lastSecurityUpdate`t localGuestAccountEnabled`t LocalAdmins`t FirewallServiceRunning`t firewallStatusDomain`t firewallStatusPrivate`t firewallStatusPublic`t ChromeInstalled`t chromeVersion`t FirefoxInstalled`t firefoxVersion`t EdgeInstalled`t msedgeVersion`t IEInstalled`t ieVersion`t AVEnabled2`t AVOnAccess`t AVRealTimeProtectionEnabled`tAVSignatureAge`t"
    Write-Host "`t+++`t${computerName}`t${windowsVersion}`t${windowsEdition}`t${ipAddress}`t${CurrentDomain}`t${defaultGateway}`t${osSupported}`t${LastGPOAppliedTime}`t${lastSecurityUpdate}`t${localGuestAccountEnabled}`t${LocalAdmins}`t${FirewallServiceRunning}`t${firewallStatusDomain}`t${firewallStatusPrivate}`t${firewallStatusPublic}`t${ChromeInstalled}`t${chromeVersion}`t${FirefoxInstalled}`t${firefoxVersion}`t${EdgeInstalled}`t${msedgeVersion}`t${IEInstalled}`t${ieVersion}`t${AVEnabled2}`t${AVOnAccess}`t${AVRealTimeProtectionEnabled}`t${AVSignatureAge}`t"

} 

# Main Function 
function EnumerateEachMachine
{
             ######################## Variables ##############################
             try {$windowsVersion = ([environment]::OSVersion.Version).build}
             catch {$windowsVersion = "unknown"}


             try { $windowsEdition = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption }
             catch { $windowsEdition = "unknown" }
             
             # to add: Windows Firewall Enabled, DomainName, Windows Automatic updates set NBT over TCP/IP disabled on all interfaces, account lockout, local password policy , Test-ComputerSecureChannel?, 
             # to double check: the IP address is currently looking for the first IPv4 match, will that work if they are on a VPN/different adapater? mmm
             
             # Get first IP out of list (might not be the primary IP, be warned )
             try {$ipAddress = $(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' } | out-null; $Matches[1])}
             catch { $ipAddress = "unknown" } 

             # Get Domain for host 
             try { $CurrentDomain = $env:USERDNSDOMAIN }
             catch { $CurrentDomain = "unknown" }

             # Get computer name 
             try { $computerName = $env:COMPUTERNAME }
             catch { $computerName = "unknown" }

             # Write-Host ">>> +++++++++++++++++ ${CurrentDomain}:${computerName}:${ipAddress}:${windowsEdition}:${windowsVersion} +++++++++++++++++ "
            
             # Write-Host "${CurrentDomain}:${computerName}:${ipAddress}:CurrentDomain:$CurrentDomain"
		       # Windows OS and GPO Enumeration

             # Get default gateway (next hop)
             try {$defaultGateway = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Foreach IPv4DefaultGateway).nexthop}
             catch { $defaultGateway = "unknown" }

             # Check OS Supported (when compared to list of unsupported Windows systems) - note: As windows 10 and server use the same code for different versions of either, 
             # this may show false positives, the codes here are for Windows 10. 

             $unsupportedOS = 10240,10586,14393,15063,16299,17134,17763,18362,18363
             try {$osSupported = $OSVersion -notin $unsupportedOS }
             catch { $osSupported = "unknown"}
             
             # Last GPO applied time  
             try {$LastGPOAppliedTime = [datetime]::FromFileTime(([Int64] ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi) -shl 32) -bor ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo))}
             catch { $LastGPOAppliedTime = "unknown" }

             # Date last security update was installed  
	     try {$lastSecurityUpdate= (Get-HotFix -Description Security* -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn)[-1].installedon}
             catch { $lastSecurityUpdate = "unknown" }

             # $localAdminAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Administrator").Enabled

             # Check Guest Account Enabled 
              
             try {$localGuestAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Guest").enabled}
             catch { $localGuestAccountEnabled = "Unknown"}
             DisplayOutput "Windows" "LocalGuestAccountEnabled" "$LocalGuestAccountEnabled"

             try { $LocalAdmins=(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name }
             catch { $LocalAdmins = "unknown" }

             
             # Check if Windows Firewall enabled 
              
             try {$FWService = (Get-Service | ?{$_.Name -eq "mpssvc"})}
             catch {$FWService = "unknown"}
             $FWService | %{If($_.Status -eq "Running"){$FirewallServiceRunning="True"}Else{$FirewallServiceRunning="False"}
             
             # Check which Windows Firewall profile is enabled (Domain/Private/Public)
              
             try {$firewallStatusDomain = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Domain" ).enabled }
             catch { $firewallStatusDomain = "unknown"}
              
             try {$firewallStatusPrivate = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Private" ).enabled }
             catch { $firewallStatusPrivate }
       
             try {$firewallStatusPublic = (Get-NetFirewallProfile | select Name,Enabled | where Name -in "Public").enabled }
             catch {$firewallStatusPublic = "unknown"}



	# Check Installed Browsers and Versions

             # Chrome 
             # Chrome Installed 
             try {$ChromeInstalled=Test-Path -Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -PathType Leaf}
             catch { $ChromeInstalled = "unknown" }


             # Chrome Version  
             try { $chromeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
             catch { $chromeVersion="unknown" }
                    # if (!$error) { "No Error Occured" }


             # Firefox 
             # Firefox Installed  
             try {$FirefoxInstalled= Test-Path -Path "C:\Program Files\Mozilla Firefox\firefox.exe" -PathType Leaf}
             catch { $FirefoxInstalled = "unknown" }

             # Firefox Version 
             try { $firefoxVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
             catch { $firefoxVersion = "unknown" }

             # Edge
             
             # Edge Installed 
             try {$EdgeInstalled= Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -PathType Leaf}
             catch { $EdgeInstalled = "unknown" }

             # Edge Version 
             try { $msedgeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
             catch { $msedgeVersion="unknown" }
             
             # IE
             # IE Installed  
             try {$IEInstalled=Test-Path -Path "C:\Program Files\Internet Explorer\iexplore.exe " -PathType Leaf}
             catch { $IEInstalled = "unknown"}

             # IE Version
             try {$ieVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe' -ErrorAction SilentlyContinue).'(Default)' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion } 
             catch { $ieVersion="unknown" }
             
             # Check AV Products
             
             # AV Enabled
             try {$AVEnabled2=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled}
             catch { $AVEnabled2 = "unknown" }
             
             # AV On Access Enabled 
             try {$AVOnAccess=(Get-MpComputerStatus -ErrorAction SilentlyContinue).OnAccessProtectionEnabled}
             catch { $AVOnAccess = "unknown" }   

             # AV Real Time PRotection Enabled 
             try {$AVRealTimeProtectionEnabled=(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled }
             catch { $AVRealTimeProtectionEnabled = "unknown" }

             # AV Signature Age 
             try { $AVSignatureAge=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge }
             catch { $AVSignatureAge = "unknown" }


             DisplayOutputAlt
             


         
 };

}

# Launch the script 
EnumerateEachMachine
