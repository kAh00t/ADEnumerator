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

# Open the parsed file, remember to choose : as delimeter. 
# libreoffice excel-parsed.csv 


# Table Columns: windowsVersion^windowsEdition^ipAddress^CurrentDomain^computerName^defaultGateway^osSupported^LastGPOAppliedTime^lastSecurityUpdate^LocalGuestAccountEnabled^LocalAdmins^FirewallServiceRunning^firewallStatusDomain^firewallStatusPrivate^firewallStatusPublic^ChromeInstalled^chromeVersion^FirefoxInstalled^firefoxVersion^EdgeInstalled^msedgeVersion^IEInstalled^ieVersion^AVEnabled2^AVOnAccess^AVRealTimeProtectionEnabled^AVSignatureAge"    

# Function to write out variables to console
function DisplayOutput {
	    param([String]$grouping,[String]$category,[String]$output) 
        # Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:${grouping}:${category}:${output}"
} 


function DisplayOutputAlt {
    # Write-Host "+++ windowsVersion^windowsEdition^ipAddress^CurrentDomain^computerName^defaultGateway^osSupported^LastGPOAppliedTime^lastSecurityUpdate^LocalGuestAccountEnabled^LocalAdmins^FirewallServiceRunning^firewallStatusDomain^firewallStatusPrivate^firewallStatusPublic^ChromeInstalled^chromeVersion^FirefoxInstalled^firefoxVersion^EdgeInstalled^msedgeVersion^IEInstalled^ieVersion^AVEnabled2^AVOnAccess^AVRealTimeProtectionEnabled^AVSignatureAge"    
    Write-Host "+++ ^${windowsVersion}^${windowsEdition}^${ipAddress}^${CurrentDomain}^${computerName}^${defaultGateway}^${osSupported}^${LastGPOAppliedTime}^${lastSecurityUpdate}^${localGuestAccountEnabled}^${LocalAdmins}^${FirewallServiceRunning}^${firewallStatusDomain}^${firewallStatusPrivate}^${firewallStatusPublic}^${ChromeInstalled}^${chromeVersion}^${FirefoxInstalled}^${firefoxVersion}^${EdgeInstalled}^${msedgeVersion}^${IEInstalled}^${ieVersion}^${AVEnabled2}^${AVOnAccess}^${AVRealTimeProtectionEnabled}^${AVSignatureAge}"
} 

# Main Function 
function EnumerateEachMachine
{
                ######################## Variables ##############################
                $windowsVersion = ([environment]::OSVersion.Version).build
                $windowsEdition = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                
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


                DisplayOutput "Windows" "DomainName" "$CurrentDomain"
                DisplayOutput "Windows" "ComputerName" "$computerName"

                # Get default gateway (next hop)
                try {$defaultGateway = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Foreach IPv4DefaultGateway).nexthop}
                catch { $defaultGateway = "unknown" }
                DisplayOutput "Windows" "DefaultGateway" "$defaultGateway"

                #Windows editions declared at beginning of function
                DisplayOutput "Windows" "Edition" "$windowsEdition"

                # Windows Version declared at the top
                DisplayOutput "Windows" "Version" "$windowsVersion"


                # Check OS Supported (when compared to list of unsupported Windows systems) - note: As windows 10 and server use the same code for different versions of either, 
                # this may show false positives, the codes here are for Windows 10. 

                $unsupportedOS = 10240,10586,14393,15063,16299,17134,17763,18362,18363
                try {$osSupported = $OSVersion -notin $unsupportedOS }
                catch { $osSupported = "unknown"}
                DisplayOutput "Windows" "OSSupported" "$osSupported"
                
                # Last GPO applied time  
                try {$LastGPOAppliedTime = [datetime]::FromFileTime(([Int64] ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi) -shl 32) -bor ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo))}
                catch { $LastGPOAppliedTime = "unknown" }
                DisplayOutput "Windows" "LastGPOAppliedTime" "$LastGPOAppliedTime"

                # Date last security update was installed  
		try {$lastSecurityUpdate= (Get-HotFix -Description Security* -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn)[-1].installedon}
                catch { $lastSecurityUpdate = "unknown" }
                DisplayOutput "Windows" "LastSecurityUpdate" "$lastSecurityUpdate"

                # $localAdminAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Administrator").Enabled
                # DisplayOutput "Windows" "LocalAdminAccountEnabled" "$localAdminAccountEnabled"

                # Check Guest Account Enabled 
                 
                try {$localGuestAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Guest").enabled}
                catch { $localGuestAccountEnabled = "Unknown"}
                DisplayOutput "Windows" "LocalGuestAccountEnabled" "$LocalGuestAccountEnabled"

                # $windowsVersionMajor = ([environment]::OSVersion.Version).Major
                # DisplayOutput "Windows" "VersionMajor" "$windowsVersionMajor"

                 
                $LocalAdmins = "na"
                try { $LocalAdmins=(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name }
                catch { $LocalAdmins = "unknown" }
                        # if (!$error) { "No Error Occured" }
                DisplayOutput "Windows" "LocalAdmins" "$LocalAdmins"
                
                # Check if Windows Firewall enabled 
                 
                try {$FWService = (Get-Service | ?{$_.Name -eq "mpssvc"})}
                catch {$FWService = "unknown"}
                $FWService | %{If($_.Status -eq "Running"){$FirewallServiceRunning="True"}Else{$FirewallServiceRunning="False"}
                DisplayOutput "Firewall" "FirewallServiceRunning" "$FirewallServiceRunning"
                
                # Check which Windows Firewall profile is enabled (Domain/Private/Public)
                 
                try {$firewallStatusDomain = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Domain" ).enabled }
                catch { $firewallStatusDomain = "unknown"}
                DisplayOutput "Firewall" "FirewallStatusDomain" "$firewallStatusDomain"
                 
                try {$firewallStatusPrivate = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Private" ).enabled }
                catch { $firewallStatusPrivate }
                DisplayOutput "Firewall" "FirewallStatusPrivate" "$firewallStatusPrivate"
        
                try {$firewallStatusPublic = (Get-NetFirewallProfile | select Name,Enabled | where Name -in "Public").enabled }
                catch {$firewallStatusPublic = "unknown"}
		DisplayOutput "Firewall" "FirewallStatusPublic" "$firewallStatusPublic"


	        # Check Installed Browsers and Versions

                # Chrome 
                # Chrome Installed 
                try {$ChromeInstalled=Test-Path -Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -PathType Leaf}
                catch { $ChromeInstalled = "unknown" }
                DisplayOutput "Browsers" "ChromeInstalled" "$ChromeInstalled"

                # Chrome Version  
                try { $chromeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $chromeVersion="unknown" }
                        # if (!$error) { "No Error Occured" }
                DisplayOutput "Browsers" "Chrome-Version" "$chromeVersion"

                # Firefox 
                # Firefox Installed  
                try {$FirefoxInstalled= Test-Path -Path "C:\Program Files\Mozilla Firefox\firefox.exe" -PathType Leaf}
                catch { $FirefoxInstalled = "unknown" }
                DisplayOutput "Browsers" "FirefoxInstalled" "$FirefoxInstalled"

                # Firefox Version 
                try { $firefoxVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $firefoxVersion = "unknown" }
                DisplayOutput "Browsers" "FireFox-Version" "$firefoxVersion"

                # Edge
                
                # Edge Installed 
                try {$EdgeInstalled= Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -PathType Leaf}
                catch { $EdgeInstalled = "unknown" }
                DisplayOutput "Browsers" "EdgeInstalled" "$EdgeInstalled"

                # Edge Version 
                try { $msedgeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $msedgeVersion="unknown" }
                DisplayOutput "Browsers" "MsEdge-Version" "$msedgeVersion"
                
                # IE
                # IE Installed  
                try {$IEInstalled=Test-Path -Path "C:\Program Files\Internet Explorer\iexplore.exe " -PathType Leaf}
                catch { $IEInstalled = "unknown"}
                DisplayOutput "Browsers" "IEInstalled" "$IEInstalled"

                # IE Version
                try {$ieVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe' -ErrorAction SilentlyContinue).'(Default)' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion } 
                catch { $ieVersion="unknown" }
                DisplayOutput "Browsers" "IE-Version" "$ieVersion"
                
                



                
                # Check AV Products
                
                # AV Enabled
                try {$AVEnabled2=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled}
                catch { $AVEnabled2 = "unknown" }
                DisplayOutput "AV" "Enabled2" "$AVEnabled2"
                
                # AV On Access Enabled 
                try {$AVOnAccess=(Get-MpComputerStatus -ErrorAction SilentlyContinue).OnAccessProtectionEnabled}
                catch { $AVOnAccess = "unknown" }   
                DisplayOutput "AV" "OnAccess" "$AVOnAccess"

                # AV Real Time PRotection Enabled 
                try {$AVRealTimeProtectionEnabled=(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled }
                catch { $AVRealTimeProtectionEnabled = "unknown" }
                DisplayOutput "AV" "RealTimeProtectionEnabled" "$AVRealTimeProtectionEnabled"

                # AV Signature Age 
                try { $AVSignatureAge=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge }
                catch { $AVSignatureAge = "unknown" }


                DisplayOutput "AV" "SignatureAge" "$AVSignatureAge"

                DisplayOutputAlt
                


           
 };

}

# Launch the script 
EnumerateEachMachine
