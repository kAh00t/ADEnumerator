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

# Function to write out variables to console
function DisplayOutput {
	    param([String]$grouping,[String]$category,[String]$output) 
        # Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:${grouping}:${category}:${output}"
} 


function DisplayOutputAlt {
    Write-Host "+++ windowsVersion^windowsEdition^ipAddress^CurrentDomain^computerName^defaultGateway^osSupported^LastGPOAppliedTime^lastSecurityUpdate^LocalGuestAccountEnabled^LocalAdmins^FirewallServiceRunning^firewallStatusDomain^firewallStatusPrivate^firewallStatusPublic^ChromeInstalled^chromeVersion^FirefoxInstalled^firefoxVersion^EdgeInstalled^msedgeVersion^IEInstalled^ieVersion^AVEnabled2^AVOnAccess^AVRealTimeProtectionEnabled^AVSignatureAge"    
    Write-Host "+++ ${windowsVersion}^${windowsEdition}^${ipAddress}^${CurrentDomain}^${computerName}^${defaultGateway}^${osSupported}^${LastGPOAppliedTime}^${lastSecurityUpdate}^${localGuestAccountEnabled}^${LocalAdmins}^${FirewallServiceRunning}^${firewallStatusDomain}^${firewallStatusPrivate}^${firewallStatusPublic}^${ChromeInstalled}^${chromeVersion}^${FirefoxInstalled}^${firefoxVersion}^${EdgeInstalled}^${msedgeVersion}^${IEInstalled}^${ieVersion}^${AVEnabled2}^${AVOnAccess}^${AVRealTimeProtectionEnabled}^${AVSignatureAge}"
} 

# Main Function 
function EnumerateEachMachine
{
                ######################## Variables ##############################
                $windowsVersion = ([environment]::OSVersion.Version).build
                $windowsEdition = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                
                # to add: Windows Firewall Enabled, DomainName, Windows Automatic updates set NBT over TCP/IP disabled on all interfaces, account lockout, local password policy , Test-ComputerSecureChannel?, 
                # to double check: the IP address is currently looking for the first IPv4 match, will that work if they are on a VPN/different adapater? mmm
                
                $ipAddress = $(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' } | out-null; $Matches[1])
                $CurrentDomain = $env:USERDNSDOMAIN

                $computerName = $env:COMPUTERNAME
                Write-Host ">>> +++++++++++++++++ ${CurrentDomain}:${computerName}:${ipAddress}:${windowsEdition}:${windowsVersion} +++++++++++++++++ "
               
                # Write-Host "${CurrentDomain}:${computerName}:${ipAddress}:CurrentDomain:$CurrentDomain"
		        # Windows OS and GPO Enumeration


                DisplayOutput "Windows" "DomainName" "$CurrentDomain"

                DisplayOutput "Windows" "ComputerName" "$computerName"

                $defaultGateway = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Foreach IPv4DefaultGateway).nexthop
                DisplayOutput "Windows" "DefaultGateway" "$defaultGateway"

                #Windows editions declared at beginning of function
                DisplayOutput "Windows" "Edition" "$windowsEdition"

                # Windows Version declared at the top
                DisplayOutput "Windows" "Version" "$windowsVersion"

                $unsupportedOS = 10240,10586,14393,15063,16299,17134,17763,18362,18363
                $osSupported = $OSVersion -notin $unsupportedOS
                DisplayOutput "Windows" "OSSupported" "$osSupported"
                
                $LastGPOAppliedTime = [datetime]::FromFileTime(([Int64] ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi) -shl 32) -bor ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo))
                DisplayOutput "Windows" "LastGPOAppliedTime" "$LastGPOAppliedTime"


		$lastSecurityUpdate= (Get-HotFix -Description Security* -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn)[-1].installedon
                DisplayOutput "Windows" "LastSecurityUpdate" "$lastSecurityUpdate"

                # $localAdminAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Administrator").Enabled
                # DisplayOutput "Windows" "LocalAdminAccountEnabled" "$localAdminAccountEnabled"

                $localGuestAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Guest").enabled
                DisplayOutput "Windows" "LocalGuestAccountEnabled" "$LocalGuestAccountEnabled"



		
                # $windowsVersionMajor = ([environment]::OSVersion.Version).Major
                # DisplayOutput "Windows" "VersionMajor" "$windowsVersionMajor"

                $LocalAdmins=(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
                DisplayOutput "Windows" "LocalAdmins" "$LocalAdmins"

                

		# Check Firewalls 
                $FWService = (Get-Service | ?{$_.Name -eq "mpssvc"})
                $FWService | %{If($_.Status -eq "Running"){$FirewallServiceRunning="True"}Else{$FirewallServiceRunning="False"}
                DisplayOutput "Firewall" "FirewallServiceRunning" "$FirewallServiceRunning"
                
                $firewallStatusDomain = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Domain" ).enabled 
                DisplayOutput "Firewall" "FirewallStatusDomain" "$firewallStatusDomain"
                
                $firewallStatusPrivate = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Private" ).enabled
                DisplayOutput "Firewall" "FirewallStatusPrivate" "$firewallStatusPrivate"
                
                $firewallStatusPublic = (Get-NetFirewallProfile | select Name,Enabled | where Name -in "Public").enabled
		        DisplayOutput "Firewall" "FirewallStatusPublic" "$firewallStatusPublic"

		        # Check potentially dangerous configurations 



	        # Check Installed Browsers and Versions

                # Chrome 
                $ChromeInstalled=Test-Path -Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -PathType Leaf
                DisplayOutput "Browsers" "ChromeInstalled" "$ChromeInstalled"

                $error.clear()
                try { $chromeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $chromeVersion="unknown" }
                        # if (!$error) { "No Error Occured" }
                DisplayOutput "Browsers" "Chrome-Version" "$chromeVersion"

                # Firefox 
                $FirefoxInstalled= Test-Path -Path "C:\Program Files\Mozilla Firefox\firefox.exe" -PathType Leaf
                DisplayOutput "Browsers" "FirefoxInstalled" "$FirefoxInstalled"

                $error.clear()
                try { $firefoxVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $firefoxVersion="unknown" }
                DisplayOutput "Browsers" "FireFox-Version" "$firefoxVersion"

                # Edge
                $EdgeInstalled= Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -PathType Leaf
                DisplayOutput "Browsers" "EdgeInstalled" "$EdgeInstalled"

                $error.clear()
                try { $msedgeVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(Default)').VersionInfo.ProductVersion }
                catch { $msedgeVersion="unknown" }
                DisplayOutput "Browsers" "MsEdge-Version" "$msedgeVersion"
                
                # IE
                $IEInstalled=Test-Path -Path "C:\Program Files\Internet Explorer\iexplore.exe " -PathType Leaf
                DisplayOutput "Browsers" "IEInstalled" "$IEInstalled"

                $error.clear()
                try {$ieVersion=(Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe' -ErrorAction SilentlyContinue).'(Default)' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion } 
                catch { $ieVersion="unknown" }
                DisplayOutput "Browsers" "IE-Version" "$ieVersion"
                
                



                
                # Check AV Products
                # I'm not entirely convinced the AV scripts do much, so there might be some duplication with the fields below until I choose when function to use. These work for defender but probably not third party AV 
                $AVEnabled2=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled
                DisplayOutput "AV" "Enabled2" "$AVEnabled2"

                $AVOnAccess=(Get-MpComputerStatus -ErrorAction SilentlyContinue).OnAccessProtectionEnabled
                DisplayOutput "AV" "OnAccess" "$AVOnAccess"

                $AVRealTimeProtectionEnabled=(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled 
                DisplayOutput "AV" "RealTimeProtectionEnabled" "$AVRealTimeProtectionEnabled"

                $AVSignatureAge=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge 
                DisplayOutput "AV" "SignatureAge" "$AVSignatureAge"


                DisplayOutputAlt
                # Handy command but not ready to impliment, check if Applocker policy is working command! 

                


                
 };

}

# Launch the script 
EnumerateEachMachine
