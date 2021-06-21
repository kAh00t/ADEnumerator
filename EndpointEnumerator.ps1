#  ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗██╗  ██╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
#  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝██║  ██║██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
#  █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║   ███████║█████╗  ███████║██║     ██║   ███████║██║     ███████║█████╗  ██║     █████╔╝ 
#  ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║   ██╔══██║██╔══╝  ██╔══██║██║     ██║   ██╔══██║██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
#  ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║   ██║  ██║███████╗██║  ██║███████╗██║   ██║  ██║╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
#  ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
#                                                                                                                                                         

# Version : 0.1
# Created by: David Manuel
# Date: 21/06/2021 
# Description: Windows AD connected/domain joined endpoint enumerator. Output of cme needs filters (commands below) and use : for delimeter in Excel to go over data. 

# Useage: 
# Launch command directly in memory, requires outbound 443, might trigger AV lol 
# powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kAh00t/ADEnumerator/main/EndpointEnumerator.ps1')"
# OR
# crackmapexec smb 192.168.123.0/24 -u 'USERNAME' -p 'PASSWORD' -x "powershell.exe -exec Bypass -C \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/kAh00t/ADEnumerator/main/EndpointEnumerator.ps1')\"" | tee cmeoutput.txt

# Parse and remove weird encoding string issue I've not worked out 
# cat cmeoutput.txt | grep ">>>" | cut -d ">" -f 4 | sed -e 's/\[0m//' >> excel-parsed.csv

# Open the parsed file, remember to choose : as delimeter. 
# libreoffice excel-parsed.csv 


# Main Function 
function EnumerateEachMachine
{
    
        # AV script, didn't write this myself, not sure if it works, will probably remove. 
        function Get-AntiVirusProduct {
        [CmdletBinding()]
        param (
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('name')]
        $computername=$env:computername

        )

        #$AntivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue' # did not work            
         $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

        $ret = @()
        foreach($AntiVirusProduct in $AntiVirusProducts){
            #Switch to determine the status of antivirus definitions and real-time protection.
            #The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
            switch ($AntiVirusProduct.productState) {
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
                }

            #Create hash-table for each computer
            $ht = @{}
            $ht.Computername = $computername
            $ht.Name = $AntiVirusProduct.displayName
            $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
            $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
            $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
            $ht.'Definition Status' = $defstatus
            $ht.'Real-time Protection Status' = $rtstatus


            #Create a new object for each computer
            $ret += New-Object -TypeName PSObject -Property $ht 
        }
        Return $ret
        }
      
        # Get Password policy script, again - somebody else wrote this, I'll need to find the original to reference here 
        function Get-PassPol
                {
	                $domain = [ADSI]"WinNT://$env:userdomain"
	                $Name = @{Name='DomainName';Expression={$_.Name}}
	                $MinPassLen = @{Name='Minimum Password Length (Chars)';Expression={$_.MinPasswordLength}}
	                $MinPassAge = @{Name='Minimum Password Age (Days)';Expression={$_.MinPasswordAge.value/86400}}
	                $MaxPassAge = @{Name='Maximum Password Age (Days)';Expression={$_.MaxPasswordAge.value/86400}}
	                $PassHistory = @{Name='Enforce Password History (Passwords remembered)';Expression={$_.PasswordHistoryLength}}
	                $AcctLockoutThreshold = @{Name='Account Lockout Threshold (Invalid logon attempts)';Expression={$_.MaxBadPasswordsAllowed}}
	                $AcctLockoutDuration =  @{Name='Account Lockout Duration (Minutes)';Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	                $ResetAcctLockoutCounter = @{Name='Reset Account Lockout Counter After (Minutes)';Expression={$_.LockoutObservationInterval.value/60}}
	                $domain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
                    #write-host $PassPol
                    
                }
                

                ######################## Variables ##############################
                $windowsVersion = ([environment]::OSVersion.Version).build
                $windowsEdition = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                # to add: Windows Firewall Enabled, DomainName, Windows Automatic updates set NBT over TCP/IP disabled on all interfaces, account lockout, local password policy , Test-ComputerSecureChannel?, 
                # to double check: the IP address is currently looking for the first IPv4 match, will that work if they are on a VPN/different adapater? mmm
                $ipAddress = $(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' } | out-null; $Matches[1])
                $CurrentDomain = $env:USERDNSDOMAIN

                $computerName = $env:COMPUTERNAME
                Write-Host ">>> +++++++++++++++++ ${CurrentDomain}:${computerName}:${ipAddress}:${windowsEdition}:${windowsVersion} +++++++++++++++++ "
                
                
                #Write-Host "${CurrentDomain}:${computerName}:${ipAddress}:CurrentDomain:$CurrentDomain"
		# Windows OS and GPO Enumeration 
                $PassPol = Get-PassPol -ErrorAction SilentlyContinue
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:Password-Policy:$PassPol"
		$lastSecurityUpdate = (Get-HotFix -Description Security* -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn)[-1].installedon
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:LastSecurityUpdate:$lastSecurityUpdate"
                $localAdminAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Administrator").Enabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:LocalAdminAccountEnabled:$localAdminAccountEnabled"
                $localGuestAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Guest").enabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:LocalGuestAccountEnabled:$localGuestAccountEnabled"
                $defaultGateway = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Foreach IPv4DefaultGateway).nexthop
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:DefaultGateway:$defaultGateway"

                # Windows Version declared at the top
             
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:Version:$windowsVersion"
                $windowsVersionMajor = ([environment]::OSVersion.Version).Major
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:VersionMajor:$windowsVersionMajor"
                
                #Windows editions declared at beginning of function
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:Edition:$windowsEdition"
                $unsupportedOS = 10240,10586,14393,15063,16299,17134,17763,18362,18363
                $osSupported = $OSVersion -notin $unsupportedOS
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:OSSupported:$osSupported"
               
                $minPassLength = $PassPol.'Minimum Password Length (Chars)'
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:MinPassLength:$minPassLength"
                $passHistoryVar = $PassPol.'Enforce Password History (Passwords remembered)'
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:MinPassHistory:$passHistoryVar"
                $acctLockoutThresholdVar = $PassPol.'Account Lockout Threshold (Invalid logon attempts)'
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:AcctLockoutThreshold:$acctLockoutThresholdVar"
                $acctLockoutDurationVar = $PassPol.'Account Lockout Duration (Minutes)'
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:AccountLockoutDuration:$acctLockoutDurationVar"
                #$gpresultoutput = gpresult /SCOPE USER /R
                #Write-Host "${computerName}:${ipAddress}:GPResultOutput:$gpresultoutput"
                $LocalAdmins=(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:LocalAdmins:$LocalAdmins"
                $CurrentLoggedInUsers=query user /server:$SERVER
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:CurrentLoggedInUsers:$CurrentLoggedInUsers"
                $LastGPOAppliedTime=[datetime]::FromFileTime(([Int64] ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi) -shl 32) -bor ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo))
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Windows:LastGPOAppliedTime:$LastGPOAppliedTime"


		# Check Firewalls 
                $FWService = (Get-Service | ?{$_.Name -eq "mpssvc"})
                $FWService | %{If($_.Status -eq "Running"){$FirewallServiceRunning="True"}Else{$FirewallServiceRunning="False"}
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Firewall:FirewallServiceRunning:$FirewallServiceRunning"
                $firewallStatusDomain = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Domain" ).enabled 
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Firewall:FirewallStatusDomain:$firewallStatusDomain"
                $firewallStatusPrivate = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Private" ).enabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Firewall:FirewallStatusPrivate:$firewallStatusPrivate"
                $firewallStatusPublic = (Get-NetFirewallProfile | select Name,Enabled | where Name -in "Public").enabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Firewall:FirewallStatusPublic:$firewallStatusPublic"
		
		# Check potentially dangerous configurations 
                $smbV1Enable = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select EnableSMB1Protocol).EnableSMB1Protocol
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:SMB:SMBv1:$smbV1Enable"
                $smbEncryptionEnabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select EncryptData).EncryptData
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:SMB:SMBEncryptionEnabled:$smbEncryptionEnabled"
                $smbSigningEnabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select RequireSecuritySignature).requiresecuritysignature
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:SMBLSMBSigningEnabled:$smbSigningEnabled"
                $llmnrstatus = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:LLMNR:LLMNR_Status:$llmnrstatus"
                $ipv6Enabled = Get-NetIPInterface -ErrorAction SilentlyContinue | where AddressFamily -in "IPv6" | select DHCP | where DHCP -Contains Enabled; If ($ipv6Enabled -ne $empty) {$ipv6EnabledStatus = 1} Else {$ipv6EnabledStatus = 0};
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:IP:IPv6_Enabled:$ipv6Enabled"
                $ldapSigningEnabled = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -ErrorAction SilentlyContinue).LdapclientIntegrity 
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:LDAP:LDAPSigningEnabled:$ldapSigningEnabled"
                
		# Check Installed Browsers
                $FirefoxInstalled= Test-Path -Path "C:\Program Files\Mozilla Firefox\firefox.exe" -PathType Leaf
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Browsers:FirefoxInstalled:$FirefoxInstalled"
                $EdgeInstalled= Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -PathType Leaf
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Browsers:EdgeInstalled:$EdgeInstalled"
                $ChromeInstalled=Test-Path -Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -PathType Leaf
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Browsers:ChromeInstalled:$ChromeInstalled"
                $IEInstalled=Test-Path -Path "C:\Program Files\Internet Explorer\iexplore.exe" -PathType Leaf
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:Browsers:IEInstalled:$IEInstalled"

                # Check AV Products
                $avName = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Name'        
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:Name:$avName"
                $avRealTimeProtectStatus = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Real-Time Protection Status'
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:RealTimeProtectStatus:$avRealTimeProtectStatus"
                $avDefinitions = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Definition Status' 
            
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:Definition:$avDefinitions"


                # I'm not entirely convinced the AV scripts do much, so there might be some duplication with the fields below until I choose when function to use. These work for defender but probably not third party AV 
                $AVEnabled2=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:Enabled2:$AVEnabled2"
                $AVOnAccess=(Get-MpComputerStatus -ErrorAction SilentlyContinue).OnAccessProtectionEnabled
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:OnAccess:$AVOnAccess"
                $AVRealTimeProtectionEnabled=(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled 
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:RealTimeProtectionEnabled:$AVRealTimeProtectionEnabled"
                $AVSignatureAge=(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge 
                Write-Host ">>> ${CurrentDomain}:${computerName}:${ipAddress}:AV:SignatureAge:$AVSignatureAge"

                # Handy command but not ready to impliment, check if Applocker policy is working command! 
                # Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\*.exe -User Everyone

 };

}

# Launch the script 
EnumerateEachMachine

