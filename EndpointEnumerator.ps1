function EnumerateEachMachine
{
    
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
        function Get-AVStatus () {

                                                                                                                                                                                                                <#
From: https://gist.github.com/jdhitsolutions/1b9dfb31fef91f34c54b344c6516c30b

.Synopsis
Get anti-virus product information.
.Description
This command uses WMI via the Get-CimInstance command to query the state of installed anti-virus products. The default behavior is to only display enabled products, unless you use -All. You can query by computername or existing CIMSessions.
.Example
PS C:\> Get-AVStatus chi-win10
Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : True
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Thu, 21 Jul 2016 15:20:18 GMT
Computername : CHI-WIN10
.Example
PS C:\>  import-csv s:\computers.csv | Get-AVStatus -All | Group Displayname | Select Name,Count | Sort Count,Name
Name                           Count
----                           -----
ESET NOD32 Antivirus 9.0.386.0    12
ESET Endpoint Security 5.0         6
Windows Defender                   4
360 Total Security                 1
Import a CSV file which includes a Computername heading. The imported objects are piped to this command. The results are sent to Group-Object.
.Example
PS C:\> $cs | Get-AVStatus | where {-Not $_.UptoDate}
Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : False
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Wed, 20 Jul 2016 11:10:13 GMT
Computername : CHI-WIN11
Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : False
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Thu, 07 Jul 2016 15:15:26 GMT
Computername : CHI-WIN81
You can also pipe CIMSession objects. In this example, the output are enabled products that are not up to date.
.Notes
version: 1.1
Learn more about PowerShell:
http://jdhitsolutions.com/blog/essential-powershell-resources/
.Inputs
[string[]]
[Microsoft.Management.Infrastructure.CimSession[]]
.Outputs
[pscustomboject]
.Link
Get-CimInstance
    #>

        [cmdletbinding(DefaultParameterSetName = "computer")]

        Param(
            #The name of a computer to query.
            [Parameter(
                Position = 0,
                ValueFromPipeline,
                ValueFromPipelineByPropertyName,
                ParameterSetName = "computer"
                )]
            [ValidateNotNullorEmpty()]
            [string[]]$Computername = $env:COMPUTERNAME,

            #An existing CIMsession.
            [Parameter(ValueFromPipeline, ParameterSetName = "session")]
            [Microsoft.Management.Infrastructure.CimSession[]]$CimSession,

            #The default is enabled products only.
            [switch]$All
        )

        Begin {
            Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"

            Function ConvertTo-Hex {
                Param([int]$Number)
                '0x{0:x}' -f $Number
            }

            #initialize an hashtable of paramters to splat to Get-CimInstance
            $cimParams = @{
                Namespace   = "root/SecurityCenter2"
                ClassName   = "Antivirusproduct"
                ErrorAction = "Stop"
            }

            If ($All) {
                Write-Verbose "[BEGIN  ] Getting all AV products"
            }

            $results = @()
        } #begin

        Process {

            #initialize an empty array to hold results
            $AV = @()

            Write-Verbose "[PROCESS] Using parameter set: $($pscmdlet.ParameterSetName)"
            Write-Verbose "[PROCESS] PSBoundparameters: "
            Write-Verbose ($PSBoundParameters | Out-String)

            if ($pscmdlet.ParameterSetName -eq 'computer') {
                foreach ($computer in $Computername) {

                    Write-Verbose "[PROCESS] Querying $($computer.ToUpper())"
                    $cimParams.ComputerName = $computer
                    Try {
                        $AV += Get-CimInstance @CimParams
                    }
                    Catch {
                        Write-Warning "[$($computer.ToUpper())] $($_.Exception.Message)"
                        $cimParams.ComputerName = $null
                    }

                } #foreach computer
            }
            else {
                foreach ($session in $CimSession) {

                    Write-Verbose "[PROCESS] Using session $($session.computername.toUpper())"
                    $cimParams.CimSession = $session
                    Try {
                        $AV += Get-CimInstance @CimParams
                    }
                    Catch {
                        Write-Warning "[$($session.computername.ToUpper())] $($_.Exception.Message)"
                        $cimParams.cimsession = $null
                    }

                } #foreach computer
            }

            foreach ($item in $AV) {
                Write-Verbose "[PROCESS] Found $($item.Displayname)"
                $hx = ConvertTo-Hex $item.ProductState
                $mid = $hx.Substring(3, 2)
                if ($mid -match "00|01") {
                    $Enabled = $False
                }
                else {
                    $Enabled = $True
                }
                $end = $hx.Substring(5)
                if ($end -eq "00") {
                    $UpToDate = $True
                }
                else {
                    $UpToDate = $False
                }

                $results += $item | Select-Object Displayname, ProductState,
                @{Name = "Enabled"; Expression = { $Enabled } },
                @{Name = "UpToDate"; Expression = { $UptoDate } },
                @{Name = "Path"; Expression = { $_.pathToSignedProductExe } },
                Timestamp,
                @{Name = "Computername"; Expression = { $_.PSComputername.toUpper() } }

            } #foreach

        } #process

        End {
            If ($All) {
                $results
            }
            else {
                #filter for enabled only
                ($results).Where( { $_.enabled })
            }

            Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
        } #end

        } #end function 
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

                
                # to add: Windows Firewall Enabled, DomainName, Windows Automatic updates set NBT over TCP/IP disabled on all interfaces, account lockout, local password policy , Test-ComputerSecureChannel?, 
                # to double check: the IP address is currently looking for the first IPv4 match, will that work if they are on a VPN/different adapater? mmm
                $ipAddress = $(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' } | out-null; $Matches[1])
                # Write-Host "${computerName}:${ipAddress}:IP:$ipAddress"
                $computerName = $env:COMPUTERNAME
                Write-Host "+++++++++++++++++ ComputerName:$computerName +++++++++++++++++ "
                
                $PassPol = Get-PassPol -ErrorAction SilentlyContinue
                Write-Host "${computerName}:${ipAddress}:Password-Policy:$PassPol"

                $firewallStatusDomain = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Domain" ).enabled 
                Write-Host "${computerName}:${ipAddress}:FirewallStatusDomain:$firewallStatusDomain"
                $firewallStatusPrivate = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Private" ).enabled
                Write-Host "${computerName}:${ipAddress}:FirewallStatusPrivate:$firewallStatusPrivate"
                $firewallStatusPublic = (Get-NetFirewallProfile | select Name,Enabled | where Name -in "Public").enabled
                Write-Host "${computerName}:${ipAddress}:FirewallStatusPublic:$firewallStatusPublic"
                $smbV1Enable = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select EnableSMB1Protocol).EnableSMB1Protocol
                Write-Host "${computerName}:${ipAddress}:SMBv1:$smbV1Enable"
                $smbEncryptionEnabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select EncryptData).EncryptData
                Write-Host "${computerName}:${ipAddress}:SMBEncryptionEnabled:$smbEncryptionEnabled"
                $smbSigningEnabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue | select RequireSecuritySignature).requiresecuritysignature
                Write-Host "${computerName}:${ipAddress}:SMBSigningEnabled:$smbSigningEnabled"
                $llmnrstatus = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
                Write-Host "${computerName}:${ipAddress}:LLMNRStatus:$llmnrstatus"
                $ipv6Enabled = Get-NetIPInterface -ErrorAction SilentlyContinue | where AddressFamily -in "IPv6" | select DHCP | where DHCP -Contains Enabled; If ($ipv6Enabled -ne $empty) {$ipv6EnabledStatus = 1} Else {$ipv6EnabledStatus = 0};
                Write-Host "${computerName}:${ipAddress}:IPv6Enabled:$ipv6Enabled"
                $ldapSigningEnabled = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -ErrorAction SilentlyContinue).LdapclientIntegrity 
                Write-Host "${computerName}:${ipAddress}:LDAPSigningEnabled:$ldapSigningEnabled"
                $lastSecurityUpdate = (Get-HotFix -Description Security* -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn)[-1].installedon
                Write-Host "${computerName}:${ipAddress}:LastSecurityUpdate:$lastSecurityUpdate"
                $localAdminAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Administrator").Enabled
                Write-Host "${computerName}:${ipAddress}:LocalAdminAccountEnabled:$localAdminAccountEnabled"
                $localGuestAccountEnabled = (Get-LocalUser -ErrorAction SilentlyContinue | select Name,Enabled | where Name -in "Guest").enabled
                Write-Host "${computerName}:${ipAddress}:LocalGuestAccountEnabled:$localGuestAccountEnabled"
                $defaultGateway = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Foreach IPv4DefaultGateway).nexthop
                Write-Host "${computerName}:${ipAddress}:DefaultGateway:$defaultGateway"
                $windowsVersion = ([environment]::OSVersion.Version).build
                Write-Host "${computerName}:${ipAddress}:WindowsVersion:$windowsVersion"
                $windowsVersionMajor = ([environment]::OSVersion.Version).Major
                Write-Host "${computerName}:${ipAddress}:WindowsVersionMajor:$windowsVersionMajor"
                $windowsEdition = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                Write-Host "${computerName}:${ipAddress}:WindowsEdition:$windowsEdition"
                $unsupportedOS = 10240,10586,14393,15063,16299,17134,17763,18362,18363
                $osSupported = $OSVersion -notin $unsupportedOS
                Write-Host "${computerName}:${ipAddress}:OSSupported:$osSupported"
                $avName = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Name'        
                Write-Host "${computerName}:${ipAddress}:AVName:$avName"
                $avRealTimeProtectStatus = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Real-Time Protection Status'
                Write-Host "${computerName}:${ipAddress}:AVRealTimeProtectStatus:$avRealTimeProtectStatus"
                $avDefinitions = (Get-AntiVirusProduct -ErrorAction SilentlyContinue).'Definition Status' 
            
                Write-Host "${computerName}:${ipAddress}:AVDefinition:$avDefinitions"
                $minPassLength = $PassPol.'Minimum Password Length (Chars)'
                Write-Host "${computerName}:${ipAddress}:MinPassLength:$minPassLength"
                $passHistoryVar = $PassPol.'Enforce Password History (Passwords remembered)'
                Write-Host "${computerName}:${ipAddress}:MinPassHistory:$passHistoryVar"
                $acctLockoutThresholdVar = $PassPol.'Account Lockout Threshold (Invalid logon attempts)'
                Write-Host "${computerName}:${ipAddress}:AcctLockoutThreshold:$acctLockoutThresholdVar"
                $acctLockoutDurationVar = $PassPol.'Account Lockout Duration (Minutes)'
                Write-Host "${computerName}:${ipAddress}:AccountLockoutDuration:$acctLockoutDurationVar"
                
                 
# }

}
EnumerateEachMachine

