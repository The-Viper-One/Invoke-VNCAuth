Function Invoke-VNCAuth {
[CmdletBinding()]
Param(

    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$true)]
    [String]$Targets = '',

    [Parameter(Mandatory=$False, Position=2, ValueFromPipeline=$true)]
    [String]$Domain = "$env:USERDNSDOMAIN",

    [Parameter(Mandatory=$False, Position=3, ValueFromPipeline=$true)]
    [String]$Threads = "8",

    [Parameter(Mandatory=$False, Position=4, ValueFromPipeline=$true)]
    [int]$Port = "",

    [Parameter(Mandatory=$False, Position=5, ValueFromPipeline=$true)]
    [Switch]$SuccessOnly
)

$startTime = Get-Date
Set-Variable MaximumHistoryCount 32767

Write-Host
Write-Host

$Banner = @'
  _____                 _         __      ___   _  _____               _   _     
 |_   _|               | |        \ \    / / \ | |/ ____|   /\        | | | |    
   | |  _ ____   _____ | | _____   \ \  / /|  \| | |       /  \  _   _| |_| |__  
   | | | '_ \ \ / / _ \| |/ / _ \   \ \/ / | . ` | |      / /\ \| | | | __| '_ \ 
  _| |_| | | \ V / (_) |   <  __/    \  /  | |\  | |____ / ____ \ |_| | |_| | | |
 |_____|_| |_|\_/ \___/|_|\_\___|     \/   |_| \_|\_____/_/    \_\__,_|\__|_| |_|
                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
                                                                                                                       
'@

Write-Output $Banner
Write-Output "Github : https://github.com/the-viper-one"
Write-Host
Write-Host

if ($Port -eq ""){$Port = "5900"} else {$Port = $Port}
$CurrentDirectory = Join-Path -Path $pwd -ChildPath "VNC-NoAuth.txt"

function Get-IPRange {
    param (
        [string]$CIDR
    )
    
    $ErrorActionPreference = "Stop"
    try {
        # Extract the base IP and subnet mask from the CIDR notation
        $baseIP, $prefixLength = $CIDR -split "/"
        
        # Ensure the base IP and prefix length are valid
        if(-not ($baseIP -match "^(\d{1,3}\.){3}\d{1,3}$") -or -not ($prefixLength -match "^\d+$")) {
            throw "Invalid CIDR format. Ensure you use the format: xxx.xxx.xxx.xxx/yy"
        }

        # Calculate the number of IP addresses in the range
        $ipCount = [math]::Pow(2, (32 - [int]$prefixLength))
        
        # Convert the base IP to a decimal number
        $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipDecimal = [BitConverter]::ToUInt32($ipBytes, 0)
        
        # Generate all IP addresses within the range
        $ipAddresses = 0..($ipCount - 1) | ForEach-Object {
            $currentIPDecimal = $ipDecimal + $_
            $currentIPBytes = [BitConverter]::GetBytes($currentIPDecimal)
            [Array]::Reverse($currentIPBytes)
            "$($currentIPBytes[0]).$($currentIPBytes[1]).$($currentIPBytes[2]).$($currentIPBytes[3])"
        }
        
        return $ipAddresses
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}


if ($Targets -match "^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$") {
    if ($Matches[0] -like "*/*") {
        $Computers = Get-IPRange -CIDR $Targets
        $CIDRorIP = $True
    }
    else {
    $CIDRorIP = $True
        $Computers = $Targets
    }
}

else {
$CIDRorIP = $False
$directoryEntry = [ADSI]"LDAP://$domain"
$searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))

if ($Targets -eq "Workstations") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -notlike "*windows*server*" -and $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "Servers") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -like "*server*" -and $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") {

$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll()

}
elseif ($Targets -eq "All" -or $Targets -eq "Everything") {


$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }`

}


elseif ($Method -ne "Spray"){
if ($Targets -is [string]) {
    $ipAddress = [System.Net.IPAddress]::TryParse($Targets, [ref]$null)
    if ($ipAddress) {
        Write-Host "IP Addresses not yet supported" -ForegroundColor "Red"
        break
    }
    else {
        
        if ($Targets -notlike "*.*") {
            $Targets = $Targets + "." + $Domain
        }
        
        $computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0] -in $Targets }
            
            }
        }
    }
}

if ($CIDRorIP -eq $False){
$NameLength = ($computers | ForEach-Object { $_.Properties["dnshostname"][0].Length } | Measure-Object -Maximum).Maximum
$OSLength = ($computers | ForEach-Object { $_.Properties["operatingSystem"][0].Length } | Measure-Object -Maximum).Maximum
}

# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($ComputerName, $Port)

      $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $connected = $true
        } catch {
            $connected = $false
        }
    } else {
        $connected = $false
    }


    if (!$connected) {$tcpClient.Close() ; return}

function VNC-NoAuth {
    param(
        [string]$ComputerName,
        [int]$Port
    )
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
    }
    catch {
        Write-Host "Error: Unable to connect to $ComputerName on port $Port"
        return "Connection Error"
    }

    try {
        $networkStream = $tcpClient.GetStream()
        $networkStream.ReadTimeout = 50
        
        # Reading Version from Server
        $buffer = New-Object byte[] 12
        $read = $networkStream.Read($buffer, 0, 12)
        if ($read -eq 0) { throw "No data received from the server" }
        $serverVersionMessage = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        
        # Sending Client Version
        $buffer = [System.Text.Encoding]::ASCII.GetBytes($serverVersionMessage)
        $networkStream.Write($buffer, 0, $buffer.Length)

        # Reading Supported Security Types
        $buffer = New-Object byte[] 2
        $read = $networkStream.Read($buffer, 0, 1)
        if ($read -eq 0) { throw "No data received from the server" }
        $numberOfSecTypes = $buffer[0]
        $buffer = New-Object byte[] $numberOfSecTypes
        $read = $networkStream.Read($buffer, 0, $numberOfSecTypes)
        if ($read -eq 0) { throw "No data received from the server" }
    }
    catch {
        Write-Host "Error: Handshake failed with $ComputerName on port $Port"
        return "Handshake Error"
    }
    finally {
        # Cleanup
        if ($null -ne $networkStream) { $networkStream.Close() }
        if ($null -ne $tcpClient) { $tcpClient.Close() }
    }

    # Check for Non-authentication (Type 1)
    if ($buffer -contains 1) {
        return "Supported"
    }
    else {
        return "Not Supported"
    }
}

$AuthSupported = VNC-NoAuth -ComputerName $ComputerName -Port $Port
return "$AuthSupported"


}




if ($CIDRorIP -eq $True){
function Get-FQDNDotNet {
    param ([string]$IPAddress)
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
        return $hostEntry.HostName
    }
    catch {}
}

function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength
    )

    # Resolve the FQDN
    $DnsName = Get-FQDNDotNet -IPAddress $ComputerName
    
    # Prefix
    Write-Host "VNC " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-16}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    # Display ComputerName and OS
    Write-Host ("{0,20}" -f $DnsName) -NoNewline
    Write-Host "   " -NoNewline

    
    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}
}

if ($CIDRorIP -eq $False){
function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength
    )

    # Prefix
    Write-Host "VNC " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
    # Display ComputerName and OS
    Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
    Write-Host "   " -NoNewline

    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}
}


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    if ($CIDRorIP -eq $False){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    if ($CIDRorIP -eq $True){
    $ComputerName = $Computer
    }
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

$FoundResults = $False

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)

                if ($result -eq "Not Supported") {
                    if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Red -statusSymbol "[-] " -statusText "AUTH REQUIRED" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 

                if ($result -eq "Handshake Error") {
                    if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "HANDSHAKE ERROR" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 
                elseif ($result -eq "Supported") {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "AUTH NOT REQUIRED" -NameLength $NameLength -OSLength $OSLength
                        try {$($runspace.ComputerName) | Out-File -FilePath $CurrentDirectory -Encoding "ASCII" -Append} Catch {}
                            $FoundResults = $True
            } 

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

Write-Host
Write-Host

if ($FoundResults -eq $True){
$TestPath = Test-Path -Path $CurrentDirectory
    if ($TestPath -eq $False){

Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Unable to find $CurrentDirectory Perhaps we lack write permissions in the current directory?"
Write-Host
}

if ($TestPath -eq $True){
Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Hosts without authentication written to $pwd\VNC-NoAuth.txt"
Get-Content -Path $CurrentDirectory | Get-Unique | Sort-Object | Set-Content -Path $CurrentDirectory
    }
}

if ($FoundResults -eq $False){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "No hosts without authentication found"
Write-Host
}

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()

Write-Host ""
$Time = (Get-Date).ToString("HH:mm:ss")
Write-Host "Script Completed : $Time"
$elapsedTime = (Get-Date) - $startTime

# Format the elapsed time
$elapsedHours = "{0:D2}" -f $elapsedTime.Hours
$elapsedMinutes = "{0:D2}" -f $elapsedTime.Minutes
$elapsedSeconds = "{0:D2}" -f $elapsedTime.Seconds
$elapsedMilliseconds = "{0:D4}" -f $elapsedTime.Milliseconds

# Display the formatted elapsed time
$elapsedTimeFormatted = "$elapsedHours h:$elapsedMinutes m:$elapsedSeconds s:$elapsedMilliseconds mi"
Write-Host "Elapsed Time     : $elapsedTime"


}
