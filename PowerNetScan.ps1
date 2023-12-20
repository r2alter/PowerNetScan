function Format-ConsoleOutput{
    <#
    .SYNOPSIS
        Helper function for format output.

    .DESCRIPTION
        Helper function which check if target object has hostname attribute set and modify output string. 
        Information about object with hostname will be displayed with this hostname.

    #>
    param(
        [Parameter(Mandatory)]$targetObject
    )

    # Check if object contains hostname and return IP address with Hostname as String
    if($targetObject.Hostname){
        return "$($targetObject.IPAddress) ($($targetObject.Hostname))"
    }
    else{
        return "$($targetObject.IPAddress)"
    }
}

function Get-ScanningTime{
    <#
    .SYNOPSIS
        Helper function for extract scanning time in readable format without useless information.

    .DESCRIPTION
        Helper function which get diffrence between start time and finish time of scanning. Check if values of days,
        hours, minutes and seconds are greater than zero and add to output string.

    #>
    param(
        [Parameter(Mandatory)]$startTime,
        [Parameter(Mandatory)]$finishTime
    )

    $executionTime = $finishTime - $startTime
    $result = [String]::Empty
    # Check days
    if($executionTime.Days -gt 0){
        $result += "$($executionTime.Days) days, "
    }
    # Check hours
    if($executionTime.Hours -gt 0){
        $result += "$($executionTime.Hours) hours, "
    }
    # Check minutes
    if($executionTime.Minutes -gt 0){
        $result += "$($executionTime.Minutes) minutes, "
    }
    # Check seconds
    if($executionTime.Seconds -gt 0){
        $result += "$($executionTime.Seconds) seconds, "
    }
    # Add miliseconds - the smallest unit
    $result += "$($executionTime.Milliseconds) milliseconds."

    return $result

}

function Format-Hosts{
    <#
    .SYNOPSIS
        Helper function for format input.

    .DESCRIPTION
        Helper function which check Hosts parameter and format it to array of target objects 
        which contain ip address and hostname (if exists) of target.

    #>
    param (
        [Parameter(Mandatory)]$hostsInput
    )

    $result = [System.Collections.ArrayList]@()

    ForEach($hostInput in $hostsInput)
    {
        # case 10.1.1.4-5
        if($hostInput -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])-([01]?\d?\d|2[0-4]\d|25[0-5])$"){
            $range = $hostInput.Split(".")[3].Split("-")
            if($range[0] -lt $range[1]){
                $prefix = $hostInput.Substring(0, $hostInput.LastIndexOf(".") + 1) # get first three octets 
                ForEach($singleHost in $range[0]..$range[1]){
                    $target = [PSCustomObject]@{
                        IPAddress = ($prefix + $singleHost)
                        Hostname = [String]::Empty
                        OpenPorts = [System.Collections.ArrayList]@()
                    }
                    $result += $target
                }
            }
            else {
                Write-Host "Bad range input *${hostInput}* Not added to scan scope."
            }
            
        }
        # case 10.1.4-5.1
        elseif($hostInput -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){2}([01]?\d?\d|2[0-4]\d|25[0-5])-([01]?\d?\d|2[0-4]\d|25[0-5])\.([01]?\d?\d|2[0-4]\d|25[0-5])$"){
            $range = $hostInput.Split(".")[2].Split("-")
            if($range[0] -lt $range[1]){
                $prefix = $hostInput.Substring(0, $hostInput.IndexOf(".", $hostInput.IndexOf(".") + 1) + 1) # get first two octets
                $suffix = $hostInput.Substring($hostInput.LastIndexOf("."), $hostInput.Split(".")[3].Length + 1) # get last octet
                ForEach($singleHost in $range[0]..$range[1]){
                    $target = [PSCustomObject]@{
                        IPAddress     = ($prefix + $singleHost + $suffix)
                        Hostname = [String]::Empty
                        OpenPorts = [System.Collections.ArrayList]@()
                    }
                    $result += $target
                }
            }
            else {
                Write-Host "Bad range input *${hostInput}* Not added to scan scope."
            }
            
        }
        # case 10.4-5.1.1
        elseif ($hostInput -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.)([01]?\d?\d|2[0-4]\d|25[0-5])-([01]?\d?\d|2[0-4]\d|25[0-5])\.([01]?\d?\d|2[0-4]\d|25[0-5])\.([01]?\d?\d|2[0-4]\d|25[0-5])$") {
            $range = $hostInput.Split(".")[1].Split("-")
            if($range[0] -lt $range[1]){
                $prefix = $hostInput.Substring(0, $hostInput.IndexOf(".") + 1) # get first octet
                $secondDotIndex = $hostInput.IndexOf(".", $hostInput.IndexOf(".") + 1) # find second dot
                $suffix = $hostInput.Substring( $secondDotIndex , $hostInput.Length - $secondDotIndex) # get last two octets
                ForEach($singleHost in $range[0]..$range[1]){
                    $target = [PSCustomObject]@{
                        IPAddress = ($prefix + $singleHost +$suffix)
                        Hostname = [String]::Empty
                        OpenPorts = [System.Collections.ArrayList]@()
                    }
                    $result += $target
                }
            }
            else {
                Write-Host "Bad range input *${hostInput}* Not added to scan scope."
            }
            
        }
        # case 20-23.1.1.1
        elseif ($hostInput -match "^([01]?\d?\d|2[0-4]\d|25[0-5])-([01]?\d?\d|2[0-4]\d|25[0-5])\.(([01]?\d?\d|2[0-4]\d|25[0-5])\.){2}([01]?\d?\d|2[0-4]\d|25[0-5])$") {
            $range = $hostInput.Split(".")[0].Split("-")
            if($range[0] -lt $range[1]){
                $firstDotIndex = $hostInput.IndexOf(".")
                $suffix = $hostInput.Substring($firstDotIndex, $hostInput.Length - $firstDotIndex) # get last three octets
                ForEach($singleHost in $range[0]..$range[1]){
                    $target = [PSCustomObject]@{
                        IPAddress = ($prefix + $singleHost)
                        Hostname = [String]::Empty
                        OpenPorts = [System.Collections.ArrayList]@()
                    }
                    $result += $target
                }
            }
            else {
                Write-Host "Bad range input *${hostInput}* Not added to scan scope."
            }
            
        }
        # case 10.0.0.0/8
        elseif ($hostInput -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\/([12]?\d|3[0-2])$") {
            $ipAddrString, $netMaskString = $hostInput.Split("/")
            if( $netMaskString -gt 30){
                $target = [PSCustomObject]@{
                    IPAddress = $ipAddrString
                    Hostname = [String]::Empty
                    OpenPorts = [System.Collections.ArrayList]@()
                }
                $result += $target

            }
            else {
                $ipAddr = [IPAddress] $ipAddrString
                $hostNumber = [Math]::Pow(2, 32 - $netMaskString) - 2
                $maskBytes = [BitConverter]::GetBytes([UInt32] (([Math]::Pow(2, $netMaskString) - 1) * [Math]::Pow(2, (32 - $netMaskString))))
                $netMaskString = (($maskBytes.Count - 1)..0 | ForEach-Object { [String] $maskBytes[$_] }) -join "."
                $netMask = [IPAddress] $netMaskString
                $baseAddr = [IPAddress] ($ipAddr.Address -band $netMask.Address)

                for($i = 0; $i -lt $hostNumber; $i++){
                    $tempAddr = $baseAddr.GetAddressBytes()
                    [array]::Reverse($tempAddr)
                    $tempAddr  = [System.BitConverter]::ToUInt32($tempAddr ,0)
                    $tempAddr++
                    $tempAddr  = [System.BitConverter]::GetBytes($tempAddr)
                    [array]::Reverse($tempAddr)
                    $baseAddr = [IPAddress] $tempAddr
                    $target = [PSCustomObject]@{
                        IPAddress = $baseAddr.IPAddressToString
                        Hostname = [String]::Empty
                        OpenPorts = [System.Collections.ArrayList]@()
                    }
                    $result += $target

                }
                
            }
        }
        # case 10.2.1.1
        elseif ($hostInput -match "^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])$") {
            $target = [PSCustomObject]@{
                IPAddress = $hostInput
                Hostname = [String]::Empty
                OpenPorts = [System.Collections.ArrayList]@()
            }
            
            $result += $target
        }
        # case - any hostname like google.com
        elseif ($hostInput.ToString().ToLower() -match "[a-z]") {
            try{
                $addresses =  ([System.Net.Dns]::GetHostEntry($hostInput)).AddressList | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
                if($addresses.Count -gt 0){
                    ForEach($address in $addresses){
                        $target = [PSCustomObject]@{
                            IPAddress = $address.IPAddressToString
                            Hostname = $hostInput
                            OpenPorts = [System.Collections.ArrayList]@()
                        }
                        $result += $target
                    }
                }
                else{
                    Write-Host "Not found IPv4 address for entry ${hostInput} - Not added to scope."
                }
            }
            catch{
                Write-Host "Cannot resolve ${hostInput} - Not added to scope."
            }
        }
        else {
            Write-Host "Input *${hostInput}* does not seem to be valid ip range or Hostname. Not added to scan scope."
        }
    }

    $result = $result | Sort-Object -Unique -Property 'IPAddress' #remove multiplication
    return $result
}

function Format-HostsFile {
    param (
        [Parameter(Mandatory)]$HostsFiles
    )
    <#
        <#
    .SYNOPSIS
        Helper function for format input.

    .DESCRIPTION
        Helper function which check HostsFile parameter - if files exists, read files treated each line as entry
        to target poll and format it to array of target objects which contain ip address and hostname of target.
        
    #>

    $result = [System.Collections.ArrayList]@()

    foreach($File in $HostsFiles){
        # check if file exists 
        if(Test-Path $File -PathType Leaf){
            # parse all lines in files and add to result array
            foreach($line in Get-Content $File){
                $result += Format-Hosts $line
            }
        }
        else{
                Write-Host "The specified file does not exist: ${File} - Not added to scan scope."
        }
    }
    $result = $result | Sort-Object -Unique -Property 'IPAddress' #remove multiplication
    return $result
}
function Format-Ports{
       <#
    .SYNOPSIS
        Helper function for format input.

    .DESCRIPTION
        Helper function which check Ports parameter and format it to array of port numbers.
        
    #>
    param(
        $inputPorts
    )
    
    $result = [System.Collections.ArrayList]@()

    foreach($ports in $inputPorts){
        if($ports -is [Int32] -And $ports -gt 0 -And $ports -le 65535){
            $result += $ports
        }
        elseif($ports -is [String] -And $ports -match "^\d+-\d+$"){
            $range = $ports.Split("-")
            if($range[0] -lt $range[1] -and $range[0] -gt 0 -and $range[1] -le 65535){
                $result += $range[0]..$range[1]
            }
        }
    }
    
    return ($result | Sort-Object -Unique)
}

function Invoke-TCPPortScan{
    <#
    .SYNOPSIS
        Script perform simple TCP port scanning using multithreading.

    .DESCRIPTION
        Script perform TCP port scanning based on asynchronous connection. It is used TcpClient object from System.Net.Sockets assemlby.
        Before starting TCP scanning hostInputs list and port scope is validating. It is possible to pass hosts list via argument OR file.
        There are three types to show results - console output, save to file or retrun object.

    .OUTPUTS
        Objects have three attributes: 
        IP address - String
        Hostname - String 
        OpenPorts - System Array with Strings 

    .EXAMPLE
        Invoke-TCPPortScan -Hosts google.com,amazon.com -Threads 50

        PowerNetScan started at: 12/19/2023 09:37:40 with command: Invoke-TCPPortScan -Hosts google.com,amazon.com -Threads 50 
        Task finished at 12/19/2023 09:37:50 and scanning time was: 9 seconds, 863 milliseconds.

        PowerNetScan scan results:
        Totally scanned 4 hosts.
        Did NOT perform ping check.

        142.250.186.206 (google.com) open ports:
        80
        443
        -----------
        205.251.242.103 (amazon.com) open ports:
        443
        80
        -----------
        52.94.236.248 (amazon.com) open ports:
        80
        443
        -----------
        54.239.28.85 (amazon.com) open ports:
        443
        80
        -----------

    .EXAMPLE
        Invoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose 

        VERBOSE: Parsing input.
        VERBOSE: Source of targets - script argument.
        VERBOSE: Scan scope summary: 1 hosts / 5 portInvoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose s.
        PowerNetScan started at: 12/19/2023 09:45:46 with command: Invoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose True 
        VERBOSE: +-------------- LIVE RESULTS -------------------+
        VERBOSE: 142.250.186.206 (google.com) - port 443 open.
        VERBOSE: 142.250.186.206 (google.com) - port 80 open.
        VERBOSE: +-----------------------------------------------+
        Task finished at 12/19/2023 09:45:49 and scanning time was: 2 seconds, 42 milliseconds.

        PowerNetScan scan results:
        Totally scanned 1 hosts.
        Did NOT perform ping check.

        142.250.186.206 (google.com) open ports:
        443
        80
        -----------

    .EXAMPLE
        Invoke-TCPPortScan -HostsFile ./test_scope.txt -Threads 50 -Timeout 0.5 -ShowScope -ObjectOutput -FileOutput results.txt

        PowerNetScan started at: 12/19/2023 10:18:28 with command: Invoke-TCPPortScan -HostsFile ./test_scope.txt -Threads 50 -Timeout 0.5 -ShowScope True -ObjectOutput True -FileOutput results.txt 
        Task finished at 12/19/2023 10:18:48 and scanning time was: 20 seconds, 83 milliseconds.


        IPAddress       Hostname      OpenPorts
        ---------       --------      ---------
        20.112.250.133  microsoft.com {443, 80}
        20.231.239.246  microsoft.com {80, 443}
        20.236.44.162   microsoft.com {80, 443}
        20.70.246.20    microsoft.com {443, 80}
        20.76.201.171   microsoft.com {443, 80}
        205.251.242.103 amazon.com    {80, 443}
        216.58.208.206  google.com    {80, 443}
        52.94.236.248   amazon.com    {80, 443}
        54.239.28.85    amazon.com    {80, 443}

    .EXAMPLE
        $results = Invoke-TCPPortScan -Hosts 192.168.88.0/24 -Ports 80 -Threads 50 -Verbose -ObjectOutput

        VERBOSE: Parsing input.
        VERBOSE: Source of targets - script argument.
        VERBOSE: Scan scope summary: 254 hosts / 1 ports.
        PowerNetScan started at: 12/19/2023 10:31:59 with command: Invoke-TCPPortScan -Hosts 192.168.88.0/24 -Ports 80 -Threads 50 -Verbose True -ObjectOutput True 
        VERBOSE: +-------------- LIVE RESULTS -------------------+
        VERBOSE: 192.168.88.183 - port 80 open.
        VERBOSE: 192.168.88.2 - port 80 open.
        VERBOSE: +-----------------------------------------------+
        Task finished at 12/19/2023 10:32:05 and scanning time was: 6 seconds, 96 milliseconds.
    
    .LINK
        https://github.com/r2alter/PowerNetScan

    #>
    [CmdletBinding()]
    param(
    # Targets to scan - ip addresses, ip address ranges, hostnames. It should be separated using comma. 
    # This parameter accept arrays of strings also.
    [Parameter(Mandatory = $true, 
    ParameterSetName = "ShellInput")]
    [Parameter(Mandatory = $false, 
    ParameterSetName = "NoShellInput")]
    $Hosts,

    # Filename contains targets to scan. Evety line in file is treated as one ip address, ip address range or hostname.
    [Parameter(Mandatory = $false, 
    ParameterSetName = "ShellInput")]
    [Parameter(Mandatory = $true, 
    ParameterSetName = "NoShellInput")]
    $HostsFile,

    # Array of ports which will be scanned. Default - top 250 from nmap
    # cat /usr/share/nmap/nmap-services | grep /tcp | sort -k3 -r -n | head -250 | awk '{ print $2}' | sed 's/\/tcp/,/g' | tr '\n' ' '
    $Ports=@(80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 
        8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 
        49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 
        49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000,
        5432, 1900, 3986, 13, 1029, 9, 6646, 5051, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001, 82,
        10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1056, 1049, 1065, 2967, 1053, 1048, 
        1064, 1054, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 8010, 1039, 4001, 2869, 9000, 5120, 2105, 636, 
        1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 1998, 2005, 1032, 1050, 6112, 3690, 
        1521, 2161, 6002, 1080, 2401, 4045, 902, 787, 7937, 1058, 2383, 32771, 1059, 1040, 1033, 50000, 5555, 10001, 1494, 
        593, 3, 2301, 7938, 3268, 1234, 1022, 1074, 9001, 8002, 1036, 1035, 1037, 464, 1935, 497, 6666, 2003, 6543, 24, 
        1352, 3269, 1111, 407, 500, 20, 2006, 1034, 3260, 15000, 1218, 4444, 264, 2004, 33, 42510, 1042, 3052, 999, 1023, 
        222, 1068, 7100, 888, 563, 1717, 992, 32770, 2008, 32772, 7001, 2007, 8082, 5550, 5801, 2009, 512, 1043, 50001, 
        2701, 1700, 7019, 4662, 2065, 2010, 42, 161, 2602),
    
    # Time to wait for response from target
    [float]$Timeout=1,

    # Number of threads
    [int]$Threads=2,
    
    # Switch to write to output all target machines and scanned ports.
    [switch]$ShowScope,

    # Switch to force write results to console output, works only with FileOutput parameter.
    [switch]$ConsoleOutput,

    # Switch to export results of scan as array of PowerShell objects.
    [switch]$ObjectOutput,

    # Path to file where save results.
    [string]$FileOutput    
    )      

    #####
     ###
      #   Input validation  

    Write-Verbose "Parsing input."

    # Check if source of targets is from parameter values of from file and format it.
    if($null -ne $Hosts){
        Write-Verbose "Source of targets - script argument."
        $targets = Format-Hosts $Hosts
    }
    else{
        Write-Verbose "Source of targets - file(s): ${HostsFile}"
       $targets = Format-HostsFile $HostsFile
    }
    
    # Format ports input.
    $portScope = Format-Ports $Ports
    
    # Check if Hosts or Ports scope is empty after formating.
    if($null -eq $targets){
        Write-Host "[!] After parsing HOSTS parameter, targets scope are empty. Check input. [!]" -ForegroundColor Red
       Return
    }
    if($null -eq $portScope){
        Write-Host "[!] After parsing PORTS parameter, port scope are empty. Check input. [!]" -ForegroundColor Red
        Return
    }

    # Show scope if user want it.
    if($ShowScope){
            Write-Verbose "Inputed hosts and ports was parsed. Scan scope:"
            Write-Verbose "Hosts:"
            ForEach($target in $targets){
                Write-Verbose "$(Format-ConsoleOutput $target)"
                }
                
            Write-Verbose "Ports: ${portScope}"
    }
   
    # Scanning scope summary
    Write-Verbose "Scan scope summary: $($targets.Count) hosts / $($portScope.Count) ports."  
    

    # Check if user use output parameters 
    if(-Not ($FileOutput -Or $ObjectOutput -Or $PSCmdlet.MyInvocation.BoundParameters["FileOutput"])){
        # If user dont use output parameters - console output default  
        $ConsoleOutput = $true
    }
    elseif($PSCmdlet.MyInvocation.BoundParameters["FileOutput"]){
        # If user used file output parameter 
        if(Test-Path $FileOutput -PathType Leaf){
            # If file already exists 
            while($response -ne "Y" -And $response -ne "y" -And $response -ne "N" -And $response -ne "n"){
                $response = Read-Host "The file ${FileOutput} already exists. Do you want to override it? (Y/N)"
            }
                
            if($response -eq "Y" -Or $response -eq "y"){
                $FileValidation = $true
            }
            else{
                while($response -ne "Y" -And $response -ne "y" -And $response -ne "N" -And $response -ne "n"){
                    $response = Read-Host "The path ${FileOutput} override canceled. Do you want to continue with console output? (Y/N)"
                }

                if($response -eq "Y" -Or $response -eq "y"){
                    $ConsoleOutput = $true
                }
                else{
                    if(-Not $ObjectOutput){
                        Write-Host "[!] No output type choosen. Scan aborted. [!]" -ForegroundColor Red
                        Return
                    }
                }
            }
        }
        elseif((Split-Path $FileOutput) -eq [String]::Empty -And -Not ($FileOutput | Test-Path -PathType Leaf)){
            # Case - only filename provided
            $FileValidation = $true
            New-Item -Path $FileOutput -ItemType File > $null
        }
        elseif(Split-Path $FileOutput | Test-Path -PathType Container){
            # If Path is valid - create output file
            $FileValidation = $true
            New-Item -Path $FileOutput -ItemType File > $null
        }
        else{
            # If path to output file is invalid 
            # Ask to contiune with console output
            while($response -ne "Y" -And $response -ne "y" -And $response -ne "N" -And $response -ne "n"){
                $response = Read-Host "The path ${FileOutput} do not exists. Do you want to continue with console output? (Y/N)"
            }
                
            if($response -eq "Y" -Or $response -eq "y"){
                $ConsoleOutput = $true
            }
            else{
                if(-Not $ObjectOutput){
                    Write-Host "[!] No output type choosen. Scan aborted. [!]" -ForegroundColor Red
                    Return
                }
            }
        }
    }

    #####
     ###
      #   Scanning block
    
    # Get start time
    $startTime = Get-Date

    # Show script execution information
    Write-Host "PowerNetScan started at: ${startTime} with command: $($MyInvocation.InvocationName) " -NoNewline
    ForEach($parameterName in $MyInvocation.BoundParameters.Keys){
        $parameterValues = $MyInvocation.BoundParameters[$parameterName] -join ' ' -replace ' ', ','
        Write-Host "-${parameterName} $parameterValues " -NoNewline
    }
    Write-Host

    # Script block with TCP Scanning using ConnectAsync TCPClient function.
    # Necessary to creating multiple threads.
    [System.Management.Automation.ScriptBlock]$ScanTCPScriptBlock = {
        param (
            $targetIPAddress,
            $targetPort,
            $timeoutSeconds
        )
        $result = [PSCustomObject]@{
            IPAddress = $targetIPAddress
            Port = [string]$targetPort
            Status = $false
        }

        $clientTCP = New-Object System.Net.Sockets.TcpClient
        $connection = $clientTCP.ConnectAsync($targetIPAddress, $targetPort)
        for($i=0; $i -lt ($timeoutSeconds*10); $i++){
            if($connection.IsCompleted) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        $clientTCP.Close()
        if($connection.Status -eq "RanToCompletion"){
            $result.Status = $true
        }
        
        $result
    }

    # Creating Runspaces pool and jobs array for saving results.
    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$Jobs = @()
    

    # Live results if verbose
    Write-Verbose "+-------------- LIVE RESULTS -------------------+"

    ForEach($target in $targets){

        # For randomize order of port scanning
        $portScope = $portScope | Get-Random -Count $portScope.Count 
            
        ForEach($port in $portScope){  
    
            # Prepare parameters for TCP Scan Script Block
            $ScanParameters = @{
                targetIPAddress = $target.IPAddress
                targetPort = $port
                timeoutSeconds = $Timeout
            }

            # Create job and add to Runspace pool
            $Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScanTCPScriptBlock).AddParameters($ScanParameters)
            $Job.RunspacePool = $RunspacePool
            
            # Create object for saving job results and add to array
            $JobResultsObject = [PSCustomObject]@{
                Indicator = $Job
                Result = $Job.BeginInvoke()
            }
            $Jobs.Add($JobResultsObject) > $null

        }
   }

   # Processing results of finished job
   Do{
        # Filter finished jobs or wait if no jobs are finished
        $JobsDone = $Jobs | Where-Object -FilterScript { $_.Result.IsCompleted }
        if ($null -eq $JobsDone) {
            Start-Sleep -Milliseconds 500
            continue
        }
        else{
            # Remove finished jobs from job array and check results. 
            # If port open add data to targets array
            foreach($JobInProcess in $JobsDone){

                $JobResults = $JobInProcess.Indicator.EndInvoke($JobInProcess.Result)
                $JobInProcess.Indicator.Dispose()
                $Jobs.Remove($JobInProcess)

                if($JobResults.Status){
                    # find target which result is connected with    
                    $foundTarget = $targets | Where-Object { $_.IPAddress -eq  $JobResults.IPAddress }
                    Write-Verbose "$(Format-ConsoleOutput $foundTarget) - port $($JobResults.Port) open."
                    $foundTarget.OpenPorts += $JobResults.Port

                }
           }
       }
   }While($Jobs.Count -gt 0)


    # Get finish time
    $finishTime = Get-Date
    Write-Verbose "+-----------------------------------------------+"
   
    #####
     ###
      #   Show results
    
    # Show finish info
    Write-Host "Task finished at ${finishTime} and scanning time was: $(Get-ScanningTime $startTime $finishTime)"
    Write-Host

    # Console output 
    if($ConsoleOutput){
        Write-Host "PowerNetScan scan results:"
        Write-Host "Totally scanned $($targets.Count) hosts."
        Write-Host "Did NOT perform ping check."
        Write-Host
    
        ForEach($target in $targets){
            If($target.OpenPorts.Count){
                Write-Host "$(Format-ConsoleOutput $target) open ports:"
                ForEach($port in $target.OpenPorts){
                    Write-Host $port
                }
            }
            else{                   
                Write-Host "No open ports detected for $(Format-ConsoleOutput $target)"
            }
            Write-Host "-----------"
        }
    }

    # File output
    if($FileValidation){
        "PowerNetScan scan results:" | Out-File $FileOutput 
        "Totally scanned $($targets.Count) hosts." | Out-File $FileOutput -Append
        "Did NOT perform ping check." | Out-File $FileOutput -Append
        "" | Out-File $FileOutput -Append

        ForEach($target in $targets){
            If($target.OpenPorts.Count){
                "$(Format-ConsoleOutput $target) open ports:" | Out-File $FileOutput -Append
                ForEach($port in $target.OpenPorts){
                    $port | Out-File $FileOutput -Append
                }
            }
            else{                   
                 "No open ports detected for $(Format-ConsoleOutput $target)" | Out-File $FileOutput -Append
            }
             "-----------" | Out-File $FileOutput -Append
        }
    }

    # Object output
    if($ObjectOutput){
        return $targets
    }
    
}
