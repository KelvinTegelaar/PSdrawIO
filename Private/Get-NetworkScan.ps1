function Get-Networkscan {
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'Network', Mandatory = $false)]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Network
    ) 
    
    begin {
        $network = $PSBoundParameters.Network
    }
    
    process {
        if ($Network) {
            write-host "Scanning network $Network"
            get-netadapter | Remove-NetNeighbor -AddressFamily IPv4 -Confirm:$false -erroraction silentlycontinue
            $ScanResults = Invoke-PSnmap -ComputerName $network -Port 22, 445, 443, 3389, 9100 -ScanOnPingFail -DNS -NoSummary -PortConnectTimeoutMS 500
        }
        else {
            write-host "Scanning all local networks"
            $networks = Get-NetIPAddress | Where-Object -Property prefixorigin -ne "WellKnown"
            $ScanResults = foreach ($Network in $networks) {
                Invoke-PSnmap -ComputerName "$($network.ipaddress)/$($Network.prefixlength)" -Port 22, 445, 443, 3389, 9100 -ScanOnPingFail -DNS -NoSummary -PortConnectTimeoutMS 500
            }
        }
           
        $i = 0
        foreach ($Result in $ScanResults | Where-Object -Property ping -ne $false) {
            if ($Result.'ip/DNS') { $hostname = $Result.'IP/DNS' } else { $hostname = $Result.computername }
            $MACList = import-csv -path "$($MyInvocation.MyCommand.Module.ModuleBase)\private\macaddress.io-db.csv" -Delimiter ','
            $OUI = ((Get-NetNeighbor $Result.computername -erroraction silentlycontinue).linklayeraddress -replace '-', ':')
            if ($OUI) { $PossibleManafacture = $MACList | Where-Object -Property oui -eq ($OUI).substring(0, 8) }
            Write-Verbose $result.computername
            Write-Verbose "OUI Match: $PossibleManafacture"
            $DeviceType = switch ($result) {
                { $null -ne $PossibleManafacture.image } { $PossibleManafacture.image; break }
                { $_.'port 9100' -eq $true } { 'mxgraph.office.devices.printer'; break }
                { $_.'port 3389' -eq $true } { 'mxgraph.office.concepts.application_windows'; break }
                { $_.'port 445' -eq $true } { 'mxgraph.office.concepts.application_windows'; break }
                { $_.'port 443' -eq $true } { 'mxgraph.office.concepts.application_web'; break }
                { $_.'port 22' -eq $true } { 'mxgraph.office.servers.topology_builder'; break }
                Default { 'mxgraph.office.concepts.help' }
            }
            $i++
            if ($i -eq 1) { $refid = $null } else { $Refid = 1 }
            [PSCustomObject]@{
                id       = $i
                hostname = $hostname
                fill     = '#F77F00'
                stroke   = '#003049'
                shape    = $devicetype
                refs     = $RefID
            }
        }
    }
    
}
