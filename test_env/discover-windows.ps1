#requires -Version 5.1
# Standalone, read-only Windows inventory. Redirect stdout to save the JSON report.
# powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\discover-windows.ps1
[CmdletBinding(DefaultParameterSetName = 'Alias')]
param(
    [Parameter(ParameterSetName = 'Alias')]
    [ValidateNotNullOrEmpty()]
    [string]$InterfaceAlias = 'Ethernet',

    [Parameter(Mandatory = $true, ParameterSetName = 'Index')]
    [ValidateRange(1, 2147483647)]
    [int]$InterfaceIndex
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$inspectionErrors = New-Object 'System.Collections.Generic.List[object]'

function Add-InspectionError {
    param([string]$Section, [string]$Message)
    $inspectionErrors.Add([ordered]@{ section = $Section; message = $Message })
}

# PowerShell redirects non-success streams only to stream 1. Separate diagnostic
# records immediately so that command warnings cannot enter inventory or stdout.
function Split-QueryOutput {
    process {
        if ($_ -is [System.Management.Automation.WarningRecord] -or
            $_ -is [System.Management.Automation.VerboseRecord] -or
            $_ -is [System.Management.Automation.DebugRecord] -or
            $_ -is [System.Management.Automation.InformationRecord]) {
            [Console]::Error.WriteLine($_.ToString())
        } else {
            $_
        }
    }
}

function Convert-Adapter {
    param($Adapter)
    $mac = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Adapter.MacAddress)) {
        $compactMac = ([string]$Adapter.MacAddress) -replace '[-:.]', ''
        if ($compactMac -notmatch '^[0-9a-fA-F]{12}$') {
            throw "Adapter '$($Adapter.Name)' returned an invalid MAC address."
        }
        $mac = (($compactMac.ToLowerInvariant() -split '(.{2})' | Where-Object { $_ }) -join ':')
    }
    [ordered]@{
        name = [string]$Adapter.Name
        interface_index = [int]$Adapter.InterfaceIndex
        mac = $mac
        status = [string]$Adapter.Status
        hardware_interface = [bool]$Adapter.HardwareInterface
        virtual = [bool]$Adapter.Virtual
        interface_description = [string]$Adapter.InterfaceDescription
        link_speed = [string]$Adapter.LinkSpeed
    }
}

$selection = [ordered]@{
    interface_alias = $null
    interface_index = $null
}
if ($PSCmdlet.ParameterSetName -eq 'Index') {
    $selection.interface_index = $InterfaceIndex
} else {
    $selection.interface_alias = $InterfaceAlias
}
$data = [ordered]@{
    adapter = $null
    addresses = $null
    routes = $null
    ip_interface = $null
    adapters = $null
    dns_servers = $null
    os = $null
    powershell_version = $PSVersionTable.PSVersion.ToString()
}

# Query all adapters once, then match literally: aliases are not wildcard selectors.
$adapters = $null
try {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
    $data.adapters = @($adapters | ForEach-Object { Convert-Adapter $_ })
} catch {
    Add-InspectionError 'adapters' $_.Exception.Message
}

$selected = $null
try {
    if ($null -eq $adapters) {
        throw 'Adapter selection is unavailable because Get-NetAdapter failed; see adapters error.'
    }
    if ($PSCmdlet.ParameterSetName -eq 'Index') {
        $matches = @($adapters | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex })
    } else {
        $matches = @($adapters | Where-Object { $_.Name -eq $InterfaceAlias })
    }
    if ($matches.Count -ne 1) {
        throw "Expected exactly one adapter matching the explicit selection; found $($matches.Count)."
    }
    $selected = $matches[0]
    $selection.interface_alias = [string]$selected.Name
    $selection.interface_index = [int]$selected.InterfaceIndex
    $data.adapter = Convert-Adapter $selected
} catch {
    Add-InspectionError 'adapter' $_.Exception.Message
}

if ($null -ne $selected) {
    $selectedIndex = [int]$selected.InterfaceIndex
    try {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $selectedIndex -AddressFamily IPv4 -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
        $data.addresses = @($addresses | ForEach-Object {
            [ordered]@{
                address = [string]$_.IPAddress
                prefix_length = [int]$_.PrefixLength
                address_state = [string]$_.AddressState
                prefix_origin = [string]$_.PrefixOrigin
                suffix_origin = [string]$_.SuffixOrigin
            }
        })
    } catch {
        Add-InspectionError 'addresses' $_.Exception.Message
    }
    try {
        $interfaces = @(Get-NetIPInterface -InterfaceIndex $selectedIndex -AddressFamily IPv4 -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
        if ($interfaces.Count -ne 1) {
            throw "Expected one selected IPv4 IP interface; found $($interfaces.Count)."
        }
        $data.ip_interface = [ordered]@{
            dhcp = [string]$interfaces[0].Dhcp
            interface_metric = [int]$interfaces[0].InterfaceMetric
            connection_state = [string]$interfaces[0].ConnectionState
        }
    } catch {
        Add-InspectionError 'ip_interface' $_.Exception.Message
    }
    try {
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $selectedIndex -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
        $data.dns_servers = @($dns | ForEach-Object {
            $family = switch ([int]$_.AddressFamily) {
                2 { 'IPv4' }
                23 { 'IPv6' }
                default { [string]$_.AddressFamily }
            }
            [ordered]@{
                interface_index = [int]$_.InterfaceIndex
                address_family = $family
                server_addresses = @($_.ServerAddresses | ForEach-Object { [string]$_ })
            }
        })
    } catch {
        Add-InspectionError 'dns_servers' $_.Exception.Message
    }
} else {
    foreach ($section in @('addresses', 'ip_interface', 'dns_servers')) {
        Add-InspectionError $section 'Inspection unavailable because the selected adapter could not be resolved; see adapter error.'
    }
}

# Do not filter by selected adapter: competing routes are part of the inventory.
try {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
    $data.routes = @($routes | ForEach-Object {
        [ordered]@{
            destination_prefix = [string]$_.DestinationPrefix
            next_hop = [string]$_.NextHop
            interface_index = [int]$_.InterfaceIndex
            route_metric = [int]$_.RouteMetric
        }
    })
} catch {
    Add-InspectionError 'routes' $_.Exception.Message
}

try {
    $systems = @(Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption, Version, BuildNumber -ErrorAction Stop 3>&1 4>&1 5>&1 6>&1 | Split-QueryOutput)
    if ($systems.Count -ne 1) {
        throw "Expected one operating system record; found $($systems.Count)."
    }
    $data.os = [ordered]@{
        caption = [string]$systems[0].Caption
        version = [string]$systems[0].Version
        build = [string]$systems[0].BuildNumber
    }
} catch {
    Add-InspectionError 'os' $_.Exception.Message
}

$envelope = [ordered]@{
    schema = 'nn-ebpf-lab-discovery'
    schema_version = 1
    role = 'windows-client'
    collected_at = [DateTime]::UtcNow.ToString('o')
    read_only = $true
    selection = $selection
    data = $data
    errors = @($inspectionErrors.ToArray())
}
$envelope | ConvertTo-Json -Depth 12
if ($inspectionErrors.Count -gt 0) {
    exit 1
}
exit 0
