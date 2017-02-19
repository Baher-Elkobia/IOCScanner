<#

.SYNOPSIS

.DESCRIPTION
This PowerShell framework is a free tool for scanning remote host systems looking for the presence of IOCs. 

.PARAMETER targets
A path to a txt file includes a list of targets each in a separate line.

.PARAMETER IOCList
A path to a CSV file includes a list of IOCs each in a sepearate column, use the template provided with the script and make sure not to change the columns' name

.PARAMETER username
A domain user name with local admin privilege in the formate of domain\username 

.PARAMETER password
A password to the provided name

.PARAMETER Block
optional switch to quarantine compromised hosts, this option will disable the network card of any host who has one or more of the provided IOCs

.EXAMPLE
.\IOC.ps1 -targets c:\IOCScanner\servers.txt -IOCList c:\IOCScanner\iocs.csv -username domain\username -password xyzpass
Full path for each file

.EXAMPLE
.\IOC.ps1 -targets servers.txt -IOCList iocs.csv -username domain\username -password xyzpass
Save all files in the same folder with the script and use the file name without a full path

.EXAMPLE
.\IOC.ps1 -targets servers.txt -IOCList iocs.csv -Block
use Block switch to quarantine any compromised host

.NOTES
Nothing so far, Send any issues or sugesstions to eng.baher@hotmail.com

.LINK
http://www.CyberInsight360.com
https://github.com/Eslam-Elkobia/IOCScanner

#>

# English check
# domain list

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True)]
   [string]$targets,
	
   [Parameter(Mandatory=$True)]
   [string]$IOCList,

   [Parameter(Mandatory=$True)]
   [string]$UserName,

   [Parameter(Mandatory=$True)]
   [string]$Password,
   
   [Parameter(Mandatory=$False)]
   [switch]$Block = $False
)

########################################## Initialization ################################################

function Write-Ascii {
# Wrapping the script in a function to make it a module

[CmdLetBinding()]
param(
    [Parameter(ValueFromPipeline=$true, Mandatory=$true)][string[]] $InputText,
    [switch] $PrependChar,
    [switch] $Compression,
    [string] $ForegroundColor = 'Default',
    [string] $BackgroundColor = 'Default'
    #[int] $MaxChars = '25'
    )

begin {
    
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    
    # Algorithm from hell... This was painful. I hope there's a better way.
    function Get-Ascii {
    
        param([string] $Text)
    
        $LetterArray = [char[]] $Text.ToLower()
    
        #Write-Host -fore green $LetterArray
    
        # Find the letter with the most lines.
        $MaxLines = 0
        $LetterArray | ForEach-Object { if ($Letters.([string] $_).Lines -gt $MaxLines ) { $MaxLines = $Letters.([string] $_).Lines } }
    
        # Now this sure was a simple way of making sure all letter align tidily without changing a lot of code!
        if (-not $Compression) { $MaxLines = 6 }
    
        $LetterWidthArray = $LetterArray | ForEach-Object { $Letter = [string] $_; $Letters.$Letter.Width }
        $LetterLinesArray = $LetterArray | ForEach-Object { $Letter = [string] $_; $Letters.$Letter.Lines }
    
        #$LetterLinesArray
    
        $Lines = @{
            '1' = ''
            '2' = ''
            '3' = ''
            '4' = ''
            '5' = ''
            '6' = ''
        }
    
        #$LineLengths = @(0, 0, 0, 0, 0, 0)
    
        # Debug
        #Write-Host "MaxLines: $Maxlines"

        $LetterPos = 0
        foreach ($Letter in $LetterArray) {
        
            # We need to work with strings for indexing the hash by letter
            $Letter = [string] $Letter
        
            # Each ASCII letter can be from 4 to 6 lines.
        
            # If the letter has the maximum of 6 lines, populate hash with all lines.
            if ($LetterLinesArray[$LetterPos] -eq 6) {
            
                #Write-Host "Six letter letter"

                foreach ($Num in 1..6) {
                
                    $StringNum = [string] $Num
                
                    $LineFragment = [string](($Letters.$Letter.ASCII).Split("`n"))[$Num-1]
                
                    if ($LineFragment.Length -lt $Letters.$Letter.Width) {
                        $LineFragment += ' ' * ($Letters.$Letter.Width - $LineFragment.Length)
                    }
                
                    $Lines.$StringNum += $LineFragment
                
                }
            
            }
        
            # Add padding for line 6 for letters with 5 lines and populate lines 2-6.
            ## Changed to top-adjust 5-line letters if there are 6 total.
            ## Added XML properties for letter alignment. Most are "default", which is top-aligned.
            ## Also added script logic to handle it (2012-12-29): <fixation>bottom</fixation>
            elseif ($LetterLinesArray[$LetterPos] -eq 5) {
            
                #Write-Host "Five-letter letter"
            
                if ($MaxLines -lt 6 -or $Letters.$Letter.fixation -eq 'bottom') {
                
                    $Padding = ' ' * $LetterWidthArray[$LetterPos]
                    $Lines.'1' += $Padding
                
                    foreach ($Num in 2..6) {
                    
                        $StringNum = [string] $Num
                    
                        $LineFragment = [string](($Letters.$Letter.ASCII).Split("`n"))[$Num-2]
                    
                        if ($LineFragment.Length -lt $Letters.$Letter.Width) {
                            $LineFragment += ' ' * ($Letters.$Letter.Width - $LineFragment.Length)
                        }
                    
                        $Lines.$StringNum += $LineFragment
                    
                    }
                
                }
            
                else {
                
                    $Padding = ' ' * $LetterWidthArray[$LetterPos]
                    $Lines.'6' += $Padding
                
                    foreach ($Num in 1..5) {
                    
                        $StringNum = [string] $Num
                    
                        $LineFragment = [string](($Letters.$Letter.ASCII).Split("`n"))[$Num-1]
                    
                        if ($LineFragment.Length -lt $Letters.$Letter.Width) {
                            $LineFragment += ' ' * ($Letters.$Letter.Width - $LineFragment.Length)
                        }
                    
                        $Lines.$StringNum += $LineFragment
                    
                    }
                
                }
            
            }
        
            # Here we deal with letters with four lines.
            # Dynamic algorithm that places four-line letters on the bottom line if there are
            # 4 or 5 lines only in the letter with the most lines.
            else {
            
                #Write-Host "Four letter letter"

                # Default to putting the 4-liners at line 3-6
                $StartRange, $EndRange, $IndexSubtract = 3, 6, 3
                $Padding = ' ' * $LetterWidthArray[$LetterPos]
            
                # If there are 4 or 5 lines...
                if ($MaxLines -lt 6) {
                
                    $Lines.'2' += $Padding
                
                }
           
                # There are 6 lines maximum, put 4-line letters in the middle.
                else {
                
                    $Lines.'1' += $Padding
                    $Lines.'6' += $Padding
                    $StartRange, $EndRange, $IndexSubtract = 2, 5, 2
                
                }
            
                # There will always be at least four lines. Populate lines 2-5 or 3-6 in the hash.
                foreach ($Num in $StartRange..$EndRange) {
                
                    $StringNum = [string] $Num
                
                    $LineFragment = [string](($Letters.$Letter.ASCII).Split("`n"))[$Num-$IndexSubtract]
                
                    if ($LineFragment.Length -lt $Letters.$Letter.Width) {
                        $LineFragment += ' ' * ($Letters.$Letter.Width - $LineFragment.Length)
                    }
                
                    $Lines.$StringNum += $LineFragment
                
                }
            
            }
        
            $LetterPos++
        
        } # end of LetterArray foreach
    
        # Return stuff
        $Lines.GetEnumerator() | Sort Name | Select -ExpandProperty Value | ?{ $_ -match '\S' } | %{ if ($PrependChar) { "'" + $_ } else { $_ } }
    
    }

    # Populate the $Letters hashtable with character data from the XML.
    Function Get-LetterXML {
    
        $LetterFile = Join-Path $PSScriptRoot 'letters.xml'
        $Xml = [xml] (Get-Content $LetterFile)
    
        $Xml.Chars.Char | ForEach-Object {
        
            $Letters.($_.Name) = New-Object PSObject -Property @{
            
                'Fixation' = $_.fixation
                'Lines'    = $_.lines
                'ASCII'    = $_.data
                'Width'    = $_.width
            
            }
        
        }
    
    }

    function Write-RainbowString {
    
        param([string] $Line,
              [string] $ForegroundColor = '',
              [string] $BackgroundColor = '')

        $Colors = @('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow',
            'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')


        # $Colors[(Get-Random -Min 0 -Max 16)]

        [char[]] $Line | %{
        
            if ($ForegroundColor -and $ForegroundColor -ieq 'rainbow') {
            
                if ($BackgroundColor -and $BackgroundColor -ieq 'rainbow') {
                    Write-Host -ForegroundColor $Colors[(Get-Random -Min 0 -Max 16)] `
                        -BackgroundColor $Colors[(Get-Random -Min 0 -Max 16)] -NoNewline $_
                }
                elseif ($BackgroundColor) {
                    Write-Host -ForegroundColor $Colors[(Get-Random -Min 0 -Max 16)] `
                        -BackgroundColor $BackgroundColor -NoNewline $_
                }
                else {
                    Write-Host -ForegroundColor $Colors[(Get-Random -Min 0 -Max 16)] -NoNewline $_
                }

            }
            # One of them has to be a rainbow, so we know the background is a rainbow here...
            else {
            
                if ($ForegroundColor) {
                    Write-Host -ForegroundColor $ForegroundColor -BackgroundColor $Colors[(Get-Random -Min 0 -Max 16)] -NoNewline $_
                }
                else {
                    Write-Host -BackgroundColor $Colors[(Get-Random -Min 0 -Max 16)] -NoNewline $_
                }
            }

        }
    
        Write-Host ''
    
    }

    # Get ASCII art letters/characters and data from XML. Make it persistent for the module.
    if (-not (Get-Variable -EA SilentlyContinue -Scope Script -Name Letters)) {
        $script:Letters = @{}
        Get-LetterXML
    }

    # Turn the [string[]] into a [string] the only way I could figure out how... wtf
    #$Text = ''
    #$InputText | ForEach-Object { $Text += "$_ " }

    # Limit to 30 characters
    #$MaxChars = 30
    #if ($Text.Length -gt $MaxChars) { "Too long text. There's a maximum of $MaxChars characters."; return }

    # Replace spaces with underscores (that's what's used for spaces in the XML).
    #$Text = $Text -replace ' ', '_'

    # Define accepted characters (which are found in XML).
    #$AcceptedChars = '[^a-z0-9 _,!?./;:<>()¤{}\[\]\|\^=\$\-''+`\\"æøåâàáéèêóòôü]' # Some chars only works when sent as UTF-8 on IRC
    $LetterArray = [string[]]($Letters.GetEnumerator() | Sort Name | Select -ExpandProperty Name)
    $AcceptedChars = [regex] ( '(?i)[^' + ([regex]::Escape(($LetterArray -join '')) -replace '-', '\-' -replace '\]', '\]') + ' ]' )
    # Debug
    #Write-Host -fore cyan $AcceptedChars.ToString()
}

process {
    if ($InputText -match $AcceptedChars) { "Unsupported character, using these accepted characters: " + ($LetterArray -join ', ') + "."; return }

    # Filthy workaround (now worked around in the foreach creating the string).
    #if ($Text.Length -eq 1) { $Text += '_' }

    $Lines = @()

    foreach ($Text in $InputText) {
        
        $ASCII = Get-Ascii ($Text -replace ' ', '_')

        if ($ForegroundColor -ne 'Default' -and $BackgroundColor -ne 'Default') {
            if ($ForegroundColor -ieq 'rainbow' -or $BackGroundColor -ieq 'rainbow') {
                $ASCII | ForEach-Object { Write-RainbowString -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -Line $_ }
            }
            else {
                Write-Host -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor ($ASCII -join "`n")
            }
        }
        elseif ($ForegroundColor -ne 'Default') {
            if ($ForegroundColor -ieq 'rainbow') {
                $ASCII | ForEach-Object { Write-RainbowString -ForegroundColor $ForegroundColor -Line $_ }
            }
            else {    
                Write-Host -ForegroundColor $ForegroundColor ($ASCII -join "`n")
            }
        }
        elseif ($BackgroundColor -ne 'Default') {
            if ($BackgroundColor -ieq 'rainbow') {
                $ASCII | ForEach-Object { Write-RainbowString -BackgroundColor $BackgroundColor -Line $_ }
            }    
            else {
                Write-Host -BackgroundColor $BackgroundColor ($ASCII -join "`n")
            }
        }
        else { $ASCII -replace '\s+$' }

    } # end of foreach

} # end of process block
    
}

Write-Ascii 'IOC Scanner'; Write-Host ""
$date =  Get-Date -format "dd-MMM-yyyy-HH-mm"
$Summary = @{}
$Clone = @{Compromised = "False";Blocked = "False";MachineName ="";WinVersion = "";FileIOCs="False";FolderIOCs="False";ProcessIOCs="False";ServiceIOCs="False";RegistryIOCs="False";ConnectionIOCS="False";PortIOCs="False";UserIOCs="False";GroupIOCs="False"}
if ($Password -and $UserName)
{
    $securePass = ConvertTo-SecureString -string $Password -AsPlainText -Force
    $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $UserName, $securePass
}

########################################## Test Parameters ################################################

if($targets)
{
    if(Test-Path $targets)
        {
        $Servers = Get-Content $targets
        }
    else
        {
        Write-Warning "$targets file is not found, please keep the file in the same location with the script or provide a full path to the file"
        Write-Host "Refer to the help for some examples, Get-help .\IOCScanner -examples" -ForegroundColor Yellow
        exit
        }
 }
 else
 {
 $Servers = $env:COMPUTERNAME
 }

if(Test-Path $IOCList)
    {
    $IOCs = Import-Csv -Path $IOCList
    $registryIOCs = @{}

        $i=1
        foreach($IOC in $IOCs)
        {
            $IOCValue = if($IOC.Value){$IOC.value}else{continue}
            $IOCKey = if($IOC.Key){$IOC.Key}else{continue}
            $registryIOCs[$i]=@{}
            $registryIOCs[$i][$IOC.RegistryPath]=@{}
            $registryIOCs[$i][$IOC.RegistryPath].add($IOCKey,$IOCValue)
            $i +=1
        }
    }
else
    {
    Write-Warning "$IOCList file is not found, please keep the file in the same location with the script or provide a full path to the file"
    Write-Host "Refer to the help for some examples, Get-help .\IOCScanner -examples" -ForegroundColor Yellow
    exit
    }

########################################## Test conntectivity to hosts ################################################


Write-Host '[+] Testing connectivity to targets ...'
Write-Host ''
[array]$Hosts = @()
foreach ($server in $Servers)
{ 
  if (test-connection -computername $server -count 1 -quiet)
  {
    if(Invoke-Command -ScriptBlock {Get-host} -ComputerName $server -Credential $cred -ErrorAction SilentlyContinue)
    {
        Write-Host '[+] Host ' $server  ' is ready for scanning ...' -ForegroundColor Green
        $Hosts += $server
    }
    else
    {
        Write-Host '[+] Remoting is not enabled in Host '$server -ForegroundColor Red 
    }
  }
  else
  {
   Write-Host '[+] Host ' $server  ' is not responding ...' -ForegroundColor Red
  }
}
Write-Host ''

if(-not $Hosts)
{
Write-Warning "All hosts are not reachable, script is terminating ..."
exit
}

########################################## Establish Sessions ################################################

get-job | Remove-Job -Force
Get-PSSession | Remove-PSSession
   
$PSSessions = New-PSSession -ComputerName $Hosts -SessionOption (New-PSSessionOption -NoMachineProfile) -Credential $cred
$jobs = Invoke-Command -FilePath '.\engine.ps1' -ArgumentList ($IOCs.file, $IOCs.folder, $registryIOCs, $IOCs.service, $IOCs.process, $IOCs.connection, $IOCs.port, $IOCs.user,$IOCs.group) -Session $PSSessions -ThrottleLimit 10 -AsJob


########################################## Console Output ################################################

# Wait for jobs and progress bar
While ($(Get-Job -state running).count -ge 1)
{
    Write-Progress  -Activity "Creating connections to targets" -Status "Waiting for threads to close" -CurrentOperation "$($jobs.ChildJobs.Count) threads created - $($($($jobs.ChildJobs |Get-Job).State -eq "running").count) threads open" -PercentComplete ($($($($jobs.ChildJobs |Get-Job).State -eq "running").count) / $Hosts.count * 100)
    Start-Sleep -Milliseconds 1
}

# prepare Summary Dictionary
foreach ($job in $jobs.ChildJobs)
{
$summary[$job.location]=$Clone.Clone()
$summary[$job.location]['WinVersion'] = Invoke-Command -ScriptBlock {Get-WmiObject -class Win32_OperatingSystem} -ComputerName $job.location -Credential $cred
$summary[$job.location]['MachineName'] = Invoke-Command -ScriptBlock {$env:computername} -ComputerName $job.location -Credential $cred
}

# check/print the result of each job/host
$compromisedHosts = @()
$Jobs.ChildJobs | Foreach-Object { 
$ChildJob = $_
$counter =0 ; $Recpt = 0
$Recpt = Receive-Job $ChildJob -Keep

Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host "                         IOCs details for" $ChildJob.location -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Yellow
$Recpt
    $i = 0
    $FileIocOut, $FolderIocOut, $GroupIocOut,$UserIocOut,$ProcessIocOut, $ServiceIocOut,$ConnectionIocOut,$RegIocOut,$PortIocOut = $null

    foreach ($item in $Recpt)
    {
        switch -Wildcard ($item) 
        {
           "-->>-- File IOCs*" {
           $summary[$ChildJob.location]["FileIOCs"] = "True" 
           $counter++
               
               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$FileIocOut += , $Recpt[$j]
               }
            }
            "-->>-- Folder IOCs*" {
           $summary[$ChildJob.location]["FolderIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$FolderIocOut += , $Recpt[$j]
               }
            }
            "-->>-- Group IOCs*" {
           $summary[$ChildJob.location]["GroupIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$GroupIocOut += , $Recpt[$j]
               }
            }
            "-->>-- User IOCs*" {
           $summary[$ChildJob.location]["UserIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$UserIocOut += , $Recpt[$j]            
               }
            }
            "-->>-- Service IOCs*" {
           $summary[$ChildJob.location]["ServiceIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$ServiceIocOut += , $Recpt[$j]            
               }            
            }
            "-->>-- Process IOCs*" {
           $summary[$ChildJob.location]["ProcessIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$ProcessIocOut += , $Recpt[$j]            
               }              
            }
            "-->>-- Port IOCs*" {
           $summary[$ChildJob.location]["PortIOCs"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$PortIocOut += , $Recpt[$j]            
               }  
            }
            "-->>-- Connection IOCs*" {
           $summary[$ChildJob.location]["ConnectionIOCS"] = "True"
           $counter++

               for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$ConnectionIocOut += , $Recpt[$j]            
               }              
            }
            "-->>-- Registry IOCs*" {
           $summary[$ChildJob.location]["RegistryIOCs"] = "True"
           $counter++

                for($j = $i+1;$j -le $Recpt.Count; $j++)
               {
               
               if(!$Recpt[$j]){break}
               [array]$RegIocOut += , $Recpt[$j]            
               }  
            }
         }
         $i++
    }
    $FileIocOut = $FileIocOut | Out-String
    $FolderIocOut = $FolderIocOut | Out-String
    $GroupIocOut = $GroupIocOut | Out-String
    $UserIocOut = $UserIocOut | Out-String
    $ServiceIocOut = $ServiceIocOut | Out-String
    $ProcessIocOut = $ProcessIocOut | Out-String
    $PortIocOut = $PortIocOut | Out-String
    $ConnectionIocOut = $ConnectionIocOut | Out-String
    $RegIocOut = $RegIocOut | Out-String
    $Server = $summary[$ChildJob.location].MachineName + "-" + $ChildJob.location 

    if($counter -gt 0)
    {
        $summary[$ChildJob.location]["Compromised"] = "True"
        [array]$compromisedHosts += $childjob | select location -ExpandProperty 'location'
        $HostIocsHTML = @"       
    <!-- Experience Start -->
    <section >
        <p></p>
        <div class="container">
           <div class="row">
                <div class="col-sm-12">
                    <div class="section-title">
                        <h1>$Server</h1>
                         <div class="divider dark">
						   <i class="icon-ghost"></i>
						  </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
			<div class="col-md-12 ">
				<div class="experience">		
				<div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>File IOCs details</h4>
						<pre> $FileIOCOUT </pre>
					</div>
				 </div>

				 <div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Folder IOCs details</h4>
						<pre> $FolderIocOut</pre>
					</div>
				 </div>
				 	

			     <div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Registry IOCs details</h4>
						<pre>$RegIocOut</pre>
					</div>
				 </div>
				 
				 <div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Service IOCs details</h4>
						<pre>$ServiceIocOut</pre>
					</div>
				 </div>
				 
				 <div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Process IOCs details</h4>
						<pre>$ProcessIocOut</pre>
					</div>
				 </div>
				 
				 <div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Connection IOCs details</h4>
						<pre>$ConnectionIocOut</pre>
					</div>
				 </div>	
							
				<div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Port IOCs details</h4>
						<pre>$PortIocOut</pre>
					</div>
				 </div>
				 		
				<div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>User IOCs details</h4>
						<pre>$UserIocOut</pre>
					</div>
				 </div>
				  		
				<div class="experience-item">
					<div class="experience-circle experience-company pink-color-bg">
					   <i class="icon-energy"></i>
					</div>
					<div class="experience-content">
						<h4>Group IOCs details</h4>
						<pre> $GroupIocOut</pre>
					</div>
				 </div>
				 
			 </div>
			</div>
            
           </div>
        </div>
    </section>
    <!-- Experience End -->
"@
        $AgreegIocHtml += $HostIocsHTML 
    }
 }

########################################## Quarantine Section ################################################

if($compromisedHosts.count -gt 0)
{
$Percentage = [math]::Round(($compromisedHosts.count*100/$Hosts.Count),2)
Write-Host ""
Write-Host "Total Number of compromised machies are:"  $compromisedHosts.count "out of"  $Hosts.count "with a percentage of" $Percentage "of total number of machines" -ForegroundColor Green    
}

$BlockedHosts = @()
if($Block -and ($compromisedHosts.count -gt 0))
{
    $BlockConfirm = Read-Host -Prompt "Type [Yes] to Confirm blocking all compromised hosts ..." 
    if($BlockConfirm -like "yes")
    {
       $BlockJobs= Invoke-Command -ScriptBlock{
                Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Wireless%'" | ForEach-Object {$_.disable()}
                Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Intel%'" | ForEach-Object {$_.disable()}
            } -ComputerName $compromisedHosts -Credential $cred -AsJob 
        
        # Wait for blocking jobs 
        Write-Host ''
        Write-Host 'Blocking compromised hosts ...' -ForegroundColor Yellow
        Write-Host ''
        Start-Sleep ($compromisedHosts.Count * 3)

        Write-Host '[+] Testing connectivity to blocked hosts ...'
        Write-Host ''

        foreach ($server in $compromisedHosts)
        { 
          if (test-connection -computername $server -count 1 -quiet)
          {
               Write-Host '[+] Host ' $server  ' is not blocked ...' -ForegroundColor Red
          }
          else
          {
               Write-Host '[+] Host ' $server  ' is  blocked ...' -ForegroundColor Yellow
               $BlockedHosts += $server
               $summary[$server]["Blocked"] = "True"
          }
        }
        $blockedCount = $BlockedHosts.Count
    }
}

########################################## Summary Section ################################################
write-host ""
write-host "===============================================================" -ForegroundColor Green
write-host "****                        Summanry                       ****" -ForegroundColor Green
write-host "===============================================================" -ForegroundColor Green
write-host "=                                Compromised        Blocked  ="
foreach ($Target in $Summary.GetEnumerator())
{
    Write-Host $Target.name"<"$Target.value['MachineName']">" -ForegroundColor Yellow

    if($Target.value['Compromised'] -eq 'True')
    {
        Write-Host "                                  >>>  Yes" -ForegroundColor Red -NoNewline

        if($Target.value['Blocked'] -eq 'True')
        {
        Write-Host "        >>>  Yes" -ForegroundColor green 
        }
        else
        {
        Write-Host "        >>>  No" -ForegroundColor Red 
        }
    }
    else
    {
        Write-Host "                                  >>>  No" -ForegroundColor Green
    }
}
    write-host "==============================================================="-ForegroundColor Green
    Write-Host "" 
   

########################################## Reporting Section ################################################

     $HostsCount = $Hosts.Count
     $compromisedHostsCount = $compromisedHosts.count
     $CleanHostsCount = $Hosts.count - $compromisedHosts.count

     $Outfile = $(".\report\IOC_Scan_Result_" + $date + ".html")
     $htmlHead = @" 
 <!DOCTYPE html>
<html lang="en">

  <head>
    
    <!-- Meta Tag -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    
    <!-- SEO -->
    <meta name="description" content="150 words">
    <meta name="author" content="Eslam Elkobia">
    <meta name="url" content="http://www.CyberInsight.com">
    <meta name="copyright" content="CyberInsight.com">
    <meta name="robots" content="index,follow">
    
    
    <title>IOC Scanner</title>
    
    <!-- Favicon -->
    <link rel="shortcut icon" href="images/favicon/favicon.ico">
    <link rel="apple-touch-icon" sizes="144x144" type="image/x-icon" href="images/favicon/apple-touch-icon.png">
    
    <!-- All CSS Plugins -->
    <link rel="stylesheet" type="text/css" href="css/plugin.css">
    
    <!-- Main CSS Stylesheet -->
    <link rel="stylesheet" type="text/css" href="css/style.css">
    
    <!-- Google Web Fonts  -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Poppins:400,300,500,600,700">
    
    
    <!-- HTML5 shiv and Respond.js support IE8 or Older for HTML5 elements and media queries -->
    <!--[if lt IE 9]>
	   <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
	   <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
    

 </head>

  <body>
	
	<!-- Preloader Start -->
    <div class="preloader">
	  <p>Loading...</p>
     </div>
     <!-- Preloader End -->

    <!-- Menu Section Start -->
    <header id="home">
        
        <div class="header-top-area">
            <div class="container">
                <div class="row">
                
                    <div class="col-sm-3">
                        <div class="logo">
                            <a href="index-2.html">Incident Report</a>
                        </div>
                    </div>                    
                 </div>
            </div>
        </div>
     </header>
     <!-- Menu Section End -->  
    
    
    <!-- Head of the page -->
               <div class="row">
                <div class="col-sm-12">
                    <div class="section-title">
                        <h1>IOC Scannr</h1>
                         <div class="divider dark">
						   <i class="icon-lock"></i>
						  </div>
                        <p>Look closer ...</p>
                    </div>
                </div>
            </div>
    
    <!-- End Head of the page -->
     
     
      <!-- statistics -->
      <section class="statistics-section section-space-padding bg-cover text-center">
         <div class="container">     
            <div class="row">
            
          <div class="col-md-3">
            <div class="statistics bg-color-6">
              <div class="statistics-icon"><i class="icon-check"></i>
              </div>
              <div class="statistics-content">
                <h5> <span data-count="$HostsCount" class="statistics-count"></span></h5><span>Hosts Scanned</span>
              </div>
            </div>
          </div>

           <div class="col-md-3">
            <div class="statistics bg-color-1">
              <div class="statistics-icon"><i class="icon-ghost"></i>
              </div>
              <div class="statistics-content">
                <h5><span data-count="$compromisedHostsCount" class="statistics-count"></span></h5><span>Compromised Hosts</span>
              </div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="statistics bg-color-4">
              <div class="statistics-icon"><i class="icon-emotsmile"></i>
              </div>
              <div class="statistics-content">
                <h5> <span data-count="$CleanHostsCount" class="statistics-count"></span></h5><span>Clean Hosts</span>
              </div>
            </div>
          </div>

          <div class="col-md-3">
            <div class="statistics bg-color-2">
              <div class="statistics-icon"><i class="icon-shield"></i>
              </div>
              <div class="statistics-content">
                <h5> <span data-count="$blockedCount" class="statistics-count"></span></h5><span>Isolated Hosts</span>
              </div>
            </div>
          </div>

         </div>
       </div>
    </section>
    <!-- statistics end -->
"@
     $htmlHead | Out-File -Encoding utf8 -FilePath $Outfile
     $AgreegIocHtml | Out-File -Append -Encoding utf8 -FilePath $Outfile
     $HTMLFooter = @"
    <!-- Footer Start -->
    <footer class="footer-section">
        <div class="container">
            <div class="row">
            <div class="col-md-12">
              <ul class="social-icon margin-bottom-30">
                 <li><a href=http://www.linkedin.com/in/eslamelkobia target="_blank" class="linkedin"><i class="icon-social-linkedin"></i></a></li>
               </ul>
          </div>
              
             <div class="col-md-12 uipasta-credit">
                <p>Design By <a>Eslam Elkobia</a></p>
                </div>
                
             </div>
        </div>
    </footer>
    <!-- Footer End -->
    
    
    <!-- Back to Top Start -->
    <a href="#" class="scroll-to-top"><i class="icon-arrow-up-circle"></i></a>
    <!-- Back to Top End -->
    
    
    <!-- All Javascript Plugins  -->
    <script type="text/javascript" src="js/jquery.min.js"></script>
    <script type="text/javascript" src="js/plugin.js"></script>
    
    <!-- Main Javascript File  -->
    <script type="text/javascript" src="js/scripts.js"></script>
  
  
  </body>
 </html>
"@
     $HTMLFooter| Out-File -Append -Encoding utf8 -FilePath $Outfile