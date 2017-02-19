[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True)]
   $FileIOCs,
  [Parameter(Mandatory=$True)]
   $FolderIOCs,
  [Parameter(Mandatory=$True)]
   $RegIOCs,
  [Parameter(Mandatory=$True)]
   $ServiceIOCs,
  [Parameter(Mandatory=$True)]
   $ProcessIOCs,
  [Parameter(Mandatory=$True)]
   $ConnectionIOCs,
  [Parameter(Mandatory=$True)]
   $PortIOCs,
  [Parameter(Mandatory=$True)]
   $UserIOCs,
  [Parameter(Mandatory=$True)]
   $GroupIOCs
)   
    $ErrorActionPreference = 'SilentlyContinue'
    $server = $env:COMPUTERNAME
    $IOCCount =0 
    function FileIOCsScan ($FileIOCsList)
    {
    $FileIOCsArray = @()
    $FileIOCsProperties = @{
        "FullName" = '';
        "CreationTime" = '';
        "LastAccessTime" = '';
        "LastWriteTime" = '' ;
    }
       
        ######################## Checking FILE IOCs ######################## 
        Write-Output ""
        Write-Output "Searching file IOCs in $server ..." 
        $counter = 0
        foreach ($fileIOC in $FileIOCsList)
            {
              $FileObject = New-Object -TypeName PSObject -Property $FileIOCsProperties

              if($fileIOC -notlike "" -and $fileIOC -match "[a-zA-z]:\\.+[a-zA-Z]{1,3}")
              {
                if(Test-Path -Path $fileIOC)
                {
                $FileObject.FullName = Get-Item -Path $fileIOC | Select-Object "fullname" -ExpandProperty fullname
                $FileObject.LastAccessTime = Get-Item -Path $fileIOC | Select-Object "LastAccessTime" -ExpandProperty LastAccessTime 
                $FileObject.LastWriteTime = Get-Item -Path $fileIOC | Select-Object "LastWriteTime" -ExpandProperty LastWriteTime
                $FileObject.CreationTime = Get-Item -Path $fileIOC | Select-Object "CreationTime" -ExpandProperty CreationTime
                $FileIOCsArray += , $FileObject

                $counter += 1
                }
              }
              elseif($fileIOC -notlike "" -and $fileIOC -notmatch "[a-zA-z]:\\.+[a-zA-Z]{1,3}")
              {
                if($FilePath = dir -Recurse c:\ $fileIOC |select "fullname" -ExpandProperty fullname)
                {
                $FileObject.FullName = $FilePath
                $FileObject.LastAccessTime = Get-Item -Path $FilePath | Select-Object "LastAccessTime" -ExpandProperty LastAccessTime
                $FileObject.LastWriteTime = Get-Item -Path $FilePath | Select-Object "LastWriteTime" -ExpandProperty LastWriteTime
                $FileObject.CreationTime = Get-Item -Path $FilePath | Select-Object "CreationTime" -ExpandProperty CreationTime
                $FileIOCsArray += , $FileObject

                $counter += 1
                }
              }
            }
        Write-Output "***********************************"

        if ($counter -gt 0)
        {
            Write-Output "-->>-- File IOCs are found in $server"
            $IOCCount++
            $FileIOCsArray
        }
        else 
        {
            Write-Output "NO File IOCs were found in $server"
        }

    }

    function FolderIOCsScan ($FolderIOCsList)
    {
        $FolderIOCsArray = @()
        $FolderIOCsProperties = @{
        "FullName" = '';
        "CreationTime" = '';
        "LastAccessTime" = '';
        "LastWriteTime" = '' ;
    }
            ######################## Checking Folder IOCs ########################
        Write-Output ""
        Write-Output "Searching folder IOCs in $server ..." 

        $counter = 0
        foreach ($folderIOC in $FolderIOCsList)
            {
              $FolderObject = New-Object -TypeName PSObject -Property $FolderIOCsProperties

              if($folderIOC -notlike "" -and $folderIOC -match "[a-zA-z]:\\.+")
              {
                if(Test-Path $folderIOC)
                {
                $FolderObject.FullName = Get-Item -Path $folderIOC | Select-Object "fullname" -ExpandProperty fullname
                $FolderObject.LastAccessTime = Get-Item -Path $folderIOC | Select-Object "LastAccessTime" -ExpandProperty LastAccessTime
                $FolderObject.LastWriteTime = Get-Item -Path $folderIOC | Select-Object "LastWriteTime" -ExpandProperty LastWriteTime
                $FolderObject.CreationTime = Get-Item -Path $folderIOC | Select-Object "CreationTime" -ExpandProperty CreationTime
                $FolderIOCsArray += , $FolderObject

                $counter += 1
                }
              }
              elseif($folderIOC -notlike "" -and $folderIOC -notmatch "[a-zA-z]:\\.+")
              {
                if($FolderPath = dir -Recurse c:\ $folderIOC |select "fullname" -ExpandProperty fullname)
                {
                $FolderObject.FullName = $FolderPath
                $FolderObject.LastAccessTime = Get-Item -Path $FolderPath | Select-Object "LastAccessTime" -ExpandProperty LastAccessTime
                $FolderObject.LastWriteTime = Get-Item -Path $FolderPath | Select-Object "LastWriteTime" -ExpandProperty LastWriteTime
                $FolderObject.CreationTime = Get-Item -Path $FolderPath | Select-Object "CreationTime" -ExpandProperty CreationTime
                $FolderIOCsArray += , $FolderObject

                $counter += 1
                }
              }
            }
        Write-Output "***************************************" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Folder IOCs are found in $server"
            $FolderIOCsArray
        }
        else 
        {
            Write-Output "NO Folder IOCs were found in $server"
        }
    }
    
    function RegistryIOCsScan ($RegistryIOCsList)
    {
        $RegIOCsArray = @()
        $RegIOCsProperties = @{
        "Value" = '';
        "Property" = '';
        "Key" = '';
    }
        ######################## Checking Registry IOCs ########################
        Write-Output ""
        Write-Output "Searching Registry IOCs in $server ..."

        $counter = 0
         foreach ($registryIOC in $RegistryIOCsList.GetEnumerator())
         {   
             foreach($item in $registryIOC.Value.GetEnumerator())
             {
                foreach($RegistryPath in $item.Value.GetEnumerator() )
                {
                   $RegObject = New-Object -TypeName PSObject -Property $RegIOCsProperties

                   #$item.Name
                   #$($RegistryPath.name)
                   #$($RegistryPath.value)

                   if($item.Name -match "(HKEY_LOCAL_MACHINE)")
                    {
                    $RegName = $RegistryPath.name
                    $RegValue = $RegistryPath.value
                    $RegLocation = $item.Name -replace "(HKEY_LOCAL_MACHINE)",'HKLM:'

                    if(((Get-ItemProperty -Path $RegLocation).$RegName) -like $RegValue)
                        {
                        $RegObject.Key = $RegLocation
                        $RegObject.Property = $RegName
                        $RegObject.Value = $RegValue
                        $RegIOCsArray += , $RegObject
 
                        $counter += 1
                        }
                    }
                   elseif($item.Name -match "(HKEY_CURRENT_USER)")
                    {
                    $RegistryLocation = $item.Name -replace "(HKEY_CURRENT_USER)",'HKCU:'
                    if(((Get-ItemProperty -Path $RegLocation).$RegName) -like $RegValue)
                        {
                        $RegObject.Key = $RegLocation
                        $RegObject.Property = $RegName
                        $RegObject.Value = $RegValue
                        $RegIOCsArray += , $RegObject
                        
                        $counter += 1
                        }
                    }
                }
             }
         }
        Write-Output "***************************************" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Registry IOCs are found in $server"
            $RegIOCsArray
        }
        else 
        {
            Write-Output "NO Registry IOCs were found in $server" 
        }
    }

    function ServiceIOCsScan ($ServiceIOCsList)
    {
        $ServiceIOCsArray = @()
        $ServiceIOCsProperties = @{
        "ServiceHandle" = '';
        "MachineName" = '';
        "CanShutdown" = '';
        "CanStop" = '';
        "CanPauseAndContinue" = '';
        "ServiceType" = '';
        "DependentServices" = '';
        "RequiredServices" = '';
        "Status" = '';
        "ServiceName" = '';
        "DisplayName" = '';
        "Name" = '';
    }
        ######################## Checking Services IOCs ########################
        Write-Output ""
        Write-Output "Searching service IOCs in $server ..." 

        $counter = 0
        foreach ($serviceIOC in $ServiceIOCsList)
            {
              $ServiceObject = New-Object -TypeName PSObject -Property $ServiceIOCsProperties

              if($serviceIOC -notlike "")
              {
                if(Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC})
                {
                $ServiceObject.ServiceHandle = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "ServiceHandle" -ExpandProperty ServiceHandle
                $ServiceObject.MachineName = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "MachineName" -ExpandProperty MachineName
                $ServiceObject.CanShutdown = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "CanShutdown" -ExpandProperty CanShutdown
                $ServiceObject.CanStop = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "CanStop" -ExpandProperty CanStop
                $ServiceObject.CanPauseAndContinue = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "CanPauseAndContinue" -ExpandProperty CanPauseAndContinue
                $ServiceObject.ServiceType = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "ServiceType" -ExpandProperty ServiceType
                $ServiceObject.DependentServices = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "DependentServices" -ExpandProperty DependentServices
                $ServiceObject.RequiredServices = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "RequiredServices" -ExpandProperty RequiredServices
                $ServiceObject.Status = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "Status" -ExpandProperty Status
                $ServiceObject.ServiceName = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "ServiceName" -ExpandProperty ServiceName
                $ServiceObject.DisplayName = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "DisplayName" -ExpandProperty DisplayName
                $ServiceObject.Name = Get-Service | Where-Object{$_.Name -like $serviceIOC -OR $_.ServiceName -like $serviceIOC} | Select-Object "Name" -ExpandProperty Name
                $ServiceIOCsArray += , $ServiceObject

                $counter += 1
                }
              }
            }
        Write-Output "***************************************" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Service IOCs are found in $server"
            $ServiceIOCsArray
        }
        else 
        {
            Write-Output "NO Service IOCs were found in $server" 
        }
    }

    function ProcessIOCsScan ($ProcessIOCsList)
    {
        $ProcessIOCsArray = @()
        $ProcessIOCsProperties = @{
        "Modules" = '';
        "ProductVersion" = '';
        "Company" = '';
        "StartTime" = '';
        "FileVersion" = '';
        "Product" = '';
        "Description" = '';
        "Path" = '';
        "Id" = '';
        "ProcessName"= '';
        "Name" = '';
    }
        ######################## Checking process IOCs ########################
        Write-Output ""
        Write-Output "Searching process IOCs in $server ..." 

        $counter = 0
        foreach ($processIOC in $ProcessIOCsList)
            {
              $ProcessObject = New-Object -TypeName PSObject -Property $ProcessIOCsProperties

              if($processIOC -notlike "")
              {
                if(Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ProcessName -like $processIOC})
                {
                $ProcessObject.Modules = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Modules" -ExpandProperty Modules
                $ProcessObject.ProductVersion = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "ProductVersion" -ExpandProperty ProductVersion
                $ProcessObject.Company = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Company" -ExpandProperty Company
                $ProcessObject.StartTime = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "StartTime" -ExpandProperty StartTime
                $ProcessObject.FileVersion = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "FileVersion" -ExpandProperty FileVersion
                $ProcessObject.Product = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Product" -ExpandProperty Product
                $ProcessObject.Description = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Description" -ExpandProperty Description
                $ProcessObject.Path = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Path" -ExpandProperty Path
                $ProcessObject.Id = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Id" -ExpandProperty Id
                $ProcessObject.ProcessName = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "ProcessName" -ExpandProperty ProcessName
                $ProcessObject.Name = Get-process | Where-Object{$_.Name -like $processIOC -OR $_.ServiceName -like $processIOC} | Select-Object "Name" -ExpandProperty Name
                $ProcessIOCsArray += , $ProcessObject                
                
                $counter += 1
                }
              }
            }
        Write-Output "***************************************" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Process IOCs are found in $server"
            $ProcessIOCsArray
        }
        else 
        {
            Write-Output "NO Process IOCs were found in $server" 
        }
    }

    function ConnectionIOCsScan ($ConnectionsIOCsList)
    {
        $ConnectionIOCsArray = @()
        $ConnectionIOCsProperties = @{
       "Description" = 'NA';
        "ExecutablePath" = 'NA';
        "Id" = 'NA';
        "ProcessName"= 'NA';
        "Name" = 'NA';
        "IP" = 'NA';
        }
        ######################## Checking Connection IOCs ########################
        Write-Output ""
        Write-Output "Searching Connection IOCs in $server ..." 

        $counter = 0
        foreach ($coneectionIOC in $ConnectionsIOCsList)
            {
              if($coneectionIOC -notlike "")
              {
                  if($ConnectionInfo = netstat -aon | findstr $coneectionIOC)
                  {
                      $ConnectionObject = New-Object -TypeName PSObject -Property $ConnectionIOCsProperties
                      $Connectionresult = if($ConnectionInfo -is [system.array]) {$ConnectionInfo[0]} else {$ConnectionInfo}

                      $Connectionresult = $Connectionresult -replace '^\s+','' -split '\s+' -split '\d:\d'
                         $Protocole = $Connectionresult[0]
                         $LocalAddress = $Connectionresult[1]
                         $LocalPort = $Connectionresult[2]
                         $ForeignAddress = $Connectionresult[3]
                         $ForeignPort = $Connectionresult[4]
                         $State = $Connectionresult[5]
                         $Process = $Connectionresult[6]
                  
                        $ConnectionObject.Description = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "Description" -ExpandProperty Description
                        $ConnectionObject.ExecutablePath = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "ExecutablePath" -ExpandProperty ExecutablePath
                        $ConnectionObject.Id = $process 
                        $ConnectionObject.ProcessName = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "ProcessName" -ExpandProperty ProcessName
                        $ConnectionObject.Name = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "Name" -ExpandProperty Name
                        $ConnectionObject.IP = $coneectionIOC

                        $ConnectionIOCsArray += , $ConnectionObject 
                        $counter += 1
                   }
               }
            }
        Write-Output "***************************************" 
        Write-Output "" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Connection IOCs are found in $server"
            $ConnectionIOCsArray
        }
        else 
        {
            Write-Output "NO Connection IOCs were found in $server" 
        }
    }

    function PortsIOCsScan ($PortsIOCsList)
    {
        $PortIOCsArray = @()
        $PortIOCsProperties = @{
        "Description" = 'NA';
        "ExecutablePath" = 'NA';
        "Id" = 'NA';
        "ProcessName"= 'NA';
        "Name" = 'NA';
        "Port" = 'NA';
    }
            ######################## Checking Port IOCs ########################
            Write-Output ""
            Write-Output "Searching Port IOCs in $server ..." 

            $counter = 0
            foreach ($portIOC in $PortsIOCsList)
            {
              if($portIOC -notlike "")
              {
                  $PortReg = "[0-9]:"+$portIOC
                  if($ConnectionInfo = netstat -aon | findstr $PortReg)
                  {
                      $PortObject = New-Object -TypeName PSObject -Property $PortIOCsProperties
                      $Connectionresult = if($ConnectionInfo -is [system.array]) {$ConnectionInfo[0]} else {$ConnectionInfo}

                      $Connectionresult = $Connectionresult -replace '^\s+','' -split '\s+' -split '\d:\d'
                         $Protocole = $Connectionresult[0]
                         $LocalAddress = $Connectionresult[1]
                         $LocalPort = $Connectionresult[2]
                         $ForeignAddress = $Connectionresult[3]
                         $ForeignPort = $Connectionresult[4]
                         $State = $Connectionresult[5]
                         $Process = $Connectionresult[6]
                  
                        $PortObject.Description = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "Description" -ExpandProperty Description
                        $PortObject.ExecutablePath = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "ExecutablePath" -ExpandProperty ExecutablePath
                        $PortObject.Id = $process 
                        $PortObject.ProcessName = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "ProcessName" -ExpandProperty ProcessName
                        $PortObject.Name = Get-WmiObject Win32_Process | where-object {$_.processid -eq $process} | Select-Object "Name" -ExpandProperty Name
                        $PortObject.Port = $portIOC

                        $PortIOCsArray += , $PortObject 
                        $counter += 1
                   }
               }
            }
            Write-Output "***************************************"

            if ($counter -gt 0)
            {
                Write-Output "-->>-- Port IOCs are found in $server"
                $PortIOCsArray 
            }
            else 
            {
                Write-Output "NO Port IOCs were found in $server" 
            }
        }

    function UsersIOCsScan ($UsersIOCsList)
    {
        $UserIOCsArray = @()
        $UserIOCsProperties = @{
        "AccountType" = 'NA';
        "Caption" = 'NA';
        "Domain"= 'NA';
        "SID" = 'NA';
        "Name" = 'NA';
    }
        ######################## Checking user IOCs ########################
        Write-Output ""
        Write-Output "Searching user IOCs in $server ..." 

        $counter = 0
        foreach ($userIOC in $UsersIOCsList)
            {
                 $UserObject = New-Object -TypeName PSObject -Property $UserIOCsProperties

                if($userIOC -notlike "")
                {
                    if(Get-WmiObject win32_useraccount | ? {$_.caption -like "$server*" -and $_.name -like $userIOC})
                    {
                    $UserObject.AccountType = Get-WmiObject win32_useraccount | ? {$_.caption -like "$server*" -and $_.name -like $userIOC} | Select-Object "AccountType" -ExpandProperty AccountType
                    $UserObject.Caption = Get-WmiObject win32_useraccount | ? {$_.caption -like "$server*" -and $_.name -like $userIOC} | Select-Object "Caption" -ExpandProperty Caption
                    $UserObject.Domain = Get-WmiObject win32_useraccount | ? {$_.caption -like "$server*" -and $_.name -like $userIOC} | Select-Object "Domain" -ExpandProperty Domain
                    $UserObject.SID = Get-WmiObject win32_useraccount | ? {$_.caption -like "$server*" -and $_.name -like $userIOC} | Select-Object "SID" -ExpandProperty SID
                    $UserObject.Name = $userIOC

                    $UserIOCsArray += , $UserObject                     
                    $counter += 1
                    }
                }
            }
        Write-Output "***************************************"

        if ($counter -gt 0)
        {
            Write-Output "-->>-- User IOCs are found in $server"
            $UserIOCsArray
        }
        else 
        {
            Write-Output "NO User IOCs were found in $server" 
        }
      }

    function GroupsIOCsScan ($GroupsIOCsList)
    {
        $GroupIOCsArray = @()
        $GroupIOCsProperties = @{
        "Caption" = 'NA';
        "Domain"= 'NA';
        "SID" = 'NA';
    }
        ######################## Checking user IOCs ########################
        Write-Output ""
        Write-Output "Searching group IOCs in $server ..." 

        $counter = 0
        foreach ($groupIOC in $GroupsIOCsList)
            {
                $GroupObject = New-Object -TypeName PSObject -Property $GroupIOCsProperties
                if($groupIOC -notlike "")
                {
                    if(Get-WmiObject win32_group | ? {$_.caption -like "$server*" -and $_.name -like $groupIOC})
                    {
                    $GroupObject.Caption = Get-WmiObject win32_group | ? {$_.caption -like "$server*" -and $_.name -like $groupIOC} | Select-Object "Caption" -ExpandProperty Caption
                    $GroupObject.Domain = Get-WmiObject win32_group | ? {$_.caption -like "$server*" -and $_.name -like $groupIOC} | Select-Object "Domain" -ExpandProperty Domain
                    $GroupObject.SID = Get-WmiObject win32_group | ? {$_.caption -like "$server*" -and $_.name -like $groupIOC} | Select-Object "SID" -ExpandProperty SID

                    $GroupIOCsArray += , $GroupObject 
                    $counter += 1
                    }
                }
            }

        Write-Output "***************************************" 

        if ($counter -gt 0)
        {
            Write-Output "-->>-- Group IOCs are found in $server"
            $GroupIOCsArray
        }
        else 
        {
            Write-Output "NO group IOCs were found in $server" 
        }
      }

    FileIOCsScan $FileIOCs
    FolderIOCsScan $FolderIOCs
    RegistryIOCsScan $RegIOCs
    ServiceIOCsScan $ServiceIOCs
    ProcessIOCsScan $ProcessIOCs 
    ConnectionIOCsScan $ConnectionIOCs
    PortsIOCsScan $PortIOCs
    UsersIOCsScan $UserIOCs
    GroupsIOCsScan $GroupIOCs
