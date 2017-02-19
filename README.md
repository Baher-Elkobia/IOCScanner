# IOCScanner
 <pre>
    IOCScanner
    PowerShell Incident Response Framework 
    Eslam Elkobia | eng.baher@hotmail.com
    v0.1 - Janurary 2017</pre>
 
 <h2> [About IOCScanner] </h2>
 IOCScanner searches for a pre-defined list of IOCs in remote Windows hosts using PowerShell, identifies compromised machines, generates HTML report including IOC details for each remote host and it can quarantine compromised hosts if required

 <h2> [How to use] </h2>
1. Prepare a text file includes a list of hosts to be scanned
2. Popoulate the IOCs.csv file with the IOCs each in its column
3. enable PSRemoting on all remote hosts using the following command options
   A- PS C:\> PsExec.exe \\192.168.0.10 -u [admin account] -p [password] -h -d powershell.exe "Enable-PSRemoting -Force"
      Download PsExec from https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx
      repeat the command for each remote host or use a script for automate it
   B- Using PowerShell script as a start-up script,however, you need to wait untill all hosts get the next update
4. Run IOCScanner
PS .\IOCScanner.ps1 -targets servers.txt -IOCList iocs.csv -UserName DomainName\UserName -Password password123 -Block

 <h2> [Parameters] </h2>
 -target   :  a txt file including remote hosts each in a separate line to scan for IOCs
 -IOCList  :  CSV list of IOCs with a psecific formate, use the template provided
 -UserName :  Domain account with local admin privilege on all remote hosts
 -Password :  Domain account password
 -Block    :  Quarantine the compromised host 
