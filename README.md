# IOCScanner
 <pre>
    IOCScanner
    PowerShell Incident Response Framework 
    Eslam Elkobia | eng.baher@hotmail.com
    v0.1 - Janurary 2017</pre>
 
 <h2> [About IOCScanner] </h2>
 IOCScanner searches for a pre-defined list of IOCs in remote Windows hosts using PowerShell, identifies compromised machines, generates HTML report including IOC details for each remote host and it can quarantine compromised hosts if required

 <h2> [How to use] </h2>
<p>1. Prepare a text file includes a list of hosts to be scanned</p>
<p>2. Popoulate the IOCs.csv file with the IOCs each in its column</p>
<p>3. enable PSRemoting on all remote hosts using the following command options</p>
<p>   A- PS C:\> PsExec.exe \\192.168.0.10 -u [admin account] -p [password] -h -d powershell.exe "Enable-PSRemoting -Force"</p>
<p>      Download PsExec from https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx</p>
<p>      Repeat the command for each remote host or use a script for automate it</p>
<p>   B- Using PowerShell script as a start-up script,however, you need to wait untill all hosts get the next update</p>
<p>4. Run IOCScanner</p>
<p>PS .\IOCScanner.ps1 -targets servers.txt -IOCList iocs.csv -UserName DomainName\UserName -Password password123 -Block </p>
<p>PS Get-help .\IOCScanner.ps1 -examples </p>

 <h2> [Parameters] </h2>
 <pre>
 -target   :  a txt file including remote hosts each in a separate line to scan for IOCs
 -IOCList  :  CSV list of IOCs with a psecific formate, use the template provided
 -UserName :  Domain account with local admin privilege on all remote hosts
 -Password :  Domain account password
 -Block    :  Quarantine the compromised host </pre>

<h2> [Report] </h2>
HTML report will be automatically generated inside the report folder including details about IOCs found for each remote host, in addition to a nice statistics dashboard

<img src="https://github.com/Eslam-Elkobia/IOCScanner/blob/master/images/Report%20Dashboard.png">
<p></p>
<img src="https://github.com/Eslam-Elkobia/IOCScanner/blob/master/images/Report%20details.png">
