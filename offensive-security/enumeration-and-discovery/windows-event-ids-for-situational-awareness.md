# Windows Event IDs and Others for Situational Awareness

Below is a living list of Windows event IDs and other miscellaenous snippets, that may be useful for  situational awareness, once you are on a box:

<table>
  <thead>
    <tr>
      <th style="text-align:left">Activity</th>
      <th style="text-align:left">Powershell to read event logs for the</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><b>Lock/screensaver</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Workstation was locked</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4800&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Workstation was unlocked</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4801&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Screensaved invoked</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4802&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Screensaver dismissed</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4803&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>System ON/OFF</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Windows is starting up</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4608&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">System uptime</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;system&apos;; Id=&apos;6013&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Windows is shutting down</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4609&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">System has been shut down</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;system&apos;; Id=&apos;1074&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>System sleep/awake</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">System entering sleep mode</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;system&apos;; Id=42 }</td>
    </tr>
    <tr>
      <td style="text-align:left">System returning from sleep</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;system&apos;; Id=&apos;1&apos;;
        ProviderName = &quot;Microsoft-Windows-Power-Troubleshooter&quot; }</td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>Logons</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Successful logons</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;Security&apos;; Id=&apos;4624&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Logons with explicit credentials</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;Security&apos;; Id=&apos;4648&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Account logoffs</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4634&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>Access</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Outbound RDP</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-TerminalServices-RDPClient/Operational&apos;;
        id=&apos;1024&apos; } | select timecreated, message | ft -AutoSize -Wrap</td>
    </tr>
    <tr>
      <td style="text-align:left">Inbound RDP</td>
      <td style="text-align:left">
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-TerminalServices-LocalSessionManager/Operational&apos;;
          id=&apos;21&apos; } | select timecreated, message | ft -AutoSize -Wrap</p>
        <p></p>
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational&apos;;
          id=131 } | select timecreated, message | ft -AutoSize -Wrap
          <br />
        </p>
        <p>
          <br />
        </p>
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational&apos;;
          id=&apos;1149&apos; } | ft -AutoSize -Wrap</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Outbound WinRM</td>
      <td style="text-align:left">
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-WinRM/Operational&apos;;
          id=6 }</p>
        <p></p>
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-WinRM/Operational&apos;;
          id=80 }</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Inbound WinRM</td>
      <td style="text-align:left">
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-WinRM/Operational&apos;;
          id=91 }</p>
        <p></p>
        <p>Get-WinEvent -FilterHashtable @{ LogName=&apos;Microsoft-Windows-WMI-Activity/Operational&apos;;
          id=5857 } | ? {$_.message -match &apos;Win32_WIN32_TERMINALSERVICE_Prov|CIMWin32&apos;}</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>Activity</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Attempt to install a service</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;Security&apos;; Id=&apos;4697&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Scheduled task created</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4698&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Scheduled task updated</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;security&apos;; Id=&apos;4702&apos;
        }</td>
    </tr>
    <tr>
      <td style="text-align:left">Sysinternals usage?</td>
      <td style="text-align:left">Get-ItemProperty &apos;HKCU:\SOFTWARE\Sysinternals\*&apos; | select PSChildName,
        EulaAccepted</td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><b>Security</b>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">LSASS started as a protected process</td>
      <td style="text-align:left">Get-WinEvent -FilterHashtable @{ LogName=&apos;system&apos;; Id=&apos;12&apos;
        ; ProviderName=&apos;Microsoft-Windows-Wininit&apos; }</td>
    </tr>
  </tbody>
</table>

