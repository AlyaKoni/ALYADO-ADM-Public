# Run following script from portal on the vm
$wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled ='true'";
$wmi.EnableDHCP();
$wmi.SetDNSServerSearchOrder();
# It's possible that no output from script will be shown
# Restart the vm
