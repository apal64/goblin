#these lines store resource group info into memory
$Connection = Get-AutomationConnection -Name "<name_of_run_time_account>"
Connect-AzAccount -ServicePrincipal -Tenant $Connection.tenantID -ApplicationID  $Connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

$Context = (Get-AzContext)
$Subscription = $Context.Subscription.Name


##grabs every VM in resource group
$azVM = Get-AzVM -ResourceGroupName "<NAME_OF_RESOURCE_GROUP>" | Select-Object "<NAME_OF_RESOURCE_GROUP>"
foreach ($i in $azVM.name) {Stop-AzVm -ResourceGroupName NameGoesHere -Name $i -Force}

# email notification 
Send-MailMessage -To "<EMAIL>" -From "<SENDER_EMAIL>" -Subject "VMs turned off" -Body "All VMs have been turned off.
