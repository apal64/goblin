$EnvironmentName = 'EnvironmentID'
$groupName='display name of the group'

#Get environment
$Environment = Get-AdminPowerAppEnvironment -EnvironmentName $EnvironmentName
if($Environment)
{
  #AzureAD part. Connect to azure and retrieve enabled users
  Connect-AzureAD

  #Using SecurityGroups
  $Group = Get-AzureADGroup | Where { $_.DisplayName -eq $groupName }
  $users = Get-AzureADGroupMember -ObjectId $group.ObjectId

  #Querying directly the AzureAD
  $users = Get-AzureADUser -all $true | where {$_.accountenabled -eq $true}
  $users
  
  #iterating through the array of users
  foreach ($user in $users)
  {
    #Force sync on each user
    Add-AdminPowerAppsSyncUser -EnvironmentName $Environment.EnvironmentName -PrincipalObjectId $user.ObjectId
  }
}
