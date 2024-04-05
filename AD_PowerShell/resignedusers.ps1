Import-Module ActiveDirectory
$SearchOU="<users OU>"
$users = Search-ADAccount -AccountExpired -SearchBase $SearchOU -SearchScope Subtree
$OU = "<Resigned users OU>"
$Stripusers = Get-ADUser -Filter "*" -SearchBase $OU -searchscope onelevel

foreach ($user in $users)
{
    move-ADobject -Identity $user -TargetPath "<resigned users OU>"
}

foreach ($Stripuser in $Stripusers)
{
    $groups = Get-ADPrincipalGroupMembership $Stripuser.SamAccountName | select name    
    foreach ($group in $groups)
    {
        if ($group.name -ne "Domain Users")
        {
            Remove-ADGroupMember -identity $group.name -Members $Stripuser -Confirm:$false
        }
    }
}
try {
	Move-ADObject -Identity $user -TargetPath 'path' -ErrorAction STOP
}
catch {
	Write-Warning -Message ('Unable to move {0}: {1}' -f $user,$_.exception.message)
	continue
}
