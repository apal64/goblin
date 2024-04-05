###ad group membership (nested)
function my-get-adgroup-membership ($adgrouptoget){
	get-adgroupmember -recursive $adgrouptoget | get-aduser -property title,department | select -property name,surname,givenname,department,title | format-table
}

###get users group:
function my-get-user-groupmembership ($usertoget){
	Get-ADprincipalGroupMembership $usertoget | select -property name,distinguishedname | format-table
}
