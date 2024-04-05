#####Search AD for users created in the last week (populate the ou&dc)
########variables

$date = (get-Date).tostring() $week = (Get-Date).AddDays(-7) write-Host "Getting users created within a week." $ADuserInWeek = Get-ADUser -Filter 'name -notlike "test"' -Properties * -Searchbase “ou=,dc=“ | where { $_.whenCreated -ge $week } | select Name,whenCreated,UserPrincipalName,office,employeeid
