##Search AD for computers created in the last week (populate ou&dc)
##variables

$week = (Get-Date).AddDays(-7) write-Host "Search AD for computers created in the last week" $ADuserInWeek = Get-ADComputer -Filter {$_.WhenCreated -gt $week} -Properties * -Searchbase “ou=,dc=“ | select Name,OperatingSystem,OperatingSystemVersion,LastLogonDate,CanonicalName
