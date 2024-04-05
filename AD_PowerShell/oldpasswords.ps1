# Using @() creates an array, which is fine, but when you add objects to an array it copies the new 
# one in and deletes the old, it's not a true append and it's inefficient.  Test it:
#
# $testArray = @()
# measure-command {0..9999 | foreach { $testArray += $_ }}
#
# $testArrayList = New-Object System.Collections.ArrayList
# measure-command {0..9999 | foreach {[void]$testArrayList.Add($_) }}
$oldPassword = New-Object System.Collections.ArrayList
foreach ( $user in $users )
{
	# New-TimeSpan will default to the end being the current date if not specified
	# so putting in -End in this case isn't necessary
	$TimeSpan = New-TimeSpan $user.PasswordLastSet
	if ( $TimeSpan.Days -gt 300 )
	{
		# I am using [ordered] to ensure that the properties are created
		# in the order I specify (sAMAccountName first, then Password Age)
		[void]$oldPassword.Add([pscustomobject][ordered]@{
			sAMAccountName 	= $user.sAMAccountName
			'Password Age'	= $TimeSpan.Days 
		})
	}
}
