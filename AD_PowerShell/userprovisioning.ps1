# Load the Active Directory Module
import-module ActiveDirectory
#Import the SQL modules
Add-PSSnapin SqlServerCmdletSnapin100
Add-PSSnapin SqlServerProviderSnapin100
#Create a sessions on the exchange server and import the commands from there
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://server.domain/PowerShell/ -Authentication Kerberos
Import-PSSession $Session
 
 
# This Function merely runs the various functions used to create and configure the user
Function Provision {
    PROCESS {
        CreateUser $_
		CreateMailbox $_
        AddToGroup $_
		CreateSQLUser $_
		CalendarPermissions $_
    }
}
 
# This Function creates a hashtable from the CSV containing user information
Function ProvisionInput {
    Param ([string]$filename)
    $users = Import-CSV $filename
    foreach ($user in $users) {
	$FINALSAM =  $user."First Name".substring(0,1) + $user."Last Name".Trim()
	#Prompts the user to enter a password for the user, this is done in the script because this way the password is never stored in cleartext
	$Password = Read-Host -AsSecureString "AccountPassword"
    #Confirm the username is not too long, if it is prompt for a new one
	While ($FINALSAM.length -gt 20) {$FINALSAM = Read-Host "$FINALSAM is too long, Plese enter a username less than 21 characters"}
	#Confirm that the Username is not in Use, if it is prompt for a new one
	If ($FINALSAM -eq "" -or (Get-ADUser $Finalsam) -ne $null) {
	DO {$FINALSAM = Read-Host "$FINALSAM username in use, Plese enter an available username"} 
	While ($FINALSAM -eq "" -or (Get-ADUser $Finalsam) -ne $null)}
        #Populate a hashtable from the CSV, you can add additional columns just match the name on the right to te column header in excel.
        $ht = @{'givenName'=$user."First Name".Trim();
                'sn'= $user."Last Name".Trim();
                'Department' = $user."Department"
                'Office'= $user."Office";
        	    'displayName'= $user."First Name".Trim() + " " + $user."Last Name".Trim();
        	    'samAccountName'= $FINALSAM.tolower()
                'Title' = $user."Title";
                'Manager' = $user."Manager";
				'AccountPassword' = $Password;
				'SSLVPN' = $user."SSLVPN User".tolower();
				'Email' = $user."Email User".tolower()
        }
        #Output the Hastable for use in provisioning
        Write-Output $ht
    }
}
 
#This function creates the SQL Application Account, users running the script require sufficient SQL permissions
Function CreateSQLUser {
	Param($userinfo)
	$FirstName = $userinfo['givenName']
	$LastName = $userinfo['sn']
	$Username = $userinfo['samAccountName']
	#Set the time zone
	If ($userinfo['Office'] -eq 'ExampleOffice') {
		$TimeZone = 54
	}
	#this secdtion runs stored procedures on the SQL Server directly.
	$query = "EXEC AutomatedNewUser @FirstName = '$($FirstName)', @LastName = '$($LastName)', @Timezone = '$($TimeZone)', @UserName = '$($UserName)';"
	Invoke-SqlCMD -ServerInstance 'server' -Database 'database' -Query $query
 
#This function is present to set the permissions for users so they can book appointmenmts for an exxample group
Function CalendarPermissions { 
	Param($userinfo)
	If ($userinfo['Title'] -like '*Example User*') {
		$Group = 'Example Group'
		$user = $userinfo['samAccountName']
		$GroupMembers = Get-ADGroupMember -Identity $Group
		ForEach ($Member in $GroupMembers) {add-MailboxFolderPermission ($User + ':\Calendar') -User $Member.SamAccountName -AccessRights Editor}
		}
	}
 
#Populate the OU details based on the hash table and then create the user, no mailbox is created at this point
Function CreateUser {
    Param($userinfo)
    	If ($userinfo['Office'] -eq 'Office' -and $userinfo['Department'] -eq 'IT') {
			$ou = 'OU=IT,OU=Office,OU=Staff Users,DC=Example,DC=Domain'
		}
		ElseIf ($userinfo['Office'] -eq 'Office' -and $userinfo['Department'] -eq 'Finance') {
			$ou = 'OU=Finance,,OU=Office,OU=Staff Users,DC=Example,DC=Domain'
		}
		Else {
			Write-Host "Invalid Office/Department Combination entered, User will be placed at OU=Staff Users,DC=Example,DC=Domain"
			$ou = 'OU=Staff Users,DC=Example,DC=Domain'
		}
		New-ADUser -UserPrincipalName ($userinfo['samAccountName'] + '@Example.Domain') -SamAccountName $userinfo['samAccountName'] -Description $userinfo['Title'] –name $userinfo['displayName'] -DisplayName $userinfo['displayName'] –Path $ou –accountpassword $userinfo['AccountPassword'] -Manager $userinfo['Manager'] –GivenName $userinfo['givenName'] –Surname $userinfo['sn'] –ChangePasswordatlogon $true -Office $userinfo['Office'] -EmailAddress ($userinfo['samAccountName'] + '@email.domain') -HomePage 'www.example.com' -Title $Userinfo['Title'] -Enabled $true -Fax '1300 000 000'
}
 
#attach the mailbox to the new user if one is required
Function CreateMailbox {
    Param ($Userinfo)
	If ($userInfo['Email'] -eq 'yes') {
		If ($UserInfo['Department'] -eq 'IT' -or $userinfo['Department'] -eq 'Administration' -or $userinfo['Department'] -eq 'Finance' -or $userinfo['Department'] -eq 'Management'){$Database = 'ADMIN'}
		ElseIf ($userinfo['Department'] -eq 'Sales') {$Database = 'SG_SALES'}
		ElseIf ($userinfo['Department'] -eq 'Operations') { $Database = 'SG_OPS'}
		Enable-Mailbox -Identity $userinfo['samAccountName'] -Database $Database -DomainController 'PrimarryDC.fqdn'
    }
}
 
#Add the user to groups as appropriate
Function AddToGroup {
	Param ($userinfo)
		Add-ADGroupMember -Identity 'Intranet Users' -members $userinfo['samAccountName']
		If ($userinfo['SSLVPN'] -eq 'Yes') {Add-ADGroupMember -Identity 'SSLVPN' -members $userinfo['samAccountName']}
		If ($userinfo['Department'] -eq 'IT') {
			Add-ADGroupMember -Identity 'IT Sec Group' -members $userinfo['samAccountName']
			}
		ElseIf ($userinfo['Department'] -eq 'Finance') {
			Add-ADGroupMember -Identity 'Finance Sec Group' -members $userinfo['samAccountName']
			}
	}
 
 
# Prompt the user for the UNC path to the CSV containing user details
$CSV = Read-Host "Enter CSV File Path"
# Place the CSV Hash Table in a variable so it can be reused
$hash = ProvisionInput $CSV
#Pipe the Hash Table into the Provision function for account creation/configuration
$hash | Provision
