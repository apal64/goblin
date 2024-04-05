##Show all users not protected from accidental deletion (populate ou&dc)

Get-ADUser -Filter * -Properties * -SearchBase "OU=,DC=" | Where-Object {$_.ProtectedFromAccidentalDeletion -eq $false} | Select-Object canonical name
