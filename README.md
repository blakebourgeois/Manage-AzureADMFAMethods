# Manage-AzureADMFAMethods
A script to check and clear MFA methods in Azure AD

## Usage
Download and run from a Powershell session (.\Manage-AzureADMFAMethods)
You'll need to make sure you have Global Admin/Authentication Admin role in AAD.
You'll also need the MSOnline module installed.

## Purpose
I got tired of typing Get-MsolUser -userprincipalname [username] | select * to check for MFA enrollment. 

Then I got tired of having to go back and check all the properties to see number of enrollments, types of enrollments, etc.

Finally, I got tired of going back into OneNote to remember the command/syntax to clear out MFA enrollments.

All the details are here. Comments in the script are pretty descriptive.

Enjoy.
