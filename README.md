# Manage-AzureADMFAMethods
A script to check and clear MFA methods in Azure AD.
The script can also get recent MFA sign ins/failures for a user to assist troubleshooting.
Eventually, this may need to be reworked with the Graph cmdlets.

## Usage
Download and run from a Powershell session (.\Manage-AzureADMFAMethods)
You'll need to make sure you have Global Admin/Authentication Admin role in AAD.
You'll also need the MSOnline and AzureADPreview module installed.
The script uses modern authentication and is compatible with MFA.

Use the menu to navigate the script.

### Functions
0: Set User. A user must be set first to use the script's functions.
1. Get registered MFA Methods and Details for User
2. Clear MFA Registration for User
3. Get recent MFA failures for User
4. Get recent MFA successes for User
5. Revoke Refresh Tokens (Require re-authentication)
