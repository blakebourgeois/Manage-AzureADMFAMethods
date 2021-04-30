<#
.DESCRIPTION
    Manage-AzureADMFA provides administrators an easy way to view and clear MFA enrollment for a user.
    The script combines the results from StrongAuthenticationMethods, StrongAuthenticationUserDetails, 
    and StrongAuthenticationPhoneAppDetails to give a holistic view of a user's MFA stance.

.DEPENDENCIES
    You must be in the Global Administrator or Authentication Administrator Role to view/edit these properties
    You must install the MSOnline Module
    You must install the AzureADPreview Module
        You may need to uninstall the AzureAD module.

.NOTES
    Version       : 2.0.6
    Author        : Blake Bourgeois
    Creation Date : 8/17/2019
    Last Edited   : 4/30/2021

#>

# modified from https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
# used to pull username from the MSOLService token so it can be passed to AzureADPreview connection w/o need to type it in...

function Parse-JWTtoken {
 
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    
    return $tokobj
}

# Variable used to stay in the program or exit
$EnterScript = 0

# Function checks for connection to Azure, and initates one if necessary
function Check-MSOLStatus{
    if(Get-MsolDomain -ErrorAction SilentlyContinue)
        {write-host "   You're already connected to Microsoft Online." -ForegroundColor Green}
    else{
        write-host "   Connecting to Microsoft Online..." -ForegroundColor Yellow
        
        Connect-MsolService
        if(Get-MsolDomain -ErrorAction SilentlyContinue){
            write-host "   Successfully connected to Microsoft Online!" -ForegroundColor Green
        }
    }
}

function Check-AzureADStatus{
    try{Get-AzureADDomain | out-null
    write-host "   You're already connected to Azure AD." -ForegroundColor Green}

    catch{
        write-host "   Connecting to Azure AD..." -ForegroundColor Yellow
        write-host "   This may result in a second authentication prompt." -ForegroundColor Yellow
        $currentToken = [Microsoft.Online.Administration.Automation.CommonFiles.AuthManager]::GetTokenForUser()
        $myUPN = (Parse-JWTtoken $currentToken).unique_Name
        write-host "   Connecting to Azure AD with $myUPN..." -ForegroundColor Yellow

        try{Connect-AzureAD -AccountId $myUPN | out-null
            write-host "   Successfully connected to Azure AD!" -ForegroundColor Green}

        catch{write-host "That still didn't work. Run the script again and provide the correct UPN. Exiting..."
              break}
        }
}

# This function pulls all the user info and displays it
function Get-MFAMethods($upn){
    $user = get-msoluser -UserPrincipalName $upn | select *
    $SAM = $user.StrongAuthenticationMethods
    $SAUD = $user.StrongAuthenticationUserDetails
    $officephone = $false
    $application = $false

    # if strong auhtentication methods are enrolled, continue
    if($SAM){
        Write-Host "   Methods:"
        foreach($M in $SAM){
            # enumerate then display all the enrolled methods
            if($M.IsDefault -eq "True")
                {$Default = $M.MethodType
                Write-Host "     $Default is the Default Method for $upn" -ForegroundColor Green}
            else{
                $Method = $M.MethodType
                Write-Host "     $Method is enabled for $upn" -ForegroundColor Yellow
                }

            # set these toggles to true so we only output relevant information
            if($M.MethodType -eq "TwoWayVoiceOffice"){
                $officephone = $true
                }
            if(($M.MethodType -eq "PhoneAppOTP") -or ($M.MethodType -eq "PhoneAppNotification")){
                $application = $true
                }
            }

        # enumerate then display the relevant user details
        Write-Host ""
        Write-Host "   User Details:"
        $personalphone = ""
        $alternatephone = ""
        if($SAUD.PhoneNumber){
            $personalphone = $SAUD.PhoneNumber
            Write-Host "     The authentication number on file is $personalphone" -ForegroundColor Green
            }
        if($SAUD.AlternativePhoneNumber){
            $alternatephone = $SAUD.AlternativePhoneNumber
            Write-Host "     The alternate phone number on file is $alternatephone" -ForegroundColor Yellow
            }
        if($officephone){
            $office = $user.PhoneNumber
            Write-Host "     The office number on file is $office" -ForegroundColor Yellow
            }

        # enumerate then display all the enrolled apps/code generators
        # generic OTP code generators won't display a name, but you can see the number of different apps/codes the user has enrolled
        if($application){
            Write-Host ""
            Write-host "   The following Phone Apps are configured:"
            $apps = $user.StrongAuthenticationPhoneAppDetails
            foreach($app in $apps){
                $device = $app.DeviceName
                $authtype = $app.AuthenticationType
                write-host "     $device is configured for $authtype" -ForegroundColor Yellow
                }
            }

        }
    
    # if there are no enrolled methods, display a message
    else{
        Write-Host "   $upn has no MFA enrollment." -ForegroundColor Yellow
        }
}


# null out the StrongAuthenticationMethods property for a user
# there is unfortunately no way to actually edit the StrongAuthenticationUserDetails
# when this is run, a user may be required to re-enroll their MFA methods
# in effect, this "unchecks" all of the enabled methods on Additional Security Verification (aka.ms/MFASetup)
# apps and phone numbers still exist on the backend...the user just has to re-enable them
# if you have to remove a phone number/alternative phone number, it has to be through GUI

function Clear-MFAMethods($upn){
    $areyousure = ""
    $ClearedOut = @()
    $displayname = (Get-MsolUser -UserPrincipalName $upn).DisplayName
    $areyousure = read-host " Are you sure you want to clear MFA methods for $displayname ($upn)? (type Y to confirm)"
    write-host ""

    if($areyousure -eq "y"){
        Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationMethods $ClearedOut
        Write-Host "   All methods for $upn have been cleared." -ForegroundColor Green
        Write-Host ""

        get-mfamethods -upn $upn
        
        }
    else{
        Write-Host "   MFA reset has not been confirmed for $upn. Going back to main menu..." -ForegroundColor Yellow
        Write-Host ""
    }

}

function Get-RecentMFAFailures($upn){
    $failures500121 = get-azureadauditsigninlogs -filter "userprincipalname eq '$upn' and status/errorCode eq 500121" | select userprincipalname,createddatetime,appdisplayname,mfadetail,ipaddress,clientappused,status,devicedetail,location 
    $failures50074 = get-azureadauditsigninlogs -filter "userprincipalname eq '$upn' and status/errorCode eq 50074" | select userprincipalname,createddatetime,appdisplayname,mfadetail,ipaddress,clientappused,status,devicedetail,location 
    $out = [System.Collections.ArrayList]@()

    foreach($entry in $failures500121){
    $out.Add($entry) | out-null
    }

    foreach($entry in $failures50074){
    $out.Add($entry) | Out-null
    }
    
    $out | sort-object createddatetime -Descending | Out-GridView -Title "MFA Failures for $upn"
}

function Get-RecentMFASuccesses($upn){
    $successes50140 = get-azureadauditsigninlogs -filter "userprincipalname eq '$upn' and status/errorCode eq 50140" |select userprincipalname,createddatetime,appdisplayname,mfadetail,ipaddress,clientappused,status,devicedetail,location
    $successes0 = get-azureadauditsigninlogs -filter "userprincipalname eq '$upn' and status/errorCode eq 0" | select userprincipalname,createddatetime,appdisplayname,mfadetail,ipaddress,clientappused,status,devicedetail,location
    $out = [System.Collections.ArrayList]@()

    foreach($entry in $successes50140){
        if($entry | select-string -Pattern "MFA completed in Azure AD"){
        $out.add($entry) | out-null}  
        if($entry | select-string -Pattern "MFA requirement satisfied by strong authentication"){
        $out.add($entry) | out-null}
        if($entry | select-string -Pattern "MFA requirement satisfied by multi-factor device"){
        $out.add($entry) | out-null
 
        } 
    }

    foreach($entry in $successes0){
        if($entry | select-string -Pattern "MFA completed in Azure AD"){
        $out.add($entry) | out-null}   
        if($entry | select-string -Pattern "MFA requirement satisfied by strong authentication"){
        $out.add($entry) | out-null}
        if($entry | select-string -Pattern "MFA requirement satisfied by multi-factor device"){
        $out.add($entry) | out-null
        }
    }

    $out | Sort-Object CreatedDateTime -Descending | Out-GridView -Title "MFA Successes for $upn"
}

function Reset-RefreshTokens($upn){
    $areyousure = ""
    $displayname = (Get-MsolUser -UserPrincipalName $upn).DisplayName
    $areyousure = read-host " Are you sure you want to invalidate all refresh tokens for $displayname ($upn)? (type Y to confirm)"
    write-host ""
    if($areyousure -eq "y"){
        Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureAdUser -searchstring $upn).ObjectID
        write-host "   Refresh tokens have been cleared. Sessions that request an access token with existing tokens will require reauthentication." -ForegroundColor Green
        write-host "   Please note that the account may still be accessed for up to an hour through current access tokens." -ForegroundColor Green
        write-host ""}
    else{
        Write-Host "   Token invalidation has not been confirmed for $upn. Going back to main menu..." -ForegroundColor Yellow
        Write-Host ""
    }
}

function Set-ScriptUser(){
    $upn = read-host " Enter the UserPrincipalName"
    return $upn
    }

# Banner/init connection
# Banner/init connection
Write-Host "
    =========================================
            Azure MFA User Management
    =========================================

    "
    
    Check-MSOLStatus
    Check-AzureADStatus

# QOL: allows us to easily get a UPN later
# you may have multiple verified domain names here--this selects the top
# you may need to adjust as needed, or replace Get-MsolDomain by specifying your preferred domain directly
# best practice remains to use your full UPN, especially if your tenant has multiple domains, like your primary and your onmicrosoft.com domain
$domain = (Get-MsolDomain).name[0]

# easy repeat/clear out user inputs
function Display-Menu{
    Write-Host "

    Select a numbered option below, or 'q' to quit.

    0) Set User

    1) Get Registered MFA Methods and Details for User

    2) Clear MFA Registration for User

    3) Get recent MFA failures for User

    4) Get recent MFA successes for User

    5) Revoke Refresh Tokens (Require re-authentication)

    "
    
    $choice = 0
    $upn = ""}


$currentUser = ""


# when user wishes to exit script we'll increment $EnterScript later
while($EnterScript -eq "0")
    {

    Display-Menu

    if($currentUser){
    write-host "   The currently loaded user is: $currentUser" -ForegroundColor Green
    write-host ""}
    else{
    write-host "   No user loaded." -ForegroundColor Red
    write-host "   Please set a user via option 0." -ForegroundColor Red
    write-host ""
    }

    $choice = read-host " Selection"
    write-host ""

    # select the case based on input, quit, or fail
    if($choice -eq "0"){
        $currentUser = Set-ScriptUser
        }

    elseif($choice -eq "1"){
        #$upn = read-host " Enter the UserPrincipalName"
        $upn = $currentUser
        write-host ""

        if(get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue){
            Get-MFAMethods -upn $upn
            }
        # I got tired of typing the full UPN so you can just supply the bit before the @ as long as you're in the right domain
        elseif(get-msoluser -UserPrincipalName "$upn@$domain" -ErrorAction SilentlyContinue){
            Get-MFAMethods -upn "$upn@$domain"
            }
        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
        }

    elseif($choice -eq "2"){
        #$upn = read-host " Enter the UserPrincipalName"
        $upn = $currentUser

        write-host ""
        if(get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue){
            Clear-MFAMethods -upn $upn
            }
        elseif(get-msoluser -UserPrincipalName "$upn@$domain" -ErrorAction SilentlyContinue){
            Clear-MFAMethods -upn "$upn@$domain"
            }
        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "3"){
        #$upn = read-host " Enter the UserPrincipalName"
        $upn = $currentUser

        write-host ""
        if(get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue){
            Get-RecentMFAFailures -upn $upn
            }
        elseif(get-msoluser -UserPrincipalName "$upn@$domain" -ErrorAction SilentlyContinue){
            Get-RecentMFAFailures -upn "$upn@$domain"
            }
        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "4"){
        #$upn = read-host " Enter the UserPrincipalName"
        $upn = $currentUser

        write-host ""
        if(get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue){
            Get-RecentMFASuccesses -upn $upn
            }
        elseif(get-msoluser -UserPrincipalName "$upn@$domain" -ErrorAction SilentlyContinue){
            Get-RecentMFASuccesses -upn "$upn@$domain"
            }
        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "5"){
        $upn = $currentUser

        write-host ""
        if(get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue){
            Reset-RefreshTokens -upn $upn
            }
        elseif(get-msoluser -UserPrincipalName "$upn@$domain" -ErrorAction SilentlyContinue){
            Reset-RefreshTokens -upn "$upn@$domain"
            }
        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif(($choice -eq "q") -or ($choice -eq "Q")){
        # when user is done increment EnterScript to kill the while loop and exit script
        $EnterScript++
        }
    else{
        #Shame on you
        write-host " Not a valid selection." -ForegroundColor Red
    }
}