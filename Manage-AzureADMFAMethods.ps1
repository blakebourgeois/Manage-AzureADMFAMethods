<#
.DESCRIPTION
    Manage-AzureADMFA provides administrators an easy way to view and clear MFA enrollment for a user.
    The script combines the results from StrongAuthenticationMethods, StrongAuthenticationUserDetails, 
    and StrongAuthenticationPhoneAppDetails to give a holistic view of a user's MFA stance.

.DEPENDENCIES
    You must be in the Global Administrator or Authentication Administrator Role to view/edit these properties
    You should also install the MSOnline Module

.NOTES
    Version       : 1.0
    Author        : Blake Bourgeois
    Creation Date : 8/17/2019

#>

# Variable used to stay in the program or exit
$EnterScript = 0

# Function checks for connection to Azure, and initates one if necessary
function Check-MSOLStatus{
        if(Get-MsolDomain -ErrorAction SilentlyContinue)
            {write-host "   You're already connected to Azure AD." -ForegroundColor Green}
        else{
            write-host "   Connecting to Azure AD..." -ForegroundColor Yellow
            Connect-MsolService
            if(Get-MsolDomain -ErrorAction SilentlyContinue){
                write-host "   Successfully connected to Azure AD!" -ForegroundColor Green
            }
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
    $ClearedOut = @()
    Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationMethods $ClearedOut
    Write-Host "   All methods for $upn have been cleared." -ForegroundColor Green
    Write-Host ""

}

# Banner/init connection
Write-Host "
    =========================================
            Azure MFA User Management
    =========================================

    "
    Check-MSOLStatus

# QOL: allows us to easily get a UPN later
$domain = (Get-MsolDomain).name

# easy repeat/clear out user inputs
function Display-Menu{
    Write-Host "

    Select a numbered option below, or 'q' to quit.

    1) Get Registered MFA Methods and Details for User

    2) Clear MFA Registration for User

    "
    
    $choice = 0
    $upn = ""}


# when user wishes to exit script we'll increment $EnterScript later
while($EnterScript -eq "0")
    {

    Display-Menu

    $choice = read-host " Selection"
    write-host ""

    # select the case based on input, quit, or fail
    if($choice -eq "1"){
        $upn = read-host " Enter the UserPrincipalName"
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
        $upn = read-host " Enter the UserPrincipalName"
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
    elseif(($choice -eq "q") -or ($choice -eq "Q")){
        # when user is done increment EnterScript to kill the while loop and exit script
        $EnterScript++
        }
    else{
        #Shame on you
        write-host " Not a valid selection." -ForegroundColor Red
    }
}
