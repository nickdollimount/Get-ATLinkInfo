<#
.SYNOPSIS
Retrieves Active Roles Access Template Link information.
.DESCRIPTION
The Get-ATLinkInfo.ps1 script allows you to report on Active Roles Access Template Link information based on providing a single property of an access template link's properties (Directory Object, Trustee, Access Template). The script will function only when supplying one of the three link properties. The script will error out if more than one of them are defined. The script provides the option to list the permissions found in the Access Template that is reported on. The script also allows for exporting an HTML report.
.PARAMETER Trustee
This parameter is used to define the Trustee of the Access Template Link. A single trustee can be defined, or a comma-separated list of trustees can be defined.
.PARAMETER AccessTemplate
This parameter is used to define the Access Template of the Access Template Link. A single access template can be defined, or a comma-separated list of access templates can be defined.
.PARAMETER DirectoryObject
This parameters is used to define the Directory Object of the Access Template Link. A single directory object can be defined, or a comma-separated list of director objects can be defined.
.PARAMETER ListPermissions
This parameter switch enables retrieving and listing the permissions contained in the access template(s).
.PARAMETER ExportToHTML
This parameters switch enables the export of HTML report(s).
.PARAMETER ExportPath
This optional parameter defines the export location for the HTML report(s). If not specified, the default location is C:\Temp.
.PARAMETER AdministrationService
This optional parameter defines the Active Roles Administration Service you wish to connect to for the reporting.
.PARAMETER UseClientLocaleDisplaySpecifiers
This opetional parameter instructs the script to use the current client's locale for display specifier checking when permissions are listed.
.EXAMPLE
Get-ATLinkInfo.ps1 -Trustee john.doe
Retrieves the access template links for user john.doe.
.EXAMPLE
Get-ATLinkInfo.ps1 -DirectoryObject domain.local/Users/Canada -ListPermissions
Retrieves the access template links on directory object domain.local/Users/Canada and lists the permissions for each access template.
.EXAMPLE
Get-ATLinkInfo.ps1 -AccessTemplate 'Users - Read All Properties' -ListPermissions -ExportToHTML
Retrieves the access template links for the access template 'Users - Read All Properties', lists the permissions for each access template and exports a single HTML report containing each link found and the permissions for the access template.
.EXAMPLE
Get-ATLinkInfo.ps1 -Trustee john.doe -ListPermissions -ExportToHTML -ExportPath C:\Temp\ATLinkInfo
Retrieves the access template links for user john.doe, lists the permissions and exports an HTML report for each link found to the folder C:\Temp\ATLinkInfo.
.NOTES
It is required that you run this script as an Active Roles Administrator since most of the information being retrieved is only accessible by an Active Roles Administrator.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,ParameterSetName='Trustee')]$Trustee,
    [Parameter(Mandatory=$True,ParameterSetName='AccessTemplate')]$AccessTemplate,
    [Parameter(Mandatory=$True,ParameterSetName='DirectoryObject')]$DirectoryObject,
    [switch]$ListPermissions,
    [switch]$ExportToHTML = $False,
    [string]$ExportPath = "C:\Temp\",
    [string]$AdministrationService,
    [switch]$UseClientLocaleForDisplaySpecifiers = $False
)

$ErrorActionPreference = "continue"

$ExportFileName = ""

if ($AdministrationService){
    Connect-QADService -Service $AdministrationService -Proxy | Out-Null
} else {
    Connect-QADService -Proxy | Out-Null
}

function Get-DisplaySpecifierPath{
    # If -UseClientLocaleForDisplaySpecifiers, the local is calculated and the appropriate display specifiers for that language is used instead of the default EN-US.
    if ($UseClientLocaleForDisplaySpecifiers){
        if (Get-QADObject ('CN=' + ('{0:x}' -f (Get-Culture).LCID) + ',CN=Consolidated Display Specifiers,CN=Application Configuration,CN=Configuration')){
            return ('CN=' + ('{0:x}' -f (Get-Culture).LCID) + ',CN=Consolidated Display Specifiers,CN=Application Configuration,CN=Configuration')
        } else {
            return 'CN=409,CN=Consolidated Display Specifiers,CN=Application Configuration,CN=Configuration'
        }
    } else {
        return 'CN=409,CN=Consolidated Display Specifiers,CN=Application Configuration,CN=Configuration'
    }
}

function Get-ClassDisplayName{
    # Retrieve the object class display name as well as checks to see if there is a Display Specifier for the object class and returns that value if so.
    Param(
        $guid
    )

    $ldapDisp = (Get-QADObject $guid -DontUseDefaultIncludedProperties -IncludedProperties ldapDisplayName).ldapDisplayName

    $DisplaySpec = Get-QADObject ($ldapDisp + '-Display') -SearchRoot (Get-DisplaySpecifierPath) -DontUseDefaultIncludedProperties -IncludedProperties classDisplayName,attributeDisplayNames

    if ($DisplaySpec.classDisplayName){
        return $DisplaySpec.classDisplayName
    } else {
        return $ldapDisp
    }
}

function Get-AttDisplayName{
    # Retrieve the attribute display name as well as checks to see if there is a Display Specifier for the attribute and returns that value if so.
    Param(
        $attGuid,
        $objGuid
    )

    $attClassDisp = Get-ClassDisplayName -guid $attGuid

    if ($objGuid -ne ""){
        $objLdapDisp = (Get-QADObject $objGuid -DontUseDefaultIncludedProperties -IncludedProperties ldapDisplayName).ldapDisplayName
        $DisplaySpec = Get-QADObject ($objLdapDisp + '-Display') -SearchRoot (Get-DisplaySpecifierPath) -DontUseDefaultIncludedProperties -IncludedProperties classDisplayName,attributeDisplayNames

        if ($DisplaySpec.attributeDisplayNames){
            $attDisp = ""
            $DisplaySpec.attributeDisplayNames | ForEach-Object{
                if($_.Split(",")[0] -eq $attClassDisp){
                    $attDisp = $_.Split(",")[1]
                }
            }
            if ($attDisp -eq ""){
                $attDisp = $attClassDisp
            }
        }
    } else {
        $attDisp = $attClassDisp
    }
    return $attDisp
}

function Get-ExtendedRights{
    # Retrive extended rights from the administration service.
    # These are not visible in the admin console.
    Param(
        $guid
    )
    $extRight = (Get-QADObject -SearchRoot 'CN=Extended Rights,CN=Application Configuration,CN=Configuration' -DontUseDefaultIncludedProperties -IncludedProperties rightsguid -LdapFilter "(rightsguid=$guid)").DisplayName.toString()

    return $extRight
}

function List-Permissions{
    # Permissions are stored in an SDDL-type format. The following parses these and returns the actual permissions that are set.
    Param(
        $AT
    )

    $permissions = @()
    $reg = [regex] "\[([^\[]*)\]" # REGEX to pull out SDDL entries without the closing brackets.

    ((Get-QARSAccessTemplate $AT -DontUseDefaultIncludedProperties -IncludedProperties edsvaEffectiveATEList).edsvaEffectiveATEList | Select-String $reg -AllMatches).Matches.Value | ForEach-Object {
        $type = ""
        $permission = ""
        $applyTo = ""

        $permArray = ($_ -replace ".$").SubString(1).Split(";") # Split the SDDL into an array.

        switch ($permArray[0]){
            "A" {$type = "Allow"}
            "D" {$type = "Deny"}
        }

        switch ($permArray[2]){
            "CCDCLCSWRPWPDTLOCRCOSDRCWDWO" {
                $permission = "Full Control"
            }
            "RP" {
                if ($permArray[3] -eq ""){
                    $attName = "All Properties"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Read $attName"
            }
            "WP" {
                if ($permArray[3] -eq ""){
                    $attName = "All Properties"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Write $attName"
            }
            "RPWP" {
                if ($permArray[3] -eq ""){
                    $attName = "All Properties"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Read/Write $attName"
            }
            "CC" {
                if ($permArray[3] -eq ""){
                    $attName = "All Child"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Create $attName Objects"
            }
            "DC" {
                if ($permArray[3] -eq ""){
                    $attName = "All Child"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Delete $attName Objects"
            }
            "CCDC" {
                if ($permArray[3] -eq ""){
                    $attName = "All Child"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Create/Delete $attName Objects"
            }
            "MT" {
                if ($permArray[3] -eq ""){
                    $attName = "All Child"
                } else {
                    $attName = Get-AttDisplayName -attGuid $permArray[3] -objGuid $permArray[4]
                }
                $permission = "Move $attName into this container"
            }
            "SD" {
                $permission = "Delete"
            }
            "DT" {
                $permission = "Delete Tree"
            }
            "RC" {
                $permission = "Read Control"
            }
            "WD" {
                $permission = "Write Control"
            }
            "RCWD" {
                $permission = "Read/Write Control"
            }
            "LC" {
                $permission = "List Contents"
            }
            "LO" {
                $permission = "List"
            }
            "CO" {
                $permission = "Copy"
            }
            "MF" {
                $permission = "Move Out"
            }
            "CR" {
                if ($permArray[3] -eq ""){
                    $permission = "All Extended Rights"
                } else {
                    $permission = (Get-ExtendedRights -guid $permArray[3])
                }
            }
            "SW" {
                if ($permArray[3] -eq ""){
                    $permission = "All Validated Writes"
                } else {
                    $permission = (Get-ExtendedRights -guid $permArray[3])
                }
            }
        }

        if ($permArray[4] -eq ""){
            $applyTo = "All Classes"
        } else {
            $applyTo = Get-ClassDisplayName -guid $permArray[4]
        }

        $permissions += [pscustomobject]@{
            Type = $type
            Permissions = $permission
            ApplyTo = $applyTo
        }
    }

    $permissions | Format-Table

    if ($ExportToHTML){
        '<p style="font-weight:bold;">Permissions Included in Access Template:</p>' | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
        ExportTo-HTML -inputObject $permissions
    }
}

function Get-ATLinkbyATguid{
    # Get Access Template Links by Access Template GUID.
    Param(
        $atDN,
        $atName
    )

    Write-Output "Retrieving access template links..."

    $results = @()

    Get-QARSAccessTemplateLink -AccessTemplate $atDN -DontUseDefaultIncludedProperties -IncludedProperties edsvaAccessTemplateDN,edsvaSecObjectDN,edsaTrusteeSID -SizeLimit 0 | ForEach-Object{
        $trustee = Get-QADObject $_.edsaTrusteeSID
        $target = Get-QADObject $_.edsvaSecObjectDN

        $results += [pscustomobject]@{
            Trustee = $trustee.DN
            Target = $target.DN
        }
    }

    if ($results){
        Write-Output "The following links were found for the access template '$atName'"
        Write-Output "==============================="

        ReportInfo-Export -ReportBy "template" -Source $atDN

        $results | ForEach-Object{
            Write-Output ("Trustee: " + $_.Trustee)
            Write-Output ("Target Object: " + $_.Target)
            Write-Output ""
        }

        if ($ExportToHTML){
            ExportTo-HTML -inputObject $results -newEntry
        }
    } else {
        ReportInfo-Export -ReportBy "template" -Source $atDN
        Write-Output "The following links were found for the access template '$atName'"
        Write-Output "==============================="
        Write-Output "NONE"
        Write-Output ""
        if ($ExportToHTML){
            ExportTo-HTML -inputObject "NONE" -newEntry
        }
    }

    if ($ListPermissions){
        Write-Output "Permissions Included in Access Template"
        List-Permissions -AT $atName
        Write-Output "==============================="
    }

    if ($ExportToHTML){
        '<div style="height:100px;">&nbsp;</div>' | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
    }
}

function Get-ATLinkbyTrustee{
    # Get Access Template Links by Trustee.
    Param(
        $trusteeName
    )

    Write-Output "Retrieving access template links..."

    $results = @()

    $trusteeObject = Get-QADObject $trusteeName -DontUseDefaultIncludedProperties -IncludedProperties objectSid,name
    $tName = $trusteeObject.name

    Get-QARSAccessTemplateLink -Trustee $trusteeObject.objectSid -DontUseDefaultIncludedProperties -IncludedProperties edsvaAccessTemplateDN,edsvaSecObjectDN,edsaTrusteeSID -SizeLimit 0 | ForEach-Object{
        $template = Get-QARSAccessTemplate $_.edsvaAccessTemplateDN
        $target = Get-QADObject $_.edsvaSecObjectDN

        $results += [pscustomobject]@{
            Template = $template.DN
            Target = $target.DN
        }
    }


    if ($results){
        Write-Output "The following links were found for the trustee: '$tName'"
        Write-Output "==============================="

        ReportInfo-Export -ReportBy "trustee" -Source $trusteeObject.dn

        $results | ForEach-Object{
            Write-Output ("Access Template: " + $_.Template)
            Write-Output ("Target Object: " + $_.Target)
            Write-Output ""

            if ($ExportToHTML){
                ExportTo-HTML -inputObject $_ -newEntry
            }

            if ($ListPermissions){
                Write-Output "Permissions Included in Access Template"
                List-Permissions -AT $_.Template
                Write-Output "==============================="
            }
        }
    } else {
        ReportInfo-Export -ReportBy "trustee" -Source $trusteeObject.dn
        Write-Output "The following links were found for the trustee '$atName'"
        Write-Output "==============================="
        Write-Output "NONE"
        Write-Output ""
        if ($ExportToHTML){
            ExportTo-HTML -inputObject "NONE" -newEntry
        }
    }
}

function Get-ATLinkbyDirectoryObject{
    # Get Access Template Links by Directory Object.
    Param(
        $DirectoryObject
    )

    Write-Output "Retrieving access template links..."

    $results = @()

    Get-QARSAccessTemplateLink -DirectoryObject $DirectoryObject -DontUseDefaultIncludedProperties -IncludedProperties edsvaAccessTemplateDN,edsvaSecObjectDN,edsaTrusteeSID -SizeLimit 0 | ForEach-Object{
        $template = Get-QARSAccessTemplate $_.edsvaAccessTemplateDN
        $trustee = Get-QADObject $_.edsaTrusteeSID

        $results += [pscustomobject]@{
            Template = $template.DN
            Trustee = $trustee.DN
        }
    }

    if ($results){
        Write-Output "The following links were found for the directory object: '$DirectoryObject'"
        Write-Output "==============================="

        ReportInfo-Export -ReportBy "directoryobject" -Source $DirectoryObject.dn

        $results | ForEach-Object{
            Write-Output ("Access Template: " + $_.Template)
            Write-Output ("Target Object: " + $_.Trustee)
            Write-Output ""

            if ($ExportToHTML){
                ExportTo-HTML -inputObject $_ -newEntry
            }

            if ($ListPermissions){
                Write-Output "Permissions Included in Access Template"
                List-Permissions -AT $_.Template
                Write-Output "==============================="
            }
        }
    } else {
        ReportInfo-Export -ReportBy "directoryobject" -Source $DirectoryObject.dn
        Write-Output "The following links were found for the directory object '$atName'"
        Write-Output "==============================="
        Write-Output "NONE"
        Write-Output ""
        if ($ExportToHTML){
            ExportTo-HTML -inputObject "NONE" -newEntry
        }
    }
}

function SetExport-Filename{
    # Sets unique filename based on the date and time of run.
    $Script:ExportFileName = ("ATLinkInfo_" + (Get-Date -Format "yyyy-MM-dd_hh.mm.ss.fff") + ".html")
}

function Pre-Export{
    # Export the beginning of the HTML including CSS.
    if ($ExportToHTML){
        $preExport = '<html>
        <head>
            <title>ATLinkInfo Export</title>
            <style>
                body{
                    font-family: arial;
                }

                th, td {
                    text-align: left;
                    padding: 15px;
                    border-bottom: 1px solid #ddd;
                    border-right: 1px solid #ddd;
                }

                h1, p {
                    text-align:;
                }

                hr {
                    display: block;
                    margin-top: 0.5em;
                    margin-bottom: 0.5em;
                    margin-left: auto;
                    margin-right: auto;
                    border: 0px;
                    border-bottom: 1px solid #000;
                }

                table {
                    border-spacing: 10px;
                }

                .source {
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
        <h1 style="text-align:center;">Access Template Link Report</h1>
        <p>&nbsp;</p>
        '

        $preExport | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName)
    }
}

function Post-Export{
    # Export the end of the HTML.
    if ($ExportToHTML){
        $postExport = '</body>
        </html>'

        $postExport | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
        Write-Host ("Report exported to: " + (Join-Path -Path $ExportPath -ChildPath $ExportFileName))
        Set-Clipboard -Value (Join-Path -Path $ExportPath -ChildPath $ExportFileName)
        Write-Host ("The full path has been copied to the clipboard.")
    }
}

function ReportInfo-Export{
    # Export the report summary information as HTML.
    Param(
        $ReportBy,
        $Source
    )

    # Report summary changes based on the type of input object used.
    if ($ExportToHTML){
        $ReportInfo = "<p>The following Access Template Link information was found for "

        switch($ReportBy){
            "trustee" {
                $ReportInfo += "Trustee: <span class=source>$Source</span>"
            }

            "directoryobject" {
                $ReportInfo += "Directory Object: <span class=source>$Source</span>"
            }

            "template" {
                $ReportInfo += "Access Template: <span class=source>$Source</span>"
            }
        }

        $ReportInfo += "</p>"

        $ReportInfo | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
    }
}

function ExportTo-HTML{
    # Export the input information as HTML.
    Param(
        $inputObject,
        [switch]$newEntry
    )

    if ($newEntry){
    "<hr />" | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
    }

    if ($inputObject -eq "NONE"){
        $inputObject | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
    } else {
        $inputObject | ConvertTo-Html -Fragment | Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ExportFileName) -Append
    }
}

function Begin-Processing{
    # Check parameters and begin processing.
    if ($ExportPath){
        if (-not (Test-Path -Path $ExportPath)){
            New-Item -Path $ExportPath -ItemType directory | Out-Null
        }
    }


    if ($DirectoryObject){
        SetExport-Filename
        Pre-Export
        foreach ($input in $DirectoryObject){
            $targetObject = Get-QADObject $input -DontUseDefaultIncludedProperties -ShowProgress -SizeLimit 0

            if ($null -eq $targetObject){
                Write-Error "Directory Object '$input' does not exist or you don't have permission to view it. Make sure to run as an Active Roles Administrator."
            } else {
                foreach ($object in $targetObject){
                    Get-ATLinkbyDirectoryObject -DirectoryObject $object
                    Write-Host "`n`n`n"
                }
            }
        }
        Post-Export
    }


    if ($AccessTemplate){
        SetExport-Filename
        Pre-Export
        foreach ($input in $AccessTemplate){
            $ATObject = Get-QARSAccessTemplate $input -DontUseDefaultIncludedProperties -IncludedProperties objectGUID -ShowProgress -SizeLimit 0

            if ($null -eq $ATObject){
                Write-Error "Access template '$input' does not exist or you don't have permission to view it. Make sure to run as an Active Roles Administrator."
            } else {
                foreach ($object in $ATObject){
                    Get-ATLinkbyATguid -atDN $Object.DN -atName $Object.Name
                    Write-Host "`n`n`n"
                }
            }
        }
        Post-Export
    }

    if ($Trustee){
        SetExport-Filename
        Pre-Export
        foreach ($input in $Trustee){
            $trusteeObject = Get-QADObject $input -DontUseDefaultIncludedProperties -ShowProgress -SizeLimit 0

            if ($null -eq $trusteeObject){
                Write-Error "Trustee '$input' does not exist or you don't have permission to view it. Make sure to run as an Active Roles Administrator."
            } else {
                foreach ($object in $trusteeObject){
                    Get-ATLinkbyTrustee -trusteeName $object
                    Write-Host "`n`n`n"
                }
            }
        }
        Post-Export
    }

    # Disconnect from the Administration Service.
    Disconnect-QADService | Out-Null
}

Begin-Processing