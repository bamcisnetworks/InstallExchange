<#
	Original credit for the majority of the logic in this module goes to:

    Michel de Rooij
    michel@eightwone.com	 
    http://eightwone.com

	And the AWS CloudFormation kickstarter for Exchange
#>

#region Constants
$script:LogPath = "$env:SystemDrive\InstallExchange.log"
$script:MajorOSVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property @{Name = "Major"; Expression = {$_.Version.Split(".")[0] + "." +$_.Version.Split(".")[1]}} | Select-Object -ExpandProperty Major
$script:MinorOSVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property @{Name = "Minor"; Expression = {$_.Version.Split(".")[2]}} | Select-Object -ExpandProperty Minor
$script:InstallExchangeTaskName = "InstallExchange"
$script:RunOnceTaskName = "InstallExchangeMonitor"

[System.Environment]::SetEnvironmentVariable("LogPath", $script:LogPath, [System.EnvironmentVariableTarget]::Machine)

$script:FilterPacks = @(
	@{
		"PackageId" = "{95140000-2000-0409-1000-0000000FF1CE}";
		"PackageName" = "Microsoft Office 2010 Filter Pack";
		"Url" = "http://download.microsoft.com/download/0/A/2/0A28BBFA-CBFA-4C03-A739-30CCA5E21659/FilterPack64bit.exe";
		"Arguments" = @("/q", "/norestart")
	},
	@{
		"PackageId" = "00004159000290400100000000F01FEC\Patches\2B24AAAA46EAEB942BF5566A6B1DE170";
		"PackageName" = "Microsoft Office 2010 Filter Pack SP1";
		"Url" = "http://download.microsoft.com/download/A/A/3/AA345161-18B8-45AE-8DC8-DA6387264CB9/filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe";
		"Arguments" = @("/q", "/norestart")
	}
)

$script:WS2008R2Prereqs = @(
	@{
		"PackageId" = "KB974405";
		"PackageName" = "KB974405: Windows Identity Foundation";
		"Url" = "http://download.microsoft.com/download/D/7/2/D72FD747-69B6-40B7-875B-C2B40A6B2BDD/Windows6.1-KB974405-x64.msu";
		"Arguments" = @("/quiet", "/norestart")
	},
	@{
		"PackageId" = "KB2619234";
		"PackageName" = "KB2619234: Enable Association Cookie/GUID used by RPC/HTTP to also be used at RPC layer";
		"Url" = "http://hotfixv4.microsoft.com/Windows 7/Windows Server2008 R2 SP1/sp2/Fix381274/7600/free/437879_intl_x64_zip.exe";
		"Arguments" = @("/quiet", "/norestart")
	},
	@{
		"PackageId" = "KB2758857";
		"PackageName" = "KB2758857: Insecure library loading could allow remote code execution (supersedes KB2533623)";
		"Url" = "http://download.microsoft.com/download/A/9/1/A91A39EA-9BD8-422F-A018-44CD62CA7485/Windows6.1-KB2758857-x64.msu";
		"Arguments" = @("/quiet", "/norestart")
	}
)

$script:WS2012Prereqs = @(
	@{
		"PackageId" = "KB2985459";
		"PackageName" = "KB2985459: The W3wp.exe process has high CPU usage when you run PowerShell commands for Exchange";
		"Url" = "http://hotfixv4.microsoft.com/Windows 8/Windows Server 2012 RTM/nosp/Fix512067/9200/free/477081_intl_x64_zip.exe";
		"Arguments" = @("/quiet", "/norestart")
	},
	@{
		"PackageId" = "KB2884597";
		"PackageName" = "KB2884597: Virtual Disk Service or applications that use the Virtual Disk Service crash or freeze in Windows Server 2012";
		"Url" = "http://hotfixv4.microsoft.com/Windows 8 RTM/nosp/Fix469260/9200/free/467323_intl_x64_zip.exe";
		"Arguments" = @("/quiet", "/norestart")
	},
	@{
		"PackageId" = "KB2894875";
		"PackageName" = "KB2894875: Windows 8-based or Windows Server 2012-based computer freezes when you run the 'dir' command on an ReFS volume";
		"Url" = "http://hotfixv4.microsoft.com/Windows 8 RTM/nosp/Fix473391/9200/free/468889_intl_x64_zip.exe";
		"Arguments" = @("/quiet", "/norestart")
	}
)

$script:WS2012R2Prereqs = @()

$script:WS2016Prereqs = @()

$COUNTDOWN_TIMER                = 10
$DOMAIN_MIXEDMODE               = 0
$FOREST_LEVEL2003               = 2

# Minimum FFL/DFL levels
$EX2013_MINFORESTLEVEL          = 15137
$EX2013_MINDOMAINLEVEL          = 13236
$EX2016_MINFORESTLEVEL          = 15317
$EX2016_MINDOMAINLEVEL          = 13236

# Supported Exchange versions
$EX2013STOREEXE_RTM             = "15.00.0516.032"
$EX2013STOREEXE_CU1             = "15.00.0620.029"
$EX2013STOREEXE_CU2             = "15.00.0712.024"
$EX2013STOREEXE_CU3             = "15.00.0775.038"
$EX2013STOREEXE_SP1             = "15.00.0847.032"
$EX2013STOREEXE_CU5             = "15.00.0913.022"
$EX2013STOREEXE_CU6             = "15.00.0995.029"
$EX2013STOREEXE_CU7             = "15.00.1044.025"
$EX2013STOREEXE_CU8             = "15.00.1076.009"
$EX2013STOREEXE_CU9             = "15.00.1104.005"
$EX2013STOREEXE_CU10            = "15.00.1130.007"
$EX2013STOREEXE_CU11            = "15.00.1156.006"
$EX2013STOREEXE_CU12            = "15.00.1178.004"
#$EX2013STOREEXE_CU13           = "15.00.1210.003"
$EX2013STOREEXE_CU13            = "15.00.1210.000" #This matches the installer version
$EX2013STOREEXE_CU14            = "15.00.1236.000"
$EX2013STOREEXE_CU15            = "15.00.1263.000"

$EX2016STOREEXE_PRE             = "15.01.0225.016"
#$EX2016STOREEXE_RTM            = "15.01.0225.042"
$EX2016STOREEXE_RTM             = "15.01.0225.037" #This matches the installer version
$EX2016STOREEXE_CU1             = "15.01.0396.030"
$EX2016STOREEXE_CU2             = "15.01.0466.034"
$EX2016STOREEXE_CU3             = "15.01.0544.027"
$EX2016STOREEXE_CU4             = "15.01.0669.032"

#Map of version numbers to their text based version
$Versions= @{ 
	$EX2013STOREEXE_RTM = "Exchange Server 2013 RTM";
	$EX2013STOREEXE_CU1 = "Exchange Server 2013 Cumulative Update 1";
	$EX2013STOREEXE_CU2 = "Exchange Server 2013 Cumulative Update 2";
	$EX2013STOREEXE_CU3 = "Exchange Server 2013 Cumulative Update 3";
	$EX2013STOREEXE_SP1 = "Exchange Server 2013 Service Pack 1";
	$EX2013STOREEXE_CU5 = "Exchange Server 2013 Cumulative Update 5";
	$EX2013STOREEXE_CU6 = "Exchange Server 2013 Cumulative Update 6";
	$EX2013STOREEXE_CU7 = "Exchange Server 2013 Cumulative Update 7";
	$EX2013STOREEXE_CU8 = "Exchange Server 2013 Cumulative Update 8";
	$EX2013STOREEXE_CU9 = "Exchange Server 2013 Cumulative Update 9";
	$EX2013STOREEXE_CU10 = "Exchange Server 2013 Cumulative Update 10";
	$EX2013STOREEXE_CU11 = "Exchange Server 2013 Cumulative Update 11";
	$EX2013STOREEXE_CU12 = "Exchange Server 2013 Cumulative Update 12";
	$EX2013STOREEXE_CU13 = "Exchange Server 2013 Cumulative Update 13";
	$EX2013STOREEXE_CU14 = "Exchange Server 2013 Cumulative Update 14";
	$EX2013STOREEXE_CU15 = "Exchange Server 2013 Cumulative Update 15";
	$EX2016STOREEXE_PRE = "Exchange Server 2016 Preview";
	$EX2016STOREEXE_RTM = "Exchange Server 2016 RTM";
	$EX2016STOREEXE_CU1 = "Exchange Server 2016 Cumulative Update 1";
	$EX2016STOREEXE_CU2 = "Exchange Server 2016 Cumulative Update 2";
	$EX2016STOREEXE_CU3 = "Exchange Server 2016 Cumulative Update 3";
	$EX2016STOREEXE_CU4 = "Exchange Server 2016 Cumulative Update 4"
}

# Exchange ISO Locations

$script:EX2016CU4_ISO = "https://download.microsoft.com/download/B/9/F/B9F59CF4-7C60-49EF-8A5B-8C2B7991FA86/ExchangeServer2016-x64-cu4.iso"
$script:EX2016CU3_ISO = "https://download.microsoft.com/download/4/C/E/4CE65F66-CE89-4F4D-96C0-A97E08FA1693/ExchangeServer2016-x64-cu3.iso"
$script:EX2016CU2_ISO = "https://download.microsoft.com/download/C/6/C/C6C10C1B-EFD8-4AE7-AEE1-C04F45869F5D/ExchangeServer2016-x64-CU2.iso"
$script:EX2016CU1_ISO = "https://download.microsoft.com/download/6/4/8/648EB83C-00F9-49B2-806D-E46033DA4AE6/ExchangeServer2016-CU1.iso"
$script:EX2016RTM_EXE = "https://download.microsoft.com/download/3/9/B/39B8DDA8-509C-4B9E-BCE9-4CD8CDC9A7DA/Exchange2016-x64.exe"
$script:EX2013CU15_EXE = "https://download.microsoft.com/download/3/A/5/3A5CE1A3-FEAA-4185-9A27-32EA90831867/Exchange2013-x64-cu15.exe"
$script:EX2013CU14_EXE = "https://download.microsoft.com/download/0/C/E/0CE142F1-E61D-4DBF-9436-334A4045A91F/Exchange2013-x64-cu14.exe"
$script:EX2013CU13_EXE = "https://download.microsoft.com/download/7/4/9/74981C3B-0D3C-4068-8272-22358F78305F/Exchange2013-x64-cu13.exe"
$script:EX2013CU12_EXE = "https://download.microsoft.com/download/2/C/1/2C151059-9B2A-466B-8220-5AE8B829489B/Exchange2013-x64-cu12.exe"

$script:Sources = @{
	"2013_CU12" = $script:EX2013CU12_EXE;
	"2013_CU13" = $script:EX2013CU13_EXE;
	"2013_CU14" = $script:EX2013CU14_EXE;
	"2013_CU15" = $script:EX2013CU15_EXE;

	"2016_RTM" = $script:EX2016RTM_EXE;
	"2016_CU1" = $script:EX2016CU1_ISO;
	"2016_CU2" = $script:EX2016CU2_ISO;
	"2016_CU3" = $script:EX2016CU3_ISO;
	"2016_CU4" = $script:EX2016CU4_ISO
}

# Supported Operating Systems
$WS2008R2_MAJOR                 = "6.1"
$WS2012_MAJOR                   = "6.2"
$WS2012R2_MAJOR                 = "6.3"
$WS2016_MAJOR                   = "10.0"

# .NET Versions
$script:NET45 = 378389
$script:NET451 = 378675
$script:NET452 = 379893
$script:NET46 = 393297
$script:NET461 = 394271



#endregion

Function Get-ExchangeInstallationMedia {
	<#
		.SYNOPSIS
			Downloads the specified Exchange installation media.

		.DESCRIPTION
			The cmdlet retrieves the installation media either from the internet or a specified AWS S3 bucket. The contents of the ISO or EXE are also automatically extracted to the destination directory.

		.PARAMETER Destination
			The location the ISO or EXE is downloaded to, should be a directory path. This defaults to "$env:SystemDrive\ExchangeSource". The contents of the ISO or EXE will also be extracted to this directory.

		.PARAMETER Source
			The URL to the installation media you want to download.

		.PARAMETER Version
			Specify the version of the installation media to download which uses preconfigured sources.

		.PARAMETER BucketName
			The AWS S3 bucket containing the installation media.

		.PARAMETER Key
			The S3 key of the installation media object.

		.PARAMETER PassThru
			Returns the destination the contents were downloaded to.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Get-ExchangeInstallationMedia -Version 2016_CU2

			Retrieves the installation media for Exchange 2016 CU2 and downloads it from the internet to the default destination.

		.EXAMPLE
			Get-ExchangeInstallationMedia -BucketName MyISOs -Key "Exchange/ExchangeServer2016-x64-CU2.iso"

			Downloads the ISO file from the MyISOs bucket, with a folder called Exchange in the bucket containing the ISO file. This method is intended to be used by an EC2 instance that is running
			with an IAM role that allows the file to download without credentials or from a public S3 bucket.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[System.String]$Destination = "$env:SystemDrive\ExchangeSource",

		[Parameter(ParameterSetName="Source",Mandatory=$true)]
		[AllowEmptyString()]
		[System.String]$Source,

		[Parameter(ParameterSetName="Version", Mandatory=$true)]
		[ValidateSet("2013_CU12", "2013_CU13", "2013_CU14", "2013_CU15", "2016_RTM","2016_CU1","2016_CU2", "2016_CU3", "2016_CU4")]
		[System.String]$Version,

		[Parameter(ParameterSetName="AWS",Mandatory=$true)]
		[System.String]$BucketName,

		[Parameter(ParameterSetName="AWS",Mandatory=$true)]
		[System.String]$Key,

		[Parameter()]
		[switch]$PassThru
	)

	Begin {
	}

	Process {
		if (-not (Test-Path -Path $Destination)) 
		{
			Write-Log -Message "Creating download destination at $Destination."
			New-Item -Path $Destination -ItemType Directory -Force -Confirm:$false | Out-Null
		}
		else
		{
			if (-not [System.IO.Directory]::Exists($Destination))
			{
				$Msg = "Provided destination $Destination is an existing file."
				Write-Log -Message $Msg -Level ERROR

				throw $Msg
			}
		}

        if ($PSCmdlet.ParameterSetName -eq "AWS") 
		{
			Write-Log -Message "Downloading $Key from AWS S3 Bucket $BucketName."

            $Parts = $Key.Split("/")
            $FileName = $Parts[$Parts.Length - 1]
            $DownloadDestination = Join-Path -Path $Destination -ChildPath $FileName

            Import-Module -Name AWSPowerShell -ErrorAction Stop

			try 
			{
				Copy-S3Object -BucketName $BucketName -Key $Key -LocalFile "$DownloadDestination"
				Write-Log -Message "Successfully downloaded file from S3."
			}
			catch [Exception] 
			{
				if ($_.Exception.Message -eq "Access Denied") 
				{
					Write-Log -Message "Received a 403 response from S3, this could be because the object $Key doesn't exist or the EC2 Instance doesn't have an IAM role with permission." -Level ERROR -ErrorRecord $_
				}
				else 
				{
					Write-Log -Message "Error downloading object from S3." -Level ERROR -ErrorRecord $_
				}

				throw $_.Exception
			}
        }
        else 
		{
			if ($PSCmdlet.ParameterSetName -eq "Version") 
			{
				$Source = $script:Sources[$Version]
			}

            $WebClient = New-Object -TypeName System.Net.WebClient
            $Uri = New-Object -TypeName System.Uri($Source)
		    $FileName = $Uri.Segments.Get($Uri.Segments.Count - 1)
            $Index = $Source.LastIndexOf("/")
            $BaseUrl = $Source.Substring(0, $Index)
		    $DownloadDestination = Join-Path -Path $Destination -ChildPath $FileName

            try 
			{
                Register-ObjectEvent -InputObject $WebClient -EventName DownloadFileCompleted -SourceIdentifier Web.DownloadFileCompleted -Action {
                    $Global:DownloadComplete = $true
                } | Out-Null

                Register-ObjectEvent -InputObject $WebClient -EventName DownloadProgressChanged -SourceIdentifier Web.DownloadProgressChanged -Action {
                    $Global:Event = $event
                } | Out-Null

                Write-Log -Message "Downloading $FileName from $BaseUrl"
                $WebClient.DownloadFileAsync($Source, $DownloadDestination)

				$Counter = 0

                while (!$Global:DownloadComplete) 
				{
                    $Percent = $Global:Event.SourceArgs.ProgressPercentage
                    $TotalBytes = $Global:Event.SourceArgs.TotalBytesToReceive
                    $ReceivedBytes = $Global:Event.SourceArgs.BytesReceived

                    if ($Percent -ne $null) 
					{
                        Write-Progress -Activity "Downloading $FileName from $BaseUrl" -Status "$ReceivedBytes bytes \ $TotalBytes bytes" -PercentComplete $Percent
                        
						if ($Counter % 30 -eq 0) 
						{
							Write-Log -Message "Downloaded $ReceivedBytes bytes \ $TotalBytes bytes - $Percent%" -Level VERBOSE
						}
                    }

                    Start-Sleep -Seconds 1 
					$Counter++
                }

                Write-Progress -Activity "Downloading $FileName from $BaseUrl" -Status "$ReceivedBytes bytes \ $TotalBytes bytes" -Completed
                Write-Log -Message "Successfully completed download."
            }
            finally 
			{
                $WebClient.Dispose()
            }
        }

		[System.IO.FileInfo]$FileInfo = New-Object -TypeName System.IO.FileInfo($DownloadDestination)

		if ($FileInfo.Extension.ToLower() -eq ".iso") 
		{
			Write-Log -Message "Mounting ISO file."
			$Result = Mount-DiskImage -ImagePath $DownloadDestination -StorageType ISO -PassThru
			$Drive = $Result | Get-Volume | Select-Object -ExpandProperty DriveLetter
			Write-Log -Message "ISO mounted at drive $Drive`:\."
			
			#Use a job because the current PowerShell instance may not be able to access the mounted ISO drive
			$Job = Start-Job -ScriptBlock {
				$Counter = 0
                while (!(Test-Path -Path "$($args[0]):") -and $Counter -lt 60) 
				{
				    Start-Sleep -Seconds 1
					$Counter++

					if ($Counter -eq 60) 
					{
						Write-Log -Message "Error waiting for mounted ISO to become available." -Level ERROR
						throw "Error waiting for mounted ISO to become available."
					}
			    }

                Write-Log -Message "Copying contents to $($args[1])."
			    Copy-Item -Path "$($args[0]):\*" -Destination "$($args[1])" -Recurse
				Write-Log -Message "Copy completed."
            } -ArgumentList @($Drive, $Destination)

			Write-Log -Message "Waiting for extraction to complete..."
            Wait-Job -Job $Job  | Out-Null

			if ($Job.State -eq [System.Management.Automation.JobState]::Failed) 
			{
				$Msg = "Job to copy ISO contents failed with error: $($Job.ChildJobs[0].Error)"
				Write-Log -Message $Msg  -Level ERROR
				throw $Msg
			}

			Write-Log -Message "Unmounting ISO."
			Dismount-DiskImage -InputObject $Result
			Write-Log -Message "Deleting ISO."
			Remove-Item -Path $DownloadDestination -Confirm:$false -Force
		}

		#The provided destination parameter is a directory
		[System.IO.DirectoryInfo]$DirectoryInfo = New-Object -TypeName System.IO.DirectoryInfo($Destination)

		if ($DirectoryInfo.GetFiles().Length -eq 1) 
		{
			Write-Log -Message "Only 1 file was downloaded or extracted, going to unpack the single file."
			$Path = Get-ChildItem -Path $Destination -Filter "*.exe" | Select-Object -First 1 -ExpandProperty FullName
			Write-Log -Message "Extracting $Path"

			<#
				/a is unpack
				/q is quiet
				/x is the destination
			#>
			Start-Process -FilePath $Path -ArgumentList @("/a","/q","/x:`"$Destination`"") -Wait
			Write-Log -Message "Successfully extracted files."
			Write-Log -Message "Deleting self extracting cab file at $Path."
			Remove-Item -Path $Path -Confirm:$false -Force
		}

		if ($PassThru)
		{
			Write-Output -InputObject $DirectoryInfo.FullName
		}
	}

	End {
	}
}

Function Get-TextVersion {
	<#
		.SYNOPSIS
			Retrieves the text based version of Exchange based on the numeric version of the installer file.

		.DESCRIPTION
			Performs a lookup of the numeric version of the installer file to match it to the text based version.

		.PARAMETER FileVersion
			The version of the installer file to match against.

		.INPUTS
			System.String

				The version number as a string can be piped to the cmdlet.

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-TextVersion -FileVersion "15.01.0466.034"

			This returns "15.01.0466.034 Exchange Server 2016 Cumulative Update 2"

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[System.String]$FileVersion
	)

	Begin {
	}

	Process {
        if ($script:Versions.ContainsKey($FileVersion)) {
            $Result = "$FileVersion ($($Versions[$FileVersion]))"
        }
        else {
            $Result = "$FileVersion (Unknown Version)"
        }

		Write-Output -InputObject $Result
	}

	End {        
	}
}

Function Get-ForestRootNC {
	<#
		.SYNOPSIS
			Gets the Active Directory Forest Root Naming Context.

		.DESCRIPTION
			This cmdlet gets the Active Directory Forest Root Naming Context.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-ForestRootNC

			For the contoso.com forest root, this returns "DC=Contsos,DC=com".

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {
	}

	Process {
		try 
		{
			Write-Log -Message "Getting forest root naming context." -Level VERBOSE
			[System.DirectoryServices.ActiveDirectory.Forest]$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
			$NamingContext = "DC=$($Forest.Name.Replace(".",",DC="))"
			Write-Log -Message "Naming context is $NamingContext." -Level VERBOSE
			Write-Output -InputObject $NamingContext
		}
		catch [Exception] 
		{
			Write-Log -Message "Could not retrieve the forest root naming context." -ErrorRecord $_ -Level ERROR
			Write-Output -InputObject $null
		}
	}
	
	End {
	}
}

Function Get-DomainNC {
	<#
		.SYNOPSIS
			Gets the Active Directory Domain Naming Context.

		.DESCRIPTION
			This cmdlet gets the Active Directory Domain Naming Context for the computer's current domain.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-DomainNC

			For the tailspintoys.com domain, this returns "DC=Tailspintoys,DC=com".

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {
	}

	Process {
		try {
			Write-Log -Message "Getting domain root naming context." -Level VERBOSE
			[System.DirectoryServices.ActiveDirectory.Domain]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
			$NamingContext = "DC=$($Domain.Name.Replace(".",",DC="))"
			Write-Log -Message "Naming context is $NamingContext." -Level VERBOSE
			Write-Output -InputObject $NamingContext
		}
		catch [Exception] {
			Write-Log -Message "Could not retrieve the domain root naming context." -ErrorRecord $_ -Level ERROR
			Write-Output -InputObject $null
		}
    }

	End {
	}
}

Function Get-ForestFunctionalLevel {
	<#
		.SYNOPSIS
			Gets the Active Directory Forest functional level.

		.DESCRIPTION
			This cmdlet gets the Active Directory Forest functional level.

		.INPUTS
			None

		.OUTPUTS
			System.Int

        .EXAMPLE
			Get-ForestFunctionalLevel

			Returns the integer value representing the current forest functional level.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {
	}

	Process {
        try 
		{
			[System.DirectoryServices.ActiveDirectory.Forest]$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
			Write-Output -InputObject $Forest.ForestModeLevel
		}
		catch [Exception] 
		{
			Write-Log "Could not retrieve forest functional level." -ErrorRecord $_ -Level ERROR
			Write-Output -InputObject $null
		}
    }

	End {
	}
}

Function Test-DomainNativeMode {
	<#
		.SYNOPSIS
			For a Windows 2000 Active Directory environment, tests if the Domain is running in native mode.

		.DESCRIPTION
			This cmdlet tests for Windows 2000 Domain native mode of the current domain.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-DomainNativeMode

			Returns true if the domain is not running Windows 2000 Mixed Mode.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
        [System.DirectoryServices.ActiveDirectory.Domain]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		Write-Output -InputObject ($Domain.DomainMode -ne [System.DirectoryServices.ActiveDirectory.DomainMode]::Windows2000MixedDomain)
	}
	
	End {}
}

Function Get-ExchangeOrganization {
	<#
		.SYNOPSIS
			Gets the Exchange Organization.

		.DESCRIPTION
			Retrieves the msExchOrganizationContainer object name from Active Directory. The cmdlet returns null of the object does not exist.

		.INPUTS
			None

		.OUTPUTS
			System.String or Null

        .EXAMPLE
			Get-ExchangeOrganization

			Returns the Exchange Organization name.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {		
	}

	Process {     
		Write-Log -Message "Getting Exchange Organization name from the msExchOrganizationContainer object class."

		$NC = Get-ForestRootNC

		if ($NC -ne $null)
		{
			try 
			{
				$Path = "LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,$NC"

				if ([System.DirectoryServices.DirectoryEntry]::Exists($Path) -eq $true) 
				{
					$ExOrgContainer = [ADSI]$Path
					$Result = $ExOrgContainer.PSBase.Children | Where-Object { $_.objectClass -eq 'msExchOrganizationContainer' } | Select-Object -ExpandProperty Name
				}
				else 
				{
					Write-Log -Message "Can't find Exchange Organization object" -Level VERBOSE
					$Result = $null
				}
			}
			catch [Exception] 
			{
				Write-Log -Message "Can't find Exchange Organization object" -ErrorRecord $_ -Level VERBOSE
				$Result = $null
			}
		}
		else
		{
			Write-Log -Message "Forest naming context was null" -Level VERBOSE
			$Result = $null
		}
        
		Write-Output -InputObject $Result
	}
	
	End {		
	}
}

Function Test-ExchangeOrganization {
	<#
		.SYNOPSIS
			Tests for the existence of a specific Exchange Organization.

		.DESCRIPTION
			This cmdlet tests for the existence of the specified Exchange Organization.

		.PARAMETER Organization
			The organization name to test the existence of.

		.INPUTS
			System.String

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-ExchangeOrganization -Organization "contoso"

			Returns true if the contoso Exchange organization exists in Active Directory.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline = $true)]
		[System.String]$Organization
	)

	Begin {
	}

	Process {
		Write-Log -Message "Testing for the existence of the $Organization organization in Active Directory."

        $NC= Get-ForestRootNC

		if ($NC -ne $null)
		{
			$Path = "LDAP://CN=$Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,$NC"
			$Result = [System.DirectoryServices.DirectoryEntry]::Exists($Path)
			Write-Output -InputObject $Result
		}
		else
		{
			Write-Log -Message "Forest root naming context was null." -Level VERBOSE
			Write-Output -InputObject $false
		}
	}

	End {	
	}
}

Function Get-ExchangeForestLevel {
	<#
		.SYNOPSIS
			Gets the current Exchange Forest level.

		.DESCRIPTION
			This cmdlet reads the ms-Exch-Schema-Version upperRange attribute.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-ExchangeForestLevel

			Returns the current Exchange environment forest level.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {      
		$NC= Get-ForestRootNC

		if ($NC -ne $null)
		{
			try
			{
				$Path = "LDAP://CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,$NC"
				if ([System.DirectoryServices.DirectoryEntry]::Exists($Path) -eq $true)
				{
					$Result = [ADSI]$Path | Select-Object -ExpandProperty rangeUpper
				}
				else 
				{
					Write-Log -Message "$Path does not exist." -Level VERBOSE
					$Result = $null
				}
			}
			catch [Exception] 
			{
				Write-Log -Message "Could not retrieve Exchange Forest Level." -ErrorRecord $_ -Level VERBOSE
				$Result = $null
			}
		}
		else
		{
			Write-Log -Message "Forest root naming context was null." -Level VERBOSE
			$Result = $null
		}

		Write-Output -InputObject $Result
	}

	End {		
	}
}

Function Get-ExchangeDomainLevel {
	<#
		.SYNOPSIS
			Gets the current Exchange Domain level.

		.DESCRIPTION
			This cmdlet reads the Microsoft Exchange System Objects objectVersion attribute.

		.INPUTS
			None

		.OUTPUTS
			System.String

        .EXAMPLE
			Get-ExchangeDomainLevel

			Returns the current Exchange environment domain level.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
		
		$NC = Get-DomainNC

		if ($NC -ne $null)
		{
			try 
			{
				$Path = "LDAP://CN=Microsoft Exchange System Objects,$NC"
				if ([System.DirectoryServices.DirectoryEntry]::Exists($Path) -eq $true) 
				{
					$Result = [ADSI]$Path | Select-Object -ExpandProperty objectVersion
				}
				else 
				{
					$Result = $null
				}
			}
			catch [Exception] 
			{
				Write-Log -Message "Could not retrieve Exchange Domain Level." -ErrorRecord $_ -Level VERBOSE
				$Result = $null
			}
		}
		else
		{
			Write-Log -Message "Domain root naming context was null." -Level VERBOSE
			$Result = $null
		}

		Write-Output -InputObject $Result
	}

	End {	
	}
}

Function Remove-AutodiscoverServiceConnectionPoint {
	<#
		.SYNOPSIS
			Removes the Autodiscover Service Connection Point from Active Directory.

		.DESCRIPTION
			This cmdlet removes the serviceConnectionPoint object from Active Directory for Exchange Autodiscover.

		.PARAMETER Name
			The name of the service connection point.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Remove-AutodiscoverServiceConnectionPoint -Name $ENV:COMPUTERNAME

			Removes the autodiscover service connection point for the current server.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[System.String]$Name
	)

	Begin {
	}

	Process {
		Write-Log -Message "Removing the Autodiscover Service Connection Point from Active Directory." -Level VERBOSE
	
		$NC= Get-ForestRootNC

		if ($NC -ne $null)
		{

			$LDAPSearch= New-Object System.DirectoryServices.DirectorySearcher
			$LDAPSearch.SearchRoot= "LDAP://CN=Configuration,$NC"
			$LDAPSearch.Filter= "(&(cn=$Name)(objectClass=serviceConnectionPoint)(serviceClassName=ms-Exchange-AutoDiscover-Service)(|(keywords=67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596)))"
        
			$LDAPSearch.FindAll() | ForEach-Object {
				Write-Log "Removing object $($_.Path)" -Level VERBOSE
				([ADSI]($_.Path)).DeleteTree()
			}
		}
		else
		{
			Write-Log -Message "Forest root naming context was null." -Level VERBOSE
		}
	}

	End {
	}
}

Function Add-AutodiscoverServiceConnectionPoint {
	<#
		.SYNOPSIS
			Adds an Autodiscover Service Connection Point in Active Directory.

		.DESCRIPTION
			This cmdlet adds the serviceConnectionPoint object in Active Directory for Exchange Autodiscover.

		.PARAMETER Name
			The name of the service connection point.

		.PARAMETER ServiceBinding
			The FQDN of the Client Access Server.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Add-AutodiscoverServiceConnectionPoint -Name $ENV:COMPUTERNAME -ServiceBinding "https://$($ENV:COMPUTERNAME).contoso.com/autodiscover/autodiscover.xml"

			Adds the autodiscover service connection point for the current server.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true, Position = 0)]
		[System.String]$Name,

		[Parameter(Mandatory=$true, Position = 1)]
		[System.String]$ServiceBinding
	)

	Begin {}

	Process {
        $NC= Get-ForestRootNC

		if ($NC -ne $null)
		{
			$LDAPSearch= New-Object System.DirectoryServices.DirectorySearcher
			$LDAPSearch.SearchRoot= "LDAP://CN=Configuration,$NC"
			$LDAPSearch.Filter= "(&(cn=$Name)(objectClass=serviceConnectionPoint)(serviceClassName=ms-Exchange-AutoDiscover-Service)(|(keywords=67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596)))"
        
			$LDAPSearch.FindAll() | ForEach-Object {
				Write-Log "Setting serviceBindingInformation on $($_.Path) to $ServiceBinding." -Level VERBOSE
            
				try 
				{
					$SCPObj= $_.GetDirectoryEntry()
					[void]$SCPObj.Put('serviceBindingInformation', $ServiceBinding)
					$SCPObj.SetInfo()
				}
				catch [Exception] 
				{
					Write-Log "Problem setting serviceBindingInformation property." -Level ERROR -ErrorRecord $_
				}
			}
		}
		else
		{
			Write-Log -Message "Forest root naming context was null." -Level VERBOSE
		}

	}

	End {
	}
}

Function Enable-IFilters {
	<#
		.SYNOPSIS
			Enables OneNote and Publisher IFilters in Exchange.

		.DESCRIPTION
			Enables OneNote and Publisher IFilters in Exchange.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Enable-IFilters

			Enables the OneNote and Publisher IFilters.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
        # Note: Requires restarting "Microsoft Exchange Transport" and "Microsoft Filtering Management Service", but reboot will take care of that
        Write-Log -Message "Enabling OneNote and Publisher filtering" -Level VERBOSE
        
		$iFilterDirName = "$env:CommonProgramFiles\Microsoft Shared\Filters\"
        $KeyParent = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\HubTransportRole"
        $CLSIDKey = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\HubTransportRole\CLSID"
        $FiltersKey = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\HubTransportRole\filters"
        $ONEFilterLocation = $iFilterDirName + "\ONIFilter.dll"
        $PUBFilterLocation = $iFilterDirName + "\PUBFILT.dll"
        $ONEGuid    ="{B8D12492-CE0F-40AD-83EA-099A03D493F1}"
        $PUBGuid    ="{A7FD8AC9-7ABF-46FC-B70B-6A5E5EC9859A}" 

        New-Item -Path $KeyParent -Name CLSID -ErrorAction SilentlyContinue -Force| Out-Null
        New-Item -Path $KeyParent -Name filters -ErrorAction SilentlyContinue -Force | Out-Null
        New-Item -Path $CLSIDKey -Name $ONEGuid -Value $ONEFilterLocation -Type String -Force| Out-Null
        New-Item -Path $CLSIDKey -Name $PUBGuid -Value $PUBFilterLocation -Type String -Force| Out-Null
        New-ItemProperty -Path "$CLSIDKey\$ONEGuid" -Name "ThreadingModel" -Value "Both" -Type String -Force| Out-Null
        New-ItemProperty -Path "$CLSIDKey\$PUBGuid" -Name "ThreadingModel" -Value "Both" -Type String -Force| Out-Null
        New-ItemProperty -Path "$CLSIDKey\$ONEGuid" -Name "Flags" -Value "1" -Type Dword -Force| Out-Null
        New-ItemProperty -Path "$CLSIDKey\$PUBGuid" -Name "Flags" -Value "1" -Type Dword -Force| Out-Null
        New-Item -Path $FiltersKey -Name ".one" -Value $ONEGuid -Type String -Force| Out-Null
        New-Item -Path $FiltersKey -Name ".pub" -Value $PUBGuid -Type String -Force| Out-Null 

        $Acl = Get-Acl -Path $KeyParent

		[System.Security.Principal.SecurityIdentifier]$NetworkService = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $null)

        [System.Security.AccessControl.RegistryAccessRule]$Rule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule($NetworkService.Translate([System.Security.Principal.NTAccount]),
			[System.Security.AccessControl.RegistryRights]::ReadKey,
			[System.Security.AccessControl.AccessControlType]::Allow)

        $Acl.SetAccessRule($Rule)
        $Acl | Set-Acl -Path $KeyParent

		Write-Warning -Message "`"Microsoft Exchange Transport`" and `"Microsoft Filtering Management Service`" must be restarted for this to take effect."
	}

	End {
	}
}
       
Function Set-DisableSharedCacheServiceProbe {
	<#
		.SYNOPSIS
			Runs the contents of KB2971467 to disable the shared cache service probe.

		.DESCRIPTION
			Taken from DisableSharedCacheServiceProbe.ps1. Copyright (c) Microsoft Corporation. All rights reserved. 

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Set-DisableSharedCacheServiceProbe

			Disables the shared cache service probe.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
        Write-Log -Message "Applying DisableSharedCacheServiceProbe (KB2971467, 'Shared Cache Service Restart' Probe Fix)"
        
		$ExchangeInstallPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup" -ErrorAction SilentlyContinue -Name MsInstallPath | Select-Object -ExpandProperty MsiInstallPath

        if (![System.String]::IsNullOrEmpty($ExchangeInstallPath) -and (Test-Path -Path "$ExchangeInstallPath")) 
		{           
			$ProbeConfigFile= Join-Path -Path "$ExchangeInstallPath" -ChildPath "Bin\Monitoring\Config\SharedCacheServiceTest.xml"
	        
			if (Test-Path $ProbeConfigFile) {
	            $Date = Get-Date -Format s
	            $Ext = ".orig_" + $Date.Replace(':', '-');
	            $Backup = $ProbeConfigFile + $Ext
	            $XmlBackup = [XML](Get-Content -Path $ProbeConfigFile)
	            $XmlBackup.Save($Backup)	
	
	            $XmlDoc = [XML](Get-Content -Path $ProbeConfigFile)
	            $Definition = $XmlDoc.Definition.MaintenanceDefinition
	
	            if ($Definition -eq $null) 
				{
                    Write-Log -Message "KB2971467: Expected XML node Definition.MaintenanceDefinition.ExtensionAttributes not found. Skipping." -Level WARNING
                }
                else {
                    $Modified = $false

                    if ($Definition.Enabled -ne $null -and $Definition.Enabled -ne "false") 
					{
                        $Definition.Enabled = "false"
                        $Modified = $true
                    }

	                if ($Modified -eq $true) 
					{
                        $XmlDoc.Save($ProbeConfigFile)
                        Write-Log -Message "Finished KB2971467, Saved $ProbeConfigFile."
                    }
                    else 
					{
                        Write-Log -Message "Finished KB2971467, No values modified."
                    }
                }
            }
            else 
			{
	            Write-Log -Message "KB2971467: Did not find file in expected location, skipping $ProbeConfigFile." -Level WARNING
	        }
        }
        else 
		{
            Write-Log -Message "KB2971467: Unable to locate Exchange install path" -Level WARNING
        }
    }

	End {}
}

Function Start-ExchangeCleanup {
	<#
		.SYNOPSIS
			Performs the necessary cleanup tasks after installing Exchange with this module.

		.DESCRIPTION
			This cmdlet removes any unneeded Windows Features, files, scheduled tasks, and RunOnce scripts after the Exchange installation.

		.PARAMETER WindowsFeatures
			The Windows features to uninstall.

		.PARAMETER Paths
			The list of files or folders to delete.		
			
		.PARAMETER TaskName
			The name of the scheduled task for an unattended installation to remove. This defaults to $script:InstallExchangeTaskName which is InstallExchange.
			
		.PARAMETER RunOnceTaskName
			The name of the RunOnce script to remove. This defaults to $script:RunOnceTaskName which is InstallExchangeMonitor.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-ExchangeCleanup -Paths @("c:\exchangetemp")

			Runs the cleanup tasks and deletes the folder c:\exchangetemp.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/26/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[System.String[]]$WindowsFeatures,

		[Parameter()]
		[System.String[]]$Paths,

		[Parameter()]
		[System.String]$TaskName = $script:InstallExchangeTaskName,

		[Parameter()]
		[System.String]$RunOnceTaskName = $script:RunOnceTaskName
	)

	Begin {		
	}

	Process {
		if ([System.String]::IsNullOrEmpty($TaskName))
		{
			$TaskName = $script:InstallExchangeTaskName
		}

		if ([System.String]::IsNullOrEmpty($RunOnceTaskName)) {
			$RunOnceTaskName = $script:RunOnceTaskName
		}

        Write-Log -Message "Cleaning up..."
		foreach ($Item in $WindowsFeatures) {
			if (Get-WindowsFeature -Name $Item -ErrorAction SilentlyContinue) {
				try {
					Write-Log -Message "Removing Windows Feature: $Item."
					Remove-WindowsFeature -Name $Item -Confirm:$false
				}
				catch [Exception] {
					Write-Log -Message "Error removing $Item" -Level ERROR -ErrorRecord $_
				}
			}
        }

		foreach ($Item in $Paths) {
			Write-Log -Message "Removing $Item" -Level VERBOSE
			Remove-Item -Path $Item -Force -Confirm:$false -ErrorAction SilentlyContinue -Recurse
		}

		Write-Log -Message "Removing scheduled task $TaskName."
		if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -ne $null) {
			Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
			Write-Log -Message "Successfully removed scheduled task."
		}
		else {
			Write-Log -Message "No scheduled task matching $TaskName present."
		}

		try {
			Write-Log -Message "Removing RunOnce scripts."
			$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
			Remove-ItemProperty -Path $Path -Name $RunOnceTaskName -ErrorAction SilentlyContinue
			Write-Log -Message "Successfully removed RunOnce command."
		}
		catch [Exception] {
			Write-Log -Message $_.Exception.Message -ErrorRecord $_ -Level WARNING
		}

		Write-Log -Message "Successfully finished cleanup."
    }

	End {		
	}
}

Function Start-ExchangeFixIt {
	<#
		.SYNOPSIS
			Launches Microsoft published Exchange FixIt scripts.

		.DESCRIPTION
			This cmdlet runs the specified Exchange FixIt script contents.

			Taken from Exchange2013-KB2938053-FixIt.ps1
			Parts taken from Exchange2013-KB2997355-FixIt.ps1
			Copyright (c) Microsoft Corporation. All rights reserved. 

		.PARAMETER KB
			The KB # of the FixIt to run.

		.INPUTS
			System.String

		.OUTPUTS
			None

        .EXAMPLE
			Start-ExchangeFixIt -KB KB2997355

			Runs the KB2997355 FixIt script.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/26/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidateSet("KB2938053", "KB2997355")]
		[System.String]$KB
	)

	Begin {
	}

	Process {
		switch ($KB) {
			"KB2938053" {

				Write-Log -Message "Applying Exchange2013-KB2938053-FixIt (KB2938053, Transport Agent Fix)"

				$BaseDirectory = "$env:windir\Microsoft.NET\assembly\GAC_MSIL"
				$PolicyDirectories = @{ "policy.14.0.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy14.0.cfg";
                        "policy.14.0.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy14.0.cfg";
                        "policy.14.1.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy14.1.cfg";
                        "policy.14.1.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy14.1.cfg";
                        "policy.14.2.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy14.2.cfg";
                        "policy.14.2.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy14.2.cfg";
                        "policy.14.3.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy14.3.cfg";
                        "policy.14.3.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy14.3.cfg";
                        "policy.14.4.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy14.4.cfg";
                        "policy.14.4.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy14.4.cfg";
                        "policy.15.0.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy15.0.cfg";
                        "policy.15.0.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy15.0.cfg";
                        "policy.8.0.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy.cfg";
                        "policy.8.0.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy.cfg";
                        "policy.8.1.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy8.1.cfg";
                        "policy.8.1.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy8.1.cfg";
                        "policy.8.2.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy8.2.cfg";
                        "policy.8.2.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy8.2.cfg";
                        "policy.8.3.Microsoft.Exchange.Data.Common" = "Microsoft.Exchange.Data.Common.VersionPolicy8.3.cfg";
                        "policy.8.3.Microsoft.Exchange.Data.Transport" = "Microsoft.Exchange.Data.Transport.VersionPolicy8.3.cfg"; }

				$Configs = @()
				foreach ($Key in $PolicyDirectories.Keys) {
					$Configs += Get-ChildItem -Path (Join-Path -Path $BaseDirectory -ChildPath $Key) -Recurse -Filter $PolicyDirectories[$Key] | Select-Object -ExpandProperty FullName
				}

				$Count = 0;
				foreach ($File in $Configs) {
					Write-Log -Message "Fixing $File..." -Level VERBOSE
					$Content = Get-Content -Path $File
					$Content -replace "[-\d+\.]*-->","-->" | Out-File $File -Force -Confirm:$false
					$Count++
				}

				Write-Log -Message "Exchange2013-KB2938053-FixIt fixed $Count files."
				break
			}
			"KB2997355" {
				Write-Log -Message "Applying Exchange2013-KB2997355-FixIt (KB2997355, Exchange Online Mailbox Management Fix)."
				$ExchangeInstallPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup" -ErrorAction SilentlyContinue -Name MsiInstallPath | Select-Object -ExpandProperty MsiInstallPath
				if (![System.String]::IsNullOrEmpty($ExchangeInstallPath) -and (Test-Path -Path $ExchangeInstallPath)) {
					$XConfigFile = Join-Path -Path (Join-Path -Path $ExchangeInstallPath -ChildPath "ClientAccess\ecp\DDI") -ChildPath "RemoteDomains.xaml"

					Write-Log -Message "KB2997355: Updating XAML file $XConfigFile..."
					$Content = Get-Content -Path "$XConfigFile"
					$Content = $Content -Replace '<Variable DataObjectName="RemoteDomain" Name="DomainName" Type="{x:Type s:String}" />','<Variable DataObjectName="RemoteDomain" Name="DomainName" Type="{x:Type s:String}" />    <Variable DataObjectName="RemoteDomain" Name="TargetDeliveryDomain" Type="{x:Type s:Boolean}" />' 
					$Content = $Content -Replace '<GetListWorkflow Output="Identity, Name, DomainName">','<GetListWorkflow Output="Identity, Name, DomainName, TargetDeliveryDomain">'
					$Content = $Content -Replace '<GetObjectWorkflow Output="Identity,Name, DomainName, AllowedOOFType, AutoReplyEnabled,AutoForwardEnabled,DeliveryReportEnabled, NDREnabled,  TNEFEnabled, MeetingForwardNotificationEnabled, CharacterSet, NonMimeCharacterSet">','<GetObjectWorkflow Output="Identity, Name, DomainName, TargetDeliveryDomain, AllowedOOFType, AutoReplyEnabled, AutoForwardEnabled, DeliveryReportEnabled, NDREnabled,  TNEFEnabled, MeetingForwardNotificationEnabled, CharacterSet, NonMimeCharacterSet">'
					$Content | Out-File "$XConfigFile" -Force -Confirm:$false
					# IISReset not required at this stage
					Write-Log -Message "KB2997355: Fixed XAML files"
				}
				else {
					Write-Log -Message 'KB2997355: Unable to locate Exchange install path' -Level WARNING
				}
				break
			}
			default {
				throw "Could not determine the selected KB to run the fix it."
				break
			}

		}
    }

	End {		
	}
}

Function Test-ExchangeReadiness {
	<#
		.SYNOPSIS
			Tests the readiness of the server and Active Directory for the Exchange installation.

		.DESCRIPTION
			This cmdlet ensures all of the prerequisites for installing Exchange are in place. This includes:

				-Ensuring the temp directory is available for installation files
				-Verifying the OS version
				-Ensuring admin credentials
				-Access to the setup.exe for Exchange
				-Domain membership
				-Credential validation
				-Required components of the config file
				-Domain and forest functional levels

		.PARAMETER Config
			The generated config object with all of the specified parameters to run this module's installation cmdlet.

		.PARAMETER Credential
			The credentials to be used during an unattended installation.

		.INPUTS
			System.Object
					
				The config object can be piped to this cmdlet.

		.OUTPUTS
			System.Boolean

        .EXAMPLE
			Test-ExchangeReadiness -Config $Config -Credential $Credential

			Tests the environment's and config's readiness to deploy exchange.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline = $true, Position = 0)]
		[System.Object]$Config,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin {	
	}

	Process {
		$MajorSetupVersion = [System.Decimal]"$($Config.SetupVersion.Split(".")[0]).$($Config.SetupVersion.Split(".")[1])"

        Write-Log -Message "Performing sanity checks."

        Write-Log -Message "Checking temporary installation folder." -Level VERBOSE

		if (!(Test-Path -Path "$($Config.TempDirectory)")) 
		{
			try 
			{
				New-Item -Path "$($Config.TempDirectory)" -ItemType Directory | Out-Null
			}
			catch [Exception] 
			{
				$Msg = "Error creating Temporary Installation Directory at $($Config.TempDirectory)."
				throw $Msg
			}
		}

        Write-Log -Message "Checking Operating System $($MajorOSVersion).$($MinorOSVersion)" -Level VERBOSE

        if (($MajorOSVersion -ne $WS2012R2_MAJOR) -and ($MajorOSVersion -ne $WS2012_MAJOR) -and ($MajorOSVersion -eq $WS2008R2_MAJOR -and $MinorOSVersion -lt 7601)) 
		{
			$Msg = "Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2 is required, but not detected"
            throw $Msg
        }

        Write-Log -Message "Checking privilege elevation..."
        if (!(Test-IsLocalAdmin)) 
		{
			$Msg = "Script requires local admin privileges."
            throw $Msg
        }
		else 
		{
			Write-Log -Message "Credentials appear to be running with local administrator rights."
		}

		Write-Log -Message "Checking for access to Exchange setup.exe file."
            
		if (!(Test-Path -Path "$($Config.SourceDirectory)\setup.exe")) 
		{
			$Msg = "Can't find Exchange setup at $($Config.SourceDirectory)\setup.exe."
			throw $Msg
        }
		else 
		{
			Write-Log -Message "Exchange Setup Version: $(Get-TextVersion $Config.SetupVersion)." -Level VERBOSE
            Write-Log -Message "Checking roles to install." -Level VERBOSE

			#This is Exchange 2016 and only the mailbox role is supported
            if ($MajorSetupVersion -ge 15.01) 
			{
                if (!$Config.InstallMailbox) 
				{
					$Msg = "No roles specified to install"
                    throw $Msg
                }
                
				if ($Config.InstallCAS) 
				{
                    Write-Log -Message "Exchange 2016 setup detected, will ignore deprecated InstallCAS parameter." -Level WARNING
                }
            }
            else 
			{
                if (!$Config.InstallMailbox -and !$Config.InstallCAS) 
				{
					$Msg = "No roles specified to install"
                    throw $Msg
                }
            }
		}
        
        Write-Log -Message "Checking domain membership status..."
        if((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain -eq $false) 
		{
			$Msg = "System is not domain-joined"
            throw $Msg
        }

        Write-Log -Message "Checking NIC configuration..."
        if ((Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True and DHCPEnabled = False") -eq $null) 
		{
            Write-Log -Message "System doesn't have a static IP address configured." -Level WARNING
        }

		if ($Config.TargetDirectory) 
		{
            $Drive = Split-Path $Config.TargetDirectory -Qualifier
            Write-Log -Message "Checking installation target directory..."

            if(!(Test-Path -Path $Drive)) 
			{
				$Msg = "Target directory drive unavailable: ($Drive)"
                throw $Msg
            }
        }

		if ($Config.InstallMDBLogPath) 
		{
            $Drive = Split-Path $Config.InstallMDBLogPath -Qualifier

            Write-Log -Message "Checking MDB log path..."

            if(!(Test-Path -Path $Drive)) 
			{
				$Msg = "MDB log drive unavailable: ($Drive)"
                throw $Msg
            }
        }

        if ($Config.InstallMDBDBPath) {
            $Drive = Split-Path $Config.InstallMDBDBPath -Qualifier

            Write-Log -Message "Checking MDB database path..."

            if(!(Test-Path -Path $Drive)) 
			{
				$Msg = "MDB database drive unavailable: ($Drive)"
                throw $Msg
            }
        }

		$ExOrg = Get-ExchangeOrganization
        if (![System.String]::IsNullOrEmpty($ExOrg)) 
		{
            if(![System.String]::IsNullOrEmpty($Config.Organization)) 
			{
                if($ExOrg -ne $Config.Organization) 
				{
					$Msg = "OrganizationName ($($Config.Organization)) mismatches with discovered Exchange Organization name ($ExOrg)."
                    throw $Msg
                }
            }

            Write-Log -Message "Exchange Organization is: $ExOrg"
        }
        else 
		{
            if(![System.String]::IsNullOrEmpty($Config.Organization)) 
			{
                Write-Log -Message "Exchange Organization will be: $($Config.Organization)."
            }
            else 
			{
				$Msg = "Organization not specified and no Exchange Organization discovered."
                throw $Msg
            }
        }

        Write-Log -Message "Checking Exchange Forest Schema Version"
		        
		if($MajorSetupVersion -ge 15.01) {
            $MinForestLevel = $EX2016_MINFORESTLEVEL
            $MinDomainLevel = $EX2016_MINDOMAINLEVEL
        }
        else {
            $MinForestLevel = $EX2013_MINFORESTLEVEL
            $MinDomainLevel = $EX2013_MINDOMAINLEVEL
        }
        
		$ExchangeForestLevel = Get-ExchangeForestLevel

        if ($ExchangeForestLevel -ne $null) 
		{
            Write-Log -Message "Exchange Forest Schema Version is $ExchangeForestLevel."

			if ($Config.Phase -eq 4 -and $ExchangeForestLevel -lt $MinForestLevel) 
			{
				# Only check before starting setup
				$Msg = "Minimum required Forest Functional Level version is $MinForestLevel, aborting."
				throw $Msg
			}
        }
        else 
		{
            Write-Log -Message "Active Directory is not prepared" -Level WARNING
        }

        Write-Log -Message "Checking Exchange Domain Version"
        $ExchangeDomainLevel = Get-ExchangeDomainLevel
        
		if($ExchangeDomainLevel -ne $null) 
		{
            Write-Log -Message "Exchange Domain Version is $ExchangeDomainLevel."

			if ($Config.Phase -eq 4 -and $ExchangeDomainLevel -lt $MinDomainLevel) 
			{
				# Only check before starting setup
				$Msg = "Minimum required Domain Functional Level version is $MinDomainLevel, aborting."
				throw $Msg
			}
		}

        Write-Log -Message "Checking domain mode"

        if ((Test-DomainNativeMode) -eq $false) 
		{
			$Msg = "Domain is in mixed mode, native mode is required"
            throw $Msg
        }
        else 
		{
            Write-Log -Message "Domain is in native mode"
        }

        Write-Log -Message "Checking Forest Functional Level"
        if ((Get-ForestFunctionalLevel) -lt $FOREST_LEVEL2003) 
		{
			$Msg = "Forest is not Functional Level 2003 or later"
            throw $Msg
        }
        else 
		{
            Write-Log -Message "Forest Functional Level is 2003 or later"
        }

        if ((Get-PSExecutionPolicy) -ne $null) 
		{
            # Referring to http://support.microsoft.com/kb/2810617/en
            Write-Log -Message "PowerShell Execution Policy is configured through GPO and may prohibit Exchange Setup. Clearing entry." -Level ERROR
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name ExecutionPolicy -Value "" -Force
        }

        if ($Config.Unattended) 
		{           
			Write-Log -Message "Checking provided credentials"
			
			if ($Credential -ne [PSCredential]::Empty) 
			{
				$Result = Test-Credentials -Credential $Credential
			}
			else 
			{
				Write-Log -Message "Unattended specified, but no credentials provided." -Level ERROR
				$Result = $false
			}

			if ($Result -ne $true) 
			{
				$Msg = "Provided credentials don't seem to be valid."
				throw $Msg
			} 
        }

		Write-Output -InputObject $true
    }

	End {		
	}
}

Function Start-ExchangeADPrep {
	<#
		.SYNOPSIS
			Runs the Active Directory preparation for Exchange.

		.DESCRIPTION
			This cmdlet tests and then prepares Active Directory using the standard Exchange installer.

		.PARAMETER Organization
			The Exchange Organization name that is being installed.

		.PARAMETER SetupFilePath
			The path to the setup.exe file used to install Exchange.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-ExchangeADPrep -Organization "contoso" -SetupFilePath "c:\exchangefiles\setup.exe"

			Runs the Exchange AD prep.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[System.String]$Organization,

		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$SetupFilePath
	)

	Begin {}

	Process {
		Write-Log -Message "Preparing Active Directory."
		$Params = @()

		Write-Log -Message "Checking Exchange Organization existence."

		if ((Test-ExchangeOrganization -Organization $Organization) -eq $false) {
			$Params += "/PrepareAD"
			$Params += "/OrganizationName:`"$Organization`""
		}
		else {
			Write-Log -Message "Organization $Organization exists, checking Exchange Forest Schema and Domain versions."
			$ForestLevel = Get-ExchangeForestLevel
			$DomainLevel = Get-ExchangeDomainLevel

			Write-Log -Message "Exchange Forest Schema version: $ForestLevel, Domain: $DomainLevel."

			$Version = New-Object -TypeName System.IO.FileInfo("$SetupFilePath") | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
			$MajorSetupVersion = [System.Decimal]"$($Version.Split(".")[0]).$($Version.Split(".")[1])"

			if ($MajorSetupVersion -ge 15.01) {
				$MinForestLevel = $EX2016_MINFORESTLEVEL
				$MinDomainLevel = $EX2016_MINDOMAINLEVEL
			}
			else {
				$MinForestLevel = $EX2013_MINFORESTLEVEL
				$MinDomainLevel = $EX2013_MINDOMAINLEVEL
			}

			if ($ForestLevel -lt $MinForestLevel -or $DomainLevel -lt $MinDomainLevel) {
				Write-Log -Message "Exchange Forest Schema or Domain needs updating. Required: Forest($MinForestLevel) / Domain($MinDomainLevel)." -Level WARNING
				$Params += "/PrepareAD"
			}
			else {
				Write-Log -Message "Active Directory is up to date."
			}
		}

		if ($Params.Count -gt 0) 
		{
			Write-Log -Message "Preparing Active Directory, Exchange Organization is $Organization."
			$Params += "/IAcceptExchangeServerLicenseTerms"
			Start-ProcessWait -FilePath $SetupFilePath -ArgumentList $Params -EnableLogging

			if (!(Test-ExchangeOrganization -Organization $Organization) -or (Get-ExchangeForestLevel) -lt $MinForestLevel -or (Get-ExchangeDomainLevel) -lt $MinDomainLevel) 
			{
				$Msg = "Problem updating schema, domain, or Exchange organization."
				throw $Msg
			}
			else 
			{
				Write-Log -Message "Active Directory has been successfully prepared for Exchange."
			}
		}
		else 
		{
			Write-Log -Message "Exchange organization $Organization already exists, skipping this step."
		}
	}

	End {

	}
}

Function Start-ExchangeInstallation {
	<#
		.SYNOPSIS
			Initiates the installation of a new Exchange environment.

		.DESCRIPTION
			This cmdlet runs the installation of Exchange using the setup.exe Exchange installer.

		.PARAMETER InstallMailbox
			Specify to install the mailbox role.

		.PARAMETER InstallCAS
			Specify to install the CAS role, this is ignored for Exchange 2016.

		.PARAMETER MDBName
			The name of the database file to be created, do not include an extension.

		.PARAMETER MDBDBPath
			The folder location to store the database file. The MDBName parameter is required to use this parameter.

		.PARAMETER MDBLogPath
			The folder location to store the database log files.

		.PARAMETER TargetDirectory
			The target directory for installation. This will default to the Exchange default.

		.PARAMETER SetupFilePath
			The path to the Exchange setup.exe file.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-ExchangeInstallation -InstallMailbox `
										 -MDBName MyDB `
										 -MDBDBPath "c:\exchange\db" `
										 -MDBLogPath "c:\exchange\logs" `
										 -SetupFilePath "c:\exchangefiles\setup.exe"

			Runs the exchange installation.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>  
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$InstallMailbox,

		[Parameter()]
		[switch]$InstallCAS,

		[Parameter()]
		[System.String]$MDBName,

		[Parameter()]
		[System.String]$MDBDBPath,

		[Parameter()]
		[System.String]$MDBLogPath,

		[Parameter()]
		[System.String]$TargetDirectory,

		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$SetupFilePath
	)

	Begin {}

	Process {
		$Version = New-Object -TypeName System.IO.FileInfo("$SetupFilePath") | Select-Object -ExpandProperty VersionInfo | Select-Object -ExpandProperty FileVersion
		$MajorSetupVersion = [System.Decimal]"$($Version.Split(".")[0]).$($Version.Split(".")[1])"
		Write-Log -Message "Installing Microsoft Exchange Server ($Version)."

		if ($MajorSetupVersion -ge 15.01) {
			$PresenceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CD981244-E9B8-405A-9026-6AEB9DCEF1F1}"
		}
		else {
			$PresenceKey= "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4934D1EA-BE46-48B1-8847-F1AF20E892C1}"
		}

		$Roles = @()

		if ($InstallMailbox) {
			$Roles += "Mailbox"
		}

		if ($InstallCAS) {
			if ($MajorSetupVersion -ge 15.01) {
				Write-Log -Message "Ignoring specified InstallCAS option for Exchange 2016." -Level WARNING
			}
			else {
				$Roles += "ClientAccess"
			}
		}

		$Roles = $Roles -join ","

		$Params = @("/Mode:Install", "/Roles:`"$Roles`"", "/IAcceptExchangeServerLicenseTerms","/InstallWindowsComponents")

		if ($InstallMailbox) {
			if (![System.String]::IsNullOrEmpty($MDBName)) {
				$Params += "/MdbName:`"$MDBName`""

				if (![System.String]::IsNullOrEmpty($MDBDBPath)) {
					$Params += "/DBFilePath:`"$MDBDBPath\$MDBName.edb`""
				}
			}

			if (![System.String]::IsNullOrEmpty($MDBLogPath)) {
				$Params += "/LogFolderPath:`"$MDBLogPath`""
			}
		}

		if (![System.String]::IsNullOrEmpty($TargetDirectory)) {
			$Params += "/TargetDir:`"$TargetDirectory`""
		}

		$Params += "/DoNotStartTransport"

		Start-ProcessWait -FilePath $SetupFilePath -ArgumentList $Params -EnableLogging

		if ((Get-Item -Path $PresenceKey -ErrorAction SilentlyContinue) -eq $null) 
		{
			$Msg = "Error encountered installing Exchange"
			throw $Msg
		}
		else 
		{
			$LocalAdmins = Get-LocalGroupMembers -LocalGroup "Administrators"
			Write-Log -Message "Current local admins: `n$($LocalAdmins -join "`n")" -Level VERBOSE
		}
	}

	End {
	}
}

Function Install-Exchange {
	<#
		.SYNOPSIS
			Runs the complete testing, preparation, installation, and cleanup for an Exchange installation.

		.DESCRIPTION
			This cmdlet performs all steps necessary to install Exhange 2013/2016. The installation runs in phases with a reboot after each phase.

			If the installation is being run unattended, scheduled tasks are used to continue the installation process. A single configuration file is generated from the parameters that is used
			to persist the config and also identify which phase is being executed by this cmdlet.

		.PARAMETER Organization
			The Exchange Organization name that is being installed.

		.PARAMETER InstallMailbox
			Specify to install the mailbox role.

		.PARAMETER InstallCAS
			Specify to install the CAS role, this is ignored for Exchange 2016.

		.PARAMETER MDBName
			The name of the database file to be created, do not include an extension.

		.PARAMETER MDBDBPath
			The folder location to store the database file. The MDBName parameter is required to use this parameter.

		.PARAMETER MDBLogPath
			The folder location to store the database log files.

		.PARAMETER TargetDirectory
			The target directory for installation. This will default to the Exchange default.

		.PARAMETER TempDirectory
			The location to temporarily store downloaded setup files. This defaults to the specified SourceDirectory containing the Exchange setup files.

		.PARAMETER Unattended
			Specify that this will be an unattended installation and will perform all necessary reboots and use Windows Task Scheduler to continue installation after reboot.

		.PARAMETER UnattendedTaskName
			The name of the scheduled task that will be used to conduct the unattended installation. This defaults to $script:InstallExchangeTaskName which is InstallExchange.

		.PARAMETER SourceDirectory
			The path to the folder containing the Exchange setup files. The setup.exe file should be at the root of this directory. The Exchange installation media should already be extracted from the
			ISO or exe in this directory.

		.PARAMETER InstallFilterPack
			Specify to install the Office filter pack.

		.PARAMETER IncludeFixes
			Specify to install and/or run all applicable KBs or FixIts for this version of Exchange.

		.PARAMETER Phase
			Indicate if you wish to start on a phase of the install other than 1. The 6 phases are

			1) Install OS Prerequisites
			2) Install Exchange Prequisites
			3) Install UCMA and prepare AD
			4) Install Exchange
			5) Run post configuration tasks
			6) Complete setup actions, add server to DAG, perform cleanup

		.PARAMETER NoSetup
			This switch specifies that only the prerequisite steps are performed and no installation is conducted. This is why the PrepareAD step is broken out into a separate phase from the 
			Install Exchange phase.

		.PARAMETER TargetDirectory
			The directory that Exchange will be installed into. This defaults to the Exchange setup default.

		.PARAMETER DAGName
			Specify the name of the DAG if this Exchange server should either setup a new DAG or join a DAG with the specified name. The cmdlet will determine which action to perform.

			Leave blank to run a standalone installation.

		.PARAMETER ProductKey
			Specify the product key to use if the installation media you are using does not have an embedded license key.

		.PARAMETER Credential
			The credential to use to execute an unattended installation and the credential that will be used to modify Active Directory.

		.PARAMETER ConfigFilePath
			The path to the existing configuration file. This is used by the unattended setup or can be used to run each phase manually without re-entering parameters.

		.PARAMETER RetryCount
			The number of times a phase will be retried if it fails. This defaults to 1 and has a maximum value of 3.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Install-Exchange -Organization "Contoso" `
								-InstallMailbox `
								-MDBDBPath "c:\Exchange\DB" `
								-MDBName "MDB1" `
								-MDBLogPath "c:\Exchange\Logs" `
								-Unattended `
								-SourceDirectory "c:\ExchangeSetup" `
								-InstallFilterPack `
								-IncludeFixes `
								-Credential (Get-Credential)								

			Launches an unattended Exchange installation for standalone instance.

		.EXAMPLE
			Install-Exchange -Organization "Contoso" `
								-InstallMailbox `
								-MDBDBPath "c:\Exchange\DB" `
								-MDBName "MDB1" `
								-MDBLogPath "c:\Exchange\Logs" `
								-Unattended `
								-SourceDirectory "c:\ExchangeSetup" `
								-InstallFilterPack `
								-IncludeFixes `
								-Credential (Get-Credential) `
								-DAGName "DAG1"							

			Launches an unattended Exchange installation for a DAG configuration.

		.EXAMPLE
			Install-Exchange -Organization "Contoso" `
								-NoSetup `							
								-Unattended `
								-SourceDirectory "c:\ExchangeSetup" `
								-Credential (Get-Credential)			

			Launches an unattended Exchange prerequisite installation, but does not install Exchange.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/26/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ParameterSetName="Parameters")]
		[System.String]$Organization,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$InstallMailbox,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$InstallCAS,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$MDBDBPath,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$MDBLogPath,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$MDBName,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$TempDirectory,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$Unattended,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$UnattendedTaskName = $script:InstallExchangeTaskName,

		[Parameter(ParameterSetName="Parameters", Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$SourceDirectory,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$InstallFilterPack,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$IncludeFixes,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateRange(1,6)]
		[System.Int32]$Phase = 1,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$NoSetup,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$TargetDirectory,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				$_.Length -le 15
			}
			else {
				return true
			}
		})]
		[System.String]$DAGName = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$ProductKey,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateRange(0, 3)]
		[System.Int32]$RetryCount = 1,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]	
		$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(ParameterSetName="ConfigFile", Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$ConfigFilePath
	)

	DynamicParam {
		[System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		$ValidateScript = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute([System.Management.Automation.ScriptBlock]::Create("if (![System.String]::IsNullOrEmpty(`$_)) { Test-Path -Path `$_ } else { return `$true }"))
		
		if (![System.String]::IsNullOrEmpty($DAGName)) {
			[System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $Attributes.ParameterSetName = "Parameters"
			$Attributes.Mandatory = $false
			$AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection.Add($Attributes)
			$AttributeCollection.Add($ValidateScript)

			[System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("WitnessServer", [System.String], $AttributeCollection)
			$DynParam.Value = [System.String]::Empty
            $ParamDictionary.Add("WitnessServer", $DynParam)
		}

        return $ParamDictionary  
	}

	Begin {		
	}

	Process {
		$ScriptFullName = $MyInvocation.MyCommand.Path
		$ParameterString = $PSBoundParameters.GetEnumerator() -join " "

		if ([System.String]::IsNullOrEmpty($TempDirectory)) 
		{
			$TempDirectory = $SourceDirectory
		}

		if ([System.String]::IsNullOrEmpty($UnattendedTaskName))
		{
			$UnattendedTaskName = $script:InstallExchangeTaskName
		}

		if ($PSCmdlet.ParameterSetName -ne "ConfigFile") 
		{
			$ConfigFile = "$TempDirectory\InstallExchange_config.json"
		}
		else 
		{
			$ConfigFile = $ConfigFilePath
		}

		Write-Log -Message "Cmdlet called using $ParameterString."
		Write-Log -Message "Running on OS Build $script:MajorOSVersion.$script:MinorOSVersion."
		Write-Log -Message "Logging to $script:LogPath." -Level VERBOSE
		Write-Log -Message "Config file path: $ConfigFile." -Level VERBOSE

		if ($PSCmdlet.ParameterSetName -eq "ConfigFile") 
		{
			$Config = ConvertFrom-Json -InputObject (Get-Content -Path "$ConfigFile" -Raw)
		}
		else 
		{
			#No config file, initialize from parameters

			if ($Unattended -eq $true -and $Credential -eq [PSCredential]::Empty) {
				try 
				{
					Write-Log -Message "Credentials not specified, prompting..."
					$Credential = Get-Credential
				}
				catch [Exception] 
				{
					$Msg = "Unattended setup specified, but no or improper credentials provided."
					Write-Log -Message $Msg  -Level ERROR
					throw $Msg
				}
			}

			$Config = @{}

			$Config.InstallMailbox = [bool]$InstallMailbox
			$Config.InstallCAS = [bool]$InstallCAS
			$Config.InstallMDBDBPath = $MDBDBPath
			$Config.InstallMDBLogPath = $MDBLogPath
			$Config.InstallMDBName = $MDBName
			$Config.TempDirectory = $TempDirectory
			$Config.PreviousPhase = ($Phase - 1)
			$Config.Phase = $Phase
			$Config.Organization = $Organization
			$Config.SourceDirectory = $SourceDirectory
			$Config.SetupVersion = Get-FileVersion -Path "$SourceDirectory\setup.exe"
			$Config.TargetDirectory = $TargetDirectory
			$Config.Unattended = [bool]$Unattended
			$Config.IncludeFixes = [bool]$IncludeFixes
			$Config.InstallFilterPack = [bool]$InstallFilterPack
			$Config.NoSetup = [bool]$NoSetup
			$Config.SCP = $SCP
			$Config.Verbose = [int]$VerbosePreference
			$Config.FirstRun = $true
			$Config.DAGName = $DAGName
			$Config.WitnessServer = $PSBoundParameters.WitnessServer
			$Config.ProductKey = $ProductKey
			$Config.TaskName = $UnattendedTaskName
			$Config.MaxRetries = $RetryCount
			$Config.RetryNumber = 0

			if(![System.String]::IsNullOrEmpty($Config.DAGName) -and [System.String]::IsNullOrEmpty($Config.WitnessServer)) {
				Write-Log -Message "No witness server defined, using a domain controller." -Level WARNING
				$Ctx = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain)
				$Server = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($Ctx) | Select-Object -ExpandProperty Name
				$Config.WitnessServer = $Server
				Write-Log -Message "Selected $Server for the witness server."
			}

			Set-Content -Path "$ConfigFile" -Value (ConvertTo-Json -InputObject $Config) -Force -Confirm:$false 
		}

		if ($Config.Unattended -eq $true) {
			if ($Config.FirstRun -eq $true) {
				$Command = @"
try { 
	Set-RunOnceScript -Command "`$env:SystemDrive\MonitorLog.ps1" -RunFile -Name "$script:RunOnceTaskName"
	Get-Content -Path "$script:LogPath" -Wait 
} 
catch [Exception] { 
	Write-Log -Message "Error running get-content for RunOnce command." -Level ERROR -ErrorRecord `$_
}
"@
				Set-Content -Path "$env:SystemDrive\MonitorLog.ps1" -Value $Command -Force -Confirm:$false
			}

			Set-RunOnceScript -Command "$env:SystemDrive\MonitorLog.ps1" -RunFile -Name $script:RunOnceTaskName
		}

		if ($Config.NoSetup -eq $true) {
			$MAX_PHASE = 3
		}
		else {
			$MAX_PHASE = 6
		}

		$VerbosePreference = $Config.Verbose

		if ($Config.Unattended -eq $true -and $Config.Phase -gt 1) 
		{
			Write-Log -Message "Will continue unattended installation of Exchange."
		}

		if ($Config.FirstRun -eq $true -or $PSBoundParameters.ContainsKey("Phase")) 
		{
			Write-Log -Message "Enabling Task Scheduler History." -Level VERBOSE
			$LogName = 'Microsoft-Windows-TaskScheduler/Operational'
			$EventLog = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
			$EventLog.IsEnabled = $true
			$EventLog.SaveChanges()

			try 
			{
				Write-Log -Message "Performing sanity checks for Exchange readiness on first run." -Level VERBOSE

				Test-ExchangeReadiness -Config $Config -Credential $Credential | Out-Null

				Write-Log -Message "Successfully completed sanity checks" -Level VERBOSE
			}
			catch [Exception]
			{
				Write-Log -ErrorRecord $_ 
				throw $_.Exception
			}
		}
		else 
		{
			Write-Log -Message "The install phase is $($Config.Phase), skipping sanity checks."
		}

		Set-OpenFileSecurityWarning -Disable

		Write-Log -Message "Checking for pending reboot..."

		if (Test-PendingReboots) 
		{
			if ($Config.Unattended) 
			{
				Write-Log -Message "Reboot pending, will reboot the system and rerun this phase, $($Config.Phase)."
			}
			else 
			{
				Write-Log -Message "Reboot pending, please reboot the system and restart the script. The parameters will be saved in the config file at $ConfigFile." -Level WARNING
			}
		}
		else 
		{
			if ($Config.PreviousPhase -eq $Config.Phase -and $Config.RetryNumber -gt $Config.MaxRetries) {
				$Msg = "Caught the installation running in a loop. The previous phase $($Config.PreviousPhase) is the same as the current phase and maximum retries have been reached."
				Write-Log -Message $Msg -Level ERROR
				Write-Log -Message "Removing scheduled task $($Config.TaskName) and ending installation."
				
				if ((Get-ScheduledTask -TaskName "$($Config.TaskName)" -ErrorAction SilentlyContinue) -ne $null) 
				{
					Unregister-ScheduledTask -TaskName "$($Config.TaskName)" -Confirm:$false
					Write-Log -Message "Successfully removed scheduled task."
				}
				else 
				{
					Write-Log -Message "No scheduled task matching $($Config.TaskName) present."
				}

				throw $Msg
			}
			else {
				Write-Log -Message "Current phase is $($Config.Phase) of $MAX_PHASE."
				$Config.PreviousPhase = $Config.Phase
				Set-Content -Path "$ConfigFile" -Value (ConvertTo-Json -InputObject $Config) -Force -Confirm:$false 

				[System.Boolean]$PhaseSuccess = $true

				switch ($Config.Phase) {
					1 {
						Write-Log -Message "*** PHASE 1 *** : Installing Operating System prerequisites."
						$Features = @("Desktop-Experience", "RSAT-ADDS", "RSAT-Clustering-CmdInterface")

						if ($MajorOSVersion -eq $WS2008R2_MAJOR) 
						{
							$Features += "NET-Framework"
						}
						else 
						{
							$Features += "Server-Media-Foundation"
						}

						if (![System.String]::IsNullOrEmpty($Config.DAGName)) 
						{
							$Features += "Failover-Clustering"
						}

						try 
						{
							Import-Module -Name ServerManager -ErrorAction Stop
							Add-WindowsFeature -Name $Features -ErrorAction Stop | Out-Null

							foreach ($Feature in $Features) 
							{
								if ((Get-WindowsFeature -Name "$Feature" -ErrorAction SilentlyContinue) -eq $null) 
								{
									Write-Log -Message "Feature $Feature appears not to be installed after attempting installation." -Level ERROR
									$PhaseSuccess = $false
								}
							}
						}
						catch [Exception] 
						{
							$PhaseSuccess = $false
							Write-Log -Message "Error installing windows features." -Level ERROR -ErrorRecord $_							
						}

						if ($PhaseSuccess -eq $true)
						{
							Write-Log -Message "Completed Operating System prerequisites."
							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					2 {
						Write-Log -Message "*** PHASE 2 *** : Installing Exchange prerequisites."

						try
						{
							if ($Config.InstallFilterPack -eq $true) 
							{
								foreach ($Item in $script:FilterPacks) 
								{
									[System.Uri]$Uri = New-Object -TypeName System.Uri("$($Item.Url)")
									$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
									Start-PackageInstallation -PackageId "$($Item.PackageId)" -PackageName "$($Item.PackageName)" -Url "$($Item.Url)" -Destination "$($Config.TempDirectory)\$FileName" -Arguments $Item.Arguments
								}
							}

							#Check if .NET 4.5.2 or later installed
							$NETVersion = Get-NETVersion
							if ($NETVersion -lt $script:NET452) 
							{
								if ($Config.SetupVersion -ge $EX2013STOREEXE_CU7) 
								{
									if ($MajorOSVersion -eq $WS2008R2_MAJOR) 
									{
										$PackageId = "{26784146-6E05-3FF9-9335-786C7C0FB5BE}"
									}
									else {
										$PackageId = "KB2934520"
									}

									$Url = "http://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe"
									[System.Uri]$Uri = New-Object -TypeName System.Uri($Url)
									$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
									Start-PackageInstallation -PackageId $PackageId -PackageName "Microsoft .NET Framework 4.5.2" -Url $Url -Destination "$($Config.TempDirectory)\$FileName" -Arguments @("/q", "/norestart")
								}
							}
							else 
							{
								Write-Log -Message ".NET Framework 4.5.2 or later already installed."
							}

							$Minimum2013Version = [System.Decimal]$EX2013STOREEXE_CU13.Replace(".","").Insert(4, ".")
							$Minimum2016Version = [System.Decimal]$EX2016STOREEXE_CU2.Replace(".","").Insert(4, ".")
							$CurrentVersion = [System.Decimal]$Config.SetupVersion.Replace(".","").Insert(4, ".")

							Write-Log -Message "Current Version $CurrentVersion, Minimum 2013 Version for .NET 4.6.1 $Minimum2013Version, Minimum 2016 Version for .NET 4.6.1 $Minimum2016Version."

							if ((($CurrentVersion -lt $Minimum2016Version) -and ($CurrentVersion -ge 1501)) -or (($CurrentVersion -lt $Minimum2013Version) -and ($CurrentVersion -lt 1501))) 
							{
								Write-Log -Message "Blocking .NET 4.6.1 installation for all installations below Exchange 2016 CU2 or Exchange 2013 CU13."
								Set-NET461InstallBlock
							}
							else 
							{
								if ($NETVersion -ge $script:NET46) 
								{
									Write-Log -Message "Installing Exchange 2016 CU2 or Exchange 2013 CU13 or greater and at least .NET 4.6 installed, installing .NET 4.6.1 hotfix rollups."

									switch ($MajorOSVersion) {
										$WS2016_MAJOR {
											$Url = ""
											$PackageId = ""
											$Arguments = @()
											break
										}
										$WS2012R2_MAJOR {
											$Url = "http://download.microsoft.com/download/6/8/0/680ee424-358c-4fdf-a0de-b45dee07b711/windows8.1-kb3154528-x64.msu"
											$PackageId = "KB3154528"
											$Arguments = @("/install", "/quiet", "/norestart")
											break
										}
										$WS2012_MAJOR {
											$Url = "http://download.microsoft.com/download/6/8/0/680ee424-358c-4fdf-a0de-b45dee07b711/windows8-rt-kb3154527-x64.msu"
											$PackageId = "KB3154527"
											$Arguments = @("/install", "/quiet", "/norestart")
											break
										}
										$WS2008R2_MAJOR {
											$Url = "http://download.microsoft.com/download/6/8/0/680ee424-358c-4fdf-a0de-b45dee07b711/ndp461-kb3154529-x86-x64-enu.exe"
											$PackageId = "KB3154529"
											$Arguments =  @("/q", "/norestart")
											break
										}
										default {
											Write-Log -Message "Unknown OS version $MajorOSVersion." -Level ERROR
											$Url = [System.String]::Empty
											$PhaseSuccess = $false
											break
										}
									}

									if (![System.String]::IsNullOrEmpty($Url)) 
									{
										[System.Uri]$Uri = New-Object -TypeName System.Uri($Url)
										$FileName = $Uri.Segments[$Uri.Segments.Count - 1]

										try 
										{
											Start-PackageInstallation -PackageId $PackageId -Url $Url -PackageName "Hotfix rollup for the .NET Framework 4.6 and 4.6.1 in Windows" -Destination "$($Config.TempDirectory)\$FileName" -Arguments $Arguments
										}
										catch [Exception] 
										{
											Write-Log -Message "Error installing .NET 4.6 and 4.6.1 hotfix rollup." -Level ERROR -ErrorRecord $_
											$PhaseSuccess = $false
										}
									}
								}
							}
					
							if ($PSVersionTable.PSVersion.Major -lt 5) {
								Write-Log -Message "WMF 5 is not installed, installing now."

								switch ($MajorOSVersion) {
									$WS2016_MAJOR {
										$Url = [System.String]::Empty
										$PackageId = [System.String]::Empty
										break
									}
									$WS2012R2_MAJOR {
										$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win8.1AndW2K12R2-KB3134758-x64.msu"
										$PackageId = "KB3134758"
										break
									}
									$WS2012_MAJOR {
										$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/W2K12-KB3134759-x64.msu"
										$PackageId = "KB3134759"
										break
									}
									$WS2008R2_MAJOR {
										$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win7AndW2K8R2-KB3134760-x64.msu"
										$PackageId = "KB3134760"
										break
									}
									default {
										Write-Log -Message "Cannot match current Major OS Version for WMF installation." -Level ERROR
										$Url = [System.String]::Empty
										$PhaseSuccess = $false
										break
									}
								}

								if (![System.String]::IsNullOrEmpty($Url)) 
								{
									[System.Uri]$Uri = New-Object -TypeName System.Uri("$Url")
									$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
									Start-PackageInstallation -PackageId $PackageId -PackageName "Windows Management Framework 5.0" -Url $Url -Destination "$($Config.TempDirectory)\$FileName" -Arguments @("/install", "/quiet", "/norestart")
								}
							}
							else 
							{
								Write-Log -Message "PowerShell version $($PSVersionTable.PSVersion.Major) detected."
							}

							switch ($MajorOSVersion) {
								$WS2016_MAJOR {
									$PrereqPackages = $script:WS2016Prereqs
									break
								}
								$WS2012R2_MAJOR {
									$PrereqPackages = $script:WS2012R2Prereqs
									break
								}
								$WS2012_MAJOR {
									$PrereqPackages = $script:WS2012Prereqs
									break
								}
								$WS2008R2_MAJOR {
									$PrereqPackages = $script:WS2008R2Prereqs
									break
								}
								default {
									Write-Log -Message "Cannot match current Major OS Version for prereq installation." -Level ERROR
									$PrereqPackages = @()
									$PhaseSuccess = $false
									break
								}
							}

							foreach ($Item in $PrereqPackages) 
							{
								[System.Uri]$Uri = New-Object -TypeName System.Uri("$($Item.Url)")
								$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
								Start-PackageInstallation -PackageId "$($Item.PackageId)" -PackageName "$($Item.PackageName)" -Url "$($Item.Url)" -Destination "$($Config.TempDirectory)\$FileName" -Arguments $Item.Arguments
							}

						}
						catch [Exception]
						{
							$PhaseSuccess = $false
							Write-Log -ErrorRecord $_ -Level ERROR
						}

						if ($PhaseSuccess -eq $true)
						{
							Write-Log -Message "Completed Operating System prerequisites."

							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					3 {
						Write-Log -Message "*** PHASE 3 *** : Installing Exchange prerequisites (continued)."

						try
						{
							$Url = "http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
							[System.Uri]$Uri = New-Object -TypeName System.Uri("$Url")
							$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
							Start-PackageInstallation -PackageId "{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -PackageName "Unified Communications Managed API 4.0 Runtime" -Url "$Url" -Destination "$($Config.TempDirectory)\$FileName" -Arguments @("/q", "/norestart")

							if (![System.String]::IsNullOrEmpty($Config.Organization)) 
							{
								Write-Log -Message "Checking/Preparing Active Directory."
								Start-ExchangeADPrep -Organization "$($Config.Organization)" -SetupFilePath "$($Config.SourceDirectory)\setup.exe"
							}

							Write-Log -Message "Completed installing Exchange prerequisites."
						}
						catch [Exception]
						{
							Write-Log -ErrorRecord $_ -Level ERROR
							$PhaseSuccess = $false
						}

						if ($PhaseSuccess -eq $true)
						{
							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					4 {
						Write-Log -Message "*** PHASE 4 *** : Installing Exchange."

						try
						{
							$MajorSetupVersion = "$($Config.SetupVersion.Split(".")[0]).$($Config.SetupVersion.Split(".")[1])"

							Start-ExchangeInstallation -InstallMailbox:$Config.InstallMailbox `
														-InstallCAS:$Config.InstallCAS `
														-MDBName $Config.InstallMDBName `
														-MDBDBPath $Config.InstallMDBDBPath `
														-MDBLogPath $Config.InstallMDBLogPath `
														-TargetDirectory "$($Config.TargetDirectory)" `
														-SetupFilePath "$($Config.SourceDirectory)\setup.exe"
																	 
							if (Get-Service -Name MSExchangeTransport -ErrorAction SilentlyContinue) {
								Write-Log -Message "Configuring MSExchangeTransport startup to Manual."
								Set-Service -Name MSExchangeTransport -StartupType Manual
							}

							if(Get-Service -Name MSExchangeFrontEndTransport -ErrorAction SilentlyContinue) {
								Write-Log -Message "Configuring MSExchangeFrontEndTransport startup to Manual."
								Set-Service -Name MSExchangeFrontEndTransport -StartupType Manual
							}

							switch($Config.SCP) {
								"" {
									# Do nothing
									break
								}
								$null   {
									Write-Log -Message "Removing Service Connection Point record"
									Remove-AutodiscoverServiceConnectionPoint -Name $ENV:COMPUTERNAME
									break
								}
								default {
									Write-Log -Message "Configuring Service Connection Point record as $($Config.SCP)"
									Add-AutodiscoverServiceConnectionPoint -Name $ENV:COMPUTERNAME -ServiceBinding $Config.SCP
									break
								}
							}

							Write-Log -Message "Completed Exchange installation step."
						}
						catch [Exception]
						{
							Write-Log -ErrorRecord $_ -Level ERROR
							$PhaseSuccess = $false
						}

						if ($PhaseSuccess -eq $true)
						{
							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					5 {
						Write-Log -Message "*** PHASE 5 *** : Post configuration tasks."

						try
						{
							Set-HighPerformancePowerPlan
							Set-Pagefile
							Disable-SSLv3						

							if ($Config.InstallMailbox) 
							{
								if ($Config.InstallFilterPack) 
								{
									Write-Log -Message "Enabling IFilters."
									Enable-IFilters
								}
								# Insert other Mailbox Server specifics here
							}
 		    
							if($Config.InstallCAS) 
							{
								# Insert Client Access Server specifics here
							}

							if($Config.IncludeFixes) {
								Write-Log -Message "Installing applicable recommended hotfixes and security updates."
								$Version = Get-FileVersion -ServiceName "MSExchangeServiceHost" 
								Write-Log -Message "Installed Exchange MSExchangeIS version is $(Get-TextVersion -FileVersion $Version)" -Level VERBOSE

								switch($Version) {
									$EX2013STOREEXE_CU2 {
										$Url = "http://download.microsoft.com/download/3/D/A/3DA5AC0D-4B94-479E-957F-C7C66DE1B30F/Exchange2013-KB2880833-x64-en.msp"
										[System.Uri]$Uri = New-Object -TypeName System.Uri("$Url")
										$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
										Start-PackageInstallation -PackageId "KB2880833" -PackageName "Security Update For Exchange Server 2013 CU2" -Destination "$($Config.SourceDirectory)\$FileName" -Url $Url -Arguments @("/q", "/norestart")
										break
									}
									$EX2013STOREEXE_CU3 {                
										$Url = "http://download.microsoft.com/download/0/E/3/0E3FFD83-FE6A-48B7-85F2-3EF92155EFBE/Exchange2013-KB2880833-x64-en.msp"
										[System.Uri]$Uri = New-Object -TypeName System.Uri("$Url")
										$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
										Start-PackageInstallation -PackageId "KB2880833" -PackageName "Security Update For Exchange Server 2013 CU3" -Destination "$($Config.SourceDirectory)\$FileName" -Url $Url -Arguments @("/q", "/norestart")
										break
									}
									$EX2013STOREEXE_SP1 {
										Start-ExchangeFixIt -KB KB2938053
										break
									}
									$EX2013STOREEXE_CU5 {
										Set-DisableSharedCacheServiceProbe
										break
									}
									$EX2013STOREEXE_CU6 {
										Start-ExchangeFixIt -KB KB2997355
										break
									}
									default {
										Write-Log -Message "No updates to install for Exchange."
										break
									}
								}
							}

							if (![System.String]::IsNullOrEmpty($Config.ProductKey)) {
								Write-Log -Message "Setting product key $($Config.ProductKey)."
								Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn
								Get-ExchangeServer | Where-Object {$_.IsE15OrLater} | ForEach-Object {
									Set-ExchangeServer -Identity $_ -ProductKey $Config.ProductKey
								}
								Write-Log -Message "Successfully set the prodcut key, restarting the Information Store service."
								Restart-Service -Name MSExchangeIS -Force -Confirm:$false
							}

							if (![System.String]::IsNullOrEmpty($Config.DAGName) -and ![System.String]::IsNullOrEmpty($Config.WitnessServer)) {
								Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn

								if ((Get-DatabaseAvailabilityGroup -Identity $Config.DAGName -ErrorAction SilentlyContinue) -eq $null) {
									Write-Log -Message "Adding Exchange Trusted Subsystem to Local Administrators on $($Config.WitnessServer) in preparation for DAG creation."
									
									$Success = Add-DomainMemberToLocalGroup -LocalGroup "Administrators" -Member "Exchange Trusted Subsystem" -MemberType Group -ComputerName $Config.WitnessServer

									if (-not $Success)
									{
										Write-Log -Message "Could not add the Exchange Trusted Subsystem to the witness server local administrators group. Cannot complete DAG setup." -Level ERROR
										$PhaseSuccess = $false
									}
								}
							}

							Write-Log -Message "Completed post-configuration tasks."
						}
						catch [Exception]
						{
							$PhaseSuccess = $false
							Write-Log -ErrorRecord $_ -Level ERROR
						}

						if ($PhaseSuccess -eq $true)
						{
							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					6 {
						Write-Log -Message "*** PHASE 6 *** Completing setup actions."

						try
						{
							if ((Get-Service -Name MSExchangeTransport -ErrorAction SilentlyContinue) -ne $null) 
							{
								Write-Log -Message "Configuring MSExchangeTransport startup to Automatic."
								Set-Service MSExchangeTransport -StartupType Automatic

								try 
								{
									Start-Service -Name MSExchangeTransport
								}
								catch [Exception] 
								{
									$PhaseSuccess = $false
									Write-Log -Message "Error starting MSExchangeTransport." -Level ERROR -ErrorRecord $_
								}
							}

							if ((Get-Service -Name MSExchangeFrontEndTransport -ErrorAction SilentlyContinue) -ne $null)
							{
								Write-Log -Message "Configuring MSExchangeFrontEndTransport startup to Automatic."
								Set-Service MSExchangeFrontEndTransport -StartupType Automatic

								try 
								{
									Start-Service -Name MSExchangeFrontEndTransport
								}
								catch [Exception] 
								{
									$PhaseSuccess = $false
									Write-Log -Message "Error starting MSExchangeFrontEndTransport." -Level ERROR -ErrorRecord $_
								}
							}

							Set-UAC -Enabled $true
							Set-IEESC -Enabled $true

							if (![System.String]::IsNullOrEmpty($Config.DAGName) -and ![System.String]::IsNullOrEmpty($Config.WitnessServer)) 
							{
								try 
								{
									Write-Log -Message "Adding this server to DAG $($Config.DAGName)."
									Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn

									$Exists = $false

									if ((Get-DatabaseAvailabilityGroup -Identity $Config.DAGName -ErrorAction SilentlyContinue) -eq $null) 
									{
										Write-Log -Message "Creating a DAG with name $($Config.DAGName)."
										New-DatabaseAvailabilityGroup -Name $Config.DAGName -WitnessServer $Config.WitnessServer -DatabaseAvailabilityGroupIPAddress ([System.Net.IPAddress]::None)
										Write-Log -Message "Successfully created DAG."
									}
									else 
									{
										$Exists = $true
									}

									try 
									{
										Write-Log -Message "Adding server to DAG."
										Write-Log -Message "Running a gpupdate."
										& gpupdate.exe /force

										Write-Log -Message "Adding Exchange Trusted Subsystem to Local Administrators in preparation for DAG join."
									
										$Success = Add-DomainMemberToLocalGroup -LocalGroup "Administrators" -Member "Exchange Trusted Subsystem" -MemberType Group

										if ($Success)
										{					
											Add-DatabaseAvailabilityGroupServer -Identity $Config.DAGName -MailboxServer $ENV:COMPUTERNAME -ErrorAction Stop
											Write-Log -Message "Successfully added server to DAG."

											if ($Exists -eq $true) 
											{
												Write-Log -Message "Since the DAG already exists, go ahead and setup copies of all the available databases."
												Get-MailboxDatabase | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $Config.DAGName -and $_.Servers -notcontains $ENV:COMPUTERNAME} | ForEach-Object {
													try 
													{
														Write-Log -Message "Creating a copy of $($_.Name) on local computer $env:COMPUTERNAME."
														Add-MailboxDatabaseCopy -Identity $_.Name -MailboxServer $env:COMPUTERNAME
													}
													catch [Exception] 
													{
														Write-Log -Message "Error creating database copy." -Level ERROR -ErrorRecord $_
													}
												}

												Write-Log -Message "Setting up database copies on the other servers."

												Get-DatabaseAvailabilityGroup -Identity $Config.DAGName | Select-Object -ExpandProperty Servers | Where-Object {$_ -notcontains $ENV:COMPUTERNAME} | ForEach-Object {
													Write-Log -Message "Setting up database copies on $_."
													$Server = $_
													Get-MailboxDatabase | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $Config.DAGName -and $_.Servers -notcontains $Server} | ForEach-Object {
														try 
														{
															Write-Log -Message "Creating a copy of $($_.Name) on remote computer $Server."
															Add-MailboxDatabaseCopy -Identity $_.Name -MailboxServer $Server
														}
														catch [Exception] 
														{
															Write-Log -Message "Error creating database copy." -Level ERROR -ErrorRecord $_
														}
													}
												}

												Write-Log -Message (Get-MailboxDatabaseCopyStatus | Format-List | Out-String)
											}
										}
										else
										{
											$PhaseSuccess = $false
											Write-Log -Message "The Exchange Trusted Subsystem could not be added to the local administrators group." -Level ERROR											
										}
									}
									catch [Exception] 
									{
										$PhaseSuccess = $false
										Write-Log -Message "Error adding server to DAG." -Level ERROR -ErrorRecord $_
									}
								}
								catch [Exception] 
								{
									$PhaseSuccess = $false
									Write-Log -Message "Error creating DAG $($Config.DAGName)." -Level ERROR -ErrorRecord $_
								}
							}
						}
						catch [Exception]
						{
							$PhaseSuccess = $false
							Write-Log -ErrorRecord $_ -Level ERROR
						}

						if ($PhaseSuccess -eq $true)
						{
							Write-Log -Message "Setup finished."
							$Config.Phase++
							$Config.RetryCount = 0
						}
						else
						{							
							$Config.RetryCount++
						}

						break
					}
					default {
						Write-Log -Message "Unknown phase $($Config.Phase)." -Level ERROR
						$PhaseSuccess = $false
						break
					}
				}
				#End of switch statement for different phases

				Set-OpenFileSecurityWarning -Enable 

				if ($Config.Unattended -eq $true ) 
				{
					if ($Config.FirstRun -eq $true) 
					{								
						$Task = New-InstallExchangeScheduledTask -Credential $Credential -ConfigFilePath $ConfigFile -TaskName "$($Config.TaskName)"
						$Config.FirstRun = $false
					}

					#Use less than or equal since the phase is incremented before this check
					if ($Config.Phase -le $MAX_PHASE) 
					{
						Write-Log -Message "Preparing system for the next phase." -Level VERBOSE
						Set-UAC -Enabled $false
						Set-IEESC -Enabled $false

						try 
						{
							Write-Log -Message "Saving updated configuration file to $ConfigFile."
							Set-Content -Path $ConfigFile -Value (ConvertTo-Json -InputObject $Config) -Force -Confirm:$false 
						}
						catch [Exception] 
						{
							Write-Log -Message "Error saving configuration file." -Level ERROR -ErrorRecord $_
							throw $_.Exception
						}

						if ($PhaseSuccess -eq $false)
						{
							if ($Config.RetryCount -le $Config.MaxRetries)
							{
								Write-Log -Message "The current phase $($Config.Phase) failed, will retry this phase."
								Write-Log -Message "Rebooting in $COUNTDOWN_TIMER seconds..."
								Start-Sleep -Seconds $COUNTDOWN_TIMER
								Set-RunOnceScript -Command "$env:SystemDrive\MonitorLog.ps1" -RunFile -Name $script:RunOnceTaskName
								Restart-Computer -Force
							}
							else
							{
								$Msg = "The current phase $($Config.Phase) failed and has reached the maximum number of retries."
								Write-Log -Message $Msg -Level ERROR

								Write-Log -Message "Performing cleanup" -Level VERBOSE
								Start-ExchangeCleanup

								throw $Msg
							}
						}
						else
						{					
							Write-Log -Message "Rebooting in $COUNTDOWN_TIMER seconds..."
							Start-Sleep -Seconds $COUNTDOWN_TIMER
							Set-RunOnceScript -Command "$env:SystemDrive\MonitorLog.ps1" -RunFile -Name $script:RunOnceTaskName
							Restart-Computer -Force
						}
					}
					else 
					{
						$Paths = @("$($Config.TempDirectory)", "$env:SystemDrive\MonitorLog.ps1")

						if ($Config.NoSetup -eq $false) 
						{
							$Paths += "$($Config.SourceDirectory)"
						}

						Start-ExchangeCleanup -Paths ($Paths | Select-Object -Unique)
						Write-Log -Message "Unattended setup complete."
					}
				}
				else
				{
					Write-Log -Message "Current phase complete, please manually initiate the next phase."
				}
			}
		}
	}

	End {		
	}
}

#region Scheduled Tasks

Function New-InstallExchangeScheduledTask {
	<#
		.SYNOPSIS
			Creates the scheduled task that is used for unattended Exchange installations.

		.DESCRIPTION
			This cmdlet creates a scheduled task that will run under the context of the provided credentials.

		.PARAMETER Credential
			The credential that the scheduled task will use to run.

		.PARAMETER ConfigFilePath
			The path to the configuration file that the scheduled task will use to continue running the Exchange installation.

		.PARAMETER TaskName
			The name to use for the scheduled task. This defaults to $script:InstallExchangeTaskName which is InstallExchange.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			New-InstallExchangeScheduledTask -Credential (Get-Credential) -ConfigFilePath "c:\exchangesource\config.json" -TaskName InstallExchange

			Creates the scheduled task for the unattended Exchange installation.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/26/2016
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]	
		$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Mandatory=$true)]
		[System.String]$ConfigFilePath,

		[Parameter()]
		[System.String]$TaskName = $script:InstallExchangeTaskName
	)

	Begin {		
	}

	Process {
		if ([System.String]::IsNullOrEmpty($TaskName)) 
		{
			$TaskName = $script:InstallExchangeTaskName
		}

		if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -ne $null) 
		{
			Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

		$Command = "try {Install-Exchange -ConfigFilePath `"$ConfigFilePath`"} catch [Exception] {Write-Log -Message `"Error running Install-Exchange from scheduled task.`" -ErrorRecord `$_ -Level ERROR}"
		$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
		$EncodedCommand = [Convert]::ToBase64String($Bytes)
        
		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
		$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
		$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
		$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew

		$ScheduledTask = Register-ScheduledTask -TaskName $TaskName `
												-Action $STAction `
												-User "$($Credential.UserName)" `
												-Password (Convert-SecureStringToString -SecureString $Credential.Password) `
												-Trigger (New-ScheduledTaskTrigger -AtStartup -RandomDelay ([System.Timespan]::FromSeconds(30))) `
												-Settings $STSettings `
												-ErrorAction Stop `
												-RunLevel Highest 
	
		Write-Output -InputObject $ScheduledTask											
	}

	End {		
	}
}

#endregion