Function Get-FixupGPOList
{
	#requires -Module GroupPolicy
	
	<#
	.SYNOPSIS
		Gets all the GPOs in the current or target domain and report if they are impacted by MS16-072.
	.DESCRIPTION
		Gets all the GPOs in the current or target domain and report if they are impacted by MS16-072.
		Script functionality:
		- Accepts current or target domain name to get list of all GPOs.
		- Checks if 'Authenticated Users' or 'Domain Computers' group have 'Read' or 'Apply' access on GPOs.
		- If not, then reports back based on the parameters supplied to review GPOs impacted by MS16-072.
	.PARAMETER DomainName
		FQDN of the current or target domain.
	.PARAMETER All
		Retrieves all the GPOs in the current or target domain.
	.PARAMETER UserConfigurationOnly
		Retrieves all the GPOs in the current or target domain containing only user configuration settings.
	.PARAMETER ComputerConfigurationOnly
		Retrieves all the GPOs in the current or target domain containing only computer configuration settings.
	.EXAMPLE
		Get-FixupGPOList -Domain domain.local -All
	.EXAMPLE
		Get-FixupGPOList -UserConfigurationOnly | Export-Csv -NoTypeInformation C:\Temp\GPOList.csv
	.NOTES
        File Name: Get-FixupGPOList.ps1
		Version: v 0.1
		Change Log:	6/23/2016 - Initial
	#>
	
	[CmdletBinding(DefaultParameterSetName= 'All')]
	param
	(
		[Parameter(Mandatory = $false)]
		[System.String]$DomainName,
		[Parameter(ParameterSetName = 'All',
				   Mandatory = $false)]
		[Switch]$All,
		[Parameter(ParameterSetName = 'UserConfiguration',
				   Mandatory = $false)]
		[Switch]$UserConfigurationOnly,
		[Parameter(ParameterSetName = 'ComputerConfiguration',
				   Mandatory = $false)]
		[Switch]$ComputerConfigurationOnly
	)
	
	Begin
	{
		#validate domain name supplied in parameter
		if ($PSBoundParameters['DomainName'])
		{
			Try
			{
				$getDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)))
				Write-Verbose "[$($DomainName.ToUpper())] exist, proceeding further."
			}
			Catch
			{
				throw $_
				break;
			}
		} #end_IF
		else
		{
			$getDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			Write-Verbose "No domain name provided, binding to default domain [$($getDomain.name.ToUpper())]"
		}
		
		
		
		#validate if GroupPolicy module is availbale on current machine or not.
		Try
		{
			Import-Module -Name GroupPolicy -ErrorAction Stop
		}
		Catch
		{
			throw $_
			break;
		}
		
	} #end_begin
	
	Process
	{
		#Get all GPOs in intended domain
		Try
		{
			$allGPO = Get-GPO -All -Domain $getDomain -ErrorAction Stop
			Write-Verbose "Total Number of GPOs in Domain: $($allGPO.Count)"
		}
		Catch
		{
			throw $_
			break;
		}
		
		#Progress counter
		$i = 1
		
		foreach ($gpo in $allGPO)
		{
			$count = $allGPO.Count
			Write-Progress -Activity "Processing GPO: $($gpo.DisplayName)" -Status "--> $i/$count <--" -PercentComplete (($i / $count) * 100) -CurrentOperation "$([Math]::Round($i / $count * 100, 3))% Completed"
			$i++
			
			#Authenticated Users ACL check
			Try
			{
				$permAU = Get-GPPermission -Guid $gpo.Id -TargetName 'Authenticated Users' -TargetType 'Group' -ErrorAction Stop -DomainName $getDomain
				$hasAuthenticatedUsers = $true
				
				if (($permAU.Permission -eq 'GpoRead') -or ($permAU.Permission -eq 'GpoApply'))
				{
					$hasAuthenticatedUsersWithPerm = $true
				}
				else
				{
					$hasAuthenticatedUsersWithPerm = $false
				}
			}
			Catch [System.ArgumentException]
			{
				$hasAuthenticatedUsers = $false
				$hasAuthenticatedUsersWithPerm = $false
			}
			
			#Domain Computers ACL check
			Try
			{
				$permDC = Get-GPPermission -Guid $gpo.Id -TargetName 'Domain Computers' -TargetType 'Group' -ErrorAction Stop -DomainName $getDomain
				$hasDomainComputers = $true
				
				if (($permDC.Permission -eq 'GpoRead') -or ($permDC.Permission -eq 'GpoApply'))
				{
					$hasDomainComputersWithPerm = $true
				}
				else
				{
					$hasDomainComputersWithPerm = $false
				}
				
			}
			Catch [System.ArgumentException]
			{
				$hasDomainComputers = $false
				$hasDomainComputersWithPerm = $false
			}
			
			#Check if review is required for GPO
			if ($hasAuthenticatedUsersWithPerm)
			{
				$requireReview = $false
			}
			else
			{
				if (-not ($hasDomainComputersWithPerm))
				{
					$requireReview = $true
				}
				else
				{
					$requireReview = $false
				}
			}
			
			#Main
			switch ($PSCmdlet.ParameterSetName)
			{
				'All' {
					if ($gpo.User.DSVersion -gt 0)
					{ $hasUserSettings = $true }
					else { $hasUserSettings = $false }
					
					if ($gpo.Computer.DSVersion -gt 0)
					{ $hasComputerSettings = $true }
					else { $hasComputerSettings = $false }
					
					$results = [Ordered]@{
						GPODisplayName = $gpo.DisplayName
						Owner = $gpo.Owner
						hasUserSettings = $hasUserSettings
						hasComputerSettings = $hasComputerSettings
						hasAuthenticatedUsers = $hasAuthenticatedUsers
						hasAuthenticatedUsersWithPerm = $hasAuthenticatedUsersWithPerm
						hasDomainComputers = $hasDomainComputers
						hasDomainComputersWithPerm = $hasDomainComputersWithPerm
						requireReview = $requireReview
						WhenCreated = $gpo.CreationTime
						WhenChanged = $gpo.ModificationTime
					}
					Write-Output (New-Object -TypeName System.Management.Automation.PSObject -Property $results)
				} #all
				
				'UserConfiguration' {
						if (($gpo.User.DSVersion -gt 0) -and ($gpo.Computer.DSVersion -eq 0))
						{
							$results = [Ordered]@{
								GPODisplayName = $gpo.DisplayName
								Owner = $gpo.Owner
								hasUserSettings = $true
								hasComputerSettings = $false
								hasAuthenticatedUsers = $hasAuthenticatedUsers
								hasAuthenticatedUsersWithPerm = $hasAuthenticatedUsersWithPerm
								hasDomainComputers = $hasDomainComputers
								hasDomainComputersWithPerm = $hasDomainComputersWithPerm
								requireReview = $requireReview
								WhenCreated = $gpo.CreationTime
								WhenChanged = $gpo.ModificationTime
							}
							Write-Output (New-Object -TypeName System.Management.Automation.PSObject -Property $results)
						}
					} #user
				
				'ComputerConfiguration' {
					if (($gpo.Computer.DSVersion -gt 0) -and ($gpo.User.DSVersion -eq 0))
					{
						$results = [Ordered]@{
							GPODisplayName = $gpo.DisplayName
							Owner = $gpo.Owner
							hasComputerSettings = $true
							hasUserSettings = $false
							hasAuthenticatedUsers = $hasAuthenticatedUsers
							hasAuthenticatedUsersWithPerm = $hasAuthenticatedUsersWithPerm
							hasDomainComputers = $hasDomainComputers
							hasDomainComputersWithPerm = $hasDomainComputersWithPerm
							requireReview = $requireReview
							WhenCreated = $gpo.CreationTime
							WhenChanged = $gpo.ModificationTime
						}
						Write-Output (New-Object -TypeName System.Management.Automation.PSObject -Property $results)
					}
				} #comp
			} #end_switch
		} #foreach
	} #end_process
} #end_function