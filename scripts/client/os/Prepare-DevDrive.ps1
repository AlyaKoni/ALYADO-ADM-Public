#Requires -Version 2.0
#Requires -RunAsAdministrator

$devDriveLetter = "D"
$devDriveDisk = "$($devDriveLetter):"
$devDrivePackageDir = "$devDriveDisk\Packages"
$devDrivePowerShellDir = "$devDriveDisk\PowerShell"

$devRedirects = @(
	@{
		name = "Npm-Cache (NodeJS)"
		dev = "$devDrivePackageDir\npm"
		loc = "$env:APPDATA\npm-cache"
		var = "npm_config_cache"
	},
	@{
		name = "NuGet"
		dev = "$devDrivePackageDir\nuget"
		loc = "$env:USERPROFILE\.nuget\packages"
		var = "NUGET_PACKAGES"
	},
	@{
		name = "vcpkg-Cache"
		dev = "$devDrivePackageDir\vcpkg"
		loc = "$env:LOCALAPPDATA\vcpkg\archives"
		var = "VCPKG_DEFAULT_BINARY_CACHE"
	},
	@{
		name = "Pip-Cache (Python)"
		dev = "$devDrivePackageDir\pip"
		loc = "$env:LOCALAPPDATA\pip\Cache"
		var = "PIP_CACHE_DIR"
	},
	@{
		name = "Cargo-Cache (Rust)"
		dev = "$devDrivePackageDir\cargo"
		loc = "$env:USERPROFILE\.cargo"
		var = "CARGO_HOME"
	},
	@{
		name = "Maven-Cache (Java)"
		dev = "$devDrivePackageDir\maven"
		loc = "$env:USERPROFILE\.m2"
		var = "MAVEN_OPTS"
		val = "-Dmaven.repo.local=$devDrivePackageDir\maven $env:MAVEN_OPTS"
	},
	@{
		name = "Gradle-Cache (Java)"
		dev = "$devDrivePackageDir\gradle"
		loc = "$env:USERPROFILE\.gradle"
		var = "GRADLE_USER_HOME"
	}
)

#Write-Host "Formatting drive"
#Format-Volume -DriveLetter $devDriveLetter -DevDrive

Write-Host "Preparing directories" -ForegroundColor Cyan
if (-Not (Test-Path $devDrivePackageDir))
{
	Write-Host "Creating directory $devDrivePackageDir"
	New-Item -Path $devDrivePackageDir -ItemType Directory -Force -ErrorAction Stop
}
else
{
	Write-Host "Directory $devDrivePackageDir already exists"
}
if (-Not (Test-Path $devDrivePowerShellDir))
{
	Write-Host "Creating directory $devDrivePowerShellDir"
	New-Item -Path $devDrivePowerShellDir -ItemType Directory -Force -ErrorAction Stop
}
else
{
	Write-Host "Directory $devDrivePowerShellDir already exists"
}
if (-Not (Test-Path "$devDrivePowerShellDir\Modules"))
{
	New-Item -Path "$devDrivePowerShellDir\Modules" -ItemType Directory -Force -ErrorAction Stop
}
if (-Not (Test-Path "$devDrivePowerShellDir\Scripts"))
{
	New-Item -Path "$devDrivePowerShellDir\Scripts" -ItemType Directory -Force -ErrorAction Stop
}

foreach($devRedirect in $devRedirects)
{
	Write-Host "Redirecting $($devRedirect.name)" -ForegroundColor Cyan
	if (-Not (Test-Path $devRedirect.dev))
	{
		Write-Host "  Creating $($devRedirect.dev)"
		New-Item -Path $devRedirect.dev -ItemType Directory -Force -ErrorAction Stop
	}
	else
	{
		Write-Host "  $($devRedirect.dev) already exists"
	}
	if (Test-Path $devRedirect.loc)
	{
		Write-Host "  Syncing source $($devRedirect.loc)"
		xcopy /devihrky $devRedirect.loc $devRedirect.dev
	}
	else
	{
		Write-Host "  No source $($devRedirect.loc) found"
	}
	if ($devRedirect.val)
	{
		Write-Host "  Setting env var $($devRedirect.var) to $($devRedirect.val)"
		setx /M $devRedirect.var $devRedirect.val
	}
	else
	{
		Write-Host "  Setting env var $($devRedirect.var) to $($devRedirect.dev)"
		setx /M $devRedirect.var $devRedirect.dev
	}
}

Write-Host "Setting PowerShell paths" -ForegroundColor Cyan
setx /M "PSModulePath" "$devDrivePowerShellDir\Modules;$env:PSModulePath"
setx /M "Path" "$devDrivePowerShellDir\Scripts;$env:Path"

Write-Host "Trusting the dev drive" -ForegroundColor Cyan
fsutil devdrv trust $devDriveDisk
fsutil devdrv query $devDriveDisk

Write-Host "Disabling AV on the dev drive" -ForegroundColor Cyan
fsutil devdrv enable /disallowAv
