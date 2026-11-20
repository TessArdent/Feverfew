# Builds Feverfew and runs its headless tests. Prints PASS or FAIL as the last line.
# Needs the .NET SDK (8 or later) and the Windows SDK's signtool (10.0.26100.0, x64).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

foreach ($project in 'src\Feverfew\Feverfew.csproj', 'tests\Feverfew.Tests\Feverfew.Tests.csproj') {
    dotnet build $project -c Release --nologo -v q
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL (build of $project)"; exit 1 }
}

& 'tests\Feverfew.Tests\bin\Release\net48\Feverfew.Tests.exe'
exit $LASTEXITCODE
