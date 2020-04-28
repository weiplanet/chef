echo "--- system details"
$Properties = 'Caption', 'CSName', 'Version', 'BuildType', 'OSArchitecture'
Get-CimInstance Win32_OperatingSystem | Select-Object $Properties | Format-Table -AutoSize

echo "--- configure winrm"
winrm quickconfig -q

echo "--- update bundler and rubygems"
echo "!!! Ruby Version !!!"
ruby -v
if (-not $?) { throw "Can't run Ruby. Is it installed?" }

$env:RUBYGEMS_VERSION=$(findstr rubygems omnibus_overrides.rb | %{ $_.split(" ")[3] })
$env:BUNDLER_VERSION=$(findstr bundler omnibus_overrides.rb | %{ $_.split(" ")[3] })

$env:RUBYGEMS_VERSION=($env:RUBYGEMS_VERSION -replace '"', "")
$env:BUNDLER_VERSION=($env:BUNDLER_VERSION -replace '"', "")

echo "RubyGems version: $env:RUBYGEMS_VERSION"
echo "Bundler version: $env:BUNDLER_VERSION"

echo "--- update rubygems"
gem update --system $env:RUBYGEMS_VERSION
if (-not $?) { throw "Unable to update system Rubygems" }
echo "!!! RubyGems version !!!"
gem --version

echo "--- update bundler"
gem install bundler -v $env:BUNDLER_VERSION --force --no-document --quiet
if (-not $?) { throw "Unable to update Bundler" }
echo "!!! bundler version !!!"
bundle --version

echo "--- bundle install project dependencies"
bundle install --jobs=3 --retry=3 --without omnibus_package docgen chefstyle
if (-not $?) { throw "Unable to install gem dependencies" }
