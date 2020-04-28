$BKScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
& "$BKScriptDir\win_setup.ps1"

echo "!!! Chocolatey version !!!"
choco --version

echo "+++ bundle exec rspec chocolatey_package_spec"
bundle exec rspec spec/functional/resource/chocolatey_package_spec.rb
if (-not $?) { throw "Chef chocolatey functional tests failing." }
