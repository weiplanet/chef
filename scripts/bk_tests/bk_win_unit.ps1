$BKScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
& "$BKScriptDir\win_setup.ps1"

echo "+++ bundle exec rake"
bundle exec rake spec:unit
if (-not $?) { throw "Chef unit tests failing." }
bundle exec rake component_specs
if (-not $?) { throw "Chef component specs failing." }
