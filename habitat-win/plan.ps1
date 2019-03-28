$pkg_name="chef-client"
$pkg_origin="stuartpreston"
$pkg_version=(Get-Content ../VERSION)
$pkg_upstream_url="https://github.com/chef/chef"
$pkg_revision="1"
$pkg_maintainer="Stuart Preston <stuart@chef.io>"
$pkg_license=@("Apache-2.0")
$pkg_bin_dirs=@("bin")
$pkg_build_deps=@("core/git", "stuartpreston/ruby-plus-devkit/2.6.1")

$src_gemspec_file="chef.gemspec"

function Invoke-Build {
    # Start by making a shallow copy of the Ruby+Devkit installation, but exclude Habitat-specific files.
    $devkit_location = Get-HabPackagePath("ruby-plus-devkit")
    New-Item -Path $pkg_prefix -ItemType Directory -Force | Out-Null
    Copy-Item -Path $devkit_location/* -Destination $pkg_prefix -Recurse -Exclude @("config", "hooks", "default.toml", "IDENT", "MANIFEST", "PATH", "run", "RUNTIME_ENVIRONMENT", "RUNTIME_PATH", "SVC_GROUP", "SVC_USER", "TARGET") -Force

    # We need to start from the root of the repo (the location of the Gemspec.lock) and let's assume it's one directory higher than the plan.
    Push-Location $PLAN_CONTEXT/../

    # The following section is required because core/git on Windows does not allow a binlink for bash.exe to work.
    # Bundler uses this internally via git-reverse-pack.exe when resolving git: references in the Gemfile.lock.
    # The workaround applied below uses the git.exe binlink to manually retrieve those references specified in the Gemfile.lock
    # and overrides bundler to use the folder paths directly to resolve the named components, allowing bundle package to resolve
    # all the required packages. The manually retrieves references are built using gem build and copied to the same cache location.
    Write-BuildLine "Detecting Git-based references in gemfile.lock"
    $gemfile_lock_gitrefs = (ruby -rbundler -rjson -e "puts Bundler::LockfileParser.new(Bundler.read_file(Bundler.default_lockfile)).specs.select{|spec|spec.source.class == Bundler::Source::Git}.map{|ref| ref.source.options.merge(name: ref.source.name)}.to_json") | ConvertFrom-Json

    foreach($gitref in $gemfile_lock_gitrefs) {
        $gitref_path = "$PLAN_CONTEXT/../{0}" -f $gitref.name
        if (Test-Path -Path $gitref_path) { 
            Remove-Item -Path $gitref_path -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -Path $gitref_path -ItemType Directory | Out-Null
        }
        try {
            git clone $gitref.uri
            Push-Location $gitref_path
            git checkout $gitref.branch
            git reset --hard $gitref.revision
            Invoke-Expression -Command ("gem build {0}" -f ($gitref.name + ".gemspec"))
            Get-ChildItem *.gem  | Copy-Item -Destination $HAB_CACHE_SRC_PATH/$pkg_dirname
        } finally {
            Pop-Location
            Invoke-Expression -Command ("bundle config local.{0} {1}" -f @($gitref.name, (Resolve-Path $gitref_path).Path))
        }
    }

    # now make sure the path references can be found as well
    Write-BuildLine "Detecting path-based references in gemfile.lock"
    $gemfile_lock_pathrefs = (ruby -rbundler -rjson -e "puts Bundler::LockfileParser.new(Bundler.read_file(Bundler.default_lockfile)).specs.select{|spec|spec.source.class == Bundler::Source::Path}.map{|ref| ref.source.options.merge(name: ref.source.name)}.uniq.to_json") | ConvertFrom-Json

    foreach($pathref in $gemfile_lock_pathrefs) {
        if ($pathref.path -eq ".") {
            Invoke-Expression -Command ("gem build {0}" -f $src_gemspec_file)
            Get-ChildItem *.gem  | Copy-Item -Destination $HAB_CACHE_SRC_PATH/$pkg_dirname
        }
        else {
            $pathref_path = "$PLAN_CONTEXT/../{0}" -f $pathref.name
            Invoke-Expression -Command ("bundle config local.{0} {1}" -f @($pathref.name, (Resolve-Path $pathref_path).Path))
            try {
                Push-Location $pathref_path
                Invoke-Expression -Command ("gem build {0}" -f ($pathref.name + ".gemspec"))
                Get-ChildItem *.gem  | Copy-Item -Destination $HAB_CACHE_SRC_PATH/$pkg_dirname
            } finally {
                Pop-Location
            }
        }
    }

    # Bundle install from the source into the vendor/cache directory to acquire the relevant gems (this location can't be overridden).
    bundle package --no-install
}
function Invoke-Install {
    # Copy any vendored gems from the build phase into the cache path
    Get-ChildItem $PLAN_CONTEXT/../vendor/cache/* | Copy-Item -Destination $HAB_CACHE_SRC_PATH/$pkg_dirname

    # Now install our built gems into the new Ruby folder structure that is under assembly.
    $gem_in_pkg_prefix = Resolve-Path "$pkg_prefix/bin/gem.cmd"
    Invoke-Expression -Command ("$gem_in_pkg_prefix install {0} --force --no-update-sources --local --no-document --conservative --no-env-shebang" -f "$HAB_CACHE_SRC_PATH/$pkg_dirname/*.gem")

    # Cleanup some files that are no longer necessary before packaging
    Get-ChildItem $pkg_prefix/lib/ruby/gems/$ruby_path_version/gems -Filter "spec" -Recurse | Remove-Item -Recurse -Force
    Get-ChildItem $pkg_prefix/lib/ruby/gems/$ruby_path_version/cache -Recurse | Remove-Item -Recurse -Force
    Get-ChildItem $pkg_prefix -Filter "unins000.*" | Remove-Item -Recurse -Force
    Get-ChildItem $pkg_prefix -Filter "share" | Remove-Item -Recurse -Force
}