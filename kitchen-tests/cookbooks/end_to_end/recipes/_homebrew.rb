#
# Cookbook:: end_to_end
# Recipe:: tests
#
# Copyright:: Copyright (c) Chef Software Inc.
#

user "homebrew_user"

homebrew_install "install homebrew" do
  user "homebrew_user"
end

homebrew_update "update" do
  action :update
end

homebrew_package "vim"

homebrew_package "vim" do
  action :purge
end