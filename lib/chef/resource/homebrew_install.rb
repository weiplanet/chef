#
# Copyright:: Copyright (c) Chef Software Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require_relative "../resource"

class Chef
  class Resource
    class HomebrewInstall < Chef::Resource
      unified_mode true

      provides :homebrew_install

      description "Use the **homebrew_install** resource to install the Homebrew package manager on macOS systems."
      introduced "16.7"
      examples <<~DOC
      **Install Homebrew using the Internet to download Command Line Tools for Xcode**:

      ```ruby
      homebrew_install 'Install Homebrew and xcode command line tools if necessary' do
        user 'someuser'
        action :install
      end
      ```

      **Install Homebrew using a local source to download Command Line Tools for Xcode from**:

      ```ruby
      homebrew_install 'Install Homebrew and xcode command line tools if necessary' do
        tools_url 'https://somewhere.something.com/downloads/command_line_tools.dmg'
        tools_pkg_name 'Command Line Tools.pkg'
        user 'someuser'
        action :install
      end
      ```
      DOC

      property :tools_url, String,
        description: "A url pointing to a local source for the Command Line Tools for Xcode dmg"

      property :tools_pkg_name, String,
        description: "The name of the pkg inside the dmg located at the tools url"

      property :brew_source, String,
        description: "A url pointing to a Homebrew installer",
        default: "https://github.com/Homebrew/brew/tarball/master"

      property :user, String,
        description: "The user to install Homebrew as. Note: Homebrew cannot be installed as root.",
        required: true

      action :install do
        # Avoid all the work in the below resources if homebrew is already installed
        return if ::File.exist?("/usr/local/bin/brew")

        if new_resource.tools_url
          dmg_package new_resource.tools_pkg_name do
            source new_resource.tools_url
            type "pkg"
          end
        else
          build_essential "install Command Line Tools for Xcode" do
            action :install
          end
        end

        directory "/usr/local/Homebrew"

        remote_file "download the Homebrew archive" do
          path "#{Chef::Config[:file_cache_path]}/homebrew.tar.gz"
          source new_resource.brew_source
          action :create
        end

        execute "extract homebrew package" do
          creates "/usr/local/Homebrew/bin/brew"
          command "tar xf #{Chef::Config[:file_cache_path]}/homebrew.tar.gz --directory /usr/local/Homebrew --strip-components=1"
        end

        bash "create /usr/local dirs and set permissions" do
          code <<-QED
            mkdir /usr/local/share || true
            mkdir /usr/local/etc || true
            mkdir /usr/local/var || true
            mkdir /usr/local/var/homebrew  || true
            chown -R #{new_resource.user} /usr/local/Homebrew
            chown -R #{new_resource.user} /usr/local/var/homebrew
            chown -R #{new_resource.user} /usr/local/etc
            chown -R #{new_resource.user} /usr/local/share
          QED
        end
      end
    end
  end
end
