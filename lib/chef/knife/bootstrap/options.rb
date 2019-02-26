# Author:: Marc Paradise (<marc@chef.io>)
# Copyright:: Copyright 2019, Chef Software Inc.
# License:: Apache License, Version 2.0
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

module Chef
  module Knife
    class Bootstrap
      module Options
        def self.included(klass)
          # SSH - :host
          klass.option :ssh_user,
            short: "-x USERNAME",
            long: "--ssh-user USERNAME",
            description: "The ssh username",
            default: "root"

          # SSH - :password
          klass.option :ssh_password,
            short: "-P PASSWORD",
            long: "--ssh-password PASSWORD",
            description: "The ssh password"

          # SSH :port
          klass.option :ssh_port,
            short: "-p PORT",
            long: "--ssh-port PORT",
            description: "The ssh port",
            proc: Proc.new { |key| Chef::Config[:knife][:ssh_port] = key }

          # TODO SSH  train gives bastion_host which seeems to map to getway/gateway_identity -
          # though not exactly.
          klass.option :ssh_gateway,
            short: "-G GATEWAY",
            long: "--ssh-gateway GATEWAY",
            description: "The ssh gateway",
            proc: Proc.new { |key| Chef::Config[:knife][:ssh_gateway] = key }

          # TODO - missing in train: ssh_gateway_identity. But could just append to
          # keyfiles - train accepts multiple?
          # TODO - train supports bastion_user and bastion_port
          # SSH  - this just maps to key_files  - under knife-ssh we would use either this,
          # _or_ ssh_identity_file
          #        either this or 'ssh_identity_file' but not both.
          klass.option :ssh_gateway_identity,
            long: "--ssh-gateway-identity SSH_GATEWAY_IDENTITY",
            description: "The SSH identity file used for gateway authentication",
            proc: Proc.new { |key| Chef::Config[:knife][:ssh_gateway_identity] = key }

          # SSH train ssh: options[:forward_agent]
          klass.option :forward_agent,
            short: "-A",
            long: "--forward-agent",
            description: "Enable SSH agent forwarding",
            boolean: true

          # SSH train: options[key_files]
          klass.option :ssh_identity_file,
            short: "-i IDENTITY_FILE",
            long: "--ssh-identity-file IDENTITY_FILE",
            description: "The SSH identity file used for authentication"

          klass.option :chef_node_name,
            short: "-N NAME",
            long: "--node-name NAME",
            description: "The Chef node name for your new node"

          klass.option :prerelease,
            long: "--prerelease",
            description: "Install the pre-release chef gems"

          # client.rb
          klass.option :bootstrap_version,
            long: "--bootstrap-version VERSION",
            description: "The version of Chef to install",
            proc: lambda { |v| Chef::Config[:knife][:bootstrap_version] = v }

          # client.rb
          klass.option :bootstrap_proxy,
            long: "--bootstrap-proxy PROXY_URL",
            description: "The proxy server for the node being bootstrapped",
            proc: Proc.new { |p| Chef::Config[:knife][:bootstrap_proxy] = p }

          # client.rb
          klass.option :bootstrap_proxy_user,
            long: "--bootstrap-proxy-user PROXY_USER",
            description: "The proxy authentication username for the node being bootstrapped"

          # client.rb
          klass.option :bootstrap_proxy_pass,
            long: "--bootstrap-proxy-pass PROXY_PASS",
            description: "The proxy authentication password for the node being bootstrapped"

          # client.rb
          klass.option :bootstrap_no_proxy,
            long: "--bootstrap-no-proxy [NO_PROXY_URL|NO_PROXY_IP]",
            description: "Do not proxy locations for the node being bootstrapped; this klass.option is used internally by Opscode",
            proc: Proc.new { |np| Chef::Config[:knife][:bootstrap_no_proxy] = np }

          # client.rb
          klass.option :bootstrap_template,
            short: "-t TEMPLATE",
            long: "--bootstrap-template TEMPLATE",
            description: "Bootstrap Chef using a built-in or custom template. Set to the full path of an erb template or use one of the built-in templates."


          # bootstrap_context - client.rb
          klass.option :node_ssl_verify_mode,
            long: "--node-ssl-verify-mode [peer|none]",
            description: "Whether or not to verify the SSL cert for all HTTPS requests.",
            proc: Proc.new { |v|
              valid_values = %w{none peer}
              unless valid_values.include?(v)
                raise "Invalid value '#{v}' for --node-ssl-verify-mode. Valid values are: #{valid_values.join(", ")}"
              end
              v
            }

            # bootstrap_context - client.rb
            klass.option :node_verify_api_cert,
              long: "--[no-]node-verify-api-cert",
              description: "Verify the SSL cert for HTTPS requests to the Chef server API.",
              boolean: true

            # runtime, prefixes to ssh command.  train: [:sudo] - auto prefixes everything
            klass.option :use_sudo,
              long: "--sudo",
              description: "Execute the bootstrap via sudo",
              boolean: true

            # runtime - prefixes to ssh command string
            klass.option :preserve_home,
              long: "--sudo-preserve-home",
              description: "Preserve non-root user HOME environment variable with sudo",
              boolean: true

            # runtime - prefixes to ssh command string
            klass.option :use_sudo_password,
              long: "--use-sudo-password",
              description: "Execute the bootstrap via sudo with password",
              boolean: false

            # runtime - client_builder - set runlist when creating node
            klass.option :run_list,
              short: "-r RUN_LIST",
              long: "--run-list RUN_LIST",
              description: "Comma separated list of roles/recipes to apply",
              proc: lambda { |o| o.split(/[\s,]+/) },
              default: []

            # runtime - client_builder - set policy name when creating node
            klass.option :policy_name,
              long: "--policy-name POLICY_NAME",
              description: "Policyfile name to use (--policy-group must also be given)",
              default: nil

            # runtime - client_builder - set policy group when creating node
            klass.option :policy_group,
              long: "--policy-group POLICY_GROUP",
              description: "Policy group name to use (--policy-name must also be given)",
              default: nil

            # runtime - client_builder -  node tags
            klass.option :tags,
              long: "--tags TAGS",
              description: "Comma separated list of tags to apply to the node",
              proc: lambda { |o| o.split(/[\s,]+/) },
              default: []

            # runtime -  bootstrap template
            klass.option :first_boot_attributes,
              short: "-j JSON_ATTRIBS",
              long: "--json-attributes",
              description: "A JSON string to be added to the first run of chef-client",
              proc: lambda { |o| Chef::JSONCompat.parse(o) },
              default: nil

            # runtime -  bootstrap template
            klass.option :first_boot_attributes_from_file,
              long: "--json-attribute-file FILE",
              description: "A JSON file to be used to the first run of chef-client",
              proc: lambda { |o| Chef::JSONCompat.parse(File.read(o)) },
              default: nil

            # ssh options - train options[:verify_host_key]
            klass.option :host_key_verify,
              long: "--[no-]host-key-verify",
              description: "Verify host key, enabled by default.",
              boolean: true,
              default: true


            # bootstrap template
            # Create ohai hints in /etc/hef/ohai/hints, fname=hintname, content=value
            klass.option :hint,
              long: "--hint HINT_NAME[=HINT_FILE]",
              description: "Specify Ohai Hint to be set on the bootstrap target. Use multiple --hint options to specify multiple hints.",
              proc: Proc.new { |h|
                Chef::Config[:knife][:hints] ||= Hash.new
                name, path = h.split("=")
                Chef::Config[:knife][:hints][name] = path ? Chef::JSONCompat.parse(::File.read(path)) : Hash.new
              }

              # bootstrap overrides  that change bootstrap behavior - runs on target
              klass.option :bootstrap_url,
                long: "--bootstrap-url URL",
                description: "URL to a custom installation script",
                proc: Proc.new { |u| Chef::Config[:knife][:bootstrap_url] = u }

              klass.option :bootstrap_install_command,
                long: "--bootstrap-install-command COMMANDS",
                description: "Custom command to install chef-client",
                proc: Proc.new { |ic| Chef::Config[:knife][:bootstrap_install_command] = ic }

              klass.option :bootstrap_preinstall_command,
                long: "--bootstrap-preinstall-command COMMANDS",
                description: "Custom commands to run before installing chef-client",
                proc: Proc.new { |preic| Chef::Config[:knife][:bootstrap_preinstall_command] = preic }

              # runtime on target - can this go away with switch to train + actions - uses mixlib-install.
              klass.option :bootstrap_wget_options,
                long: "--bootstrap-wget-options OPTIONS",
                description: "Add options to wget when installing chef-client",
                proc: Proc.new { |wo| Chef::Config[:knife][:bootstrap_wget_options] = wo }

              # runtime - can this go away with switch to train + actions - uses mixlib-install.
              klass.option :bootstrap_curl_options,
                long: "--bootstrap-curl-options OPTIONS",
                description: "Add options to curl when install chef-client",
                proc: Proc.new { |co| Chef::Config[:knife][:bootstrap_curl_options] = co }

              klass.option :bootstrap_vault_file,
                long: "--bootstrap-vault-file VAULT_FILE",
                description: "A JSON file with a list of vault(s) and item(s) to be updated"

              klass.option :bootstrap_vault_json,
                long: "--bootstrap-vault-json VAULT_JSON",
                description: "A JSON string with the vault(s) and item(s) to be updated"

              klass.option :bootstrap_vault_item,
                long: "--bootstrap-vault-item VAULT_ITEM",
                description: 'A single vault and item to update as "vault:item"',
                proc: Proc.new { |i|
                  (vault, item) = i.split(/:/)
                  Chef::Config[:knife][:bootstrap_vault_item] ||= {}
                  Chef::Config[:knife][:bootstrap_vault_item][vault] ||= []
                  Chef::Config[:knife][:bootstrap_vault_item][vault].push(item)
                  Chef::Config[:knife][:bootstrap_vault_item]
                }

        end
      end
    end
  end
end
