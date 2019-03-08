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

class Chef
  class Knife
    class Bootstrap
      module Options
        def self.included(includer)
          includer.class_eval do
            # Common connectivity options
            option :user,  # TODO - deprecate ssh_user which this replaces
              short: "-u USERNAME",
              long: "--user USERNAME",
              description: "The remote user to connect as"

            option :password, # TODO - deprecate ssh_password
              short: "-P PASSWORD",
              long: "--ssh-password PASSWORD",
              description: "The password of the remote user."

            option :port,
              short: "-p PORT",
              long: "--ssh-port PORT",
              description: "The port on the target node to connect to.",

              proc: Proc.new { |key| Chef::Config[:knife][:ssh_port] = key }

            option :protocol,
              short: "-o PROTOCOL",
              long: "--protocol PROTOCOL",
              description: "The protocol to use to connect to the target node.  Supports ssh and winrm."

            # TODO SSH  train gives bastion_host which seeems to map to getway/gateway_identity -
            # though not exactly.
            option :ssh_gateway,
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
            option :ssh_gateway_identity,
              long: "--ssh-gateway-identity SSH_GATEWAY_IDENTITY",
              description: "The SSH identity file used for gateway authentication",
              proc: Proc.new { |key| Chef::Config[:knife][:ssh_gateway_identity] = key }

            # SSH train ssh: options[:forward_agent]
            option :forward_agent,
              short: "-A",
              long: "--forward-agent",
              description: "Enable SSH agent forwarding",
              boolean: true

            # SSH train: options[key_files]
            option :ssh_identity_file,
              short: "-i IDENTITY_FILE",
              long: "--ssh-identity-file IDENTITY_FILE",
              description: "The SSH identity file used for authentication"

            # ssh options - train options[:verify_host_key]
            option :host_key_verify,
              long: "--[no-]host-key-verify",
              description: "Verify host key, enabled by default.",
              boolean: true,
              default: true

            # argument to installer in chef-full, via bootstrap_context
            option :prerelease,
              long: "--prerelease",
              description: "Install the pre-release chef gems"

            # client.rb content via chef-full/bootstrap_context
            option :bootstrap_version,
              long: "--bootstrap-version VERSION",
              description: "The version of Chef to install",
              proc: lambda { |v| Chef::Config[:knife][:bootstrap_version] = v }

            # client.rb content via chef-full/bootstrap_context
            option :bootstrap_proxy,
              long: "--bootstrap-proxy PROXY_URL",
              description: "The proxy server for the node being bootstrapped",
              proc: Proc.new { |p| Chef::Config[:knife][:bootstrap_proxy] = p }

            # client.rb content via bootstrap_context
            option :bootstrap_proxy_user,
              long: "--bootstrap-proxy-user PROXY_USER",
              description: "The proxy authentication username for the node being bootstrapped"

            # client.rb content via bootstrap_context
            option :bootstrap_proxy_pass,
              long: "--bootstrap-proxy-pass PROXY_PASS",
              description: "The proxy authentication password for the node being bootstrapped"

            # client.rb content via bootstrap_context
            option :bootstrap_no_proxy,
              long: "--bootstrap-no-proxy [NO_PROXY_URL|NO_PROXY_IP]",
              description: "Do not proxy locations for the node being bootstrapped; this option is used internally by Chef",
              proc: Proc.new { |np| Chef::Config[:knife][:bootstrap_no_proxy] = np }

            # client.rb content via bootstrap_context
            option :bootstrap_template,
              short: "-t TEMPLATE",
              long: "--bootstrap-template TEMPLATE",
              description: "Bootstrap Chef using a built-in or custom template. Set to the full path of an erb template or use one of the built-in templates."

            # client.rb content via bootstrap_context
            option :node_ssl_verify_mode,
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
              option :node_verify_api_cert,
                long: "--[no-]node-verify-api-cert",
                description: "Verify the SSL cert for HTTPS requests to the Chef server API.",
                boolean: true

              # runtime, prefixes to ssh command.  train: [:sudo] - auto prefixes everything
              option :use_sudo,
                long: "--sudo",
                description: "Execute the bootstrap via sudo",
                boolean: true

              # runtime - prefixes to ssh command string
              option :preserve_home,
                long: "--sudo-preserve-home",
                description: "Preserve non-root user HOME environment variable with sudo",
                boolean: true

              # runtime - prefixes to ssh command string
              option :use_sudo_password,
                long: "--use-sudo-password",
                description: "Execute the bootstrap via sudo with password",
                boolean: false

              # runtime - client_builder
              option :chef_node_name,
                short: "-N NAME",
                long: "--node-name NAME",
                description: "The Chef node name for your new node"

              # runtime - client_builder - set runlist when creating node
              option :run_list,
                short: "-r RUN_LIST",
                long: "--run-list RUN_LIST",
                description: "Comma separated list of roles/recipes to apply",
                proc: lambda { |o| o.split(/[\s,]+/) },
                default: []

              # runtime - client_builder - set policy name when creating node
              option :policy_name,
                long: "--policy-name POLICY_NAME",
                description: "Policyfile name to use (--policy-group must also be given)",
                default: nil

              # runtime - client_builder - set policy group when creating node
              option :policy_group,
                long: "--policy-group POLICY_GROUP",
                description: "Policy group name to use (--policy-name must also be given)",
                default: nil

              # runtime - client_builder -  node tags
              option :tags,
                long: "--tags TAGS",
                description: "Comma separated list of tags to apply to the node",
                proc: lambda { |o| o.split(/[\s,]+/) },
                default: []

              # bootstrap template
              option :first_boot_attributes,
                short: "-j JSON_ATTRIBS",
                long: "--json-attributes",
                description: "A JSON string to be added to the first run of chef-client",
                proc: lambda { |o| Chef::JSONCompat.parse(o) },
                default: nil

              # bootstrap template
              option :first_boot_attributes_from_file,
                long: "--json-attribute-file FILE",
                description: "A JSON file to be used to the first run of chef-client",
                proc: lambda { |o| Chef::JSONCompat.parse(File.read(o)) },
                default: nil

              # bootstrap template
              # Create ohai hints in /etc/chef/ohai/hints, fname=hintname, content=value
              option :hint,
                long: "--hint HINT_NAME[=HINT_FILE]",
                description: "Specify Ohai Hint to be set on the bootstrap target. Use multiple --hint options to specify multiple hints.",
                proc: Proc.new { |h|
                  Chef::Config[:knife][:hints] ||= Hash.new
                  name, path = h.split("=")
                  Chef::Config[:knife][:hints][name] = path ? Chef::JSONCompat.parse(::File.read(path)) : Hash.new
                }

                # bootstrap override: url of a an installer shell script touse in place of omnitruck
                # TODO - this replaces --msi-url out of knife windows bootstrap
                option :bootstrap_url,
                  long: "--bootstrap-url URL",
                  description: "URL to a custom installation script",
                  proc: Proc.new { |u| Chef::Config[:knife][:bootstrap_url] = u }


                # bootstrap override: Do this instead of our own setup.sh from omnitruck. Causes bootstrap_url to be ignored.
                option :bootstrap_install_command,
                  long: "--bootstrap-install-command COMMANDS",
                  description: "Custom command to install chef-client",
                  proc: Proc.new { |ic| Chef::Config[:knife][:bootstrap_install_command] = ic }

                # bootstrap template: Run this command first in the bootstrap script
                option :bootstrap_preinstall_command,
                  long: "--bootstrap-preinstall-command COMMANDS",
                  description: "Custom commands to run before installing chef-client",
                  proc: Proc.new { |preic| Chef::Config[:knife][:bootstrap_preinstall_command] = preic }

                # bootstrap template
                option :bootstrap_wget_options,
                  long: "--bootstrap-wget-options OPTIONS",
                  description: "Add options to wget when installing chef-client",
                  proc: Proc.new { |wo| Chef::Config[:knife][:bootstrap_wget_options] = wo }

                # bootstrap template
                option :bootstrap_curl_options,
                  long: "--bootstrap-curl-options OPTIONS",
                  description: "Add options to curl when install chef-client",
                  proc: Proc.new { |co| Chef::Config[:knife][:bootstrap_curl_options] = co }

                # chef_vault_handler
                option :bootstrap_vault_file,
                  long: "--bootstrap-vault-file VAULT_FILE",
                  description: "A JSON file with a list of vault(s) and item(s) to be updated"

                # chef_vault_handler
                option :bootstrap_vault_json,
                  long: "--bootstrap-vault-json VAULT_JSON",
                  description: "A JSON string with the vault(s) and item(s) to be updated"

                # chef_vault_handler
                option :bootstrap_vault_item,
                  long: "--bootstrap-vault-item VAULT_ITEM",
                  description: 'A single vault and item to update as "vault:item"',
                  proc: Proc.new { |i|
                    (vault, item) = i.split(/:/)
                    Chef::Config[:knife][:bootstrap_vault_item] ||= {}
                    Chef::Config[:knife][:bootstrap_vault_item][vault] ||= []
                    Chef::Config[:knife][:bootstrap_vault_item][vault].push(item)
                    Chef::Config[:knife][:bootstrap_vault_item]
                  }

                  # TODO
                  # Windows only
                  option :install_as_service,
                    :long => "--install-as-service",
                    :description => "Install chef-client as a Windows service. (Windows only)",
                    :default => false

                  # Windows only
                  option :winrm_self_signed_cert,
                    long: "--winrm-self-signed-cert",
                    :description => "Expect a self-signed certificate when transport is 'ssl'. Defaults to false.",
                    :default => false

                  option :winrm_transport,
                    long: "--winrm-transport TRANSPORT",
                    :description => "Specify WinRM transport. Supported values are ssl, plaintext, Defaults to 'negotiate'.",
                    :default => "negotiate"

                  option :winrm_ssl,
                    long: "--winrm-ssl",
                    :description => "Connect to WinRM over HTTPS. Defaults to false",
                    :default => false

                  option :winrm_codepage,
                    :long => "--winrm-codepage Codepage",
                    :description => "The codepage to use for the winrm cmd shell",
                    :default => 65001
                  # TODO - bootstrap - compat in train?
                  option :ssl_peer_fingerprint,
                    :long => "--ssl-peer-fingerprint FINGERPRINT",
                    :description => "ssl Cert Fingerprint to bypass normal cert chain checks"

                  option :winrm_port,
                    :short => "-p PORT",
                    :long => "--winrm-port PORT",
                    :description => "The WinRM port, by default this is '5985' for 'plaintext' and '5986' for 'ssl' winrm transport",
                    :default => '5985',
                    :proc => Proc.new { |key| Chef::Config[:knife][:winrm_port] = key }

                  option :winrm_shell, # bootstrap only works with cmd
                    :long => "--winrm-shell SHELL",
                    :description => "The WinRM shell type. Valid choices are [cmd, powershell, elevated]. 'elevated' runs powershell in a scheduled task",
                    :default => :cmd,
                    :proc => Proc.new { |shell| shell.to_sym }

                  option :ca_trust_file,
                    :short => "-f CA_TRUST_FILE",
                    :long => "--ca-trust-file CA_TRUST_FILE",
                    :description => "The Certificate Authority (CA) trust file used for SSL transport",
                    :proc => Proc.new { |trust| Chef::Config[:knife][:ca_trust_file] = trust }

                  option :winrm_authentication_protocol,
                    :long => "--winrm-authentication-protocol AUTHENTICATION_PROTOCOL",
                    :description => "The authentication protocol used during WinRM communication. The supported protocols are #{WINRM_AUTH_PROTOCOL_LIST.join(',')}. Default is 'negotiate'.",
                    :default => "negotiate",
                    :proc => Proc.new { |protocol| Chef::Config[:knife][:winrm_authentication_protocol] = protocol }
                  option :winrm-ssl,
                    winrm_transport,
                    :short => "-w TRANSPORT",
                    :long => "--winrm-transport TRANSPORT",
                    :description => "The WinRM transport type. Valid choices are [ssl, plaintext]",
                    :default => 'plaintext',
                    :proc => Proc.new { |transport| Chef::Config[:knife][:winrm_port] = '5986' if transport == 'ssl'
                                        Chef::Config[:knife][:winrm_transport] = transport }

                  option :kerberos_keytab_file,
                    :short => "-T KEYTAB_FILE",
                    :long => "--keytab-file KEYTAB_FILE",
                    :description => "The Kerberos keytab file used for authentication",
                    :proc => Proc.new { |keytab| Chef::Config[:knife][:kerberos_keytab_file] = keytab }

                  option :kerberos_realm,
                    :short => "-R KERBEROS_REALM",
                    :long => "--kerberos-realm KERBEROS_REALM",
                    :description => "The Kerberos realm used for authentication",
                    :proc => Proc.new { |realm| Chef::Config[:knife][:kerberos_realm] = realm }

                  option :kerberos_service,
                    :short => "-S KERBEROS_SERVICE",
                    :long => "--kerberos-service KERBEROS_SERVICE",
                    :description => "The Kerberos service used for authentication",
                    :proc => Proc.new { |service| Chef::Config[:knife][:kerberos_service] = service }
          end
        end
      end
    end
  end
end
