#
# Author:: Adam Jacob (<adam@chef.io>)
# Copyright:: Copyright 2010-2019, Chef Software Inc.
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

require "chef/knife"
require "chef/knife/data_bag_secret_options"
require "erubis"
require "chef/knife/bootstrap/chef_vault_handler"
require "chef/knife/bootstrap/client_builder"
require "chef/util/path_helper"
require "chef/knife/bootstrap/options"

class Chef
  class Knife
    class Bootstrap < Knife
      include DataBagSecretOptions

      # Command line flags and options for bootstrap - there's a large number of them
      # so we'll keep this file a little smaller by splitting them out.
      include Bootstrap::Options

      attr_accessor :client_builder
      attr_accessor :chef_vault_handler
      attr_reader   :target_host

      deps do
        require "chef/json_compat"
        require "tempfile"
        require "chef_core/text" # i18n and standardized error structures
        require "chef_core/target_host"
        require "chef_core/target_resolver"

        # Because nothing else is using i18n out of Chef::Text yet, we're treating it
        # as a dependency to avoid loading localization files before we need them.
        ChefCore::Text.add_gem_localization("chef")
      end

      banner "knife bootstrap [PROTOCOL://][USER@]FQDN (options)"

      def initialize(argv = [])
        super
        # TODO - these map cleanly to action support classes
        @client_builder = Chef::Knife::Bootstrap::ClientBuilder.new(
          chef_config: Chef::Config,
          knife_config: config,
          ui: ui
        )
        @chef_vault_handler = Chef::Knife::Bootstrap::ChefVaultHandler.new(
          knife_config: config,
          ui: ui
        )
      end

      # The default bootstrap template to use to bootstrap a server.
      # This is a public API hook which knife plugins use or inherit and override.
      #
      # @return [String] Default bootstrap template
      def default_bootstrap_template
        if target_host.base_os == :windows
          "windows-chef-client-msi"
        else
          "chef-full"
        end
      end

      def host_descriptor
        Array(@name_args).first
      end

      # The server_name is the DNS or IP we are going to connect to, it is not necessarily
      # the node name, the fqdn, or the hostname of the server.  This is a public API hook
      # which knife plugins use or inherit and override.
      #
      # @return [String] The DNS or IP that bootstrap will connect to
      def server_name
        if host_descriptor
          @server_name ||= host_descriptor.split("@").reverse[0]
        end
      end


      # @return [String] The CLI specific bootstrap template or the default
      def bootstrap_template
        # Allow passing a bootstrap template or use the default
        config[:bootstrap_template] || default_bootstrap_template
      end

      def find_template
        template = bootstrap_template

        # Use the template directly if it's a path to an actual file
        if File.exists?(template)
          Chef::Log.trace("Using the specified bootstrap template: #{File.dirname(template)}")
          return template
        end

        # Otherwise search the template directories until we find the right one
        bootstrap_files = []
        bootstrap_files << File.join(File.dirname(__FILE__), "bootstrap/templates", "#{template}.erb")
        bootstrap_files << File.join(Knife.chef_config_dir, "bootstrap", "#{template}.erb") if Chef::Knife.chef_config_dir
        Chef::Util::PathHelper.home(".chef", "bootstrap", "#{template}.erb") { |p| bootstrap_files << p }
        bootstrap_files << Gem.find_files(File.join("chef", "knife", "bootstrap", "#{template}.erb"))
        bootstrap_files.flatten!

        template_file = Array(bootstrap_files).find do |bootstrap_template|
          Chef::Log.trace("Looking for bootstrap template in #{File.dirname(bootstrap_template)}")
          File.exists?(bootstrap_template)
        end

        unless template_file
          ui.info("Can not find bootstrap definition for #{template}")
          raise Errno::ENOENT
        end

        Chef::Log.trace("Found bootstrap template in #{File.dirname(template_file)}")

        template_file
      end

      def secret
        @secret ||= encryption_secret_provided_ignore_encrypt_flag? ? read_secret : nil
      end

      def bootstrap_context
        @bootstrap_context ||=
          if target_host.base_os == :windows

            require "chef/knife/core/windows_bootstrap_context"
            Knife::Core::WindowsBootstrapContext.new(config, config[:run_list],
                                                     Chef::Config, secret)
          else
            require "chef/knife/core/bootstrap_context"
            Knife::Core::BootstrapContext.new(config, config[:run_list],
                                              Chef::Config, secret)
          end
      end

      def first_boot_attributes
        @config[:first_boot_attributes] || @config[:first_boot_attributes_from_file] || {}
      end

      def render_template
        @config[:first_boot_attributes] = first_boot_attributes
        template_file = find_template
        template = IO.read(template_file).chomp
        Erubis::Eruby.new(template).evaluate(bootstrap_context)
      end

      def run
        if @config[:first_boot_attributes] && @config[:first_boot_attributes_from_file]
          raise Chef::Exceptions::BootstrapCommandInputError
        end

        validate_name_args!
        validate_options!

        $stdout.sync = true

        # chef-vault integration must use the new client-side hawtness, otherwise to use the
        # new client-side hawtness, just delete your validation key.
        if chef_vault_handler.doing_chef_vault? ||
            (Chef::Config[:validation_key] && !File.exist?(File.expand_path(Chef::Config[:validation_key])))

          unless config[:chef_node_name]
            ui.error("You must pass a node name with -N when bootstrapping with user credentials")
            exit 1
          end

          client_builder.run

          chef_vault_handler.run(client_builder.client)

        else
          ui.info("Doing old-style registration with the validation key at #{Chef::Config[:validation_key]}...")
          ui.info("Delete your validation key in order to use your user credentials instead")
          ui.info("")
        end

        ui.info("Connecting to #{ui.color(server_name, :bold)}")

        begin
          # Resolve the given host name to a TargetHost instance. We will limit
          # the number of hosts to 1 (effectivly eliminating wildcard support) since
          # we only support running bootstrap against one host at a time.
          resolver = ChefCore::TargetResolver.new(host_descriptor, config[:protocol] || "ssh",
                                                  connection_opts, max_expanded_targets: 1)
          @target_host = resolver.targets.first
          # rescue: TargetResolverError
          target_host.connect!
          # Now that we have a connected target_host, we can use (by referencing it...)
          # "bootstrap_context".
          unless client_builder.client_path.nil?
            bootstrap_context.client_pem = client_builder.client_path
          end
          bootstrap_path = render_and_upload_bootstrap
          r = target_host.run_command(bootstrap_command(bootstrap_path))
          if r.exit_status != 0
            ui.error("The following error occurred on #{server_name}:")
            ui.error(r.stderr)
            exit 1
          end

          # TODO mp 2019-02-22 this *should* be the same behavior under train without
          # forcing the behavior here, but we need to verify that.
          #
          # rescue Net::SSH::AuthenticationFailed
          #   if config[:password]
          #     raise
          #   else
          #     ui.info("Failed to authenticate #{knife_ssh.config[:user]} - trying password auth")
          #     knife_ssh_with_password_auth.run
          # def knife_ssh_with_password_auth
          #   # prompt for a password then return a knife ssh object with that password set
          #   # and with ssh_identity_file set to nil
          #   ssh = knife_ssh
          #   ssh.config[:ssh_identity_file] = nil
          #   ssh.config[:password] = ssh.get_password
          #   ssh
          # end
          #   end
        end
      end

      # fail if the server_name is nil
      def validate_name_args!
        if server_name.nil?
          ui.error("Must pass an FQDN or ip to bootstrap")
          exit 1
        end
      end

      # Ensure options are valid by checking policyfile values.
      #
      # The method call will cause the program to exit(1) if:
      #   * Only one of --policy-name and --policy-group is specified
      #   * Policyfile options are set and --run-list is set as well
      #
      # @return [TrueClass] If options are valid.
      def validate_options!
        if incomplete_policyfile_options?
          ui.error("--policy-name and --policy-group must be specified together")
          exit 1
        elsif policyfile_and_run_list_given?
          ui.error("Policyfile options and --run-list are exclusive")
          exit 1
        end
        true
      end

      def connection_protocol

      end


      # Createa configuration object based on setup a Chef::Knife::Ssh object using the passed config options
      #
      # @return a configuration hash suitable for connecting to the remote host.
      def connection_opts
        # Mapping of our options ot train options - they're pretty similar with removal of
        # the ssh- prefix, but there's more to corre2ct
        # TODO - is now the time to change flag names for consistency?
        opts = {
          port: config[:port], # Default if it's not in the connection string
          user: config[:user], #  "
          password: config[:password], # TODO - check if we need to exclude if not set, diff behavior for nil?
          key_files: config[:ssh_identity_file],
          logger:  Chef::Log,
          # WinRM options - they will be ignored for ssh
          # TODO train will throw if this is not valid, should be OK as-is
          winrm_transport: config[:winrm_transport],
          self_signed: config[:winrm_self_signed_cert],
          ssl: config[:winrm_ssl]
        }

        if config[:use_sudo]
          opts[:sudo] = true
          # TODO this preserves original logic - we're using the provided password for sudo
          # if sudo is enabled.  Note that train supports a separate sudo password.
          # TODO - check original, what if password was not given? Where do we validate?
          if opts[:use_sudo_password]
            opts[:sudo_password] = config[:password]
          end
          if opts[:preserve_home]
             opts[:sudo_options] = "-H"
          end
        end

        if config[:password]
          opts[:password] = config[:password]
        end

        if config[:ssh_identity_file]
          # TODO - to get the matching original knife bootstrap fallback behavior of prompting for password
          # when we don't provide it, I think we'll want  to _not_ do this here - we should get automatic
          # keyboard-interactive auth if we don't set this and key fails.
          opts[:keys_only] = true
        end
        # ssh.config[:ssh_gateway_identity] = config[:ssh_gateway_identity]
        # ssh.config[:forward_agent] = config[:forward_agent]
        # ssh.config[:ssh_identity_file] = config[:ssh_identity_file]
        # ssh.config[:manual] = true
        # TODO train appears to false this to always false.  We'll need to make it an option.
        # ssh.config[:host_key_verify] = config[:host_key_verify]
        # ssh.config[:on_error] = true
        # TODO: proxy command
        # TODO - ssh_identity_file and ssh_gateway_identity appear to be implemented
        #        as mutually exclsuive in knife ssh. Is there a valid case for two keys?
        #        If so, train should accept more than one.
        # key_files << config[:ssh_identity_file]
        # TODO _ we're forcing knife ssh :on_error to true which will cause immediate exit on problem.
        #        Need to see what that means, and if we have to implement anything in train to support it.
        # option :on_error,
        # short: "-e",
        # long: "--exit-on-error",
        # description: "Immediately exit if an error is encountered.",
        opts
      end



      def render_and_upload_bootstrap
        content = render_template
        script_name = target_host.base_os == :windows ? "bootstrap.bat" : "bootstrap.sh"
        remote_path = target_host.normalize_path(File.join(target_host.temp_dir, script_name))
        target_host.save_as_remote_file(content, remote_path)
        remote_path
      end


      # build the command string for bootrapping
      # @return String
      def bootstrap_command(remote_path)
        if target_host.base_os == :windows
          "cmd.exe /C #{remote_path}"
        else
          "sh #{remote_path} "
        end
      end

      private

      # True if policy_name and run_list are both given
      def policyfile_and_run_list_given?
        run_list_given? && policyfile_options_given?
      end

      def run_list_given?
        !config[:run_list].nil? && !config[:run_list].empty?
      end

      def policyfile_options_given?
        !!config[:policy_name]
      end

      # True if one of policy_name or policy_group was given, but not both
      def incomplete_policyfile_options?
        (!!config[:policy_name] ^ config[:policy_group])
      end

    end
  end
end
