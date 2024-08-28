{ pkgs, lib, matrix-lib, config, ... }:
with lib;
let
  matrix-lib = (import ../lib.nix { inherit lib; });

  cfg = config.services.matrix-synapse;
  wcfg = cfg.workers;
  format = pkgs.formats.yaml { };

  filterRecursiveNull = o:
    if isAttrs o then
      mapAttrs (_: v: filterRecursiveNull v) (filterAttrs (_: v: v != null) o)
    else if isList o then
      map filterRecursiveNull (filter (v: v != null) o)
    else
      o;

  # remove null values from the final configuration
  finalSettings = filterRecursiveNull cfg.settings;
  configFile = format.generate "homeserver.yaml" finalSettings;

  # Used to generate proper defaultTexts.
  cfgText = "config.services.matrix-synapse";
  wcfgText = "config.services.matrix-synapse.workers";

  matrix-synapse-common-config = format.generate "matrix-synapse-common-config.yaml" (cfg.settings // {
    listeners = map (lib.filterAttrsRecursive (_: v: v != null)) cfg.settings.listeners;
  });


  usePostgresql = cfg.settings.database.name == "psycopg2";
  hasLocalPostgresDB = let args = cfg.settings.database.args; in
    usePostgresql
    && (!(args ? host) || (elem args.host [ "localhost" "127.0.0.1" "::1" ]))
    && config.services.postgresql.enable;
  hasWorkers = cfg.workers != { };

  defaultExtras = [
    "systemd"
    "postgres"
    "url-preview"
    "redis"
    "user-search"
  ];

  wrapped = pkgs.matrix-synapse.override {
    extras = defaultExtras;
    inherit (cfg) plugins;
  };

  defaultCommonLogConfig = {
    version = 1;
    formatters.journal_fmt.format = "%(name)s: [%(request)s] %(message)s";
    handlers.journal = {
      class = "systemd.journal.JournalHandler";
      formatter = "journal_fmt";
    };
    root = {
      level = "DEBUG";
      handlers = [ "journal" ];
    };
    disable_existing_loggers = false;
  };

  defaultCommonLogConfigText = generators.toPretty { } defaultCommonLogConfig;

  logConfigText = logName:
    lib.literalMD ''
      Path to a yaml file generated from this Nix expression:

      ```
      ${generators.toPretty { } (
        recursiveUpdate defaultCommonLogConfig { handlers.journal.SYSLOG_IDENTIFIER = logName; }
      )}
      ```
    '';

  genLogConfigFile = logName: format.generate
    "synapse-log-${logName}.yaml"
    (cfg.log // optionalAttrs (cfg.log?handlers.journal) {
      handlers.journal = cfg.log.handlers.journal // {
        SYSLOG_IDENTIFIER = logName;
      };
    });

  toIntBase8 = str:
    lib.pipe str [
      lib.stringToCharacters
      (map lib.toInt)
      (lib.foldl (acc: digit: acc * 8 + digit) 0)
    ];

  toDecimalFilePermission = value:
    if value == null then
      null
    else
      toIntBase8 value;
in
{
  disabledModules = [ "services/matrix/synapse.nix" ];

  imports = [
    ./nginx.nix
    (import ./workers.nix {
      inherit throw' matrix-synapse-common-config wrapped format matrix-lib;
    })
  ];

  options.services.matrix-synapse = {
    enable = mkEnableOption "matrix-synapse";

    package = mkPackageOption pkgs "matrix-synapse" { };

    plugins = mkOption {
      type = types.listOf types.package;
      default = [ ];
      example = literalExpression ''
        with ${cfgText}.package.plugins; [
          matrix-synapse-ldap3
          matrix-synapse-pam
        ];
      '';
      description = ''
        List of additional Matrix plugins to make available.
      '';
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/matrix-synapse";
      description = ''
        The directory where matrix-synapse stores its stateful data such as
        certificates, media and uploads.
      '';
    };

    socketDir = mkOption {
      type = types.path;
      default = "/run/matrix-synapse";
      description = ''
        The directory where matrix-synapse by default stores the sockets of
        all listeners that bind to UNIX sockets.
      '';
    };

    serviceUnit = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      description = ''
        The systemd unit (a service or a target) for other services to depend on if they
        need to be started after matrix-synapse.

        This option is useful as the actual parent unit for all matrix-synapse processes
        changes when configuring workers.
      '';
    };


    configFile = mkOption {
      type = types.path;
      readOnly = true;
      description = ''
        Path to the configuration file on the target system. Useful to configure e.g. workers
        that also need this.
      '';
    };

    log = mkOption {
      type = types.attrsOf format.type;
      defaultText = literalExpression defaultCommonLogConfigText;
      description = ''
        Default configuration for the loggers used by `matrix-synapse` and its workers.
        The defaults are added with the default priority which means that
        these will be merged with additional declarations. These additional
        declarations also take precedence over the defaults when declared
        with at least normal priority. For instance
        the log-level for synapse and its workers can be changed like this:

        ```nix
        { lib, ... }: {
          services.matrix-synapse.log.root.level = "WARNING";
        }
        ```

        And another field can be added like this:

        ```nix
        {
          services.matrix-synapse.log = {
            loggers."synapse.http.matrixfederationclient".level = "DEBUG";
          };
        }
        ```

        Additionally, the field `handlers.journal.SYSLOG_IDENTIFIER` will be added to
        each log config, i.e.
        * `synapse` for `matrix-synapse.service`
        * `synapse-<worker name>` for `matrix-synapse-worker-<worker name>.service`

        This is only done if this option has a `handlers.journal` field declared.

        To discard all settings declared by this option for each worker and synapse,
        `lib.mkForce` can be used.

        To discard all settings declared by this option for a single worker or synapse only,
        [](#opt-services.matrix-synapse.workers._name_.worker_log_config) or
        [](#opt-services.matrix-synapse.settings.log_config) can be used.
      '';
    };

    enableNginx = mkEnableOption "The synapse module managing nginx";

    public_baseurl = mkOption {
      type = types.str;
      default = "${cfg.settings.server_name}";
      description = ''
        The domain where clients and such will connect.
        This may be different from server_name if using delegation.
      '';
    };

    mainLogConfig = mkOption {
      type = with types; coercedTo path lib.readFile lines;
      default = ./matrix-synapse-log_config.yaml;
      description = "A yaml python logging config file";
    };

    enableSlidingSync = mkEnableOption (lib.mdDoc "automatic Sliding Sync setup at `slidingsync.<domain>`");

    settings = mkOption {
      type = types.submodule {
        freeformType = format.type;
        options = {
          server_name = mkOption {
            type = types.str;
            description = ''
              The server_name name will appear at the end of usernames and room addresses
              created on this server. For example if the server_name was example.com,
              usernames on this server would be in the format @user:example.com

              In most cases you should avoid using a matrix specific subdomain such as
              matrix.example.com or synapse.example.com as the server_name for the same
              reasons you wouldn't use user@email.example.com as your email address.
              See https://github.com/matrix-org/synapse/blob/master/docs/delegate.md
              for information on how to host Synapse on a subdomain while preserving
              a clean server_name.

              The server_name cannot be changed later so it is important to
              configure this correctly before you start Synapse. It should be all
              lowercase and may contain an explicit port.
            '';
            example = "matrix.org";
          };

          public_baseurl = mkOption {
            type = types.str;
            default = "${cfg.settings.server_name}";
            description = ''
              The domain where clients and such will connect.
              This may be different from server_name if using delegation.
            '';
          };


          use_presence = mkOption {
            type = types.bool;
            description = "Disable presence tracking, if you're having perfomance issues this can have a big impact";
            default = true;
          };

          listeners = mkOption {
            type = types.listOf (types.submodule {
              options = {
                port = mkOption {
                  type = with types; nullOr types.port;
                  default = null;
                  description = ''
                    The TCP port to bind to.

                    ::: {.note}
                      This option will be ignored if {option}`path` is set to a non-null value.
                    :::
                  '';
                  example = 8448;
                };

                path = mkOption {
                  type = with types; nullOr path;
                  default = null;
                  description = ''
                    The UNIX socket to bind to.

                    ::: {.note}
                      This option will override {option}`bind_addresses` and {option}`port`
                      if set to a non-null value.
                    :::
                  '';
                  example = literalExpression ''''${${cfgText}.socketDir}/matrix-synapse.sock'';
                };

                bind_addresses = mkOption {
                  type = types.listOf types.str;
                  default = [ ];
                  description = ''
                    A list of local addresses to listen on.

                    ::: {.note}
                      This option will be ignored if {option}`path` is set to a non-null value.
                    :::
                  '';
                };

                type = mkOption {
                  type = types.enum [ "http" "manhole" "metrics" "replication" ];
                  description = "The type of the listener";
                  default = "http";
                };

                tls = mkOption {
                  type = types.bool;
                  description = ''
                    Set to true to enable TLS for this listener.

                    Will use the TLS key/cert specified in tls_private_key_path / tls_certificate_path.
                  '';
                  default = false;
                };

                x_forwarded = mkOption {
                  type = types.bool;
                  description = ''
                    Set to true to use the X-Forwarded-For header as the client IP.

                    Only valid for an 'http' listener.
                    Useful when Synapse is behind a reverse-proxy.
                  '';
                  default = true;
                };

                resources = mkOption {
                  type = types.listOf (types.submodule {
                    options = {
                      names = mkOption {
                        type = with types; listOf (enum [
                          "client"
                          "consent"
                          "federation"
                          "keys"
                          "media"
                          "metrics"
                          "openid"
                          "replication"
                          "static"
                          "webclient"
                        ]);
                        description = "A list of resources to host on this port";
                      };

                      compress = mkEnableOption "HTTP compression for this resource";
                    };
                  });
                };
              };
            });
            description = "List of ports that Synapse should listen on, their purpose and their configuration";
            # TODO: add defaultText
            default = [
              {
                path = "${cfg.socketDir}/matrix-synapse.sock";
                resources = [
                  { names = [ "client" ]; compress = true; }
                  { names = [ "federation" ]; compress = false; }
                ];
              }
              (mkIf (wcfg.instances != { }) {
                path = "${cfg.socketDir}/matrix-synapse-replication.sock";
                resources = [
                  { names = [ "replication" ]; }
                ];
              })
              (mkIf cfg.settings.enable_metrics {
                port = 9000;
                bind_addresses = [ "127.0.0.1" ];
                resources = [
                  { names = [ "metrics" ]; }
                ];
              })
            ];
          };

          federation_ip_range_blacklist = mkOption {
            type = types.listOf types.str;
            description = ''
              Prevent federation requests from being sent to the following
              blacklist IP address CIDR ranges. If this option is not specified, or
              specified with an empty list, no ip range blacklist will be enforced.
            '';
            default = [
              "127.0.0.0/8"
              "10.0.0.0/8"
              "172.16.0.0/12"
              "192.168.0.0/16"
              "100.64.0.0/10"
              "169.254.0.0/16"
              "::1/128"
              "fe80::/64"
              "fc00::/7"
            ];
          };

          log_config = mkOption {
            type = types.path;
            description = ''
              A yaml python logging config file as described by
              https://docs.python.org/3.7/library/logging.config.html#configuration-dictionary-schema
            '';
            default = pkgs.writeText "log_config.yaml" cfg.mainLogConfig;
            defaultText = "A config file generated from ${cfgText}.mainLogConfig";
          };

          media_store_path = mkOption {
            type = types.path;
            description = "Directory where uploaded images and attachments are stored";
            default = "${cfg.dataDir}/media_store";
            defaultText = literalExpression ''''${${cfgText}.dataDir}/media_store'';
          };

          max_upload_size = mkOption {
            type = types.str;
            description = "The largest allowed upload size in bytes";
            default = "50M";
            example = "800K";
          };

          enable_registration = mkEnableOption "registration for new users";
          enable_metrics = mkEnableOption "collection and rendering of performance metrics";
          report_stats = mkEnableOption "reporting usage stats";

          app_service_config_files = mkOption {
            type = types.listOf types.path;
            description = "A list of application service config files to use";
            default = [ ];
          };

          signing_key_path = mkOption {
            type = types.path;
            description = "Path to the signing key to sign messages with";
            default = "${cfg.dataDir}/homeserver.signing.key";
            defaultText = literalExpression ''''${${cfgText}.dataDir}/homeserver.signing.key'';
          };

          trusted_key_servers = mkOption {
            type = types.listOf (types.submodule {
              freeformType = format.type;

              options.server_name = mkOption {
                type = types.str;
                description = "The name of the server. This is required.";
              };
            });
            description = "The trusted servers to download signing keys from";
            default = [
              {
                server_name = "matrix.org";
                verify_keys."ed25519:auto" = "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw";
              }
            ];
          };

          federation_sender_instances = mkOption {
            type = types.listOf types.str;
            description = ''
              This configuration must be shared between all federation sender workers.

              When changed, all federation sender workers must be stopped at the same time and
              restarted, to ensure that all instances are running with the same config.
              Otherwise, events may be dropped.
            '';
            default = [ ];
          };

          redis = mkOption {
            type = types.submodule {
              freeformType = format.type;

              options.enabled = mkOption {
                type = types.bool;
                description = ''
                  Whether to enable redis within synapse.

                  This is required for worker support.
                '';
                default = wcfg.instances != { };
                defaultText = literalExpression "${wcfgText}.instances != { }";
              };
            };
            default = { };
            description = "Redis configuration for synapse and workers";
          };
        };
      };
    };

    extraConfigFiles = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = ''
        Extra config files to include.
        The configuration files will be included based on the command line
        argument --config-path. This allows to configure secrets without
        having to go through the Nix store, e.g. based on deployment keys if
        NixOPS is in use.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = map
      (l: {
        assertion = l.path == null -> (l.bind_addresses != [ ] && l.port != null);
        message = "Some listeners are missing either a socket path or a bind_address + port to listen on";
      })
      cfg.settings.listeners;

    users.users.matrix-synapse = {
      group = "matrix-synapse";
      home = cfg.dataDir;
      createHome = true;
      shell = "${pkgs.bash}/bin/bash";
      uid = config.ids.uids.matrix-synapse;
    };

    users.groups.matrix-synapse = {
      gid = config.ids.gids.matrix-synapse;
    };


    services.matrix-synapse.serviceUnit = if hasWorkers then "matrix-synapse.target" else "matrix-synapse.service";
    services.matrix-synapse.configFile = configFile;
    services.matrix-synapse.package = wrapped;

    services.matrix-synapse.log = mapAttrsRecursive (const mkDefault) defaultCommonLogConfig;

    systemd = {
      targets.matrix-synapse = {
        description = "Matrix synapse parent target";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
      };

      slices.system-matrix-synapse = {
        description = "Matrix synapse slice";
        requires = [ "system.slice" ];
        after = [ "system.slice" ];
      };

      services.matrix-synapse = {
        description = "Synapse Matrix homeserver";
        partOf = [ "matrix-synapse.target" ];
        wantedBy = [ "matrix-synapse.target" ];

        preStart =
          let
            flags = lib.cli.toGNUCommandLineShell { } {
              config-path = [ matrix-synapse-common-config ] ++ cfg.extraConfigFiles;
              keys-directory = cfg.dataDir;
              generate-keys = true;
            };
          in
          "${cfg.package}/bin/synapse_homeserver ${flags}";

        serviceConfig = {
          Type = "notify";
          User = "matrix-synapse";
          Group = "matrix-synapse";
          Slice = "system-matrix-synapse.slice";
          WorkingDirectory = cfg.dataDir;
          StateDirectory = "matrix-synapse";
          RuntimeDirectory = "matrix-synapse";
          ExecStart =
            let
              flags = lib.cli.toGNUCommandLineShell { } {
                config-path = [ matrix-synapse-common-config ] ++ cfg.extraConfigFiles;
                keys-directory = cfg.dataDir;
              };
            in
            "${wrapped}/bin/synapse_homeserver ${flags}";
          ExecReload = "${pkgs.utillinux}/bin/kill -HUP $MAINPID";
          Restart = "on-failure";
        };
      };
    };
    services.matrix-synapse.settings.extra_well_known_client_content."org.matrix.msc3575.proxy" = mkIf cfg.enableSlidingSync {
      url = "https://${config.services.matrix-sliding-sync.publicBaseUrl}";
    };
    services.matrix-sliding-sync = mkIf cfg.enableSlidingSync {
      enable = true;
      enableNginx = lib.mkDefault cfg.enableNginx;
      publicBaseUrl = lib.mkDefault "slidingsync.${cfg.settings.server_name}";

      settings = {
        SYNCV3_SERVER = lib.mkDefault "https://${cfg.public_baseurl}";
        SYNCV3_PROM = lib.mkIf cfg.settings.enable_metrics (lib.mkDefault "127.0.0.1:9001");
      };
    };
  };
}
