# VMWare vRealize Operations Metrics Input Plugin

The VMware vSphere plugin uses the vSphere API to gather metrics from multiple
vCenter servers.

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Configuration

```toml @sample.conf
[[inputs.vrops]]
  interval = "1m"
  hostname = "10.95.159.64"
  username = "admin"
  password = "Abcd123$"
  metric = ["cpu|usagemhz_average", "disk|usage_average"]
  
  # timeout = "60s"
  # period = "20m"  # will be used for initial collection, after first collection, data will be queried between each 'interval'
  # delay = "30s"  # data will be queried with a delay. window end = current time - delay
  # interval_quantifier = 1  # Number for the interval type 

  ## Interval type requested by the user. Possible values are: HOURS , MINUTES , SECONDS , DAYS , WEEKS , MONTHS , YEARS
  # interval_type = "MINUTES"
  
  ## How to rollup the data within an interval. Possible values are: SUM , AVG , MIN , MAX , NONE , LATEST , COUNT
  # rollup_type = "AVG"
  
  ## Number of resources to batch in single metric request
  # batch_size = 100
  
  # scheme = "https"

  ## Resources can be filtered on the resource_kind or adapter_kind
  # resource_kind = "VirtualMachine"
  # adapter_kind = ""

  ## HTTP Proxy support
  # use_system_proxy = true
  # http_proxy_url = ""

  ## Optional SSL Config
  # ssl_ca = "/path/to/cafile"
  # ssl_cert = "/path/to/certfile"
  # ssl_key = "/path/to/keyfile"
  ## Use SSL but skip chain & host verification
  insecure_skip_verify = true
```