# FileMaker DNS Plugin (`fDNS`)

A cross-platform DNS plugin for FileMaker Pro, providing DNS resolution and reverse lookup capabilities. This plugin is built using the FileMaker PluginSDK (using the FMWrapper) and is currently supported for macOS (Xcode project).

## Features

- **Hostname to IP Resolution**
  `fDNS_Resolve(hostname {; timeoutMs})`
  Resolves a hostname to an IPv4 address.

- **Reverse DNS Lookup**
  `fDNS_Reverse(ipAddress {; timeoutMs})`
  Resolves an IPv4 address to its hostname.

- **Custom DNS Server Support**
  `fDNS_Set_Server(dnsServer)`
  Sets the DNS server to use for subsequent requests. Use an empty string (`""`) to reset to the system default.

- **System DNS Server Query**
  `fDNS_Get_Systems_Server()`
  Returns the system's DNS server(s).

- **Current DNS Server Query**
  `fDNS_Get_Current_Server()`
  Returns the DNS server currently set in the plugin.

- **Plugin Initialization/Cleanup**
  `fDNS_Initialize()` / `fDNS_Uninitialize()`
  Initializes and cleans up the DNS subsystem. Should be called at plugin load/unload.

## Behavior

- Default timeout for DNS operations is **3 seconds** (3000 ms).
- If no custom DNS server is set, the plugin uses the OS system resolver (`getaddrinfo`/`getnameinfo`), ensuring robust operation on macOS, Linux, and Windows.
- When a custom DNS server is set, the plugin uses **c-ares** for DNS queries.
- Hybrid approach avoids known c-ares/macOS issues and ensures reliability.

## Installation

1. **Download Plugin from Releases**
Download the plugin from the latest release

2. **Unzip the Plugin file**

3. **Deploy the Plugin**
   Copy the `.fmplugin` bundle to your FileMaker Extensions folder:
   ~/Library/Application Support/FileMaker/Extensions/

4. **Restart FileMaker Pro**
   The plugin should be detected and loaded automatically.

## Usage

Call the plugin functions from FileMaker calculations or scripts. See the `fDNS_DemoFile.fmp12`


## License

Copyright © 2025 Sotirios Karagiannis. All rights reserved.

## Support

For help and documentation, visit:
[https://github.com/sotiriskaragiannis/fDNS](https://github.com/sotiriskaragiannis/fDNS)
