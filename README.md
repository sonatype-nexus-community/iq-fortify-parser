# Sonatype IQ Fortify SSC Integration
This project has been recently updated to include all of the components needed for the integration into one project space. The iq-fortify-ssc-integration project has been moved into here. This new multi-module structure will streamline our release and build processes.

## This plugin imports IQ Server application scan results and imports them into Fortify Software Security Center

The plugin can be downloaded from the Sonatype IQ Server Download & Compatibility Page

The https://github.com/sonatype-nexus-community/iq-fortify-ssc-integration project is what feeds data to the plugin

### INSTALLING THE PARSER
- SSC version 18.20 supports plugin installation through the plugin management UI (Administration > Plugins).
- All installed plugins are disabled after installation, in that the plugins are defined in SSC, but cannot do any work or accept any requests from SSC.
- To enable a plugin, select the plugin row in the Plugins list, and then click Enable.
- The plugin container log `<fortify.plugins.home>/log` should contain an INFO record about the plugin's successful installation or enablement (start). For example: `org.apache.felix.fileinstall - 3.5.4 | Started bundle: file:<fortify.plugins.home>/plugins/com.example.parser.jar`
- SSC performs several validation steps when plugins are being installed or enabled. SSC can block plugin installation and enablement if conditions such as the following exist:
    - Installing a plugin is not allowed if a plugin from the same family but later version is already installed in SSC. Because plugins are developed by 3rd-party developers, SSC has no access to details about the logic implemented in plugins. In this case, SSC assumes that later versions of some plugins can produce data that is incompatible with an earlier version of the plugins, resulting in SSC system instability. If you absolutely must install an earlier version of a plugin (for example, to roll back from a defective later version), remove the later version of the plugin, and then install the earlier version.
    - You cannot install an earlier data version of a plugin in SSC.
    - To maintain consistency of information displayed in the Administration UI with the underlying pluginIds, SSC ensures that plugins in the same family have the same name and other identifying attributes (such as engineType).
    - Only one plugin of a plugin family (sharing the same pluginId and name) can be enabled at a given time.


## DEVELOPING

### CONFIGURING THE DEVELOPER ENVIRONMENT FOR THE PARSER

This is a Maven project so import into your you IDE accordingly

### BUILDING THE PARSER
The binaries for this project will be made available on the Sonatype IQ server Download page. Should you need to build it from scratch however here is what you need to know. The build process is handled by Maven and makes use the of the Maven wrapper to help with portability. The following command can be used for a local build:

```
./mvnw clean package
```
