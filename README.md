
> _Note, the information below is valid only for the upcoming Flopsar 3.0._



# Flopsar Server Authentication Plugin

This is a simple implementation of LDAP authentication plugin for use with Flopsar.

## Building the Plugin

First, download the project source code into `ldap` directory:

```
$ git clone --recurse-submodules <project_url> ldap
```
If you want to download a specific version, replace `TAG` with the version:

```
$ git clone -b TAG --recurse-submodules <project_url> ldap
```
Next, rebuild the configuration:
```
$ cd ldap
$ autoreconf -i
```
Configure and build:
```
$ ./configure && make
```
If the build is successful, the plugin file `.libs/flopsar-ldap.so` should be created.


### Available Configure Options

#### Debug support

```
$ ./configure --enable-debug
```

## Install the Plugin

This implementation has a configuration file `resources/ldap.conf`, which must be installed along with the plugin.
Follow the instructions in the [Flopsar documentation](https://docs.flopsar.com/administrator-guide/server#plugins) to install the plugin.




