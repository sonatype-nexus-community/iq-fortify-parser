# Fortify Virtual Machine

## About
This directory contains a Vagrantfile that will start a Fortify development environment.

## Pre-requisites
- The latest version of [Vagrant](https://www.vagrantup.com)
- The latest version of [VirtualBox](https://www.virtualbox.org)
- The MicroFocus Fortify SSC Demonstration Suite (Ask on Slack)
- The Fortify Developer `fortify.license` file (Ask on Slack)
- A 64-bit Java runtime RPM for centos / rhel 7, such as `jre-8u181-linux-x64.rpm` or similar.

## Installation

1. Unpack the tarball for the Fortify SSC demo suite, and place this Vagrantfile in the same directory as the unpacked files.
2. Copy the `fortify.license` file into the same directory as the unpacked files.
3. Copy the Java runtime RPM to the same directory as the unpacked files.
   

## Usage

### Starting the VM
Start the VM with `vagrant up`. This will download the linux VM image if it's not already present, install Java, then start Fortify. NOTE: Starting Fortify takes a VERY LONG TIME, as much as 15 minutes. It will repeatedly print `default: .` the entire time it is starting up. This is irritating but normal.

Eventually, it WILL start and print:

```
    default: ================================================================
    default: .        Fortify Demo Suite Startup Complete                .
    default: .                                                              .
    default: . http://127.0.0.1:8180/ssc                                    .
    default: .     Fortify Software Security Center - login: admin/admin .
    default: ================================================================
```

### Accessing Fortify
Once Fortify is started, login is at `http://localhost:8080/ssc`.

### Acquiring shell access to the VM
Shell access to the VM can be had with `vagrant ssh`. No need to worry about FTP'ing files into the VM, nny files put in the project root will be available inside the VM at `/vagrant/`.

### Stop the VM
Stop the VM with `vagrant halt`.

### Re-deploy Fortify
If for some reason Fortify is not running in the VM, re-run the provisioning script to start it with `vagrant provision`.

### Wiping the development environment
Wipe the development environment completely with `vagrant destroy`. This will completely delete the VM. Next time you run `vagrant up`, it will start from scratch.
