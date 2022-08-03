# oc-mirror-init
An extension to the oc-mirror plugin to create a mirror config from a running cluster

# What is this for?

[oc-mirror](https://github.com/openshift/oc-mirror) is a great tool to prepare a mirror of all required images to run an OpenShift / OKD cluster disconnected from the public internet. To help getting started with a valid configuration file that `oc mirror` uses, this utility got created.

Oftentimes you have a running OpenShift / OKD cluster as a sandbox that you would like to take as a starting point for running disconnected. `oc-mirror-init` makes it easy to create a mirroring configuration for `oc-mirror` to download exactly the amount of content that is needed to run that cluster offline.

# What does it do?

`oc-mirror-init` will connect to an OpenShift / OKD cluster of your choice and introspect its configuration. It will determine what version the cluster is running on and which update channel it is currently using. It will also introspect all installed [OLM](https://github.com/operator-framework/operator-lifecycle-manager-managed) operators and their versions and catalogs.

With this information `oc-mirror-init` will create an `ImageSetConfiguration` manifest that contains all the content and settings to create a mirror of the required container images for the cluster and its operators.

# What do I need and how do I install it?

`oc-mirror-init` is a simple Python script and requires Python 3.7 or newer and the `pip` command available on your machine.

1. git-clone this repo
1. run `pip install -r requirements.txt`

# How do I use it?

All you need is a working Kubeconfig, as in: having the `KUBECONFIG` variable point to a valid Kubernetes client configuration file or have the file in the default location, usually `$HOME/.kube/config`

By default, with no argument, `oc-mirror-init` will attempt to use the currently selected cluster (`current-context`) from your Kubeconfig:

```sh
$ ./oc-mirror-init.py
```

If all goes well it respond with an `ImageSetConfiguration` manifest aligned with the installed content of your cluster.

```yaml
---
apiVersion: mirror.openshift.io/v1alpha2
kind: ImageSetConfiguration
mirror:
  operators:
  - catalog: mirror-registry.example.com:8443/mirror/redhat/redhat-operator-index:v4.10
    packages:
    - channels:
      - minVersion: 2.1.2+0.1657075072
        name: stable-2.1-cluster-scoped
      name: ansible-automation-platform-operator
    - channels:
      - minVersion: 1.1.5
        name: stable
      name: costmanagement-metrics-operator
    - channels:
      - minVersion: 0.4.0
        name: alpha
      name: idp-mgmt-operator-product
    - channels:
      - minVersion: 7.5.1-opr-005
        name: alpha
      name: rhsso-operator
    - channels:
      - name: stable-2.0
      name: multicluster-engine
    - channels:
      - minVersion: 2.5.1
        name: release-2.5
      name: advanced-cluster-management
  platform:
    channels:
    - minVersion: 4.10.22
      name: fast-4.10
    graph: 'true'
```

You can use this file directly as input for `oc mirror` itself.

The tool cannot create configurations for clusters that aren't subscribed to updates. Equally, operators that are installed but have their catalog information removed, will be ignored.

# Additional options

To select another cluster context from your Kubeconfig you can supply it to the tool:

```sh
$ ./oc-mirror-init.py --context default/api-example-cluster:6443/dmesser
```

To get a list of available contexts run `kubectl config get-contexts`.

If you don't need the `platform` part of the `ImageSetConfig` or the `operators` portion you can disable them with these switches:

```sh
$ ./oc-mirror-init.py --no-operators
$ ./oc-mirror-init.py --no-platform
```

If you want to know what the tool is doing while introspecting your cluster you can run it with debug logs:

```sh
$ ./oc-mirror-init.py --debug
```

If you are connecting to a cluster with a self-signed TLS certificate used by the cluster's API server `oc-mirror-init` will connect to it but display warnings. You can suppress those:

```sh
$ ./oc-mirror-init.py --ignore-insecure
```

# Known issues

- if an operator is installed multiples times in different versions in the cluster, the resulting `ImageSetConfig` will have separate entries for this operator