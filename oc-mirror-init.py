#!/usr/bin/env python

"""An extension to the oc-mirror plugin to generate an image set configuration file using a running OpenShift cluster as input.

The exact version and the configured update channel of the cluster will be determined by connecting to it and leveraging well-known OpenShift APIs. Similarly, all installed operators will be retrieved and their Subscription settings introspected to determine the list of running operators and their versions and channel settings.
This information is used compile the image set configuration file oc-mirror relies on with the list of operators and OpenShift releases to be mirrored aligned with your running cluster.
"""

from dataclasses import dataclass
from gettext import install
from kubernetes.dynamic.exceptions import NotFoundError
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException
from kubernetes.client import configuration, api_client
from kubernetes import client, config, dynamic

import sys
import yaml
import pick
import click
import string
import logging
import urllib3

logging.basicConfig(datefmt='%Y-%m-%d %H:%M:%S',
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ClusterVersion:
    version: string
    channel: string

    def is_on_official_channel(self) -> bool:
        return self.channel.startswith("fast") or self.channel.startswith("candidate") or self.channel.startswith("stable")


@dataclass
class InstalledOperator:
    name: string
    version: string = None
    channel: string = None


def login_to_cluster(kubeConfigContext) -> dynamic.DynamicClient:
    logger.debug("Loading KUBECONFIG context %s" % kubeConfigContext)
    dynamicClient = dynamic.DynamicClient(
        api_client.ApiClient(
            configuration=config.load_kube_config(context=kubeConfigContext))
    )

    logger.debug(
        "Attempting to contact authorization API to verify credentials")
    client.AuthorizationApi().get_api_group()

    return dynamicClient


def is_compatible_platform() -> bool:
    logger.debug("Trying to verify if config.openshift.io/v1 API exists")
    for api in client.ApisApi().get_api_versions().groups:
        if api.name == "config.openshift.io":
            for v in api.versions:
                if v.group_version == "config.openshift.io/v1" and v.version == "v1":
                    return True
    return False


def can_introspect_platform() -> bool:
    api_instance = client.AuthorizationV1Api()
    ssar = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                group="config.openshift.io",
                version="v1",
                resource="ClusterVersion",
                verb="get",
                name="version")
        )
    )

    api_response = api_instance.create_self_subject_access_review(ssar)
    logger.debug("Verifying 'get' permission on object 'version' of type 'clusterversion.config.openshift.io/v1' at cluster-scope, outcome: %s" % ("allowed" if api_response.status.allowed else "not allowed"))

    return api_response.status.allowed == True


def can_introspect_operators() -> bool:
    requiredAccess = [
        {
            "group": "operators.coreos.com",
            "version": "v1alpha1",
            "resource": "Subscription",
            "verb": "list"
        },
        {
            "group": "operators.coreos.com",
            "version": "v1alpha1",
            "resource": "Subscription",
            "verb": "get"
        },
        {
            "group": "operators.coreos.com",
            "version": "v1alpha1",
            "resource": "InstallPlan",
            "verb": "get"
        },
        {
            "group": "operators.coreos.com",
            "version": "v1alpha1",
            "resource": "ClusterServiceVersion",
            "verb": "get"
        },
        {
            "group": "operators.coreos.com",
            "version": "v1alpha1",
            "resource": "CatalogSource",
            "verb": "get"
        }
    ]

    api_instance = client.AuthorizationV1Api()

    for permission in requiredAccess:
        ssar = client.V1SelfSubjectAccessReview(
            spec=client.V1SelfSubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(
                    group=permission["group"],
                    version=permission["version"],
                    resource=permission["resource"],
                    verb=permission["verb"]
                )
            )
        )

        api_response = api_instance.create_self_subject_access_review(ssar)
        logger.debug("Verifying '%s' permission on resource '%s' of type '%s/%s' at cluster-scope, outcome: %s" %
                     (permission["verb"],
                      permission["resource"],
                      permission["group"],
                      permission["version"],
                      ("allowed" if api_response.status.allowed else "not allowed"))
                     )

        if api_response.status.allowed is not True:
            return False

    return True


def get_platform_data(client: dynamic.DynamicClient) -> ClusterVersion:
    logger.debug("Getting object of type clusterversion.config.openshift.io/v1")
    api = client.resources.get(
        group="config.openshift.io", api_version="v1", kind="ClusterVersion")
    cluster_config = api.get(name="version")

    if cluster_config.spec.channel is None:
        logger.fatal("Cluster is not configured to receive updates. A working image set configuration cannot be created. Please subscribe the cluster to an officially supported Red Hat OpenShift release channel or omit the platform mirroring configuration with --no-platform.")
        sys.exit(1)

    update_channel = cluster_config.spec.channel
    cluster_version = cluster_config.status.desired.version

    logger.debug("Cluster is at version %s using channel %s" % (cluster_version, update_channel))

    return ClusterVersion(version=cluster_version, channel=update_channel)


def get_catalog_data(client: dynamic.DynamicClient) -> dict:
    catalog_data = {}
    subscription_api = client.resources.get(
        group="operators.coreos.com", api_version="v1alpha1", kind="Subscription")

    logger.debug("Getting all objects of type subscription.operators.coreos.com/v1alpha1 on the cluster")

    for subscription in subscription_api.get().items:
        operator_name = subscription.spec.name
        channel_name = subscription.spec.channel
        operator_version = None
        catalog_image = None

        logger.debug("Processing Subscription '%s' in namespace '%s'" % (subscription.metadata.name, subscription.metadata.namespace))

        if subscription.spec.source is not None:
            catalog_name = subscription.spec.source
            catalog_namespace = subscription.spec.sourceNamespace if subscription.spec.sourceNamespace is not None else subscription.metadata.namespace

            try:
                catalog_api = client.resources.get(group="operators.coreos.com",
                                                   api_version="v1alpha1",
                                                   kind="CatalogSource")

                catalog = catalog_api.get(
                    name=catalog_name, namespace=catalog_namespace)
                catalog_image = catalog.spec.image

                logger.debug("Referenced CatalogSource '%s' found in namespace %s with image set to %s" %
                                (catalog_name, catalog_namespace, catalog_image))

            except NotFoundError as e:
                logger.warning("Referenced CatalogSource '%s' not found in namespace %s, disregarding Subscription %s in namespace %s" %
                            (catalog_name, catalog_namespace, subscription.metadata.name, subscription.metadata.namespace))
                pass

        if subscription.status.installedCSV is not None and subscription.status.installPlanRef is not None:
            csv_name = subscription.status.installedCSV

            logger.debug("Referenced ClusterServiceVersion is '%s'" % csv_name)
            
            csv_api = client.resources.get(group="operators.coreos.com",
                                           api_version="v1alpha1",
                                           kind="ClusterServiceVersion")
            installed_csv = csv_api.get(
                name=csv_name, namespace=subscription.metadata.namespace)

            try:
                logger.debug("Referenced InstallPlan is '%s'" % subscription.status.installPlanRef.name)

                installplan_api = client.resources.get(group="operators.coreos.com",
                                                       api_version="v1alpha1",
                                                       kind="InstallPlan")
                installplan = installplan_api.get(name=subscription.status.installPlanRef.name,
                                                  namespace=subscription.status.installPlanRef.namespace)

                operator_version = installed_csv.spec.version

                logger.debug("Got operator version '%s' from ClusterServiceVersion '%s'" % (operator_version, installed_csv.metadata.name))

                logger.debug("Determining resolved CatalogSource from InstallPlan '%s' that generated ClusterServiceVersion '%s'" %
                             (installplan.metadata.name, installed_csv.metadata.name))

                if installplan.status.bundleLookups is not None:
                    catalog_refs = [
                        catalogRef for catalogRef in installplan.status.bundleLookups if catalogRef["identifier"] == csv_name]

                    if catalog_refs is not None and len(catalog_refs) == 1:
                        catalog_ref = catalog_refs[0].catalogSourceRef
                        catalog_api = client.resources.get(group="operators.coreos.com",
                                                           api_version="v1alpha1",
                                                           kind="CatalogSource")

                        catalog = catalog_api.get(
                            name=catalog_ref.name, namespace=catalog_ref.namespace)

                        logger.debug("Resolved CatalogSource from InstallPlan '%s' for ClusterServiceVersion '%s' is '%s' in namespace '%s' with image set to '%s'" %
                             (installplan.metadata.name, installed_csv.metadata.name, catalog.metadata.name, catalog.metadata.namespace, catalog.spec.image))

                        catalog_image = catalog.spec.image
            except NotFoundError as e:
                pass

        if catalog_image is None:
            logger.warning("Couldn't determine image used by catalog '%s namespace %s, disregarding Subscription %s in namespace %s" %
                            (catalog_name, catalog_namespace, subscription.metadata.name, subscription.metadata.namespace))
            continue
        else:
            if catalog_image not in catalog_data.keys():
                catalog_data[catalog_image] = []

            catalog_data[catalog_image].append(InstalledOperator(name=operator_name,
                                                                 version=operator_version,
                                                                 channel=channel_name))
    return catalog_data

def transform_op_to_dict(operator: InstalledOperator) -> dict:
    d = {"name": operator.name}

    if operator.channel is not None:
        channel = {"name": operator.channel}

        if operator.version is not None:
            channel["minVersion"] = operator.version

        d["channels"] = [channel]
    elif operator.version is not None:
        d["minVersion"] = operator.version

    return d

def create_imageset_config(platformData, catalogData):
    imagesetconfig_manifest = {
        "apiVersion": "mirror.openshift.io/v1alpha2",
        "kind": "ImageSetConfiguration",
        "mirror": {
        }
    }

    if platformData is not None:
        imagesetconfig_manifest["mirror"] = {
            "platform": {
                "channels": [
                     { 
                        "name": platformData.channel,
                        "minVersion": platformData.version
                     }   
                ],
                "graph": "true"
            }
        }

    if catalogData is not None:
        imagesetconfig_manifest["mirror"]["operators"] = []

        for catalog_image, installed_operators in catalogData.items():
            imagesetconfig_manifest["mirror"]["operators"].append({
                "catalog": catalog_image,
                "packages": list(map(transform_op_to_dict, installed_operators))
            })
           


    return imagesetconfig_manifest


def determine_kube_context(context):
    try:
        logger.debug("Attempting to load contexts from " +
                     config.KUBE_CONFIG_DEFAULT_LOCATION)
        contexts, current_context = config.list_kube_config_contexts()
    except ConfigException as e:
        exit(e)

    if not contexts:
        exit("Cannot connect to cluster. Couldn't find any context in " +
             config.KUBE_CONFIG_DEFAULT_LOCATION)

    contexts = [context['name'] for context in contexts]

    logger.debug("Found the following contexts:\n\n-> " +
                 "\n-> ".join(contexts) + "\n")

    if not context:
        if not current_context:
            logger.debug("No current-context set, letting the user pick")
            context, _ = pick(
                contexts, title="Pick the KUBECONFIG context to load")
            logger.debug("User picked: %s" % context)
        else:
            context = current_context['name']
            logger.debug("found current-context %s" % context)
    else:
        logger.debug("Context %s given" % context)
        if context not in contexts:
            exit("Specified context '" + context + "' not found in " +
                 config.KUBE_CONFIG_DEFAULT_LOCATION)
    return context


@click.command()
@click.option('--context', '-c', help='A KUBECONFIG context other than the current-context to use to connect to a cluster')
@click.option('--platform/--no-platform', type=bool, default=True, help='Whether to include the cluster core platform version in the mirroring configuration.')
@click.option('--operators/--no-operators', type=bool, default=True, help='Whether to include operators in the mirroring configuration.')
@click.option('--debug', is_flag=True, default=False, help='Turn on verbose logging')
@click.option('--ignore-insecure', is_flag=True, default=False, help='Suppress warnings about connecting to an API server with an untrusted certificate.')
def main(context, platform, operators, debug, ignore_insecure):
    logger.setLevel(level=logging.DEBUG if debug else logging.INFO)

    if ignore_insecure:
        urllib3.disable_warnings()

    logger.debug("Platform configuration: %s" %
                 "selected" if platform else "not selected")
    logger.debug("Operator configuration: %s" %
                 "selected" if platform else "not selected")
    logger.debug("Desired KUBECONFIG context: %s" %
                 (context if context is not None else "none given"))

    if not platform and not operators:
        logger.fatal("Neither platform nor operators selected for instrospection. Nothing to do.")
        sys.exit(1)

    context = determine_kube_context(context)

    try:
        client = login_to_cluster(context)
    except ApiException as e:
        if e.status == 401:
            logger.fatal("Failed to login to cluster with reason: %s. Check your credentials." % e.reason)
            sys.exit(1)

    if not is_compatible_platform():
        logger.fatal("The target cluster does not appear to be an OpenShift or OKD cluster. This tool is intended to only work with these two types of Kubernetes distribution.")
        sys.exit(1)

    if platform and not can_introspect_platform():
        logger.fatal("Not enough permissions to introspect cluster version and update settings. Check your permissions on the ClusterVersion API.")
        sys.exit(1)

    if operators and not can_introspect_operators():
        logger.fatal("Not enough permissions to introspect installed operators. Check your permissions on the Subscription API across all namespaces.")
        sys.exit(1)

    platform_data = get_platform_data(client) if platform else None

    if platform and not platform_data.is_on_official_channel():
        logger.fatal("This cluster is not using an officially supported channel. A working image set configuration cannot be created. Please subscribe the cluster to an officially supported Red Hat OpenShift release channel or omit the platform mirroring configuration with --no-platform.")
        sys.exit(1)

    
    catalog_data = get_catalog_data(client) if operators else None

    mirrorConfiguration = create_imageset_config(platform_data, catalog_data)

    print("---\n" + yaml.dump(mirrorConfiguration))


if __name__ == "__main__":
    main()
