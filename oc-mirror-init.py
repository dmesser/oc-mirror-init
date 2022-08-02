#!/usr/bin/env python

"""An extension to the oc-mirror plugin to generate an image set configuration file using a running OpenShift cluster as input.

The exact version and the configured update channel of the cluster will be determined by connecting to it and leveraging well-known OpenShift APIs. Similarly, all installed operators will be retrieved and their Subscription settings introspected to determine the list of running operators and their versions and channel settings.
This information is used compile the image set configuration file oc-mirror relies on with the list of operators and OpenShift releases to be mirrored aligned with your running cluster.
"""
\
import string
import click
import pick
import yaml

from kubernetes import client, config, dynamic
from kubernetes.client import configuration, api_client
from kubernetes.config.config_exception import ConfigException
from kubernetes.client.rest import ApiException
from kubernetes.dynamic.exceptions import NotFoundError

from dataclasses import dataclass

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
    dynamicClient = dynamic.DynamicClient(
        api_client.ApiClient(configuration=config.load_kube_config(context=kubeConfigContext))
    )

    client.AuthorizationApi().get_api_group()

    return dynamicClient

def is_compatible_platform() -> bool:
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

        if api_response.status.allowed is not True:
            return False

    return True

def get_platform_data(client: dynamic.DynamicClient) -> ClusterVersion:
    api = client.resources.get(group="config.openshift.io", api_version="v1", kind="ClusterVersion")
    cluster_config = api.get(name="version")

    update_channel = cluster_config.spec.channel
    cluster_version = cluster_config.spec.desiredUpdate.version

    return ClusterVersion(version=cluster_version, channel=update_channel)

def get_catalog_data(client: dynamic.DynamicClient) -> dict:
    catalog_data = {}    
    subscription_api = client.resources.get(group="operators.coreos.com", api_version="v1alpha1", kind="Subscription")

    for subscription in subscription_api.get().items:
        operator_name = subscription.spec.name
        channel_name = subscription.spec.channel
        operator_version = None
        catalog_image = None

        if subscription.spec.source is not None:
            catalog_name = subscription.spec.source
            catalog_namespace = subscription.spec.sourceNamespace if subscription.spec.sourceNamespace is not None else subscription.metadata.namespace

            try:
                catalog_api = client.resources.get(group="operators.coreos.com", 
                                            api_version="v1alpha1",
                                            kind="CatalogSource")

                catalog = catalog_api.get(name=catalog_name, namespace=catalog_namespace)
                catalog_image = catalog.spec.image
            except NotFoundError as e:
                pass

        if subscription.status.installedCSV is not None and subscription.status.installPlanRef is not None:
            csv_name = subscription.status.installedCSV

            csv_api = client.resources.get(group="operators.coreos.com", 
                                           api_version="v1alpha1",
                                           kind="ClusterServiceVersion")
            installed_csv = csv_api.get(name=csv_name, namespace=subscription.metadata.namespace)

            try:
                installplan_api = client.resources.get(group="operators.coreos.com", 
                                                    api_version="v1alpha1",
                                                    kind="InstallPlan")
                installplan = installplan_api.get(name=subscription.status.installPlanRef.name,
                                                namespace=subscription.status.installPlanRef.namespace)

                operator_version = installed_csv.spec.version
                
                if installplan.status.bundleLookups is not None:
                    catalog_refs = [catalogRef for catalogRef in installplan.status.bundleLookups if catalogRef["identifier"] == csv_name]

                    if catalog_refs is not None and len(catalog_refs) == 1:
                        catalog_ref = catalog_refs[0].catalogSourceRef
                        catalog_api = client.resources.get(group="operators.coreos.com", 
                                                api_version="v1alpha1",
                                                kind="CatalogSource")

                        catalog = catalog_api.get(name=catalog_ref.name, namespace=catalog_ref.namespace)
                        catalog_image = catalog.spec.image
            except NotFoundError as e:
                pass

        if catalog_image is None:
            continue
        else:
            if catalog_image not in catalog_data.keys():
                catalog_data[catalog_image] = []

            catalog_data[catalog_image].append(InstalledOperator(name=operator_name,
                                                                 version=operator_version,
                                                                 channel=channel_name))
    return catalog_data

def create_imageset_config(platformData, catalogData):
    return

@click.command()
@click.option('--context', '-c', help='A KUBECONFIG context other than the current-context to use to connect to a cluster')
@click.option('--platform/--no-platform', type=bool, default=True, help='Whether to include the cluster core platform version in the mirroring configuration.')
@click.option('--operators/--no-operators', default=True, help='Whether to include operators in the mirroring configuration.')
def main(context, platform, operators):
    if not platform and not operators:
        exit("Neither platform nor operators selected for instrospection. Nothing to do.")

    try: 
        contexts, current_context = config.list_kube_config_contexts()
    except ConfigException as e:
        exit(e)

    if not contexts:
        exit("Cannot connect to cluster. Couldn't find any context in " + config.KUBE_CONFIG_DEFAULT_LOCATION)

    contexts = [context['name'] for context in contexts]

    if not context:
        if not current_context:
            context, _ = pick(contexts, title="Pick the KUBECONFIG context to load")
        else:
            context = current_context['name']
    else:
        if context not in contexts:
            exit("Specified context '" + context + "' not found in "  + config.KUBE_CONFIG_DEFAULT_LOCATION)

    try:
        client = login_to_cluster(context)
    except ApiException as e:
        if e.status == 401:
            exit("Failed to login to cluster with reason: " + e.reason + " Check your credentials.")

    if not is_compatible_platform():
        exit("The target cluster does not appear to be an OpenShift or OKD cluster. This tool is intended to only work with these two types of Kubernetes distribution.")

    if platform and not can_introspect_platform():
        exit("Not enough permissions to introspect cluster version and update settings. Check your permissions on the ClusterVersion API.")

    if operators and not can_introspect_operators():
        exit("Not enough permissions to introspect installed operators. Check your permissions on the Subscription API across all namespaces.")

    platform_data = get_platform_data(client) if platform else None
    catalog_data = get_catalog_data(client) if operators else None

    if not platform_data.is_on_official_channel():
        exit("This cluster is not using an officially supported channel. A working mirror configuration cannot be created. Please subscribe the cluster to an officially supported Red Hat OpenShift release channel or omit the platform mirroring configuration with --no-platform.")

    mirrorConfiguration = create_imageset_config(platform_data, catalog_data)

    yaml.dump(mirrorConfiguration)

if __name__ == "__main__":
    main()
