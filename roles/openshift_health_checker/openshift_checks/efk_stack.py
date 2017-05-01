# pylint: disable=missing-docstring
'''
  Module for performing checks on an elasticseatch, fluentd, and kibana stack
'''

import json
import os
import ssl
import urllib2

from openshift_checks import OpenShiftCheck, OpenShiftCheckException, get_var


class EFKStack(OpenShiftCheck):
    """Module that checks an EFK stack shipped with OCP"""

    name = "efk_stack"
    tags = ["health"]

    ES_HEALTH_GREEN = 2
    ES_HEALTH_YELLOW = 1
    ES_HEALTH_RED = 0

    def __init__(self, **kwargs):
        super(EFKStack, self).__init__(**kwargs)

        es_curl_base = "curl -s --cert {base}cert --key {base}key --cacert {base}ca -XGET "
        self.es_curl = es_curl_base.format(base="/etc/elasticsearch/secret/admin-")
        watches_base = "watches --url https://localhost:9200 --cert {base}cert --key {base}key --cacert {base}ca"
        self.watches = watches_base.format(base="/etc/elasticsearch/secret/admin-")

    @classmethod
    def is_active(cls, task_vars):
        """Skip hosts that do not have recommended disk space requirements."""
        group_names = get_var(task_vars, "group_names", default=[])
        is_active = "masters" in group_names
        return super(EFKStack, cls).is_active(task_vars) and is_active

    def run(self, tmp, task_vars):
        es_pods, fluentd_pods, curator_pods = self.get_pods(task_vars)

        status = dict()

        status['elasticsearch'] = self.check_elasticsearch(es_pods, task_vars)
        status['fluentd'] = self.check_fluentd(fluentd_pods, task_vars)
        status['curator'] = self.check_curator(curator_pods, task_vars)
        status['kibana_route'] = self.check_kibana_route(task_vars)

        errors = ["The following errors occurred:"]

        if not status["elasticsearch"].get("pods"):
            errors.append("Unable to find any elasticsearch pods. Is elasticsearch deployed on the platform?")

        if status["fluentd"]["number_expected_pods"] != status["fluentd"]["number_pods"]:
            errors.append("Unable to find all expected fluentd pods. "
                          "{expected} pods were expected, but only {found} found."
                          .format(expected=status["fluentd"]["number_expected_pods"],
                                  found=status["fluentd"]["number_pods"])
                          )
        elif status["fluentd"]["node_mismatch"]:
            errors.append("Unable to find a schedulable node for fluentd pods.")

        if not status["kibana_route"]:
            errors.append("No route is defined for Kibana in the logging namespace. Is logging deployed?")
        elif status["kibana_route"].get("route_not_accepted"):
            errors.append("The route for the Kibana logging url is not being routed, "
                          "so we cannot check if it works. Is a router running?")
        elif status["kibana_route"].get("route_missing_host"):
            errors.append("The route for the Kibana logging url has no host defined, "
                          "which should never happen. Did something alter its definition?")
        elif status["kibana_route"].get("bad_response"):
            errors.append("Attempting to access the Kibana logging url returned an invalid response: ")
            errors.append(status["kibana_route"].get("bad_response"))

        if not status["curator"]["number_pods"]:
            errors.append("Unable to find any curator pods. Is curator deployed on the platform?")
        elif not status["curator"]["running"]:
            errors.append("Curator has been deployed, but some or all pods are not yet ready.")

        if len(errors) > 1:
            return {"failed": True, "msg": "\n".join(errors)}

        return {"changed": False, "msg": status}

    def get_pods(self, task_vars):
        """Get all pods and filter them in one pass"""
        pods = json.loads(self.exec_oc("get pods -o json", [], task_vars))
        es_pods = []
        fluentd_pods = []
        curator_pods = []

        for pod in pods['items']:
            if 'component' in pod['metadata']['labels']:
                # Get ES pods
                if pod['metadata']['labels']['component'] == 'es':
                    es_pods.append(pod)
                elif pod['metadata']['labels']['component'] == 'fluentd':
                    fluentd_pods.append(pod)
                elif pod['metadata']['labels']['component'] == 'curator':
                    curator_pods.append(pod)

        return es_pods, fluentd_pods, curator_pods

    def check_elasticsearch(self, es_pods, task_vars):
        """Various checks for elasticsearch"""
        es_status = dict()
        es_status['single_master'] = None
        es_master_name = None
        es_status['pods'] = {}

        for pod in es_pods:
            pod_dc = pod.get('metadata', {}).get('labels', {}).get('deploymentconfig', '')
            if not pod_dc:
                continue

            pod_name = pod.get('metadata', {}).get('name', '')
            es_status['pods'][pod_dc] = {}

            if not pod_name:
                continue

            es_health_check = self.check_es_cluster_health(pod_name, task_vars)
            es_status['pods'][pod_dc]['elasticsearch_health'] = es_health_check

            es_disk_check = self.check_elasticsearch_diskspace(pod_name, task_vars)
            es_status['pods'][pod_dc]['disk'] = es_disk_check

            # Compare the master across all ES nodes to see if we have split brain
            curl_cmd = "{} 'https://localhost:9200/_cat/master'".format(self.es_curl)
            es_master = "exec -ti {} -- {}".format(pod_name, curl_cmd)
            master_name = self.exec_oc(es_master, [pod_name], task_vars).split(' ')[1]

            if es_status['single_master'] is None:
                es_status['single_master'] = True
                es_master_name = master_name
            elif es_master_name != master_name:
                es_status['single_master'] = False

            for watches_cmd in get_var(task_vars, "watches", default=[]):
                cmd = "exec {} -- {} {}".format(pod_name, self.watches, watches_cmd)
                result = self.exec_oc(cmd, [], task_vars)
                try:
                    es_status[watches_cmd] = json.loads(result)
                except ValueError:
                    es_status[watches_cmd] = result

        if not es_master_name:
            return es_status

        # fix for 3.4 logging where es_master_name is getting set to an ip.
        # so we set a try check around in case it fails just so it keeps working for 3.3
        for pod in es_pods:
            try:
                if pod['status']['podIP'] == es_master_name:
                    es_master_name = pod['metadata']['name']
            except ValueError:
                continue

        # get cluster nodes
        curl_cmd = "{} 'https://localhost:9200/_nodes'".format(self.es_curl)
        node_cmd = "exec -ti {} -- {}".format(es_master_name, curl_cmd)

        try:
            cluster_nodes = json.loads(self.exec_oc(node_cmd, [], task_vars))['nodes']
        except ValueError:
            return es_status

        es_status['all_nodes_registered'] = 1
        # The internal ES node name is a random string we do not track anywhere
        # pylint: disable=unused-variable
        for node, data in cluster_nodes.items():
            has_matched = False
            for pod in es_pods:
                if data['host'] == pod['metadata']['name'] or data['host'] == pod['status']['podIP']:
                    has_matched = True
                    break

            if has_matched is False:
                es_status['all_nodes_registered'] = 0

        return es_status

    def check_es_cluster_health(self, es_pod, task_vars):
        """Exec into the elasticsearch pod and check the cluster health"""
        try:
            cmd = "{} cluster_health".format(self.watches)
            cluster_health = "exec {} -- {}".format(es_pod, cmd)
            print "running cmd", cluster_health
            health_res = json.loads(self.exec_oc(cluster_health, [], task_vars))

            if health_res['status'] == 'green':
                return self.ES_HEALTH_GREEN
            elif health_res['status'] == 'yellow':
                return self.ES_HEALTH_YELLOW
            else:
                return self.ES_HEALTH_RED
        except ValueError:
            # The check failed so ES is in a bad state
            return self.ES_HEALTH_RED

    def check_elasticsearch_diskspace(self, es_pod, task_vars):
        """Exec into a elasticsearch pod and query the diskspace"""
        results = {}
        try:
            disk_used = 0
            disk_free = 0
            trash_var = 0

            disk_output = self.exec_oc("exec -ti {} -- df".format(es_pod), [], task_vars).split(' ')
            disk_output = [x for x in disk_output if x]
            for item in disk_output:
                if item != "/elasticsearch/persistent":
                    disk_used = disk_free
                    disk_free = trash_var
                    trash_var = item
                else:
                    break

            results['used'] = int(disk_used)
            results['free'] = int(disk_free)
        except ValueError:
            results['used'] = int(0)
            results['free'] = int(0)

        return results

    def check_fluentd(self, fluentd_pods, task_vars):
        """Verify fluentd is running"""
        fluentd_status = dict(
            number_expected_pods=0,
            number_pods=0,
            node_mismatch=0,
            running=0,
        )

        # Get all nodes with fluentd label
        try:
            nodes = json.loads(self.exec_oc("get nodes -o json", [], task_vars))
        except ValueError:
            return fluentd_status

        fluentd_nodes = []
        for node in nodes['items']:
            if 'logging-infra-fluentd' in node['metadata']['labels']:
                if node['metadata']['labels']['logging-infra-fluentd'] == 'true':
                    fluentd_nodes.append(node)

        # Make sure fluentd is on all the nodes and the pods are running
        fluentd_status['number_expected_pods'] = len(fluentd_nodes)
        fluentd_status['number_pods'] = len(fluentd_pods)
        fluentd_status['node_mismatch'] = 0
        fluentd_status['running'] = 1

        for pod in fluentd_pods:
            node_matched = False

            if pod['status']['containerStatuses'][0]['ready'] is False:
                fluentd_status['running'] = 0

            # If there is already a problem don't worry about looping over the remaining pods/nodes
            for node in fluentd_nodes:
                internal_ip = ""
                for address in node['status']['addresses']:
                    if address['type'] == "InternalIP":
                        internal_ip = address['address']

                if node['metadata']['labels']['kubernetes.io/hostname'] == pod.get('spec', {}).get('host'):
                    node_matched = True
                    break
                elif internal_ip == pod['spec']['nodeName'] or node['metadata']['name'] == pod['spec']['nodeName']:
                    node_matched = True
                    break

            if node_matched is False:
                fluentd_status['node_mismatch'] = 1
                break

        return fluentd_status

    def check_kibana_route(self, task_vars):
        """Check to see if kibana route is up and working"""

        # Get logging url
        get_route = self.exec_oc("get route logging-kibana -o json", [], task_vars)
        if not get_route:
            return {}

        route = json.loads(get_route)

        # check that the route has been accepted by a router
        ingress = route["status"]["ingress"]
        # ingress can be null if there is no router, or empty if not routed
        if not ingress or not ingress[0]:
            return {'route_not_accepted': True}

        host = route.get("spec", {}).get("host")
        if not host:
            return {'route_missing_host': True}

        kibana_url = "https://{}/".format(host)

        # Disable SSL cert verification to work around self signed clusters
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # TODO: True? It should match on hostname
        ctx.verify_mode = ssl.CERT_NONE

        # Verify that the url is returning a valid response
        # We only care if the url opens
        response, failed = self.verify_url(kibana_url, ctx)
        if failed:
            return {'bad_response': str(response)}

        return {'site_up': True}

    @staticmethod
    def verify_url(url, ctx=None):
        res = ""

        try:
            res = urllib2.urlopen(url, context=ctx)
        except urllib2.HTTPError as httperr:
            if httperr.code >= 500:
                return httperr.reason, True

        except urllib2.URLError as urlerr:
            return urlerr, True

        return res, False

    @staticmethod
    def check_curator(curator_pods, task_vars):
        """Check to see if curator is up and working"""
        curator_status = dict()

        curator_status['number_pods'] = len(curator_pods)
        curator_status['running'] = 1

        for pod in curator_pods:
            if pod['status']['containerStatuses'][0]['ready'] is False:
                curator_status['running'] = 0

        return curator_status

    def exec_oc(self, cmd_str, extra_args, task_vars):
        """Execute an 'oc' command in the remote host"""
        config_base = get_var(task_vars, "openshift", "common", "config_base")
        args = {
            "namespace": get_var(task_vars, "openshift_logging_namespace", default="logging"),
            "config_file": os.path.join(config_base, "master", "admin.kubeconfig"),
            "cmd": cmd_str,
            "extra_args": list(extra_args),
        }

        result = self.module_executor("ocutil", args, task_vars)
        if result.get("failed"):
            msg = "error executing `oc` command: \"oc {cmd}\"".format(cmd=args['cmd'])
            raise OpenShiftCheckException(result["result"], msg)

        return result.get("result", "")
