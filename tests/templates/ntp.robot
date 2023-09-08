*** Settings ***
Documentation   Verify NTP Health
Suite Setup     Login APIC
Default Tags    apic   day1   config   fabric_policies
Resource        ./apic_common.resource

*** Test Cases ***
# Verify NTP configuration
{% for policy in apic.fabric_policies.pod_policies.date_time_policies | default([]) %}
{% set date_time_policy_name = policy.name %}

Verify Date and Time Policy {{ date_time_policy_name }}
    ${r}=   GET On Session   apic   /api/mo/uni/fabric/time-{{ date_time_policy_name }}.json   params=rsp-subtree=full 
    Should Be Equal Value Json String   ${r.json()}   $..datetimePol.attributes.name   {{ date_time_policy_name }}
    Should Be Equal Value Json String   ${r.json()}   $..datetimePol.attributes.adminSt   {{ policy.ntp_admin_state | cisco.nac.nac_bool("enabled") }}
    Should Be Equal Value Json String   ${r.json()}   $..datetimePol.attributes.StratumValue   {{ policy.apic_ntp_server_master_stratum | default(defaults.apic.fabric_policies.pod_policies.date_time_policies.apic_ntp_server_master_stratum) }}
    Should Be Equal Value Json String   ${r.json()}   $..datetimePol.attributes.authSt   {{ policy.ntp_auth_state | cisco.nac.nac_bool("enabled") }}
    Should Be Equal Value Json String   ${r.json()}   $..datetimePol.attributes.serverState   {{ policy.apic_ntp_server_state | cisco.nac.nac_bool("enabled") }}
    {% for server in policy.ntp_servers | default([]) %}

# Verify NTP Server {{ server.hostname_ip }}
    ${server}=   Set Variable   $..datetimePol.children[?(@.datetimeNtpProv.attributes.name=='{{ server.hostname_ip }}')]
    Should Be Equal Value Json String   ${r.json()}    ${server}..datetimeNtpProv.attributes.name   {{ server.hostname_ip }}
    Should Be Equal Value Json String   ${r.json()}    ${server}..datetimeNtpProv.attributes.preferred   {{ server.preferred | default(defaults.apic.fabric_policies.pod_policies.date_time_policies.ntp_servers.preferred) | cisco.nac.nac_bool("yes") }}
    {% endfor %}
{% endfor %}

{% if apic.fabric_policies.pod_policies.date_time_policies is defined %}
    {% for node in apic.node_policies.nodes | default([]) %}
        {% if node.role != 'apic' %}
# Verify NTP state {{ node.id }}
Verify NTP state on node node-{{ node.id }}
   ${r}=   GET On Session   apic   /api/node/mo/topology/pod-{{ node.pod }}/node-{{ node.id }}/sys/time.json   params=rsp-subtree=full
   Should Be Equal Value Json String   ${r.json()}   $..datetimeClkPol.attributes.srvStatus   synced_remote_server
   Should Be Equal Value Json String   ${r.json()}   $..datetimeClkPol.attributes.name   {{ apic.fabric_policies.pod_policies.date_time_policies[0].policy.name }}
   Should Be Equal Value Json String   ${r.json()}   $..datetimeClkPol.attributes.refName   {{ apic.fabric_policies.pod_policies.date_time_policies[0].policy.ntp_servers[0].hostname_ip }}
        {% endif %}
    {% endfor %}
{% endif %}
