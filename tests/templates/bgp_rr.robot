*** Settings ***
Documentation   Verify BGP Configuration
Suite Setup     Login APIC
Default Tags    apic   day1   config   fabric_policies
Resource        ./apic_common.resource

*** Test Cases ***
# Verify BGP RR Configuration on APIC
{% for node_id in apic.fabric_policies.fabric_bgp_rr | default([]) %}

Verify BGP RR Configuration for Node-{{ node_id }}
    ${r}=   GET On Session   apic   /api/mo/uni/fabric/bgpInstP-default/rr/node-{{ node_id }}.json
    Should Be Equal Value Json String   ${r.json()}   $..bgpRRNodePEp.attributes.id   {{ node_id }}
{% endfor %}

# Verify BGP RR Configuration on nodes
{% for node_id in apic.fabric_policies.fabric_bgp_rr | default([]) %}

Verify BGP RR Configuration on Node-{{ node_id }}
    ${node_info}=   GET On Session   apic   /api/mo/uni/fabric/bgpInstP-default/rr/node-{{ node_id }}.json
    ${pod_id}=   Get Value From Json   ${node_info.json()}   $..bgpRRNodePEp.attributes.podId 
    ${fabric_info}=   GET On Session   apic   /api/mo/uni/controller/setuppol/setupp-1.json
    ${tep_pool}=   GET Value From Json   ${fabric_info.json()}   $..fabricSetupP.attributes.tepPool
    ${r}=   GET On Session   apic   /api/mo/topology/pod-${pod_id}[0]/node-{{ node_id }}/sys/bgp/inst/dom-overlay-1/peer-[${tep_pool}[0]].json
    Should Be Equal Value Json String   ${r.json()}   $..bgpPeer.attributes.addr   ${tep_pool}[0]
{% endfor %} 

# Verify BGP AS Configuration
{% if apic.fabric_policies.fabric_bgp_as is defined %}

Verify BGP AS Configuration on APIC
    ${r}=   GET On Session   apic   /api/mo/uni/fabric/bgpInstP-default.json   params=query-target=subtree&target-subtree-class=bgpAsP
    Should Be Equal Value Json String   ${r.json()}   $..bgpAsP.attributes.asn   {{ apic.fabric_policies.fabric_bgp_as }}

#Verify BGP AS Configuration on Nodes
    {% for node in apic.node_policies.nodes | default([]) %}
        {% if node.role != 'apic' %}

Verify BGP AS on Node-{{ node.id }}
    ${r}=   GET On Session   apic   /api/mo/topology/pod-{{ node.pod }}/node-{{ node.id }}/sys/bgp/inst/dom-overlay-1.json   params=query-target=subtree&target-subtree-class=bgpPeer
    Should Be Equal Value Json String   ${r.json()}   $..bgpPeer.attributes.asn   {{ apic.fabric_policies.fabric_bgp_as }}     
        {% endif %}
    {% endfor %}
{% endif %}