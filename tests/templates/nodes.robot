*** Settings ***
Documentation   Verify Fabric Nodes
Suite Setup     Login APIC
Default Tags    apic   day1   node_policies
Resource        ./apic_common.resource


*** Test Cases ***
# Verify node fabric registration
{% for node in apic.node_policies.nodes | default([]) %}

{% if node.role != 'apic' %}
Verify fabric registration for Node-{{ node.id }}
    ${r}=   GET On Session   apic   /api/mo/uni/controller/nodeidentpol/nodep-{{ node.serial_number }}.json
    Should Be Equal Value Json String   ${r.json()}   $..fabricNodeIdentP.attributes.nodeId   {{ node.id }}
    Should Be Equal Value Json String   ${r.json()}   $..fabricNodeIdentP.attributes.podId   {{ node.pod | default(defaults.apic.node_policies.nodes.pod) }}

{% endif %}
{% endfor %}

{% if apic.node_policies.oob_endpoint_group is defined %}

# Verify oob address configuration
    {% for node in apic.node_policies.nodes | default([]) %}
        {% if node.oob_address is defined %}
Verify oob address for Node-{{ node.id }}
    ${r}=   GET On Session   apic   /api/mo/uni/tn-mgmt/mgmtp-default/oob-{{ apic.node_policies.oob_endpoint_group }}/rsooBStNode-[topology/pod-{{ node.pod  | default(defaults.apic.node_policies.nodes.pod)}}/node-{{ node.id }}].json
    Should Be Equal Value Json String   ${r.json()}   $..mgmtRsOoBStNode.attributes.addr   {{ node.oob_address }}
    Should Be Equal Value Json String   ${r.json()}   $..mgmtRsOoBStNode.attributes.gw   {{ node.oob_gateway }}
    ${r}=   GET On Session   apic   /api/mo/topology/pod-{{ node.pod | default(defaults.apic.node_policies.nodes.pod) }}/node-{{ node.id }}/sys.json
    @{oob_addr}=   Split String   {{ node.oob_address }}   /
    Should Be Equal Value Json String   ${r.json()}   $..topSystem.attributes.oobMgmtAddr   ${oob_addr}[0]
    Should Be Equal Value Json String   ${r.json()}   $..topSystem.attributes.inbMgmtAddrMask   ${oob_addr}[1]
    Should Be Equal Value Json String   ${r.json()}   $..topSystem.attributes.oobMgmtGateway   {{ node.oob_gateway }}
        {% endif %}
    {% endfor %}

{% endif %}