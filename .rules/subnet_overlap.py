import ipaddress


class Rule:
    id = "104"
    description = "Verify VRF subnet overlap"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            for tenant in data["apic"]["tenants"]:
                for vrf in tenant["vrfs"]:

                    # get a list of all bridge domain subnets of a vrf
                    subnets = []
                    for bd in tenant["bridge_domains"]:
                        if bd["vrf"] == vrf["name"]:
                            for subnet in bd.get("subnets", []):
                                subnets.append(
                                    ipaddress.ip_network(subnet["ip"], strict=False)
                                )

                    # check subnet overlap with every other subnet
                    for idx, subnet in enumerate(subnets):
                        if idx + 1 >= len(subnets):
                            break
                        for other_subnet in subnets[idx + 1 :]:
                            if subnet.overlaps(other_subnet):
                                results.append(
                                    "apic.tenants.bridge_domains.subnets.ip - {}.{}.{}".format(
                                        tenant["name"], vrf["name"], subnet
                                    )
                                )

        except KeyError:
            pass
        return results
