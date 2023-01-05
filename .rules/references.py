from operator import truediv


class Rule:
    id = "102"
    description = "Verify references"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            for tenant in data["apic"]["tenants"]:
                # check vrf references of bridge_domains
                for bd in tenant["bridge_domains"]:
                    found_vrf = False
                    for vrf in tenant["vrfs"]:
                        if bd["vrf"] == vrf["name"]:
                            found_vrf = True
                            break
                    if not found_vrf:
                        results.append(
                            "apic.tenants.bridge_domains.vrf - {}.{}".format(
                                tenant["name"], bd["name"]
                            )
                        )

                # check bridge_domain references of endpoint_groups
                for ap in tenant["application_profiles"]:
                    for epg in ap["endpoint_groups"]:
                        found_bd = False
                        for bd in tenant["bridge_domains"]:
                            if epg["bridge_domain"] == bd["name"]:
                                found_bd = True
                                break
                        if not found_bd:
                            results.append(
                                "apic.tenants.application_profiles.endpoint_groups.bridge_domain - {}.{}.{}".format(
                                    tenant["name"], ap["name"], epg["name"]
                                )
                            )

        except KeyError:
            pass
        return results
