class Rule:
    id = "103"
    description = "Verify VRF preferred group"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        vrf_preferred_group_default = (
            data.get("defaults", {})
            .get("apic", {})
            .get("tenants", {})
            .get("vrfs", {})
            .get("preferred_group", False)
        )
        epg_preferred_group_default = (
            data.get("defaults", {})
            .get("apic", {})
            .get("tenants", {})
            .get("application_profiles", {})
            .get("endpoint_groups", {})
            .get("preferred_group", False)
        )
        results = []
        try:
            for tenant in data["apic"]["tenants"]:
                for vrf in tenant["vrfs"]:
                    preferred_group = vrf.get(
                        "preferred_group", vrf_preferred_group_default
                    )

                    # if preferred_group is enabled at the VRF level there is no need to check EPGs
                    if preferred_group:
                        continue

                    # get a list of all bridge domains of a VRF
                    bds = []
                    for bd in tenant["bridge_domains"]:
                        if bd["vrf"] == vrf["name"]:
                            bds.append(bd["name"])

                    # check all EPGs of a VRF if any of them has preferred_group enabled
                    for ap in tenant["application_profiles"]:
                        for epg in ap["endpoint_groups"]:
                            if epg["bridge_domain"] in bds and epg.get(
                                "preferred_group", epg_preferred_group_default
                            ):
                                results.append(
                                    "apic.tenants.application_profiles.endpoint_groups - {}.{}.{}".format(
                                        tenant["name"], ap["name"], epg["name"]
                                    )
                                )

        except KeyError:
            pass
        return results
