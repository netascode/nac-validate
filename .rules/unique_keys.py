class Rule:
    id = "101"
    description = "Verify unique keys"
    severity = "HIGH"

    @classmethod
    def validate_vrf(cls, tenant):
        results = []
        try:
            values = []
            for vrf in tenant["vrfs"]:
                if vrf["name"] in values:
                    results.append(
                        "apic.tenants.vrfs.name - {}.{}".format(
                            tenant["name"], vrf["name"]
                        )
                    )
                values.append(vrf["name"])
        except KeyError:
            pass
        return results

    @classmethod
    def validate_bd(cls, tenant):
        results = []
        try:
            values = []
            for bd in tenant["bridge_domains"]:
                if bd["name"] in values:
                    results.append(
                        "apic.tenants.bridge_domains.name - {}.{}".format(
                            tenant["name"], bd["name"]
                        )
                    )
                values.append(bd["name"])

                results.extend(cls.validate_bd_subnet(tenant, bd))
        except KeyError:
            pass
        return results

    @classmethod
    def validate_bd_subnet(cls, tenant, bd):
        results = []
        try:
            values = []
            for subnet in bd["subnets"]:
                if subnet["ip"] in values:
                    results.append(
                        "apic.tenants.bridge_domains.subnets.ip - {}.{}.{}".format(
                            tenant["name"], bd["name"], subnet["ip"]
                        )
                    )
                values.append(subnet["ip"])
        except KeyError:
            pass
        return results

    @classmethod
    def validate_ap(cls, tenant):
        results = []
        try:
            values = []
            for ap in tenant["application_profiles"]:
                if ap["name"] in values:
                    results.append(
                        "apic.tenants.application_profiles.name - {}.{}".format(
                            tenant["name"], ap["name"]
                        )
                    )
                values.append(ap["name"])

                results.extend(cls.validate_ap_epg(tenant, ap))
        except KeyError:
            pass
        return results

    @classmethod
    def validate_ap_epg(cls, tenant, ap):
        results = []
        try:
            values = []
            for epg in ap["endpoint_groups"]:
                if epg["name"] in values:
                    results.append(
                        "apic.tenants.application_profiles.endpoint_groups.name - {}.{}.{}".format(
                            tenant["name"], ap["name"], epg["name"]
                        )
                    )
                values.append(epg["name"])
        except KeyError:
            pass
        return results

    @classmethod
    def match(cls, data):
        results = []
        try:
            values = []
            for tenant in data["apic"]["tenants"]:
                if tenant["name"] in values:
                    results.append("apic.tenants.name - {}".format(tenant["name"]))
                values.append(tenant["name"])

                results.extend(cls.validate_vrf(tenant))
                results.extend(cls.validate_bd(tenant))
                results.extend(cls.validate_ap(tenant))

        except KeyError:
            pass
        return results
