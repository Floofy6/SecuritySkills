# Vulnerable NAT and Object Expansion Cases

Use these cases to validate that `firewall-review` reaches conclusions from the effective traffic set, not from alias names alone.

---

## Case 1: Service Group Hides Additional Public Ports

**Configuration excerpt:**

```asa
object-group network DMZ_WEB
  network-object host 10.0.20.10
  network-object host 10.0.20.11

object-group service WEB-SVC tcp
  port-object eq 80
  port-object eq 443
  port-object eq 8443

access-list outside_in extended permit tcp any object-group DMZ_WEB object-group WEB-SVC
```

**Expected review behavior:**

- Flag `FW-EXPAND-01` and `FW-EXPAND-02` if the report only says "`DMZ_WEB` allows web traffic."
- Expanded evidence must show `any -> 10.0.20.10,10.0.20.11 tcp/80,443,8443`.
- Classify as **High** if the rule is internet-facing because tcp/8443 may expose a management or alternate application port that was hidden by the service group name.

---

## Case 2: DNAT/VIP Exposure Missed When Only Internal Destination Is Reviewed

**Configuration excerpt:**

```text
nat rule vip-web
  original source zone: untrust
  original destination: 203.0.113.10
  original service: tcp/443
  translated destination: 10.0.20.15
  translated service: tcp/8443

security rule allow-vip-web
  source zone: untrust
  destination zone: dmz
  destination address: 10.0.20.15
  service: tcp/8443
  action: allow
```

**Expected review behavior:**

- Flag `FW-NAT-01` if the review fails to join the public VIP to the internal security rule.
- Expanded evidence must include both `203.0.113.10:443` pre-translation and `10.0.20.15:8443` post-translation.
- The exposure conclusion should be based on the public listener, not only the internal object.

---

## Case 3: Nested Object Group Makes Shadowed Deny Visible

**Configuration excerpt:**

```asa
object-group network APP_NETS
  network-object 10.40.0.0 255.255.0.0
  group-object APP_ADMIN_NETS

object-group network APP_ADMIN_NETS
  network-object 10.40.50.0 255.255.255.0

access-list internal extended permit tcp object-group APP_NETS any eq 22
access-list internal extended deny tcp 10.40.50.0 255.255.255.0 any eq 22
```

**Expected review behavior:**

- Flag `FW-SHADOW-01` if shadow analysis compares `APP_NETS` and `10.40.50.0/24` as unrelated strings.
- Expanded evidence must show that `10.40.50.0/24` is contained in `APP_NETS`.
- Classify the shadowed deny as **High** because a security control intended to block SSH from the admin subnet is ineffective.
