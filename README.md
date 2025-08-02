<p align="center">
  <img src="https://github.com/user-attachments/assets/4a9b499f-2301-49f5-9a60-5521b5c35fca" alt="Description" width="600">
</p>

# Potential-Impossible-Travel

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel 
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

##  Scenario

Sometimes corporations have policies against working outside of designated geographic regions, account sharing (this should be standard), or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are too erratic. “Too erratic” can be defined as logging in from multiple geographic regions within a given time period.

Whenever a user logs into Azure or authenticates with their main Azure account, logs will be created in the “SigninLogs” table, which is being forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger whenever a user logs into more than one location in a 7 day time period. Not all triggers will be true positives, but it will give us a chance to investigate.

---

## Detection & Analysis

A user account was flagged for potential impossible travel based on sign-in activity over the past 7 days.

The screenshot below shows the alert configured to trigger when an event of this nature occurs:

<img width="2356" height="638" alt="image" src="https://github.com/user-attachments/assets/ad04b613-c7cd-4b64-ac0d-32ec2b32fa51" />

---

The screenshot below displays the incident that was generated when the above alert was triggered by this type of event:

<img width="2370" height="682" alt="image" src="https://github.com/user-attachments/assets/db451bce-4142-43af-864a-15b76c0a76d3" />

---

## Affected Account:

- Username: e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de@lognpacific.com
- Device/VM: kylesvm
- Instances Detected: 2

**Query used to locate events:**

```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look let NumberOfDifferentLocationsAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName contains "kylesvm"
or UserPrincipalName contains "e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de"
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId | where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

<img width="2200" height="650" alt="image" src="https://github.com/user-attachments/assets/84c253b2-46d5-43fc-be0f-ef2ab86dcb15" />

---

Upon further investigation, sign-in activity was observed from two U.S. locations:

- Boydton, Virginia
- New York, New York

<img width="2074" height="1180" alt="image" src="https://github.com/user-attachments/assets/66fa4bb8-83cf-427e-b80e-2ab69c41798b" />

---

These sign-ins occurred within a 30-minute time window. While the locations are geographically distant, the activity is not considered truly anomalous due to both logins occurring within the same country and a plausible explanation being the use of a VPN or cloud infrastructure redirecting IP location.

**Query used to locate events:**

```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName contains "e3cf69dbacbbce89aa76d8f5acef15ea51a051580fa22288481eedda249514de"
| extend City = tostring(parse_json(LocationDetails).city),
State = tostring(parse_json(LocationDetails).state),
Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project TimeGenerated, UserPrincipalName, City, State, Country | order by TimeGenerated desc
```
<img width="1608" height="772" alt="image" src="https://github.com/user-attachments/assets/beceaac7-2dd0-4b33-b3e2-b316884d7ba8" />

---

## Containment, Eradication, and Recovery

- The alert was determined to be true but benign.
- Sign-ins from Virginia and New York within a short time frame are consistent with expected behavior, particularly if a VPN or Azure-based redirect was involved.
- No suspicious or malicious behavior was identified.
- The user account was not disabled, and no containment actions were necessary.

---

## Post-Incident Activities

- Explored the option of implementing geo-fencing to prevent logins from outside the country.
- Recommended documenting this behavior pattern to avoid similar benign alerts in the future.
