# Cisco-SFR-to-FTD-
we faced an issue during migrating from Cisco ASA with Firepower to Firepower Threat Defense..

Problem Description :

we have a very big number of Access Policy Rules on the FMC (Firepower Management Center), all of this rules contains source and destination zone..

Note: SFR interface zone type is "ASA" However FTD interface zone type is "Routed".. and because of that we can't assign the same SFR Access policy to the new FTD..

-to assign this Access policy to the new FTD Device we should first change every zone in each rule to the new FTD zones,

-to do that and before execute my script i created new zones with type Routed

-then i accessed the FMC API and retrieved the zone list

- devided the zones to two different files "new-zones.json" and "old-zones.json"

- then i executed the FMC.py file

this contains script to do the following after the API login to the targeted FMC:
1- select original policy (SFR Policy) to migrate from
2- Select the Destination Policy to migrate to
3- retrieve rules from old policy
4- replace zones from old-zone.json in every rule by the mapped zone in new-zone.json 
5- post the modified rules to the new zone




