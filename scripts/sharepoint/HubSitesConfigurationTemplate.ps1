# Constants
$prefix = $AlyaCompanyNameShort.ToUpper() + "SP"
$themeName = $AlyaCompanyName
$defaultSiteScript = @"
{
  "$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
  "actions": [
    {
      "verb": "applyTheme",
      "themeName": "$themeName"
    },
    {
      "verb": "setRegionalSettings",
      "timeZone": 4,
      "locale": 2055,
      "sortOrder": 25,
      "hourFormat": "24"
    }
  ],
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
#TODO locale and timeZone from config
$cusSubSiteScript = @"
{
  "$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
  "actions": [
    {
      "verb": "applyTheme",
      "themeName": "$themeName"
    },
    {
      "verb": "setRegionalSettings",
      "timeZone": 4,
      "locale": 2055,
      "sortOrder": 25,
      "hourFormat": "24"
    },
    {
      "verb": "createSPList",
      "listName": "Projekte",
      "templateType": 100,
      "addNavLink": true,
      "subactions": [
        {
          "displayName": "Projektname",
          "internalName": "Title",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Text",
          "enforceUnique": true,
          "verb": "addSPField"
        },
        {
          "displayName": "Referenz",
          "internalName": "Referenz",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Text",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "displayName": "Bemerkungen",
          "internalName": "Bemerkungen",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Note",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "verb": "setDescription",
          "description": "Liste der Projekte"
        },
        {
          "verb": "setTitle",
          "title": "Projekte"
        }
      ]
    },
    {
      "verb": "createSPList",
      "listName": "Zeiterfassung",
      "addNavLink": true,
      "templateType": 100,
      "subactions": [
        {
          "displayName": "Beschreibung",
          "internalName": "Title",
          "isRequired": true,
          "addToDefaultView": false,
          "fieldType": "Text",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "schemaXml": "<Field Type=\"Lookup\" DisplayName=\"Projekt\" Required=\"TRUE\" EnforceUniqueValues=\"FALSE\" ShowField=\"Title\" UnlimitedLengthInDocumentLibrary=\"FALSE\" RelationshipDeleteBehavior=\"None\" ID=\"{5ea49afa-f77e-11ea-adc1-0242ac120002}\" StaticName=\"Projekt\" Name=\"Projekt\" />",
          "addToDefaultView": true,
          "targetListName": "Projekte",
          "verb": "addSPLookupFieldXml"
        },
        {
          "displayName": "Datum",
          "internalName": "Datum",
          "isRequired": true,
          "addToDefaultView": true,
          "fieldType": "DateTime",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "displayName": "Aufwand",
          "internalName": "Aufwand",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Number",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "schemaXml": "<Field Type=\"Choice\" DisplayName=\"Ort\" Required=\"TRUE\" Format=\"Dropdown\" StaticName=\"Ort\" Name=\"Ort\"><Default>Remote</Default><CHOICES><CHOICE>Remote</CHOICE><CHOICE>OnSite</CHOICE></CHOICES></Field>",
          "addToDefaultView": true,
          "verb": "addSPFieldXml"
        },
        {
          "displayName": "Fahrzeit",
          "internalName": "Fahrzeit",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Number",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "fieldType": "Boolean",
          "displayName": "Verrechnet",
          "internalName": "Verrechnet",
          "isRequired": true,
          "addToDefaultView": true,
          "verb": "addSPField"
        },
        {
          "verb": "setDescription",
          "description": "Erfasste Aufwände für ein Projekt"
        },
        {
          "verb": "setTitle",
          "title": "Zeiterfassung"
        }
      ]
    }
  ],
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
#TODO locale and timeZone from config
$prtSubSiteScript = @"
{
  "$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
  "actions": [
    {
      "verb": "applyTheme",
      "themeName": "$themeName"
    },
    {
      "verb": "setRegionalSettings",
      "timeZone": 4,
      "locale": 2055,
      "sortOrder": 25,
      "hourFormat": "24"
    },
    {
      "verb": "createSPList",
      "listName": "Kunden",
      "templateType": 100,
      "addNavLink": true,
      "subactions": [
        {
          "displayName": "Kundenname",
          "internalName": "Title",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Text",
          "enforceUnique": true,
          "verb": "addSPField"
        },
        {
          "displayName": "Bemerkungen",
          "internalName": "Bemerkungen",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Note",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "verb": "setDescription",
          "description": "Liste der Kunden"
        },
        {
          "verb": "setTitle",
          "title": "Kunden"
        }
      ]
    },
    {
      "verb": "createSPList",
      "listName": "Projekte",
      "templateType": 100,
      "addNavLink": true,
      "subactions": [
        {
          "displayName": "Projektname",
          "internalName": "Title",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Text",
          "enforceUnique": true,
          "verb": "addSPField"
        },
        {
          "schemaXml": "<Field Type=\"Lookup\" DisplayName=\"Kunde\" Required=\"TRUE\" EnforceUniqueValues=\"FALSE\" ShowField=\"Title\" UnlimitedLengthInDocumentLibrary=\"FALSE\" RelationshipDeleteBehavior=\"None\" ID=\"{5ea49afa-f77e-11ea-adc1-0242ac120003}\" StaticName=\"Kunde\" Name=\"Kunde\" />",
          "addToDefaultView": true,
          "targetListName": "Kunden",
          "verb": "addSPLookupFieldXml"
        },
        {
          "displayName": "Referenz",
          "internalName": "Referenz",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Text",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "displayName": "Bemerkungen",
          "internalName": "Bemerkungen",
          "isRequired": false,
          "addToDefaultView": false,
          "fieldType": "Note",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "verb": "setDescription",
          "description": "Liste der Projekte"
        },
        {
          "verb": "setTitle",
          "title": "Projekte"
        }
      ]
    },
    {
      "verb": "createSPList",
      "listName": "Zeiterfassung",
      "addNavLink": true,
      "templateType": 100,
      "subactions": [
        {
          "displayName": "Beschreibung",
          "internalName": "Title",
          "isRequired": true,
          "addToDefaultView": false,
          "fieldType": "Text",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "schemaXml": "<Field Type=\"Lookup\" DisplayName=\"Projekt\" Required=\"TRUE\" EnforceUniqueValues=\"FALSE\" ShowField=\"Title\" UnlimitedLengthInDocumentLibrary=\"FALSE\" RelationshipDeleteBehavior=\"None\" ID=\"{5ea49afa-f77e-11ea-adc1-0242ac120002}\" StaticName=\"Projekt\" Name=\"Projekt\" />",
          "addToDefaultView": true,
          "targetListName": "Projekte",
          "verb": "addSPLookupFieldXml"
        },
        {
          "displayName": "Datum",
          "internalName": "Datum",
          "isRequired": true,
          "addToDefaultView": true,
          "fieldType": "DateTime",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "displayName": "Aufwand",
          "internalName": "Aufwand",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Number",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "schemaXml": "<Field Type=\"Choice\" DisplayName=\"Ort\" Required=\"TRUE\" Format=\"Dropdown\" StaticName=\"Ort\" Name=\"Ort\"><Default>Remote</Default><CHOICES><CHOICE>Remote</CHOICE><CHOICE>OnSite</CHOICE></CHOICES></Field>",
          "addToDefaultView": true,
          "verb": "addSPFieldXml"
        },
        {
          "displayName": "Fahrzeit",
          "internalName": "Fahrzeit",
          "isRequired": false,
          "addToDefaultView": true,
          "fieldType": "Number",
          "enforceUnique": false,
          "verb": "addSPField"
        },
        {
          "fieldType": "Boolean",
          "displayName": "Verrechnet",
          "internalName": "Verrechnet",
          "isRequired": true,
          "addToDefaultView": true,
          "verb": "addSPField"
        },
        {
          "verb": "setDescription",
          "description": "Erfasste Aufwände für ein Projekt"
        },
        {
          "verb": "setTitle",
          "title": "Zeiterfassung"
        }
      ]
    }
  ],
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
$hubSites = @(
    @{
        short = "ADM"
        title = "$prefix-ADM-Hub"
        url = "$prefix-ADM-Hub"
        template = "TeamSite"
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit in der Administration"
        siteScriptDescription = "Fügt der Hub Site das ADM Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $null
        headerLayout = "Compact"   # Standard, Compact
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
    },
    @{
        short = "CUS"
        title = "$prefix-CUS-Hub"
        url = "$prefix-CUS-Hub"
        template = "TeamSite"
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit mit Kunden"
        siteScriptDescription = "Fügt der Hub Site das CUS Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $cusSubSiteScript
        headerLayout = "Compact"   # Standard, Compact
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
    },
    @{
        short = "PRT"
        title = "$prefix-PRT-Hub"
        url = "$prefix-PRT-Hub"
        template = "TeamSite"
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit mit Partnern"
        siteScriptDescription = "Fügt der Hub Site das PRT Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $prtSubSiteScript
        headerLayout = "Compact"   # Standard, Compact
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
    },
    @{
        short = "COL"
        title = "$prefix-COL-Hub"
        url = "$prefix-COL-Hub"
        template = "TeamSite"
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Kollaboration mit Externen"
        siteScriptDescription = "Fügt der Hub Site das COL Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $null
        headerLayout = "Compact"   # Standard, Compact
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
    },
    @{
        short = "PRI"
        title = "$prefix-PRI-Hub"
        url = "$prefix-PRI-Hub"
        template = "TeamSite"
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für private Seiten"
        siteScriptDescription = "Fügt der Hub Site das PRI Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $null
        headerLayout = "Compact"   # Standard, Compact
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
    }
)
