#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


#>

# Constants
$prefix = "$($AlyaCompanyNameShortM365.ToUpper())SP"
$ThemeName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Theme"
$defaultSiteScript = @"
{
  "`$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
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
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
#TODO locale and timeZone from config
$defaultSubSiteScript = @"
{
  "`$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
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
      "verb": "joinHubSite",
      "hubSiteId": "##HUBSITEID##",
      "name": "##HUBSITENAME##"
    }
  ],
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
$cusSubSiteScript = @"
{
  "`$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
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
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Name des Projekts\" DisplayName=\"Projektname\" Required=\"TRUE\" Type=\"Text\" Name=\"Title\" SourceID=\"http://schemas.microsoft.com/sharepoint/v3\" StaticName=\"Title\" FromBaseType=\"TRUE\" ShowInNewForm=\"TRUE\" ShowInEditForm=\"TRUE\" />",
          "addToDefaultView": true
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
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Beschreibung des Aufwandes\" DisplayName=\"Beschreibung\" Required=\"TRUE\" Type=\"Text\" Name=\"Title\" SourceID=\"http://schemas.microsoft.com/sharepoint/v3\" StaticName=\"Title\" FromBaseType=\"TRUE\" ShowInNewForm=\"TRUE\" ShowInEditForm=\"TRUE\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPLookupFieldXml",
          "schemaXml": "<Field Description=\"Auf das zu buchende Projekt\" Type=\"Lookup\" DisplayName=\"Projekt\" Required=\"TRUE\" EnforceUniqueValues=\"FALSE\" ShowField=\"Title\" UnlimitedLengthInDocumentLibrary=\"FALSE\" RelationshipDeleteBehavior=\"None\" ID=\"{5ea49afa-f77e-11ea-adc1-0242ac120002}\" StaticName=\"Projekt\" Name=\"Projekt\" />",
          "addToDefaultView": true,
          "targetListName": "Projekte"
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Datum der Dienstleistung\" DisplayName=\"Datum\" FriendlyDisplayFormat=\"Disabled\" Format=\"DateOnly\" Name=\"Datum\" Required=\"TRUE\" Title=\"Datum\" Type=\"DateTime\" ID=\"{7c6830e2-3fff-4ecc-b277-7fcfdf53579b}\" StaticName=\"Datum\"><Default>[today]</Default></Field>",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Decimals=\"2\" Description=\"Aufwand in Stunden\" DisplayName=\"Aufwand\" Format=\"Dropdown\" Min=\"0\" Name=\"Aufwand\" Percentage=\"FALSE\" Required=\"TRUE\" Title=\"Aufwand\" Type=\"Number\" ID=\"{099f6e16-46d1-4936-9645-6e0fc91cccfb}\" StaticName=\"Aufwand\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Ort der Leistungserbringung\" Type=\"Choice\" DisplayName=\"Ort\" Required=\"TRUE\" Format=\"Dropdown\" StaticName=\"Ort\" Name=\"Ort\" ID=\"{71638146-62b0-495b-9dce-f9f11a90d86a}\"><Default>Remote</Default><CHOICES><CHOICE>Remote</CHOICE><CHOICE>OnSite</CHOICE></CHOICES></Field>",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Decimals=\"2\" Description=\"Reisezeit zum Kunden\" DisplayName=\"Fahrzeit\" Format=\"Dropdown\" Min=\"0\" Name=\"Fahrzeit\" Percentage=\"FALSE\" Required=\"FALSE\" Title=\"Fahrzeit\" Type=\"Number\" ID=\"{1be037a2-c97e-49ff-913c-4d8a9c5c73bc}\" StaticName=\"Fahrzeit\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Gibt an, ob die Leistung bereits verrechnet wurde\" DisplayName=\"Verrechnet\" Format=\"Dropdown\" Name=\"Verrechnet\" Title=\"Verrechnet\" Type=\"Boolean\" ID=\"{7ed723dc-b331-4119-a158-1ce8c02684b5}\" StaticName=\"Verrechnet\"><Default>0</Default></Field>",
          "addToDefaultView": true
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
    },
    {
      "verb": "joinHubSite",
      "hubSiteId": "##HUBSITEID##",
      "name": "##HUBSITENAME##"
    }
  ],
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
#TODO locale and timeZone from config
$prtSubSiteScript = @"
{
  "`$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
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
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Name des Projekts\" DisplayName=\"Projektname\" Required=\"TRUE\" Type=\"Text\" Name=\"Title\" SourceID=\"http://schemas.microsoft.com/sharepoint/v3\" StaticName=\"Title\" FromBaseType=\"TRUE\" ShowInNewForm=\"TRUE\" ShowInEditForm=\"TRUE\" />",
          "addToDefaultView": true
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
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Beschreibung des Aufwandes\" DisplayName=\"Beschreibung\" Required=\"TRUE\" Type=\"Text\" Name=\"Title\" SourceID=\"http://schemas.microsoft.com/sharepoint/v3\" StaticName=\"Title\" FromBaseType=\"TRUE\" ShowInNewForm=\"TRUE\" ShowInEditForm=\"TRUE\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPLookupFieldXml",
          "schemaXml": "<Field Description=\"Auf das zu buchende Projekt\" Type=\"Lookup\" DisplayName=\"Projekt\" Required=\"TRUE\" EnforceUniqueValues=\"FALSE\" ShowField=\"Title\" UnlimitedLengthInDocumentLibrary=\"FALSE\" RelationshipDeleteBehavior=\"None\" ID=\"{5ea49afa-f77e-11ea-adc1-0242ac120002}\" StaticName=\"Projekt\" Name=\"Projekt\" />",
          "addToDefaultView": true,
          "targetListName": "Projekte"
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Datum der Dienstleistung\" DisplayName=\"Datum\" FriendlyDisplayFormat=\"Disabled\" Format=\"DateOnly\" Name=\"Datum\" Required=\"TRUE\" Title=\"Datum\" Type=\"DateTime\" ID=\"{7c6830e2-3fff-4ecc-b277-7fcfdf53579b}\" StaticName=\"Datum\"><Default>[today]</Default></Field>",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Decimals=\"2\" Description=\"Aufwand in Stunden\" DisplayName=\"Aufwand\" Format=\"Dropdown\" Min=\"0\" Name=\"Aufwand\" Percentage=\"FALSE\" Required=\"TRUE\" Title=\"Aufwand\" Type=\"Number\" ID=\"{099f6e16-46d1-4936-9645-6e0fc91cccfb}\" StaticName=\"Aufwand\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Ort der Leistungserbringung\" Type=\"Choice\" DisplayName=\"Ort\" Required=\"TRUE\" Format=\"Dropdown\" StaticName=\"Ort\" Name=\"Ort\" ID=\"{71638146-62b0-495b-9dce-f9f11a90d86a}\"><Default>Remote</Default><CHOICES><CHOICE>Remote</CHOICE><CHOICE>OnSite</CHOICE></CHOICES></Field>",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Decimals=\"2\" Description=\"Reisezeit zum Kunden\" DisplayName=\"Fahrzeit\" Format=\"Dropdown\" Min=\"0\" Name=\"Fahrzeit\" Percentage=\"FALSE\" Required=\"FALSE\" Title=\"Fahrzeit\" Type=\"Number\" ID=\"{1be037a2-c97e-49ff-913c-4d8a9c5c73bc}\" StaticName=\"Fahrzeit\" />",
          "addToDefaultView": true
        },
        {
          "verb": "addSPFieldXml",
          "schemaXml": "<Field Description=\"Gibt an, ob die Leistung bereits verrechnet wurde\" DisplayName=\"Verrechnet\" Format=\"Dropdown\" Name=\"Verrechnet\" Title=\"Verrechnet\" Type=\"Boolean\" ID=\"{7ed723dc-b331-4119-a158-1ce8c02684b5}\" StaticName=\"Verrechnet\"><Default>0</Default></Field>",
          "addToDefaultView": true
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
    },
    {
      "verb": "joinHubSite",
      "hubSiteId": "##HUBSITEID##",
      "name": "##HUBSITENAME##"
    }
  ],
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
$homePageTemplateGenHubTeamSite = @"
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2020/02/ProvisioningSchema">
  <pnp:Preferences Generator="OfficeDevPnP.Core, Version=3.22.2006.2, Culture=neutral, PublicKeyToken=5e633289e95c321a" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-A2BA1813C436408E9D627E9700B0CBE6">
    <pnp:ProvisioningTemplate ID="TEMPLATE-A2BA1813C436408E9D627E9700B0CBE6" Version="0" Scope="Undefined">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Homepage" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="Default" LayoutType="FullWidthImage" TextAlignment="Center" ShowTopicHeader="false" ShowPublishDate="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="TwoColumnLeft">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, 
				
					&quot;instanceId&quot;: &quot;418ba70b-4cf7-410a-a5fd-ea38386915ac&quot;, 
					&quot;title&quot;: &quot;Quick links&quot;, 
					&quot;description&quot;: &quot;&quot;, 
					&quot;dataVersion&quot;: &quot;2.2&quot;, 
					&quot;properties&quot;:{&quot;items&quot;:[],
					&quot;isMigrated&quot;:true,&quot;layoutId&quot;:&quot;Button&quot;,
					&quot;shouldShowThumbnail&quot;:true,
					&quot;hideWebPartWhenEmpty&quot;:true,
					&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,
					&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;showIcon&quot;:true},
					&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;buttonTreatment&quot;:2,&quot;iconPositionType&quot;:2,
					&quot;textAlignmentVertical&quot;:2,
					&quot;textAlignmentHorizontal&quot;:2,
					&quot;linesOfText&quot;:2},
					&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,
					&quot;onlyShowThumbnail&quot;:false},
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,
					&quot;pane_link_button&quot;:0,
					&quot;imageWidth&quot;:100}, 
					&quot;serverProcessedContent&quot;:{&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{
					
						&quot;title&quot;:&quot;Featured&quot;,
						&quot;items[0].title&quot;:&quot;Support&quot;
						
					},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{
					
						&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;,
						&quot;items[0].sourceItem.url&quot;:&quot;$($AlyaSupportUrl)&quot;
						
					},
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="1" Column="1" />
                
				<pnp:CanvasControl WebPartType="ContentRollup" JsonControlData="{
				
					&quot;id&quot;: &quot;daf0b71c-6de8-4ef7-b511-faae7c388708&quot;, 
					&quot;instanceId&quot;: &quot;1d62f704-40f0-47e7-be5a-4f7e56be06a0&quot;, 
					&quot;title&quot;: &quot;Highlighted content&quot;, &quot;description&quot;: &quot;Dynamically display content based on location, type, and filtering&quot;, &quot;dataVersion&quot;: &quot;2.4&quot;, 
					&quot;properties&quot;: {&quot;displayMaps&quot;:{&quot;1&quot;:{&quot;headingText&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;headingUrl&quot;:{&quot;sources&quot;:[&quot;SPWebUrl&quot;]},
					&quot;title&quot;:{&quot;sources&quot;:[&quot;UserName&quot;,
					&quot;Title&quot;]},
					&quot;personImageUrl&quot;:{&quot;sources&quot;:[&quot;ProfileImageSrc&quot;]},
					&quot;name&quot;:{&quot;sources&quot;:[&quot;Name&quot;]},
					&quot;initials&quot;:{&quot;sources&quot;:[&quot;Initials&quot;]},
					&quot;itemUrl&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]},
					&quot;activity&quot;:{&quot;sources&quot;:[&quot;ModifiedDate&quot;]},
					&quot;previewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;,
					&quot;PictureThumbnailURL&quot;]},
					&quot;iconUrl&quot;:{&quot;sources&quot;:[&quot;IconUrl&quot;]},
					&quot;accentColor&quot;:{&quot;sources&quot;:[&quot;AccentColor&quot;]},
					&quot;cardType&quot;:{&quot;sources&quot;:[&quot;CardType&quot;]},
					&quot;tipActionLabel&quot;:{&quot;sources&quot;:[&quot;TipActionLabel&quot;]},
					&quot;tipActionButtonIcon&quot;:{&quot;sources&quot;:[&quot;TipActionButtonIcon&quot;]},
					&quot;className&quot;:{&quot;sources&quot;:[&quot;ClassName&quot;]}},
					&quot;2&quot;:{&quot;column1&quot;:{&quot;heading&quot;:&quot;&quot;,
					&quot;sources&quot;:[&quot;FileType&quot;],
					&quot;width&quot;:34},
					&quot;column2&quot;:{&quot;heading&quot;:&quot;Title&quot;,
					&quot;sources&quot;:[&quot;Title&quot;],
					&quot;linkUrls&quot;:[&quot;WebPath&quot;],
					&quot;width&quot;:250},
					&quot;column3&quot;:{&quot;heading&quot;:&quot;Modified&quot;,
					&quot;sources&quot;:[&quot;ModifiedDate&quot;],
					&quot;width&quot;:100},
					&quot;column4&quot;:{&quot;heading&quot;:&quot;Modified By&quot;,&quot;sources&quot;:[&quot;Name&quot;],
					&quot;width&quot;:150}},
					&quot;3&quot;:{&quot;id&quot;:{&quot;sources&quot;:[&quot;UniqueID&quot;]},
					&quot;edit&quot;:{&quot;sources&quot;:[&quot;edit&quot;]},
					&quot;DefaultEncodingURL&quot;:{&quot;sources&quot;:[&quot;DefaultEncodingURL&quot;]},
					&quot;FileExtension&quot;:{&quot;sources&quot;:[&quot;FileExtension&quot;]},
					&quot;FileType&quot;:{&quot;sources&quot;:[&quot;FileType&quot;]},
					&quot;Path&quot;:{&quot;sources&quot;:[&quot;Path&quot;]},
					&quot;PictureThumbnailURL&quot;:{&quot;sources&quot;:[&quot;PictureThumbnailURL&quot;]},
					&quot;PreviewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;]},
					&quot;SiteID&quot;:{&quot;sources&quot;:[&quot;SiteID&quot;]},
					&quot;SiteTitle&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;Title&quot;:{&quot;sources&quot;:[&quot;Title&quot;]},
					&quot;UniqueID&quot;:{&quot;sources&quot;:[&quot;UniqueID&quot;]},
					&quot;WebId&quot;:{&quot;sources&quot;:[&quot;WebId&quot;]},
					&quot;WebPath&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]}},
					&quot;4&quot;:{&quot;headingText&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;headingUrl&quot;:{&quot;sources&quot;:[&quot;SPWebUrl&quot;]},
					&quot;title&quot;:{&quot;sources&quot;:[&quot;UserName&quot;,
					&quot;Title&quot;]},
					&quot;personImageUrl&quot;:{&quot;sources&quot;:[&quot;ProfileImageSrc&quot;]},
					&quot;name&quot;:{&quot;sources&quot;:[&quot;Name&quot;]},
					&quot;initials&quot;:{&quot;sources&quot;:[&quot;Initials&quot;]},
					&quot;itemUrl&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]},
					&quot;activity&quot;:{&quot;sources&quot;:[&quot;ModifiedDate&quot;]},
					&quot;previewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;,&quot;PictureThumbnailURL&quot;]},
					&quot;iconUrl&quot;:{&quot;sources&quot;:[&quot;IconUrl&quot;]},
					&quot;accentColor&quot;:{&quot;sources&quot;:[&quot;AccentColor&quot;]},
					&quot;cardType&quot;:{&quot;sources&quot;:[&quot;CardType&quot;]},
					&quot;tipActionLabel&quot;:{&quot;sources&quot;:[&quot;TipActionLabel&quot;]},
					&quot;tipActionButtonIcon&quot;:{&quot;sources&quot;:[&quot;TipActionButtonIcon&quot;]},
					&quot;className&quot;:{&quot;sources&quot;:[&quot;ClassName&quot;]}}},
					&quot;query&quot;:{&quot;contentLocation&quot;:5,
					&quot;contentTypes&quot;:[1],
					&quot;sortType&quot;:4,&quot;filters&quot;:[{&quot;filterType&quot;:1,&quot;value&quot;:&quot;&quot;}],
					&quot;documentTypes&quot;:[99],
					&quot;advancedQueryText&quot;:&quot;contentclass:STS_Site &quot;,
					&quot;sortFieldMatchText&quot;:&quot;site&quot;,
					&quot;sortField&quot;:&quot;SPSiteURL&quot;},
					&quot;templateId&quot;:1,
					&quot;maxItemsPerPage&quot;:50,&quot;hideWebPartWhenEmpty&quot;:false,
					&quot;sites&quot;:[],
					&quot;queryMode&quot;:&quot;Advanced&quot;,
					&quot;layoutId&quot;:&quot;Card&quot;,
					&quot;dataProviderId&quot;:&quot;Search&quot;,
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Alle Seiten / All Sites&quot;},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;},
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;62680648-d047-46ec-81e0-475ee78e482d&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="daf0b71c-6de8-4ef7-b511-faae7c388708" Order="2" Column="1" />
					
				<pnp:CanvasControl WebPartType="News" JsonControlData="{&quot;id&quot;: &quot;8c88f208-6c77-4bdb-86a0-0c47b4316588&quot;, 
				
					&quot;instanceId&quot;: &quot;f7bfdec9-09c5-4fb6-bc97-3ba225d35ad4&quot;, 
					&quot;title&quot;: &quot;News&quot;, 
					&quot;description&quot;: &quot;&quot;, 
					&quot;dataVersion&quot;: &quot;1.11&quot;, 
					&quot;properties&quot;: {&quot;layoutId&quot;:&quot;FeaturedNews&quot;,
					&quot;dataProviderId&quot;:&quot;news&quot;,
					&quot;emptyStateHelpItemsCount&quot;:&quot;1&quot;,
					&quot;showChrome&quot;:true,&quot;carouselSettings&quot;:{&quot;autoplay&quot;:false,
					&quot;autoplaySpeed&quot;:5,
					&quot;dots&quot;:true,&quot;lazyLoad&quot;:true},
					&quot;showNewsMetadata&quot;:{&quot;showSocialActions&quot;:true,
					&quot;showAuthor&quot;:true,
					&quot;showDate&quot;:true},
					&quot;prefetchCount&quot;:4,
					&quot;filters&quot;:[{&quot;filterType&quot;:1,
					&quot;value&quot;:&quot;&quot;,
					&quot;values&quot;:[]}],
					&quot;newsDataSourceProp&quot;:2,
					&quot;newsSiteList&quot;:[],
					&quot;renderItemsSliderValue&quot;:4,
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,
					&quot;layoutComponentId&quot;:&quot;&quot;}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="8c88f208-6c77-4bdb-86a0-0c47b4316588" Order="1" Column="2" />
                
				<pnp:CanvasControl WebPartType="SiteActivity" JsonControlData="{&quot;id&quot;: &quot;eb95c819-ab8f-4689-bd03-0c2d65d47b1f&quot;, 
				
					&quot;instanceId&quot;: &quot;f2a8650b-5ea0-4ac2-9cde-56e0fd0279b0&quot;, 
					&quot;title&quot;: &quot;Site activity&quot;, 
					&quot;description&quot;: &quot;&quot;, 
					&quot;dataVersion&quot;: &quot;1.0&quot;, 
					&quot;properties&quot;: {&quot;maxItems&quot;:9}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="eb95c819-ab8f-4689-bd03-0c2d65d47b1f" Order="2" Column="2" />
				
              </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$homePageTemplateColHubTeamSite = @"
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2020/02/ProvisioningSchema">
  <pnp:Preferences Generator="OfficeDevPnP.Core, Version=3.22.2006.2, Culture=neutral, PublicKeyToken=5e633289e95c321a" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-3940765AA81744DB8C5DE0508525E2B9">
    <pnp:ProvisioningTemplate ID="TEMPLATE-3940765AA81744DB8C5DE0508525E2B9" Version="0" Scope="Undefined">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Homepage" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="Default" LayoutType="FullWidthImage" TextAlignment="Center" ShowTopicHeader="false" ShowPublishDate="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="TwoColumnLeft">
              <pnp:Controls>
			  
                <pnp:CanvasControl WebPartType="Text" ControlId="e99e59fa-fa55-4177-a21d-8e900060b080" Order="1" Column="1">
                  <pnp:CanvasControlProperties>
				  
                    <pnp:CanvasControlProperty Key="Text" Value="&lt;h2&gt;Willkommen auf der Informationsseite für Kunden und Partner der $($AlyaCompanyNameFull)&lt;/h2&gt;&lt;p&gt;Auf dieser Seite findest Du alle Informationen, die Dir von uns zur Verfügung gestellt werden.&amp;nbsp;&lt;/p&gt;" />
                  
				  </pnp:CanvasControlProperties>
                </pnp:CanvasControl>
				
                <pnp:CanvasControl WebPartType="Text" ControlId="3365c6c2-b36a-4618-aab8-77eec661df40" Order="2" Column="1">
                  <pnp:CanvasControlProperties>
				  
                    <pnp:CanvasControlProperty Key="Text" Value="&lt;h2&gt;Welcome to the information page for customers and partners of $($AlyaCompanyNameFull)&lt;/h2&gt;&lt;p&gt;On this page you will find all the information that we have made available to you.&amp;nbsp;&lt;/p&gt;" />
                  
				  </pnp:CanvasControlProperties>
                </pnp:CanvasControl>
				
                <pnp:CanvasControl WebPartType="ContentRollup" JsonControlData="{&quot;id&quot;: &quot;daf0b71c-6de8-4ef7-b511-faae7c388708&quot;, 
				
					&quot;instanceId&quot;: &quot;8b3a9561-b6d3-4298-bd5f-2090cf72c5c4&quot;, 
					&quot;title&quot;: &quot;Hervorgehobener Inhalt&quot;, 
					&quot;description&quot;: &quot;Dynamisches Anzeigen von Inhalten, basierend auf Ort, Typ und Filterung.&quot;, 
					&quot;dataVersion&quot;: &quot;2.4&quot;, 
					&quot;properties&quot;: {&quot;displayMaps&quot;:{&quot;1&quot;:{&quot;headingText&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;headingUrl&quot;:{&quot;sources&quot;:[&quot;SPWebUrl&quot;]},
					&quot;title&quot;:{&quot;sources&quot;:[&quot;UserName&quot;,
					&quot;Title&quot;]},
					&quot;personImageUrl&quot;:{&quot;sources&quot;:[&quot;ProfileImageSrc&quot;]},
					&quot;name&quot;:{&quot;sources&quot;:[&quot;Name&quot;]},
					&quot;initials&quot;:{&quot;sources&quot;:[&quot;Initials&quot;]},
					&quot;itemUrl&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]},
					&quot;activity&quot;:{&quot;sources&quot;:[&quot;ModifiedDate&quot;]},
					&quot;previewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;,
					&quot;PictureThumbnailURL&quot;]},
					&quot;iconUrl&quot;:{&quot;sources&quot;:[&quot;IconUrl&quot;]},
					&quot;accentColor&quot;:{&quot;sources&quot;:[&quot;AccentColor&quot;]},
					&quot;cardType&quot;:{&quot;sources&quot;:[&quot;CardType&quot;]},
					&quot;tipActionLabel&quot;:{&quot;sources&quot;:[&quot;TipActionLabel&quot;]},
					&quot;tipActionButtonIcon&quot;:{&quot;sources&quot;:[&quot;TipActionButtonIcon&quot;]},
					&quot;className&quot;:{&quot;sources&quot;:[&quot;ClassName&quot;]}},
					&quot;2&quot;:{&quot;column1&quot;:{&quot;heading&quot;:&quot;&quot;,
					&quot;sources&quot;:[&quot;FileType&quot;],
					&quot;width&quot;:34},
					&quot;column2&quot;:{&quot;heading&quot;:&quot;Titel&quot;,
					&quot;sources&quot;:[&quot;Title&quot;],
					&quot;linkUrls&quot;:[&quot;WebPath&quot;],
					&quot;width&quot;:250},
					&quot;column3&quot;:{&quot;heading&quot;:&quot;Geändert&quot;,
					&quot;sources&quot;:[&quot;ModifiedDate&quot;],
					&quot;width&quot;:100},
					&quot;column4&quot;:{&quot;heading&quot;:&quot;Geändert von&quot;,
					&quot;sources&quot;:[&quot;Name&quot;],
					&quot;width&quot;:150}},
					&quot;3&quot;:{&quot;id&quot;:{&quot;sources&quot;:[&quot;UniqueID&quot;]},
					&quot;edit&quot;:{&quot;sources&quot;:[&quot;edit&quot;]},
					&quot;DefaultEncodingURL&quot;:{&quot;sources&quot;:[&quot;DefaultEncodingURL&quot;]},
					&quot;FileExtension&quot;:{&quot;sources&quot;:[&quot;FileExtension&quot;]},
					&quot;FileType&quot;:{&quot;sources&quot;:[&quot;FileType&quot;]},
					&quot;Path&quot;:{&quot;sources&quot;:[&quot;Path&quot;]},
					&quot;PictureThumbnailURL&quot;:{&quot;sources&quot;:[&quot;PictureThumbnailURL&quot;]},
					&quot;PreviewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;]},
					&quot;SiteID&quot;:{&quot;sources&quot;:[&quot;SiteID&quot;]},
					&quot;SiteTitle&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;Title&quot;:{&quot;sources&quot;:[&quot;Title&quot;]},
					&quot;UniqueID&quot;:{&quot;sources&quot;:[&quot;UniqueID&quot;]},
					&quot;WebId&quot;:{&quot;sources&quot;:[&quot;WebId&quot;]},
					&quot;WebPath&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]}},
					&quot;4&quot;:{&quot;headingText&quot;:{&quot;sources&quot;:[&quot;SiteTitle&quot;]},
					&quot;headingUrl&quot;:{&quot;sources&quot;:[&quot;SPWebUrl&quot;]},
					&quot;title&quot;:{&quot;sources&quot;:[&quot;UserName&quot;,
					&quot;Title&quot;]},
					&quot;personImageUrl&quot;:{&quot;sources&quot;:[&quot;ProfileImageSrc&quot;]},
					&quot;name&quot;:{&quot;sources&quot;:[&quot;Name&quot;]},
					&quot;initials&quot;:{&quot;sources&quot;:[&quot;Initials&quot;]},
					&quot;itemUrl&quot;:{&quot;sources&quot;:[&quot;WebPath&quot;]},
					&quot;activity&quot;:{&quot;sources&quot;:[&quot;ModifiedDate&quot;]},
					&quot;previewUrl&quot;:{&quot;sources&quot;:[&quot;PreviewUrl&quot;,
					&quot;PictureThumbnailURL&quot;]},
					&quot;iconUrl&quot;:{&quot;sources&quot;:[&quot;IconUrl&quot;]},
					&quot;accentColor&quot;:{&quot;sources&quot;:[&quot;AccentColor&quot;]},
					&quot;cardType&quot;:{&quot;sources&quot;:[&quot;CardType&quot;]},
					&quot;tipActionLabel&quot;:{&quot;sources&quot;:[&quot;TipActionLabel&quot;]},
					&quot;tipActionButtonIcon&quot;:{&quot;sources&quot;:[&quot;TipActionButtonIcon&quot;]},
					&quot;className&quot;:{&quot;sources&quot;:[&quot;ClassName&quot;]}}},
					&quot;query&quot;:{&quot;contentLocation&quot;:3,
					&quot;contentTypes&quot;:[1],
					&quot;sortType&quot;:4,&quot;filters&quot;:[{&quot;filterType&quot;:1,
					&quot;value&quot;:&quot;&quot;}],
					&quot;documentTypes&quot;:[99],
					&quot;advancedQueryText&quot;:&quot;contentclass:STS_Site path:{hosturl}/sites/&quot;,
					&quot;sortFieldMatchText&quot;:&quot;Site&quot;,
					&quot;sortField&quot;:&quot;SPSiteURL&quot;},
					&quot;templateId&quot;:2,
					&quot;maxItemsPerPage&quot;:90,
					&quot;hideWebPartWhenEmpty&quot;:false,
					&quot;sites&quot;:[],&quot;queryMode&quot;:&quot;Advanced&quot;,
					&quot;layoutId&quot;:&quot;List&quot;,
					&quot;dataProviderId&quot;:&quot;Search&quot;,
					&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Seiten / Sites&quot;},&quot;imageSources&quot;:{},
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;},
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;cea5863a-b857-46bb-aaf0-ae5f7cb447b6&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="daf0b71c-6de8-4ef7-b511-faae7c388708" Order="3" Column="1" />
					
                <pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, 
				
					&quot;instanceId&quot;: &quot;418ba70b-4cf7-410a-a5fd-ea38386915ac&quot;, 
					&quot;title&quot;: &quot;Quicklinks&quot;, 
					&quot;description&quot;: &quot;&quot;, 
					&quot;dataVersion&quot;: &quot;2.2&quot;, 
					&quot;properties&quot;: {&quot;items&quot;:[],
					&quot;isMigrated&quot;:true,
					&quot;layoutId&quot;:&quot;List&quot;,
					&quot;shouldShowThumbnail&quot;:true,
					&quot;hideWebPartWhenEmpty&quot;:true,
					&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,
					&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;showIcon&quot;:true},
					&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;buttonTreatment&quot;:2,
					&quot;iconPositionType&quot;:2,
					&quot;textAlignmentVertical&quot;:2,
					&quot;textAlignmentHorizontal&quot;:2,
					&quot;linesOfText&quot;:2},
					&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,
					&quot;onlyShowThumbnail&quot;:false},
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,
					&quot;pane_link_button&quot;:0}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{
					
						&quot;title&quot;:&quot;Quicklinks&quot;,
						&quot;items[0].title&quot;:&quot;Support&quot;
					
					},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{
					
						&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;,
						&quot;items[0].sourceItem.url&quot;:&quot;$($AlyaSupportUrl)&quot;
						
					},
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="1" Column="2" />
					
                <pnp:CanvasControl WebPartType="News" JsonControlData="{&quot;id&quot;: &quot;8c88f208-6c77-4bdb-86a0-0c47b4316588&quot;, 
				
					&quot;instanceId&quot;: &quot;f7bfdec9-09c5-4fb6-bc97-3ba225d35ad4&quot;, 
					&quot;title&quot;: &quot;Neuigkeiten&quot;, 
					&quot;description&quot;: &quot;&quot;, 
					&quot;dataVersion&quot;: &quot;1.11&quot;, 
					&quot;properties&quot;: {&quot;layoutId&quot;:&quot;FeaturedNews&quot;,
					&quot;dataProviderId&quot;:&quot;news&quot;,
					&quot;emptyStateHelpItemsCount&quot;:&quot;1&quot;,
					&quot;showChrome&quot;:true,&quot;carouselSettings&quot;:{&quot;autoplay&quot;:false,&quot;autoplaySpeed&quot;:5,
					&quot;dots&quot;:true,
					&quot;lazyLoad&quot;:true},
					&quot;showNewsMetadata&quot;:{&quot;showSocialActions&quot;:true,
					&quot;showAuthor&quot;:true,
					&quot;showDate&quot;:true},
					&quot;prefetchCount&quot;:4,
					&quot;filters&quot;:[{&quot;filterType&quot;:1,
					&quot;value&quot;:&quot;&quot;,
					&quot;values&quot;:[]}],
					&quot;newsDataSourceProp&quot;:1,
					&quot;newsSiteList&quot;:[],
					&quot;renderItemsSliderValue&quot;:4,
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}{site}&quot;},
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;a2752e70-c076-41bf-a42e-1d955b449fbc&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="8c88f208-6c77-4bdb-86a0-0c47b4316588" Order="2" Column="2" />
              
			  </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$homePageTemplateRootTeamSite = @"
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2020/02/ProvisioningSchema">
  <pnp:Preferences Generator="OfficeDevPnP.Core, Version=3.22.2006.2, Culture=neutral, PublicKeyToken=5e633289e95c321a" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-63AB748351994E7FB87B89714DA92117">
    <pnp:ProvisioningTemplate ID="TEMPLATE-63AB748351994E7FB87B89714DA92117" Version="0" Scope="Undefined">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Homepage" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="Default" LayoutType="FullWidthImage" TextAlignment="Center" ShowTopicHeader="false" ShowPublishDate="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="OneColumn">
              <pnp:Controls>
			  
                <pnp:CanvasControl WebPartType="Text" ControlId="afca2a68-4c3c-418f-b19b-c4a1b519d99b" Order="1" Column="1">
                  <pnp:CanvasControlProperties>
				  
                    <pnp:CanvasControlProperty Key="Text" Value="&lt;h2&gt;Willkommen bei $($AlyaCompanyNameFull)&lt;/h2&gt;&lt;p&gt;Wir heissen Dich herzlich willkommen auf der SharePoint Seite von $($AlyaCompanyNameFull). Bitte wähle unten eine Option, um Deine Inhalte möglichst einfach zu finden.&lt;/p&gt;" />
                  
				  </pnp:CanvasControlProperties>
                </pnp:CanvasControl>
				
				<pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, 
					&quot;instanceId&quot;: &quot;ed34bbb9-73ee-43fb-8919-c0dbd312ed7d&quot;, 
					&quot;title&quot;: &quot;Quick links&quot;, 
					&quot;description&quot;: &quot;Add links to important documents and pages.&quot;, 
					&quot;dataVersion&quot;: &quot;2.2&quot;, 
					&quot;properties&quot;: {&quot;items&quot;:[{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,
					&quot;fileExtension&quot;:&quot;&quot;,
					&quot;progId&quot;:&quot;&quot;},
					&quot;thumbnailType&quot;:2,&quot;id&quot;:2,
					&quot;description&quot;:&quot;&quot;,
					&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;contact&quot;},
					&quot;altText&quot;:&quot;&quot;},
					{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,
					&quot;fileExtension&quot;:&quot;&quot;,
					&quot;progId&quot;:&quot;&quot;},
					&quot;thumbnailType&quot;:2,&quot;id&quot;:1,
					&quot;description&quot;:&quot;&quot;,
					&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;userwarning&quot;},
					&quot;altText&quot;:&quot;&quot;}],
					&quot;isMigrated&quot;:true,&quot;layoutId&quot;:&quot;Button&quot;,
					&quot;shouldShowThumbnail&quot;:true,
					&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;buttonTreatment&quot;:2,&quot;iconPositionType&quot;:2,
					&quot;textAlignmentVertical&quot;:2,
					&quot;textAlignmentHorizontal&quot;:2,&quot;linesOfText&quot;:2},
					&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;showIcon&quot;:true},
					&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,
					&quot;onlyShowThumbnail&quot;:false},
					&quot;hideWebPartWhenEmpty&quot;:true,
					&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,
					&quot;pane_link_button&quot;:0}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Bitte wähle eine Option&quot;,
					&quot;items[0].title&quot;:&quot;Ich bin ein $($AlyaCompanyName) Mitarbeiter&quot;,&quot;items[1].title&quot;:&quot;Ich bin KEIN $($AlyaCompanyName) Mitarbeiter&quot;},
					&quot;imageSources&quot;:{&quot;items[1].rawPreviewImageUrl&quot;:&quot;{site}_api{site}v2.1{site}sites{site}alyaconsulting031.sharepoint.com,0ea97c04-97f2-4c4b-9506-d823c3b6bd5a,d587f72d-9c8f-4de7-9d86-61c0a6912374{site}items{site}af646fff-dcb1-4cbd-8d5b-23b36dc6a23a{site}driveItem{site}thumbnails{site}0{site}c400x99999{site}content?preferNoRedirect=true&quot;},
					
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}&quot;,
						&quot;items[0].sourceItem.url&quot;:&quot;{hosturl}/_layouts/15/sharepoint.aspx&quot;,
						&quot;items[1].sourceItem.url&quot;:&quot;{hosturl}/sites/$($prefix)-COL-Hub&quot;},
					
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, &quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="2" Column="1" />
                
				<pnp:CanvasControl WebPartType="Text" ControlId="b5ba8bc7-de7a-4ffc-afeb-9ce950dbee6b" Order="3" Column="1">
                  <pnp:CanvasControlProperties>
				  
                    <pnp:CanvasControlProperty Key="Text" Value="&lt;h2&gt;Welcome to $($AlyaCompanyNameFull)&lt;/h2&gt;&lt;p&gt;We welcome you to the SharePoint site of $($AlyaCompanyNameFull). Please select an option below to find your content as easy as possible.&lt;/p&gt;" />
                  
				  </pnp:CanvasControlProperties>
                </pnp:CanvasControl>
				
                <pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, 
				
					&quot;instanceId&quot;: &quot;76bb7dd8-c956-4289-8ea8-b48c3f275d9c&quot;, 
					&quot;title&quot;: &quot;Quick links&quot;, 
					&quot;description&quot;: &quot;Add links to important documents and pages.&quot;, 
					&quot;dataVersion&quot;: &quot;2.2&quot;, &quot;properties&quot;: {&quot;items&quot;:[{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,
					&quot;fileExtension&quot;:&quot;&quot;,
					&quot;progId&quot;:&quot;&quot;},
					&quot;thumbnailType&quot;:2,
					&quot;id&quot;:1,
					&quot;description&quot;:&quot;&quot;,
					&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;contact&quot;},
					&quot;altText&quot;:&quot;&quot;},
					{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,
					&quot;fileExtension&quot;:&quot;&quot;,
					&quot;progId&quot;:&quot;&quot;},
					&quot;thumbnailType&quot;:2,
					&quot;id&quot;:2,
					&quot;description&quot;:&quot;&quot;,
					&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;userwarning&quot;},
					&quot;altText&quot;:&quot;&quot;}],
					&quot;isMigrated&quot;:true,
					&quot;layoutId&quot;:&quot;Button&quot;,
					&quot;shouldShowThumbnail&quot;:true,
					&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;buttonTreatment&quot;:2,
					&quot;iconPositionType&quot;:2,
					&quot;textAlignmentVertical&quot;:2,
					&quot;textAlignmentHorizontal&quot;:2,
					&quot;linesOfText&quot;:2},
					&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,
					&quot;showIcon&quot;:true},
					&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,
					&quot;onlyShowThumbnail&quot;:false},
					&quot;hideWebPartWhenEmpty&quot;:true,
					&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,
					&quot;webId&quot;:&quot;{siteid}&quot;,
					&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,
					&quot;pane_link_button&quot;:0}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					
					&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Please choose an option&quot;,
						&quot;items[0].title&quot;:&quot;I'm an $($AlyaCompanyName) employee&quot;,
						&quot;items[1].title&quot;:&quot;I'm NOT an $($AlyaCompanyName) employee&quot;},
					&quot;imageSources&quot;:{&quot;items[1].rawPreviewImageUrl&quot;:&quot;{site}_api{site}v2.1{site}sites{site}alyaconsulting031.sharepoint.com,0ea97c04-97f2-4c4b-9506-d823c3b6bd5a,d587f72d-9c8f-4de7-9d86-61c0a6912374{site}items{site}af646fff-dcb1-4cbd-8d5b-23b36dc6a23a{site}driveItem{site}thumbnails{site}0{site}c400x99999{site}content?preferNoRedirect=true&quot;},
					
					&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{hosturl}&quot;,
						&quot;items[0].sourceItem.url&quot;:&quot;{hosturl}/_layouts/15/sharepoint.aspx&quot;,
						&quot;items[1].sourceItem.url&quot;:&quot;{hosturl}/sites/$($prefix)-COL-Hub&quot;},
					
					&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, 
					&quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="4" Column="1" />
					
                <pnp:CanvasControl WebPartType="LinkPreview" JsonControlData="{&quot;id&quot;: &quot;6410b3b6-d440-4663-8744-378976dc041e&quot;, 
				
					&quot;instanceId&quot;: &quot;ad97f067-5c9a-48f7-a839-4c63fd16942b&quot;, 
					&quot;title&quot;: &quot;Link&quot;, 
					&quot;description&quot;: &quot;Hinzufügen eines Links und seiner Vorschau für eine Seite, ein Video oder Bild.&quot;, 
					&quot;dataVersion&quot;: &quot;1.0&quot;, 
					&quot;properties&quot;: {&quot;linkPreviewComponentMode&quot;:2,
					&quot;previewContent&quot;:{},
					&quot;title&quot;:&quot;&quot;,
					&quot;description&quot;:&quot;&quot;,
					&quot;url&quot;:&quot;&quot;,
					&quot;imageURL&quot;:&quot;&quot;}, 
					&quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},
					&quot;searchablePlainTexts&quot;:{},
					&quot;imageSources&quot;:{},
					&quot;links&quot;:{}}, 
					&quot;dynamicDataPaths&quot;: {}, 
					&quot;dynamicDataValues&quot;: {}}" ControlId="6410b3b6-d440-4663-8744-378976dc041e" Order="5" Column="1" />
					
              </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$homePageTemplateDocumentSiteCOL = @"
<?xml version="1.0"?>
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2022/09/ProvisioningSchema">
  <pnp:Preferences Generator="PnP.Framework, Version=1.11.2.0, Culture=neutral, PublicKeyToken=0d501f89f11b748c" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-C1EDC7B9CFE0459096B49AB11D7BA245">
    <pnp:ProvisioningTemplate ID="TEMPLATE-C1EDC7B9CFE0459096B49AB11D7BA245" Version="0" Scope="Undefined">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Homepage" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="Default" LayoutType="FullWidthImage" ShowTopicHeader="false" ShowPublishDate="false" ShowBackgroundGradient="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="OneColumn">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="List" JsonControlData="{&quot;id&quot;: &quot;f92bf067-bc19-489e-a556-7fe95f508720&quot;, &quot;instanceId&quot;: &quot;529cd7e5-72ee-4552-8242-bfd0f2e67f6c&quot;, &quot;title&quot;: &quot;Dokumentbibliothek&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;isDocumentLibrary&quot;:true,&quot;showDefaultDocumentLibrary&quot;:true,&quot;webpartHeightKey&quot;:4,&quot;selectedListUrl&quot;:&quot;&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;listTitle&quot;:&quot;Dokumente&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {&quot;filterBy&quot;:{}}}" ControlId="f92bf067-bc19-489e-a556-7fe95f508720" Order="1" Column="1" />
              </pnp:Controls>
            </pnp:Section>
            <pnp:Section Order="2" Type="TwoColumnLeft">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="News" JsonControlData="{&quot;id&quot;: &quot;8c88f208-6c77-4bdb-86a0-0c47b4316588&quot;, &quot;instanceId&quot;: &quot;3c6fde1d-e9a5-417f-a4bf-e37a58c313f8&quot;, &quot;title&quot;: &quot;Neuigkeiten&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.12&quot;, &quot;properties&quot;: {&quot;layoutId&quot;:&quot;FeaturedNews&quot;,&quot;dataProviderId&quot;:&quot;news&quot;,&quot;emptyStateHelpItemsCount&quot;:&quot;1&quot;,&quot;showChrome&quot;:true,&quot;carouselSettings&quot;:{&quot;autoplay&quot;:false,&quot;autoplaySpeed&quot;:5,&quot;dots&quot;:true,&quot;lazyLoad&quot;:true},&quot;showNewsMetadata&quot;:{&quot;showSocialActions&quot;:false,&quot;showAuthor&quot;:true,&quot;showDate&quot;:true},&quot;newsDataSourceProp&quot;:1,&quot;carouselHeroWrapperComponentId&quot;:&quot;&quot;,&quot;prefetchCount&quot;:4,&quot;filters&quot;:[{&quot;filterType&quot;:1,&quot;value&quot;:&quot;&quot;,&quot;values&quot;:[]}],&quot;newsSiteList&quot;:[],&quot;renderItemsSliderValue&quot;:4,&quot;layoutComponentId&quot;:&quot;&quot;,&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,&quot;filterKQLQuery&quot;:&quot;&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{},&quot;imageSources&quot;:{},&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{site}&quot;}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="8c88f208-6c77-4bdb-86a0-0c47b4316588" Order="1" Column="1" />
                <pnp:CanvasControl WebPartType="SiteActivity" JsonControlData="{&quot;id&quot;: &quot;eb95c819-ab8f-4689-bd03-0c2d65d47b1f&quot;, &quot;instanceId&quot;: &quot;47d192c0-9ceb-4907-b3e0-4727212f7e6c&quot;, &quot;title&quot;: &quot;Websiteaktivität&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;maxItems&quot;:9}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="eb95c819-ab8f-4689-bd03-0c2d65d47b1f" Order="2" Column="1" />
                <pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, &quot;instanceId&quot;: &quot;3ce69596-0170-4e31-aeb5-77aa76aea7c1&quot;, &quot;title&quot;: &quot;Quicklinks&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;2.2&quot;, &quot;properties&quot;: {&quot;items&quot;:[{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,&quot;fileExtension&quot;:&quot;&quot;,&quot;progId&quot;:&quot;&quot;},&quot;thumbnailType&quot;:2,&quot;id&quot;:1,&quot;description&quot;:&quot;&quot;,&quot;altText&quot;:&quot;&quot;,&quot;rawPreviewImageMinCanvasWidth&quot;:32767,&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;sharepointappicon16&quot;}},{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,&quot;fileExtension&quot;:&quot;&quot;,&quot;progId&quot;:&quot;&quot;},&quot;thumbnailType&quot;:2,&quot;id&quot;:2,&quot;description&quot;:&quot;&quot;,&quot;altText&quot;:&quot;&quot;,&quot;rawPreviewImageMinCanvasWidth&quot;:32767}],&quot;isMigrated&quot;:true,&quot;layoutId&quot;:&quot;List&quot;,&quot;shouldShowThumbnail&quot;:true,&quot;hideWebPartWhenEmpty&quot;:true,&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;showIcon&quot;:true},&quot;imageWidth&quot;:100,&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;buttonTreatment&quot;:2,&quot;iconPositionType&quot;:2,&quot;textAlignmentVertical&quot;:2,&quot;textAlignmentHorizontal&quot;:2,&quot;linesOfText&quot;:2},&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,&quot;onlyShowThumbnail&quot;:false},&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,&quot;pane_link_button&quot;:0,&quot;iconPicker&quot;:&quot;sharepointappicon16&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Quicklinks&quot;,&quot;items[0].title&quot;:&quot;Collaboration Hub&quot;,&quot;items[1].title&quot;:&quot;$($AlyaCompanyName) Webseite&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{&quot;baseUrl&quot;:&quot;https://{fqdn}{site}&quot;,&quot;items[0].sourceItem.url&quot;:&quot;/sites/$($AlyaCompanyNameShortM365)SP-COL-Hub&quot;,&quot;items[1].sourceItem.url&quot;:&quot;$($AlyaWebPage)&quot;},&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="1" Column="2" />
              </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$homePageTemplateDocumentSiteADM = @"
<?xml version="1.0"?>
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2022/09/ProvisioningSchema">
  <pnp:Preferences Generator="PnP.Framework, Version=1.11.2.0, Culture=neutral, PublicKeyToken=0d501f89f11b748c" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-C1EDC7B9CFE0459096B49AB11D7BA245">
    <pnp:ProvisioningTemplate ID="TEMPLATE-C1EDC7B9CFE0459096B49AB11D7BA245" Version="0" Scope="Undefined">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Homepage" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="Default" LayoutType="FullWidthImage" ShowTopicHeader="false" ShowPublishDate="false" ShowBackgroundGradient="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="OneColumn">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="List" JsonControlData="{&quot;id&quot;: &quot;f92bf067-bc19-489e-a556-7fe95f508720&quot;, &quot;instanceId&quot;: &quot;529cd7e5-72ee-4552-8242-bfd0f2e67f6c&quot;, &quot;title&quot;: &quot;Dokumentbibliothek&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;isDocumentLibrary&quot;:true,&quot;showDefaultDocumentLibrary&quot;:true,&quot;webpartHeightKey&quot;:4,&quot;selectedListUrl&quot;:&quot;&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;listTitle&quot;:&quot;Dokumente&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {&quot;filterBy&quot;:{}}}" ControlId="f92bf067-bc19-489e-a556-7fe95f508720" Order="1" Column="1" />
              </pnp:Controls>
            </pnp:Section>
            <pnp:Section Order="2" Type="TwoColumnLeft">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="News" JsonControlData="{&quot;id&quot;: &quot;8c88f208-6c77-4bdb-86a0-0c47b4316588&quot;, &quot;instanceId&quot;: &quot;3c6fde1d-e9a5-417f-a4bf-e37a58c313f8&quot;, &quot;title&quot;: &quot;Neuigkeiten&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.12&quot;, &quot;properties&quot;: {&quot;layoutId&quot;:&quot;FeaturedNews&quot;,&quot;dataProviderId&quot;:&quot;news&quot;,&quot;emptyStateHelpItemsCount&quot;:&quot;1&quot;,&quot;showChrome&quot;:true,&quot;carouselSettings&quot;:{&quot;autoplay&quot;:false,&quot;autoplaySpeed&quot;:5,&quot;dots&quot;:true,&quot;lazyLoad&quot;:true},&quot;showNewsMetadata&quot;:{&quot;showSocialActions&quot;:false,&quot;showAuthor&quot;:true,&quot;showDate&quot;:true},&quot;newsDataSourceProp&quot;:1,&quot;carouselHeroWrapperComponentId&quot;:&quot;&quot;,&quot;prefetchCount&quot;:4,&quot;filters&quot;:[{&quot;filterType&quot;:1,&quot;value&quot;:&quot;&quot;,&quot;values&quot;:[]}],&quot;newsSiteList&quot;:[],&quot;renderItemsSliderValue&quot;:4,&quot;layoutComponentId&quot;:&quot;&quot;,&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,&quot;filterKQLQuery&quot;:&quot;&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{},&quot;imageSources&quot;:{},&quot;links&quot;:{&quot;baseUrl&quot;:&quot;{site}&quot;}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="8c88f208-6c77-4bdb-86a0-0c47b4316588" Order="1" Column="1" />
                <pnp:CanvasControl WebPartType="SiteActivity" JsonControlData="{&quot;id&quot;: &quot;eb95c819-ab8f-4689-bd03-0c2d65d47b1f&quot;, &quot;instanceId&quot;: &quot;47d192c0-9ceb-4907-b3e0-4727212f7e6c&quot;, &quot;title&quot;: &quot;Websiteaktivität&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;maxItems&quot;:9}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="eb95c819-ab8f-4689-bd03-0c2d65d47b1f" Order="2" Column="1" />
                <pnp:CanvasControl WebPartType="QuickLinks" JsonControlData="{&quot;id&quot;: &quot;c70391ea-0b10-4ee9-b2b4-006d3fcad0cd&quot;, &quot;instanceId&quot;: &quot;3ce69596-0170-4e31-aeb5-77aa76aea7c1&quot;, &quot;title&quot;: &quot;Quicklinks&quot;, &quot;description&quot;: &quot;&quot;, &quot;dataVersion&quot;: &quot;2.2&quot;, &quot;properties&quot;: {&quot;items&quot;:[{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,&quot;fileExtension&quot;:&quot;&quot;,&quot;progId&quot;:&quot;&quot;},&quot;thumbnailType&quot;:2,&quot;id&quot;:1,&quot;description&quot;:&quot;&quot;,&quot;altText&quot;:&quot;&quot;,&quot;rawPreviewImageMinCanvasWidth&quot;:32767,&quot;fabricReactIcon&quot;:{&quot;iconName&quot;:&quot;sharepointappicon16&quot;}},{&quot;sourceItem&quot;:{&quot;itemType&quot;:2,&quot;fileExtension&quot;:&quot;&quot;,&quot;progId&quot;:&quot;&quot;},&quot;thumbnailType&quot;:2,&quot;id&quot;:2,&quot;description&quot;:&quot;&quot;,&quot;altText&quot;:&quot;&quot;,&quot;rawPreviewImageMinCanvasWidth&quot;:32767}],&quot;isMigrated&quot;:true,&quot;layoutId&quot;:&quot;List&quot;,&quot;shouldShowThumbnail&quot;:true,&quot;hideWebPartWhenEmpty&quot;:true,&quot;dataProviderId&quot;:&quot;QuickLinks&quot;,&quot;listLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;showIcon&quot;:true},&quot;imageWidth&quot;:100,&quot;buttonLayoutOptions&quot;:{&quot;showDescription&quot;:false,&quot;buttonTreatment&quot;:2,&quot;iconPositionType&quot;:2,&quot;textAlignmentVertical&quot;:2,&quot;textAlignmentHorizontal&quot;:2,&quot;linesOfText&quot;:2},&quot;waffleLayoutOptions&quot;:{&quot;iconSize&quot;:1,&quot;onlyShowThumbnail&quot;:false},&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,&quot;pane_link_button&quot;:0,&quot;iconPicker&quot;:&quot;sharepointappicon16&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;title&quot;:&quot;Quicklinks&quot;,&quot;items[0].title&quot;:&quot;Administration Hub&quot;,&quot;items[1].title&quot;:&quot;SharePoint Home&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{&quot;baseUrl&quot;:&quot;https://{fqdn}{site}&quot;,&quot;items[0].sourceItem.url&quot;:&quot;/sites/$($AlyaCompanyNameShortM365)SP-ADM-Hub&quot;,&quot;items[1].sourceItem.url&quot;:&quot;/_layouts/15/sharepoint.aspx&quot;},&quot;componentDependencies&quot;:{&quot;layoutComponentId&quot;:&quot;706e33c8-af37-4e7b-9d22-6e5694d92a6f&quot;}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="c70391ea-0b10-4ee9-b2b4-006d3fcad0cd" Order="1" Column="2" />
              </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$hubSites = @(
    <#@{
        short = "PRS"
        title = "$prefix-PRS-Hub"
        url = "$prefix-PRS-Hub"
        parent = $null
        externalSharing = $false
        template = "CommunicationSite" # TeamSite, CommunicationSite
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für persönliche Seiten"
        siteScriptDescription = "Fügt der Hub Site das PRS Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $defaultSubSiteScript
        headerLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
        homePageTemplate = $homePageTemplateGenHubTeamSite
    },#>
    @{
        short = "ADM"
        title = "$prefix-ADM-Hub"
        url = "$prefix-ADM-Hub"
        parent = $null
        externalSharing = $false
        template = "CommunicationSite" # TeamSite, CommunicationSite
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit in der Administration"
        siteScriptDescription = "Fügt der Hub Site das ADM Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $defaultSubSiteScript
        headerLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
        homePageTemplate = $homePageTemplateGenHubTeamSite
    },
    <#@{
        short = "CUS"
        title = "$prefix-CUS-Hub"
        url = "$prefix-CUS-Hub"
        parent = $null
        externalSharing = $false
        template = "CommunicationSite" # TeamSite, CommunicationSite
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit mit Kunden"
        siteScriptDescription = "Fügt der Hub Site das CUS Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $cusSubSiteScript
        headerLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
        homePageTemplate = $homePageTemplateGenHubTeamSite
    },
    @{
        short = "PRT"
        title = "$prefix-PRT-Hub"
        url = "$prefix-PRT-Hub"
        parent = $null
        externalSharing = $false
        template = "CommunicationSite" # TeamSite, CommunicationSite
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Zusammenarbeit mit Partnern"
        siteScriptDescription = "Fügt der Hub Site das PRT Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $prtSubSiteScript
        headerLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
        homePageTemplate = $homePageTemplateGenHubTeamSite
    },#>
    @{
        short = "COL"
        title = "$prefix-COL-Hub"
        url = "$prefix-COL-Hub"
        parent = $null
        externalSharing = $true
        template = "CommunicationSite" # TeamSite, CommunicationSite
        locale4Creation = 1031 #TODO from config
        description = "Hub Seite für die Kollaboration mit Externen"
        siteScriptDescription = "Fügt der Hub Site das COL Design hinzu"
        siteScript = $defaultSiteScript
        subSiteScript = $defaultSubSiteScript
        headerLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
        headerEmphasis = "None"  # None, Neutral, Soft, Strong
        siteLogoUrl = $AlyaLogoUrlQuad
        homePageTemplate = $homePageTemplateColHubTeamSite
    }
)
$rootSiteHeaderLayout = "Compact"   # Standard, Compact (others not yet supported by MS)
$rootSiteHeaderEmphasis = "None"  # None, Neutral, Soft, Strong
$rootSiteSiteLogoUrl = $AlyaLogoUrlQuad
$rootSiteQuickLaunchEnabled = $false

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpnwrBT1NqOW0a
# nFXFdli1Pfer/Empj1Em2NRhEYRVC6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINNh1AuJ
# bC3HWYZWM4CF/w1Ewv65qTECuArU4VtZQWFrMA0GCSqGSIb3DQEBAQUABIICAHrg
# PSphah/qTYDpQECscdmbaHQQ3pdgl0a6JtRfdEkywOscqbEm4glw9W+lmDkHCMIf
# vtrQzW0fbBZyXIVwlHJTiO9hOEy5WCni2UTpYwmhYVHCFU0oFnlSyvqev4THz2ob
# dqE+Xo85NDaNAmbBzVf8rkaJoGxWuFXpaZG8CKqP6EQIopEpd9a6CXzH6SF3sUWp
# Zyoz7Tq3wYWMfEu97gvfBBsUWO25kUbGo4PIjH/P9QBvwmGjHxvxNfMnwJWf3X5f
# nCA1qwqQ4zTpKTvuurRmL/aZkd9A4Mea6jjdDH/iyDpwQPHz40t2zA2CQtvyURuE
# xFJnFbi+NsTz3a7u7iD9DSxFHCR4TsvmP3AZbjtudUSsQu8Kc0F0qxSSf+VidXrF
# QT/DPtWizWxtfG5XQ3q2VkeBednZaI5egvjpInVeQzNgsH/fYCw8IRzqvl9fXmQK
# +pj3HUH/dTnF/kOWLVx+1jT8HpUcNiTe8NaO6Ljw8D3jCz/Yd47M4167XDl7cAan
# osjO21BWSpbt8zJKP57di5+rICo3Ht/AKd5f19MlyAIzXPVugEVRGdbuLSM8b/0Q
# tD7QqUZHtlxFkhofBOE75ERvmr8jNRdHtsXpc/KKzGY9WE/Uiv4Qr3oqjETy7zbv
# F9GTr2VuW0SwHh+6bo/aIAzw4/WzO77wOV9y3kORoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCkH2Tga4a1NTmy/Tv6ID4InqU8Ok/i5cqRjzr49CKAUwIUc/j4
# 2cGwVdYfxDUp47I1wl1pMakYDzIwMjUwMjA2MTkzMzU2WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIGGjFTBmjlk6EVsIxnN2sVboHpJ0rg3H
# Ydhpp+K9Wc6XMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGABV2e4xYasVPraSK8otne/B7e3km0gGUjLv0YZKl99NXw
# sqL9RaWbtll7GpSnssaNaxBfWVMD4sMBCXqg7cFmfiQjJfLMtgqrP1VP6Mc79QyA
# Rj5bwf/pKRtD5/vPljSzUqonMNQ0SoGAO811AU9X7nP0s2b0e5FoPkbWhi9vJvA7
# uE/Kcr1npUEHdzo5uCoTk+3iEstRz9bCvf+VnafSR4EwPLSwjfaIMWsyK2Z53GdQ
# +F4FFKVGFkC06I8nWdyCqPL0AMGHv+Sq7RMhTkkVSuMOZ3rsrYVxaVTGt77xY/1h
# BOtNxafRiSSraCQjDX0r9Giodd4KRSL6Q1myGzjsjXEm7p6K3+s8kRP24W+WVj/f
# EyfEkGbqFTahY+O3cwFloto9EFVfafA46R2rpqaLqVpD46PtXYmBo/nAS7bnfZ1X
# norbqRzPrYA8Tx5Bep4uKHMCm5VzLInkO2tbYwpVsMMBw/bZISA+X2t+lj1lR1sm
# ZAlMsN7uU0aWO+YbHC1x
# SIG # End signature block
