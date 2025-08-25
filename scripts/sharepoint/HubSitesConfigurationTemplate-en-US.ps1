#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2025

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
      "locale": 1033,
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
      "locale": 1033,
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
      "locale": 1033,
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
      "locale": 1033,
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
        locale4Creation = 1033 #TODO from config
        description = "Hub site for the personal sites"
        siteScriptDescription = "Assigns the PRS site design"
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
        locale4Creation = 1033 #TODO from config
        description = "Hub site for the administrative sites"
        siteScriptDescription = "Assigns the ADM site design"
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
        locale4Creation = 1033 #TODO from config
        description = "Hub site for the collaboration with customers"
        siteScriptDescription = "Assigns the CUS site design"
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
        locale4Creation = 1033 #TODO from config
        description = "Hub site for the collaboration with partners"
        siteScriptDescription = "Assigns the PRT site design"
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
        locale4Creation = 1033 #TODO from config
        description = "Hub site for the collaboration with externals"
        siteScriptDescription = "Assigns the COL site design"
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
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDsxHLVG4LjDZ81
# HoWIumbajrfV7l6aODIa/7/A6sCjEqCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINtWWHdctlsgInz1
# CdSu56QpgBmxomeueAHoyMyvYSRxMA0GCSqGSIb3DQEBAQUABIICAJw6msn5aDne
# Qei35N0O10gUwtSf5f7EDNNai0oW26NRfFYFzOxbvyCcXSp2AEpZCZQU1OSE9D13
# dYAnJebYS0R6SUi+tnCzf4YwPbx6KdiWVTuLKCC1anH0A4AjdQ9F85EoPvdJlvcR
# sd8wpc3JfD3EYLfemfDImAsKo1zEez2IO6dlUeuOGLeFR5hOEYtMnt7pgHvdMiE0
# fBRKopDBIGwv4XWVhSsens3xemhzwEEbccPGUsOam0r1qUJ/0B+enBfpmV/6jG29
# 0DqOzN7UPt+fHCbHgcHsBpEuKHsWmajyyF7OWaXaFxgmS5aFrmmHtTTGTeXpNt6U
# KRb2lf+GmcbNDTY4kp+28ZwYLvH4f3H0lDI/OLs1AAWxNP4hCGXLF4OTEGayU2Bd
# eVsVoHnzFmGs6tFTS1XOIHNyxDSeraeaxC7dIF8khY67uSL1igrnmIFEOz6tRjhg
# S4cIWl7sJFKGC1yPeKkN+07w9SIjX5BseNrWOySvUftJh8nb0nKKj4+5AsABXJBi
# S0riM8xZN2RnozqtqDxisQZoxVw81kZe8diKA3440Vm8nTgE/NdecSUeZrj6oAn3
# y4i2LY3cB4/QYPHdCCy+lAdyjpqCue+tZLKTsaVSkoegCNtcXZP0zfdotM+BsvcM
# joVCzBWVQVDTISytAnttr3wV+L6Hx7z1oYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCC27ALIuTh8agep/lIVZf8SVtV7mN5a7tCXT7+LoPGIIAIUKJS776EJAV00
# /+QGx9NJagyXG1IYDzIwMjUwODI1MTU0OTM5WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IBF9ybIVeVzp3SruCsCJ7ZZqL3db/Syid/ozYQ8YtOnzMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGADmgAZsuRnk1M
# q7V3FM1DzC8w2sh18hZz0Sx9sLwrfmks/BphaQ3pjezaA7pCtFTaE25aspe3gKtb
# xpKfK4vLpJym5dDzjgazHdOrFv4/foShTU9wEQ/tWm5IL1Ex84a5GD6rZG+9cYGZ
# Gdch6kEE5NdhguJyGNZ7nHt4qTD2J7bbYozoNlHHe+Qm7gJiL2tHcUj2qOp88CXM
# igKWu5ruHXcvSa+P3eM3zG6/kST894R7r+I8XgnurWxsuwYtneb96zzVlh/0uTjZ
# yrYK1USb6XDPvcKXFtFuZ/yc20tNGWopMXoYE0pB3e0JZ8LHjJOAA3CtH1es+vjI
# BI+Lam8dPO5EN3eqt8gqoW0j9tOm+tHXSPh0Kvx+rdauwuVeQnAZuu0VLr8D4gvT
# yoIQOLJ5qlZmxynhhoGTX8aMVb9GtbTzI8VmILPN32Oln2wwiost+khe4x5fy1SL
# mb20byKUToaT8ONEA4cnh4OCIDKZk8Sdp1kquoUzpd1ak+ZQb7em
# SIG # End signature block
