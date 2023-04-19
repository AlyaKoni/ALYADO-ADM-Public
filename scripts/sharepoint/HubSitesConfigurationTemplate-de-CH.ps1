# Constants
$prefix = "$($AlyaCompanyNameShortM365.ToUpper())SP"
$ThemeName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Theme"
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
  "bindata": {},
  "version": 1
}
"@ #https://www.sitedesigner.io/#/
#TODO locale and timeZone from config
$defaultSubSiteScript = @"
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
						&quot;items[0].sourceItem.url&quot;:&quot;https://www.alyaconsulting.ch/Home/Support&quot;
						
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
						&quot;items[0].sourceItem.url&quot;:&quot;https://www.alyaconsulting.ch/Home/Support&quot;
						
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
    @{
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
    },
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
    @{
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
    },
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
