# Azure Monitor / Log Analytics

Compatible with the `azure-monitor-ingestion` and `azure-monitor-query` SDKs, the
`Microsoft.OperationalInsights` / `Microsoft.Insights` ARM management plane, and any HTTP client.
Floci AZ emulates the **Logs Ingestion API** (push custom logs through a Data Collection Rule) and
the **Log Analytics query API** (read them back with a subset of KQL), all in-process.

> **HTTP-only: no Docker.** Workspaces, Data Collection Endpoints/Rules, ingestion, and querying
> are all in-process. There is no sidecar.

---

## Features

- **Log Analytics workspaces**: `Microsoft.OperationalInsights/workspaces` CreateOrUpdate, Get,
  Delete, and List in a resource group or across the subscription; a `customerId` (workspace GUID) is generated when not supplied, kept across redeploys, and
  indexed for query resolution. `sharedKeys` (and the `listKeys` form ARM templates call) answer
  `primarySharedKey` and `secondarySharedKey`, stable for the workspace's life
- **Data Collection Endpoints (DCE)**: `Microsoft.Insights/dataCollectionEndpoints` CreateOrUpdate,
  Get, Delete, List in a resource group or across the subscription; the returned `logsIngestion.endpoint` points back at the emulator base URL
- **Data Collection Rules (DCR)**: `Microsoft.Insights/dataCollectionRules` CreateOrUpdate, Get,
  Delete, List in a resource group or across the subscription; an `immutableId` is generated when not supplied, kept across
  redeploys, and used to route ingestion
- **Diagnostic settings**: `{resourceUri}/providers/Microsoft.Insights/diagnosticSettings/{name}` on any
  resource, and on a subscription for the Activity Log: CreateOrUpdate, Get, Delete, and List for the resource or
  subscription they extend; see [Diagnostic settings](#diagnostic-settings)
- **Resource ids** compare case-insensitively, as in ARM: a PUT through another casing of the same id
  updates the one resource, and the id keeps the casing it was created with. Workspaces, data
  collection endpoints and rules and diagnostic settings persist under the `monitor` storage mode
- **Logs Ingestion API**: `POST /dataCollectionRules/{immutableId}/streams/{stream}` accepts a JSON
  array of log records (plain or `Content-Encoding: gzip`, which the ingestion SDKs always send), resolves the DCR's Log Analytics destination, and stores each record against
  the destination workspace (`TimeGenerated` is honoured or defaulted to now)
- **Log query API**: `POST /v1/workspaces/{workspaceId}/query` runs a KQL subset over the stored
  records and returns the standard `{tables:[{name,columns,rows}]}` shape with inferred column types

---

## Endpoints

Management operations use ARM paths; ingestion and query use the Monitor data-plane paths.

```
PUT    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces
GET    /subscriptions/{sub}/providers/Microsoft.OperationalInsights/workspaces
GET    /subscriptions/{sub}[/resourceGroups/{rg}]/providers/Microsoft.OperationalInsights/deletedWorkspaces
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
DELETE /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
POST   /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}/sharedKeys
POST   /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}/listKeys

PUT    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints/{name}
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints
GET    /subscriptions/{sub}/providers/Microsoft.Insights/dataCollectionEndpoints
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints/{name}
DELETE /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints/{name}

PUT    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{name}
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules
GET    /subscriptions/{sub}/providers/Microsoft.Insights/dataCollectionRules
GET    /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{name}
DELETE /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{name}

POST   /dataCollectionRules/{immutableId}/streams/{stream}   # data-plane ingestion
POST   /v1/workspaces/{workspaceId}/query                    # data-plane query
```

---

## Quickstart

### 1: Create a workspace, DCE, and DCR

```bash
BASE="http://localhost:4577/subscriptions/my-sub/resourceGroups/my-rg/providers"
API="?api-version=2023-09-01"

# Workspace: capture the returned properties.customerId for queries
curl -s -X PUT "$BASE/Microsoft.OperationalInsights/workspaces/my-ws$API" \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus","properties":{}}'

# Data Collection Endpoint
curl -s -X PUT "$BASE/Microsoft.Insights/dataCollectionEndpoints/my-dce$API" \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus","properties":{}}'

# Data Collection Rule: destination is the workspace; capture properties.immutableId
curl -s -X PUT "$BASE/Microsoft.Insights/dataCollectionRules/my-dcr$API" \
  -H "Content-Type: application/json" \
  -d '{
    "location": "eastus",
    "properties": {
      "destinations": {
        "logAnalytics": [{
          "name": "ws",
          "workspaceResourceId": "/subscriptions/my-sub/resourceGroups/my-rg/providers/Microsoft.OperationalInsights/workspaces/my-ws"
        }]
      }
    }
  }'
```

### 2: Ingest logs

Post a JSON array of records to the DCR's `immutableId` and stream name:

```bash
curl -s -X POST \
  "http://localhost:4577/dataCollectionRules/<immutableId>/streams/Custom-MyTable_CL?api-version=2023-01-01" \
  -H "Content-Type: application/json" \
  -d '[
    {"TimeGenerated":"2026-06-25T10:00:00Z","Level":"INFO","Message":"hello"},
    {"TimeGenerated":"2026-06-25T10:01:00Z","Level":"ERROR","Message":"boom"}
  ]'
# → 204 No Content
```

### 3: Query logs

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

client = LogsQueryClient(DefaultAzureCredential(), endpoint="http://localhost:4577")
response = client.query_workspace(
    workspace_id="<customerId>",
    query="MyTable_CL | where Level == 'ERROR' | project TimeGenerated, Message | take 10",
    timespan=None,
)
for table in response.tables:
    print(table.columns, table.rows)
```

The workspace can be addressed by its `customerId` GUID or by its workspace name; the stream/table
name is matched with or without the `Custom-` prefix and the `_CL` suffix used by custom logs.

---

## Activity Log

`GET /subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values` serves the
subscription Activity Log the way the Activity Logs list operation does. Every management-plane PUT,
PATCH, DELETE and POST action on an existing subscription is recorded as an `Administrative`
entry: a `BeginRequest` entry with status `Started` when the request enters, and an `EndRequest`
entry with `Succeeded` or `Failed`, the HTTP status word as `subStatus` and `properties.statusCode`,
when the request is answered. A write the ARM request gate refuses before its handler runs (an
invalid or taken name, a missing resource group, a policy deny) is logged as `Failed` at `Error`
level with the refusal's error, as Azure shows validation and policy refusals in the Activity Log; a
request refused because its subscription is unknown or read-only is not. Reads and listings are not
logged, as in Azure. Entries carry the caller and
claims of the request's bearer token, the `x-ms-correlation-request-id` and `x-ms-client-request-id`
headers, the `authorization` action and scope, the `httpRequest` method, uri and client address, and
the resource's id, type, provider, group and subscription. Operation names follow ARM:
`Microsoft.Storage/storageAccounts/write`, `.../delete`, `.../listKeys/action`,
`Microsoft.Resources/subscriptions/resourceGroups/write`.

```bash
curl -s "http://localhost:4577/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&\$filter=eventTimestamp%20ge%20'2026-01-01T00:00:00Z'%20and%20resourceGroupName%20eq%20'rg1'" | jq .
```

- **`$filter`** (required) takes `eventTimestamp ge '...'` plus `eventTimestamp le`, `resourceGroupName eq`,
  `resourceUri eq` / `resourceId eq`, `resourceProvider eq`, `correlationId eq`, `eventChannels eq`,
  `levels eq`, `operations eq`, `status eq`, `subStatus eq`, `caller eq`, `category eq` and
  `searchText eq`, joined with `and`; the list-valued fields take comma-separated values. Values are
  quoted or bare tokens, and a date-time without an offset is read as UTC, which is how
  `az monitor activity-log list` sends the window it computes. Anything else answers `400 BadRequest`,
  as does a filter without a start time; errors use this API's flat `{"code": ..., "message": ...}`
  shape rather than ARM's `error` wrapper.
- **`$select`** narrows each entry to the named properties.
- **Paging**: `activity-log.page-size` entries per page (default 1000), the rest behind `nextLink`
  with an opaque `$skiptoken`. Entries are newest first.
- **`Policy` entries**: services that evaluate policy can record
  `Microsoft.Authorization/policies/{effect}/action` entries through `ActivityLog.recordPolicyEffect`,
  with the `properties.policies` JSON the Policy category carries.
- Any `api-version` is accepted, the stable `2015-04-01` and the `2017-03-01-preview` alike.

## Diagnostic settings

A setting is kept as it was sent and answered in the shape Azure answers it. Nothing is made up: a setting sent
with a destination and no `logs` or `metrics` is accepted, as Azure accepts it, and has no categories.

- **On a resource**: every property is written. The destinations (`storageAccountId`, `serviceBusRuleId`,
  `workspaceId`, `eventHubAuthorizationRuleId`, `eventHubName`) and `logAnalyticsDestinationType` are `null` when
  unset, `logs` and `metrics` are `[]` when not sent, each log entry carries `category`, `categoryGroup`, `enabled`
  and `retentionPolicy` (`{"enabled": false, "days": 0}` when not sent), each metric entry `category`, `enabled`
  and `retentionPolicy`, and `location`, `kind`, `tags` and `identity` are `null`.
- **On a subscription** (`/subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings/{name}`, the Activity
  Log's export): the id is `/subscriptions/{id}/providers/microsoft.insights/diagnosticSettings/{name}`, `location`
  is `global`, and only the properties that were sent are written. A read lists every Activity Log category,
  `Security`, `Administrative`, `ServiceHealth`, `Alert`, `Recommendation`, `Policy`, `Autoscale` and
  `ResourceHealth`, those not sent as `"enabled": false`.
- **A missing setting** answers `404` with `{"code": "ResourceNotFound", "message": "The diagnostic setting
  '{name}' doesn't exist."}`. This text is taken from Azure CLI output of 2021; no later capture was found.
- **Categories**: `diagnosticSettingsCategories` on a subscription answers `400 ResourceTypeNotSupported`
  (`The resource type '/' does not support diagnostic settings.`), as Azure does. The categories of each resource
  type are not modelled: on a resource it answers `404`.

With `floci-az.parity-overrides.strict-diagnostic-settings` (on from `parity: strict`), a setting is refused as Azure
refuses it, with the flat `{"code": ..., "message": ...}` body:

| Refused | Answer |
|---|---|
| A subscription log `category` that is not one of the eight Activity Log categories (a category group name sent as `category` included) | `400 BadRequest`, `Category '{category}' is not supported.` |
| A log or metric entry with `retentionPolicy.enabled: true` | `400 BadRequest`, `Diagnostic settings does not support retention for new diagnostic settings.` |
| A data sink (`storageAccountId`, `workspaceId`, `eventHubAuthorizationRuleId`, `serviceBusRuleId`, `marketplacePartnerId`) that another setting of the same resource or subscription already uses for an enabled category this one enables | `409 Conflict`, `Data sink '{sink}' is already used in diagnostic setting '{other}' for category '{category}'. Data sinks can't be reused in different settings on the same category for the same resource.` |

Not refused, in any mode, because no Azure answer could be found for them: a setting with no destination, a sixth
setting on one resource (Azure allows five), a destination that does not exist, a log entry with both `category`
and `categoryGroup` or a setting mixing category groups with categories, `metrics` on a subscription setting, and
the read of a setting saved without categories (Azure may answer it `404`). A resource's category or category group
is not checked against its type.

## Activity Log export

A subscription's diagnostic setting (see [Diagnostic settings](#diagnostic-settings)) exports the subscription's
Activity Log entries as they are recorded: an entry goes through every setting of its subscription with an enabled
log entry naming its category (`Administrative`, `Policy`, ...) or the `allLogs` category group. Azure documents a
latency of 3 to 20 minutes for the Activity Log; floci-az delivers at once. Entries recorded before the setting, and
tenant and management-group entries (no subscription), are not exported.

- **Log Analytics** (`workspaceId`): each entry is a row of the workspace's `AzureActivity` table, readable through
  the query API (`AzureActivity | where CategoryValue == 'Administrative'`). The row carries the table's columns as
  Azure writes them: `OperationNameValue`, `ResourceProviderValue` and `ResourceGroup` uppercased, `_ResourceId` and
  `SubscriptionId` lowercased, `ActivityStatusValue` `Start`, `Success` or `Failure`, `ActivitySubstatusValue` the
  HTTP status word (empty on a start), `Level` `Information`, `Warning` or `Error`, `Caller`, `CallerIpAddress`,
  `CorrelationId`, `EventDataId`, `Hierarchy` (`{tenant}/{management groups}/{subscription}`), `Authorization` and
  `Claims` as text and as `Authorization_d` and `Claims_d`, `Properties` and `Properties_d` (the exported properties
  plus `caller`, `eventDataId`, `eventSubmissionTimestamp`, `httpRequest`, `resource`, `resourceGroup`,
  `resourceProviderValue`, `subscriptionId`, `activityStatusValue` and `activitySubstatusValue`), `HTTPRequest`,
  `TimeGenerated` and `EventSubmissionTimestamp`, `TenantId` the workspace id, `SourceSystem` `Azure` and `Type`
  `AzureActivity`. The deprecated columns (`OperationName`, `Category`, `ActivityStatus`, `ActivitySubstatus`,
  `ResourceId`, `ResourceProvider`, `Resource`, `OperationId`) are empty.
- **Storage account** (`storageAccountId`): each entry's exported record is appended, as one line of JSON (no
  `records` wrapper), to the append blob
  `insights-activity-logs/resourceId=/SUBSCRIPTIONS/{SUBSCRIPTION ID}/y={yyyy}/m={MM}/d={dd}/h={HH}/m=00/PT1H.json`
  of the setting's storage account, one blob per hour in UTC; the container and the blob are created on first use and
  read back through the Blob service. The hour is the entry's own time, which with an immediate delivery is also the
  time it is written; Azure's documentation names the "original generation time" without saying which.
- **Event Hubs** (`eventHubAuthorizationRuleId`, with `eventHubName`): each entry is sent as an event whose body is
  `{"records": [<exported record>]}` to the setting's `eventHubName`, or, when the setting names no hub, to
  `insights-logs-operational-logs`, the hub Azure's documentation says Azure Monitor creates for the Activity Log.
  The namespace is the one the authorization rule's id names; its broker must be running and declare the hub in its
  entities (`FLOCI_AZ_SERVICES_EVENT_HUB_ENTITIES`, or the namespace's `entities`), since floci-az does not create
  the hub as Azure does. Events are sent in the background, in order, without a partition key; one event carries one
  record. Some consumers wait on a hub named `insights-activity-logs` instead, which no Microsoft source names.
- **The exported record**, the resource-log schema storage accounts and event hubs receive, is built once per entry:
  `time`, `resourceId` and `operationName` uppercased, `category`, `resultType` (`Start`, `Success`, `Failure`),
  `resultSignature` (`Started.`, `Succeeded.Created`), `durationMs` as a string (`0` on a start, the time since the
  start on an end), `callerIpAddress`, `correlationId`, `identity` (`authorization` with `scope` and `action`,
  `claims`), `level`, `properties` (the entry's own, plus `eventCategory`, `entity`, `message` and `hierarchy`,
  empty for a Policy entry) and `tenantId`.
- **Not reproduced**: the undocumented `RoleLocation`, `Stamp` and `ReleaseVersion` fields, `properties.requestbody`
  and `responseBody`, `identity.authorization.evidence` (role assignments are not evaluated), and the `audit`
  category group of a subscription setting. A failed entry's `resultSignature` is `Failed.{subStatus}`, as the
  table's columns imply; no exported failure record was found to confirm it. Azure batches several records into
  one event and documents no batch size; the event's content type is not documented either, and none is set.

## Resource logs

A service's resource log records (Key Vault's `AuditEvent`, see [Key Vault](key-vault.md#audit-logs), and Blob
storage's `StorageRead`, `StorageWrite` and `StorageDelete`, see [Blob](blob.md#resource-logs)) go
through every diagnostic setting of the resource with an enabled log entry naming the record's category or one of
its category groups, as they are recorded:

- **Storage account**: one line of JSON per record in the hourly append blob
  `insights-logs-{category}/resourceId={RESOURCE ID}/y={yyyy}/m={MM}/d={dd}/h={HH}/m=00/PT1H.json`, the resource id
  uppercased as the resource logs reference writes it, except for Blob storage, whose paths keep the id's case.
- **Event Hubs**: an event `{"records": [<record>]}` to the setting's `eventHubName`, else to
  `insights-logs-{category}` (`insights-logs-auditevent`); the hub must be declared in the namespace's entities.
- **Log Analytics**: a row of the shared `AzureDiagnostics` table, or, for a setting whose
  `logAnalyticsDestinationType` is `Dedicated`, of the category's own table (`AZKVAuditLogs`). Blob storage's logs
  have no `AzureDiagnostics` form and always go to `StorageBlobLogs`. An `AzureDiagnostics`
  row carries `ResourceId`, `ResourceGroup`, `ResourceProvider`, `ResourceType` and `Resource` uppercased,
  `_ResourceId` lowercased, the schema's columns (`OperationName`, `ResultType`, `ResultSignature`,
  `ResultDescription`, `CorrelationId`, `CallerIPAddress`, `OperationVersion`, `DurationMs`), and every other field
  flattened into a column named after its path joined by `_`, claims under `identity_claim_`, with the suffix of its
  type (`requestUri_s`, `httpStatusCode_d`, `isAccessPolicyMatch_b`, `identity_claim_oid_g`). A list is not
  flattened: it is one `_s` column holding the list as compact JSON (`keyProperties_operations_s` is
  `["sign","verify"]`).

## Supported KQL subset

The query engine implements a pragmatic subset of KQL: enough for the assertions test suites and
local dashboards typically make:

| Operator | Notes |
|---|---|
| `where <expr>` | comparisons `==`, `!=`, `>`, `<`, `>=`, `<=` against string/number/datetime columns |
| `project <cols>` | comma-separated column projection |
| `take N` / `limit N` | row cap |
| `timespan` | request-level `timespan` (ISO-8601 duration such as `PT1H`, or a start/end range) filters by `TimeGenerated` before the query runs |

Column types in the response are inferred from the data (`datetime` for `TimeGenerated`, `bool`,
`long`, `real`, otherwise `string`).

---

## Configuration

```yaml
floci-az:
  services:
    monitor:
      enabled: true
      activity-log:
        enabled: true
        capacity: 10000
        page-size: 1000
```

| Env var | Default | Description |
|---|---|---|
| `FLOCI_AZ_SERVICES_MONITOR_ENABLED` | `true` | Enable/disable the service |
| `FLOCI_AZ_SERVICES_MONITOR_ACTIVITY_LOG_ENABLED` | `true` | Records `Administrative` Activity Log entries for every ARM write, delete and action and serves the list operation |
| `FLOCI_AZ_SERVICES_MONITOR_ACTIVITY_LOG_CAPACITY` | `10000` | Activity Log entries kept in memory; the oldest are dropped beyond it |
| `FLOCI_AZ_SERVICES_MONITOR_ACTIVITY_LOG_PAGE_SIZE` | `1000` | Entries per page of the Activity Log list operation |

Stored log records use the global `StorageBackend` (`FLOCI_AZ_STORAGE_MODE`), so logs can survive
restarts in `persistent`/`hybrid`/`wal` modes.

---

## Notes & limitations

- **Deleted workspaces are kept for 14 days.** A workspace deleted without `force=true`, or with its resource group
  when `parity-overrides.resource-group-delete` makes the group delete cascade, is listed by `deletedWorkspaces` (at
  subscription and resource-group scope) and no longer answers queries or ingestion. A `PUT` on the same id recovers
  it with the same `customerId`, so its shared keys and its ingested records come back. `force=true` removes the
  workspace and frees its name, which is what `azd down --purge` sends. A workspace of the same name in another
  location of the group is not refused while the deleted one is kept.
- **KQL is a subset.** `summarize`, `extend`, `join`, `order by`, `parse`, scalar functions, and
  aggregations are not implemented: only `where` / `project` / `take` / `limit` plus `timespan`
  filtering.
- **The Activity Log is in memory** (`activity-log.capacity` entries, default 10000, `0` keeps none) and covers the
  management plane only: no `ServiceHealth`, `Alert`, `Autoscale`, `Security` or `Recommendation`
  categories, no tenant-level log (`/providers/Microsoft.Insights/eventtypes/management/values` without a
  subscription), and `authorization.role` is not reported.
- **Metrics are out of scope.** Only the logs surface (ingestion + Log Analytics query) is emulated;
  `Microsoft.Insights/metrics`, alerts, action groups, and autoscale are not.
- **Auth is permissive.** Bearer tokens are accepted but not validated (dev mode), matching the rest
  of the emulator.
- **Transformations are ignored.** A DCR's `dataFlows`/`transformKql` are stored but not applied;
  records are written to the workspace as posted.
