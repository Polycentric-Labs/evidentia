/** Synthetic examples only. No cloud account was queried. */
import type { StorageRetentionCollectResult } from "@/lib/api";

export const STORAGE_RETENTION_EXAMPLES: Record<
  "partial" | "complete" | "unavailable",
  StorageRetentionCollectResult
> = {
  partial: {
    schema_version: "storage-retention-collection/v1",
    provider: "azure",
    scope_label: "synthetic-demo",
    status: "partial",
    started_at: "2024-01-02T03:04:05.123456Z",
    finished_at: "2024-01-02T03:04:07.123456Z",
    observation_scope: "configuration",
    coverage_scope: "selected_resources",
    object_enforcement_assessed: false,
    recordset_completeness_assessed: false,
    identity_basis: "operator-declared",
    authenticated_identity_verified: false,
    requested_resources: 1,
    attempted_resources: 1,
    planned_components: 3,
    attempted_components: 3,
    completed_components: 1,
    resources: [
      {
        target: {
          subscription_id: "11111111-2222-4333-8444-555555555555",
          resource_group: "Synthetic_Group",
          account: "syntheticstore",
          container: "synthetic-container",
        },
        canonical_resource_id:
          "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
        status: "partial",
        components: [
          {
            component_id: "azure-account",
            canonical_resource_id:
              "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
            status: "complete",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 200,
            diagnostics: [],
            projection: {
              api_version: "2026-04-01",
              projection_version: "storage-retention-projection/v1",
              native_scope: "Microsoft.Storage/storageAccounts",
              fields: {
                id: "/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/Synthetic_Group/providers/Microsoft.Storage/storageAccounts/syntheticstore",
                properties: {
                  immutableStorageWithVersioning: {
                    enabled: true,
                    immutabilityPolicy: {
                      allowProtectedAppendWrites: false,
                      immutabilityPeriodSinceCreationInDays: 365,
                      state: "Locked",
                    },
                  },
                  isHnsEnabled: false,
                },
              },
              source_etag: '"synthetic-source-etag"',
              source_metageneration: null,
              canonical_projection_sha256:
                "abf247a6b99064d16ba9201a12fc5f24e3c69a70cb05ff9e6aa51ef62afded24",
            },
          },
          {
            component_id: "azure-blob-service",
            canonical_resource_id:
              "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
            status: "unavailable",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 403,
            diagnostics: [
              {
                code: "forbidden",
                http_status: 403,
              },
            ],
            projection: null,
          },
          {
            component_id: "azure-container",
            canonical_resource_id:
              "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
            status: "partial",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 200,
            diagnostics: [
              {
                code: "unsupported_source_value",
                http_status: null,
              },
            ],
            projection: {
              api_version: "2026-04-01",
              projection_version: "storage-retention-projection/v1",
              native_scope:
                "Microsoft.Storage/storageAccounts/blobServices/containers",
              fields: {
                id: "/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/Synthetic_Group/providers/Microsoft.Storage/storageAccounts/syntheticstore/blobServices/default/containers/synthetic-container",
                properties: {
                  hasImmutabilityPolicy: true,
                  hasLegalHold: false,
                  immutabilityPolicy: {
                    etag: '"synthetic-policy-etag"',
                    properties: {
                      allowProtectedAppendWrites: false,
                      allowProtectedAppendWritesAll: true,
                      immutabilityPeriodSinceCreationInDays: 730,
                      state: "Locked",
                    },
                  },
                  immutableStorageWithVersioning: {
                    enabled: true,
                    migrationState: "Completed",
                    timeStamp: "2024-01-02T03:04:05.1234567Z",
                  },
                  legalHold: {
                    hasLegalHold: true,
                    protectedAppendWritesHistory: {
                      allowProtectedAppendWritesAll: true,
                    },
                    tags: [
                      {
                        tag: "case1",
                      },
                    ],
                  },
                },
              },
              source_etag: '"synthetic-source-etag"',
              source_metageneration: null,
              canonical_projection_sha256:
                "b82c9c603cf5be05521bc9dffb1c55609f365eacd42af6654b999c3f8d97db80",
            },
          },
        ],
      },
    ],
    findings: [
      {
        id: "0b302c80-782a-58f0-9612-3ec29e6dc128",
        title: "Selected storage retention configuration",
        description:
          "Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.",
        severity: "informational",
        status: "active",
        compliance_status: "unknown",
        remediation: null,
        source_system: "storage-retention",
        source_finding_id:
          "azure-retention-configuration:azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
        resource_type:
          "Microsoft.Storage/storageAccounts/blobServices/containers",
        resource_id:
          "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
        resource_region: null,
        resource_account: null,
        control_mappings: [],
        collection_context: {
          collector_id: "storage-retention-scan",
          collector_version: "0.12.1",
          run_id: "synthetic-storage-partial",
          collected_at: "2024-01-02T03:04:07.123456Z",
          credential_identity: "operator-configured:identity-unverified",
          source_system_id:
            "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
          filter_applied: {
            provider: "azure",
            scope_label: "synthetic-demo",
            selected_targets: [
              {
                subscription_id: "11111111-2222-4333-8444-555555555555",
                resource_group: "Synthetic_Group",
                account: "syntheticstore",
                container: "synthetic-container",
              },
            ],
            component_ids: [
              "azure-account",
              "azure-blob-service",
              "azure-container",
            ],
            observation_scope: "configuration",
            coverage_scope: "selected_resources",
            limits: {
              max_targets: 20,
              request_bytes: 65536,
              response_raw_bytes: 1048576,
              response_decoded_bytes: 1048576,
              run_raw_bytes: 16777216,
              run_decoded_bytes: 16777216,
              projection_bytes: 16384,
              run_projection_bytes: 1048576,
              result_bytes: 4194304,
              max_attempts: 3,
              run_seconds: 120,
            },
            canonical_resource_id:
              "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
          },
          pagination_context: null,
          evidentia_version: "0.12.1",
        },
        raw_data: {
          resource: {
            target: {
              subscription_id: "11111111-2222-4333-8444-555555555555",
              resource_group: "Synthetic_Group",
              account: "syntheticstore",
              container: "synthetic-container",
            },
            canonical_resource_id:
              "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
            status: "partial",
            components: [
              {
                component_id: "azure-account",
                canonical_resource_id:
                  "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
                status: "complete",
                attempts: 1,
                raw_bytes: 512,
                decoded_bytes: 512,
                started_at: "2024-01-02T03:04:05.123456Z",
                finished_at: "2024-01-02T03:04:07.123456Z",
                http_status: 200,
                diagnostics: [],
                projection: {
                  api_version: "2026-04-01",
                  projection_version: "storage-retention-projection/v1",
                  native_scope: "Microsoft.Storage/storageAccounts",
                  fields: {
                    id: "/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/Synthetic_Group/providers/Microsoft.Storage/storageAccounts/syntheticstore",
                    properties: {
                      immutableStorageWithVersioning: {
                        enabled: true,
                        immutabilityPolicy: {
                          allowProtectedAppendWrites: false,
                          immutabilityPeriodSinceCreationInDays: 365,
                          state: "Locked",
                        },
                      },
                      isHnsEnabled: false,
                    },
                  },
                  source_etag: '"synthetic-source-etag"',
                  source_metageneration: null,
                  canonical_projection_sha256:
                    "abf247a6b99064d16ba9201a12fc5f24e3c69a70cb05ff9e6aa51ef62afded24",
                },
              },
              {
                component_id: "azure-blob-service",
                canonical_resource_id:
                  "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
                status: "unavailable",
                attempts: 1,
                raw_bytes: 512,
                decoded_bytes: 512,
                started_at: "2024-01-02T03:04:05.123456Z",
                finished_at: "2024-01-02T03:04:07.123456Z",
                http_status: 403,
                diagnostics: [
                  {
                    code: "forbidden",
                    http_status: 403,
                  },
                ],
                projection: null,
              },
              {
                component_id: "azure-container",
                canonical_resource_id:
                  "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
                status: "partial",
                attempts: 1,
                raw_bytes: 512,
                decoded_bytes: 512,
                started_at: "2024-01-02T03:04:05.123456Z",
                finished_at: "2024-01-02T03:04:07.123456Z",
                http_status: 200,
                diagnostics: [
                  {
                    code: "unsupported_source_value",
                    http_status: null,
                  },
                ],
                projection: {
                  api_version: "2026-04-01",
                  projection_version: "storage-retention-projection/v1",
                  native_scope:
                    "Microsoft.Storage/storageAccounts/blobServices/containers",
                  fields: {
                    id: "/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/Synthetic_Group/providers/Microsoft.Storage/storageAccounts/syntheticstore/blobServices/default/containers/synthetic-container",
                    properties: {
                      hasImmutabilityPolicy: true,
                      hasLegalHold: false,
                      immutabilityPolicy: {
                        etag: '"synthetic-policy-etag"',
                        properties: {
                          allowProtectedAppendWrites: false,
                          allowProtectedAppendWritesAll: true,
                          immutabilityPeriodSinceCreationInDays: 730,
                          state: "Locked",
                        },
                      },
                      immutableStorageWithVersioning: {
                        enabled: true,
                        migrationState: "Completed",
                        timeStamp: "2024-01-02T03:04:05.1234567Z",
                      },
                      legalHold: {
                        hasLegalHold: true,
                        protectedAppendWritesHistory: {
                          allowProtectedAppendWritesAll: true,
                        },
                        tags: [
                          {
                            tag: "case1",
                          },
                        ],
                      },
                    },
                  },
                  source_etag: '"synthetic-source-etag"',
                  source_metageneration: null,
                  canonical_projection_sha256:
                    "b82c9c603cf5be05521bc9dffb1c55609f365eacd42af6654b999c3f8d97db80",
                },
              },
            ],
          },
          scope: {
            provider: "azure",
            scope_label: "synthetic-demo",
            selected_targets: [
              {
                subscription_id: "11111111-2222-4333-8444-555555555555",
                resource_group: "Synthetic_Group",
                account: "syntheticstore",
                container: "synthetic-container",
              },
            ],
            component_ids: [
              "azure-account",
              "azure-blob-service",
              "azure-container",
            ],
            observation_scope: "configuration",
            coverage_scope: "selected_resources",
            limits: {
              max_targets: 20,
              request_bytes: 65536,
              response_raw_bytes: 1048576,
              response_decoded_bytes: 1048576,
              run_raw_bytes: 16777216,
              run_decoded_bytes: 16777216,
              projection_bytes: 16384,
              run_projection_bytes: 1048576,
              result_bytes: 4194304,
              max_attempts: 3,
              run_seconds: 120,
            },
          },
          object_enforcement_assessed: false,
          recordset_completeness_assessed: false,
          identity_basis: "operator-declared",
          authenticated_identity_verified: false,
        },
        first_observed: "2024-01-02T03:04:05.123456Z",
        last_observed: "2024-01-02T03:04:07.123456Z",
        resolved_at: null,
      },
    ],
    diagnostics: [],
    manifest: {
      run_id: "synthetic-storage-partial",
      collector_id: "storage-retention-scan",
      collector_version: "0.12.1",
      collection_started_at: "2024-01-02T03:04:05.123456Z",
      collection_finished_at: "2024-01-02T03:04:07.123456Z",
      source_system_ids: [
        "azure:/subscriptions/11111111-2222-4333-8444-555555555555/resourcegroups/synthetic_group/providers/microsoft.storage/storageaccounts/syntheticstore/blobservices/default/containers/synthetic-container",
      ],
      filters_applied: {
        provider: "azure",
        scope_label: "synthetic-demo",
        selected_targets: [
          {
            subscription_id: "11111111-2222-4333-8444-555555555555",
            resource_group: "Synthetic_Group",
            account: "syntheticstore",
            container: "synthetic-container",
          },
        ],
        component_ids: [
          "azure-account",
          "azure-blob-service",
          "azure-container",
        ],
        observation_scope: "configuration",
        coverage_scope: "selected_resources",
        limits: {
          max_targets: 20,
          request_bytes: 65536,
          response_raw_bytes: 1048576,
          response_decoded_bytes: 1048576,
          run_raw_bytes: 16777216,
          run_decoded_bytes: 16777216,
          projection_bytes: 16384,
          run_projection_bytes: 1048576,
          result_bytes: 4194304,
          max_attempts: 3,
          run_seconds: 120,
        },
      },
      coverage_counts: [
        {
          resource_type: "requested-targets",
          scanned: 1,
          matched_filter: 1,
          collected: 1,
        },
        {
          resource_type: "planned-components",
          scanned: 3,
          matched_filter: 3,
          collected: 1,
        },
      ],
      total_findings: 1,
      is_complete: false,
      incomplete_reason: "Selected configuration reads are incomplete.",
      empty_categories: [],
      warnings: [
        "Configuration observations do not establish object enforcement or recordset completeness.",
      ],
      errors: [
        "storage-retention:forbidden",
        "storage-retention:unsupported_source_value",
      ],
      evidentia_version: "0.12.1",
    },
  },
  complete: {
    schema_version: "storage-retention-collection/v1",
    provider: "gcs",
    scope_label: "synthetic-demo",
    status: "complete",
    started_at: "2024-01-02T03:04:05.123456Z",
    finished_at: "2024-01-02T03:04:07.123456Z",
    observation_scope: "configuration",
    coverage_scope: "selected_resources",
    object_enforcement_assessed: false,
    recordset_completeness_assessed: false,
    identity_basis: "operator-declared",
    authenticated_identity_verified: false,
    requested_resources: 1,
    attempted_resources: 1,
    planned_components: 1,
    attempted_components: 1,
    completed_components: 1,
    resources: [
      {
        target: {
          bucket: "synthetic-archive",
        },
        canonical_resource_id: "gcs:synthetic-archive",
        status: "complete",
        components: [
          {
            component_id: "gcs-bucket",
            canonical_resource_id: "gcs:synthetic-archive",
            status: "complete",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 200,
            diagnostics: [],
            projection: {
              api_version: "v1",
              projection_version: "storage-retention-projection/v1",
              native_scope: "bucket",
              fields: {
                metageneration: "00017",
                name: "synthetic-archive",
                objectRetention: {
                  mode: "Enabled",
                },
                retentionPolicy: {
                  effectiveTime: "2024-01-02T03:04:05.123456789+02:00",
                  isLocked: true,
                  retentionPeriod: "00086400",
                },
                versioning: {
                  enabled: false,
                },
              },
              source_etag: '"synthetic-gcs-etag"',
              source_metageneration: "00017",
              canonical_projection_sha256:
                "3795233cdcb757c74b0e641c38a3f84fbe8a68608cfde99b4d730092db0a84d3",
            },
          },
        ],
      },
    ],
    findings: [
      {
        id: "fcb5309e-d320-5380-8a9f-2ce6fa1fed0d",
        title: "Selected storage retention configuration",
        description:
          "Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.",
        severity: "informational",
        status: "active",
        compliance_status: "unknown",
        remediation: null,
        source_system: "storage-retention",
        source_finding_id: "gcs-retention-configuration:gcs:synthetic-archive",
        resource_type: "storage.googleapis.com/Bucket",
        resource_id: "gcs:synthetic-archive",
        resource_region: null,
        resource_account: null,
        control_mappings: [],
        collection_context: {
          collector_id: "storage-retention-scan",
          collector_version: "0.12.1",
          run_id: "synthetic-storage-complete",
          collected_at: "2024-01-02T03:04:07.123456Z",
          credential_identity: "operator-configured:identity-unverified",
          source_system_id: "gcs:synthetic-archive",
          filter_applied: {
            provider: "gcs",
            scope_label: "synthetic-demo",
            selected_targets: [
              {
                bucket: "synthetic-archive",
              },
            ],
            component_ids: ["gcs-bucket"],
            observation_scope: "configuration",
            coverage_scope: "selected_resources",
            limits: {
              max_targets: 20,
              request_bytes: 65536,
              response_raw_bytes: 1048576,
              response_decoded_bytes: 1048576,
              run_raw_bytes: 16777216,
              run_decoded_bytes: 16777216,
              projection_bytes: 16384,
              run_projection_bytes: 1048576,
              result_bytes: 4194304,
              max_attempts: 3,
              run_seconds: 120,
            },
            canonical_resource_id: "gcs:synthetic-archive",
          },
          pagination_context: null,
          evidentia_version: "0.12.1",
        },
        raw_data: {
          resource: {
            target: {
              bucket: "synthetic-archive",
            },
            canonical_resource_id: "gcs:synthetic-archive",
            status: "complete",
            components: [
              {
                component_id: "gcs-bucket",
                canonical_resource_id: "gcs:synthetic-archive",
                status: "complete",
                attempts: 1,
                raw_bytes: 512,
                decoded_bytes: 512,
                started_at: "2024-01-02T03:04:05.123456Z",
                finished_at: "2024-01-02T03:04:07.123456Z",
                http_status: 200,
                diagnostics: [],
                projection: {
                  api_version: "v1",
                  projection_version: "storage-retention-projection/v1",
                  native_scope: "bucket",
                  fields: {
                    metageneration: "00017",
                    name: "synthetic-archive",
                    objectRetention: {
                      mode: "Enabled",
                    },
                    retentionPolicy: {
                      effectiveTime: "2024-01-02T03:04:05.123456789+02:00",
                      isLocked: true,
                      retentionPeriod: "00086400",
                    },
                    versioning: {
                      enabled: false,
                    },
                  },
                  source_etag: '"synthetic-gcs-etag"',
                  source_metageneration: "00017",
                  canonical_projection_sha256:
                    "3795233cdcb757c74b0e641c38a3f84fbe8a68608cfde99b4d730092db0a84d3",
                },
              },
            ],
          },
          scope: {
            provider: "gcs",
            scope_label: "synthetic-demo",
            selected_targets: [
              {
                bucket: "synthetic-archive",
              },
            ],
            component_ids: ["gcs-bucket"],
            observation_scope: "configuration",
            coverage_scope: "selected_resources",
            limits: {
              max_targets: 20,
              request_bytes: 65536,
              response_raw_bytes: 1048576,
              response_decoded_bytes: 1048576,
              run_raw_bytes: 16777216,
              run_decoded_bytes: 16777216,
              projection_bytes: 16384,
              run_projection_bytes: 1048576,
              result_bytes: 4194304,
              max_attempts: 3,
              run_seconds: 120,
            },
          },
          object_enforcement_assessed: false,
          recordset_completeness_assessed: false,
          identity_basis: "operator-declared",
          authenticated_identity_verified: false,
        },
        first_observed: "2024-01-02T03:04:05.123456Z",
        last_observed: "2024-01-02T03:04:07.123456Z",
        resolved_at: null,
      },
    ],
    diagnostics: [],
    manifest: {
      run_id: "synthetic-storage-complete",
      collector_id: "storage-retention-scan",
      collector_version: "0.12.1",
      collection_started_at: "2024-01-02T03:04:05.123456Z",
      collection_finished_at: "2024-01-02T03:04:07.123456Z",
      source_system_ids: ["gcs:synthetic-archive"],
      filters_applied: {
        provider: "gcs",
        scope_label: "synthetic-demo",
        selected_targets: [
          {
            bucket: "synthetic-archive",
          },
        ],
        component_ids: ["gcs-bucket"],
        observation_scope: "configuration",
        coverage_scope: "selected_resources",
        limits: {
          max_targets: 20,
          request_bytes: 65536,
          response_raw_bytes: 1048576,
          response_decoded_bytes: 1048576,
          run_raw_bytes: 16777216,
          run_decoded_bytes: 16777216,
          projection_bytes: 16384,
          run_projection_bytes: 1048576,
          result_bytes: 4194304,
          max_attempts: 3,
          run_seconds: 120,
        },
      },
      coverage_counts: [
        {
          resource_type: "requested-targets",
          scanned: 1,
          matched_filter: 1,
          collected: 1,
        },
        {
          resource_type: "planned-components",
          scanned: 1,
          matched_filter: 1,
          collected: 1,
        },
      ],
      total_findings: 1,
      is_complete: true,
      incomplete_reason: null,
      empty_categories: [],
      warnings: [
        "Configuration observations do not establish object enforcement or recordset completeness.",
      ],
      errors: [],
      evidentia_version: "0.12.1",
    },
  },
  unavailable: {
    schema_version: "storage-retention-collection/v1",
    provider: "s3",
    scope_label: "synthetic-demo",
    status: "unavailable",
    started_at: "2024-01-02T03:04:05.123456Z",
    finished_at: "2024-01-02T03:04:07.123456Z",
    observation_scope: "configuration",
    coverage_scope: "selected_resources",
    object_enforcement_assessed: false,
    recordset_completeness_assessed: false,
    identity_basis: "operator-declared",
    authenticated_identity_verified: false,
    requested_resources: 1,
    attempted_resources: 1,
    planned_components: 2,
    attempted_components: 2,
    completed_components: 0,
    resources: [
      {
        target: {
          bucket: "synthetic-archive",
          region: "us-east-1",
          expected_owner: null,
        },
        canonical_resource_id: "s3:us-east-1:synthetic-archive",
        status: "unavailable",
        components: [
          {
            component_id: "s3-object-lock",
            canonical_resource_id: "s3:us-east-1:synthetic-archive",
            status: "unavailable",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 403,
            diagnostics: [
              {
                code: "forbidden",
                http_status: 403,
              },
            ],
            projection: null,
          },
          {
            component_id: "s3-versioning",
            canonical_resource_id: "s3:us-east-1:synthetic-archive",
            status: "unavailable",
            attempts: 1,
            raw_bytes: 512,
            decoded_bytes: 512,
            started_at: "2024-01-02T03:04:05.123456Z",
            finished_at: "2024-01-02T03:04:07.123456Z",
            http_status: 403,
            diagnostics: [
              {
                code: "forbidden",
                http_status: 403,
              },
            ],
            projection: null,
          },
        ],
      },
    ],
    findings: [],
    diagnostics: [],
    manifest: {
      run_id: "synthetic-storage-unavailable",
      collector_id: "storage-retention-scan",
      collector_version: "0.12.1",
      collection_started_at: "2024-01-02T03:04:05.123456Z",
      collection_finished_at: "2024-01-02T03:04:07.123456Z",
      source_system_ids: ["s3:us-east-1:synthetic-archive"],
      filters_applied: {
        provider: "s3",
        scope_label: "synthetic-demo",
        selected_targets: [
          {
            bucket: "synthetic-archive",
            region: "us-east-1",
            expected_owner: null,
          },
        ],
        component_ids: ["s3-object-lock", "s3-versioning"],
        observation_scope: "configuration",
        coverage_scope: "selected_resources",
        limits: {
          max_targets: 20,
          request_bytes: 65536,
          response_raw_bytes: 1048576,
          response_decoded_bytes: 1048576,
          run_raw_bytes: 16777216,
          run_decoded_bytes: 16777216,
          projection_bytes: 16384,
          run_projection_bytes: 1048576,
          result_bytes: 4194304,
          max_attempts: 3,
          run_seconds: 120,
        },
      },
      coverage_counts: [
        {
          resource_type: "requested-targets",
          scanned: 1,
          matched_filter: 1,
          collected: 0,
        },
        {
          resource_type: "planned-components",
          scanned: 2,
          matched_filter: 2,
          collected: 0,
        },
      ],
      total_findings: 0,
      is_complete: false,
      incomplete_reason: "Selected configuration reads are incomplete.",
      empty_categories: [],
      warnings: [
        "Configuration observations do not establish object enforcement or recordset completeness.",
      ],
      errors: ["storage-retention:forbidden"],
      evidentia_version: "0.12.1",
    },
  },
};

export function storageRetentionDemoResult(): StorageRetentionCollectResult {
  return structuredClone(STORAGE_RETENTION_EXAMPLES.partial);
}

/** Factory-validated synthetic numeric wire controls. The contract case is not a provider recording. */
export const STORAGE_RETENTION_NUMERIC_WIRES = {
  s3: '{"schema_version":"storage-retention-collection/v1","provider":"s3","scope_label":"synthetic","status":"complete","started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","observation_scope":"configuration","coverage_scope":"selected_resources","object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false,"requested_resources":1,"attempted_resources":1,"planned_components":2,"attempted_components":2,"completed_components":2,"resources":[{"target":{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":199,"decoded_bytes":199,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":75,"decoded_bytes":75,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]}],"findings":[{"id":"5cf792ed-ecab-5438-ae58-2020f9e48f91","title":"Selected storage retention configuration","description":"Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.","severity":"informational","status":"active","compliance_status":"unknown","remediation":null,"source_system":"storage-retention","source_finding_id":"s3-retention-configuration:s3:us-east-1:synthetic-retention","resource_type":"AWS::S3::Bucket","resource_id":"s3:us-east-1:synthetic-retention","resource_region":"us-east-1","resource_account":null,"control_mappings":[],"collection_context":{"collector_id":"storage-retention-scan","collector_version":"0.12.1","run_id":"synthetic_run","collected_at":"2025-01-02T03:04:05.123456Z","credential_identity":"operator-configured:identity-unverified","source_system_id":"s3:us-east-1:synthetic-retention","filter_applied":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120},"canonical_resource_id":"s3:us-east-1:synthetic-retention"},"pagination_context":null,"evidentia_version":"0.12.1"},"raw_data":{"resource":{"target":{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":199,"decoded_bytes":199,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":75,"decoded_bytes":75,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]},"scope":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false},"first_observed":"2025-01-02T03:04:05.123456Z","last_observed":"2025-01-02T03:04:05.123456Z","resolved_at":null}],"diagnostics":[],"manifest":{"run_id":"synthetic_run","collector_id":"storage-retention-scan","collector_version":"0.12.1","collection_started_at":"2025-01-02T03:04:05.123456Z","collection_finished_at":"2025-01-02T03:04:05.123456Z","source_system_ids":["s3:us-east-1:synthetic-retention"],"filters_applied":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"coverage_counts":[{"resource_type":"requested-targets","scanned":1,"matched_filter":1,"collected":1},{"resource_type":"planned-components","scanned":2,"matched_filter":2,"collected":2}],"total_findings":1,"is_complete":true,"incomplete_reason":null,"empty_categories":[],"warnings":["Configuration observations do not establish object enforcement or recordset completeness."],"errors":[],"evidentia_version":"0.12.1"}}\n',
  contract:
    '{"schema_version":"storage-retention-collection/v1","provider":"gcs","scope_label":"synthetic-contract","status":"complete","started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","observation_scope":"configuration","coverage_scope":"selected_resources","object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false,"requested_resources":1,"attempted_resources":1,"planned_components":1,"attempted_components":1,"completed_components":1,"resources":[{"target":{"bucket":"synthetic-contract"},"canonical_resource_id":"gcs:synthetic-contract","status":"complete","components":[{"component_id":"gcs-bucket","canonical_resource_id":"gcs:synthetic-contract","status":"complete","attempts":1,"raw_bytes":900,"decoded_bytes":900,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"v1","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"__proto__":{"source":true},"constructor":{"source":false},"escaped_key\\\\\\"":{"fields":[[],{},null,false,"0001",{"quote":"\\\\\\""}]},"integral_float":1.0,"large_exponent":1e+20,"literal_time":"2025-01-02T03:04:05.123456789+02:00","negative_bound":-99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,"negative_zero":-0.0,"positive_bound":99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,"quoted_lookalike":"\\"fields\\":{\\"negative_zero\\":1},\\"projection\\":{\\"fields\\":{}}","quoted_seconds":"0009007199254740993","small_exponent":1e-6},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"887c4c3c1d9532bdc348696026c5aaaf5776e4b5dc34639fbc375d55d4e56529"}}]}],"findings":[{"id":"235ac825-9224-56b2-8fc2-7f7e9c97730b","title":"Selected storage retention configuration","description":"Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.","severity":"informational","status":"active","compliance_status":"unknown","remediation":null,"source_system":"storage-retention","source_finding_id":"gcs-retention-configuration:gcs:synthetic-contract","resource_type":"storage.googleapis.com/Bucket","resource_id":"gcs:synthetic-contract","resource_region":null,"resource_account":null,"control_mappings":[],"collection_context":{"collector_id":"storage-retention-scan","collector_version":"0.12.1","run_id":"synthetic-contract","collected_at":"2025-01-02T03:04:05.123456Z","credential_identity":"operator-configured:identity-unverified","source_system_id":"gcs:synthetic-contract","filter_applied":{"provider":"gcs","scope_label":"synthetic-contract","selected_targets":[{"bucket":"synthetic-contract"}],"component_ids":["gcs-bucket"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120},"canonical_resource_id":"gcs:synthetic-contract"},"pagination_context":null,"evidentia_version":"0.12.1"},"raw_data":{"resource":{"target":{"bucket":"synthetic-contract"},"canonical_resource_id":"gcs:synthetic-contract","status":"complete","components":[{"component_id":"gcs-bucket","canonical_resource_id":"gcs:synthetic-contract","status":"complete","attempts":1,"raw_bytes":900,"decoded_bytes":900,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"v1","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"__proto__":{"source":true},"constructor":{"source":false},"escaped_key\\\\\\"":{"fields":[[],{},null,false,"0001",{"quote":"\\\\\\""}]},"integral_float":1.0,"large_exponent":1e+20,"literal_time":"2025-01-02T03:04:05.123456789+02:00","negative_bound":-99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,"negative_zero":-0.0,"positive_bound":99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,"quoted_lookalike":"\\"fields\\":{\\"negative_zero\\":1},\\"projection\\":{\\"fields\\":{}}","quoted_seconds":"0009007199254740993","small_exponent":1e-6},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"887c4c3c1d9532bdc348696026c5aaaf5776e4b5dc34639fbc375d55d4e56529"}}]},"scope":{"provider":"gcs","scope_label":"synthetic-contract","selected_targets":[{"bucket":"synthetic-contract"}],"component_ids":["gcs-bucket"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false},"first_observed":"2025-01-02T03:04:05.123456Z","last_observed":"2025-01-02T03:04:05.123456Z","resolved_at":null}],"diagnostics":[],"manifest":{"run_id":"synthetic-contract","collector_id":"storage-retention-scan","collector_version":"0.12.1","collection_started_at":"2025-01-02T03:04:05.123456Z","collection_finished_at":"2025-01-02T03:04:05.123456Z","source_system_ids":["gcs:synthetic-contract"],"filters_applied":{"provider":"gcs","scope_label":"synthetic-contract","selected_targets":[{"bucket":"synthetic-contract"}],"component_ids":["gcs-bucket"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"coverage_counts":[{"resource_type":"requested-targets","scanned":1,"matched_filter":1,"collected":1},{"resource_type":"planned-components","scanned":1,"matched_filter":1,"collected":1}],"total_findings":1,"is_complete":true,"incomplete_reason":null,"empty_categories":[],"warnings":["Configuration observations do not establish object enforcement or recordset completeness."],"errors":[],"evidentia_version":"0.12.1"}}\n',
};

/** Two factory-validated selected resources for ordered-request binding tests. */
export const STORAGE_RETENTION_ORDERED_WIRE =
  '{"schema_version":"storage-retention-collection/v1","provider":"s3","scope_label":"synthetic","status":"complete","started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","observation_scope":"configuration","coverage_scope":"selected_resources","object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false,"requested_resources":2,"attempted_resources":2,"planned_components":4,"attempted_components":4,"completed_components":4,"resources":[{"target":{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]},{"target":{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]}],"findings":[{"id":"5cf792ed-ecab-5438-ae58-2020f9e48f91","title":"Selected storage retention configuration","description":"Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.","severity":"informational","status":"active","compliance_status":"unknown","remediation":null,"source_system":"storage-retention","source_finding_id":"s3-retention-configuration:s3:us-east-1:synthetic-retention","resource_type":"AWS::S3::Bucket","resource_id":"s3:us-east-1:synthetic-retention","resource_region":"us-east-1","resource_account":null,"control_mappings":[],"collection_context":{"collector_id":"storage-retention-scan","collector_version":"0.12.1","run_id":"synthetic-two","collected_at":"2025-01-02T03:04:05.123456Z","credential_identity":"operator-configured:identity-unverified","source_system_id":"s3:us-east-1:synthetic-retention","filter_applied":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120},"canonical_resource_id":"s3:us-east-1:synthetic-retention"},"pagination_context":null,"evidentia_version":"0.12.1"},"raw_data":{"resource":{"target":{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-retention","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]},"scope":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false},"first_observed":"2025-01-02T03:04:05.123456Z","last_observed":"2025-01-02T03:04:05.123456Z","resolved_at":null},{"id":"c9d90da4-2658-5e3e-b273-e97be25f43a6","title":"Selected storage retention configuration","description":"Configuration observed for an explicitly selected resource. Object enforcement and recordset completeness were not assessed.","severity":"informational","status":"active","compliance_status":"unknown","remediation":null,"source_system":"storage-retention","source_finding_id":"s3-retention-configuration:s3:us-east-1:synthetic-second","resource_type":"AWS::S3::Bucket","resource_id":"s3:us-east-1:synthetic-second","resource_region":"us-east-1","resource_account":null,"control_mappings":[],"collection_context":{"collector_id":"storage-retention-scan","collector_version":"0.12.1","run_id":"synthetic-two","collected_at":"2025-01-02T03:04:05.123456Z","credential_identity":"operator-configured:identity-unverified","source_system_id":"s3:us-east-1:synthetic-second","filter_applied":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120},"canonical_resource_id":"s3:us-east-1:synthetic-second"},"pagination_context":null,"evidentia_version":"0.12.1"},"raw_data":{"resource":{"target":{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"},"canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","components":[{"component_id":"s3-object-lock","canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Days":9007199254740993,"Mode":"GOVERNANCE"}}},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"d339f727ef70a26840e96309c1a8732deb12dd4bf8a590014a9fc5c3da682b43"}},{"component_id":"s3-versioning","canonical_resource_id":"s3:us-east-1:synthetic-second","status":"complete","attempts":1,"raw_bytes":500,"decoded_bytes":500,"started_at":"2025-01-02T03:04:05.123456Z","finished_at":"2025-01-02T03:04:05.123456Z","http_status":200,"diagnostics":[],"projection":{"api_version":"2006-03-01","projection_version":"storage-retention-projection/v1","native_scope":"bucket","fields":{"Status":"Enabled"},"source_etag":null,"source_metageneration":null,"canonical_projection_sha256":"6702685e5dad99d0694ab38393b12b162851de8e7b65990521a6176bb8ad9170"}}]},"scope":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"object_enforcement_assessed":false,"recordset_completeness_assessed":false,"identity_basis":"operator-declared","authenticated_identity_verified":false},"first_observed":"2025-01-02T03:04:05.123456Z","last_observed":"2025-01-02T03:04:05.123456Z","resolved_at":null}],"diagnostics":[],"manifest":{"run_id":"synthetic-two","collector_id":"storage-retention-scan","collector_version":"0.12.1","collection_started_at":"2025-01-02T03:04:05.123456Z","collection_finished_at":"2025-01-02T03:04:05.123456Z","source_system_ids":["s3:us-east-1:synthetic-retention","s3:us-east-1:synthetic-second"],"filters_applied":{"provider":"s3","scope_label":"synthetic","selected_targets":[{"bucket":"synthetic-retention","region":"us-east-1","expected_owner":"123456789012"},{"bucket":"synthetic-second","region":"us-east-1","expected_owner":"123456789012"}],"component_ids":["s3-object-lock","s3-versioning"],"observation_scope":"configuration","coverage_scope":"selected_resources","limits":{"max_targets":20,"request_bytes":65536,"response_raw_bytes":1048576,"response_decoded_bytes":1048576,"run_raw_bytes":16777216,"run_decoded_bytes":16777216,"projection_bytes":16384,"run_projection_bytes":1048576,"result_bytes":4194304,"max_attempts":3,"run_seconds":120}},"coverage_counts":[{"resource_type":"requested-targets","scanned":2,"matched_filter":2,"collected":2},{"resource_type":"planned-components","scanned":4,"matched_filter":4,"collected":4}],"total_findings":2,"is_complete":true,"incomplete_reason":null,"empty_categories":[],"warnings":["Configuration observations do not establish object enforcement or recordset completeness."],"errors":[],"evidentia_version":"0.12.1"}}\n';
