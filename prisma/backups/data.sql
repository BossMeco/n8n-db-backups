SET session_replication_role = replica;

--
-- PostgreSQL database dump
--

-- Dumped from database version 17.4
-- Dumped by pg_dump version 17.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: audit_log_entries; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."audit_log_entries" ("instance_id", "id", "payload", "created_at", "ip_address") FROM stdin;
\.


--
-- Data for Name: flow_state; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."flow_state" ("id", "user_id", "auth_code", "code_challenge_method", "code_challenge", "provider_type", "provider_access_token", "provider_refresh_token", "created_at", "updated_at", "authentication_method", "auth_code_issued_at") FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."users" ("instance_id", "id", "aud", "role", "email", "encrypted_password", "email_confirmed_at", "invited_at", "confirmation_token", "confirmation_sent_at", "recovery_token", "recovery_sent_at", "email_change_token_new", "email_change", "email_change_sent_at", "last_sign_in_at", "raw_app_meta_data", "raw_user_meta_data", "is_super_admin", "created_at", "updated_at", "phone", "phone_confirmed_at", "phone_change", "phone_change_token", "phone_change_sent_at", "email_change_token_current", "email_change_confirm_status", "banned_until", "reauthentication_token", "reauthentication_sent_at", "is_sso_user", "deleted_at", "is_anonymous") FROM stdin;
\.


--
-- Data for Name: identities; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."identities" ("provider_id", "user_id", "identity_data", "provider", "last_sign_in_at", "created_at", "updated_at", "id") FROM stdin;
\.


--
-- Data for Name: instances; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."instances" ("id", "uuid", "raw_base_config", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sessions" ("id", "user_id", "created_at", "updated_at", "factor_id", "aal", "not_after", "refreshed_at", "user_agent", "ip", "tag") FROM stdin;
\.


--
-- Data for Name: mfa_amr_claims; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_amr_claims" ("session_id", "created_at", "updated_at", "authentication_method", "id") FROM stdin;
\.


--
-- Data for Name: mfa_factors; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_factors" ("id", "user_id", "friendly_name", "factor_type", "status", "created_at", "updated_at", "secret", "phone", "last_challenged_at", "web_authn_credential", "web_authn_aaguid") FROM stdin;
\.


--
-- Data for Name: mfa_challenges; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_challenges" ("id", "factor_id", "created_at", "verified_at", "ip_address", "otp_code", "web_authn_session_data") FROM stdin;
\.


--
-- Data for Name: one_time_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."one_time_tokens" ("id", "user_id", "token_type", "token_hash", "relates_to", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."refresh_tokens" ("instance_id", "id", "token", "user_id", "revoked", "created_at", "updated_at", "parent", "session_id") FROM stdin;
\.


--
-- Data for Name: sso_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sso_providers" ("id", "resource_id", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: saml_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."saml_providers" ("id", "sso_provider_id", "entity_id", "metadata_xml", "metadata_url", "attribute_mapping", "created_at", "updated_at", "name_id_format") FROM stdin;
\.


--
-- Data for Name: saml_relay_states; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."saml_relay_states" ("id", "sso_provider_id", "request_id", "for_email", "redirect_to", "created_at", "updated_at", "flow_state_id") FROM stdin;
\.


--
-- Data for Name: sso_domains; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sso_domains" ("id", "sso_provider_id", "domain", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: annotation_tag_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."annotation_tag_entity" ("id", "name", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user" ("id", "email", "firstName", "lastName", "password", "personalizationAnswers", "createdAt", "updatedAt", "settings", "disabled", "mfaEnabled", "mfaSecret", "mfaRecoveryCodes", "role", "lastActiveAt") FROM stdin;
88db01db-d4e7-4be8-a6fa-634c72be2604	micjol04@gmail.com	Mico	Meco	$2a$10$D0o1mcaJ23b2rOlm5IC5vuXwVlVksbhc2ZAb6AKxHTCeY2d44.Q7y	{"version":"v4","personalization_survey_submitted_at":"2025-08-11T07:27:57.891Z","personalization_survey_n8n_version":"1.105.4","companyType":"saas"}	2025-08-11 07:16:21.325+00	2025-08-11 07:28:00.074+00	{"userActivated": false}	f	f	\N	\N	global:owner	2025-08-11
\.


--
-- Data for Name: auth_identity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."auth_identity" ("userId", "providerId", "providerType", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: auth_provider_sync_history; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."auth_provider_sync_history" ("id", "providerType", "runMode", "status", "startedAt", "endedAt", "scanned", "created", "updated", "disabled", "error") FROM stdin;
\.


--
-- Data for Name: credentials_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."credentials_entity" ("name", "data", "type", "createdAt", "updatedAt", "id", "isManaged") FROM stdin;
\.


--
-- Data for Name: event_destinations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."event_destinations" ("id", "destination", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: project; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."project" ("id", "name", "type", "createdAt", "updatedAt", "icon", "description") FROM stdin;
5krdVSd1JSu4TUOy	Mico Meco <micjol04@gmail.com>	personal	2025-08-11 07:22:59.601+00	2025-08-11 07:27:00.37+00	\N	\N
\.


--
-- Data for Name: folder; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."folder" ("id", "name", "parentFolderId", "projectId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: workflow_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."workflow_entity" ("name", "active", "nodes", "connections", "createdAt", "updatedAt", "settings", "staticData", "pinData", "versionId", "triggerCount", "id", "meta", "parentFolderId", "isArchived") FROM stdin;
\.


--
-- Data for Name: execution_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."execution_entity" ("id", "finished", "mode", "retryOf", "retrySuccessId", "startedAt", "stoppedAt", "waitTill", "status", "workflowId", "deletedAt", "createdAt") FROM stdin;
\.


--
-- Data for Name: execution_annotations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."execution_annotations" ("id", "executionId", "vote", "note", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: execution_annotation_tags; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."execution_annotation_tags" ("annotationId", "tagId") FROM stdin;
\.


--
-- Data for Name: execution_data; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."execution_data" ("executionId", "workflowData", "data") FROM stdin;
\.


--
-- Data for Name: execution_metadata; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."execution_metadata" ("id", "executionId", "key", "value") FROM stdin;
\.


--
-- Data for Name: tag_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."tag_entity" ("name", "createdAt", "updatedAt", "id") FROM stdin;
\.


--
-- Data for Name: folder_tag; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."folder_tag" ("folderId", "tagId") FROM stdin;
\.


--
-- Data for Name: insights_metadata; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."insights_metadata" ("metaId", "workflowId", "projectId", "workflowName", "projectName") FROM stdin;
\.


--
-- Data for Name: insights_by_period; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."insights_by_period" ("id", "metaId", "type", "value", "periodUnit", "periodStart") FROM stdin;
\.


--
-- Data for Name: insights_raw; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."insights_raw" ("id", "metaId", "type", "value", "timestamp") FROM stdin;
\.


--
-- Data for Name: installed_packages; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."installed_packages" ("packageName", "installedVersion", "authorName", "authorEmail", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: installed_nodes; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."installed_nodes" ("name", "type", "latestVersion", "package") FROM stdin;
\.


--
-- Data for Name: invalid_auth_token; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."invalid_auth_token" ("token", "expiresAt") FROM stdin;
\.


--
-- Data for Name: migrations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."migrations" ("id", "timestamp", "name") FROM stdin;
1	1587669153312	InitialMigration1587669153312
2	1589476000887	WebhookModel1589476000887
3	1594828256133	CreateIndexStoppedAt1594828256133
4	1607431743768	MakeStoppedAtNullable1607431743768
5	1611144599516	AddWebhookId1611144599516
6	1617270242566	CreateTagEntity1617270242566
7	1620824779533	UniqueWorkflowNames1620824779533
8	1626176912946	AddwaitTill1626176912946
9	1630419189837	UpdateWorkflowCredentials1630419189837
10	1644422880309	AddExecutionEntityIndexes1644422880309
11	1646834195327	IncreaseTypeVarcharLimit1646834195327
12	1646992772331	CreateUserManagement1646992772331
13	1648740597343	LowerCaseUserEmail1648740597343
14	1652254514002	CommunityNodes1652254514002
15	1652367743993	AddUserSettings1652367743993
16	1652905585850	AddAPIKeyColumn1652905585850
17	1654090467022	IntroducePinData1654090467022
18	1658932090381	AddNodeIds1658932090381
19	1659902242948	AddJsonKeyPinData1659902242948
20	1660062385367	CreateCredentialsUserRole1660062385367
21	1663755770893	CreateWorkflowsEditorRole1663755770893
22	1664196174001	WorkflowStatistics1664196174001
23	1665484192212	CreateCredentialUsageTable1665484192212
24	1665754637025	RemoveCredentialUsageTable1665754637025
25	1669739707126	AddWorkflowVersionIdColumn1669739707126
26	1669823906995	AddTriggerCountColumn1669823906995
27	1671535397530	MessageEventBusDestinations1671535397530
28	1671726148421	RemoveWorkflowDataLoadedFlag1671726148421
29	1673268682475	DeleteExecutionsWithWorkflows1673268682475
30	1674138566000	AddStatusToExecutions1674138566000
31	1674509946020	CreateLdapEntities1674509946020
32	1675940580449	PurgeInvalidWorkflowConnections1675940580449
33	1676996103000	MigrateExecutionStatus1676996103000
34	1677236854063	UpdateRunningExecutionStatus1677236854063
35	1677501636754	CreateVariables1677501636754
36	1679416281778	CreateExecutionMetadataTable1679416281778
37	1681134145996	AddUserActivatedProperty1681134145996
38	1681134145997	RemoveSkipOwnerSetup1681134145997
39	1690000000000	MigrateIntegerKeysToString1690000000000
40	1690000000020	SeparateExecutionData1690000000020
41	1690000000030	RemoveResetPasswordColumns1690000000030
42	1690000000030	AddMfaColumns1690000000030
43	1690787606731	AddMissingPrimaryKeyOnExecutionData1690787606731
44	1691088862123	CreateWorkflowNameIndex1691088862123
45	1692967111175	CreateWorkflowHistoryTable1692967111175
46	1693491613982	ExecutionSoftDelete1693491613982
47	1693554410387	DisallowOrphanExecutions1693554410387
48	1694091729095	MigrateToTimestampTz1694091729095
49	1695128658538	AddWorkflowMetadata1695128658538
50	1695829275184	ModifyWorkflowHistoryNodesAndConnections1695829275184
51	1700571993961	AddGlobalAdminRole1700571993961
52	1705429061930	DropRoleMapping1705429061930
53	1711018413374	RemoveFailedExecutionStatus1711018413374
54	1711390882123	MoveSshKeysToDatabase1711390882123
55	1712044305787	RemoveNodesAccess1712044305787
56	1714133768519	CreateProject1714133768519
57	1714133768521	MakeExecutionStatusNonNullable1714133768521
58	1717498465931	AddActivatedAtUserSetting1717498465931
59	1720101653148	AddConstraintToExecutionMetadata1720101653148
60	1721377157740	FixExecutionMetadataSequence1721377157740
61	1723627610222	CreateInvalidAuthTokenTable1723627610222
62	1723796243146	RefactorExecutionIndices1723796243146
63	1724753530828	CreateAnnotationTables1724753530828
64	1724951148974	AddApiKeysTable1724951148974
65	1726606152711	CreateProcessedDataTable1726606152711
66	1727427440136	SeparateExecutionCreationFromStart1727427440136
67	1728659839644	AddMissingPrimaryKeyOnAnnotationTagMapping1728659839644
68	1729607673464	UpdateProcessedDataValueColumnToText1729607673464
69	1729607673469	AddProjectIcons1729607673469
70	1730386903556	CreateTestDefinitionTable1730386903556
71	1731404028106	AddDescriptionToTestDefinition1731404028106
72	1731582748663	MigrateTestDefinitionKeyToString1731582748663
73	1732271325258	CreateTestMetricTable1732271325258
74	1732549866705	CreateTestRun1732549866705
75	1733133775640	AddMockedNodesColumnToTestDefinition1733133775640
76	1734479635324	AddManagedColumnToCredentialsTable1734479635324
77	1736172058779	AddStatsColumnsToTestRun1736172058779
78	1736947513045	CreateTestCaseExecutionTable1736947513045
79	1737715421462	AddErrorColumnsToTestRuns1737715421462
80	1738709609940	CreateFolderTable1738709609940
81	1739549398681	CreateAnalyticsTables1739549398681
82	1740445074052	UpdateParentFolderIdColumn1740445074052
83	1741167584277	RenameAnalyticsToInsights1741167584277
84	1742918400000	AddScopesColumnToApiKeys1742918400000
85	1745322634000	ClearEvaluation1745322634000
86	1745587087521	AddWorkflowStatisticsRootCount1745587087521
87	1745934666076	AddWorkflowArchivedColumn1745934666076
88	1745934666077	DropRoleTable1745934666077
89	1747824239000	AddProjectDescriptionColumn1747824239000
90	1750252139166	AddLastActiveAtColumnToUser1750252139166
91	1752669793000	AddInputsOutputsToTestCaseExecution1752669793000
\.


--
-- Data for Name: processed_data; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."processed_data" ("workflowId", "context", "createdAt", "updatedAt", "value") FROM stdin;
\.


--
-- Data for Name: project_relation; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."project_relation" ("projectId", "userId", "role", "createdAt", "updatedAt") FROM stdin;
5krdVSd1JSu4TUOy	88db01db-d4e7-4be8-a6fa-634c72be2604	project:personalOwner	2025-08-11 07:22:59.601+00	2025-08-11 07:22:59.601+00
\.


--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."settings" ("key", "value", "loadOnStartup") FROM stdin;
ui.banners.dismissed	["V1"]	t
features.ldap	{"loginEnabled":false,"loginLabel":"","connectionUrl":"","allowUnauthorizedCerts":false,"connectionSecurity":"none","connectionPort":389,"baseDn":"","bindingAdminDn":"","bindingAdminPassword":"","firstNameAttribute":"","lastNameAttribute":"","emailAttribute":"","loginIdAttribute":"","ldapIdAttribute":"","userFilter":"","synchronizationEnabled":false,"synchronizationInterval":60,"searchPageSize":0,"searchTimeout":60}	t
features.oidc	{"clientId":"","clientSecret":"","discoveryEndpoint":"","loginEnabled":false}	t
userManagement.authenticationMethod	email	t
features.sourceControl.sshKeys	{"encryptedPrivateKey":"U2FsdGVkX18jW95ZIcxIkoQQewYy5yU2G+dMb4OHMlZHZtLVtHHDTUwXlCsqH18dUjHThTf5Eiy9tq+3phy9/g24QsY5c9w/OuxYLGkKB9cp48cjUrgUI9Qc3UlXz/jVnV7WuvPPkb7ti7MAi0bdDL2CDMy/x+L543+W0c0nfDlujG8roaQJV+lgv/h//XjEudBLt5F7YnTEjtfn35xydyixe6NPqpOK8VzcAXGOWW6HavFoO9kYxjgPK5QarBRJcGmUCpBTZHzUxnJ6g4AGFB7v7dGZQnjRfLXNoz+2NTEVdTsIXGa76515X5f0zSxtp3Jd67Ewl3utkQB4+KjkEEO7ws2ejCwMrcVDBaqHHyuXJNIK0lQo+UBTZwmpQsEC7UHBmGuyvDi+n0Y4l1El/KDI5wIwAlOYZYk+wkZESW3KcRv+pwjfEPM+LzHWcOchMAl9BR2TH3cj3b1C+7vEreiAf7QgpzV9UZU5ASa00TjTGvoRTQ4UHyBIEy7vRclbxXW6lCsAkcgF5pJfJcfcxY6b/X/hzmeIjmQ6tGiQ/D/6MIxlqacPGxjwtMzCd//e","publicKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAGUXzNy0RLBHxDeobX/VrTBJ7/aH3lpsHeOVOcINfR n8n deploy key"}	t
features.sourceControl	{"branchName":"main","keyGeneratorType":"ed25519"}	t
userManagement.isInstanceOwnerSetUp	true	t
license.cert	eyJsaWNlbnNlS2V5IjoiLS0tLS1CRUdJTiBMSUNFTlNFIEtFWS0tLS0tXG52VnFQanB2UDNYUHlTUjFiVUtOSGsvejJib3lUMW1kTTJEL1pPYXo0RWlqRUFvQmt1emExeWFPTnJIT3g2Nk1CXG52ODI3WmFPMU9WM3gwTkdvdHZrMWJOZzR3amJsOVdVMVNyejg4ZFZUZEFrZEdyODhwVDdJdGRSMnJyd29kWjlIXG43R0lXeC8vamZCUkhvdVJnMDJ1YnFpemRQbVdlKyszSU5qemhxM3NuTCs5UVNLRTQvV29wTXo5WGFkendIVS95XG40eE92SW5ScEJFdXF4aTRwQzdhZmJKckJZa0xVOUVXazAwMlNoSmlETWJYZkFicTJ4R21CeVNwWTNtVnRCd0lYXG5wRVZob3lzcUVaZVNHQTZOVVAvRmlJd1B4SDEwd3ZTTjV0eHNmMndlcEhJOWJqWnc1Um1UaUFoM3dxMlByRXgrXG4waG1rOC92ZDhVWUg0Z0E0L2xZZDdnPT18fFUyRnNkR1ZrWDE4NHlqMU5Ud3pudmdJa0xKNGZFZ0FnM2pPRE5NXG5pRUFNNnVGMkJjMkNtUzIvemg0TnZ2azBVdDFpdGloaDlHVlZPbms1ajNDczJGT05EWFROeGovckNYMWd4aTBQXG5rT0MxUXBKQm9uZWRWdFZXK2xZeGhIc2xuRVVwWkd5SXFBRDBBek1ySGNSTGFEZ3N6b2FmYzF0SVlZdGUxcVFXXG44ZzMxejl3VkdWUU5ZTUczc0k4YXhvdFlGV2swcTlwQWZMK2dXMUs4TmNRWE1xcTR2WGR6QmtBREpNekNjbEF6XG4vbFRnakVwZmJkN1dOMDdUaXFGOXd6TlRkMll1djJlQWQ1bzNzMk9qQW1aZVdnMWEwZHliZEM0MXdXNTBBa21mXG5xcmpmbjdWWDJHS3UxZDRkRlhwL3M3VDNmczNKUzdvMkoxZHBocS9OOXN2TVJJQUttYlR4bzlNVUQ1REk0WTR1XG5QT0M2WlFxY0QyaTY2NVFJRGFhRG9FZzNzU3oxRGVPYjVSeWtPYWxRVS9OdzU4Rzk3UW5PR3pDaTk5MTJvSk05XG43MXpQaFpiUU41TjRDU3N0Q0ZieHNXUXlwdEcyY0gwU1FCaHJDN0owSG5yZDZ0UzNKQ2ZQT3BGS3JYWXBjSHFLXG5mWmhET3RyOTFZMkxmOE9LczY3dHpweENwVnZ1YW8zZlI5NFFybUpWZXFWdnRHaWVtWU1iWlp4azg3U1dtYTRwXG5YeTlxV0dvWnNLMk9RaURXNU05MzJkbFErN215c0F1cHhmUmZtV1pLdHc0ZzVPVXR3anpVMmdiUE5tS05vVmZMXG4weTNzd2llRkYzVE4vd1llUFREUmUwZlNKYXVqWDhHTlBzTW5zWEl1NXFIQWh5ZVNhQnZqU2QzVGRtVFNRczd6XG5Ydjg2UVBYeXZiNmk5MnhyYWx3L2tFUXlBVHQwd3RZTUhFSzFZNkF3ZHhVWlppYlFTMDJZVXVEU2xGbGlPakNkXG45Z3FzOERScit5dW55T1dTZG5yOVM1Tlh1S3FBRkdHd0JCZ295QWFWcHdIbFdMdnhZYmxieDVZbzJkZWhGWFJBXG50Q2ZBamxwMTdUQmlWSFBqRGlLdzVPeFBxMS9IK092UzhDb3FzZW0zRXBxQmVibHIrZnYvUWxJdGhuL3JwS1hWXG5OQWNqa0pjQnpJa1plR3FSeWVuZUZZakFIeTNMaE50c1c2cHlXamNCMWk1UG80NHF2L0dVUmxCRWk4bTRaeVkzXG45ajAwQ1ZuSVV3THRHT1dIY2Z6aDNKTjhIVG9lbUZDMUpGNmdYT21oYXg0QTk2K2ViWllDaEIxd2Q1MUxGZVlEXG4rLzEyd01tUi8zRkNINHBiczZLR0RXMWRIcUluODB0b0lGc1p3TTJLM0VRM3VIa2FOUnJBek1LMTlqM2ppM1hBXG4weDU2dHJaNm5EajNja09NTXl1OVVna0s3b3pSL2VaTWxyc0h1dzlHUHQvWXVweDZrbFc1MHFFY1c5ZGxra2dVXG5WMVF2UGh4dW1pcU1OLzZmdTgrbmFSRzBVMGE1ZHg5KzF1ZVc0MUtnbE9DQkZKeFh0ajV2MS9Halp0N2E2STg4XG55QitLK3RnN1RxajIwaEE2Y1BOZkNyUytZUEg2RXo2R2RxblZsOGZnMCtqdWliTkVLWWt0azZ6WnlydXlOeDRGXG5nUnE2RWo0QTZYSWZaUTRyRU15QVZ5TCthVVpqNGlxRzR1amN5N2wvRm92ZGlZTHMvK1UvVlF5WXluVk0wUllWXG5Pd2wwRjBKTGo3ZnA1ejYzcWh5eFozK3NIeHRLOVNHM3BsbmJpRmlzR2wvL3Q2bXpLZlZiR01WMVVYNEorTmdaXG5pTFM1MzEyQjJYd0VlVTRtWENTeVFtVDZUa3N3UnRVdmtiWlZ2VmMzWU5rakpLZVVwYWpHVGxPdzQwTFZmVTZsXG5iY29ZZ3pnclpIQTRYT1IraFNwZ2hQMmpaTzVaQ3N0OGRsK29Hc25iQ0xqc1NETkJLWms3enp1ME45eXVLdUVOXG5ZY2VTL1YxMTViVmRKSE55T0hwMXVpWW9uTGdFOWRLUDJubE9DZWlFd2VibFo0NVFvcXcySllSVjRqQmNrTWptXG51emJRV1IzSjUrUFVXL3ovZnZ0ZnZwVko2SFkycDNZUlh5eTVBeElFNEg1Snp5THQwK1lYS0ZkRkdvTHdOZnhiXG5zQnBJcC9jdVFxUm43Y1MvcVBuNTNUUUZqc0crZHk2SWdaUUJSUmtJcE1nWlY3STlmTUY4K2Z6dW1HT1pRYi9pXG5hNW9IMUU1TytuRVBjdEpKbGFRT1o3bWRsY0tlYWpmQ1Y5Rmp3a0N1d0dyYjMrRWJyQXF2ZmpoNHZpZXg0SWJWXG5tR3duMlRudGI2OTlpRUhjWmZxdThTSmsrb3Ywa2w5QjNuaXc0TjJEd3ZMUUpYa1ZveUZFb01lV3NaTUdWenZ0XG5qaEZ6T0FjY1k1Ni83bjNyQ1lpVGlzbHNtNUhVRkVURXhma3N3eitMKzNyaUFxRDYwTVNTVitpWXhuTGJ2K1ZkXG52dldpVWFFNktTbndGdVFaRlEwSGw5bVRNQXVveEU2TE9qTm5hZGNHN0JSWmVpNUQwUTE2enRBUlhSQjIxMWxrXG5ZYkMyRWNLdFlGN0dRdjBCQ3JrY2FkZElkUHpBVkNnOCtkR05EcjNhYlJReEdjUkplOS9WLy91ZUVrenZNaGloXG5zYzZnUEdISk5McG9NU2k2Wk10elJWYXB2YTRheVZGcTBla2orUFhlVGJxODkzRjc0TklHZm5PNmtlM3ltdlF5XG5weUlBckVOMkY0b1U5WjExZGJFVEsxMEpBbzdXYW9xWSt3T3dtVE5BakUza2ptRkcvK3J4R2MrQ096ZHJxMGRKXG5NUFZwZHdaZ0ZnV21kbjBhV1FPZDAwRVBDcDYxWmw3WXh0WjhzRzVjTDlwcWhaY2E4RWl2ZzBFZHNWRVVHbVF2XG5GbVhZc0pCM2ZIZE9keXlmZ0ZyZUt1N0tFNFVWMlNZQVdlUzh4V3VqMnBETWxheS9SdXZ2MjgyQ2tDQ2x4TVA2XG45WVU2ZTJEYW9LVVZZYzVhOHgrdXdxeFJlOS9UcCt1Q2Z6Z0dQeS9ueFg4SnY2V3c9PXx8dlBKYlNTTllGeFZLXG50OFZ2LytiemM4OGdveExETVFZNWJNOWtvV0RUY3oyZE1vcHZXZlZlQzJrOXliZ0VUNlhDaUdBeFZENjBDRFRjXG5PUTR1UXovUjJvcHJDdUlnYUpZQjVSc2V5MkNyWndBekxxZVhiWHhPemNZbHVZVEhzRXliT1crYjE1R3hwUzZLXG5xNUpUcHNKTXJxeWU1NnFmckhCZEFvazYyZWJsdzdxRmM4YWFHRmd4LzZsQkMyU3RBYU50QnphYjJqTGU3M24rXG5zdVlFdk43OGhpcy83S1FtL1hjZVdDaDZlVU80ZStkQUo0TWhEVkVBNk5hYzRPWEpQT3RleHd6L3pDVUNUbk5YXG5jTWtEME5lclJpYUloZFUwZ05hSnkvZXR1SG53aGdSYzN5b0MvS2NCMjJZbS9FMSt2OVlwbHpTeTlaeFJ1N2pUXG5CZW5VcTNDazNnPT1cbi0tLS0tRU5EIExJQ0VOU0UgS0VZLS0tLS0iLCJ4NTA5IjoiLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlFRERDQ0FmUUNDUUNxZzJvRFQ4MHh3akFOQmdrcWhraUc5dzBCQVFVRkFEQklNUXN3Q1FZRFZRUUdFd0pFXG5SVEVQTUEwR0ExVUVDQXdHUW1WeWJHbHVNUTh3RFFZRFZRUUhEQVpDWlhKc2FXNHhGekFWQmdOVkJBTU1EbXhwXG5ZMlZ1YzJVdWJqaHVMbWx2TUI0WERUSXlNRFl5TkRBME1UQTBNRm9YRFRJek1EWXlOREEwTVRBME1Gb3dTREVMXG5NQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWdNQmtKbGNteHBiakVQTUEwR0ExVUVCd3dHUW1WeWJHbHVNUmN3XG5GUVlEVlFRRERBNXNhV05sYm5ObExtNDRiaTVwYnpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDXG5BUW9DZ2dFQkFNQk0wNVhCNDRnNXhmbUNMd2RwVVR3QVQ4K0NCa3lMS0ZzZXprRDVLLzZXaGFYL1hyc2QvUWQwXG4yMEo3d2w1V2RIVTRjVkJtRlJqVndWemtsQ0syeVlKaThtang4c1hzR3E5UTFsYlVlTUtmVjlkc2dmdWhubEFTXG50blFaZ2x1Z09uRjJGZ1JoWGIvakswdHhUb2FvK2JORTZyNGdJRXpwa3RITEJUWXZ2aXVKbXJlZjdXYlBSdDRJXG5uZDlEN2xoeWJlYnloVjdrdXpqUUEvcFBLSFRGczhNVEhaOGhZVXhSeXJwbTMrTVl6UUQrYmpBMlUxRkljdGFVXG53UVhZV2FON3QydVR3Q3Q5ekFLc21ZL1dlT2J2bDNUWk41T05MQXp5V0dDdWxtNWN3S1IzeGJsQlp6WG5CNmdzXG5Pbk4yT0FkU3RjelRWQ3ljbThwY0ZVcnl0S1NLa0dFQ0F3RUFBVEFOQmdrcWhraUc5dzBCQVFVRkFBT0NBZ0VBXG5sSjAxd2NuMXZqWFhDSHVvaTdSMERKMWxseDErZGFmcXlFcVBBMjdKdStMWG1WVkdYUW9yUzFiOHhqVXFVa2NaXG5UQndiV0ZPNXo1ZFptTnZuYnlqYXptKzZvT2cwUE1hWXhoNlRGd3NJMlBPYmM3YkZ2MmVheXdQdC8xQ3BuYzQwXG5xVU1oZnZSeC9HQ1pQQ1d6My8yUlBKV1g5alFEU0hYQ1hxOEJXK0kvM2N1TERaeVkzZkVZQkIwcDNEdlZtYWQ2XG42V0hRYVVyaU4wL0xxeVNPcC9MWmdsbC90MDI5Z1dWdDA1WmliR29LK2NWaFpFY3NMY1VJaHJqMnVGR0ZkM0ltXG5KTGcxSktKN2pLU0JVUU9kSU1EdnNGVUY3WWRNdk11ckNZQTJzT05OOENaK0k1eFFWMUtTOWV2R0hNNWZtd2dTXG5PUEZ2UHp0RENpMC8xdVc5dE9nSHBvcnVvZGFjdCtFWk5rQVRYQ3ZaaXUydy9xdEtSSkY0VTRJVEVtNWFXMGt3XG42enVDOHh5SWt0N3ZoZHM0OFV1UlNHSDlqSnJBZW1sRWl6dEdJTGhHRHF6UUdZYmxoVVFGR01iQmI3amhlTHlDXG5MSjFXT0c2MkYxc3B4Q0tCekVXNXg2cFIxelQxbWhFZ2Q0TWtMYTZ6UFRwYWNyZDk1QWd4YUdLRUxhMVJXU0ZwXG5NdmRoR2s0TnY3aG5iOHIrQnVNUkM2aWVkUE1DelhxL001MGNOOEFnOGJ3K0oxYUZvKzBFSzJoV0phN2tpRStzXG45R3ZGalNkekNGbFVQaEtra1Vaa1NvNWFPdGNRcTdKdTZrV0JoTG9GWUtncHJscDFRVkIwc0daQTZvNkR0cWphXG5HNy9SazZ2YmFZOHdzTllLMnpCWFRUOG5laDVab1JaL1BKTFV0RUV0YzdZPVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLSJ9	f
\.


--
-- Data for Name: shared_credentials; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."shared_credentials" ("credentialsId", "projectId", "role", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: shared_workflow; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."shared_workflow" ("workflowId", "projectId", "role", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: test_run; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."test_run" ("id", "workflowId", "status", "errorCode", "errorDetails", "runAt", "completedAt", "metrics", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: test_case_execution; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."test_case_execution" ("id", "testRunId", "executionId", "status", "runAt", "completedAt", "errorCode", "errorDetails", "metrics", "createdAt", "updatedAt", "inputs", "outputs") FROM stdin;
\.


--
-- Data for Name: user_api_keys; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user_api_keys" ("id", "userId", "label", "apiKey", "createdAt", "updatedAt", "scopes") FROM stdin;
\.


--
-- Data for Name: variables; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."variables" ("key", "type", "value", "id") FROM stdin;
\.


--
-- Data for Name: webhook_entity; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."webhook_entity" ("webhookPath", "method", "node", "webhookId", "pathLength", "workflowId") FROM stdin;
\.


--
-- Data for Name: workflow_history; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."workflow_history" ("versionId", "workflowId", "authors", "createdAt", "updatedAt", "nodes", "connections") FROM stdin;
\.


--
-- Data for Name: workflow_statistics; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."workflow_statistics" ("count", "latestEvent", "name", "workflowId", "rootCount") FROM stdin;
\.


--
-- Data for Name: workflows_tags; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."workflows_tags" ("workflowId", "tagId") FROM stdin;
\.


--
-- Data for Name: buckets; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."buckets" ("id", "name", "owner", "created_at", "updated_at", "public", "avif_autodetection", "file_size_limit", "allowed_mime_types", "owner_id") FROM stdin;
\.


--
-- Data for Name: objects; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."objects" ("id", "bucket_id", "name", "owner", "created_at", "updated_at", "last_accessed_at", "metadata", "version", "owner_id", "user_metadata") FROM stdin;
\.


--
-- Data for Name: s3_multipart_uploads; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."s3_multipart_uploads" ("id", "in_progress_size", "upload_signature", "bucket_id", "key", "version", "owner_id", "created_at", "user_metadata") FROM stdin;
\.


--
-- Data for Name: s3_multipart_uploads_parts; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."s3_multipart_uploads_parts" ("id", "upload_id", "size", "part_number", "bucket_id", "key", "etag", "owner_id", "version", "created_at") FROM stdin;
\.


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: auth; Owner: supabase_auth_admin
--

SELECT pg_catalog.setval('"auth"."refresh_tokens_id_seq"', 1, false);


--
-- Name: auth_provider_sync_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."auth_provider_sync_history_id_seq"', 1, false);


--
-- Name: execution_annotations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."execution_annotations_id_seq"', 1, false);


--
-- Name: execution_entity_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."execution_entity_id_seq"', 1, false);


--
-- Name: execution_metadata_temp_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."execution_metadata_temp_id_seq"', 1, false);


--
-- Name: insights_by_period_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."insights_by_period_id_seq"', 1, false);


--
-- Name: insights_metadata_metaId_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."insights_metadata_metaId_seq"', 1, false);


--
-- Name: insights_raw_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."insights_raw_id_seq"', 1, false);


--
-- Name: migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('"public"."migrations_id_seq"', 91, true);


--
-- PostgreSQL database dump complete
--

RESET ALL;
