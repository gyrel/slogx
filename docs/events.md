# Event catalog

Every event has `schema_version=1`, `event`, `component`, and `outcome`. Optional standard attributes are `op_id`, `req_id`, `sandbox_id`, `generation`, `duration_ms`, and `error_code`. IDs and hashes must be caller-generated identifiers and digests; hosts must be policy target hostnames. Constructors reject invalid enum values.

## component=daemon

| event | component | level | outcome | fields |
|---|---|---|---|---|
| rheic.daemon.start | daemon | INFO | ok, failed | listen_kind(unix|pipe), socket_path_hash, uid(count), runtime_bundle_digest(hash), managed_verify(ok|refused) |
| rheic.daemon.ready | daemon | INFO | ok | startup_ms(count), recovered_count(count) |
| rheic.daemon.shutdown | daemon | INFO | ok, failed | signal(string-id), inflight_ops(count), flush_ok(bool) |
| rheic.daemon.reconcile | daemon | INFO | ok | scanned(count), adopted(count), left_alone(count), generation_mismatch(count) |
| rheic.journal.recover | daemon | WARN | ok, denied, failed | finding(MarkerMissing|MarkerMismatch|SymlinkRefused|OutsideRoot|ParseFailed|TempOrphan|ForeignResource|UnsupportedOwnership), action(LEAVE|DELETE|ADOPT), resource_kind(string-id), path_hash |
| rheic.journal.commit | daemon | DEBUG | ok, failed | journal_id(string-id), fsync_ok(bool), rename_ok(bool) |
| rheic.create.unwind | daemon | WARN | ok, failed | stage(string-id), cleanup_ok(bool), network_stopped(bool), reason(string-id) |
| rheic.peercred.reject | daemon | WARN | denied | peer_uid(count, unix) or peer_sid_hash(hash, windows), expected_hash, transport(unix|pipe) |
| rheic.platform.unsupported | daemon | WARN | unsupported | capability(RootlessUnsupported|WorkspaceDirectUnsupported|WHPUnavailable|VaultHeadless|LoopDeviceUnavailable|ApprovalProviderMissing), hint_id(string-id) |
| rheic.approval.requested | daemon | INFO | ok | approval_id, kind(header_disclosure|vault_ref|mcp_register|host_command|other), disclosure_boundary(headers|vault_refs), provider(os|none) |
| rheic.approval.responded | daemon | INFO | ok, denied, failed | approval_id, decision(APPROVE|EXACT|DENY), result(ok|FAILED_PRECONDITION) |
| rheic.approval.expired | daemon | INFO | ok | approval_id, ttl_ms(count) |
| rheic.secret.write | daemon | INFO | ok, failed | secret_ref_id, vault_backend(keychain|credman|secretservice), placeholder_issued(bool) |
| rheic.secret.substitute | daemon | INFO (ok), WARN (denied/failed) | ok, denied, failed | secret_ref_id, host, scheme=https, decision(substituted|dropped_header|refused), reason(InsecureScheme|VaultLocked|RefMissing; required exactly when outcome != ok, omitted on ok) |
| rheic.secret.canary | daemon | INFO (hits=0), ERROR (hits>0) | ok, failed | scanned_stores(count), hits(count) |
| rheic.kit.check | daemon | INFO | ok, denied | kit_ref, source, allowed_sources_hash, allow_local(bool), require_signature(bool), decision(allow|deny), reason(SourceNotAllowed|LocalKitDisabled|SignatureRequired|ManagedSticky; required exactly when outcome != ok, omitted on ok), mode(offline|daemon-checked) |
| rheic.mcp.register | daemon | INFO | ok, denied | server_id_hash, challenge_issued(bool), stored(bool) |
| rheic.mcp.attest | daemon | INFO | ok, denied, unsupported | server_id_hash, state(owned|absent|foreign), registry_included(bool) |
| rheic.mcp.load | daemon | INFO | ok, denied, failed | server_id_hash, tools_count(count), approval_id |
| rheic.mcp.unload | daemon | INFO | ok, failed | server_id_hash |
| rheic.mcp.inspect | daemon | INFO | ok, denied | server_id_hash, tools_count(count) |
| rheic.template.save | daemon | INFO | ok, failed, unsupported | template_id, layers(count), whiteouts(count), opaque_dirs(count), host_workspace_included(bool), guest_secrets_warning(bool), bytes(count), digest(hash) |
| rheic.template.load | daemon | INFO | ok, failed, unsupported | template_id, layers(count), bytes(count), digest(hash) |

## component=runtime

| event | component | level | outcome | fields |
|---|---|---|---|---|
| rheic.runtime.verify | runtime | INFO | ok, denied, failed | artifact(string-id), expected_digest, actual_digest, result(ok|mismatch|missing) |
| rheic.runtime.launch | runtime | INFO | ok, failed | backend(libkrun|qemu-whpx), kernel_digest, rootfs_digest, netdev(gvproxy), boot_ms(count) |
| rheic.keeper.recover | runtime | WARN | ok, failed | child_pid(count), socket_repoint(bool), stale_refused(bool), task_state(running|stopped|unknown) |

## component=gateway

| event | component | level | outcome | fields |
|---|---|---|---|---|
| rheic.egress.decision | gateway | INFO (allow), WARN (deny) | ok, denied | direction(in|out), host, port(count), proto(tcp|udp), action(allow|deny), reason(OrgDeny|PolicyDeny|NoRule|DNSRebind|TTLGuard|IPv6Unsupported|QUICCapabilityOff|AuditWriteFailed; required exactly when outcome != ok, omitted on ok), policy_generation(count), l7_phase(count) |
| rheic.egress.dns | gateway | DEBUG | ok, denied | qname, resolved_count(count), ttl_ms(count), rebind_suspected(bool) |
| rheic.egress.audit_failure | gateway | ERROR | failed | sink(string-id), action_taken(deny) |

## cross-component

| event | component | level | outcome | fields |
|---|---|---|---|---|
| rheic.fault.detected | daemon, runtime, gateway, guest, cli | WARN | ok, failed | fault(DaemonKill|ShimKill|GuestKill|DiskFull|StaleSocket|StalePID|InterruptedMigration|ConcurrentOp|AttesterFailure|VaultLocked), recovery_action(journal_reconcile|keeper_restart|detach_reattach|unwind_cleanup|refused_foreign|unsupported), data_loss(none|possible) |
| rheic.obs.log_dropped | daemon, runtime, gateway, guest, cli | WARN | failed | dropped_count(count), queue_len(count) — component = dropping component |
| rheic.obs.id_rejected | daemon, runtime, gateway, guest, cli | DEBUG | denied | field(op_id|req_id|parent_req_id), rule(canonical_length|charset|prefix), regenerated(bool=true) |

## component=cli

| event | component | level | outcome | fields |
|---|---|---|---|---|
| rheic.diagnose.build | cli | INFO | ok, denied, failed | files(count), bytes(count), redaction_hits(count), result(ok|refused|error), bundle_sha256 |


## Examples

```jsonl
{"schema_version":1,"event":"rheic.daemon.start","component":"daemon","outcome":"ok","listen_kind":"unix","socket_path_hash":"example-id","uid":0,"runtime_bundle_digest":"example-id","managed_verify":"ok"}
{"schema_version":1,"event":"rheic.daemon.ready","component":"daemon","outcome":"ok","startup_ms":0,"recovered_count":0}
{"schema_version":1,"event":"rheic.daemon.shutdown","component":"daemon","outcome":"ok","signal":"example-id","inflight_ops":0,"flush_ok":true}
{"schema_version":1,"event":"rheic.daemon.reconcile","component":"daemon","outcome":"ok","scanned":0,"adopted":0,"left_alone":0,"generation_mismatch":0}
{"schema_version":1,"event":"rheic.journal.recover","component":"daemon","outcome":"ok","finding":"MarkerMissing","action":"LEAVE","resource_kind":"example-id","path_hash":"example-id"}
{"schema_version":1,"event":"rheic.journal.commit","component":"daemon","outcome":"ok","journal_id":"example-id","fsync_ok":true,"rename_ok":true}
{"schema_version":1,"event":"rheic.create.unwind","component":"daemon","outcome":"ok","stage":"example-id","cleanup_ok":true,"network_stopped":true,"reason":"example-id"}
{"schema_version":1,"event":"rheic.peercred.reject","component":"daemon","outcome":"denied","peer_uid":0,"expected_hash":"example-id","transport":"unix"}
{"schema_version":1,"event":"rheic.platform.unsupported","component":"daemon","outcome":"unsupported","capability":"RootlessUnsupported","hint_id":"example-id"}
{"schema_version":1,"event":"rheic.approval.requested","component":"daemon","outcome":"ok","approval_id":"example-id","kind":"header_disclosure","disclosure_boundary":"headers","provider":"os"}
{"schema_version":1,"event":"rheic.approval.responded","component":"daemon","outcome":"ok","approval_id":"example-id","decision":"APPROVE","result":"ok"}
{"schema_version":1,"event":"rheic.approval.expired","component":"daemon","outcome":"ok","approval_id":"example-id","ttl_ms":0}
{"schema_version":1,"event":"rheic.secret.write","component":"daemon","outcome":"ok","secret_ref_id":"example-id","vault_backend":"keychain","placeholder_issued":true}
{"schema_version":1,"event":"rheic.secret.substitute","component":"daemon","outcome":"ok","secret_ref_id":"example-id","host":"example.test","scheme":"https","decision":"substituted"}
{"schema_version":1,"event":"rheic.secret.canary","component":"daemon","outcome":"ok","scanned_stores":0,"hits":0}
{"schema_version":1,"event":"rheic.kit.check","component":"daemon","outcome":"ok","kit_ref":"example-id","source":"example-id","allowed_sources_hash":"example-id","allow_local":true,"require_signature":true,"decision":"allow","mode":"offline"}
{"schema_version":1,"event":"rheic.mcp.register","component":"daemon","outcome":"ok","server_id_hash":"example-id","challenge_issued":true,"stored":true}
{"schema_version":1,"event":"rheic.mcp.attest","component":"daemon","outcome":"ok","server_id_hash":"example-id","state":"owned","registry_included":true}
{"schema_version":1,"event":"rheic.mcp.load","component":"daemon","outcome":"ok","server_id_hash":"example-id","tools_count":0,"approval_id":"example-id"}
{"schema_version":1,"event":"rheic.mcp.unload","component":"daemon","outcome":"ok","server_id_hash":"example-id"}
{"schema_version":1,"event":"rheic.mcp.inspect","component":"daemon","outcome":"ok","server_id_hash":"example-id","tools_count":0}
{"schema_version":1,"event":"rheic.template.save","component":"daemon","outcome":"ok","template_id":"example-id","layers":0,"whiteouts":0,"opaque_dirs":0,"host_workspace_included":true,"guest_secrets_warning":true,"bytes":0,"digest":"example-id"}
{"schema_version":1,"event":"rheic.template.load","component":"daemon","outcome":"ok","template_id":"example-id","layers":0,"bytes":0,"digest":"example-id"}
{"schema_version":1,"event":"rheic.runtime.verify","component":"runtime","outcome":"ok","artifact":"example-id","expected_digest":"example-id","actual_digest":"example-id","result":"ok"}
{"schema_version":1,"event":"rheic.runtime.launch","component":"runtime","outcome":"ok","backend":"libkrun","kernel_digest":"example-id","rootfs_digest":"example-id","netdev":"gvproxy","boot_ms":0}
{"schema_version":1,"event":"rheic.keeper.recover","component":"runtime","outcome":"ok","child_pid":0,"socket_repoint":true,"stale_refused":true,"task_state":"running"}
{"schema_version":1,"event":"rheic.egress.decision","component":"gateway","outcome":"ok","direction":"in","host":"example.test","port":0,"proto":"tcp","action":"allow","policy_generation":0,"l7_phase":0}
{"schema_version":1,"event":"rheic.egress.dns","component":"gateway","outcome":"ok","qname":"example.test","resolved_count":0,"ttl_ms":0,"rebind_suspected":true}
{"schema_version":1,"event":"rheic.egress.audit_failure","component":"gateway","outcome":"failed","sink":"example-id","action_taken":"deny"}
{"schema_version":1,"event":"rheic.fault.detected","component":"daemon","outcome":"ok","fault":"DaemonKill","recovery_action":"journal_reconcile","data_loss":"none"}
{"schema_version":1,"event":"rheic.obs.log_dropped","component":"daemon","outcome":"failed","dropped_count":0,"queue_len":0}
{"schema_version":1,"event":"rheic.obs.id_rejected","component":"daemon","outcome":"denied","field":"op_id","rule":"canonical_length","regenerated":true}
{"schema_version":1,"event":"rheic.diagnose.build","component":"cli","outcome":"ok","files":0,"bytes":0,"redaction_hits":0,"result":"ok","bundle_sha256":"example-id"}
```
