package events

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const portTestSandboxID = "sandbox-1"

func catalogCases() []struct {
	name, component string
	level           slog.Level
	outcomes        []Outcome
	call            func(Outcome) (Event, error)
} {
	return []struct {
		name, component string
		level           slog.Level
		outcomes        []Outcome
		call            func(Outcome) (Event, error)
	}{
		{"gyrel.daemon.start", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return DaemonStart(o, DaemonStartParams{ListenKind: "unix", ManagedVerify: "ok"})
		}},
		{"gyrel.daemon.ready", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return DaemonReady(o, DaemonReadyParams{}) }},
		{"gyrel.daemon.shutdown", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return DaemonShutdown(o, DaemonShutdownParams{}) }},
		{"gyrel.daemon.reconcile", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return DaemonReconcile(o, DaemonReconcileParams{}) }},
		{"gyrel.port.publish-granted", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) {
			return PortPublishGranted(o, PortPublishGrantedParams{SandboxID: portTestSandboxID, GuestPort: 1, HostPort: 65535, Protocol: "tcp", BindCIDRLabel: "loopback", BindIP: "127.0.0.1"})
		}},
		{"gyrel.port.publish-refused", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeDenied}, func(o Outcome) (Event, error) {
			return PortPublishRefused(o, PortPublishRefusedParams{SandboxID: portTestSandboxID, RequestedIP: "192.0.2.1", Reason: PortPublishRefusedReasonBindForbidden})
		}},
		{"gyrel.journal.recover", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			return JournalRecover(o, JournalRecoverParams{Finding: "MarkerMissing", Action: "LEAVE"})
		}},
		{"gyrel.journal.commit", string(ComponentDaemon), slog.LevelDebug, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return JournalCommit(o, JournalCommitParams{}) }},
		{"gyrel.create.unwind", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return CreateUnwind(o, CreateUnwindParams{}) }},
		{"gyrel.peercred.reject", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeDenied}, func(o Outcome) (Event, error) { return PeerCredReject(o, PeerCredRejectParams{Transport: "unix"}) }},
		{"gyrel.platform.unsupported", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeUnsupported}, func(o Outcome) (Event, error) {
			return PlatformUnsupported(o, PlatformUnsupportedParams{Capability: "RootlessUnsupported"})
		}},
		{"gyrel.approval.requested", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) {
			return ApprovalRequested(o, ApprovalRequestedParams{Kind: "header_disclosure", DisclosureBoundary: "headers", Provider: "os"})
		}},
		{"gyrel.approval.responded", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			return ApprovalResponded(o, ApprovalRespondedParams{Decision: "APPROVE", Result: "ok"})
		}},
		{"gyrel.approval.expired", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return ApprovalExpired(o, ApprovalExpiredParams{}) }},
		{"gyrel.secret.write", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return SecretWrite(o, SecretWriteParams{VaultBackend: "keychain"}) }},
		{"gyrel.secret.substitute", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			reason := SecretSubstituteReason("")
			if o != OutcomeOK {
				reason = SecretSubstituteReasonInsecurescheme
			}
			return SecretSubstitute(o, SecretSubstituteParams{Scheme: SecretSubstituteSchemeHTTPS, Decision: SecretSubstituteDecisionSubstituted, Reason: reason})
		}},
		{"gyrel.secret.canary", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return SecretCanary(o, SecretCanaryParams{}) }},
		{"gyrel.kit.check", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) {
			reason := KitCheckReason("")
			if o != OutcomeOK {
				reason = KitCheckReasonSourcenotallowed
			}
			return KitCheck(o, KitCheckParams{Decision: KitCheckDecisionAllow, Reason: reason, Mode: KitCheckModeOffline})
		}},
		{"gyrel.mcp.register", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return MCPRegister(o, MCPRegisterParams{}) }},
		{"gyrel.mcp.attest", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeUnsupported}, func(o Outcome) (Event, error) { return MCPAttest(o, MCPAttestParams{State: "owned"}) }},
		{"gyrel.mcp.load", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return MCPLoad(o, MCPLoadParams{}) }},
		{"gyrel.mcp.unload", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return MCPUnload(o, MCPUnloadParams{}) }},
		{"gyrel.mcp.inspect", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return MCPInspect(o, MCPInspectParams{}) }},
		{"gyrel.template.save", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed, OutcomeUnsupported}, func(o Outcome) (Event, error) { return TemplateSave(o, TemplateSaveParams{}) }},
		{"gyrel.template.load", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed, OutcomeUnsupported}, func(o Outcome) (Event, error) { return TemplateLoad(o, TemplateLoadParams{}) }},
		{"gyrel.runtime.verify", string(ComponentRuntime), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return RuntimeVerify(o, RuntimeVerifyParams{Result: "ok"}) }},
		{"gyrel.runtime.launch", string(ComponentRuntime), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return RuntimeLaunch(o, RuntimeLaunchParams{Backend: "libkrun", Netdev: "gvproxy"})
		}},
		{"gyrel.keeper.recover", string(ComponentRuntime), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return KeeperRecover(o, KeeperRecoverParams{TaskState: "running"}) }},
		{"gyrel.egress.decision", string(ComponentGateway), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) {
			reason := EgressDecisionReason("")
			if o != OutcomeOK {
				reason = EgressDecisionReasonOrgdeny
			}
			return EgressDecision(o, EgressDecisionParams{Direction: EgressDecisionDirectionIn, Proto: EgressDecisionProtoTCP, Action: EgressDecisionActionAllow, Reason: reason})
		}},
		{"gyrel.egress.dns", string(ComponentGateway), slog.LevelDebug, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return EgressDNS(o, EgressDNSParams{}) }},
		{"gyrel.egress.audit_failure", string(ComponentGateway), slog.LevelError, []Outcome{OutcomeFailed}, func(o Outcome) (Event, error) {
			return EgressAuditFailure(o, EgressAuditFailureParams{ActionTaken: "deny"})
		}},
		{"gyrel.fault.detected", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return FaultDetected(o, FaultDetectedParams{Component: ComponentDaemon, Fault: "DaemonKill", RecoveryAction: "journal_reconcile", DataLoss: "none"})
		}},
		{"gyrel.obs.log_dropped", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeFailed}, func(o Outcome) (Event, error) {
			return ObsLogDropped(o, ObsLogDroppedParams{Component: ComponentDaemon})
		}},
		{"gyrel.obs.id_rejected", string(ComponentDaemon), slog.LevelDebug, []Outcome{OutcomeDenied}, func(o Outcome) (Event, error) {
			return ObsIDRejected(o, ObsIDRejectedParams{Component: ComponentDaemon, Field: "op_id", Rule: "canonical_length", Regenerated: true})
		}},
		{"gyrel.diagnose.build", "cli", slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return DiagnoseBuild(o, DiagnoseBuildParams{Result: "ok"}) }},
	}
}

func TestReasonOptionalityMatrix(t *testing.T) {
	if _, err := SecretSubstitute(OutcomeOK, SecretSubstituteParams{Scheme: SecretSubstituteSchemeHTTPS, Decision: "substituted", Reason: "InsecureScheme"}); !errors.Is(err, errInvalid) {
		t.Error("success with refusal reason must be rejected")
	}
	if _, err := SecretSubstitute(OutcomeDenied, SecretSubstituteParams{Scheme: SecretSubstituteSchemeHTTPS, Decision: "refused"}); !errors.Is(err, errInvalid) {
		t.Error("denial without reason must be rejected")
	}
	if _, err := KitCheck(OutcomeOK, KitCheckParams{Decision: KitCheckDecisionAllow, Reason: KitCheckReasonManagedsticky, Mode: KitCheckModeOffline}); !errors.Is(err, errInvalid) {
		t.Error("kit success with reason must be rejected")
	}
	ev, err := KitCheck(OutcomeDenied, KitCheckParams{Decision: KitCheckDecisionDeny, Reason: KitCheckReasonManagedsticky, Mode: KitCheckModeDaemonChecked})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Attrs(Standard{})[10].Key != "reason" || ev.Attrs(Standard{})[10].Value.String() != string(KitCheckReasonManagedsticky) { // envelope 4 + kit_ref/source/hash/allow_local/require_sig/decision + reason
		t.Errorf("denial reason attr position/value drift: %v", ev.Attrs(Standard{}))
	}
	if _, err := KitCheck(OutcomeDenied, KitCheckParams{Decision: KitCheckDecisionDeny, Reason: KitCheckReasonInvalidreference, Mode: KitCheckModeDaemonChecked}); err != nil {
		t.Errorf("InvalidReference reason rejected: %v", err)
	}
	if _, err := KitCheck(OutcomeDenied, KitCheckParams{Decision: KitCheckDecisionDeny, Reason: KitCheckReasonPolicyunavailable, Mode: KitCheckModeDaemonChecked}); err != nil {
		t.Errorf("PolicyUnavailable reason rejected: %v", err)
	}
	if _, err := EgressDecision(OutcomeOK, EgressDecisionParams{Direction: EgressDecisionDirectionOut, Proto: EgressDecisionProtoTCP, Action: EgressDecisionActionAllow, Reason: EgressDecisionReasonNorule}); !errors.Is(err, errInvalid) {
		t.Error("egress allow with reason must be rejected")
	}
	ev, err = EgressDecision(OutcomeOK, EgressDecisionParams{Direction: "out", Proto: "tcp", Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range ev.Attrs(Standard{}) {
		if a.Key == "reason" {
			t.Error("empty reason attr must not be emitted")
		}
	}
}

func TestConstructorsAndDocs(t *testing.T) {
	doc, err := os.ReadFile("../docs/events.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\| (gyrel\.[a-z0-9_.-]+) \|`).FindAllStringSubmatch(string(doc), -1)
	docs := map[string]int{}
	for _, row := range rows {
		docs[row[1]]++
	}
	cases := catalogCases()
	if len(cases) != 35 {
		t.Fatalf("got %d constructors", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if docs[tc.name] != 1 {
				t.Errorf("documentation rows: %d", docs[tc.name])
			}
			delete(docs, tc.name)
			for _, outcome := range []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed, OutcomeUnsupported, "invalid"} {
				event, err := tc.call(outcome)
				legal := false
				for _, v := range tc.outcomes {
					if outcome == v {
						legal = true
					}
				}
				if !legal {
					if err == nil {
						t.Errorf("accepted %q", outcome)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%q: %v", outcome, err)
				}
				wantLevel := tc.level
				if tc.name == "gyrel.secret.substitute" && outcome != OutcomeOK {
					wantLevel = slog.LevelWarn
				}
				if event.Name() != tc.name || event.Level() != wantLevel {
					t.Errorf("name/level %s %v", event.Name(), event.Level())
				}
				a := event.Attrs(Standard{})
				if len(a) < 4 || a[0].Value.Int64() != 1 || a[1].Value.String() != tc.name || a[2].Value.String() != tc.component || a[3].Value.String() != string(outcome) {
					t.Errorf("bad envelope: %v", a)
				}
			}
		})
	}
	if len(docs) != 0 {
		t.Errorf("undocumented constructors: %v", docs)
	}
	for _, tc := range cases {
		if !canonicalEventName(tc.name) {
			t.Errorf("%s missing from catalog membership switch", tc.name)
		}
	}
	lines := strings.Split(string(doc), "\n")
	examples := map[string]int{}
	for _, line := range lines {
		if strings.HasPrefix(line, "{") {
			var v map[string]any
			if err := json.Unmarshal([]byte(line), &v); err != nil {
				t.Fatal(err)
			}
			name, _ := v["event"].(string)
			examples[name]++
		}
	}
	for _, tc := range cases {
		if examples[tc.name] != 1 {
			t.Errorf("%s examples: %d", tc.name, examples[tc.name])
		}
		delete(examples, tc.name)
	}
	if len(examples) > 0 {
		t.Errorf("extra examples: %v", examples)
	}
}

func TestNoFreeFormFields(t *testing.T) {
	for _, tc := range catalogCases() {
		e, err := tc.call(tc.outcomes[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range e.Attrs(Standard{}) {
			if a.Key == "value" || a.Key == "payload" {
				t.Errorf("%s contains %s", tc.name, a.Key)
			}
		}
	}
	// Port publication uses explicitly named string fields in its public API.
	portStrings := map[reflect.Type]map[string]bool{
		reflect.TypeOf(PortPublishGrantedParams{}): {"SandboxID": true, "Protocol": true, "BindCIDRLabel": true, "BindIP": true},
		reflect.TypeOf(PortPublishRefusedParams{}): {"SandboxID": true, "RequestedIP": true},
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(DaemonStartParams{}),
		reflect.TypeOf(DaemonReadyParams{}),
		reflect.TypeOf(DaemonShutdownParams{}),
		reflect.TypeOf(DaemonReconcileParams{}),
		reflect.TypeOf(PortPublishGrantedParams{}),
		reflect.TypeOf(PortPublishRefusedParams{}),
		reflect.TypeOf(JournalRecoverParams{}),
		reflect.TypeOf(JournalCommitParams{}),
		reflect.TypeOf(CreateUnwindParams{}),
		reflect.TypeOf(PeerCredRejectParams{}),
		reflect.TypeOf(PlatformUnsupportedParams{}),
		reflect.TypeOf(ApprovalRequestedParams{}),
		reflect.TypeOf(ApprovalRespondedParams{}),
		reflect.TypeOf(ApprovalExpiredParams{}),
		reflect.TypeOf(SecretWriteParams{}),
		reflect.TypeOf(SecretSubstituteParams{}),
		reflect.TypeOf(SecretCanaryParams{}),
		reflect.TypeOf(KitCheckParams{}),
		reflect.TypeOf(MCPRegisterParams{}),
		reflect.TypeOf(MCPAttestParams{}),
		reflect.TypeOf(MCPLoadParams{}),
		reflect.TypeOf(MCPUnloadParams{}),
		reflect.TypeOf(MCPInspectParams{}),
		reflect.TypeOf(TemplateSaveParams{}),
		reflect.TypeOf(TemplateLoadParams{}),
		reflect.TypeOf(RuntimeVerifyParams{}),
		reflect.TypeOf(RuntimeLaunchParams{}),
		reflect.TypeOf(KeeperRecoverParams{}),
		reflect.TypeOf(EgressDecisionParams{}),
		reflect.TypeOf(EgressDNSParams{}),
		reflect.TypeOf(EgressAuditFailureParams{}),
		reflect.TypeOf(FaultDetectedParams{}),
		reflect.TypeOf(ObsLogDroppedParams{}),
		reflect.TypeOf(ObsIDRejectedParams{}),
		reflect.TypeOf(DiagnoseBuildParams{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Type.Kind() == reflect.Interface || f.Type.Kind() == reflect.Map || (f.Type == reflect.TypeOf("") && !portStrings[typ][f.Name]) {
				t.Errorf("%s.%s has untyped free-form field", typ.Name(), f.Name)
			}
		}
	}
}

func FuzzCanonicalEventName(f *testing.F) {
	for _, tc := range catalogCases() {
		f.Add(tc.name)
	}
	f.Add("gyrel.unknown")
	f.Fuzz(func(t *testing.T, name string) {
		got := canonicalEventName(name)
		found := false
		for _, tc := range catalogCases() {
			if name == tc.name {
				found = true
			}
		}
		if got != found {
			t.Fatalf("name %q: %v", name, got)
		}
	})
}

func TestConditionalLevelsAndPeerCredentials(t *testing.T) {
	e, err := SecretCanary(OutcomeFailed, SecretCanaryParams{Hits: 1})
	if err != nil || e.Level() != slog.LevelError {
		t.Fatalf("canary: %v %v", e.Level(), err)
	}
	e, err = EgressDecision(OutcomeDenied, EgressDecisionParams{Direction: EgressDecisionDirectionOut, Proto: EgressDecisionProtoTCP, Action: EgressDecisionActionDeny, Reason: EgressDecisionReasonNorule})
	if err != nil || e.Level() != slog.LevelWarn {
		t.Fatalf("egress: %v %v", e.Level(), err)
	}
	e, err = PeerCredReject(OutcomeDenied, PeerCredRejectParams{Transport: "pipe", PeerSIDHash: "digest"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range e.Attrs(Standard{}) {
		if a.Key == "peer_uid" {
			t.Fatal("pipe event contains peer_uid")
		}
	}
	if _, err = PeerCredReject(OutcomeDenied, PeerCredRejectParams{Transport: "pipe"}); err == nil {
		t.Fatal("missing SID hash accepted")
	}
}

func TestPortPublishGranted(t *testing.T) {
	p := PortPublishGrantedParams{SandboxID: portTestSandboxID, GuestPort: 1, HostPort: 65535, Protocol: "udp", BindCIDRLabel: "loopback", BindIP: "::1"}
	e, err := PortPublishGranted(OutcomeOK, p)
	if err != nil {
		t.Fatal(err)
	}
	opID := ID("operation-1")
	want := []slog.Attr{
		slog.String("sandbox_id", p.SandboxID),
		slog.Uint64("guest_port", 1),
		slog.Uint64("host_port", 65535),
		slog.String("protocol", "udp"),
		slog.String("bind_cidr_label", p.BindCIDRLabel),
		slog.String("bind_ip", p.BindIP),
		slog.String("op_id", string(opID)),
	}
	if got := e.Attrs(Standard{OpID: &opID})[4:]; !reflect.DeepEqual(got, want) {
		t.Errorf("attributes = %v, want %v", got, want)
	}

	for _, tc := range []struct {
		name   string
		change func(*PortPublishGrantedParams)
	}{
		{"empty sandbox ID", func(p *PortPublishGrantedParams) { p.SandboxID = "" }},
		{"zero guest port", func(p *PortPublishGrantedParams) { p.GuestPort = 0 }},
		{"zero host port", func(p *PortPublishGrantedParams) { p.HostPort = 0 }},
		{"empty protocol", func(p *PortPublishGrantedParams) { p.Protocol = "" }},
		{"bad protocol", func(p *PortPublishGrantedParams) { p.Protocol = "icmp" }},
		{"empty bind CIDR label", func(p *PortPublishGrantedParams) { p.BindCIDRLabel = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := p
			tc.change(&invalid)
			if _, err := PortPublishGranted(OutcomeOK, invalid); !errors.Is(err, errInvalid) {
				t.Errorf("error = %v, want %v", err, errInvalid)
			}
		})
	}
}

func TestPortPublishRefused(t *testing.T) {
	p := PortPublishRefusedParams{SandboxID: portTestSandboxID, RequestedIP: "192.0.2.1", Reason: PortPublishRefusedReasonAllowlistInvalid}
	e, err := PortPublishRefused(OutcomeDenied, p)
	if err != nil {
		t.Fatal(err)
	}
	want := []slog.Attr{
		slog.String("sandbox_id", p.SandboxID),
		slog.String("requested_ip", p.RequestedIP),
		slog.String("reason", "allowlist_invalid"),
	}
	if got := e.Attrs(Standard{})[4:]; !reflect.DeepEqual(got, want) {
		t.Errorf("attributes = %v, want %v", got, want)
	}
	for _, invalid := range []PortPublishRefusedParams{
		{SandboxID: p.SandboxID, RequestedIP: p.RequestedIP},
		{SandboxID: p.SandboxID, RequestedIP: p.RequestedIP, Reason: "unknown"},
		{RequestedIP: p.RequestedIP, Reason: p.Reason},
	} {
		if _, err := PortPublishRefused(OutcomeDenied, invalid); !errors.Is(err, errInvalid) {
			t.Errorf("PortPublishRefused(%+v) error = %v, want %v", invalid, err, errInvalid)
		}
	}
}
