package events

import (
	"encoding/json"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

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
		{"rheic.daemon.start", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return DaemonStart(o, DaemonStartParams{ListenKind: "unix", ManagedVerify: "ok"})
		}},
		{"rheic.daemon.ready", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return DaemonReady(o, DaemonReadyParams{}) }},
		{"rheic.daemon.shutdown", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return DaemonShutdown(o, DaemonShutdownParams{}) }},
		{"rheic.daemon.reconcile", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return DaemonReconcile(o, DaemonReconcileParams{}) }},
		{"rheic.journal.recover", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			return JournalRecover(o, JournalRecoverParams{Finding: "MarkerMissing", Action: "LEAVE"})
		}},
		{"rheic.journal.commit", string(ComponentDaemon), slog.LevelDebug, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return JournalCommit(o, JournalCommitParams{}) }},
		{"rheic.create.unwind", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return CreateUnwind(o, CreateUnwindParams{}) }},
		{"rheic.peercred.reject", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeDenied}, func(o Outcome) (Event, error) { return PeerCredReject(o, PeerCredRejectParams{Transport: "unix"}) }},
		{"rheic.platform.unsupported", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeUnsupported}, func(o Outcome) (Event, error) {
			return PlatformUnsupported(o, PlatformUnsupportedParams{Capability: "RootlessUnsupported"})
		}},
		{"rheic.approval.requested", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) {
			return ApprovalRequested(o, ApprovalRequestedParams{Kind: "header_disclosure", DisclosureBoundary: "headers", Provider: "os"})
		}},
		{"rheic.approval.responded", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			return ApprovalResponded(o, ApprovalRespondedParams{Decision: "APPROVE", Result: "ok"})
		}},
		{"rheic.approval.expired", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK}, func(o Outcome) (Event, error) { return ApprovalExpired(o, ApprovalExpiredParams{}) }},
		{"rheic.secret.write", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return SecretWrite(o, SecretWriteParams{VaultBackend: "keychain"}) }},
		{"rheic.secret.substitute", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) {
			return SecretSubstitute(o, SecretSubstituteParams{Scheme: "https", Decision: "substituted", Reason: "InsecureScheme"})
		}},
		{"rheic.secret.canary", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return SecretCanary(o, SecretCanaryParams{}) }},
		{"rheic.kit.check", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) {
			return KitCheck(o, KitCheckParams{Decision: "allow", Reason: "SourceNotAllowed", Mode: "offline"})
		}},
		{"rheic.mcp.register", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return MCPRegister(o, MCPRegisterParams{}) }},
		{"rheic.mcp.attest", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeUnsupported}, func(o Outcome) (Event, error) { return MCPAttest(o, MCPAttestParams{State: "owned"}) }},
		{"rheic.mcp.load", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return MCPLoad(o, MCPLoadParams{}) }},
		{"rheic.mcp.unload", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return MCPUnload(o, MCPUnloadParams{}) }},
		{"rheic.mcp.inspect", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return MCPInspect(o, MCPInspectParams{}) }},
		{"rheic.template.save", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed, OutcomeUnsupported}, func(o Outcome) (Event, error) { return TemplateSave(o, TemplateSaveParams{}) }},
		{"rheic.template.load", string(ComponentDaemon), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed, OutcomeUnsupported}, func(o Outcome) (Event, error) { return TemplateLoad(o, TemplateLoadParams{}) }},
		{"rheic.runtime.verify", string(ComponentRuntime), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return RuntimeVerify(o, RuntimeVerifyParams{Result: "ok"}) }},
		{"rheic.runtime.launch", string(ComponentRuntime), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return RuntimeLaunch(o, RuntimeLaunchParams{Backend: "libkrun", Netdev: "gvproxy"})
		}},
		{"rheic.keeper.recover", string(ComponentRuntime), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) { return KeeperRecover(o, KeeperRecoverParams{TaskState: "running"}) }},
		{"rheic.egress.decision", string(ComponentGateway), slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) {
			return EgressDecision(o, EgressDecisionParams{Direction: "in", Proto: "tcp", Action: "allow", Reason: "OrgDeny"})
		}},
		{"rheic.egress.dns", string(ComponentGateway), slog.LevelDebug, []Outcome{OutcomeOK, OutcomeDenied}, func(o Outcome) (Event, error) { return EgressDNS(o, EgressDNSParams{}) }},
		{"rheic.egress.audit_failure", string(ComponentGateway), slog.LevelError, []Outcome{OutcomeFailed}, func(o Outcome) (Event, error) {
			return EgressAuditFailure(o, EgressAuditFailureParams{ActionTaken: "deny"})
		}},
		{"rheic.fault.detected", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeOK, OutcomeFailed}, func(o Outcome) (Event, error) {
			return FaultDetected(o, FaultDetectedParams{Component: ComponentDaemon, Fault: "DaemonKill", RecoveryAction: "journal_reconcile", DataLoss: "none"})
		}},
		{"rheic.obs.log_dropped", string(ComponentDaemon), slog.LevelWarn, []Outcome{OutcomeFailed}, func(o Outcome) (Event, error) {
			return ObsLogDropped(o, ObsLogDroppedParams{Component: ComponentDaemon})
		}},
		{"rheic.obs.id_rejected", string(ComponentDaemon), slog.LevelDebug, []Outcome{OutcomeDenied}, func(o Outcome) (Event, error) {
			return ObsIDRejected(o, ObsIDRejectedParams{Component: ComponentDaemon, Field: "op_id", Rule: "canonical_length", Regenerated: true})
		}},
		{"rheic.diagnose.build", "cli", slog.LevelInfo, []Outcome{OutcomeOK, OutcomeDenied, OutcomeFailed}, func(o Outcome) (Event, error) { return DiagnoseBuild(o, DiagnoseBuildParams{Result: "ok"}) }},
	}
}

func TestConstructorsAndDocs(t *testing.T) {
	doc, err := os.ReadFile("../docs/events.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\| (rheic\.[a-z0-9_.]+) \|`).FindAllStringSubmatch(string(doc), -1)
	docs := map[string]int{}
	for _, row := range rows {
		docs[row[1]]++
	}
	cases := catalogCases()
	if len(cases) != 33 {
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
				if tc.name == "rheic.secret.substitute" && outcome != OutcomeOK {
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
	for _, typ := range []reflect.Type{
		reflect.TypeOf(DaemonStartParams{}),
		reflect.TypeOf(DaemonReadyParams{}),
		reflect.TypeOf(DaemonShutdownParams{}),
		reflect.TypeOf(DaemonReconcileParams{}),
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
			if f.Type.Kind() == reflect.Interface || f.Type.Kind() == reflect.Map || f.Type == reflect.TypeOf("") {
				t.Errorf("%s.%s has untyped free-form field", typ.Name(), f.Name)
			}
		}
	}
}

func FuzzCanonicalEventName(f *testing.F) {
	for _, tc := range catalogCases() {
		f.Add(tc.name)
	}
	f.Add("rheic.unknown")
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
	e, err = EgressDecision(OutcomeDenied, EgressDecisionParams{Direction: "out", Proto: "tcp", Action: "deny", Reason: "NoRule"})
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
