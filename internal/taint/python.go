// Package taint provides AST-based source→sink analysis for Python using
// tree-sitter (the same parsing infrastructure GitHub and Neovim use).
//
// This is the answer to regex's false-positive problem: instead of flagging
// every `requests.get(...)` line, we prove `url = request.args.get("url")`
// happened earlier and only then flag `requests.get(url)`.
package taint

import (
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"
	tspython "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/raj921/vulngate/internal/rules"
)

// Result is one AST-confirmed finding.
type Result struct {
	RuleID string
	Name   string
	CWE    string
	Line   int
	Code   string
	Fix    string
}

var sourcePrefixes = []string{
	"request.args", "request.form", "request.values", "request.headers",
	"request.cookies", "request.data", "request.json", "request.GET", "request.POST",
	"flask.request", "self.request",
}

type sinkClass struct {
	RuleID string
	Name   string
	CWE    string
	Fix    string
}

// sinks keyed by exact function name or suffix rule.
var sinks = []struct {
	match func(fnText string) bool
	class sinkClass
}{
	{func(f string) bool {
		for _, p := range []string{"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.head"} {
			if strings.HasPrefix(f, p) {
				return true
			}
		}
		return false
	}, sinkClass{"VG-T01", "SSRF via tainted input", "CWE-918",
		"Validate against an allow-list of hosts; never fetch raw user-supplied URLs."}},
	{func(f string) bool {
		return f == "os.system" || f == "os.popen" ||
			strings.HasPrefix(f, "subprocess.call") || strings.HasPrefix(f, "subprocess.run") ||
			strings.HasPrefix(f, "subprocess.Popen")
	}, sinkClass{"VG-T02", "Command injection via tainted input", "CWE-78",
		"Avoid the shell; pass argv lists. Data provenance: user-controlled input reached a shell."}},
	{func(f string) bool {
		return strings.HasSuffix(f, ".execute") || strings.HasSuffix(f, ".executemany")
	}, sinkClass{"VG-T03", "SQL injection via tainted input", "CWE-89",
		"Use parameterized queries: execute(sql, (params,)). A tainted variable reached the query."}},
	{func(f string) bool {
		return strings.HasPrefix(f, "pickle.load") || strings.HasPrefix(f, "yaml.load")
	}, sinkClass{"VG-T04", "Unsafe deserialization of tainted input", "CWE-502",
		"Use json or yaml.safe_load(). pickle on user data = RCE."}},
	{func(f string) bool { return f == "eval" || f == "exec" },
		sinkClass{"VG-T05", "Code injection (eval/exec of tainted input)", "CWE-94",
			"Never eval/exec input-derived strings. Use ast.literal_eval or a real parser."}},
}

// AnalyzePython runs source→sink taint analysis on one Python source file.
func AnalyzePython(src []byte) []Result {
	parser := ts.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(ts.NewLanguage(tspython.Language())); err != nil {
		return nil
	}
	tree := parser.Parse(src, nil)
	defer tree.Close()
	root := tree.RootNode()

	lines := strings.Split(string(src), "\n")

	// --- collect assignments, propagate taint to fixpoint
	type assign struct{ name string }
	tainted := map[string]bool{}
	var assignments []*ts.Node
	walk(root, func(n *ts.Node) {
		if n.Kind() == "assignment" {
			assignments = append(assignments, n)
		}
	})

	for changed, pass := true, 0; changed && pass < 16; pass++ {
		changed = false
		for _, a := range assignments {
			left, right := a.ChildByFieldName("left"), a.ChildByFieldName("right")
			if left == nil || right == nil || left.Kind() != "identifier" {
				continue
			}
			name := left.Utf8Text(src)
			if tainted[name] {
				continue
			}
			if isSource(right, src) || containsTainted(right, src, tainted) {
				tainted[name] = true
				changed = true
			}
		}
	}

	// --- find sink calls reached by tainted data (or direct request input)
	var out []Result
	walk(root, func(n *ts.Node) {
		if n.Kind() != "call" {
			return
		}
		fn := n.ChildByFieldName("function")
		args := n.ChildByFieldName("arguments")
		if fn == nil || args == nil {
			return
		}
		fnText := fn.Utf8Text(src)
		for _, s := range sinks {
			if !s.match(fnText) {
				continue
			}
			if s.class.RuleID == "VG-T03" && isParameterizedQuery(args, src) {
				continue // execute("... WHERE id = ?", (uid,)) — safe shape
			}
			if !containsTainted(args, src, tainted) && !isSource(args, src) {
				continue
			}
			row := int(n.StartPosition().Row)
			code := ""
			if row < len(lines) {
				code = strings.TrimSpace(lines[row])
			}
			out = append(out, Result{
				RuleID: s.class.RuleID, Name: s.class.Name, CWE: s.class.CWE,
				Line: row + 1, Code: code, Fix: s.class.Fix,
			})
			break
		}
	})
	return out
}

// isSource reports whether the subtree reads user-controlled input:
// a call to input()/request.*, or a bare request.* attribute access.
func isSource(n *ts.Node, src []byte) bool {
	found := false
	walk(n, func(c *ts.Node) {
		if found {
			return
		}
		switch c.Kind() {
		case "call":
			if fn := c.ChildByFieldName("function"); fn != nil {
				t := fn.Utf8Text(src)
				if t == "input" || t == "request.get_json" {
					found = true
				}
			}
		case "attribute", "dotted_name":
			t := c.Utf8Text(src)
			for _, p := range sourcePrefixes {
				if strings.HasPrefix(t, p+".") || t == p {
					found = true
					return
				}
			}
		}
	})
	return found
}

// isParameterizedQuery recognizes the safe sink shape
// execute("<literal>", (params,)): first argument a plain string literal with
// no interpolation AND at least a second argument carrying the parameters.
func isParameterizedQuery(args *ts.Node, src []byte) bool {
	if args.NamedChildCount() < 2 {
		return false
	}
	first := args.NamedChild(0)
	if first == nil || first.Kind() != "string" {
		return false
	}
	hasInterp := false
	walk(first, func(c *ts.Node) {
		if c.Kind() == "interpolation" {
			hasInterp = true
		}
	})
	return !hasInterp
}

// containsTainted reports whether the subtree references any tainted identifier.
func containsTainted(n *ts.Node, src []byte, tainted map[string]bool) bool {
	found := false
	walk(n, func(c *ts.Node) {
		if found {
			return
		}
		if c.Kind() == "identifier" && tainted[c.Utf8Text(src)] {
			found = true
		}
	})
	return found
}

func walk(n *ts.Node, fn func(*ts.Node)) {
	fn(n)
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil {
			walk(c, fn)
		}
	}
}

// SeverityOf returns the severity for a taint rule id (all HIGH for now).
func SeverityOf(id string) string { return rules.High }
