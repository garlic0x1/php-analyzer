package main

import (
	"log"
	"os"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
	"gopkg.in/yaml.v2"
)

type Context struct {
	Class string
	Block string
}

type Vuln struct {
	Sources []string
	Sinks   []string
	Args    map[string][]int
	Filters []string
}

type Taint struct {
	Name   string
	Type   string
	Scope  Context
	Vertex ast.Vertex
	Parent *Taint
	Stack  string
}

type Item struct {
	Name   string
	Type   string
	Scope  Context
	Vertex ast.Vertex
}

type Analyzer struct {
	visitor.Null

	CallStack      []Item
	Tainted        []Taint
	CurrentContext Context
	Data           map[string]Vuln
	Filename       string
}

func NewAnalyzer(filename string, datafile string) *Analyzer {
	var analyzer = &Analyzer{
		Filename: filename,
	}

	analyzer.LoadData(datafile)

	return analyzer
}

func (a *Analyzer) Push(item Item) {
	a.CallStack = append([]Item{item}, a.CallStack...)
}

func (a *Analyzer) Pop() Item {
	ret := a.CallStack[0]
	a.CallStack = a.CallStack[1:]
	return ret
}

func (a *Analyzer) Top() Item {
	return a.CallStack[0]
}

func (a *Analyzer) DumpStack(taint Taint) string {
	str := ""
	for i := len(a.CallStack) - 1; i >= 0; i-- {
		str += "[" + a.CallStack[i].Type + "] " + a.CallStack[i].Name + " <- "
	}
	str += "[taint] " + taint.Name
	return str
}

// Trace up to the nearest sink, assignment, or valid filter
func (a *Analyzer) Trace(taint Taint) {
	for _, item := range a.CallStack {
		switch item.Type {
		case "filter":
			for _, f := range a.Data[taint.Type].Filters {
				if item.Name == f {
					return
				}
			}
		case "sink":
			for sink, _ := range a.Data[taint.Type].Args {
				if item.Name == sink {
					// send to results when a taint meets a sink
					Results <- Result{Vertex: item.Vertex, Type: taint.Type, LastTaint: taint, Filename: a.Filename, Stack: a.DumpStack(taint)}
				}
			}
			for _, sink := range a.Data[taint.Type].Sinks {
				if item.Name == sink {
					// send to results when a taint meets a sink
					Results <- Result{Vertex: item.Vertex, Type: taint.Type, LastTaint: taint, Filename: a.Filename, Stack: a.DumpStack(taint)}
				}
			}
		case "assign":
			a.AddTaint(Taint{Name: item.Name, Type: taint.Type, Scope: item.Scope, Vertex: item.Vertex, Parent: &taint, Stack: a.DumpStack(taint)})
			return
		case "break":
			return
		}
	}
}

func (a *Analyzer) VarVertex(name string) {
	for _, taint := range a.Tainted {
		if taint.Name == name {
			if a.CompareContexts(taint.Scope, a.CurrentContext) {
				a.Trace(taint)
			}
		}
	}
}

// search for taints to track

func (a *Analyzer) ExprVariable(n *ast.ExprVariable) {
	id, ok := n.Name.(*ast.Identifier)
	if !ok {
		return
	}
	name := string(id.Value)

	a.VarVertex(name)
}

func (a *Analyzer) ExprPropertyFetch(n *ast.ExprPropertyFetch) {
	id, ok := n.Prop.(*ast.Identifier)
	if !ok {
		return
	}
	name := string(id.Value)

	a.VarVertex(name)
}

func (a *Analyzer) ExprFunctionCall(n *ast.ExprFunctionCall) {
	name := ""
	funcName, ok := n.Function.(*ast.Name)
	if !ok {
		return
	}
	for _, v := range funcName.Parts {
		name += string(v.(*ast.NamePart).Value)
	}

	a.VarVertex(name)
}

func (a *Analyzer) ExprMethodCall(n *ast.ExprMethodCall) {
	obj, ok := n.Var.(*ast.ExprVariable)
	if !ok {
		return
	}
	cid, ok := obj.Name.(*ast.Identifier)
	if !ok {
		return
	}
	mid, ok := n.Method.(*ast.Identifier)
	if !ok {
		return
	}

	methodname := string(mid.Value)
	fullname := string(cid.Value) + "->" + methodname

	a.VarVertex(fullname)
	a.VarVertex(methodname)
}

// auxiliary funcs

func (a *Analyzer) AddTaint(add Taint) {
	for _, taint := range a.Tainted {
		if a.CompareTaints(add, taint) {
			return
		}
	}

	//log.Println("Tainted: ", add.Name, add.Type, &add.Scope)
	a.Tainted = append(a.Tainted, add)
}

func (a *Analyzer) CompareTaints(t1 Taint, t2 Taint) bool {
	return t1.Name == t2.Name && t1.Type == t2.Type && a.CompareContexts(t1.Scope, t2.Scope)
}

func (a *Analyzer) CompareContexts(c1 Context, c2 Context) bool {
	return (c1.Block == c2.Block || c1.Block == "*" || c2.Block == "*") && (c1.Class == c2.Class || c1.Class == "*" || c2.Class == "*")
}

func (a *Analyzer) LoadData(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	d := yaml.NewDecoder(file)

	err = d.Decode(&a.Data)
	if err != nil {
		panic(err)
	}

	// add sources to taint list
	for t, vuln := range a.Data {
		for _, source := range vuln.Sources {
			a.AddTaint(Taint{Name: source, Type: t, Scope: Context{Class: "*", Block: "*"}})
		}
	}
}
