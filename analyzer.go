package main

import (
	"fmt"
	"log"
	"os"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
	"gopkg.in/yaml.v2"
)

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
}

type Item struct {
	Name   string
	Type   string
	Scope  Context
	Vertex ast.Vertex
}

type Analyzer struct {
	visitor.Null

	CallStack []Item
	Tainted   map[Taint]string
	Data      map[string]Vuln
	Filename  string
}

func NewAnalyzer(filename string, datafile string) *Analyzer {
	var analyzer = &Analyzer{
		Filename: filename,
		Tainted:  make(map[Taint]string),
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

func (a *Analyzer) DumpStack() string {
	str := ""
	for i, item := range a.CallStack {
		str += fmt.Sprintf("%d. Name: %s, Type: %s\n", i, item.Name, item.Type)
	}
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
					Results <- Result{Vertex: item.Vertex, Type: taint.Type, LastTaint: taint, Filename: a.Filename}
				}
			}
			for _, sink := range a.Data[taint.Type].Sinks {
				if item.Name == sink {
					// send to results when a taint meets a sink
					Results <- Result{Vertex: item.Vertex, Type: taint.Type, LastTaint: taint, Filename: a.Filename}
				}
			}
		case "assign":
			a.Tainted[Taint{Name: item.Name, Type: taint.Type, Scope: item.Scope, Vertex: item.Vertex, Parent: &taint}] = item.Name
			return
		case "break":
			return
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

	for taint, str := range a.Tainted {
		if str == name {
			a.Trace(taint)
		}
	}
}

func (a *Analyzer) ExprPropertyFetch(n *ast.ExprPropertyFetch) {
	id, ok := n.Prop.(*ast.Identifier)
	if !ok {
		return
	}
	name := string(id.Value)

	for taint, str := range a.Tainted {
		if str == name {
			a.Trace(taint)
		}
	}
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

	for taint, str := range a.Tainted {
		if str == name {
			a.Trace(taint)
		}
	}
}

func (a *Analyzer) ExprMethodCall(n *ast.ExprMethodCall) {
	id, ok := n.Method.(*ast.Identifier)
	if !ok {
		return
	}

	name := string(id.Value)

	for taint, str := range a.Tainted {
		if str == name {
			a.Trace(taint)
		}
	}
}

// auxiliary funcs

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
			a.Tainted[Taint{Name: source, Type: t, Scope: Context{Class: "", Block: ""}}] = source
		}
	}
}
