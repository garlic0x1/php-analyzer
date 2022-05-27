// Package visitor contains walker.visitor implementations
package main

import (
	"errors"
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor"
)

// NamespaceResolver visitor
type NamespaceResolver struct {
	visitor.Null
	Namespace     *Namespace
	ResolvedNames map[ast.Vertex]string

	goDeep bool
}

// NewNamespaceResolver NamespaceResolver type constructor
func NewNamespaceResolver() *NamespaceResolver {
	return &NamespaceResolver{
		Namespace:     NewNamespace(""),
		ResolvedNames: map[ast.Vertex]string{},
		goDeep:        true,
	}
}

func (nsr *NamespaceResolver) EnterNode(n ast.Vertex) bool {
	n.Accept(nsr)

	if !nsr.goDeep {
		nsr.goDeep = true
		return false
	}

	return true
}

func (nsr *NamespaceResolver) StmtFunction(n *ast.StmtFunction) {
	nsr.AddNamespacedName(n, string(n.Name.(*ast.Identifier).Value))

	for _, parameter := range n.Params {
		nsr.ResolveType(parameter.(*ast.Parameter).Type)
	}

	if n.ReturnType != nil {
		nsr.ResolveType(n.ReturnType)
	}
}

func (nsr *NamespaceResolver) StmtClassMethod(n *ast.StmtClassMethod) {
	nsr.AddNamespacedName(n, string(n.Name.(*ast.Identifier).Value))

	for _, parameter := range n.Params {
		nsr.ResolveType(parameter.(*ast.Parameter).Type)
	}

	if n.ReturnType != nil {
		nsr.ResolveType(n.ReturnType)
	}
}

// LeaveNode is invoked after node process
func (nsr *NamespaceResolver) LeaveNode(n ast.Vertex) {
	switch nn := n.(type) {
	case *ast.StmtNamespace:
		if nn.Stmts != nil {
			nsr.Namespace = NewNamespace("")
		}
	}
}

// AddAlias adds a new alias
func (nsr *NamespaceResolver) AddAlias(useType string, nn ast.Vertex, prefix []ast.Vertex) {
	switch use := nn.(type) {
	case *ast.StmtUse:
		if use.Type != nil {
			useType = string(use.Type.(*ast.Identifier).Value)
		}

		useNameParts := use.Use.(*ast.Name).Parts
		var alias string
		if use.Alias == nil {
			alias = string(useNameParts[len(useNameParts)-1].(*ast.NamePart).Value)
		} else {
			alias = string(use.Alias.(*ast.Identifier).Value)
		}

		nsr.Namespace.AddAlias(useType, concatNameParts(prefix, useNameParts), alias)
	}
}

// AddNamespacedName adds namespaced name by node
func (nsr *NamespaceResolver) AddNamespacedName(nn ast.Vertex, nodeName string) {
	if nsr.Namespace.Namespace == "" {
		nsr.ResolvedNames[nn] = nodeName
	} else {
		nsr.ResolvedNames[nn] = nsr.Namespace.Namespace + "\\" + nodeName
	}
}

// ResolveName adds a resolved fully qualified name by node
func (nsr *NamespaceResolver) ResolveName(nameNode ast.Vertex, aliasType string) {
	resolved, err := nsr.Namespace.ResolveName(nameNode, aliasType)
	if err == nil {
		nsr.ResolvedNames[nameNode] = resolved
	}
}

// ResolveType adds a resolved fully qualified type name
func (nsr *NamespaceResolver) ResolveType(n ast.Vertex) {
	switch nn := n.(type) {
	case *ast.Nullable:
		nsr.ResolveType(nn.Expr)
	case *ast.Name:
		nsr.ResolveName(n, "")
	case *ast.NameRelative:
		nsr.ResolveName(n, "")
	case *ast.NameFullyQualified:
		nsr.ResolveName(n, "")
	}
}

// Namespace context
type Namespace struct {
	Namespace string
	Aliases   map[string]map[string]string
}

// NewNamespace constructor
func NewNamespace(NSName string) *Namespace {
	return &Namespace{
		Namespace: NSName,
		Aliases: map[string]map[string]string{
			"":         {},
			"const":    {},
			"function": {},
		},
	}
}

// AddAlias adds a new alias
func (ns *Namespace) AddAlias(aliasType string, aliasName string, alias string) {
	aliasType = strings.ToLower(aliasType)

	if aliasType == "const" {
		ns.Aliases[aliasType][alias] = aliasName
	} else {
		ns.Aliases[aliasType][strings.ToLower(alias)] = aliasName
	}
}

// ResolveName returns a resolved fully qualified name
func (ns *Namespace) ResolveName(nameNode ast.Vertex, aliasType string) (string, error) {
	switch n := nameNode.(type) {
	case *ast.NameFullyQualified:
		// Fully qualifid name is already resolved
		return concatNameParts(n.Parts), nil

	case *ast.NameRelative:
		if ns.Namespace == "" {
			return concatNameParts(n.Parts), nil
		}
		return ns.Namespace + "\\" + concatNameParts(n.Parts), nil

	case *ast.Name:
		if aliasType == "const" && len(n.Parts) == 1 {
			part := strings.ToLower(string(n.Parts[0].(*ast.NamePart).Value))
			if part == "true" || part == "false" || part == "null" {
				return part, nil
			}
		}

		if aliasType == "" && len(n.Parts) == 1 {
			part := strings.ToLower(string(n.Parts[0].(*ast.NamePart).Value))

			switch part {
			case "self":
				fallthrough
			case "static":
				fallthrough
			case "parent":
				fallthrough
			case "int":
				fallthrough
			case "float":
				fallthrough
			case "bool":
				fallthrough
			case "string":
				fallthrough
			case "void":
				fallthrough
			case "iterable":
				fallthrough
			case "object":
				return part, nil
			}
		}

		aliasName, err := ns.ResolveAlias(nameNode, aliasType)
		if err != nil {
			// resolve as relative name if alias not found
			if ns.Namespace == "" {
				return concatNameParts(n.Parts), nil
			}
			return ns.Namespace + "\\" + concatNameParts(n.Parts), nil
		}

		if len(n.Parts) > 1 {
			// if name qualified, replace first part by alias
			return aliasName + "\\" + concatNameParts(n.Parts[1:]), nil
		}

		return aliasName, nil
	}

	return "", errors.New("must be instance of name.Names")
}

// ResolveAlias returns alias or error if not found
func (ns *Namespace) ResolveAlias(nameNode ast.Vertex, aliasType string) (string, error) {
	aliasType = strings.ToLower(aliasType)
	nameParts := nameNode.(*ast.Name).Parts

	firstPartStr := string(nameParts[0].(*ast.NamePart).Value)

	if len(nameParts) > 1 { // resolve aliases for qualified names, always against class alias type
		firstPartStr = strings.ToLower(firstPartStr)
		aliasType = ""
	} else {
		if aliasType != "const" { // constants are case-sensitive
			firstPartStr = strings.ToLower(firstPartStr)
		}
	}

	aliasName, ok := ns.Aliases[aliasType][firstPartStr]
	if !ok {
		return "", errors.New("Not found")
	}

	return aliasName, nil
}

func concatNameParts(parts ...[]ast.Vertex) string {
	str := ""

	for _, p := range parts {
		for _, n := range p {
			if str == "" {
				str = string(n.(*ast.NamePart).Value)
			} else {
				str = str + "\\" + string(n.(*ast.NamePart).Value)
			}
		}
	}

	return str
}
