package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VKCOM/noverify/src/php/parseutil"
	"github.com/VKCOM/php-parser/pkg/ast"
	"github.com/VKCOM/php-parser/pkg/visitor/printer"
	"gopkg.in/yaml.v2"
)

var (
	Queue   = make(chan string)
	Results = make(chan Result)
	sm      sync.Map
	Files   = 0
	Vulns   = 0
)

type Result struct {
	Vertex    ast.Vertex
	Type      string
	Code      string
	Stack     string
	LastTaint Taint
	Filename  string
}

func main() {
	depth := flag.Int("d", 10, "Number of times to traverse the tree (Tracing through function calls requires multiple passes)")
	threads := flag.Int("t", 100, "Number of goroutines to use")
	datafile := flag.String("f", "data.yaml", "Specify a data file of sources, sinks, and filters")
	fyaml := flag.Bool("yaml", false, "Output as YAML, (JSON by default)")
	flag.Parse()

	t := time.Now()

	defer func() {
		log.Printf("Scanned %d files\tFound %d vulns\tIn time %v", Files, Vulns, time.Since(t))
	}()

	go reader()
	go workers(*depth, *threads, *datafile)
	writer(*fyaml)

}

func worker(depth int, datafile string) {

	// recover from parseutil.ParseFie() panic on bad syntax

	for filename := range Queue {
		defer func() {
			if err := recover(); err != nil {
				log.Println("RECOVERING:", err, "\tFILE:", filename)
				worker(depth, datafile)
			}
		}()
		// read the file
		content, err := readFile(filename)
		if err != nil {
			log.Println(err)
			continue
		}

		// convert PHP to AST
		root, err := parseutil.ParseFile(content)
		if err != nil {
			log.Println(err, filename)
			continue
		}

		Files++

		// create visitor
		a := NewAnalyzer(filename, datafile)
		t := NewTraverser(a)
		for j := 0; j < depth; j++ {
			t.Traverse(root)
		}
	}
}

func workers(depth int, n int, datafile string) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			worker(depth, datafile)
		}()
	}
	wg.Wait()
	close(Results)
}

func reader() {
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		filename := s.Text()

		Queue <- filename
	}
	close(Queue)
}

func writer(fyaml bool) {
	for result := range Results {
		defer func() {
			if err := recover(); err != nil {
				writer(fyaml)
			}
		}()

		type tt struct {
			Stack string
			Code  string
		}
		var taintPath []tt
		var reversed []tt
		taint := result.LastTaint

		o := bytes.NewBufferString("")
		//f := formatter.NewFormatter().WithState(formatter.FormatterStatePHP)
		//result.Vertex.Accept(f)
		p := printer.NewPrinter(o).WithState(printer.PrinterStatePHP)
		result.Vertex.Accept(p)
		code := fmt.Sprintf("%s %d:%d", strings.TrimSpace(o.String()), result.Vertex.GetPosition().StartLine, result.Vertex.GetPosition().StartPos)

		type output struct {
			File string
			Type string
			Path []tt
		}

		taintPath = append(taintPath, tt{Code: code, Stack: result.Stack})
		for taint.Vertex != nil {
			o := bytes.NewBufferString("")
			//d := dumper.NewDumper(o)
			p := printer.NewPrinter(o).WithState(printer.PrinterStatePHP)
			//result.Vertex.Accept(f)
			taint.Vertex.Accept(p)
			taintstring := fmt.Sprintf("%s %d:%d", strings.TrimSpace(o.String()), taint.Vertex.GetPosition().StartLine, taint.Vertex.GetPosition().StartPos)
			taintPath = append(taintPath, tt{Code: taintstring, Stack: taint.Stack})

			taint = *taint.Parent
		}

		for i := len(taintPath) - 1; i >= 0; i-- {
			reversed = append(reversed, taintPath[i])
		}

		var (
			bytes []byte
			err   error
		)

		if !(fyaml) {
			bytes, err = json.Marshal(output{
				File: result.Filename,
				Type: result.Type,
				Path: reversed,
			})
			if err != nil {
				log.Println(err)
			}
		} else {
			bytes, err = yaml.Marshal(output{
				File: result.Filename,
				Type: result.Type,
				Path: reversed,
			})
			if err != nil {
				log.Println(err)
			}
		}

		if isUnique(code) {
			Vulns++
			fmt.Println(string(bytes))
		}
	}
}

func readFile(filename string) ([]byte, error) {
	if strings.HasPrefix(filename, "http://") || strings.HasPrefix(filename, "https://") {
		return download(filename)
	} else {
		return ioutil.ReadFile(filename)
	}
}

func isUnique(url string) bool {
	_, present := sm.Load(url)
	if present {
		return false
	}
	sm.Store(url, true)
	return true
}

func download(u string) ([]byte, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
