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
	Queue   = make(chan Task)
	Results = make(chan Result)
	sm      sync.Map
	Files   = 0
	Vulns   = 0
)

type Task struct {
	Filename string
	Vertex   ast.Vertex
}

type Result struct {
	Vertex    ast.Vertex
	Type      string
	Code      string
	Stack     string
	LastTaint Taint
	Filename  string
}

func main() {
	depth := flag.Int("d", 5, "Number of times to traverse the tree (Tracing through function calls requires multiple passes)")
	threads := flag.Int("t", 10, "Number of goroutines to use")
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

func workers(depth int, n int, datafile string) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for task := range Queue {
				a := NewAnalyzer(task.Filename, datafile)
				t := NewTraverser(a)
				for j := 0; j < depth; j++ {
					t.Traverse(task.Vertex)
				}
			}
		}()
	}
	wg.Wait()
	close(Results)
}

func reader() {
	defer func() {
		if err := recover(); err != nil {
			log.Println("recovering", err)
			reader()
		}
	}()
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		filename := s.Text()

		content, err := readFile(filename)
		if err != nil {
			log.Println(err)
			continue
		}

		root, err := parseutil.ParseFile(content)
		if err != nil {
			log.Println(err)
			continue
		}

		Files++

		Queue <- Task{Filename: filename, Vertex: root}
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
		taint := result.LastTaint

		o := bytes.NewBufferString("")
		//f := formatter.NewFormatter().WithState(formatter.FormatterStatePHP)
		//result.Vertex.Accept(f)
		p := printer.NewPrinter(o).WithState(printer.PrinterStatePHP)
		result.Vertex.Accept(p)
		code := strings.TrimSpace(o.String())

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
			taintstring := strings.TrimSpace(o.String())
			taintPath = append(taintPath, tt{Code: taintstring, Stack: taint.Stack})

			taint = *taint.Parent
		}

		var (
			bytes []byte
			err   error
		)

		if !(fyaml) {
			bytes, err = json.Marshal(output{
				File: result.Filename,
				Type: result.Type,
				Path: taintPath,
			})
			if err != nil {
				log.Println(err)
			}
		} else {
			bytes, err = yaml.Marshal(output{
				File: result.Filename,
				Type: result.Type,
				Path: taintPath,
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
