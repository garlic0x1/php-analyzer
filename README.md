# dataflow-analyzer
Current performance:  
`2022/05/28 11:29:04 Scanned 997 files    Found 144 vulns    In time 1m33.712987818s`  

Example:
```
$ echo test.php | ./dataflow-analyzer -yaml
file: test.php
type: sqli
path:
- stack: '[sink] query <- [taint] $_GET'
  code: query($_GET[])

file: test.php
type: sqli
path:
- stack: '[sink] query <- [taint] $t'
  code: query($t)
- stack: '[assign] $t <- [taint] dangerous'
  code: $t = $d->dangerous($_GET)
- stack: '[assign] dangerous <- [taint] $temp'
  code: return $temp;
- stack: '[assign] $temp <- [filter] unknown_filter_func <- [taint] $param'
  code: $temp = unknown_filter_func($param)
- stack: '[assign] $t <- [assign] $param <- [taint] $_GET'
  code: $d->dangerous($_GET)

2022/05/28 10:21:13 Scanned 1 files
Found 2 vulns

```

Help:
```
$ ./dataflow-analyzer -h
Usage of ./dataflow-analyzer:
  -d int
    	Number of times to traverse the tree (Tracing through function calls requires multiple passes) (default 5)
  -f string
    	Specify a data file of sources, sinks, and filters (default "data.yaml")
  -t int
    	Number of goroutines to use (default 10)
  -yaml
    	Output as YAML, (JSON by default)
```
