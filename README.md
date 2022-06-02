# dataflow-analyzer
Current performance:  
`2022/05/28 12:41:35 Scanned 4981 files    Found 428 vulns    In time 25.159522618s` 
  
Input is filenames or URLs of PHP files.  

Output is the PHP representation of the vertex of the assignment or sink and it's line:char position, along with the traced stack for each step in the path.  

To do:
- HTML context awareness  
- Don't traverse tree multiple times (and dont traverse dead code)  
- Scan whole repos instead of files  (this will require more WP research)
  
Example:
```
$ echo test.php | dataflow-analyzer -yaml
file: test.php
type: sqli
path:
- stack: '[sink] query <- [taint] $_GET'
  code: query($_GET[]) 6:112

file: test.php
type: sqli
path:
- stack: '[assign] $t <- [assign] $param <- [taint] $_GET'
  code: $d->dangerous($_GET) 16:201
- stack: '[assign] $temp <- [filter] unknown_filter_func <- [taint] $param'
  code: $temp = unknown_filter_func($param) 4:51
- stack: '[assign] dangerous <- [taint] $temp'
  code: return $temp; 7:130
- stack: '[assign] $t <- [taint] dangerous'
  code: $t = $d->dangerous($_GET) 16:196
- stack: '[sink] query <- [taint] $t'
  code: query($t) 17:223

2022/06/01 18:09:36 Scanned 1 files	Found 2 vulns	In time 2.557277ms
```

Help:
```
$ ./dataflow-analyzer -h
Usage of ./dataflow-analyzer:
  -d int
    	Number of times to traverse the tree (Tracing through function calls requires multiple passes) (default 10)
  -f string
    	Specify a data file of sources, sinks, and filters (default "data.yaml")
  -t int
    	Number of goroutines to use (default 100)
  -yaml
    	Output as YAML, (JSON by default)
```
