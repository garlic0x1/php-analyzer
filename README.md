# dataflow-analyzer

Usage:
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
