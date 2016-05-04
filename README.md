NSS Root Store Tools
====================

The NSS root store is provided in a rather inconvienient format in the NSS repo.
This repo has some tools for rendering it to JSON and extracting some
information from it.

```
cp $NSS_ROOT/lib/ckfw/builtins/certdata.txt .
python certdata_to_json.py <certdata.txt >certdata.json
go run root-props.go
```
