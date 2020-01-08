```bash
$ lbx genesis-create [--sign privkey.pem] candies.yaml
```

```bash
$ lbx cv-commit [-e --entropy entropy] [-t --tx TXFILE] [-m --msg MSGFILE]* <TX_OUTFILE> <CV_OUTFILE>
```

```bash
$ lbx cv-verify [-e --entropy entropy] [-t --tx TXFILE] [-m --msg MSGFILE]* [CV_FILE]
```


```bash
$ lbx rgb-transcode [-f --from-format yaml|json|rgb] [-t --to-format] [-i INFILE] [-o OUTFILE]
```

Old stuff:
```bash
$ lbx genesis-state --schema asset_schema.yaml --sign key.pem -i pls.yaml
$ lbx transition --schema asset_schema.yaml --history data.dat
```
