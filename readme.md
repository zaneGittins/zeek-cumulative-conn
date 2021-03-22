# Zeek Cumulative Connection Duration

Gets cumulative connection duration from Zeek logs. Something similar can be done with the following command:

```bash
zcat conn.*.log.gz | zeek-cut id.orig_h id.resp_h duration | sort | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
```

However, I decided to create this small program, as I found it difficult to filter out RFC1918 addresses from the id.resp_h in the above command.