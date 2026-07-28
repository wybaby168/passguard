# Optional historical source

`probable-v2_top-12000.txt` is an archival subset derived from the Probable Wordlists v2 project by `berzerk0` and contributors.

- Upstream project: `https://github.com/berzerk0/Probable-Wordlists`
- License: Creative Commons Attribution-ShareAlike 4.0 International
- License copy: `Probable-Wordlists-LICENSE.txt`
- Modification in this kit: no content changes; the file is kept separate from the default generated lists
- Default status: excluded from `backend-blocklist.txt`

It adds only 121 unique NFC-normalized values to the four-source default union. To evaluate the larger 125,812-entry backend union, run:

```bash
python3 scripts/update_lists.py --input-dir data/source --ref 2026.1 --include-probable
```

Review the attribution and ShareAlike obligations before redistributing a generated union that includes this source.
