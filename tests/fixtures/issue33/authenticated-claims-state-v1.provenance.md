# Issue 33 authenticated claims journal capture

Source: `.git/maco/state/authenticated-claims-state-v1/6ce2913c16ab9fe3388b4d29719afd3b2549aa6d90975b2cf8ddc4173d0999f4/`

The six direct regular files in this live physical journal were copied on
2026-07-26 without moving, deleting, changing permissions, acquiring a lock, or
otherwise directing a write at the source state. The sorted live inventory was
recorded immediately before and after the copy:

| Name | Size (bytes) | SHA-256 before | SHA-256 after |
| --- | ---: | --- | --- |
| `.claims-snapshot.lock` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `.head-3148f5fe04ce377a2d203a52e1f8283dd70db8b328527d471eda85a6f24a74cd.tmp` | 745 | `a90a9774aef36608fd468787310ecb8ef6505f89edb861da04b92aa210936031` | `a90a9774aef36608fd468787310ecb8ef6505f89edb861da04b92aa210936031` |
| `.record-00000000000000000004-0fe05baf5b349c6df936b9789c9ea34606c3a7df2a89e798c90b52486c0a1998.tmp` | 1590 | `ac6226aade23f8f3f7c8292e2e1350651af23abbe72038c813bac1ac3863274c` | `ac6226aade23f8f3f7c8292e2e1350651af23abbe72038c813bac1ac3863274c` |
| `00000000000000000001.json` | 1164 | `55fcecff8fb014c4a6bb764af8af072630f914c78df4df2394354d1eafb165e9` | `55fcecff8fb014c4a6bb764af8af072630f914c78df4df2394354d1eafb165e9` |
| `00000000000000000002.json` | 1402 | `71971090b0ee95a8653123c494cf5880b33f3a67e5f7a13ea19b3585cd26c263` | `71971090b0ee95a8653123c494cf5880b33f3a67e5f7a13ea19b3585cd26c263` |
| `00000000000000000003.json` | 1164 | `285c231824965e08b235748d946e6e5dcad3a6250de707702b4f90832f52bcb9` | `285c231824965e08b235748d946e6e5dcad3a6250de707702b4f90832f52bcb9` |

Every fixture file also matched its source byte-for-byte after capture.
`authenticated-claims-state-v1.sha256` is the deterministic integrity manifest
for the captured bytes.

Exact-byte capture integrity is established, but the current attached pinned
binary does not establish that it wrote or authenticated these journal bytes.
The capture therefore does not establish writer provenance.
