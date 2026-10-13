## bugfix/memtx

* Fixed an iterator over a multikey or functional index returning some entries
  of the tuple it was paused on twice, or skipping them, after the index was
  modified concurrently (gh-13410).
