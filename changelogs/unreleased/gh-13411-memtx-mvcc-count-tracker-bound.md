## bugfix/memtx

* Fixed a use-after-free in the memtx transaction manager: a transaction that
  selected with an offset and reached an uncommitted replacement of a tuple by
  another transaction, which was rolled back later, made a following write to
  the space access freed memory (gh-13411).
