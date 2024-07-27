## feature/replication

* Added a compat option `box_cfg_replication_synchro_timeout` to control
  whether `replication_synchro_timeout` is accessible from `box.cfg`. It's
  `old` by default, meaning the option is available and has the same default
  value as before (5 seconds).
* A new `replication_synchro_queue_max_size` option puts a limit on the number
  of transactions in the master synchronous queue.
  `replication_synchro_queue_max_size` is measured in the number of bytes to be
  written (0 means unlimited, which was the default behavior before). Currently
  this option defaults to 16 megabytes.
  (gh-7486)
