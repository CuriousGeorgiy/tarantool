#feature/replication

 * Introduce `box.info.replication[n].downstream.lag` to monitor state
   of replication which is especially important for synchronous spaces
   where malfunctioning replicas may prevent quorum from gathering votes
   to commit a transaction.
