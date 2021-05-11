## core/bugfix

 * Fix error, related to the fact, that if user change listen address,
   all iproto threads closed same socket multiple times.
   Fix error, related to the fact, that tarantool did not delete the unix
   socket path, when it's finishing work.