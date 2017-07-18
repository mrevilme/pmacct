#include <stdlib.h>
#include <sys/poll.h>
#include <time.h>

#if (!defined __PROMETHEUS_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif
EXT void prometheus_plugin(int, struct configuration *, void *);
EXT void prometheus_cache_purge(struct chained_cache *[], int, int);

#undef EXT

