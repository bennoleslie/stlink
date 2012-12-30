/*
 * Ugly, low performance, configurable level, logging "framework"
 */
#define UDEBUG 90
#define UINFO  50
#define UWARN  30
#define UERROR 20
#define UFATAL 10

#define DLOG(format, args...) ugly_log(UDEBUG, LOG_TAG, format, ## args)
#define ILOG(format, args...) ugly_log(UINFO, LOG_TAG, format, ## args)
#define WLOG(format, args...) ugly_log(UWARN, LOG_TAG, format, ## args)
#define ELOG(format, args...) ugly_log(UERROR, LOG_TAG, format, ## args)
#define fatal(format, args...) ugly_log(UFATAL, LOG_TAG, format, ## args)

int ugly_init(int maximum_threshold);
int ugly_log(int level, const char *tag, const char *format, ...);
