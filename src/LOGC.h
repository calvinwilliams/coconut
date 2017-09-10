#ifndef _H_LOGC_
#define _H_LOGC_

/*
 * iLOG3Lite - log function library written in c
 * author	: calvin
 * email	: calvinwilliams@163.com
 * LastVersion	: v1.0.10
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#if ( defined _WIN32 )
#include <windows.h>
#include <share.h>
#include <io.h>
#include <fcntl.h>
#elif ( defined __unix ) || ( defined _AIX ) || ( defined __linux__ ) || ( defined __hpux )
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ������ */
#ifndef MAXLEN_FILENAME
#define MAXLEN_FILENAME			256
#endif

#ifndef STRCMP
#define STRCMP(_a_,_C_,_b_) ( strcmp(_a_,_b_) _C_ 0 )
#define STRNCMP(_a_,_C_,_b_,_n_) ( strncmp(_a_,_b_,_n_) _C_ 0 )
#endif

#ifndef MEMCMP
#define MEMCMP(_a_,_C_,_b_,_n_) ( memcmp(_a_,_b_,_n_) _C_ 0 )
#endif

/* ��ƽ̨�� */
#if ( defined __linux__ ) || ( defined __unix ) || ( defined _AIX )
#define TLS		__thread
#define VSNPRINTF	vsnprintf
#define SNPRINTF	snprintf
#define OPEN		open
#define READ		read
#define WRITE		write
#define CLOSE		close
#define PROCESSID	(unsigned long)getpid()
#define THREADID	(unsigned long)pthread_self()
#define NEWLINE		"\n"
#elif ( defined _WIN32 )
#define TLS		__declspec( thread )
#define VSNPRINTF	_vsnprintf
#define SNPRINTF	_snprintf
#define OPEN		_open
#define READ		_read
#define WRITE		_write
#define CLOSE		_close
#define PROCESSID	(unsigned long)GetCurrentProcessId()
#define THREADID	(unsigned long)GetCurrentThreadId()
#define NEWLINE		"\r\n"
#endif

/* ����־���� */
#ifndef LOGLEVEL_DEBUG
#define LOGLEVEL_DEBUG		1
#define LOGLEVEL_INFO		2
#define LOGLEVEL_WARN		3
#define LOGLEVEL_ERROR		4
#define LOGLEVEL_FATAL		5
#endif

void SetLogFile( char *format , ... );
void SetLogFileV( char *format , va_list valist );
void SetLogLevel( int log_level );

#if ( defined __STDC_VERSION__ ) && ( __STDC_VERSION__ >= 199901 )

extern TLS int		g_log_level ;

int WriteLogBaseV( int log_level , char *c_filename , long c_fileline , char *format , va_list valist );
int WriteLogBase( int log_level , char *c_filename , long c_fileline , char *format , ... );

#define WriteLog(_log_level_,_c_filename_,_c_fileline_,...) \
	if( (_log_level_) >= g_log_level ) \
		WriteLogBase( _log_level_ , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

#define FatalLog(_c_filename_,_c_fileline_,...) \
	if( LOGLEVEL_FATAL >= g_log_level ) \
		WriteLogBase( LOGLEVEL_FATAL , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

#define ErrorLog(_c_filename_,_c_fileline_,...) \
	if( LOGLEVEL_ERROR >= g_log_level ) \
		WriteLogBase( LOGLEVEL_ERROR , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

#define WarnLog(_c_filename_,_c_fileline_,...) \
	if( LOGLEVEL_WARN >= g_log_level ) \
		WriteLogBase( LOGLEVEL_WARN , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

#define InfoLog(_c_filename_,_c_fileline_,...) \
	if( LOGLEVEL_INFO >= g_log_level ) \
		WriteLogBase( LOGLEVEL_INFO , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

#define DebugLog(_c_filename_,_c_fileline_,...) \
	if( LOGLEVEL_DEBUG >= g_log_level ) \
		WriteLogBase( LOGLEVEL_DEBUG , _c_filename_ , _c_fileline_ , __VA_ARGS__ );

int WriteHexLogBaseV( int log_level , char *c_filename , long c_fileline , char *buf , long buflen , char *format , va_list valist );
int WriteHexLogBase( int log_level , char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );

#define WriteHexLog(_log_level_,_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( (_log_level_) >= g_log_level ) \
		WriteHexLogBase( _log_level_ , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#define FatalHexLog(_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( LOGLEVEL_FATAL >= g_log_level ) \
		WriteHexLogBase( LOGLEVEL_FATAL , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#define ErrorHexLog(_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( LOGLEVEL_ERROR >= g_log_level ) \
		WriteHexLogBase( LOGLEVEL_ERROR , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#define WarnHexLog(_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( LOGLEVEL_WARN >= g_log_level ) \
		WriteHexLogBase( LOGLEVEL_WARN , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#define InfoHexLog(_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( LOGLEVEL_INFO >= g_log_level ) \
		WriteHexLogBase( LOGLEVEL_INFO , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#define DebugHexLog(_c_filename_,_c_fileline_,_buf_,_buflen_,...) \
	if( LOGLEVEL_DEBUG >= g_log_level ) \
		WriteHexLogBase( LOGLEVEL_DEBUG , _c_filename_ , _c_fileline_ , _buf_ , _buflen_ , __VA_ARGS__ );

#else

int WriteLog( int log_level , char *c_filename , long c_fileline , char *format , ... );
int FatalLog( char *c_filename , long c_fileline , char *format , ... );
int ErrorLog( char *c_filename , long c_fileline , char *format , ... );
int WarnLog( char *c_filename , long c_fileline , char *format , ... );
int InfoLog( char *c_filename , long c_fileline , char *format , ... );
int DebugLog( char *c_filename , long c_fileline , char *format , ... );

int WriteHexLog( int log_level , char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );
int FatalHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );
int ErrorHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );
int WarnHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );
int InfoHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );
int DebugHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... );

#endif

#if ( defined __STDC_VERSION__ ) && ( __STDC_VERSION__ >= 199901 )

#define WRITELOG(_log_level_,...)	WriteLog( _log_level_ , __FILE__ , __LINE__ , __VA_ARGS__ );
#define FATALLOG(...)			FatalLog( __FILE__ , __LINE__ , __VA_ARGS__ );
#define ERRORLOG(...)			ErrorLog( __FILE__ , __LINE__ , __VA_ARGS__ );
#define WARNLOG(...)			WarnLog( __FILE__ , __LINE__ , __VA_ARGS__ );
#define INFOLOG(...)			InfoLog( __FILE__ , __LINE__ , __VA_ARGS__ );
#define DEBUGLOG(...)			DebugLog( __FILE__ , __LINE__ , __VA_ARGS__ );

#define WRITEHEXLOG(_log_level_,_buf_,_buflen_,...)	WriteHexLog( _log_level_ , __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );
#define FATALHEXLOG(_buf_,_buflen_,...)	FatalHexLog( __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );
#define ERRORHEXLOG(_buf_,_buflen_,...)	ErrorHexLog( __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );
#define WARNHEXLOG(_buf_,_buflen_,...)	WarnHexLog( __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );
#define INFOHEXLOG(_buf_,_buflen_,...)	InfoHexLog( __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );
#define DEBUGHEXLOG(_buf_,_buflen_,...)	DebugHexLog( __FILE__ , __LINE__ , buf , buflen , __VA_ARGS__ );

#endif

#define set_log_file		SetLogFile
#define set_log_level		SetLogLevel

#define write_log		WriteLog
#define fatal_log		FatalLog
#define error_log		ErrorLog
#define warn_log		WarnLog
#define info_log		InfoLog
#define debug_log		DebugLog

#define write_hex_log		WriteHexLog
#define fatal_hex_log		FatalHexLog
#define error_hex_log		ErrorHexLog
#define warn_hex_log		WarnHexLog
#define info_hex_log		InfoHexLog
#define debug_hex_log		DebugHexLog

#ifdef __cplusplus
}
#endif

#endif

