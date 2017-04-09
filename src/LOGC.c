#include "LOGC.h"

/*
 * iLOG3Lite - log function library written in c
 * author	: calvin
 * email	: calvinwilliams.c@gmail.com
 * LastVersion	: v1.0.9
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

/* ����� */
#define OFFSET_BUFPTR(_buffer_,_bufptr_,_len_,_buflen_,_remain_len_) \
	if( _len_ > 0 && _buflen_+_len_ <= sizeof(_buffer_)-1 && _bufptr_[0] ) \
	{ \
		_bufptr_ += _len_ ; \
		_buflen_ += _len_ ; \
		_remain_len_ -= _len_ ; \
	} \

#define OFFSET_BUFPTR_IN_LOOP(_buffer_,_bufptr_,_len_,_buflen_,_remain_len_) \
	if( _len_ > 0 && _buflen_+_len_ <= sizeof(_buffer_)-1 && _bufptr_[0] ) \
	{ \
		_bufptr_ += _len_ ; \
		_buflen_ += _len_ ; \
		_remain_len_ -= _len_ ; \
	} \
	else \
	{ \
		break; \
	} \

/* ��־�ļ��� */
TLS char	g_log_pathfilename[ MAXLEN_FILENAME + 1 ] = "" ;
TLS int		g_log_level = LOGLEVEL_INFO ;

const char log_level_itoa[][6] = { "DEBUG" , "INFO" , "WARN" , "ERROR" , "FATAL" } ;

/* ������־�ļ��� */
void SetLogFile( char *format , ... )
{
	va_list		valist ;
	
	va_start( valist , format );
	VSNPRINTF( g_log_pathfilename , sizeof(g_log_pathfilename)-1 , format , valist );
	va_end( valist );
	
	return;
}

void SetLogFileV( char *format , va_list valist )
{
	VSNPRINTF( g_log_pathfilename , sizeof(g_log_pathfilename)-1 , format , valist );
	
	return;
}

/* ������־�ȼ� */
void SetLogLevel( int log_level )
{
	g_log_level = log_level ;
	
	return;
}

/* �����־ */
static int WriteLogBase( int log_level , char *c_filename , long c_fileline , char *format , va_list valist )
{
	char		c_filename_copy[ MAXLEN_FILENAME + 1 ] ;
	char		*p_c_filename = NULL ;
	
	struct timeval	tv ;
	struct tm	stime ;
	
	char		log_buffer[ 1024 + 1 ] ;
	char		*log_bufptr = NULL ;
	size_t		log_buflen ;
	size_t		log_buf_remain_len ;
	size_t		len ;
	
	/* ����Դ�����ļ��� */
	memset( c_filename_copy , 0x00 , sizeof(c_filename_copy) );
	strncpy( c_filename_copy , c_filename , sizeof(c_filename_copy)-1 );
	p_c_filename = strrchr( c_filename_copy , '\\' ) ;
	if( p_c_filename )
		p_c_filename++;
	else
		p_c_filename = c_filename_copy ;

	/* �������־ */
#if ( defined __linux__ ) || ( defined __unix ) || ( defined _AIX )
	gettimeofday( & tv , NULL );
	localtime_r( &(tv.tv_sec) , & stime );
#elif ( defined _WIN32 )
	{
	SYSTEMTIME	stNow ;
	GetLocalTime( & stNow );
	tv.tv_usec = stNow.wMilliseconds * 1000 ;
	stime.tm_year = stNow.wYear - 1900 ;
	stime.tm_mon = stNow.wMonth - 1 ;
	stime.tm_mday = stNow.wDay ;
	stime.tm_hour = stNow.wHour ;
	stime.tm_min = stNow.wMinute ;
	stime.tm_sec = stNow.wSecond ;
	}
#endif

	memset( log_buffer , 0x00 , sizeof(log_buffer) );
	log_bufptr = log_buffer ;
	log_buflen = 0 ;
	log_buf_remain_len = sizeof(log_buffer) - 1 ;
	
	len = strftime( log_bufptr , log_buf_remain_len , "%Y-%m-%d %H:%M:%S" , & stime ) ;
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	len = SNPRINTF( log_bufptr , log_buf_remain_len , ".%06ld" , (long)(tv.tv_usec) ) ;
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	len = SNPRINTF( log_bufptr , log_buf_remain_len , " | %-5s" , log_level_itoa[log_level] ) ;
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	len = SNPRINTF( log_bufptr , log_buf_remain_len , " | %lu:%lu:%s:%ld | " , PROCESSID , THREADID , p_c_filename , c_fileline ) ;
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	len = VSNPRINTF( log_bufptr , log_buf_remain_len , format , valist );
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	len = SNPRINTF( log_bufptr , log_buf_remain_len , NEWLINE ) ;
	OFFSET_BUFPTR( log_buffer , log_bufptr , len , log_buflen , log_buf_remain_len );
	
	/* �������־ */
	if( g_log_pathfilename[0] == '\0' )
	{
		WRITE( 1 , log_buffer , log_buflen );
	}
	else
	{
		int		fd ;
		
#if ( defined __linux__ ) || ( defined __unix ) || ( defined _AIX )
		fd = OPEN( g_log_pathfilename , O_CREAT | O_WRONLY | O_APPEND , S_IRWXU | S_IRWXG | S_IRWXO ) ;
#elif ( defined _WIN32 )
		fd = OPEN( g_log_pathfilename , _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY , _S_IREAD | _S_IWRITE ) ;
#endif
		if( fd == -1 )
			return -1;
		
		WRITE( fd , log_buffer , log_buflen );
		
		CLOSE( fd );
	}
	
	return 0;
}

int WriteLog( int log_level , char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( log_level < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( log_level , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

int FatalLog( char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_FATAL < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( LOGLEVEL_FATAL , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

int ErrorLog( char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_ERROR < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( LOGLEVEL_ERROR , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

int WarnLog( char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_WARN < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( LOGLEVEL_WARN , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

int InfoLog( char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_INFO < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( LOGLEVEL_INFO , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

int DebugLog( char *c_filename , long c_fileline , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_DEBUG < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteLogBase( LOGLEVEL_DEBUG , c_filename , c_fileline , format , valist );
	va_end( valist );
	
	return 0;
}

static int WriteHexLogBase( int log_level , char *c_filename , long c_fileline , char *buf , long buflen , char *format , va_list valist )
{
	char		hexlog_buffer[ 4096 * 10 + 1 ] ;
	char		*hexlog_bufptr = NULL ;
	size_t		hexlog_buflen ;
	size_t		hexlog_buf_remain_len ;
	size_t		len ;
	
	int		row_offset , col_offset ;
	
	if( buf == NULL && buflen <= 0 )
		return 0;
	if( buflen > sizeof(hexlog_buffer) - 1 )
		return -1;
	
	/* �������־ */
	WriteLogBase( log_level , c_filename , c_fileline , format , valist );
	
	/* ���ʮ�����ƿ���־ */
	memset( hexlog_buffer , 0x00 , sizeof(hexlog_buffer) );
	hexlog_bufptr = hexlog_buffer ;
	hexlog_buflen = 0 ;
	hexlog_buf_remain_len = sizeof(hexlog_buffer) - 1 ;
	
	len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF" ) ;
	OFFSET_BUFPTR( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
	len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , NEWLINE ) ;
	OFFSET_BUFPTR( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
	
	row_offset = 0 ;
	col_offset = 0 ;
	while( hexlog_buf_remain_len > 0 )
	{
		len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "0x%08X   " , row_offset * 16 ) ;
		OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
		for( col_offset = 0 ; col_offset < 16 ; col_offset++ )
		{
			if( row_offset * 16 + col_offset < buflen )
			{
				len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "%02X " , *((unsigned char *)buf+row_offset*16+col_offset)) ;
				OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
			}
			else
			{
				len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "   " ) ;
				OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
			}
		}
		len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "  " ) ;
		OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
		for( col_offset = 0 ; col_offset < 16 ; col_offset++ )
		{
			if( row_offset * 16 + col_offset < buflen )
			{
				if( isprint( (int)*(buf+row_offset*16+col_offset) ) )
				{
					len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "%c" , *((unsigned char *)buf+row_offset*16+col_offset) ) ;
					OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
				}
				else
				{
					len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , "." ) ;
					OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
				}
			}
			else
			{
				len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , " " ) ;
				OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
			}
		}
		len = SNPRINTF( hexlog_bufptr , hexlog_buf_remain_len , NEWLINE ) ;
		OFFSET_BUFPTR_IN_LOOP( hexlog_buffer , hexlog_bufptr , len , hexlog_buflen , hexlog_buf_remain_len );
		if( row_offset * 16 + col_offset >= buflen )
			break;
		row_offset++;
	}
	
	if( STRNCMP( hexlog_bufptr-(sizeof(NEWLINE)-1) , != , NEWLINE , sizeof(NEWLINE)-1 ) )
	{
		memcpy( hexlog_bufptr-(sizeof(NEWLINE)-1) , NEWLINE , sizeof(NEWLINE)-1 );
	}
	
	/* ���ʮ�����ƿ���־ */
	if( g_log_pathfilename[0] == '\0' )
	{
		WRITE( 1 , hexlog_buffer , hexlog_buflen );
	}
	else
	{
		int		fd ;
		
#if ( defined __linux__ ) || ( defined __unix ) || ( defined _AIX )
		fd = OPEN( g_log_pathfilename , O_CREAT | O_WRONLY | O_APPEND , S_IRWXU | S_IRWXG | S_IRWXO ) ;
#elif ( defined _WIN32 )
		fd = OPEN( g_log_pathfilename , _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY , _S_IREAD | _S_IWRITE ) ;
#endif
		if( fd == -1 )
			return -1;
		
		WRITE( fd , hexlog_buffer , hexlog_buflen );
		
		CLOSE( fd );
	}
	
	return 0;
}

int WriteHexLog( int log_level , char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( log_level < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( log_level , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

int FatalHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_FATAL < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( LOGLEVEL_FATAL , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

int ErrorHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_ERROR < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( LOGLEVEL_ERROR , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

int WarnHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_WARN < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( LOGLEVEL_WARN , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

int InfoHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_INFO < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( LOGLEVEL_INFO , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

int DebugHexLog( char *c_filename , long c_fileline , char *buf , long buflen , char *format , ... )
{
	va_list		valist ;
	
	if( LOGLEVEL_DEBUG < g_log_level )
		return 0;
	
	va_start( valist , format );
	WriteHexLogBase( LOGLEVEL_DEBUG , c_filename , c_fileline , buf , buflen , format , valist );
	va_end( valist );
	
	return 0;
}

