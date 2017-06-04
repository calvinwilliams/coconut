#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define __USE_GNU
#include <sched.h>

#include "LOGC.h"
#include "fasterhttp.h"
#include "tcpdaemon.h"

/* �����ṩ��ȡ���к�URI */
#define URI_FETCH		"/fetch"
/* �����ṩ�������к�URI */
#define URI_EXPLAIN__SEQUENCE	"/explain?sequence="

/* ��ʮ�Ľ�λ���ַ��� */
static char sg_64_scale_system_charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_" ;

/* ͨѶ������Ϣ�ṹ */
struct NetAddress
{
	char			ip[ 20 + 1 ] ;
	int			port ;
	SOCKET			sock ;
	struct sockaddr_in	addr ;
} ;

/* �ͻ������ӻỰ�ṹ */
struct AcceptedSession
{
	struct NetAddress	netaddr ;
	struct HttpEnv		*http ;
} ;

/* �����ڴ���Ϣ�ṹ */
struct ShareMemory
{
	int			proj_id ; /* ���ڼ��㹲���ڴ�key��ftok���� */
	key_t			shmkey ; /* �����ڴ�key */
	int			shmid ; /* �����ڴ�sequence_buffer */
	void			*base ; /* �����ڴ����ӻ���ַ */
	int			size ; /* �����ڴ��С */
} ;

/* ����˻����ṹ */
struct CoconutServerEnvironment
{
	uint64_t			reserve ;
	uint64_t			server_no ;
	int				listen_port ;
	int				processor_count ;
	int				log_level ;
	int				cpu_affinity ;
	
	struct ShareMemory		serial_space_shm ;
	uint64_t			*p_serial_no ;
	
	char				sequence_buffer[ 16 + 1 ] ;
	char				explain_buffer[ 128 + 1 ] ;
} ;

/* ��NetAddress�����á��õ�IP��PORT�� */
#define SETNETADDRESS(_netaddr_) \
	memset( & ((_netaddr_).addr) , 0x00 , sizeof(struct sockaddr_in) ); \
	(_netaddr_).addr.sin_family = AF_INET ; \
	if( (_netaddr_).ip[0] == '\0' ) \
		(_netaddr_).addr.sin_addr.s_addr = INADDR_ANY ; \
	else \
		(_netaddr_).addr.sin_addr.s_addr = inet_addr((_netaddr_).ip) ; \
	(_netaddr_).addr.sin_port = htons( (unsigned short)((_netaddr_).port) );

#define GETNETADDRESS(_netaddr_) \
	strcpy( (_netaddr_).ip , inet_ntoa((_netaddr_).addr.sin_addr) ); \
	(_netaddr_).port = (int)ntohs( (_netaddr_).addr.sin_port ) ;

/* ת����־�ȼ�ֵ */
static int ConvertLogLevel( char *log_level_desc )
{
	if( strcmp( log_level_desc , "DEBUG" ) == 0 )
		return LOGLEVEL_DEBUG ;
	else if( strcmp( log_level_desc , "INFO" ) == 0 )
		return LOGLEVEL_INFO ;
	else if( strcmp( log_level_desc , "WARN" ) == 0 )
		return LOGLEVEL_WARN ;
	else if( strcmp( log_level_desc , "ERROR" ) == 0 )
		return LOGLEVEL_ERROR ;
	else if( strcmp( log_level_desc , "FATAL" ) == 0 )
		return LOGLEVEL_FATAL ;
	else
		return -1;
}

/* ��CPU��Ե�� */
int BindCpuAffinity( int processor_no )
{
	cpu_set_t	cpu_mask ;
	
	int		nret = 0 ;
	
	CPU_ZERO( & cpu_mask );
	CPU_SET( processor_no , & cpu_mask );
	nret = sched_setaffinity( 0 , sizeof(cpu_mask) , & cpu_mask ) ;
	return nret;
}

/* ��ʼ�����к�ǰ��� */
static void InitSequence( struct CoconutServerEnvironment *p_env )
{
	uint64_t	index_region ;
	uint64_t	reserve_region_length = 1 ;
	uint64_t	server_no_region_length = 2 ;
	uint64_t	secondstamp_region_length = 6 ;
	uint64_t	serial_no_region_length = 5 ;
	
	/*
	��һ�� ����Ŀ¼ 2����ʮ�Ľ����ַ� ��12��������λ
			��һ��3��������λ��ʾ��������ʮ�Ľ����ַ�����
			�ڶ���3��������λ��ʾ�������������ʮ�Ľ����ַ�����
			������3��������λ��ʾ�������ʮ�Ľ����ַ�����
			���Ķ�3��������λ��ʾ�������ʮ�Ľ����ַ�����
	�ڶ��� ������ 1����ʮ�Ľ����ַ� ��6��������λ����
	������ ����������� 2����ʮ�Ľ����ַ� �ɱ�ʾ4096̨������������
	������ ����� 6����ʮ�Ľ����ַ� �ɱ�ʾ2179������
	������ ����� 5����ʮ�Ľ����ַ� �������[1,10��]
			��16����ʮ�Ľ����ַ�
	*/
	
	/* ����Ŀ¼ */
	index_region = (reserve_region_length<<9) + (server_no_region_length<<6) + (secondstamp_region_length<<3) + (serial_no_region_length) ;
	p_env->sequence_buffer[0] = sg_64_scale_system_charset[(index_region>>6)&0x3F] ;
	p_env->sequence_buffer[1] = sg_64_scale_system_charset[index_region&0x3F] ;
	
	/* ������ */
	p_env->sequence_buffer[2] = sg_64_scale_system_charset[p_env->reserve&0x3F] ;
	
	/* ����������� */
	p_env->sequence_buffer[3] = sg_64_scale_system_charset[(p_env->server_no>>6)&0x3F] ;
	p_env->sequence_buffer[4] = sg_64_scale_system_charset[p_env->server_no&0x3F] ;
	
	return;
}
		
/* ��ȡ���к� */
static void FetchSequence( struct CoconutServerEnvironment *p_env )
{
	uint64_t	secondstamp ;
	uint64_t	ret_serial_no ;
	// static uint64_t	ret_serial_no = 0 ;
	
	/* ����� */
	secondstamp = time( NULL );
	p_env->sequence_buffer[5] = sg_64_scale_system_charset[(secondstamp>>30)&0x3F] ;
	p_env->sequence_buffer[6] = sg_64_scale_system_charset[(secondstamp>>24)&0x3F] ;
	p_env->sequence_buffer[7] = sg_64_scale_system_charset[(secondstamp>>18)&0x3F] ;
	p_env->sequence_buffer[8] = sg_64_scale_system_charset[(secondstamp>>12)&0x3F] ;
	p_env->sequence_buffer[9] = sg_64_scale_system_charset[(secondstamp>>6)&0x3F] ;
	p_env->sequence_buffer[10] = sg_64_scale_system_charset[secondstamp&0x3F] ;
	
	/* ����� */
	ret_serial_no = __sync_fetch_and_add( p_env->p_serial_no , 1 ) ; /* �������һ */
	// ret_serial_no++;
	p_env->sequence_buffer[11] = sg_64_scale_system_charset[(ret_serial_no>>24)&0x3F] ;
	p_env->sequence_buffer[12] = sg_64_scale_system_charset[(ret_serial_no>>18)&0x3F] ;
	p_env->sequence_buffer[13] = sg_64_scale_system_charset[(ret_serial_no>>12)&0x3F] ;
	p_env->sequence_buffer[14] = sg_64_scale_system_charset[(ret_serial_no>>6)&0x3F] ;
	p_env->sequence_buffer[15] = sg_64_scale_system_charset[ret_serial_no&0x3F] ;
	
	return;
}

/* ��ȡ���к� */
static int ExplainSequence( struct CoconutServerEnvironment *p_env , char *sequence )
{
	char		*pos = NULL ;
	int		i ;
	uint64_t	index_region ;
	uint64_t	reserve_region_length ;
	uint64_t	server_no_region_length ;
	uint64_t	secondstamp_region_length ;
	uint64_t	serial_no_region_length ;
	
	uint64_t	reserve ;
	uint64_t	server_no ;
	time_t		secondstamp ;
	struct tm	stime ;
	uint64_t	serial_no ;
	
	index_region = 0 ;
	for( i = 0 ; i < 2 ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		index_region = (index_region<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	serial_no_region_length = (index_region&0x7) ; index_region >>= 3 ;
	secondstamp_region_length = (index_region&0x7) ; index_region >>= 3 ;
	server_no_region_length = (index_region&0x7) ; index_region >>= 3 ;
	reserve_region_length = (index_region&0x7) ; index_region >>= 3 ;
	
	reserve = 0 ;
	for( i = 0 ; i < reserve_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		reserve = (reserve<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	server_no = 0 ;
	for( i = 0 ; i < server_no_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		server_no = (server_no<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	secondstamp = 0 ;
	for( i = 0 ; i < secondstamp_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		secondstamp = (secondstamp<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	serial_no = 0 ;
	for( i = 0 ; i < serial_no_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		serial_no = (serial_no<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	memset( p_env->explain_buffer , 0x00 , sizeof(p_env->explain_buffer) );
	localtime_r( & secondstamp , & stime );
	snprintf( p_env->explain_buffer , sizeof(p_env->explain_buffer)-1 , "reserve: %"PRIu64"  server_no: %"PRIu64"  secondstamp: %ld (%04d-%02d-%02d %02d:%02d:%02d)  serial_no: %"PRIu64"\n"
		, reserve , server_no , (long)secondstamp
		, stime.tm_year+1900 , stime.tm_mon+1 , stime.tm_mday , stime.tm_hour , stime.tm_min , stime.tm_sec
		, serial_no );
	
	return HTTP_OK;
}

/* Ӧ�ò㴦�� */
static int DispatchProcess( struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	char			*uri = NULL ;
	int			uri_len ;
	
	int			nret = 0 ;
	
	/* �õ�URI */
	uri = GetHttpHeaderPtr_URI( p_accepted_session->http , & uri_len ) ;
	InfoLog( __FILE__ , __LINE__ , "uri[%.*s]" , uri_len , uri );
	
	/* ��ȡ���к� */
	if( uri_len == sizeof(URI_FETCH)-1 && MEMCMP( uri , == , URI_FETCH , uri_len ) )
	{
		FetchSequence( p_env );
		
		nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
			, "Content-length: %d" HTTP_RETURN_NEWLINE
			HTTP_RETURN_NEWLINE
			"%s\n" HTTP_RETURN_NEWLINE
			, sizeof(p_env->sequence_buffer)
			, p_env->sequence_buffer ) ;
		if( nret )
		{
			ErrorLog( __FILE__ , __LINE__ , "FormatHttpResponseStartLine failed[%d]" , nret );
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	/* ��ȡ���к� */
	else if( MEMCMP( uri , == , URI_EXPLAIN__SEQUENCE , sizeof(URI_EXPLAIN__SEQUENCE)-1 ) )
	{
		nret = ExplainSequence( p_env , uri+sizeof(URI_EXPLAIN__SEQUENCE)-1 ) ;
		if( nret != HTTP_OK )
			return nret;
		
		nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
			, "Content-length: %d" HTTP_RETURN_NEWLINE
			HTTP_RETURN_NEWLINE
			"%s" HTTP_RETURN_NEWLINE
			, strlen(p_env->explain_buffer)
			, p_env->explain_buffer ) ;
		if( nret )
		{
			ErrorLog( __FILE__ , __LINE__ , "FormatHttpResponseStartLine failed[%d]" , nret );
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else
	{
		return HTTP_NOT_FOUND;
	}
	
	return HTTP_OK;
}

/* ��������������¼� */
static int OnAcceptingSocket( struct TcpdaemonServerEnvirment *p , struct CoconutServerEnvironment *p_env , int sock , struct sockaddr *p_addr )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	int			epoll_fd = TDGetThisEpoll(p) ;
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/*  */
	p_accepted_session = (struct AcceptedSession *)malloc( sizeof(struct AcceptedSession) ) ;
	if( p_accepted_session == NULL )
		return -1;
	memset( p_accepted_session , 0x00 , sizeof(struct AcceptedSession) );
	
	p_accepted_session->netaddr.sock = sock ;
	memcpy( & (p_accepted_session->netaddr.addr) , & p_addr , sizeof(struct sockaddr) );
	
	/* ��ʼ��HTTP���� */
	p_accepted_session->http = CreateHttpEnv() ;
	if( p_accepted_session->http == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "CreateHttpEnv failed , errno[%d]" , ERRNO );
		return -1;
	}
	SetHttpTimeout( p_accepted_session->http , -1 );
	ResetHttpEnv( p_accepted_session->http );
	
	/* �������׽��ֿɶ��¼���epoll */
	memset( & event , 0x00 , sizeof(struct epoll_event) );
	event.events = EPOLLIN | EPOLLERR ;
	event.data.ptr = p_accepted_session ;
	nret = epoll_ctl( epoll_fd , EPOLL_CTL_ADD , p_accepted_session->netaddr.sock , & event ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] failed , errno[%d]" , epoll_fd , p_accepted_session->netaddr.sock , errno );
		DestroyHttpEnv( p_accepted_session->http );
		close( p_accepted_session->netaddr.sock );
		free( p_accepted_session );
		return 1;
	}
	else
	{
		DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] ok" , epoll_fd , p_accepted_session->netaddr.sock );
	}
	
	return 0;
}

/* �����ر��׽��� */
static int OnClosingSocket( struct TcpdaemonServerEnvirment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			epoll_fd = TDGetThisEpoll(p) ;
	
	if( p_accepted_session )
	{
		InfoLog( __FILE__ , __LINE__ , "close session[%d]" , p_accepted_session->netaddr.sock );
		epoll_ctl( epoll_fd , EPOLL_CTL_DEL , p_accepted_session->netaddr.sock , NULL );
		DestroyHttpEnv( p_accepted_session->http );
		close( p_accepted_session->netaddr.sock );
	}
	
	return 0;
}

/* ���տͻ����׽������� */
static int OnReceivingSocket( struct TcpdaemonServerEnvirment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			epoll_fd = TDGetThisEpoll(p) ;
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/* ������������ */
	nret = ReceiveHttpRequestNonblock( p_accepted_session->netaddr.sock , NULL , p_accepted_session->http ) ;
	if( nret == FASTERHTTP_INFO_NEED_MORE_HTTP_BUFFER )
	{
		DebugLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return FASTERHTTP_INFO_NEED_MORE_HTTP_BUFFER" , p_accepted_session->netaddr.sock );
		return 0;
	}
	else if( nret == FASTERHTTP_INFO_TCP_CLOSE )
	{
		InfoLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return CLOSE[%d]" , p_accepted_session->netaddr.sock , nret );
		return 1;
	}
	else if( nret )
	{
		ErrorLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return ERROR[%d]" , p_accepted_session->netaddr.sock , nret );
		return 1;
	}
	else
	{
		/* ���������� */
		DebugLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		/* ����Ӧ�ò� */
		nret = DispatchProcess( p_env , p_accepted_session ) ;
		if( nret != HTTP_OK )
		{
			nret = FormatHttpResponseStartLine( nret , p_accepted_session->http , 1 , NULL ) ;
			if( nret )
			{
				ErrorLog( __FILE__ , __LINE__ , "FormatHttpResponseStartLine failed[%d]" , nret );
				return 1;
			}
		}
		
		/* �л�Ϊ��д�¼� */
		memset( & event , 0x00 , sizeof(struct epoll_event) );
		event.events = EPOLLOUT | EPOLLERR ;
		event.data.ptr = p_accepted_session ;
		nret = epoll_ctl( epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* ���Ϳͻ����׽������� */
static int OnSendingSocket( struct TcpdaemonServerEnvirment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			epoll_fd = TDGetThisEpoll(p) ;
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/* ������Ӧ���� */
	nret = SendHttpResponseNonblock( p_accepted_session->netaddr.sock , NULL , p_accepted_session->http ) ;
	if( nret == FASTERHTTP_INFO_TCP_SEND_WOULDBLOCK )
	{
		DebugLog( __FILE__ , __LINE__ , "SendHttpResponseNonblock[%d] return FASTERHTTP_INFO_TCP_SEND_WOULDBLOCK" , p_accepted_session->netaddr.sock );
		return 0;
	}
	else if( nret )
	{
		ErrorLog( __FILE__ , __LINE__ , "SendHttpResponseNonblock[%d] return ERROR[%d]" , p_accepted_session->netaddr.sock , nret );
		return 1;
	}
	else
	{
		DebugLog( __FILE__ , __LINE__ , "SendHttpResponseNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		if( ! CheckHttpKeepAlive(p_accepted_session->http) )
		{
			return 1;
		}
		
		SetHttpTimeout( p_accepted_session->http , -1 );
		ResetHttpEnv( p_accepted_session->http ) ;
		
		/* �л�Ϊ�ɶ��¼� */
		memset( & event , 0x00 , sizeof(struct epoll_event) );
		event.events = EPOLLIN | EPOLLERR ;
		event.data.ptr = p_accepted_session ;
		nret = epoll_ctl( epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

static func_tcpmain tcpmain ;
int tcpmain( struct TcpdaemonServerEnvirment *p , int sock , void *p_addr )
{
	struct CoconutServerEnvironment	*p_env = TDGetTcpmainParameter(p) ;
	
	switch( TDGetIoMultiplexEvent(p) )
	{
		case IOMP_ON_ACCEPTING_SOCKET :
			return OnAcceptingSocket( p , p_env , sock , (struct sockaddr *)p_addr ) ;
		case IOMP_ON_CLOSING_SOCKET :
			return OnClosingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		case IOMP_ON_RECEIVING_SOCKET :
			return OnReceivingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		case IOMP_ON_SENDING_SOCKET :
			return OnSendingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		default :
			return -1;
	}
}

static void usage()
{
	printf( "coconut v0.1.0.0\n" );
	printf( "Copyright by calvin 2017\n" );
	printf( "USAGE : coconut -r (reserve) -s (server_no) -p (listen_port) [ -c (processor_count) ] [ --log-level (DEBUG|INFO|WARN|ERROR|FATAL) ] [ --cpu-affinity ]\n" );
	return;
}

int main( int argc , char *argv[] )
{
	struct CoconutServerEnvironment	env , *p_env = & env ;
	int				i ;
	struct TcpdaemonEntryParameter	para ;
	
	int				nret = 0 ;
	
	if( argc > 1 )
	{
		memset( & env , 0x00 , sizeof(struct CoconutServerEnvironment) );
		
		/* ���������в��� */
		for( i = 1 ; i < argc ; i++ )
		{
			if( strcmp( argv[i] , "-r" ) == 0 && i + 1 < argc )
			{
				p_env->reserve = (uint64_t)atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-s" ) == 0 && i + 1 < argc )
			{
				p_env->server_no = (uint64_t)atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-p" ) == 0 && i + 1 < argc )
			{
				p_env->listen_port = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-c" ) == 0 && i + 1 < argc )
			{
				p_env->processor_count = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "--log-level" ) == 0 && i + 1 < argc )
			{
				p_env->log_level = ConvertLogLevel( argv[++i] ) ;
				if( p_env->log_level == -1 )
				{
					printf( "Invalid command parameter 'log_level'\n" );
					usage();
					exit(7);
				}
			}
			else if( strcmp( argv[i] , "--cpu-affinity" ) == 0 )
			{
				p_env->cpu_affinity = 1 ;
			}
		}
		
		if( p_env->log_level == 0 )
		{
			p_env->log_level = LOGLEVEL_WARN ;
		}
		
		if( p_env->listen_port < 0 )
		{
			printf( "Invalid command parameter 'listen_port'\n" );
			usage();
			exit(7);
		}
		
		if( p_env->processor_count == 0 )
			p_env->processor_count = 1 ;
		else if( p_env->processor_count == -1 )
			p_env->processor_count = sysconf(_SC_NPROCESSORS_ONLN) ;
		else if( p_env->processor_count <= 0 )
		{
			printf( "Invalid command parameter 'processor_count'\n" );
			usage();
			exit(7);
		}
		
		/* �������й����ڴ� */
		p_env->serial_space_shm.shmkey = 0 ;
		p_env->serial_space_shm.size = sizeof(uint64_t) ;
		p_env->serial_space_shm.shmid = shmget( p_env->serial_space_shm.shmkey , p_env->serial_space_shm.size , IPC_CREAT|0644 ) ;
		if( p_env->serial_space_shm.shmid == -1 )
		{
			printf( "shmget failed , errno[%d]\n" , errno );
			return 1;
		}
		
		/* �������й����ڴ� */
		p_env->serial_space_shm.base = shmat( p_env->serial_space_shm.shmid , NULL , 0 ) ;
		if( p_env->serial_space_shm.base == NULL )
		{
			printf( "shmat failed , errno[%d]\n" , errno );
			return 1;
		}
		p_env->p_serial_no = (uint64_t*)(p_env->serial_space_shm.base) ;
		*(p_env->p_serial_no) = 0 ;
		
		/* ��ʼ�����к�ǰ��� */
		InitSequence( & env );
		
		/* ��ʼ��tcpdaemon�����ṹ */
		memset( & para , 0x00 , sizeof(struct TcpdaemonEntryParameter) );
		para.daemon_level = 1 ;
		snprintf( para.log_pathfilename , sizeof(para.log_pathfilename)-1 , "%s/log/coconut.log" , getenv("HOME") );
		para.log_level = p_env->log_level ;
		strcpy( para.server_model , "IOMP" );
		para.process_count = p_env->processor_count ;
		strcpy( para.ip , "0" );
		para.port = p_env->listen_port ;
		para.pfunc_tcpmain = & tcpmain ;
		para.param_tcpmain = & env ;
		para.tcp_nodelay = 1 ;
		
		/* ����tcpdaemon���� */
		nret = tcpdaemon( & para ) ;
		if( nret )
		{
			printf( "call tcpdaemon failed[%d] , errno[%d]\n" , nret , errno );
		}
		
		/* �Ͽ������ڴ� */
		shmdt( p_env->serial_space_shm.base );
		
		/* ɾ�������ڴ� */
		shmctl( p_env->serial_space_shm.shmid , IPC_RMID , NULL );
	}
	else
	{
		usage();
		exit(7);
	}
	
	return 0;
}
