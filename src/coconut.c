#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>

#include "LOGC.h"
#include "fasterhttp.h"

int	g_SIGTERM_flag = 0 ;

/* ÿ�ֲ���epoll�¼����ֵ */
#define MAX_EPOLL_EVENTS		1024

/* �����ṩ��ȡ���к�URI */
#define URI_FETCH_SEQUENCE		"/fetch_sequence"

/* ��ʮ�Ľ�λ���ַ��� */
static char sg_64_scale_system_charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+" ;

/* ͨѶ������Ϣ�ṹ */
struct NetAddress
{
	char			ip[ 20 + 1 ] ;
	int			port ;
	SOCKET			sock ;
	struct sockaddr_in	addr ;
	
	struct sockaddr_in	local_addr ;
	char			local_ip[ 20 + 1 ] ;
	int			local_port ;
	
	struct sockaddr_in	remote_addr ;
	char			remote_ip[ 20 + 1 ] ;
	int			remote_port ;
} ;

/* �����Ự�ṹ */
struct ListenSession
{
	struct NetAddress	netaddr ;
} ;

/* �ͻ������ӻỰ�ṹ */
struct AcceptedSession
{
	struct NetAddress	netaddr ;
	
	struct HttpEnv		*http ;
} ;

/* ����˻����ṹ */
struct ServerEnv
{
	uint64_t		reserve ;
	uint64_t		server_no ;
	int			listen_port ;
	
	int			epoll_fd ;
	
	char			id[ 64 + 1 ] ;
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

#define GETNETADDRESS_LOCAL(_netaddr_) \
	{ \
	socklen_t	socklen = sizeof(struct sockaddr) ; \
	int		nret = 0 ; \
	nret = getsockname( (_netaddr_).sock , (struct sockaddr*)&((_netaddr_).local_addr) , & socklen ) ; \
	if( nret == 0 ) \
	{ \
		strcpy( (_netaddr_).local_ip , inet_ntoa((_netaddr_).local_addr.sin_addr) ); \
		(_netaddr_).local_port = (int)ntohs( (_netaddr_).local_addr.sin_port ) ; \
	} \
	}

#define GETNETADDRESS_REMOTE(_netaddr_) \
	{ \
	socklen_t	socklen = sizeof(struct sockaddr) ; \
	int		nret = 0 ; \
	nret = getpeername( (_netaddr_).sock , (struct sockaddr*)&((_netaddr_).remote_addr) , & socklen ) ; \
	if( nret == 0 ) \
	{ \
		strcpy( (_netaddr_).remote_ip , inet_ntoa((_netaddr_).remote_addr.sin_addr) ); \
		(_netaddr_).remote_port = (int)ntohs( (_netaddr_).remote_addr.sin_port ) ; \
	} \
	}

/* ת����ǰ����Ϊ�ػ����� */
static int BindDaemonServer( int (* ServerMain)( void *pv ) , void *pv )
{
	int	pid ;
	
	pid = fork() ;
	switch( pid )
	{
		case -1:
			return -1;
		case 0:
			break;
		default		:
			return 0;
	}
	
	pid = fork() ;
	switch( pid )
	{
		case -1:
			return -2;
		case 0:
			break ;
		default:
			return 0;
	}
	
	close(0);
	close(1);
	close(2);
	
	umask( 0 ) ;
	
	chdir( "/tmp" );
	
	ServerMain( pv );
	
	return 0;
}

/* �źŴ����� */
static void sig_set_flag( int sig_no )
{
	if( sig_no == SIGTERM )
	{
		g_SIGTERM_flag = 1 ; /* �˳� */
	}
	
	return;
}

/* ��ʼ�����к�ǰ��� */
static void InitSequence( struct ServerEnv *p_env )
{
	uint64_t	reserve_region_length = 1 ;
	uint64_t	host_no_region_length = 2 ;
	uint64_t	tt_region_length = 6 ;
	uint64_t	sequence_region_length = 5 ;
	uint64_t	index_region ;
	
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
	index_region = (reserve_region_length<<9) + (host_no_region_length<<6) + (tt_region_length<<3) + (sequence_region_length) ;
	p_env->id[0] = sg_64_scale_system_charset[(index_region>>6)&0x3F] ;
	p_env->id[1] = sg_64_scale_system_charset[index_region&0x3F] ;
	
	/* ������ */
	p_env->id[2] = sg_64_scale_system_charset[p_env->reserve&0x3F] ;
	
	/* ����������� */
	p_env->id[3] = sg_64_scale_system_charset[(p_env->server_no>>6)&0x3F] ;
	p_env->id[4] = sg_64_scale_system_charset[p_env->server_no&0x3F] ;
	
	return;
}
		
/* ��ȡ���к� */
static void FetchSequence( struct ServerEnv *p_env )
{
	uint64_t	secondstamp ;
	static uint64_t	sequence = 0 ;
	
	/* ����� */
	secondstamp = time( NULL );
	p_env->id[5] = sg_64_scale_system_charset[(secondstamp>>30)&0x3F] ;
	p_env->id[6] = sg_64_scale_system_charset[(secondstamp>>24)&0x3F] ;
	p_env->id[7] = sg_64_scale_system_charset[(secondstamp>>18)&0x3F] ;
	p_env->id[8] = sg_64_scale_system_charset[(secondstamp>>12)&0x3F] ;
	p_env->id[9] = sg_64_scale_system_charset[(secondstamp>>6)&0x3F] ;
	p_env->id[10] = sg_64_scale_system_charset[secondstamp&0x3F] ;
	
	/* ����� */
	p_env->id[11] = sg_64_scale_system_charset[(sequence>>24)&0x3F] ;
	p_env->id[12] = sg_64_scale_system_charset[(sequence>>18)&0x3F] ;
	p_env->id[13] = sg_64_scale_system_charset[(sequence>>12)&0x3F] ;
	p_env->id[14] = sg_64_scale_system_charset[(sequence>>6)&0x3F] ;
	p_env->id[15] = sg_64_scale_system_charset[sequence&0x3F] ;
	
	/* �������һ */
	sequence++;
	
	return;
}

/* Ӧ�ò㴦�� */
static int OnProcess( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	char			*uri = NULL ;
	int			uri_len ;
	
	int			nret = 0 ;
	
	/* �õ�URI */
	uri = GetHttpHeaderPtr_URI( p_accepted_session->http , & uri_len ) ;
	InfoLog( __FILE__ , __LINE__ , "uri[%.*s]" , uri_len , uri );
	
	/* ��ȡ���к� */
	if( uri_len == sizeof(URI_FETCH_SEQUENCE)-1 && MEMCMP( uri , == , URI_FETCH_SEQUENCE , uri_len ) )
	{
		FetchSequence( p_env );
		
		nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
			, "Content-length: %d" HTTP_RETURN_NEWLINE
			HTTP_RETURN_NEWLINE
			"%s"
			, strlen(p_env->id)
			, p_env->id ) ;
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
static int OnAcceptingSocket( struct ServerEnv *p_env , struct ListenSession *p_listen_session )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	SOCKLEN_T		accept_addr_len ;
	
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/* �����ڴ��Դ�ſͻ������ӻỰ�ṹ */
	p_accepted_session = (struct AcceptedSession *)malloc( sizeof(struct AcceptedSession) ) ;
	if( p_accepted_session == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "malloc failed , errno[%d]" , errno );
		return 1;
	}
	memset( p_accepted_session , 0x00 , sizeof(struct AcceptedSession) );
	
	/* ���������� */
	accept_addr_len = sizeof(struct sockaddr) ;
	p_accepted_session->netaddr.sock = accept( p_listen_session->netaddr.sock , (struct sockaddr *) & (p_accepted_session->netaddr.addr) , & accept_addr_len ) ;
	if( p_accepted_session->netaddr.sock == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "accept failed , errno[%d]" , errno );
		free( p_accepted_session );
		return 1;
	}
	
	SetHttpNonblock( p_accepted_session->netaddr.sock );
	SetHttpNodelay( p_accepted_session->netaddr.sock , 1 );
	
	GETNETADDRESS( p_accepted_session->netaddr )
	GETNETADDRESS_REMOTE( p_accepted_session->netaddr )
	
	/* ����HTTP���� */
	p_accepted_session->http = CreateHttpEnv() ;
	if( p_accepted_session->http == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "CreateHttpEnv failed , errno[%d]" , errno );
		close( p_accepted_session->netaddr.sock );
		free( p_accepted_session );
		return 1;
	}
	
	/* �������׽��ֿɶ��¼���epoll */
	memset( & event , 0x00 , sizeof(struct epoll_event) );
	event.events = EPOLLIN | EPOLLERR ;
	event.data.ptr = p_accepted_session ;
	nret = epoll_ctl( p_env->epoll_fd , EPOLL_CTL_ADD , p_accepted_session->netaddr.sock , & event ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] failed , errno[%d]" , p_env->epoll_fd , p_accepted_session->netaddr.sock , errno );
		DestroyHttpEnv( p_accepted_session->http );
		close( p_accepted_session->netaddr.sock );
		free( p_accepted_session );
		return 1;
	}
	else
	{
		DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] ok" , p_env->epoll_fd , p_accepted_session->netaddr.sock );
	}
	
	return 0;
}

/* �����ر��׽��� */
static void OnClosingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	if( p_accepted_session )
	{
		InfoLog( __FILE__ , __LINE__ , "close session[%d]" , p_accepted_session->netaddr.sock );
		DestroyHttpEnv( p_accepted_session->http );
		epoll_ctl( p_env->epoll_fd , EPOLL_CTL_DEL , p_accepted_session->netaddr.sock , NULL );
		close( p_accepted_session->netaddr.sock );
		free( p_accepted_session );
	}
	
	return;
}

/* ���տͻ����׽������� */
static int OnReceivingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
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
		WarnLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return ERROR[%d]" , p_accepted_session->netaddr.sock , nret );
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
		nret = OnProcess( p_env , p_accepted_session ) ;
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
		nret = epoll_ctl( p_env->epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , p_env->epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , p_env->epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* ���Ϳͻ����׽������� */
static int OnSendingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
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
		nret = epoll_ctl( p_env->epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , p_env->epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , p_env->epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* ������������ */
int coconut( void *pv )
{
	struct ServerEnv	*p_env = (struct ServerEnv *)pv ;
	
	struct ListenSession	listen_session ;
	
	struct epoll_event	event ;
	struct epoll_event	events[ MAX_EPOLL_EVENTS ] ;
	int			epoll_nfds ;
	int			i ;
	struct epoll_event	*p_event = NULL ;
	struct ListenSession	*p_listen_session = NULL ;
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	int			nret = 0 ;
	
	SetLogFile( "%s/log/coconut.log" , getenv("HOME") );
	SetLogLevel( LOGLEVEL_WARN );
	
	InfoLog( __FILE__ , __LINE__ , "--- coconut begin ---" );
	
	/* ����epoll�� */
	p_env->epoll_fd = epoll_create( 1024 ) ;
	if( p_env->epoll_fd == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_create failed , errno[%d]" , errno );
		return -1;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "epoll_create ok" );
	}
	
	/* �����׽��� */
	memset( & listen_session , 0x00 , sizeof(struct ListenSession) );
	listen_session.netaddr.sock = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP ) ;
	if( listen_session.netaddr.sock == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "socket failed , errno[%d]" , errno );
		goto E1;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "socket ok[%d]" , listen_session.netaddr.sock );
	}
	
	SetHttpNonblock( listen_session.netaddr.sock );
	SetHttpReuseAddr( listen_session.netaddr.sock );
	SetHttpNodelay( listen_session.netaddr.sock , 1 );
	
	/* ���׽��ֵ������˿� */
	strcpy( listen_session.netaddr.ip , "0" );
	listen_session.netaddr.port = p_env->listen_port ;
	SETNETADDRESS( listen_session.netaddr )
	nret = bind( listen_session.netaddr.sock , (struct sockaddr *) & (listen_session.netaddr.addr) , sizeof(struct sockaddr) ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "bind[%s:%d][%d] failed , errno[%d]" , listen_session.netaddr.ip , listen_session.netaddr.port , listen_session.netaddr.sock , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "bind[%s:%d][%d] ok" , listen_session.netaddr.ip , listen_session.netaddr.port , listen_session.netaddr.sock );
	}
	
	/* ��������״̬�� */
	nret = listen( listen_session.netaddr.sock , 10240 ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "listen[%s:%d][%d] failed , errno[%d]" , listen_session.netaddr.ip , listen_session.netaddr.port , listen_session.netaddr.sock , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "listen[%s:%d][%d] ok" , listen_session.netaddr.ip , listen_session.netaddr.port , listen_session.netaddr.sock );
	}
	
	/* ���������ɶ��¼���epoll */
	memset( & event , 0x00 , sizeof(struct epoll_event) );
	event.events = EPOLLIN | EPOLLERR ;
	event.data.ptr = & listen_session ;
	nret = epoll_ctl( p_env->epoll_fd , EPOLL_CTL_ADD , listen_session.netaddr.sock , & event ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session failed , errno[%d]" , p_env->epoll_fd , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session[%d]" , p_env->epoll_fd , listen_session.netaddr.sock );
	}
	
	/* �����źŴ����� */
	signal( SIGTERM , sig_set_flag );
	
	/* ��������ѭ�� */
	while( ! g_SIGTERM_flag )
	{
		/* �ȴ�epoll�¼�������1�볬ʱ */
		InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] ..." , p_env->epoll_fd );
		memset( events , 0x00 , sizeof(events) );
		epoll_nfds = epoll_wait( p_env->epoll_fd , events , MAX_EPOLL_EVENTS , 1000 ) ;
		if( epoll_nfds == -1 )
		{
			if( errno == EINTR )
			{
				InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] interrupted" , p_env->epoll_fd );
				continue;
			}
			else
			{
				ErrorLog( __FILE__ , __LINE__ , "epoll_wait[%d] failed , errno[%d]" , p_env->epoll_fd , ERRNO );
			}
			
			return -1;
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] return[%d]events" , p_env->epoll_fd , epoll_nfds );
		}
		
		/* ���������¼� */
		for( i = 0 , p_event = events ; i < epoll_nfds ; i++ , p_event++ )
		{
			/* �����׽����¼� */
			if( p_event->data.ptr == & listen_session )
			{
				p_listen_session = (struct ListenSession *)(p_event->data.ptr) ;
				
				/* �ɶ��¼� */
				if( p_event->events & EPOLLIN )
				{
					nret = OnAcceptingSocket( p_env , p_listen_session ) ;
					if( nret < 0 )
					{
						FatalLog( __FILE__ , __LINE__ , "OnAcceptingSocket failed[%d]" , nret );
						return -1;
					}
					else if( nret > 0 )
					{
						InfoLog( __FILE__ , __LINE__ , "OnAcceptingSocket return[%d]" , nret );
					}
					else
					{
						DebugLog( __FILE__ , __LINE__ , "OnAcceptingSocket ok" );
					}
				}
				/* �����¼� */
				else if( ( p_event->events & EPOLLERR ) || ( p_event->events & EPOLLHUP ) )
				{
					FatalLog( __FILE__ , __LINE__ , "listen session err or hup event[0x%X]" , p_event->events );
					return -1;
				}
				/* �����¼� */
				else
				{
					FatalLog( __FILE__ , __LINE__ , "Unknow listen session event[0x%X]" , p_event->events );
					return -1;
				}
			}
			/* �����¼������ͻ������ӻỰ�¼� */
			else
			{
				p_accepted_session = (struct AcceptedSession *)(p_event->data.ptr) ;
				
				/* �ɶ��¼� */
				if( p_event->events & EPOLLIN )
				{
					nret = OnReceivingSocket( p_env , p_accepted_session ) ;
					if( nret < 0 )
					{
						FatalLog( __FILE__ , __LINE__ , "OnReceivingSocket failed[%d]" , nret );
						return -1;
					}
					else if( nret > 0 )
					{
						InfoLog( __FILE__ , __LINE__ , "OnReceivingSocket return[%d]" , nret );
						OnClosingSocket( p_env , p_accepted_session );
					}
					else
					{
						DebugLog( __FILE__ , __LINE__ , "OnReceivingSocket ok" );
					}
				}
				/* ��д�¼� */
				else if( p_event->events & EPOLLOUT )
				{
					nret = OnSendingSocket( p_env , p_accepted_session ) ;
					if( nret < 0 )
					{
						FatalLog( __FILE__ , __LINE__ , "OnSendingSocket failed[%d]" , nret );
						return -1;
					}
					else if( nret > 0 )
					{
						InfoLog( __FILE__ , __LINE__ , "OnSendingSocket return[%d]" , nret );
						OnClosingSocket( p_env , p_accepted_session );
					}
					else
					{
						DebugLog( __FILE__ , __LINE__ , "OnSendingSocket ok" );
					}
				}
				/* �����¼� */
				else if( ( p_event->events & EPOLLERR ) || ( p_event->events & EPOLLHUP ) )
				{
					FatalLog( __FILE__ , __LINE__ , "accepted session err or hup event[0x%X]" , p_event->events );
					OnClosingSocket( p_env , p_accepted_session );
				}
				/* �����¼� */
				else
				{
					FatalLog( __FILE__ , __LINE__ , "Unknow accepted session event[0x%X]" , p_event->events );
					return -1;
				}
			}
		}
	}
	
E2 :
	/* �ر������˿� */
	close( listen_session.netaddr.sock );
	
E1 :
	/* ����epoll�� */
	close( p_env->epoll_fd );
	
	InfoLog( __FILE__ , __LINE__ , "--- coconut end ---" );
	
	return 0;
}

static void usage()
{
	printf( "coconut v0.0.1\n" );
	printf( "Copyright by calvin 2017\n" );
	printf( "USAGE : coconut -r (reserve) -s (server_no) -p (listen_port)\n" );
	return;
}

int main( int argc , char *argv[] )
{
	struct ServerEnv	env ;
	int			i ;
	
	int			nret = 0 ;
	
	if( argc > 1 )
	{
		memset( & env , 0x00 , sizeof(struct ServerEnv) );
		
		/* ���������в��� */
		for( i = 1 ; i < argc ; i++ )
		{
			if( strcmp( argv[i] , "-r" ) == 0 && i + 1 < argc )
			{
				env.reserve = (uint64_t)atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-s" ) == 0 && i + 1 < argc )
			{
				env.server_no = (uint64_t)atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-p" ) == 0 && i + 1 < argc )
			{
				env.listen_port = atoi(argv[++i]) ;
			}
		}
		
		if( env.listen_port <= 0 )
		{
			printf( "Invalid command parameter\n" );
			usage();
			exit(7);
		}
		
		/* ��ʼ�����к�ǰ��� */
		InitSequence( & env );
		
		/* ��������������� */
		nret = BindDaemonServer( & coconut , (void*) & env ) ;
		if( nret )
		{
			printf( "Convert to daemon failed[%d] , errno[%d]\n" , nret , errno );
		}
	}
	else
	{
		usage();
		exit(7);
	}
	
	return 0;
}

