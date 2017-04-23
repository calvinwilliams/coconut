#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define __USE_GNU
#include <sched.h>

#include "list.h"
#include "LOGC.h"
#include "fasterhttp.h"

int	g_SIGTERM_flag = 0 ;

/* 每次预分配客户端会话数组 */
#define PREALLOC_ACCEPTED_SESSION_ARRAY_SIZE	100

/* 每轮捕获epoll事件最大值 */
#define MAX_EPOLL_EVENTS	1024

/* 对外提供获取序列号URI */
#define URI_FETCH		"/fetch"
/* 对外提供解释序列号URI */
#define URI_EXPLAIN__SEQUENCE	"/explain?sequence="

/* 六十四进位制字符集 */
static char sg_64_scale_system_charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_" ;

/* 通讯基础信息结构 */
struct NetAddress
{
	char			ip[ 20 + 1 ] ;
	int			port ;
	SOCKET			sock ;
	struct sockaddr_in	addr ;
} ;

/* 侦听会话结构 */
struct ListenSession
{
	struct NetAddress	netaddr ;
} ;

/* 客户端连接会话结构 */
struct AcceptedSession
{
	struct NetAddress	netaddr ;
	
	struct HttpEnv		*http ;
	
	struct list_head	unused_node ;
} ;

/* 客户端连接会话物理结构 */
struct AcceptedSessionArray
{
	struct AcceptedSession	*accepted_session_array ;
	int			array_count ;
	
	struct list_head	prealloc_node ;
} ;

/* 管道会话结构 */
struct PipeSession
{
	int			fds[ 2 ] ;
} ;

/* 共享内存信息结构 */
struct ShareMemory
{
	int			proj_id ; /* 用于计算共享内存key的ftok参数 */
	key_t			shmkey ; /* 共享内存key */
	int			shmid ; /* 共享内存sequence_buffer */
	void			*base ; /* 共享内存连接基地址 */
	int			size ; /* 共享内存大小 */
} ;

/* 服务端环境结构 */
struct ServerEnv
{
	uint64_t			reserve ;
	uint64_t			server_no ;
	int				listen_port ;
	int				processor_count ;
	int				log_level ;
	int				cpu_affinity ;
	struct ProcessorInfo
	{
		struct PipeSession	pipe_session ;
		pid_t			pid ;
		
		int			epoll_fd ;
	} *processor_info_array , *this_processor_info ;
	
	struct ShareMemory		serial_space_shm ;
	uint64_t			*p_serial_no ;
	
	struct ListenSession		listen_session ;
	
	struct AcceptedSessionArray	accepted_session_array_list ;
	struct AcceptedSession		accepted_session_unused_list ;
	
	char				sequence_buffer[ 16 + 1 ] ;
	char				explain_buffer[ 128 + 1 ] ;
} ;

/* 从NetAddress中设置、得到IP、PORT宏 */
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

/* 转换当前进程为守护进程 */
static int BindDaemonServer( int (* ServerMain)( void *pv ) , void *pv , int close_flag )
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
	
	if( close_flag )
	{
		close(0);
		close(1);
		close(2);
	}
	
	umask( 0 ) ;
	
	chdir( "/tmp" );
	
	ServerMain( pv );
	
	return 0;
}

/* 绑定CPU亲缘性 */
int BindCpuAffinity( int processor_no )
{
	cpu_set_t	cpu_mask ;
	
	int		nret = 0 ;
	
	CPU_ZERO( & cpu_mask );
	CPU_SET( processor_no , & cpu_mask );
	nret = sched_setaffinity( 0 , sizeof(cpu_mask) , & cpu_mask ) ;
	return nret;
}

/* 信号处理函数 */
static void sig_set_flag( int sig_no )
{
	if( sig_no == SIGTERM )
	{
		g_SIGTERM_flag = 1 ; /* 退出 */
	}
	
	return;
}

/* 初始化序列号前半段 */
static void InitSequence( struct ServerEnv *p_env )
{
	uint64_t	index_region ;
	uint64_t	reserve_region_length = 1 ;
	uint64_t	server_no_region_length = 2 ;
	uint64_t	secondstamp_region_length = 6 ;
	uint64_t	serial_no_region_length = 5 ;
	
	/*
	第一区 分区目录 2个六十四进制字符 共12个二进制位
			第一段3个二进制位表示保留区六十四进制字符个数
			第二段3个二进制位表示服务器编号区六十四进制字符个数
			第三段3个二进制位表示秒戳区六十四进制字符个数
			第四段3个二进制位表示序号区六十四进制字符个数
	第二区 保留区 1个六十四进制字符 有6个二进制位可用
	第三区 服务器编号区 2个六十四进制字符 可表示4096台发起器服务器
	第四区 秒戳区 6个六十四进制字符 可表示2179年的秒戳
	第五区 序号区 5个六十四进制字符 序号区间[1,10亿]
			共16个六十四进制字符
	*/
	
	/* 分区目录 */
	index_region = (reserve_region_length<<9) + (server_no_region_length<<6) + (secondstamp_region_length<<3) + (serial_no_region_length) ;
	p_env->sequence_buffer[0] = sg_64_scale_system_charset[(index_region>>6)&0x3F] ;
	p_env->sequence_buffer[1] = sg_64_scale_system_charset[index_region&0x3F] ;
	
	/* 保留区 */
	p_env->sequence_buffer[2] = sg_64_scale_system_charset[p_env->reserve&0x3F] ;
	
	/* 服务器编号区 */
	p_env->sequence_buffer[3] = sg_64_scale_system_charset[(p_env->server_no>>6)&0x3F] ;
	p_env->sequence_buffer[4] = sg_64_scale_system_charset[p_env->server_no&0x3F] ;
	
	return;
}
		
/* 获取序列号 */
static void FetchSequence( struct ServerEnv *p_env )
{
	uint64_t	secondstamp ;
	uint64_t	ret_serial_no ;
	// static uint64_t	ret_serial_no = 0 ;
	
	/* 秒戳区 */
	secondstamp = time( NULL );
	p_env->sequence_buffer[5] = sg_64_scale_system_charset[(secondstamp>>30)&0x3F] ;
	p_env->sequence_buffer[6] = sg_64_scale_system_charset[(secondstamp>>24)&0x3F] ;
	p_env->sequence_buffer[7] = sg_64_scale_system_charset[(secondstamp>>18)&0x3F] ;
	p_env->sequence_buffer[8] = sg_64_scale_system_charset[(secondstamp>>12)&0x3F] ;
	p_env->sequence_buffer[9] = sg_64_scale_system_charset[(secondstamp>>6)&0x3F] ;
	p_env->sequence_buffer[10] = sg_64_scale_system_charset[secondstamp&0x3F] ;
	
	/* 序号区 */
	ret_serial_no = __sync_fetch_and_add( p_env->p_serial_no , 1 ) ; /* 序号自增一 */
	// ret_serial_no++;
	p_env->sequence_buffer[11] = sg_64_scale_system_charset[(ret_serial_no>>24)&0x3F] ;
	p_env->sequence_buffer[12] = sg_64_scale_system_charset[(ret_serial_no>>18)&0x3F] ;
	p_env->sequence_buffer[13] = sg_64_scale_system_charset[(ret_serial_no>>12)&0x3F] ;
	p_env->sequence_buffer[14] = sg_64_scale_system_charset[(ret_serial_no>>6)&0x3F] ;
	p_env->sequence_buffer[15] = sg_64_scale_system_charset[ret_serial_no&0x3F] ;
	
	return;
}

/* 获取序列号 */
static int ExplainSequence( struct ServerEnv *p_env , char *sequence )
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

/* 应用层处理 */
static int DispatchProcess( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	char			*uri = NULL ;
	int			uri_len ;
	
	int			nret = 0 ;
	
	/* 得到URI */
	uri = GetHttpHeaderPtr_URI( p_accepted_session->http , & uri_len ) ;
	InfoLog( __FILE__ , __LINE__ , "uri[%.*s]" , uri_len , uri );
	
	/* 获取序列号 */
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
	/* 获取序列号 */
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

/* 预分配空闲客户端会话结构 */
static int IncreaseAcceptedSessions( struct ServerEnv *p_env , int increase_count )
{
	struct AcceptedSessionArray	*p_accepted_session_array = NULL ;
	struct AcceptedSession		*p_accepted_session = NULL ;
	int				i ;
	
	/* 批量增加空闲HTTP通讯会话 */
	p_accepted_session_array = (struct AcceptedSessionArray *)malloc( sizeof(struct AcceptedSessionArray) ) ;
	if( p_accepted_session_array == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "malloc failed , errno[%d]" , ERRNO );
		return -1;
	}
	memset( p_accepted_session_array , 0x00 , sizeof(struct AcceptedSessionArray) );
	list_add_tail( & (p_accepted_session_array->prealloc_node) , & (p_env->accepted_session_array_list.prealloc_node) );
	
	p_accepted_session_array->accepted_session_array = (struct AcceptedSession *)malloc( sizeof(struct AcceptedSession) * increase_count ) ;
	if( p_accepted_session_array->accepted_session_array == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "malloc failed , errno[%d]" , ERRNO );
		return -1;
	}
	memset( p_accepted_session_array->accepted_session_array , 0x00 , sizeof(struct AcceptedSession) * increase_count );
	p_accepted_session_array->array_count = increase_count ;
	
	for( i = 0 , p_accepted_session = p_accepted_session_array->accepted_session_array ; i < increase_count ; i++ , p_accepted_session++ )
	{
		p_accepted_session->http = CreateHttpEnv() ;
		if( p_accepted_session->http == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "CreateHttpEnv failed , errno[%d]" , ERRNO );
			return -1;
		}
		SetHttpTimeout( p_accepted_session->http , -1 );
		ResetHttpEnv( p_accepted_session->http );
		
		list_add_tail( & (p_accepted_session->unused_node) , & (p_env->accepted_session_unused_list.unused_node) );
		DebugLog( __FILE__ , __LINE__ , "init accepted session[%p] http env[%p]" , p_accepted_session , p_accepted_session->http );
	}
	
	return 0;
}

/* 从预分配的空闲客户端会话结构中取出一个 */
static struct AcceptedSession *FetchAcceptedSessionUnused( struct ServerEnv *p_env )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	int			nret = 0 ;
	
	/* 如果空闲客户端会话链表为空 */
	if( list_empty( & (p_env->accepted_session_unused_list.unused_node) ) )
	{
		nret = IncreaseAcceptedSessions( p_env , PREALLOC_ACCEPTED_SESSION_ARRAY_SIZE ) ;
		if( nret )
			return NULL;
	}
	
	/* 从空闲HTTP通讯会话链表中移出一个会话，并返回之 */
	p_accepted_session = list_first_entry( & (p_env->accepted_session_unused_list.unused_node) , struct AcceptedSession , unused_node ) ;
	list_del( & (p_accepted_session->unused_node) );
	
	ResetHttpEnv( p_accepted_session->http ) ;
	
	DebugLog( __FILE__ , __LINE__ , "fetch accepted session[%p] http env[%p]" , p_accepted_session , p_accepted_session->http );
	
	return p_accepted_session;
}

/* 把当前客户端会话放回空闲链表中去 */
static void SetAcceptedSessionUnused( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	DebugLog( __FILE__ , __LINE__ , "reset accepted session[%p] http env[%p]" , p_accepted_session , p_accepted_session->http );
	
	/* 把当前工作HTTP通讯会话移到空闲HTTP通讯会话链表中 */
	list_add_tail( & (p_accepted_session->unused_node) , & (p_env->accepted_session_unused_list.unused_node) );
	
	return;
}

/* 销毁所有客户端物理会话结构 */
static void FreeAllAcceptedSessionArray( struct ServerEnv *p_env )
{
	struct list_head		*p_curr = NULL , *p_next = NULL ;
	int				i ;
	struct AcceptedSessionArray	*p_accepted_session_array = NULL ;
	struct AcceptedSession		*p_accepted_session = NULL ;
	
	list_for_each_safe( p_curr , p_next , & (p_env->accepted_session_array_list.prealloc_node) )
	{
		p_accepted_session_array = container_of( p_curr , struct AcceptedSessionArray , prealloc_node ) ;
		list_del( & (p_accepted_session_array->prealloc_node) );
		
		for( i = 0 , p_accepted_session = p_accepted_session_array->accepted_session_array ; i < p_accepted_session_array->array_count ; i++ , p_accepted_session++ )
		{
			DestroyHttpEnv( p_accepted_session->http );
		}
		
		free( p_accepted_session_array->accepted_session_array );
		free( p_accepted_session_array );
	}
	
	return;
}

/* 处理接受新连接事件 */
static int OnAcceptingSocket( struct ServerEnv *p_env , struct ListenSession *p_listen_session )
{
	struct AcceptedSession	accepted_session ;
	struct AcceptedSession	*p_accepted_session = NULL ;
	SOCKLEN_T		accept_addr_len ;
	
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	while(1)
	{
		/* 接受新连接 */
		memset( & accepted_session , 0x00 , sizeof(struct AcceptedSession) );
		accept_addr_len = sizeof(struct sockaddr) ;
		accepted_session.netaddr.sock = accept( p_listen_session->netaddr.sock , (struct sockaddr *) & (accepted_session.netaddr.addr) , & accept_addr_len ) ;
		if( accepted_session.netaddr.sock == -1 )
		{
			if( errno == EAGAIN )
				break;
			ErrorLog( __FILE__ , __LINE__ , "accept failed , errno[%d]" , errno );
			return 1;
		}
		
		/* 从空闲客户端会话链表中取出一个 */
		p_accepted_session = FetchAcceptedSessionUnused( p_env ) ;
		if( p_accepted_session == NULL )
		{
			ErrorLog( __FILE__ , __LINE__ , "FetchAcceptedSessionUnused failed , errno[%d]" , errno );
			return 1;
		}
		
		p_accepted_session->netaddr.sock = accepted_session.netaddr.sock ;
		memcpy( & (p_accepted_session->netaddr.addr) , & (accepted_session.netaddr.addr) , sizeof(struct sockaddr) );
		
		/* 设置通讯选项 */
		SetHttpNonblock( p_accepted_session->netaddr.sock );
		SetHttpNodelay( p_accepted_session->netaddr.sock , 1 );
		
		GETNETADDRESS( p_accepted_session->netaddr )
		
		/* 加入新套接字可读事件到epoll */
		memset( & event , 0x00 , sizeof(struct epoll_event) );
		event.events = EPOLLIN | EPOLLERR ;
		event.data.ptr = p_accepted_session ;
		nret = epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_ADD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] failed , errno[%d]" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock , errno );
			DestroyHttpEnv( p_accepted_session->http );
			close( p_accepted_session->netaddr.sock );
			free( p_accepted_session );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add[%d] ok" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* 主动关闭套接字 */
static void OnClosingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	if( p_accepted_session )
	{
		InfoLog( __FILE__ , __LINE__ , "close session[%d]" , p_accepted_session->netaddr.sock );
		epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_DEL , p_accepted_session->netaddr.sock , NULL );
		close( p_accepted_session->netaddr.sock );
		SetAcceptedSessionUnused( p_env , p_accepted_session );
	}
	
	return;
}

/* 接收客户端套接字数据 */
static int OnReceivingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/* 接收请求数据 */
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
		/* 接收完整了 */
		DebugLog( __FILE__ , __LINE__ , "ReceiveHttpRequestNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		/* 调用应用层 */
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
		
		/* 切换为可写事件 */
		memset( & event , 0x00 , sizeof(struct epoll_event) );
		event.events = EPOLLOUT | EPOLLERR ;
		event.data.ptr = p_accepted_session ;
		nret = epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* 发送客户端套接字数据 */
static int OnSendingSocket( struct ServerEnv *p_env , struct AcceptedSession *p_accepted_session )
{
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	/* 发送响应数据 */
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
		
		/* 切换为可读事件 */
		memset( & event , 0x00 , sizeof(struct epoll_event) );
		event.events = EPOLLIN | EPOLLERR ;
		event.data.ptr = p_accepted_session ;
		nret = epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_MOD , p_accepted_session->netaddr.sock , & event ) ;
		if( nret == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] failed , errno[%d]" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock , errno );
			return 1;
		}
		else
		{
			DebugLog( __FILE__ , __LINE__ , "epoll_ctl[%d] modify[%d] ok" , p_env->this_processor_info->epoll_fd , p_accepted_session->netaddr.sock );
		}
	}
	
	return 0;
}

/* 服务器主函数 */
static int CoconutWorker( struct ServerEnv *p_env )
{
	struct epoll_event	event ;
	struct epoll_event	events[ MAX_EPOLL_EVENTS ] ;
	int			epoll_nfds ;
	int			i , j ;
	struct epoll_event	*p_event = NULL ;
	struct ListenSession	*p_listen_session = NULL ;
	struct AcceptedSession	*p_accepted_session = NULL ;
	int			quit_flag ;
	
	int			nret = 0 ;
	
	SetLogFile( "%s/log/coconut.log" , getenv("HOME") );
	
	InfoLog( __FILE__ , __LINE__ , "sock[%d] pipe[%d]" , p_env->listen_session.netaddr.sock , p_env->this_processor_info->pipe_session.fds[0] );
	
	/* 加入侦听可读事件到epoll */
	memset( & event , 0x00 , sizeof(struct epoll_event) );
	event.events = EPOLLIN | EPOLLERR ;
	event.data.ptr = & (p_env->this_processor_info->pipe_session) ;
	nret = epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_ADD , p_env->this_processor_info->pipe_session.fds[0] , & event ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add pipe_session[%d] failed , errno[%d]" , p_env->this_processor_info->epoll_fd , p_env->this_processor_info->pipe_session.fds[0] , errno );
		return -1;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add pipe_session[%d] ok" , p_env->this_processor_info->epoll_fd , p_env->this_processor_info->pipe_session.fds[0] );
	}
	
	/* 设置信号处理函数 */
	signal( SIGTERM , SIG_IGN );
	
	/* 服务器主循环 */
	quit_flag = 0 ;
	while( ! quit_flag )
	{
		/* 等待epoll事件，或者1秒超时 */
		InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] ..." , p_env->this_processor_info->epoll_fd );
		memset( events , 0x00 , sizeof(events) );
		epoll_nfds = epoll_wait( p_env->this_processor_info->epoll_fd , events , MAX_EPOLL_EVENTS , 1000 ) ;
		if( epoll_nfds == -1 )
		{
			if( errno == EINTR )
			{
				InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] interrupted" , p_env->this_processor_info->epoll_fd );
				continue;
			}
			else
			{
				ErrorLog( __FILE__ , __LINE__ , "epoll_wait[%d] failed , errno[%d]" , p_env->this_processor_info->epoll_fd , ERRNO );
			}
			
			return -1;
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "epoll_wait[%d] return[%d]events" , p_env->this_processor_info->epoll_fd , epoll_nfds );
		}
		
		/* 处理所有事件 */
		for( i = 0 , p_event = events ; i < epoll_nfds ; i++ , p_event++ )
		{
			/* 侦听套接字事件 */
			if( p_event->data.ptr == & (p_env->listen_session) )
			{
				p_listen_session = (struct ListenSession *)(p_event->data.ptr) ;
				
				/* 可读事件 */
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
					
					/* 转移侦听可读事件到下一个epoll */
					j = p_env->this_processor_info - p_env->processor_info_array + 1 ;
					if( j >= p_env->processor_count )
						j = 0 ;
					
					epoll_ctl( p_env->this_processor_info->epoll_fd , EPOLL_CTL_DEL , p_env->listen_session.netaddr.sock , NULL );
					
					memset( & event , 0x00 , sizeof(struct epoll_event) );
					event.events = EPOLLIN | EPOLLERR ;
					event.data.ptr = & (p_env->listen_session) ;
					nret = epoll_ctl( p_env->processor_info_array[j].epoll_fd , EPOLL_CTL_ADD , p_env->listen_session.netaddr.sock , & event ) ;
					if( nret == -1 )
					{
						ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session failed , errno[%d]" , p_env->processor_info_array[j].epoll_fd , errno );
						return -1;
					}
					else
					{
						InfoLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session[%d] ok" , p_env->processor_info_array[j].epoll_fd , p_env->listen_session.netaddr.sock );
					}
				}
				/* 出错事件 */
				else if( ( p_event->events & EPOLLERR ) || ( p_event->events & EPOLLHUP ) )
				{
					FatalLog( __FILE__ , __LINE__ , "listen session err or hup event[0x%X]" , p_event->events );
					return -1;
				}
				/* 其它事件 */
				else
				{
					FatalLog( __FILE__ , __LINE__ , "Unknow listen session event[0x%X]" , p_event->events );
					return -1;
				}
			}
			/* 命令管道事件 */
			else if( p_event->data.ptr == & (p_env->this_processor_info->pipe_session) )
			{
				quit_flag = 1 ;
			}
			/* 其它事件，即客户端连接会话事件 */
			else
			{
				p_accepted_session = (struct AcceptedSession *)(p_event->data.ptr) ;
				
				/* 可读事件 */
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
				/* 可写事件 */
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
				/* 出错事件 */
				else if( ( p_event->events & EPOLLERR ) || ( p_event->events & EPOLLHUP ) )
				{
					FatalLog( __FILE__ , __LINE__ , "accepted session err or hup event[0x%X]" , p_event->events );
					OnClosingSocket( p_env , p_accepted_session );
				}
				/* 其它事件 */
				else
				{
					FatalLog( __FILE__ , __LINE__ , "Unknow accepted session event[0x%X]" , p_event->events );
					return -1;
				}
			}
		}
	}
	
	InfoLog( __FILE__ , __LINE__ , "child exiting" );
	
	return 0;
}

static int CoconutMonitor( void *pv )
{
	struct ServerEnv	*p_env = (struct ServerEnv *)pv ;
	
	struct sigaction	act ;
	int			i , j ;
	pid_t			pid ;
	int			status ;
	
	struct epoll_event	event ;
	
	int			nret = 0 ;
	
	SetLogLevel( p_env->log_level );
	SetLogFile( "%s/log/coconut.log" , getenv("HOME") );
	
	InfoLog( __FILE__ , __LINE__ , "--- coconut begin ---" );
	
	/* 创建套接字 */
	p_env->listen_session.netaddr.sock = socket( AF_INET , SOCK_STREAM , IPPROTO_TCP ) ;
	if( p_env->listen_session.netaddr.sock == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "socket failed , errno[%d]" , errno );
		goto E1;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "socket ok[%d]" , p_env->listen_session.netaddr.sock );
	}
	
	SetHttpNonblock( p_env->listen_session.netaddr.sock );
	SetHttpReuseAddr( p_env->listen_session.netaddr.sock );
	SetHttpNodelay( p_env->listen_session.netaddr.sock , 1 );
	
	/* 绑定套接字到侦听端口 */
	strcpy( p_env->listen_session.netaddr.ip , "" );
	p_env->listen_session.netaddr.port = p_env->listen_port ;
	SETNETADDRESS( p_env->listen_session.netaddr )
	nret = bind( p_env->listen_session.netaddr.sock , (struct sockaddr *) & (p_env->listen_session.netaddr.addr) , sizeof(struct sockaddr) ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "bind[%s:%d][%d] failed , errno[%d]" , p_env->listen_session.netaddr.ip , p_env->listen_session.netaddr.port , p_env->listen_session.netaddr.sock , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "bind[%s:%d][%d] ok" , p_env->listen_session.netaddr.ip , p_env->listen_session.netaddr.port , p_env->listen_session.netaddr.sock );
	}
	
	/* 处于侦听状态了 */
	nret = listen( p_env->listen_session.netaddr.sock , 10240 ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "listen[%s:%d][%d] failed , errno[%d]" , p_env->listen_session.netaddr.ip , p_env->listen_session.netaddr.port , p_env->listen_session.netaddr.sock , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "listen[%s:%d][%d] ok" , p_env->listen_session.netaddr.ip , p_env->listen_session.netaddr.port , p_env->listen_session.netaddr.sock );
	}
	
	/* 创建序列共享内存 */
	p_env->serial_space_shm.shmkey = 0 ;
	p_env->serial_space_shm.size = sizeof(uint64_t) ;
	p_env->serial_space_shm.shmid = shmget( p_env->serial_space_shm.shmkey , p_env->serial_space_shm.size , IPC_CREAT|0644 ) ;
	if( p_env->serial_space_shm.shmid == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "shmget failed , errno[%d]" , errno );
		goto E2;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "shmget ok , shmid[%d] shmsize[%d]" , p_env->serial_space_shm.shmid , p_env->serial_space_shm.size );
	}
	
	/* 连接序列共享内存 */
	p_env->serial_space_shm.base = shmat( p_env->serial_space_shm.shmid , NULL , 0 ) ;
	if( p_env->serial_space_shm.base == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "shmat failed , errno[%d]" , errno );
		goto E3;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "shmat ok , shmid[%d] base[%p]" , p_env->serial_space_shm.shmid , p_env->serial_space_shm.base );
	}
	p_env->p_serial_no = (uint64_t*)(p_env->serial_space_shm.base) ;
	*(p_env->p_serial_no) = 0 ;
	
	/* 创建epoll池 */
	for( i = 0 ; i < p_env->processor_count ; i++ )
	{
		p_env->processor_info_array[i].epoll_fd = epoll_create( 1024 ) ;
		if( p_env->processor_info_array[i].epoll_fd == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "epoll_create failed , errno[%d]" , errno );
			goto E4;
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "epoll_create ok" );
		}
	}
	
	/* 加入侦听可读事件到epoll */
	memset( & event , 0x00 , sizeof(struct epoll_event) );
	event.events = EPOLLIN | EPOLLERR ;
	event.data.ptr = & (p_env->listen_session) ;
	nret = epoll_ctl( p_env->processor_info_array[0].epoll_fd , EPOLL_CTL_ADD , p_env->listen_session.netaddr.sock , & event ) ;
	if( nret == -1 )
	{
		ErrorLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session failed , errno[%d]" , p_env->processor_info_array[0].epoll_fd , errno );
		goto E5;
	}
	else
	{
		InfoLog( __FILE__ , __LINE__ , "epoll_ctl[%d] add listen_session[%d] ok" , p_env->processor_info_array[0].epoll_fd , p_env->listen_session.netaddr.sock );
	}
	
	/* 创建空闲客户端会话物理结构链表 */
	memset( & (p_env->accepted_session_array_list) , 0x00 , sizeof(struct AcceptedSessionArray) );
	INIT_LIST_HEAD( & (p_env->accepted_session_array_list.prealloc_node) );
	
	/* 创建空闲客户端会话结构链表 */
	memset( & (p_env->accepted_session_unused_list) , 0x00 , sizeof(struct AcceptedSession) );
	INIT_LIST_HEAD( & (p_env->accepted_session_unused_list.unused_node) );
	
	/* 预分配空闲客户端会话 */
	nret = IncreaseAcceptedSessions( p_env , PREALLOC_ACCEPTED_SESSION_ARRAY_SIZE ) ;
	if( nret )
	{
		ErrorLog( __FILE__ , __LINE__ , "IncreaseAcceptedSessions failed[%d] , errno[%d]" , nret , ERRNO );
		goto E5;
	}
	
	/* 设置信号处理函数 */
	act.sa_handler = & sig_set_flag ;
	sigemptyset( & (act.sa_mask) );
	act.sa_flags = 0 ;
	sigaction( SIGTERM , & act , NULL );
	
	/* 创建工作进程组 */
	for( i = 0 ; i < p_env->processor_count ; i++ )
	{
		nret = pipe( p_env->processor_info_array[i].pipe_session.fds ) ;
		if( nret )
		{
			ErrorLog( __FILE__ , __LINE__ , "pipe failed , errno[%d]" , errno );
			goto EE;
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "pipe ok , pipe[%d][%d]" , p_env->processor_info_array[i].pipe_session.fds[0] , p_env->processor_info_array[i].pipe_session.fds[1] );
		}
		
		p_env->processor_info_array[i].pid = fork() ;
		if( p_env->processor_info_array[i].pid == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "fork failed , errno[%d]" , errno );
			goto EE;
		}
		else if( p_env->processor_info_array[i].pid == 0 )
		{
			InfoLog( __FILE__ , __LINE__ , "child : [%ld] fork [%ld]" , getppid() , getpid() );
			InfoLog( __FILE__ , __LINE__ , "child close [%d]" , p_env->processor_info_array[i].pipe_session.fds[1] );
			close( p_env->processor_info_array[i].pipe_session.fds[1] );
			for( j = i - 1 ; j >= 0 ; j-- )
			{
				InfoLog( __FILE__ , __LINE__ , "child close [%d] too" , p_env->processor_info_array[j].pipe_session.fds[1] );
				close( p_env->processor_info_array[j].pipe_session.fds[1] );
			}
			p_env->this_processor_info = p_env->processor_info_array+i ;
			if( p_env->cpu_affinity )
				BindCpuAffinity( i );
			exit( -CoconutWorker( p_env ) );
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "parent : [%ld] fork [%ld]" , getpid() , p_env->processor_info_array[i].pid );
			InfoLog( __FILE__ , __LINE__ , "parent close [%d]" , p_env->processor_info_array[i].pipe_session.fds[0] );
			close( p_env->processor_info_array[i].pipe_session.fds[0] );
		}
	}
	
	while( ! g_SIGTERM_flag )
	{
		/* 监控工作进程结束 */
		pid = waitpid( -1 , & status , 0 ) ;
		if( pid == -1 )
		{
			if( errno == EINTR )
				continue;
			ErrorLog( __FILE__ , __LINE__ , "waitpid failed , errno[%d]" , errno );
			goto EE;
		}
		
		/* 判断是否正常结束 */
		if( WIFSIGNALED(status) || WTERMSIG(status) )
		{
			ErrorLog( __FILE__ , __LINE__ , "waitpid[%d] WEXITSTATUS[%d] WIFSIGNALED[%d] WTERMSIG[%d]" , pid , WEXITSTATUS(status) , WIFSIGNALED(status) , WTERMSIG(status) );
		}
		else if( WEXITSTATUS(status) )
		{
			WarnLog( __FILE__ , __LINE__ , "waitpid[%d] WEXITSTATUS[%d] WIFSIGNALED[%d] WTERMSIG[%d]" , pid , WEXITSTATUS(status) , WIFSIGNALED(status) , WTERMSIG(status) );
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "waitpid[%d] WEXITSTATUS[%d] WIFSIGNALED[%d] WTERMSIG[%d]" , pid , WEXITSTATUS(status) , WIFSIGNALED(status) , WTERMSIG(status) );
		}
		
		/* 查询是哪个工作进程 */
		for( i = 0 ; i < p_env->processor_count ; i++ )
		{
			if( p_env->processor_info_array[i].pid == pid )
				break;
		}
		if( i >= p_env->processor_count )
		{
			ErrorLog( __FILE__ , __LINE__ , "unknow pid[%d]" , pid );
			goto EE;
		}
		
		/* 创建工作进程 */
		nret = pipe( p_env->processor_info_array[i].pipe_session.fds ) ;
		if( nret )
		{
			ErrorLog( __FILE__ , __LINE__ , "pipe failed , errno[%d]" , errno );
			goto EE;
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "pipe ok , pipe[%d][%d]" , p_env->processor_info_array[i].pipe_session.fds[0] , p_env->processor_info_array[i].pipe_session.fds[1] );
		}
		
		p_env->processor_info_array[i].pid = fork() ;
		if( p_env->processor_info_array[i].pid == -1 )
		{
			ErrorLog( __FILE__ , __LINE__ , "fork failed , errno[%d]" , errno );
			goto EE;
		}
		else if( p_env->processor_info_array[i].pid == 0 )
		{
			InfoLog( __FILE__ , __LINE__ , "child : [%ld] fork [%ld]" , getppid() , getpid() );
			InfoLog( __FILE__ , __LINE__ , "child close [%d]" , p_env->processor_info_array[i].pipe_session.fds[1] );
			close( p_env->processor_info_array[i].pipe_session.fds[1] );
			for( j = i - 1 ; j >= 0 ; j-- )
			{
				InfoLog( __FILE__ , __LINE__ , "child close [%d] too" , p_env->processor_info_array[j].pipe_session.fds[1] );
				close( p_env->processor_info_array[j].pipe_session.fds[1] );
			}
			p_env->this_processor_info = p_env->processor_info_array+i ;
			if( p_env->cpu_affinity )
				BindCpuAffinity( i );
			exit( CoconutWorker( p_env ) );
		}
		else
		{
			InfoLog( __FILE__ , __LINE__ , "parent : [%ld] fork [%ld]" , getpid() , p_env->processor_info_array[i].pid );
			InfoLog( __FILE__ , __LINE__ , "parent close [%d]" , p_env->processor_info_array[i].pipe_session.fds[0] );
			close( p_env->processor_info_array[i].pipe_session.fds[0] );
		}
	}
	
	InfoLog( __FILE__ , __LINE__ , "parent exiting" );
	
	/* 关闭所有命令管道 */
	for( i = 0 ; i < p_env->processor_count ; i++ )
	{
		close( p_env->processor_info_array[i].pipe_session.fds[1] ) ;
	}
	
	/* 回收工作进程组 */
	for( i = 0 ; i < p_env->processor_count ; i++ )
	{
		pid = waitpid( -1 , & status , 0 ) ;
	}
	
EE :
	/* 释放所有客户端物理会话 */
	FreeAllAcceptedSessionArray( p_env );
	
E5 :
	/* 销毁epoll池 */
	for( i = 0 ; i < p_env->processor_count ; i++ )
	{
		close( p_env->processor_info_array[i].epoll_fd );
	}
	
E4 :
	/* 断开共享内存 */
	shmdt( p_env->serial_space_shm.base );
	
E3 :
	/* 删除共享内存 */
	shmctl( p_env->serial_space_shm.shmid , IPC_RMID , NULL );
	
E2 :
	/* 关闭侦听端口 */
	close( p_env->listen_session.netaddr.sock );
	
E1 :
	InfoLog( __FILE__ , __LINE__ , "--- coconut end ---" );
	
	return 0;
}
	
static void usage()
{
	printf( "coconut v0.0.4.0\n" );
	printf( "Copyright by calvin 2017\n" );
	printf( "USAGE : coconut -r (reserve) -s (server_no) -p (listen_port) [ -c (processor_count) ] [ --log-level (DEBUG|INFO|WARN|ERROR|FATAL) ] [ --cpu-affinity ]\n" );
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
		
		/* 解析命令行参数 */
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
			else if( strcmp( argv[i] , "-c" ) == 0 && i + 1 < argc )
			{
				env.processor_count = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "--log-level" ) == 0 && i + 1 < argc )
			{
				env.log_level = ConvertLogLevel( argv[++i] ) ;
				if( env.log_level == -1 )
				{
					printf( "Invalid command parameter 'log_level'\n" );
					usage();
					exit(7);
				}
			}
			else if( strcmp( argv[i] , "--cpu-affinity" ) == 0 )
			{
				env.cpu_affinity = 1 ;
			}
		}
		
		if( env.log_level == 0 )
		{
			env.log_level = LOGLEVEL_WARN ;
		}
		
		if( env.listen_port < 0 )
		{
			printf( "Invalid command parameter 'listen_port'\n" );
			usage();
			exit(7);
		}
		
		if( env.processor_count == 0 )
			env.processor_count = 1 ;
		else if( env.processor_count == -1 )
			env.processor_count = sysconf(_SC_NPROCESSORS_ONLN) ;
		else if( env.processor_count <= 0 )
		{
			printf( "Invalid command parameter 'processor_count'\n" );
			usage();
			exit(7);
		}
		
		env.processor_info_array = (struct ProcessorInfo *)malloc( sizeof(struct ProcessorInfo) * env.processor_count ) ;
		if( env.processor_info_array == NULL )
		{
			printf( "malloc failed , errno[%d]\n" , errno );
			exit(1);
		}
		memset( env.processor_info_array , 0x00 , sizeof(struct ProcessorInfo) * env.processor_count );
		
		/* 初始化序列号前半段 */
		InitSequence( & env );
		
		/* 进入服务器主函数 */
		nret = BindDaemonServer( & CoconutMonitor , (void*) & env , 1 ) ;
		if( nret )
		{
			printf( "Convert to daemon failed[%d] , errno[%d]\n" , nret , errno );
		}
		
		free( env.processor_info_array );
	}
	else
	{
		usage();
		exit(7);
	}
	
	return 0;
}

